// Package dlp detects data-loss / sensitive-data exposure in HTTP responses and screenshots.
//
// Two detection methods:
//  1. Regex patterns run against the raw HTTP response body of each asset's main page.
//     Complements the webcontent scanner (which focuses on JavaScript files).
//  2. Claude Vision analysis of screenshot findings captured by the screenshot scanner.
//     Catches sensitive data rendered by JS apps that isn't present in raw HTML.
//
// Additionally, a curated set of high-value configuration/environment dump paths are
// fetched and scanned for API keys, secrets, and credentials. These paths (e.g.
// /actuator/env, /rails/info/properties) return plaintext config data when exposed,
// and are prime locations for leaked database passwords, API keys, and cloud credentials.
//
// All checks are passive observers of publicly accessible content — no credentials,
// no payloads, no login attempts. ModeSurface-safe.
package dlp

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const (
	scannerName       = "dlp"
	maxBodyBytes      = 512 * 1024 // 512 KB — enough to catch patterns without buffering huge files
	emailListMinCount = 25         // flag if this many unique email addresses appear on one page
	// 25 reduces false positives on contact pages, blog author lists, and event
	// pages that legitimately show 10-20 addresses. A true data dump typically
	// contains hundreds of distinct addresses.
)

// pattern pairs a check ID with a compiled regex and human label.
type pattern struct {
	checkID finding.CheckID
	label   string
	re      *regexp.Regexp
}

// dlpPatterns are applied against the full page body.
// These complement webcontent's JS-focused patterns.
var dlpPatterns = []pattern{
	// US Social Security Numbers with dashes — NNN-NN-NNNN format.
	// Invalid ranges (000, 666, 9xx area; 00 group; 0000 serial) filtered in code.
	{
		finding.CheckDLPSSN,
		"US Social Security Number",
		regexp.MustCompile(`\b(\d{3})-(\d{2})-(\d{4})\b`),
	},
	// Major credit card number formats (Visa, MC, Amex, Discover)
	{
		finding.CheckDLPCreditCard,
		"Credit card number",
		regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|2(?:2[2-9][1-9]|[3-6]\d\d|7[01]\d|720)[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b`),
	},
	// Database connection strings with embedded credentials
	{
		finding.CheckDLPDatabaseURL,
		"Database connection string",
		regexp.MustCompile(`(?i)(?:mysql|postgres|postgresql|mongodb|redis|mssql|sqlserver):\/\/[^:@\s"'<>]{1,64}:[^@\s"'<>]{1,64}@[^\s"'<>]+`),
	},
	// PEM private keys — extremely high signal
	{
		finding.CheckDLPPrivateKey,
		"PEM private key",
		regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----`),
	},
	// Ethereum private key — raw hex assignment in source/config
	{
		finding.CheckDLPPrivateKey,
		"Ethereum private key",
		regexp.MustCompile(`(?i)(?:private[_\s]?key|privateKey)["\s]*[:=]["\s]*(?:0x)?[0-9a-fA-F]{64}`),
	},
	// Possible crypto seed phrase — 12 to 24 consecutive short lowercase words.
	// BIP-39 mnemonics consist of 12 or 24 words from a fixed wordlist; this
	// pattern catches sequences of 12+ lowercase alphabetical tokens which are
	// uncommon in normal prose at that length.
	{
		finding.CheckDLPAPIKey,
		"Possible crypto seed phrase",
		regexp.MustCompile(`\b[a-z]{3,8}(?:\s+[a-z]{3,8}){11,23}\b`),
	},
	// EVM contract/wallet address — 0x followed by exactly 40 hex chars.
	// Only flag when the address appears in a sensitive context (assigned to a
	// variable or returned in a JSON field) to avoid matching benign hex values
	// like SHA hashes or padding bytes.
	{
		finding.CheckWeb3ContractFound,
		"EVM contract/wallet address",
		regexp.MustCompile(`(?i)(?:address|contract|wallet|from|to)["\s]*[:=]\s*["']?(0x[0-9a-fA-F]{40})\b`),
	},
}

// apiKeyPatterns are applied against high-value config/env dump paths.
// These paths return JSON or plaintext environment variables that commonly
// contain API keys, cloud credentials, and service secrets.
var apiKeyPatterns = []pattern{
	{finding.CheckDLPAPIKey, "AWS Access Key ID", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{finding.CheckDLPAPIKey, "AWS Secret Access Key", regexp.MustCompile(`(?i)aws.{0,20}secret.{0,20}['"` + "`" + `\s]*[=:]\s*['"` + "`" + `]?[0-9a-zA-Z/+]{40}`)},
	{finding.CheckDLPAPIKey, "GitHub Token", regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`)},
	{finding.CheckDLPAPIKey, "Stripe Secret Key", regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`)},
	{finding.CheckDLPAPIKey, "Google API Key", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)},
	{finding.CheckDLPAPIKey, "OpenAI API Key", regexp.MustCompile(`sk-[A-Za-z0-9]{48}`)},
	{finding.CheckDLPAPIKey, "Anthropic API Key", regexp.MustCompile(`sk-ant-[A-Za-z0-9\-_]{93}`)},
	{finding.CheckDLPAPIKey, "Slack Token", regexp.MustCompile(`xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}`)},
	{finding.CheckDLPAPIKey, "SendGrid API Key", regexp.MustCompile(`SG\.[0-9a-zA-Z\-_]{22}\.[0-9a-zA-Z\-_]{43}`)},
	{finding.CheckDLPAPIKey, "Generic API Key", regexp.MustCompile(`(?i)(api[_-]?key|apikey|api[_-]?secret|secret[_-]?key)['"` + "`" + `\s]*[=:]\s*['"` + "`" + `]?[0-9a-zA-Z\-_]{20,}`)},
	// Database URLs in config dumps (complement root-page dlpPatterns)
	{finding.CheckDLPDatabaseURL, "Database connection string", regexp.MustCompile(`(?i)(?:mysql|postgres|postgresql|mongodb|redis|mssql|sqlserver):\/\/[^:@\s"'<>]{1,64}:[^@\s"'<>]{1,64}@[^\s"'<>]+`)},
	// Private keys
	{finding.CheckDLPPrivateKey, "PEM private key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----`)},
	// Web3 RPC provider API keys embedded in config dumps
	{finding.CheckDLPAPIKey, "Web3 RPC API key (Infura/Alchemy/QuickNode/Ankr)", regexp.MustCompile(`(?i)(?:infura|alchemy|quicknode|ankr)[_\s]?(?:api[_\s]?key|project[_\s]?id|secret)["\s]*[:=]["\s]*[0-9a-zA-Z]{20,}`)},
	// Ethereum private key hex in config dump
	{finding.CheckDLPPrivateKey, "Ethereum private key hex", regexp.MustCompile(`(?i)(?:private|priv)[_\s]?key["\s]*[:=]["\s]*(?:0x)?[0-9a-fA-F]{64}`)},
}

// highValuePaths are endpoints that return configuration data or environment dumps
// when exposed without authentication. Their response bodies are scanned for secrets.
// These are paths that classify/nuclei already flag as exposed, but whose response
// bodies are not otherwise scanned for actual credential values.
var highValuePaths = []string{
	// Dotenv / credential files — directly contain secrets as KEY=VALUE pairs.
	// These are also flagged by exposedfiles as a structural finding; DLP scans
	// the content here to surface individual secret findings (API keys, DB URLs, etc.).
	"/.env",
	"/.env.local",
	"/.env.production",
	"/.env.staging",
	"/.env.backup",
	"/.env.dev",
	"/.env.test",
	"/.aws/credentials",
	"/.docker/config.json",
	"/config/database.yml",
	"/config/secrets.yml",
	"/app/config/parameters.yml",

	// Spring Boot Actuator — returns all environment variables including passwords
	"/actuator/env",
	"/actuator/configprops",
	// Rails info — returns Rails config including secret_key_base, database URL
	"/rails/info/properties",
	"/rails/info",
	// Go pprof debug endpoint — returns goroutine state and vars
	"/debug/vars",
	"/api/debug/vars",
	// Generic config/env dump endpoints common in microservices
	"/env",
	"/config",
	"/api/config",
	"/api/v1/config",
	"/api/env",
	// PHP info pages — reveal all env vars and server config
	"/phpinfo.php",
	"/info.php",
	// HashiCorp Vault — unauthenticated status endpoints
	"/v1/sys/mounts",
	// Laravel Ignition debug page — reveals app config and .env values
	"/_ignition",
	// Symfony profiler — reveals full request/response cycle including headers and config
	"/_profiler",
	// Django debug toolbar API
	"/__debug__/",
	// Node.js server status common paths
	"/status",
	"/api/status",
	"/healthz",
	"/health",
	"/api/health",
	"/metrics",
	"/api/metrics",
}

// seenKey deduplicates DLP findings across root page and high-value path scans.
type seenKey struct {
	id    finding.CheckID
	label string
}

// emailPattern is used separately for count-based detection.
var emailPattern = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)

// Scanner fetches the main HTTP response body and runs DLP pattern matching.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, _ module.ScanType) ([]finding.Finding, error) {
	client := &http.Client{
		Timeout: 20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	body, url, err := fetchBody(ctx, client, asset)
	if err != nil || len(body) == 0 {
		return nil, nil
	}

	var findings []finding.Finding
	now := time.Now()
	bodyStr := string(body)

	for _, p := range dlpPatterns {
		match := p.re.FindString(bodyStr)
		if match == "" {
			continue
		}
		// For SSN: filter out well-known invalid ranges to cut false positives.
		if p.checkID == finding.CheckDLPSSN && !validSSN(match) {
			continue
		}
		redacted := redact(match)
		findings = append(findings, finding.Finding{
			CheckID:  p.checkID,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityCritical,
			Title:    fmt.Sprintf("%s exposed on %s", p.label, asset),
			Description: fmt.Sprintf(
				"A pattern matching a %s was found in the HTTP response from %s. "+
					"This data should not be publicly accessible.",
				strings.ToLower(p.label), url),
			Asset:        asset,
			Evidence:     map[string]any{"url": url, "pattern": p.label, "sample_redacted": redacted},
			DiscoveredAt: now,
		})
	}

	// Email list: count UNIQUE addresses — many distinct emails suggests a data dump.
	// We deduplicate first so that a page repeating one address 100 times doesn't trigger.
	emails := emailPattern.FindAllString(bodyStr, -1)
	seen := map[string]bool{}
	var unique []string
	for _, e := range emails {
		if !seen[e] {
			seen[e] = true
			unique = append(unique, e)
		}
	}
	if len(unique) >= emailListMinCount {
		sample := unique
		if len(sample) > 5 {
			sample = sample[:5]
		}
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckDLPEmailList,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Title:    fmt.Sprintf("%d email addresses exposed on %s", len(unique), asset),
			Description: fmt.Sprintf(
				"%d unique email addresses were found in the HTTP response from %s. "+
					"This may indicate an exposed user list or data export.",
				len(unique), url),
			Asset: asset,
			Evidence: map[string]any{
				"url":    url,
				"count":  len(unique),
				"sample": sample,
			},
			DiscoveredAt: now,
		})
	}

	// Scan high-value config/env dump paths for API keys and secrets.
	// These paths return plaintext or JSON environment variables when exposed.
	// Track (checkID, label) pairs already found to avoid duplicate findings
	// when the same secret appears in multiple paths.
	alreadySeen := map[seenKey]bool{}
	for _, f := range findings {
		alreadySeen[seenKey{f.CheckID, ""}] = true
	}

	scheme := "https"
	if strings.HasPrefix(url, "http://") {
		scheme = "http"
	}
	base := scheme + "://" + asset

	for _, path := range highValuePaths {
		pathFindings := scanPath(ctx, client, asset, base+path, alreadySeen, now)
		findings = append(findings, pathFindings...)
		for _, f := range pathFindings {
			alreadySeen[seenKey{f.CheckID, ""}] = true
		}
	}

	return findings, nil
}

// scanPath fetches a single path and runs apiKeyPatterns + dlpPatterns against its body.
// Returns findings only for patterns not already reported from the root page.
func scanPath(ctx context.Context, client *http.Client, asset, url string, alreadySeen map[seenKey]bool, now time.Time) []finding.Finding {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner/1.0)")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Only scan successful responses — 2xx means the path is exposed and returning data.
	// 3xx would require following redirects (which we disabled); skip them.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if len(body) == 0 {
		return nil
	}
	bodyStr := string(body)

	var findings []finding.Finding
	for _, p := range apiKeyPatterns {
		k := seenKey{p.checkID, p.label}
		if alreadySeen[k] {
			continue
		}
		match := p.re.FindString(bodyStr)
		if match == "" {
			continue
		}
		alreadySeen[k] = true
		redacted := redact(match)
		findings = append(findings, finding.Finding{
			CheckID:  p.checkID,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityCritical,
			Title:    fmt.Sprintf("%s found in exposed config endpoint on %s", p.label, asset),
			Description: fmt.Sprintf(
				"A pattern matching a %s was found in the response body of %s. "+
					"This endpoint is publicly accessible and is returning sensitive configuration data. "+
					"Restrict access to this endpoint immediately and rotate any exposed credentials.",
				strings.ToLower(p.label), url),
			Asset: asset,
			Evidence: map[string]any{
				"url":             url,
				"pattern":         p.label,
				"sample_redacted": redacted,
			},
			DiscoveredAt: now,
		})
	}
	return findings
}

// fetchBody retrieves the HTTP response body, trying HTTPS then HTTP.
// Returns the body (capped at maxBodyBytes), the final URL, and any error.
func fetchBody(ctx context.Context, client *http.Client, asset string) ([]byte, string, error) {
	for _, scheme := range []string{"https", "http"} {
		url := scheme + "://" + asset
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner/1.0)")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
		if err != nil {
			return nil, url, err
		}
		return body, url, nil
	}
	return nil, "", fmt.Errorf("no HTTP response from %s", asset)
}

// validSSN returns false for SSNs with well-known invalid area/group/serial values.
func validSSN(s string) bool {
	parts := strings.SplitN(s, "-", 3)
	if len(parts) != 3 {
		return false
	}
	area, group, serial := parts[0], parts[1], parts[2]
	if area == "000" || area == "666" || strings.HasPrefix(area, "9") {
		return false
	}
	if group == "00" || serial == "0000" {
		return false
	}
	return true
}

// redact replaces the middle 60% of a matched string with asterisks
// so the finding confirms presence without storing raw sensitive data.
func redact(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	keep := len(s) / 5 // show ~20% at start and end
	return s[:keep] + strings.Repeat("*", len(s)-keep*2) + s[len(s)-keep:]
}
