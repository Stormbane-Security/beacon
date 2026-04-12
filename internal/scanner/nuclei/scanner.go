// Package nuclei wraps the Nuclei CLI as a subprocess scanner.
// Nuclei is the primary scanner for TLS, DNS, HTTP headers, exposure,
// misconfiguration, web vulnerabilities, and subdomain takeover detection.
//
// # WAF interaction
//
// ScanAuthorized Nuclei templates include active exploit probes — fuzzing, path enumeration,
// and exploit PoC payloads.
// Active exploitation probes require ScanAuthorized mode (--authorized flag). These WILL trigger WAF managed rules and may
// result in a source-IP block for the duration of the scan or longer.
// Expected behaviour on WAF-protected targets:
//   - Cloudflare/AWS WAF: probe requests return 403 with a WAF challenge page.
//     Nuclei treats 403 as a non-match; template findings will be suppressed.
//   - Imperva/Akamai: may issue a CAPTCHA or silently drop probes.
//   - Rate-based rules: bursts of requests may trigger temporary 429 blocks.
//
// dos, crash, and destructive tags are always excluded (-etags) regardless of
// scan mode, as those templates could disrupt the target service.
package nuclei

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanner/toolinstall"
)

const scannerName = "nuclei"

const staleTemplateThreshold = 30 * 24 * time.Hour // 30 days

// nativelyExcluded lists nuclei template IDs whose checks are fully covered
// by beacon's native scanners with superior detection logic. These are passed
// to nuclei via -exclude-id to avoid redundant probes and duplicate findings.
//
// Native scanner coverage:
//   - tls scanner: full TLS handshake, 19+ checks including cipher/protocol/BEAST/POODLE
//   - secheaders scanner: all security headers + cspaudit deep CSP analysis
//   - dns scanner: actual AXFR transfer, CAA lookup, DNSSEC validation
//   - exposedfiles scanner: 124+ exposure patterns including Git, env, backup, admin
//   - takeover scanner: CNAME-aware fingerprint matching for 30+ services
//   - graphql scanner: full introspection with schema analysis
var nativelyExcluded = []string{
	// TLS — native tls scanner does full handshake + cipher/protocol analysis
	"ssl-dns-names",
	"expired-ssl",
	"expiring-ssl-30d",
	"self-signed-ssl",
	"untrusted-root-certificate",
	"ssl-weak-cipher",
	"tls-version",

	// Security headers — native secheaders + cspaudit scanners
	"missing-csp",
	"missing-hsts",
	"missing-x-frame-options",
	"x-content-type-options",
	"referrer-policy",
	"permissions-policy",
	"http-missing-security-headers",
	"strict-transport-security",

	// DNS — native dns scanner does real AXFR/CAA/DNSSEC
	"dns-zone-transfer",
	"missing-caa-record",
	"dnssec-detection",

	// Exposure — native exposedfiles scanner covers these patterns
	"git-config",
	"git-head",
	"ds-store",
	"dotenv-file",
	"laravel-env",
	"backup-files",
	"db-backup-files",
	"robots-txt-endpoint",

	// API docs — native exposedfiles + swagger scanner
	"swagger-api",
	"swagger-ui",
	"openapi",

	// GraphQL — native graphql scanner does full introspection
	"graphql-introspection",

	// Subdomain takeover — native takeover scanner has CNAME-aware fingerprints
	"subdomain-takeover",
	"azure-takeover-detection",
	"aws-bucket-takeover",
	"github-pages-takeover",
	"netlify-takeover",
	"heroku-takeover",

	// CORS — native cors scanner does credentialed + preflight + null origin
	"cors-misconfig",

	// Tech detection — native fingerprintTech() + fingerprintdb covers 95+
	// technologies via header/body/cookie analysis. Nuclei tech-detect
	// duplicates this into findings instead of the Evidence struct where
	// playbook selection reads it. One authoritative source.
	"tech-detect",
	"wappalyzer-detect",
	"wordpress-detect",
	"drupal-detect",
	"joomla-detect",
	"magento-detect",
	"shopify-detect",

	// Server version disclosure — native classify/versions.go emits
	// classify.eol_software for the same version info
	"server-version-disclosure",
}

// Scanner wraps the nuclei binary as a subprocess.
type Scanner struct {
	bin         string
	surfaceList string // path to curated surface template IDs file
	deepList    string // path to deep template IDs file

	staleOnce    sync.Once
	staleWarning []finding.Finding // emitted once per Scanner instance
}

// New creates a Scanner. bin is the path to the nuclei binary.
func New(bin, surfaceList, deepList string) *Scanner {
	return &Scanner{bin: bin, surfaceList: surfaceList, deepList: deepList}
}

func (s *Scanner) Name() string { return scannerName }

// isValidHostname returns true if s is a well-formed RFC 1123 hostname safe
// to pass as a -target argument to the nuclei subprocess. Rejects anything
// containing hyphens at label boundaries, non-alnum characters, or sequences
// that could be interpreted as CLI flags (e.g. "--config").
func isValidHostname(s string) bool {
	// Strip port suffix (e.g. "localhost:8080" → "localhost") before
	// validating the hostname portion. The port is valid for nuclei targets.
	host := s
	if idx := strings.LastIndex(s, ":"); idx > 0 {
		portPart := s[idx+1:]
		allDigits := true
		for _, c := range portPart {
			if c < '0' || c > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			host = s[:idx]
		}
	}

	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for i, c := range label {
			switch {
			case c >= 'a' && c <= 'z':
			case c >= 'A' && c <= 'Z':
			case c >= '0' && c <= '9':
			case c == '-':
				if i == 0 || i == len(label)-1 {
					return false
				}
			default:
				return false
			}
		}
	}
	return true
}

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	// Validate asset is a well-formed hostname before passing to exec.
	// Prevents argument injection (e.g. "--config /etc/passwd") if a
	// malformed hostname slips through discovery filtering.
	if !isValidHostname(asset) {
		return nil, fmt.Errorf("nuclei: invalid hostname %q", asset)
	}
	// Check template freshness once per scanner instance (not per asset).
	s.staleOnce.Do(func() {
		age := s.TemplateAge()
		if age > staleTemplateThreshold {
			s.staleWarning = []finding.Finding{{
				CheckID:      finding.CheckNucleiStaleTemplates,
				Module:       "surface",
				Scanner:      scannerName,
				Severity:     finding.SeverityMedium,
				Title:        fmt.Sprintf("Nuclei templates are %.0f days old — update recommended", age.Hours()/24),
				Description:  "Nuclei vulnerability templates haven't been updated in over 30 days. New CVE checks added since then will not run. Run `nuclei -update-templates` to refresh.",
				Asset:        asset,
				DiscoveredAt: time.Now(),
			}}
		}
	})

	resolvedBin, err := toolinstall.Ensure(s.bin)
	if err != nil {
		return nil, fmt.Errorf("nuclei: %w", err)
	}

	// Use tag-based filtering: surface mode runs safe/passive templates,
	// authorized mode enables exploitation templates.
	_ = s.surfaceList // template list files no longer used (nuclei v3.x uses -tags)
	_ = s.deepList

	// Ensure target has a scheme — nuclei with -no-httpx doesn't
	// auto-detect the scheme from bare host:port.
	target := asset
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}

	args := []string{
		"-target", target,
		"-jsonl",     // JSONL to stdout (v3.x)
		"-no-color",  // no ANSI codes
		"-omit-raw",  // exclude full request/response from JSONL
		// NOTE: -silent suppresses -jsonl stdout in v3.x, so we omit it.
		// The parser ignores non-JSON lines (banner, progress, [WRN]).
		"-timeout", "30",
		"-retries", "1",
		"-no-interactsh",       // skip OOB interaction server (saves 2-3s startup)
		"-disable-update-check", // skip version check (saves 1s)
		"-no-httpx",            // we already probed HTTP, skip nuclei's httpx check
		"-concurrency", "15",   // parallel template execution
		"-bulk-size", "15",     // batch requests
		"-rate-limit", "50",    // 50 req/s max
		// Skip templates fully covered by native beacon scanners.
		"-eid", strings.Join(nativelyExcluded, ","),
	}

	// Build excluded tags list — single -etags call (nuclei v3.x
	// doesn't reliably handle multiple -etags flags).
	excludeTags := []string{"dos", "crash", "destructive"}
	if scanType == module.ScanSurface {
		// Exclude active exploitation tags in surface mode.
		excludeTags = append(excludeTags, "intrusive", "rce", "sqli", "ssrf", "ssti", "upload", "deserialization")
	}
	args = append(args, "-etags", strings.Join(excludeTags, ","))

	// Fingerprint-driven tag selection: if Phase A identified specific
	// services, only run nuclei templates tagged for those services.
	if fpTags := TagsFromContext(ctx); len(fpTags) > 0 {
		args = append(args, "-tags", strings.Join(fpTags, ","))
	}

	cmd := exec.CommandContext(ctx, resolvedBin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// Nuclei exits non-zero when it finds issues — that's expected.
		// Only fail if stdout is empty and stderr has a real error.
		if stdout.Len() == 0 && stderr.Len() > 0 {
			return nil, fmt.Errorf("nuclei: %s", strings.TrimSpace(stderr.String()))
		}
	}

	findings, err := parseOutput(asset, stdout.Bytes())
	if err != nil {
		return nil, err
	}
	// Prepend the stale-template warning (emitted on first asset only via staleOnce).
	// We copy s.staleWarning into a fresh slice to avoid a data race: if two Run()
	// calls are concurrent and s.staleWarning's backing array has spare capacity,
	// append would write into it from two goroutines simultaneously.
	if len(s.staleWarning) == 0 {
		return findings, nil
	}
	result := make([]finding.Finding, len(s.staleWarning), len(s.staleWarning)+len(findings))
	copy(result, s.staleWarning)
	return append(result, findings...), nil
}

// TemplateAge returns the age of the nuclei templates directory, or -1 if it
// cannot be determined. Used to warn when templates are stale.
func (s *Scanner) TemplateAge() time.Duration {
	resolvedBin, err := toolinstall.Ensure(s.bin)
	if err != nil {
		return -1
	}
	// Nuclei stores templates in ~/.local/nuclei-templates by default.
	// We find the binary's parent, then look for nuclei-templates sibling dir.
	home, err := os.UserHomeDir()
	if err != nil {
		_ = resolvedBin
		return -1
	}
	candidates := []string{
		home + "/.local/nuclei-templates",
		home + "/nuclei-templates",
		home + "/.nuclei-templates",
	}
	for _, dir := range candidates {
		info, err := os.Stat(dir)
		if err == nil && info.IsDir() {
			return time.Since(info.ModTime())
		}
	}
	return -1
}

// RunWithTags runs nuclei against the asset using a specific set of tags
// instead of a template list file. Used by the playbook engine.
func (s *Scanner) RunWithTags(ctx context.Context, asset string, tags []string) ([]finding.Finding, error) {
	if !isValidHostname(asset) {
		return nil, fmt.Errorf("nuclei: invalid hostname %q", asset)
	}
	resolvedBin, err := toolinstall.Ensure(s.bin)
	if err != nil {
		return nil, fmt.Errorf("nuclei: %w", err)
	}

	target := asset
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}

	args := []string{
		"-target", target,
		"-tags", strings.Join(tags, ","),
		"-jsonl",
		"-no-color",
		"-timeout", "30",
		"-retries", "1",
		"-etags", "dos,crash,destructive",
		// Skip templates fully covered by native beacon scanners.
		"-eid", strings.Join(nativelyExcluded, ","),
	}

	cmd := exec.CommandContext(ctx, resolvedBin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if stdout.Len() == 0 && stderr.Len() > 0 {
			return nil, fmt.Errorf("nuclei: %s", strings.TrimSpace(stderr.String()))
		}
	}

	return parseOutput(asset, stdout.Bytes())
}

// nucleiResult is the JSON structure emitted by nuclei -json-export.
type nucleiResult struct {
	TemplateID  string `json:"template-id"`
	Info        struct {
		Name        string   `json:"name"`
		Severity    string   `json:"severity"`
		Description string   `json:"description"`
		Tags        []string `json:"tags"`
		Reference   []string `json:"reference"`
	} `json:"info"`
	Host             string            `json:"host"`
	MatchedAt        string            `json:"matched-at"`
	ExtractedResults []string          `json:"extracted-results"`
	Meta             map[string]string `json:"meta"`
	CurlCommand      string            `json:"curl-command"`
	MatcherName      string            `json:"matcher-name"`
	Type             string            `json:"type"`
	Timestamp        time.Time         `json:"timestamp"`
}

func parseOutput(asset string, data []byte) ([]finding.Finding, error) {
	var findings []finding.Finding
	scanner := bufio.NewScanner(bytes.NewReader(data))

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var r nucleiResult
		if err := json.Unmarshal(line, &r); err != nil {
			// Log parse failures for non-empty lines that look like JSON.
			if len(line) > 0 && line[0] == '{' {
			}
			continue // skip malformed lines
		}
		if r.TemplateID == "" || r.Info.Name == "" {
			continue // skip incomplete results
		}

		checkID := finding.MapNucleiTemplate(r.TemplateID)
		sev := finding.ParseSeverity(r.Info.Severity)

		evidence := map[string]any{
			"template_id":       r.TemplateID,
			"matched_at":        r.MatchedAt,
			"extracted_results": r.ExtractedResults,
			"meta":              r.Meta,
		}
		// Preserve additional context fields when present.
		if r.MatcherName != "" {
			evidence["matcher_name"] = r.MatcherName
		}
		if r.Type != "" {
			evidence["type"] = r.Type
		}
		if len(r.Info.Tags) > 0 {
			evidence["tags"] = r.Info.Tags
		}
		if len(r.Info.Reference) > 0 {
			evidence["references"] = r.Info.Reference
		}

		// Map nuclei tags to vulnerability class for exploit chain routing.
		// When --authorized --yes is used, the exploit dispatcher can route
		// nuclei findings to the appropriate exploit module (SQLi, LFI, etc.).
		if vc := nucleiTagsToVulnClass(r.Info.Tags); vc != "" {
			evidence["vuln_class"] = vc
		}

		// Use nuclei's curl-command as the proof command when available.
		proofCmd := r.CurlCommand

		findings = append(findings, finding.Finding{
			CheckID:      checkID,
			Module:       "surface",
			Scanner:      scannerName,
			Severity:     sev,
			Title:        r.Info.Name,
			Description:  r.Info.Description,
			Asset:        asset,
			Evidence:     evidence,
			ProofCommand: proofCmd,
			DiscoveredAt: r.Timestamp,
		})
	}

	return findings, scanner.Err()
}

// nucleiTagsToVulnClass maps nuclei template tags to a vulnerability class
// that the exploit chain dispatcher can route on. Returns empty string if
// no exploitable class is identified.
func nucleiTagsToVulnClass(tags []string) string {
	for _, tag := range tags {
		switch tag {
		case "sqli", "sql-injection":
			return "sqli"
		case "lfi", "local-file-inclusion", "file-inclusion":
			return "lfi"
		case "ssrf", "server-side-request-forgery":
			return "ssrf"
		case "rce", "remote-code-execution":
			return "rce"
		case "ssti", "template-injection":
			return "ssti"
		case "xxe", "xml-external-entity":
			return "xxe"
		case "cmdi", "command-injection", "os-command-injection":
			return "cmdinj"
		}
	}
	return ""
}
