// Package harvester wraps theHarvester CLI to enumerate employee email addresses,
// names, subdomains, and IPs from public sources (LinkedIn, Google, Bing, GitHub,
// Hunter.io, etc.).
//
// Results are used to:
//  1. Identify employee identities for targeted attack surface analysis.
//  2. Feed discovered emails into the HIBP breach checker.
//  3. Surface company name, ASN, and social presence as context for AI analysis.
//
// theHarvester must be installed and reachable via the configured binary path.
// If the binary is not found or the domain has no results, the scanner is a no-op.
//
// Installation: pip install theHarvester  (or: apt install theharvester)
package harvester

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
	"github.com/stormbane/beacon/internal/scanner/toolinstall"
)

const scannerName = "harvester"

// Scanner wraps the theHarvester CLI.
type Scanner struct {
	bin string // path to theHarvester binary
}

// New returns a new Scanner.
// bin is the path to the theHarvester binary (e.g. "/usr/bin/theHarvester").
// If bin is empty the scanner is a no-op.
func New(bin string) *Scanner { return &Scanner{bin: bin} }

func (s *Scanner) Name() string { return scannerName }

// Run executes theHarvester against the root domain and emits findings for
// discovered emails and subdomains. Only runs on root domains (single dot).
func (s *Scanner) Run(ctx context.Context, asset string, _ module.ScanType) ([]finding.Finding, error) {
	// Only run on root domain to avoid N identical OSINT lookups per subdomain.
	// "example.co.uk" has 2 dots and is a valid ccTLD+SLD root domain.
	// Anything with more than 2 dots is guaranteed to be a subdomain.
	if strings.Count(asset, ".") > 2 {
		return nil, nil
	}

	// Resolve or auto-install the binary. Use the configured path if set,
	// otherwise try PATH then attempt pip install.
	bin := s.bin
	if bin == "" {
		bin = "theHarvester"
	}
	resolvedBin, err := toolinstall.EnsurePython(bin)
	if err != nil {
		// Emit an info finding so operators know harvester is unavailable,
		// rather than silently skipping valuable OSINT data.
		return []finding.Finding{{
			CheckID:  finding.CheckHarvesterUnavailable,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityInfo,
			Asset:    asset,
			Title:    "theHarvester not available — OSINT email/subdomain enumeration skipped",
			Description: fmt.Sprintf(
				"theHarvester could not be found or installed automatically. "+
					"Install it with: pip3 install theHarvester (or: sudo apt install theharvester). "+
					"Error: %s", err,
			),
			Evidence:     map[string]any{"install_error": err.Error()},
			DiscoveredAt: time.Now(),
		}}, nil
	}

	emails, subdomains, err := runHarvester(ctx, resolvedBin, asset)
	if err != nil || (len(emails) == 0 && len(subdomains) == 0) {
		return nil, nil
	}

	var findings []finding.Finding
	now := time.Now()

	if len(emails) > 0 {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckHarvesterEmails,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityInfo,
			Asset:    asset,
			Title:    fmt.Sprintf("theHarvester found %d employee email(s) for %s", len(emails), asset),
			Description: fmt.Sprintf(
				"theHarvester discovered %d email addresses associated with %s from public sources "+
					"(search engines, LinkedIn, GitHub, Hunter.io). These identities represent the "+
					"human attack surface: credential stuffing targets, phishing recipients, and "+
					"social engineering entry points. Check HIBP for breach exposure.",
				len(emails), asset,
			),
			Evidence: map[string]any{
				"emails": emails,
				"count":  len(emails),
			},
			DiscoveredAt: now,
		})
	}

	if len(subdomains) > 0 {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckHarvesterSubdomains,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityInfo,
			Asset:    asset,
			Title:    fmt.Sprintf("theHarvester found %d subdomain(s) for %s", len(subdomains), asset),
			Description: fmt.Sprintf(
				"theHarvester discovered %d subdomains for %s from public OSINT sources. "+
					"These may include assets not found by certificate transparency or DNS brute-force.",
				len(subdomains), asset,
			),
			Evidence: map[string]any{
				"subdomains": subdomains,
				"count":      len(subdomains),
			},
			DiscoveredAt: now,
		})
	}

	return findings, nil
}

// runHarvester executes theHarvester and parses its output for emails and subdomains.
func runHarvester(ctx context.Context, bin, domain string) (emails, subdomains []string, err error) {
	// Use multiple sources for broader coverage. Limit to 500 results per source.
	// Sources that don't require API keys: bing, google, yahoo, github, dnsdumpster, urlscan
	cmd := exec.CommandContext(ctx, bin,
		"-d", domain,
		"-b", "bing,google,yahoo,github,dnsdumpster,urlscan,crtsh",
		"-l", "500",
		"-f", "/dev/null", // no output file
	)

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = nil // suppress stderr noise

	// theHarvester can be slow — allow up to 2 minutes
	runCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd = exec.CommandContext(runCtx, bin,
		"-d", domain,
		"-b", "bing,google,yahoo,github,dnsdumpster,urlscan,crtsh",
		"-l", "500",
	)
	cmd.Stdout = &out
	cmd.Stderr = nil

	if runErr := cmd.Run(); runErr != nil {
		// theHarvester exits non-zero even on partial results — parse what we have
		if out.Len() == 0 {
			return nil, nil, runErr
		}
	}

	emailSet := make(map[string]bool)
	subSet := make(map[string]bool)

	scanner := bufio.NewScanner(&out)
	inEmails := false
	inHosts := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// theHarvester output sections
		if strings.Contains(line, "[*] Emails found:") || strings.Contains(line, "Emails found") {
			inEmails = true
			inHosts = false
			continue
		}
		if strings.Contains(line, "[*] Hosts found:") || strings.Contains(line, "Hosts found") {
			inHosts = true
			inEmails = false
			continue
		}
		if strings.HasPrefix(line, "[*]") || strings.HasPrefix(line, "---") {
			inEmails = false
			inHosts = false
			continue
		}

		if line == "" {
			continue
		}

		if inEmails {
			if isEmail(line) {
				emailSet[strings.ToLower(line)] = true
			}
		} else if inHosts {
			// Lines may be "hostname:IP" or just "hostname"
			host := strings.Split(line, ":")[0]
			host = strings.TrimSpace(host)
			if host != "" && strings.Contains(host, ".") && !strings.Contains(host, " ") {
				subSet[strings.ToLower(host)] = true
			}
		} else {
			// Fallback: detect emails anywhere in output
			if isEmail(line) {
				emailSet[strings.ToLower(line)] = true
			}
		}
	}

	for e := range emailSet {
		emails = append(emails, e)
	}
	for s := range subSet {
		subdomains = append(subdomains, s)
	}
	return emails, subdomains, nil
}

// isEmail returns true if s looks like an email address.
func isEmail(s string) bool {
	at := strings.Index(s, "@")
	if at < 1 || at >= len(s)-1 {
		return false
	}
	domain := s[at+1:]
	return strings.Contains(domain, ".") && !strings.ContainsAny(s, " \t<>")
}
