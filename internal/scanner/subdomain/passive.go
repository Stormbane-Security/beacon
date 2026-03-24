// Package subdomain handles asset discovery via passive and active enumeration.
// Discovered subdomains are returned as findings so they appear in reports,
// AND are used by the pipeline to run all other scanners against each asset.
package subdomain

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
	"github.com/stormbane/beacon/internal/scanner/toolinstall"
)

const scannerName = "subdomain"

// PassiveScanner discovers subdomains using crt.sh and subfinder in passive mode.
type PassiveScanner struct {
	subfinderBin string
	ammassBin    string
	otxAPIKey    string
}

func NewPassive(subfinderBin, ammassBin string) *PassiveScanner {
	return &PassiveScanner{subfinderBin: subfinderBin, ammassBin: ammassBin}
}

// NewPassiveWithKeys creates a PassiveScanner with optional API keys for
// enriched passive DNS sources (OTX).
func NewPassiveWithKeys(subfinderBin, ammassBin, otxAPIKey string) *PassiveScanner {
	return &PassiveScanner{subfinderBin: subfinderBin, ammassBin: ammassBin, otxAPIKey: otxAPIKey}
}

func (s *PassiveScanner) Name() string { return scannerName + "/passive" }

// isValidHostname returns true if s is a well-formed RFC 1123 hostname safe
// to pass as a -d argument to subfinder and amass subprocesses.
func isValidHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
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

// Run discovers subdomains for the root domain.
// Returns findings of type "asset.subdomain_discovered" for each unique subdomain found.
// The pipeline uses the Evidence field to extract discovered assets for further scanning.
func (s *PassiveScanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	subdomains := make(map[string]struct{})

	// Source 1: crt.sh Certificate Transparency logs
	crtSubs, err := crtsh(ctx, asset)
	if err == nil {
		for _, sub := range crtSubs {
			subdomains[sub] = struct{}{}
		}
	}

	// Source 2: subfinder — passive on surface scans, active (DNS resolve + all
	// sources) on deep scans where permission has been confirmed.
	finderSubs, err := runSubfinder(ctx, s.subfinderBin, asset, scanType == module.ScanDeep)
	if err == nil {
		for _, sub := range finderSubs {
			subdomains[sub] = struct{}{}
		}
	}

	// Source 3: amass passive/OSINT (surface) or active (deep)
	active := scanType == module.ScanDeep
	amassSubs, err := runAmass(ctx, s.ammassBin, asset, active)
	if err == nil {
		for _, sub := range amassSubs {
			subdomains[sub] = struct{}{}
		}
	}

	// Source 4: urlscan.io passive search index (no key required)
	for _, sub := range urlscanSubdomains(ctx, asset) {
		subdomains[sub] = struct{}{}
	}

	// Source 5: AlienVault OTX passive DNS (optional, requires API key)
	for _, sub := range otxSubdomains(ctx, asset, s.otxAPIKey) {
		subdomains[sub] = struct{}{}
	}

	// Source 6: DNS brute-force with common subdomain wordlist.
	// Purely passive from a target perspective — standard DNS lookups only.
	// Resolves ~160 common prefixes in parallel; adds only those that exist.
	for _, sub := range bruteForceSubdomains(ctx, asset) {
		subdomains[sub] = struct{}{}
	}

	if len(subdomains) == 0 {
		return nil, nil
	}

	// Return discovered subdomains as findings.
	// The pipeline reads asset.subdomain_discovered findings to build its target list.
	var all []string
	for sub := range subdomains {
		if sub != asset {
			all = append(all, sub)
		}
	}

	if len(all) == 0 {
		return nil, nil
	}

	return []finding.Finding{{
		CheckID:      "asset.subdomains_discovered",
		Module:       "surface",
		Scanner:      scannerName,
		Severity:     finding.SeverityInfo,
		Title:        fmt.Sprintf("%d subdomains discovered for %s", len(all), asset),
		Description:  "These subdomains were discovered via passive DNS, certificate transparency logs, and OSINT sources. All are included in the scan.",
		Asset:        asset,
		Evidence:     map[string]any{"subdomains": all, "count": len(all)},
		DiscoveredAt: time.Now(),
	}}, nil
}

// Subdomains extracts the list of discovered subdomains from a subdomain discovery finding.
func Subdomains(f finding.Finding) []string {
	if f.CheckID != "asset.subdomains_discovered" {
		return nil
	}
	raw, ok := f.Evidence["subdomains"]
	if !ok {
		return nil
	}
	// After a JSON round-trip (e.g. from SQLite), the slice deserialises as
	// []interface{}, not []string. Handle both forms.
	switch v := raw.(type) {
	case []string:
		return v
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// crtsh queries the crt.sh Certificate Transparency API for subdomains.
func crtsh(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20)) // 2MB max
	if err != nil {
		return nil, err
	}

	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	var subs []string
	for _, e := range entries {
		// name_value may contain newline-separated names
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.TrimSpace(strings.ToLower(name))
			if name == "" || strings.HasPrefix(name, "*") {
				continue
			}
			if _, ok := seen[name]; !ok {
				seen[name] = struct{}{}
				subs = append(subs, name)
			}
		}
	}
	return subs, nil
}

// runSubfinder runs subfinder in passive mode to discover subdomains.
func runSubfinder(ctx context.Context, bin, domain string, active bool) ([]string, error) {
	if !isValidHostname(domain) {
		return nil, fmt.Errorf("subfinder: invalid domain %q", domain)
	}
	resolvedBin, err := toolinstall.Ensure(bin)
	if err != nil {
		return nil, fmt.Errorf("subfinder: %w", err)
	}

	args := []string{"-d", domain, "-silent", "-o", "-"}
	if !active {
		args = append(args, "-passive")
	}

	cmd := exec.CommandContext(ctx, resolvedBin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil && stdout.Len() == 0 {
		return nil, fmt.Errorf("subfinder: %w", err)
	}

	var subs []string
	scanner := bufio.NewScanner(&stdout)
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" {
			subs = append(subs, strings.ToLower(line))
		}
	}
	return subs, scanner.Err()
}

// runAmass runs amass in passive (OSINT) or active mode.
func runAmass(ctx context.Context, bin, domain string, active bool) ([]string, error) {
	if !isValidHostname(domain) {
		return nil, fmt.Errorf("amass: invalid domain %q", domain)
	}
	resolvedBin, err := toolinstall.Ensure(bin)
	if err != nil {
		return nil, fmt.Errorf("amass: %w", err)
	}

	args := []string{"enum", "-d", domain, "-silent", "-o", "-"}
	if !active {
		args = append(args, "-passive")
	}

	cmd := exec.CommandContext(ctx, resolvedBin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil && stdout.Len() == 0 {
		return nil, fmt.Errorf("amass: %w", err)
	}

	var subs []string
	scanner := bufio.NewScanner(&stdout)
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" {
			subs = append(subs, strings.ToLower(line))
		}
	}
	return subs, scanner.Err()
}
