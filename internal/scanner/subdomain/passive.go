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
	"net"
	"net/http"
	neturl "net/url"
	"os/exec"
	"strings"
	"sync"
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
	// All sources run concurrently under a single deadline so no single slow or
	// hung source (subfinder querying GitHub, amass doing zone-walking) can block
	// the entire discovery phase. Passive: 5 min total. Deep: 12 min total.
	deadline := 5 * time.Minute
	if scanType == module.ScanDeep {
		deadline = 12 * time.Minute
	}
	runCtx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()

	active := scanType == module.ScanDeep
	otxKey := s.otxAPIKey

	type sourceResult struct{ subs []string }
	ch := make(chan sourceResult, 6)
	var wg sync.WaitGroup

	launch := func(fn func() []string) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ch <- sourceResult{fn()}
		}()
	}

	// Source 1: crt.sh Certificate Transparency logs
	launch(func() []string { subs, _ := crtsh(runCtx, asset); return subs })

	// Source 2: subfinder — passive on surface, active (all sources + DNS) on deep
	launch(func() []string { subs, _ := runSubfinder(runCtx, s.subfinderBin, asset, active); return subs })

	// Source 3: amass passive/OSINT (surface) or active (deep)
	launch(func() []string { subs, _ := runAmass(runCtx, s.ammassBin, asset, active); return subs })

	// Source 4: urlscan.io passive search index (no key required)
	launch(func() []string { return urlscanSubdomains(runCtx, asset) })

	// Source 5: AlienVault OTX passive DNS (optional, requires API key)
	launch(func() []string { return otxSubdomains(runCtx, asset, otxKey) })

	// Source 6: DNS brute-force with common subdomain wordlist
	launch(func() []string { return bruteForceSubdomains(runCtx, asset) })

	go func() { wg.Wait(); close(ch) }()

	subdomains := make(map[string]struct{})
	for r := range ch {
		for _, sub := range r.subs {
			subdomains[sub] = struct{}{}
		}
	}

	if len(subdomains) == 0 {
		return nil, nil
	}

	// ── Wildcard DNS detection ────────────────────────────────────────────────
	// Before building the subdomain list, check if *.asset resolves. If it does,
	// any subdomain resolving to the same wildcard IP set is a false positive
	// from the wildcard record, not a unique discovery.
	wildcardIPs := detectWildcardDNS(runCtx, asset)
	isWildcard := len(wildcardIPs) > 0

	// Return discovered subdomains as findings.
	// The pipeline reads asset.subdomain_discovered findings to build its target list.
	var all []string
	var wildcardFiltered int
	for sub := range subdomains {
		if sub == asset {
			continue
		}
		// Filter wildcard false positives: resolve each subdomain and check
		// if ALL its IPs are in the wildcard set.
		if isWildcard {
			addrs, err := net.DefaultResolver.LookupHost(runCtx, sub)
			if err == nil && len(addrs) > 0 {
				allWild := true
				for _, a := range addrs {
					if _, ok := wildcardIPs[a]; !ok {
						allWild = false
						break
					}
				}
				if allWild {
					wildcardFiltered++
					continue
				}
			}
		}
		all = append(all, sub)
	}

	if len(all) == 0 {
		return nil, nil
	}

	var findings []finding.Finding

	// If wildcard DNS was detected, emit an informational finding.
	if isWildcard {
		var wcIPs []string
		for ip := range wildcardIPs {
			wcIPs = append(wcIPs, ip)
		}
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckDNSWildcard,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityInfo,
			Title:    fmt.Sprintf("Wildcard DNS detected for *.%s", asset),
			Description: fmt.Sprintf(
				"*.%s resolves to %v. %d subdomain results were filtered as wildcard "+
					"false positives. Remaining %d subdomains resolve to unique IPs.",
				asset, wcIPs, wildcardFiltered, len(all)),
			Asset: asset,
			Evidence: map[string]any{
				"wildcard_ips":     wcIPs,
				"filtered_count":   wildcardFiltered,
				"remaining_count":  len(all),
			},
			DiscoveredAt: time.Now(),
		})
	}

	findings = append(findings, finding.Finding{
		CheckID:      "asset.subdomains_discovered",
		Module:       "surface",
		Scanner:      scannerName,
		Severity:     finding.SeverityInfo,
		Title:        fmt.Sprintf("%d subdomains discovered for %s", len(all), asset),
		Description:  "These subdomains were discovered via passive DNS, certificate transparency logs, and OSINT sources. All are included in the scan.",
		Asset:        asset,
		Evidence:     map[string]any{"subdomains": all, "count": len(all)},
		DiscoveredAt: time.Now(),
	})

	return findings, nil
}

// detectWildcardDNS resolves a random subdomain under domain. If it resolves,
// the domain has wildcard DNS configured. Returns the set of wildcard IPs, or
// nil if no wildcard is detected.
func detectWildcardDNS(ctx context.Context, domain string) map[string]struct{} {
	probe := "beacon-wc-probe-z9x8w7v6." + domain
	addrs, err := net.DefaultResolver.LookupHost(ctx, probe)
	if err != nil || len(addrs) == 0 {
		return nil
	}
	ips := make(map[string]struct{}, len(addrs))
	for _, a := range addrs {
		ips[a] = struct{}{}
	}
	return ips
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
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", neturl.QueryEscape(domain))
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

	// Cap subfinder runtime — some passive sources (GitHub, Shodan, etc.) stall
	// indefinitely. 8 min is generous for passive; 15 min for active DNS resolve.
	sfTimeout := 8 * time.Minute
	if active {
		sfTimeout = 15 * time.Minute
	}
	sfCtx, sfCancel := context.WithTimeout(ctx, sfTimeout)
	defer sfCancel()

	args := []string{"-d", domain, "-silent", "-o", "-", "-timeout", "30"}
	if !active {
		args = append(args, "-passive")
	}

	cmd := exec.CommandContext(sfCtx, resolvedBin, args...)
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
