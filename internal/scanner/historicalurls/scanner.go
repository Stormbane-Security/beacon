// Package historicalurls wraps gau (getallurls) to fetch known URLs for a domain
// from the Wayback Machine and AlienVault OTX. Historical URLs often reveal
// forgotten endpoints, old API versions, and backup files that may still be live.
// gau is MIT-licensed: https://github.com/lc/gau
package historicalurls

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

const scannerName = "historicalurls"

// Scanner wraps the gau binary as a subprocess.
type Scanner struct {
	bin string
}

func New(bin string) *Scanner {
	if bin == "" {
		bin = "gau"
	}
	return &Scanner{bin: bin}
}

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, _ module.ScanType) ([]finding.Finding, error) {
	// Only run on root domain — gau recurses into subdomains itself.
	// "example.co.uk" has 2 dots and is a valid ccTLD+SLD root domain.
	// Anything with more than 2 dots is guaranteed to be a subdomain.
	if strings.Count(asset, ".") > 2 {
		return nil, nil
	}

	resolvedBin, err := toolinstall.Ensure(s.bin)
	if err != nil {
		return nil, fmt.Errorf("gau: %w", err)
	}
	s.bin = resolvedBin

	// gau flags: --subs includes subdomains, --retries 2, timeout via context
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, resolvedBin,
		"--subs",           // include subdomains
		"--retries", "2",
		"--timeout", "10",
		asset,
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, nil // timeout — return what we have
		}
		return nil, nil
	}

	// Parse URLs — one per line
	seen := make(map[string]struct{})
	var urls []string

	scanner := bufio.NewScanner(&stdout)
	for scanner.Scan() {
		u := strings.TrimSpace(scanner.Text())
		if u == "" {
			continue
		}
		if _, ok := seen[u]; ok {
			continue
		}
		seen[u] = struct{}{}
		urls = append(urls, u)
	}

	if len(urls) == 0 {
		return nil, nil
	}

	// Cap at 500 URLs for evidence — the full list can be enormous
	shown := urls
	if len(shown) > 500 {
		shown = shown[:500]
	}

	// Flag interesting patterns — these are high-signal URLs worth noting
	var interesting []string
	for _, u := range urls {
		ul := strings.ToLower(u)
		if isInteresting(ul) {
			interesting = append(interesting, u)
			if len(interesting) >= 50 {
				break
			}
		}
	}

	return []finding.Finding{{
		CheckID:     finding.CheckAssetHistoricalURLs,
		Module:      "surface",
		Scanner:     scannerName,
		Severity:    finding.SeverityInfo,
		Title:       fmt.Sprintf("%d historical URLs discovered for %s", len(urls), asset),
		Description: fmt.Sprintf("The Wayback Machine and AlienVault OTX contain records of %d URLs previously crawled under %s. These may include old API endpoints, backup files, and admin paths that are no longer linked but could still be accessible.", len(urls), asset),
		Asset:       asset,
		Evidence: map[string]any{
			"total_count":  len(urls),
			"sample_urls":  shown,
			"interesting":  interesting,
		},
		DiscoveredAt: time.Now(),
	}}, nil
}

// isInteresting returns true for URL patterns worth flagging in the report.
func isInteresting(u string) bool {
	patterns := []string{
		".env", ".bak", ".backup", ".sql", ".db", ".tar", ".zip", ".gz",
		"/admin", "/wp-admin", "/phpmyadmin", "/cpanel",
		"/api/", "/v1/", "/v2/", "/graphql", "/swagger", "/openapi",
		"/_debug", "/.git", "/config", "/credentials",
		"token=", "key=", "password=", "secret=", "api_key=",
		"/staging", "/dev/", "/test/",
	}
	for _, p := range patterns {
		if strings.Contains(u, p) {
			return true
		}
	}
	return false
}
