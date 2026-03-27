// Package crawler wraps katana, a JavaScript-aware web crawler from ProjectDiscovery.
// Katana discovers endpoints, forms, and API paths that static HTML analysis misses.
// License: MIT — https://github.com/projectdiscovery/katana
// Skips gracefully if katana is not installed.
package crawler

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
	"github.com/stormbane/beacon/internal/scanner/toolinstall"
)

const scannerName = "crawler"

// Scanner wraps the katana binary as a subprocess.
type Scanner struct {
	bin string
}

func New(bin string) *Scanner {
	if bin == "" {
		bin = "katana"
	}
	return &Scanner{bin: bin}
}

func (s *Scanner) Name() string { return scannerName }

// urlOnDomain returns true when rawURL's host equals asset or is a subdomain of
// it. asset is the bare hostname passed to Run (e.g. "example.com"). This
// prevents the DLP feed from receiving third-party URLs that katana discovers
// while following external links.
func urlOnDomain(rawURL, asset string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	base := strings.ToLower(strings.SplitN(asset, ":", 2)[0]) // strip port if present
	return host == base || strings.HasSuffix(host, "."+base)
}

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	resolvedBin, err := toolinstall.Ensure(s.bin)
	if err != nil {
		return nil, fmt.Errorf("katana: %w", err)
	}

	target := "https://" + asset

	// Scope regex: restrict katana to the target domain and its subdomains.
	// This prevents katana from following external links and crawling third-party
	// sites that the operator has not authorized. The DLP feed filter is a second
	// layer of defence, but limiting katana's scope avoids fetching those pages
	// at all, saving bandwidth and preventing unintended contact.
	bareAsset := strings.SplitN(asset, ":", 2)[0] // strip port if present
	scopeRegex := `.*` + regexp.QuoteMeta(bareAsset) + `.*`

	// Surface: shallow crawl — depth 2, 8 req/s, 2 concurrent, cap 100 pages.
	// Deep: deeper crawl with JS rendering — depth 3, 3 req/s, 2 concurrent, cap 200 pages.
	// Rate limiting (-rl) and page cap (-max-count) prevent excessive load on the target.
	depth, rl, maxCount := "2", "8", "100"
	var extraArgs []string
	if scanType == module.ScanDeep {
		depth, rl, maxCount = "3", "3", "200"
		extraArgs = []string{"-js-crawl"} // parse JS for more endpoints
	}

	args := []string{
		"-u", target,
		"-silent",
		"-no-color",
		"-timeout", "20",
		"-depth", depth,
		"-rl", rl,                           // max requests/second — avoids hammering target
		"-c", "2",                           // 2 concurrent requests
		"-max-count", maxCount,              // hard page cap
		"-max-response-size", "2",           // 2MB max per response
		"-known-files", "all",               // check robots.txt, sitemap.xml
		"-robots",                           // respect robots.txt Disallow rules
		"-cs", scopeRegex,                   // restrict crawl to target domain only
	}
	args = append(args, extraArgs...)

	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, resolvedBin, args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr

	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("katana: stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("katana: start: %w", err)
	}

	// If the orchestrator placed a crawl-feed channel in context, close it via
	// the shared closer (CrawlFeedCloserKey) when katana exits. The closer uses
	// the module's sync.Once, so both this defer and the module's deferred
	// safety-net closer are safe to call — only the first call closes the channel.
	var feedCh chan<- string
	if v := ctx.Value(module.CrawlFeedKey); v != nil {
		if ch, ok := v.(chan string); ok {
			feedCh = ch
		}
	}
	if v := ctx.Value(module.CrawlFeedCloserKey); v != nil {
		if closer, ok := v.(func()); ok {
			defer closer()
		}
	}

	// Stream katana output line by line so each URL reaches the DLP side-goroutine
	// immediately rather than waiting for the full crawl to finish.
	seen := make(map[string]struct{})
	var endpoints []string

	sc := bufio.NewScanner(pipe)
	for sc.Scan() {
		u := strings.TrimSpace(sc.Text())
		if u == "" || !strings.HasPrefix(u, "http") {
			continue
		}
		if _, ok := seen[u]; ok {
			continue
		}
		seen[u] = struct{}{}
		endpoints = append(endpoints, u)

		// Non-blocking send: only forward URLs that belong to the target domain.
		// Katana follows external links by default; the DLP side-goroutine must
		// not fetch third-party domains without separate operator authorization.
		if feedCh != nil && urlOnDomain(u, asset) {
			select {
			case feedCh <- u:
			default:
				// DLP is busy — continue; URL is still in endpoints for the finding.
			}
		}
	}

	// Wait for katana to exit after the pipe is fully drained (os/exec contract).
	if err := cmd.Wait(); err != nil {
		slog.Debug("katana exited with non-zero status", "asset", asset, "error", err,
			"stderr", strings.TrimSpace(stderr.String()))
	}

	// feedOnce fires via defer — signals DLP that the crawl is complete.

	if len(endpoints) == 0 {
		return nil, nil
	}

	// Cap at 200 for evidence
	shown := endpoints
	if len(shown) > 200 {
		shown = shown[:200]
	}

	return []finding.Finding{{
		CheckID:     finding.CheckAssetCrawlEndpoints,
		Module:      "surface",
		Scanner:     scannerName,
		Severity:    finding.SeverityInfo,
		Title:       fmt.Sprintf("%d endpoints discovered on %s via web crawl", len(endpoints), asset),
		Description: fmt.Sprintf("Web crawl of %s discovered %d unique endpoints. These include API paths, forms, and linked resources that expand the attack surface.", asset, len(endpoints)),
		Asset:       asset,
		Evidence: map[string]any{
			"total_count": len(endpoints),
			"endpoints":   shown,
		},
		DiscoveredAt: time.Now(),
	}}, nil
}
