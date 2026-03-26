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
	"os/exec"
	"strings"
	"sync"
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

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	resolvedBin, err := toolinstall.Ensure(s.bin)
	if err != nil {
		return nil, fmt.Errorf("katana: %w", err)
	}

	target := "https://" + asset

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

	// If the orchestrator placed a crawl-feed channel in context, we own closing
	// it when katana exits. Use a sync.Once so the close is safe even if this
	// function returns early (e.g. context cancelled mid-scan).
	var feedCh chan<- string
	var feedOnce sync.Once
	if v := ctx.Value(module.CrawlFeedKey); v != nil {
		if ch, ok := v.(chan string); ok {
			feedCh = ch
			defer feedOnce.Do(func() { close(feedCh) })
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

		// Non-blocking send: drop if the consumer is behind rather than stalling
		// the stdout reader (which would cause katana to block on its write).
		if feedCh != nil {
			select {
			case feedCh <- u:
			default:
				// DLP is busy — continue; the URL is still in endpoints for the finding.
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
