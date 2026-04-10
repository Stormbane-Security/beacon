// Package crawler — native Go fallback crawler for when katana is not installed.
// Performs BFS crawling, extracts links from HTML, and parses JS bundles for
// API endpoints using the jsendpoints bundle parser.
package crawler

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scan"
	"github.com/stormbane-security/beacon/internal/scanner/jsendpoints"
)

// ── Link extraction patterns ──────────────────────────────────────────────

var (
	hrefRe   = regexp.MustCompile(`(?i)\bhref\s*=\s*["']([^"'#]+)["']`)
	srcRe    = regexp.MustCompile(`(?i)\bsrc\s*=\s*["']([^"'#]+)["']`)
	actionRe = regexp.MustCompile(`(?i)\baction\s*=\s*["']([^"'#]+)["']`)
)

// NativeCrawl performs a recursive HTTP crawl without external dependencies.
// Extracts links from HTML (href, src, action), follows redirects, and
// parses JS files for API endpoints using the bundle parser.
func NativeCrawl(ctx context.Context, client *http.Client, baseURL string, maxDepth int, maxPages int) []string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}

	type item struct {
		u     string
		depth int
	}

	seen := make(map[string]struct{})
	var result []string
	queue := []item{{u: baseURL, depth: 0}}
	seen[baseURL] = struct{}{}

	// Semaphore for concurrency (5 concurrent requests).
	sem := make(chan struct{}, 5)
	var mu sync.Mutex

	for len(queue) > 0 && len(result) < maxPages {
		// Take a batch from the queue (up to semaphore size).
		batchSize := len(queue)
		if batchSize > 5 {
			batchSize = 5
		}
		batch := queue[:batchSize]
		queue = queue[batchSize:]

		var wg sync.WaitGroup
		for _, it := range batch {
			if ctx.Err() != nil {
				break
			}
			mu.Lock()
			if len(result) >= maxPages {
				mu.Unlock()
				break
			}
			mu.Unlock()

			if it.depth > maxDepth {
				continue
			}

			wg.Add(1)
			it := it
			sem <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-sem }()

				links := fetchAndExtract(ctx, client, it.u, base)

				mu.Lock()
				defer mu.Unlock()
				if len(result) >= maxPages {
					return
				}
				result = append(result, it.u)

				for _, link := range links {
					if _, ok := seen[link]; ok {
						continue
					}
					if len(seen) >= maxPages*2 { // don't queue too many
						break
					}
					seen[link] = struct{}{}
					queue = append(queue, item{u: link, depth: it.depth + 1})
				}
			}()
		}
		wg.Wait()
	}

	return result
}

// fetchAndExtract fetches a URL and extracts links from its content.
// For JS files, it also runs the bundle parser to extract API endpoints.
func fetchAndExtract(ctx context.Context, client *http.Client, rawURL string, base *url.URL) []string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner)")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	// Follow redirects manually — the shared client doesn't follow them.
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		loc := resp.Header.Get("Location")
		if loc != "" {
			if resolved := resolveURL(base, loc); resolved != "" && isSameOrigin(base, resolved) {
				return []string{resolved}
			}
		}
		return nil
	}

	if resp.StatusCode != 200 {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024)) // 2MB max
	if err != nil {
		return nil
	}
	content := string(body)

	var links []string
	ct := resp.Header.Get("Content-Type")

	// Parse JS files with the bundle parser for API routes.
	if strings.Contains(ct, "javascript") || strings.HasSuffix(rawURL, ".js") {
		bf := jsendpoints.ParseBundle(content, rawURL)
		for _, ep := range bf.APIEndpoints {
			if resolved := resolveURL(base, ep.Path); resolved != "" && isSameOrigin(base, resolved) {
				links = append(links, resolved)
			}
		}
	}

	// Extract links from HTML attributes.
	for _, re := range []*regexp.Regexp{hrefRe, srcRe, actionRe} {
		for _, m := range re.FindAllStringSubmatch(content, 500) {
			raw := strings.TrimSpace(m[1])
			if raw == "" || strings.HasPrefix(raw, "javascript:") || strings.HasPrefix(raw, "mailto:") || strings.HasPrefix(raw, "data:") {
				continue
			}
			if resolved := resolveURL(base, raw); resolved != "" && isSameOrigin(base, resolved) {
				links = append(links, resolved)
			}
		}
	}

	return links
}

// resolveURL resolves a potentially relative URL against a base.
func resolveURL(base *url.URL, raw string) string {
	ref, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	resolved := base.ResolveReference(ref)
	// Strip fragment.
	resolved.Fragment = ""
	return resolved.String()
}

// isSameOrigin returns true if rawURL belongs to the same host or a subdomain.
func isSameOrigin(base *url.URL, rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	baseHost := strings.ToLower(base.Hostname())
	return host == baseHost || strings.HasSuffix(host, "."+baseHost)
}

// runNativeFallback invokes NativeCrawl and feeds results into the crawl pipeline
// the same way the katana-based Run method does.
func (s *Scanner) runNativeFallback(ctx context.Context, asset, target string, scanType module.ScanType) ([]finding.Finding, error) {
	maxDepth, maxPages := 3, 200
	timeout := 90 * time.Second
	switch scanType {
	case module.ScanDeep:
		maxDepth, maxPages = 5, 500
		timeout = 180 * time.Second
	case module.ScanAuthorized:
		maxDepth, maxPages = 7, 1000
		timeout = 300 * time.Second
	}

	// Build an HTTP client — use the scan context's client if available.
	client := scan.SharedClient(15 * time.Second)
	if sctx, ok := scan.FromContext(ctx); ok {
		client = sctx.HTTPClient()
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	endpoints := NativeCrawl(ctx, client, target, maxDepth, maxPages)

	// Feed discovered URLs into the crawl-feed channel for downstream scanners.
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

	for _, u := range endpoints {
		if feedCh != nil && urlOnDomain(u, asset) {
			select {
			case feedCh <- u:
			default:
			}
		}
	}

	if len(endpoints) == 0 {
		return nil, nil
	}

	shown := endpoints
	if len(shown) > 200 {
		shown = shown[:200]
	}

	slog.Info("native crawler completed", "asset", asset, "endpoints", len(endpoints))

	return []finding.Finding{{
		CheckID:     finding.CheckAssetCrawlEndpoints,
		Module:      "surface",
		Scanner:     scannerName,
		Severity:    finding.SeverityInfo,
		Title:       fmt.Sprintf("%d endpoints discovered on %s via native web crawl", len(endpoints), asset),
		Description: fmt.Sprintf("Native Go crawl of %s discovered %d unique endpoints (katana not available). These include API paths, forms, and linked resources that expand the attack surface.", asset, len(endpoints)),
		Asset:       asset,
		Evidence: map[string]any{
			"total_count": len(endpoints),
			"endpoints":   shown,
			"crawler":     "native",
		},
		DiscoveredAt: time.Now(),
	}}, nil
}
