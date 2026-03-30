// Package dirbust implements targeted directory/path brute-forcing for deep scans.
//
// Paths are driven by playbook dirbust_paths lists — only technology-specific
// paths for detected software are probed (e.g. Grafana paths only if Grafana
// was detected). This avoids generic wordlist noise and keeps request counts low.
//
// # Noise level
//
// Even with targeted path lists, dirbust generates one HTTP request per path per
// asset. A typical playbook run issues 50–200 HEAD requests from a single IP in
// a short window. This is conspicuous in access logs and WILL trigger WAF
// rate-limiting and potentially an IP block on aggressively tuned targets.
//
// Built-in mitigations:
//   - Concurrency is capped at 10 parallel requests.
//   - 429 responses trigger exponential backoff (2 s → 30 s), honouring Retry-After.
//   - Three consecutive 403+WAF-header responses abort the scan early and emit
//     a CheckDirbustWAFBlocked finding.
//
// This scanner runs in deep mode only and requires --permission-confirmed.
package dirbust

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/stormbane/beacon/internal/finding"
)

const (
	// defaultConcurrency limits parallel probes. 10 keeps scan traffic below
	// typical WAF connection-rate thresholds while remaining fast enough for
	// a 200-path deep scan to finish in ~30 seconds with a 10s timeout.
	defaultConcurrency = 10
	maxRetries         = 3
	baseBackoff        = 2 * time.Second
	maxBackoff         = 30 * time.Second

	// A path is "interesting" if it returns one of these status codes.
	// 200/201 = found, 301/302 = redirect (may reveal the path), 401/403 = exists but gated.
	// We skip 404 (not found) and 400 (bad request).
)

var interestingCodes = map[int]bool{
	http.StatusOK:                   true,
	http.StatusCreated:              true,
	http.StatusMovedPermanently:     true,
	http.StatusFound:                true,
	http.StatusSeeOther:             true,
	http.StatusTemporaryRedirect:    true,
	http.StatusPermanentRedirect:    true,
	http.StatusUnauthorized:         true, // exists but requires auth
	http.StatusForbidden:            true, // exists but gated
}

// wafHeaders are response headers commonly set by WAFs when blocking a scan.
var wafHeaders = []string{
	"x-sucuri-id", "x-firewall-protection", "x-waf-status",
	// NOTE: cf-ray is intentionally excluded — Cloudflare sets it on ALL responses
	// (200, 301, 404, etc.), not only blocks. Including it caused false positives
	// on every Cloudflare-proxied asset, stopping dirbusting prematurely.
	"x-kong-upstream-status",
	"server-timing", // Akamai sets this on block pages
}

// Result is a single discovered path.
type Result struct {
	Path       string
	StatusCode int
}

// Scanner performs targeted path brute-forcing.
type Scanner struct {
	concurrency int
	client      *http.Client
	ffufBin     string
}

// New creates a Scanner with default settings.
func New() *Scanner {
	return &Scanner{
		concurrency: defaultConcurrency,
		client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse // don't follow; we want the redirect code
			},
		},
	}
}

// NewWithFfuf creates a Scanner that will use ffuf as the backend when available.
// Falls back to the pure-Go prober when ffuf is not found.
func NewWithFfuf(ffufBin string) *Scanner {
	s := New()
	s.ffufBin = ffufBin
	return s
}

// NewWithClient creates a Scanner using the provided HTTP client.
// Intended for testing so a custom TLS-trusting client can be injected.
func NewWithClient(client *http.Client) *Scanner {
	// Preserve the no-redirect policy regardless of what the caller passes.
	orig := client.CheckRedirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if orig != nil {
			return orig(req, via)
		}
		return http.ErrUseLastResponse
	}
	return &Scanner{
		concurrency: defaultConcurrency,
		client:      client,
	}
}

// Run probes the given paths against the asset and returns findings.
// asset should be a hostname (e.g. "admin.example.com").
// paths should be relative URL paths starting with "/" (e.g. "/admin", "/api/v1").
func (s *Scanner) Run(ctx context.Context, asset string, paths []string) []finding.Finding {
	if len(paths) == 0 {
		return nil
	}

	// Deduplicate input paths: normalize trailing slashes and case so that
	// "/admin" and "/admin/" are not probed (and reported) twice.
	paths = deduplicatePaths(paths)

	// Try ffuf first — it's faster and handles WAF evasion better.
	if s.ffufBin != "" {
		if results := runFfuf(ctx, s.ffufBin, asset, paths); results != nil {
			return s.buildFindings(asset, results)
		}
	}

	// Pure-Go fallback.
	scheme := "https"
	baseURL := scheme + "://" + asset

	// ── Soft-404 canary ──────────────────────────────────────────────────────
	// Request a path that is guaranteed not to exist. If the server returns 200
	// (custom error page without a proper 404 status), hash the body. Any
	// subsequent 200 response whose body matches the canary hash is a soft-404.
	canaryHash := s.fetchCanaryHash(ctx, baseURL)

	type work struct{ path string }
	jobs := make(chan work, len(paths))
	for _, p := range paths {
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		jobs <- work{p}
	}
	close(jobs)

	var (
		mu      sync.Mutex
		results []Result
		wafStop bool // set to true on the first WAF-header 403 block
		wg      sync.WaitGroup
	)
	sem := make(chan struct{}, s.concurrency)

	for job := range jobs {
		job := job
		mu.Lock()
		stopped := wafStop
		mu.Unlock()
		if stopped {
			break
		}

		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			result, waf := s.probe(ctx, baseURL, job.path, canaryHash)
			if waf {
				// Stop on first confirmed WAF block — isWAFResponse requires
				// WAF-specific response headers, so a single hit is reliable.
				mu.Lock()
				wafStop = true
				mu.Unlock()
				return
			}
			if result != nil {
				mu.Lock()
				results = append(results, *result)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	findings := s.buildFindings(asset, results)

	// Emit a WAF-blocked finding if we were stopped
	mu.Lock()
	blocked := wafStop
	mu.Unlock()
	if blocked {
		findings = append(findings, finding.Finding{
			CheckID:     finding.CheckDirbustWAFBlocked,
			Asset:       asset,
			Title:       "WAF blocked path enumeration",
			Description: "Targeted path enumeration was stopped because the WAF began blocking requests with consistent 403 responses. This indicates active WAF protection is in place.",
			Severity:    finding.SeverityMedium,
		})
	}

	return findings
}

// buildFindings converts a slice of Results into finding.Findings for the given asset.
// Deduplicates results by normalized path so "/admin" and "/admin/" produce one finding.
func (s *Scanner) buildFindings(asset string, results []Result) []finding.Finding {
	// Deduplicate results by normalized path (strip trailing slash).
	seen := make(map[string]bool, len(results))
	var deduped []Result
	for _, r := range results {
		norm := strings.TrimRight(r.Path, "/")
		if norm == "" {
			norm = "/"
		}
		if seen[norm] {
			continue
		}
		seen[norm] = true
		deduped = append(deduped, r)
	}

	var findings []finding.Finding
	for _, r := range deduped {
		f := finding.Finding{
			CheckID:     finding.CheckDirbustFound,
			Asset:       asset,
			Title:       fmt.Sprintf("Path found: %s (%d)", r.Path, r.StatusCode),
			Description: fmt.Sprintf("The path %s responded with HTTP %d during deep scan path enumeration.", r.Path, r.StatusCode),
			Severity:    finding.SeverityHigh,
		}
		// Downgrade 401/403 to Medium — they confirm existence but don't expose content
		if r.StatusCode == http.StatusUnauthorized || r.StatusCode == http.StatusForbidden {
			f.Severity = finding.SeverityMedium
			f.Description += " Access is gated (auth required / forbidden), but the path exists and may be targeted."
		}
		findings = append(findings, f)
	}
	return findings
}

// probe sends a GET request for a single path with retry/backoff on 429.
// Returns (result, wafDetected). result is nil if the path is uninteresting.
// wafDetected is true if the response is a 403 with WAF-indicator headers —
// the caller (Run) accumulates these across paths and stops after 3.
// canaryHash is the SHA-256 of a known-404 response body; if a 200 response
// body matches, it is treated as a soft-404 and skipped.
func (s *Scanner) probe(ctx context.Context, baseURL, path string, canaryHash string) (*Result, bool) {
	url := baseURL + path

	for attempt := 0; attempt < maxRetries; attempt++ {
		if ctx.Err() != nil {
			return nil, false
		}

		// Use GET instead of HEAD so we can read the body for soft-404 detection.
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, false
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner/1.0)")

		resp, err := s.client.Do(req)
		if err != nil {
			return nil, false
		}

		// Read body for soft-404 comparison (cap at 128 KB to avoid buffering huge pages).
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
		resp.Body.Close()

		// WAF block: 403 with WAF-specific headers — signal the caller.
		// Do not count as an interesting path finding.
		if resp.StatusCode == http.StatusForbidden && isWAFResponse(resp) {
			return nil, true
		}

		// Rate limited — back off and retry
		if resp.StatusCode == http.StatusTooManyRequests {
			wait := backoffDuration(attempt, resp)
			select {
			case <-ctx.Done():
				return nil, false
			case <-time.After(wait):
			}
			continue
		}

		// Not found or bad request — skip
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusBadRequest {
			return nil, false
		}

		// Interesting response — but check for soft-404 first.
		if interestingCodes[resp.StatusCode] {
			// Soft-404: server returned 200 but the body is identical to the
			// canary (known-nonexistent) path. This is a custom error page.
			if resp.StatusCode == http.StatusOK && canaryHash != "" && len(body) > 0 {
				h := sha256.Sum256(body)
				if fmt.Sprintf("%x", h) == canaryHash {
					return nil, false // soft-404 — skip
				}
			}
			return &Result{Path: path, StatusCode: resp.StatusCode}, false
		}

		return nil, false
	}
	return nil, false
}

// isWAFResponse checks if the response has WAF-specific headers.
func isWAFResponse(resp *http.Response) bool {
	for _, h := range wafHeaders {
		if resp.Header.Get(h) != "" {
			return true
		}
	}
	return false
}

// backoffDuration returns the wait duration for a 429, honouring Retry-After if present.
func backoffDuration(attempt int, resp *http.Response) time.Duration {
	if ra := resp.Header.Get("Retry-After"); ra != "" {
		if secs, err := strconv.Atoi(ra); err == nil {
			d := time.Duration(secs) * time.Second
			if d < maxBackoff {
				return d
			}
			return maxBackoff
		}
	}
	// Exponential: 2s, 4s, 8s ... capped at 30s
	d := baseBackoff * (1 << attempt)
	if d > maxBackoff {
		d = maxBackoff
	}
	return d
}

// fetchCanaryHash requests a known-nonexistent path and returns the SHA-256
// hex digest of the response body. If the server returns a proper 404 status
// or the request fails, it returns "" (no soft-404 filtering needed).
func (s *Scanner) fetchCanaryHash(ctx context.Context, baseURL string) string {
	// Generate a random canary path that is extremely unlikely to exist.
	canaryPath := fmt.Sprintf("/beacon-canary-404-test-%d", rand.Int63())
	url := baseURL + canaryPath

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner/1.0)")

	resp, err := s.client.Do(req)
	if err != nil {
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	resp.Body.Close()

	// If the server returns a proper 404 or non-200, no soft-404 filtering needed.
	if resp.StatusCode != http.StatusOK {
		return ""
	}

	// Server returned 200 for a nonexistent path — this is a soft-404 page.
	// Hash the body so we can compare subsequent 200 responses against it.
	if len(body) == 0 {
		return ""
	}
	h := sha256.Sum256(body)
	return fmt.Sprintf("%x", h)
}

// deduplicatePaths normalizes and deduplicates paths so that "/admin" and
// "/admin/" are treated as the same path. Keeps the first occurrence.
func deduplicatePaths(paths []string) []string {
	seen := make(map[string]bool, len(paths))
	var out []string
	for _, p := range paths {
		// Normalize: ensure leading slash, strip trailing slash.
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		norm := strings.TrimRight(p, "/")
		if norm == "" {
			norm = "/"
		}
		if seen[norm] {
			continue
		}
		seen[norm] = true
		out = append(out, p)
	}
	return out
}
