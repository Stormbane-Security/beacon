// Package cacheprobe detects CDN/reverse-proxy caching behavior and tests for
// cache poisoning vulnerabilities by discovering unkeyed headers that are
// reflected in cached responses.
//
// Techniques:
//
//  1. Cache behavior fingerprinting: X-Cache, CF-Cache-Status, Age, Vary headers
//     reveal what the CDN caches, which headers are part of the cache key, and
//     how long content is cached.
//
//  2. Unkeyed header discovery (deep mode): Sends requests with unique values in
//     headers that CDNs commonly ignore for cache key computation (X-Forwarded-Host,
//     X-Original-URL, X-Rewrite-URL). If the injected value appears in the cached
//     response body, the header is unkeyed — enabling cache poisoning.
//
//  3. Cache deception detection (deep mode): Tests whether the CDN caches responses
//     to paths with static file extensions appended to dynamic endpoints
//     (e.g., /account.css). If the CDN caches a personalized page under a guessable
//     URL, other users can retrieve it.
//
//  4. PURGE method testing: Checks if the CDN accepts unauthenticated PURGE
//     requests, which allows an attacker to evict cached content at will.
//
//  5. Host header routing: Tests whether different Host header values route to
//     different backend applications — revealing multi-tenant or internal services.
//
// Surface mode: passive cache header analysis only.
// Deep mode: active cache poisoning and deception probes.
package cacheprobe

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/scan"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)


func init() {
	scan.RegisterWithCheckDecls(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	},
		scan.Check(finding.CheckCacheBehaviorDetected, finding.SeverityInfo, finding.ModeSurface),
		scan.Check(finding.CheckCacheDeception, finding.SeverityHigh, finding.ModeDeep),
		scan.Check(finding.CheckCacheHostRouting, finding.SeverityMedium, finding.ModeDeep),
		scan.Check(finding.CheckCachePoisonUnkeyed, finding.SeverityHigh, finding.ModeDeep),
		scan.Check(finding.CheckCachePurgeEnabled, finding.SeverityMedium, finding.ModeSurface),
		scan.Check(finding.CheckCacheVaryRisky, finding.SeverityLow, finding.ModeSurface),
	)
}
const scannerName = "cacheprobe"

// unkeyedHeaders are headers that CDNs commonly exclude from the cache key.
// If the response body reflects content from these headers, the cache can be
// poisoned by injecting malicious values that get served to other users.
var unkeyedHeaders = []struct {
	name    string
	value   string // injected value to detect in response
	context string // what this header is used for
}{
	{"X-Forwarded-Host", "beacon-cache-probe-%s.example.com", "proxy host routing"},
	{"X-Host", "beacon-cache-probe-%s.example.com", "proxy host override"},
	{"X-Original-URL", "/beacon-cache-probe-%s", "URL rewriting (IIS/nginx)"},
	{"X-Rewrite-URL", "/beacon-cache-probe-%s", "URL rewriting"},
	{"X-Forwarded-Scheme", "nothttps", "protocol override"},
	{"X-Forwarded-Proto", "nothttps", "protocol override"},
	{"X-Forwarded-Port", "1337", "port override"},
}

// cacheDeceptionExtensions are static file extensions that CDNs commonly cache.
// Appending these to dynamic paths can trick CDNs into caching personalized content.
var cacheDeceptionExtensions = []string{
	".css", ".js", ".png", ".jpg", ".gif", ".ico", ".svg",
}

// Scanner detects CDN caching behavior and cache poisoning vectors.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}

	scheme := detectScheme(ctx, client, asset)
	if scheme == "" {
		return nil, nil
	}

	var findings []finding.Finding

	// 1. Cache behavior fingerprint (surface mode)
	cacheInfo := fingerprintCache(ctx, client, scheme, asset)
	if cacheInfo != nil {
		findings = append(findings, *cacheInfo)
	}

	// 2. PURGE method test (surface mode — single probe)
	if purge := testPurge(ctx, client, scheme, asset); purge != nil {
		findings = append(findings, *purge)
	}

	// 3. Vary header analysis — what's in the cache key
	if vary := analyzeVary(ctx, client, scheme, asset); vary != nil {
		findings = append(findings, *vary)
	}

	// Deep mode: active cache poisoning tests
	if scanType == module.ScanDeep || scanType == module.ScanAuthorized {
		// 4. Unkeyed header discovery
		for _, uh := range unkeyedHeaders {
			if ctx.Err() != nil {
				break
			}
			if f := testUnkeyedHeader(ctx, client, scheme, asset, uh.name, uh.value, uh.context); f != nil {
				findings = append(findings, *f)
			}
		}

		// 5. Cache deception
		if f := testCacheDeception(ctx, client, scheme, asset); f != nil {
			findings = append(findings, *f)
		}

		// 6. Host header backend routing
		if f := testHostRouting(ctx, client, scheme, asset); f != nil {
			findings = append(findings, *f)
		}
	}

	return findings, nil
}

// fingerprintCache detects caching infrastructure from response headers.
func fingerprintCache(ctx context.Context, client *http.Client, scheme, asset string) *finding.Finding {
	// Two requests to detect caching (first populates, second may HIT)
	var cacheHeaders map[string]string
	for i := 0; i < 2; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+asset+"/", nil)
		if err != nil {
			return nil
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon Security Scanner)")

		resp, err := client.Do(req)
		if err != nil {
			return nil
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()

		if i == 1 {
			cacheHeaders = extractCacheHeaders(resp)
		}
	}

	if len(cacheHeaders) == 0 {
		return nil
	}

	// Identify CDN/cache vendor
	vendor := identifyCacheVendor(cacheHeaders)
	cacheable := isCacheable(cacheHeaders)

	return &finding.Finding{
		CheckID:  finding.CheckCacheBehaviorDetected,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityInfo,
		Asset:    asset,
		Title:    fmt.Sprintf("Cache layer detected: %s at %s", vendor, asset),
		Description: fmt.Sprintf(
			"HTTP caching infrastructure detected at %s (vendor: %s, cacheable: %v). "+
				"Cache behavior headers: %v. Understanding the cache layer is important "+
				"for identifying cache poisoning and cache deception attack vectors.",
			asset, vendor, cacheable, cacheHeaders),
		Evidence: map[string]any{
			"vendor":        vendor,
			"cacheable":     cacheable,
			"cache_headers": cacheHeaders,
		},
		ProofCommand: fmt.Sprintf("curl -sI %s://%s/ | grep -iE '(x-cache|age|cf-cache|vary|cache-control)'", scheme, asset),
		DiscoveredAt: time.Now(),
	}
}

// extractCacheHeaders pulls cache-related headers from the response.
func extractCacheHeaders(resp *http.Response) map[string]string {
	interesting := []string{
		"X-Cache", "X-Cache-Hits", "Age", "CF-Cache-Status",
		"X-Varnish", "X-Served-By", "Cache-Control", "Vary",
		"X-Cache-Status", "CDN-Cache-Control", "Surrogate-Control",
		"X-Fastly-Request-ID", "X-Amz-Cf-Pop", "X-Edge-IP",
	}

	out := make(map[string]string)
	for _, name := range interesting {
		if val := resp.Header.Get(name); val != "" {
			out[strings.ToLower(name)] = val
		}
	}
	return out
}

// identifyCacheVendor identifies the CDN/cache vendor from headers.
func identifyCacheVendor(headers map[string]string) string {
	if _, ok := headers["cf-cache-status"]; ok {
		return "Cloudflare"
	}
	if v, ok := headers["x-cache"]; ok {
		lv := strings.ToLower(v)
		switch {
		case strings.Contains(lv, "cloudfront"):
			return "CloudFront"
		case strings.Contains(lv, "varnish"):
			return "Varnish"
		case strings.Contains(lv, "fastly"):
			return "Fastly"
		}
	}
	if _, ok := headers["x-varnish"]; ok {
		return "Varnish"
	}
	if _, ok := headers["x-fastly-request-id"]; ok {
		return "Fastly"
	}
	if _, ok := headers["x-amz-cf-pop"]; ok {
		return "CloudFront"
	}
	if _, ok := headers["x-edge-ip"]; ok {
		return "Edgecast/Verizon"
	}
	if _, ok := headers["x-cache-status"]; ok {
		return "nginx/proxy_cache"
	}
	if _, ok := headers["age"]; ok {
		return "Unknown Cache"
	}
	return "Unknown"
}

// isCacheable checks if Cache-Control indicates the response is cacheable.
func isCacheable(headers map[string]string) bool {
	cc, ok := headers["cache-control"]
	if !ok {
		// No Cache-Control with Age or X-Cache present means caching is happening
		if _, hasAge := headers["age"]; hasAge {
			return true
		}
		if xc, hasXC := headers["x-cache"]; hasXC {
			return strings.Contains(strings.ToLower(xc), "hit")
		}
		return false
	}
	lc := strings.ToLower(cc)
	if strings.Contains(lc, "no-store") || strings.Contains(lc, "no-cache") || strings.Contains(lc, "private") {
		return false
	}
	return true
}

// testPurge checks if the CDN accepts unauthenticated PURGE requests.
func testPurge(ctx context.Context, client *http.Client, scheme, asset string) *finding.Finding {
	req, err := http.NewRequestWithContext(ctx, "PURGE", scheme+"://"+asset+"/", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon Security Scanner)")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()

	// Successful PURGE (200, 204) without authentication = vulnerability
	if resp.StatusCode == 200 || resp.StatusCode == 204 {
		bodyStr := strings.ToLower(string(body))
		// Confirm it's actually a PURGE response, not just a 200 to any method
		if strings.Contains(bodyStr, "purge") || strings.Contains(bodyStr, "cache") ||
			strings.Contains(bodyStr, "ok") || resp.StatusCode == 204 {
			return &finding.Finding{
				CheckID:  finding.CheckCachePurgeEnabled,
				Module:   "surface",
				Scanner:  scannerName,
				Severity: finding.SeverityMedium,
				Asset:    asset,
				Title:    fmt.Sprintf("Unauthenticated cache PURGE accepted at %s", asset),
				Description: fmt.Sprintf(
					"The cache/CDN at %s accepts HTTP PURGE requests without authentication. "+
						"An attacker can evict any cached content, forcing the origin server to "+
						"regenerate responses — enabling DoS amplification against the origin "+
						"and cache poisoning when combined with concurrent race-condition requests. "+
						"Fix: restrict PURGE to authorized IPs or require authentication.",
					asset),
				Evidence: map[string]any{
					"status_code": resp.StatusCode,
					"response":    string(body),
				},
				ProofCommand: fmt.Sprintf("curl -sk -X PURGE %s://%s/", scheme, asset),
				DiscoveredAt: time.Now(),
			}
		}
	}

	return nil
}

// analyzeVary checks the Vary header for weak cache key configurations.
func analyzeVary(ctx context.Context, client *http.Client, scheme, asset string) *finding.Finding {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+asset+"/", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon Security Scanner)")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck
	_ = resp.Body.Close()

	vary := resp.Header.Get("Vary")
	if vary == "" || vary == "*" {
		return nil
	}

	// Check for dangerous Vary configurations
	// If Vary includes headers that attackers control but CDNs don't key on,
	// it creates cache fragmentation that can be exploited
	varyParts := strings.Split(strings.ToLower(vary), ",")
	var risky []string
	for _, part := range varyParts {
		part = strings.TrimSpace(part)
		switch part {
		case "x-forwarded-host", "x-host", "x-original-url", "x-rewrite-url",
			"x-forwarded-scheme", "x-forwarded-proto", "x-forwarded-port":
			risky = append(risky, part)
		}
	}

	if len(risky) > 0 {
		return &finding.Finding{
			CheckID:  finding.CheckCacheVaryRisky,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityLow,
			Asset:    asset,
			Title:    fmt.Sprintf("Cache Vary header includes attacker-controllable headers at %s", asset),
			Description: fmt.Sprintf(
				"The Vary response header at %s includes %s. These headers are "+
					"attacker-controllable and may not be included in the CDN's cache key, "+
					"creating potential for cache poisoning or cache fragmentation attacks. "+
					"If the CDN caches responses per-Vary-value without rate limiting, an attacker "+
					"can pollute the cache with arbitrary header values.",
				asset, strings.Join(risky, ", ")),
			Evidence: map[string]any{
				"vary":          vary,
				"risky_headers": risky,
			},
			DiscoveredAt: time.Now(),
		}
	}

	return nil
}

// testUnkeyedHeader tests whether a specific header is excluded from the cache key
// by injecting a unique value and checking if it appears in a subsequently cached response.
func testUnkeyedHeader(ctx context.Context, client *http.Client, scheme, asset, headerName, valueTmpl, headerContext string) *finding.Finding {
	// Generate a unique marker per test
	marker := fmt.Sprintf(valueTmpl, randomHex(8))

	// Use a unique query parameter as cache buster so we test a fresh cache entry
	cacheBuster := fmt.Sprintf("_bcb=%s", randomHex(6))
	baseURL := fmt.Sprintf("%s://%s/?%s", scheme, asset, cacheBuster)

	// Step 1: Send poisoning request with the unkeyed header
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon Security Scanner)")
	req.Header.Set(headerName, marker)

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	poisonBody, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	_ = resp.Body.Close()

	// Check if the marker appears in the response body (even in the poisoning request)
	if !strings.Contains(string(poisonBody), marker) {
		return nil
	}

	// Step 2: Send a clean request without the header to see if cached response reflects marker
	time.Sleep(500 * time.Millisecond) // give the cache time to store

	req2, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
	if err != nil {
		return nil
	}
	req2.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon Security Scanner)")

	resp2, err := client.Do(req2)
	if err != nil {
		return nil
	}
	cleanBody, _ := io.ReadAll(io.LimitReader(resp2.Body, 128*1024))
	_ = resp2.Body.Close()

	// If marker STILL appears in the clean response → the cache served the poisoned version
	if strings.Contains(string(cleanBody), marker) {
		return &finding.Finding{
			CheckID:  finding.CheckCachePoisonUnkeyed,
			Module:   "deep",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Asset:    asset,
			Title:    fmt.Sprintf("Cache poisoning via unkeyed %s header at %s", headerName, asset),
			Description: fmt.Sprintf(
				"The CDN/cache at %s does not include the %s header in its cache key, "+
					"but the application reflects values from this header in the response body. "+
					"An attacker can inject malicious content (e.g., JavaScript) via this header "+
					"and have it cached and served to all subsequent visitors. "+
					"Header context: %s. "+
					"Fix: either include this header in the cache key or stop reflecting it in responses.",
				asset, headerName, headerContext),
			Evidence: map[string]any{
				"unkeyed_header": headerName,
				"context":        headerContext,
				"marker":         marker,
			},
			ProofCommand: fmt.Sprintf(
				"curl -sH '%s: <script>alert(1)</script>' '%s://%s/?cachebuster=test' && sleep 1 && curl -s '%s://%s/?cachebuster=test' | grep alert",
				headerName, scheme, asset, scheme, asset),
			DiscoveredAt: time.Now(),
		}
	}

	return nil
}

// testCacheDeception checks if the CDN caches dynamic pages when a static
// file extension is appended to the URL path.
func testCacheDeception(ctx context.Context, client *http.Client, scheme, asset string) *finding.Finding {
	// First, get the normal page to establish baseline
	baseURL := scheme + "://" + asset + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon Security Scanner)")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	baseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	_ = resp.Body.Close()
	baseCC := resp.Header.Get("Cache-Control")

	// If the base response is already publicly cacheable (no no-store/private),
	// cache deception isn't interesting — the content is cached regardless.
	// We only care when the base is NOT cacheable but adding an extension makes it so.
	if !strings.Contains(strings.ToLower(baseCC), "no-store") &&
		!strings.Contains(strings.ToLower(baseCC), "private") {
		return nil
	}

	for _, ext := range cacheDeceptionExtensions {
		if ctx.Err() != nil {
			break
		}

		// Append static extension to the root path
		deceptURL := fmt.Sprintf("%s://%s/beacon-probe%s%s", scheme, asset, randomHex(4), ext)
		req2, err := http.NewRequestWithContext(ctx, http.MethodGet, deceptURL, nil)
		if err != nil {
			continue
		}
		req2.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon Security Scanner)")

		resp2, err := client.Do(req2)
		if err != nil {
			continue
		}
		deceptBody, _ := io.ReadAll(io.LimitReader(resp2.Body, 64*1024))
		_ = resp2.Body.Close()

		// If the deceptive URL returns the same content as the base page
		// AND has different caching headers (cacheable), it's a cache deception vuln
		deceptCC := resp2.Header.Get("Cache-Control")
		xCache := resp2.Header.Get("X-Cache")
		age := resp2.Header.Get("Age")

		bodyMatch := len(baseBody) > 100 && len(deceptBody) > 100 &&
			float64(len(deceptBody))/float64(len(baseBody)) > 0.8

		cacheableDecept := (!strings.Contains(strings.ToLower(deceptCC), "no-store") &&
			!strings.Contains(strings.ToLower(deceptCC), "private")) ||
			xCache != "" || age != ""

		if bodyMatch && cacheableDecept {
			return &finding.Finding{
				CheckID:  finding.CheckCacheDeception,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityHigh,
				Asset:    asset,
				Title:    fmt.Sprintf("Cache deception: dynamic content cached with %s extension at %s", ext, asset),
				Description: fmt.Sprintf(
					"The CDN/cache at %s serves the same dynamic content when a static file "+
						"extension (%s) is appended to the URL path, and the response becomes cacheable. "+
						"An attacker can trick a victim into visiting a URL like /account%s, causing "+
						"the CDN to cache the victim's personalized page. The attacker then fetches "+
						"the same URL to read the victim's data. "+
						"Fix: configure the CDN to not cache based on file extension alone, "+
						"or ensure dynamic endpoints return proper Cache-Control: no-store headers.",
					asset, ext, ext),
				Evidence: map[string]any{
					"extension":          ext,
					"base_cache_control": baseCC,
					"decept_cache_control": deceptCC,
					"base_body_len":      len(baseBody),
					"decept_body_len":    len(deceptBody),
				},
				ProofCommand: fmt.Sprintf("curl -sI '%s://%s/account.css' | grep -iE '(cache-control|x-cache|age)'", scheme, asset),
				DiscoveredAt: time.Now(),
			}
		}
	}

	return nil
}

// testHostRouting checks if different Host header values route to different backends.
func testHostRouting(ctx context.Context, client *http.Client, scheme, asset string) *finding.Finding {
	// Get baseline response with correct Host
	baseURL := scheme + "://" + asset + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon Security Scanner)")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	baseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	_ = resp.Body.Close()
	baseStatus := resp.StatusCode
	baseServer := resp.Header.Get("Server")

	// Test with alternate host headers
	testHosts := []string{
		"localhost",
		"127.0.0.1",
		"internal." + asset,
		"admin." + asset,
	}

	for _, host := range testHosts {
		if ctx.Err() != nil {
			break
		}

		req2, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
		if err != nil {
			continue
		}
		req2.Host = host
		req2.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon Security Scanner)")

		resp2, err := client.Do(req2)
		if err != nil {
			continue
		}
		altBody, _ := io.ReadAll(io.LimitReader(resp2.Body, 32*1024))
		_ = resp2.Body.Close()

		altServer := resp2.Header.Get("Server")

		// Different Server header or significantly different content = different backend
		if altServer != baseServer && altServer != "" && baseServer != "" {
			return &finding.Finding{
				CheckID:  finding.CheckCacheHostRouting,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityMedium,
				Asset:    asset,
				Title:    fmt.Sprintf("Host header routes to different backend: %s → %s at %s", host, altServer, asset),
				Description: fmt.Sprintf(
					"Sending Host: %s to %s routes to a different backend server (%s instead of %s). "+
						"This reveals that the proxy/CDN performs host-based routing to multiple backends. "+
						"An attacker may be able to access internal services or other tenants' applications "+
						"by manipulating the Host header. "+
						"Fix: validate Host header values and reject requests with unexpected hosts.",
					host, asset, altServer, baseServer),
				Evidence: map[string]any{
					"test_host":   host,
					"alt_server":  altServer,
					"base_server": baseServer,
				},
				ProofCommand: fmt.Sprintf("curl -sI -H 'Host: %s' %s://%s/ | grep -i server", host, scheme, asset),
				DiscoveredAt: time.Now(),
			}
		}

		// Significantly different content with same status
		if resp2.StatusCode == baseStatus && baseStatus == 200 &&
			len(baseBody) > 100 && len(altBody) > 100 {
			similarity := roughSimilarity(string(baseBody), string(altBody))
			if similarity < 0.3 {
				return &finding.Finding{
					CheckID:  finding.CheckCacheHostRouting,
					Module:   "deep",
					Scanner:  scannerName,
					Severity: finding.SeverityMedium,
					Asset:    asset,
					Title:    fmt.Sprintf("Host header %q routes to different application at %s", host, asset),
					Description: fmt.Sprintf(
						"Sending Host: %s to %s returns significantly different content (%.0f%% similarity). "+
							"The proxy routes different Host values to different backend applications. "+
							"This may expose internal services, admin panels, or other tenants' data.",
						host, asset, similarity*100),
					Evidence: map[string]any{
						"test_host":      host,
						"similarity_pct": int(similarity * 100),
						"base_body_len":  len(baseBody),
						"alt_body_len":   len(altBody),
					},
					DiscoveredAt: time.Now(),
				}
			}
		}
	}

	return nil
}

func roughSimilarity(a, b string) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	wordsA := strings.Fields(a)
	wordsB := strings.Fields(b)
	setA := make(map[string]struct{}, len(wordsA))
	for _, w := range wordsA {
		setA[w] = struct{}{}
	}
	setB := make(map[string]struct{}, len(wordsB))
	for _, w := range wordsB {
		setB[w] = struct{}{}
	}
	intersection := 0
	for w := range setA {
		if _, ok := setB[w]; ok {
			intersection++
		}
	}
	union := len(setA) + len(setB) - intersection
	if union == 0 {
		return 0
	}
	return float64(intersection) / float64(union)
}

func randomHex(n int) string {
	const chars = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b)
}

func detectScheme(ctx context.Context, client *http.Client, asset string) string {
	for _, scheme := range []string{"https", "http"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, scheme+"://"+asset+"/", nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		_ = resp.Body.Close()
		return scheme
	}
	return ""
}
