// Package jsendpoints extracts API endpoint URLs, internal hostnames, and
// undocumented paths from JavaScript bundles served by web applications.
//
// Modern SPAs (React, Vue, Angular) and webpack/vite bundles embed API
// endpoint URLs as string literals. Extracting these reveals:
//   - Internal/staging API endpoints not in robots.txt or sitemap
//   - Admin/debug paths hardcoded in frontend code
//   - Internal hostnames and IP addresses
//   - API keys and tokens (already covered by webcontent, but paths are not)
//
// Surface mode only — reads JavaScript files already served by the web server.
package jsendpoints

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanner/authctx"
	"github.com/stormbane-security/beacon/internal/scanner/schemedetect"
)

const scannerName = "jsendpoints"

// jsPaths — common JavaScript bundle locations.
var jsPaths = []string{
	"/static/js/main.js",
	"/static/js/app.js",
	"/static/js/bundle.js",
	"/assets/index.js",
	"/dist/app.js",
	"/build/static/js/main.js",
	"/js/app.js",
	"/app.js",
	"/_next/static/chunks/main.js",
	"/_next/static/chunks/app.js",
}

// endpointPatterns match API endpoint URLs in JavaScript source.
var endpointPatterns = []*regexp.Regexp{
	// Absolute URLs to API endpoints.
	regexp.MustCompile(`["']https?://[a-zA-Z0-9._-]+(?::\d+)?/api/[a-zA-Z0-9/_-]+["']`),
	// Relative API paths.
	regexp.MustCompile(`["']/api/v[0-9]+/[a-zA-Z0-9/_-]+["']`),
	// Internal endpoints with explicit host.
	regexp.MustCompile(`["']https?://(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)(?::\d+)?/[a-zA-Z0-9/_-]*["']`),
	// Staging/dev/internal subdomains.
	regexp.MustCompile(`["']https?://(?:staging|dev|internal|admin|api-internal|api-dev)[a-zA-Z0-9._-]*\.[a-zA-Z]+(?::\d+)?/[a-zA-Z0-9/_-]*["']`),
	// GraphQL endpoints.
	regexp.MustCompile(`["'](?:https?://[a-zA-Z0-9._-]+)?/graphql["']`),
	// Admin paths.
	regexp.MustCompile(`["']/(?:admin|dashboard|internal|manage|debug|_debug|phpinfo|actuator)/[a-zA-Z0-9/_-]*["']`),
}

// privateIPPattern matches RFC1918 addresses in JS source.
var privateIPPattern = regexp.MustCompile(`(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})`)

type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanSurface && scanType != module.ScanDeep && scanType != module.ScanAuthorized {
		return nil, nil
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if c := authctx.HTTPClient(ctx); c != nil {
		client = c
	}

	base := schemedetect.Base(ctx, client, asset)

	// Step 1: Find JavaScript files. First check the main page for script tags,
	// then probe common paths.
	jsURLs := discoverJSFiles(ctx, client, base)
	if len(jsURLs) == 0 {
		return nil, nil
	}

	// Step 2: Download and scan each JS file for endpoints.
	allEndpoints := make(map[string]bool)
	var internalIPs []string

	for _, jsURL := range jsURLs {
		if ctx.Err() != nil {
			break
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, jsURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner)")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024)) // 2MB max per JS file
		resp.Body.Close()

		if resp.StatusCode != 200 {
			continue
		}

		bodyStr := string(body)

		// Extract endpoint URLs.
		for _, re := range endpointPatterns {
			matches := re.FindAllString(bodyStr, 50)
			for _, m := range matches {
				// Strip quotes.
				ep := strings.Trim(m, `"'`)
				allEndpoints[ep] = true
			}
		}

		// Extract private IPs.
		ips := privateIPPattern.FindAllString(bodyStr, 20)
		for _, ip := range ips {
			allEndpoints[ip] = true
			internalIPs = append(internalIPs, ip)
		}
	}

	if len(allEndpoints) == 0 {
		return nil, nil
	}

	// Build a deduplicated list.
	var endpoints []string
	for ep := range allEndpoints {
		endpoints = append(endpoints, ep)
	}

	return []finding.Finding{{
		CheckID:  finding.CheckJSInternalEndpoint,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityMedium,
		Title:    fmt.Sprintf("JavaScript bundles expose %d internal/API endpoints", len(endpoints)),
		Description: fmt.Sprintf(
			"JavaScript files on %s contain hardcoded API endpoint URLs, internal hostnames, "+
				"or private IP addresses. These endpoints may include undocumented admin paths, "+
				"staging servers, or internal services not intended for public access. Each "+
				"discovered endpoint should be tested for unauthorized access.",
			asset),
		Asset: asset,
		ProofCommand: fmt.Sprintf(
			"curl -s '%s' | grep -oP '\"https?://[^\"]+/api/[^\"]+\"'", base+"/"),
		Evidence: map[string]any{
			"endpoints":    endpoints,
			"internal_ips": internalIPs,
			"js_files":     len(jsURLs),
		},
		DiscoveredAt: time.Now(),
	}}, nil
}

// discoverJSFiles finds JavaScript file URLs by parsing the main page and
// probing common bundle paths.
func discoverJSFiles(ctx context.Context, client *http.Client, base string) []string {
	var jsURLs []string
	seen := make(map[string]bool)

	// Parse main page for <script src="..."> tags.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/", nil)
	if err == nil {
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner)")
		resp, err := client.Do(req)
		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
			resp.Body.Close()

			// Simple regex to find script src attributes.
			srcRe := regexp.MustCompile(`<script[^>]+src=["']([^"']+\.js[^"']*)["']`)
			matches := srcRe.FindAllStringSubmatch(string(body), 20)
			for _, m := range matches {
				src := m[1]
				// Make absolute.
				if strings.HasPrefix(src, "//") {
					src = "https:" + src
				} else if strings.HasPrefix(src, "/") {
					src = base + src
				} else if !strings.HasPrefix(src, "http") {
					src = base + "/" + src
				}
				// Only same-origin JS.
				if u, err := url.Parse(src); err == nil {
					baseU, _ := url.Parse(base)
					if baseU != nil && u.Host == baseU.Host {
						if !seen[src] {
							seen[src] = true
							jsURLs = append(jsURLs, src)
						}
					}
				}
			}
		}
	}

	// Probe common JS bundle paths.
	for _, path := range jsPaths {
		jsURL := base + path
		if seen[jsURL] {
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, jsURL, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == 200 {
			ct := resp.Header.Get("Content-Type")
			if strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript") ||
				strings.HasSuffix(path, ".js") {
				seen[jsURL] = true
				jsURLs = append(jsURLs, jsURL)
			}
		}
	}

	return jsURLs
}
