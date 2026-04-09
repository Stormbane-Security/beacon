// Package jsendpoints extracts API endpoint URLs, internal hostnames, and
// undocumented paths from JavaScript bundles served by web applications.
//
// Modern SPAs (React, Vue, Angular) and webpack/vite bundles embed API
// endpoint URLs as string literals. Extracting these reveals:
//   - Internal/staging API endpoints not in robots.txt or sitemap
//   - Admin/debug paths hardcoded in frontend code
//   - Internal hostnames and IP addresses
//   - API keys and tokens (already covered by webcontent, but paths are not)//
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
	"github.com/stormbane-security/beacon/internal/scan"
	"github.com/stormbane-security/beacon/internal/scanner/authctx"
	"github.com/stormbane-security/beacon/internal/scanner/paramdiscovery"
	"github.com/stormbane-security/beacon/internal/scanner/schemedetect"
)

func init() {
	scan.RegisterWithCheckDecls(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	},
		scan.Check(finding.CheckJSInternalEndpoint, finding.SeverityMedium, finding.ModeSurface),
		scan.Check(finding.CheckJSAPIEndpointDiscovered, finding.SeverityInfo, finding.ModeSurface),
		scan.Check(finding.CheckJSHardcodedSecret, finding.SeverityCritical, finding.ModeSurface),
		scan.Check(finding.CheckJSInternalURLLeaked, finding.SeverityMedium, finding.ModeSurface),
		scan.Check(finding.CheckJSSourceMapExposed, finding.SeverityHigh, finding.ModeSurface),
		scan.Check(finding.CheckJSWebSocketEndpoint, finding.SeverityInfo, finding.ModeSurface),
	)
}

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

	// Step 2: Download and scan each JS file for endpoints (legacy) and deep
	// bundle analysis (new).
	allEndpoints := make(map[string]bool)
	var internalIPs []string
	merged := &BundleFindings{}

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
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024)) // 5MB max per JS file
		_ = resp.Body.Close()

		if resp.StatusCode != 200 {
			continue
		}

		bodyStr := string(body)

		// Legacy endpoint extraction.
		for _, re := range endpointPatterns {
			matches := re.FindAllString(bodyStr, 50)
			for _, m := range matches {
				ep := strings.Trim(m, `"'`)
				allEndpoints[ep] = true
			}
		}

		// Legacy private IP extraction.
		ips := privateIPPattern.FindAllString(bodyStr, 20)
		for _, ip := range ips {
			allEndpoints[ip] = true
			internalIPs = append(internalIPs, ip)
		}

		// Deep bundle analysis.
		bf := ParseBundle(bodyStr, jsURL)
		merged.Merge(bf)
	}

	var findings []finding.Finding

	// Legacy finding: internal endpoints (preserved for backward compatibility).
	if len(allEndpoints) > 0 {
		var endpoints []string
		for ep := range allEndpoints {
			endpoints = append(endpoints, ep)
		}
		findings = append(findings, finding.Finding{
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
		})
	}

	// New finding: API endpoints from deep bundle analysis.
	if len(merged.APIEndpoints) > 0 {
		epList := make([]map[string]string, 0, len(merged.APIEndpoints))
		for _, ep := range merged.APIEndpoints {
			epList = append(epList, map[string]string{
				"method": ep.Method,
				"path":   ep.Path,
				"source": ep.Source,
			})
		}
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckJSAPIEndpointDiscovered,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityInfo,
			Title:    fmt.Sprintf("JS bundles contain %d API endpoint references", len(merged.APIEndpoints)),
			Description: fmt.Sprintf(
				"Deep analysis of JavaScript bundles on %s extracted %d API endpoint URLs "+
					"from fetch(), axios, XMLHttpRequest, jQuery AJAX, and GraphQL patterns. "+
					"These endpoints should be tested for authentication bypass and injection vulnerabilities.",
				asset, len(merged.APIEndpoints)),
			Asset: asset,
			ProofCommand: fmt.Sprintf(
				"curl -s '%s' | grep -oE 'fetch\\(\"[^\"]+\"' | head -20", base+"/"),
			Evidence: map[string]any{
				"api_endpoints": epList,
				"count":         len(merged.APIEndpoints),
				"js_files":      len(jsURLs),
			},
			DiscoveredAt: time.Now(),
		})

		// Feed discovered API endpoints into paramdiscovery context so
		// downstream scanners (SQLi, XSS, IDOR) can probe them.
		feedDiscoveredEndpoints(ctx, merged.APIEndpoints)
	}

	// New finding: hardcoded secrets.
	if len(merged.HardcodedSecrets) > 0 {
		secretList := make([]map[string]string, 0, len(merged.HardcodedSecrets))
		for _, s := range merged.HardcodedSecrets {
			secretList = append(secretList, map[string]string{
				"type":  s.Type,
				"value": s.Value,
			})
		}
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckJSHardcodedSecret,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityCritical,
			Title:    fmt.Sprintf("JS bundles contain %d hardcoded secrets", len(merged.HardcodedSecrets)),
			Description: fmt.Sprintf(
				"JavaScript bundles on %s contain hardcoded API keys, tokens, or credentials. "+
					"These secrets are accessible to anyone who views the page source and should "+
					"be immediately rotated.",
				asset),
			Asset: asset,
			ProofCommand: fmt.Sprintf(
				"curl -s '%s' | grep -oE 'AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+'", base+"/"),
			Evidence: map[string]any{
				"secrets": secretList,
				"count":   len(merged.HardcodedSecrets),
			},
			DiscoveredAt: time.Now(),
		})
	}

	// New finding: internal/staging URLs.
	if len(merged.InternalURLs) > 0 {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckJSInternalURLLeaked,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityMedium,
			Title:    fmt.Sprintf("JS bundles leak %d internal/staging URLs", len(merged.InternalURLs)),
			Description: fmt.Sprintf(
				"JavaScript bundles on %s contain URLs pointing to internal, staging, or "+
					"development servers (localhost, RFC1918, .internal, .local, .dev domains). "+
					"These reveal internal infrastructure topology and may be directly accessible.",
				asset),
			Asset: asset,
			ProofCommand: fmt.Sprintf(
				"curl -s '%s' | grep -oE 'https?://(localhost|127\\.0\\.0\\.1|10\\.|192\\.168\\.)[^\"'\\s]*'", base+"/"),
			Evidence: map[string]any{
				"internal_urls": merged.InternalURLs,
				"count":         len(merged.InternalURLs),
			},
			DiscoveredAt: time.Now(),
		})
	}

	// New finding: source maps exposed.
	if len(merged.SourceMaps) > 0 {
		// Check if source maps are actually accessible.
		accessibleMaps := checkSourceMapAccess(ctx, client, base, jsURLs, merged.SourceMaps)
		if len(accessibleMaps) > 0 {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckJSSourceMapExposed,
				Module:   "surface",
				Scanner:  scannerName,
				Severity: finding.SeverityHigh,
				Title:    fmt.Sprintf("%d source maps accessible — full source code exposed", len(accessibleMaps)),
				Description: fmt.Sprintf(
					"JavaScript bundles on %s reference source maps that are publicly accessible. "+
						"Source maps contain the original unminified source code, including comments, "+
						"variable names, and potentially sensitive logic or credentials.",
					asset),
				Asset: asset,
				ProofCommand: fmt.Sprintf(
					"curl -sI '%s'", accessibleMaps[0]),
				Evidence: map[string]any{
					"source_maps": accessibleMaps,
					"count":       len(accessibleMaps),
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	// New finding: WebSocket endpoints.
	if len(merged.WebSockets) > 0 {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckJSWebSocketEndpoint,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityInfo,
			Title:    fmt.Sprintf("JS bundles reference %d WebSocket endpoints", len(merged.WebSockets)),
			Description: fmt.Sprintf(
				"JavaScript bundles on %s contain WebSocket endpoint URLs. WebSocket connections "+
					"often bypass traditional web security controls and should be tested for "+
					"authentication, authorization, and injection vulnerabilities.",
				asset),
			Asset: asset,
			ProofCommand: fmt.Sprintf(
				"curl -s '%s' | grep -oE 'wss?://[^\"'\\s]+'", base+"/"),
			Evidence: map[string]any{
				"websockets": merged.WebSockets,
				"count":      len(merged.WebSockets),
			},
			DiscoveredAt: time.Now(),
		})
	}

	return findings, nil
}

// feedDiscoveredEndpoints pushes extracted API endpoints into the
// paramdiscovery context so injection scanners can target them.
func feedDiscoveredEndpoints(ctx context.Context, endpoints []APIEndpoint) {
	existing := paramdiscovery.DiscoveredParamsFromContext(ctx)
	if existing == nil {
		// Context is immutable here — callers that want to propagate these
		// endpoints should read them from finding evidence. The scan
		// orchestrator handles cross-scanner data flow.
		return
	}
	// If there's already a param map, add endpoint paths as keys so
	// downstream scanners know to probe them.
	for _, ep := range endpoints {
		u, err := url.Parse(ep.Path)
		if err != nil {
			continue
		}
		path := u.Path
		if path == "" {
			path = ep.Path
		}
		if _, ok := existing[path]; !ok {
			existing[path] = nil // mark path for probing, no params known yet
		}
	}
}

// checkSourceMapAccess verifies whether referenced source maps are actually
// downloadable. Returns the URLs of accessible maps.
func checkSourceMapAccess(ctx context.Context, client *http.Client, base string, jsURLs []string, maps []string) []string {
	var accessible []string
	for _, sm := range maps {
		if ctx.Err() != nil {
			break
		}
		// Resolve relative source map URLs against the JS file URL or base.
		smURL := sm
		if !strings.HasPrefix(sm, "http") {
			// Try to resolve against base URL.
			if strings.HasPrefix(sm, "/") {
				smURL = base + sm
			} else {
				// Relative to the JS file — use base as fallback.
				smURL = base + "/" + sm
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, smURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner)")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode == 200 {
			accessible = append(accessible, smURL)
		}
	}
	return accessible
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
			_ = resp.Body.Close()

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
		_ = resp.Body.Close()
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
