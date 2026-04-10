// Package crawler — API endpoint discovery from crawled pages.
// Combines link extraction, JS bundle parsing, sitemap/robots parsing,
// and OpenAPI/Swagger spec parsing to build a comprehensive API inventory.
package crawler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/stormbane-security/beacon/internal/scanner/jsendpoints"
)

// APIEndpoint represents an API endpoint discovered from crawled content.
type APIEndpoint struct {
	Method       string   `json:"method"`        // GET, POST, PUT, DELETE, PATCH
	Path         string   `json:"path"`          // /api/v1/users
	Params       []string `json:"params"`        // discovered parameter names
	Source       string   `json:"source"`        // "html", "js-bundle", "swagger", "sitemap", "robots", "well-known"
	AuthRequired bool     `json:"auth_required"` // true if endpoint returned 401/403
}

// DiscoverAPIs extracts API endpoints from crawled pages.
// Combines: link extraction, JS bundle parsing, sitemap parsing,
// robots.txt Disallow paths, and OpenAPI/Swagger spec parsing.
func DiscoverAPIs(ctx context.Context, client *http.Client, baseURL string, crawledURLs []string) []APIEndpoint {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}

	seen := make(map[string]struct{})
	var endpoints []APIEndpoint

	addEndpoint := func(ep APIEndpoint) {
		key := ep.Method + "|" + ep.Path
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		endpoints = append(endpoints, ep)
	}

	// 1. Extract API-like paths from crawled URLs (query params, REST patterns).
	for _, raw := range crawledURLs {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		path := u.Path
		if path == "" {
			path = "/"
		}
		// Only include API-like paths, not every HTML page.
		if isAPIPath(path) {
			var params []string
			for k := range u.Query() {
				params = append(params, k)
			}
			sort.Strings(params)
			addEndpoint(APIEndpoint{
				Method: "GET",
				Path:   path,
				Params: params,
				Source: "html",
			})
		}
	}

	// 2. Parse JS files from crawled URLs for API routes.
	for _, raw := range crawledURLs {
		if !isJSURL(raw) {
			continue
		}
		bf := jsendpoints.ParseBundleFromURL(ctx, client, raw)
		for _, ep := range bf.APIEndpoints {
			method := ep.Method
			if method == "" {
				method = "GET"
			}
			addEndpoint(APIEndpoint{
				Method: method,
				Path:   ep.Path,
				Source: "js-bundle",
			})
		}
	}

	// 3. Parse /robots.txt for Disallow paths (admin panels, APIs).
	robotsEPs := parseRobotsTxt(ctx, client, base)
	for _, ep := range robotsEPs {
		addEndpoint(ep)
	}

	// 4. Parse /sitemap.xml for all listed URLs.
	sitemapEPs := parseSitemap(ctx, client, base)
	for _, ep := range sitemapEPs {
		addEndpoint(ep)
	}

	// 5. Check OpenAPI/Swagger specs.
	swaggerEPs := parseSwaggerSpecs(ctx, client, base)
	for _, ep := range swaggerEPs {
		addEndpoint(ep)
	}

	// 6. Check /.well-known/ endpoints.
	wellKnownEPs := checkWellKnown(ctx, client, base)
	for _, ep := range wellKnownEPs {
		addEndpoint(ep)
	}

	// 7. Probe discovered endpoints for auth requirements.
	probeAuth(ctx, client, base, endpoints)

	return endpoints
}

// ── robots.txt parsing ────────────────────────────────────────────────────

var disallowRe = regexp.MustCompile(`(?i)^Disallow:\s*(\S+)`)

func parseRobotsTxt(ctx context.Context, client *http.Client, base *url.URL) []APIEndpoint {
	robotsURL := base.Scheme + "://" + base.Host + "/robots.txt"
	body, err := fetchBody(ctx, client, robotsURL, 256*1024) // 256KB max
	if err != nil {
		return nil
	}

	var endpoints []APIEndpoint
	for _, line := range strings.Split(body, "\n") {
		m := disallowRe.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		path := m[1]
		if path == "/" || path == "" {
			continue
		}
		endpoints = append(endpoints, APIEndpoint{
			Method: "GET",
			Path:   path,
			Source: "robots",
		})
	}
	return endpoints
}

// ── sitemap.xml parsing ───────────────────────────────────────────────────

var sitemapLocRe = regexp.MustCompile(`<loc>\s*(https?://[^<]+)\s*</loc>`)

func parseSitemap(ctx context.Context, client *http.Client, base *url.URL) []APIEndpoint {
	sitemapURL := base.Scheme + "://" + base.Host + "/sitemap.xml"
	body, err := fetchBody(ctx, client, sitemapURL, 1*1024*1024) // 1MB max
	if err != nil {
		return nil
	}

	var endpoints []APIEndpoint
	matches := sitemapLocRe.FindAllStringSubmatch(body, 500)
	for _, m := range matches {
		u, err := url.Parse(m[1])
		if err != nil {
			continue
		}
		// Only include same-origin paths.
		if !strings.EqualFold(u.Hostname(), base.Hostname()) {
			continue
		}
		path := u.Path
		if path == "" {
			path = "/"
		}
		endpoints = append(endpoints, APIEndpoint{
			Method: "GET",
			Path:   path,
			Source: "sitemap",
		})
	}
	return endpoints
}

// ── OpenAPI / Swagger spec parsing ────────────────────────────────────────

var swaggerPaths = []string{
	"/swagger.json",
	"/openapi.json",
	"/api-docs",
	"/api-docs/swagger.json",
	"/v1/swagger.json",
	"/v2/swagger.json",
	"/v3/api-docs",
	"/swagger/v1/swagger.json",
}

func parseSwaggerSpecs(ctx context.Context, client *http.Client, base *url.URL) []APIEndpoint {
	var endpoints []APIEndpoint

	for _, path := range swaggerPaths {
		specURL := base.Scheme + "://" + base.Host + path
		body, err := fetchBody(ctx, client, specURL, 5*1024*1024) // 5MB max
		if err != nil {
			continue
		}
		// Quick validity check — must look like JSON with paths.
		if !strings.Contains(body, "\"paths\"") {
			continue
		}

		eps := parseOpenAPISpec(body)
		endpoints = append(endpoints, eps...)
		if len(eps) > 0 {
			slog.Debug("parsed OpenAPI spec", "url", specURL, "endpoints", len(eps))
			break // found a valid spec, don't check others
		}
	}

	return endpoints
}

// parseOpenAPISpec extracts API endpoints from an OpenAPI/Swagger JSON spec.
func parseOpenAPISpec(specJSON string) []APIEndpoint {
	var spec struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal([]byte(specJSON), &spec); err != nil {
		return nil
	}

	var endpoints []APIEndpoint
	for path, methods := range spec.Paths {
		for method := range methods {
			method = strings.ToUpper(method)
			switch method {
			case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS":
				// Extract parameter names from the operation.
				var op struct {
					Parameters []struct {
						Name string `json:"name"`
					} `json:"parameters"`
				}
				if err := json.Unmarshal(methods[strings.ToLower(method)], &op); err == nil {
					var params []string
					for _, p := range op.Parameters {
						if p.Name != "" {
							params = append(params, p.Name)
						}
					}
					endpoints = append(endpoints, APIEndpoint{
						Method: method,
						Path:   path,
						Params: params,
						Source: "swagger",
					})
				} else {
					endpoints = append(endpoints, APIEndpoint{
						Method: method,
						Path:   path,
						Source: "swagger",
					})
				}
			}
		}
	}
	return endpoints
}

// ── .well-known endpoints ─────────────────────────────────────────────────

var wellKnownPaths = []string{
	"/.well-known/openid-configuration",
	"/.well-known/jwks.json",
	"/.well-known/security.txt",
	"/.well-known/assetlinks.json",
	"/.well-known/apple-app-site-association",
	"/.well-known/change-password",
}

func checkWellKnown(ctx context.Context, client *http.Client, base *url.URL) []APIEndpoint {
	var endpoints []APIEndpoint
	for _, path := range wellKnownPaths {
		checkURL := base.Scheme + "://" + base.Host + path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, checkURL, nil)
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
			endpoints = append(endpoints, APIEndpoint{
				Method: "GET",
				Path:   path,
				Source: "well-known",
			})
		}
	}
	return endpoints
}

// ── Auth probing ──────────────────────────────────────────────────────────

// probeAuth sends unauthenticated HEAD requests to discovered endpoints and
// marks those returning 401/403 as requiring authentication.
func probeAuth(ctx context.Context, client *http.Client, base *url.URL, endpoints []APIEndpoint) {
	// Only probe a sample — don't hammer the target.
	limit := 50
	if len(endpoints) < limit {
		limit = len(endpoints)
	}

	for i := 0; i < limit; i++ {
		ep := &endpoints[i]
		checkURL := base.Scheme + "://" + base.Host + ep.Path
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, checkURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner)")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		_ = resp.Body.Close()

		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			ep.AuthRequired = true
		}
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────

var apiPathRe = regexp.MustCompile(`(?i)(?:/api/|/v[0-9]+/|/graphql|/rest/|/rpc/|\.json$|\.xml$)`)

func isAPIPath(path string) bool {
	return apiPathRe.MatchString(path)
}

func isJSURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return strings.HasSuffix(strings.ToLower(u.Path), ".js")
}

func fetchBody(ctx context.Context, client *http.Client, rawURL string, maxBytes int64) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner)")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

