// Package gateway probes for exposed management interfaces and misconfigurations
// in API gateways, load balancers, CDN edges, and service mesh sidecars.
//
// Each probe targets a vendor-specific admin endpoint or debug mechanism.
// All checks run in surface mode — only GET/HEAD requests to well-known paths.
// No authentication credentials are tested or submitted.
package gateway

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const (
	scannerName = "gateway"
	maxBody     = 16 * 1024 // 16 KB — enough to identify admin UI content
)

// Scanner probes for exposed infrastructure management interfaces.
type Scanner struct{}

// New returns a new Scanner.
func New() *Scanner { return &Scanner{} }

// Name returns the stable scanner identifier.
func (s *Scanner) Name() string { return scannerName }

// Run executes all gateway/LB/CDN/mesh probes appropriate for the scan type.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	scheme := detectScheme(ctx, client, asset)
	base := scheme + "://" + asset

	var findings []finding.Finding

	// Run all probes — each returns a finding or nil.
	probes := []func() []finding.Finding{
		func() []finding.Finding { return probeKongAdmin(ctx, client, asset) },
		func() []finding.Finding { return probeHAProxyStats(ctx, client, base, asset) },
		func() []finding.Finding { return probeNginxStatus(ctx, client, base, asset) },
		func() []finding.Finding { return probeTraefikAPI(ctx, client, base, asset) },
		func() []finding.Finding { return probeEnvoyAdmin(ctx, client, base, asset) },
		func() []finding.Finding { return probeLinkerdViz(ctx, client, base, asset) },
		func() []finding.Finding { return probeVarnishDebug(ctx, client, base, asset) },
		func() []finding.Finding { return probeAkamaiDebug(ctx, client, base, asset) },
		func() []finding.Finding { return probeTykDashboard(ctx, client, base, asset) },
	}

	for _, probe := range probes {
		findings = append(findings, probe()...)
	}

	return findings, nil
}

// probeKongAdmin tries the default Kong Admin API port (8001) and common
// admin path mounts. Kong admin is often deployed on a separate port that
// gets accidentally exposed.
func probeKongAdmin(ctx context.Context, client *http.Client, asset string) []finding.Finding {
	// Strip port from asset for port override
	host := asset
	if idx := strings.LastIndex(host, ":"); idx > strings.LastIndex(host, "]") {
		host = host[:idx] // strip existing port
	}

	adminTargets := []struct {
		url  string
		desc string
	}{
		{fmt.Sprintf("http://%s:8001/", host), "port 8001 (default admin)"},
		{fmt.Sprintf("https://%s:8444/", host), "port 8444 (default admin TLS)"},
	}

	for _, target := range adminTargets {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			continue
		}

		bodyStr := string(body)
		// Kong admin root returns JSON with "version" and "tagline" fields
		if !strings.Contains(bodyStr, `"tagline"`) && !strings.Contains(bodyStr, `"version"`) &&
			!strings.Contains(bodyStr, "kong") {
			continue
		}

		return []finding.Finding{{
			CheckID:  finding.CheckGatewayKongAdminExposed,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityCritical,
			Title:    fmt.Sprintf("Kong Admin API exposed on %s (%s)", asset, target.desc),
			Description: fmt.Sprintf(
				"The Kong API gateway admin API at %s is accessible without authentication. "+
					"The Kong admin API allows full control of the gateway: creating routes, "+
					"services, plugins, and consumer credentials. An attacker can use this to "+
					"add malicious routes, disable authentication plugins, exfiltrate all "+
					"configured API keys, or redirect traffic to attacker-controlled backends.",
				target.url),
			Asset:        asset,
			ProofCommand: fmt.Sprintf("curl -s %s | jq .version", target.url),
			Evidence: map[string]any{
				"url":         target.url,
				"status_code": resp.StatusCode,
				"port":        target.desc,
			},
			DiscoveredAt: time.Now(),
		}}
	}

	return nil
}

// probeHAProxyStats checks for the HAProxy stats page which exposes backend
// server health, request rates, and sometimes allows management actions.
func probeHAProxyStats(ctx context.Context, client *http.Client, base, asset string) []finding.Finding {
	paths := []string{
		"/haproxy?stats",
		"/stats",
		"/admin?stats",
		"/:stats",
		"/haproxy-status",
	}

	for _, path := range paths {
		u := base + path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "text/html")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		resp.Body.Close()

		// Only flag on a real 200 response — redirects (3xx) often contain
		// the word "haproxy" in the redirect body without the stats being accessible.
		if resp.StatusCode != http.StatusOK {
			continue
		}

		bodyStr := string(body)
		// HAProxy stats page includes these distinctive strings
		if !strings.Contains(bodyStr, "Statistics Report") && !strings.Contains(bodyStr, "HAProxy") &&
			!strings.Contains(bodyStr, "haproxy") {
			continue
		}

		return []finding.Finding{{
			CheckID:  finding.CheckGatewayHAProxyStatsExposed,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Title:    fmt.Sprintf("HAProxy statistics page exposed on %s", asset),
			Description: fmt.Sprintf(
				"The HAProxy statistics page at %s is publicly accessible. "+
					"This page reveals all configured frontends and backends including "+
					"internal server hostnames, IP addresses, port numbers, current "+
					"connection counts, error rates, and health status. In some "+
					"configurations it also allows management actions such as disabling "+
					"backend servers.",
				u),
			Asset:        asset,
			ProofCommand: fmt.Sprintf("curl -s '%s' | grep -i haproxy", u),
			Evidence: map[string]any{
				"url":         u,
				"path":        path,
				"status_code": resp.StatusCode,
			},
			DiscoveredAt: time.Now(),
		}}
	}
	return nil
}

// probeNginxStatus checks for the nginx stub_status module endpoint which
// leaks connection counts, request rates, and active connections.
func probeNginxStatus(ctx context.Context, client *http.Client, base, asset string) []finding.Finding {
	paths := []string{
		"/nginx_status",
		"/server-status",    // Apache mod_status (same risk level)
		"/nginx-status",
		"/status",
	}

	for _, path := range paths {
		u := base + path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			continue
		}

		bodyStr := string(body)
		ct := strings.ToLower(resp.Header.Get("Content-Type"))
		// nginx stub_status has a very specific format: "Active connections:" line
		// Apache mod_status has "Total Accesses:" and "Server Version:"
		isNginxStatus := strings.Contains(bodyStr, "Active connections:") &&
			strings.Contains(bodyStr, "server accepts handled requests")
		isApacheStatus := strings.Contains(bodyStr, "Total Accesses:") ||
			strings.Contains(bodyStr, "Server Version:")
		if !isNginxStatus && !isApacheStatus {
			continue
		}
		// Ignore HTML responses (could be a catch-all)
		if strings.Contains(ct, "text/html") && !isNginxStatus && !isApacheStatus {
			continue
		}

		return []finding.Finding{{
			CheckID:  finding.CheckGatewayNginxStatusExposed,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityMedium,
			Title:    fmt.Sprintf("Web server status page exposed on %s (%s)", asset, path),
			Description: fmt.Sprintf(
				"The web server status endpoint at %s is publicly accessible. "+
					"This reveals active connection counts, request throughput, "+
					"worker states, and uptime information. The data helps attackers "+
					"profile the server load, identify optimal attack timing, "+
					"and confirm the server software version.",
				u),
			Asset:        asset,
			ProofCommand: fmt.Sprintf("curl -s '%s'", u),
			Evidence: map[string]any{
				"url":         u,
				"path":        path,
				"status_code": resp.StatusCode,
			},
			DiscoveredAt: time.Now(),
		}}
	}
	return nil
}

// probeTraefikAPI checks whether the Traefik dashboard API is accessible
// without authentication and enumerates routers/services if so.
func probeTraefikAPI(ctx context.Context, client *http.Client, base, asset string) []finding.Finding {
	u := base + "/api/rawdata"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	bodyStr := string(body)
	// Traefik /api/rawdata returns JSON with "routers" and "services" keys
	if !strings.Contains(bodyStr, `"routers"`) && !strings.Contains(bodyStr, `"services"`) {
		return nil
	}

	// Count routers to give context in the description
	routerCount := strings.Count(bodyStr, `"@`)

	return []finding.Finding{{
		CheckID:  finding.CheckGatewayTraefikAPIExposed,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Title:    fmt.Sprintf("Traefik API exposes all routes and backends on %s", asset),
		Description: fmt.Sprintf(
			"The Traefik API endpoint /api/rawdata on %s is publicly accessible and "+
				"returned the full gateway configuration (~%d entries). This reveals all "+
				"configured routers, backend service URLs, middlewares, TLS certificates, "+
				"and entrypoints — effectively a complete map of the internal service "+
				"topology. Attackers can use this to discover internal hostnames, "+
				"authentication middlewares, and unprotected backend services.",
			asset, routerCount),
		Asset:        asset,
		ProofCommand: fmt.Sprintf("curl -s '%s' | jq '.routers | keys'", u),
		Evidence: map[string]any{
			"url":          u,
			"status_code":  resp.StatusCode,
			"entry_count":  routerCount,
		},
		DiscoveredAt: time.Now(),
	}}
}

// probeEnvoyAdmin checks whether the Envoy admin interface is accessible
// and tests for the most dangerous endpoints.
func probeEnvoyAdmin(ctx context.Context, client *http.Client, base, asset string) []finding.Finding {
	u := base + "/config_dump"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	bodyStr := string(body)
	// Envoy /config_dump returns JSON with "configs" array containing bootstrap, clusters, listeners
	if !strings.Contains(bodyStr, `"@type"`) || !strings.Contains(bodyStr, "envoy") {
		return nil
	}

	return []finding.Finding{{
		CheckID:  finding.CheckGatewayEnvoyAdminExposed,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("Envoy admin /config_dump exposed on %s", asset),
		Description: fmt.Sprintf(
			"The Envoy proxy admin interface /config_dump on %s is publicly accessible. "+
				"This endpoint returns the complete Envoy configuration including all "+
				"listener definitions, cluster upstream addresses, TLS certificates and keys "+
				"(in some configurations), route rules, and filter chain configurations. "+
				"In Istio service mesh deployments this reveals the entire service-to-service "+
				"communication topology. The /quitquitquit endpoint may also be accessible, "+
				"allowing denial of service.",
			asset),
		Asset:        asset,
		ProofCommand: fmt.Sprintf("curl -s '%s' | jq '.configs[0][\"@type\"]'", u),
		Evidence: map[string]any{
			"url":         u,
			"status_code": resp.StatusCode,
		},
		DiscoveredAt: time.Now(),
	}}
}

// probeLinkerdViz checks for the Linkerd viz dashboard which exposes the
// service mesh topology, traffic metrics, and health status.
func probeLinkerdViz(ctx context.Context, client *http.Client, base, asset string) []finding.Finding {
	paths := []string{
		"/api/v1/stat",         // Linkerd viz REST stats API
		"/api/v1/top",          // Linkerd top (live traffic)
		"/api/v1/edges",        // Linkerd service mesh edge map
	}

	for _, path := range paths {
		u := base + path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			continue
		}

		bodyStr := string(body)
		if !strings.Contains(bodyStr, "linkerd") && !strings.Contains(bodyStr, "meshedPodCount") &&
			!strings.Contains(bodyStr, "dst") {
			continue
		}

		return []finding.Finding{{
			CheckID:  finding.CheckGatewayLinkerdVizExposed,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Title:    fmt.Sprintf("Linkerd viz API exposed on %s", asset),
			Description: fmt.Sprintf(
				"The Linkerd service mesh visualization API at %s is publicly accessible. "+
					"This exposes service-to-service traffic statistics, request rates, "+
					"error budgets, and the complete mesh topology. Attackers can use this "+
					"to map internal microservice communication patterns and identify "+
					"high-value targets within the cluster.",
				u),
			Asset:        asset,
			ProofCommand: fmt.Sprintf("curl -s '%s'", u),
			Evidence: map[string]any{
				"url":         u,
				"path":        path,
				"status_code": resp.StatusCode,
			},
			DiscoveredAt: time.Now(),
		}}
	}
	return nil
}

// probeVarnishDebug checks whether Varnish exposes debug information or
// accepts unauthenticated PURGE requests for cache invalidation.
func probeVarnishDebug(ctx context.Context, client *http.Client, base, asset string) []finding.Finding {
	var findings []finding.Finding

	// Check 1: Akamai-style Pragma debug (works on Varnish too)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/", nil)
	if err == nil {
		req.Header.Set("Pragma", "akamai-x-cache-on, akamai-x-check-cacheable, akamai-x-get-cache-key")
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			// Varnish/CDN debug headers appear in response
			if resp.Header.Get("X-Cache-Debug") != "" || resp.Header.Get("X-Check-Cacheable") != "" ||
				resp.Header.Get("X-Varnish-Cache") != "" {
				findings = append(findings, finding.Finding{
					CheckID:  finding.CheckGatewayVarnishDebugExposed,
					Module:   "surface",
					Scanner:  scannerName,
					Severity: finding.SeverityLow,
					Title:    fmt.Sprintf("Varnish/CDN debug headers exposed on %s", asset),
					Description: fmt.Sprintf(
						"The server at %s returns debug headers when sent a Pragma debug request. "+
							"These headers reveal whether content is cached, the cache key, "+
							"TTL values, and internal routing decisions. This information helps "+
							"attackers understand the caching strategy and craft cache poisoning attacks.",
						asset),
					Asset:        asset,
					ProofCommand: fmt.Sprintf(`curl -sI -H 'Pragma: akamai-x-cache-on' '%s/' | grep -i cache`, base),
					Evidence: map[string]any{
						"url":           base + "/",
						"debug_headers": resp.Header.Get("X-Cache-Debug"),
					},
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	// Check 2: PURGE method (cache invalidation without auth = DoS + cache poisoning)
	purgeReq, err := http.NewRequestWithContext(ctx, "PURGE", base+"/", nil)
	if err == nil {
		resp, err := client.Do(purgeReq)
		if err == nil {
			resp.Body.Close()
			// 200 or 201 on PURGE = no auth required
			if resp.StatusCode == http.StatusOK || resp.StatusCode == 201 {
				findings = append(findings, finding.Finding{
					CheckID:  finding.CheckCDNVarnishPurgeEnabled,
					Module:   "surface",
					Scanner:  scannerName,
					Severity: finding.SeverityMedium,
					Title:    fmt.Sprintf("Unauthenticated cache PURGE accepted on %s", asset),
					Description: fmt.Sprintf(
						"The server at %s accepted an unauthenticated PURGE request (HTTP %d). "+
							"This allows any attacker to invalidate cached content, forcing "+
							"expensive cache misses (denial of service against origin) and "+
							"potentially facilitating cache poisoning attacks by controlling "+
							"what content gets re-cached after purge.",
						asset, resp.StatusCode),
					Asset:        asset,
					ProofCommand: fmt.Sprintf("curl -si -X PURGE '%s/'", base),
					Evidence: map[string]any{
						"url":         base + "/",
						"status_code": resp.StatusCode,
					},
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return findings
}

// probeAkamaiDebug sends Pragma debug headers to check whether Akamai
// exposes cache-control debug information in responses.
func probeAkamaiDebug(ctx context.Context, client *http.Client, base, asset string) []finding.Finding {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Pragma", "akamai-x-cache-on, akamai-x-check-cacheable, akamai-x-get-cache-key, akamai-x-get-true-cache-key")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	resp.Body.Close()

	// Akamai returns X-Check-Cacheable and X-Cache-Key when debug is enabled
	cacheKey := resp.Header.Get("X-Cache-Key")
	checkCacheable := resp.Header.Get("X-Check-Cacheable")
	if cacheKey == "" && checkCacheable == "" {
		return nil
	}

	return []finding.Finding{{
		CheckID:  finding.CheckCDNAkamaiPragmaInfo,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityLow,
		Title:    fmt.Sprintf("Akamai CDN debug information exposed on %s", asset),
		Description: fmt.Sprintf(
			"The Akamai CDN serving %s returns debug headers in response to Pragma debug requests. "+
				"X-Check-Cacheable (%q) and X-Cache-Key (%q) reveal the internal cache key format, "+
				"caching policy, and configuration details. This information can be used to "+
				"craft cache key manipulation attacks or understand cache bypass strategies.",
			asset, checkCacheable, cacheKey),
		Asset:        asset,
		ProofCommand: fmt.Sprintf(`curl -sI -H 'Pragma: akamai-x-cache-on,akamai-x-check-cacheable,akamai-x-get-cache-key' '%s/'`, base),
		Evidence: map[string]any{
			"url":              base + "/",
			"x_check_cacheable": checkCacheable,
			"x_cache_key":      cacheKey,
		},
		DiscoveredAt: time.Now(),
	}}
}

// probeTykDashboard checks whether the Tyk API Gateway dashboard or
// management API is accessible without authentication.
func probeTykDashboard(ctx context.Context, client *http.Client, base, asset string) []finding.Finding {
	paths := []string{
		"/api/apis",          // Tyk management API — list all configured APIs
		"/api/keys",          // Tyk key management — list or create API keys
		"/hello",             // Tyk gateway health with version info
	}

	for _, path := range paths {
		u := base + path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			continue
		}

		bodyStr := string(body)
		// Tyk responses typically include "node_id" or "tyk_api_gateway" or API definition fields
		if !strings.Contains(bodyStr, "tyk") && !strings.Contains(bodyStr, "node_id") &&
			!strings.Contains(bodyStr, "api_definition") {
			continue
		}

		return []finding.Finding{{
			CheckID:  finding.CheckGatewayTykDashExposed,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Title:    fmt.Sprintf("Tyk API Gateway management API exposed on %s (%s)", asset, path),
			Description: fmt.Sprintf(
				"The Tyk API Gateway management API at %s is accessible without authentication. "+
					"This allows enumeration of all configured APIs, authentication policies, "+
					"and API keys. An attacker with access to /api/keys can create new API keys "+
					"bypassing normal access controls, or revoke existing keys causing a denial "+
					"of service.",
				u),
			Asset:        asset,
			ProofCommand: fmt.Sprintf("curl -s '%s'", u),
			Evidence: map[string]any{
				"url":         u,
				"path":        path,
				"status_code": resp.StatusCode,
			},
			DiscoveredAt: time.Now(),
		}}
	}
	return nil
}

// detectScheme tries HTTPS first, falling back to HTTP.
func detectScheme(ctx context.Context, client *http.Client, asset string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+asset, nil)
	if err != nil {
		return "http"
	}
	resp, err := client.Do(req)
	if err != nil {
		return "http"
	}
	resp.Body.Close()
	return "https"
}
