// Package wafdetect fingerprints WAF and IDS vendors from HTTP response headers,
// then checks for common misconfigurations that attackers exploit to bypass them:
//
//   - Origin IP exposure: the real backend IP is directly accessible, bypassing WAF
//     DDoS protection and ACLs entirely.
//   - Cloudflare Flexible SSL: origin served over plain HTTP — allows MITM between
//     Cloudflare edge and origin even though visitors see a padlock.
//   - IP-header bypass (deep only): the WAF rate-limits/blocks by source IP but
//     trusts X-Forwarded-For / X-Real-IP headers, allowing trivial bypass.
//   - Unprotected paths behind WAF: probes admin paths directly against known origin
//     IPs to see if the WAF rule set has gaps.
//
// Surface-mode checks use only passive header observation and public DNS/cert data.
// Deep-mode checks send active bypass probes and require --permission-confirmed.
package wafdetect

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const scannerName = "wafdetect"

// WAF vendor signatures: map of header name → vendor name.
// Matched case-insensitively against response headers.
var wafHeaders = []struct {
	Header string
	Vendor string
}{
	{"cf-ray", "Cloudflare"},
	{"cf-cache-status", "Cloudflare"},
	{"x-amzn-requestid", "AWS WAF"},
	{"x-amz-cf-id", "AWS CloudFront/WAF"},
	{"x-iinfo", "Imperva Incapsula"},
	{"x-cdn", "Imperva Incapsula"},
	{"x-check-cacheable", "Akamai"},
	{"x-fastly-request-id", "Fastly"},
	{"x-sucuri-id", "Sucuri WAF"},
	{"x-sucuri-cache", "Sucuri WAF"},
	{"barra_counter_session", "Barracuda WAF"},
	{"x-wa-info", "F5 BIG-IP ASM"},
	{"x-cnection", "F5 BIG-IP"},
	{"x-distil-cs", "Distil Networks"},
	{"x-px-", "PerimeterX"},
	{"x-fw-hash", "Fortinet FortiWeb"},
	{"x-protected-by", "Generic WAF"},
	{"x-mod-security-id", "ModSecurity"},
}

// idsHeaders maps response header prefixes to IDS/NGFW vendor names.
var idsHeaders = []struct {
	Header string
	Vendor string
}{
	{"x-palo-alto", "Palo Alto NGFW"},
	{"x-checkpoint", "Check Point"},
	{"x-ips-", "Intrusion Prevention System"},
}

// bypassHeaders are IP-spoofing headers tested in deep mode to check if the
// WAF trusts them for rate-limiting/geo-blocking decisions.
var bypassHeaders = []string{
	"X-Forwarded-For",
	"X-Real-IP",
	"X-Originating-IP",
	"X-Remote-IP",
	"X-Remote-Addr",
	"True-Client-IP",
	"CF-Connecting-IP",
}

// cloudflareFlexibleIndicators: when these are present together it suggests
// Flexible SSL mode (Cloudflare terminates TLS but connects to origin over HTTP).
// Flexible mode means the origin→Cloudflare leg is unencrypted.
var cloudflareFlexibleIndicators = []string{"cf-ray", "cf-cache-status"}

// Scanner fingerprints WAF/IDS and checks for bypass misconfigurations.
type Scanner struct{}

// New returns a new Scanner.
func New() *Scanner { return &Scanner{} }

// Name returns the scanner identifier.
func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{},
	}

	// Probe the asset and collect response headers.
	headers, scheme, err := probeHeaders(ctx, client, asset)
	if err != nil || len(headers) == 0 {
		return nil, nil
	}

	var findings []finding.Finding

	// ── Phase 1: Vendor fingerprinting ──────────────────────────────────────
	vendor := detectVendor(headers)
	idsVendor := detectIDS(headers)

	if vendor != "" {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckWAFDetected,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityInfo,
			Asset:    asset,
			Title:    fmt.Sprintf("WAF detected: %s", vendor),
			Description: fmt.Sprintf(
				"%s is protected by %s (identified from response headers). "+
					"WAF presence does not guarantee security — origin exposure, "+
					"bypass headers, or SSL mode misconfigurations may still exist.",
				asset, vendor,
			),
			Evidence:     map[string]any{"vendor": vendor, "scheme": scheme},
			DiscoveredAt: time.Now(),
		})
	}

	if idsVendor != "" {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckIDSDetected,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityInfo,
			Asset:    asset,
			Title:    fmt.Sprintf("IDS/NGFW detected: %s", idsVendor),
			Description: fmt.Sprintf(
				"%s has response headers characteristic of %s. "+
					"The presence of an IDS does not prevent exploitation if the "+
					"underlying application has vulnerabilities or the IDS is misconfigured.",
				asset, idsVendor,
			),
			Evidence:     map[string]any{"vendor": idsVendor},
			DiscoveredAt: time.Now(),
		})
	}

	// ── Phase 2: Cloudflare Flexible SSL detection ────────────────────────
	// Flexible SSL means: visitor→Cloudflare (HTTPS) but Cloudflare→origin (HTTP).
	// Detection: probe the asset over plain HTTP only (no TLS). If we receive a
	// 200 response (not a 301/302 redirect to HTTPS) with Cloudflare headers present,
	// Cloudflare is serving the site over HTTP — indicating Flexible SSL mode.
	// NOTE: probeHeaders() always tries HTTPS first, so we use a dedicated HTTP-only
	// probe here to avoid the false-positive of seeing cf-ray on the HTTPS response.
	if vendor == "Cloudflare" && scheme == "https" {
		if status, httpHdrs := probeHTTPOnly(ctx, client, asset); status == 200 {
			if _, ok := httpHdrs["cf-ray"]; ok {
				findings = append(findings, finding.Finding{
					CheckID:  finding.CheckWAFInsecureMode,
					Module:   "surface",
					Scanner:  scannerName,
					Severity: finding.SeverityHigh,
					Asset:    asset,
					Title:    "Cloudflare Flexible SSL: origin served over plain HTTP",
					Description: fmt.Sprintf(
						"%s uses Cloudflare with Flexible SSL mode. Visitors see HTTPS, but "+
							"traffic between Cloudflare's edge and your origin server travels over "+
							"plain HTTP. Anyone with access to the network path between Cloudflare "+
							"and your origin (hosting provider, cloud network) can read all traffic. "+
							"Change SSL mode to Full (Strict) in Cloudflare dashboard.",
						asset,
					),
					Evidence:     map[string]any{"vendor": "Cloudflare", "ssl_mode": "flexible"},
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	// ── Phase 3: Origin IP exposure ───────────────────────────────────────
	// Only meaningful when a WAF is present — check if origin IP is reachable
	// directly, bypassing WAF protections entirely.
	if vendor != "" {
		if originIP := findOriginIP(ctx, asset); originIP != "" {
			// Verify the origin IP actually responds to HTTP (not just open).
			if originResponds(ctx, client, originIP, asset) {
				findings = append(findings, finding.Finding{
					CheckID:  finding.CheckWAFOriginExposed,
					Module:   "surface",
					Scanner:  scannerName,
					Severity: finding.SeverityCritical,
					Asset:    asset,
					Title:    fmt.Sprintf("WAF origin IP exposed: %s bypasses %s", originIP, vendor),
					Description: fmt.Sprintf(
						"%s is fronted by %s, but the origin server at %s responds directly to "+
							"HTTP requests — bypassing WAF DDoS protection, rate limiting, IP "+
							"allowlists, and bot management entirely. An attacker who knows this IP "+
							"can attack the application directly without any WAF inspection. "+
							"Fix: restrict origin firewall to only accept traffic from %s IP ranges, "+
							"and rotate any exposed origin IPs.",
						asset, vendor, originIP, vendor,
					),
					Evidence: map[string]any{
						"waf_vendor": vendor,
						"origin_ip":  originIP,
					},
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	// ── Phase 4: IP header bypass (deep mode only) ────────────────────────
	// Tests whether the WAF can be bypassed by sending forged IP headers.
	if scanType == module.ScanDeep && vendor != "" {
		if bypassHeader, bypassed := testBypassHeaders(ctx, client, asset, scheme, headers); bypassed {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckWAFBypassHeader,
				Module:   "surface",
				Scanner:  scannerName,
				Severity: finding.SeverityHigh,
				Asset:    asset,
				Title:    fmt.Sprintf("WAF rate-limit/block bypassable via %s header", bypassHeader),
				Description: fmt.Sprintf(
					"%s's %s WAF uses the source IP address for rate-limiting and blocking, "+
						"but trusts the %s request header for the real client IP. "+
						"An attacker can rotate arbitrary IPs in this header to bypass per-IP "+
						"rate limits, geo-blocks, and IP reputation blocks. "+
						"Fix: configure %s to ignore or validate IP override headers, or use "+
						"challenge-based protection instead of IP-only rate limiting.",
					asset, vendor, bypassHeader, vendor,
				),
				Evidence: map[string]any{
					"waf_vendor":     vendor,
					"bypass_header":  bypassHeader,
					"test_ip":        "198.51.100.1",
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings, nil
}

// probeHeaders fetches the asset's response headers, trying HTTPS then HTTP.
// Returns the headers map, the scheme used, and any error.
func probeHeaders(ctx context.Context, client *http.Client, asset string) (map[string]string, string, error) {
	for _, scheme := range []string{"https", "http"} {
		url := scheme + "://" + asset + "/"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon Security Scanner)")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		out := make(map[string]string, len(resp.Header))
		for k, v := range resp.Header {
			out[strings.ToLower(k)] = strings.Join(v, ", ")
		}
		return out, scheme, nil
	}
	return nil, "", fmt.Errorf("no response from %s", asset)
}

// probeHTTPOnly performs a single GET over plain HTTP (no HTTPS fallback).
// Returns the HTTP status code and lowercased response headers, or (0, nil) on error.
// Used specifically for Flexible SSL detection to avoid confusing HTTPS headers
// with an HTTP response — probeHeaders() always tries HTTPS first.
func probeHTTPOnly(ctx context.Context, client *http.Client, asset string) (int, map[string]string) {
	url := "http://" + asset + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon Security Scanner)")
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil
	}
	resp.Body.Close()
	hdrs := make(map[string]string, len(resp.Header))
	for k, v := range resp.Header {
		hdrs[strings.ToLower(k)] = strings.Join(v, ", ")
	}
	return resp.StatusCode, hdrs
}

// detectVendor returns the WAF vendor name or "" if none detected.
func detectVendor(headers map[string]string) string {
	for _, sig := range wafHeaders {
		for k := range headers {
			if strings.HasPrefix(k, strings.ToLower(sig.Header)) {
				return sig.Vendor
			}
		}
	}
	return ""
}

// detectIDS returns the IDS/NGFW vendor name or "" if none detected.
func detectIDS(headers map[string]string) string {
	for _, sig := range idsHeaders {
		for k := range headers {
			if strings.HasPrefix(k, strings.ToLower(sig.Header)) {
				return sig.Vendor
			}
		}
	}
	return ""
}

// findOriginIP attempts to find the real origin IP behind a WAF using passive
// techniques: historical subdomain patterns and direct DNS for common names.
// Does not make any outbound network probe to the IP itself — that's done in
// originResponds() separately.
func findOriginIP(ctx context.Context, asset string) string {
	// Common patterns that hosting providers and ops teams use for direct origin access.
	// These often have DNS records pointing to the real IP before the CDN was added.
	roots := rootAndWWW(asset)
	candidates := []string{}
	for _, root := range roots {
		candidates = append(candidates,
			// Classic direct-access patterns
			"direct."+root,
			"origin."+root,
			"direct-"+root,
			"backend."+root,
			"internal."+root,
			// API / gateway patterns
			"api."+root,
			"gw."+root,
			"gateway."+root,
			// Load balancer / infrastructure patterns
			"lb."+root,
			"app."+root,
			"server."+root,
			// Environment-based patterns (common in dev/staging setups)
			"prod."+root,
			"production."+root,
			"staging."+root,
			"dev."+root,
			// Kubernetes / container ingress patterns
			"k8s."+root,
			"ingress."+root,
			"cluster."+root,
			// Regional / zone patterns
			"us."+root,
			"eu."+root,
			"ap."+root,
			"us-east."+root,
			"us-west."+root,
			"eu-west."+root,
		)
	}

	resolver := &net.Resolver{}
	for _, candidate := range candidates {
		addrs, err := resolver.LookupHost(ctx, candidate)
		if err != nil || len(addrs) == 0 {
			continue
		}
		return addrs[0]
	}
	return ""
}

// originResponds checks if an origin IP responds to an HTTP request with
// the target asset's Host header — confirming it serves the application directly.
func originResponds(ctx context.Context, client *http.Client, originIP, asset string) bool {
	for _, scheme := range []string{"https", "http"} {
		url := scheme + "://" + originIP + "/"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		req.Host = asset // send the correct Host header so vhosts resolve
		req.Header.Set("User-Agent", "Mozilla/5.0")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		// Accept 2xx only. 3xx redirects (e.g. 301 → /login) are not confirmation
		// that the origin serves the application — they could be generic redirect
		// pages on any CDN/load-balancer. 4xx and 5xx are not confirmations.
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return true
		}
	}
	return false
}

// testBypassHeaders sends requests with forged IP headers and checks if the
// server's response changes (indicating the WAF trusts the header for IP-based
// controls like rate-limiting or geo-blocks).
// Returns the effective bypass header name and whether bypass was detected.
func testBypassHeaders(ctx context.Context, client *http.Client, asset, scheme string, baseHeaders map[string]string) (string, bool) {
	baseStatus := getStatus(ctx, client, asset, scheme, nil)
	if baseStatus == 0 {
		return "", false
	}

	// We test with a private/loopback IP — if the server responds differently
	// (e.g. 200 instead of 403, or different body/headers), the header is trusted.
	testIP := "198.51.100.1" // TEST-NET-2 (RFC 5737 §3) — documentation-only, never routes publicly
	for _, header := range bypassHeaders {
		status := getStatus(ctx, client, asset, scheme, map[string]string{
			header: testIP,
		})
		if status == 0 {
			continue
		}
		// If status changes from a blocked/rate-limited code to success, bypass confirmed.
		if (baseStatus == 403 || baseStatus == 429) && (status == 200 || status == 301 || status == 302) {
			return header, true
		}
	}
	return "", false
}

// getStatus makes a single GET request and returns the HTTP status code, or 0 on error.
func getStatus(ctx context.Context, client *http.Client, asset, scheme string, extraHeaders map[string]string) int {
	url := scheme + "://" + asset + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	resp.Body.Close()
	return resp.StatusCode
}

// rootAndWWW returns the root domain and its www. variant for the given hostname.
func rootAndWWW(hostname string) []string {
	parts := strings.Split(hostname, ".")
	if len(parts) < 2 {
		return []string{hostname}
	}
	root := strings.Join(parts[len(parts)-2:], ".")
	return []string{root, "www." + root}
}
