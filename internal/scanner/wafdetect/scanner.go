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
	"io"
	"net"
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
		scan.Check(finding.CheckIDSDetected, finding.SeverityInfo, finding.ModeSurface),
		scan.Check(finding.CheckWAFBypassContentType, finding.SeverityHigh, finding.ModeDeep),
		scan.Check(finding.CheckWAFBypassHeader, finding.SeverityHigh, finding.ModeDeep),
		scan.Check(finding.CheckWAFBypassMethod, finding.SeverityMedium, finding.ModeDeep),
		scan.Check(finding.CheckWAFBypassPath, finding.SeverityHigh, finding.ModeDeep),
		scan.Check(finding.CheckWAFDetected, finding.SeverityInfo, finding.ModeSurface),
		scan.Check(finding.CheckWAFInsecureMode, finding.SeverityHigh, finding.ModeSurface),
		scan.Check(finding.CheckWAFOriginExposed, finding.SeverityCritical, finding.ModeSurface),
		scan.Check(finding.CheckWAFProductVersion, finding.SeverityInfo, finding.ModeSurface),
	)
}
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

// wafBodyPatterns maps response body substrings (case-insensitive) to WAF vendor names.
// WAFs often inject signature strings into HTML error/block pages that are not
// present in headers. Matching body content catches WAFs that strip custom headers.
var wafBodyPatterns = []struct {
	Pattern string
	Vendor  string
}{
	{"attention required! | cloudflare", "Cloudflare"},
	{"cf-error-details", "Cloudflare"},
	{"cloudflare ray id", "Cloudflare"},
	{"please wait... | cloudflare", "Cloudflare"},
	{"access denied | sucuri", "Sucuri WAF"},
	{"sucuri website firewall", "Sucuri WAF"},
	{"request blocked", "Generic WAF"},
	{"access denied", "Generic WAF"},
	{"your request has been blocked", "Generic WAF"},
	{"this request was blocked by the security rules", "Generic WAF"},
	{"web application firewall", "Generic WAF"},
	{"<title>403 forbidden</title>", "Generic WAF"},
	{"powered by incapsula", "Imperva Incapsula"},
	{"incapsula incident id", "Imperva Incapsula"},
	{"_incapsula_resource", "Imperva Incapsula"},
	{"akamai ghost", "Akamai"},
	{"akamaighost", "Akamai"},
	{"ak.reference", "Akamai"},
	{"<h1>access denied</h1>", "Generic WAF"},
	{"ddos protection by", "Generic WAF"},
	{"barracuda web application firewall", "Barracuda WAF"},
	{"f5 big-ip", "F5 BIG-IP ASM"},
	{"the requested url was rejected", "F5 BIG-IP ASM"},
	{"support id:", "F5 BIG-IP ASM"},
	{"modsecurity", "ModSecurity"},
	{"fortiweb", "Fortinet FortiWeb"},
	{"fortigate", "Fortinet FortiGate"},
	{"palo alto next generation", "Palo Alto NGFW"},
	{"wallarm", "Wallarm WAF"},
	{"wordfence", "Wordfence"},
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

	// Probe the asset and collect response headers + body.
	headers, scheme, body, err := probeHeaders(ctx, client, asset)
	if err != nil || len(headers) == 0 {
		return nil, nil
	}

	var findings []finding.Finding

	// ── Phase 1: Vendor fingerprinting ──────────────────────────────────────
	vendor := detectVendor(headers, body)
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
				Confidence:   finding.ConfidenceObserved,
		})

		// Try to extract WAF product version from headers.
		version := extractWAFVersion(headers, vendor)
		if version != "" {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckWAFProductVersion,
				Module:   "surface",
				Scanner:  scannerName,
				Severity: finding.SeverityInfo,
				Asset:    asset,
				Title:    fmt.Sprintf("WAF version: %s %s", vendor, version),
				Description: fmt.Sprintf(
					"%s is running %s version %s. Knowing the exact version helps "+
						"identify applicable CVEs and bypass techniques.",
					asset, vendor, version,
				),
				Evidence:     map[string]any{"vendor": vendor, "version": version, "scheme": scheme},
				DiscoveredAt: time.Now(),
				Confidence:   finding.ConfidenceObserved,
			})
		}
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
				Confidence:   finding.ConfidenceObserved,
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
				Confidence:   finding.ConfidenceObserved,
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
				Confidence:   finding.ConfidenceObserved,
				})
			}
		}
	}

	// ── Phase 4: IP header bypass (deep mode only) ────────────────────────
	// Tests whether the WAF can be bypassed by sending forged IP headers.
	if (scanType == module.ScanDeep || scanType == module.ScanAuthorized) && vendor != "" {
		if bypassHeader, bypassed := testBypassHeaders(ctx, client, asset, scheme, headers); bypassed {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckWAFBypassHeader,
				Module:   "deep",
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
				Confidence:   finding.ConfidenceObserved,
			})
		}
	}

	// ── Phase 5: Path normalization bypass (authorized mode) ────────────
	// Tests whether the WAF can be bypassed by abusing path normalization
	// differences between the WAF and the backend server.
	if scanType == module.ScanAuthorized && vendor != "" {
		findings = append(findings, testPathNormalization(ctx, client, asset, scheme, vendor)...)
	}

	// ── Phase 6: HTTP method override bypass (authorized mode) ──────────
	// Tests whether WAF rules can be bypassed by using method override headers.
	if scanType == module.ScanAuthorized && vendor != "" {
		findings = append(findings, testMethodOverride(ctx, client, asset, scheme, vendor)...)
	}

	// ── Phase 7: Content-Type confusion bypass (authorized mode) ────────
	// Tests whether WAF body inspection can be bypassed by changing Content-Type.
	if scanType == module.ScanAuthorized && vendor != "" {
		findings = append(findings, testContentTypeBypass(ctx, client, asset, scheme, vendor)...)
	}

	// ── Phase 8: Behavioral WAF detection ───────────────────────────────
	// If no vendor was fingerprinted from headers, try behavioral detection:
	// send a SQLi payload and check if it gets blocked (403) while a normal
	// request succeeds (200). This catches WAFs that hide their identity
	// (e.g., ModSecurity CRS behind nginx without signature headers).
	if vendor == "" {
		base := scheme + "://" + asset
		normalReq, _ := http.NewRequestWithContext(ctx, "GET", base+"/", nil)
		sqliReq, _ := http.NewRequestWithContext(ctx, "GET", base+"/?q='+OR+1=1--", nil)

		if normalReq != nil && sqliReq != nil {
			normalResp, err1 := client.Do(normalReq)
			sqliResp, err2 := client.Do(sqliReq)

			if err1 == nil && err2 == nil {
				_ = normalResp.Body.Close()
				_ = sqliResp.Body.Close()

				// Normal succeeds (200) but SQLi blocked (403/406/429) = WAF present
				if normalResp.StatusCode == 200 && (sqliResp.StatusCode == 403 || sqliResp.StatusCode == 406 || sqliResp.StatusCode == 429) {
					findings = append(findings, finding.Finding{
						CheckID:     finding.CheckWAFDetected,
						Module:      "surface",
						Scanner:     scannerName,
						Severity:    finding.SeverityInfo,
						Asset:       asset,
						Title:       "WAF detected (behavioral: SQLi payload blocked)",
						Description: fmt.Sprintf("%s blocks SQL injection payloads (HTTP %d) while allowing normal requests (HTTP %d). A WAF or application firewall is active but its vendor is not identifiable from response headers.", asset, sqliResp.StatusCode, normalResp.StatusCode),
						Evidence: map[string]any{
							"detection":     "behavioral",
							"normal_status": normalResp.StatusCode,
							"sqli_status":   sqliResp.StatusCode,
						},
						Confidence:   finding.ConfidenceObserved,
						DiscoveredAt: time.Now(),
					})
				}
			}
		}
	}

	return findings, nil
}

// probeHeaders fetches the asset's response headers and body, trying HTTPS then HTTP.
// Returns the headers map, the scheme used, the response body (up to 64 KB for
// WAF body-pattern matching), and any error.
func probeHeaders(ctx context.Context, client *http.Client, asset string) (map[string]string, string, string, error) {
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
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		_ = resp.Body.Close()
		out := make(map[string]string, len(resp.Header))
		for k, v := range resp.Header {
			out[strings.ToLower(k)] = strings.Join(v, ", ")
		}
		return out, scheme, string(bodyBytes), nil
	}
	return nil, "", "", fmt.Errorf("no response from %s", asset)
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
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck
	_ = resp.Body.Close()
	hdrs := make(map[string]string, len(resp.Header))
	for k, v := range resp.Header {
		hdrs[strings.ToLower(k)] = strings.Join(v, ", ")
	}
	return resp.StatusCode, hdrs
}

// detectVendor returns the WAF vendor name or "" if none detected.
// Checks both response headers and body content for WAF signatures.
func detectVendor(headers map[string]string, body string) string {
	// Check headers first — most reliable signal.
	for _, sig := range wafHeaders {
		for k := range headers {
			if strings.HasPrefix(k, strings.ToLower(sig.Header)) {
				return sig.Vendor
			}
		}
	}
	// Fall back to body pattern matching — catches WAFs that strip custom
	// headers but inject signature strings into HTML error/block pages.
	if body != "" {
		bodyLower := strings.ToLower(body)
		genericMatch := false
		for _, bp := range wafBodyPatterns {
			if strings.Contains(bodyLower, bp.Pattern) {
				// Named vendor match is definitive — return immediately.
				if bp.Vendor != "Generic WAF" {
					return bp.Vendor
				}
				// "Generic WAF" is a fallback — keep looking for a named vendor.
				genericMatch = true
			}
		}
		if genericMatch {
			return "Generic WAF"
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

	// Resolve the main asset's IPs (WAF edge IPs) so we can filter them out.
	// An origin candidate that resolves to the same IP as the WAF edge is not
	// a real origin exposure.
	mainAddrs, _ := resolver.LookupHost(ctx, asset)
	wafIPs := make(map[string]struct{}, len(mainAddrs))
	for _, a := range mainAddrs {
		wafIPs[a] = struct{}{}
	}

	for _, candidate := range candidates {
		addrs, err := resolver.LookupHost(ctx, candidate)
		if err != nil || len(addrs) == 0 {
			continue
		}
		if _, isWAF := wafIPs[addrs[0]]; isWAF {
			continue // same IP as the WAF edge — not a real origin
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
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck
		_ = resp.Body.Close()
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
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck
	_ = resp.Body.Close()
	return resp.StatusCode
}

// rootAndWWW returns the registrable domain and its www. variant for the given hostname.
// It handles common multi-part TLDs (.co.uk, .com.au, etc.).
func rootAndWWW(hostname string) []string {
	parts := strings.Split(hostname, ".")
	if len(parts) < 2 {
		return []string{hostname}
	}
	// Handle common two-part TLDs: keep 3 labels instead of 2.
	n := 2
	if len(parts) >= 3 {
		sld := parts[len(parts)-2]
		tld := parts[len(parts)-1]
		if isTwoPartTLD(sld, tld) {
			n = 3
		}
	}
	if n > len(parts) {
		n = len(parts)
	}
	root := strings.Join(parts[len(parts)-n:], ".")
	return []string{root, "www." + root}
}

// isTwoPartTLD returns true for common second-level domains under country-code TLDs
// (e.g., co.uk, com.au, co.jp) where the registrable domain has 3 labels.
func isTwoPartTLD(sld, tld string) bool {
	key := sld + "." + tld
	switch key {
	case "co.uk", "org.uk", "me.uk", "net.uk", "ac.uk",
		"com.au", "net.au", "org.au", "edu.au",
		"co.nz", "net.nz", "org.nz",
		"co.jp", "or.jp", "ne.jp", "ac.jp",
		"co.kr", "or.kr", "ne.kr",
		"co.in", "net.in", "org.in", "ac.in",
		"com.br", "net.br", "org.br",
		"co.za", "org.za", "net.za",
		"com.cn", "net.cn", "org.cn",
		"com.mx", "org.mx", "net.mx",
		"com.sg", "net.sg", "org.sg",
		"co.il", "org.il", "net.il",
		"com.tw", "net.tw", "org.tw",
		"co.th", "or.th", "ac.th",
		"com.hk", "org.hk", "net.hk",
		"com.my", "net.my", "org.my":
		return true
	}
	return false
}

// ── Phase 5–7: Authorized-mode bypass techniques ────────────────────────────

// pathNormalizationPayloads are URL path transformations that may bypass WAF rules
// by exploiting normalization differences between the WAF and the backend server.
// Example: WAF blocks /admin but not //admin or /./admin — backend still serves it.
var pathNormalizationPayloads = []struct {
	name      string
	transform func(string) string
}{
	{"double-slash", func(p string) string { return "/" + p }},                         // //admin
	{"dot-segment", func(p string) string { return "/./" + p[1:] }},                   // /./admin
	{"dot-dot-semicolon", func(p string) string { return "/x/..;" + p }},              // /x/..;/admin (Tomcat/Jetty)
	{"url-encoded-slash", func(p string) string { return "/%2f" + p[1:] }},            // /%2f/admin
	{"double-url-encoded", func(p string) string { return "/%252f" + p[1:] }},         // /%252f/admin
	{"null-byte", func(p string) string { return p + "%00" }},                         // /admin%00
	{"backslash", func(p string) string { return strings.ReplaceAll(p, "/", "\\") }},  // \admin
	{"tab-injection", func(p string) string { return p[:1] + "%09" + p[1:] }},         // /%09admin
	{"case-variation", func(p string) string { return strings.ToUpper(p) }},            // /ADMIN
}

// testPathNormalization probes the WAF with path normalization tricks.
// It first finds a path that the WAF blocks (403), then tries path transformations
// to see if any bypass the block while still reaching the backend.
func testPathNormalization(ctx context.Context, client *http.Client, asset, scheme, vendor string) []finding.Finding {
	// Paths commonly blocked by WAF rules
	blockedPaths := []string{"/admin", "/wp-admin", "/phpmyadmin", "/server-status"}

	var findings []finding.Finding

	// Fetch root status once — it doesn't change per path.
	baseStatus := getStatus(ctx, client, asset, scheme, nil)
	if baseStatus == 0 {
		return findings
	}

	for _, path := range blockedPaths {
		if ctx.Err() != nil {
			break
		}

		// Check if this path is actually blocked
		pathStatus := getStatusPath(ctx, client, asset, scheme, path, nil)

		if pathStatus == 0 {
			continue
		}
		if pathStatus != 403 && pathStatus != 406 && pathStatus != 429 {
			continue // path not blocked
		}

		// Try each normalization technique
		for _, payload := range pathNormalizationPayloads {
			if ctx.Err() != nil {
				break
			}

			transformed := payload.transform(path)
			status := getStatusPath(ctx, client, asset, scheme, transformed, nil)

			// If the transformed path gets a different (non-blocked) response, it's a bypass
			if status >= 200 && status < 400 && status != pathStatus {
				findings = append(findings, finding.Finding{
					CheckID:  finding.CheckWAFBypassPath,
					Module:   "authorized",
					Scanner:  scannerName,
					Severity: finding.SeverityHigh,
					Asset:    asset,
					Title:    fmt.Sprintf("WAF path normalization bypass: %s technique bypasses block on %s", payload.name, path),
					Description: fmt.Sprintf(
						"%s's %s WAF blocks %s (HTTP %d) but the path normalization technique %q "+
							"transforms it to %s which returns HTTP %d. The WAF and backend server "+
							"normalize URL paths differently, allowing an attacker to bypass WAF rules. "+
							"Fix: ensure the WAF normalizes paths the same way as the backend, or "+
							"implement path normalization before WAF rule evaluation.",
						asset, vendor, path, pathStatus, payload.name, transformed, status),
					Evidence: map[string]any{
						"waf_vendor":     vendor,
						"blocked_path":   path,
						"blocked_status": pathStatus,
						"bypass_path":    transformed,
						"bypass_status":  status,
						"technique":      payload.name,
					},
					ProofCommand: fmt.Sprintf("curl -sk -o /dev/null -w '%%{http_code}' '%s://%s%s'", scheme, asset, transformed),
					DiscoveredAt: time.Now(),
				Confidence:   finding.ConfidenceObserved,
				})
				break // one bypass per path is enough
			}
		}
	}

	return findings
}

// testMethodOverride checks if WAF rules can be bypassed by using HTTP method
// override headers. Many frameworks support X-HTTP-Method-Override to change the
// effective method — a WAF blocking POST to /admin may still allow GET with the
// override header set to POST.
func testMethodOverride(ctx context.Context, client *http.Client, asset, scheme, vendor string) []finding.Finding {
	overrideHeaders := []struct {
		name  string
		value string
	}{
		{"X-HTTP-Method-Override", "POST"},
		{"X-HTTP-Method", "POST"},
		{"X-Method-Override", "POST"},
	}

	var findings []finding.Finding

	// Find a path where POST is blocked but GET isn't
	testPaths := []string{"/", "/api", "/login"}

	for _, path := range testPaths {
		if ctx.Err() != nil {
			break
		}

		getResp := getStatusPath(ctx, client, asset, scheme, path, nil)
		postResp := getStatusMethod(ctx, client, asset, scheme, path, "POST", nil)

		// POST is blocked but GET isn't
		if getResp < 200 || getResp >= 400 {
			continue
		}
		if postResp != 403 && postResp != 405 {
			continue
		}

		// Try method override headers with GET
		for _, oh := range overrideHeaders {
			if ctx.Err() != nil {
				break
			}

			status := getStatusPath(ctx, client, asset, scheme, path, map[string]string{
				oh.name: oh.value,
			})

			// If override header changes the behavior vs plain GET, the backend processes it
			if status != getResp && status >= 200 && status < 400 {
				findings = append(findings, finding.Finding{
					CheckID:  finding.CheckWAFBypassMethod,
					Module:   "authorized",
					Scanner:  scannerName,
					Severity: finding.SeverityMedium,
					Asset:    asset,
					Title:    fmt.Sprintf("WAF bypass via %s method override at %s%s", oh.name, asset, path),
					Description: fmt.Sprintf(
						"The WAF at %s blocks POST requests to %s (HTTP %d), but sending a GET request "+
							"with %s: %s header returns HTTP %d. The backend server processes the override "+
							"header, effectively converting the GET to a POST and bypassing WAF method-based rules. "+
							"Fix: strip method override headers at the WAF/proxy layer, or include them in WAF rules.",
						asset, path, postResp, oh.name, oh.value, status),
					Evidence: map[string]any{
						"waf_vendor":      vendor,
						"path":            path,
						"blocked_method":  "POST",
						"blocked_status":  postResp,
						"override_header": oh.name,
						"override_value":  oh.value,
						"bypass_status":   status,
					},
					ProofCommand: fmt.Sprintf("curl -sk -H '%s: %s' '%s://%s%s'", oh.name, oh.value, scheme, asset, path),
					DiscoveredAt: time.Now(),
				Confidence:   finding.ConfidenceObserved,
				})
				break
			}
		}
	}

	return findings
}

// testContentTypeBypass checks if WAF body inspection can be bypassed by using
// unexpected Content-Type headers. Some WAFs only inspect application/x-www-form-urlencoded
// or application/json but ignore multipart/form-data or text/plain.
func testContentTypeBypass(ctx context.Context, client *http.Client, asset, scheme, vendor string) []finding.Finding {
	// First check if any POST endpoint exists and has WAF body inspection
	testPath := "/"
	sqliPayload := "' OR 1=1-- -"

	// Test with standard form content type — should be blocked by WAF
	blockedStatus := postWithContentType(ctx, client, asset, scheme, testPath,
		"application/x-www-form-urlencoded", "q="+sqliPayload)

	if blockedStatus != 403 && blockedStatus != 406 {
		return nil // WAF didn't block the payload, nothing to bypass
	}

	// Test with alternative content types
	altTypes := []string{
		"text/plain",
		"application/xml",
		"multipart/form-data; boundary=----BeaconTest",
		"application/x-www-form-urlencoded; charset=ibm500",
	}

	var findings []finding.Finding

	for _, ct := range altTypes {
		if ctx.Err() != nil {
			break
		}

		status := postWithContentType(ctx, client, asset, scheme, testPath, ct, "q="+sqliPayload)
		if status != blockedStatus && status >= 200 && status < 500 && status != 403 {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckWAFBypassContentType,
				Module:   "authorized",
				Scanner:  scannerName,
				Severity: finding.SeverityHigh,
				Asset:    asset,
				Title:    fmt.Sprintf("WAF body inspection bypass via Content-Type: %s at %s", ct, asset),
				Description: fmt.Sprintf(
					"The WAF at %s blocks malicious payloads in application/x-www-form-urlencoded bodies (HTTP %d), "+
						"but allows the same payload through with Content-Type: %s (HTTP %d). "+
						"The WAF only inspects bodies with certain content types, allowing attackers to "+
						"bypass body-based rules by changing the Content-Type header. "+
						"Fix: configure WAF body inspection for all content types, not just form-urlencoded and JSON.",
					asset, blockedStatus, ct, status),
				Evidence: map[string]any{
					"waf_vendor":           vendor,
					"blocked_content_type": "application/x-www-form-urlencoded",
					"blocked_status":       blockedStatus,
					"bypass_content_type":  ct,
					"bypass_status":        status,
				},
				DiscoveredAt: time.Now(),
				Confidence:   finding.ConfidenceObserved,
			})
			break // one is enough
		}
	}

	return findings
}

// getStatusPath makes a GET request to a specific path and returns the status code.
func getStatusPath(ctx context.Context, client *http.Client, asset, scheme, path string, extraHeaders map[string]string) int {
	reqURL := scheme + "://" + asset + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
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
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck
	_ = resp.Body.Close()
	return resp.StatusCode
}

// getStatusMethod makes a request with a specific HTTP method and returns the status code.
func getStatusMethod(ctx context.Context, client *http.Client, asset, scheme, path, method string, extraHeaders map[string]string) int {
	reqURL := scheme + "://" + asset + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return 0
	}
	req.Method = method
	req.Header.Set("User-Agent", "Mozilla/5.0")
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck
	_ = resp.Body.Close()
	return resp.StatusCode
}

// extractWAFVersion attempts to determine the WAF product version from
// response headers. Returns "" if no version information is found.
func extractWAFVersion(headers map[string]string, vendor string) string {
	switch vendor {
	case "Cloudflare":
		// Cloudflare doesn't expose version, but cf-ray contains datacenter code.
		return ""
	case "Imperva Incapsula":
		if v, ok := headers["x-cdn"]; ok && v != "" {
			return v
		}
	case "Akamai":
		if v, ok := headers["server"]; ok && strings.Contains(strings.ToLower(v), "akamai") {
			return v
		}
	case "ModSecurity":
		if v, ok := headers["server"]; ok {
			lower := strings.ToLower(v)
			if idx := strings.Index(lower, "mod_security"); idx >= 0 {
				return v[idx:]
			}
			if idx := strings.Index(lower, "modsecurity"); idx >= 0 {
				return v[idx:]
			}
		}
	case "F5 BIG-IP", "F5 BIG-IP ASM":
		if v, ok := headers["server"]; ok && strings.Contains(strings.ToLower(v), "big-ip") {
			return v
		}
	}

	// Generic: check Server header for version info.
	if server, ok := headers["server"]; ok {
		lower := strings.ToLower(server)
		for _, kw := range []string{"waf", "firewall", "proxy"} {
			if strings.Contains(lower, kw) {
				return server
			}
		}
	}

	return ""
}

// postWithContentType sends a POST request with the given content type and body.
func postWithContentType(ctx context.Context, client *http.Client, asset, scheme, path, contentType, body string) int {
	reqURL := scheme + "://" + asset + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, strings.NewReader(body))
	if err != nil {
		return 0
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Content-Type", contentType)
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck
	_ = resp.Body.Close()
	return resp.StatusCode
}
