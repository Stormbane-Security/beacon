// Package proxychain detects multi-layer proxy/CDN/WAF/LB infrastructure
// between the scanner and the target application by analyzing HTTP response
// headers that leak intermediate hop information.
//
// Techniques:
//  1. Via header parsing (RFC 7230 S5.7.1) — each proxy appends its version+alias
//  2. X-Cache / X-Cache-Hits / Age — CDN cache layer detection
//  3. X-Served-By — multi-POP CDN path (Fastly, Varnish, etc.)//  4. Server header inconsistency — different Server values on different paths
//     reveals multiple backend servers behind a reverse proxy
//  5. TRACE method reflection — Max-Forwards countdown reveals proxy depth
//  6. X-Forwarded-For echo — proxy leaks the chain by echoing back XFF
//  7. Alt-Svc / ALPN — protocol support reveals proxy capabilities (H2, H3)
//
// All surface-mode checks are passive (normal HTTP requests with header analysis).
// Deep-mode adds TRACE probing which is active but non-destructive.
package proxychain

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
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
		scan.Check(finding.CheckProxyChainDetected, finding.SeverityInfo, finding.ModeSurface),
		scan.Check(finding.CheckProxyHopDetected, finding.SeverityInfo, finding.ModeSurface),
		scan.Check(finding.CheckProxyTraceEnabled, finding.SeverityMedium, finding.ModeDeep),
		scan.Check(finding.CheckProxyXFFLeak, finding.SeverityMedium, finding.ModeSurface),
	)
}
const scannerName = "proxychain"

// hopInfo represents a detected intermediary in the request path.
type hopInfo struct {
	Type       string // "cdn", "proxy", "waf", "lb", "cache", "unknown"
	Product    string // e.g., "Varnish", "nginx", "Cloudflare", "HAProxy"
	Version    string // version if detected
	Source     string // which header/technique revealed this hop
	Confidence string // "high", "medium"
}

// probePaths used for header consistency detection across different URL paths.
var probePaths = []string{"/", "/robots.txt", "/favicon.ico", "/404-beacon-probe"}

// viaProductPatterns maps Via header product tokens to infrastructure types.
var viaProductPatterns = []struct {
	pattern *regexp.Regexp
	product string
	hopType string
}{
	{regexp.MustCompile(`(?i)varnish`), "Varnish", "cache"},
	{regexp.MustCompile(`(?i)cloudfront`), "CloudFront", "cdn"},
	{regexp.MustCompile(`(?i)cloudflare`), "Cloudflare", "cdn"},
	{regexp.MustCompile(`(?i)fastly`), "Fastly", "cdn"},
	{regexp.MustCompile(`(?i)akamai`), "Akamai", "cdn"},
	{regexp.MustCompile(`(?i)squid`), "Squid", "proxy"},
	{regexp.MustCompile(`(?i)haproxy`), "HAProxy", "lb"},
	{regexp.MustCompile(`(?i)nginx`), "nginx", "proxy"},
	{regexp.MustCompile(`(?i)apache`), "Apache", "proxy"},
	{regexp.MustCompile(`(?i)traefik`), "Traefik", "proxy"},
	{regexp.MustCompile(`(?i)envoy`), "Envoy", "proxy"},
	{regexp.MustCompile(`(?i)kong`), "Kong", "proxy"},
	{regexp.MustCompile(`(?i)caddy`), "Caddy", "proxy"},
	{regexp.MustCompile(`(?i)ATS`), "Apache Traffic Server", "cdn"},
	{regexp.MustCompile(`(?i)vegur`), "Heroku Router", "lb"},
}

// serverFingerprints maps Server header values to infrastructure types.
var serverFingerprints = []struct {
	pattern *regexp.Regexp
	product string
	hopType string
}{
	{regexp.MustCompile(`(?i)^cloudflare$`), "Cloudflare", "cdn"},
	{regexp.MustCompile(`(?i)^AmazonS3$`), "Amazon S3", "cdn"},
	{regexp.MustCompile(`(?i)^AkamaiGHost`), "Akamai", "cdn"},
	{regexp.MustCompile(`(?i)^Varnish$`), "Varnish", "cache"},
	{regexp.MustCompile(`(?i)^nginx`), "nginx", "proxy"},
	{regexp.MustCompile(`(?i)^Apache`), "Apache", "proxy"},
	{regexp.MustCompile(`(?i)^openresty`), "OpenResty", "proxy"},
	{regexp.MustCompile(`(?i)^Caddy$`), "Caddy", "proxy"},
	{regexp.MustCompile(`(?i)^Cowboy$`), "Cowboy/Heroku", "lb"},
	{regexp.MustCompile(`(?i)^gunicorn`), "Gunicorn", "app"},
	{regexp.MustCompile(`(?i)^Kestrel$`), "Kestrel", "app"},
	{regexp.MustCompile(`(?i)^Werkzeug`), "Werkzeug/Flask", "app"},
	{regexp.MustCompile(`(?i)^Jetty`), "Jetty", "app"},
	{regexp.MustCompile(`(?i)^Microsoft-IIS`), "IIS", "app"},
	{regexp.MustCompile(`(?i)^Tomcat`), "Tomcat", "app"},
	{regexp.MustCompile(`(?i)^uvicorn`), "Uvicorn", "app"},
	{regexp.MustCompile(`(?i)^waitress`), "Waitress", "app"},
	{regexp.MustCompile(`(?i)^Puma`), "Puma", "app"},
	{regexp.MustCompile(`(?i)^WEBrick`), "WEBrick", "app"},
	{regexp.MustCompile(`(?i)^Tengine`), "Tengine", "cdn"},
}

// Scanner detects multi-layer proxy/CDN/LB chains.
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
	var hops []hopInfo

	// 1. Analyze Via headers — each proxy adds an entry
	viaHops := analyzeViaHeaders(ctx, client, scheme, asset)
	hops = append(hops, viaHops...)

	// 2. Detect cache layer from X-Cache / Age / X-Cache-Hits
	cacheHops := detectCacheLayer(ctx, client, scheme, asset)
	hops = append(hops, cacheHops...)

	// 3. Detect multi-POP from X-Served-By
	popHops := detectMultiPOP(ctx, client, scheme, asset)
	hops = append(hops, popHops...)

	// 4. Server header inconsistency across paths
	serverHops := detectServerInconsistency(ctx, client, scheme, asset)
	hops = append(hops, serverHops...)

	// 5. Detect protocol layers from Alt-Svc / ALPN
	protoHops := detectProtocolLayers(ctx, client, scheme, asset)
	hops = append(hops, protoHops...)

	// 6. XFF echo detection — proxy leaking internal chain
	xffHops := detectXFFEcho(ctx, client, scheme, asset)
	hops = append(hops, xffHops...)

	// 7. Deep mode: TRACE method reflection
	if scanType == module.ScanDeep || scanType == module.ScanAuthorized {
		traceHops := probeTrace(ctx, client, scheme, asset)
		hops = append(hops, traceHops...)
	}

	// Deduplicate hops by product name
	hops = deduplicateHops(hops)

	if len(hops) == 0 {
		return nil, nil
	}

	// Build findings
	if len(hops) >= 2 {
		// Multi-layer chain detected — main finding
		findings = append(findings, buildChainFinding(asset, scheme, hops))
	}

	// Individual hop findings
	for _, hop := range hops {
		findings = append(findings, buildHopFinding(asset, scheme, hop))
	}

	// Check for XFF information disclosure
	for _, hop := range hops {
		if hop.Source == "x-forwarded-for-echo" {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckProxyXFFLeak,
				Module:   "surface",
				Scanner:  scannerName,
				Severity: finding.SeverityMedium,
				Asset:    asset,
				Title:    fmt.Sprintf("Proxy leaks X-Forwarded-For chain at %s", asset),
				Description: fmt.Sprintf(
					"The proxy chain at %s echoes the X-Forwarded-For header back in the response, "+
						"revealing internal IP addresses and proxy architecture. An attacker can use this "+
						"to map internal network topology and identify origin servers. "+
						"Fix: configure proxies to not reflect XFF headers in responses.",
					asset),
				Evidence: map[string]any{
					"product": hop.Product,
					"source":  hop.Source,
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	// Check for TRACE method enabled
	for _, hop := range hops {
		if hop.Source == "trace-reflection" {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckProxyTraceEnabled,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityMedium,
				Asset:    asset,
				Title:    fmt.Sprintf("HTTP TRACE method enabled at %s", asset),
				Description: fmt.Sprintf(
					"The server at %s responds to HTTP TRACE requests, reflecting headers "+
						"back in the response body. This can be used for Cross-Site Tracing (XST) "+
						"attacks to steal credentials from HttpOnly cookies, and reveals the "+
						"full proxy chain including internal hop details. "+
						"Fix: disable TRACE method on all web servers and proxies.",
					asset),
				Evidence: map[string]any{
					"product": hop.Product,
				},
				ProofCommand: fmt.Sprintf("curl -sk -X TRACE %s://%s/", scheme, asset),
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings, nil
}

// analyzeViaHeaders parses the Via response header to extract proxy hops.
// RFC 7230 S5.7.1: Via = 1#( received-protocol RWS received-by [ RWS comment ] )
func analyzeViaHeaders(ctx context.Context, client *http.Client, scheme, asset string) []hopInfo {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+asset+"/", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon Security Scanner)")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck
	resp.Body.Close()

	via := resp.Header.Get("Via")
	if via == "" {
		return nil
	}

	var hops []hopInfo
	// Via entries are comma-separated
	for _, entry := range strings.Split(via, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		hop := hopInfo{
			Type:       "proxy",
			Source:     "via-header",
			Confidence: "high",
		}

		// Try to identify the product
		for _, p := range viaProductPatterns {
			if p.pattern.MatchString(entry) {
				hop.Product = p.product
				hop.Type = p.hopType
				break
			}
		}

		if hop.Product == "" {
			// Extract version/protocol from Via entry (e.g., "1.1 proxy.example.com")
			parts := strings.Fields(entry)
			if len(parts) >= 2 {
				hop.Product = parts[1]
				hop.Version = parts[0]
			} else {
				hop.Product = entry
			}
		}

		hops = append(hops, hop)
	}

	return hops
}

// detectCacheLayer looks for CDN/cache indicators in response headers.
func detectCacheLayer(ctx context.Context, client *http.Client, scheme, asset string) []hopInfo {
	// Make two requests — caching behavior differs between first and second
	var hops []hopInfo

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
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck
		resp.Body.Close()

		// Only process second response (more likely to show cache HIT)
		if i == 0 {
			continue
		}

		// X-Cache header
		xCache := resp.Header.Get("X-Cache")
		if xCache != "" {
			hop := hopInfo{
				Source:     "x-cache",
				Confidence: "high",
			}

			lc := strings.ToLower(xCache)
			switch {
			case strings.Contains(lc, "cloudfront"):
				hop.Product = "CloudFront"
				hop.Type = "cdn"
			case strings.Contains(lc, "varnish"):
				hop.Product = "Varnish"
				hop.Type = "cache"
			default:
				hop.Product = "CDN/Cache"
				hop.Type = "cache"
			}
			hops = append(hops, hop)
		}

		// Age header indicates a cache layer exists
		if age := resp.Header.Get("Age"); age != "" && age != "0" {
			// Only add if we didn't already detect from X-Cache
			if xCache == "" {
				hops = append(hops, hopInfo{
					Type:       "cache",
					Product:    "Cache Layer",
					Source:     "age-header",
					Confidence: "medium",
				})
			}
		}

		// CF-Cache-Status — Cloudflare specific
		if cfCache := resp.Header.Get("CF-Cache-Status"); cfCache != "" {
			hops = append(hops, hopInfo{
				Type:       "cdn",
				Product:    "Cloudflare",
				Source:     "cf-cache-status",
				Confidence: "high",
			})
		}

		// X-Varnish header
		if xv := resp.Header.Get("X-Varnish"); xv != "" {
			hops = append(hops, hopInfo{
				Type:       "cache",
				Product:    "Varnish",
				Source:     "x-varnish",
				Confidence: "high",
			})
		}

		// Fastly-Debug-Digest
		if resp.Header.Get("Fastly-Debug-Digest") != "" {
			hops = append(hops, hopInfo{
				Type:       "cdn",
				Product:    "Fastly",
				Source:     "fastly-debug-digest",
				Confidence: "high",
			})
		}
	}

	return hops
}

// detectMultiPOP detects multi-datacenter CDN routing from X-Served-By.
func detectMultiPOP(ctx context.Context, client *http.Client, scheme, asset string) []hopInfo {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+asset+"/", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon Security Scanner)")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck
	resp.Body.Close()

	xServedBy := resp.Header.Get("X-Served-By")
	if xServedBy == "" {
		return nil
	}

	var hops []hopInfo
	// X-Served-By can contain comma-separated POP identifiers
	for _, pop := range strings.Split(xServedBy, ",") {
		pop = strings.TrimSpace(pop)
		if pop == "" {
			continue
		}

		hop := hopInfo{
			Product:    pop,
			Type:       "cdn",
			Source:     "x-served-by",
			Confidence: "high",
		}

		// Try to identify CDN from POP naming patterns
		lc := strings.ToLower(pop)
		switch {
		case strings.Contains(lc, "cache-"):
			hop.Product = "Fastly (" + pop + ")"
		case strings.Contains(lc, "varnish"):
			hop.Product = "Varnish (" + pop + ")"
			hop.Type = "cache"
		}

		hops = append(hops, hop)
	}

	return hops
}

// detectServerInconsistency sends requests to multiple paths and checks for
// different Server headers — indicating multiple backend servers behind a proxy.
func detectServerInconsistency(ctx context.Context, client *http.Client, scheme, asset string) []hopInfo {
	servers := make(map[string]string) // server header → first path seen

	for _, path := range probePaths {
		if ctx.Err() != nil {
			break
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+asset+path, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon Security Scanner)")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck
		resp.Body.Close()

		srv := resp.Header.Get("Server")
		if srv != "" {
			if _, seen := servers[srv]; !seen {
				servers[srv] = path
			}
		}
	}

	// If we see different Server headers, there are multiple layers
	if len(servers) <= 1 {
		return nil
	}

	var hops []hopInfo
	for srv, path := range servers {
		hop := hopInfo{
			Product:    srv,
			Source:     fmt.Sprintf("server-header:%s", path),
			Confidence: "medium",
		}

		// Classify
		for _, fp := range serverFingerprints {
			if fp.pattern.MatchString(srv) {
				hop.Product = fp.product
				hop.Type = fp.hopType
				break
			}
		}
		if hop.Type == "" {
			hop.Type = "unknown"
		}

		hops = append(hops, hop)
	}

	return hops
}

// detectProtocolLayers checks for Alt-Svc and TLS ALPN to detect protocol support.
func detectProtocolLayers(ctx context.Context, client *http.Client, scheme, asset string) []hopInfo {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+asset+"/", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon Security Scanner)")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck
	resp.Body.Close()

	var hops []hopInfo

	// Alt-Svc indicates HTTP/3 (QUIC) support — only CDNs typically support this
	altSvc := resp.Header.Get("Alt-Svc")
	if altSvc != "" && strings.Contains(altSvc, "h3") {
		hops = append(hops, hopInfo{
			Type:       "cdn",
			Product:    "HTTP/3 (QUIC) Endpoint",
			Source:     "alt-svc-h3",
			Confidence: "medium",
		})
	}

	// Check TLS ALPN negotiation for h2
	if scheme == "https" {
		host := asset
		if !strings.Contains(host, ":") {
			host = host + ":443"
		}
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		conn, err := tls.DialWithDialer(dialer, "tcp", host, &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec
			NextProtos:         []string{"h2", "http/1.1"},
		})
		if err == nil {
			negotiated := conn.ConnectionState().NegotiatedProtocol
			conn.Close()
			if negotiated == "h2" {
				// H2 support at the edge but backend might be H1 — this is a
				// proxy layer indicator (most app servers don't do H2 natively)
				hops = append(hops, hopInfo{
					Type:       "proxy",
					Product:    "HTTP/2 Termination",
					Source:     "alpn-h2",
					Confidence: "medium",
				})
			}
		}
	}

	return hops
}

// detectXFFEcho checks if the server echoes X-Forwarded-For back in the response.
func detectXFFEcho(ctx context.Context, client *http.Client, scheme, asset string) []hopInfo {
	// Send a request with a unique marker in XFF
	marker := "10.13.37.42"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+asset+"/", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon Security Scanner)")
	req.Header.Set("X-Forwarded-For", marker)

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	resp.Body.Close()

	// Check if our marker appears in response body or headers
	bodyStr := string(body)
	headerStr := fmt.Sprintf("%v", resp.Header)

	if strings.Contains(bodyStr, marker) || strings.Contains(headerStr, marker) {
		return []hopInfo{{
			Type:       "proxy",
			Product:    "XFF-reflecting proxy",
			Source:     "x-forwarded-for-echo",
			Confidence: "high",
		}}
	}

	return nil
}

// probeTrace uses HTTP TRACE to enumerate proxy hops via Max-Forwards.
func probeTrace(ctx context.Context, client *http.Client, scheme, asset string) []hopInfo {
	req, err := http.NewRequestWithContext(ctx, http.MethodTrace, scheme+"://"+asset+"/", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon Security Scanner)")
	req.Header.Set("Max-Forwards", "10")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	resp.Body.Close()

	// TRACE should echo back the request — if it does, TRACE is enabled
	if resp.StatusCode == 200 && strings.Contains(string(body), "TRACE") {
		return []hopInfo{{
			Type:       "proxy",
			Product:    "TRACE-enabled server",
			Source:     "trace-reflection",
			Confidence: "high",
		}}
	}

	return nil
}

// deduplicateHops removes duplicate hops by product name, keeping the highest-confidence one.
func deduplicateHops(hops []hopInfo) []hopInfo {
	seen := make(map[string]int) // product → index in result
	var result []hopInfo

	for _, h := range hops {
		key := strings.ToLower(h.Product)
		if idx, exists := seen[key]; exists {
			// Keep higher confidence
			if h.Confidence == "high" && result[idx].Confidence != "high" {
				result[idx] = h
			}
			continue
		}
		seen[key] = len(result)
		result = append(result, h)
	}

	return result
}

// buildChainFinding creates the main multi-layer chain finding.
func buildChainFinding(asset, scheme string, hops []hopInfo) finding.Finding {
	// Build the chain description
	var layers []string
	for _, h := range hops {
		label := h.Product
		if h.Type != "" && h.Type != "unknown" {
			label = fmt.Sprintf("%s (%s)", h.Product, h.Type)
		}
		layers = append(layers, label)
	}
	chain := strings.Join(layers, " → ")

	// Sort hop types for evidence
	types := make(map[string]bool)
	for _, h := range hops {
		types[h.Type] = true
	}
	var typeList []string
	for t := range types {
		typeList = append(typeList, t)
	}
	sort.Strings(typeList)

	return finding.Finding{
		CheckID:  finding.CheckProxyChainDetected,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityInfo,
		Asset:    asset,
		Title:    fmt.Sprintf("Multi-layer proxy chain detected: %d hops at %s", len(hops), asset),
		Description: fmt.Sprintf(
			"The request path to %s traverses multiple infrastructure layers: %s. "+
				"Each layer adds latency and potential attack surface. The chain topology "+
				"reveals the hosting architecture and may expose bypass opportunities "+
				"(e.g., connecting directly to a backend layer, skipping WAF/CDN).",
			asset, chain),
		Evidence: map[string]any{
			"chain":      chain,
			"hop_count":  len(hops),
			"hop_types":  typeList,
			"scheme":     scheme,
		},
		ProofCommand: fmt.Sprintf("curl -sI %s://%s/ | grep -iE '(via|x-cache|x-served-by|server|age|alt-svc)'", scheme, asset),
		DiscoveredAt: time.Now(),
	}
}

// buildHopFinding creates a finding for an individual detected hop.
func buildHopFinding(asset, scheme string, hop hopInfo) finding.Finding {
	return finding.Finding{
		CheckID:  finding.CheckProxyHopDetected,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityInfo,
		Asset:    asset,
		Title:    fmt.Sprintf("Infrastructure layer detected: %s (%s) at %s", hop.Product, hop.Type, asset),
		Description: fmt.Sprintf(
			"Detected %s infrastructure layer %q serving %s (source: %s, confidence: %s). "+
				"This information helps map the full request path and identify potential "+
				"bypass vectors or misconfigurations at each layer.",
			hop.Type, hop.Product, asset, hop.Source, hop.Confidence),
		Evidence: map[string]any{
			"product":    hop.Product,
			"type":       hop.Type,
			"source":     hop.Source,
			"confidence": hop.Confidence,
			"version":    hop.Version,
		},
		DiscoveredAt: time.Now(),
	}
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
		resp.Body.Close()
		return scheme
	}
	return ""
}
