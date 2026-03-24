// Package classify collects observable evidence about a single asset and
// returns a structured Evidence packet used by the playbook engine for matching.
//
// It makes one HTTP(S) request to the asset, one DNS resolution, and one
// ASN lookup — all surface-safe operations. No payloads, no fuzzing.
package classify

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/stormbane/beacon/internal/playbook"
)

// contractAddrRe matches a 0x-prefixed 40-hex-char EVM address that is
// surrounded by non-hex characters on both sides, avoiding false positives
// inside longer hex strings (e.g. 64-char tx hashes).
var contractAddrRe = regexp.MustCompile(`(?i)(?:^|[^0-9a-fA-F])(0x[0-9a-fA-F]{40})(?:[^0-9a-fA-F]|$)`)

// scriptSrcRe extracts the src attribute value from <script src="..."> tags.
var scriptSrcRe = regexp.MustCompile(`(?i)<script[^>]+\bsrc=["']([^"']{4,256})["']`)

// subdomainRe is built dynamically per-hostname in extractBodySubdomains.

// vendorPattern maps a domain substring to a vendor label.
type vendorPattern struct{ domain, vendor string }

// vendorDomainPatterns is used both for CSP header parsing and <script src> extraction.
// A vendor is emitted once per asset regardless of how many times its domain appears.
var vendorDomainPatterns = []vendorPattern{
	{"stripe.com", "stripe"},
	{"sentry.io", "sentry"},
	{"browser.sentry-cdn.com", "sentry"},
	{"newrelic.com", "newrelic"},
	{"nr-data.net", "newrelic"},
	{"datadoghq.com", "datadog"},
	{"datadoghq-browser-agent.com", "datadog"},
	{"intercom.io", "intercom"},
	{"intercomcdn.com", "intercom"},
	{"zendesk.com", "zendesk"},
	{"zopim.com", "zendesk"},
	{"salesforce.com", "salesforce"},
	{"salesforceliveagent.com", "salesforce"},
	{"hubspot.com", "hubspot"},
	{"hs-scripts.com", "hubspot"},
	{"hs-analytics.net", "hubspot"},
	{"segment.com", "segment"},
	{"segment.io", "segment"},
	{"onesignal.com", "onesignal"},
	{"braintreegateway.com", "braintree"},
	{"paypalobjects.com", "paypal"},
	{"paypal.com", "paypal"},
	{"twilio.com", "twilio"},
	{"sendgrid.net", "sendgrid"},
	{"bugsnag.com", "bugsnag"},
	{"rollbar.com", "rollbar"},
	{"mixpanel.com", "mixpanel"},
	{"amplitude.com", "amplitude"},
	{"logrocket.io", "logrocket"},
	{"logrocket.com", "logrocket"},
	{"fullstory.com", "fullstory"},
	{"hotjar.com", "hotjar"},
	{"google-analytics.com", "google-analytics"},
	{"googletagmanager.com", "google-tag-manager"},
	{"googletagservices.com", "google-tag-manager"},
	{"facebook.net", "facebook"},
	{"connect.facebook.net", "facebook"},
	{"auth0.com", "auth0"},
	{"cdn.auth0.com", "auth0"},
	{"firebaseapp.com", "firebase"},
	{"pendo.io", "pendo"},
	{"heapanalytics.com", "heap"},
	{"cdn.heapanalytics.com", "heap"},
	{"appcues.com", "appcues"},
	{"launchdarkly.com", "launchdarkly"},
	{"split.io", "split"},
	{"cloudflareinsights.com", "cloudflare"},
	{"recaptcha.net", "recaptcha"},
}

const (
	httpTimeout    = 10 * time.Second
	asnTimeout     = 3 * time.Second  // short timeout for non-critical external ASN lookup
	bodyPrefixBytes = 512 // enough to reach <meta name="generator"> in most pages
)

var httpClient = &http.Client{
	Timeout: httpTimeout,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return http.ErrUseLastResponse
		}
		return nil
	},
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // we want to observe misconfigs
	},
}

// Collect probes an asset and returns an Evidence packet for playbook matching.
// It never fails hard — partial evidence is returned on any error so matching
// can still proceed with whatever data was collected.
//
// hostname may be a bare hostname ("api.example.com") or a host:port pair
// ("api.example.com:3000"). When a port is specified, HTTP probing targets that
// port directly, enabling per-service fingerprinting for multi-service hosts.
// DNS operations always use the bare hostname.
func Collect(ctx context.Context, hostname string) playbook.Evidence {
	e := playbook.Evidence{
		Hostname: hostname,
		Headers:  make(map[string]string),
	}

	// Split host:port if present. DNS operations use bare host; HTTP uses full.
	bareHost := hostname
	if h, _, err := net.SplitHostPort(hostname); err == nil {
		bareHost = h
	}

	// DNS resolution + CNAME chain (always use bare hostname).
	// Must complete before ASN lookup (needs the resolved IP).
	resolveInto(ctx, bareHost, &e)

	// ASN lookup and HTTP probe are independent — run concurrently.
	// ASN only writes ASNNum/ASNOrg; HTTP writes all other fields — no overlap.
	var wg sync.WaitGroup
	if e.IP != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lookupASN(ctx, e.IP, &e)
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		probeHTTP(ctx, hostname, &e)
	}()
	wg.Wait()

	// Technology fingerprinting — derive structured signals from collected evidence.
	fingerprintTech(&e)

	// Fingerprint path probing — probe a curated set of technology-specific paths
	// to populate RespondingPaths, which enables path_responds playbook matching.
	// Only runs when we got an HTTP response (no point probing a dead host).
	// Skip when the bare host uses wildcard DNS — every path would respond,
	// making RespondingPaths completely unreliable as a technology signal.
	if e.StatusCode > 0 && !isWildcardDomain(ctx, bareHost) {
		e.RespondingPaths = probeFingerprintPaths(ctx, hostname)
		// Re-run auth system detection now that RespondingPaths is populated.
		fingerprintTech(&e)
	}

	// Robots.txt — disallowed paths reveal hidden admin/internal routes
	e.RobotsTxtPaths = probeRobotsTxt(ctx, hostname)

	// Favicon hash — fingerprints software and correlates assets
	e.FaviconHash = fetchFaviconHash(ctx, hostname)

	// DNS intelligence — TXT records (SPF, DMARC, verification tokens),
	// NS records (authoritative nameservers), and direct SPF IP ranges.
	// Use bare host for DNS queries; skip for port-specific assets (redundant).
	if bareHost == hostname {
		collectDNSIntel(ctx, bareHost, &e)
	}

	// JARM TLS fingerprint — only probe when we saw a TLS response.
	// For port-specific assets probe that specific port; default is 443.
	if e.StatusCode > 0 && e.CertIssuer != "" {
		e.JARMFingerprint = jarmFingerprint(ctx, hostname)
	}

	return e
}

// resolveInto fills IP and CNAMEChain via DNS lookup.
func resolveInto(ctx context.Context, hostname string, e *playbook.Evidence) {
	// Resolve CNAMEs
	cname, err := net.DefaultResolver.LookupCNAME(ctx, hostname)
	if err == nil {
		cname = strings.TrimSuffix(cname, ".")
		if !strings.EqualFold(cname, hostname) {
			e.CNAMEChain = append(e.CNAMEChain, cname)
			e.DNSSuffix = dnsSuffix(cname)
		}
	}

	// Resolve to IP
	addrs, err := net.DefaultResolver.LookupHost(ctx, hostname)
	if err == nil && len(addrs) > 0 {
		e.IP = addrs[0]
	}
}

// asnClient is a short-timeout client for the non-critical ip-api.com lookup.
// ASN data is low-value intel — we don't want to block 10s per asset if the
// external service is slow.
var asnClient = &http.Client{Timeout: asnTimeout}

// lookupASN queries ip-api.com for ASN/org info — keyless, free tier.
func lookupASN(ctx context.Context, ip string, e *playbook.Evidence) {
	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("https://ip-api.com/json/%s?fields=as,org", ip), nil)
	if err != nil {
		return
	}

	resp, err := asnClient.Do(req)
	if err != nil {
		return
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	s := string(body)

	// Quick JSON field extract without importing encoding/json
	e.ASNNum = jsonField(s, "as")
	e.ASNOrg = jsonField(s, "org")
}

// probeHTTP makes one HTTP GET and collects headers, title, and body prefix.
func probeHTTP(ctx context.Context, hostname string, e *playbook.Evidence) {
	for _, scheme := range []string{"https", "http"} {
		url := scheme + "://" + hostname + "/"
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon/1.0)")

		resp, err := httpClient.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		e.StatusCode = resp.StatusCode

		// Collect headers (lower-case keys)
		for k, vs := range resp.Header {
			if len(vs) > 0 {
				e.Headers[strings.ToLower(k)] = vs[0]
			}
		}

		// Extract software/version strings from well-known headers.
		e.ServiceVersions = parseServiceVersions(e.Headers)

		// TLS cert SANs
		if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
			cert := resp.TLS.PeerCertificates[0]
			e.CertIssuer = cert.Issuer.CommonName
			for _, san := range cert.DNSNames {
				e.CertSANs = append(e.CertSANs, san)
			}
		}

		// Redirect-target hostname — if the HTTP client followed redirects to a
		// different host, capture that hostname for downstream asset discovery.
		// resp.Request.URL reflects the final URL after all redirect hops.
		if finalHost := resp.Request.URL.Hostname(); finalHost != "" {
			bareOrig := hostname
			if h, _, err := net.SplitHostPort(hostname); err == nil {
				bareOrig = h
			}
			if !strings.EqualFold(finalHost, bareOrig) {
				e.SubdomainsInBody = append(e.SubdomainsInBody, strings.ToLower(finalHost))
			}
		}

		// HTTP/2 detection — resp.Proto is set by Go's http.Client from ALPN negotiation.
		e.HTTP2Enabled = resp.Proto == "HTTP/2.0"

		// WWW-Authenticate auth scheme — captured here because it's only present on
		// the initial response; probeHTTP stores all response headers in e.Headers
		// but we parse the scheme now for direct use in fingerprintTech / playbook matching.
		if wa := e.Headers["www-authenticate"]; wa != "" {
			e.AuthScheme = parseAuthScheme(wa)
		}

		// Body — read up to 8 KB; store 512 bytes for playbook body_contains matching,
		// but run full-body extraction before truncating so we don't miss signals.
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		fullBody := string(bodyBytes)
		if len(bodyBytes) > bodyPrefixBytes {
			e.Body512 = string(bodyBytes[:bodyPrefixBytes])
		} else {
			e.Body512 = fullBody
		}
		e.Title = extractTitle(fullBody)

		// Meta generator tag — WordPress, Joomla, Drupal embed version here
		if gen := extractMetaGenerator(fullBody); gen != "" {
			if e.ServiceVersions == nil {
				e.ServiceVersions = make(map[string]string)
			}
			e.ServiceVersions["generator_meta"] = gen
		}

		// Full-body signal extraction (requires >512 bytes; done before truncation).
		// Vendor signals from <script src> attributes.
		e.VendorSignals = extractScriptVendors(fullBody)
		// Subdomains of the root domain mentioned in the page source.
		// Use the bare hostname (strip port) as the base for root-domain derivation.
		bareForBody := hostname
		if h, _, err := net.SplitHostPort(hostname); err == nil {
			bareForBody = h
		}
		e.SubdomainsInBody = extractBodySubdomains(fullBody, bareForBody)

		// Web3 keyword signals — search the full body, not just the 512-byte prefix.
		// Contract addresses and web3 library references typically appear deeper in
		// the HTML/JS payload, well beyond the first 512 bytes.
		fullBodyLower := strings.ToLower(fullBody)
		web3Keywords := []string{
			// EVM / Ethereum
			"ethers", "web3.js", "viem", "wagmi", "walletconnect",
			"window.ethereum", "infura.io", "alchemyapi.io",
			"metamask", "coinbase wallet", "rainbow",
			// Solana
			"window.solana", "@solana/wallet-adapter", "solflare",
			"backpack", "phantom",
		}
		seenWeb3 := map[string]bool{}
		for _, kw := range web3Keywords {
			if strings.Contains(fullBodyLower, kw) {
				if !seenWeb3[kw] {
					seenWeb3[kw] = true
					e.Web3Signals = append(e.Web3Signals, kw)
				}
			}
		}
		// Wallet library signals — map pattern → canonical label for Web3Signals.
		// These use normalised label names and are deduped against already-appended values.
		walletLibs := []struct{ pattern, label string }{
			{"ethers", "ethers.js"},
			{"viem", "viem"},
			{"wagmi", "wagmi"},
			{"web3.js", "web3.js"},
			{"web3.min.js", "web3.js"},
			{"@rainbow-me", "rainbowkit"},
			{"connectkit", "connectkit"},
		}
		seenWalletLabel := map[string]bool{}
		for _, sig := range e.Web3Signals {
			seenWalletLabel[sig] = true
		}
		for _, wl := range walletLibs {
			if strings.Contains(fullBodyLower, wl.pattern) && !seenWalletLabel[wl.label] {
				seenWalletLabel[wl.label] = true
				e.Web3Signals = append(e.Web3Signals, wl.label)
			}
		}
		seen := map[string]bool{}
		// EVM contract addresses — scan the full body for 0x-prefixed 40-hex addresses.
		for _, m := range contractAddrRe.FindAllStringSubmatch(fullBody, -1) {
			if len(m) >= 2 {
				addr := strings.ToLower(m[1])
				if !seen[addr] {
					seen[addr] = true
					e.ContractAddresses = append(e.ContractAddresses, m[1])
				}
			}
		}

		return // stop after first successful scheme
	}
}

var metaGeneratorRe = regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']|<meta[^>]+content=["']([^"']+)["'][^>]+name=["']generator["']`)

// extractMetaGenerator returns the content of <meta name="generator">.
// Handles both attribute orderings: name-first and content-first.
func extractMetaGenerator(body string) string {
	m := metaGeneratorRe.FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	// One of the two capture groups will be non-empty
	if m[1] != "" {
		return strings.TrimSpace(m[1])
	}
	return strings.TrimSpace(m[2])
}

// parseAuthScheme returns a normalized auth scheme from a WWW-Authenticate header value.
// Returns one of: "negotiate", "ntlm", "bearer", "basic", "digest", "aws", or "".
func parseAuthScheme(wa string) string {
	lower := strings.ToLower(strings.TrimSpace(wa))
	switch {
	case strings.HasPrefix(lower, "negotiate"):
		return "negotiate" // Kerberos / SPNEGO — Windows domain environments
	case strings.HasPrefix(lower, "ntlm"):
		return "ntlm"
	case strings.HasPrefix(lower, "bearer"):
		return "bearer" // OAuth / JWT
	case strings.HasPrefix(lower, "basic"):
		return "basic"
	case strings.HasPrefix(lower, "digest"):
		return "digest"
	case strings.HasPrefix(lower, "aws4-hmac-sha256"):
		return "aws"
	}
	return ""
}

// extractScriptVendors scans <script src="..."> tags in a page body and
// returns vendor names for any recognised third-party domains found.
func extractScriptVendors(body string) []string {
	matches := scriptSrcRe.FindAllStringSubmatch(body, -1)
	seen := map[string]bool{}
	var vendors []string
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		src := strings.ToLower(m[1])
		for _, p := range vendorDomainPatterns {
			if strings.Contains(src, p.domain) && !seen[p.vendor] {
				seen[p.vendor] = true
				vendors = append(vendors, p.vendor)
			}
		}
	}
	return vendors
}

// extractBodySubdomains scans a full page body for hostnames that share the
// same 2-label root as the given hostname. These are subdomains that were
// linked or referenced on the page but may not appear in passive DNS enumeration.
// Returns at most 20 unique results to bound the discovery expansion.
func extractBodySubdomains(body, hostname string) []string {
	root := baseDomain(hostname)
	if root == "" || root == hostname {
		return nil // single-label or already at root — nothing to extract
	}
	// Build a pattern that matches label.label...root without matching bare root.
	reStr := `(?i)(?:^|[\s"'=(,])([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)*\.` + regexp.QuoteMeta(root) + `)(?:$|[\s"'/?,)])`
	re, err := regexp.Compile(reStr)
	if err != nil {
		return nil
	}
	matches := re.FindAllStringSubmatch(body, -1)
	seen := map[string]bool{strings.ToLower(hostname): true, root: true}
	var result []string
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		sub := strings.ToLower(strings.TrimSpace(m[1]))
		if seen[sub] || sub == root {
			continue
		}
		seen[sub] = true
		result = append(result, sub)
		if len(result) >= 20 {
			break
		}
	}
	return result
}

// extractCSPVendors scans a Content-Security-Policy header value for known
// third-party domain patterns and returns vendor names.
func extractCSPVendors(csp string) []string {
	lower := strings.ToLower(csp)
	seen := map[string]bool{}
	var vendors []string
	for _, p := range vendorDomainPatterns {
		if strings.Contains(lower, p.domain) && !seen[p.vendor] {
			seen[p.vendor] = true
			vendors = append(vendors, p.vendor)
		}
	}
	return vendors
}

// baseDomain returns the last two dot-separated labels of a hostname.
// "api.example.com" → "example.com", "example.com" → "example.com", "localhost" → "".
func baseDomain(hostname string) string {
	// Strip port if present
	if h, _, err := net.SplitHostPort(hostname); err == nil {
		hostname = h
	}
	parts := strings.Split(strings.ToLower(hostname), ".")
	if len(parts) < 2 {
		return ""
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// fingerprintPaths is the curated list of technology-specific paths probed on
// every asset to populate RespondingPaths. These are chosen because each path
// is strongly associated with a single product — a 200/401/403 response is
// high-confidence evidence that the product is running.
//
// Rules for inclusion:
//   - Path must appear in at least one playbook's path_responds match rule, OR
//     be a canonical health/status endpoint for a widely-deployed product.
//   - Path must not be a generic word (e.g. "/admin") that appears on thousands
//     of unrelated products — those stay in the deep dirbust dictionary.
//   - Total list must stay under ~80 paths; each path is one HTTP HEAD request.
var fingerprintPaths = []string{
	// ── Spring Boot / Java ─────────────────────────────────────────────────
	"/actuator", "/actuator/health", "/actuator/env", "/actuator/mappings",
	"/j_spring_security_check",
	// ── HashiCorp Vault ────────────────────────────────────────────────────
	"/v1/sys/health", "/v1/sys/seal-status",
	// ── Keycloak / OIDC ───────────────────────────────────────────────────
	"/auth/realms", "/realms", "/auth/admin",
	"/.well-known/openid-configuration",
	"/.well-known/oauth-authorization-server",
	// ── Elasticsearch / OpenSearch ─────────────────────────────────────────
	"/_cat/indices", "/_cluster/health", "/_nodes",
	// ── GitLab ────────────────────────────────────────────────────────────
	"/-/health", "/-/readiness", "/-/healthy", "/lab",
	// ── Grafana ───────────────────────────────────────────────────────────
	"/api/health",
	// ── Prometheus ────────────────────────────────────────────────────────
	"/targets", "/metrics",
	// ── Airflow ───────────────────────────────────────────────────────────
	"/api/v1/health", "/api/v1/dags",
	// ── Jupyter ───────────────────────────────────────────────────────────
	"/api/kernels", "/api/contents",
	// ── Hasura ────────────────────────────────────────────────────────────
	"/v1/graphql", "/v1/metadata",
	// ── Traefik ───────────────────────────────────────────────────────────
	"/api/rawdata", "/api/overview", "/api/entrypoints",
	// ── Cassandra Reaper ──────────────────────────────────────────────────
	"/api/v0/ops/node/status",
	// ── Kafka REST / Confluent ─────────────────────────────────────────────
	"/topics", "/v3/clusters",
	// ── Splunk ────────────────────────────────────────────────────────────
	"/services/server/info", "/en-US/account/login",
	// ── InfluxDB ──────────────────────────────────────────────────────────
	"/ping", "/query", "/health",
	// ── WordPress ─────────────────────────────────────────────────────────
	"/wp-login.php", "/wp-json", "/wp-admin",
	// ── Laravel / Telescope ───────────────────────────────────────────────
	"/telescope", "/horizon",
	// ── Rails ─────────────────────────────────────────────────────────────
	"/rails/info/properties", "/cable",
	// ── Django ────────────────────────────────────────────────────────────
	"/api/instance",
	// ── Ghost CMS ─────────────────────────────────────────────────────────
	"/ghost", "/ghost/api",
	// ── pgAdmin ───────────────────────────────────────────────────────────
	"/pgadmin4", "/pgadmin4/", "/pgadmin",
	// ── phpMyAdmin / Adminer ──────────────────────────────────────────────
	"/phpmyadmin", "/phpmyadmin/", "/adminer", "/adminer.php", "/pma",
	// ── OAuth endpoints ───────────────────────────────────────────────────
	"/oauth/authorize", "/oauth2/authorize",
	// ── AI / LLM ──────────────────────────────────────────────────────────
	"/v1/models", "/v1/chat/completions", "/api/tags",
	// ── Kubernetes / cluster APIs ─────────────────────────────────────────
	"/clusters",
	// ── Ignition (Laravel debug) ──────────────────────────────────────────
	"/_ignition",
	// ── Drupal ────────────────────────────────────────────────────────────
	"/sites/default",
	// ── n8n workflow automation (CVE-2026-21858, CVE-2025-68613) ─────────
	"/healthz", "/api/v1/settings",
	// ── Langflow AI pipeline (CVE-2026-33017) ─────────────────────────────
	"/api/v1/version", "/api/v1/flows",
	// ── BeyondTrust Remote Support (CVE-2026-1731) ────────────────────────
	"/appliance/api/info",
	// ── Nginx-UI (CVE-2026-27944) ─────────────────────────────────────────
	"/api/backup",
	// ── SolarWinds Web Help Desk (CVE-2025-26399) ─────────────────────────
	"/helpdesk/WebObjects/Helpdesk.woa/",
	// ── Ivanti Endpoint Manager (CVE-2026-1603) ───────────────────────────
	"/ams/",
	// ── Omnissa / VMware Workspace ONE (CVE-2021-22054) ───────────────────
	"/catalog-portal/ui",
	// ── Laravel Livewire (CVE-2025-54068) ─────────────────────────────────
	"/livewire/update",
	// ── Citrix NetScaler ADC/Gateway (CVE-2025-5777 CitrixBleed 2) ────────
	"/vpn/index.html", "/p/u/doAuthentication.do",
	// ── HPE OneView (CVE-2025-37164 pre-auth RCE, CVSS 10.0) ──────────────
	"/rest/version",
	// ── FortiGate SSL VPN / FortiOS (CVE-2026-24858 SSO bypass, KEV) ──────
	"/remote/login",
	// ── FortiWeb WAF (CVE-2025-64446 path traversal auth bypass, 9.8) ─────
	"/api/v2.0/",
	// ── Cisco ASA / FTD AnyConnect (CVE-2025-20333/20362 chained RCE) ─────
	"/+CSCOE+/logon.html",
	// ── Ivanti EPMM MDM (CVE-2026-1281/1340 pre-auth OS cmd injection) ────
	"/mifs/c/appstore/fob/", "/mifs/c/aftstore/fob/",
	// ── MCP server (Model Context Protocol) SSE transport ─────────────────
	"/sse",
	// ── Oracle WebLogic admin console (CVE-2026-21962, CVSS 10.0) ─────────
	"/console/",
	// ── Oracle Identity Manager ────────────────────────────────────────────
	"/identity/",
	// ── Cisco Firepower Management Center (CVE-2026-20131, CVSS 10.0) ─────
	"/login",
	// ── Ivanti Connect Secure / Pulse Secure SSL VPN (CVE-2025-22457, KEV) ─
	"/dana-na/auth/url_default/welcome.cgi", "/dana-na/",
	// ── Palo Alto PAN-OS / GlobalProtect (CVE-2025-0108, KEV) ────────────
	"/global-protect/login.esp", "/php/login.php",
	// ── Veeam Backup & Replication (CVE-2025-23120, CVSS 9.9, KEV) ───────
	"/api/v1/serverInfo",
	// ── Apache Tomcat (CVE-2025-24813, CVSS 9.8, KEV) ────────────────────
	"/manager/html", "/manager/status",
	// ── Zabbix monitoring (CVE-2024-22120, CVSS 9.9) ─────────────────────
	"/api_jsonrpc.php",
	// ── Wazuh SIEM/XDR API ────────────────────────────────────────────────
	"/api/v2/manager/info",
	// ── Next.js (CVE-2025-29927, CVSS 9.1) ───────────────────────────────
	"/_next/static/chunks/main.js",
	// ── Vite dev server (exposed dev/staging) ────────────────────────────
	"/__vite_ping",
	// ── F5 BIG-IP (CVE-2022-1388 iControl REST auth bypass, CVSS 9.8) ───
	"/tmui/login.jsp", "/mgmt/shared/authn/login",
	// ── SonicWall (CVE-2024-40766, CVSS 9.3 — ransomware campaigns) ─────
	"/auth.html",
	// ── Check Point (CVE-2024-24919 arbitrary file read, CVSS 8.6) ──────
	"/clients/MyCRL",
	// ── Juniper J-Web (CVE-2023-36845 PHP env var injection, CVSS 9.8) ──
	"/cgi-bin/webauth.pl",
	// ── SOHO router fingerprinting ────────────────────────────────────────
	"/HNAP1/",              // D-Link HNAP SOAP endpoint (reliable D-Link fingerprint)
	"/currentsetting.htm", // Netgear model info without auth
	// ── SAP NetWeaver (CVE-2025-31324, CVSS 10.0, KEV — mass exploitation)
	"/developmentserver/metadatauploader", "/irj/portal",
	// ── IP camera fingerprinting (Hikvision, generic CGI-based cameras) ───
	"/ISAPI/System/deviceInfo", // Hikvision ISAPI — camera-specific, never appears on other products
	"/cgi-bin/snapshot.cgi",    // Generic IP camera snapshot CGI — very high precision signal
	// ── Next.js ──────────────────────────────────────────────────────────
	"/_next/static/chunks/webpack.js", // Next.js webpack chunk (alternate to main.js)
	// ── Craft CMS ────────────────────────────────────────────────────────
	"/actions/users/login",     // Craft CMS action URL pattern
	"/index.php?p=admin/login", // Craft CMS admin via index.php routing
	// ── Ollama LLM (generate endpoint) ───────────────────────────────────
	"/api/generate", // Ollama generate — distinct from OpenAI-compat /v1/chat/completions
	// ── Redis Insight web UI ─────────────────────────────────────────────
	"/api/info", // Redis Insight REST info endpoint
	// ── Portainer container management ───────────────────────────────────
	"/api/settings", "/api/status", // Portainer REST API paths
	// ── Kibana legacy paths (pre-8.x navigation) ─────────────────────────
	"/app/home", "/app/kibana", // Kibana home/legacy redirect paths
	// ── Envoy admin interface ─────────────────────────────────────────────
	"/config_dump", "/stats", // Envoy admin API — unique to Envoy proxy
	// ── Hasura GraphQL Engine console ────────────────────────────────────
	"/console", // Hasura console (distinct from /v1/graphql health path)
	// ── Traefik dashboard ─────────────────────────────────────────────────
	"/dashboard", // Traefik dashboard (also used by api/overview but this is the UI)
	// ── Apache Tomcat Host Manager ────────────────────────────────────────
	"/host-manager/html", // Tomcat host-manager app — very specific
	// ── Cisco IOS HTTP web interface ─────────────────────────────────────
	"/level/15/exec/-/show/version", // Cisco IOS EXEC-level HTTP interface
	// ── Laravel Livewire ─────────────────────────────────────────────────
	"/livewire/upload-file", // Livewire file upload endpoint
	// ── Ubiquiti UniFi controller ─────────────────────────────────────────
	"/manage/account/login", // UniFi controller login page
	// ── phpMyAdmin alternate path ─────────────────────────────────────────
	"/mysql", // phpMyAdmin alias path (common in shared hosting)
	// ── Rails info endpoint ───────────────────────────────────────────────
	"/rails/info", // Rails info controller (less specific than /rails/info/properties)
	// ── API documentation discovery ──────────────────────────────────────
	"/swagger.json", "/openapi.json", // OpenAPI/Swagger spec endpoints
	"/graphql", // Generic GraphQL endpoint (distinct from /v1/graphql Hasura path)
	// ── MikroTik RouterOS web interface ──────────────────────────────────
	"/webfig/", // MikroTik WebFig UI — product-unique path
	// ── Zabbix monitoring ─────────────────────────────────────────────────
	"/zabbix/", // Zabbix web UI root path
}

// isWildcardDomain returns true when the bare hostname has wildcard DNS configured.
// A wildcard domain returns a valid A record for any random subdomain query, making
// probeFingerprintPaths unreliable (every path would appear to respond).
func isWildcardDomain(ctx context.Context, hostname string) bool {
	// Probe a nonsense subdomain — if it resolves, wildcard DNS is in use.
	probe := "beacon-wc-probe-xqzjmkpv." + hostname
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, probe)
	return err == nil && len(addrs) > 0
}

// probeFingerprintPaths probes each path in fingerprintPaths concurrently and
// returns those that responded with a non-404, non-5xx status code.
// A 401 or 403 still confirms the path exists (auth-gated endpoint).
func probeFingerprintPaths(ctx context.Context, hostname string) []string {
	// Determine scheme from a quick probe (reuse whatever worked in probeHTTP).
	scheme := "https"
	checkClient := &http.Client{
		Timeout: 3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}
	testReq, err := http.NewRequestWithContext(ctx, http.MethodHead, "https://"+hostname, nil)
	if err == nil {
		if resp, err2 := checkClient.Do(testReq); err2 != nil {
			scheme = "http"
		} else {
			resp.Body.Close()
		}
	}

	base := scheme + "://" + hostname

	var (
		mu      sync.Mutex
		found   []string
		wg      sync.WaitGroup
		sem     = make(chan struct{}, 10) // max 10 concurrent probes
	)

	for _, path := range fingerprintPaths {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			req, err := http.NewRequestWithContext(ctx, http.MethodHead, base+p, nil)
			if err != nil {
				return
			}
			resp, err := checkClient.Do(req)
			if err != nil {
				return
			}
			resp.Body.Close()

			// Accept any response that proves the path exists:
			// 2xx, 3xx redirects, 401 (auth required), 403 (forbidden).
			// Reject 404 (not found) and 5xx (server error / not this product).
			sc := resp.StatusCode
			if sc == http.StatusNotFound || sc >= 500 {
				return
			}
			mu.Lock()
			found = append(found, p)
			mu.Unlock()
		}(path)
	}
	wg.Wait()
	return found
}

// probeRobotsTxt fetches /robots.txt and returns all Disallow paths.
// These frequently reveal admin panels, internal APIs, and backup paths.
func probeRobotsTxt(ctx context.Context, hostname string) []string {
	var paths []string
	seen := map[string]bool{}

	for _, scheme := range []string{"https", "http"} {
		url := scheme + "://" + hostname + "/robots.txt"
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon/1.0)")
		resp, err := httpClient.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
		resp.Body.Close()
		for _, p := range parseRobotsTxtBody(string(body)) {
			if !seen[p] {
				seen[p] = true
				paths = append(paths, p)
			}
		}
		return paths // stop on first successful fetch
	}
	return paths
}

// parseRobotsTxtBody extracts Disallow paths from a robots.txt body.
// Skips wildcards, the root path, and empty entries.
func parseRobotsTxtBody(body string) []string {
	var paths []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(strings.ToLower(line), "disallow:") {
			continue
		}
		path := strings.TrimSpace(line[len("disallow:"):])
		if path == "" || path == "/" || strings.Contains(path, "*") {
			continue
		}
		paths = append(paths, path)
	}
	return paths
}

// fetchFaviconHash fetches /favicon.ico and returns an FNV-1a hash of its
// base64 encoding. Equal hashes across different assets indicate the same
// software, enabling technology fingerprinting and asset correlation.
// Returns empty string if the favicon cannot be fetched.
func fetchFaviconHash(ctx context.Context, hostname string) string {
	for _, scheme := range []string{"https", "http"} {
		url := scheme + "://" + hostname + "/favicon.ico"
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon/1.0)")
		resp, err := httpClient.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 100*1024)) // 100 KB max
		resp.Body.Close()
		if err != nil || len(data) == 0 {
			continue
		}
		encoded := base64.StdEncoding.EncodeToString(data)
		h := fnv.New32a()
		h.Write([]byte(encoded))
		return fmt.Sprintf("%d", h.Sum32())
	}
	return ""
}

// dnsSuffix returns the last two labels of a hostname (e.g. ".cloudfront.net").
func dnsSuffix(hostname string) string {
	parts := strings.Split(strings.ToLower(hostname), ".")
	if len(parts) < 2 {
		return ""
	}
	return "." + strings.Join(parts[len(parts)-2:], ".")
}

// extractTitle pulls <title>...</title> from HTML.
// The byte offsets derived from lower are used to slice body. This is correct
// because <title> and </title> are pure ASCII — strings.ToLower does not change
// the byte length of any ASCII character, so byte positions in lower for ASCII
// tags are identical to byte positions in body. Non-ASCII characters within
// the title content are preserved verbatim from body.
func extractTitle(body string) string {
	lower := strings.ToLower(body)
	start := strings.Index(lower, "<title>")
	if start == -1 {
		return ""
	}
	start += len("<title>")
	end := strings.Index(lower[start:], "</title>")
	if end == -1 {
		return ""
	}
	return strings.TrimSpace(body[start : start+end])
}

// parseServiceVersions extracts software/version strings from HTTP response headers.
// Keys are stable role names; values are the raw header strings (e.g. "Apache/2.4.51").
// Returns nil (not an empty map) when no version signals are present.
func parseServiceVersions(headers map[string]string) map[string]string {
	versions := make(map[string]string)

	// Server: Apache/2.4.51 (Ubuntu)  |  nginx/1.24.0  |  Microsoft-IIS/10.0
	if v := headers["server"]; v != "" {
		versions["web_server"] = v
	}
	// X-Powered-By: PHP/8.1.12  |  Express  |  ASP.NET
	if v := headers["x-powered-by"]; v != "" {
		versions["powered_by"] = v
	}
	// X-AspNet-Version: 4.0.30319
	if v := headers["x-aspnet-version"]; v != "" {
		versions["aspnet_version"] = v
	}
	// X-AspNetMvc-Version: 5.2
	if v := headers["x-aspnetmvc-version"]; v != "" {
		versions["aspnetmvc_version"] = v
	}
	// X-Generator: Drupal 10 (https://www.drupal.org)
	if v := headers["x-generator"]; v != "" {
		versions["generator"] = v
	}
	// X-Confluence-Request-Time — Atlassian Confluence
	if headers["x-confluence-request-time"] != "" {
		versions["platform"] = "confluence"
	}
	// X-Jira-Request-Id — Atlassian Jira
	if headers["x-jira-request-id"] != "" {
		versions["platform"] = "jira"
	}
	// X-Wp-Total — WordPress REST API (appears on /wp-json responses)
	if headers["x-wp-total"] != "" {
		versions["platform"] = "wordpress"
	}
	// X-Drupal-Cache — Drupal
	if headers["x-drupal-cache"] != "" || headers["x-drupal-dynamic-cache"] != "" {
		versions["platform"] = "drupal"
	}
	// X-Shopify-Stage — Shopify
	if headers["x-shopify-stage"] != "" || headers["x-shopify-request-id"] != "" {
		versions["platform"] = "shopify"
	}
	// X-Ghost-Cache — Ghost CMS
	if headers["x-ghost-cache-status"] != "" {
		versions["platform"] = "ghost"
	}

	// Cookie name fingerprinting — session cookie names reliably identify platforms.
	// Set-Cookie header may contain multiple values; we check for known prefixes.
	if v := headers["set-cookie"]; v != "" {
		cookieTech := cookieTechHint(v)
		if cookieTech != "" {
			versions["cookie_tech"] = cookieTech
		}
	}

	if len(versions) == 0 {
		return nil
	}
	return versions
}

// cookieTechHint returns a technology hint based on well-known session cookie names.
// These cookie names are strong signals: frameworks set them by default and they
// rarely change unless deliberately configured otherwise.
func cookieTechHint(setCookieHeader string) string {
	lower := strings.ToLower(setCookieHeader)
	switch {
	case strings.Contains(lower, "phpsessid"):
		return "PHP"
	case strings.Contains(lower, "jsessionid"):
		return "Java (Servlet/JSP)"
	case strings.Contains(lower, "asp.net_sessionid"):
		return "ASP.NET"
	case strings.Contains(lower, "_rails"):
		return "Ruby on Rails"
	case strings.Contains(lower, "laravel_session"):
		return "Laravel (PHP)"
	case strings.Contains(lower, "django"):
		return "Django (Python)"
	case strings.Contains(lower, "express.sid") || strings.Contains(lower, "connect.sid"):
		return "Node.js (Express)"
	case strings.Contains(lower, "cfid") || strings.Contains(lower, "cftoken"):
		return "ColdFusion"
	case strings.Contains(lower, "wp-settings"):
		return "WordPress"
	}
	return ""
}

// fingerprintTech derives structured technology signals from already-collected
// Evidence fields (headers, body, hostname, responding paths) and writes them
// into the new fingerprinting fields on the Evidence struct.
// It is called once after probeHTTP completes.
func fingerprintTech(e *playbook.Evidence) {
	h := e.Headers // lower-case keys, already normalised by probeHTTP
	body := strings.ToLower(e.Body512)
	hostname := strings.ToLower(e.Hostname)

	// ── CloudProvider ────────────────────────────────────────────────────────
	switch {
	case h["cf-ray"] != "":
		e.CloudProvider = "cloudflare"
	case h["x-vercel-id"] != "":
		e.CloudProvider = "vercel"
	case h["x-nf-request-id"] != "":
		e.CloudProvider = "netlify"
	case h["x-amz-cf-id"] != "":
		e.CloudProvider = "aws" // CloudFront
	case h["x-amzn-requestid"] != "" || h["x-amz-apigw-id"] != "":
		e.CloudProvider = "aws" // Lambda / API Gateway
	case strings.Contains(strings.ToLower(h["server"]), "amazons3"):
		e.CloudProvider = "aws" // S3
	case h["x-azure-ref"] != "" || h["x-ms-request-id"] != "":
		e.CloudProvider = "azure"
	case strings.HasPrefix(h["x-goog-request-id"], "") && h["x-goog-request-id"] != "":
		e.CloudProvider = "gcp"
	case strings.Contains(strings.ToLower(h["via"]), "google"):
		e.CloudProvider = "gcp"
	case strings.Contains(strings.ToLower(h["via"]), "vegur"):
		e.CloudProvider = "heroku"
	default:
		// scan all headers for x-goog- prefix
		for k := range h {
			if strings.HasPrefix(k, "x-goog-") {
				e.CloudProvider = "gcp"
				break
			}
		}
	}

	// ── ProxyType + InfraLayer ────────────────────────────────────────────────
	// ProxyType is the vendor/product name of the detected infrastructure layer.
	// InfraLayer is its role: cdn_edge | api_gateway | load_balancer | service_mesh | reverse_proxy.
	// Detection priority: more-specific signals (unique headers) override less-specific (Server header).
	serverLower := strings.ToLower(h["server"])
	viaLower := strings.ToLower(h["via"])
	xfwdSrvLower := strings.ToLower(h["x-forwarded-server"])
	switch {
	// ── Service mesh sidecars ─────────────────────────────────────────────────
	case serverLower == "envoy" || h["x-envoy-upstream-service-time"] != "" || h["x-envoy-decorator-operation"] != "":
		e.ProxyType = "envoy"
		e.InfraLayer = "service_mesh"
	case h["l5d-dst-canonical"] != "" || h["l5d-proxy-error"] != "" || strings.Contains(serverLower, "linkerd"):
		// Linkerd service mesh: l5d-* headers are Linkerd-specific
		e.ProxyType = "linkerd"
		e.InfraLayer = "service_mesh"
	case h["x-consul-index"] != "" || strings.Contains(serverLower, "consul"):
		// Consul Connect / service mesh
		e.ProxyType = "consul"
		e.InfraLayer = "service_mesh"
	// ── API gateways ──────────────────────────────────────────────────────────
	case h["x-kong-request-id"] != "" || h["x-kong-proxy-latency"] != "" || h["x-kong-upstream-latency"] != "":
		e.ProxyType = "kong"
		e.InfraLayer = "api_gateway"
	case strings.Contains(viaLower, "traefik") || strings.Contains(xfwdSrvLower, "traefik") || strings.Contains(serverLower, "traefik"):
		e.ProxyType = "traefik"
		e.InfraLayer = "api_gateway"
	case (h["x-amzn-requestid"] != "" || h["x-amzn-trace-id"] != "") && h["x-amz-apigw-id"] != "":
		// AWS API Gateway: combination of x-amzn-requestid + x-amz-apigw-id is unique
		e.ProxyType = "aws_api_gateway"
		e.InfraLayer = "api_gateway"
	case h["apim-request-id"] != "" || h["x-ms-gateway-service-instancid"] != "" || strings.Contains(serverLower, "api-management"):
		// Azure API Management
		e.ProxyType = "azure_apim"
		e.InfraLayer = "api_gateway"
	case h["x-apigee-fault-code"] != "" || h["x-apigee-fault-source"] != "" || strings.Contains(serverLower, "apigee"):
		// Google Cloud Apigee
		e.ProxyType = "apigee"
		e.InfraLayer = "api_gateway"
	case h["x-tyk-api-expires"] != "" || h["x-tyk-node-id"] != "":
		// Tyk API Gateway
		e.ProxyType = "tyk"
		e.InfraLayer = "api_gateway"
	// ── Load balancers ────────────────────────────────────────────────────────
	case strings.Contains(serverLower, "haproxy") || haproxyHeader(h):
		e.ProxyType = "haproxy"
		e.InfraLayer = "load_balancer"
	case h["x-wa-info"] != "" || strings.Contains(serverLower, "bigip") || strings.Contains(h["set-cookie"], "BIGipServer"):
		// F5 BIG-IP: X-WA-Info header or BIGipServer cookie name
		e.ProxyType = "f5"
		e.InfraLayer = "load_balancer"
	case strings.Contains(serverLower, "netscaler") || h["ns_af_"] != "" || strings.Contains(viaLower, "netscaler"):
		// Citrix NetScaler / ADC
		e.ProxyType = "citrix_netscaler"
		e.InfraLayer = "load_balancer"
	case h["x-amz-lb-id"] != "" || strings.Contains(serverLower, "awselb") || strings.Contains(serverLower, "awsalb"):
		// AWS Elastic/Application Load Balancer
		e.ProxyType = "aws_elb"
		e.InfraLayer = "load_balancer"
	// ── CDN edges ─────────────────────────────────────────────────────────────
	case h["x-varnish"] != "" || strings.Contains(viaLower, "varnish") || strings.Contains(serverLower, "varnish"):
		e.ProxyType = "varnish"
		e.InfraLayer = "cdn_edge"
	case h["x-check-cacheable"] != "" || h["x-akamai-request-id"] != "" || strings.Contains(viaLower, "akamai"):
		// Akamai CDN
		e.ProxyType = "akamai"
		e.InfraLayer = "cdn_edge"
	case h["x-served-by"] != "" && (strings.Contains(strings.ToLower(h["x-served-by"]), "cache") || h["fastly-restarts"] != ""):
		// Fastly CDN: x-served-by with cache node or fastly-restarts header
		e.ProxyType = "fastly"
		e.InfraLayer = "cdn_edge"
	case strings.Contains(viaLower, "squid") || strings.Contains(serverLower, "squid"):
		// Squid forward/reverse proxy / caching
		e.ProxyType = "squid"
		e.InfraLayer = "cdn_edge"
	case strings.Contains(viaLower, "apache traffic server") || strings.Contains(serverLower, "ats"):
		// Apache Traffic Server — used by Yahoo, LinkedIn, CDNs
		e.ProxyType = "ats"
		e.InfraLayer = "cdn_edge"
	case strings.Contains(viaLower, "keycdn") || strings.Contains(serverLower, "keycdn"):
		e.ProxyType = "keycdn"
		e.InfraLayer = "cdn_edge"
	case strings.Contains(serverLower, "bunnycdn") || h["bunny-request-id"] != "":
		// BunnyCDN
		e.ProxyType = "bunnycdn"
		e.InfraLayer = "cdn_edge"
	case strings.Contains(serverLower, "sucuri"):
		e.ProxyType = "sucuri"
		e.InfraLayer = "cdn_edge"
	// ── Reverse proxies ───────────────────────────────────────────────────────
	case strings.Contains(serverLower, "caddy"):
		e.ProxyType = "caddy"
		e.InfraLayer = "reverse_proxy"
	case strings.Contains(serverLower, "nginx"):
		e.ProxyType = "nginx"
		e.InfraLayer = "reverse_proxy"
	case strings.Contains(serverLower, "apache") && (h["x-forwarded-for"] != "" || h["x-real-ip"] != ""):
		// Apache acting as reverse proxy (mod_proxy signals)
		e.ProxyType = "apache"
		e.InfraLayer = "reverse_proxy"
	}

	// ── Framework ────────────────────────────────────────────────────────────
	xpbLower := strings.ToLower(h["x-powered-by"])
	setCookieLower := strings.ToLower(h["set-cookie"])
	switch {
	case strings.Contains(body, "__next_data__") || strings.Contains(xpbLower, "next.js"):
		e.Framework = "nextjs"
	case strings.Contains(body, "__nuxt__"):
		e.Framework = "nuxt"
	case strings.Contains(body, "__sveltekit") || strings.Contains(body, "_sveltekit"):
		e.Framework = "sveltekit"
	case strings.Contains(body, "astro.glob") || strings.Contains(body, "data-astro-"):
		e.Framework = "astro"
	case strings.Contains(xpbLower, "phusion passenger") || strings.Contains(setCookieLower, "_rails"):
		e.Framework = "rails"
	case strings.Contains(setCookieLower, "csrftoken") && strings.Contains(setCookieLower, "django"):
		e.Framework = "django"
	case h["x-application-context"] != "" || strings.Contains(body, "whitelabel error page"):
		e.Framework = "spring"
	case strings.Contains(setCookieLower, "laravel_session") || strings.Contains(xpbLower, "laravel"):
		e.Framework = "laravel"
	case xpbLower == "express":
		e.Framework = "express"
	}

	// ── Platform detection from body (products not captured by Framework) ────
	// These are specific products rather than web frameworks. We set them in
	// ServiceVersions["platform"] so they don't collide with the Framework field.
	// Only set when the header-based detection in parseServiceVersions didn't
	// already identify a platform (avoid overwriting a more-specific signal).
	if e.ServiceVersions == nil {
		e.ServiceVersions = make(map[string]string)
	}
	if _, alreadySet := e.ServiceVersions["platform"]; !alreadySet {
		switch {
		case strings.Contains(body, "dashboard [jenkins]") || strings.Contains(body, "jenkins ver.") ||
			strings.Contains(body, "/static/f1d3ef3f/images/jenkins") ||
			strings.Contains(strings.ToLower(h["x-jenkins"]), "") && h["x-jenkins"] != "":
			e.ServiceVersions["platform"] = "jenkins"
		case strings.Contains(body, "ajs-product-name") && strings.Contains(body, "confluence"):
			e.ServiceVersions["platform"] = "confluence"
		case strings.Contains(body, "ajs-product-name") && strings.Contains(body, "jira"):
			e.ServiceVersions["platform"] = "jira"
		case strings.Contains(body, "swagger-ui-bundle.js") || strings.Contains(body, "swagger-ui.css") ||
			strings.Contains(body, "swagger-ui/swagger-ui"):
			e.ServiceVersions["platform"] = "swagger-ui"
		case strings.Contains(body, "grafana") && strings.Contains(body, "app-grafana"):
			e.ServiceVersions["platform"] = "grafana"
		case strings.Contains(body, "kibana") && (strings.Contains(body, "kbn-") || strings.Contains(body, "__kbnBootstrap")):
			e.ServiceVersions["platform"] = "kibana"
		case strings.Contains(body, "prometheus") && strings.Contains(body, "/graph"):
			e.ServiceVersions["platform"] = "prometheus"
		case strings.Contains(body, "gitea") || strings.Contains(body, "go-gitea"):
			e.ServiceVersions["platform"] = "gitea"
		case strings.Contains(body, "gitlab") && strings.Contains(body, "gon.gitlab"):
			e.ServiceVersions["platform"] = "gitlab"
		case strings.Contains(body, "rangitaki") || (strings.Contains(body, "nextcloud") && strings.Contains(body, "server")):
			e.ServiceVersions["platform"] = "nextcloud"
		}
	}
	// Jenkins also exposes an X-Jenkins header — detect regardless of body.
	if h["x-jenkins"] != "" && e.ServiceVersions["platform"] == "" {
		e.ServiceVersions["platform"] = "jenkins"
	}

	// ── AuthSystem ───────────────────────────────────────────────────────────
	for _, path := range e.RespondingPaths {
		pl := strings.ToLower(path)
		if strings.Contains(pl, "/saml") {
			e.AuthSystem = "saml"
			break
		}
		if strings.Contains(pl, "/realms/") {
			e.AuthSystem = "keycloak"
			break
		}
		if pl == "/.well-known/openid-configuration" {
			e.AuthSystem = "oidc"
			break
		}
	}
	if e.AuthSystem == "" {
		switch {
		case strings.Contains(body, "okta.com") || strings.Contains(body, "okta-hosted-login") ||
			strings.Contains(hostname, "okta"):
			e.AuthSystem = "okta"
		case strings.Contains(body, "auth0.com") || strings.Contains(body, "auth0"):
			e.AuthSystem = "auth0"
		case strings.Contains(body, "/realms/") && strings.Contains(body, "keycloak"):
			e.AuthSystem = "keycloak"
		case strings.Contains(body, "cognito") || strings.Contains(body, "aws.amazon.com/cognito"):
			e.AuthSystem = "cognito"
		// samlrequest and samlresponse — body is already lowercased
		case strings.Contains(body, "samlrequest") || strings.Contains(body, "samlresponse"):
			e.AuthSystem = "saml"
		case strings.Contains(body, "ldap"):
			e.AuthSystem = "ldap"
		// Form-based password auth — <input type="password"> indicates a login form
		case strings.Contains(body, `type="password"`) || strings.Contains(body, `type='password'`):
			e.AuthSystem = "form"
		// Solana wallet auth — window.solana or Solana wallet-adapter signals Phantom / Solflare
		case strings.Contains(body, "window.solana") ||
			strings.Contains(body, "@solana/wallet-adapter") ||
			strings.Contains(body, "sign in with solana"):
			e.AuthSystem = "solana_wallet"
		// EVM wallet auth — window.ethereum / SIWE signals MetaMask / EIP-1193 connect flow
		case strings.Contains(body, "window.ethereum") ||
			strings.Contains(body, "sign-in with ethereum") ||
			strings.Contains(body, `"siwe"`):
			e.AuthSystem = "web3_wallet"
		}
	}

	// ── CookieNames ──────────────────────────────────────────────────────────
	if sc := h["set-cookie"]; sc != "" {
		e.CookieNames = extractCookieNames(sc)
	}

	// ── IsServerless ─────────────────────────────────────────────────────────
	e.IsServerless = (h["x-amzn-requestid"] != "" && h["x-amz-apigw-id"] != "") ||
		h["x-vercel-id"] != "" ||
		h["x-nf-request-id"] != "" ||
		h["cf-worker"] != ""

	// ── IsKubernetes ──────────────────────────────────────────────────────────
	e.IsKubernetes = strings.Contains(strings.ToLower(h["server"]), "kube-apiserver") ||
		h["x-kubernetes-pf-flowschema-uid"] != ""

	// ── IsReverseProxy ────────────────────────────────────────────────────────
	// Detect proxy from ProxyType (header-based vendor fingerprint) or from
	// proxy-specific response headers. We intentionally exclude x-forwarded-for
	// and x-real-ip from the response check: some apps echo these request headers
	// back in the response, which would produce false positives.
	e.IsReverseProxy = e.ProxyType != "" ||
		h["x-envoy-upstream-service-time"] != "" ||
		h["x-kong-proxy-latency"] != "" ||
		h["x-cache"] != "" ||
		h["age"] != ""

	// ── AuthScheme (from WWW-Authenticate — already set in probeHTTP) ──────────
	// fingerprintTech is called twice (before + after path probing); preserve the
	// value set by probeHTTP on the first call rather than overwriting with "".
	if e.AuthScheme == "" {
		if wa := h["www-authenticate"]; wa != "" {
			e.AuthScheme = parseAuthScheme(wa)
		}
	}

	// ── Link header — WordPress, Drupal, HAL/JSON APIs ────────────────────────
	if link := h["link"]; link != "" {
		linkLower := strings.ToLower(link)
		if strings.Contains(linkLower, "api.w.org") {
			// WordPress always advertises the REST API via Link header
			if e.ServiceVersions == nil {
				e.ServiceVersions = make(map[string]string)
			}
			if e.ServiceVersions["platform"] == "" {
				e.ServiceVersions["platform"] = "wordpress"
			}
		}
	}

	// ── CSP vendor extraction ─────────────────────────────────────────────────
	// Parse Content-Security-Policy (or report-only variant) for third-party
	// domain patterns. These reveal the vendor ecosystem without extra requests.
	csp := h["content-security-policy"]
	if csp == "" {
		csp = h["content-security-policy-report-only"]
	}
	if csp != "" {
		cspVendors := extractCSPVendors(csp)
		existing := map[string]bool{}
		for _, v := range e.VendorSignals {
			existing[v] = true
		}
		for _, v := range cspVendors {
			if !existing[v] {
				existing[v] = true
				e.VendorSignals = append(e.VendorSignals, v)
			}
		}
	}

	// Note: Web3Signals and ContractAddresses are populated in probeHTTP
	// using the full 8 KB body. They are intentionally absent here because
	// fingerprintTech operates on the truncated e.Body512 (512 bytes) which
	// would miss almost all contract addresses and library references.

	// ── BackendServices ───────────────────────────────────────────────────────
	// Infer named backend services from RespondingPaths. Used by the AI enricher
	// and topology renderer for richer service context. Each path prefix maps to
	// a canonical service name; the first match per service wins.
	e.BackendServices = inferBackendServices(e.RespondingPaths)
}

// pathServiceMap maps a responding path prefix/exact to a canonical service name.
// Only paths that uniquely identify a specific product are included — generic
// paths like /admin or /health that appear across many services are excluded.
var pathServiceMap = []struct {
	prefix  string
	service string
}{
	{"/actuator", "Spring Boot"},
	{"/v1/sys/health", "HashiCorp Vault"},
	{"/v1/sys/seal-status", "HashiCorp Vault"},
	{"/_cat/indices", "Elasticsearch"},
	{"/_cluster/health", "Elasticsearch"},
	{"/_nodes", "Elasticsearch"},
	{"/api/health", "Grafana"},
	{"/targets", "Prometheus"},
	{"/metrics", "Prometheus"},
	{"/api/v1/health", "Apache Airflow"},
	{"/api/v1/dags", "Apache Airflow"},
	{"/api/kernels", "Jupyter"},
	{"/api/contents", "Jupyter"},
	{"/v1/graphql", "Hasura"},
	{"/v1/metadata", "Hasura"},
	{"/api/rawdata", "Traefik"},
	{"/api/overview", "Traefik"},
	{"/api/entrypoints", "Traefik"},
	{"/topics", "Kafka"},
	{"/v3/clusters", "Kafka"},
	{"/services/server/info", "Splunk"},
	{"/-/health", "GitLab"},
	{"/-/readiness", "GitLab"},
	{"/api_jsonrpc.php", "Zabbix"},
	{"/zabbix/", "Zabbix"},
	{"/api/v2/manager/info", "Wazuh"},
	{"/wp-login.php", "WordPress"},
	{"/wp-json", "WordPress"},
	{"/auth/realms", "Keycloak"},
	{"/realms", "Keycloak"},
	{"/telescope", "Laravel"},
	{"/horizon", "Laravel"},
	{"/rails/info", "Ruby on Rails"},
	{"/cable", "Ruby on Rails"},
	{"/ghost", "Ghost CMS"},
	{"/pgadmin4", "pgAdmin"},
	{"/pgadmin", "pgAdmin"},
	{"/phpmyadmin", "phpMyAdmin"},
	{"/adminer", "Adminer"},
	{"/config_dump", "Envoy"},
	{"/console", "Hasura"},
	{"/api/v1/serverInfo", "Veeam"},
	{"/manager/html", "Apache Tomcat"},
	{"/manager/status", "Apache Tomcat"},
	{"/host-manager/html", "Apache Tomcat"},
	{"/api/settings", "Portainer"},
	{"/api/status", "Portainer"},
	{"/app/kibana", "Kibana"},
	{"/app/home", "Kibana"},
	{"/dashboard", "Traefik"},
	{"/swagger.json", "OpenAPI"},
	{"/openapi.json", "OpenAPI"},
	{"/graphql", "GraphQL"},
	{"/v1/models", "OpenAI-compatible API"},
	{"/v1/chat/completions", "OpenAI-compatible API"},
	{"/api/generate", "Ollama"},
	{"/api/tags", "Ollama"},
	{"/v1/flows", "Langflow"},
	{"/api/v1/settings", "n8n"},
}

// inferBackendServices returns a deduplicated list of named backend services
// inferred from the set of responding paths. Called by fingerprintTech after
// probeFingerprintPaths populates e.RespondingPaths.
func inferBackendServices(paths []string) []string {
	seen := make(map[string]bool)
	var services []string
	for _, path := range paths {
		pl := strings.ToLower(path)
		for _, entry := range pathServiceMap {
			if strings.HasPrefix(pl, strings.ToLower(entry.prefix)) {
				if !seen[entry.service] {
					seen[entry.service] = true
					services = append(services, entry.service)
				}
				break
			}
		}
	}
	return services
}

// haproxyHeader returns true when any header key starts with "x-haproxy-".
func haproxyHeader(h map[string]string) bool {
	for k := range h {
		if strings.HasPrefix(k, "x-haproxy-") {
			return true
		}
	}
	return false
}

// extractCookieNames parses a Set-Cookie header value and returns recognised
// session cookie names (without their values). Multiple cookies in the header
// are comma-separated in Go's http.Header representation after canonicalisation,
// but the raw first-value string we store may only contain one; we handle both.
func extractCookieNames(setCookie string) []string {
	known := []string{
		"JSESSIONID", "PHPSESSID", "ASP.NET_SessionId",
		"connect.sid", "_session_id", "laravel_session",
		"XSRF-TOKEN", "express.sid",
	}
	lower := strings.ToLower(setCookie)
	var found []string
	for _, name := range known {
		if strings.Contains(lower, strings.ToLower(name)) {
			found = append(found, name)
		}
	}
	return found
}

// jsonField extracts a string value from a flat JSON object without a full parse.
func jsonField(s, key string) string {
	needle := `"` + key + `":"`
	idx := strings.Index(s, needle)
	if idx == -1 {
		return ""
	}
	rest := s[idx+len(needle):]
	end := strings.Index(rest, `"`)
	if end == -1 {
		return ""
	}
	return rest[:end]
}
