// Package cdnbypass discovers the real origin IP behind a CDN
// (Cloudflare, Fastly, Akamai, etc.) using passive DNS enumeration,
// MX record analysis, and SPF record parsing.
//
// CDN detection is performed by inspecting HTTP response headers rather than
// querying third-party IP reputation services (e.g. ip-api.com). This avoids
// sending target IP addresses to external parties.
//
// Confidence scoring uses a multi-signal fingerprint comparison to prevent
// false positives from DNS-only signals (e.g. MX records pointing to mail
// servers on the same IP that don't serve web content).
//
// Score thresholds:
//
//	< 20   → not emitted (DNS artifact, not a real bypass)
//	20–44  → Medium (probable origin — responds + weak content match)
//	45+    → High   (strong origin — title/favicon/asset overlap confirmed)
package cdnbypass

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const scannerName = "cdnbypass"

// scoreThresholdHigh is the minimum fingerprint score to emit a High finding.
const scoreThresholdHigh = 45

// scoreThresholdMedium is the minimum score to emit a Medium finding.
// Below this the candidate is considered a DNS artifact and is not emitted.
const scoreThresholdMedium = 20

// originSubdomainPrefixes are common DNS prefixes used to expose origin servers
// directly without routing through the CDN.
var originSubdomainPrefixes = []string{
	"origin",
	"direct",
	"backend",
	"real",
	"prod",
	"www-origin",
	"ssl",
}

// cdnHeaderSignatures maps response header checks to CDN provider names.
var cdnHeaderSignatures = []struct {
	header string
	value  string // if non-empty, header value must contain this (lowercase)
	cdn    string
}{
	{"CF-Ray", "", "cloudflare"},
	{"Server", "cloudflare", "cloudflare"},
	{"X-Amz-Cf-Id", "", "amazon cloudfront"},
	{"X-Amz-Cf-Pop", "", "amazon cloudfront"},
	{"X-Cache", "cloudfront", "amazon cloudfront"},
	{"X-Served-By", "", "fastly"},
	{"Via", "fastly", "fastly"},
	{"X-Check-Cacheable", "", "akamai"},
	{"Server", "akamaighost", "akamai"},
	{"X-Sucuri-ID", "", "sucuri"},
	{"X-CDN", "incapsula", "incapsula"},
	{"X-Iinfo", "", "incapsula"},
	{"X-Edge-IP", "", "edgecast"},
	{"X-EC-Debug", "", "edgecast"},
}

// Regexps used during HTML normalization and extraction. Compiled once at init.
var (
	// Dynamic attributes that change per-request — replace value with placeholder.
	reDynamicAttr = regexp.MustCompile(
		`(?i)(content|nonce|value)="[A-Za-z0-9+/=_\-]{16,}"`)

	// ISO 8601 timestamps and UNIX epoch strings.
	reTimestamp = regexp.MustCompile(
		`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}`)

	// UUIDs.
	reUUID = regexp.MustCompile(
		`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

	// Long hex strings (request IDs, build hashes, etc.).
	reLongHex = regexp.MustCompile(`[0-9a-f]{20,}`)

	// Page title.
	reTitle = regexp.MustCompile(`(?i)<title[^>]*>([^<]{1,200})</title>`)

	// Linked JS/CSS asset filenames (src= or href= attributes).
	reAsset = regexp.MustCompile(`(?i)(?:src|href)="[^"]*?/([^/"?]+\.(?:js|css))"`)
)

// pathProbe holds the result of fetching one URL path.
type pathProbe struct {
	status int
	body   string // normalized HTML body (up to 256 KB raw, then normalized)
}

// siteFingerprint holds stable signals collected from a site (CDN-fronted or direct).
type siteFingerprint struct {
	probes      map[string]pathProbe // path → probe result
	faviconHash uint32               // FNV-32a hash of /favicon.ico bytes; 0 if unavailable
	title       string               // <title> from root path
	assets      map[string]struct{}  // JS/CSS filenames extracted from root HTML
}

// probePaths is the list of paths fetched for fingerprinting.
// Root + login + robots are cheap; favicon is hashed separately.
var probePaths = []string{"/", "/login", "/robots.txt"}

// ── Scanner ───────────────────────────────────────────────────────────────────

type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, _ module.ScanType) ([]finding.Finding, error) {
	client := &http.Client{
		Timeout: 12 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Step 1: detect CDN from response headers.
	cdnProvider, err := detectCDNFromHeaders(ctx, client, asset)
	if err != nil || cdnProvider == "" {
		return nil, nil
	}

	// Step 2: collect baseline fingerprint from CDN-fronted site.
	baseline := collectFingerprint(ctx, client, asset, "")

	// Step 3: discover origin IP candidates from DNS/MX/SPF/CT logs.
	domain := rootDomain(asset)

	type candidate struct {
		ip     string
		method string
	}

	// Gather all unique candidates first (fast DNS/HTTP lookups, no scoring).
	seenIPs := make(map[string]string) // ip → first method seen

	addIP := func(ip, method string) {
		if _, dup := seenIPs[ip]; !dup {
			seenIPs[ip] = method
		}
	}

	// Method a: common origin subdomain patterns
	for _, prefix := range originSubdomainPrefixes {
		sub := prefix + "." + domain
		originIP, ok := resolveHost(ctx, sub)
		if !ok {
			continue
		}
		if candidateCDN, _ := detectCDNFromHeaders(ctx, client, sub); candidateCDN != "" {
			continue
		}
		addIP(originIP, "origin_subdomain:"+sub)
	}

	// Method b: MX records
	for _, originIP := range mxOriginIPs(ctx, domain) {
		addIP(originIP, "mx_record")
	}

	// Method c: SPF ip4: directives
	for _, originIP := range spfOriginIPs(ctx, domain) {
		addIP(originIP, "spf_ip4_record")
	}

	// Method d: Certificate Transparency log subdomain discovery
	for _, originIP := range certTransparencyIPs(ctx, client, domain) {
		addIP(originIP, "ct_log")
	}

	if len(seenIPs) == 0 {
		return nil, nil
	}

	// Step 4: score all candidates in parallel — each scoreCandidate makes
	// several outbound HTTP requests, so parallelism here gives a major
	// speedup when there are 5–15 candidates.
	type scored struct {
		ip     string
		method string
		score  int
	}
	results := make(chan scored, len(seenIPs))
	var wg sync.WaitGroup
	for ip, method := range seenIPs {
		wg.Add(1)
		go func(ip, method string) {
			defer wg.Done()
			s := scoreCandidate(ctx, client, ip, asset, baseline)
			results <- scored{ip: ip, method: method, score: s}
		}(ip, method)
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	var findings []finding.Finding
	for r := range results {
		if r.score < scoreThresholdMedium {
			continue
		}
		findings = append(findings, buildFinding(asset, r.ip, cdnProvider, r.method, r.score))
	}

	if len(findings) == 0 {
		return nil, nil
	}
	return findings, nil
}

// ── Fingerprint collection ────────────────────────────────────────────────────

// collectFingerprint fetches probePaths + /favicon.ico from target, forcing
// hostHeader as the Host header when non-empty (used for direct-IP probes).
func collectFingerprint(ctx context.Context, client *http.Client, target, hostHeader string) siteFingerprint {
	fp := siteFingerprint{
		probes: make(map[string]pathProbe),
		assets: make(map[string]struct{}),
	}

	for _, path := range probePaths {
		body, status := fetchPath(ctx, client, target, path, hostHeader)
		fp.probes[path] = pathProbe{status: status, body: normalizeHTML(body)}
		if path == "/" {
			fp.title = extractTitle(body)
			for _, name := range extractAssetNames(body) {
				fp.assets[name] = struct{}{}
			}
		}
	}

	fp.faviconHash = fetchFaviconHash(ctx, client, target, hostHeader)
	return fp
}

// scoreCandidate probes originIP (with asset as Host header) and returns a
// weighted similarity score against the CDN-fronted baseline fingerprint.
//
// Scoring weights:
//
//	+10  same HTTP status on /
//	+10  same HTTP status on /login
//	+20  same page title (non-empty)
//	+30  favicon hash matches (non-zero)
//	+15  3+ matching JS/CSS asset filenames
//	+10  1-2 matching asset filenames
//	+20  body token Jaccard similarity on / > 0.65
//	+10  body token Jaccard similarity on / > 0.40
//	-30  candidate returns mail server banner or cloud placeholder
func scoreCandidate(ctx context.Context, client *http.Client, originIP, asset string, baseline siteFingerprint) int {
	cand := collectFingerprint(ctx, client, originIP, asset)

	// If root path got no 2xx at all, skip.
	if cand.probes["/"].status < 200 || cand.probes["/"].status >= 300 {
		return 0
	}

	score := 0

	// TLS cert SAN/CN match — cryptographic proof the IP serves the target app.
	// Carry +40 for a match; this alone is enough to clear the Medium threshold.
	if certMatchesAsset(ctx, originIP, asset) {
		score += 40
	}

	// Status code agreement.
	for _, path := range []string{"/", "/login"} {
		b := baseline.probes[path]
		c := cand.probes[path]
		if b.status > 0 && c.status > 0 && b.status == c.status {
			score += 10
		}
	}

	// Title match (strong signal).
	if baseline.title != "" && cand.title != "" && baseline.title == cand.title {
		score += 20
	}

	// Favicon hash (very strong signal — unique per app).
	if baseline.faviconHash != 0 && cand.faviconHash != 0 &&
		baseline.faviconHash == cand.faviconHash {
		score += 30
	}

	// Asset filename overlap (e.g. main-abc123.js appearing in both pages).
	overlap := 0
	for name := range cand.assets {
		if _, ok := baseline.assets[name]; ok {
			overlap++
		}
	}
	switch {
	case overlap >= 3:
		score += 15
	case overlap >= 1:
		score += 10
	}

	// Normalized body token Jaccard similarity on root path.
	j := jaccardSimilarity(baseline.probes["/"].body, cand.probes["/"].body)
	switch {
	case j >= 0.65:
		score += 20
	case j >= 0.40:
		score += 10
	}

	// Penalize obvious non-web-app responses (mail banners, cloud placeholders).
	rootBody := strings.ToLower(cand.probes["/"].body)
	for _, marker := range []string{
		"smtp", "220 ", "esmtp",                            // mail server
		"default nginx", "welcome to nginx",                // nginx placeholder
		"it works", "apache2 ubuntu default",              // Apache placeholder
		"amazon s3", "nosuchwebsite", "domain not found",  // cloud/DNS placeholders
	} {
		if strings.Contains(rootBody, marker) {
			score -= 30
			break
		}
	}

	return score
}

// ── Fingerprint helpers ───────────────────────────────────────────────────────

// fetchPath fetches scheme://target+path with an optional forced Host header.
// Returns (body string, HTTP status). On error returns ("", 0).
func fetchPath(ctx context.Context, client *http.Client, target, path, hostHeader string) (string, int) {
	for _, scheme := range []string{"https", "http"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+target+path, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon Security Scanner)")
		if hostHeader != "" {
			req.Host = hostHeader
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		resp.Body.Close()
		return string(body), resp.StatusCode
	}
	return "", 0
}

// fetchFaviconHash fetches /favicon.ico and returns its FNV-32a hash.
// Returns 0 if the fetch fails or the response is not 2xx.
func fetchFaviconHash(ctx context.Context, client *http.Client, target, hostHeader string) uint32 {
	body, status := fetchPath(ctx, client, target, "/favicon.ico", hostHeader)
	if status < 200 || status >= 300 || len(body) == 0 {
		return 0
	}
	h := fnv.New32a()
	h.Write([]byte(body))
	return h.Sum32()
}

// normalizeHTML strips dynamic per-request values from HTML so that two
// responses from the same app (but different requests) compare as equal.
func normalizeHTML(body string) string {
	s := body
	s = reDynamicAttr.ReplaceAllString(s, `$1="<token>"`)
	s = reTimestamp.ReplaceAllString(s, "<ts>")
	s = reUUID.ReplaceAllString(s, "<uuid>")
	s = reLongHex.ReplaceAllString(s, "<hex>")
	// Collapse whitespace.
	s = strings.Join(strings.Fields(s), " ")
	return s
}

// extractTitle returns the text content of the first <title> tag.
func extractTitle(body string) string {
	m := reTitle.FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// extractAssetNames returns the base filenames (e.g. "main-abc123.js") of
// all <script src="..."> and <link href="..."> assets in the HTML.
func extractAssetNames(body string) []string {
	matches := reAsset.FindAllStringSubmatch(body, -1)
	var names []string
	seen := make(map[string]struct{})
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		name := m[1]
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	return names
}

// jaccardSimilarity returns the Jaccard index of the word-bigram sets of two
// normalized HTML strings. Result is in [0, 1]. Returns 0 for empty inputs.
func jaccardSimilarity(a, b string) float64 {
	setA := bigrams(a)
	setB := bigrams(b)
	if len(setA) == 0 || len(setB) == 0 {
		return 0
	}
	intersection := 0
	for k := range setA {
		if _, ok := setB[k]; ok {
			intersection++
		}
	}
	union := len(setA) + len(setB) - intersection
	if union == 0 {
		return 0
	}
	return float64(intersection) / float64(union)
}

// bigrams returns the set of consecutive word-pair "bigrams" from a string.
// Each bigram is encoded as a uint64 (two FNV-32a hashes packed together)
// to avoid allocating strings.
func bigrams(s string) map[uint64]struct{} {
	words := strings.Fields(s)
	out := make(map[uint64]struct{}, len(words))
	for i := 1; i < len(words); i++ {
		h1 := fnvStr(words[i-1])
		h2 := fnvStr(words[i])
		key := uint64(h1)<<32 | uint64(h2)
		out[key] = struct{}{}
	}
	return out
}

func fnvStr(s string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(s))
	return binary.LittleEndian.Uint32(h.Sum(nil))
}

// ── Finding construction ──────────────────────────────────────────────────────

// buildFinding constructs a CDN origin-bypass finding. Severity and description
// are derived from the fingerprint match score.
func buildFinding(asset, originIP, cdnProvider, discoveryMethod string, score int) finding.Finding {
	var sev finding.Severity
	var confidenceLabel, evidenceNote string
	switch {
	case score >= scoreThresholdHigh:
		sev = finding.SeverityHigh
		confidenceLabel = "content_match"
		evidenceNote = "Strong fingerprint match: title, favicon, and/or asset names match the CDN-fronted site."
	default:
		sev = finding.SeverityMedium
		confidenceLabel = "probable"
		evidenceNote = "Moderate fingerprint match: IP responds with correct Host header and partial content similarity."
	}

	return finding.Finding{
		CheckID: finding.CheckCDNOriginFound,
		Module:  "surface",
		Scanner: scannerName,
		Asset:   asset,
		Severity: sev,
		Title: fmt.Sprintf("CDN origin IP found: %s bypasses %s protection on %s", originIP, cdnProvider, asset),
		Description: fmt.Sprintf(
			"The real origin server IP address %s was discovered behind the %s CDN for %s "+
				"(fingerprint score: %d). %s "+
				"An attacker can bypass WAF and CDN protections by connecting directly to this IP. "+
				"Discovery method: %s. "+
				"Fix: restrict your origin firewall to only accept traffic from %s IP ranges.",
			originIP, cdnProvider, asset, score, evidenceNote, discoveryMethod, cdnProvider,
		),
		Evidence: map[string]any{
			"origin_ip":          originIP,
			"cdn_provider":       cdnProvider,
			"discovery_method":   discoveryMethod,
			"origin_confidence":  confidenceLabel,
			"fingerprint_score":  score,
			"asset":              asset,
		},
		DiscoveredAt: time.Now(),
	}
}

// ── CDN detection ─────────────────────────────────────────────────────────────

func detectCDNFromHeaders(ctx context.Context, client *http.Client, asset string) (string, error) {
	for _, scheme := range []string{"https", "http"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+asset+"/", nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		for _, sig := range cdnHeaderSignatures {
			val := resp.Header.Get(sig.header)
			if val == "" {
				continue
			}
			if sig.value == "" || strings.Contains(strings.ToLower(val), sig.value) {
				return sig.cdn, nil
			}
		}
		return "", nil
	}
	return "", nil
}

// ── DNS helpers ───────────────────────────────────────────────────────────────

func resolveHost(ctx context.Context, host string) (string, bool) {
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(lookupCtx, host)
	if err != nil || len(addrs) == 0 {
		return "", false
	}
	return addrs[0], true
}

var thirdPartyMailProviderSuffixes = []string{
	".google.com",
	".googlemail.com",
	".outlook.com",
	".office365.com",
	".sendgrid.net",
	".mailgun.org",
	".amazonses.com",
	".mimecast.com",
	".proofpoint.com",
	".messagelabs.com",
	".pphosted.com",
	".barracudanetworks.com",
	".mailprotect.com",
}

func isThirdPartyMailHost(host string) bool {
	h := strings.ToLower(host)
	for _, suffix := range thirdPartyMailProviderSuffixes {
		if strings.HasSuffix(h, suffix) {
			return true
		}
	}
	return false
}

func mxOriginIPs(ctx context.Context, domain string) []string {
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	mxs, err := net.DefaultResolver.LookupMX(lookupCtx, domain)
	if err != nil {
		return nil
	}
	var ips []string
	for _, mx := range mxs {
		host := strings.TrimSuffix(mx.Host, ".")
		if isThirdPartyMailHost(host) {
			continue
		}
		addrs, err := net.DefaultResolver.LookupHost(ctx, host)
		if err != nil || len(addrs) == 0 {
			continue
		}
		ips = append(ips, addrs[0])
	}
	return ips
}

func spfOriginIPs(ctx context.Context, domain string) []string {
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	txts, err := net.DefaultResolver.LookupTXT(lookupCtx, domain)
	if err != nil {
		return nil
	}
	var ips []string
	for _, record := range txts {
		if !strings.HasPrefix(record, "v=spf1") {
			continue
		}
		for _, field := range strings.Fields(record) {
			if !strings.HasPrefix(field, "ip4:") {
				continue
			}
			raw := strings.TrimPrefix(field, "ip4:")
			host := raw
			if idx := strings.Index(raw, "/"); idx >= 0 {
				host = raw[:idx]
			}
			if net.ParseIP(host) == nil {
				continue
			}
			ips = append(ips, host)
		}
	}
	return ips
}

func rootDomain(asset string) string {
	parts := strings.Split(asset, ".")
	if len(parts) <= 2 {
		return asset
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// certTransparencyIPs queries the crt.sh Certificate Transparency log search
// API for subdomains of domain and returns any IPs that resolve for those
// subdomains that are not behind a CDN.
// Returns at most 20 candidate IPs to avoid excessive probing.
func certTransparencyIPs(ctx context.Context, client *http.Client, domain string) []string {
	// Use the crt.sh JSON API: https://crt.sh/?q=%.domain&output=json
	// This is a passive, read-only query against public CT logs.
	ctCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	url := "https://crt.sh/?q=%25." + domain + "&output=json"
	req, err := http.NewRequestWithContext(ctCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon Security Scanner)")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return nil
	}

	// Parse the JSON: array of {"name_value": "subdomain.example.com", ...}
	// Use simple string extraction to avoid importing encoding/json.
	// crt.sh returns lines like: "name_value":"sub.example.com"
	seen := make(map[string]struct{})
	var ips []string

	// Extract name_value fields using regex-like parsing
	remaining := string(body)
	const key = `"name_value":"`
	for len(ips) < 20 {
		idx := strings.Index(remaining, key)
		if idx < 0 {
			break
		}
		remaining = remaining[idx+len(key):]
		end := strings.Index(remaining, `"`)
		if end < 0 {
			break
		}
		name := remaining[:end]
		remaining = remaining[end:]

		// Skip wildcards and the apex domain
		if strings.HasPrefix(name, "*") || name == domain {
			continue
		}
		// Skip names that are not subdomains of domain
		if !strings.HasSuffix(name, "."+domain) {
			continue
		}
		// Skip names we've already tried
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}

		ip, ok := resolveHost(ctx, name)
		if !ok {
			continue
		}
		if _, ipdup := seen[ip]; ipdup {
			continue
		}
		seen[ip] = struct{}{}
		ips = append(ips, ip)
	}
	return ips
}

// certMatchesAsset returns true if the TLS certificate presented by originIP
// (using asset as the SNI/Host) contains asset in its Subject CN or SANs.
// This is the strongest fingerprint signal — it is cryptographic proof that
// the IP is configured to serve the target hostname.
func certMatchesAsset(ctx context.Context, originIP, asset string) bool {
	host := strings.Split(asset, ":")[0]
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	dialer := &net.Dialer{}
	netConn, err := dialer.DialContext(dialCtx, "tcp", net.JoinHostPort(originIP, "443"))
	if err != nil {
		return false
	}
	tlsConn := tls.Client(netConn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	})
	tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		netConn.Close()
		return false
	}
	state := tlsConn.ConnectionState()
	tlsConn.Close()

	if len(state.PeerCertificates) == 0 {
		return false
	}
	cert := state.PeerCertificates[0]

	// Check CN
	if strings.EqualFold(cert.Subject.CommonName, host) {
		return true
	}
	// Check SANs
	for _, san := range cert.DNSNames {
		if strings.EqualFold(san, host) {
			return true
		}
		// Wildcard match: *.example.com covers sub.example.com
		if strings.HasPrefix(san, "*.") {
			wildDomain := san[2:]
			parts := strings.SplitN(host, ".", 2)
			if len(parts) == 2 && strings.EqualFold(parts[1], wildDomain) {
				return true
			}
		}
	}
	return false
}
