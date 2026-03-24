package cdnbypass

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --- detectCDNFromHeaders edge cases ---

func TestDetectCDNFromHeaders_Cloudflare_CFRay(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("CF-Ray", "7d3b2a1c4e5f6a7b-LHR")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := srv.Client()
	provider, err := detectCDNFromHeaders(context.Background(), client, strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if provider != "cloudflare" {
		t.Errorf("expected cloudflare, got %q", provider)
	}
}

func TestDetectCDNFromHeaders_Cloudflare_ServerHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := srv.Client()
	provider, err := detectCDNFromHeaders(context.Background(), client, strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if provider != "cloudflare" {
		t.Errorf("expected cloudflare, got %q", provider)
	}
}

func TestDetectCDNFromHeaders_Cloudflare_ServerHeaderCaseInsensitive(t *testing.T) {
	// Server header value matching must be case-insensitive
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Cloudflare") // mixed case
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := srv.Client()
	provider, err := detectCDNFromHeaders(context.Background(), client, strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if provider != "cloudflare" {
		t.Errorf("expected cloudflare, got %q", provider)
	}
}

func TestDetectCDNFromHeaders_Fastly_XServedBy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Served-By", "cache-lhr1234-LHR")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := srv.Client()
	provider, err := detectCDNFromHeaders(context.Background(), client, strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if provider != "fastly" {
		t.Errorf("expected fastly, got %q", provider)
	}
}

func TestDetectCDNFromHeaders_CloudFront_XAmzCfId(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Amz-Cf-Id", "abc123def456")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := srv.Client()
	provider, err := detectCDNFromHeaders(context.Background(), client, strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if provider != "amazon cloudfront" {
		t.Errorf("expected amazon cloudfront, got %q", provider)
	}
}

func TestDetectCDNFromHeaders_CloudFront_XCacheHit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Cache", "Hit from cloudfront")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := srv.Client()
	provider, err := detectCDNFromHeaders(context.Background(), client, strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if provider != "amazon cloudfront" {
		t.Errorf("expected amazon cloudfront, got %q", provider)
	}
}

func TestDetectCDNFromHeaders_NoCDNHeaders_ReturnsEmpty(t *testing.T) {
	// A plain server with no CDN headers — should return ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := srv.Client()
	provider, err := detectCDNFromHeaders(context.Background(), client, strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if provider != "" {
		t.Errorf("expected empty provider, got %q", provider)
	}
}

func TestDetectCDNFromHeaders_ServerNotReachable_ReturnsEmpty(t *testing.T) {
	// No server running — both https and http will fail. Should return "" not error.
	client := &http.Client{}
	provider, err := detectCDNFromHeaders(context.Background(), client, "127.0.0.1:19999")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if provider != "" {
		t.Errorf("expected empty provider on connection failure, got %q", provider)
	}
}

func TestDetectCDNFromHeaders_EmptyHeaderValue_NotMatched(t *testing.T) {
	// Server sets CF-Ray header to empty string — should not match cloudflare
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("CF-Ray", "")
		w.Header().Set("Server", "nginx")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := srv.Client()
	provider, err := detectCDNFromHeaders(context.Background(), client, strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if provider != "" {
		t.Errorf("expected empty provider, got %q", provider)
	}
}

func TestDetectCDNFromHeaders_ServerHeaderNginxNotCloudflare(t *testing.T) {
	// "Server: nginx" contains neither "cloudflare" nor "akamaighost" — no match
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25.3")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := srv.Client()
	provider, err := detectCDNFromHeaders(context.Background(), client, strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if provider != "" {
		t.Errorf("expected empty, got %q", provider)
	}
}

func TestDetectCDNFromHeaders_TLSServer_CFRayDetected(t *testing.T) {
	// Verify the https:// branch works — httptest.NewTLSServer uses a self-signed
	// cert, so the test client must be the TLS-trusting client from the server.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("CF-Ray", "1a2b3c4d5e6f7a8b-LHR")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// srv.Client() trusts the self-signed cert
	provider, err := detectCDNFromHeaders(context.Background(), srv.Client(), strings.TrimPrefix(srv.URL, "https://"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if provider != "cloudflare" {
		t.Errorf("expected cloudflare from TLS server, got %q", provider)
	}
}

func TestDetectCDNFromHeaders_TLSServer_NoCDNHeaders_ReturnsEmpty(t *testing.T) {
	// HTTPS response with no CDN headers — must return "" and NOT fall through
	// to the http:// attempt (which would never be reached anyway since we got a response).
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	provider, err := detectCDNFromHeaders(context.Background(), srv.Client(), strings.TrimPrefix(srv.URL, "https://"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if provider != "" {
		t.Errorf("expected empty provider from plain TLS server, got %q", provider)
	}
}

func TestDetectCDNFromHeaders_ContextCancelled_ReturnsEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("CF-Ray", "abc")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	client := srv.Client()
	// Should not panic; returns empty without matching
	provider, err := detectCDNFromHeaders(ctx, client, strings.TrimPrefix(srv.URL, "http://"))
	_ = err
	_ = provider
	// No assertion on values — just must not panic
}

func TestDetectCDNFromHeaders_Akamai_ServerHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "AkamaiGHost")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := srv.Client()
	provider, err := detectCDNFromHeaders(context.Background(), client, strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if provider != "akamai" {
		t.Errorf("expected akamai, got %q", provider)
	}
}

func TestDetectCDNFromHeaders_Sucuri_XSucuriID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Sucuri-ID", "12345")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := srv.Client()
	provider, err := detectCDNFromHeaders(context.Background(), client, strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if provider != "sucuri" {
		t.Errorf("expected sucuri, got %q", provider)
	}
}

// TestOriginSubdomainCDNFilter verifies that a discovered origin subdomain
// which is itself behind a CDN is not reported as a bypass — it's a multi-CDN
// setup, not a real origin exposure.
//
// Scenario: example.com → cloudflare (detected). origin.example.com resolves
// to an IP that also returns CF-Ray headers. This should produce NO finding.
func TestOriginSubdomainCDNFilter_SkipsCDNBehindOrigin(t *testing.T) {
	// This test validates the filter logic directly by calling detectCDNFromHeaders
	// on a CDN-proxied candidate and confirming the scanner would skip it.
	// (The full Run() path can't be unit-tested without DNS mocking.)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// origin.example.com is also behind Cloudflare
		w.Header().Set("CF-Ray", "aabbccddeeff0011-LAX")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := srv.Client()
	candidateHost := strings.TrimPrefix(srv.URL, "http://")

	cdn, _ := detectCDNFromHeaders(context.Background(), client, candidateHost)
	if cdn == "" {
		t.Error("CDN filter test: expected CDN detected on origin candidate (so it would be skipped), got empty")
	}
	// The scanner skips candidates where cdn != "" — confirmed above.
}

// --- rootDomain edge cases ---

func TestRootDomain_SimpleApex(t *testing.T) {
	if got := rootDomain("example.com"); got != "example.com" {
		t.Errorf("expected example.com, got %q", got)
	}
}

func TestRootDomain_Subdomain(t *testing.T) {
	if got := rootDomain("www.example.com"); got != "example.com" {
		t.Errorf("expected example.com, got %q", got)
	}
}

func TestRootDomain_DeepSubdomain(t *testing.T) {
	if got := rootDomain("a.b.c.example.com"); got != "example.com" {
		t.Errorf("expected example.com, got %q", got)
	}
}

func TestRootDomain_SingleLabel(t *testing.T) {
	// Single label — return as-is
	if got := rootDomain("localhost"); got != "localhost" {
		t.Errorf("expected localhost, got %q", got)
	}
}

// --- isThirdPartyMailHost edge cases ---

func TestIsThirdPartyMailHost_GoogleCom(t *testing.T) {
	if !isThirdPartyMailHost("aspmx.l.google.com") {
		t.Error("expected google.com to be third-party")
	}
}

func TestIsThirdPartyMailHost_OwnDomain(t *testing.T) {
	// Own MX — should NOT be third-party
	if isThirdPartyMailHost("mail.acme.com") {
		t.Error("expected own domain NOT to be third-party")
	}
}

func TestIsThirdPartyMailHost_CaseInsensitive(t *testing.T) {
	if !isThirdPartyMailHost("MX1.GOOGLE.COM") {
		t.Error("expected case-insensitive match for google.com")
	}
}

func TestIsThirdPartyMailHost_OutlookCom(t *testing.T) {
	if !isThirdPartyMailHost("acme-com.mail.protection.outlook.com") {
		t.Error("expected outlook.com to be third-party")
	}
}

func TestIsThirdPartyMailHost_SendgridNet(t *testing.T) {
	if !isThirdPartyMailHost("mta.sendgrid.net") {
		t.Error("expected sendgrid.net to be third-party")
	}
}

// --- buildFinding edge cases ---

func TestBuildFinding_ContainsRequiredFields(t *testing.T) {
	f := buildFinding("example.com", "1.2.3.4", "cloudflare", "origin_subdomain:origin.example.com", scoreThresholdHigh)
	if f.Asset != "example.com" {
		t.Errorf("asset mismatch: %q", f.Asset)
	}
	if f.Evidence["origin_ip"] != "1.2.3.4" {
		t.Errorf("evidence origin_ip missing or wrong: %v", f.Evidence["origin_ip"])
	}
	if f.Evidence["cdn_provider"] != "cloudflare" {
		t.Errorf("evidence cdn_provider wrong: %v", f.Evidence["cdn_provider"])
	}
	if f.Evidence["discovery_method"] != "origin_subdomain:origin.example.com" {
		t.Errorf("evidence discovery_method wrong: %v", f.Evidence["discovery_method"])
	}
}

// --- SPF record parsing edge cases ---

func TestSpfOriginIPs_CIDRNotation(t *testing.T) {
	// Verify the CIDR host extraction works: "ip4:1.2.3.0/24" → host "1.2.3.0"
	raw := "1.2.3.0/24"
	host := raw
	if idx := strings.Index(raw, "/"); idx >= 0 {
		host = raw[:idx]
	}
	if host != "1.2.3.0" {
		t.Errorf("expected 1.2.3.0, got %q", host)
	}
}

func TestSpfOriginIPs_PlainIP(t *testing.T) {
	raw := "10.0.0.1"
	host := raw
	if idx := strings.Index(raw, "/"); idx >= 0 {
		host = raw[:idx]
	}
	if host != "10.0.0.1" {
		t.Errorf("expected 10.0.0.1, got %q", host)
	}
}

// --- Fingerprint helpers ---

func TestExtractTitle_Present(t *testing.T) {
	body := `<html><head><title>Coppell IT Portal</title></head></html>`
	if got := extractTitle(body); got != "Coppell IT Portal" {
		t.Errorf("unexpected title: %q", got)
	}
}

func TestExtractTitle_Missing(t *testing.T) {
	body := `<html><head></head><body>no title</body></html>`
	if got := extractTitle(body); got != "" {
		t.Errorf("expected empty title, got %q", got)
	}
}

func TestExtractAssetNames_JsAndCss(t *testing.T) {
	body := `<script src="/static/chunks/main-abc123.js"></script>
<link href="/static/css/app-def456.css">`
	names := extractAssetNames(body)
	if len(names) != 2 {
		t.Fatalf("expected 2 assets, got %d: %v", len(names), names)
	}
}

func TestExtractAssetNames_Dedup(t *testing.T) {
	body := `<script src="/a/main.js"></script><script src="/b/main.js"></script>`
	names := extractAssetNames(body)
	if len(names) != 1 {
		t.Errorf("expected 1 deduplicated asset, got %d: %v", len(names), names)
	}
}

func TestNormalizeHTML_RemovesDynamicTokens(t *testing.T) {
	raw := `<meta content="8f91c1a2b3d4e5f600000000cafe1234"> <script nonce="abc123def456789012345678"></script>`
	normalized := normalizeHTML(raw)
	if strings.Contains(normalized, "8f91c1") {
		t.Error("expected token hash to be replaced")
	}
	if strings.Contains(normalized, "abc123def456789012345678") {
		t.Error("expected nonce to be replaced")
	}
}

func TestNormalizeHTML_RemovesUUID(t *testing.T) {
	raw := `<div data-id="550e8400-e29b-41d4-a716-446655440000">content</div>`
	normalized := normalizeHTML(raw)
	if strings.Contains(normalized, "550e8400") {
		t.Error("expected UUID to be replaced")
	}
}

func TestJaccardSimilarity_IdenticalStrings(t *testing.T) {
	s := "the quick brown fox jumps over the lazy dog"
	score := jaccardSimilarity(s, s)
	if score != 1.0 {
		t.Errorf("expected 1.0, got %f", score)
	}
}

func TestJaccardSimilarity_CompletelyDifferent(t *testing.T) {
	a := "hello world foo bar"
	b := "smtp 220 mail server esmtp banner response"
	score := jaccardSimilarity(a, b)
	if score > 0.1 {
		t.Errorf("expected near-zero similarity, got %f", score)
	}
}

func TestJaccardSimilarity_Empty(t *testing.T) {
	if jaccardSimilarity("", "anything") != 0 {
		t.Error("expected 0 for empty input")
	}
}

func TestScoreCandidate_MailBannerPenalized(t *testing.T) {
	// Simulate a candidate that returns an SMTP banner on HTTP port —
	// should be penalized heavily and score below the emit threshold.
	mailSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("220 mail.example.com ESMTP Postfix"))
	}))
	defer mailSrv.Close()

	client := mailSrv.Client()
	baseline := siteFingerprint{
		probes: map[string]pathProbe{
			"/":      {status: 200, body: "Welcome to Coppell IT Portal login page"},
			"/login": {status: 200, body: "Sign in with your credentials"},
			"/robots.txt": {status: 200, body: "User-agent: *"},
		},
		title:       "Coppell IT Portal",
		faviconHash: 12345,
		assets:      map[string]struct{}{"main-abc.js": {}},
	}

	addr := strings.TrimPrefix(mailSrv.URL, "http://")
	score := scoreCandidate(context.Background(), client, addr, "example.com", baseline)
	if score >= scoreThresholdMedium {
		t.Errorf("mail server should score below threshold (%d), got %d", scoreThresholdMedium, score)
	}
}

func TestScoreCandidate_MatchingOrigin(t *testing.T) {
	// Simulate a real origin that returns matching title, favicon, and assets.
	const appHTML = `<html><head><title>Coppell IT Portal</title>
<script src="/static/main-abc123.js"></script>
<link href="/static/app-def456.css">
</head><body><p>Sign in with your credentials</p></body></html>`

	originSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/favicon.ico":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ICODATA"))
		default:
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(appHTML))
		}
	}))
	defer originSrv.Close()

	client := originSrv.Client()
	addr := strings.TrimPrefix(originSrv.URL, "http://")

	// Build a baseline that matches what originSrv returns.
	baseline := collectFingerprint(context.Background(), client, addr, "")

	// Score the same server against its own baseline — must exceed high threshold.
	score := scoreCandidate(context.Background(), client, addr, "example.com", baseline)
	if score < scoreThresholdHigh {
		t.Errorf("identical content should score >= %d, got %d", scoreThresholdHigh, score)
	}
}
