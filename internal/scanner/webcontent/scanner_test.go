package webcontent

import (
	"net/http"
	"testing"

	"github.com/stormbane/beacon/internal/finding"
)

// ---------------------------------------------------------------------------
// Helper: find all findings with a given CheckID
// ---------------------------------------------------------------------------

func findingsByCheckID(findings []finding.Finding, id finding.CheckID) []finding.Finding {
	var out []finding.Finding
	for _, f := range findings {
		if f.CheckID == id {
			out = append(out, f)
		}
	}
	return out
}

// ===========================================================================
// redactHeader
// ===========================================================================

func TestRedactHeader(t *testing.T) {
	tests := []struct {
		name  string
		val   string
		match string
		want  string
	}{
		{
			name:  "short match <= 8 chars is fully masked",
			val:   "Bearer ABCD1234",
			match: "ABCD1234",
			want:  "********",
		},
		{
			name:  "exactly 8 chars is fully masked",
			val:   "key=12345678",
			match: "12345678",
			want:  "********",
		},
		{
			name:  "longer match shows first 4 and last 4",
			val:   "token=AKIA1234567890ABCDEF",
			match: "AKIA1234567890ABCDEF",
			want:  "AKIA************CDEF",
		},
		{
			name:  "9 char match shows first 4, 1 star, last 4",
			val:   "x=123456789",
			match: "123456789",
			want:  "1234*6789",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := redactHeader(tt.val, tt.match)
			if got != tt.want {
				t.Errorf("redactHeader(%q, %q) = %q, want %q", tt.val, tt.match, got, tt.want)
			}
		})
	}
}

// ===========================================================================
// secretProofKeyword
// ===========================================================================

func TestSecretProofKeyword(t *testing.T) {
	tests := []struct {
		label string
		want  string
	}{
		{"Generic Password", "password"},
		{"Generic API Key", "apikey"},
		{"AWS Secret Key", "aws_secret"},
		{"GitHub Token", "ghp_"},
		{"Stripe Secret Key", "sk_live_"},
		{"Stripe Publishable Key", "pk_live_"},
		{"Slack Token", "xoxb-"},
		{"SendGrid API Key", "SG\\."},
		{"Twilio Account SID", "AC[a-f0-9]"},
		{"Google API Key", "AIza"},
		{"Private Key", "PRIVATE KEY"},
		{"OpenAI API Key", "sk-[A-Za-z0-9]"},
		{"Anthropic API Key", "sk-ant-"},
		{"Firebase API Key", "AIzaSy"},
		{"Mailgun API Key", "key-[a-f0-9]"},
	}

	for _, tt := range tests {
		t.Run(tt.label, func(t *testing.T) {
			got := secretProofKeyword(tt.label)
			if got != tt.want {
				t.Errorf("secretProofKeyword(%q) = %q, want %q", tt.label, got, tt.want)
			}
		})
	}
}

func TestSecretProofKeyword_UnknownLabel_FallsBackToFirstWord(t *testing.T) {
	got := secretProofKeyword("Custom Secret Scanner")
	if got != "custom" {
		t.Errorf("expected fallback to first word lowercased 'custom', got %q", got)
	}
}

func TestSecretProofKeyword_EmptyLabel_ReturnsFallback(t *testing.T) {
	got := secretProofKeyword("")
	if got != "secret" {
		t.Errorf("expected fallback 'secret' for empty label, got %q", got)
	}
}

// ===========================================================================
// extractJSURLs
// ===========================================================================

func TestExtractJSURLs(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
		html    string
		want    []string
	}{
		{
			name:    "absolute HTTPS URL",
			baseURL: "https://example.com",
			html:    `<script src="https://cdn.example.com/app.js"></script>`,
			want:    []string{"https://cdn.example.com/app.js"},
		},
		{
			name:    "protocol-relative URL gets https: prepended",
			baseURL: "https://example.com",
			html:    `<script src="//cdn.example.com/bundle.js"></script>`,
			want:    []string{"https://cdn.example.com/bundle.js"},
		},
		{
			name:    "root-relative URL resolved against base",
			baseURL: "https://example.com",
			html:    `<script src="/assets/main.js"></script>`,
			want:    []string{"https://example.com/assets/main.js"},
		},
		{
			name:    "root-relative URL with path in base",
			baseURL: "https://example.com/app/page",
			html:    `<script src="/js/app.js"></script>`,
			want:    []string{"https://example.com/js/app.js"},
		},
		{
			name:    "multiple scripts deduped",
			baseURL: "https://example.com",
			html: `<script src="https://example.com/a.js"></script>
			        <script src="https://example.com/a.js"></script>
			        <script src="https://example.com/b.js"></script>`,
			want: []string{"https://example.com/a.js", "https://example.com/b.js"},
		},
		{
			name:    "single quotes also work",
			baseURL: "https://example.com",
			html:    `<script src='https://cdn.example.com/lib.js'></script>`,
			want:    []string{"https://cdn.example.com/lib.js"},
		},
		{
			name:    "no script tags returns empty",
			baseURL: "https://example.com",
			html:    `<div>hello world</div>`,
			want:    nil,
		},
		{
			name:    "script without src is ignored",
			baseURL: "https://example.com",
			html:    `<script>console.log("hello")</script>`,
			want:    nil,
		},
		{
			name:    ".json src is matched because regex matches .js substring",
			baseURL: "https://example.com",
			html:    `<script src="https://example.com/data.json"></script>`,
			want:    []string{"https://example.com/data.json"},
		},
		{
			name:    "JS with query string is included",
			baseURL: "https://example.com",
			html:    `<script src="https://example.com/app.js?v=123"></script>`,
			want:    []string{"https://example.com/app.js?v=123"},
		},
		{
			name:    "case insensitive SCRIPT tag",
			baseURL: "https://example.com",
			html:    `<SCRIPT SRC="https://example.com/upper.js"></SCRIPT>`,
			want:    []string{"https://example.com/upper.js"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractJSURLs(tt.baseURL, tt.html)
			if len(got) != len(tt.want) {
				t.Fatalf("extractJSURLs() returned %d URLs, want %d: %v", len(got), len(tt.want), got)
			}
			for i, u := range got {
				if u != tt.want[i] {
					t.Errorf("URL[%d] = %q, want %q", i, u, tt.want[i])
				}
			}
		})
	}
}

// ===========================================================================
// analyzeCookies
// ===========================================================================

func TestAnalyzeCookies_SessionCookieMissingSecure(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{
			"Set-Cookie": []string{"session_id=abc123; HttpOnly; SameSite=Strict"},
		},
	}
	findings := analyzeCookies("example.com", resp)
	found := findingsByCheckID(findings, finding.CheckCookieMissingSecure)
	if len(found) != 1 {
		t.Fatalf("expected 1 CheckCookieMissingSecure finding, got %d", len(found))
	}
	if found[0].Severity != finding.SeverityMedium {
		t.Errorf("expected SeverityMedium, got %s", found[0].Severity)
	}
}

func TestAnalyzeCookies_SessionCookieMissingHTTPOnly(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{
			"Set-Cookie": []string{"auth_token=xyz; Secure; SameSite=Lax"},
		},
	}
	findings := analyzeCookies("example.com", resp)
	found := findingsByCheckID(findings, finding.CheckCookieMissingHTTPOnly)
	if len(found) != 1 {
		t.Fatalf("expected 1 CheckCookieMissingHTTPOnly finding, got %d", len(found))
	}
}

func TestAnalyzeCookies_SessionCookieSameSiteNone(t *testing.T) {
	// SameSite=None triggers the finding (http.SameSiteNoneMode path).
	resp := &http.Response{
		Header: http.Header{
			"Set-Cookie": []string{"sid=val; Secure; HttpOnly; SameSite=None"},
		},
	}
	findings := analyzeCookies("example.com", resp)
	found := findingsByCheckID(findings, finding.CheckCookieMissingSameSite)
	if len(found) != 1 {
		t.Fatalf("expected 1 CheckCookieMissingSameSite finding for SameSite=None, got %d", len(found))
	}
	if found[0].Severity != finding.SeverityLow {
		t.Errorf("expected SeverityLow, got %s", found[0].Severity)
	}
}

func TestAnalyzeCookies_SessionCookieNoSameSiteAttribute(t *testing.T) {
	// When Go parses a Set-Cookie header with no SameSite attribute, the
	// SameSite field is left at Go's zero value (0), which is distinct from
	// http.SameSiteDefaultMode (1). The scanner checks for SameSiteDefaultMode
	// and SameSiteNoneMode, so an absent attribute (zero value) does NOT
	// trigger the finding. This test documents that behavior.
	resp := &http.Response{
		Header: http.Header{
			"Set-Cookie": []string{"sid=val; Secure; HttpOnly"},
		},
	}
	findings := analyzeCookies("example.com", resp)
	found := findingsByCheckID(findings, finding.CheckCookieMissingSameSite)
	if len(found) != 0 {
		t.Errorf("expected 0 CheckCookieMissingSameSite findings when SameSite attr is absent (Go zero value != SameSiteDefaultMode), got %d", len(found))
	}
}

func TestAnalyzeCookies_AllFlagsPresent_NoFindings(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{
			"Set-Cookie": []string{"session_id=abc; Secure; HttpOnly; SameSite=Strict"},
		},
	}
	findings := analyzeCookies("example.com", resp)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for properly secured session cookie, got %d", len(findings))
	}
}

func TestAnalyzeCookies_NonSessionCookie_Ignored(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{
			"Set-Cookie": []string{
				"theme=dark",
				"lang=en",
				"analytics_id=123",
			},
		},
	}
	findings := analyzeCookies("example.com", resp)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-session cookies (theme, lang, analytics_id), got %d", len(findings))
	}
}

func TestAnalyzeCookies_NoCookies_NoFindings(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{},
	}
	findings := analyzeCookies("example.com", resp)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when no cookies are set, got %d", len(findings))
	}
}

func TestAnalyzeCookies_MultipleBadSessionCookies(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{
			"Set-Cookie": []string{
				"session_id=abc; SameSite=None", // missing Secure, HttpOnly; SameSite=None triggers finding
				"auth_token=xyz; SameSite=None", // missing Secure, HttpOnly; SameSite=None triggers finding
				"theme=dark",                     // non-session, should be ignored
			},
		},
	}
	findings := analyzeCookies("example.com", resp)
	secureFindings := findingsByCheckID(findings, finding.CheckCookieMissingSecure)
	httpOnlyFindings := findingsByCheckID(findings, finding.CheckCookieMissingHTTPOnly)
	sameSiteFindings := findingsByCheckID(findings, finding.CheckCookieMissingSameSite)

	if len(secureFindings) != 2 {
		t.Errorf("expected 2 CheckCookieMissingSecure findings, got %d", len(secureFindings))
	}
	if len(httpOnlyFindings) != 2 {
		t.Errorf("expected 2 CheckCookieMissingHTTPOnly findings, got %d", len(httpOnlyFindings))
	}
	if len(sameSiteFindings) != 2 {
		t.Errorf("expected 2 CheckCookieMissingSameSite findings, got %d", len(sameSiteFindings))
	}
}

func TestAnalyzeCookies_SessionKeywords(t *testing.T) {
	// Verify that all session-like cookie names are recognized
	sessionNames := []string{
		"session_data",
		"auth_key",
		"access_token",
		"my_sid",
		"remember_me",
		"_session_id",
	}
	for _, name := range sessionNames {
		t.Run(name, func(t *testing.T) {
			resp := &http.Response{
				Header: http.Header{
					"Set-Cookie": []string{name + "=val"},
				},
			}
			findings := analyzeCookies("example.com", resp)
			if len(findings) == 0 {
				t.Errorf("expected findings for session-like cookie %q, got none", name)
			}
		})
	}
}

// ===========================================================================
// analyzeCSP
// ===========================================================================

func TestAnalyzeCSP_NoCSPHeader_NoFindings(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{},
	}
	findings := analyzeCSP("example.com", resp)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when CSP header is absent, got %d", len(findings))
	}
}

func TestAnalyzeCSP_UnsafeInline(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{
			"Content-Security-Policy": []string{"default-src 'self'; script-src 'self' 'unsafe-inline'"},
		},
	}
	findings := analyzeCSP("example.com", resp)
	found := findingsByCheckID(findings, finding.CheckCSPUnsafeInline)
	if len(found) != 1 {
		t.Fatalf("expected 1 CheckCSPUnsafeInline finding, got %d", len(found))
	}
	if found[0].Severity != finding.SeverityMedium {
		t.Errorf("expected SeverityMedium, got %s", found[0].Severity)
	}
}

func TestAnalyzeCSP_UnsafeEval(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{
			"Content-Security-Policy": []string{"script-src 'self' 'unsafe-eval'"},
		},
	}
	findings := analyzeCSP("example.com", resp)
	found := findingsByCheckID(findings, finding.CheckCSPUnsafeEval)
	if len(found) != 1 {
		t.Fatalf("expected 1 CheckCSPUnsafeEval finding, got %d", len(found))
	}
}

func TestAnalyzeCSP_BothUnsafeInlineAndEval(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{
			"Content-Security-Policy": []string{"script-src 'unsafe-inline' 'unsafe-eval'"},
		},
	}
	findings := analyzeCSP("example.com", resp)
	inlineFindings := findingsByCheckID(findings, finding.CheckCSPUnsafeInline)
	evalFindings := findingsByCheckID(findings, finding.CheckCSPUnsafeEval)
	if len(inlineFindings) != 1 {
		t.Errorf("expected 1 unsafe-inline finding, got %d", len(inlineFindings))
	}
	if len(evalFindings) != 1 {
		t.Errorf("expected 1 unsafe-eval finding, got %d", len(evalFindings))
	}
}

func TestAnalyzeCSP_WildcardInScriptSrc(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{
			"Content-Security-Policy": []string{"script-src * 'self'"},
		},
	}
	findings := analyzeCSP("example.com", resp)
	found := findingsByCheckID(findings, finding.CheckCSPWildcardSource)
	if len(found) != 1 {
		t.Fatalf("expected 1 CheckCSPWildcardSource finding, got %d", len(found))
	}
	if found[0].Severity != finding.SeverityHigh {
		t.Errorf("expected SeverityHigh, got %s", found[0].Severity)
	}
	// Verify the directive is correctly identified
	if dir, ok := found[0].Evidence["directive"].(string); !ok || dir != "script-src" {
		t.Errorf("expected directive='script-src', got %v", found[0].Evidence["directive"])
	}
}

func TestAnalyzeCSP_WildcardInDefaultSrc(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{
			"Content-Security-Policy": []string{"default-src *"},
		},
	}
	findings := analyzeCSP("example.com", resp)
	found := findingsByCheckID(findings, finding.CheckCSPWildcardSource)
	if len(found) != 1 {
		t.Fatalf("expected 1 CheckCSPWildcardSource finding, got %d", len(found))
	}
	if dir, ok := found[0].Evidence["directive"].(string); !ok || dir != "default-src" {
		t.Errorf("expected directive='default-src', got %v", found[0].Evidence["directive"])
	}
}

func TestAnalyzeCSP_WildcardInStyleSrc_NoWildcardFinding(t *testing.T) {
	// Wildcard in style-src should NOT trigger the wildcard-source check
	// (the regex only matches script-src and default-src)
	resp := &http.Response{
		Header: http.Header{
			"Content-Security-Policy": []string{"style-src *; script-src 'self'"},
		},
	}
	findings := analyzeCSP("example.com", resp)
	found := findingsByCheckID(findings, finding.CheckCSPWildcardSource)
	if len(found) != 0 {
		t.Errorf("expected 0 wildcard findings for style-src wildcard only, got %d", len(found))
	}
}

func TestAnalyzeCSP_StrictPolicy_NoFindings(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{
			"Content-Security-Policy": []string{"default-src 'self'; script-src 'self' https://cdn.example.com; style-src 'self'"},
		},
	}
	findings := analyzeCSP("example.com", resp)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for strict CSP, got %d: %+v", len(findings), findings)
	}
}

func TestAnalyzeCSP_CaseInsensitive(t *testing.T) {
	// unsafe-inline in uppercase should still be detected
	resp := &http.Response{
		Header: http.Header{
			"Content-Security-Policy": []string{"script-src 'UNSAFE-INLINE'"},
		},
	}
	findings := analyzeCSP("example.com", resp)
	found := findingsByCheckID(findings, finding.CheckCSPUnsafeInline)
	if len(found) != 1 {
		t.Errorf("expected 1 unsafe-inline finding for uppercase 'UNSAFE-INLINE', got %d", len(found))
	}
}

// ===========================================================================
// detectWAF
// ===========================================================================

func TestDetectWAF_Cloudflare_NoFinding(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{
			"Cf-Ray":          []string{"abc123"},
			"Cf-Cache-Status": []string{"HIT"},
			"Server":          []string{"cloudflare"},
		},
	}
	f := detectWAF("example.com", resp)
	if f != nil {
		t.Error("expected nil finding when Cloudflare WAF is detected")
	}
}

func TestDetectWAF_AWSCloudFront_NoFinding(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{
			"X-Amz-Cf-Id":  []string{"xyz"},
			"X-Amz-Cf-Pop": []string{"IAD89-P3"},
		},
	}
	f := detectWAF("example.com", resp)
	if f != nil {
		t.Error("expected nil finding when CloudFront is detected")
	}
}

func TestDetectWAF_Akamai_NoFinding(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{
			"X-Akamai-Transformed": []string{"9 - 0"},
		},
	}
	f := detectWAF("example.com", resp)
	if f != nil {
		t.Error("expected nil finding when Akamai is detected")
	}
}

func TestDetectWAF_NoWAFHeaders_FindingEmitted(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{
			"Content-Type": []string{"text/html"},
			"X-Custom":     []string{"value"},
		},
	}
	f := detectWAF("example.com", resp)
	if f == nil {
		t.Fatal("expected a finding when no WAF headers are present")
	}
	if f.CheckID != finding.CheckWAFNotDetected {
		t.Errorf("expected CheckWAFNotDetected, got %s", f.CheckID)
	}
	if f.Severity != finding.SeverityMedium {
		t.Errorf("expected SeverityMedium, got %s", f.Severity)
	}
}

func TestDetectWAF_EmptyHeaders_FindingEmitted(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{},
	}
	f := detectWAF("example.com", resp)
	if f == nil {
		t.Fatal("expected a finding when response has no headers at all")
	}
	if f.CheckID != finding.CheckWAFNotDetected {
		t.Errorf("expected CheckWAFNotDetected, got %s", f.CheckID)
	}
}

func TestDetectWAF_Fastly_NoFinding(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{
			"X-Served-By": []string{"cache-iad-1234"},
		},
	}
	f := detectWAF("example.com", resp)
	if f != nil {
		t.Error("expected nil finding when Fastly is detected via x-served-by")
	}
}

func TestDetectWAF_Sucuri_NoFinding(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{
			"X-Sucuri-Id": []string{"12345"},
		},
	}
	f := detectWAF("example.com", resp)
	if f != nil {
		t.Error("expected nil finding when Sucuri is detected")
	}
}

func TestDetectWAF_Imperva_NoFinding(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{
			"X-Iinfo": []string{"4-12345-12345"},
		},
	}
	f := detectWAF("example.com", resp)
	if f != nil {
		t.Error("expected nil finding when Imperva is detected")
	}
}

// ===========================================================================
// analyzeResponseHeaders
// ===========================================================================

func TestAnalyzeResponseHeaders_AWSKeyInHeader(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{
			"X-Debug": []string{"AKIAIOSFODNN7EXAMPLE"},
		},
	}
	findings := analyzeResponseHeaders("example.com", resp)
	found := findingsByCheckID(findings, finding.CheckSecretInResponseHeader)
	if len(found) != 1 {
		t.Fatalf("expected 1 secret-in-header finding for AWS key, got %d", len(found))
	}
	if found[0].Severity != finding.SeverityHigh {
		t.Errorf("expected SeverityHigh, got %s", found[0].Severity)
	}
}

func TestAnalyzeResponseHeaders_GitHubTokenInHeader(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{
			"X-Token": []string{"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"},
		},
	}
	findings := analyzeResponseHeaders("example.com", resp)
	found := findingsByCheckID(findings, finding.CheckSecretInResponseHeader)
	if len(found) != 1 {
		t.Fatalf("expected 1 finding for GitHub token in header, got %d", len(found))
	}
}

func TestAnalyzeResponseHeaders_StripeKeyInHeader(t *testing.T) {
	// Construct at runtime to avoid triggering GitHub push protection.
	fakeKey := "sk_" + "live_ABCDEFGHIJKLMNOPQRSTUVWXyz"
	resp := &http.Response{
		Header: http.Header{
			"Authorization": []string{fakeKey},
		},
	}
	findings := analyzeResponseHeaders("example.com", resp)
	found := findingsByCheckID(findings, finding.CheckSecretInResponseHeader)
	if len(found) != 1 {
		t.Fatalf("expected 1 finding for Stripe key in header, got %d", len(found))
	}
}

func TestAnalyzeResponseHeaders_NoSecrets_NoFindings(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{
			"Content-Type":  []string{"text/html"},
			"Cache-Control": []string{"no-cache"},
			"X-Request-Id":  []string{"abc-123-def"},
		},
	}
	findings := analyzeResponseHeaders("example.com", resp)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean response headers, got %d", len(findings))
	}
}

func TestAnalyzeResponseHeaders_GenericAPIKeyInHeader(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{
			"X-Debug-Info": []string{"apikey=AbCdEfGhIjKlMnOpQrStUvWx"},
		},
	}
	findings := analyzeResponseHeaders("example.com", resp)
	found := findingsByCheckID(findings, finding.CheckSecretInResponseHeader)
	if len(found) != 1 {
		t.Fatalf("expected 1 finding for generic API key in header, got %d", len(found))
	}
}

// ===========================================================================
// Secret pattern matching (unit tests on the compiled regexes)
// ===========================================================================

func TestSecretPatterns_AWSAccessKey(t *testing.T) {
	tests := []struct {
		input string
		match bool
	}{
		{"AKIAIOSFODNN7EXAMPLE", true},
		{"AKIA1234567890ABCDEF", true},
		{"AKIA123", false},           // too short
		{"BKIAIOSFODNN7EXAMPLE", false}, // wrong prefix
	}
	re := secretPatterns["AWS Access Key"]
	for _, tt := range tests {
		if got := re.MatchString(tt.input); got != tt.match {
			t.Errorf("AWS Access Key pattern on %q: got %v, want %v", tt.input, got, tt.match)
		}
	}
}

func TestSecretPatterns_GitHubToken(t *testing.T) {
	tests := []struct {
		input string
		match bool
	}{
		{"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", true},
		{"ghp_12345678901234567890123456789012345a", true},
		{"ghp_short", false},
		{"ghr_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", false}, // wrong prefix
	}
	re := secretPatterns["GitHub Token"]
	for _, tt := range tests {
		if got := re.MatchString(tt.input); got != tt.match {
			t.Errorf("GitHub Token pattern on %q: got %v, want %v", tt.input, got, tt.match)
		}
	}
}

func TestSecretPatterns_StripeSecretKey(t *testing.T) {
	tests := []struct {
		input string
		match bool
	}{
		{"sk_" + "live_ABCDEFGHIJKLMNOPQRSTUVWXyz", true},
		{"sk_" + "live_1234567890ABCDEFGHIJKLMNop", true},
		{"sk_test_ABCDEFGHIJKLMNOPQRSTUVWXyz", false}, // not "live"
		{"sk_" + "live_short", false},                   // too short
	}
	re := secretPatterns["Stripe Secret Key"]
	for _, tt := range tests {
		if got := re.MatchString(tt.input); got != tt.match {
			t.Errorf("Stripe Secret Key pattern on %q: got %v, want %v", tt.input, got, tt.match)
		}
	}
}

func TestSecretPatterns_PrivateKey(t *testing.T) {
	tests := []struct {
		input string
		match bool
	}{
		{"-----BEGIN PRIVATE KEY-----", true},
		{"-----BEGIN RSA PRIVATE KEY-----", true},
		{"-----BEGIN EC PRIVATE KEY-----", true},
		{"-----BEGIN PUBLIC KEY-----", false},
	}
	re := secretPatterns["Private Key"]
	for _, tt := range tests {
		if got := re.MatchString(tt.input); got != tt.match {
			t.Errorf("Private Key pattern on %q: got %v, want %v", tt.input, got, tt.match)
		}
	}
}

func TestSecretPatterns_GenericAPIKey(t *testing.T) {
	tests := []struct {
		input string
		match bool
	}{
		{`api_key="abcdefghijklmnopqrstuvwxyz"`, true},
		{`apiKey='12345678901234567890'`, true},
		{`api-secret="ABCDEFGHIJKLMNOPqrst"`, true},
		{`api_key="short"`, false},                      // too short
	}
	re := secretPatterns["Generic API Key"]
	for _, tt := range tests {
		if got := re.MatchString(tt.input); got != tt.match {
			t.Errorf("Generic API Key pattern on %q: got %v, want %v", tt.input, got, tt.match)
		}
	}
}

func TestSecretPatterns_GenericPassword(t *testing.T) {
	tests := []struct {
		input string
		match bool
	}{
		{`password="MyS3cur3P@ss!"`, true},
		{`passwd='v3ryL0ngP@ssw0rd'`, true},
		{`pwd="12345678"`, true},
		{`password="short"`, false}, // < 8 chars
	}
	re := secretPatterns["Generic Password"]
	for _, tt := range tests {
		if got := re.MatchString(tt.input); got != tt.match {
			t.Errorf("Generic Password pattern on %q: got %v, want %v", tt.input, got, tt.match)
		}
	}
}

func TestSecretPatterns_OpenAIKey(t *testing.T) {
	key := "sk-" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv"
	re := secretPatterns["OpenAI API Key"]
	if !re.MatchString(key) {
		t.Errorf("expected OpenAI API Key pattern to match %q", key)
	}
	if re.MatchString("sk-tooshort") {
		t.Error("OpenAI API Key pattern should not match short values")
	}
}

func TestSecretPatterns_FirebaseAPIKey(t *testing.T) {
	tests := []struct {
		input string
		match bool
	}{
		{"AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ12345678", true},
		{"AIzaSy-_abcdefghijklmnopqrstuvwxyz12345", true},
		{"AIzaNotFirebase", false}, // AIza but not AIzaSy
	}
	re := secretPatterns["Firebase API Key"]
	for _, tt := range tests {
		if got := re.MatchString(tt.input); got != tt.match {
			t.Errorf("Firebase API Key pattern on %q: got %v, want %v", tt.input, got, tt.match)
		}
	}
}

// ===========================================================================
// Secret deduplication logic
// ===========================================================================

func TestGenericPwdFalsePositives(t *testing.T) {
	knownFP := []string{
		"password", "Password", "passwd", "pwd",
		"current-password", "new-password", "one-time-code",
		"off", "username,password",
	}
	for _, fp := range knownFP {
		if !genericPwdFalsePositives[fp] {
			t.Errorf("expected %q to be in genericPwdFalsePositives", fp)
		}
	}
}

func TestGenericPwdPlaceholderRe(t *testing.T) {
	tests := []struct {
		input string
		match bool
	}{
		{"%PASSWORD%", true},
		{"{secret}", true},
		{"<password>", true},
		{"{{PASSWORD}}", true},
		{"$SECRET_KEY", true},
		{"YOUR_PASSWORD", true},
		{"EXAMPLE", true},
		{"REPLACE", true},
		{"CHANGEME", true},
		{"TODO", true},
		{"FIXME", true},
		{"REDACTED", true},
		{"FILTERED", true},
		{"actualpassword123", false},
		{"MyS3cur3Pass!", false},
	}
	for _, tt := range tests {
		if got := genericPwdPlaceholderRe.MatchString(tt.input); got != tt.match {
			t.Errorf("genericPwdPlaceholderRe on %q: got %v, want %v", tt.input, got, tt.match)
		}
	}
}

func TestGenericPwdValueRe(t *testing.T) {
	tests := []struct {
		input string
		want  string // expected captured group, empty if no match
	}{
		{`="MyPassword"`, "MyPassword"},
		{`='secretval'`, "secretval"},
		{": `backtick`", "backtick"},
		{`= "spaced"`, "spaced"},
		{`no-match-here`, ""},
	}
	for _, tt := range tests {
		sub := genericPwdValueRe.FindStringSubmatch(tt.input)
		if tt.want == "" {
			if sub != nil {
				t.Errorf("genericPwdValueRe on %q: expected no match, got %v", tt.input, sub)
			}
			continue
		}
		if sub == nil || len(sub) < 2 || sub[1] != tt.want {
			got := ""
			if sub != nil && len(sub) >= 2 {
				got = sub[1]
			}
			t.Errorf("genericPwdValueRe on %q: got %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ===========================================================================
// Internal endpoint patterns
// ===========================================================================

func TestInternalEndpointPatterns(t *testing.T) {
	positives := []string{
		"http://localhost/api/v1",
		"http://127.0.0.1/admin",
		"http://10.0.0.1/internal",
		"http://172.16.0.1/api",
		"http://172.31.255.255/path",
		"http://192.168.1.1/config",
		"https://api.internal/v2",
		"https://service.localhost/health",
		"https://dev.example.com/api",
		"https://staging.example.com/v1",
		"https://test.example.org/api",
		"https://uat.example.com/health",
		"https://qa.example.com/data",
	}
	for _, u := range positives {
		matched := false
		for _, re := range internalEndpointPatterns {
			if re.MatchString(u) {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("expected internal endpoint pattern to match %q", u)
		}
	}

	negatives := []string{
		"https://api.example.com/v1",
		"https://cdn.example.com/bundle.js",
		"https://www.google.com",
	}
	for _, u := range negatives {
		matched := false
		for _, re := range internalEndpointPatterns {
			if re.MatchString(u) {
				matched = true
				break
			}
		}
		if matched {
			t.Errorf("expected internal endpoint pattern NOT to match %q", u)
		}
	}
}

// ===========================================================================
// CSP wildcard regex
// ===========================================================================

func TestCSPWildcardRe(t *testing.T) {
	tests := []struct {
		name  string
		input string
		match bool
	}{
		{"wildcard in script-src", "script-src * 'self'", true},
		{"wildcard in default-src", "default-src *", true},
		{"no wildcard in script-src", "script-src 'self' https://cdn.example.com", false},
		{"wildcard in style-src only", "style-src *; script-src 'self'", false},
		{"wildcard after semicolon in different directive", "script-src 'self'; style-src *", false},
		{"case insensitive Script-Src", "Script-Src *", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cspWildcardRe.MatchString(tt.input)
			if got != tt.match {
				t.Errorf("cspWildcardRe on %q: got %v, want %v", tt.input, got, tt.match)
			}
		})
	}
}

// ===========================================================================
// WAF signatures table completeness
// ===========================================================================

func TestWAFSignatures_AllVendorsHaveSignatures(t *testing.T) {
	expectedVendors := []string{
		"Cloudflare", "AWS CloudFront", "Akamai", "Fastly",
		"Sucuri", "Imperva", "Nginx WAF", "AWS WAF",
	}
	for _, vendor := range expectedVendors {
		sigs, ok := wafSignatures[vendor]
		if !ok {
			t.Errorf("missing WAF vendor %q in wafSignatures", vendor)
			continue
		}
		if len(sigs) == 0 {
			t.Errorf("WAF vendor %q has zero signatures", vendor)
		}
	}
}

// ===========================================================================
// Scanner Name
// ===========================================================================

func TestScannerName(t *testing.T) {
	s := New()
	if s.Name() != "webcontent" {
		t.Errorf("expected scanner name 'webcontent', got %q", s.Name())
	}
}

// ===========================================================================
// Firebase vs Google API Key dedup: Firebase keys match both patterns,
// but the Google API Key pattern should be suppressed in favor of Firebase.
// ===========================================================================

func TestFirebaseKeyMatchesBothGoogleAndFirebase(t *testing.T) {
	// A Firebase key (AIzaSy...) should match both Firebase API Key and Google API Key patterns
	key := "AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ12345678"

	firebaseMatch := secretPatterns["Firebase API Key"].MatchString(key)
	googleMatch := secretPatterns["Google API Key"].MatchString(key)

	if !firebaseMatch {
		t.Error("expected Firebase API Key pattern to match AIzaSy... key")
	}
	if !googleMatch {
		t.Error("expected Google API Key pattern to match AIzaSy... key (dedup is done in analyzeJS)")
	}
}

// ===========================================================================
// extractJSURLs edge cases
// ===========================================================================

func TestExtractJSURLs_ProtocolRelativeWithPath(t *testing.T) {
	got := extractJSURLs("https://example.com", `<script src="//cdn.com/path/to/bundle.js"></script>`)
	if len(got) != 1 || got[0] != "https://cdn.com/path/to/bundle.js" {
		t.Errorf("expected https://cdn.com/path/to/bundle.js, got %v", got)
	}
}

func TestExtractJSURLs_Cap50Scripts(t *testing.T) {
	// Build HTML with 60 unique script tags
	var html string
	for i := 0; i < 60; i++ {
		html += `<script src="https://cdn.example.com/file` + string(rune('A'+i%26)) + string(rune('A'+i/26)) + `.js"></script>`
	}
	got := extractJSURLs("https://example.com", html)
	if len(got) > 50 {
		t.Errorf("expected at most 50 JS URLs (capped), got %d", len(got))
	}
}

func TestExtractJSURLs_MixedAbsoluteAndRelative(t *testing.T) {
	html := `
		<script src="https://cdn.example.com/vendor.js"></script>
		<script src="/static/app.js"></script>
		<script src="//other.cdn.com/lib.js"></script>
	`
	got := extractJSURLs("https://example.com", html)
	if len(got) != 3 {
		t.Fatalf("expected 3 JS URLs, got %d: %v", len(got), got)
	}
	expected := []string{
		"https://cdn.example.com/vendor.js",
		"https://example.com/static/app.js",
		"https://other.cdn.com/lib.js",
	}
	for i, want := range expected {
		if got[i] != want {
			t.Errorf("URL[%d] = %q, want %q", i, got[i], want)
		}
	}
}
