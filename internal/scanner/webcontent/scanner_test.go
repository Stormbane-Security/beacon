package webcontent

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
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
	// SameSite field is left at Go's zero value (0). Absent SameSite should
	// trigger the finding since the browser will default to Lax but the
	// server hasn't explicitly set a policy.
	resp := &http.Response{
		Header: http.Header{
			"Set-Cookie": []string{"sid=val; Secure; HttpOnly"},
		},
	}
	findings := analyzeCookies("example.com", resp)
	found := findingsByCheckID(findings, finding.CheckCookieMissingSameSite)
	if len(found) != 1 {
		t.Errorf("expected 1 CheckCookieMissingSameSite finding when SameSite attr is absent, got %d", len(found))
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
		if len(sub) < 2 || sub[1] != tt.want {
			got := ""
			if len(sub) >= 2 {
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

// TestExtractJSURLs_HTTPScheme verifies relative path resolution works
// correctly for http:// base URLs (7-char scheme, not 8-char https://).
func TestExtractJSURLs_HTTPScheme(t *testing.T) {
	html := `<script src="/js/app.js"></script>`
	got := extractJSURLs("http://example.com", html)
	if len(got) != 1 {
		t.Fatalf("expected 1 JS URL, got %d: %v", len(got), got)
	}
	want := "http://example.com/js/app.js"
	if got[0] != want {
		t.Errorf("URL = %q, want %q", got[0], want)
	}
}

// TestExtractJSURLs_HTTPWithPath verifies base URL path is stripped correctly.
func TestExtractJSURLs_HTTPWithPath(t *testing.T) {
	html := `<script src="/bundle.js"></script>`
	got := extractJSURLs("http://example.com/some/page", html)
	if len(got) != 1 {
		t.Fatalf("expected 1 JS URL, got %d: %v", len(got), got)
	}
	want := "http://example.com/bundle.js"
	if got[0] != want {
		t.Errorf("URL = %q, want %q", got[0], want)
	}
}

// TestExtractJSURLs_HTTPSWithPort verifies port numbers are preserved.
func TestExtractJSURLs_HTTPSWithPort(t *testing.T) {
	html := `<script src="/app.js"></script>`
	got := extractJSURLs("https://example.com:8443/path", html)
	if len(got) != 1 {
		t.Fatalf("expected 1 JS URL, got %d: %v", len(got), got)
	}
	want := "https://example.com:8443/app.js"
	if got[0] != want {
		t.Errorf("URL = %q, want %q", got[0], want)
	}
}

// TestExtractJSURLs_NoScheme verifies graceful handling when baseURL has no scheme.
func TestExtractJSURLs_NoScheme(t *testing.T) {
	html := `<script src="/app.js"></script>`
	got := extractJSURLs("example.com", html)
	// Relative URL resolved against schemeless base won't start with "http",
	// so it should be filtered out.
	if len(got) != 0 {
		t.Errorf("expected 0 JS URLs for schemeless base, got %d: %v", len(got), got)
	}
}

// ===========================================================================
// CSP wildcard regex — subdomain pattern should NOT be flagged
// ===========================================================================

// ===========================================================================
// detectServerInfoLeak
// ===========================================================================

func TestDetectServerInfoLeak_NginxVersion_FindingEmitted(t *testing.T) {
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Set("Server", "nginx/1.25.3")

	f := detectServerInfoLeak("example.com", resp)
	if f == nil {
		t.Fatal("expected finding for Server header with version")
	}
	if f.CheckID != finding.CheckHeadersServerInfoLeak {
		t.Errorf("unexpected CheckID: %s", f.CheckID)
	}
	if f.Evidence["server"] != "nginx/1.25.3" {
		t.Errorf("expected server evidence, got: %v", f.Evidence)
	}
}

func TestDetectServerInfoLeak_ServerNoVersion_NoFinding(t *testing.T) {
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Set("Server", "nginx")

	f := detectServerInfoLeak("example.com", resp)
	if f != nil {
		t.Errorf("Server header without version should not emit finding, got: %v", f)
	}
}

func TestDetectServerInfoLeak_XPoweredBy_FindingEmitted(t *testing.T) {
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Set("X-Powered-By", "Express")

	f := detectServerInfoLeak("example.com", resp)
	if f == nil {
		t.Fatal("expected finding for X-Powered-By header")
	}
	if f.Evidence["x_powered_by"] != "Express" {
		t.Errorf("expected x_powered_by evidence, got: %v", f.Evidence)
	}
}

func TestDetectServerInfoLeak_AspNetVersion_FindingEmitted(t *testing.T) {
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Set("X-AspNet-Version", "4.0.30319")

	f := detectServerInfoLeak("example.com", resp)
	if f == nil {
		t.Fatal("expected finding for X-AspNet-Version header")
	}
	if f.Evidence["x_aspnet_version"] != "4.0.30319" {
		t.Errorf("expected x_aspnet_version evidence, got: %v", f.Evidence)
	}
}

func TestDetectServerInfoLeak_MultipleHeaders_AllInEvidence(t *testing.T) {
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Set("Server", "Apache/2.4.51")
	resp.Header.Set("X-Powered-By", "PHP/8.1.0")
	resp.Header.Set("X-AspNetMvc-Version", "5.2")

	f := detectServerInfoLeak("example.com", resp)
	if f == nil {
		t.Fatal("expected finding for multiple leaking headers")
	}
	if f.Evidence["server"] != "Apache/2.4.51" {
		t.Error("missing server evidence")
	}
	if f.Evidence["x_powered_by"] != "PHP/8.1.0" {
		t.Error("missing x_powered_by evidence")
	}
	if f.Evidence["x_aspnetmvc_version"] != "5.2" {
		t.Error("missing x_aspnetmvc_version evidence")
	}
}

func TestDetectServerInfoLeak_NoHeaders_NoFinding(t *testing.T) {
	resp := &http.Response{Header: http.Header{}}

	f := detectServerInfoLeak("example.com", resp)
	if f != nil {
		t.Errorf("no leaking headers should not emit finding, got: %v", f)
	}
}

func TestCSPWildcardRe_SubdomainPatternNotFlagged(t *testing.T) {
	// "*.example.com" is a subdomain wildcard, NOT a bare wildcard.
	// Only a bare "*" (with whitespace boundaries) should be flagged.
	tests := []struct {
		name  string
		input string
		match bool
	}{
		{
			name:  "subdomain wildcard in script-src",
			input: "script-src 'self' *.example.com",
			match: false,
		},
		{
			name:  "multiple subdomain wildcards",
			input: "script-src *.cdn.example.com *.static.example.com",
			match: false,
		},
		{
			name:  "subdomain wildcard in default-src",
			input: "default-src 'self' *.example.com",
			match: false,
		},
		{
			name:  "bare wildcard should still be flagged",
			input: "script-src 'self' *",
			match: true,
		},
		{
			name:  "bare wildcard mid-directive",
			input: "script-src * 'unsafe-inline'",
			match: true,
		},
		{
			name:  "bare wildcard with semicolon after",
			input: "script-src *; style-src 'self'",
			match: true,
		},
		{
			name:  "subdomain wildcard with bare wildcard — should flag",
			input: "script-src *.example.com *",
			match: true,
		},
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

// ---------------------------------------------------------------------------
// discoverNextJSChunks tests
// ---------------------------------------------------------------------------

func TestDiscoverNextJSChunks_ManifestParsed(t *testing.T) {
	const buildID = "abc123XYZ"
	manifest := `self.__BUILD_MANIFEST={
		"/": ["static/chunks/pages/index-9f2a1b3c.js"],
		"/about": ["static/chunks/pages/about-d4e5f678.js"],
		"/dashboard": ["static/chunks/pages/dashboard-1a2b3c4d.js"],
		"_app": ["static/chunks/app/layout-aabbccdd.js"]
	}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expected := "/_next/static/" + buildID + "/_buildManifest.js"
		if r.URL.Path == expected {
			_, _ = fmt.Fprint(w, manifest)
		} else {
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	html := fmt.Sprintf(`<script id="__NEXT_DATA__">{"buildId":"%s","props":{}}</script>`, buildID)
	chunks := discoverNextJSChunks(context.Background(), srv.Client(), srv.URL, html)

	if len(chunks) != 4 {
		t.Fatalf("expected 4 chunks, got %d: %v", len(chunks), chunks)
	}
	for _, c := range chunks {
		if c[:len(srv.URL)] != srv.URL {
			t.Errorf("chunk URL should start with server URL: %s", c)
		}
	}
}

func TestDiscoverNextJSChunks_NoBuildID_ReturnsNil(t *testing.T) {
	html := `<html><body>Not a Next.js app</body></html>`
	chunks := discoverNextJSChunks(context.Background(), http.DefaultClient, "https://example.com", html)
	if chunks != nil {
		t.Fatalf("expected nil for non-Next.js page, got %v", chunks)
	}
}

func TestDiscoverNextJSChunks_ManifestNotFound_ReturnsEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	html := `<script id="__NEXT_DATA__">{"buildId":"testBuild123","props":{}}</script>`
	chunks := discoverNextJSChunks(context.Background(), srv.Client(), srv.URL, html)
	if len(chunks) != 0 {
		t.Fatalf("expected 0 chunks when manifest 404s, got %d", len(chunks))
	}
}

func TestDiscoverNextJSChunks_HTMLInlineChunkRefs(t *testing.T) {
	// Chunks referenced in __NEXT_DATA__ JSON or inline script variables
	// use the same "static/chunks/..." pattern the regex expects.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	html := `<script id="__NEXT_DATA__">{"buildId":"inlineBuild","props":{},
		"chunks":["static/chunks/pages/inline-aabb1122.js","app/layout-ccdd3344.js"]}</script>`

	chunks := discoverNextJSChunks(context.Background(), srv.Client(), srv.URL, html)
	if len(chunks) != 2 {
		t.Fatalf("expected 2 inline chunks, got %d: %v", len(chunks), chunks)
	}
}

func TestDiscoverNextJSChunks_Deduplication(t *testing.T) {
	const buildID = "dedup123"
	manifest := `self.__BUILD_MANIFEST={"/": ["static/chunks/pages/index-aabb.js"]}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_next/static/"+buildID+"/_buildManifest.js" {
			_, _ = fmt.Fprint(w, manifest)
		} else {
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	html := fmt.Sprintf(`<script id="__NEXT_DATA__">{"buildId":"%s"}</script>
	<script src="/_next/static/chunks/pages/index-aabb.js"></script>`, buildID)

	chunks := discoverNextJSChunks(context.Background(), srv.Client(), srv.URL, html)
	if len(chunks) != 1 {
		t.Fatalf("expected 1 deduplicated chunk, got %d: %v", len(chunks), chunks)
	}
}

// ---------------------------------------------------------------------------
// extractServiceReferences tests
// ---------------------------------------------------------------------------

func TestExtractServiceReferences_HeliusRPC(t *testing.T) {
	src := `const rpcURL = "https://mainnet.helius-rpc.com/?api-key=${p.env.HELIUS_API_KEY}";`
	findings := extractServiceReferences("example.com", "https://example.com/app.js", src, time.Now())

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.CheckID != finding.CheckJSExternalServiceRef {
		t.Errorf("wrong check ID: %s", f.CheckID)
	}
	if f.Evidence["service"] != "Helius RPC (Solana)" {
		t.Errorf("wrong service: %v", f.Evidence["service"])
	}
	if f.Evidence["category"] != "blockchain" {
		t.Errorf("wrong category: %v", f.Evidence["category"])
	}
}

func TestExtractServiceReferences_MultipleServices(t *testing.T) {
	src := `
		fetch("https://api.stripe.com/v1/charges", {headers: {"Authorization": "Bearer " + key}});
		fetch("https://o123.sentry.io/api/456/store/", {body: JSON.stringify(event)});
		fetch("https://mainnet.helius-rpc.com/?api-key=test123");
	`
	findings := extractServiceReferences("example.com", "https://example.com/app.js", src, time.Now())

	if len(findings) != 3 {
		t.Fatalf("expected 3 findings (Stripe, Sentry, Helius), got %d", len(findings))
	}

	services := make(map[string]bool)
	for _, f := range findings {
		svc := f.Evidence["service"].(string)
		services[svc] = true
	}
	for _, expected := range []string{"Stripe API", "Sentry", "Helius RPC (Solana)"} {
		if !services[expected] {
			t.Errorf("missing expected service: %s", expected)
		}
	}
}

func TestExtractServiceReferences_DeduplicatesSameService(t *testing.T) {
	src := `
		fetch("https://api.stripe.com/v1/charges");
		fetch("https://api.stripe.com/v1/customers");
		fetch("https://api.stripe.com/v1/invoices");
	`
	findings := extractServiceReferences("example.com", "https://example.com/app.js", src, time.Now())

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (deduplicated Stripe), got %d", len(findings))
	}
}

func TestExtractServiceReferences_NoKnownServices(t *testing.T) {
	src := `
		const x = "hello world";
		fetch("https://internal.company.com/api/v1/data");
		fetch("https://cdn.example.com/assets/logo.png");
	`
	findings := extractServiceReferences("example.com", "https://example.com/app.js", src, time.Now())

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for unknown services, got %d", len(findings))
	}
}

func TestExtractServiceReferences_NoURLs(t *testing.T) {
	src := `const greeting = "hello"; function add(a,b) { return a+b; }`
	findings := extractServiceReferences("example.com", "https://example.com/app.js", src, time.Now())

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for JS without URLs, got %d", len(findings))
	}
}

func TestExtractServiceReferences_AllCategories(t *testing.T) {
	src := `
		fetch("https://mainnet.helius-rpc.com/rpc");
		fetch("https://api.stripe.com/v1/charges");
		fetch("https://myapp.auth0.com/authorize");
		fetch("https://api.openai.com/v1/chat");
		fetch("https://s3.amazonaws.com/bucket/key");
		fetch("https://api.segment.io/v1/track");
		fetch("https://o123.sentry.io/api/store");
		fetch("https://api.sendgrid.com/v3/mail/send");
		fetch("https://search.algolia.net/1/indexes");
		fetch("https://db.neon.tech/sql");
	`
	findings := extractServiceReferences("example.com", "https://example.com/app.js", src, time.Now())

	categories := make(map[string]bool)
	for _, f := range findings {
		cat := f.Evidence["category"].(string)
		categories[cat] = true
	}

	expected := []string{"blockchain", "payments", "auth", "ai", "cloud", "analytics", "monitoring", "messaging", "search", "database"}
	for _, cat := range expected {
		if !categories[cat] {
			t.Errorf("missing category: %s (found: %v)", cat, categories)
		}
	}
}

func TestExtractServiceReferences_ProofCommandFormat(t *testing.T) {
	src := `fetch("https://api.stripe.com/v1/charges");`
	findings := extractServiceReferences("example.com", "https://example.com/app.js", src, time.Now())

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	proof := findings[0].ProofCommand
	if proof == "" {
		t.Fatal("ProofCommand should not be empty")
	}
	if !strContains(proof, "curl") || !strContains(proof, "api.stripe.com") {
		t.Errorf("ProofCommand should contain curl and domain: %s", proof)
	}
}

// ---------------------------------------------------------------------------
// extractEnvVarRefs tests
// ---------------------------------------------------------------------------

func TestExtractEnvVarRefs_ProcessEnv(t *testing.T) {
	src := `const url = "https://api.example.com/" + process.env.API_KEY;`
	refs := extractEnvVarRefs(src, "https://api.example.com/")

	if len(refs) == 0 {
		t.Fatal("expected env var refs, got none")
	}
	// The regex matches "process.env." as the pattern — the variable name
	// isn't captured by the env var regex, but the presence of process.env.
	// near the URL is the signal we care about.
	found := false
	for _, r := range refs {
		if strContains(r, "process.env") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected process.env ref, got: %v", refs)
	}
}

func TestExtractEnvVarRefs_ImportMetaEnv(t *testing.T) {
	src := `const endpoint = import.meta.env.VITE_API_URL + "/v1/data";`
	refs := extractEnvVarRefs(src, "/v1/data")

	found := false
	for _, r := range refs {
		if strContains(r, "import.meta.env") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected import.meta.env ref, got: %v", refs)
	}
}

func TestExtractEnvVarRefs_TemplateLiteral(t *testing.T) {
	src := `const url = "https://rpc.helius.com/?api-key=${p.env.HELIUS_API_KEY}";`
	refs := extractEnvVarRefs(src, "https://rpc.helius.com/")

	found := false
	for _, r := range refs {
		if strContains(r, "env") && strContains(r, "HELIUS") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected HELIUS env var ref, got: %v", refs)
	}
}

func TestExtractEnvVarRefs_ConstantPattern(t *testing.T) {
	src := `const headers = { "Authorization": "Bearer " + STRIPE_SECRET_KEY }; fetch("https://api.stripe.com/v1/charges");`
	refs := extractEnvVarRefs(src, "https://api.stripe.com/")

	found := false
	for _, r := range refs {
		if strContains(r, "STRIPE_SECRET_KEY") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected STRIPE_SECRET_KEY ref, got: %v", refs)
	}
}

func TestExtractEnvVarRefs_URLNotFound_ReturnsNil(t *testing.T) {
	src := `const x = "hello world";`
	refs := extractEnvVarRefs(src, "https://not-in-source.com/")

	if refs != nil {
		t.Fatalf("expected nil when URL not found, got %v", refs)
	}
}

func TestExtractEnvVarRefs_NoDuplicates(t *testing.T) {
	src := `process.env.KEY process.env.KEY fetch("https://api.example.com/") process.env.KEY`
	refs := extractEnvVarRefs(src, "https://api.example.com/")

	if len(refs) != 1 {
		t.Fatalf("expected 1 deduplicated ref, got %d: %v", len(refs), refs)
	}
}

// ---------------------------------------------------------------------------
// Next.js regex tests
// ---------------------------------------------------------------------------

func TestNextBuildIDRe(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"standard", `{"buildId":"abc123XYZ","props":{}}`, "abc123XYZ"},
		{"with spaces", `{"buildId" : "def-456_ghi","runtimeConfig":{}}`, "def-456_ghi"},
		{"no match", `{"version":"1.0","name":"app"}`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := nextBuildIDRe.FindStringSubmatch(tt.input)
			got := ""
			if len(m) >= 2 {
				got = m[1]
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNextChunkRefRe(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int
	}{
		{"pages chunk", `"static/chunks/pages/index-9f2a1b3c.js"`, 1},
		{"app chunk", `"app/layout-aabbccdd.js"`, 1},
		{"multiple", `"static/chunks/1-hash.js","pages/about-hash.js","app/page-hash.js"`, 3},
		{"no match", `"styles/globals.css","images/logo.png"`, 0},
		{"non-js", `"static/chunks/data.json"`, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := nextChunkRefRe.FindAllStringSubmatch(tt.input, -1)
			if len(matches) != tt.want {
				t.Errorf("got %d matches, want %d", len(matches), tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Integration: discoverNextJSChunks → extractServiceReferences pipeline
// ---------------------------------------------------------------------------

func TestNextJSChunks_ServiceRefsInChunks(t *testing.T) {
	const buildID = "pipelineBuild"

	manifest := `self.__BUILD_MANIFEST={"/dashboard": ["static/chunks/pages/dashboard-aabb.js"]}`
	chunkBody := `
		import {Connection} from "@solana/web3.js";
		const conn = new Connection("https://mainnet.helius-rpc.com/?api-key=${p.env.HELIUS_API_KEY}");
	`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/_next/static/" + buildID + "/_buildManifest.js":
			_, _ = fmt.Fprint(w, manifest)
		case "/_next/static/chunks/pages/dashboard-aabb.js":
			_, _ = fmt.Fprint(w, chunkBody)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	html := fmt.Sprintf(`<script id="__NEXT_DATA__">{"buildId":"%s"}</script>`, buildID)

	chunks := discoverNextJSChunks(context.Background(), srv.Client(), srv.URL, html)
	if len(chunks) != 1 {
		t.Fatalf("expected 1 chunk, got %d", len(chunks))
	}

	body := fetchJSBody(context.Background(), srv.Client(), chunks[0])
	findings := extractServiceReferences("example.com", chunks[0], body, time.Now())

	if len(findings) != 1 {
		t.Fatalf("expected 1 service ref finding, got %d", len(findings))
	}
	if findings[0].Evidence["service"] != "Helius RPC (Solana)" {
		t.Errorf("wrong service: %v", findings[0].Evidence)
	}
}

// ---------------------------------------------------------------------------
// checkAPIKeyInURLs — public key domain exclusions
// ---------------------------------------------------------------------------

func TestCheckAPIKeyInURLs_SentryDSN_Excluded(t *testing.T) {
	src := `Sentry.init({ dsn: "https://o447951.ingest.sentry.io/api/450?key=dfb07d783ad5325c245c1fd3725390" });`
	matches := checkAPIKeyInURLs(src)
	if len(matches) != 0 {
		t.Errorf("Sentry DSN should be excluded from API key check, got %d matches: %v", len(matches), matches)
	}
}

func TestCheckAPIKeyInURLs_SentryLegacy_Excluded(t *testing.T) {
	src := `fetch("https://sentry.io/api/123/store/?sentry_key=abc123def456");`
	matches := checkAPIKeyInURLs(src)
	if len(matches) != 0 {
		t.Errorf("Sentry legacy DSN should be excluded, got %d matches", len(matches))
	}
}

func TestCheckAPIKeyInURLs_RealAPIKey_StillDetected(t *testing.T) {
	src := `fetch("https://api.example.com/v1/data?api_key=sk_live_1234567890abcdef");`
	matches := checkAPIKeyInURLs(src)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match for real API key, got %d", len(matches))
	}
}

func TestCheckAPIKeyInURLs_AlgoliaSearch_Excluded(t *testing.T) {
	src := `fetch("https://APPID.algolia.net/1/indexes?key=searchOnlyKey123");`
	matches := checkAPIKeyInURLs(src)
	if len(matches) != 0 {
		t.Errorf("Algolia search key should be excluded, got %d matches", len(matches))
	}
}

func strContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
