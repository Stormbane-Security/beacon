package chainengine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)

func TestNew_RejectsNonAuthorized(t *testing.T) {
	tests := []struct {
		name     string
		scanType module.ScanType
	}{
		{"ScanSurface", module.ScanSurface},
		{"ScanDeep", module.ScanDeep},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.scanType)
			if err == nil {
				t.Fatalf("expected error for %s, got nil", tt.scanType)
			}
			if !strings.Contains(err.Error(), "ScanAuthorized") {
				t.Errorf("error should mention ScanAuthorized, got: %v", err)
			}
		})
	}
}

func TestNew_AcceptsScanAuthorized(t *testing.T) {
	e, err := New(module.ScanAuthorized)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e == nil {
		t.Fatal("engine is nil")
	}
	if e.scanType != module.ScanAuthorized {
		t.Errorf("expected ScanAuthorized, got %q", e.scanType)
	}
}

func TestOnFinding_NonTriggerReturnsEmpty(t *testing.T) {
	e, err := New(module.ScanAuthorized)
	if err != nil {
		t.Fatal(err)
	}

	// Feed a finding that doesn't match any chain trigger.
	f := finding.Finding{
		CheckID: "headers.missing_csp",
		Asset:   "example.com",
	}

	results := e.OnFinding(context.Background(), f)
	if len(results) != 0 {
		t.Errorf("expected 0 results for non-trigger finding, got %d", len(results))
	}
}

func TestOnFinding_SSRFChainExecutes(t *testing.T) {
	// Set up a mock server that simulates the SSRF + metadata endpoint.
	roleName := "test-iam-role"
	credJSON := fmt.Sprintf(`{"AccessKeyId":"AKIA1234567890ABCDEF","SecretAccessKey":"secret","Token":"tok"}`)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		switch {
		case strings.Contains(target, "/latest/meta-data/iam/security-credentials/"+roleName):
			fmt.Fprint(w, credJSON)
		case strings.Contains(target, "/latest/meta-data/iam/security-credentials/"):
			fmt.Fprint(w, roleName)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	e, err := New(module.ScanAuthorized)
	if err != nil {
		t.Fatal(err)
	}

	trigger := finding.Finding{
		CheckID: finding.CheckWebSSRF,
		Asset:   "target.example.com",
		Evidence: map[string]any{
			"url":       srv.URL + "/fetch?url=placeholder",
			"parameter": "url",
		},
	}

	results := e.OnFinding(context.Background(), trigger)
	if len(results) != 1 {
		t.Fatalf("expected 1 chain finding, got %d", len(results))
	}

	f := results[0]
	if f.CheckID != finding.CheckChainSSRFToCloudCreds {
		t.Errorf("expected check ID %q, got %q", finding.CheckChainSSRFToCloudCreds, f.CheckID)
	}
	if f.Severity != finding.SeverityCritical {
		t.Errorf("expected Critical severity, got %q", f.Severity)
	}

	// Verify IAM role is in evidence.
	if role, ok := f.Evidence["iam_role"].(string); !ok || role != roleName {
		t.Errorf("expected iam_role %q, got %v", roleName, f.Evidence["iam_role"])
	}

	// Verify access key is redacted.
	accessKey, _ := f.Evidence["access_key_id"].(string)
	if strings.Contains(accessKey, "567890") {
		t.Errorf("access key should be redacted, got %q", accessKey)
	}
	if !strings.HasPrefix(accessKey, "AKIA") {
		t.Errorf("redacted key should start with first 4 chars, got %q", accessKey)
	}
}

func TestOnFinding_ChainDepthAndEnabledBy(t *testing.T) {
	roleName := "my-role"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		if strings.Contains(target, "/latest/meta-data/iam/security-credentials/"+roleName) {
			fmt.Fprint(w, `{"AccessKeyId":"AKIAXXXXXXXXYYYYYYYY","SecretAccessKey":"s"}`)
		} else if strings.Contains(target, "/latest/meta-data/iam/security-credentials/") {
			fmt.Fprint(w, roleName)
		} else {
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	e, _ := New(module.ScanAuthorized)

	trigger := finding.Finding{
		CheckID:    finding.CheckWebSSRF,
		Asset:      "app.example.com",
		ChainDepth: 0,
		Evidence: map[string]any{
			"url":       srv.URL + "/proxy?url=placeholder",
			"parameter": "url",
		},
	}

	results := e.OnFinding(context.Background(), trigger)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	f := results[0]
	if f.ChainDepth != 1 {
		t.Errorf("expected ChainDepth 1, got %d", f.ChainDepth)
	}
	if f.EnabledBy != "web.ssrf|app.example.com" {
		t.Errorf("expected EnabledBy %q, got %q", "web.ssrf|app.example.com", f.EnabledBy)
	}
}

func TestOnFinding_EnvChainRedactsCredentials(t *testing.T) {
	e, _ := New(module.ScanAuthorized)

	envContent := `
DB_HOST=db.internal.example.com
DB_USER=admin
DB_PASS=supersecretpassword123
DB_NAME=production
`
	trigger := finding.Finding{
		CheckID: finding.CheckExposureEnvFile,
		Asset:   "app.example.com",
		Evidence: map[string]any{
			"content": envContent,
			"url":     "https://app.example.com/.env",
		},
	}

	results := e.OnFinding(context.Background(), trigger)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	f := results[0]
	if f.CheckID != finding.CheckChainEnvToDatabaseAccess {
		t.Errorf("expected %q, got %q", finding.CheckChainEnvToDatabaseAccess, f.CheckID)
	}

	// Verify password is redacted.
	password, _ := f.Evidence["password"].(string)
	if password != "****" {
		t.Errorf("password should be redacted as '****', got %q", password)
	}

	// Verify the actual password is NOT in any evidence field.
	for k, v := range f.Evidence {
		if str, ok := v.(string); ok && strings.Contains(str, "supersecretpassword123") {
			t.Errorf("real password leaked in evidence field %q: %q", k, str)
		}
	}

	// Verify database host is present.
	if host, _ := f.Evidence["database_host"].(string); host != "db.internal.example.com" {
		t.Errorf("expected database_host %q, got %q", "db.internal.example.com", host)
	}
}

func TestOnFinding_DefaultCredsChainMatches(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "admin panel")
	}))
	defer srv.Close()

	e, _ := New(module.ScanAuthorized)

	trigger := finding.Finding{
		CheckID: "port.grafana_default_credentials",
		Asset:   "grafana.example.com",
		Evidence: map[string]any{
			"login_url":     srv.URL + "/login",
			"username":      "admin",
			"password":      "admin",
			"session_token": "grafana_session=abc123def456ghi789",
		},
	}

	results := e.OnFinding(context.Background(), trigger)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	f := results[0]
	if f.CheckID != finding.CheckChainDefaultCredsToAdmin {
		t.Errorf("expected %q, got %q", finding.CheckChainDefaultCredsToAdmin, f.CheckID)
	}

	// Verify session token is redacted.
	redacted, _ := f.Evidence["session_token_redacted"].(string)
	if strings.Contains(redacted, "abc123def456ghi789") {
		t.Error("session token should be redacted")
	}
	if !strings.Contains(redacted, "****") {
		t.Errorf("redacted token should contain ****, got %q", redacted)
	}

	// Verify visibility.
	if f.Visibility != finding.VisibilityAuthenticated {
		t.Errorf("expected authenticated visibility, got %q", f.Visibility)
	}
}

func TestOnFinding_ContextCancellation(t *testing.T) {
	e, _ := New(module.ScanAuthorized)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	trigger := finding.Finding{
		CheckID: finding.CheckWebSSRF,
		Asset:   "target.example.com",
		Evidence: map[string]any{
			"url":       "http://target.example.com/fetch?url=test",
			"parameter": "url",
		},
	}

	results := e.OnFinding(ctx, trigger)
	if len(results) != 0 {
		t.Errorf("expected 0 results when context cancelled, got %d", len(results))
	}
}

func TestResults_AccumulatesFindings(t *testing.T) {
	e, _ := New(module.ScanAuthorized)

	// Manually add findings to verify Results() returns them.
	e.mu.Lock()
	e.findings = append(e.findings, finding.Finding{
		CheckID: finding.CheckChainSSRFToCloudCreds,
		Asset:   "a.example.com",
	}, finding.Finding{
		CheckID: finding.CheckChainEnvToDatabaseAccess,
		Asset:   "b.example.com",
	})
	e.mu.Unlock()

	results := e.Results()
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	// Verify Results() returns a copy.
	results[0].Asset = "modified"
	original := e.Results()
	if original[0].Asset == "modified" {
		t.Error("Results() should return a copy, not a reference")
	}
}

func TestParseEnvContent(t *testing.T) {
	content := `
# Database config
DB_HOST=localhost
DB_USER=admin
DB_PASS="my secret password"
DB_NAME='production'
EMPTY=
# Comment line
REDIS_URL=redis://localhost:6379
`
	vars := parseEnvContent(content)

	tests := []struct {
		key, want string
	}{
		{"DB_HOST", "localhost"},
		{"DB_USER", "admin"},
		{"DB_PASS", "my secret password"},
		{"DB_NAME", "production"},
		{"REDIS_URL", "redis://localhost:6379"},
	}
	for _, tt := range tests {
		if got := vars[tt.key]; got != tt.want {
			t.Errorf("parseEnvContent[%q] = %q, want %q", tt.key, got, tt.want)
		}
	}
}

func TestBuildUnionSelectPayload(t *testing.T) {
	payload := buildUnionSelectPayload(4)
	if !strings.Contains(payload, "UNION SELECT") {
		t.Error("payload should contain UNION SELECT")
	}
	if !strings.Contains(payload, "username") {
		t.Error("payload should contain 'username'")
	}
	if !strings.Contains(payload, "password") {
		t.Error("payload should contain 'password'")
	}
	if !strings.Contains(payload, "NULL") {
		t.Error("4-column payload should contain NULL")
	}
	if !strings.Contains(payload, "FROM users") {
		t.Error("payload should target users table")
	}
}

func TestCountCredentialRows(t *testing.T) {
	// Body with bcrypt hashes.
	body := `admin,$2b$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ123
user1,$2b$12$xyzxyzxyzxyzxyzxyzxyzuvABCDEFGHIJKLMNOPQRSTUVWXYZ456`
	count := countCredentialRows(body)
	if count == 0 {
		t.Error("should detect credential rows with bcrypt hashes")
	}

	// Body with no credential data.
	empty := `<html><body>Not Found</body></html>`
	count = countCredentialRows(empty)
	if count != 0 {
		t.Errorf("expected 0 for non-credential body, got %d", count)
	}
}

func TestExtractBaseURL(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"https://example.com/login", "https://example.com"},
		{"http://example.com:8080/admin/login", "http://example.com:8080"},
		{"http://example.com", "http://example.com"},
	}
	for _, tt := range tests {
		if got := extractBaseURL(tt.input); got != tt.want {
			t.Errorf("extractBaseURL(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestBuildSSRFURL(t *testing.T) {
	tests := []struct {
		ssrfURL, param, payload, want string
	}{
		{
			"http://target.com/fetch?url=original",
			"url",
			"http://169.254.169.254/",
			"http://target.com/fetch?url=http://169.254.169.254/",
		},
		{
			"http://target.com/fetch?a=1&url=original",
			"url",
			"http://metadata/",
			"http://target.com/fetch?a=1&url=http://metadata/",
		},
		{
			"http://target.com/fetch",
			"url",
			"http://metadata/",
			"http://target.com/fetch?url=http://metadata/",
		},
	}
	for _, tt := range tests {
		got := buildSSRFURL(tt.ssrfURL, tt.param, tt.payload)
		if got != tt.want {
			t.Errorf("buildSSRFURL(%q, %q, %q) = %q, want %q", tt.ssrfURL, tt.param, tt.payload, got, tt.want)
		}
	}
}

func TestXSSChainRequiresHTTPOnlyFinding(t *testing.T) {
	e, _ := New(module.ScanAuthorized)

	// XSS trigger without any matching cookie.missing_httponly finding.
	trigger := finding.Finding{
		CheckID: finding.CheckWebReflectedXSS,
		Asset:   "app.example.com",
		Evidence: map[string]any{
			"url":       "https://app.example.com/search?q=test",
			"parameter": "q",
		},
	}

	results := e.OnFinding(context.Background(), trigger)
	if len(results) != 0 {
		t.Errorf("XSS chain should not fire without matching HttpOnly finding, got %d results", len(results))
	}
}

func TestXSSChainFiresWithHTTPOnlyFinding(t *testing.T) {
	e, _ := New(module.ScanAuthorized)

	// Pre-populate with a cookie.missing_httponly finding.
	e.mu.Lock()
	e.findings = append(e.findings, finding.Finding{
		CheckID: finding.CheckCookieMissingHTTPOnly,
		Asset:   "app.example.com",
		Evidence: map[string]any{
			"cookie_name": "session_id",
		},
	})
	e.mu.Unlock()

	trigger := finding.Finding{
		CheckID: finding.CheckWebReflectedXSS,
		Asset:   "app.example.com",
		Evidence: map[string]any{
			"url":       "https://app.example.com/search?q=test",
			"parameter": "q",
		},
	}

	results := e.OnFinding(context.Background(), trigger)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	f := results[0]
	if f.CheckID != finding.CheckChainXSSToSessionTheftPoC {
		t.Errorf("expected %q, got %q", finding.CheckChainXSSToSessionTheftPoC, f.CheckID)
	}
	if f.Severity != finding.SeverityHigh {
		t.Errorf("expected High severity, got %q", f.Severity)
	}

	// Verify PoC HTML is in evidence.
	poc, _ := f.Evidence["poc_html"].(string)
	if !strings.Contains(poc, "Session Theft PoC") {
		t.Error("PoC HTML should contain 'Session Theft PoC'")
	}
	if !strings.Contains(poc, "session_id") {
		t.Error("PoC HTML should reference the cookie name")
	}
}

func TestDefaultCredsPatternMatches(t *testing.T) {
	matches := []string{
		"port.grafana_default_credentials",
		"port.jenkins_no_auth",
		"port.minio_default_credentials",
		"port.sonarqube_default_credentials",
		"web.default_credentials",
	}
	for _, id := range matches {
		if !defaultCredsPattern.MatchString(id) {
			t.Errorf("expected %q to match defaultCredsPattern", id)
		}
	}

	nonMatches := []string{
		"web.ssrf",
		"exposure.env_file_exposed",
		"headers.missing_csp",
	}
	for _, id := range nonMatches {
		if defaultCredsPattern.MatchString(id) {
			t.Errorf("expected %q NOT to match defaultCredsPattern", id)
		}
	}
}
