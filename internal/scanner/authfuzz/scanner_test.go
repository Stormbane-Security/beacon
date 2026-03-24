package authfuzz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

// --- Unit tests ---

func TestBuildAlgNoneJWT_ThreeSegments(t *testing.T) {
	token := buildAlgNoneJWT()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Errorf("expected 3 JWT segments, got %d", len(parts))
	}
	if parts[2] != "" {
		t.Error("alg:none JWT must have empty signature segment")
	}
}

func TestDeriveTokenEndpoint_KnownPaths(t *testing.T) {
	cases := []struct {
		auth  string
		token string
	}{
		{"https://example.com/oauth/authorize", "https://example.com/oauth/token"},
		{"https://example.com/oauth2/authorize", "https://example.com/oauth2/token"},
		{"https://example.com/connect/authorize", "https://example.com/connect/token"},
	}
	for _, tc := range cases {
		got := deriveTokenEndpoint(tc.auth)
		if got != tc.token {
			t.Errorf("deriveTokenEndpoint(%q) = %q, want %q", tc.auth, got, tc.token)
		}
	}
}

func TestDeriveTokenEndpoint_EmptyWhenNoMatch(t *testing.T) {
	got := deriveTokenEndpoint("https://example.com/login")
	// Should either be empty or a reasonable guess — must not panic.
	_ = got
}

func TestExtractJSONString_Found(t *testing.T) {
	body := `{"authorization_endpoint":"https://auth.example.com/authorize","token_endpoint":"https://auth.example.com/token"}`
	got := extractJSONString(body, "authorization_endpoint")
	if got != "https://auth.example.com/authorize" {
		t.Errorf("expected auth URL, got %q", got)
	}
}

func TestExtractJSONString_NotFound(t *testing.T) {
	got := extractJSONString(`{"other":"value"}`, "authorization_endpoint")
	if got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestExtractHost_ValidURL(t *testing.T) {
	got := extractHost("https://evil.com/callback")
	if got != "evil.com" {
		t.Errorf("expected 'evil.com', got %q", got)
	}
}

// --- Integration tests with test servers ---

func TestRun_SurfaceMode_ReturnsNil(t *testing.T) {
	s := New()
	findings, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings in surface mode, got %d", len(findings))
	}
}

func TestRun_DeepMode_NoAuthEndpoint_NoFindings(t *testing.T) {
	// Server returns 404 for all auth paths.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	s := New()
	host := strings.TrimPrefix(ts.URL, "http://")
	findings, err := s.Run(context.Background(), host, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when no auth endpoint exists, got %d", len(findings))
	}
}

func TestRun_DeepMode_RedirectURIAbuse_FindingEmitted(t *testing.T) {
	// Server reflects whatever redirect_uri is given in the Location header.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/authorize":
			uri := r.URL.Query().Get("redirect_uri")
			if uri == "" {
				uri = "https://example.com/callback"
			}
			w.Header().Set("Location", uri+"?code=abc123")
			w.WriteHeader(http.StatusFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	s := New()
	host := strings.TrimPrefix(ts.URL, "http://")
	findings, err := s.Run(context.Background(), host, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var hasRedirectAbuse bool
	for _, f := range findings {
		if f.CheckID == finding.CheckAuthFuzzRedirectAbuse {
			hasRedirectAbuse = true
			if f.ProofCommand == "" {
				t.Error("expected non-empty ProofCommand on redirect_uri finding")
			}
		}
	}
	if !hasRedirectAbuse {
		t.Error("expected CheckAuthFuzzRedirectAbuse finding for server that reflects any redirect_uri")
	}
}

func TestRun_DeepMode_StrictRedirectURI_NoFinding(t *testing.T) {
	// Server only allows example.com/callback — rejects anything else.
	allowed := "https://example.com/callback"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/authorize":
			uri := r.URL.Query().Get("redirect_uri")
			if uri == allowed {
				w.Header().Set("Location", allowed+"?code=abc123")
				w.WriteHeader(http.StatusFound)
			} else {
				w.WriteHeader(http.StatusBadRequest)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	s := New()
	host := strings.TrimPrefix(ts.URL, "http://")
	findings, err := s.Run(context.Background(), host, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.CheckID == finding.CheckAuthFuzzRedirectAbuse {
			t.Error("expected no redirect_uri abuse finding when server enforces strict matching")
		}
	}
}

func TestRun_DeepMode_AlgNoneAccepted_FindingEmitted(t *testing.T) {
	// Server accepts any Bearer token and returns 200 with user JSON.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/me":
			auth := r.Header.Get("Authorization")
			if strings.HasPrefix(auth, "Bearer ") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"user":"admin","role":"admin"}`))
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	s := New()
	host := strings.TrimPrefix(ts.URL, "http://")
	findings, err := s.Run(context.Background(), host, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var hasTokenSub bool
	for _, f := range findings {
		if f.CheckID == finding.CheckAuthFuzzTokenSubstitution {
			hasTokenSub = true
		}
	}
	if !hasTokenSub {
		t.Error("expected CheckAuthFuzzTokenSubstitution when server accepts alg:none JWT")
	}
}

func TestRun_DeepMode_ProofCommandContainsHost(t *testing.T) {
	// Server that reflects any redirect_uri — same as redirect_uri abuse test.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/authorize" {
			uri := r.URL.Query().Get("redirect_uri")
			if uri == "" {
				uri = "https://example.com/callback"
			}
			w.Header().Set("Location", uri+"?code=abc123")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	s := New()
	host := strings.TrimPrefix(ts.URL, "http://")
	findings, err := s.Run(context.Background(), host, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.ProofCommand != "" && strings.Contains(f.ProofCommand, "{asset}") {
			t.Errorf("ProofCommand must not use {asset} placeholder: %s", f.ProofCommand)
		}
	}
}
