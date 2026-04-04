package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane-security/beacon/internal/auth"
	"github.com/stormbane-security/beacon/internal/config"
)

func TestAuthenticate_Bearer(t *testing.T) {
	var gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("Authorization")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	cfgs := []config.AuthConfig{{Asset: "example.com", Method: "bearer", Token: "mytoken123"}}
	client, session, err := auth.Authenticate(context.Background(), cfgs, "example.com", &http.Client{})
	if err != nil {
		t.Fatal(err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if session.Method != "bearer" {
		t.Errorf("expected bearer, got %s", session.Method)
	}
	_, _ = client.Get(srv.URL)
	if gotHeader != "Bearer mytoken123" {
		t.Errorf("unexpected Authorization header: %q", gotHeader)
	}
}

func TestAuthenticate_NoMatch(t *testing.T) {
	cfgs := []config.AuthConfig{{Asset: "other.com", Method: "bearer", Token: "tok"}}
	client, session, err := auth.Authenticate(context.Background(), cfgs, "example.com", &http.Client{})
	if err != nil || client != nil || session != nil {
		t.Errorf("expected nil results for non-matching asset, got client=%v session=%v err=%v", client, session, err)
	}
}

func TestAuthenticate_Cookie(t *testing.T) {
	var gotCookie string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCookie = r.Header.Get("Cookie")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	cfgs := []config.AuthConfig{{Asset: "*", Method: "cookie", Cookie: "session=abc123"}}
	client, _, err := auth.Authenticate(context.Background(), cfgs, "anyhost.com", &http.Client{})
	if err != nil || client == nil {
		t.Fatalf("err=%v client=%v", err, client)
	}
	_, _ = client.Get(srv.URL)
	if gotCookie != "session=abc123" {
		t.Errorf("unexpected Cookie: %q", gotCookie)
	}
}

// ── CR/LF injection prevention ──────────────────────────────────────────────

func TestAuthenticate_BearerToken_CRLFRejected(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{"carriage return", "token\rinjected"},
		{"line feed", "token\ninjected"},
		{"CRLF pair", "token\r\nX-Injected: evil"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfgs := []config.AuthConfig{{Asset: "*", Method: "bearer", Token: tt.token}}
			_, _, err := auth.Authenticate(context.Background(), cfgs, "target.com", &http.Client{})
			if err == nil {
				t.Fatal("expected error for token containing CR/LF, got nil")
			}
			if !strings.Contains(err.Error(), "invalid characters") {
				t.Errorf("error should mention invalid characters, got: %v", err)
			}
		})
	}
}

func TestAuthenticate_Cookie_CRLFRejected(t *testing.T) {
	tests := []struct {
		name   string
		cookie string
	}{
		{"carriage return", "session=abc\r123"},
		{"line feed", "session=abc\n123"},
		{"CRLF pair", "session=abc\r\nSet-Cookie: evil=1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfgs := []config.AuthConfig{{Asset: "*", Method: "cookie", Cookie: tt.cookie}}
			_, _, err := auth.Authenticate(context.Background(), cfgs, "target.com", &http.Client{})
			if err == nil {
				t.Fatal("expected error for cookie containing CR/LF, got nil")
			}
			if !strings.Contains(err.Error(), "invalid characters") {
				t.Errorf("error should mention invalid characters, got: %v", err)
			}
		})
	}
}

func TestAuthenticate_HeaderName_CRLFRejected(t *testing.T) {
	tests := []struct {
		name   string
		header string
	}{
		{"carriage return in header name", "X-Custom\rHeader"},
		{"line feed in header name", "X-Custom\nHeader"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfgs := []config.AuthConfig{{
				Asset: "*", Method: "bearer", Token: "safe-token", Header: tt.header,
			}}
			_, _, err := auth.Authenticate(context.Background(), cfgs, "target.com", &http.Client{})
			if err == nil {
				t.Fatal("expected error for header name containing CR/LF, got nil")
			}
			if !strings.Contains(err.Error(), "header name") {
				t.Errorf("error should mention header name, got: %v", err)
			}
		})
	}
}

// ── Basic auth header formation ─────────────────────────────────────────────

func TestAuthenticate_BasicAuth_HeaderFormation(t *testing.T) {
	var gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("Authorization")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	cfgs := []config.AuthConfig{{
		Asset: "api.example.com", Method: "basic", Username: "admin", Password: "s3cret",
	}}
	client, session, err := auth.Authenticate(context.Background(), cfgs, "api.example.com", &http.Client{})
	if err != nil {
		t.Fatal(err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if session.Method != "basic" {
		t.Errorf("expected method=basic, got %s", session.Method)
	}
	if !strings.Contains(session.Label, "admin") {
		t.Errorf("expected label to contain username, got %q", session.Label)
	}

	_, _ = client.Get(srv.URL)
	if !strings.HasPrefix(gotHeader, "Basic ") {
		t.Errorf("expected Authorization header to start with 'Basic ', got %q", gotHeader)
	}
	// Verify it's a valid base64-encoded "admin:s3cret" — Go's SetBasicAuth
	// encodes correctly; we just verify the prefix is present and non-empty.
	if len(gotHeader) <= len("Basic ") {
		t.Error("Basic auth header has no encoded credentials")
	}
}

func TestAuthenticate_BasicAuth_CRLFInUsernameRejected(t *testing.T) {
	cfgs := []config.AuthConfig{{
		Asset: "*", Method: "basic", Username: "admin\r\n", Password: "pass",
	}}
	_, _, err := auth.Authenticate(context.Background(), cfgs, "target.com", &http.Client{})
	if err == nil {
		t.Fatal("expected error for username containing CR/LF")
	}
}

func TestAuthenticate_BasicAuth_CRLFInPasswordRejected(t *testing.T) {
	cfgs := []config.AuthConfig{{
		Asset: "*", Method: "basic", Username: "admin", Password: "pass\nword",
	}}
	_, _, err := auth.Authenticate(context.Background(), cfgs, "target.com", &http.Client{})
	if err == nil {
		t.Fatal("expected error for password containing CR/LF")
	}
}

// ── OIDC token URL allowlist validation ─────────────────────────────────────

func TestAuthenticate_OIDC_AllowedIssuers(t *testing.T) {
	// Set up a fake token endpoint that returns a valid access_token.
	fakeSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "test-oidc-token"})
	}))
	defer fakeSrv.Close()

	// Even though we have a valid server, the URL won't match the allowlist
	// because 127.0.0.1 is not a recognized OIDC provider.
	cfgs := []config.AuthConfig{{
		Asset:        "*",
		Method:       "oidc",
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		TokenURL:     fakeSrv.URL + "/oauth/token",
		Scopes:       []string{"openid"},
	}}
	_, _, err := auth.Authenticate(context.Background(), cfgs, "target.com", &http.Client{})
	if err == nil {
		t.Fatal("expected error for non-allowlisted token URL")
	}
	if !strings.Contains(err.Error(), "not a recognized OIDC provider") {
		t.Errorf("expected allowlist rejection, got: %v", err)
	}
}

func TestAuthenticate_OIDC_HTTPSchemeRejected(t *testing.T) {
	cfgs := []config.AuthConfig{{
		Asset:        "*",
		Method:       "oidc",
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		TokenURL:     "http://accounts.google.com/o/oauth2/token",
		Scopes:       []string{"openid"},
	}}
	_, _, err := auth.Authenticate(context.Background(), cfgs, "target.com", &http.Client{})
	if err == nil {
		t.Fatal("expected error for HTTP (non-HTTPS) token URL")
	}
	if !strings.Contains(err.Error(), "HTTPS") {
		t.Errorf("expected HTTPS requirement error, got: %v", err)
	}
}

func TestAuthenticate_OIDC_UnknownProviderRejected(t *testing.T) {
	cfgs := []config.AuthConfig{{
		Asset:        "*",
		Method:       "oidc",
		ClientID:     "id",
		ClientSecret: "secret",
		TokenURL:     "https://evil.attacker.com/steal-creds",
	}}
	_, _, err := auth.Authenticate(context.Background(), cfgs, "target.com", &http.Client{})
	if err == nil {
		t.Fatal("expected error for unknown OIDC provider")
	}
	if !strings.Contains(err.Error(), "not a recognized OIDC provider") {
		t.Errorf("expected allowlist rejection, got: %v", err)
	}
}

// ── Session metadata ────────────────────────────────────────────────────────

func TestAuthenticate_SessionMetadata(t *testing.T) {
	tests := []struct {
		name       string
		cfg        config.AuthConfig
		wantMethod string
		wantLabel  string
	}{
		{
			name:       "bearer returns correct metadata",
			cfg:        config.AuthConfig{Asset: "*", Method: "bearer", Token: "tok"},
			wantMethod: "bearer",
			wantLabel:  "bearer token",
		},
		{
			name:       "api_key returns correct metadata with default header",
			cfg:        config.AuthConfig{Asset: "*", Method: "api_key", Token: "key123"},
			wantMethod: "api_key",
			wantLabel:  "X-API-Key header",
		},
		{
			name:       "api_key returns correct metadata with custom header",
			cfg:        config.AuthConfig{Asset: "*", Method: "api_key", Token: "key123", Header: "X-Custom-Auth"},
			wantMethod: "api_key",
			wantLabel:  "X-Custom-Auth header",
		},
		{
			name:       "cookie returns correct metadata",
			cfg:        config.AuthConfig{Asset: "*", Method: "cookie", Cookie: "sess=1"},
			wantMethod: "cookie",
			wantLabel:  "session cookie",
		},
		{
			name:       "basic returns correct metadata",
			cfg:        config.AuthConfig{Asset: "*", Method: "basic", Username: "admin", Password: "pw"},
			wantMethod: "basic",
			wantLabel:  "basic auth (admin)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfgs := []config.AuthConfig{tt.cfg}
			_, session, err := auth.Authenticate(context.Background(), cfgs, "target.com", &http.Client{})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if session == nil {
				t.Fatal("expected non-nil session")
			}
			if session.Method != tt.wantMethod {
				t.Errorf("Method = %q, want %q", session.Method, tt.wantMethod)
			}
			if session.Label != tt.wantLabel {
				t.Errorf("Label = %q, want %q", session.Label, tt.wantLabel)
			}
		})
	}
}

// ── API key auth injects header correctly ───────────────────────────────────

func TestAuthenticate_APIKey_CustomHeader(t *testing.T) {
	var gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Custom-Auth")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	cfgs := []config.AuthConfig{{
		Asset: "*", Method: "api_key", Token: "my-api-key-value", Header: "X-Custom-Auth",
	}}
	client, _, err := auth.Authenticate(context.Background(), cfgs, "target.com", &http.Client{})
	if err != nil {
		t.Fatal(err)
	}
	client.Get(srv.URL)
	if gotHeader != "my-api-key-value" {
		t.Errorf("expected X-Custom-Auth = %q, got %q", "my-api-key-value", gotHeader)
	}
}

// ── Unknown method ──────────────────────────────────────────────────────────

func TestAuthenticate_UnknownMethodReturnsError(t *testing.T) {
	cfgs := []config.AuthConfig{{Asset: "*", Method: "kerberos", Token: "ticket"}}
	_, _, err := auth.Authenticate(context.Background(), cfgs, "target.com", &http.Client{})
	if err == nil {
		t.Fatal("expected error for unknown auth method")
	}
	if !strings.Contains(err.Error(), "unknown method") {
		t.Errorf("expected 'unknown method' error, got: %v", err)
	}
}

// ── Wildcard asset matching ─────────────────────────────────────────────────

func TestAuthenticate_WildcardAssetMatchesAny(t *testing.T) {
	cfgs := []config.AuthConfig{{Asset: "*", Method: "bearer", Token: "wildcard-token"}}
	_, session, err := auth.Authenticate(context.Background(), cfgs, "anything.example.com", &http.Client{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if session == nil {
		t.Fatal("wildcard asset should match any hostname")
	}
}

// ── Bearer prefix handling ──────────────────────────────────────────────────

func TestAuthenticate_Bearer_DoesNotDoublePrefixBearerToken(t *testing.T) {
	var gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("Authorization")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	// Token already includes "Bearer " prefix.
	cfgs := []config.AuthConfig{{Asset: "*", Method: "bearer", Token: "Bearer already-prefixed"}}
	client, _, err := auth.Authenticate(context.Background(), cfgs, "target.com", &http.Client{})
	if err != nil {
		t.Fatal(err)
	}
	client.Get(srv.URL)
	// Should NOT produce "Bearer Bearer already-prefixed".
	if strings.HasPrefix(gotHeader, "Bearer Bearer") {
		t.Errorf("double Bearer prefix detected: %q", gotHeader)
	}
}
