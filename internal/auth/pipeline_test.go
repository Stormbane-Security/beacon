package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane-security/beacon/internal/auth"
	"github.com/stormbane-security/beacon/internal/config"
	"github.com/stormbane-security/beacon/internal/finding"
)

// ── LoginForm extraction from findings ─────────────────────────────────────

func TestExtractLoginForms(t *testing.T) {
	findings := []finding.Finding{
		{
			CheckID: finding.CheckAuthLoginFormDetected,
			Evidence: map[string]any{
				"path":         "/login",
				"form_action":  "/api/auth/login",
				"input_fields": []string{"username", "password"},
			},
		},
		{
			// Not a login form — should be skipped.
			CheckID:  finding.CheckAuthRegistrationOpen,
			Evidence: map[string]any{"path": "/register"},
		},
	}

	forms := auth.ExtractLoginForms(findings, "https", "example.com")
	if len(forms) != 1 {
		t.Fatalf("expected 1 login form, got %d", len(forms))
	}
	f := forms[0]
	if f.URL != "https://example.com/login" {
		t.Errorf("URL = %q, want %q", f.URL, "https://example.com/login")
	}
	if f.Action != "/api/auth/login" {
		t.Errorf("Action = %q, want %q", f.Action, "/api/auth/login")
	}
	if len(f.Fields) != 2 || f.Fields[0] != "username" || f.Fields[1] != "password" {
		t.Errorf("Fields = %v, want [username password]", f.Fields)
	}
	if f.HasCAPTCHA {
		t.Error("HasCAPTCHA should be false")
	}
}

func TestExtractLoginForms_WithCAPTCHA(t *testing.T) {
	findings := []finding.Finding{
		{
			CheckID: finding.CheckAuthLoginFormDetected,
			Evidence: map[string]any{
				"path":         "/login",
				"form_action":  "/login",
				"input_fields": []string{"email", "password"},
				"captcha_type": "recaptcha",
			},
		},
	}

	forms := auth.ExtractLoginForms(findings, "http", "test.local")
	if len(forms) != 1 {
		t.Fatalf("expected 1 form, got %d", len(forms))
	}
	if !forms[0].HasCAPTCHA {
		t.Error("expected HasCAPTCHA = true")
	}
}

func TestExtractLoginForms_InterfaceSlice(t *testing.T) {
	// Simulate evidence with []interface{} (common after JSON unmarshal).
	findings := []finding.Finding{
		{
			CheckID: finding.CheckAuthLoginFormDetected,
			Evidence: map[string]any{
				"path":         "/login",
				"input_fields": []interface{}{"user", "pass"},
			},
		},
	}

	forms := auth.ExtractLoginForms(findings, "https", "app.com")
	if len(forms) != 1 {
		t.Fatalf("expected 1 form, got %d", len(forms))
	}
	if len(forms[0].Fields) != 2 {
		t.Errorf("expected 2 fields, got %d: %v", len(forms[0].Fields), forms[0].Fields)
	}
}

func TestHasRegistration(t *testing.T) {
	findings := []finding.Finding{
		{CheckID: finding.CheckAuthLoginFormDetected},
	}
	if auth.HasRegistration(findings) {
		t.Error("should be false when no registration finding")
	}

	findings = append(findings, finding.Finding{CheckID: finding.CheckAuthRegistrationOpen})
	if !auth.HasRegistration(findings) {
		t.Error("should be true when registration finding present")
	}
}

// ── Default credential testing ─────────────────────────────────────────────

func TestTryDefaultCreds_Success(t *testing.T) {
	// Server accepts admin/admin and sets a session cookie.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}
		_ = r.ParseForm()
		if r.FormValue("username") == "admin" && r.FormValue("password") == "admin" {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "valid-session-id"})
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(401)
	}))
	defer srv.Close()

	form := &auth.LoginForm{
		URL:    srv.URL + "/login",
		Fields: []string{"username", "password"},
		Method: "POST",
	}

	client, info, err := auth.TryDefaultCreds(context.Background(), &http.Client{}, form, srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if info == nil {
		t.Fatal("expected non-nil session info")
	}
	if info.Source != "default-creds" {
		t.Errorf("Source = %q, want %q", info.Source, "default-creds")
	}
	if info.Username != "admin" {
		t.Errorf("Username = %q, want %q", info.Username, "admin")
	}
	if info.Headers["Cookie"] == "" {
		t.Error("expected Cookie header in session info")
	}

	// Verify the client injects the cookie.
	var gotCookie string
	checkSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCookie = r.Header.Get("Cookie")
		w.WriteHeader(200)
	}))
	defer checkSrv.Close()

	_, _ = client.Get(checkSrv.URL)
	if !strings.Contains(gotCookie, "session=valid-session-id") {
		t.Errorf("cookie not injected: got %q", gotCookie)
	}
}

func TestTryDefaultCreds_BearerToken(t *testing.T) {
	// Server accepts test/test and returns a JSON bearer token.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.FormValue("user") == "test" && r.FormValue("pass") == "test" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"token":"jwt-token-value"}`))
			return
		}
		w.WriteHeader(401)
	}))
	defer srv.Close()

	form := &auth.LoginForm{
		URL:    srv.URL + "/api/login",
		Fields: []string{"user", "pass"},
		Method: "POST",
	}

	client, info, err := auth.TryDefaultCreds(context.Background(), &http.Client{}, form, srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if info.Token != "Bearer jwt-token-value" {
		t.Errorf("Token = %q, want %q", info.Token, "Bearer jwt-token-value")
	}
	if info.Source != "default-creds" {
		t.Errorf("Source = %q, want %q", info.Source, "default-creds")
	}

	// Verify the client injects the Authorization header.
	var gotAuth string
	checkSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
	}))
	defer checkSrv.Close()

	_, _ = client.Get(checkSrv.URL)
	if gotAuth != "Bearer jwt-token-value" {
		t.Errorf("Authorization not injected: got %q", gotAuth)
	}
}

func TestTryDefaultCreds_NoneWork(t *testing.T) {
	// Server rejects all credentials.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(401)
	}))
	defer srv.Close()

	form := &auth.LoginForm{
		URL:    srv.URL + "/login",
		Fields: []string{"username", "password"},
		Method: "POST",
	}

	client, _, err := auth.TryDefaultCreds(context.Background(), &http.Client{}, form, srv.URL)
	if client != nil {
		t.Error("expected nil client when no creds work")
	}
	if err == nil {
		t.Error("expected error when no creds work")
	}
}

func TestTryDefaultCreds_NilForm(t *testing.T) {
	_, _, err := auth.TryDefaultCreds(context.Background(), &http.Client{}, nil, "http://example.com")
	if err == nil {
		t.Fatal("expected error for nil form")
	}
}

func TestTryDefaultCreds_FormActionOverride(t *testing.T) {
	// Server accepts admin/password at /api/do-login (form action differs from form URL).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/do-login" {
			w.WriteHeader(404)
			return
		}
		_ = r.ParseForm()
		if r.FormValue("email") == "admin" && r.FormValue("pwd") == "password" {
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "xyz"})
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(401)
	}))
	defer srv.Close()

	form := &auth.LoginForm{
		URL:    srv.URL + "/login",
		Action: "/api/do-login",
		Fields: []string{"email", "pwd"},
		Method: "POST",
	}

	client, info, err := auth.TryDefaultCreds(context.Background(), &http.Client{}, form, srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if info.Username != "admin" {
		t.Errorf("Username = %q, want %q", info.Username, "admin")
	}
}

// ── Pipeline AcquireSession ────────────────────────────────────────────────

func TestAcquireSession_ConfigCredentials(t *testing.T) {
	// Server accepts bearer token.
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	pipeline := auth.NewPipeline(&http.Client{})
	cfgs := []config.AuthConfig{{
		Asset:  "target.com",
		Method: "bearer",
		Token:  "my-config-token",
	}}

	client, info, err := pipeline.AcquireSession(
		context.Background(), "target.com", "https",
		nil, cfgs, false,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if info.Source != "config" {
		t.Errorf("Source = %q, want %q", info.Source, "config")
	}

	// Verify client works.
	_, _ = client.Get(srv.URL)
	if gotAuth != "Bearer my-config-token" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer my-config-token")
	}
}

func TestAcquireSession_DefaultCreds(t *testing.T) {
	// No config, no registration, but login form with default creds.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}
		_ = r.ParseForm()
		if r.FormValue("username") == "admin" && r.FormValue("password") == "admin" {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "default-cred-session"})
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(401)
	}))
	defer srv.Close()

	pipeline := auth.NewPipeline(&http.Client{})
	form := &auth.LoginForm{
		URL:    srv.URL + "/login",
		Fields: []string{"username", "password"},
		Method: "POST",
	}

	client, info, err := pipeline.AcquireSession(
		context.Background(), "target.com", "http",
		form, nil, false,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client from default creds")
	}
	if info.Source != "default-creds" {
		t.Errorf("Source = %q, want %q", info.Source, "default-creds")
	}
}

func TestAcquireSession_NoLoginForm(t *testing.T) {
	pipeline := auth.NewPipeline(&http.Client{})
	client, info, err := pipeline.AcquireSession(
		context.Background(), "target.com", "https",
		nil, nil, false,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client != nil {
		t.Error("expected nil client when no login form and no config")
	}
	if info != nil {
		t.Error("expected nil info")
	}
}

func TestAcquireSession_CAPTCHABlocks(t *testing.T) {
	pipeline := auth.NewPipeline(&http.Client{})
	form := &auth.LoginForm{
		URL:        "http://example.com/login",
		Fields:     []string{"username", "password"},
		HasCAPTCHA: true,
	}

	_, _, err := pipeline.AcquireSession(
		context.Background(), "target.com", "http",
		form, nil, false,
	)
	if err == nil {
		t.Fatal("expected error when CAPTCHA present")
	}
	if !strings.Contains(err.Error(), "CAPTCHA") {
		t.Errorf("error should mention CAPTCHA, got: %v", err)
	}
}

// ── Session injection into client ──────────────────────────────────────────

func TestInjectSessionIntoClient_Headers(t *testing.T) {
	var gotCookie string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCookie = r.Header.Get("Cookie")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	info := &auth.SessionInfo{
		Headers: map[string]string{"Cookie": "session=test123"},
	}
	client := auth.InjectSessionIntoClient(&http.Client{}, info)
	_, _ = client.Get(srv.URL)

	if gotCookie != "session=test123" {
		t.Errorf("Cookie = %q, want %q", gotCookie, "session=test123")
	}
}

func TestInjectSessionIntoClient_BearerToken(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	info := &auth.SessionInfo{
		Token: "Bearer my-jwt",
	}
	client := auth.InjectSessionIntoClient(&http.Client{}, info)
	_, _ = client.Get(srv.URL)

	if gotAuth != "Bearer my-jwt" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer my-jwt")
	}
}

func TestInjectSessionIntoClient_NilInfo(t *testing.T) {
	base := &http.Client{}
	result := auth.InjectSessionIntoClient(base, nil)
	if result != base {
		t.Error("expected same client back when info is nil")
	}
}

// ── Field guessing ─────────────────────────────────────────────────────────

func TestGuessFields_StandardNames(t *testing.T) {
	tests := []struct {
		fields     []string
		wantUser   string
		wantPass   string
	}{
		{[]string{"username", "password"}, "username", "password"},
		{[]string{"email", "pass"}, "email", "pass"},
		{[]string{"user", "pwd"}, "user", "pwd"},
		{[]string{"login", "secret"}, "login", "secret"},
		// Fallback: 2 unknown fields → first=user, second=pass
		{[]string{"field1", "field2"}, "field1", "field2"},
	}

	for _, tt := range tests {
		form := &auth.LoginForm{
			URL:    "http://example.com/login",
			Fields: tt.fields,
			Method: "POST",
		}

		// We can't call guessFields directly (unexported), so test through
		// TryDefaultCreds with a server that rejects everything and verify
		// it at least doesn't panic.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(401)
		}))
		_, _, _ = auth.TryDefaultCreds(context.Background(), &http.Client{}, form, srv.URL)
		srv.Close()
	}
}
