package authsurface

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane-security/beacon/internal/module"
)

func TestDetectsLoginForm(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			w.WriteHeader(200)
			_, _ = fmt.Fprint(w, `<html><body><form action="/auth"><input type="text" name="email"><input type="password" name="password"><button>Login</button></form></body></html>`)
			return
		}
		w.WriteHeader(200)
		_, _ = fmt.Fprint(w, `<html><body><a href="/login">Login</a></body></html>`)
	}))
	defer srv.Close()

	s := &Scanner{}
	findings, err := s.Run(context.Background(), srv.Listener.Addr().String(), module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == "auth.login_form_detected" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected auth.login_form_detected finding")
	}
}

func TestDetectsRegistration(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/register" {
			w.WriteHeader(200)
			_, _ = fmt.Fprint(w, `<html><body><h1>Create Account</h1><form><input type="text" name="email"><input type="password" name="password"><button>Register</button></form></body></html>`)
			return
		}
		w.WriteHeader(200)
		_, _ = fmt.Fprint(w, `<html><body><a href="/register">Sign Up</a></body></html>`)
	}))
	defer srv.Close()

	s := &Scanner{}
	findings, err := s.Run(context.Background(), srv.Listener.Addr().String(), module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == "auth.registration_open" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected auth.registration_open finding")
	}
}

func TestDetectsSSO(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			w.WriteHeader(200)
			_, _ = fmt.Fprint(w, `<html><body><form><input type="password" name="pass"></form><a href="/auth/google">Login with Google</a><a href="/auth/github">Sign in with GitHub</a></body></html>`)
			return
		}
		w.WriteHeader(200)
		_, _ = fmt.Fprint(w, `<html><body><a href="/login">Login</a></body></html>`)
	}))
	defer srv.Close()

	s := &Scanner{}
	findings, err := s.Run(context.Background(), srv.Listener.Addr().String(), module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundSSO := false
	for _, f := range findings {
		if f.CheckID == "auth.sso_endpoint" {
			foundSSO = true
			break
		}
	}
	if !foundSSO {
		t.Error("expected auth.sso_endpoint finding for Google/GitHub SSO")
	}
}

func TestDetectsCAPTCHA(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			w.WriteHeader(200)
			_, _ = fmt.Fprint(w, `<html><body><form><input type="password" name="pass"><div class="g-recaptcha" data-sitekey="test"></div></form></body></html>`)
			return
		}
		w.WriteHeader(200)
		_, _ = fmt.Fprint(w, `<html><body><a href="/login">Login</a></body></html>`)
	}))
	defer srv.Close()

	s := &Scanner{}
	findings, err := s.Run(context.Background(), srv.Listener.Addr().String(), module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundCaptcha := false
	for _, f := range findings {
		if f.CheckID == "auth.mfa_detected" {
			foundCaptcha = true
			break
		}
	}
	if !foundCaptcha {
		t.Error("expected auth.mfa_detected finding for reCAPTCHA")
	}
}

func TestNegative_NoLoginForm(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = fmt.Fprint(w, `<html><body><h1>Welcome</h1><p>No login here.</p></body></html>`)
	}))
	defer srv.Close()

	s := &Scanner{}
	findings, err := s.Run(context.Background(), srv.Listener.Addr().String(), module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if f.CheckID == "auth.login_form_detected" {
			t.Error("should NOT detect login form on page without password field")
		}
	}
}

func TestDedup(t *testing.T) {
	input := []string{"/login", "/admin", "/login", "/register", "/admin"}
	result := dedup(input)
	if len(result) != 3 {
		t.Errorf("dedup(%v) = %d items, want 3", input, len(result))
	}
}

func TestExtractInputNames_FiltersNoise(t *testing.T) {
	html := `<html>
	<head><meta name="viewport" content="width"><meta name="description" content="test"></head>
	<body>
	<form action="/login">
		<input type="text" name="email">
		<input type="password" name="password">
		<div class="mat-mdc-button-ripple" name="mat-mdc-button-ripple"></div>
		<button>Login</button>
	</form>
	</body></html>`
	names := extractInputNames(html)
	for _, n := range names {
		if n == "viewport" || n == "description" || n == "mat-mdc-button-ripple" {
			t.Errorf("extractInputNames should not include %q", n)
		}
	}
	hasEmail, hasPassword := false, false
	for _, n := range names {
		if n == "email" {
			hasEmail = true
		}
		if n == "password" {
			hasPassword = true
		}
	}
	if !hasEmail {
		t.Error("expected 'email' in extracted input names")
	}
	if !hasPassword {
		t.Error("expected 'password' in extracted input names")
	}
}

func TestHasLoginForm_AngularReactiveForms(t *testing.T) {
	// Angular Material reactive form — no type="password" but has formcontrolname="password"
	html := `<mat-form-field><input matInput formcontrolname="password" type="password"></mat-form-field>`
	if !hasLoginForm(strings.ToLower(html)) {
		t.Error("expected Angular reactive form with formcontrolname=password to be detected")
	}
}

func TestHasLoginForm_IDPassword(t *testing.T) {
	// Form with id="password" instead of type="password"
	html := `<form><input id="password" type="text"><button>Log in</button></form>`
	lower := strings.ToLower(html)
	if !hasLoginForm(lower) {
		t.Error("expected form with id=password to be detected as login form")
	}
}
