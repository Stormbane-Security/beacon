package cookie

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)

func TestCookieMissingSecure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:  "session",
			Value: "abc123",
			// No Secure flag
		})
		w.WriteHeader(200)
	}))
	defer srv.Close()

	s := New()
	// Override to use test server's port
	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}

	hasSecure := false
	for _, f := range findings {
		if f.CheckID == finding.CheckCookieMissingSecure {
			hasSecure = true
		}
	}
	if !hasSecure {
		t.Error("expected CheckCookieMissingSecure finding")
	}
}

func TestCookieAllSecure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     "__Host-session",
			Value:    "abc123",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			Path:     "/",
		})
		w.WriteHeader(200)
	}))
	defer srv.Close()

	s := New()
	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range findings {
		if f.Severity >= finding.SeverityMedium {
			t.Errorf("unexpected medium+ finding: %s", f.CheckID)
		}
	}
}

func TestCookieExcessiveScope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:   "session",
			Value:  "abc123",
			Domain: ".example.com",
			Secure: true,
		})
		w.WriteHeader(200)
	}))
	defer srv.Close()

	s := New()
	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}

	hasScope := false
	for _, f := range findings {
		if f.CheckID == finding.CheckCookieExcessiveScope {
			hasScope = true
		}
	}
	if !hasScope {
		t.Error("expected CheckCookieExcessiveScope finding")
	}
}
