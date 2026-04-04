package cspaudit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)

func TestCSPDataURI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "script-src 'self' data:; default-src 'self'")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	s := New()
	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckCSPDataURI {
			found = true
		}
	}
	if !found {
		t.Error("expected CheckCSPDataURI finding")
	}
}

func TestCSPReportOnlyMode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy-Report-Only", "script-src 'self'; default-src 'self'")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	s := New()
	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckCSPReportOnly {
			found = true
		}
	}
	if !found {
		t.Error("expected CheckCSPReportOnly finding")
	}
}

func TestCSPMissingDirectives(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "script-src 'self'; style-src 'self'")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	s := New()
	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}

	checks := map[finding.CheckID]bool{
		finding.CheckCSPBaseURIMissing: false,
		finding.CheckCSPFrameAncestors: false,
		finding.CheckCSPObjectSrc:      false,
	}

	for _, f := range findings {
		if _, ok := checks[f.CheckID]; ok {
			checks[f.CheckID] = true
		}
	}

	for id, found := range checks {
		if !found {
			t.Errorf("expected finding %s", id)
		}
	}
}

func TestCSPStrongPolicy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; script-src 'self'; style-src 'self'; "+
				"img-src 'self'; font-src 'self'; connect-src 'self'; "+
				"frame-ancestors 'none'; base-uri 'self'; object-src 'none'")
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
		if f.Severity >= finding.SeverityHigh {
			t.Errorf("unexpected high+ finding with strong CSP: %s — %s", f.CheckID, f.Title)
		}
	}
}

func TestNoCSP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	s := New()
	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	// No CSP header at all — should emit 0 CSP audit findings.
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for no CSP, got %d", len(findings))
	}
}
