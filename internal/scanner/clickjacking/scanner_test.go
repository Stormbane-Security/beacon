package clickjacking

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane/beacon/internal/module"
)

func TestClickjacking_MissingBothHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].CheckID != "http.clickjacking" {
		t.Errorf("unexpected check ID: %s", findings[0].CheckID)
	}
	if findings[0].ProofCommand == "" {
		t.Error("ProofCommand should be set")
	}
}

func TestClickjacking_XFrameOptionsPresent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when X-Frame-Options is set, got %d", len(findings))
	}
}

func TestClickjacking_CSPFrameAncestorsPresent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'self'")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when CSP frame-ancestors is set, got %d", len(findings))
	}
}

func TestClickjacking_NonHTMLSkipped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for non-HTML response, got %d", len(findings))
	}
}

func TestClickjacking_Unreachable(t *testing.T) {
	// Port 1 is almost certainly not open.
	findings, err := New().Run(t.Context(), "127.0.0.1:1", module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for unreachable host, got %d", len(findings))
	}
}

func TestClickjacking_EmptyContentType(t *testing.T) {
	// Content-Type not set — should check headers (ambiguous, but we report the finding)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	// Empty Content-Type passes the HTML check (ct == ""), so we expect a finding.
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for empty content-type, got %d", len(findings))
	}
}
