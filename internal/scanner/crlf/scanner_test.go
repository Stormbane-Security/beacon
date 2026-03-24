package crlf

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

// TestCRLF_InjectionConfirmed verifies that when the server reflects the
// injected header back to the client a High finding is emitted.
func TestCRLF_InjectionConfirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirect := r.URL.Query().Get("redirect")
		if redirect == "" {
			redirect = r.URL.Query().Get("url")
		}
		if redirect == "" {
			redirect = r.URL.Query().Get("next")
		}
		// Simulate vulnerable server: echo the injected header.
		if strings.Contains(redirect, injectedHeader) {
			// A real vulnerable server would split the header; we simulate
			// the outcome by setting the injected header directly.
			w.Header().Set(injectedHeader, injectedValue)
		}
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least 1 CRLF injection finding, got none")
	}
	for _, f := range findings {
		if f.CheckID != finding.CheckWebCRLFInjection {
			t.Errorf("unexpected check ID: %s", f.CheckID)
		}
		if f.Severity != finding.SeverityHigh {
			t.Errorf("expected High severity, got %s", f.Severity)
		}
		if f.ProofCommand == "" {
			t.Error("ProofCommand should be set")
		}
	}
}

// TestCRLF_NoInjection verifies that a normally redirecting server (no header
// injection) does not produce a finding.
func TestCRLF_NoInjection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Redirect safely without reflecting the parameter into headers.
		w.Header().Set("Location", "https://example.com/")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	for _, f := range findings {
		if f.CheckID == finding.CheckWebCRLFInjection {
			t.Errorf("unexpected CRLF finding on safe server: %+v", f)
		}
	}
}

// TestCRLF_SkippedInSurfaceMode ensures no probes are sent in surface mode.
func TestCRLF_SkippedInSurfaceMode(t *testing.T) {
	probed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probed = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings in surface mode, got %d", len(findings))
	}
	if probed {
		t.Error("scanner should not send any HTTP requests in surface mode")
	}
}

// TestCRLF_NoRedirectParams verifies that a server ignoring all redirect
// parameters (returning 200 with no injected header) produces no findings.
func TestCRLF_NoRedirectParams(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Server completely ignores redirect params and returns a plain page.
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>Home</body></html>")) //nolint:errcheck
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	for _, f := range findings {
		if f.CheckID == finding.CheckWebCRLFInjection {
			t.Errorf("unexpected CRLF finding when server ignores redirect params: %+v", f)
		}
	}
}
