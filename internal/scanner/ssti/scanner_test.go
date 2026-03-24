package ssti

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

// TestSSTI_Jinja2Detected verifies that a server that evaluates {{7*7}} to 49
// produces a Critical finding.
func TestSSTI_Jinja2Detected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		// Simulate Jinja2-style template evaluation.
		if strings.Contains(q, "{{7*7}}") {
			fmt.Fprintln(w, "Result: 49")
			return
		}
		fmt.Fprintln(w, "Search results")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least 1 finding for Jinja2 SSTI, got none")
	}
	for _, f := range findings {
		if f.CheckID != finding.CheckWebSSTI {
			t.Errorf("unexpected check ID: %s", f.CheckID)
		}
		if f.Severity != finding.SeverityCritical {
			t.Errorf("expected Critical severity, got %s", f.Severity)
		}
		if f.ProofCommand == "" {
			t.Error("ProofCommand should be set")
		}
	}
}

// TestSSTI_FreeMarkerDetected verifies that a server reflecting ${7*7} as 49
// produces a Critical finding.
func TestSSTI_FreeMarkerDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		// Simulate FreeMarker/EL evaluation.
		if strings.Contains(q, "${7*7}") {
			fmt.Fprintln(w, "Output: 49")
			return
		}
		fmt.Fprintln(w, "No results")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least 1 finding for FreeMarker SSTI, got none")
	}
	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckWebSSTI && f.Severity == finding.SeverityCritical {
			found = true
		}
	}
	if !found {
		t.Error("expected a Critical web.ssti finding")
	}
}

// TestSSTI_EchoesInputNotEvaluated verifies that a server echoing the literal
// string {{7*7}} (not evaluated) does NOT produce a finding.
func TestSSTI_EchoesInputNotEvaluated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		// Echo the input back literally — no evaluation.
		fmt.Fprintf(w, "You searched for: %s\n", q)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	for _, f := range findings {
		if f.CheckID == finding.CheckWebSSTI {
			t.Errorf("unexpected SSTI finding when input is not evaluated: %+v", f)
		}
	}
}

// TestSSTI_SkippedInSurfaceMode ensures no probes are sent in surface mode.
func TestSSTI_SkippedInSurfaceMode(t *testing.T) {
	probed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probed = true
		fmt.Fprintln(w, "hello")
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

// TestSSTI_404Skipped verifies that paths returning 404 are skipped without
// emitting false positives.
func TestSSTI_404Skipped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	for _, f := range findings {
		if f.CheckID == finding.CheckWebSSTI {
			t.Errorf("unexpected SSTI finding on all-404 server: %+v", f)
		}
	}
}
