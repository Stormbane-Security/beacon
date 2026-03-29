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
	findings, err := New().Run(context.Background(), asset, module.ScanAuthorized)
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
	findings, err := New().Run(context.Background(), asset, module.ScanAuthorized)
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
	findings, err := New().Run(context.Background(), asset, module.ScanAuthorized)
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
	findings, err := New().Run(context.Background(), asset, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	for _, f := range findings {
		if f.CheckID == finding.CheckWebSSTI {
			t.Errorf("unexpected SSTI finding on all-404 server: %+v", f)
		}
	}
}

// ---------------------------------------------------------------------------
// False positive: page naturally contains "49" in its content
// ---------------------------------------------------------------------------

func TestSSTI_BaselineContains49_NoFalsePositive(t *testing.T) {
	// Server that always returns "49" in the body regardless of input.
	// The delta check should suppress this because the baseline also has "49".
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Showing 49 results for your query")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	for _, f := range findings {
		if f.CheckID == finding.CheckWebSSTI {
			t.Errorf("unexpected SSTI false positive when baseline already contains '49': %+v", f)
		}
	}
}

// ---------------------------------------------------------------------------
// SkippedInDeepMode: SSTI requires ScanAuthorized, not ScanDeep
// ---------------------------------------------------------------------------

func TestSSTI_SkippedInDeepMode(t *testing.T) {
	probed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probed = true
		fmt.Fprintln(w, "hello")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings in deep mode, got %d", len(findings))
	}
	if probed {
		t.Error("scanner should not send any HTTP requests in deep mode (requires authorized)")
	}
}

// ---------------------------------------------------------------------------
// Jinja2 string repeat: {{7*'7'}} → "7777777"
// ---------------------------------------------------------------------------

func TestSSTI_Jinja2StringRepeat_Detected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if strings.Contains(q, "{{7*'7'}}") {
			fmt.Fprintln(w, "Result: 7777777")
			return
		}
		fmt.Fprintln(w, "Search results")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	var found bool
	for _, f := range findings {
		if f.CheckID == finding.CheckWebSSTI {
			found = true
		}
	}
	if !found {
		t.Error("expected SSTI finding for Jinja2 string repeat payload")
	}
}

// ---------------------------------------------------------------------------
// Empty response body — no crash
// ---------------------------------------------------------------------------

func TestSSTI_EmptyResponse_NoCrash(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Empty body
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	for _, f := range findings {
		if f.CheckID == finding.CheckWebSSTI {
			t.Errorf("unexpected SSTI finding on empty body: %+v", f)
		}
	}
}

// ---------------------------------------------------------------------------
// evaluatedInBody unit tests — word boundary matching
// ---------------------------------------------------------------------------

func TestEvaluatedInBody_49_WordBoundary(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{"standalone 49", "The answer is 49 today", true},
		{"49 at start", "49 is the result", true},
		{"49 at end", "result: 49", true},
		{"49 inside larger number", "The value is 1490", false},
		{"49 embedded", "item49code", false},
		{"empty body", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evaluatedInBody("49", tt.body)
			if got != tt.want {
				t.Errorf("evaluatedInBody(\"49\", %q) = %v, want %v", tt.body, got, tt.want)
			}
		})
	}
}

func TestEvaluatedInBody_7777777_WordBoundary(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{"standalone", "output: 7777777", true},
		{"embedded in larger", "x77777770y", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evaluatedInBody("7777777", tt.body)
			if got != tt.want {
				t.Errorf("evaluatedInBody(\"7777777\", %q) = %v, want %v", tt.body, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// countOccurrences unit tests
// ---------------------------------------------------------------------------

func TestCountOccurrences_49(t *testing.T) {
	body := "There are 49 items and 49 users"
	got := countOccurrences("49", body)
	if got != 2 {
		t.Errorf("countOccurrences(\"49\", ...) = %d, want 2", got)
	}
}
