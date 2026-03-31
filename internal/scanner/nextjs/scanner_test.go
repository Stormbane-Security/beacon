package nextjs

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func hostFromURL(url string) string {
	return strings.TrimPrefix(url, "http://")
}

func hasCheckID(findings []finding.Finding, id finding.CheckID) bool {
	for _, f := range findings {
		if f.CheckID == id {
			return true
		}
	}
	return false
}

func findByCheckID(findings []finding.Finding, id finding.CheckID) *finding.Finding {
	for _, f := range findings {
		if f.CheckID == id {
			return &f
		}
	}
	return nil
}

// nextJSHandler returns an http.Handler that simulates a Next.js application.
// nextjsOK controls whether /_next/static/chunks/main.js returns 200.
// protectedPaths maps path -> baseline status code (before bypass).
// vulnerable controls whether the bypass header changes the response to 200.
func nextJSHandler(nextjsOK bool, protectedPaths map[string]int, vulnerable bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Next.js fingerprint endpoint.
		if r.URL.Path == "/_next/static/chunks/main.js" {
			if nextjsOK {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("// next.js main chunk"))
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
			return
		}

		// Check if this is a protected path.
		if baselineStatus, ok := protectedPaths[r.URL.Path]; ok {
			bypassHdr := r.Header.Get(bypassHeader)
			if vulnerable && bypassHdr == bypassValue {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"message":"welcome admin"}`))
				return
			}
			w.WriteHeader(baselineStatus)
			return
		}

		// Default — unprotected path.
		w.WriteHeader(http.StatusOK)
	})
}

// ---------------------------------------------------------------------------
// Test: Name() returns expected value
// ---------------------------------------------------------------------------

func TestScanner_Name(t *testing.T) {
	s := New()
	if s.Name() != "nextjs" {
		t.Errorf("expected scanner name %q, got %q", "nextjs", s.Name())
	}
}

// ---------------------------------------------------------------------------
// Test: non-Next.js server → no findings
// ---------------------------------------------------------------------------

func TestRun_NotNextJS_ReturnsNil(t *testing.T) {
	ts := httptest.NewServer(nextJSHandler(false, nil, false))
	defer ts.Close()

	s := New()
	findings, err := s.Run(context.Background(), hostFromURL(ts.URL), module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-Next.js server, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Test: Next.js server, no protected paths → no findings
// ---------------------------------------------------------------------------

func TestRun_NextJS_NoProtectedPaths_ReturnsNil(t *testing.T) {
	// All probe paths return 200 (unprotected), so no bypass attempt is made.
	ts := httptest.NewServer(nextJSHandler(true, nil, false))
	defer ts.Close()

	s := New()
	findings, err := s.Run(context.Background(), hostFromURL(ts.URL), module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when no paths are protected, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Test: CVE-2025-29927 — vulnerable Next.js app (302 baseline, 200 with bypass)
// ---------------------------------------------------------------------------

func TestRun_CVE202529927_Vulnerable_EmitsCritical(t *testing.T) {
	protectedPaths := map[string]int{
		"/admin": http.StatusFound, // 302 redirect to login
	}
	ts := httptest.NewServer(nextJSHandler(true, protectedPaths, true))
	defer ts.Close()

	s := New()
	findings, err := s.Run(context.Background(), hostFromURL(ts.URL), module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckCVENextJSMiddlewareBypass) {
		t.Fatal("expected CheckCVENextJSMiddlewareBypass finding")
	}

	f := findByCheckID(findings, finding.CheckCVENextJSMiddlewareBypass)
	if f.Severity != finding.SeverityCritical {
		t.Errorf("expected SeverityCritical, got %v", f.Severity)
	}
	if f.ProofCommand == "" {
		t.Error("expected non-empty ProofCommand")
	}
	if f.Scanner != scannerName {
		t.Errorf("expected scanner %q, got %q", scannerName, f.Scanner)
	}

	// Verify evidence fields.
	ev := f.Evidence
	if ev["baseline_status"] != http.StatusFound {
		t.Errorf("expected baseline_status %d, got %v", http.StatusFound, ev["baseline_status"])
	}
	if ev["bypass_status"] != http.StatusOK {
		t.Errorf("expected bypass_status %d, got %v", http.StatusOK, ev["bypass_status"])
	}
	if ev["bypass_header"] != bypassHeader {
		t.Errorf("expected bypass_header %q, got %v", bypassHeader, ev["bypass_header"])
	}
}

// ---------------------------------------------------------------------------
// Test: protected path returns 401, bypass still returns 401 → not vulnerable
// ---------------------------------------------------------------------------

func TestRun_ProtectedPath_BypassFails_ReturnsNil(t *testing.T) {
	protectedPaths := map[string]int{
		"/admin": http.StatusUnauthorized,
	}
	// vulnerable=false: bypass header has no effect.
	ts := httptest.NewServer(nextJSHandler(true, protectedPaths, false))
	defer ts.Close()

	s := New()
	findings, err := s.Run(context.Background(), hostFromURL(ts.URL), module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(findings, finding.CheckCVENextJSMiddlewareBypass) {
		t.Error("did not expect bypass finding when bypass fails")
	}
}

// ---------------------------------------------------------------------------
// Test: protected path returns 403 (Forbidden), bypass yields 200 → critical
// ---------------------------------------------------------------------------

func TestRun_403Baseline_BypassTo200_Critical(t *testing.T) {
	protectedPaths := map[string]int{
		"/dashboard": http.StatusForbidden,
	}
	ts := httptest.NewServer(nextJSHandler(true, protectedPaths, true))
	defer ts.Close()

	s := New()
	findings, err := s.Run(context.Background(), hostFromURL(ts.URL), module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckCVENextJSMiddlewareBypass) {
		t.Fatal("expected CheckCVENextJSMiddlewareBypass for 403->200 bypass")
	}
}

// ---------------------------------------------------------------------------
// Test: protected path returns 301 (MovedPermanently), bypass yields 200
// ---------------------------------------------------------------------------

func TestRun_301Baseline_BypassTo200_Critical(t *testing.T) {
	protectedPaths := map[string]int{
		"/settings": http.StatusMovedPermanently,
	}
	ts := httptest.NewServer(nextJSHandler(true, protectedPaths, true))
	defer ts.Close()

	s := New()
	findings, err := s.Run(context.Background(), hostFromURL(ts.URL), module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckCVENextJSMiddlewareBypass) {
		t.Fatal("expected bypass finding for 301->200")
	}
}

// ---------------------------------------------------------------------------
// Test: cancelled context → no findings, no error
// ---------------------------------------------------------------------------

func TestRun_CancelledContext_ReturnsNil(t *testing.T) {
	ts := httptest.NewServer(nextJSHandler(true, map[string]int{"/admin": 302}, true))
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	s := New()
	findings, err := s.Run(ctx, hostFromURL(ts.URL), module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings on cancelled context, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Test: ScanAuthorized mode → scanner does not run (only surface and deep)
// ---------------------------------------------------------------------------

func TestRun_AuthorizedMode_ReturnsNil(t *testing.T) {
	ts := httptest.NewServer(nextJSHandler(true, map[string]int{"/admin": 302}, true))
	defer ts.Close()

	s := New()
	findings, err := s.Run(context.Background(), hostFromURL(ts.URL), module.ScanAuthorized)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings in authorized mode (scanner only runs in surface/deep), got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Test: deep mode also runs the scanner
// ---------------------------------------------------------------------------

func TestRun_DeepMode_Runs(t *testing.T) {
	protectedPaths := map[string]int{
		"/admin": http.StatusFound,
	}
	ts := httptest.NewServer(nextJSHandler(true, protectedPaths, true))
	defer ts.Close()

	s := New()
	findings, err := s.Run(context.Background(), hostFromURL(ts.URL), module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckCVENextJSMiddlewareBypass) {
		t.Fatal("expected bypass finding in deep mode")
	}
}

// ---------------------------------------------------------------------------
// Test: isNextJS helper — confirms 200 on the main.js path
// ---------------------------------------------------------------------------

func TestIsNextJS_True(t *testing.T) {
	ts := httptest.NewServer(nextJSHandler(true, nil, false))
	defer ts.Close()

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if !isNextJS(context.Background(), client, ts.URL) {
		t.Error("expected isNextJS to return true")
	}
}

func TestIsNextJS_False(t *testing.T) {
	ts := httptest.NewServer(nextJSHandler(false, nil, false))
	defer ts.Close()

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if isNextJS(context.Background(), client, ts.URL) {
		t.Error("expected isNextJS to return false")
	}
}

// ---------------------------------------------------------------------------
// Test: statusCode helper
// ---------------------------------------------------------------------------

func TestStatusCode_WithHeaders(t *testing.T) {
	var gotHeader string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Custom")
		w.WriteHeader(http.StatusTeapot)
	}))
	defer ts.Close()

	client := &http.Client{}
	code, err := statusCode(context.Background(), client, ts.URL, map[string]string{
		"X-Custom": "test-value",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != http.StatusTeapot {
		t.Errorf("expected status %d, got %d", http.StatusTeapot, code)
	}
	if gotHeader != "test-value" {
		t.Errorf("expected header %q, got %q", "test-value", gotHeader)
	}
}

func TestStatusCode_NilHeaders(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := &http.Client{}
	code, err := statusCode(context.Background(), client, ts.URL, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, code)
	}
}

// ---------------------------------------------------------------------------
// Test: scanner returns early on first vulnerable path found
// ---------------------------------------------------------------------------

func TestRun_ReturnsOnFirstVulnerablePath(t *testing.T) {
	protectedPaths := map[string]int{
		"/admin":     http.StatusFound,
		"/dashboard": http.StatusFound,
		"/account":   http.StatusFound,
	}
	ts := httptest.NewServer(nextJSHandler(true, protectedPaths, true))
	defer ts.Close()

	s := New()
	findings, err := s.Run(context.Background(), hostFromURL(ts.URL), module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Scanner returns on first bypassed path, so exactly 1 finding.
	if len(findings) != 1 {
		t.Errorf("expected exactly 1 finding (scanner returns early), got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Test: empty response from server → no panic
// ---------------------------------------------------------------------------

func TestRun_EmptyServerResponse_NoPanic(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return 200 for everything but write nothing.
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	s := New()
	findings, err := s.Run(context.Background(), hostFromURL(ts.URL), module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Server responds 200 on main.js (so isNextJS=true) but also 200 on all
	// probe paths, meaning no baseline is restricted → no bypass attempt.
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when no paths are restricted, got %d", len(findings))
	}
}
