package redos_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanner/redos"
)

// TestReDoS_SkippedInSurfaceMode ensures no requests are sent in surface mode
// since ReDoS detection requires active payload injection (deep mode only).
func TestReDoS_SkippedInSurfaceMode(t *testing.T) {
	probed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probed = true
		_, _ = fmt.Fprintln(w, "ok")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := redos.New().Run(context.Background(), asset, module.ScanSurface)
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

// TestReDoS_SlowEvil_FastBaseline_FindingEmitted simulates a server where the
// evil payload causes >5s delay while the benign baseline responds instantly,
// indicating a vulnerable regex.
func TestReDoS_SlowEvil_FastBaseline_FindingEmitted(t *testing.T) {
	// The scanner injects payloads via query parameters (q, search, email, url, input).
	// For the "email regex" payload the evil input is 30 'a's + '!'.
	evilSuffix := strings.Repeat("a", 30) + "!"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check all known query parameters for the evil payload.
		for _, param := range []string{"q", "search", "email", "url", "input"} {
			val := r.URL.Query().Get(param)
			if strings.Contains(val, evilSuffix) {
				// Simulate catastrophic backtracking — sleep long enough to
				// exceed the 5000ms threshold. We use a modest sleep since
				// the scanner measures wall-clock time and the threshold is
				// checked as evilMs > 5000.
				time.Sleep(5500 * time.Millisecond)
				_, _ = fmt.Fprintln(w, "slow")
				return
			}
		}
		// Benign/baseline requests return immediately.
		_, _ = fmt.Fprintln(w, "fast")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := redos.New().Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least 1 ReDoS finding for slow evil payload, got none")
	}

	f := findings[0]
	if f.CheckID != finding.CheckWebReDoS {
		t.Errorf("expected check ID %s, got %s", finding.CheckWebReDoS, f.CheckID)
	}
	if f.Severity != finding.SeverityHigh {
		t.Errorf("expected High severity, got %s", f.Severity)
	}
	if f.ProofCommand == "" {
		t.Error("ProofCommand should be set")
	}
	if f.Scanner != "redos" {
		t.Errorf("expected scanner name 'redos', got %q", f.Scanner)
	}

	// Verify evidence fields.
	if _, ok := f.Evidence["evil_ms"]; !ok {
		t.Error("expected evil_ms in evidence")
	}
	if _, ok := f.Evidence["baseline_ms"]; !ok {
		t.Error("expected baseline_ms in evidence")
	}
	if _, ok := f.Evidence["parameter"]; !ok {
		t.Error("expected parameter in evidence")
	}
	if _, ok := f.Evidence["payload_type"]; !ok {
		t.Error("expected payload_type in evidence")
	}
}

// TestReDoS_FastResponses_NoFinding verifies that when both evil and benign
// payloads get fast responses, no finding is emitted.
func TestReDoS_FastResponses_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, "fast response")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := redos.New().Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	for _, f := range findings {
		if f.CheckID == finding.CheckWebReDoS {
			t.Errorf("unexpected ReDoS finding when all responses are fast: %+v", f)
		}
	}
}

// TestReDoS_SlowBaseline_Skipped verifies that when the baseline (benign)
// request itself takes >1s, the scanner skips that parameter/payload combo
// to avoid false positives from generally slow servers.
func TestReDoS_SlowBaseline_Skipped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Every request is slow — simulates a slow server.
		time.Sleep(1200 * time.Millisecond)
		_, _ = fmt.Fprintln(w, "slow baseline")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := redos.New().Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	for _, f := range findings {
		if f.CheckID == finding.CheckWebReDoS {
			t.Errorf("unexpected ReDoS finding when baseline is slow (>1s): %+v", f)
		}
	}
}

// TestReDoS_ContextCancelled_NoPanic verifies that a cancelled context does
// not cause a panic and returns gracefully.
func TestReDoS_ContextCancelled_NoPanic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, "ok")
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, _ := redos.New().Run(ctx, asset, module.ScanDeep)
	_ = findings
}

// TestReDoS_UnreachableTarget_NoFindings verifies that an unreachable target
// produces zero findings and no error. Uses a short context deadline to avoid
// waiting for the scanner's 30s HTTP client timeout.
func TestReDoS_UnreachableTarget_NoFindings(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	findings, err := redos.New().Run(ctx, "192.0.2.1:1", module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for unreachable target, got %d", len(findings))
	}
}

// TestReDoS_EvilJustUnderThreshold_NoFinding verifies that a response time
// just under 5000ms does not produce a finding. Only delays on the email
// regex payload to keep the test runtime reasonable.
func TestReDoS_EvilJustUnderThreshold_NoFinding(t *testing.T) {
	evilSuffix := strings.Repeat("a", 30) + "!"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.URL.Query().Get("q")
		if strings.Contains(val, evilSuffix) {
			// Sleep for 4s — under the 5000ms threshold.
			time.Sleep(4 * time.Second)
			_, _ = fmt.Fprintln(w, "moderate")
			return
		}
		_, _ = fmt.Fprintln(w, "fast")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := redos.New().Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	for _, f := range findings {
		if f.CheckID == finding.CheckWebReDoS {
			t.Errorf("unexpected ReDoS finding when evil response is under threshold: %+v", f)
		}
	}
}

// TestReDoS_Name verifies the scanner returns the expected name.
func TestReDoS_Name(t *testing.T) {
	s := redos.New()
	if s.Name() != "redos" {
		t.Errorf("expected scanner name 'redos', got %q", s.Name())
	}
}

// TestReDoS_MultiplePayloadTypes_FindingsEmitted verifies that the scanner can
// detect multiple vulnerable regex patterns on the same server. Only the first
// parameter ("q") is made slow to keep the test runtime reasonable.
func TestReDoS_MultiplePayloadTypes_FindingsEmitted(t *testing.T) {
	emailEvil := strings.Repeat("a", 30) + "!"
	urlEvil := "http://" + strings.Repeat("a", 30)
	numericEvil := strings.Repeat("1", 30) + "a"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only the "q" parameter is "vulnerable" — keeps the test fast
		// because the scanner processes params in order and tries all
		// payloads for each param before moving on.
		val := r.URL.Query().Get("q")
		if strings.Contains(val, emailEvil) ||
			strings.Contains(val, urlEvil) ||
			strings.Contains(val, numericEvil) {
			time.Sleep(5500 * time.Millisecond)
			_, _ = fmt.Fprintln(w, "slow")
			return
		}
		_, _ = fmt.Fprintln(w, "fast")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := redos.New().Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	// All 3 payload types on param "q" should trigger findings.
	if len(findings) < 2 {
		t.Errorf("expected multiple ReDoS findings, got %d", len(findings))
	}

	payloadTypes := make(map[string]bool)
	for _, f := range findings {
		if f.CheckID != finding.CheckWebReDoS {
			continue
		}
		pt, _ := f.Evidence["payload_type"].(string)
		payloadTypes[pt] = true
	}
	if len(payloadTypes) < 2 {
		t.Errorf("expected findings for multiple payload types, got types: %v", payloadTypes)
	}
}

// TestReDoS_FindingFields_Complete verifies that all required fields on a
// ReDoS finding are populated correctly.
func TestReDoS_FindingFields_Complete(t *testing.T) {
	evilSuffix := strings.Repeat("a", 30) + "!"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.URL.Query().Get("q")
		if strings.Contains(val, evilSuffix) {
			time.Sleep(5500 * time.Millisecond)
			_, _ = fmt.Fprintln(w, "slow")
			return
		}
		_, _ = fmt.Fprintln(w, "fast")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := redos.New().Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	// Find the first finding on param "q".
	var f *finding.Finding
	for i := range findings {
		if findings[i].CheckID == finding.CheckWebReDoS {
			p, _ := findings[i].Evidence["parameter"].(string)
			if p == "q" {
				f = &findings[i]
				break
			}
		}
	}
	if f == nil {
		t.Fatal("expected ReDoS finding on parameter 'q', got none")
	}

	if f.Module != "deep" {
		t.Errorf("expected module 'deep', got %q", f.Module)
	}
	if f.Asset != asset {
		t.Errorf("expected asset %q, got %q", asset, f.Asset)
	}
	if !strings.Contains(f.Title, "ReDoS") {
		t.Errorf("expected title to contain 'ReDoS', got %q", f.Title)
	}
	if !strings.Contains(f.Description, "backtracking") {
		t.Errorf("expected description to mention backtracking, got %q", f.Description)
	}
	if f.DiscoveredAt.IsZero() {
		t.Error("expected DiscoveredAt to be set")
	}
	if !strings.Contains(f.ProofCommand, "curl") {
		t.Errorf("expected ProofCommand to contain curl, got %q", f.ProofCommand)
	}

	// Verify evidence has the threshold.
	threshold, ok := f.Evidence["threshold_ms"]
	if !ok {
		t.Error("expected threshold_ms in evidence")
	}
	if th, ok := threshold.(int); ok && th != 5000 {
		t.Errorf("expected threshold_ms=5000, got %d", th)
	}

	// Evil response time should be >5000.
	evilMs, ok := f.Evidence["evil_ms"].(int64)
	if ok && evilMs <= 5000 {
		t.Errorf("expected evil_ms > 5000, got %d", evilMs)
	}

	// Baseline should be <1000.
	baselineMs, ok := f.Evidence["baseline_ms"].(int64)
	if ok && baselineMs >= 1000 {
		t.Errorf("expected baseline_ms < 1000, got %d", baselineMs)
	}
}
