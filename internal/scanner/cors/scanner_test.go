package cors_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
	"github.com/stormbane/beacon/internal/scanner/cors"
)

func hasCheckID(findings []finding.Finding, id finding.CheckID) bool {
	for _, f := range findings {
		if f.CheckID == id {
			return true
		}
	}
	return false
}

func hasSeverity(findings []finding.Finding, id finding.CheckID, sev finding.Severity) bool {
	for _, f := range findings {
		if f.CheckID == id && f.Severity == sev {
			return true
		}
	}
	return false
}

// runOnServer runs the CORS scanner against the given test server in deep mode.
// The scanner targets https first; since the test server is plain HTTP, the
// HTTPS attempt fails and the scanner falls back to HTTP.
func runOnServer(t *testing.T, ts *httptest.Server) ([]finding.Finding, error) {
	t.Helper()
	asset := strings.TrimPrefix(ts.URL, "http://")
	s := cors.New()
	return s.Run(context.Background(), asset, module.ScanDeep)
}

// ---------------------------------------------------------------------------
// Surface mode — scanner must be a no-op
// ---------------------------------------------------------------------------

func TestSurfaceMode_ReturnsNil(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://evil.com")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	asset := strings.TrimPrefix(ts.URL, "http://")
	s := cors.New()
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings in surface mode (CORS scanner is deep-only), got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Case 1: arbitrary origin reflected with credentials → Critical
// ---------------------------------------------------------------------------

func TestArbitraryOriginWithCredentials_Critical(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckCORSMisconfiguration) {
		t.Error("expected CheckCORSMisconfiguration finding when arbitrary origin is reflected with credentials")
	}
	if !hasSeverity(findings, finding.CheckCORSMisconfiguration, finding.SeverityCritical) {
		t.Error("expected SeverityCritical when arbitrary origin is reflected with ACAC:true")
	}
}

// ---------------------------------------------------------------------------
// Case 2: wildcard origin with credentials → High
// ---------------------------------------------------------------------------

func TestWildcardWithCredentials_High(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckCORSMisconfiguration) {
		t.Error("expected CheckCORSMisconfiguration finding for wildcard+credentials")
	}
	if !hasSeverity(findings, finding.CheckCORSMisconfiguration, finding.SeverityHigh) {
		t.Error("expected SeverityHigh for wildcard origin + ACAC:true")
	}
}

// ---------------------------------------------------------------------------
// Case 3: null origin reflected → High
// ---------------------------------------------------------------------------

func TestNullOriginReflected_High(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") == "null" {
			w.Header().Set("Access-Control-Allow-Origin", "null")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckCORSMisconfiguration) {
		t.Error("expected CheckCORSMisconfiguration finding when null origin is reflected")
	}
	if !hasSeverity(findings, finding.CheckCORSMisconfiguration, finding.SeverityHigh) {
		t.Error("expected SeverityHigh for null origin reflection")
	}
}

// ---------------------------------------------------------------------------
// No CORS headers → no findings
// ---------------------------------------------------------------------------

func TestNoCORSHeaders_NoFindings(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No CORS headers at all.
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when server sets no CORS headers, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Non-null arbitrary origin reflected WITHOUT credentials → no finding
// (reflection without ACAC:true is not a CORS vuln for authenticated cross-origin reads)
// Note: null origin reflection IS flagged even without credentials (sandbox bypass risk).
// ---------------------------------------------------------------------------

func TestArbitraryOriginWithoutCredentials_NoFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		// Reflect non-null origins only; return nothing for "null" to avoid Case 3.
		if origin != "" && origin != "null" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			// No Access-Control-Allow-Credentials header
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(findings, finding.CheckCORSMisconfiguration) {
		t.Error("expected no finding when non-null origin is reflected but credentials are NOT allowed")
	}
}

// ---------------------------------------------------------------------------
// Wildcard without credentials → no finding
// ---------------------------------------------------------------------------

func TestWildcardWithoutCredentials_NoFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		// No ACAC header
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(findings, finding.CheckCORSMisconfiguration) {
		t.Error("expected no finding for wildcard origin without credentials")
	}
}

// ---------------------------------------------------------------------------
// Unreachable server → no panic, no findings
// ---------------------------------------------------------------------------

func TestUnreachableServer_NoFindingsNoPanic(t *testing.T) {
	s := cors.New()
	// Port 1 is reserved and should be unreachable on loopback.
	findings, err := s.Run(context.Background(), "127.0.0.1:1", module.ScanDeep)
	_ = err
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for unreachable server, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Context cancellation
// ---------------------------------------------------------------------------

func TestContextCancelled_NoPanic(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Run

	asset := strings.TrimPrefix(ts.URL, "http://")
	s := cors.New()
	findings, _ := s.Run(ctx, asset, module.ScanDeep)
	_ = findings // must not panic
}

// ---------------------------------------------------------------------------
// ProofCommand and evidence.url correctness
// ---------------------------------------------------------------------------

// TestArbitraryOriginWithCredentials_EvidenceHasURLField verifies that the
// Critical CORS finding includes a "url" key in Evidence so reporters can
// surface the exact endpoint that was probed (not just the asset name).
func TestArbitraryOriginWithCredentials_EvidenceHasURLField(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && origin != "null" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if f.CheckID != finding.CheckCORSMisconfiguration {
			continue
		}
		url, ok := f.Evidence["url"]
		if !ok {
			t.Error("CORS finding must include 'url' in Evidence")
		} else if urlStr, _ := url.(string); urlStr == "" {
			t.Error("Evidence['url'] must not be empty")
		}
	}
}

// TestArbitraryOriginWithCredentials_ProofCommandHasActualURL verifies that
// ProofCommand contains the actual target URL, not a generic {asset} placeholder.
func TestArbitraryOriginWithCredentials_ProofCommandHasActualURL(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && origin != "null" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	host := strings.TrimPrefix(ts.URL, "http://")
	for _, f := range findings {
		if f.CheckID != finding.CheckCORSMisconfiguration {
			continue
		}
		if f.ProofCommand == "" {
			t.Error("ProofCommand must not be empty on CORS finding")
		}
		if strings.Contains(f.ProofCommand, "{asset}") {
			t.Errorf("ProofCommand must not use {asset} placeholder, got: %s", f.ProofCommand)
		}
		if !strings.Contains(f.ProofCommand, host) {
			t.Errorf("ProofCommand must contain actual server host %q, got: %s", host, f.ProofCommand)
		}
	}
}

// TestACACUppercase_StillDetected verifies that Access-Control-Allow-Credentials
// with value "TRUE" (uppercase) is still caught by the lower-case comparison.
func TestACACUppercase_StillDetected(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && origin != "null" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "TRUE") // uppercase
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckCORSMisconfiguration) {
		t.Error("expected CORS finding even when ACAC header is uppercase TRUE")
	}
}
