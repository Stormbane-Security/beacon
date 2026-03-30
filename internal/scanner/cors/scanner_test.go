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

	if !hasCheckID(findings, finding.CheckCORSNullOrigin) {
		t.Error("expected CheckCORSNullOrigin finding when null origin is reflected")
	}
	if !hasSeverity(findings, finding.CheckCORSNullOrigin, finding.SeverityHigh) {
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

// ---------------------------------------------------------------------------
// Catch-all OPTIONS preflight: server mirrors any origin with credentials for
// every path including non-existent ones. The canary guard must suppress the
// preflight finding; however, GET probes on the root ARE still legitimate.
// ---------------------------------------------------------------------------

func TestPreflightCatchAll_PreflightSuppressed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// OPTIONS: mirrors origin+credentials for ALL paths (catch-all preflight).
		// GET: no CORS headers — so GET probes produce no findings.
		if r.Method == http.MethodOptions {
			origin := r.Header.Get("Origin")
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "POST")
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// GET probes find nothing; the canary detects the catch-all OPTIONS pattern
	// and suppresses the preflight probe — so we expect zero findings.
	if len(findings) != 0 {
		t.Errorf("expected 0 findings on catch-all OPTIONS site (canary guard should suppress preflight), got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Preflight-only detection: GET returns no CORS, OPTIONS on root only is vuln.
// The canary probes a random path (404 → no CORS headers) so catch-all guard
// does not fire, and the preflight on the real root URL detects the issue.
// ---------------------------------------------------------------------------

func TestPreflightOnly_CriticalFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions && r.URL.Path == "/" {
			// Only the root path is vulnerable on OPTIONS — random paths return 404.
			origin := r.Header.Get("Origin")
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "POST")
			w.WriteHeader(http.StatusOK)
			return
		}
		// All other paths (including the canary UUID path) return 404 with no CORS.
		http.NotFound(w, r)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// GET probes return no CORS; canary OPTIONS returns 404 (no catch-all).
	// Preflight on root should fire and produce a Critical finding.
	if !hasCheckID(findings, finding.CheckCORSPreflightMisconfig) {
		t.Error("expected CheckCORSPreflightMisconfig via preflight probe when GET returns no CORS headers but OPTIONS does")
	}
}

// ---------------------------------------------------------------------------
// TestACACUppercase_StillDetected verifies that Access-Control-Allow-Credentials
// with value "TRUE" (uppercase) is still caught by the lower-case comparison.
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// PUT preflight variant: server allows PUT + X-Custom without credentials → High
// ---------------------------------------------------------------------------

func TestPreflightPUT_WithoutCredentials_High(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions && r.URL.Path == "/" {
			origin := r.Header.Get("Origin")
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, POST")
			w.Header().Set("Access-Control-Allow-Headers", "X-Custom")
			// No Access-Control-Allow-Credentials header
			w.WriteHeader(http.StatusOK)
			return
		}
		// GET probes: no CORS headers — so GET probes produce no findings.
		// Canary OPTIONS on random paths: 404 with no CORS — no catch-all.
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckCORSPreflightMisconfig) {
		t.Error("expected CheckCORSPreflightMisconfig when OPTIONS allows PUT with custom headers")
	}
	if !hasSeverity(findings, finding.CheckCORSPreflightMisconfig, finding.SeverityHigh) {
		t.Error("expected SeverityHigh for PUT preflight without credentials")
	}
}

// ---------------------------------------------------------------------------
// PUT preflight variant: server allows PUT + X-Custom WITH credentials → Critical
// ---------------------------------------------------------------------------

func TestPreflightPUT_WithCredentials_Critical(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions && r.URL.Path == "/" {
			origin := r.Header.Get("Origin")
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, DELETE")
			w.Header().Set("Access-Control-Allow-Headers", "X-Custom, Authorization")
			w.WriteHeader(http.StatusOK)
			return
		}
		// GET probes: no CORS headers.
		// Canary OPTIONS on random paths: 404 with no CORS.
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckCORSPreflightMisconfig) {
		t.Error("expected CheckCORSPreflightMisconfig when OPTIONS allows PUT with credentials")
	}
	if !hasSeverity(findings, finding.CheckCORSPreflightMisconfig, finding.SeverityCritical) {
		t.Error("expected SeverityCritical for PUT preflight with credentials enabled")
	}
}

// ---------------------------------------------------------------------------
// PUT preflight variant: wildcard Access-Control-Allow-Methods → detected
// ---------------------------------------------------------------------------

func TestPreflightPUT_WildcardMethods_Detected(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions && r.URL.Path == "/" {
			origin := r.Header.Get("Origin")
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "*") // wildcard methods
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Wildcard methods with reflected origin should still be caught by PUT check.
	if !hasCheckID(findings, finding.CheckCORSPreflightMisconfig) {
		t.Error("expected CheckCORSPreflightMisconfig when Access-Control-Allow-Methods is wildcard")
	}
}

// ---------------------------------------------------------------------------
// Credentialed reflection compound check (Case 4): origin reflected with
// credentials produces both CheckCORSMisconfiguration AND the dedicated
// CheckCORSCredentialedReflection finding.
// ---------------------------------------------------------------------------

func TestCredentialedReflection_CompoundCheck_Emitted(t *testing.T) {
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

	// Case 1 should fire (CheckCORSMisconfiguration)
	if !hasCheckID(findings, finding.CheckCORSMisconfiguration) {
		t.Error("expected CheckCORSMisconfiguration for origin reflected with credentials")
	}

	// Case 4 compound check should ALSO fire (CheckCORSCredentialedReflection)
	if !hasCheckID(findings, finding.CheckCORSCredentialedReflection) {
		t.Error("expected CheckCORSCredentialedReflection compound finding when non-null origin is reflected with credentials")
	}
	if !hasSeverity(findings, finding.CheckCORSCredentialedReflection, finding.SeverityCritical) {
		t.Error("expected SeverityCritical for credentialed reflection compound finding")
	}

	// Verify evidence includes the compound marker.
	for _, f := range findings {
		if f.CheckID == finding.CheckCORSCredentialedReflection {
			compound, ok := f.Evidence["compound"]
			if !ok {
				t.Error("credentialed reflection finding must include 'compound' key in Evidence")
			}
			if v, _ := compound.(bool); !v {
				t.Error("Evidence['compound'] must be true")
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Credentialed reflection compound check: null origin should NOT trigger
// Case 4 (compound), even when credentials are enabled.
// ---------------------------------------------------------------------------

func TestCredentialedReflection_NullOrigin_NoCompound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "null" {
			w.Header().Set("Access-Control-Allow-Origin", "null")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// null origin → Case 1 fires (reflected with creds) AND Case 3 fires (null origin).
	// But Case 4 compound check explicitly excludes null origins.
	if hasCheckID(findings, finding.CheckCORSCredentialedReflection) {
		t.Error("Case 4 compound check must NOT fire for null origin (only non-null origins)")
	}
}

// ---------------------------------------------------------------------------
// Edge: non-null origin reflection emits both Case 1 AND Case 4
// ---------------------------------------------------------------------------

func TestReflectedOriginWithCredentials_EmitsBothChecks(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Case 1: generic CORS misconfiguration
	if !hasCheckID(findings, finding.CheckCORSMisconfiguration) {
		t.Error("expected CheckCORSMisconfiguration (Case 1) for reflected origin with credentials")
	}
	// Case 4: compound credentialed reflection (only for non-null origins)
	if !hasCheckID(findings, finding.CheckCORSCredentialedReflection) {
		t.Error("expected CheckCORSCredentialedReflection (Case 4) for reflected non-null origin with credentials")
	}
	// Both should be Critical severity.
	if !hasSeverity(findings, finding.CheckCORSMisconfiguration, finding.SeverityCritical) {
		t.Error("Case 1 should be Critical severity")
	}
	if !hasSeverity(findings, finding.CheckCORSCredentialedReflection, finding.SeverityCritical) {
		t.Error("Case 4 should be Critical severity")
	}
}

// ---------------------------------------------------------------------------
// Edge: wildcard with credentials (Case 2) should NOT also emit Case 4
// ---------------------------------------------------------------------------

func TestWildcardWithCredentials_DoesNotEmitCase4(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckCORSMisconfiguration) {
		t.Error("expected CheckCORSMisconfiguration for wildcard+credentials")
	}
	// Case 2 uses 'continue' so Case 4 should NOT fire.
	if hasCheckID(findings, finding.CheckCORSCredentialedReflection) {
		t.Error("Case 4 should NOT fire for wildcard origin (Case 2 has 'continue')")
	}
}

// ---------------------------------------------------------------------------
// Edge: origin reflected WITHOUT credentials — no findings
// ---------------------------------------------------------------------------

func TestReflectedOriginWithoutCredentials_NoFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			// No credentials header
		}
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Without credentials, the origin reflection is not exploitable for
	// credentialed requests. Neither Case 1 nor Case 4 should fire.
	if hasCheckID(findings, finding.CheckCORSMisconfiguration) {
		t.Error("should not emit CheckCORSMisconfiguration without credentials")
	}
	if hasCheckID(findings, finding.CheckCORSCredentialedReflection) {
		t.Error("should not emit CheckCORSCredentialedReflection without credentials")
	}
}

// ---------------------------------------------------------------------------
// Edge: scanner handles context cancellation
// ---------------------------------------------------------------------------

func TestCancelledContext_ReturnsNoError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}))
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	asset := strings.TrimPrefix(ts.URL, "http://")
	s := cors.New()
	_, err := s.Run(ctx, asset, module.ScanDeep)
	// Should not panic — either returns error or empty findings.
	if err != nil && !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("unexpected error: %v", err)
	}
}
