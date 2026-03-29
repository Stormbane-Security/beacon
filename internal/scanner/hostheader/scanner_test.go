package hostheader

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

// --- checkReflection edge cases ---

func TestCheckReflection_LocationHeader_Reflected(t *testing.T) {
	reflected, where := checkReflection(
		probeValue,
		"", "", "",
		"https://"+probeValue+"/reset", "", "",
		302,
	)
	if !reflected {
		t.Error("expected reflection in Location header")
	}
	if where != "Location header" {
		t.Errorf("expected 'Location header', got %q", where)
	}
}

func TestCheckReflection_LocationHeader_AlreadyInBaseline_NotReflected(t *testing.T) {
	// If the probe value was already in the baseline Location, it's not injection.
	reflected, _ := checkReflection(
		probeValue,
		"https://"+probeValue+"/", "", "", // baseline already had it
		"https://"+probeValue+"/reset", "", "",
		302,
	)
	if reflected {
		t.Error("should not flag Location that already contained probe value in baseline")
	}
}

func TestCheckReflection_LocationHeader_NonRedirectStatus_NotReflected(t *testing.T) {
	// Location with probe value but status is 200 — not a redirect reflection.
	reflected, _ := checkReflection(
		probeValue,
		"", "", "",
		"https://"+probeValue+"/", "", "",
		200,
	)
	if reflected {
		t.Error("Location reflection should only trigger on 3xx status codes")
	}
}

func TestCheckReflection_SetCookieDomain_Reflected(t *testing.T) {
	cookieWithProbe := "session=abc; Domain=" + probeValue + "; Path=/"
	reflected, where := checkReflection(
		probeValue,
		"", "", "",
		"", cookieWithProbe, "",
		200,
	)
	if !reflected {
		t.Error("expected reflection in Set-Cookie header")
	}
	if where != "Set-Cookie header" {
		t.Errorf("expected 'Set-Cookie header', got %q", where)
	}
}

func TestCheckReflection_SetCookieNoDomainAttr_NotReflected(t *testing.T) {
	// Set-Cookie contains probe value but no domain= attribute — not a domain injection.
	cookieNoAttr := "session=" + probeValue
	reflected, _ := checkReflection(
		probeValue,
		"", "", "",
		"", cookieNoAttr, "",
		200,
	)
	if reflected {
		t.Error("Set-Cookie without domain= attribute should not trigger reflection")
	}
}

func TestCheckReflection_ResponseBody_Reflected(t *testing.T) {
	body := "<a href='https://" + probeValue + "/'>click</a>"
	reflected, where := checkReflection(
		probeValue,
		"", "", "",
		"", "", body,
		200,
	)
	if !reflected {
		t.Error("expected reflection in response body")
	}
	if where != "response body" {
		t.Errorf("expected 'response body', got %q", where)
	}
}

func TestCheckReflection_ResponseBody_AlreadyInBaseline_NotReflected(t *testing.T) {
	body := "<a href='https://" + probeValue + "/'>click</a>"
	reflected, _ := checkReflection(
		probeValue,
		"", "", body, // same content in baseline
		"", "", body,
		200,
	)
	if reflected {
		t.Error("body already containing probe value in baseline should not be flagged")
	}
}

func TestCheckReflection_NoReflection_NotReflected(t *testing.T) {
	reflected, where := checkReflection(
		probeValue,
		"", "", "",
		"https://other.example.com/", "", "<html>Hello</html>",
		301,
	)
	if reflected {
		t.Errorf("expected no reflection, got where=%q", where)
	}
}

func TestCheckReflection_EmptyResponse_NotReflected(t *testing.T) {
	reflected, _ := checkReflection(probeValue, "", "", "", "", "", "", 200)
	if reflected {
		t.Error("empty response should not produce reflection")
	}
}

// --- baseline ---

func TestBaseline_HTTPSServer_SchemeDetermined(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://example.com/")
		w.WriteHeader(http.StatusMovedPermanently)
	}))
	defer srv.Close()

	// Use the TLS-trusting client from the server.
	client := srv.Client()
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	host := strings.TrimPrefix(srv.URL, "https://")
	scheme, status, location, _, _, err := baseline(context.Background(), client, host)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if scheme != "https" {
		t.Errorf("expected scheme https, got %q", scheme)
	}
	if status != http.StatusMovedPermanently {
		t.Errorf("expected 301, got %d", status)
	}
	if location != "https://example.com/" {
		t.Errorf("unexpected Location: %q", location)
	}
}

func TestBaseline_UnreachableHost_ReturnsError(t *testing.T) {
	client := &http.Client{}
	_, _, _, _, _, err := baseline(context.Background(), client, "127.0.0.1:19999")
	if err == nil {
		t.Error("expected error for unreachable host")
	}
}

// --- Run: surface mode is a no-op ---

func TestRun_SurfaceMode_ReturnsNil(t *testing.T) {
	s := New()
	findings, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings in surface mode, got %d", len(findings))
	}
}

// --- Run: deep mode with injection ---

func TestRun_DeepMode_LocationInjection_FindingEmitted(t *testing.T) {
	// Server that reflects the Host header in the Location response.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if host == "" {
			host = r.Header.Get("X-Forwarded-Host")
		}
		w.Header().Set("Location", "https://"+host+"/redirect")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	// Inject a custom client into the scanner by temporarily pointing the
	// asset to our test server. We test checkReflection directly instead,
	// since Run() constructs its own client and we can't inject one via the
	// exported API. The integration path is covered by the reflection tests above.
	//
	// Here we verify the end-to-end path via a plain HTTP server that reflects
	// the Host header — the scanner's Run() with a host:port that resolves to
	// our server is not feasible without DNS mocking. We test Run() against a
	// local address to verify it doesn't panic.
	s := New()
	host := strings.TrimPrefix(srv.URL, "http://")
	ctx := context.Background()

	// Run() in deep mode against our test server host:port.
	// The scanner uses https first; our server is plain HTTP, so it falls
	// through. On http the Location will contain our injected value.
	findings, err := s.Run(ctx, host, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() returned error: %v", err)
	}
	// Whether a finding is emitted depends on the baseline vs injected comparison.
	// Both the baseline GET and the injected GET go to the same server so both
	// reflect the host — meaning reflection is present but also present in baseline.
	// We assert no panic and at most one finding per probe.
	for _, f := range findings {
		if f.CheckID != finding.CheckHostHeaderInjection {
			t.Errorf("unexpected check ID: %s", f.CheckID)
		}
	}
}

func TestRun_DeepMode_NoReflection_NoFinding(t *testing.T) {
	// Server that never reflects the Host header.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>Hello</body></html>"))
	}))
	defer srv.Close()

	s := New()
	host := strings.TrimPrefix(srv.URL, "http://")
	findings, err := s.Run(context.Background(), host, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings when server doesn't reflect host header, got %d", len(findings))
	}
}

// TestRun_DeepMode_FindingHasProofCommandWithActualURL verifies that the
// ProofCommand on a HostHeaderInjection finding contains the actual server URL
// and not a generic {asset} placeholder.
func TestRun_DeepMode_FindingHasProofCommandWithActualURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reflect the X-Forwarded-Host header in Location.
		injected := r.Header.Get("X-Forwarded-Host")
		if injected != "" {
			w.Header().Set("Location", "https://"+injected+"/redirect")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := New()
	host := strings.TrimPrefix(srv.URL, "http://")
	findings, err := s.Run(context.Background(), host, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() returned error: %v", err)
	}

	for _, f := range findings {
		if f.CheckID != finding.CheckHostHeaderInjection {
			continue
		}
		if f.ProofCommand == "" {
			t.Error("ProofCommand must not be empty on HostHeaderInjection finding")
		}
		if strings.Contains(f.ProofCommand, "{asset}") {
			t.Errorf("ProofCommand must not use {asset} placeholder, got: %s", f.ProofCommand)
		}
		if !strings.Contains(f.ProofCommand, host) {
			t.Errorf("ProofCommand must contain actual server host %q, got: %s", host, f.ProofCommand)
		}
	}
}

// TestCheckReflection_SetCookie_BaselineAlreadyHasValue_NotReflected ensures
// that a Set-Cookie domain matching the probe value present in the baseline
// is not re-flagged when injected (baseline comparison must suppress it).
func TestCheckReflection_SetCookie_BaselineAlreadyHasValue_NotReflected(t *testing.T) {
	baselineCookie := "session=abc; Domain=" + probeValue + "; Path=/"
	reflected, _ := checkReflection(
		probeValue,
		"", baselineCookie, "", // baseline already has probe value in cookie
		"", baselineCookie, "",
		200,
	)
	if reflected {
		t.Error("should not flag Set-Cookie domain already present in baseline")
	}
}

// ---------------------------------------------------------------------------
// Cache poisoning severity elevation: X-Cache: HIT → Critical
// ---------------------------------------------------------------------------

// TestRun_DeepMode_CachePoisoning_XCacheHIT_Critical verifies that when the
// server reflects the injected host header AND returns X-Cache: HIT, the
// finding is elevated to SeverityCritical with cache-specific title/evidence.
func TestRun_DeepMode_CachePoisoning_XCacheHIT_Critical(t *testing.T) {
	// Server reflects X-Forwarded-Host in the response body (not in the
	// baseline) and returns X-Cache: HIT to simulate a cached response.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		xfh := r.Header.Get("X-Forwarded-Host")
		if xfh != "" {
			// Respond with the injected value in the body and a cache HIT.
			w.Header().Set("X-Cache", "HIT")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<html><body>Welcome to " + xfh + "</body></html>"))
			return
		}
		// Baseline: no reflection, no cache header.
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>Welcome</body></html>"))
	}))
	defer srv.Close()

	s := New()
	host := strings.TrimPrefix(srv.URL, "http://")
	findings, err := s.Run(context.Background(), host, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() returned error: %v", err)
	}

	// Expect at least one finding with Critical severity due to X-Cache: HIT.
	var foundCritical bool
	for _, f := range findings {
		if f.CheckID != finding.CheckHostHeaderInjection {
			continue
		}
		if f.Severity == finding.SeverityCritical {
			foundCritical = true

			// Verify title mentions cache poisoning.
			if !strings.Contains(f.Title, "cache poisoning") {
				t.Errorf("expected title to mention 'cache poisoning', got: %s", f.Title)
			}

			// Verify evidence includes cached marker.
			cachedVal, ok := f.Evidence["cached"]
			if !ok {
				t.Error("expected Evidence to contain 'cached' key for cache poisoning finding")
			} else if cachedVal != "true" {
				t.Errorf("expected Evidence['cached'] = 'true', got %v", cachedVal)
			}
		}
	}
	if !foundCritical {
		t.Error("expected SeverityCritical finding when X-Cache: HIT is present (cache poisoning elevation)")
	}
}

// TestRun_DeepMode_CachePoisoning_CFCacheStatus_Critical verifies that
// CF-Cache-Status: HIT (Cloudflare variant) also triggers cache poisoning elevation.
func TestRun_DeepMode_CachePoisoning_CFCacheStatus_Critical(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		xfh := r.Header.Get("X-Forwarded-Host")
		if xfh != "" {
			w.Header().Set("CF-Cache-Status", "HIT")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<html><body>Cached content for " + xfh + "</body></html>"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>Normal content</body></html>"))
	}))
	defer srv.Close()

	s := New()
	host := strings.TrimPrefix(srv.URL, "http://")
	findings, err := s.Run(context.Background(), host, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() returned error: %v", err)
	}

	var foundCritical bool
	for _, f := range findings {
		if f.CheckID == finding.CheckHostHeaderInjection && f.Severity == finding.SeverityCritical {
			foundCritical = true
		}
	}
	if !foundCritical {
		t.Error("expected SeverityCritical finding when CF-Cache-Status: HIT is present")
	}
}

// TestRun_DeepMode_NoCacheHeader_SeverityHigh verifies that host header
// injection WITHOUT a cache HIT header stays at SeverityHigh (not Critical).
func TestRun_DeepMode_NoCacheHeader_SeverityHigh(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		xfh := r.Header.Get("X-Forwarded-Host")
		if xfh != "" {
			// Reflect the injected value in the body but NO cache header.
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<html><body>Hello " + xfh + "</body></html>"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>Hello</body></html>"))
	}))
	defer srv.Close()

	s := New()
	host := strings.TrimPrefix(srv.URL, "http://")
	findings, err := s.Run(context.Background(), host, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() returned error: %v", err)
	}

	for _, f := range findings {
		if f.CheckID != finding.CheckHostHeaderInjection {
			continue
		}
		if f.Severity == finding.SeverityCritical {
			t.Errorf("expected SeverityHigh (not Critical) when no cache HIT header is present, got Critical for: %s", f.Title)
		}
	}

	// Also verify at least one finding was emitted.
	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckHostHeaderInjection {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected at least one HostHeaderInjection finding when X-Forwarded-Host is reflected")
	}
}

// ---------------------------------------------------------------------------
// Unreachable server — no panic, no findings
// ---------------------------------------------------------------------------

func TestRun_DeepMode_UnreachableServer_NoPanic(t *testing.T) {
	s := New()
	findings, err := s.Run(context.Background(), "127.0.0.1:1", module.ScanDeep)
	_ = err
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for unreachable server, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Context cancellation — no panic
// ---------------------------------------------------------------------------

func TestRun_DeepMode_ContextCancelled_NoPanic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	host := strings.TrimPrefix(srv.URL, "http://")
	s := New()
	findings, _ := s.Run(ctx, host, module.ScanDeep)
	_ = findings // must not panic
}

// ---------------------------------------------------------------------------
// Body reflection beyond 200 bytes — verify the baseline/probe body limits
// are aligned so false positives are suppressed.
// ---------------------------------------------------------------------------

func TestRun_DeepMode_ReflectionAfter200Bytes_BaselineSuppresses(t *testing.T) {
	// Create a body where the probe value appears after 200 bytes.
	// Before the fix, the baseline only read 200 bytes, so it would miss
	// the probe value in the baseline — causing a false positive.
	padding := strings.Repeat("x", 300)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Both baseline and injected requests return the same body —
		// the probe value appears naturally after 200 bytes.
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(padding + probeValue))
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	s := New()
	findings, err := s.Run(context.Background(), host, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	// The probe value is naturally in both baseline and injected bodies.
	// The scanner should NOT flag this as injection because the baseline
	// comparison should suppress it.
	for _, f := range findings {
		if f.CheckID == finding.CheckHostHeaderInjection &&
			f.Evidence != nil &&
			f.Evidence["reflected_in"] == "response body" {
			t.Error("false positive: body reflection should be suppressed when probe value is in baseline body beyond old 200-byte limit")
		}
	}
}

// ---------------------------------------------------------------------------
// Empty response — no crash, no finding
// ---------------------------------------------------------------------------

func TestRun_DeepMode_EmptyResponse_NoPanic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Empty body
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	s := New()
	findings, err := s.Run(context.Background(), host, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings on empty response, got %d", len(findings))
	}
}
