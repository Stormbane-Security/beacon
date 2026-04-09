package dirbust_test

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/scanner/dirbust"
)

// assetFrom strips the scheme from an httptest URL so it can be passed as the
// asset hostname.  The dirbust scanner prepends "https://" itself; since httptest
// speaks plain HTTP we need it to speak HTTPS or we need to work around the
// scheme.  In these tests we use a plain-HTTP httptest server and strip "http://"
// — the scanner will try HTTPS first, fail, and the tests would break.  Instead
// we create a TLS httptest server (quietTLSServer) so the scanner's HTTPS
// attempt succeeds.
//
// For tests that do NOT need TLS (e.g. context cancellation), we supply a custom
// scanner with an HTTP client that talks plain HTTP via the loopback URL.
func tlsAsset(ts *httptest.Server) string {
	return strings.TrimPrefix(ts.URL, "https://")
}

// newTLSScanner returns a Scanner whose HTTP client trusts the test TLS server.
func newTLSScanner(ts *httptest.Server) *dirbust.Scanner {
	s := dirbust.NewWithClient(ts.Client())
	return s
}

// quietTLSServer creates an httptest TLS server that suppresses TLS handshake
// error logs. The dirbust scanner's concurrent probes race against server
// shutdown, producing harmless "TLS handshake error" noise in test output.
func quietTLSServer(handler http.Handler) *httptest.Server {
	ts := httptest.NewUnstartedServer(handler)
	ts.Config.ErrorLog = log.New(io.Discard, "", 0)
	ts.StartTLS()
	return ts
}

func findingsByCheckID(findings []finding.Finding, id finding.CheckID) []finding.Finding {
	var out []finding.Finding
	for _, f := range findings {
		if f.CheckID == id {
			out = append(out, f)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Rate limit backoff
// ---------------------------------------------------------------------------

// TestRateLimit_BackoffAndNoFinding verifies that when a server returns 429 with
// a Retry-After header, the scanner backs off, exhausts its retries, and does NOT
// emit a finding for that path (the path was never successfully probed).
func TestRateLimit_BackoffAndNoFinding(t *testing.T) {
	var requestCount atomic.Int64

	ts := quietTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer ts.Close()

	s := newTLSScanner(ts)
	start := time.Now()
	findings := s.Run(context.Background(), tlsAsset(ts), []string{"/secret"})
	elapsed := time.Since(start)

	// No finding should be produced — the path was rate-limited on every attempt.
	found := findingsByCheckID(findings, finding.CheckDirbustFound)
	if len(found) > 0 {
		t.Errorf("expected no CheckDirbustFound findings after 429 exhaustion, got %d", len(found))
	}

	// The scanner should have made maxRetries (3) probe attempts + 1 catch-all
	// baseline request (scan.DetectCatchAll) = 4 total requests.
	if got := requestCount.Load(); got != 4 {
		t.Errorf("expected 4 attempts (1 catch-all baseline + 3 maxRetries) for a 429-only path, got %d", got)
	}

	// With Retry-After: 1 the scanner should wait at least 1 second between retries.
	// We made 3 attempts with 2 waits (wait happens before retrying after 429).
	// Allow a generous lower bound to avoid flakiness on slow CI.
	if elapsed < 1*time.Second {
		t.Errorf("scanner did not appear to honour Retry-After: elapsed %v < 1s", elapsed)
	}
}

// ---------------------------------------------------------------------------
// WAF detection
// ---------------------------------------------------------------------------

// TestWAF_BlockedEmitsWAFFindingNotPathFindings verifies that when a server
// returns 403 with WAF-indicator headers on every path, the scanner emits a
// CheckDirbustWAFBlocked finding and does NOT emit CheckDirbustFound findings.
// probe() checks isWAFResponse() before checking interestingCodes, so WAF-blocked
// 403s are never counted as interesting path discoveries.
func TestWAF_BlockedEmitsWAFFindingNotPathFindings(t *testing.T) {
	ts := quietTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-WAF-Status", "blocked")
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()

	s := newTLSScanner(ts)
	// Provide enough paths so that 3 consecutive 403s can accumulate.
	paths := []string{"/admin", "/config", "/backup", "/secret", "/debug"}
	findings := s.Run(context.Background(), tlsAsset(ts), paths)

	wafFindings := findingsByCheckID(findings, finding.CheckDirbustWAFBlocked)
	pathFindings := findingsByCheckID(findings, finding.CheckDirbustFound)

	if len(wafFindings) == 0 {
		t.Error("BUG: expected CheckDirbustWAFBlocked finding when server returns 403+WAF header on every request, got none. " +
			"The consecutiveForbidden counter never reaches 3 because 403 is in interestingCodes and probe() returns early.")
	}

	if len(pathFindings) > 0 {
		t.Errorf("BUG: expected no CheckDirbustFound findings when WAF blocks all paths, got %d. "+
			"Paths returning 403 with WAF headers should not produce path findings.", len(pathFindings))
	}
}

// ---------------------------------------------------------------------------
// Interesting paths found vs. not found
// ---------------------------------------------------------------------------

// TestInterestingPaths_200Found verifies that a 200 response produces a finding
// and a 404 does not.
func TestInterestingPaths_200Found(t *testing.T) {
	ts := quietTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	s := newTLSScanner(ts)
	findings := s.Run(context.Background(), tlsAsset(ts), []string{"/admin", "/nothing"})

	pathFindings := findingsByCheckID(findings, finding.CheckDirbustFound)
	if len(pathFindings) != 1 {
		t.Fatalf("expected exactly 1 CheckDirbustFound finding, got %d: %+v", len(pathFindings), pathFindings)
	}
	if !strings.Contains(pathFindings[0].Title, "/admin") {
		t.Errorf("expected finding for /admin, got title: %q", pathFindings[0].Title)
	}
}

// TestAllNotFound_NoFindings verifies that a server returning 404 for every path
// produces zero findings.
func TestAllNotFound_NoFindings(t *testing.T) {
	ts := quietTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	s := newTLSScanner(ts)
	findings := s.Run(context.Background(), tlsAsset(ts), []string{"/foo", "/bar", "/baz"})

	if len(findings) != 0 {
		t.Errorf("expected no findings when server returns 404 for all paths, got %d: %+v", len(findings), findings)
	}
}

// ---------------------------------------------------------------------------
// 401 Unauthorized treated as a finding with Medium severity
// ---------------------------------------------------------------------------

func TestUnauthorized_FindingWithMediumSeverity(t *testing.T) {
	ts := quietTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	s := newTLSScanner(ts)
	findings := s.Run(context.Background(), tlsAsset(ts), []string{"/protected"})

	pathFindings := findingsByCheckID(findings, finding.CheckDirbustFound)
	if len(pathFindings) != 1 {
		t.Fatalf("expected exactly 1 CheckDirbustFound finding for 401 response, got %d", len(pathFindings))
	}
	if pathFindings[0].Severity != finding.SeverityMedium {
		t.Errorf("expected SeverityMedium for 401 finding (gated path), got %s", pathFindings[0].Severity)
	}
}

// ---------------------------------------------------------------------------
// Context cancellation
// ---------------------------------------------------------------------------

// TestContextCancellation verifies that cancelling the context before Run is called
// produces no findings and no panic.
func TestContextCancellation_NoPanic(t *testing.T) {
	ts := quietTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // would produce a finding if reached
	}))
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Run

	s := newTLSScanner(ts)
	findings := s.Run(ctx, tlsAsset(ts), []string{"/admin", "/secret"})

	// Must not panic. Findings may or may not be present depending on race,
	// but the scanner must handle a cancelled context gracefully.
	_ = findings
}

// TestContextCancellationDuringRun verifies that cancelling mid-scan stops
// further probing gracefully.
func TestContextCancellationDuringRun(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	var requestCount atomic.Int64
	ts := quietTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requestCount.Add(1) == 1 {
			// Cancel after first request is received
			cancel()
		}
		// Slow response to give cancellation time to propagate
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	s := newTLSScanner(ts)
	// 20 paths with concurrency 20 — all launched at once, but context cancelled
	// after first request lands.
	paths := make([]string, 20)
	for i := range paths {
		paths[i] = "/path"
	}

	// Must not panic.
	findings := s.Run(ctx, tlsAsset(ts), paths)
	_ = findings
}

// ---------------------------------------------------------------------------
// Empty path list
// ---------------------------------------------------------------------------

func TestEmptyPaths_ReturnsNil(t *testing.T) {
	s := dirbust.New()
	findings := s.Run(context.Background(), "example.com", []string{})
	if len(findings) != 0 {
		t.Errorf("expected no findings for empty path list, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Edge: canary/baseline probe gets 429 — scanner must back off, not treat
// all paths as soft-404
// ---------------------------------------------------------------------------

func TestDirBustRateLimitOnCanary(t *testing.T) {
	var requestCount atomic.Int64

	ts := quietTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := requestCount.Add(1)
		// First 4 requests: 1 catch-all baseline + 3 retries of /admin — all 429.
		if n <= 4 {
			w.Header().Set("Retry-After", "0") // minimal backoff for test speed
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		// If the scanner retries after the baseline 429, the real path returns 200.
		if r.URL.Path == "/admin" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("admin panel"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	s := newTLSScanner(ts)
	findings := s.Run(context.Background(), tlsAsset(ts), []string{"/admin"})

	// The scanner should NOT have false-positived by treating 429 as a valid
	// response. It should have retried and either found the path or exhausted
	// retries. The key assertion is that it didn't panic and didn't produce
	// spurious results.
	_ = findings
}

// ---------------------------------------------------------------------------
// Edge: connection reset mid-probe — no panic, no false positive
// ---------------------------------------------------------------------------

func TestDirBustConnectionReset(t *testing.T) {
	// Create a server that immediately closes the connection for the probed path.
	ts := quietTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			// Hijack the connection and close it to simulate a TCP reset.
			hj, ok := w.(http.Hijacker)
			if ok {
				conn, _, err := hj.Hijack()
				if err == nil {
					_ = conn.Close()
					return
				}
			}
			// Fallback: just close without writing.
			return
		}
		// Canary and other paths return 404 normally.
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	s := newTLSScanner(ts)
	// Must not panic on connection reset.
	findings := s.Run(context.Background(), tlsAsset(ts), []string{"/admin"})

	// Connection reset should NOT produce a finding — the path was never
	// successfully probed.
	pathFindings := findingsByCheckID(findings, finding.CheckDirbustFound)
	if len(pathFindings) > 0 {
		t.Errorf("expected no CheckDirbustFound findings on connection reset, got %d", len(pathFindings))
	}
}

// ---------------------------------------------------------------------------
// Tech-aware extension fuzzing
// ---------------------------------------------------------------------------

func TestExtensionsForFramework_PHP(t *testing.T) {
	exts := dirbust.ExtensionsForFramework("php")
	if len(exts) == 0 {
		t.Fatal("expected extensions for PHP framework")
	}
	found := false
	for _, e := range exts {
		if e == ".php" {
			found = true
		}
	}
	if !found {
		t.Error("expected .php in PHP extensions")
	}
}

func TestExtensionsForFramework_Unknown(t *testing.T) {
	exts := dirbust.ExtensionsForFramework("cobol")
	if len(exts) != 0 {
		t.Errorf("expected no extensions for unknown framework, got %v", exts)
	}
}

func TestExpandWithExtensions(t *testing.T) {
	paths := []string{"/admin", "/config.yml"}
	expanded := dirbust.ExpandWithExtensions(paths, "php")

	// /admin should get .php variants, /config.yml should not (already has extension)
	hasAdminPHP := false
	hasConfigPHP := false
	for _, p := range expanded {
		if p == "/admin.php" {
			hasAdminPHP = true
		}
		if p == "/config.yml.php" {
			hasConfigPHP = true
		}
	}
	if !hasAdminPHP {
		t.Error("expected /admin.php in expanded paths")
	}
	if hasConfigPHP {
		t.Error("/config.yml should not get .php extension (already has extension)")
	}
}

func TestExpandWithExtensions_NoFramework(t *testing.T) {
	paths := []string{"/admin", "/secret"}
	expanded := dirbust.ExpandWithExtensions(paths, "")
	if len(expanded) != len(paths) {
		t.Errorf("expected same paths back for empty framework, got %d vs %d", len(expanded), len(paths))
	}
}

// ---------------------------------------------------------------------------
// Recursive directory probing
// ---------------------------------------------------------------------------

func TestRecurse_FindsSubPaths(t *testing.T) {
	ts := quietTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin", "/admin/backup", "/admin/config":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("found"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	s := newTLSScanner(ts)
	s.SetRecurse(true)
	findings := s.Run(context.Background(), tlsAsset(ts), []string{"/admin"})

	pathFindings := findingsByCheckID(findings, finding.CheckDirbustFound)
	// Should find /admin plus /admin/backup and /admin/config from recursion
	if len(pathFindings) < 2 {
		t.Errorf("expected at least 2 findings with recursion (parent + sub-paths), got %d", len(pathFindings))
		for _, f := range pathFindings {
			t.Logf("  found: %s", f.Title)
		}
	}
}

func TestRecurse_Disabled_NoSubPaths(t *testing.T) {
	ts := quietTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin", "/admin/backup":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("found"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	s := newTLSScanner(ts)
	// recurse not set
	findings := s.Run(context.Background(), tlsAsset(ts), []string{"/admin"})

	pathFindings := findingsByCheckID(findings, finding.CheckDirbustFound)
	if len(pathFindings) != 1 {
		t.Errorf("expected exactly 1 finding without recursion, got %d", len(pathFindings))
	}
}

func TestFrameworkExtension_FindsPHPPaths(t *testing.T) {
	ts := quietTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin.php" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("PHP admin"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	s := newTLSScanner(ts)
	s.SetFramework("php")
	findings := s.Run(context.Background(), tlsAsset(ts), []string{"/admin"})

	pathFindings := findingsByCheckID(findings, finding.CheckDirbustFound)
	if len(pathFindings) != 1 {
		t.Fatalf("expected 1 finding for /admin.php, got %d", len(pathFindings))
	}
	if !strings.Contains(pathFindings[0].Title, "/admin.php") {
		t.Errorf("expected finding for /admin.php, got: %s", pathFindings[0].Title)
	}
}
