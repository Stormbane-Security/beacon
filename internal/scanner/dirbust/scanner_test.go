package dirbust_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/scanner/dirbust"
)

// assetFrom strips the scheme from an httptest URL so it can be passed as the
// asset hostname.  The dirbust scanner prepends "https://" itself; since httptest
// speaks plain HTTP we need it to speak HTTPS or we need to work around the
// scheme.  In these tests we use a plain-HTTP httptest server and strip "http://"
// — the scanner will try HTTPS first, fail, and the tests would break.  Instead
// we create a TLS httptest server (httptest.NewTLSServer) so the scanner's HTTPS
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

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	// The scanner should have made maxRetries (3) attempts.
	if got := requestCount.Load(); got != 3 {
		t.Errorf("expected 3 attempts (maxRetries) for a 429-only path, got %d", got)
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
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
