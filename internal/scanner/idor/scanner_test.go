package idor_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanner/idor"
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

// runOnServer runs the IDOR scanner against the given test server in the
// specified scan mode. The scanner uses schemedetect.Base which tries HTTPS
// first; since the test server is plain HTTP, the HTTPS probe fails and the
// scanner falls back to HTTP.
func runOnServer(t *testing.T, ts *httptest.Server, scanType module.ScanType) ([]finding.Finding, error) {
	t.Helper()
	asset := strings.TrimPrefix(ts.URL, "http://")
	s := idor.New()
	return s.Run(context.Background(), asset, scanType)
}

// ---------------------------------------------------------------------------
// Surface mode -- scanner must be a no-op (IDOR is deep-mode only)
// ---------------------------------------------------------------------------

func TestSurfaceMode_ReturnsNil(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serve a vulnerable response that would trigger findings in deep mode.
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"user_id": %s, "email": "user@example.com"}`, r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:])
	}))
	defer ts.Close()

	s := idor.New()
	asset := strings.TrimPrefix(ts.URL, "http://")
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings in surface mode (IDOR scanner is deep-only), got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Sequential ID detection -- different content for adjacent IDs
// ---------------------------------------------------------------------------

func TestSequentialID_DifferentContent_EmitsFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return distinct JSON for each numeric ID across all API prefixes.
		path := r.URL.Path
		lastSlash := strings.LastIndex(path, "/")
		if lastSlash < 0 {
			http.NotFound(w, r)
			return
		}
		id := path[lastSlash+1:]

		// Only respond to recognized API prefixes with numeric IDs.
		if strings.HasPrefix(path, "/api/") && id != "" && id[0] >= '0' && id[0] <= '9' {
			w.Header().Set("Content-Type", "application/json")
			// Return different body per ID so the scanner detects IDOR.
			_, _ = fmt.Fprintf(w, `{"id": %s, "name": "user_%s", "email": "user%s@example.com"}`, id, id, id)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckIDORSequentialID) {
		t.Error("expected CheckIDORSequentialID finding when adjacent IDs return different resources")
	}
	if !hasSeverity(findings, finding.CheckIDORSequentialID, finding.SeverityHigh) {
		t.Error("expected SeverityHigh for sequential ID IDOR finding")
	}
}

// ---------------------------------------------------------------------------
// Sequential ID detection -- same content for all IDs (generic response)
// ---------------------------------------------------------------------------

func TestSequentialID_SameContent_NoFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		// Return the exact same body for every ID -- this looks like a generic
		// response or error page, not a real per-object resource.
		if strings.HasPrefix(path, "/api/") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"status": "ok", "message": "welcome"}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckIDORSequentialID) {
		t.Error("expected no IDOR finding when all IDs return identical content (generic response)")
	}
}

// ---------------------------------------------------------------------------
// Sequential ID detection -- seed returns 200 but adjacent returns 404
// ---------------------------------------------------------------------------

func TestSequentialID_AdjacentNotFound_NoFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		lastSlash := strings.LastIndex(path, "/")
		if lastSlash < 0 {
			http.NotFound(w, r)
			return
		}
		id := path[lastSlash+1:]

		// Only ID "1" returns 200; all others return 404.
		if strings.HasPrefix(path, "/api/") && id == "1" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"id": 1, "name": "only_one"}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckIDORSequentialID) {
		t.Error("expected no IDOR finding when adjacent IDs return 404")
	}
}

// ---------------------------------------------------------------------------
// Non-API endpoint -- no false positives
// ---------------------------------------------------------------------------

func TestNonAPIEndpoint_NoFalsePositive(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serve HTML on all paths -- this is a regular website, not an API.
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, "<html><body>Welcome</body></html>")
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckIDORSequentialID) {
		t.Error("expected no IDOR finding on non-API endpoint serving identical HTML")
	}
}

// ---------------------------------------------------------------------------
// BOLA: unauthenticated access to user data endpoint
// ---------------------------------------------------------------------------

func TestBOLA_UnauthenticatedUserData_EmitsFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /api/me returns user data without any auth check.
		if r.URL.Path == "/api/me" || r.URL.Path == "/api/v1/me" ||
			r.URL.Path == "/api/profile" || r.URL.Path == "/api/v1/profile" ||
			r.URL.Path == "/api/user" || r.URL.Path == "/api/v1/user" ||
			r.URL.Path == "/api/account" || r.URL.Path == "/api/v1/account" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"username": "admin", "email": "admin@example.com", "phone": "+1234567890"}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckBOLAHorizontalAccess) {
		t.Error("expected CheckBOLAHorizontalAccess finding when /api/me returns user data without auth")
	}
	if !hasSeverity(findings, finding.CheckBOLAHorizontalAccess, finding.SeverityCritical) {
		t.Error("expected SeverityCritical for BOLA horizontal access finding")
	}
}

// ---------------------------------------------------------------------------
// BOLA: endpoint returns 200 but no user-data signals
// ---------------------------------------------------------------------------

func TestBOLA_NoUserDataSignals_NoFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /api/me returns a generic JSON without any user data fields.
		if r.URL.Path == "/api/me" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"status": "healthy", "version": "1.0"}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckBOLAHorizontalAccess) {
		t.Error("expected no BOLA finding when endpoint returns no user-data signals (email, username, etc.)")
	}
}

// ---------------------------------------------------------------------------
// BOLA: endpoint returns 401/403 -- no finding
// ---------------------------------------------------------------------------

func TestBOLA_Unauthorized_NoFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/me" || r.URL.Path == "/api/v1/me" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = fmt.Fprint(w, `{"error": "unauthorized"}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckBOLAHorizontalAccess) {
		t.Error("expected no BOLA finding when endpoint returns 401")
	}
}

// ---------------------------------------------------------------------------
// BOLA: endpoint returns empty body -- no finding
// ---------------------------------------------------------------------------

func TestBOLA_EmptyBody_NoFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/me" {
			w.WriteHeader(http.StatusOK)
			// empty body
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckBOLAHorizontalAccess) {
		t.Error("expected no BOLA finding when endpoint returns empty body")
	}
}

// ---------------------------------------------------------------------------
// ScanAuthorized mode -- scanner should also run
// ---------------------------------------------------------------------------

func TestAuthorizedMode_AlsoRuns(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		lastSlash := strings.LastIndex(path, "/")
		if lastSlash < 0 {
			http.NotFound(w, r)
			return
		}
		id := path[lastSlash+1:]

		if strings.HasPrefix(path, "/api/") && id != "" && id[0] >= '0' && id[0] <= '9' {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"id": %s, "secret": "data_%s"}`, id, id)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckIDORSequentialID) {
		t.Error("expected IDOR findings in ScanAuthorized mode (scanner should run for deep AND authorized)")
	}
}

// ---------------------------------------------------------------------------
// Finding metadata -- ProofCommand and Evidence correctness
// ---------------------------------------------------------------------------

func TestSequentialID_FindingMetadata(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		lastSlash := strings.LastIndex(path, "/")
		if lastSlash < 0 {
			http.NotFound(w, r)
			return
		}
		id := path[lastSlash+1:]

		if strings.HasPrefix(path, "/api/") && id != "" && id[0] >= '0' && id[0] <= '9' {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"id": %s, "record": "item_%s"}`, id, id)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	host := strings.TrimPrefix(ts.URL, "http://")
	for _, f := range findings {
		if f.CheckID != finding.CheckIDORSequentialID {
			continue
		}

		// ProofCommand must contain actual host, not a placeholder.
		if f.ProofCommand == "" {
			t.Error("ProofCommand must not be empty on IDOR finding")
		}
		if !strings.Contains(f.ProofCommand, host) {
			t.Errorf("ProofCommand must contain test server host %q, got: %s", host, f.ProofCommand)
		}

		// Evidence must have key fields.
		if _, ok := f.Evidence["endpoint"]; !ok {
			t.Error("IDOR finding Evidence must include 'endpoint'")
		}
		if _, ok := f.Evidence["seed_id"]; !ok {
			t.Error("IDOR finding Evidence must include 'seed_id'")
		}
		if _, ok := f.Evidence["adjacent_id"]; !ok {
			t.Error("IDOR finding Evidence must include 'adjacent_id'")
		}

		// Module and scanner fields.
		if f.Module != "deep" {
			t.Errorf("expected Module='deep', got %q", f.Module)
		}
		if f.Scanner != "idor" {
			t.Errorf("expected Scanner='idor', got %q", f.Scanner)
		}
		if !f.DeepOnly {
			t.Error("IDOR finding must have DeepOnly=true")
		}
		if f.Asset != host {
			t.Errorf("expected Asset=%q, got %q", host, f.Asset)
		}
		return // only need to check one finding
	}
}

func TestBOLA_FindingMetadata(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/me" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"username": "alice", "email": "alice@example.com"}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	host := strings.TrimPrefix(ts.URL, "http://")
	for _, f := range findings {
		if f.CheckID != finding.CheckBOLAHorizontalAccess {
			continue
		}

		if f.ProofCommand == "" {
			t.Error("ProofCommand must not be empty on BOLA finding")
		}
		if !strings.Contains(f.ProofCommand, host) {
			t.Errorf("ProofCommand must contain test server host %q, got: %s", host, f.ProofCommand)
		}

		if _, ok := f.Evidence["url"]; !ok {
			t.Error("BOLA finding Evidence must include 'url'")
		}
		if _, ok := f.Evidence["status"]; !ok {
			t.Error("BOLA finding Evidence must include 'status'")
		}

		if f.Module != "deep" {
			t.Errorf("expected Module='deep', got %q", f.Module)
		}
		if f.Scanner != "idor" {
			t.Errorf("expected Scanner='idor', got %q", f.Scanner)
		}
		if !f.DeepOnly {
			t.Error("BOLA finding must have DeepOnly=true")
		}
		return
	}
}

// ---------------------------------------------------------------------------
// One finding per prefix -- scanner should not duplicate findings
// ---------------------------------------------------------------------------

func TestSequentialID_OneFindingPerPrefix(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		lastSlash := strings.LastIndex(path, "/")
		if lastSlash < 0 {
			http.NotFound(w, r)
			return
		}
		id := path[lastSlash+1:]

		if strings.HasPrefix(path, "/api/") && id != "" && id[0] >= '0' && id[0] <= '9' {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"id": %s, "data": "resource_%s"}`, id, id)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Count IDOR findings per endpoint prefix. The scanner uses goto nextPrefix
	// to emit at most one finding per prefix.
	prefixCounts := make(map[string]int)
	for _, f := range findings {
		if f.CheckID == finding.CheckIDORSequentialID {
			ep, _ := f.Evidence["endpoint"].(string)
			prefixCounts[ep]++
		}
	}

	for ep, count := range prefixCounts {
		if count > 1 {
			t.Errorf("expected at most 1 IDOR finding for prefix %q, got %d", ep, count)
		}
	}
}

// ---------------------------------------------------------------------------
// Unreachable server -- no panic, no findings
// ---------------------------------------------------------------------------

func TestUnreachableServer_NoFindingsNoPanic(t *testing.T) {
	s := idor.New()
	// Port 1 is reserved and should be unreachable on loopback.
	findings, err := s.Run(context.Background(), "127.0.0.1:1", module.ScanDeep)
	_ = err
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for unreachable server, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Context cancellation -- no panic
// ---------------------------------------------------------------------------

func TestContextCancelled_NoPanic(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		lastSlash := strings.LastIndex(path, "/")
		if lastSlash >= 0 {
			id := path[lastSlash+1:]
			if id != "" && id[0] >= '0' && id[0] <= '9' {
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprintf(w, `{"id": %s}`, id)
				return
			}
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Run

	asset := strings.TrimPrefix(ts.URL, "http://")
	s := idor.New()
	findings, _ := s.Run(ctx, asset, module.ScanDeep)
	_ = findings // must not panic
}

// ---------------------------------------------------------------------------
// Scanner Name
// ---------------------------------------------------------------------------

func TestName(t *testing.T) {
	s := idor.New()
	if s.Name() != "idor" {
		t.Errorf("expected scanner name 'idor', got %q", s.Name())
	}
}

// ---------------------------------------------------------------------------
// Seed returns 200 but empty body -- no finding
// ---------------------------------------------------------------------------

func TestSequentialID_EmptySeedBody_NoFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.WriteHeader(http.StatusOK)
			// empty body
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckIDORSequentialID) {
		t.Error("expected no IDOR finding when seed returns empty body")
	}
}

// ---------------------------------------------------------------------------
// BOLA: only one BOLA finding emitted even if multiple endpoints are vulnerable
// ---------------------------------------------------------------------------

func TestBOLA_OnlyOneFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// All user-scoped endpoints return user data.
		bolaEndpoints := map[string]bool{
			"/api/me":         true,
			"/api/v1/me":      true,
			"/api/user":       true,
			"/api/v1/user":    true,
			"/api/profile":    true,
			"/api/v1/profile": true,
			"/api/account":    true,
			"/api/v1/account": true,
		}
		if bolaEndpoints[r.URL.Path] {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"username": "admin", "email": "admin@corp.com", "address": "123 Main St"}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	bolaCount := 0
	for _, f := range findings {
		if f.CheckID == finding.CheckBOLAHorizontalAccess {
			bolaCount++
		}
	}
	if bolaCount > 1 {
		t.Errorf("expected at most 1 BOLA finding (scanner should break after first), got %d", bolaCount)
	}
}

// ---------------------------------------------------------------------------
// Combined: both IDOR and BOLA detected on same server
// ---------------------------------------------------------------------------

func TestCombined_IDORAndBOLA(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// BOLA: /api/me leaks user data without auth.
		if path == "/api/me" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"username": "bob", "email": "bob@example.com"}`)
			return
		}

		// IDOR: sequential ID endpoints return different resources.
		lastSlash := strings.LastIndex(path, "/")
		if lastSlash >= 0 {
			id := path[lastSlash+1:]
			if strings.HasPrefix(path, "/api/") && id != "" && id[0] >= '0' && id[0] <= '9' {
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprintf(w, `{"id": %s, "name": "user_%s"}`, id, id)
				return
			}
		}

		http.NotFound(w, r)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckIDORSequentialID) {
		t.Error("expected CheckIDORSequentialID finding")
	}
	if !hasCheckID(findings, finding.CheckBOLAHorizontalAccess) {
		t.Error("expected CheckBOLAHorizontalAccess finding")
	}
}
