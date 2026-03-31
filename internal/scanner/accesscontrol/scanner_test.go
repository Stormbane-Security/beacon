package accesscontrol_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
	"github.com/stormbane/beacon/internal/scanner/accesscontrol"
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

// runOnServer runs the access control scanner against the given test server
// in the specified scan mode. The scanner tries HTTPS first; since the test
// server is plain HTTP, the HTTPS attempt fails and it falls back to HTTP.
func runOnServer(t *testing.T, ts *httptest.Server, scanType module.ScanType) ([]finding.Finding, error) {
	t.Helper()
	asset := strings.TrimPrefix(ts.URL, "http://")
	s := accesscontrol.New()
	return s.Run(context.Background(), asset, scanType)
}

// ---------------------------------------------------------------------------
// Surface mode — scanner must be a no-op (deep-only scanner)
// ---------------------------------------------------------------------------

func TestSurfaceMode_ReturnsNil(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return an admin page that would normally trigger a finding.
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><title>Admin Dashboard</title><body>Management Settings Users Control Panel</body></html>"))
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings in surface mode (access control scanner is deep-only), got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Deep mode — unauthenticated admin access (Check 1)
// ---------------------------------------------------------------------------

func TestAdminPath_200WithAdminContent_CriticalFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" || r.URL.Path == "/admin/" {
			w.WriteHeader(http.StatusOK)
			// Body with 2+ admin signals to pass looksLikeAdminPage.
			w.Write([]byte("<html><title>Admin Dashboard</title><body>User Management Settings</body></html>"))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckAccessControlVerticalEscalation) {
		t.Error("expected CheckAccessControlVerticalEscalation when admin path returns 200 with admin content")
	}
	if !hasSeverity(findings, finding.CheckAccessControlVerticalEscalation, finding.SeverityCritical) {
		t.Error("expected SeverityCritical for unauthenticated admin access")
	}
}

func TestAdminPath_200WithAdminContent_EvidenceFields(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" || r.URL.Path == "/admin/" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<html><title>Admin Dashboard</title><body>System Configuration Users</body></html>"))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if f.CheckID != finding.CheckAccessControlVerticalEscalation {
			continue
		}
		if f.ProofCommand == "" {
			t.Error("ProofCommand must not be empty")
		}
		if _, ok := f.Evidence["url"]; !ok {
			t.Error("Evidence must contain 'url' key")
		}
		if _, ok := f.Evidence["path"]; !ok {
			t.Error("Evidence must contain 'path' key")
		}
		if _, ok := f.Evidence["status_code"]; !ok {
			t.Error("Evidence must contain 'status_code' key")
		}
		if !f.DeepOnly {
			t.Error("finding must have DeepOnly=true")
		}
		return // only need to check one
	}
}

func TestAdminPath_200WithGenericContent_NoFinding(t *testing.T) {
	// Server returns 200 but body has fewer than 2 admin signals.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>Welcome to our website</body></html>"))
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckAccessControlVerticalEscalation) {
		t.Error("should not emit vertical escalation finding when response body lacks admin signals")
	}
}

func TestAdminPath_404_NoFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings when all admin paths return 404, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Deep mode — HTTP method bypass (Check 2)
// ---------------------------------------------------------------------------

func TestMethodBypass_GET403_POST200_HighFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" || r.URL.Path == "/admin/" {
			if r.Method == http.MethodGet {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte("Forbidden"))
				return
			}
			// POST (and other methods) bypass the auth check.
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Admin panel content"))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckAccessControlMethodBypass) {
		t.Error("expected CheckAccessControlMethodBypass when GET returns 403 but POST returns 200")
	}
	if !hasSeverity(findings, finding.CheckAccessControlMethodBypass, finding.SeverityHigh) {
		t.Error("expected SeverityHigh for method bypass finding")
	}
}

func TestMethodBypass_EvidenceFields(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" || r.URL.Path == "/admin/" {
			if r.Method == http.MethodGet {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Bypassed"))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if f.CheckID != finding.CheckAccessControlMethodBypass {
			continue
		}
		if f.ProofCommand == "" {
			t.Error("ProofCommand must not be empty on method bypass finding")
		}
		if !strings.Contains(f.ProofCommand, "-X") {
			t.Errorf("ProofCommand should include -X flag for method bypass, got: %s", f.ProofCommand)
		}
		if _, ok := f.Evidence["bypass_method"]; !ok {
			t.Error("Evidence must contain 'bypass_method' key")
		}
		if _, ok := f.Evidence["get_status"]; !ok {
			t.Error("Evidence must contain 'get_status' key")
		}
		if _, ok := f.Evidence["bypass_status"]; !ok {
			t.Error("Evidence must contain 'bypass_status' key")
		}
		if !f.DeepOnly {
			t.Error("finding must have DeepOnly=true")
		}
		return
	}
}

func TestMethodBypass_GET403_AllMethods403_NoFinding(t *testing.T) {
	// Auth properly enforced on all methods — no bypass possible.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" || r.URL.Path == "/admin/" {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Forbidden"))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckAccessControlMethodBypass) {
		t.Error("should not emit method bypass finding when all methods return 403")
	}
}

func TestMethodBypass_GET200_NoMethodProbing(t *testing.T) {
	// When GET returns 200, method bypass is not tested (Check 1 fires instead
	// if the body looks like admin content, or nothing happens if it doesn't).
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckAccessControlMethodBypass) {
		t.Error("should not test method bypass when GET does not return 403")
	}
}

func TestMethodBypass_GET403_POST200EmptyBody_NoFinding(t *testing.T) {
	// POST returns 200 but with an empty body — scanner requires len(bypassBody) > 0.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" || r.URL.Path == "/admin/" {
			if r.Method == http.MethodGet {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusOK)
			// Empty body
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckAccessControlMethodBypass) {
		t.Error("should not emit method bypass finding when bypass response body is empty")
	}
}

// ---------------------------------------------------------------------------
// Deep mode — path traversal bypass (Check 3)
// ---------------------------------------------------------------------------

func TestPathTraversalBypass_GET403_VariantReturns200_HighFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Exact admin paths are blocked.
		for _, blocked := range []string{"/admin", "/admin/", "/dashboard", "/console"} {
			if path == blocked {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte("Forbidden"))
				return
			}
		}

		// Path variant using uppercase bypasses the naive auth middleware.
		if strings.EqualFold(path, "/admin") || strings.EqualFold(path, "/dashboard") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Admin bypass content"))
			return
		}

		http.NotFound(w, r)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckAccessControlPathTraversalBypass) {
		t.Error("expected CheckAccessControlPathTraversalBypass when path variant bypasses 403")
	}
	if !hasSeverity(findings, finding.CheckAccessControlPathTraversalBypass, finding.SeverityHigh) {
		t.Error("expected SeverityHigh for path traversal bypass finding")
	}
}

func TestPathTraversalBypass_EvidenceFields(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/admin" || path == "/admin/" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		// Trailing dot variant bypasses auth.
		if path == "/admin/." {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Bypassed via trailing dot"))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if f.CheckID != finding.CheckAccessControlPathTraversalBypass {
			continue
		}
		if f.ProofCommand == "" {
			t.Error("ProofCommand must not be empty on path traversal bypass finding")
		}
		if _, ok := f.Evidence["original_path"]; !ok {
			t.Error("Evidence must contain 'original_path' key")
		}
		if _, ok := f.Evidence["original_status"]; !ok {
			t.Error("Evidence must contain 'original_status' key")
		}
		if _, ok := f.Evidence["variant_path"]; !ok {
			t.Error("Evidence must contain 'variant_path' key")
		}
		if _, ok := f.Evidence["variant_desc"]; !ok {
			t.Error("Evidence must contain 'variant_desc' key")
		}
		if _, ok := f.Evidence["variant_status"]; !ok {
			t.Error("Evidence must contain 'variant_status' key")
		}
		if !f.DeepOnly {
			t.Error("finding must have DeepOnly=true")
		}
		return
	}
}

func TestPathTraversalBypass_GET401_VariantReturns200_HighFinding(t *testing.T) {
	// Path traversal is also tested when GET returns 401 (not just 403).
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/admin" || path == "/admin/" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized"))
			return
		}
		// Case variation bypasses auth.
		if strings.EqualFold(path, "/admin") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Admin bypass content"))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckAccessControlPathTraversalBypass) {
		t.Error("expected path traversal bypass finding when GET returns 401 and variant returns 200")
	}
}

func TestPathTraversalBypass_GET403_AllVariants403_NoFinding(t *testing.T) {
	// Auth properly enforced on all path variants — no bypass possible.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Block everything under admin paths regardless of variant.
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Forbidden"))
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckAccessControlPathTraversalBypass) {
		t.Error("should not emit path traversal bypass when all variants return 403")
	}
}

func TestPathTraversalBypass_VariantReturnsSameBodyAs403_NoFinding(t *testing.T) {
	// Variant returns 200 but with the exact same body as the 403 response.
	// The scanner requires variantBody != body to avoid false positives.
	forbiddenBody := "Access Denied"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/admin" || path == "/admin/" {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(forbiddenBody))
			return
		}
		// Variant returns 200 but identical body.
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(forbiddenBody))
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckAccessControlPathTraversalBypass) {
		t.Error("should not emit path traversal bypass when variant body matches the original 403 body")
	}
}

// ---------------------------------------------------------------------------
// Authorized mode — scanner should also run
// ---------------------------------------------------------------------------

func TestAuthorizedMode_FindingsEmitted(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" || r.URL.Path == "/admin/" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<html><title>Admin</title><body>Dashboard Management System Users</body></html>"))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckAccessControlVerticalEscalation) {
		t.Error("expected findings in authorized mode (scanner should run in both deep and authorized)")
	}
}

// ---------------------------------------------------------------------------
// ProofCommand contains actual URL
// ---------------------------------------------------------------------------

func TestProofCommand_ContainsActualURL(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" || r.URL.Path == "/admin/" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<html>Admin Dashboard Management System Users Settings</html>"))
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
		if f.ProofCommand == "" {
			t.Errorf("ProofCommand must not be empty on finding %s", f.CheckID)
		}
		if !strings.Contains(f.ProofCommand, host) {
			t.Errorf("ProofCommand must contain actual server host %q, got: %s", host, f.ProofCommand)
		}
	}
}

// ---------------------------------------------------------------------------
// Scanner name
// ---------------------------------------------------------------------------

func TestName_ReturnsAccessControl(t *testing.T) {
	s := accesscontrol.New()
	if s.Name() != "accesscontrol" {
		t.Errorf("expected scanner name %q, got %q", "accesscontrol", s.Name())
	}
}

// ---------------------------------------------------------------------------
// Unreachable server — no panic, no findings
// ---------------------------------------------------------------------------

func TestUnreachableServer_NoFindingsNoPanic(t *testing.T) {
	s := accesscontrol.New()
	findings, err := s.Run(context.Background(), "127.0.0.1:1", module.ScanDeep)
	_ = err
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for unreachable server, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Context cancellation — no panic
// ---------------------------------------------------------------------------

func TestContextCancelled_NoPanic(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html>Admin Dashboard Management System</html>"))
	}))
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Run

	asset := strings.TrimPrefix(ts.URL, "http://")
	s := accesscontrol.New()
	findings, _ := s.Run(ctx, asset, module.ScanDeep)
	_ = findings // must not panic
}

// ---------------------------------------------------------------------------
// Multiple admin paths — one finding per vulnerable path
// ---------------------------------------------------------------------------

func TestMultipleAdminPaths_FindingsPerPath(t *testing.T) {
	adminPages := map[string]bool{
		"/admin":     true,
		"/admin/":    true,
		"/dashboard": true,
		"/console":   true,
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if adminPages[r.URL.Path] {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<html>Admin Dashboard Users Management Settings Configuration</html>"))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have at least findings for /admin, /dashboard, /console.
	// (/admin/ is also in adminPaths but /admin triggers first and continues,
	// skipping further checks for that path; /admin/ is a separate entry.)
	count := 0
	for _, f := range findings {
		if f.CheckID == finding.CheckAccessControlVerticalEscalation {
			count++
		}
	}
	if count < 3 {
		t.Errorf("expected at least 3 vertical escalation findings for multiple admin paths, got %d", count)
	}
}

// ---------------------------------------------------------------------------
// Method bypass: only one bypass finding per path (first method that works)
// ---------------------------------------------------------------------------

func TestMethodBypass_OnlyOnePerPath(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" || r.URL.Path == "/admin/" {
			if r.Method == http.MethodGet {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			// All non-GET methods succeed.
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Bypassed"))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Count method bypass findings for /admin specifically.
	count := 0
	for _, f := range findings {
		if f.CheckID == finding.CheckAccessControlMethodBypass {
			if path, ok := f.Evidence["path"].(string); ok && path == "/admin" {
				count++
			}
		}
	}
	if count > 1 {
		t.Errorf("expected at most 1 method bypass finding per path, got %d for /admin", count)
	}
}

// ---------------------------------------------------------------------------
// Path traversal bypass: only one variant finding per path (first that works)
// ---------------------------------------------------------------------------

func TestPathTraversalBypass_OnlyOnePerPath(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/admin" || path == "/admin/" {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Forbidden"))
			return
		}
		// Multiple path variants would bypass auth.
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Different content from the forbidden page"))
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	count := 0
	for _, f := range findings {
		if f.CheckID == finding.CheckAccessControlPathTraversalBypass {
			if origPath, ok := f.Evidence["original_path"].(string); ok && origPath == "/admin" {
				count++
			}
		}
	}
	if count > 1 {
		t.Errorf("expected at most 1 path traversal bypass finding per path, got %d for /admin", count)
	}
}

// ---------------------------------------------------------------------------
// Admin page detection: requires at least 2 signals
// ---------------------------------------------------------------------------

func TestAdminPath_200WithOnlyOneSignal_NoFinding(t *testing.T) {
	// Body has only one admin signal ("admin") — should not trigger.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>Contact the admin for help</body></html>"))
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckAccessControlVerticalEscalation) {
		t.Error("should not flag as admin page when body contains only 1 admin signal")
	}
}

func TestAdminPath_200WithTwoSignals_Finding(t *testing.T) {
	// Body has exactly 2 admin signals — should trigger.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" || r.URL.Path == "/admin/" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<html><body>Dashboard - Users list</body></html>"))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckAccessControlVerticalEscalation) {
		t.Error("expected vertical escalation finding when body has 2 admin signals (dashboard + users)")
	}
}

// ---------------------------------------------------------------------------
// When admin path returns 200 with admin content, method and path traversal
// checks are skipped for that path (the scanner uses continue).
// ---------------------------------------------------------------------------

func TestAdminAccess_SkipsMethodAndTraversalChecks(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" || r.URL.Path == "/admin/" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<html>Admin Dashboard Management System Users Settings</html>"))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have vertical escalation but NOT method bypass or path traversal
	// for the same path, since the scanner uses continue after Check 1.
	for _, f := range findings {
		if f.CheckID == finding.CheckAccessControlMethodBypass {
			if path, ok := f.Evidence["path"].(string); ok && (path == "/admin" || path == "/admin/") {
				t.Error("should not emit method bypass for a path where unauthenticated admin access was already found")
			}
		}
		if f.CheckID == finding.CheckAccessControlPathTraversalBypass {
			if path, ok := f.Evidence["original_path"].(string); ok && (path == "/admin" || path == "/admin/") {
				t.Error("should not emit path traversal bypass for a path where unauthenticated admin access was already found")
			}
		}
	}
}

// ---------------------------------------------------------------------------
// All findings have module="deep" and scanner="accesscontrol"
// ---------------------------------------------------------------------------

func TestAllFindings_ModuleAndScannerSet(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" || r.URL.Path == "/admin/" {
			if r.Method == http.MethodGet {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Bypassed"))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if f.Module != "deep" {
			t.Errorf("expected Module=%q, got %q", "deep", f.Module)
		}
		if f.Scanner != "accesscontrol" {
			t.Errorf("expected Scanner=%q, got %q", "accesscontrol", f.Scanner)
		}
	}
}
