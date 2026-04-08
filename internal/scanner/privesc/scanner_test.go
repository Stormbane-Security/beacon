package privesc_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanner/privesc"
)

func hasCheckID(findings []finding.Finding, id finding.CheckID) bool {
	for _, f := range findings {
		if f.CheckID == id {
			return true
		}
	}
	return false
}

// runOnServer runs the privesc scanner against the given test server.
func runOnServer(t *testing.T, ts *httptest.Server, scanType module.ScanType) ([]finding.Finding, error) {
	t.Helper()
	asset := strings.TrimPrefix(ts.URL, "http://")
	s := privesc.New()
	return s.Run(context.Background(), asset, scanType)
}

// ---------------------------------------------------------------------------
// Non-authorized modes -- scanner must be a no-op
// ---------------------------------------------------------------------------

func TestSurfaceMode_ReturnsNil(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><body>admin dashboard management settings users system</body></html>`))
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings in surface mode, got %d", len(findings))
	}
}

func TestDeepMode_ReturnsNil(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><body>admin dashboard management settings users system</body></html>`))
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings in deep mode (privesc is authorized-only), got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Vertical privesc: admin endpoint accessible to unauth user → finding emitted
// ---------------------------------------------------------------------------

func TestVerticalPrivesc_AdminAccessible_EmitsFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serve admin-like content on admin paths.
		if strings.HasPrefix(r.URL.Path, "/admin") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><title>Admin Dashboard</title><body>
				<h1>Administration Panel</h1>
				<p>Welcome to the admin dashboard. Manage users and system settings here.</p>
			</body></html>`))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckPrivescBrokenAccessControl) {
		t.Error("expected broken_access_control finding for accessible admin endpoint, got none")
	}
}

// ---------------------------------------------------------------------------
// Vertical privesc: admin endpoint returns 403 → no finding
// ---------------------------------------------------------------------------

func TestVerticalPrivesc_AdminForbidden_NoFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/admin") || strings.HasPrefix(r.URL.Path, "/dashboard") ||
			strings.HasPrefix(r.URL.Path, "/console") || strings.HasPrefix(r.URL.Path, "/manage") ||
			strings.HasPrefix(r.URL.Path, "/panel") || strings.HasPrefix(r.URL.Path, "/internal") ||
			strings.HasPrefix(r.URL.Path, "/api/admin") || strings.HasPrefix(r.URL.Path, "/settings") ||
			strings.HasPrefix(r.URL.Path, "/management") || strings.HasPrefix(r.URL.Path, "/cpanel") {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("Access Denied"))
			return
		}
		// Also block all API IDOR endpoints so no horizontal findings fire.
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("Access Denied"))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(findings, finding.CheckPrivescBrokenAccessControl) {
		t.Error("expected no broken_access_control finding when admin returns 403")
	}
}

// ---------------------------------------------------------------------------
// Method bypass: GET=403, POST=200 → finding emitted
// ---------------------------------------------------------------------------

func TestMethodBypass_POST200_EmitsFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/admin") {
			if r.Method == http.MethodGet {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte("Forbidden"))
				return
			}
			// POST/PUT/DELETE/PATCH all return 200 — broken access control.
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok","action":"admin_update"}`))
			return
		}
		// Block IDOR endpoints too.
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckPrivescMethodBypass) {
		t.Error("expected method_bypass finding when POST returns 200 but GET returns 403")
	}
}

// ---------------------------------------------------------------------------
// Horizontal privesc: IDOR via sequential ID → finding emitted
// ---------------------------------------------------------------------------

func TestHorizontalPrivesc_SequentialID_EmitsFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serve different user data for different IDs on /api/users/<id>.
		path := r.URL.Path
		if strings.HasPrefix(path, "/api/users/") || strings.HasPrefix(path, "/api/v1/users/") {
			// Extract the ID from the last path segment.
			parts := strings.Split(strings.TrimRight(path, "/"), "/")
			id := parts[len(parts)-1]
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `{"user_id":%s,"email":"user%s@example.com","name":"User %s"}`, id, id, id)
			return
		}
		// Block admin endpoints so no vertical findings fire.
		if strings.HasPrefix(path, "/admin") || strings.HasPrefix(path, "/dashboard") ||
			strings.HasPrefix(path, "/console") || strings.HasPrefix(path, "/manage") ||
			strings.HasPrefix(path, "/panel") || strings.HasPrefix(path, "/internal") ||
			strings.HasPrefix(path, "/settings") || strings.HasPrefix(path, "/management") {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("Forbidden"))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckPrivescHorizontalPrivesc) {
		t.Error("expected horizontal_privesc finding for sequential ID enumeration, got none")
	}
}

// ---------------------------------------------------------------------------
// ContainsNumericID helper
// ---------------------------------------------------------------------------

func TestContainsNumericID(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/api/users/123", true},
		{"/api/users/123/profile", true},
		{"/api/users/abc", false},
		{"/api/users", false},
	}
	for _, tt := range tests {
		if got := privesc.ContainsNumericID(tt.path); got != tt.want {
			t.Errorf("ContainsNumericID(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}
