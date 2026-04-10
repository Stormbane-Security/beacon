package statemachine_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanner/authctx"
	"github.com/stormbane-security/beacon/internal/scanner/statemachine"
)

func hasCheckID(findings []finding.Finding, id finding.CheckID) bool {
	for _, f := range findings {
		if f.CheckID == id {
			return true
		}
	}
	return false
}

func runOnServer(t *testing.T, ts *httptest.Server, scanType module.ScanType) ([]finding.Finding, error) {
	t.Helper()
	asset := strings.TrimPrefix(ts.URL, "http://")
	s := statemachine.New()
	return s.Run(context.Background(), asset, scanType)
}

func runOnServerWithAuth(t *testing.T, ts *httptest.Server, scanType module.ScanType, authClient *http.Client) ([]finding.Finding, error) {
	t.Helper()
	asset := strings.TrimPrefix(ts.URL, "http://")
	ctx := authctx.WithHTTPClient(context.Background(), authClient)
	s := statemachine.New()
	return s.Run(ctx, asset, scanType)
}

// ---------------------------------------------------------------------------
// Non-authorized modes -- scanner must be a no-op
// ---------------------------------------------------------------------------

func TestSurfaceMode_ReturnsNil(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><body>Welcome to the dashboard. Your account settings and profile are here. Logout</body></html>`))
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
		_, _ = w.Write([]byte(`<html><body>Welcome to the dashboard. Your account settings and profile are here. Logout</body></html>`))
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings in deep mode (statemachine is authorized-only), got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// State skip: post-auth endpoint accessible without auth → finding emitted
// ---------------------------------------------------------------------------

func TestStateSkip_DashboardAccessible_EmitsFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/dashboard" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><title>Dashboard</title><body>
				<h1>Welcome to your dashboard</h1>
				<p>Manage your account settings and profile here.</p>
				<a href="/logout">Logout</a>
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
	if !hasCheckID(findings, finding.CheckStateSkipDetected) {
		t.Error("expected state_skip_detected finding for accessible /dashboard, got none")
	}
}

// ---------------------------------------------------------------------------
// State skip: post-auth endpoint redirects to login → no finding
// ---------------------------------------------------------------------------

func TestStateSkip_DashboardRedirects_NoFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/dashboard" || r.URL.Path == "/account" ||
			r.URL.Path == "/profile" || r.URL.Path == "/settings" ||
			r.URL.Path == "/admin" || strings.HasPrefix(r.URL.Path, "/admin/") ||
			r.URL.Path == "/home" || r.URL.Path == "/app" ||
			r.URL.Path == "/members" || r.URL.Path == "/my-account" ||
			r.URL.Path == "/billing" || r.URL.Path == "/subscription" ||
			r.URL.Path == "/user/settings" || r.URL.Path == "/account/settings" ||
			strings.HasPrefix(r.URL.Path, "/api/") {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		// Premium/payment endpoints also redirect.
		if r.URL.Path == "/premium" || r.URL.Path == "/pro" ||
			r.URL.Path == "/paid" || r.URL.Path == "/courses" ||
			r.URL.Path == "/downloads" || strings.HasPrefix(r.URL.Path, "/premium/") ||
			r.URL.Path == "/subscription/manage" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(findings, finding.CheckStateSkipDetected) {
		t.Error("expected no state_skip_detected finding when /dashboard redirects to /login")
	}
}

// ---------------------------------------------------------------------------
// State skip: login page content returned → no finding (isLogin filter)
// ---------------------------------------------------------------------------

func TestStateSkip_LoginPageContent_NoFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return login page for all protected paths.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><title>Login</title><body>
			<h1>Sign In</h1>
			<form><input name="password" type="password" /><button>Log in</button></form>
			<p>Please authenticate with your password to sign in.</p>
		</body></html>`))
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(findings, finding.CheckStateSkipDetected) {
		t.Error("expected no state_skip_detected finding when login page is returned")
	}
}

// ---------------------------------------------------------------------------
// Incomplete auth flow: same content with and without auth → finding emitted
// ---------------------------------------------------------------------------

func TestIncompleteAuthFlow_SameContent_EmitsFinding(t *testing.T) {
	content := `<html><title>Dashboard</title><body>
		<h1>Welcome to your dashboard</h1>
		<p>Manage your account settings and profile here.</p>
		<a href="/logout">Sign out</a>
	</body></html>`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/dashboard" {
			// Return same content regardless of auth.
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(content))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	// Create a distinct auth client (different from default) so the scanner
	// recognizes we have auth and runs the comparison.
	authClient := &http.Client{}

	findings, err := runOnServerWithAuth(t, ts, module.ScanAuthorized, authClient)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckIncompleteAuthFlow) {
		t.Error("expected incomplete_auth_flow finding when content is identical with/without auth, got none")
	}
}

// ---------------------------------------------------------------------------
// Incomplete auth flow: different content → no finding
// ---------------------------------------------------------------------------

func TestIncompleteAuthFlow_DifferentContent_NoFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/dashboard" {
			auth := r.Header.Get("Authorization")
			if auth != "" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`<html><body>Welcome admin! Dashboard with account, profile, settings. Logout.</body></html>`))
			} else {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`<html><body>Please sign in. Login form. Password required. Authenticate now.</body></html>`))
			}
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	authTransport := &headerTransport{header: "Authorization", value: "Bearer token123"}
	authClient := &http.Client{Transport: authTransport}

	findings, err := runOnServerWithAuth(t, ts, module.ScanAuthorized, authClient)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(findings, finding.CheckIncompleteAuthFlow) {
		t.Error("expected no incomplete_auth_flow finding when responses differ")
	}
}

// ---------------------------------------------------------------------------
// Step bypass: verification exists + premium accessible → finding emitted
// ---------------------------------------------------------------------------

func TestStepBypass_VerificationExists_PremiumAccessible_EmitsFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/verify-email":
			// Verification step exists.
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><body>Please verify your email address.</body></html>`))
		case "/premium":
			// Premium content accessible without auth.
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><body>
				<h1>Premium Dashboard</h1>
				<p>Welcome to premium content. Manage your account and subscription settings.</p>
				<a href="/logout">Sign out</a>
			</body></html>`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckStepBypass) {
		t.Error("expected step_bypass finding when verification exists but premium is accessible, got none")
	}
}

// ---------------------------------------------------------------------------
// Step bypass: no verification endpoints → no step_bypass finding
// ---------------------------------------------------------------------------

func TestStepBypass_NoVerificationEndpoints_NoFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/premium" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><body>Premium dashboard with account settings and profile. Logout.</body></html>`))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	findings, err := runOnServer(t, ts, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(findings, finding.CheckStepBypass) {
		t.Error("expected no step_bypass finding when no verification endpoints exist")
	}
}

// ---------------------------------------------------------------------------
// Scanner name
// ---------------------------------------------------------------------------

func TestName(t *testing.T) {
	s := statemachine.New()
	if s.Name() != "statemachine" {
		t.Errorf("Name() = %q, want %q", s.Name(), "statemachine")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// headerTransport adds a fixed header to every request, simulating auth.
type headerTransport struct {
	header string
	value  string
}

func (t *headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set(t.header, t.value)
	return http.DefaultTransport.RoundTrip(req)
}
