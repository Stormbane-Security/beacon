package iam

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

// TestIAM_SCIMUnauthenticated verifies that when a SCIM endpoint returns user
// data without authentication, a Critical CheckSCIMUnauthenticated finding is
// produced.
func TestIAM_SCIMUnauthenticated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/scim/v2/") {
			w.Header().Set("Content-Type", "application/scim+json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],"totalResults":3,"Resources":[]}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckSCIMUnauthenticated {
			found = true
			if f.Severity != finding.SeverityCritical {
				t.Errorf("expected Critical severity, got %s", f.Severity)
			}
			if f.ProofCommand == "" {
				t.Error("ProofCommand should be set")
			}
			break
		}
	}
	if !found {
		t.Errorf("expected %s finding when SCIM is unauthenticated, got %v", finding.CheckSCIMUnauthenticated, findings)
	}
}

// TestIAM_SCIMAuthRequired verifies that when a SCIM endpoint returns 401,
// no CheckSCIMUnauthenticated finding is produced (only a lower-severity
// CheckSCIMExposed may be produced, which is acceptable).
func TestIAM_SCIMAuthRequired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/scim/") {
			w.Header().Set("WWW-Authenticate", `Bearer realm="SCIM"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range findings {
		if f.CheckID == finding.CheckSCIMUnauthenticated {
			t.Errorf("should not produce %s when SCIM requires authentication", finding.CheckSCIMUnauthenticated)
		}
	}
}

// TestIAM_OIDCUserinfoLeak verifies that when the OIDC userinfo endpoint
// returns sub/email without an Authorization header, a High finding is emitted.
func TestIAM_OIDCUserinfoLeak(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			doc := map[string]string{
				"issuer":            "http://" + r.Host,
				"userinfo_endpoint": "http://" + r.Host + "/userinfo",
			}
			_ = json.NewEncoder(w).Encode(doc)
		case "/userinfo":
			// Return user data without checking Authorization header.
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintln(w, `{"sub":"user123","email":"alice@example.com","name":"Alice"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckOIDCUserinfoLeak {
			found = true
			if f.Severity != finding.SeverityHigh {
				t.Errorf("expected High severity, got %s", f.Severity)
			}
			if f.Evidence["userinfo_url"] == nil {
				t.Error("evidence should contain userinfo_url")
			}
			break
		}
	}
	if !found {
		t.Errorf("expected %s finding when userinfo endpoint leaks data", finding.CheckOIDCUserinfoLeak)
	}
}

// TestIAM_DeviceFlowExposed verifies that when the device authorization
// endpoint returns a device_code, a Medium finding is produced.
func TestIAM_DeviceFlowExposed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/device_authorization" && r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintln(w, `{"device_code":"DC-abc123","user_code":"ABCD-1234","verification_uri":"https://example.com/activate","expires_in":1800}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckOAuthDeviceFlowExposed {
			found = true
			if f.Severity != finding.SeverityMedium {
				t.Errorf("expected Medium severity, got %s", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Errorf("expected %s finding when device flow is exposed", finding.CheckOAuthDeviceFlowExposed)
	}
}

// TestIAM_DynamicClientReg verifies that when the dynamic client registration
// endpoint returns a client_id, a High finding is produced.
func TestIAM_DynamicClientReg(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/register" && r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintln(w, `{"client_id":"new-client-abc","client_secret":"s3cr3t","redirect_uris":["https://beacon-test.invalid"]}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckOAuthDynClientReg {
			found = true
			if f.Severity != finding.SeverityHigh {
				t.Errorf("expected High severity, got %s", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Errorf("expected %s finding when dynamic client registration is open", finding.CheckOAuthDynClientReg)
	}
}

// TestIAM_IntrospectExposed verifies that when the token introspection endpoint
// responds to unauthenticated requests with active:true, a High finding is
// produced.
func TestIAM_IntrospectExposed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/introspect" && r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintln(w, `{"active":true,"sub":"user@example.com","scope":"openid profile","exp":9999999999}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckOAuthIntrospectExposed {
			found = true
			if f.Severity != finding.SeverityHigh {
				t.Errorf("expected High severity, got %s", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Errorf("expected %s finding when introspect is exposed", finding.CheckOAuthIntrospectExposed)
	}
}

// TestIAM_IdPAdminExposed verifies that when an IdP admin path returns HTTP 200
// without authentication, a Critical finding is produced.
func TestIAM_IdPAdminExposed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/admin/" {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `<html><body><h1>Keycloak Admin Console</h1></body></html>`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckIdentityProviderExposed {
			found = true
			if f.Severity != finding.SeverityCritical {
				t.Errorf("expected Critical severity, got %s", f.Severity)
			}
			if f.Evidence["path"] == nil {
				t.Error("evidence should contain path")
			}
			break
		}
	}
	if !found {
		t.Errorf("expected %s finding when IdP admin panel is exposed", finding.CheckIdentityProviderExposed)
	}
}

// TestIAM_RoleAssignmentExposed verifies that when a role API endpoint returns
// a JSON array without authentication, a Critical finding is produced.
func TestIAM_RoleAssignmentExposed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/roles" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `[{"id":"1","name":"admin"},{"id":"2","name":"editor"},{"id":"3","name":"viewer"}]`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckIdentityRoleEscalation {
			found = true
			if f.Severity != finding.SeverityCritical {
				t.Errorf("expected Critical severity, got %s", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Errorf("expected %s finding when role endpoint is exposed", finding.CheckIdentityRoleEscalation)
	}
}

// TestIAM_NoFindings verifies that when all paths return 404, no findings are
// produced.
func TestIAM_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when all paths return 404, got %d: %v", len(findings), findings)
	}
}
