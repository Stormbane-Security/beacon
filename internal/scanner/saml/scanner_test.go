package saml

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

// isProbe returns true for the catch-all detection path used by the scanner.
// Test servers must return 404 for this path so the catch-all check doesn't
// skip the entire scan.
func isProbe(r *http.Request) bool {
	return strings.Contains(r.URL.Path, "beacon-probe-c4a7f2d9b3e1-doesnotexist")
}

// samlMetadataBody is a minimal SAML metadata document.
const samlMetadataBody = `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
  entityID="https://idp.example.com">
  <IDPSSODescriptor WantAuthnRequestsSigned="false">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      Location="https://idp.example.com/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`

// TestSAML_EndpointDiscovery_MetadataFound verifies that a server returning
// SAML metadata produces a CheckSAMLMetadataExposed finding.
func TestSAML_EndpointDiscovery_MetadataFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/saml/metadata" {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(samlMetadataBody))
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
		if f.CheckID == finding.CheckSAMLMetadataExposed {
			found = true
			if f.Severity != finding.SeverityInfo {
				t.Errorf("expected Info severity for metadata exposure, got %s", f.Severity)
			}
			if f.ProofCommand == "" {
				t.Error("ProofCommand should be set")
			}
			break
		}
	}
	if !found {
		t.Errorf("expected %s finding when SAML metadata is exposed, got %v", finding.CheckSAMLMetadataExposed, findings)
	}
}

// TestSAML_NoEndpoints_NoFinding verifies that a server returning 404 for all
// SAML paths produces no findings.
func TestSAML_NoEndpoints_NoFinding(t *testing.T) {
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
		t.Fatalf("expected 0 findings when all SAML paths return 404, got %d: %v", len(findings), findings)
	}
}

// TestSAML_SkippedInSurfaceMode_ForActiveChecks verifies that ACS active
// probes (signature bypass, issuer mismatch, XXE, open redirect) do NOT run
// in surface mode even when an ACS endpoint exists.
func TestSAML_SkippedInSurfaceMode_ForActiveChecks(t *testing.T) {
	activeCheckIDs := []string{
		finding.CheckSAMLSignatureNotValidated,
		finding.CheckSAMLIssuerNotValidated,
		finding.CheckSAMLOpenRedirect,
		finding.CheckSAMLXXEInjection,
	}

	acsCalled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isProbe(r) {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodPost {
			acsCalled = true
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.URL.Path == "/saml/metadata" {
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(samlMetadataBody))
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

	if acsCalled {
		t.Error("ACS endpoint should not be POSTed to in surface mode")
	}

	for _, f := range findings {
		for _, activeID := range activeCheckIDs {
			if f.CheckID == activeID {
				t.Errorf("active check %s should not run in surface mode", activeID)
			}
		}
	}
}

// TestSAML_UnsignedAssertionAccepted verifies that when the ACS endpoint
// accepts a SAMLResponse with no Signature element, a Critical finding is
// emitted with CheckSAMLSignatureNotValidated.
func TestSAML_UnsignedAssertionAccepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isProbe(r) {
			http.NotFound(w, r)
			return
		}
		switch {
		case r.Method == http.MethodPost:
			// Accept everything — simulates broken signature validation.
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><body>Welcome back!</body></html>"))
		case r.URL.Path == "/saml/metadata":
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(samlMetadataBody))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanDeep)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckSAMLSignatureNotValidated {
			found = true
			if f.Severity != finding.SeverityCritical {
				t.Errorf("expected Critical severity, got %s", f.Severity)
			}
			if !f.DeepOnly {
				t.Error("DeepOnly should be true for signature bypass finding")
			}
			if f.ProofCommand == "" {
				t.Error("ProofCommand should be set")
			}
			break
		}
	}
	if !found {
		t.Errorf("expected %s finding when ACS accepts unsigned assertion", finding.CheckSAMLSignatureNotValidated)
	}
}

// TestSAML_IssuerMismatch_Accepted verifies that when the ACS endpoint
// accepts a SAMLResponse with a wrong Issuer, a High finding is emitted.
func TestSAML_IssuerMismatch_Accepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isProbe(r) {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodPost {
			// Accept all POSTs including ones with a mismatched issuer.
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html>Logged in</html>"))
			return
		}
		// Return 404 for all GET paths so only deep-mode active checks fire.
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanDeep)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckSAMLIssuerNotValidated {
			found = true
			if f.Severity != finding.SeverityHigh {
				t.Errorf("expected High severity, got %s", f.Severity)
			}
			ev := f.Evidence
			if ev["attacker_issuer"] == nil {
				t.Error("evidence should contain attacker_issuer")
			}
			break
		}
	}
	if !found {
		t.Errorf("expected %s finding when ACS accepts wrong issuer", finding.CheckSAMLIssuerNotValidated)
	}
}

// TestSAML_OpenRedirectViaRelayState verifies that when the ACS endpoint
// redirects to the RelayState value, a Medium open-redirect finding is emitted.
func TestSAML_OpenRedirectViaRelayState(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isProbe(r) {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodPost {
			_ = r.ParseForm()
			relay := r.FormValue("RelayState")
			if relay != "" {
				http.Redirect(w, r, relay, http.StatusFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanDeep)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckSAMLOpenRedirect {
			found = true
			if f.Severity != finding.SeverityMedium {
				t.Errorf("expected Medium severity, got %s", f.Severity)
			}
			loc, ok := f.Evidence["location_header"].(string)
			if !ok || !strings.Contains(loc, "evil.beacon-test.invalid") {
				t.Errorf("evidence location_header should reference evil URL, got %q", loc)
			}
			break
		}
	}
	if !found {
		t.Errorf("expected %s finding when ACS follows RelayState redirect", finding.CheckSAMLOpenRedirect)
	}
}

// TestSAML_XXEInjection verifies that when the ACS response contains
// /etc/passwd content (XXE resolved), a Critical finding is emitted.
func TestSAML_XXEInjection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isProbe(r) {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodPost {
			_ = r.ParseForm()
			encoded := r.FormValue("SAMLResponse")
			if encoded != "" {
				decoded, err := base64.StdEncoding.DecodeString(encoded)
				if err == nil && strings.Contains(string(decoded), "SYSTEM") {
					// Simulate XXE being resolved — echo /etc/passwd content in error.
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`Error processing assertion: root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin`))
					return
				}
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanDeep)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckSAMLXXEInjection {
			found = true
			if f.Severity != finding.SeverityCritical {
				t.Errorf("expected Critical severity, got %s", f.Severity)
			}
			if !f.DeepOnly {
				t.Error("DeepOnly should be true for XXE finding")
			}
			break
		}
	}
	if !found {
		t.Errorf("expected %s finding when ACS leaks /etc/passwd via XXE", finding.CheckSAMLXXEInjection)
	}
}
