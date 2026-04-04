package secheaders_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanner/secheaders"
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

func run(t *testing.T, handler http.HandlerFunc) []finding.Finding {
	t.Helper()
	ts := httptest.NewServer(handler)
	defer ts.Close()
	asset := strings.TrimPrefix(ts.URL, "http://")
	s := secheaders.New()
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return findings
}

// ---------------------------------------------------------------------------
// Name
// ---------------------------------------------------------------------------

func TestName(t *testing.T) {
	s := secheaders.New()
	if s.Name() != "secheaders" {
		t.Errorf("expected name 'secheaders', got %q", s.Name())
	}
}

// ---------------------------------------------------------------------------
// All headers present — no findings for missing headers
// ---------------------------------------------------------------------------

func TestAllHeadersPresent_NoMissingFindings(t *testing.T) {
	findings := run(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=()")
		w.WriteHeader(http.StatusOK)
	})

	missingChecks := []finding.CheckID{
		finding.CheckHeadersMissingCSP,
		finding.CheckHeadersMissingHSTS,
		finding.CheckHeadersMissingXFrameOptions,
		finding.CheckHeadersMissingXContentType,
		finding.CheckHeadersMissingReferrerPolicy,
		finding.CheckHeadersMissingPermissionsPolicy,
	}
	for _, id := range missingChecks {
		if hasCheckID(findings, id) {
			t.Errorf("should not emit %s when header is present", id)
		}
	}
}

// ---------------------------------------------------------------------------
// No headers at all — emit all missing header findings
// ---------------------------------------------------------------------------

func TestNoHeaders_EmitsAllMissing(t *testing.T) {
	findings := run(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	expected := []finding.CheckID{
		finding.CheckHeadersMissingCSP,
		finding.CheckHeadersMissingHSTS,
		finding.CheckHeadersMissingXFrameOptions,
		finding.CheckHeadersMissingXContentType,
		finding.CheckHeadersMissingReferrerPolicy,
		finding.CheckHeadersMissingPermissionsPolicy,
	}
	for _, id := range expected {
		if !hasCheckID(findings, id) {
			t.Errorf("expected finding %s for bare response", id)
		}
	}
}

// ---------------------------------------------------------------------------
// CSP with frame-ancestors downgrades X-Frame-Options to Info
// ---------------------------------------------------------------------------

func TestCSPFrameAncestors_DowngradesXFO(t *testing.T) {
	findings := run(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		w.WriteHeader(http.StatusOK)
	})

	if !hasCheckID(findings, finding.CheckHeadersMissingXFrameOptions) {
		t.Fatal("expected X-Frame-Options finding even with CSP frame-ancestors")
	}
	if !hasSeverity(findings, finding.CheckHeadersMissingXFrameOptions, finding.SeverityInfo) {
		t.Error("X-Frame-Options finding should be Info when CSP frame-ancestors is set")
	}
}

// ---------------------------------------------------------------------------
// No CSP and no X-Frame-Options — XFO stays Medium
// ---------------------------------------------------------------------------

func TestNoCSP_XFOStaysMedium(t *testing.T) {
	findings := run(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	if !hasSeverity(findings, finding.CheckHeadersMissingXFrameOptions, finding.SeverityMedium) {
		t.Error("X-Frame-Options finding should be Medium when CSP is also missing")
	}
}

// ---------------------------------------------------------------------------
// Server header with version — info leak
// ---------------------------------------------------------------------------

func TestServerVersionLeak(t *testing.T) {
	findings := run(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin")
		w.Header().Set("Permissions-Policy", "camera=()")
		w.WriteHeader(http.StatusOK)
	})

	if !hasCheckID(findings, finding.CheckHeadersServerInfoLeak) {
		t.Error("expected server info leak finding for versioned Server header")
	}
}

// ---------------------------------------------------------------------------
// Server header without version — no info leak
// ---------------------------------------------------------------------------

func TestServerNoVersion_NoLeak(t *testing.T) {
	findings := run(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "nginx")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin")
		w.Header().Set("Permissions-Policy", "camera=()")
		w.WriteHeader(http.StatusOK)
	})

	if hasCheckID(findings, finding.CheckHeadersServerInfoLeak) {
		t.Error("should not emit server info leak for unversioned Server header")
	}
}

// ---------------------------------------------------------------------------
// X-Powered-By header — info leak
// ---------------------------------------------------------------------------

func TestXPoweredByLeak(t *testing.T) {
	findings := run(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Powered-By", "Express")
		w.WriteHeader(http.StatusOK)
	})

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckHeadersServerInfoLeak {
			if f.Evidence["header"] == "X-Powered-By" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected info leak finding for X-Powered-By header")
	}
}

// ---------------------------------------------------------------------------
// Feature-Policy (legacy) satisfies Permissions-Policy check
// ---------------------------------------------------------------------------

func TestFeaturePolicy_SatisfiesPermissionsPolicy(t *testing.T) {
	findings := run(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Feature-Policy", "camera 'none'")
		w.WriteHeader(http.StatusOK)
	})

	if hasCheckID(findings, finding.CheckHeadersMissingPermissionsPolicy) {
		t.Error("should not emit missing Permissions-Policy when Feature-Policy is set")
	}
}

// ---------------------------------------------------------------------------
// Scanner runs in surface mode (not deep-only)
// ---------------------------------------------------------------------------

func TestRunsInSurfaceMode(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	asset := strings.TrimPrefix(ts.URL, "http://")
	s := secheaders.New()

	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected findings in surface mode — scanner should not be deep-only")
	}
}

// ---------------------------------------------------------------------------
// ProofCommand is set on every finding
// ---------------------------------------------------------------------------

func TestProofCommandSet(t *testing.T) {
	findings := run(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	for _, f := range findings {
		if f.ProofCommand == "" {
			t.Errorf("finding %s has empty ProofCommand", f.CheckID)
		}
	}
}
