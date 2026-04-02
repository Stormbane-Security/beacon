package openredir_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanner/openredir"
)

func hasCheckID(findings []finding.Finding, id finding.CheckID) bool {
	for _, f := range findings {
		if f.CheckID == id {
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
	s := openredir.New()
	findings, err := s.Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return findings
}

// ---------------------------------------------------------------------------
// Name
// ---------------------------------------------------------------------------

func TestName(t *testing.T) {
	s := openredir.New()
	if s.Name() != "openredir" {
		t.Errorf("expected name 'openredir', got %q", s.Name())
	}
}

// ---------------------------------------------------------------------------
// Surface mode — scanner must be a no-op
// ---------------------------------------------------------------------------

func TestSurfaceMode_ReturnsNil(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("url") != "" {
			w.Header().Set("Location", r.URL.Query().Get("url"))
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	asset := strings.TrimPrefix(ts.URL, "http://")
	s := openredir.New()
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings in surface mode, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Open redirect via ?url= parameter — absolute URL
// ---------------------------------------------------------------------------

func TestAbsoluteURLRedirect(t *testing.T) {
	findings := run(t, func(w http.ResponseWriter, r *http.Request) {
		if u := r.URL.Query().Get("url"); u != "" {
			w.Header().Set("Location", u)
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	if !hasCheckID(findings, finding.CheckWebOpenRedirect) {
		t.Error("expected open redirect finding for ?url= with absolute URL")
	}
}

// ---------------------------------------------------------------------------
// Open redirect via ?redirect= parameter
// ---------------------------------------------------------------------------

func TestRedirectParam(t *testing.T) {
	findings := run(t, func(w http.ResponseWriter, r *http.Request) {
		if u := r.URL.Query().Get("redirect"); u != "" {
			w.Header().Set("Location", u)
			w.WriteHeader(http.StatusMovedPermanently)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	if !hasCheckID(findings, finding.CheckWebOpenRedirect) {
		t.Error("expected open redirect finding for ?redirect=")
	}

	// Verify param name is in evidence.
	for _, f := range findings {
		if f.CheckID == finding.CheckWebOpenRedirect {
			if f.Evidence["parameter"] != "redirect" {
				t.Errorf("expected parameter='redirect', got %v", f.Evidence["parameter"])
			}
			return
		}
	}
}

// ---------------------------------------------------------------------------
// No redirect — server ignores the parameter
// ---------------------------------------------------------------------------

func TestNoRedirect_NoFindings(t *testing.T) {
	findings := run(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	if hasCheckID(findings, finding.CheckWebOpenRedirect) {
		t.Error("should not emit findings when server doesn't redirect")
	}
}

// ---------------------------------------------------------------------------
// Redirect to same domain — not an open redirect
// ---------------------------------------------------------------------------

func TestSameDomainRedirect_NoFindings(t *testing.T) {
	findings := run(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("url") != "" {
			// Redirect to self, not to the canary domain.
			w.Header().Set("Location", "/dashboard")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	if hasCheckID(findings, finding.CheckWebOpenRedirect) {
		t.Error("should not emit findings for same-domain redirect")
	}
}

// ---------------------------------------------------------------------------
// Protocol-relative redirect (//evil.example.com)
// ---------------------------------------------------------------------------

func TestProtocolRelativeRedirect(t *testing.T) {
	findings := run(t, func(w http.ResponseWriter, r *http.Request) {
		if u := r.URL.Query().Get("url"); u != "" {
			w.Header().Set("Location", u)
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	if !hasCheckID(findings, finding.CheckWebOpenRedirect) {
		t.Error("expected open redirect finding for protocol-relative URL payload")
	}
}

// ---------------------------------------------------------------------------
// ProofCommand is set on every finding
// ---------------------------------------------------------------------------

func TestProofCommandSet(t *testing.T) {
	findings := run(t, func(w http.ResponseWriter, r *http.Request) {
		if u := r.URL.Query().Get("url"); u != "" {
			w.Header().Set("Location", u)
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	for _, f := range findings {
		if f.ProofCommand == "" {
			t.Errorf("finding %s has empty ProofCommand", f.CheckID)
		}
	}
}

// ---------------------------------------------------------------------------
// Deduplicate: one finding per parameter, not per payload
// ---------------------------------------------------------------------------

func TestDeduplicatePerParam(t *testing.T) {
	findings := run(t, func(w http.ResponseWriter, r *http.Request) {
		// Accept any redirect parameter value — all payloads succeed.
		if u := r.URL.Query().Get("url"); u != "" {
			w.Header().Set("Location", u)
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	count := 0
	for _, f := range findings {
		if f.CheckID == finding.CheckWebOpenRedirect {
			if f.Evidence["parameter"] == "url" {
				count++
			}
		}
	}
	if count > 1 {
		t.Errorf("expected at most 1 finding per parameter, got %d for 'url'", count)
	}
}

// ---------------------------------------------------------------------------
// 200 response (not a redirect) — no findings even with Location header
// ---------------------------------------------------------------------------

func TestNonRedirectStatusWithLocation_NoFindings(t *testing.T) {
	findings := run(t, func(w http.ResponseWriter, r *http.Request) {
		if u := r.URL.Query().Get("url"); u != "" {
			w.Header().Set("Location", u)
			w.WriteHeader(http.StatusOK) // 200, not 3xx
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	if hasCheckID(findings, finding.CheckWebOpenRedirect) {
		t.Error("should not emit findings when status is 200 (not a redirect)")
	}
}
