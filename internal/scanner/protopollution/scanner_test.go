package protopollution

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

// TestProtoPollution_PayloadReflected verifies that when the probe marker
// appears in the GET response after a POST a High finding is emitted.
func TestProtoPollution_PayloadReflected(t *testing.T) {
	// Simulate a vulnerable endpoint: stores the polluted property and returns
	// it on subsequent GETs.
	polluted := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			polluted = true
			w.WriteHeader(http.StatusOK)
			return
		}
		// GET: if already "polluted", reflect the marker.
		if polluted {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"` + probeMarker + `":true,"other":"data"}`)) //nolint:errcheck
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`)) //nolint:errcheck
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least 1 finding for prototype pollution, got none")
	}
	for _, f := range findings {
		if f.CheckID != finding.CheckWebPrototypePollution {
			t.Errorf("unexpected check ID: %s", f.CheckID)
		}
		if f.Severity != finding.SeverityHigh {
			t.Errorf("expected High severity, got %s", f.Severity)
		}
		if f.ProofCommand == "" {
			t.Error("ProofCommand should be set")
		}
	}
}

// TestProtoPollution_NotReflected verifies that when the GET response does not
// contain the probe marker no finding is emitted.
func TestProtoPollution_NotReflected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Response never includes the marker regardless of POST payload.
		w.Write([]byte(`{"status":"ok"}`)) //nolint:errcheck
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	for _, f := range findings {
		if f.CheckID == finding.CheckWebPrototypePollution {
			t.Errorf("unexpected prototype pollution finding when marker not reflected: %+v", f)
		}
	}
}

// TestProtoPollution_DeepModeOnly ensures no requests are sent in surface mode.
func TestProtoPollution_DeepModeOnly(t *testing.T) {
	probed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probed = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings in surface mode, got %d", len(findings))
	}
	if probed {
		t.Error("scanner should not send any HTTP requests in surface mode")
	}
}
