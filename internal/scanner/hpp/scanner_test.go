package hpp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

// TestHPP_SecondValueUsed verifies that when a server uses the second "role"
// parameter value (admin) instead of the first (user), a finding is emitted.
func TestHPP_SecondValueUsed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a server that uses the LAST value of a duplicated parameter.
		// In Go's url.Values, r.URL.Query()["role"] returns all values in order.
		roles := r.URL.Query()["role"]
		if len(roles) > 0 {
			// Use the last role value — simulating the vulnerable behaviour.
			lastRole := roles[len(roles)-1]
			if lastRole == "admin" {
				fmt.Fprintln(w, "Welcome, admin user!")
				return
			}
			fmt.Fprintln(w, "Welcome, regular user!")
			return
		}
		fmt.Fprintln(w, "Hello!")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	var hppFindings []finding.Finding
	for _, f := range findings {
		if f.CheckID == finding.CheckWebHPP {
			hppFindings = append(hppFindings, f)
		}
	}
	if len(hppFindings) == 0 {
		t.Fatal("expected at least 1 CheckWebHPP finding, got none")
	}
	for _, f := range hppFindings {
		if f.Severity != finding.SeverityMedium {
			t.Errorf("expected Medium severity, got %s", f.Severity)
		}
		if f.DeepOnly != true {
			t.Error("DeepOnly should be true for HPP finding")
		}
	}
}

// TestHPP_BothIgnored verifies that when a server ignores duplicate parameters
// and returns the same response regardless, no findings are emitted.
func TestHPP_BothIgnored(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Server ignores all query parameters — always returns the same response.
		fmt.Fprintln(w, "Standard response: id=1 result here.")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	for _, f := range findings {
		if f.CheckID == finding.CheckWebHPP {
			t.Errorf("unexpected HPP finding when server ignores duplicates: %+v", f)
		}
	}
}

// TestHPP_DeepModeOnly verifies that no probes are sent and no findings
// are returned when running in surface mode.
func TestHPP_DeepModeOnly(t *testing.T) {
	probed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probed = true
		fmt.Fprintln(w, "hello")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if findings != nil {
		t.Errorf("expected nil findings in surface mode, got %d", len(findings))
	}
	if probed {
		t.Error("scanner should not send any HTTP requests in surface mode")
	}
}
