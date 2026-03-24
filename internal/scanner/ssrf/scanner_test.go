package ssrf

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

// TestSSRF_MetadataReflected verifies that when a server reflects cloud
// metadata content in its response, a Critical SSRF finding is emitted.
func TestSSRF_MetadataReflected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate an SSRF-vulnerable server that fetches the URL param and
		// echoes back the content — we return metadata-like content directly.
		urlParam := r.URL.Query().Get("url")
		if urlParam != "" {
			fmt.Fprintln(w, "ami-id: ami-0abcdef1234567890")
			fmt.Fprintln(w, "instance-id: i-1234567890abcdef0")
			return
		}
		fmt.Fprintln(w, "Welcome")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least 1 SSRF finding, got none")
	}
	for _, f := range findings {
		if f.CheckID != finding.CheckWebSSRF {
			t.Errorf("unexpected check ID: %s", f.CheckID)
		}
		if f.Severity != finding.SeverityCritical {
			t.Errorf("expected Critical severity, got %s", f.Severity)
		}
		if f.DeepOnly != true {
			t.Error("DeepOnly should be true for SSRF finding")
		}
	}
}

// TestSSRF_NoReflection verifies that a server returning normal content
// does not produce any SSRF findings.
func TestSSRF_NoReflection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello, world! This is a normal page.")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	for _, f := range findings {
		if f.CheckID == finding.CheckWebSSRF {
			t.Errorf("unexpected SSRF finding on normal page: %+v", f)
		}
	}
}

// TestSSRF_DeepModeOnly verifies that no probes are sent and no findings
// are returned when running in surface mode.
func TestSSRF_DeepModeOnly(t *testing.T) {
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
