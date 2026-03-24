package log4shell

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

// TestLog4Shell_JavaSignalDetected_SurfaceOnly verifies that when the server
// sets a JSESSIONID cookie the surface scan returns no findings (Java signals
// are informational only and do not produce an emitted finding).
func TestLog4Shell_JavaSignalDetected_SurfaceOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "ABCDEF1234567890"})
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintln(w, "<html><body>App</body></html>")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	// Surface mode must never emit a finding — Java signals are purely
	// informational and recorded in detectJavaSignals(), not in findings.
	if len(findings) != 0 {
		t.Errorf("surface mode should not emit findings, got %d", len(findings))
	}
}

// TestLog4Shell_ReflectionInBody_DeepMode verifies that when the server echoes
// the JNDI string back in the response body a Critical finding is emitted.
func TestLog4Shell_ReflectionInBody_DeepMode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a Java debug endpoint: set Tomcat Server header (Java signal)
		// and echo all request headers back in the response body.
		w.Header().Set("Server", "Apache Tomcat/9.0.75")
		var sb strings.Builder
		for name, vals := range r.Header {
			sb.WriteString(name + ": " + strings.Join(vals, ", ") + "\n")
		}
		fmt.Fprintln(w, sb.String())
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least 1 Critical finding for JNDI reflection, got none")
	}
	f := findings[0]
	if f.CheckID != finding.CheckCVELog4Shell {
		t.Errorf("expected check ID %s, got %s", finding.CheckCVELog4Shell, f.CheckID)
	}
	if f.Severity != finding.SeverityCritical {
		t.Errorf("expected Critical severity, got %s", f.Severity)
	}
	if f.ProofCommand == "" {
		t.Error("ProofCommand should be set")
	}
}

// TestLog4Shell_NoReflection_NoFinding verifies that when the server ignores
// the JNDI headers and returns a plain response no finding is emitted.
func TestLog4Shell_NoReflection_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Server completely ignores injected headers.
		fmt.Fprintln(w, "<html><body>Welcome</body></html>")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	for _, f := range findings {
		if f.CheckID == finding.CheckCVELog4Shell {
			t.Errorf("unexpected Log4Shell finding when no reflection: %+v", f)
		}
	}
}

// TestLog4Shell_SkippedInSurfaceMode_ActiveProbes verifies that in surface
// mode the scanner does not inject JNDI payloads into request headers.
func TestLog4Shell_SkippedInSurfaceMode_ActiveProbes(t *testing.T) {
	jndiSeen := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, vals := range r.Header {
			for _, v := range vals {
				if strings.Contains(v, jndiPrefix) {
					jndiSeen = true
				}
			}
		}
		fmt.Fprintln(w, "ok")
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
	if jndiSeen {
		t.Error("JNDI payload was injected in a request header during surface mode scan")
	}
}
