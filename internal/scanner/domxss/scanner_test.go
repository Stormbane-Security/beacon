package domxss

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)

func TestDOMXSS_SkipsNonAuthorized(t *testing.T) {
	s := New()
	for _, st := range []module.ScanType{module.ScanSurface, module.ScanDeep} {
		findings, err := s.Run(context.Background(), "example.com", st)
		if err != nil {
			t.Fatal(err)
		}
		if len(findings) != 0 {
			t.Errorf("DOM XSS scanner should skip scan type %v", st)
		}
	}
}

func TestDOMXSS_GracefulSkipNoChrome(t *testing.T) {
	// If Chrome isn't installed, the scanner should return nil gracefully
	if chromeAvailable() {
		t.Skip("Chrome is available — this test verifies graceful skip without Chrome")
	}
	s := New()
	findings, err := s.Run(context.Background(), "example.com", module.ScanAuthorized)
	if err != nil {
		t.Errorf("expected nil error when Chrome unavailable, got: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when Chrome unavailable, got %d", len(findings))
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input string
		max   int
		want  string
	}{
		{"short", 10, "short"},
		{"hello world", 5, "hello..."},
		{"", 5, ""},
		{"exact", 5, "exact"},
	}
	for _, tt := range tests {
		got := truncate(tt.input, tt.max)
		if got != tt.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.max, got, tt.want)
		}
	}
}

func TestCanaryConstant(t *testing.T) {
	if canary == "" {
		t.Error("canary string must not be empty")
	}
	if len(canary) < 10 {
		t.Error("canary string should be long enough to avoid false matches")
	}
}

func TestTracerJS_Embedded(t *testing.T) {
	if tracerJS == "" {
		t.Fatal("tracer.js was not embedded")
	}
	if len(tracerJS) < 100 {
		t.Error("tracer.js seems too short — embedding may have failed")
	}
}

func TestChromeAvailable(t *testing.T) {
	// Just verify it doesn't panic — result depends on the host
	_ = chromeAvailable()
}

// TestDOMXSS_DetectsInnerHTMLSink verifies end-to-end detection: a page that
// assigns location.hash to innerHTML should produce a web.xss finding.
func TestDOMXSS_DetectsInnerHTMLSink(t *testing.T) {
	if !chromeAvailable() {
		t.Skip("Chrome not available — DOM XSS detection requires headless Chrome")
	}

	// Vulnerable page: reads location.hash and writes it into innerHTML.
	vulnPage := `<!DOCTYPE html>
<html><body>
<div id="output"></div>
<script>
document.getElementById('output').innerHTML = decodeURIComponent(location.hash.slice(1));
</script>
</body></html>`

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot start test server: %v", err)
	}
	defer l.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, vulnPage)
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(l)
	defer srv.Close()

	asset := l.Addr().String() // "127.0.0.1:XXXXX"
	s := New()
	findings, err := s.Run(context.Background(), asset, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("scanner returned error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckWebXSS {
			found = true
			sink, _ := f.Evidence["sink"].(string)
			if sink != "innerHTML" {
				t.Errorf("expected sink=innerHTML, got %q", sink)
			}
			break
		}
	}
	if !found {
		t.Errorf("expected web.xss finding for innerHTML sink, got %d findings: %+v", len(findings), findings)
	}
}

// TestDOMXSS_NoFindingOnSafePage verifies no false positive on a page that
// does not use any dangerous sinks with user-controlled data.
func TestDOMXSS_NoFindingOnSafePage(t *testing.T) {
	if !chromeAvailable() {
		t.Skip("Chrome not available")
	}

	safePage := `<!DOCTYPE html>
<html><body><p>Hello, world!</p></body></html>`

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot start test server: %v", err)
	}
	defer l.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, safePage)
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(l)
	defer srv.Close()

	asset := l.Addr().String()
	s := New()
	findings, err := s.Run(context.Background(), asset, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("scanner returned error: %v", err)
	}
	for _, f := range findings {
		if f.CheckID == finding.CheckWebXSS {
			t.Errorf("expected no XSS finding on safe page, got: %s", f.Title)
		}
	}
}
