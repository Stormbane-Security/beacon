package domxss

import (
	"context"
	"testing"

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
