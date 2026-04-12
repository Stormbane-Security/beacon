package scan

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)

type stubScanner struct {
	name     string
	findings []finding.Finding
	err      error
	panics   bool
}

func (s *stubScanner) Name() string { return s.name }
func (s *stubScanner) Run(_ context.Context, _ string, _ module.ScanType) ([]finding.Finding, error) {
	if s.panics {
		panic("test panic")
	}
	return s.findings, s.err
}

func TestExecuteSuccess(t *testing.T) {
	s := &stubScanner{
		name:     "test",
		findings: []finding.Finding{{CheckID: "test.finding"}},
	}
	r := Execute(s, context.Background(), "example.com", module.ScanSurface)
	if !r.OK() {
		t.Fatalf("expected OK, got error: %v", r.Error)
	}
	if len(r.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(r.Findings))
	}
	if r.Metrics.ScannerName != "test" {
		t.Errorf("ScannerName = %q, want %q", r.Metrics.ScannerName, "test")
	}
	if r.Metrics.Duration < 0 {
		t.Error("Duration should be non-negative")
	}
}

func TestExecuteError(t *testing.T) {
	s := &stubScanner{
		name: "errscanner",
		err:  errors.New("scan failed"),
	}
	r := Execute(s, context.Background(), "example.com", module.ScanDeep)
	if r.OK() {
		t.Fatal("expected error")
	}
	if r.Panicked {
		t.Error("should not be marked as panicked")
	}
}

func TestExecutePanicRecovery(t *testing.T) {
	s := &stubScanner{
		name:   "panicscanner",
		panics: true,
	}
	r := Execute(s, context.Background(), "example.com", module.ScanSurface)
	if r.OK() {
		t.Fatal("expected error from panic")
	}
	if !r.Panicked {
		t.Error("should be marked as panicked")
	}
	if !strings.Contains(r.Error.Error(), "panicked") {
		t.Errorf("error should mention panic: %v", r.Error)
	}
}

func TestScannerTimeout_InjectionScanners(t *testing.T) {
	for _, name := range []string{"cmdinj", "sqli", "ssti", "crlf", "openredir", "hpp", "xxe", "rxss", "ssrf"} {
		got := ScannerTimeout(name)
		if got != 5*time.Minute {
			t.Errorf("ScannerTimeout(%q) = %v, want 5m", name, got)
		}
	}
}

func TestScannerTimeout_SpecialScanners(t *testing.T) {
	if got := ScannerTimeout("portscan"); got != 3*time.Minute {
		t.Errorf("ScannerTimeout(portscan) = %v, want 3m", got)
	}
	if got := ScannerTimeout("nuclei"); got != 10*time.Minute {
		t.Errorf("ScannerTimeout(nuclei) = %v, want 10m", got)
	}
}

func TestScannerTimeout_DefaultScanners(t *testing.T) {
	for _, name := range []string{"cors", "jwt", "secheaders", "tls", "dns"} {
		got := ScannerTimeout(name)
		if got != 2*time.Minute {
			t.Errorf("ScannerTimeout(%q) = %v, want 2m", name, got)
		}
	}
}

func TestIsInjectionScanner(t *testing.T) {
	if !IsInjectionScanner("cmdinj") {
		t.Error("cmdinj should be an injection scanner")
	}
	if IsInjectionScanner("cors") {
		t.Error("cors should not be an injection scanner")
	}
}
