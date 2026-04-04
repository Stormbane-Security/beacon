package scan

import (
	"context"
	"errors"
	"strings"
	"testing"

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
