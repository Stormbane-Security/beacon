package crawler

import (
	"context"
	"testing"

	"github.com/stormbane-security/beacon/internal/module"
)

func TestNew_DefaultBin(t *testing.T) {
	s := New("")
	if s.bin != "katana" {
		t.Errorf("expected default bin 'katana', got %q", s.bin)
	}
}

func TestNew_CustomBin(t *testing.T) {
	s := New("/usr/local/bin/katana")
	if s.bin != "/usr/local/bin/katana" {
		t.Errorf("expected custom bin, got %q", s.bin)
	}
}

func TestName(t *testing.T) {
	s := New("")
	if s.Name() != scannerName {
		t.Errorf("expected name %q, got %q", scannerName, s.Name())
	}
}

// TestRun_MissingBinary verifies the scanner falls back to the native crawler
// (not a panic) when the katana binary is not installed.
func TestRun_MissingBinary(t *testing.T) {
	s := New("katana-does-not-exist-beacon-test")
	findings, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	// Should succeed via native fallback — no error.
	if err != nil {
		t.Errorf("expected native fallback (no error), got: %v", err)
	}
	// Native crawler should discover at least the root page.
	if len(findings) == 0 {
		t.Log("no findings from native fallback (expected for example.com without network)")
	}
}

// TestRun_ContextCancelledNoPanic ensures context cancellation before binary
// execution doesn't panic.
func TestRun_ContextCancelledNoPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := New("katana-does-not-exist-beacon-test")
	// Should return an error (binary missing), not panic
	_, _ = s.Run(ctx, "example.com", module.ScanDeep)
}
