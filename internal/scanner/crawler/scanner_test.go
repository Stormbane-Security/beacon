package crawler

import (
	"context"
	"testing"

	"github.com/stormbane/beacon/internal/module"
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

// TestRun_MissingBinary verifies the scanner returns a wrapped error (not a panic)
// when the katana binary is not installed. Uses a deliberately invalid binary name.
func TestRun_MissingBinary(t *testing.T) {
	s := New("katana-does-not-exist-beacon-test")
	_, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err == nil {
		t.Error("expected error when binary is not installed, got nil")
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
