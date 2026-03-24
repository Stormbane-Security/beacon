package smuggling

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/stormbane/beacon/internal/module"
)

// ---------------------------------------------------------------------------
// isTimeoutError
// ---------------------------------------------------------------------------

func TestIsTimeoutError_Nil(t *testing.T) {
	if isTimeoutError(nil) {
		t.Error("isTimeoutError(nil) should return false")
	}
}

func TestIsTimeoutError_NonNetworkError(t *testing.T) {
	if isTimeoutError(errors.New("some generic error")) {
		t.Error("isTimeoutError should return false for a non-net.Error")
	}
}

func TestIsTimeoutError_NonTimeoutNetError(t *testing.T) {
	// net.OpError wrapping a non-timeout error.
	err := &net.OpError{Op: "read", Err: errors.New("connection refused")}
	if isTimeoutError(err) {
		t.Error("isTimeoutError should return false for a non-timeout net.Error")
	}
}

// mockTimeoutErr implements net.Error with Timeout() == true.
type mockTimeoutErr struct{}

func (mockTimeoutErr) Error() string   { return "i/o timeout" }
func (mockTimeoutErr) Timeout() bool   { return true }
func (mockTimeoutErr) Temporary() bool { return true }

func TestIsTimeoutError_TimeoutNetError(t *testing.T) {
	if !isTimeoutError(mockTimeoutErr{}) {
		t.Error("isTimeoutError should return true for a net.Error with Timeout()==true")
	}
}

// ---------------------------------------------------------------------------
// stripScheme
// ---------------------------------------------------------------------------

func TestStripScheme_WithHTTPS(t *testing.T) {
	got := stripScheme("https://example.com")
	if got != "example.com" {
		t.Errorf("stripScheme(\"https://example.com\") = %q, want \"example.com\"", got)
	}
}

func TestStripScheme_WithHTTP(t *testing.T) {
	got := stripScheme("http://example.com/path")
	if got != "example.com/path" {
		t.Errorf("stripScheme(\"http://example.com/path\") = %q, want \"example.com/path\"", got)
	}
}

func TestStripScheme_NoScheme(t *testing.T) {
	got := stripScheme("example.com")
	if got != "example.com" {
		t.Errorf("stripScheme(\"example.com\") = %q, want \"example.com\"", got)
	}
}

// ---------------------------------------------------------------------------
// Surface mode — scanner must be a no-op
// ---------------------------------------------------------------------------

func TestRun_SurfaceMode_ReturnsNil(t *testing.T) {
	s := New()
	findings, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error in surface mode: %v", err)
	}
	if findings != nil {
		t.Errorf("expected nil findings in surface mode, got %v", findings)
	}
}

// ---------------------------------------------------------------------------
// Name
// ---------------------------------------------------------------------------

func TestName(t *testing.T) {
	s := New()
	if s.Name() != "smuggling" {
		t.Errorf("expected scanner name 'smuggling', got %q", s.Name())
	}
}

// ---------------------------------------------------------------------------
// Unreachable target — deep mode, no panic
// ---------------------------------------------------------------------------

func TestRun_DeepMode_UnreachableTarget_NoFindingsNoPanic(t *testing.T) {
	s := New()
	// Port 1 is reserved — connection refused immediately, no timeout needed.
	findings, err := s.Run(context.Background(), "127.0.0.1:1", module.ScanDeep)
	_ = err
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for unreachable target, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Context cancellation — must not panic
// ---------------------------------------------------------------------------

func TestRun_CancelledContext_NoPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	s := New()
	findings, _ := s.Run(ctx, "example.com", module.ScanDeep)
	_ = findings
}

// ---------------------------------------------------------------------------
// Constants sanity checks
// ---------------------------------------------------------------------------

func TestConstants(t *testing.T) {
	if probeTimeout <= baselineMax {
		t.Errorf("probeTimeout (%v) must exceed baselineMax (%v)", probeTimeout, baselineMax)
	}
	if smuggleDelay >= probeTimeout {
		t.Errorf("smuggleDelay (%v) must be less than probeTimeout (%v)", smuggleDelay, probeTimeout)
	}
	if baselineMax <= 0 {
		t.Errorf("baselineMax must be positive, got %v", baselineMax)
	}
}
