package scan

import (
	"errors"
	"net"
	"testing"
)

func TestHostTimeoutTracker_BasicFlow(t *testing.T) {
	tr := NewHostTimeoutTracker()

	// Initially no host should be skipped.
	if tr.ShouldSkip("example.com") {
		t.Fatal("fresh tracker should not skip any host")
	}

	// Record timeouts below threshold — should not bail.
	for i := 0; i < HostTimeoutThreshold-1; i++ {
		if tr.RecordTimeout("example.com") {
			t.Fatalf("RecordTimeout returned true after %d timeouts, threshold is %d", i+1, HostTimeoutThreshold)
		}
	}
	if tr.ShouldSkip("example.com") {
		t.Fatal("host should not be skipped before reaching threshold")
	}

	// One more timeout should trigger bail.
	if !tr.RecordTimeout("example.com") {
		t.Fatal("RecordTimeout should return true at threshold")
	}
	if !tr.ShouldSkip("example.com") {
		t.Fatal("host should be skipped after reaching threshold")
	}
}

func TestHostTimeoutTracker_SuccessResets(t *testing.T) {
	tr := NewHostTimeoutTracker()

	// Accumulate timeouts just below threshold.
	for i := 0; i < HostTimeoutThreshold-1; i++ {
		tr.RecordTimeout("example.com")
	}

	// A success should reset the counter.
	tr.RecordSuccess("example.com")

	// Now we should need a full threshold again.
	for i := 0; i < HostTimeoutThreshold-1; i++ {
		if tr.RecordTimeout("example.com") {
			t.Fatalf("bailed too early after reset: timeout %d", i+1)
		}
	}
	if tr.ShouldSkip("example.com") {
		t.Fatal("should not skip — counter was reset by success")
	}
}

func TestHostTimeoutTracker_IndependentHosts(t *testing.T) {
	tr := NewHostTimeoutTracker()

	// Bail host A.
	for i := 0; i < HostTimeoutThreshold; i++ {
		tr.RecordTimeout("a.example.com")
	}

	// Host B should be unaffected.
	if tr.ShouldSkip("b.example.com") {
		t.Fatal("host B should not be affected by host A timeouts")
	}
}

func TestHostTimeoutTracker_PortNormalization(t *testing.T) {
	tr := NewHostTimeoutTracker()

	// Timeouts on host:443 and host:8080 should count toward the same host.
	for i := 0; i < HostTimeoutThreshold-1; i++ {
		tr.RecordTimeout("example.com:443")
	}
	tr.RecordTimeout("example.com:8080")

	if !tr.ShouldSkip("example.com") {
		t.Fatal("port-normalized host should be bailed")
	}
	if !tr.ShouldSkip("example.com:443") {
		t.Fatal("host:443 should be bailed via normalized lookup")
	}
}

func TestHostTimeoutTracker_BailedHosts(t *testing.T) {
	tr := NewHostTimeoutTracker()

	for i := 0; i < HostTimeoutThreshold; i++ {
		tr.RecordTimeout("bailed.example.com")
	}
	tr.RecordTimeout("ok.example.com") // only 1, not bailed

	bailed := tr.BailedHosts()
	if len(bailed) != 1 || bailed[0] != "bailed.example.com" {
		t.Fatalf("BailedHosts = %v, want [bailed.example.com]", bailed)
	}
}

// mockTimeoutError implements net.Error with Timeout() == true.
type mockTimeoutError struct{}

func (mockTimeoutError) Error() string   { return "i/o timeout" }
func (mockTimeoutError) Timeout() bool   { return true }
func (mockTimeoutError) Temporary() bool { return true }

func TestIsTimeoutError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"generic error", errors.New("something failed"), false},
		{"net timeout", mockTimeoutError{}, true},
		{"wrapped net timeout", &net.OpError{Err: mockTimeoutError{}}, true},
		{"deadline exceeded string", errors.New("context deadline exceeded"), true},
		{"i/o timeout string", errors.New("read tcp: i/o timeout"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsTimeoutError(tt.err); got != tt.want {
				t.Errorf("IsTimeoutError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
