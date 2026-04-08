package evasion

import (
	"context"
	"testing"
	"time"
)

func TestNewAdaptiveRate_Defaults(t *testing.T) {
	ar := NewAdaptiveRate(100*time.Millisecond, 30*time.Second)
	if ar.currentDelay != 100*time.Millisecond {
		t.Errorf("initial delay = %v, want 100ms", ar.currentDelay)
	}
	if ar.maxDelay != 30*time.Second {
		t.Errorf("max delay = %v, want 30s", ar.maxDelay)
	}
}

func TestCurrentRate_ReturnsCorrectRPS(t *testing.T) {
	ar := NewAdaptiveRate(100*time.Millisecond, 30*time.Second)
	rate := ar.CurrentRate()
	// 100ms delay → 10 rps
	if rate < 9.9 || rate > 10.1 {
		t.Errorf("CurrentRate() = %f, want ~10.0", rate)
	}
}

func TestCurrentRate_ZeroDelay(t *testing.T) {
	ar := NewAdaptiveRate(0, 30*time.Second)
	rate := ar.CurrentRate()
	if rate != 0 {
		t.Errorf("CurrentRate() with zero delay = %f, want 0", rate)
	}
}

// bootstrapBaseline sends 5 normal responses to establish the latency baseline.
func bootstrapBaseline(ar *AdaptiveRate, latency time.Duration) {
	for i := 0; i < 5; i++ {
		ar.RecordResponse(latency, 200)
	}
}

func TestRecordResponse_429_TriplesDelayPlus10s(t *testing.T) {
	ar := NewAdaptiveRate(100*time.Millisecond, 60*time.Second)
	bootstrapBaseline(ar, 50*time.Millisecond)

	ar.RecordResponse(50*time.Millisecond, 429)
	got := ar.CurrentDelay()
	// 100ms * 3 + 10s = 10.3s
	want := 100*time.Millisecond*3 + 10*time.Second
	if got != want {
		t.Errorf("after 429: delay = %v, want %v", got, want)
	}
}

func TestRecordResponse_503_TriplesDelayPlus10s(t *testing.T) {
	ar := NewAdaptiveRate(200*time.Millisecond, 60*time.Second)
	bootstrapBaseline(ar, 50*time.Millisecond)

	ar.RecordResponse(50*time.Millisecond, 503)
	got := ar.CurrentDelay()
	want := 200*time.Millisecond*3 + 10*time.Second
	if got != want {
		t.Errorf("after 503: delay = %v, want %v", got, want)
	}
}

func TestRecordResponse_SlowResponses_DoublesDelay(t *testing.T) {
	ar := NewAdaptiveRate(100*time.Millisecond, 60*time.Second)
	// Establish 50ms baseline.
	bootstrapBaseline(ar, 50*time.Millisecond)

	// 3 consecutive slow responses (>2× 50ms = >100ms).
	ar.RecordResponse(150*time.Millisecond, 200)
	ar.RecordResponse(150*time.Millisecond, 200)
	ar.RecordResponse(150*time.Millisecond, 200)

	got := ar.CurrentDelay()
	want := 200 * time.Millisecond // 100ms * 2
	if got != want {
		t.Errorf("after 3 slow responses: delay = %v, want %v", got, want)
	}
}

func TestRecordResponse_NormalAfterSlow_ResetsSlowCount(t *testing.T) {
	ar := NewAdaptiveRate(100*time.Millisecond, 60*time.Second)
	bootstrapBaseline(ar, 50*time.Millisecond)

	// 2 slow, then 1 normal — should NOT double.
	ar.RecordResponse(150*time.Millisecond, 200)
	ar.RecordResponse(150*time.Millisecond, 200)
	ar.RecordResponse(30*time.Millisecond, 200) // normal

	got := ar.CurrentDelay()
	if got != 100*time.Millisecond {
		t.Errorf("after 2 slow + 1 normal: delay = %v, want 100ms (unchanged)", got)
	}
}

func TestRecordResponse_Recovery_HalvesDelay(t *testing.T) {
	ar := NewAdaptiveRate(100*time.Millisecond, 60*time.Second)
	bootstrapBaseline(ar, 50*time.Millisecond)

	// Trigger a rate-limit bump.
	ar.RecordResponse(50*time.Millisecond, 429)
	bumped := ar.CurrentDelay()

	// 10 consecutive successful normal responses → halve.
	for i := 0; i < 10; i++ {
		ar.RecordResponse(30*time.Millisecond, 200)
	}
	got := ar.CurrentDelay()
	want := bumped / 2
	if got != want {
		t.Errorf("after recovery: delay = %v, want %v", got, want)
	}
}

func TestRecordResponse_Recovery_ClampsToBaseDelay(t *testing.T) {
	ar := NewAdaptiveRate(100*time.Millisecond, 60*time.Second)
	bootstrapBaseline(ar, 50*time.Millisecond)

	// Already at base delay; 10 successes should not go below.
	for i := 0; i < 10; i++ {
		ar.RecordResponse(30*time.Millisecond, 200)
	}
	got := ar.CurrentDelay()
	if got != 100*time.Millisecond {
		t.Errorf("delay should not drop below base: got %v, want 100ms", got)
	}
}

func TestRecordResponse_MaxDelayCeiling(t *testing.T) {
	ar := NewAdaptiveRate(100*time.Millisecond, 15*time.Second)
	bootstrapBaseline(ar, 50*time.Millisecond)

	// Multiple 429 responses to push delay past max.
	for i := 0; i < 5; i++ {
		ar.RecordResponse(50*time.Millisecond, 429)
	}
	got := ar.CurrentDelay()
	if got != 15*time.Second {
		t.Errorf("delay should be clamped to max: got %v, want 15s", got)
	}
}

func TestWait_RespectsContextCancellation(t *testing.T) {
	ar := NewAdaptiveRate(10*time.Second, 60*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	ar.Wait(ctx)
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Errorf("Wait did not respect cancelled context, elapsed=%v", elapsed)
	}
}

func TestWait_ZeroDelay_ReturnsImmediately(t *testing.T) {
	ar := NewAdaptiveRate(0, 30*time.Second)
	start := time.Now()
	ar.Wait(context.Background())
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Errorf("Wait with zero delay took %v", elapsed)
	}
}

func TestMedian(t *testing.T) {
	tests := []struct {
		name    string
		samples []time.Duration
		want    time.Duration
	}{
		{"empty", nil, 0},
		{"single", []time.Duration{5 * time.Millisecond}, 5 * time.Millisecond},
		{"odd", []time.Duration{3, 1, 2}, 2},
		{"even", []time.Duration{4, 1, 3, 2}, (2 + 3) / 2},
		{"five", []time.Duration{50, 10, 30, 20, 40}, 30},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := median(tt.samples)
			if got != tt.want {
				t.Errorf("median(%v) = %v, want %v", tt.samples, got, tt.want)
			}
		})
	}
}

func TestBaselineEstablished_After5Samples(t *testing.T) {
	ar := NewAdaptiveRate(100*time.Millisecond, 60*time.Second)

	// First 4 samples: baseline not ready.
	for i := 0; i < 4; i++ {
		ar.RecordResponse(50*time.Millisecond, 200)
	}
	ar.mu.Lock()
	ready := ar.baselineReady
	ar.mu.Unlock()
	if ready {
		t.Error("baseline should not be ready after only 4 samples")
	}

	// 5th sample triggers baseline.
	ar.RecordResponse(50*time.Millisecond, 200)
	ar.mu.Lock()
	ready = ar.baselineReady
	bl := ar.baselineLatency
	ar.mu.Unlock()
	if !ready {
		t.Error("baseline should be ready after 5 samples")
	}
	if bl != 50*time.Millisecond {
		t.Errorf("baseline latency = %v, want 50ms", bl)
	}
}
