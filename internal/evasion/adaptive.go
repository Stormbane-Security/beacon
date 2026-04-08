package evasion

import (
	"context"
	"sync"
	"time"
)

// AdaptiveRate automatically adjusts request pacing based on observed response
// patterns. When targets show signs of stress (slow responses, rate-limit
// errors) the delay increases; when responses normalize the delay decreases.
type AdaptiveRate struct {
	mu sync.Mutex

	baseDelay    time.Duration
	currentDelay time.Duration
	maxDelay     time.Duration

	// Tracking consecutive anomalies.
	errorCount   int
	slowCount    int
	successCount int

	// baselineLatency is the p50 latency from the first few requests, used to
	// detect slow responses (>2× baseline).
	baselineLatency time.Duration
	latencySamples  []time.Duration
	baselineReady   bool

	// consecutiveSlowThreshold is the number of consecutive slow responses
	// before the delay doubles.
	consecutiveSlowThreshold int

	// successRecoveryThreshold is the number of consecutive successes before
	// the delay halves.
	successRecoveryThreshold int
}

// NewAdaptiveRate creates an AdaptiveRate with the given base delay and maximum
// delay ceiling. The base delay is the initial and minimum per-request delay.
func NewAdaptiveRate(baseDelay, maxDelay time.Duration) *AdaptiveRate {
	return &AdaptiveRate{
		baseDelay:                baseDelay,
		currentDelay:             baseDelay,
		maxDelay:                 maxDelay,
		consecutiveSlowThreshold: 3,
		successRecoveryThreshold: 10,
	}
}

// RecordResponse records an observed response latency and status code, adjusting
// the internal delay accordingly.
//
// Rules:
//   - 429 or 503 status: triple the delay and add a 10 s penalty.
//   - 3+ consecutive slow responses (>2× baseline latency): double the delay.
//   - 10 consecutive normal successes: halve the delay (min = baseDelay).
func (a *AdaptiveRate) RecordResponse(latency time.Duration, statusCode int) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Bootstrap baseline from first 5 samples.
	if !a.baselineReady {
		a.latencySamples = append(a.latencySamples, latency)
		if len(a.latencySamples) >= 5 {
			a.baselineLatency = median(a.latencySamples)
			a.baselineReady = true
		}
	}

	// Handle rate-limit / service-unavailable codes.
	if statusCode == 429 || statusCode == 503 {
		a.errorCount++
		a.slowCount = 0
		a.successCount = 0
		newDelay := a.currentDelay*3 + 10*time.Second
		a.setDelay(newDelay)
		return
	}

	// Check for slow response (>2× baseline).
	if a.baselineReady && latency > 2*a.baselineLatency {
		a.slowCount++
		a.successCount = 0
		if a.slowCount >= a.consecutiveSlowThreshold {
			a.setDelay(a.currentDelay * 2)
			a.slowCount = 0
		}
		return
	}

	// Normal successful response.
	a.errorCount = 0
	a.slowCount = 0
	a.successCount++
	if a.successCount >= a.successRecoveryThreshold {
		a.successCount = 0
		newDelay := a.currentDelay / 2
		if newDelay < a.baseDelay {
			newDelay = a.baseDelay
		}
		a.setDelay(newDelay)
	}
}

// Wait sleeps for the current adaptive delay, respecting ctx cancellation.
func (a *AdaptiveRate) Wait(ctx context.Context) {
	a.mu.Lock()
	d := a.currentDelay
	a.mu.Unlock()

	if d <= 0 {
		return
	}
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

// CurrentRate returns the current effective requests-per-second rate. Returns 0
// if the delay is zero (unlimited).
func (a *AdaptiveRate) CurrentRate() float64 {
	a.mu.Lock()
	d := a.currentDelay
	a.mu.Unlock()

	if d <= 0 {
		return 0
	}
	return 1.0 / d.Seconds()
}

// CurrentDelay returns the current delay between requests.
func (a *AdaptiveRate) CurrentDelay() time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.currentDelay
}

// setDelay clamps the delay to [baseDelay, maxDelay] and stores it.
// Caller must hold a.mu.
func (a *AdaptiveRate) setDelay(d time.Duration) {
	if d < a.baseDelay {
		d = a.baseDelay
	}
	if d > a.maxDelay {
		d = a.maxDelay
	}
	a.currentDelay = d
}

// median returns the median of a time.Duration slice. The slice is not sorted
// in place; a copy is made.
func median(samples []time.Duration) time.Duration {
	n := len(samples)
	if n == 0 {
		return 0
	}
	sorted := make([]time.Duration, n)
	copy(sorted, samples)
	// Simple insertion sort — only called once with ≤5 elements.
	for i := 1; i < n; i++ {
		key := sorted[i]
		j := i - 1
		for j >= 0 && sorted[j] > key {
			sorted[j+1] = sorted[j]
			j--
		}
		sorted[j+1] = key
	}
	if n%2 == 1 {
		return sorted[n/2]
	}
	return (sorted[n/2-1] + sorted[n/2]) / 2
}
