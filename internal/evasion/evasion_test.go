package evasion

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestHTTPClient_NoConfig_ReturnsSameClient verifies that when neither ProxyPool
// nor MaxJitterMs is set, HTTPClient returns the base client unchanged.
func TestHTTPClient_NoConfig_ReturnsSameClient(t *testing.T) {
	s := &Strategy{}
	base := &http.Client{}
	got := s.HTTPClient(base)
	if got != base {
		t.Error("expected same client when no evasion configured")
	}
}

// TestHTTPClient_WithJitter_ReturnsDifferentClient verifies that when MaxJitterMs
// is set, a new client is returned with a wrapped transport.
func TestHTTPClient_WithJitter_ReturnsDifferentClient(t *testing.T) {
	s := &Strategy{MaxJitterMs: 5}
	base := &http.Client{}
	got := s.HTTPClient(base)
	if got == base {
		t.Error("expected new client when jitter is configured")
	}
	if got.Transport == nil {
		t.Error("expected non-nil Transport on evasion client")
	}
}

// TestJitter_ZeroMs_ReturnsImmediately verifies that zero jitter does not block.
func TestJitter_ZeroMs_ReturnsImmediately(t *testing.T) {
	s := &Strategy{MaxJitterMs: 0}
	start := time.Now()
	s.Jitter(context.Background())
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Errorf("Jitter with MaxJitterMs=0 took too long: %v", elapsed)
	}
}

// TestJitter_WithBound_StaysWithinBound verifies jitter stays within MaxJitterMs.
func TestJitter_WithBound_StaysWithinBound(t *testing.T) {
	s := &Strategy{MaxJitterMs: 20}
	start := time.Now()
	s.Jitter(context.Background())
	elapsed := time.Since(start)
	if elapsed > 100*time.Millisecond {
		t.Errorf("Jitter exceeded bound (max=20ms), elapsed=%v", elapsed)
	}
}

// TestJitter_ContextCancelled_ReturnsEarly verifies that a cancelled context
// causes Jitter to return before the delay expires.
func TestJitter_ContextCancelled_ReturnsEarly(t *testing.T) {
	s := &Strategy{MaxJitterMs: 10000} // 10 seconds — would block if ctx not respected
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	s.Jitter(ctx)
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Errorf("Jitter did not respect cancelled context, elapsed=%v", elapsed)
	}
}

// TestNextProxy_RoundRobin verifies that proxies are distributed in order.
func TestNextProxy_RoundRobin(t *testing.T) {
	s := &Strategy{ProxyPool: []string{"http://a:1080", "http://b:1080", "http://c:1080"}}
	got := []string{s.nextProxy(), s.nextProxy(), s.nextProxy(), s.nextProxy()}
	want := []string{"http://a:1080", "http://b:1080", "http://c:1080", "http://a:1080"}
	for i, g := range got {
		if g != want[i] {
			t.Errorf("proxy[%d] = %q, want %q", i, g, want[i])
		}
	}
}

// TestNextProxy_EmptyPool_ReturnsEmpty verifies that an empty pool returns "".
func TestNextProxy_EmptyPool_ReturnsEmpty(t *testing.T) {
	s := &Strategy{}
	if p := s.nextProxy(); p != "" {
		t.Errorf("expected empty string, got %q", p)
	}
}

// TestHTTPClient_RequestReachesServer verifies that the evasion client can
// successfully reach a local test server (no proxy, with jitter).
func TestHTTPClient_RequestReachesServer(t *testing.T) {
	var hit atomic.Bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	s := &Strategy{MaxJitterMs: 2}
	client := s.HTTPClient(&http.Client{})
	resp, err := client.Get(ts.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()
	if !hit.Load() {
		t.Error("request did not reach test server")
	}
}
