package evasion

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	_ = resp.Body.Close()
	if !hit.Load() {
		t.Error("request did not reach test server")
	}
}

// ── Transport caching ───────────────────────────────────────────────────────

// TestTransportCaching_SameProxyReturnsSameTransport verifies that multiple
// requests through the same proxy URL reuse a cached *http.Transport rather
// than allocating a new one each time.
func TestTransportCaching_SameProxyReturnsSameTransport(t *testing.T) {
	s := &Strategy{ProxyPool: []string{"http://proxy.local:8080"}}
	base := &http.Client{}
	client := s.HTTPClient(base)

	et, ok := client.Transport.(*evasionTransport)
	if !ok {
		t.Fatal("expected *evasionTransport")
	}

	// Simulate two lookups for the same proxy URL.
	parsed, _ := parseProxyURL("http://proxy.local:8080")
	tr1 := et.getOrCreateTransport("http://proxy.local:8080", parsed)
	tr2 := et.getOrCreateTransport("http://proxy.local:8080", parsed)

	if tr1 != tr2 {
		t.Error("expected the same *http.Transport for repeated calls with the same proxy URL")
	}
}

// TestTransportCaching_DifferentProxiesGetDifferentTransports verifies that
// distinct proxy URLs produce distinct cached transports.
func TestTransportCaching_DifferentProxiesGetDifferentTransports(t *testing.T) {
	s := &Strategy{ProxyPool: []string{"http://a:8080", "http://b:8080"}}
	base := &http.Client{}
	client := s.HTTPClient(base)

	et := client.Transport.(*evasionTransport)

	parsedA, _ := parseProxyURL("http://a:8080")
	parsedB, _ := parseProxyURL("http://b:8080")
	trA := et.getOrCreateTransport("http://a:8080", parsedA)
	trB := et.getOrCreateTransport("http://b:8080", parsedB)

	if trA == trB {
		t.Error("expected different transports for different proxy URLs")
	}
}

// ── Proxy rotation through the transport ────────────────────────────────────

// TestProxyRotation_DifferentRequestsCanGetDifferentProxies verifies that
// the round-robin proxy selection distributes requests across the pool.
func TestProxyRotation_DifferentRequestsCanGetDifferentProxies(t *testing.T) {
	s := &Strategy{ProxyPool: []string{"http://proxy-a:1080", "http://proxy-b:1080"}}

	// Reset counter for a clean test.
	s.counter.Store(0)

	first := s.nextProxy()
	second := s.nextProxy()

	if first == second {
		t.Errorf("expected different proxies for consecutive requests, both got %q", first)
	}
	if first != "http://proxy-a:1080" {
		t.Errorf("first proxy = %q, want http://proxy-a:1080", first)
	}
	if second != "http://proxy-b:1080" {
		t.Errorf("second proxy = %q, want http://proxy-b:1080", second)
	}
}

// ── Rate limiting (jitter delay) ────────────────────────────────────────────

// TestRateLimiting_JitterAppliesDelay verifies that a non-zero MaxJitterMs
// actually introduces a measurable delay on requests sent through the transport.
func TestRateLimiting_JitterAppliesDelay(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// Use a large enough jitter that we can detect a delay. With MaxJitterMs=100
	// the expected average delay is ~50ms, so at least some requests should take
	// measurably longer than zero.
	s := &Strategy{MaxJitterMs: 100}
	client := s.HTTPClient(&http.Client{})

	// Run several requests and check that the total time is non-trivial.
	const requests = 5
	start := time.Now()
	for range requests {
		resp, err := client.Get(ts.URL)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		_ = resp.Body.Close()
	}
	elapsed := time.Since(start)

	// With 5 requests at avg 50ms jitter each, we expect ~250ms total.
	// Use a generous lower bound: at least 50ms total (one non-zero jitter).
	if elapsed < 50*time.Millisecond {
		t.Errorf("expected measurable delay from jitter, but %d requests took only %v", requests, elapsed)
	}
}

// ── Fallback on invalid proxy URL ───────────────────────────────────────────

// TestFallback_InvalidProxyURL_RequestSucceeds verifies that when the proxy
// pool contains an unparseable URL, the transport falls back to a direct
// connection and the request succeeds.
func TestFallback_InvalidProxyURL_RequestSucceeds(t *testing.T) {
	var hit atomic.Bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// "://invalid" is not a valid URL — url.Parse will fail on it.
	s := &Strategy{ProxyPool: []string{"://invalid"}}
	client := s.HTTPClient(&http.Client{})

	resp, err := client.Get(ts.URL)
	if err != nil {
		t.Fatalf("expected fallback to direct connection, got error: %v", err)
	}
	_ = resp.Body.Close()
	if !hit.Load() {
		t.Error("request did not reach test server via fallback")
	}
}

// parseProxyURL is a test helper that mirrors the parsing in RoundTrip.
func parseProxyURL(raw string) (*url.URL, error) {
	return url.Parse(raw)
}
