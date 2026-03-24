// Package evasion provides transport-layer request evasion for Beacon scanners.
//
// It wraps a base *http.Client with two independent mechanisms:
//   - Proxy rotation: round-robins requests across a pool of SOCKS5/HTTP proxies
//   - Request jitter: injects a random [0, MaxJitterMs] ms delay before each request
//
// Neither mechanism changes scanner logic — they are applied at the HTTP transport
// layer so individual scanners require no modification.
package evasion

import (
	"context"
	"math/rand/v2"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"
)

// Strategy holds evasion configuration.
type Strategy struct {
	// ProxyPool is an ordered list of proxy URLs (socks5:// or http://).
	// Requests are distributed round-robin. Empty means no proxy.
	ProxyPool []string

	// MaxJitterMs is the upper bound (inclusive) for random per-request delay in ms.
	// 0 disables jitter.
	MaxJitterMs int

	counter atomic.Uint64
}

// HTTPClient returns a new *http.Client derived from base that applies the
// evasion strategy. base is not modified. If neither ProxyPool nor MaxJitterMs
// is configured, base is returned unchanged.
func (s *Strategy) HTTPClient(base *http.Client) *http.Client {
	if len(s.ProxyPool) == 0 && s.MaxJitterMs == 0 {
		return base
	}

	// Copy the base client so we can swap the transport without mutating it.
	clone := *base
	var baseTransport http.RoundTripper = base.Transport
	if baseTransport == nil {
		baseTransport = http.DefaultTransport
	}

	clone.Transport = &evasionTransport{
		base:     baseTransport,
		strategy: s,
	}
	return &clone
}

// Jitter sleeps a random duration in [0, MaxJitterMs] ms, respecting ctx cancellation.
// If MaxJitterMs is 0 it returns immediately.
func (s *Strategy) Jitter(ctx context.Context) {
	if s.MaxJitterMs <= 0 {
		return
	}
	delay := time.Duration(rand.IntN(s.MaxJitterMs+1)) * time.Millisecond
	select {
	case <-ctx.Done():
	case <-time.After(delay):
	}
}

// nextProxy returns the next proxy URL in round-robin order, or "" if the pool
// is empty.
func (s *Strategy) nextProxy() string {
	if len(s.ProxyPool) == 0 {
		return ""
	}
	idx := s.counter.Add(1) - 1
	return s.ProxyPool[int(idx)%len(s.ProxyPool)]
}

// evasionTransport is an http.RoundTripper that applies jitter and proxy rotation.
type evasionTransport struct {
	base     http.RoundTripper
	strategy *Strategy
}

func (t *evasionTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Apply jitter before sending.
	t.strategy.Jitter(req.Context())

	// If a proxy is configured, swap in a transport that routes through it.
	proxyURL := t.strategy.nextProxy()
	if proxyURL == "" {
		return t.base.RoundTrip(req)
	}

	parsed, err := url.Parse(proxyURL)
	if err != nil {
		// Misconfigured proxy — fall back to direct.
		return t.base.RoundTrip(req)
	}

	// Build a one-shot transport with the chosen proxy. We clone the default
	// transport rather than the base to avoid mutating shared state.
	proxied := &http.Transport{
		Proxy: http.ProxyURL(parsed),
	}
	if dt, ok := t.base.(*http.Transport); ok {
		proxied = dt.Clone()
		proxied.Proxy = http.ProxyURL(parsed)
	}
	return proxied.RoundTrip(req)
}
