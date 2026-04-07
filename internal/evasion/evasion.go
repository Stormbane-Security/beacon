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
	"log"
	"math/rand/v2"
	"net/http"
	"net/url"
	"sync"
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

	// BaseDelayMs is a fixed delay added before each request, in milliseconds.
	// Used by the detection monitor to slow down scanning when rate limiting is detected.
	// 0 means no base delay.
	BaseDelayMs int

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
	baseTransport := base.Transport
	if baseTransport == nil {
		baseTransport = http.DefaultTransport
	}

	clone.Transport = &evasionTransport{
		base:     baseTransport,
		strategy: s,
	}
	return &clone
}

// Jitter sleeps a random duration in [BaseDelayMs, BaseDelayMs+MaxJitterMs] ms,
// respecting ctx cancellation. If both BaseDelayMs and MaxJitterMs are 0 it
// returns immediately.
func (s *Strategy) Jitter(ctx context.Context) {
	base := time.Duration(s.BaseDelayMs) * time.Millisecond
	var jitter time.Duration
	if s.MaxJitterMs > 0 {
		jitter = time.Duration(rand.IntN(s.MaxJitterMs+1)) * time.Millisecond
	}
	delay := base + jitter
	if delay <= 0 {
		return
	}
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

	// mu guards the transports cache.
	mu         sync.Mutex
	transports map[string]*http.Transport // proxy URL → cached transport
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
		// Misconfigured proxy — log a warning and fall back to direct.
		log.Printf("evasion: invalid proxy URL %q, falling back to direct connection: %v", proxyURL, err)
		return t.base.RoundTrip(req)
	}

	// Look up or create a cached transport for this proxy URL.
	transport := t.getOrCreateTransport(proxyURL, parsed)
	return transport.RoundTrip(req)
}

// getOrCreateTransport returns a cached *http.Transport for the given proxy URL,
// creating one if it doesn't already exist.
func (t *evasionTransport) getOrCreateTransport(proxyURL string, parsed *url.URL) *http.Transport {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.transports == nil {
		t.transports = make(map[string]*http.Transport)
	}
	if tr, ok := t.transports[proxyURL]; ok {
		return tr
	}

	proxied := &http.Transport{
		Proxy: http.ProxyURL(parsed),
	}
	if dt, ok := t.base.(*http.Transport); ok {
		proxied = dt.Clone()
		proxied.Proxy = http.ProxyURL(parsed)
	}
	t.transports[proxyURL] = proxied
	return proxied
}
