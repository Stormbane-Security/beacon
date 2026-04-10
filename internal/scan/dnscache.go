// Package scan — DNS resolution cache shared across all scanners.
package scan

import (
	"context"
	"net"
	"sync"
	"time"
)

// dnsEntry stores a cached DNS resolution result.
type dnsEntry struct {
	addrs []string
	err   error
	ready chan struct{} // closed when lookup completes
}

// dnsCache is an in-process DNS resolution cache shared across all scanners.
// Multiple scanners resolving the same hostname get the cached result,
// eliminating redundant DNS lookups during a scan.
var dnsCache sync.Map // hostname → *dnsEntry

// CachedLookupHost resolves a hostname using the in-process cache.
// The first caller for a given host triggers the real lookup; concurrent
// callers block until the result is ready and then share it.
func CachedLookupHost(ctx context.Context, host string) ([]string, error) {
	entry := &dnsEntry{ready: make(chan struct{})}
	if existing, loaded := dnsCache.LoadOrStore(host, entry); loaded {
		// Another goroutine is resolving (or already resolved) this host.
		cached := existing.(*dnsEntry)
		select {
		case <-cached.ready:
			return cached.addrs, cached.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	// We are the first — do the real lookup.
	entry.addrs, entry.err = net.DefaultResolver.LookupHost(ctx, host)
	close(entry.ready)
	return entry.addrs, entry.err
}

// CachedDialContext returns a net.Dialer.DialContext-compatible function that
// uses the DNS cache for hostname resolution. Numeric addresses bypass the
// cache entirely.
func CachedDialContext() func(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return dialer.DialContext(ctx, network, addr)
		}
		// Numeric IPs don't need DNS.
		if net.ParseIP(host) != nil {
			return dialer.DialContext(ctx, network, addr)
		}
		addrs, err := CachedLookupHost(ctx, host)
		if err != nil || len(addrs) == 0 {
			// Fall back to the system resolver.
			return dialer.DialContext(ctx, network, addr)
		}
		// Try each resolved address in order.
		var lastErr error
		for _, ip := range addrs {
			resolved := net.JoinHostPort(ip, port)
			conn, err := dialer.DialContext(ctx, network, resolved)
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
}

// ResetDNSCache clears all cached DNS entries. Useful between scan runs
// in long-lived processes or test suites.
func ResetDNSCache() {
	dnsCache.Range(func(key, _ any) bool {
		dnsCache.Delete(key)
		return true
	})
}
