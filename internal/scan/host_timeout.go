package scan

import (
	"log"
	"net"
	"strings"
	"sync"
)

const (
	// HostTimeoutThreshold is the number of consecutive timeouts before
	// a host is considered unresponsive and remaining probes are skipped.
	// At 10s per timeout, 5 consecutive = 50s of evidence.
	HostTimeoutThreshold = 5
)

// HostTimeoutTracker tracks consecutive HTTP request timeouts per host.
// When a host accumulates HostTimeoutThreshold consecutive timeouts, it is
// marked as bailed — all further probes for that host are skipped, avoiding
// minutes of wasted time on unresponsive targets.
//
// A single successful response resets the counter, so intermittently slow
// hosts are not penalized.
type HostTimeoutTracker struct {
	mu     sync.Mutex
	counts map[string]int  // host → consecutive timeout count
	bailed map[string]bool // host → true if we gave up
}

// NewHostTimeoutTracker creates a ready-to-use tracker.
func NewHostTimeoutTracker() *HostTimeoutTracker {
	return &HostTimeoutTracker{
		counts: make(map[string]int),
		bailed: make(map[string]bool),
	}
}

// RecordTimeout increments the consecutive timeout counter for a host.
// Returns true when the threshold is reached and the host should be bailed on.
func (t *HostTimeoutTracker) RecordTimeout(host string) bool {
	host = normalizeHost(host)
	t.mu.Lock()
	defer t.mu.Unlock()
	t.counts[host]++
	if t.counts[host] >= HostTimeoutThreshold {
		if !t.bailed[host] {
			t.bailed[host] = true
			log.Printf("beacon: host %s bailed after %d consecutive timeouts — skipping remaining probes", host, t.counts[host])
		}
		return true
	}
	return false
}

// RecordSuccess resets the consecutive timeout counter for a host.
// A single successful response proves the host is reachable.
func (t *HostTimeoutTracker) RecordSuccess(host string) {
	host = normalizeHost(host)
	t.mu.Lock()
	defer t.mu.Unlock()
	t.counts[host] = 0
}

// ShouldSkip returns true if the host has been bailed on due to
// excessive consecutive timeouts.
func (t *HostTimeoutTracker) ShouldSkip(host string) bool {
	host = normalizeHost(host)
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.bailed[host]
}

// BailedHosts returns a snapshot of all hosts that were bailed on.
func (t *HostTimeoutTracker) BailedHosts() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	hosts := make([]string, 0, len(t.bailed))
	for h := range t.bailed {
		hosts = append(hosts, h)
	}
	return hosts
}

// IsTimeoutError returns true if the error is a network timeout
// (net.Error with Timeout() == true) or a context deadline exceeded.
func IsTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	// net.Error.Timeout() covers both client-side and dial timeouts.
	var netErr net.Error
	if ok := errorAs(err, &netErr); ok && netErr.Timeout() {
		return true
	}
	// Also catch context.DeadlineExceeded wrapped in url.Error, etc.
	msg := err.Error()
	return strings.Contains(msg, "context deadline exceeded") ||
		strings.Contains(msg, "i/o timeout")
}

// errorAs is a helper that wraps errors.As for the net.Error interface.
func errorAs(err error, target interface{}) bool {
	// Use the standard errors.As through the interface assertion path.
	type unwrapper interface {
		Unwrap() error
	}
	// Direct type assertion first.
	if ne, ok := err.(net.Error); ok {
		*target.(*net.Error) = ne
		return true
	}
	// Unwrap chain.
	for {
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
		if err == nil {
			return false
		}
		if ne, ok := err.(net.Error); ok {
			*target.(*net.Error) = ne
			return true
		}
	}
}

// normalizeHost strips port suffixes so "example.com:443" and "example.com"
// map to the same counter.
func normalizeHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
