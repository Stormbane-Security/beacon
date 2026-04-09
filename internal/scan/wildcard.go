package scan

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
)

// DetectWildcard checks if *.domain resolves by querying a random non-existent
// subdomain. If it resolves, all DNS brute-force results for the domain will be
// false positives (the wildcard record catches everything).
//
// Returns true and the wildcard IP address if wildcard DNS is detected,
// false and "" otherwise.
func DetectWildcard(ctx context.Context, domain string) (bool, string) {
	// Generate a random subdomain that is extremely unlikely to exist.
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// Fallback to a fixed probe name if crypto/rand fails.
		return detectWildcardFixed(ctx, domain)
	}
	probe := "beacon-wc-" + hex.EncodeToString(buf[:]) + "." + domain

	addrs, err := net.DefaultResolver.LookupHost(ctx, probe)
	if err != nil || len(addrs) == 0 {
		return false, ""
	}

	// Double-check with a second random probe to reduce false positives from
	// DNS load balancers that happen to resolve one random name.
	var buf2 [8]byte
	if _, err := rand.Read(buf2[:]); err == nil {
		probe2 := "beacon-wc-" + hex.EncodeToString(buf2[:]) + "." + domain
		addrs2, err2 := net.DefaultResolver.LookupHost(ctx, probe2)
		if err2 != nil || len(addrs2) == 0 {
			return false, "" // first resolved but second didn't — not a wildcard
		}
	}

	return true, addrs[0]
}

// detectWildcardFixed is a fallback that uses a deterministic probe name.
func detectWildcardFixed(ctx context.Context, domain string) (bool, string) {
	probe := "beacon-wildcard-probe-x7q2m5k8." + domain
	addrs, err := net.DefaultResolver.LookupHost(ctx, probe)
	if err != nil || len(addrs) == 0 {
		return false, ""
	}
	return true, addrs[0]
}
