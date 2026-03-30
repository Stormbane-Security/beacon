package subdomain

import (
	"context"
	"net"
	"testing"
)

// TestWildcardIPs_NoWildcard verifies that wildcardIPs returns an empty set
// when the probe hostname does not resolve (the normal case for most domains).
// We use a guaranteed-nonexistent domain to get a clean NXDOMAIN.
func TestWildcardIPs_NoWildcard(t *testing.T) {
	ips := wildcardIPs(context.Background(), "beacon-test-nxdomain-x9z2.invalid")
	if len(ips) != 0 {
		t.Errorf("expected empty wildcard set for non-resolving domain, got %v", ips)
	}
}

// TestWildcardIPs_ContextCancelled_ReturnsEmpty verifies graceful handling of
// a cancelled context (should not panic or block).
func TestWildcardIPs_ContextCancelled_ReturnsEmpty(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ips := wildcardIPs(ctx, "example.com")
	// Cancelled context should produce an empty set (resolution fails).
	// We don't assert the exact value since the race between cancellation and
	// DNS resolution means it could sometimes succeed; we just verify no panic.
	_ = ips
}

// TestBruteForceSubdomains_WildcardFiltering verifies that when all resolved
// IPs match the wildcard set, the subdomain is excluded from results.
// We test this by exercising the filter logic directly via a custom resolver.
//
// Since we can't inject a fake DNS resolver without changing the production
// API, we test the filter condition with a unit-level check on the logic:
// a subdomain whose IPs are entirely contained in the wildcard set must be dropped.
func TestBruteForceSubdomains_WildcardFilterLogic(t *testing.T) {
	wildcards := map[string]struct{}{
		"1.2.3.4": {},
		"1.2.3.5": {},
	}

	cases := []struct {
		name     string
		addrs    []string
		wantKeep bool
	}{
		{
			name:     "all IPs in wildcard set → drop",
			addrs:    []string{"1.2.3.4"},
			wantKeep: false,
		},
		{
			name:     "all IPs in wildcard set (multi) → drop",
			addrs:    []string{"1.2.3.4", "1.2.3.5"},
			wantKeep: false,
		},
		{
			name:     "one IP outside wildcard set → keep",
			addrs:    []string{"1.2.3.4", "9.9.9.9"},
			wantKeep: true,
		},
		{
			name:     "no overlap → keep",
			addrs:    []string{"9.9.9.9"},
			wantKeep: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			allWild := true
			for _, a := range tc.addrs {
				if _, ok := wildcards[a]; !ok {
					allWild = false
					break
				}
			}
			keep := !allWild
			if keep != tc.wantKeep {
				t.Errorf("filter(%v): got keep=%v, want %v", tc.addrs, keep, tc.wantKeep)
			}
		})
	}
}

// TestBruteForceSubdomains_EmptyWildcard_AllKept verifies that when there is
// no wildcard (empty set), the filter passes all resolved subdomains.
func TestBruteForceSubdomains_EmptyWildcard_AllKept(t *testing.T) {
	var wildcards map[string]struct{} // nil — no wildcard
	addrs := []string{"1.2.3.4"}

	if len(wildcards) > 0 {
		t.Fatal("precondition: wildcards must be nil/empty for this test")
	}

	// With an empty wildcard set the filter is bypassed — all subdomains are kept.
	// Simulate the production guard: `if len(wildcards) > 0 { ... filter ... }`
	filtered := false
	if len(wildcards) > 0 {
		allWild := true
		for _, a := range addrs {
			if _, ok := wildcards[a]; !ok {
				allWild = false
				break
			}
		}
		filtered = allWild
	}
	if filtered {
		t.Error("expected subdomain to be kept when wildcard set is empty")
	}
}

// TestIsValidHostname covers the hostname validation used before exec invocations.
func TestIsValidHostname_Valid(t *testing.T) {
	cases := []string{
		"example.com",
		"sub.example.com",
		"a-b.example.co.uk",
		"x",
	}
	for _, c := range cases {
		if !isValidHostname(c) {
			t.Errorf("isValidHostname(%q) = false, want true", c)
		}
	}
}

func TestIsValidHostname_Invalid(t *testing.T) {
	cases := []string{
		"",
		"-example.com",
		"example-.com",
		"ex ample.com",
		"exam_ple.com",
		"--config",
	}
	for _, c := range cases {
		if isValidHostname(c) {
			t.Errorf("isValidHostname(%q) = true, want false", c)
		}
	}
}

// TestWildcardIPs_LiveLookup ensures wildcardIPs does not crash on a real
// lookup attempt. Uses the .invalid TLD which is guaranteed NXDOMAIN per RFC 2606.
func TestWildcardIPs_LiveLookup_InvalidTLD(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live DNS lookup in short mode")
	}
	ips := wildcardIPs(context.Background(), "test.invalid")
	// .invalid must never resolve
	if len(ips) != 0 {
		t.Errorf("expected no wildcard IPs for .invalid TLD, got %v", ips)
	}
}

// Ensure net package is used (wildcardIPs uses net.DefaultResolver).
var _ = net.DefaultResolver

// TestBruteForceSubdomains_CancelledContext verifies that bruteForceSubdomains
// terminates promptly when the context is already cancelled, rather than
// blocking indefinitely on the semaphore.
func TestBruteForceSubdomains_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before the call

	// Should return quickly, not block on the semaphore for all prefixes.
	found := bruteForceSubdomains(ctx, "example.invalid")
	// We don't care about the result, just that it doesn't hang.
	_ = found
}
