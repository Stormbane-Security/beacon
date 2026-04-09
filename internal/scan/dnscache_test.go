package scan

import (
	"context"
	"sync"
	"testing"
)

func TestCachedLookupHostLocalhost(t *testing.T) {
	ResetDNSCache()
	addrs, err := CachedLookupHost(context.Background(), "localhost")
	if err != nil {
		t.Fatalf("unexpected error resolving localhost: %v", err)
	}
	if len(addrs) == 0 {
		t.Fatal("expected at least one address for localhost")
	}
	// Second call should hit cache — verify it returns the same result.
	addrs2, err := CachedLookupHost(context.Background(), "localhost")
	if err != nil {
		t.Fatalf("unexpected error on cached lookup: %v", err)
	}
	if len(addrs2) != len(addrs) {
		t.Errorf("cached result length %d != original %d", len(addrs2), len(addrs))
	}
}

func TestCachedLookupHostConcurrent(t *testing.T) {
	ResetDNSCache()
	const goroutines = 20
	var wg sync.WaitGroup
	results := make([][]string, goroutines)
	errs := make([]error, goroutines)

	for i := 0; i < goroutines; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = CachedLookupHost(context.Background(), "localhost")
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d got error: %v", i, err)
		}
	}
	// All should resolve to the same set.
	for i := 1; i < goroutines; i++ {
		if len(results[i]) != len(results[0]) {
			t.Errorf("goroutine %d got %d addrs, goroutine 0 got %d", i, len(results[i]), len(results[0]))
		}
	}
}

func TestResetDNSCache(t *testing.T) {
	ResetDNSCache()
	_, _ = CachedLookupHost(context.Background(), "localhost")
	// Verify entry exists.
	if _, ok := dnsCache.Load("localhost"); !ok {
		t.Fatal("expected localhost in cache after lookup")
	}
	ResetDNSCache()
	if _, ok := dnsCache.Load("localhost"); ok {
		t.Fatal("expected cache empty after reset")
	}
}
