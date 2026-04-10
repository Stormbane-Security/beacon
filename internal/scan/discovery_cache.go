package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// DefaultCacheTTL is the default time-to-live for cached discovery results.
const DefaultCacheTTL = 24 * time.Hour

// discoveryCacheEntry is the on-disk JSON structure for cached subdomain data.
type discoveryCacheEntry struct {
	Domain     string    `json:"domain"`
	Subdomains []string  `json:"subdomains"`
	Timestamp  time.Time `json:"timestamp"`
}

// DiscoveryCache caches subdomain discovery results to speed up re-scans.
// Cache key is the root domain. TTL is 24 hours by default.
// Files are stored under ~/.beacon/cache/discovery/ as JSON.
type DiscoveryCache struct {
	dir string
	ttl time.Duration
}

// NewDiscoveryCache creates a DiscoveryCache using ~/.beacon/cache/discovery/.
// Returns nil if the cache directory cannot be created.
func NewDiscoveryCache() *DiscoveryCache {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	dir := filepath.Join(home, ".beacon", "cache", "discovery")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil
	}
	return &DiscoveryCache{dir: dir, ttl: DefaultCacheTTL}
}

// NewDiscoveryCacheWithDir creates a DiscoveryCache with a custom directory
// and TTL. Useful for testing.
func NewDiscoveryCacheWithDir(dir string, ttl time.Duration) *DiscoveryCache {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil
	}
	return &DiscoveryCache{dir: dir, ttl: ttl}
}

// cacheFile returns the path to the cache file for a given domain.
func (c *DiscoveryCache) cacheFile(domain string) string {
	// Simple filename: domain.json. Domains are already validated hostnames
	// so they are safe for filenames.
	return filepath.Join(c.dir, domain+".json")
}

// Get returns cached subdomains for a domain if the cache entry is fresh
// (within TTL). Returns nil, false if no cache or expired.
func (c *DiscoveryCache) Get(domain string) ([]string, bool) {
	if c == nil {
		return nil, false
	}
	data, err := os.ReadFile(c.cacheFile(domain))
	if err != nil {
		return nil, false
	}
	var entry discoveryCacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, false
	}
	if time.Since(entry.Timestamp) > c.ttl {
		return nil, false
	}
	return entry.Subdomains, true
}

// Put stores the discovered subdomains for a domain with the current timestamp.
func (c *DiscoveryCache) Put(domain string, subdomains []string) {
	if c == nil {
		return
	}
	// Sort for deterministic output and efficient diffing.
	sorted := make([]string, len(subdomains))
	copy(sorted, subdomains)
	sort.Strings(sorted)

	entry := discoveryCacheEntry{
		Domain:     domain,
		Subdomains: sorted,
		Timestamp:  time.Now(),
	}
	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(c.cacheFile(domain), data, 0o600)
}

// Diff compares the current subdomain list against the cached version and
// returns newly added and removed subdomains. If no cache exists, all current
// subdomains are returned as added.
func (c *DiscoveryCache) Diff(domain string, current []string) (added, removed []string) {
	if c == nil {
		return current, nil
	}
	cached, ok := c.Get(domain)
	if !ok {
		return current, nil
	}

	cachedSet := make(map[string]struct{}, len(cached))
	for _, s := range cached {
		cachedSet[s] = struct{}{}
	}
	currentSet := make(map[string]struct{}, len(current))
	for _, s := range current {
		currentSet[s] = struct{}{}
	}

	for _, s := range current {
		if _, ok := cachedSet[s]; !ok {
			added = append(added, s)
		}
	}
	for _, s := range cached {
		if _, ok := currentSet[s]; !ok {
			removed = append(removed, s)
		}
	}
	return added, removed
}
