package scan

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDiscoveryCacheRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cache")
	c := NewDiscoveryCacheWithDir(dir, 24*time.Hour)
	if c == nil {
		t.Fatal("NewDiscoveryCacheWithDir returned nil")
	}

	// Empty cache returns miss.
	if _, ok := c.Get("example.com"); ok {
		t.Fatal("expected cache miss on empty cache")
	}

	subs := []string{"api.example.com", "www.example.com", "dev.example.com"}
	c.Put("example.com", subs)

	got, ok := c.Get("example.com")
	if !ok {
		t.Fatal("expected cache hit after Put")
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 subdomains, got %d", len(got))
	}
	// Put sorts the subdomains.
	if got[0] != "api.example.com" || got[1] != "dev.example.com" || got[2] != "www.example.com" {
		t.Fatalf("unexpected order: %v", got)
	}
}

func TestDiscoveryCacheTTL(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cache")
	c := NewDiscoveryCacheWithDir(dir, 1*time.Millisecond)
	if c == nil {
		t.Fatal("NewDiscoveryCacheWithDir returned nil")
	}

	c.Put("example.com", []string{"a.example.com"})
	time.Sleep(5 * time.Millisecond)

	if _, ok := c.Get("example.com"); ok {
		t.Fatal("expected cache miss after TTL expiry")
	}
}

func TestDiscoveryCacheDiff(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cache")
	c := NewDiscoveryCacheWithDir(dir, 24*time.Hour)
	if c == nil {
		t.Fatal("NewDiscoveryCacheWithDir returned nil")
	}

	c.Put("example.com", []string{"a.example.com", "b.example.com", "c.example.com"})

	current := []string{"b.example.com", "c.example.com", "d.example.com"}
	added, removed := c.Diff("example.com", current)

	if len(added) != 1 || added[0] != "d.example.com" {
		t.Fatalf("expected added=[d.example.com], got %v", added)
	}
	if len(removed) != 1 || removed[0] != "a.example.com" {
		t.Fatalf("expected removed=[a.example.com], got %v", removed)
	}
}

func TestDiscoveryCacheDiffNoCache(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cache")
	c := NewDiscoveryCacheWithDir(dir, 24*time.Hour)

	current := []string{"a.example.com", "b.example.com"}
	added, removed := c.Diff("example.com", current)

	if len(added) != 2 {
		t.Fatalf("expected all current as added, got %v", added)
	}
	if len(removed) != 0 {
		t.Fatalf("expected no removed, got %v", removed)
	}
}

func TestDiscoveryCacheNil(t *testing.T) {
	var c *DiscoveryCache

	// All methods should be safe to call on nil.
	if _, ok := c.Get("example.com"); ok {
		t.Fatal("nil cache should return miss")
	}
	c.Put("example.com", []string{"a.example.com"}) // should not panic
	added, removed := c.Diff("example.com", []string{"a.example.com"})
	if len(added) != 1 {
		t.Fatalf("nil cache Diff should return all as added, got %v", added)
	}
	if len(removed) != 0 {
		t.Fatalf("nil cache Diff should return no removed, got %v", removed)
	}
}

func TestDiscoveryCacheFileCreated(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cache")
	c := NewDiscoveryCacheWithDir(dir, 24*time.Hour)

	c.Put("example.com", []string{"a.example.com"})

	path := filepath.Join(dir, "example.com.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatalf("cache file not created at %s", path)
	}
}
