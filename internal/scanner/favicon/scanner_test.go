package favicon

import (
	"testing"
)

func TestMmh3Hash(t *testing.T) {
	// Known test vector: empty input.
	hash := murmur3_32([]byte{}, 0)
	if hash != 0 {
		t.Errorf("mmh3(\"\", 0) = %d, want 0", hash)
	}

	// Known test vector: "test".
	hash2 := murmur3_32([]byte("test"), 0)
	if hash2 == 0 {
		t.Error("mmh3(\"test\", 0) should not be 0")
	}

	// Consistency check: same input → same output.
	h1 := mmh3Hash([]byte("hello world"))
	h2 := mmh3Hash([]byte("hello world"))
	if h1 != h2 {
		t.Errorf("mmh3 not consistent: %d != %d", h1, h2)
	}

	// Different input → different output (with high probability).
	h3 := mmh3Hash([]byte("different"))
	if h1 == h3 {
		t.Error("different inputs should produce different hashes")
	}
}

func TestKnownFaviconsNotEmpty(t *testing.T) {
	if len(knownFavicons) == 0 {
		t.Error("knownFavicons database is empty")
	}
}
