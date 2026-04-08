package diffing

import (
	"math"
	"testing"
)

func TestCompare_IdenticalBodies_ReturnsOne(t *testing.T) {
	body := []byte(`<html><body>Hello World</body></html>`)
	score := Compare(body, body)
	if score != 1.0 {
		t.Errorf("Compare(identical) = %f, want 1.0", score)
	}
}

func TestCompare_CompletelyDifferent_ReturnsZero(t *testing.T) {
	a := []byte(`alpha bravo charlie`)
	b := []byte(`delta echo foxtrot`)
	score := Compare(a, b)
	if score != 0.0 {
		t.Errorf("Compare(completely different) = %f, want 0.0", score)
	}
}

func TestCompare_EmptyBodies_ReturnsOne(t *testing.T) {
	score := Compare([]byte{}, []byte{})
	if score != 1.0 {
		t.Errorf("Compare(empty, empty) = %f, want 1.0", score)
	}
}

func TestCompare_PartialOverlap(t *testing.T) {
	a := []byte(`the quick brown fox`)
	b := []byte(`the slow brown dog`)
	score := Compare(a, b)
	// "the" and "brown" overlap → 2 common out of 6 union → ~0.33
	if score < 0.2 || score > 0.5 {
		t.Errorf("Compare(partial overlap) = %f, want ~0.33", score)
	}
}

func TestCompare_IgnoresTimestamps(t *testing.T) {
	a := []byte(`<span>Generated at 2024-01-15T10:30:00Z</span> Hello World`)
	b := []byte(`<span>Generated at 2025-06-20T14:00:00Z</span> Hello World`)
	score := Compare(a, b)
	if score < 0.9 {
		t.Errorf("Compare should ignore timestamps, got %f", score)
	}
}

func TestCompare_IgnoresCSRFTokens(t *testing.T) {
	a := []byte(`<input name="csrf" value="aabbccdd11223344aabbccdd11223344"> Submit`)
	b := []byte(`<input name="csrf" value="zzyyxxww99887766zzyyxxww99887766"> Submit`)
	score := Compare(a, b)
	if score < 0.8 {
		t.Errorf("Compare should ignore CSRF tokens, got %f", score)
	}
}

func TestCompare_IgnoresUUIDs(t *testing.T) {
	a := []byte(`session: 550e8400-e29b-41d4-a716-446655440000 content here`)
	b := []byte(`session: 6ba7b810-9dad-11d1-80b4-00c04fd430c8 content here`)
	score := Compare(a, b)
	if score < 0.8 {
		t.Errorf("Compare should ignore UUIDs, got %f", score)
	}
}

func TestStripDynamic_RemovesTimestamps(t *testing.T) {
	input := []byte(`time: 2024-01-15T10:30:00Z end`)
	out := string(StripDynamic(input))
	if contains(out, "2024-01-15") {
		t.Error("StripDynamic should remove ISO timestamps")
	}
}

func TestStripDynamic_RemovesUUIDs(t *testing.T) {
	input := []byte(`id: 550e8400-e29b-41d4-a716-446655440000 done`)
	out := string(StripDynamic(input))
	if contains(out, "550e8400") {
		t.Error("StripDynamic should remove UUIDs")
	}
}

func TestSignificantDiff_SimilarBodies_ReturnsFalse(t *testing.T) {
	a := []byte(`<html><body>Hello World</body></html>`)
	b := []byte(`<html><body>Hello World</body></html>`)
	if SignificantDiff(a, b, 0.7) {
		t.Error("SignificantDiff should be false for identical bodies")
	}
}

func TestSignificantDiff_DifferentBodies_ReturnsTrue(t *testing.T) {
	a := []byte(`<html><body>Error: SQL syntax near</body></html>`)
	b := []byte(`<html><body>Welcome to our website</body></html>`)
	if !SignificantDiff(a, b, 0.7) {
		t.Error("SignificantDiff should be true for very different bodies")
	}
}

func TestCompare_OnlyDynamicContent_ReturnsHigh(t *testing.T) {
	// Two responses that differ only in dynamic content should be very similar.
	a := []byte(`token="aabbccdd11223344eeff0011aabbccdd" nonce="1234567890"`)
	b := []byte(`token="11223344aabbccddeeff001122334455" nonce="9876543210"`)
	score := Compare(a, b)
	if score < 0.7 {
		t.Errorf("Responses differing only in dynamic content should score high, got %f", score)
	}
}

func TestJaccard_Symmetry(t *testing.T) {
	a := []byte(`hello world foo`)
	b := []byte(`world bar baz`)
	s1 := Compare(a, b)
	s2 := Compare(b, a)
	if math.Abs(s1-s2) > 1e-9 {
		t.Errorf("Jaccard should be symmetric: %f != %f", s1, s2)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && indexOf(s, substr) >= 0
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
