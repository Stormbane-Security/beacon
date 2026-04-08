package wafbypass

import (
	"testing"
)

func TestDoubleEncode(t *testing.T) {
	input := "' OR 1=1"
	encoded := doubleEncode(input)
	if encoded == input {
		t.Error("doubleEncode should produce different output")
	}
	// Double encoding should not contain raw single quotes
	if containsRaw(encoded, "'") {
		t.Error("double-encoded string should not contain raw single quote")
	}
}

func TestUnicodeEncode(t *testing.T) {
	input := "OR 1=1"
	encoded := unicodeEncode(input)
	if encoded == input {
		t.Error("unicodeEncode should produce different output")
	}
	if len(encoded) == 0 {
		t.Error("unicodeEncode should produce non-empty output")
	}
}

func TestUnicodeEncode_PreservesSpaces(t *testing.T) {
	// Spaces are outside the fullwidth range, should be preserved or converted
	input := "test value"
	encoded := unicodeEncode(input)
	if len(encoded) == 0 {
		t.Error("should handle strings with spaces")
	}
}

func TestIsBlocked_NilClient(t *testing.T) {
	// isBlocked with invalid URL should return false, not panic
	result := isBlocked(nil, nil, "not-a-valid-url")
	if result {
		t.Error("invalid URL should not be considered blocked")
	}
}

func containsRaw(s, sub string) bool {
	for i := 0; i < len(s)-len(sub)+1; i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
