package recon

import "testing"

func TestNormalizeTarget(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"example.com", "example.com"},
		{"https://example.com", "example.com"},
		{"http://example.com/path/to/page", "example.com"},
		{"https://example.com:8443/api", "example.com:8443"},
		{"https://example.com:443/api", "example.com"},
		{"http://example.com:80", "example.com"},
		{"example.com:8080", "example.com:8080"},
		{"example.com:443", "example.com"},
		{"192.168.1.1", "192.168.1.1"},
		{"http://192.168.1.1:9200", "192.168.1.1:9200"},
		{"  example.com  ", "example.com"},
		{"", ""},
		{"https://sub.example.com", "sub.example.com"},
	}

	for _, tt := range tests {
		got := NormalizeTarget(tt.input)
		if got != tt.want {
			t.Errorf("NormalizeTarget(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestDeduplicateTargets(t *testing.T) {
	input := []string{"example.com", "EXAMPLE.COM", "test.com", "example.com", "test.com"}
	got := DeduplicateTargets(input)
	if len(got) != 2 {
		t.Errorf("DeduplicateTargets returned %d items, want 2: %v", len(got), got)
	}
	// First occurrence should be preserved.
	if got[0] != "example.com" {
		t.Errorf("got[0] = %q, want %q", got[0], "example.com")
	}
}
