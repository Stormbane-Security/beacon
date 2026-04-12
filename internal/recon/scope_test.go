package recon

import "testing"

func TestIsInScope(t *testing.T) {
	s := &Scope{
		InScope:    []string{"*.example.com", "api.test.com"},
		OutOfScope: []string{"staging.example.com", "*.internal.example.com"},
	}

	tests := []struct {
		domain string
		want   bool
	}{
		{"example.com", true},         // wildcard covers base
		{"sub.example.com", true},     // wildcard match
		{"deep.sub.example.com", true}, // nested subdomain matches *.example.com
		{"api.test.com", true},        // exact match
		{"staging.example.com", false}, // out-of-scope exclusion
		{"dev.internal.example.com", false}, // out-of-scope wildcard
		{"other.com", false},          // not in scope at all
		{"", false},                   // empty
		{"https://sub.example.com/path", true}, // URL with scheme and path
		{"sub.example.com:8080", true},         // host:port
	}

	for _, tt := range tests {
		got := s.IsInScope(tt.domain)
		if got != tt.want {
			t.Errorf("IsInScope(%q) = %v, want %v", tt.domain, got, tt.want)
		}
	}
}

func TestFilterInScope(t *testing.T) {
	s := &Scope{
		InScope:    []string{"*.example.com"},
		OutOfScope: []string{"staging.example.com"},
	}

	targets := []string{"app.example.com", "staging.example.com", "other.com", "api.example.com"}
	got := s.FilterInScope(targets)
	if len(got) != 2 {
		t.Errorf("FilterInScope returned %d items, want 2: %v", len(got), got)
	}
}

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		pattern string
		domain  string
		want    bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "sub.example.com", false},
		{"*.example.com", "sub.example.com", true},
		{"*.example.com", "example.com", true},
		{"*.api.example.com", "v1.api.example.com", true},
		{"*.api.example.com", "api.example.com", true},
		{"*.api.example.com", "example.com", false},
	}

	for _, tt := range tests {
		got := matchPattern(tt.pattern, tt.domain)
		if got != tt.want {
			t.Errorf("matchPattern(%q, %q) = %v, want %v", tt.pattern, tt.domain, got, tt.want)
		}
	}
}
