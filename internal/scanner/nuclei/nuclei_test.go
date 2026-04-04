package nuclei

import (
	"strings"
	"testing"
)

func TestIsValidHostname(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "valid hostname",
			input: "example.com",
			want:  true,
		},
		{
			name:  "valid subdomain",
			input: "sub.example.com",
			want:  true,
		},
		{
			name:  "deeply nested subdomain",
			input: "a.b.c.d.example.com",
			want:  true,
		},
		{
			name:  "empty string",
			input: "",
			want:  false,
		},
		{
			name:  "too long hostname over 253 chars",
			input: strings.Repeat("a", 254),
			want:  false,
		},
		{
			name:  "exactly 253 chars single label",
			input: strings.Repeat("a", 253),
			want:  false, // single label > 63 chars
		},
		{
			name:  "label exactly 63 chars",
			input: strings.Repeat("a", 63) + ".com",
			want:  true,
		},
		{
			name:  "label over 63 chars",
			input: strings.Repeat("a", 64) + ".com",
			want:  false,
		},
		{
			name:  "leading hyphen",
			input: "-example.com",
			want:  false,
		},
		{
			name:  "trailing hyphen in label",
			input: "example-.com",
			want:  false,
		},
		{
			name:  "hyphen in middle",
			input: "my-host.example.com",
			want:  true,
		},
		{
			name:  "non-alnum chars underscore",
			input: "my_host.example.com",
			want:  false,
		},
		{
			name:  "non-alnum chars space",
			input: "my host.com",
			want:  false,
		},
		{
			name:  "argument injection double dash",
			input: "--config",
			want:  false, // starts with -- (leading hyphen at label start)
		},
		{
			name:  "argument injection with dot",
			input: "--config.evil.com",
			want:  false, // first label starts with hyphen
		},
		{
			name:  "IP address",
			input: "1.2.3.4",
			want:  true, // all labels are digits, valid per RFC 1123
		},
		{
			name:  "localhost",
			input: "localhost",
			want:  true, // single-label hostname, valid per RFC 1123
		},
		{
			name:  "trailing dot",
			input: "example.com.",
			want:  false, // trailing dot creates empty label
		},
		{
			name:  "double dot",
			input: "example..com",
			want:  false, // empty label between dots
		},
		{
			name:  "uppercase letters",
			input: "Example.COM",
			want:  true,
		},
		{
			name:  "mixed alphanumeric",
			input: "host123.example456.com",
			want:  true,
		},
		{
			name:  "single char labels",
			input: "a.b.c",
			want:  true,
		},
		{
			name:  "single dash as label",
			input: "-.example.com",
			want:  false, // dash at start and end of label
		},
		{
			name:  "semicolon injection",
			input: "example.com;whoami",
			want:  false,
		},
		{
			name:  "pipe injection",
			input: "example.com|cat",
			want:  false,
		},
		{
			name:  "backtick injection",
			input: "example.com`id`",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidHostname(tt.input)
			if got != tt.want {
				t.Errorf("isValidHostname(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// TestNativelyExcluded_NoDuplicates verifies the exclusion list has no duplicates.
func TestNativelyExcluded_NoDuplicates(t *testing.T) {
	seen := make(map[string]bool, len(nativelyExcluded))
	for _, id := range nativelyExcluded {
		if seen[id] {
			t.Errorf("duplicate in nativelyExcluded: %q", id)
		}
		seen[id] = true
	}
}

// TestNativelyExcluded_AllNonEmpty verifies no empty strings in the list.
func TestNativelyExcluded_AllNonEmpty(t *testing.T) {
	for i, id := range nativelyExcluded {
		if id == "" {
			t.Errorf("nativelyExcluded[%d] is empty", i)
		}
	}
}

// TestRunWithTags_RejectsShellMetachars verifies that RunWithTags rejects
// hostnames containing shell metacharacters that could lead to command
// injection via the nuclei subprocess.
func TestRunWithTags_RejectsShellMetachars(t *testing.T) {
	s := New("/nonexistent/nuclei", "", "")

	malicious := []struct {
		name  string
		input string
	}{
		{"semicolon", "example.com;whoami"},
		{"pipe", "example.com|cat /etc/passwd"},
		{"dollar_expansion", "$(whoami).example.com"},
		{"backtick", "example.com`id`"},
		{"ampersand", "example.com&sleep 5"},
		{"newline", "example.com\nwhoami"},
		{"space", "example.com whoami"},
	}

	for _, tt := range malicious {
		t.Run(tt.name, func(t *testing.T) {
			_, err := s.RunWithTags(t.Context(), tt.input, []string{"ssl"})
			if err == nil {
				t.Errorf("RunWithTags(%q) should reject hostname with shell metachar, got nil error", tt.input)
			}
			if err != nil && !strings.Contains(err.Error(), "invalid hostname") {
				t.Errorf("RunWithTags(%q) error = %v, want 'invalid hostname' error", tt.input, err)
			}
		})
	}
}

// TestRunWithTags_AcceptsValidHostname verifies that RunWithTags passes
// validation for well-formed hostnames (it will fail at the binary-not-found
// stage, which proves the hostname validation itself passed).
func TestRunWithTags_AcceptsValidHostname(t *testing.T) {
	s := New("/nonexistent/nuclei", "", "")

	_, err := s.RunWithTags(t.Context(), "valid.example.com", []string{"ssl"})
	if err == nil {
		// Shouldn't happen since the binary doesn't exist
		return
	}
	// The error should NOT be about invalid hostname — it should be about the missing binary.
	if strings.Contains(err.Error(), "invalid hostname") {
		t.Errorf("valid hostname was incorrectly rejected: %v", err)
	}
}
