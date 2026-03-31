package report

import (
	"testing"
)

func TestSanitizeShellArg(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "normal hostname",
			input: "example.com",
			want:  "example.com",
		},
		{
			name:  "IP address",
			input: "192.168.1.1",
			want:  "192.168.1.1",
		},
		{
			name:  "shell metachar semicolon rm",
			input: "; rm -rf /",
			want:  "rm-rf/",
		},
		{
			name:  "pipe",
			input: "foo | bar",
			want:  "foobar",
		},
		{
			name:  "backticks",
			input: "foo`whoami`bar",
			want:  "foowhoamibar",
		},
		{
			name:  "dollar expansion",
			input: "foo$(cmd)bar",
			want:  "foocmdbar",
		},
		{
			name:  "ampersand",
			input: "foo & bar",
			want:  "foobar",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "github org/repo",
			input: "owner/repo",
			want:  "owner/repo",
		},
		{
			name:  "URL with special chars",
			input: "https://example.com:8080/path?q=1&r=2#frag",
			want:  "https://example.com:8080/pathq1r2frag",
		},
		{
			name:  "subdomain hostname",
			input: "sub.domain.example.com",
			want:  "sub.domain.example.com",
		},
		{
			name:  "IPv6 address in brackets",
			input: "[::1]",
			want:  "[::1]",
		},
		{
			name:  "email address",
			input: "user@example.com",
			want:  "user@example.com",
		},
		{
			name:  "hyphenated hostname",
			input: "my-host.example.com",
			want:  "my-host.example.com",
		},
		{
			name:  "underscore in hostname",
			input: "my_host.example.com",
			want:  "my_host.example.com",
		},
		{
			name:  "newline injection",
			input: "example.com\nmalicious",
			want:  "example.commalicious",
		},
		{
			name:  "single quotes",
			input: "it's a test",
			want:  "itsatest",
		},
		{
			name:  "double quotes",
			input: `host"name`,
			want:  "hostname",
		},
		{
			name:  "redirect operators",
			input: "foo > /etc/passwd",
			want:  "foo/etc/passwd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeShellArg(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeShellArg(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
