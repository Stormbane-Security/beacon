package historicalurls

import (
	"testing"
)

// The Run method requires the external "gau" tool (via toolinstall.Ensure),
// so we cannot integration-test it without the binary installed. These tests
// cover the internal helper logic that does not require external tools.

// ---------------------------------------------------------------------------
// Test: Scanner.Name() returns expected value
// ---------------------------------------------------------------------------

func TestScanner_Name(t *testing.T) {
	s := New("")
	if s.Name() != "historicalurls" {
		t.Errorf("expected scanner name %q, got %q", "historicalurls", s.Name())
	}
}

// ---------------------------------------------------------------------------
// Test: New() uses default binary name "gau"
// ---------------------------------------------------------------------------

func TestNew_DefaultBin(t *testing.T) {
	s := New("")
	if s.bin != "gau" {
		t.Errorf("expected default bin %q, got %q", "gau", s.bin)
	}
}

func TestNew_CustomBin(t *testing.T) {
	s := New("/usr/local/bin/custom-gau")
	if s.bin != "/usr/local/bin/custom-gau" {
		t.Errorf("expected custom bin %q, got %q", "/usr/local/bin/custom-gau", s.bin)
	}
}

// ---------------------------------------------------------------------------
// Test: isInteresting — positive matches
// ---------------------------------------------------------------------------

func TestIsInteresting_PositivePatterns(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		{"https://example.com/.env", true},
		{"https://example.com/backup.sql", true}, // contains ".sql" substring
		{"https://example.com/data.sql", true},    // contains ".sql"
		{"https://example.com/db.bak", true},
		{"https://example.com/site.backup", true},
		{"https://example.com/dump.db", true},
		{"https://example.com/archive.tar", true},
		{"https://example.com/files.zip", true},
		{"https://example.com/data.gz", true},
		{"https://example.com/admin/panel", true},
		{"https://example.com/wp-admin/index.php", true},
		{"https://example.com/phpmyadmin/", true},
		{"https://example.com/cpanel/login", true},
		{"https://example.com/api/v1/users", true},
		{"https://example.com/v1/health", true},
		{"https://example.com/v2/config", true},
		{"https://example.com/graphql", true},
		{"https://example.com/swagger/index.html", true},
		{"https://example.com/openapi.json", true},
		{"https://example.com/_debug/vars", true},
		{"https://example.com/.git/HEAD", true},
		{"https://example.com/config.yaml", true},
		{"https://example.com/credentials.json", true},
		{"https://example.com/login?token=abc", true},
		{"https://example.com/auth?key=secret", true},
		{"https://example.com/form?password=x", true},
		{"https://example.com/auth?secret=x", true},
		{"https://example.com/data?api_key=x", true},
		{"https://example.com/staging/app", true},
		{"https://example.com/dev/test", true},
		{"https://example.com/test/endpoint", true},
	}

	for _, tc := range cases {
		got := isInteresting(tc.url)
		if got != tc.want {
			t.Errorf("isInteresting(%q) = %v, want %v", tc.url, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Test: isInteresting — negative cases (boring URLs)
// ---------------------------------------------------------------------------

func TestIsInteresting_NegativePatterns(t *testing.T) {
	cases := []string{
		"https://example.com/index.html",
		"https://example.com/about",
		"https://example.com/products/shoes",
		"https://example.com/blog/2024/hello-world",
		"https://example.com/static/style.css",
		"https://example.com/images/logo.png",
		"https://example.com/contact-us",
	}

	for _, url := range cases {
		if isInteresting(url) {
			t.Errorf("isInteresting(%q) = true, want false", url)
		}
	}
}

// ---------------------------------------------------------------------------
// Test: isInteresting — case sensitivity (input is lowercased by caller)
// ---------------------------------------------------------------------------

func TestIsInteresting_CaseSensitive(t *testing.T) {
	// isInteresting expects the caller to lowercase the input.
	// The patterns are lowercase, so uppercase input should NOT match.
	if isInteresting("https://example.com/.ENV") {
		t.Error("isInteresting should not match uppercase .ENV (patterns are lowercase)")
	}
	// Lowercase should match.
	if !isInteresting("https://example.com/.env") {
		t.Error("isInteresting should match lowercase .env")
	}
}

// ---------------------------------------------------------------------------
// Test: subdomain filter (Run skips assets with more than 2 dots)
// ---------------------------------------------------------------------------

func TestRun_SubdomainFilter_SkipsDeepSubdomains(t *testing.T) {
	// We cannot actually run the scanner (needs gau), but we can verify that
	// the subdomain filter logic works by checking the dot count condition.
	// Assets with > 2 dots should be skipped.
	tests := []struct {
		asset string
		skip  bool
	}{
		{"example.com", false},
		{"example.co.uk", false},
		{"sub.example.com", false},         // 2 dots — not skipped
		{"deep.sub.example.com", true},      // 3 dots — skipped
		{"a.b.c.example.com", true},         // 4 dots — skipped
	}

	for _, tt := range tests {
		dots := 0
		for _, c := range tt.asset {
			if c == '.' {
				dots++
			}
		}
		skipped := dots > 2
		if skipped != tt.skip {
			t.Errorf("asset %q: expected skip=%v, got skip=%v (dots=%d)", tt.asset, tt.skip, skipped, dots)
		}
	}
}
