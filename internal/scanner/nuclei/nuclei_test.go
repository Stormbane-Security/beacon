package nuclei

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
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

// ── parseOutput tests ──────────────────────────────────────────────────────

func TestParseOutput_ValidJSONL(t *testing.T) {
	input := []byte(`{"template-id":"expired-ssl","info":{"name":"Expired SSL","severity":"high","description":"The SSL certificate has expired."},"host":"https://example.com","matched-at":"https://example.com:443","extracted-results":["cert expired"],"meta":{},"timestamp":"2025-01-15T10:00:00Z"}
{"template-id":"missing-csp","info":{"name":"Missing CSP","severity":"medium","description":"No Content-Security-Policy header."},"host":"https://example.com","matched-at":"https://example.com","extracted-results":null,"meta":{},"timestamp":"2025-01-15T10:00:01Z"}`)

	findings, err := parseOutput("example.com", input)
	if err != nil {
		t.Fatalf("parseOutput returned error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	// First finding: expired-ssl maps to a known CheckID.
	if findings[0].CheckID != finding.CheckTLSCertExpiry7d {
		t.Errorf("finding[0] CheckID = %q, want %q", findings[0].CheckID, finding.CheckTLSCertExpiry7d)
	}
	if findings[0].Title != "Expired SSL" {
		t.Errorf("finding[0] Title = %q, want %q", findings[0].Title, "Expired SSL")
	}
	if findings[0].Severity != finding.SeverityHigh {
		t.Errorf("finding[0] Severity = %d, want %d (high)", findings[0].Severity, finding.SeverityHigh)
	}
	if findings[0].Asset != "example.com" {
		t.Errorf("finding[0] Asset = %q, want %q", findings[0].Asset, "example.com")
	}

	// Second finding: missing-csp maps to a known CheckID.
	if findings[1].CheckID != finding.CheckHeadersMissingCSP {
		t.Errorf("finding[1] CheckID = %q, want %q", findings[1].CheckID, finding.CheckHeadersMissingCSP)
	}
}

func TestParseOutput_UnknownTemplate(t *testing.T) {
	input := []byte(`{"template-id":"custom-vuln-xyz","info":{"name":"Custom Vuln","severity":"critical","description":"A custom vulnerability."},"host":"https://target.com","matched-at":"https://target.com/path","timestamp":"2025-01-15T10:00:00Z"}`)

	findings, err := parseOutput("target.com", input)
	if err != nil {
		t.Fatalf("parseOutput returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	// Unknown templates get "nuclei." prefix.
	if findings[0].CheckID != "nuclei.custom-vuln-xyz" {
		t.Errorf("CheckID = %q, want %q", findings[0].CheckID, "nuclei.custom-vuln-xyz")
	}
	if findings[0].Severity != finding.SeverityCritical {
		t.Errorf("Severity = %d, want critical", findings[0].Severity)
	}
}

func TestParseOutput_MalformedJSON(t *testing.T) {
	input := []byte(`not json at all
{"template-id":"expired-ssl","info":{"name":"Expired SSL","severity":"high","description":"desc"},"host":"h","matched-at":"m","timestamp":"2025-01-15T10:00:00Z"}
{broken json
`)

	findings, err := parseOutput("example.com", input)
	if err != nil {
		t.Fatalf("parseOutput returned error for mixed input: %v", err)
	}
	// Should parse the one valid line and skip malformed ones.
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding from mixed input, got %d", len(findings))
	}
	if findings[0].Title != "Expired SSL" {
		t.Errorf("Title = %q, want %q", findings[0].Title, "Expired SSL")
	}
}

func TestParseOutput_EmptyInput(t *testing.T) {
	findings, err := parseOutput("example.com", []byte{})
	if err != nil {
		t.Fatalf("parseOutput returned error for empty input: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty input, got %d", len(findings))
	}
}

func TestParseOutput_EmptyLines(t *testing.T) {
	input := []byte("\n\n\n")
	findings, err := parseOutput("example.com", input)
	if err != nil {
		t.Fatalf("parseOutput returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for blank lines, got %d", len(findings))
	}
}

func TestParseOutput_MissingFields(t *testing.T) {
	// Missing template-id → should be skipped.
	input := []byte(`{"info":{"name":"No Template","severity":"high","description":"d"},"host":"h","matched-at":"m","timestamp":"2025-01-15T10:00:00Z"}
{"template-id":"","info":{"name":"","severity":"high","description":"d"},"host":"h","matched-at":"m","timestamp":"2025-01-15T10:00:00Z"}`)

	findings, err := parseOutput("example.com", input)
	if err != nil {
		t.Fatalf("parseOutput returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for entries with missing required fields, got %d", len(findings))
	}
}

func TestParseOutput_EvidenceFields(t *testing.T) {
	input := []byte(`{"template-id":"test-tmpl","info":{"name":"Test","severity":"info","description":"d"},"host":"h","matched-at":"https://example.com/path","extracted-results":["secret123"],"meta":{"key":"value"},"timestamp":"2025-01-15T10:00:00Z"}`)

	findings, err := parseOutput("example.com", input)
	if err != nil {
		t.Fatalf("parseOutput returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	ev := findings[0].Evidence
	if ev["template_id"] != "test-tmpl" {
		t.Errorf("evidence template_id = %v, want %q", ev["template_id"], "test-tmpl")
	}
	if ev["matched_at"] != "https://example.com/path" {
		t.Errorf("evidence matched_at = %v, want %q", ev["matched_at"], "https://example.com/path")
	}
	extracted, ok := ev["extracted_results"].([]string)
	if !ok || len(extracted) != 1 || extracted[0] != "secret123" {
		t.Errorf("evidence extracted_results = %v, want [secret123]", ev["extracted_results"])
	}
}

// ── TemplateAge tests ──────────────────────────────────────────────────────

func TestTemplateAge_NoTemplateDir(t *testing.T) {
	// With a nonexistent binary and no template dirs, should return -1.
	s := New("/nonexistent/nuclei", "", "")
	age := s.TemplateAge()
	if age != -1 {
		t.Errorf("TemplateAge = %v, want -1 for missing binary", age)
	}
}

func TestTemplateAge_StaleTemplates(t *testing.T) {
	// Create a fake nuclei binary and template dir to test age calculation.
	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "nuclei")
	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Create a template directory with old modification time.
	home := t.TempDir()
	templateDir := filepath.Join(home, ".local", "nuclei-templates")
	if err := os.MkdirAll(templateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Set mtime to 60 days ago.
	oldTime := time.Now().Add(-60 * 24 * time.Hour)
	if err := os.Chtimes(templateDir, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}

	// TemplateAge relies on os.UserHomeDir which we can't easily override,
	// so we test the age math directly: if the dir mtime is 60 days ago,
	// time.Since(mtime) should be >= 59 days.
	info, err := os.Stat(templateDir)
	if err != nil {
		t.Fatal(err)
	}
	age := time.Since(info.ModTime())
	if age < 59*24*time.Hour {
		t.Errorf("expected age >= 59 days, got %v", age)
	}
	if age <= staleTemplateThreshold {
		t.Errorf("expected age > staleTemplateThreshold (%v), got %v", staleTemplateThreshold, age)
	}
}
