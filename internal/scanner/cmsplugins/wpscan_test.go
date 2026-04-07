package cmsplugins

import (
	"context"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
)

func TestRunWPScan_SkipsWhenBinEmpty(t *testing.T) {
	t.Parallel()
	findings, err := runWPScan(context.Background(), "https://example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Error("expected no findings when wpscanBin is empty")
	}
}

func TestRunWPScan_SkipsWhenBinNotFound(t *testing.T) {
	t.Parallel()
	findings, err := runWPScan(context.Background(), "https://example.com", "wpscan-nonexistent-binary-12345")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Error("expected no findings when wpscan binary not in PATH")
	}
}

func TestParseWPScanOutput_VulnerablePlugin(t *testing.T) {
	t.Parallel()
	jsonData := []byte(`{
		"plugins": {
			"elementor": {
				"slug": "elementor",
				"version": {"number": "3.18.0"},
				"vulnerabilities": [
					{
						"title": "Elementor < 3.18.2 - RCE via File Upload",
						"references": {
							"cve": ["CVE-2023-48777"],
							"url": ["https://wpscan.com/vulnerability/123"]
						}
					}
				]
			}
		},
		"themes": {},
		"users": []
	}`)

	findings, err := parseWPScanOutput(jsonData, "https://example.com")
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.CheckID != finding.CheckCMSPluginVulnerable {
		t.Errorf("check ID = %q, want %q", f.CheckID, finding.CheckCMSPluginVulnerable)
	}
	if f.Severity != finding.SeverityHigh {
		t.Errorf("severity = %v, want High", f.Severity)
	}
	if f.Evidence["plugin"] != "elementor" {
		t.Errorf("evidence plugin = %v, want elementor", f.Evidence["plugin"])
	}
	if f.Asset != "example.com" {
		t.Errorf("asset = %q, want example.com", f.Asset)
	}
}

func TestParseWPScanOutput_VulnerableTheme(t *testing.T) {
	t.Parallel()
	jsonData := []byte(`{
		"plugins": {},
		"themes": {
			"twentytwentyone": {
				"slug": "twentytwentyone",
				"version": {"number": "1.8"},
				"vulnerabilities": [
					{
						"title": "Twenty Twenty-One < 1.9 - Stored XSS",
						"references": {
							"cve": ["CVE-2023-99999"],
							"url": []
						}
					}
				]
			}
		},
		"users": []
	}`)

	findings, err := parseWPScanOutput(jsonData, "https://example.com")
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Evidence["theme"] != "twentytwentyone" {
		t.Errorf("evidence theme = %v, want twentytwentyone", findings[0].Evidence["theme"])
	}
}

func TestParseWPScanOutput_UserEnumeration(t *testing.T) {
	t.Parallel()
	jsonData := []byte(`{
		"plugins": {},
		"themes": {},
		"users": [
			{"id": 1, "slug": "admin"},
			{"id": 2, "slug": "editor"}
		]
	}`)

	findings, err := parseWPScanOutput(jsonData, "https://blog.example.com")
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for user enumeration, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != finding.SeverityMedium {
		t.Errorf("severity = %v, want Medium", f.Severity)
	}
	if f.Evidence["user_count"] != 2 {
		t.Errorf("user_count = %v, want 2", f.Evidence["user_count"])
	}
}

func TestParseWPScanOutput_NoVulnerabilities(t *testing.T) {
	t.Parallel()
	jsonData := []byte(`{
		"plugins": {
			"akismet": {
				"slug": "akismet",
				"version": {"number": "5.0"},
				"vulnerabilities": []
			}
		},
		"themes": {},
		"users": []
	}`)

	findings, err := parseWPScanOutput(jsonData, "https://example.com")
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean scan, got %d", len(findings))
	}
}

func TestParseWPScanOutput_InvalidJSON(t *testing.T) {
	t.Parallel()
	_, err := parseWPScanOutput([]byte("not json"), "https://example.com")
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestExtractWPScanHost(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		want  string
	}{
		{"https://example.com/wp-admin", "example.com"},
		{"http://blog.example.com:8080/", "blog.example.com:8080"},
		{"example.com", "example.com"},
	}
	for _, tt := range tests {
		got := extractWPScanHost(tt.input)
		if got != tt.want {
			t.Errorf("extractWPScanHost(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
