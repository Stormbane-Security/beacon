package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stormbane-security/beacon/internal/enrichment"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/store"
)

// sampleFindings returns a mix of severities for testing reports.
func sampleFindings() []enrichment.EnrichedFinding {
	return []enrichment.EnrichedFinding{
		{
			Finding: finding.Finding{
				CheckID:      "web.cors_wildcard",
				Severity:     finding.SeverityCritical,
				Title:        "CORS Wildcard Origin",
				Asset:        "api.example.com",
				Description:  "The server responds with Access-Control-Allow-Origin: * allowing any origin.",
				ProofCommand: "curl -sI -H 'Origin: https://evil.com' https://api.example.com/",
				Evidence: map[string]any{
					"url":    "https://api.example.com/data",
					"origin": "*",
				},
			},
			Explanation: "CORS wildcard allows credential theft from any origin.",
			Impact:      "Attacker can read API responses cross-origin.",
			Remediation: "Set Access-Control-Allow-Origin to specific trusted origins.",
		},
		{
			Finding: finding.Finding{
				CheckID:      "tls.weak_cipher",
				Severity:     finding.SeverityHigh,
				Title:        "Weak TLS Cipher Suite",
				Asset:        "www.example.com",
				Description:  "Server supports CBC-mode cipher suites vulnerable to BEAST/Lucky13.",
				ProofCommand: "nmap --script ssl-enum-ciphers -p 443 www.example.com",
			},
			Explanation: "Weak cipher suites allow potential downgrade attacks.",
			Impact:      "Traffic may be decrypted by a network attacker.",
			Remediation: "Disable CBC-mode ciphers; use AEAD only.",
			ComplianceTags: []string{"PCI-DSS-4.2", "SOC2-CC6.7"},
		},
		{
			Finding: finding.Finding{
				CheckID:  "http.missing_hsts",
				Severity: finding.SeverityMedium,
				Title:    "Missing HSTS Header",
				Asset:    "www.example.com",
			},
			Explanation: "No Strict-Transport-Security header.",
			Remediation: "Add HSTS header with max-age >= 31536000.",
		},
		{
			Finding: finding.Finding{
				CheckID:  "http.server_header",
				Severity: finding.SeverityLow,
				Title:    "Server Version Disclosed",
				Asset:    "www.example.com",
			},
			Explanation: "Server header reveals version information.",
		},
		{
			Finding: finding.Finding{
				CheckID:  "dns.caa_missing",
				Severity: finding.SeverityInfo,
				Title:    "No CAA Record",
				Asset:    "example.com",
			},
			Explanation: "No CAA DNS record limits certificate issuance.",
		},
	}
}

// --- RenderEnhancedMarkdown comprehensive test ---

func TestPDFReport_RenderEnhancedMarkdown_AllSections(t *testing.T) {
	t.Parallel()
	run := testRun()
	findings := sampleFindings()

	md := RenderEnhancedMarkdown(run, findings, "5 findings across 3 assets.", nil, "screenshots")

	// Title
	if !strings.Contains(md, "# Beacon Security Report") {
		t.Error("missing report title")
	}
	if !strings.Contains(md, "example.com") {
		t.Error("missing domain in title")
	}

	// Executive Summary
	if !strings.Contains(md, "## Executive Summary") {
		t.Error("missing Executive Summary section")
	}
	if !strings.Contains(md, "5 findings across 3 assets.") {
		t.Error("missing summary text")
	}

	// Severity count table
	if !strings.Contains(md, "| Severity | Count |") {
		t.Error("missing severity count table")
	}

	// Table of Contents
	if !strings.Contains(md, "## Table of Contents") {
		t.Error("missing Table of Contents")
	}
	if !strings.Contains(md, "CORS Wildcard Origin") {
		t.Error("missing finding title in TOC")
	}

	// Findings section
	if !strings.Contains(md, "## Findings") {
		t.Error("missing Findings section")
	}

	// Evidence table
	if !strings.Contains(md, "#### Evidence") {
		t.Error("missing Evidence section for finding with evidence")
	}

	// Proof command
	if !strings.Contains(md, "#### Proof Command") {
		t.Error("missing Proof Command section")
	}
	if !strings.Contains(md, "curl -sI") {
		t.Error("missing proof command content")
	}

	// Remediation
	if !strings.Contains(md, "#### Remediation") {
		t.Error("missing Remediation section")
	}

	// Compliance tags
	if !strings.Contains(md, "PCI-DSS-4.2") {
		t.Error("missing compliance tag")
	}

	// Screenshot references
	if !strings.Contains(md, "![Screenshot for") {
		t.Error("missing screenshot references")
	}

	// Appendix
	if !strings.Contains(md, "## Appendix: Scan Metadata") {
		t.Error("missing Appendix section")
	}

	// Severity ordering: critical should appear before info
	critIdx := strings.Index(md, "CORS Wildcard Origin")
	infoIdx := strings.Index(md, "No CAA Record")
	if critIdx == -1 || infoIdx == -1 {
		t.Fatal("expected both critical and info findings")
	}
	if critIdx > infoIdx {
		t.Error("critical finding should appear before info finding")
	}
}

func TestPDFReport_RenderEnhancedMarkdown_NoFindings(t *testing.T) {
	t.Parallel()
	md := RenderEnhancedMarkdown(testRun(), nil, "Clean scan.", nil, "")
	if !strings.Contains(md, "No findings") {
		t.Error("expected 'No findings' message for empty results")
	}
	if !strings.Contains(md, "**0**") {
		t.Error("expected zero total count")
	}
}

// --- markdownToHTML ---

func TestPDFReport_MarkdownToHTML_FullDocument(t *testing.T) {
	t.Parallel()
	run := testRun()
	findings := sampleFindings()
	md := RenderEnhancedMarkdown(run, findings, "Test summary.", nil, "")

	html := markdownToHTML(md, run.Domain)

	// Valid HTML structure
	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Error("missing DOCTYPE")
	}
	if !strings.Contains(html, "<html>") {
		t.Error("missing html tag")
	}
	if !strings.Contains(html, "</html>") {
		t.Error("missing closing html tag")
	}
	if !strings.Contains(html, "<head>") {
		t.Error("missing head tag")
	}
	if !strings.Contains(html, "<body>") {
		t.Error("missing body tag")
	}
	if !strings.Contains(html, "</body>") {
		t.Error("missing closing body tag")
	}

	// Domain in title
	if !strings.Contains(html, "example.com") {
		t.Error("missing domain in HTML title")
	}

	// CSS styles present
	if !strings.Contains(html, "<style>") {
		t.Error("missing style block")
	}
	if !strings.Contains(html, "badge-critical") {
		t.Error("missing severity badge CSS")
	}

	// Content converted
	if !strings.Contains(html, "<h1>") {
		t.Error("missing h1 from markdown conversion")
	}
	if !strings.Contains(html, "<h2") {
		t.Error("missing h2 from markdown conversion")
	}
	if !strings.Contains(html, "<table>") {
		t.Error("missing table from markdown conversion")
	}
}

func TestPDFReport_MarkdownToHTML_SeverityBadges(t *testing.T) {
	t.Parallel()
	md := "Some text with \U0001f534 and \U0001f7e0 badges.\n"
	html := markdownToHTML(md, "")

	if !strings.Contains(html, `class="badge-critical"`) {
		t.Error("expected critical badge span")
	}
	if !strings.Contains(html, `class="badge-high"`) {
		t.Error("expected high badge span")
	}
	if !strings.Contains(html, "CRITICAL") {
		t.Error("expected CRITICAL label text")
	}
}

func TestPDFReport_MarkdownToHTML_CodeBlocks(t *testing.T) {
	t.Parallel()
	md := "```sh\ncurl -sI https://example.com\n```\n"
	html := markdownToHTML(md, "")

	if !strings.Contains(html, "<pre><code>") {
		t.Error("expected pre/code block")
	}
	if !strings.Contains(html, "curl") {
		t.Error("expected command in code block")
	}
}

func TestPDFReport_MarkdownToHTML_Tables(t *testing.T) {
	t.Parallel()
	md := "| Key | Value |\n|-----|-------|\n| foo | bar |\n| baz | qux |\n"
	html := markdownToHTML(md, "")

	if !strings.Contains(html, "<table>") {
		t.Error("expected table tag")
	}
	if !strings.Contains(html, "<thead>") {
		t.Error("expected thead")
	}
	if !strings.Contains(html, "<tbody>") {
		t.Error("expected tbody")
	}
	if strings.Count(html, "<th>") != 2 {
		t.Errorf("expected 2 th tags, got %d", strings.Count(html, "<th>"))
	}
	if strings.Count(html, "<td>") != 4 {
		t.Errorf("expected 4 td tags, got %d", strings.Count(html, "<td>"))
	}
}

func TestPDFReport_MarkdownToHTML_InlineFormatting(t *testing.T) {
	t.Parallel()
	md := "Some **bold** and `code` text.\n"
	html := markdownToHTML(md, "")

	if !strings.Contains(html, "<strong>bold</strong>") {
		t.Error("expected bold tag")
	}
	if !strings.Contains(html, "<code>code</code>") {
		t.Error("expected code tag")
	}
}

func TestPDFReport_MarkdownToHTML_Images(t *testing.T) {
	t.Parallel()
	md := "![Screenshot](screenshots/finding-000-test.png)\n"
	html := markdownToHTML(md, "")

	if !strings.Contains(html, "<img") {
		t.Error("expected img tag")
	}
	if !strings.Contains(html, `src="screenshots/finding-000-test.png"`) {
		t.Error("expected correct image src")
	}
}

func TestPDFReport_MarkdownToHTML_HorizontalRule(t *testing.T) {
	t.Parallel()
	md := "Above\n---\nBelow\n"
	html := markdownToHTML(md, "")

	if !strings.Contains(html, "<hr>") {
		t.Error("expected hr tag")
	}
}

// --- ScreenshotFilename ---

func TestPDFReport_ScreenshotFilename_Generation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		index   int
		checkID finding.CheckID
		want    string
	}{
		{0, "web.cors_wildcard", "finding-000-web-cors_wildcard.png"},
		{1, "tls.weak_cipher", "finding-001-tls-weak_cipher.png"},
		{42, "http.missing_hsts", "finding-042-http-missing_hsts.png"},
		{100, "dns.caa_missing", "finding-100-dns-caa_missing.png"},
	}
	for _, tt := range tests {
		got := ScreenshotFilename(tt.index, tt.checkID)
		if got != tt.want {
			t.Errorf("ScreenshotFilename(%d, %q) = %q, want %q", tt.index, tt.checkID, got, tt.want)
		}
	}
}

func TestPDFReport_ScreenshotFilename_HasPNGExtension(t *testing.T) {
	t.Parallel()
	name := ScreenshotFilename(5, "web.xss")
	if !strings.HasSuffix(name, ".png") {
		t.Errorf("expected .png extension, got %q", name)
	}
}

func TestPDFReport_ScreenshotFilename_HasFindingPrefix(t *testing.T) {
	t.Parallel()
	name := ScreenshotFilename(0, "test.check")
	if !strings.HasPrefix(name, "finding-") {
		t.Errorf("expected finding- prefix, got %q", name)
	}
}

// --- RenderPDF (requires Chrome) ---

func TestPDFReport_RenderPDF_IfChromeAvailable(t *testing.T) {
	if !ChromeAvailable() {
		t.Skip("Chrome not available, skipping PDF rendering test")
	}
	t.Parallel()

	run := testRun()
	findings := sampleFindings()

	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "report.pdf")

	err := RenderPDF(run, findings, "Test summary.", nil, "", outPath)
	if err != nil {
		t.Fatalf("RenderPDF failed: %v", err)
	}

	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("PDF file not created: %v", err)
	}
	if info.Size() == 0 {
		t.Error("PDF file is empty")
	}
	// A real PDF should be at least a few KB
	if info.Size() < 1024 {
		t.Errorf("PDF file suspiciously small: %d bytes", info.Size())
	}
}

func TestPDFReport_RenderPDF_FallbackWithoutChrome(t *testing.T) {
	if ChromeAvailable() {
		t.Skip("Chrome is available, skipping fallback test")
	}
	t.Parallel()

	run := testRun()
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "report.pdf")

	err := RenderPDF(run, nil, "", nil, "", outPath)
	if err == nil {
		t.Fatal("expected error when Chrome is not available")
	}
	if !strings.Contains(err.Error(), "Chrome") {
		t.Errorf("error should mention Chrome: %v", err)
	}

	// Should have written a markdown fallback
	mdPath := filepath.Join(tmpDir, "report.md")
	if _, statErr := os.Stat(mdPath); statErr != nil {
		t.Error("expected markdown fallback file to be created")
	}
}

// --- RenderMarkdown with AssetExecution ---

func TestPDFReport_RenderMarkdown_AssetInventory(t *testing.T) {
	t.Parallel()
	findings := sampleFindings()
	execs := []store.AssetExecution{
		{Asset: "api.example.com", ScannersRun: []string{"cors"}},
		{Asset: "www.example.com", ScannersRun: []string{"tls"}},
		{Asset: "clean.example.com", ScannersRun: []string{"tls"}},
	}
	md := RenderMarkdown(testRun(), findings, "", execs)
	if !strings.Contains(md, "## Asset Inventory") {
		t.Error("expected Asset Inventory section")
	}
}
