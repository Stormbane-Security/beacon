package report

import (
	"strings"
	"testing"

	"github.com/stormbane-security/beacon/internal/enrichment"
	"github.com/stormbane-security/beacon/internal/finding"
)

// --- RenderMarkdown (original) ---

func TestRenderMarkdown_ContainsDomain(t *testing.T) {
	out := RenderMarkdown(testRun(), nil, "", nil)
	if !strings.Contains(out, "example.com") {
		t.Error("expected domain in markdown output")
	}
}

func TestRenderMarkdown_ContainsH1Title(t *testing.T) {
	out := RenderMarkdown(testRun(), nil, "", nil)
	if !strings.Contains(out, "# Beacon Security Report") {
		t.Error("expected H1 title in markdown output")
	}
}

func TestRenderMarkdown_SeverityTable(t *testing.T) {
	findings := []enrichment.EnrichedFinding{
		enrichedWith(finding.SeverityCritical, "Crit", "a"),
		enrichedWith(finding.SeverityHigh, "High", "b"),
	}
	out := RenderMarkdown(testRun(), findings, "", nil)
	if !strings.Contains(out, "| Critical |") {
		t.Error("expected Critical row in severity table")
	}
	if !strings.Contains(out, "| High     |") {
		t.Error("expected High row in severity table")
	}
}

func TestRenderMarkdown_FindingsOrderedBySeverity(t *testing.T) {
	findings := []enrichment.EnrichedFinding{
		enrichedWith(finding.SeverityInfo, "Info Issue", "a"),
		enrichedWith(finding.SeverityCritical, "Critical Issue", "b"),
	}
	out := RenderMarkdown(testRun(), findings, "", nil)
	critIdx := strings.Index(out, "Critical Issue")
	infoIdx := strings.Index(out, "Info Issue")
	if critIdx == -1 || infoIdx == -1 {
		t.Fatal("expected both findings in output")
	}
	if critIdx > infoIdx {
		t.Error("critical finding should appear before info finding")
	}
}

func TestRenderMarkdown_NoFindings_ShowsNoFindingsMessage(t *testing.T) {
	out := RenderMarkdown(testRun(), nil, "", nil)
	if !strings.Contains(out, "No findings") {
		t.Error("expected 'No findings' when slice is empty")
	}
}

func TestRenderMarkdown_ExplainsEachFinding(t *testing.T) {
	ef := enrichedWith(finding.SeverityMedium, "Med Issue", "x.example.com")
	ef.Explanation = "Unique explanation text"
	ef.Impact = "Unique impact text"
	ef.Remediation = "Unique remediation text"
	out := RenderMarkdown(testRun(), []enrichment.EnrichedFinding{ef}, "", nil)
	for _, s := range []string{"Unique explanation text", "Unique impact text", "Unique remediation text"} {
		if !strings.Contains(out, s) {
			t.Errorf("expected %q in markdown output", s)
		}
	}
}

func TestRenderMarkdown_ExecutiveSummarySection(t *testing.T) {
	out := RenderMarkdown(testRun(), nil, "Summary: all good.", nil)
	if !strings.Contains(out, "## Executive Summary") {
		t.Error("expected ## Executive Summary heading")
	}
	if !strings.Contains(out, "Summary: all good.") {
		t.Error("expected summary text in output")
	}
}

func TestRenderMarkdown_OmitsExecutiveSummaryWhenEmpty(t *testing.T) {
	out := RenderMarkdown(testRun(), nil, "", nil)
	if strings.Contains(out, "## Executive Summary") {
		t.Error("should not include ## Executive Summary heading when summary is empty")
	}
}

func TestRenderMarkdown_FindingUsesH3(t *testing.T) {
	ef := enrichedWith(finding.SeverityHigh, "My High Finding", "x.example.com")
	out := RenderMarkdown(testRun(), []enrichment.EnrichedFinding{ef}, "", nil)
	if !strings.Contains(out, "### [High] My High Finding") {
		t.Error("expected H3 with severity label and title")
	}
}

func TestRenderMarkdown_ComplianceTagsIncluded(t *testing.T) {
	ef := enrichedWith(finding.SeverityMedium, "TLS Issue", "x.example.com")
	ef.ComplianceTags = []string{"SOC2-CC6.7", "PCI-DSS-4.2"}
	out := RenderMarkdown(testRun(), []enrichment.EnrichedFinding{ef}, "", nil)
	if !strings.Contains(out, "SOC2-CC6.7") {
		t.Error("expected compliance tag SOC2-CC6.7 in markdown output")
	}
}

func TestRenderMarkdown_DeltaStatusIncluded(t *testing.T) {
	ef := enrichedWith(finding.SeverityLow, "Recurring Issue", "x.example.com")
	ef.DeltaStatus = "recurring"
	out := RenderMarkdown(testRun(), []enrichment.EnrichedFinding{ef}, "", nil)
	if !strings.Contains(out, "recurring") {
		t.Error("expected delta status in markdown output")
	}
}

func TestRenderMarkdown_FindingSeparator(t *testing.T) {
	findings := []enrichment.EnrichedFinding{
		enrichedWith(finding.SeverityHigh, "A", "x"),
		enrichedWith(finding.SeverityHigh, "B", "y"),
	}
	out := RenderMarkdown(testRun(), findings, "", nil)
	// Each finding ends with "---" separator
	if strings.Count(out, "\n---\n") < 2 {
		t.Error("expected at least 2 finding separators (---)")
	}
}

// --- RenderEnhancedMarkdown ---

func TestEnhancedMarkdown_AllSeverityLevels(t *testing.T) {
	findings := []enrichment.EnrichedFinding{
		enrichedWith(finding.SeverityCritical, "Critical Bug", "a.example.com"),
		enrichedWith(finding.SeverityHigh, "High Bug", "b.example.com"),
		enrichedWith(finding.SeverityMedium, "Medium Bug", "c.example.com"),
		enrichedWith(finding.SeverityLow, "Low Bug", "d.example.com"),
		enrichedWith(finding.SeverityInfo, "Info Note", "e.example.com"),
	}
	out := RenderEnhancedMarkdown(testRun(), findings, "Test summary.", nil, "")

	// Severity badges (emoji)
	for _, badge := range []string{
		"\U0001f534 Critical",
		"\U0001f7e0 High",
		"\U0001f7e1 Medium",
		"\U0001f535 Low",
		"\u26aa Info",
	} {
		if !strings.Contains(out, badge) {
			t.Errorf("expected severity badge %q in enhanced markdown", badge)
		}
	}
}

func TestEnhancedMarkdown_TableOfContents(t *testing.T) {
	findings := []enrichment.EnrichedFinding{
		enrichedWith(finding.SeverityHigh, "XSS Vulnerability", "a.example.com"),
		enrichedWith(finding.SeverityMedium, "Missing Header", "b.example.com"),
	}
	out := RenderEnhancedMarkdown(testRun(), findings, "", nil, "")

	if !strings.Contains(out, "## Table of Contents") {
		t.Error("expected Table of Contents heading")
	}
	if !strings.Contains(out, "XSS Vulnerability") {
		t.Error("expected finding title in TOC")
	}
	if !strings.Contains(out, "#finding-") {
		t.Error("expected anchor links in TOC")
	}
}

func TestEnhancedMarkdown_EvidenceTable(t *testing.T) {
	ef := enrichedWith(finding.SeverityHigh, "CORS Misconfig", "a.example.com")
	ef.Finding.Evidence = map[string]any{
		"url":    "https://a.example.com/api",
		"method": "GET",
		"origin": "https://evil.com",
	}
	out := RenderEnhancedMarkdown(testRun(), []enrichment.EnrichedFinding{ef}, "", nil, "")

	if !strings.Contains(out, "#### Evidence") {
		t.Error("expected Evidence heading")
	}
	if !strings.Contains(out, "| Key | Value |") {
		t.Error("expected evidence table header")
	}
	if !strings.Contains(out, "`url`") {
		t.Error("expected evidence key 'url' in table")
	}
}

func TestEnhancedMarkdown_ScreenshotEmbedding(t *testing.T) {
	ef := enrichedWith(finding.SeverityHigh, "Open Redirect", "a.example.com")
	out := RenderEnhancedMarkdown(testRun(), []enrichment.EnrichedFinding{ef}, "", nil, "screenshots")

	if !strings.Contains(out, "![Screenshot for Open Redirect](screenshots/") {
		t.Error("expected screenshot image reference in markdown")
	}
	if !strings.Contains(out, ".png)") {
		t.Error("expected .png extension in screenshot path")
	}
}

func TestEnhancedMarkdown_NoScreenshotWhenDirEmpty(t *testing.T) {
	ef := enrichedWith(finding.SeverityHigh, "Open Redirect", "a.example.com")
	out := RenderEnhancedMarkdown(testRun(), []enrichment.EnrichedFinding{ef}, "", nil, "")

	if strings.Contains(out, "![Screenshot") {
		t.Error("should not include screenshot references when screenshotDir is empty")
	}
}

func TestEnhancedMarkdown_ProofCommand(t *testing.T) {
	ef := enrichedWith(finding.SeverityMedium, "Missing HSTS", "a.example.com")
	ef.Finding.ProofCommand = "curl -sI https://a.example.com | grep Strict"
	out := RenderEnhancedMarkdown(testRun(), []enrichment.EnrichedFinding{ef}, "", nil, "")

	if !strings.Contains(out, "#### Proof Command") {
		t.Error("expected Proof Command heading")
	}
	if !strings.Contains(out, "```sh") {
		t.Error("expected code block for proof command")
	}
	if !strings.Contains(out, "curl -sI") {
		t.Error("expected proof command text")
	}
}

func TestEnhancedMarkdown_Remediation(t *testing.T) {
	ef := enrichedWith(finding.SeverityMedium, "Weak TLS", "a.example.com")
	ef.Remediation = "Upgrade to TLS 1.3"
	ef.TechSpecificRemediation = "Set ssl_protocols TLSv1.3 in nginx.conf"
	out := RenderEnhancedMarkdown(testRun(), []enrichment.EnrichedFinding{ef}, "", nil, "")

	if !strings.Contains(out, "#### Remediation") {
		t.Error("expected Remediation heading")
	}
	if !strings.Contains(out, "Upgrade to TLS 1.3") {
		t.Error("expected remediation text")
	}
	if !strings.Contains(out, "Tech-specific fix:") {
		t.Error("expected tech-specific remediation")
	}
}

func TestEnhancedMarkdown_AppendixMetadata(t *testing.T) {
	out := RenderEnhancedMarkdown(testRun(), nil, "", nil, "")

	if !strings.Contains(out, "## Appendix: Scan Metadata") {
		t.Error("expected Appendix heading")
	}
	if !strings.Contains(out, "example.com") {
		t.Error("expected domain in appendix")
	}
	if !strings.Contains(out, "surface") {
		t.Error("expected scan type in appendix")
	}
	if !strings.Contains(out, "Duration") {
		t.Error("expected duration in appendix")
	}
}

func TestEnhancedMarkdown_ExecutiveSummary(t *testing.T) {
	out := RenderEnhancedMarkdown(testRun(), nil, "Everything is secure.", nil, "")

	if !strings.Contains(out, "## Executive Summary") {
		t.Error("expected Executive Summary heading")
	}
	if !strings.Contains(out, "Everything is secure.") {
		t.Error("expected summary text")
	}
}

func TestEnhancedMarkdown_SeverityCountTable(t *testing.T) {
	findings := []enrichment.EnrichedFinding{
		enrichedWith(finding.SeverityCritical, "C1", "a"),
		enrichedWith(finding.SeverityCritical, "C2", "a"),
		enrichedWith(finding.SeverityHigh, "H1", "a"),
	}
	out := RenderEnhancedMarkdown(testRun(), findings, "", nil, "")

	// The total row should show 3
	if !strings.Contains(out, "**3**") {
		t.Error("expected total count of 3")
	}
}

func TestEnhancedMarkdown_OmittedFindingsFiltered(t *testing.T) {
	ef1 := enrichedWith(finding.SeverityHigh, "Visible", "a.example.com")
	ef2 := enrichedWith(finding.SeverityHigh, "Hidden", "b.example.com")
	ef2.Omit = true
	out := RenderEnhancedMarkdown(testRun(), []enrichment.EnrichedFinding{ef1, ef2}, "", nil, "")

	if !strings.Contains(out, "Visible") {
		t.Error("expected visible finding")
	}
	if strings.Contains(out, "Hidden") {
		t.Error("omitted finding should be filtered out")
	}
}

func TestEnhancedMarkdown_FindingsOrderedBySeverity(t *testing.T) {
	findings := []enrichment.EnrichedFinding{
		enrichedWith(finding.SeverityInfo, "Info Thing", "a"),
		enrichedWith(finding.SeverityCritical, "Critical Thing", "b"),
	}
	out := RenderEnhancedMarkdown(testRun(), findings, "", nil, "")
	critIdx := strings.Index(out, "Critical Thing")
	infoIdx := strings.Index(out, "Info Thing")
	if critIdx == -1 || infoIdx == -1 {
		t.Fatal("expected both findings")
	}
	if critIdx > infoIdx {
		t.Error("critical should appear before info")
	}
}

// --- ScreenshotFilename ---

func TestScreenshotFilename_Format(t *testing.T) {
	name := ScreenshotFilename(0, "web.cors_wildcard")
	if name != "finding-000-web-cors_wildcard.png" {
		t.Errorf("unexpected filename: %s", name)
	}
}

func TestScreenshotFilename_IndexPadding(t *testing.T) {
	name := ScreenshotFilename(42, "tls.weak_cipher")
	if !strings.HasPrefix(name, "finding-042-") {
		t.Errorf("expected zero-padded index: %s", name)
	}
}

// --- slugify ---

func TestSlugify(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"Hello World", "hello-world"},
		{"Critical -- Bug", "critical-bug"},
		{"test.check_id", "testcheckid"},
		{"", ""},
	}
	for _, tt := range tests {
		got := slugify(tt.input)
		if got != tt.want {
			t.Errorf("slugify(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// --- markdownToHTML ---

func TestMarkdownToHTML_ContainsHTMLStructure(t *testing.T) {
	md := "# Test Report\n\nSome text.\n"
	html := markdownToHTML(md, "example.com")

	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Error("expected DOCTYPE")
	}
	if !strings.Contains(html, "<h1>") {
		t.Error("expected h1 tag")
	}
	if !strings.Contains(html, "example.com") {
		t.Error("expected domain in title")
	}
}

func TestMarkdownToHTML_CodeBlock(t *testing.T) {
	md := "```sh\ncurl -sI https://example.com\n```\n"
	html := markdownToHTML(md, "")

	if !strings.Contains(html, "<pre><code>") {
		t.Error("expected pre/code block")
	}
	if !strings.Contains(html, "curl") {
		t.Error("expected command content")
	}
}

func TestMarkdownToHTML_Table(t *testing.T) {
	md := "| Key | Value |\n|-----|-------|\n| foo | bar |\n"
	html := markdownToHTML(md, "")

	if !strings.Contains(html, "<table>") {
		t.Error("expected table tag")
	}
	if !strings.Contains(html, "<th>") {
		t.Error("expected th tag")
	}
	if !strings.Contains(html, "<td>") {
		t.Error("expected td tag")
	}
}
