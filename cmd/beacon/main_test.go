package main

import (
	"strings"
	"testing"
	"time"

	"github.com/stormbane/beacon/internal/enrichment"
	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/store"
)

// --- helpers ---

func ef(sev finding.Severity, title string) enrichment.EnrichedFinding {
	return enrichment.EnrichedFinding{
		Finding: finding.Finding{
			Severity: sev,
			Title:    title,
			CheckID:  "test.check",
			Asset:    "example.com",
		},
	}
}

func scanRun() store.ScanRun {
	c := time.Now()
	return store.ScanRun{
		ID:          "run-1",
		Domain:      "example.com",
		ScanType:    "surface",
		StartedAt:   time.Now(),
		CompletedAt: &c,
	}
}

func fakeReport() *store.Report {
	return &store.Report{
		ScanRunID:   "run-1",
		Domain:      "example.com",
		HTMLContent: "<html>report</html>",
		Summary:     "summary",
	}
}

// --- filterBySeverity ---

func TestFilterBySeverity_EmptyFlag_ReturnsAll(t *testing.T) {
	in := []enrichment.EnrichedFinding{
		ef(finding.SeverityInfo, "info"),
		ef(finding.SeverityLow, "low"),
		ef(finding.SeverityCritical, "crit"),
	}
	out := filterBySeverity(in, "")
	if len(out) != 3 {
		t.Errorf("expected all 3 findings, got %d", len(out))
	}
}

func TestFilterBySeverity_InfoFlag_ReturnsAll(t *testing.T) {
	in := []enrichment.EnrichedFinding{
		ef(finding.SeverityInfo, "info"),
		ef(finding.SeverityCritical, "crit"),
	}
	out := filterBySeverity(in, "info")
	if len(out) != 2 {
		t.Errorf("expected 2 findings for info filter, got %d", len(out))
	}
}

func TestFilterBySeverity_HighFilter_DropsLowerSeverities(t *testing.T) {
	in := []enrichment.EnrichedFinding{
		ef(finding.SeverityInfo, "info"),
		ef(finding.SeverityLow, "low"),
		ef(finding.SeverityMedium, "medium"),
		ef(finding.SeverityHigh, "high"),
		ef(finding.SeverityCritical, "crit"),
	}
	out := filterBySeverity(in, "high")
	if len(out) != 2 {
		t.Errorf("expected 2 findings (high+critical), got %d", len(out))
	}
	for _, f := range out {
		if f.Finding.Severity < finding.SeverityHigh {
			t.Errorf("unexpected severity %v in filtered results", f.Finding.Severity)
		}
	}
}

func TestFilterBySeverity_CriticalFilter_OnlyRetainsCritical(t *testing.T) {
	in := []enrichment.EnrichedFinding{
		ef(finding.SeverityHigh, "high"),
		ef(finding.SeverityCritical, "crit1"),
		ef(finding.SeverityCritical, "crit2"),
	}
	out := filterBySeverity(in, "critical")
	if len(out) != 2 {
		t.Errorf("expected 2 critical findings, got %d", len(out))
	}
}

func TestFilterBySeverity_UnknownSeverityFlag_ReturnsAll(t *testing.T) {
	// Unknown strings parse to SeverityInfo (the lowest), so nothing is filtered.
	in := []enrichment.EnrichedFinding{
		ef(finding.SeverityInfo, "info"),
		ef(finding.SeverityHigh, "high"),
	}
	out := filterBySeverity(in, "bogus")
	if len(out) != 2 {
		t.Errorf("expected all findings for unknown flag, got %d", len(out))
	}
}

func TestFilterBySeverity_MediumFilter_ExcludesLowAndInfo(t *testing.T) {
	in := []enrichment.EnrichedFinding{
		ef(finding.SeverityInfo, "info"),
		ef(finding.SeverityLow, "low"),
		ef(finding.SeverityMedium, "medium"),
	}
	out := filterBySeverity(in, "medium")
	if len(out) != 1 {
		t.Errorf("expected 1 finding (medium), got %d", len(out))
	}
	if out[0].Finding.Severity != finding.SeverityMedium {
		t.Errorf("expected medium severity, got %v", out[0].Finding.Severity)
	}
}

func TestFilterBySeverity_EmptyInput_ReturnsEmpty(t *testing.T) {
	out := filterBySeverity(nil, "high")
	if len(out) != 0 {
		t.Errorf("expected empty output for nil input, got %d", len(out))
	}
}

// --- renderFormat ---

func TestRenderFormat_DefaultIsText(t *testing.T) {
	out, err := renderFormat("", scanRun(), nil, "", fakeReport(), nil, nil)
	if err != nil {
		t.Fatalf("renderFormat error: %v", err)
	}
	// Text format always contains the ASCII border characters
	if !strings.Contains(out, "BEACON SECURITY REPORT") {
		t.Error("default format should be text; expected 'BEACON SECURITY REPORT'")
	}
}

func TestRenderFormat_TextExplicit(t *testing.T) {
	out, err := renderFormat("text", scanRun(), nil, "", fakeReport(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "BEACON SECURITY REPORT") {
		t.Error("expected text report header")
	}
}

func TestRenderFormat_HTML_ReturnsFakeHTMLContent(t *testing.T) {
	out, err := renderFormat("html", scanRun(), nil, "", fakeReport(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out != "<html>report</html>" {
		t.Errorf("expected HTML content from report, got %q", out)
	}
}

func TestRenderFormat_JSON_IsValidJSON(t *testing.T) {
	import_json := func(s string) bool {
		return len(s) > 0 && s[0] == '{'
	}
	out, err := renderFormat("json", scanRun(), nil, "", fakeReport(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !import_json(out) {
		t.Errorf("expected JSON object, got %q", out[:min(30, len(out))])
	}
}

func TestRenderFormat_Markdown_ContainsH1(t *testing.T) {
	out, err := renderFormat("markdown", scanRun(), nil, "", fakeReport(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "# Beacon Security Report") {
		t.Error("expected markdown H1 header")
	}
}

func TestRenderFormat_MarkdownAlias_md(t *testing.T) {
	out, err := renderFormat("md", scanRun(), nil, "", fakeReport(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "# Beacon Security Report") {
		t.Error("'md' alias should render markdown")
	}
}

func TestRenderFormat_CaseInsensitive(t *testing.T) {
	out, err := renderFormat("JSON", scanRun(), nil, "", fakeReport(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 || out[0] != '{' {
		t.Error("format flag should be case-insensitive; expected JSON output")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
