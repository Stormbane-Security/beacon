package report

import (
	"strings"
	"testing"

	"github.com/stormbane/beacon/internal/enrichment"
	"github.com/stormbane/beacon/internal/finding"
)

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
