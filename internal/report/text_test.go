package report

import (
	"strings"
	"testing"
	"time"

	"github.com/stormbane/beacon/internal/enrichment"
	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/store"
)

func testRun() store.ScanRun {
	completed := time.Date(2026, 3, 22, 11, 0, 0, 0, time.UTC)
	return store.ScanRun{
		ID:          "run-1",
		Domain:      "example.com",
		ScanType:    "surface",
		StartedAt:   time.Date(2026, 3, 22, 10, 0, 0, 0, time.UTC),
		CompletedAt: &completed,
	}
}

func enrichedWith(sev finding.Severity, title, asset string) enrichment.EnrichedFinding {
	return enrichment.EnrichedFinding{
		Finding: finding.Finding{
			CheckID:  "test.check",
			Severity: sev,
			Title:    title,
			Asset:    asset,
		},
		Explanation: "Explanation for " + title,
		Impact:      "Impact for " + title,
		Remediation: "Fix for " + title,
	}
}

// --- RenderText ---

func TestRenderText_ContainsDomain(t *testing.T) {
	out := RenderText(testRun(), nil, "", nil)
	if !strings.Contains(out, "example.com") {
		t.Error("expected domain in text output")
	}
}

func TestRenderText_ContainsSeverityCounts(t *testing.T) {
	findings := []enrichment.EnrichedFinding{
		enrichedWith(finding.SeverityCritical, "Critical Issue", "a.example.com"),
		enrichedWith(finding.SeverityHigh, "High Issue", "b.example.com"),
	}
	out := RenderText(testRun(), findings, "", nil)
	if !strings.Contains(out, "Critical") {
		t.Error("expected Critical in summary")
	}
	if !strings.Contains(out, "High") {
		t.Error("expected High in summary")
	}
}

func TestRenderText_FindingsOrderedBySeverity(t *testing.T) {
	findings := []enrichment.EnrichedFinding{
		enrichedWith(finding.SeverityLow, "Low Issue", "a.example.com"),
		enrichedWith(finding.SeverityCritical, "Critical Issue", "b.example.com"),
	}
	out := RenderText(testRun(), findings, "", nil)
	critIdx := strings.Index(out, "Critical Issue")
	lowIdx := strings.Index(out, "Low Issue")
	if critIdx == -1 || lowIdx == -1 {
		t.Fatal("expected both findings in output")
	}
	if critIdx > lowIdx {
		t.Error("critical finding should appear before low finding")
	}
}

func TestRenderText_NoFindings_ShowsNoFindingsMessage(t *testing.T) {
	out := RenderText(testRun(), nil, "", nil)
	if !strings.Contains(out, "No findings") {
		t.Error("expected 'No findings' message when slice is empty")
	}
}

func TestRenderText_ExplainsEachFinding(t *testing.T) {
	ef := enrichedWith(finding.SeverityMedium, "Medium Issue", "x.example.com")
	ef.Explanation = "Detailed explanation"
	ef.Impact = "Business impact"
	ef.Remediation = "Apply patch"
	out := RenderText(testRun(), []enrichment.EnrichedFinding{ef}, "", nil)
	for _, s := range []string{"Detailed explanation", "Business impact", "Apply patch"} {
		if !strings.Contains(out, s) {
			t.Errorf("expected %q in text output", s)
		}
	}
}

func TestRenderText_IncludesExecutiveSummary(t *testing.T) {
	out := RenderText(testRun(), nil, "This is the summary.", nil)
	if !strings.Contains(out, "EXECUTIVE SUMMARY") {
		t.Error("expected EXECUTIVE SUMMARY header")
	}
	if !strings.Contains(out, "This is the summary.") {
		t.Error("expected summary text in output")
	}
}

func TestRenderText_OmitsExecutiveSummaryWhenEmpty(t *testing.T) {
	out := RenderText(testRun(), nil, "", nil)
	if strings.Contains(out, "EXECUTIVE SUMMARY") {
		t.Error("should not include EXECUTIVE SUMMARY header when summary is empty")
	}
}

func TestRenderText_ComplianceTagsIncluded(t *testing.T) {
	ef := enrichedWith(finding.SeverityHigh, "TLS Issue", "x.example.com")
	ef.ComplianceTags = []string{"PCI-DSS-4.2", "SOC2-CC6.7"}
	out := RenderText(testRun(), []enrichment.EnrichedFinding{ef}, "", nil)
	if !strings.Contains(out, "PCI-DSS-4.2") {
		t.Error("expected compliance tag PCI-DSS-4.2 in output")
	}
}

func TestRenderText_TechSpecificRemediationIncluded(t *testing.T) {
	ef := enrichedWith(finding.SeverityHigh, "Config Issue", "x.example.com")
	ef.TechSpecificRemediation = "Set X-Frame-Options: DENY in nginx.conf"
	out := RenderText(testRun(), []enrichment.EnrichedFinding{ef}, "", nil)
	if !strings.Contains(out, "Set X-Frame-Options") {
		t.Error("expected tech-specific remediation in output")
	}
}

func TestRenderText_DeltaStatusIncluded(t *testing.T) {
	ef := enrichedWith(finding.SeverityMedium, "Old Issue", "x.example.com")
	ef.DeltaStatus = "recurring"
	out := RenderText(testRun(), []enrichment.EnrichedFinding{ef}, "", nil)
	if !strings.Contains(out, "recurring") {
		t.Error("expected delta status 'recurring' in output")
	}
}

func TestRenderText_CompletedAtShown(t *testing.T) {
	out := RenderText(testRun(), nil, "", nil)
	if !strings.Contains(out, "2026-03-22 11:00") {
		t.Error("expected completed-at timestamp in output")
	}
}

// --- wordWrap ---

func TestWordWrap_ShortTextFitsOnOneLine(t *testing.T) {
	out := wordWrap("hello world", 80, "  ")
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 1 {
		t.Errorf("expected 1 line, got %d: %q", len(lines), out)
	}
}

func TestWordWrap_LongTextWraps(t *testing.T) {
	// 5 words of 10 chars each = 54 chars with spaces; maxWidth=20 forces wrapping
	out := wordWrap("abcdefghij abcdefghij abcdefghij abcdefghij", 20, "")
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) < 2 {
		t.Errorf("expected wrapping to multiple lines, got %d: %q", len(lines), out)
	}
}

func TestWordWrap_IndentAppliedToAllLines(t *testing.T) {
	out := wordWrap("one two three four five six seven eight nine ten eleven", 20, ">> ")
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if !strings.HasPrefix(line, ">> ") {
			t.Errorf("line missing indent: %q", line)
		}
	}
}

func TestWordWrap_EmptyStringReturnsEmpty(t *testing.T) {
	if wordWrap("", 80, "  ") != "" {
		t.Error("expected empty string for empty input")
	}
}

// --- countSeverities ---

func TestCountSeverities_CountsCorrectly(t *testing.T) {
	findings := []enrichment.EnrichedFinding{
		enrichedWith(finding.SeverityCritical, "C1", "a"),
		enrichedWith(finding.SeverityCritical, "C2", "a"),
		enrichedWith(finding.SeverityHigh, "H1", "a"),
		enrichedWith(finding.SeverityInfo, "I1", "a"),
	}
	counts := countSeverities(findings)
	if counts[finding.SeverityCritical] != 2 {
		t.Errorf("expected 2 critical, got %d", counts[finding.SeverityCritical])
	}
	if counts[finding.SeverityHigh] != 1 {
		t.Errorf("expected 1 high, got %d", counts[finding.SeverityHigh])
	}
	if counts[finding.SeverityMedium] != 0 {
		t.Errorf("expected 0 medium, got %d", counts[finding.SeverityMedium])
	}
}

func TestCountSeverities_EmptySlice(t *testing.T) {
	counts := countSeverities(nil)
	if counts[finding.SeverityCritical] != 0 {
		t.Error("expected zero counts for empty slice")
	}
}
