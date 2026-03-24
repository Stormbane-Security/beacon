package report

import (
	"encoding/json"
	"testing"

	"github.com/stormbane/beacon/internal/enrichment"
	"github.com/stormbane/beacon/internal/finding"
)

func TestRenderJSON_ValidJSON(t *testing.T) {
	run := testRun()
	findings := []enrichment.EnrichedFinding{
		enrichedWith(finding.SeverityHigh, "Exposed Admin", "admin.example.com"),
	}
	out, err := RenderJSON(run, findings, "Executive summary text")
	if err != nil {
		t.Fatalf("RenderJSON error: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
}

func TestRenderJSON_ContainsDomain(t *testing.T) {
	out, err := RenderJSON(testRun(), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal([]byte(out), &m)
	if m["domain"] != "example.com" {
		t.Errorf("expected domain 'example.com', got %v", m["domain"])
	}
}

func TestRenderJSON_FindingCountMatchesSlice(t *testing.T) {
	findings := []enrichment.EnrichedFinding{
		enrichedWith(finding.SeverityCritical, "A", "x"),
		enrichedWith(finding.SeverityLow, "B", "y"),
		enrichedWith(finding.SeverityInfo, "C", "z"),
	}
	out, err := RenderJSON(testRun(), findings, "")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal([]byte(out), &m)
	if int(m["finding_count"].(float64)) != 3 {
		t.Errorf("expected finding_count 3, got %v", m["finding_count"])
	}
}

func TestRenderJSON_ExecutiveSummaryIncluded(t *testing.T) {
	out, err := RenderJSON(testRun(), nil, "Top-level risk: SQL injection")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal([]byte(out), &m)
	if m["executive_summary"] != "Top-level risk: SQL injection" {
		t.Errorf("expected summary in JSON, got %v", m["executive_summary"])
	}
}

func TestRenderJSON_EmptyExecutiveSummaryOmitted(t *testing.T) {
	out, err := RenderJSON(testRun(), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal([]byte(out), &m)
	if _, ok := m["executive_summary"]; ok {
		t.Error("empty executive_summary should be omitted from JSON")
	}
}

func TestRenderJSON_CompletedAtPresent(t *testing.T) {
	out, err := RenderJSON(testRun(), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal([]byte(out), &m)
	if m["completed_at"] == nil {
		t.Error("expected completed_at in JSON")
	}
}

func TestRenderJSON_NoFindings_EmptyArray(t *testing.T) {
	out, err := RenderJSON(testRun(), []enrichment.EnrichedFinding{}, "")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal([]byte(out), &m)
	arr, ok := m["findings"].([]any)
	if !ok {
		t.Fatal("expected 'findings' to be an array")
	}
	if len(arr) != 0 {
		t.Errorf("expected empty findings array, got %d elements", len(arr))
	}
}

// TestRenderNonStringEvidence verifies that a Finding whose Evidence map
// contains non-string values (integer port, string-slice IPs) renders without
// panicking in all three output formats: text, markdown, and JSON.
func TestRenderNonStringEvidence(t *testing.T) {
	f := finding.Finding{
		CheckID:  "infra.redis_exposed",
		Severity: finding.SeverityHigh,
		Title:    "Redis port exposed",
		Asset:    "1.2.3.4",
		Evidence: map[string]any{
			"port": 6379,
			"ips":  []string{"1.2.3.4"},
		},
	}
	ef := enrichment.EnrichedFinding{
		Finding:     f,
		Explanation: "Redis is accessible without authentication.",
		Impact:      "Unauthorised read/write access to the datastore.",
		Remediation: "Bind Redis to 127.0.0.1 and enable requirepass.",
	}

	run := testRun()
	findings := []enrichment.EnrichedFinding{ef}

	// text must not panic
	_ = RenderText(run, findings, "", nil)

	// markdown must not panic
	_ = RenderMarkdown(run, findings, "", nil)

	// JSON must not panic and must produce valid JSON
	out, err := RenderJSON(run, findings, "")
	if err != nil {
		t.Fatalf("RenderJSON error with non-string evidence: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("RenderJSON produced invalid JSON for non-string evidence: %v\n%s", err, out)
	}
}
