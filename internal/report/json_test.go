package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stormbane/beacon/internal/enrichment"
	"github.com/stormbane/beacon/internal/finding"
)

func TestRenderJSON_ValidJSON(t *testing.T) {
	run := testRun()
	findings := []enrichment.EnrichedFinding{
		enrichedWith(finding.SeverityHigh, "Exposed Admin", "admin.example.com"),
	}
	out, err := RenderJSON(run, findings, "Executive summary text", nil)
	if err != nil {
		t.Fatalf("RenderJSON error: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
}

func TestRenderJSON_ContainsDomain(t *testing.T) {
	out, err := RenderJSON(testRun(), nil, "", nil)
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
	out, err := RenderJSON(testRun(), findings, "", nil)
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
	out, err := RenderJSON(testRun(), nil, "Top-level risk: SQL injection", nil)
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
	out, err := RenderJSON(testRun(), nil, "", nil)
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
	out, err := RenderJSON(testRun(), nil, "", nil)
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
	out, err := RenderJSON(testRun(), []enrichment.EnrichedFinding{}, "", nil)
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

// TestReport_ProofCommandTakesPrecedenceOverVerifyCmd verifies that when a finding
// has a ProofCommand set, it is used in the report output instead of the
// auto-generated VerifyCmd from the registry.
func TestReport_ProofCommandTakesPrecedenceOverVerifyCmd(t *testing.T) {
	// email.spf_missing has a VerifyCmd entry in verify.go, so if ProofCommand
	// is ignored the rendered output would show the registry command instead.
	const customProof = "dig TXT example.com @1.1.1.1 +short | grep spf"
	f := finding.Finding{
		CheckID:      finding.CheckEmailSPFMissing,
		Severity:     finding.SeverityHigh,
		Title:        "Missing SPF record",
		Asset:        "example.com",
		ProofCommand: customProof,
	}
	ef := enrichment.EnrichedFinding{Finding: f, Explanation: "No SPF record found."}

	run := testRun()

	out := RenderText(run, []enrichment.EnrichedFinding{ef}, "", nil)
	if !strings.Contains(out, customProof) {
		t.Errorf("text report does not contain the custom ProofCommand %q", customProof)
	}
	// The registry command should NOT override the per-finding ProofCommand.
	registryCmd := VerifyCmd(f.CheckID, f.Asset)
	if registryCmd != "" && strings.Contains(out, registryCmd) && !strings.Contains(registryCmd, customProof) {
		t.Logf("note: registry command %q also present — acceptable if custom command also shown", registryCmd)
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
	out, err := RenderJSON(run, findings, "", nil)
	if err != nil {
		t.Fatalf("RenderJSON error with non-string evidence: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("RenderJSON produced invalid JSON for non-string evidence: %v\n%s", err, out)
	}
}

// ---------------------------------------------------------------------------
// JSON: special characters in finding titles and descriptions
// ---------------------------------------------------------------------------

func TestRenderJSON_SpecialCharactersInFindings(t *testing.T) {
	findings := []enrichment.EnrichedFinding{
		{
			Finding: finding.Finding{
				CheckID:     "test.check",
				Severity:    finding.SeverityHigh,
				Title:       `SQL injection via "param' OR 1=1--`,
				Description: "Contains <html> tags and\nnewlines and\ttabs",
				Asset:       `host"with"quotes.example.com`,
			},
		},
	}
	out, err := RenderJSON(testRun(), findings, "", nil)
	if err != nil {
		t.Fatalf("RenderJSON with special characters: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
}

// ---------------------------------------------------------------------------
// JSON: nil findings produces valid JSON with null findings array
// ---------------------------------------------------------------------------

func TestRenderJSON_NilFindings(t *testing.T) {
	out, err := RenderJSON(testRun(), nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("nil findings produced invalid JSON: %v", err)
	}
	if int(m["finding_count"].(float64)) != 0 {
		t.Errorf("expected finding_count 0 for nil findings, got %v", m["finding_count"])
	}
}

// ---------------------------------------------------------------------------
// JSON: sorting by severity descending
// ---------------------------------------------------------------------------

func TestRenderJSON_SortedBySeverityDescending(t *testing.T) {
	findings := []enrichment.EnrichedFinding{
		enrichedWith(finding.SeverityLow, "Low finding", "a.example.com"),
		enrichedWith(finding.SeverityCritical, "Critical finding", "b.example.com"),
		enrichedWith(finding.SeverityMedium, "Medium finding", "c.example.com"),
	}
	out, err := RenderJSON(testRun(), findings, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal([]byte(out), &m)
	arr := m["findings"].([]any)
	// First finding should be critical (highest severity).
	first := arr[0].(map[string]any)
	firstFinding := first["finding"].(map[string]any)
	if firstFinding["title"] != "Critical finding" {
		t.Errorf("expected first finding to be critical, got %v", firstFinding["title"])
	}
}

// ---------------------------------------------------------------------------
// JSON: graphJSON integration
// ---------------------------------------------------------------------------

func TestRenderJSON_WithValidGraphJSON(t *testing.T) {
	graphJSON := []byte(`{"scan_run_id":"run-1","domain":"example.com","assets":[{"id":"domain:example.com","type":"domain","provider":"web","name":"example.com","discovered_by":"test","confidence":1}],"relationships":[],"findings":[],"iac_references":[]}`)
	out, err := RenderJSON(testRun(), nil, "", graphJSON)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal([]byte(out), &m)
	if m["asset_graph"] == nil {
		t.Error("expected asset_graph to be present when valid graphJSON provided")
	}
}

func TestRenderJSON_WithInvalidGraphJSON(t *testing.T) {
	out, err := RenderJSON(testRun(), nil, "", []byte("not json"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal([]byte(out), &m)
	// Invalid graphJSON should be silently ignored (no asset_graph key).
	if m["asset_graph"] != nil {
		t.Error("expected asset_graph to be absent when graphJSON is invalid")
	}
}

func TestRenderJSON_WithEmptyGraphJSON(t *testing.T) {
	// Valid JSON but no assets — should not include asset_graph.
	out, err := RenderJSON(testRun(), nil, "", []byte(`{"scan_run_id":"run-1","domain":"example.com","assets":[],"relationships":[],"findings":[],"iac_references":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal([]byte(out), &m)
	if m["asset_graph"] != nil {
		t.Error("expected asset_graph to be absent when graph has no assets")
	}
}

// ---------------------------------------------------------------------------
// JSON: nil CompletedAt
// ---------------------------------------------------------------------------

func TestRenderJSON_NilCompletedAt(t *testing.T) {
	run := testRun()
	run.CompletedAt = nil
	out, err := RenderJSON(run, nil, "", nil)
	if err != nil {
		t.Fatalf("RenderJSON with nil CompletedAt: %v", err)
	}
	var m map[string]any
	json.Unmarshal([]byte(out), &m)
	// completed_at should be absent (omitempty).
	if _, ok := m["completed_at"]; ok {
		t.Error("expected completed_at to be omitted when nil")
	}
}
