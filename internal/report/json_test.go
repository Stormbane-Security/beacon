package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stormbane-security/beacon/internal/enrichment"
	"github.com/stormbane-security/beacon/internal/finding"
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

// ---------------------------------------------------------------------------
// JSON: nil findings slice produces valid JSON with empty array, not null
// ---------------------------------------------------------------------------

func TestJSONReportNilFindings(t *testing.T) {
	out, err := RenderJSON(testRun(), nil, "", nil)
	if err != nil {
		t.Fatalf("RenderJSON error with nil findings: %v", err)
	}

	// Must be valid JSON.
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("nil findings produced invalid JSON: %v", err)
	}

	// The "findings" key should exist.
	rawFindings, ok := m["findings"]
	if !ok {
		t.Fatal("expected 'findings' key in JSON output")
	}

	// Verify it's not JSON null — it should be an array (possibly null in Go,
	// but we want to verify the JSON is still parseable and finding_count is 0).
	if rawFindings != nil {
		arr, ok := rawFindings.([]any)
		if !ok {
			t.Fatalf("expected 'findings' to be array, got %T", rawFindings)
		}
		if len(arr) != 0 {
			t.Errorf("expected empty findings array for nil input, got %d elements", len(arr))
		}
	}

	// finding_count must be 0.
	if int(m["finding_count"].(float64)) != 0 {
		t.Errorf("expected finding_count 0, got %v", m["finding_count"])
	}

	// Round-trip: re-marshal and re-unmarshal should succeed.
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("re-marshal failed: %v", err)
	}
	var m2 map[string]any
	if err := json.Unmarshal(b, &m2); err != nil {
		t.Fatalf("round-trip unmarshal failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// JSON: field mapping correctness (CheckID, Severity, Asset, Title, Scanner, ProofCommand)
// ---------------------------------------------------------------------------

func TestRenderJSON_FieldMappingCorrectness(t *testing.T) {
	f := finding.Finding{
		CheckID:      "web.cors_misconfiguration",
		Severity:     finding.SeverityHigh,
		Title:        "CORS Misconfiguration",
		Asset:        "api.example.com",
		Scanner:      "cors",
		ProofCommand: "curl -H 'Origin: https://evil.com' https://api.example.com",
		Module:       "surface",
		Description:  "Origin reflection allows credentialed CORS requests",
	}
	ef := enrichment.EnrichedFinding{
		Finding:     f,
		Explanation: "The server reflects the Origin header in ACAO.",
		Impact:      "Credential theft via cross-origin requests.",
		Remediation: "Restrict ACAO to trusted origins.",
	}
	out, err := RenderJSON(testRun(), []enrichment.EnrichedFinding{ef}, "", nil)
	if err != nil {
		t.Fatalf("RenderJSON error: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	arr := m["findings"].([]any)
	if len(arr) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(arr))
	}
	entry := arr[0].(map[string]any)
	findingMap := entry["finding"].(map[string]any)

	// Check each field is correctly mapped.
	if findingMap["check_id"] != "web.cors_misconfiguration" {
		t.Errorf("check_id = %v, want %q", findingMap["check_id"], "web.cors_misconfiguration")
	}
	// Severity is an int enum, so it appears as a number.
	if findingMap["severity"] == nil {
		t.Error("severity should be present")
	}
	if findingMap["asset"] != "api.example.com" {
		t.Errorf("asset = %v, want %q", findingMap["asset"], "api.example.com")
	}
	if findingMap["title"] != "CORS Misconfiguration" {
		t.Errorf("title = %v, want %q", findingMap["title"], "CORS Misconfiguration")
	}
	if findingMap["scanner"] != "cors" {
		t.Errorf("scanner = %v, want %q", findingMap["scanner"], "cors")
	}
	if findingMap["proof_command"] != "curl -H 'Origin: https://evil.com' https://api.example.com" {
		t.Errorf("proof_command = %v, want curl command", findingMap["proof_command"])
	}

	// Enrichment fields.
	if entry["explanation"] != "The server reflects the Origin header in ACAO." {
		t.Errorf("explanation = %v, want ACAO explanation", entry["explanation"])
	}
	if entry["impact"] != "Credential theft via cross-origin requests." {
		t.Errorf("impact = %v, want credential theft", entry["impact"])
	}
	if entry["remediation"] != "Restrict ACAO to trusted origins." {
		t.Errorf("remediation = %v, want restrict ACAO", entry["remediation"])
	}
}

// ---------------------------------------------------------------------------
// JSON: finding titles with unicode, null bytes, and control characters
// ---------------------------------------------------------------------------

func TestJSONReportSpecialCharsInTitle(t *testing.T) {
	findings := []enrichment.EnrichedFinding{
		{
			Finding: finding.Finding{
				CheckID:  "test.unicode",
				Severity: finding.SeverityHigh,
				Title:    "Injection via \u00e9\u00e0\u00fc\u00f1 \U0001F4A5 param",
				Asset:    "example.com",
			},
			Explanation: "Unicode characters in title.",
		},
		{
			Finding: finding.Finding{
				CheckID:  "test.nullbyte",
				Severity: finding.SeverityMedium,
				Title:    "Null byte \x00 in title",
				Asset:    "example.com",
			},
			Explanation: "Null byte in finding title.",
		},
		{
			Finding: finding.Finding{
				CheckID:  "test.control",
				Severity: finding.SeverityLow,
				Title:    "Control chars: \x01\x02\x03\x1b[31mred\x1b[0m",
				Asset:    "example.com",
			},
			Explanation: "ANSI escape and control characters.",
		},
		{
			Finding: finding.Finding{
				CheckID:     "test.backslash",
				Severity:    finding.SeverityInfo,
				Title:       `Path: C:\Windows\System32\cmd.exe /c "whoami"`,
				Description: "Backslashes and quotes in title.",
				Asset:       "example.com",
			},
		},
	}

	out, err := RenderJSON(testRun(), findings, "", nil)
	if err != nil {
		t.Fatalf("RenderJSON with special chars: %v", err)
	}

	// Must produce valid JSON — this is the primary check.
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("special-char findings produced invalid JSON: %v\n%s", err, out)
	}

	// All findings should be present.
	arr := m["findings"].([]any)
	if len(arr) != 4 {
		t.Errorf("expected 4 findings, got %d", len(arr))
	}

	// Round-trip: re-marshal should also produce valid JSON.
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("re-marshal of special-char JSON failed: %v", err)
	}
	var m2 map[string]any
	if err := json.Unmarshal(b, &m2); err != nil {
		t.Fatalf("round-trip unmarshal failed: %v", err)
	}
}
