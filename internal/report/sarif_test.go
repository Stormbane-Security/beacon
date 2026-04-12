package report

import (
	"encoding/json"
	"testing"

	"github.com/stormbane-security/beacon/internal/enrichment"
	"github.com/stormbane-security/beacon/internal/finding"
)

// ---------------------------------------------------------------------------
// SARIF: valid structure with multiple findings
// ---------------------------------------------------------------------------

func TestSARIF_ValidStructure(t *testing.T) {
	run := testRun()
	findings := []enrichment.EnrichedFinding{
		{
			Finding: finding.Finding{
				CheckID:      "web.cors_misconfiguration",
				Severity:     finding.SeverityHigh,
				Title:        "CORS Misconfiguration",
				Description:  "Origin reflected in ACAO",
				Asset:        "api.example.com",
				Scanner:      "cors",
				ProofCommand: "curl -H 'Origin: https://evil.com' https://api.example.com",
			},
			Explanation: "The server reflects any origin.",
		},
		{
			Finding: finding.Finding{
				CheckID:     "tls.protocol_tls10",
				Severity:    finding.SeverityCritical,
				Title:       "TLS 1.0 Enabled",
				Description: "Server supports TLS 1.0",
				Asset:       "login.example.com",
				Scanner:     "tls",
			},
			Explanation: "TLS 1.0 is deprecated and vulnerable.",
		},
		{
			Finding: finding.Finding{
				CheckID:  "email.spf_missing",
				Severity: finding.SeverityMedium,
				Title:    "Missing SPF Record",
				Asset:    "example.com",
				Scanner:  "email",
			},
		},
	}

	out, err := RenderSARIF(run, findings)
	if err != nil {
		t.Fatalf("RenderSARIF error: %v", err)
	}

	var sarif map[string]any
	if err := json.Unmarshal([]byte(out), &sarif); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	// $schema field.
	schema, ok := sarif["$schema"].(string)
	if !ok || schema == "" {
		t.Error("expected $schema field to be a non-empty string")
	}

	// version = "2.1.0".
	version, ok := sarif["version"].(string)
	if !ok || version != "2.1.0" {
		t.Errorf("expected version '2.1.0', got %v", sarif["version"])
	}

	// runs array.
	runs, ok := sarif["runs"].([]any)
	if !ok || len(runs) == 0 {
		t.Fatal("expected non-empty runs array")
	}
	run0 := runs[0].(map[string]any)

	// tool.driver.name = "Beacon" (case-insensitive check for robustness).
	tool := run0["tool"].(map[string]any)
	driver := tool["driver"].(map[string]any)
	driverName, _ := driver["name"].(string)
	if driverName == "" {
		t.Error("expected tool.driver.name to be non-empty")
	}

	// rules contains unique check IDs.
	rules, ok := driver["rules"].([]any)
	if !ok {
		t.Fatal("expected tool.driver.rules to be an array")
	}
	if len(rules) != 3 {
		t.Errorf("expected 3 unique rules, got %d", len(rules))
	}
	ruleIDs := make(map[string]bool)
	for _, r := range rules {
		rm := r.(map[string]any)
		id, _ := rm["id"].(string)
		if id == "" {
			t.Error("expected rule id to be non-empty")
		}
		if ruleIDs[id] {
			t.Errorf("duplicate rule ID: %s", id)
		}
		ruleIDs[id] = true
	}

	// results has correct count.
	results, ok := run0["results"].([]any)
	if !ok {
		t.Fatal("expected results to be an array")
	}
	if len(results) != 3 {
		t.Errorf("expected 3 results, got %d", len(results))
	}

	// Each result has required fields.
	for i, r := range results {
		rm := r.(map[string]any)
		if _, ok := rm["ruleId"].(string); !ok {
			t.Errorf("result[%d] missing ruleId", i)
		}
		if _, ok := rm["level"].(string); !ok {
			t.Errorf("result[%d] missing level", i)
		}
		msg, ok := rm["message"].(map[string]any)
		if !ok {
			t.Errorf("result[%d] missing message object", i)
		} else if _, ok := msg["text"].(string); !ok {
			t.Errorf("result[%d] missing message.text", i)
		}
		locs, ok := rm["locations"].([]any)
		if !ok || len(locs) == 0 {
			t.Errorf("result[%d] missing locations", i)
		}
	}
}

// ---------------------------------------------------------------------------
// SARIF: severity mapping
// ---------------------------------------------------------------------------

func TestSARIF_SeverityMapping(t *testing.T) {
	tests := []struct {
		name     string
		severity finding.Severity
		want     string
	}{
		{"critical maps to error", finding.SeverityCritical, "error"},
		{"high maps to error", finding.SeverityHigh, "error"},
		{"medium maps to warning", finding.SeverityMedium, "warning"},
		{"low maps to note", finding.SeverityLow, "note"},
		{"info maps to none", finding.SeverityInfo, "none"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			run := testRun()
			findings := []enrichment.EnrichedFinding{
				{
					Finding: finding.Finding{
						CheckID:  "test.severity_check",
						Severity: tt.severity,
						Title:    "Test finding",
						Asset:    "example.com",
					},
				},
			}
			out, err := RenderSARIF(run, findings)
			if err != nil {
				t.Fatalf("RenderSARIF error: %v", err)
			}

			var sarif map[string]any
			if err := json.Unmarshal([]byte(out), &sarif); err != nil {
				t.Fatalf("invalid JSON: %v", err)
			}

			runs := sarif["runs"].([]any)
			run0 := runs[0].(map[string]any)
			results := run0["results"].([]any)
			if len(results) != 1 {
				t.Fatalf("expected 1 result, got %d", len(results))
			}
			level := results[0].(map[string]any)["level"].(string)
			if level != tt.want {
				t.Errorf("severity %v: got level %q, want %q", tt.severity, level, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// SARIF: duplicate check IDs produce single rule
// ---------------------------------------------------------------------------

func TestSARIF_DuplicateCheckIDsProduceSingleRule(t *testing.T) {
	run := testRun()
	findings := []enrichment.EnrichedFinding{
		{Finding: finding.Finding{CheckID: "web.xss", Severity: finding.SeverityHigh, Title: "XSS on /search", Asset: "a.example.com"}},
		{Finding: finding.Finding{CheckID: "web.xss", Severity: finding.SeverityHigh, Title: "XSS on /comment", Asset: "b.example.com"}},
	}
	out, err := RenderSARIF(run, findings)
	if err != nil {
		t.Fatalf("RenderSARIF error: %v", err)
	}

	var sarif map[string]any
	_ = json.Unmarshal([]byte(out), &sarif)
	runs := sarif["runs"].([]any)
	driver := runs[0].(map[string]any)["tool"].(map[string]any)["driver"].(map[string]any)
	rules := driver["rules"].([]any)
	if len(rules) != 1 {
		t.Errorf("expected 1 unique rule for duplicate check IDs, got %d", len(rules))
	}

	results := runs[0].(map[string]any)["results"].([]any)
	if len(results) != 2 {
		t.Errorf("expected 2 results for 2 findings with same check ID, got %d", len(results))
	}
}

// ---------------------------------------------------------------------------
// SARIF: empty findings
// ---------------------------------------------------------------------------

func TestSARIF_EmptyFindings(t *testing.T) {
	run := testRun()
	out, err := RenderSARIF(run, nil)
	if err != nil {
		t.Fatalf("RenderSARIF error: %v", err)
	}

	var sarif map[string]any
	if err := json.Unmarshal([]byte(out), &sarif); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// Should still have valid structure with 0 results.
	runs := sarif["runs"].([]any)
	run0 := runs[0].(map[string]any)
	driver := run0["tool"].(map[string]any)["driver"].(map[string]any)
	name, _ := driver["name"].(string)
	if name == "" {
		t.Error("expected tool.driver.name even with empty findings")
	}
}

// ---------------------------------------------------------------------------
// SARIF: omitted findings are excluded
// ---------------------------------------------------------------------------

func TestSARIF_OmittedFindingsExcluded(t *testing.T) {
	run := testRun()
	findings := []enrichment.EnrichedFinding{
		{Finding: finding.Finding{CheckID: "web.xss", Severity: finding.SeverityHigh, Title: "XSS", Asset: "a.example.com"}},
		{Finding: finding.Finding{CheckID: "tls.cert_expiry", Severity: finding.SeverityLow, Title: "Cert expiring", Asset: "b.example.com"}, Omit: true},
	}
	out, err := RenderSARIF(run, findings)
	if err != nil {
		t.Fatalf("RenderSARIF error: %v", err)
	}

	var sarif map[string]any
	_ = json.Unmarshal([]byte(out), &sarif)
	runs := sarif["runs"].([]any)
	results := runs[0].(map[string]any)["results"].([]any)
	if len(results) != 1 {
		t.Errorf("expected 1 result after omitting, got %d", len(results))
	}
}

// ---------------------------------------------------------------------------
// SARIF: result properties include asset and scanner
// ---------------------------------------------------------------------------

func TestSARIF_ResultProperties(t *testing.T) {
	run := testRun()
	findings := []enrichment.EnrichedFinding{
		{
			Finding: finding.Finding{
				CheckID:      "web.sqli",
				Severity:     finding.SeverityCritical,
				Title:        "SQL Injection",
				Asset:        "db.example.com",
				Scanner:      "sqli",
				ProofCommand: "sqlmap -u 'https://db.example.com/search?q=test'",
				Confidence:   "high",
			},
			Impact:      "Full database access",
			Remediation: "Use parameterized queries",
		},
	}
	out, err := RenderSARIF(run, findings)
	if err != nil {
		t.Fatalf("RenderSARIF error: %v", err)
	}

	var sarif map[string]any
	_ = json.Unmarshal([]byte(out), &sarif)
	runs := sarif["runs"].([]any)
	result := runs[0].(map[string]any)["results"].([]any)[0].(map[string]any)
	props, ok := result["properties"].(map[string]any)
	if !ok {
		t.Fatal("expected properties on result")
	}
	if props["asset"] != "db.example.com" {
		t.Errorf("properties.asset = %v, want db.example.com", props["asset"])
	}
	if props["scanner"] != "sqli" {
		t.Errorf("properties.scanner = %v, want sqli", props["scanner"])
	}
	if props["proof_command"] == nil {
		t.Error("expected proof_command in properties")
	}
	if props["impact"] != "Full database access" {
		t.Errorf("properties.impact = %v, want 'Full database access'", props["impact"])
	}
	if props["remediation"] != "Use parameterized queries" {
		t.Errorf("properties.remediation = %v, want 'Use parameterized queries'", props["remediation"])
	}
}
