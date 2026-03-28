package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stormbane/beacon/internal/enrichment"
	"github.com/stormbane/beacon/internal/finding"
)

func TestRenderOCSF_ValidNDJSON(t *testing.T) {
	run := testRun()
	findings := []enrichment.EnrichedFinding{
		enrichedWith(finding.SeverityCritical, "CVE-2023-3519: Citrix ADC RCE", "citrix.example.com"),
		enrichedWith(finding.SeverityHigh, "Redis exposed", "redis.example.com"),
	}
	out, err := RenderOCSF(run, findings)
	if err != nil {
		t.Fatalf("RenderOCSF error: %v", err)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	// Expect 1 envelope + 2 finding events = 3 lines.
	if len(lines) != 3 {
		t.Fatalf("expected 3 NDJSON lines (1 envelope + 2 findings), got %d", len(lines))
	}
	for i, line := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Errorf("line %d is not valid JSON: %v\n%s", i, err, line)
		}
	}
}

func TestRenderOCSF_EnvelopeIsFirstLine(t *testing.T) {
	out, err := RenderOCSF(testRun(), nil)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) == 0 {
		t.Fatal("expected at least one line")
	}
	var m map[string]any
	json.Unmarshal([]byte(lines[0]), &m)
	if int(m["class_uid"].(float64)) != 2004 {
		t.Errorf("first line should be scan envelope (class_uid 2004), got %v", m["class_uid"])
	}
}

func TestRenderOCSF_FindingEventHasCorrectClassUID(t *testing.T) {
	findings := []enrichment.EnrichedFinding{
		enrichedWith(finding.SeverityHigh, "Exposed admin panel", "admin.example.com"),
	}
	out, err := RenderOCSF(testRun(), findings)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	// Second line is the finding event.
	var m map[string]any
	json.Unmarshal([]byte(lines[1]), &m)
	if int(m["class_uid"].(float64)) != 2002 {
		t.Errorf("finding event should have class_uid 2002, got %v", m["class_uid"])
	}
}

func TestRenderOCSF_CVEParsedIntoVulnerabilities(t *testing.T) {
	ef := enrichment.EnrichedFinding{
		Finding: finding.Finding{
			CheckID:      "cve.citrix_adc_rce_2023",
			Severity:     finding.SeverityCritical,
			Title:        "CVE-2023-3519: Citrix ADC RCE on citrix.example.com",
			Description:  "CVE-2023-3519 stack buffer overflow (CVSS 9.8, KEV)",
			Asset:        "citrix.example.com",
			DiscoveredAt: time.Now(),
		},
		Remediation: "Upgrade to NetScaler 13.1-49.15 or later.",
	}
	out, err := RenderOCSF(testRun(), []enrichment.EnrichedFinding{ef})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	var m map[string]any
	json.Unmarshal([]byte(lines[1]), &m)

	vulns, ok := m["vulnerabilities"].([]any)
	if !ok || len(vulns) == 0 {
		t.Fatal("expected vulnerabilities array in CVE finding")
	}
	vuln := vulns[0].(map[string]any)
	cve, ok := vuln["cve"].(map[string]any)
	if !ok {
		t.Fatal("expected cve object in vulnerability")
	}
	if cve["uid"] != "CVE-2023-3519" {
		t.Errorf("expected CVE-2023-3519, got %v", cve["uid"])
	}
}

func TestRenderOCSF_SeverityMappedCorrectly(t *testing.T) {
	cases := []struct {
		sev      finding.Severity
		wantID   float64
		wantName string
	}{
		{finding.SeverityCritical, 5, "Critical"},
		{finding.SeverityHigh, 4, "High"},
		{finding.SeverityMedium, 3, "Medium"},
		{finding.SeverityLow, 2, "Low"},
		{finding.SeverityInfo, 1, "Informational"},
	}
	for _, tc := range cases {
		ef := enrichedWith(tc.sev, "Test finding", "host.example.com")
		out, err := RenderOCSF(testRun(), []enrichment.EnrichedFinding{ef})
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
		var m map[string]any
		json.Unmarshal([]byte(lines[1]), &m)
		if m["severity_id"] != tc.wantID {
			t.Errorf("severity %v: want severity_id %v, got %v", tc.sev, tc.wantID, m["severity_id"])
		}
		if m["severity"] != tc.wantName {
			t.Errorf("severity %v: want severity %q, got %v", tc.sev, tc.wantName, m["severity"])
		}
	}
}

func TestRenderOCSF_OmittedFindingsExcluded(t *testing.T) {
	findings := []enrichment.EnrichedFinding{
		{Finding: finding.Finding{CheckID: "test.a", Severity: finding.SeverityHigh, Title: "Visible", Asset: "a.example.com"}},
		{Finding: finding.Finding{CheckID: "test.b", Severity: finding.SeverityLow, Title: "Suppressed", Asset: "b.example.com"}, Omit: true},
	}
	out, err := RenderOCSF(testRun(), findings)
	if err != nil {
		t.Fatal(err)
	}
	// 1 envelope + 1 visible finding = 2 lines (omitted finding excluded).
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 2 {
		t.Errorf("expected 2 lines (omitted excluded), got %d", len(lines))
	}
}

func TestRenderOCSF_ResourceContainsAsset(t *testing.T) {
	ef := enrichedWith(finding.SeverityHigh, "Open admin port", "192.168.1.1")
	out, err := RenderOCSF(testRun(), []enrichment.EnrichedFinding{ef})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	var m map[string]any
	json.Unmarshal([]byte(lines[1]), &m)
	resources := m["resources"].([]any)
	if len(resources) == 0 {
		t.Fatal("expected resources array")
	}
	r := resources[0].(map[string]any)
	if r["hostname"] != "192.168.1.1" {
		t.Errorf("expected hostname 192.168.1.1, got %v", r["hostname"])
	}
}
