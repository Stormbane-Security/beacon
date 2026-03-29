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

func TestRenderOCSF_EnvelopeClassUID5001(t *testing.T) {
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
	if int(m["class_uid"].(float64)) != 5001 {
		t.Errorf("envelope should have class_uid 5001, got %v", m["class_uid"])
	}
	if m["class_name"] != "Vulnerability Finding" {
		t.Errorf("envelope should have class_name 'Vulnerability Finding', got %v", m["class_name"])
	}
}

func TestRenderOCSF_FindingEventClassUID5001(t *testing.T) {
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
	if int(m["class_uid"].(float64)) != 5001 {
		t.Errorf("finding event should have class_uid 5001, got %v", m["class_uid"])
	}
}

func TestRenderOCSF_CategoryIsDiscovery(t *testing.T) {
	findings := []enrichment.EnrichedFinding{
		enrichedWith(finding.SeverityMedium, "Weak TLS", "tls.example.com"),
	}
	out, err := RenderOCSF(testRun(), findings)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	var m map[string]any
	json.Unmarshal([]byte(lines[1]), &m)
	if int(m["category_uid"].(float64)) != 5 {
		t.Errorf("expected category_uid 5 (Discovery), got %v", m["category_uid"])
	}
	if m["category_name"] != "Discovery" {
		t.Errorf("expected category_name 'Discovery', got %v", m["category_name"])
	}
}

func TestRenderOCSF_MetadataVersion(t *testing.T) {
	findings := []enrichment.EnrichedFinding{
		enrichedWith(finding.SeverityLow, "Info disclosure", "info.example.com"),
	}
	out, err := RenderOCSF(testRun(), findings)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	var m map[string]any
	json.Unmarshal([]byte(lines[1]), &m)
	meta := m["metadata"].(map[string]any)
	if meta["version"] != "1.3.0" {
		t.Errorf("expected metadata version '1.3.0', got %v", meta["version"])
	}
	product := meta["product"].(map[string]any)
	if product["name"] != "Beacon" {
		t.Errorf("expected product name 'Beacon', got %v", product["name"])
	}
	if product["vendor_name"] != "Stormbane" {
		t.Errorf("expected vendor_name 'Stormbane', got %v", product["vendor_name"])
	}
}

func TestRenderOCSF_FindingInfoFields(t *testing.T) {
	ef := enrichment.EnrichedFinding{
		Finding: finding.Finding{
			CheckID:      "tls.weak_cipher",
			Severity:     finding.SeverityMedium,
			Title:        "Weak TLS cipher suite",
			Description:  "Server supports DES-CBC3-SHA which is deprecated.",
			Asset:        "www.example.com",
			ProofCommand: "nmap --script ssl-enum-ciphers -p 443 www.example.com",
			DiscoveredAt: time.Date(2026, 3, 29, 10, 0, 0, 0, time.UTC),
		},
	}
	out, err := RenderOCSF(testRun(), []enrichment.EnrichedFinding{ef})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	var m map[string]any
	json.Unmarshal([]byte(lines[1]), &m)

	fi := m["finding_info"].(map[string]any)
	if fi["uid"] != "tls.weak_cipher" {
		t.Errorf("expected finding_info.uid 'tls.weak_cipher', got %v", fi["uid"])
	}
	if fi["title"] != "Weak TLS cipher suite" {
		t.Errorf("expected finding_info.title, got %v", fi["title"])
	}
	if fi["desc"] != "Server supports DES-CBC3-SHA which is deprecated." {
		t.Errorf("expected finding_info.desc, got %v", fi["desc"])
	}
	// created_time should be the discovery timestamp as epoch ms
	expectedTS := float64(time.Date(2026, 3, 29, 10, 0, 0, 0, time.UTC).UnixMilli())
	if fi["created_time"] != expectedTS {
		t.Errorf("expected finding_info.created_time %v, got %v", expectedTS, fi["created_time"])
	}
	// src_url should be the proof command
	if fi["src_url"] != "nmap --script ssl-enum-ciphers -p 443 www.example.com" {
		t.Errorf("expected finding_info.src_url to be proof command, got %v", fi["src_url"])
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
	if vuln["title"] != ef.Finding.Title {
		t.Errorf("expected vulnerability title to match finding title, got %v", vuln["title"])
	}
	if vuln["severity"] != "Critical" {
		t.Errorf("expected vulnerability severity 'Critical', got %v", vuln["severity"])
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
	resource := m["resource"].(map[string]any)
	if resource["name"] != "192.168.1.1" {
		t.Errorf("expected resource.name '192.168.1.1', got %v", resource["name"])
	}
	if resource["uid"] != "192.168.1.1" {
		t.Errorf("expected resource.uid '192.168.1.1', got %v", resource["uid"])
	}
	if resource["type"] == nil || resource["type"] == "" {
		t.Error("expected resource.type to be set")
	}
}

func TestRenderOCSF_ActivityAndStatusFields(t *testing.T) {
	ef := enrichedWith(finding.SeverityMedium, "Test finding", "test.example.com")
	out, err := RenderOCSF(testRun(), []enrichment.EnrichedFinding{ef})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	var m map[string]any
	json.Unmarshal([]byte(lines[1]), &m)
	if int(m["activity_id"].(float64)) != 1 {
		t.Errorf("expected activity_id 1 (Create), got %v", m["activity_id"])
	}
	if m["activity_name"] != "Create" {
		t.Errorf("expected activity_name 'Create', got %v", m["activity_name"])
	}
	if int(m["status_id"].(float64)) != 1 {
		t.Errorf("expected status_id 1 (New), got %v", m["status_id"])
	}
	if m["status"] != "New" {
		t.Errorf("expected status 'New', got %v", m["status"])
	}
}

func TestRenderOCSF_TimeIsEpochMs(t *testing.T) {
	ts := time.Date(2026, 3, 29, 12, 0, 0, 0, time.UTC)
	ef := enrichment.EnrichedFinding{
		Finding: finding.Finding{
			CheckID:      "test.check",
			Severity:     finding.SeverityHigh,
			Title:        "Test",
			Asset:        "test.example.com",
			DiscoveredAt: ts,
		},
	}
	out, err := RenderOCSF(testRun(), []enrichment.EnrichedFinding{ef})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	var m map[string]any
	json.Unmarshal([]byte(lines[1]), &m)
	expectedMs := float64(ts.UnixMilli())
	if m["time"] != expectedMs {
		t.Errorf("expected time %v (epoch ms), got %v", expectedMs, m["time"])
	}
}

func TestRenderOCSF_RemediationIncluded(t *testing.T) {
	ef := enrichment.EnrichedFinding{
		Finding: finding.Finding{
			CheckID:  "test.check",
			Severity: finding.SeverityHigh,
			Title:    "Test",
			Asset:    "test.example.com",
		},
		Remediation: "Apply the security patch immediately.",
	}
	out, err := RenderOCSF(testRun(), []enrichment.EnrichedFinding{ef})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	var m map[string]any
	json.Unmarshal([]byte(lines[1]), &m)
	rem := m["remediation"].(map[string]any)
	if rem["desc"] != "Apply the security patch immediately." {
		t.Errorf("expected remediation desc, got %v", rem["desc"])
	}
}

func TestRenderOCSF_NoRemediationOmitted(t *testing.T) {
	ef := enrichment.EnrichedFinding{
		Finding: finding.Finding{
			CheckID:  "test.check",
			Severity: finding.SeverityLow,
			Title:    "Test",
			Asset:    "test.example.com",
		},
	}
	out, err := RenderOCSF(testRun(), []enrichment.EnrichedFinding{ef})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	var m map[string]any
	json.Unmarshal([]byte(lines[1]), &m)
	if m["remediation"] != nil {
		t.Error("expected remediation to be omitted when empty")
	}
}

// ---------------------------------------------------------------------------
// OCSF severity mapping: verify informational maps to severity_id 1
// ---------------------------------------------------------------------------

func TestOcsfSeverity_DefaultIsInformational(t *testing.T) {
	// SeverityInfo maps to "info" via String(), but OCSF returns "Informational".
	id, name := ocsfSeverity(finding.SeverityInfo)
	if id != 1 {
		t.Errorf("SeverityInfo: want severity_id 1, got %d", id)
	}
	if name != "Informational" {
		t.Errorf("SeverityInfo: want 'Informational', got %q", name)
	}
}

func TestOcsfSeverity_UnknownSeverity(t *testing.T) {
	// A severity value not in the switch should default to Informational.
	id, name := ocsfSeverity(finding.Severity(99))
	if id != 1 || name != "Informational" {
		t.Errorf("unknown severity: want (1, 'Informational'), got (%d, %q)", id, name)
	}
}

// ---------------------------------------------------------------------------
// OCSF resource type mapping
// ---------------------------------------------------------------------------

func TestOcsfResourceType_AllPrefixes(t *testing.T) {
	tests := []struct {
		checkID  string
		wantType string
	}{
		{"port.open_http", "Network"},
		{"tls.weak_cipher", "Web Server"},
		{"email.spf_missing", "DNS"},
		{"iam.primitive_role", "Cloud Account"},
		{"cloud.gcp.bucket_public", "Cloud Resource"},
		{"secret.exposed_key", "Data Store"},
		{"dlp.pii_exposed", "Data Store"},
		{"cors.wildcard", "Web Server"},     // default
		{"unknown.check", "Web Server"},     // default
	}
	for _, tt := range tests {
		t.Run(tt.checkID, func(t *testing.T) {
			got := ocsfResourceType(tt.checkID)
			if got != tt.wantType {
				t.Errorf("ocsfResourceType(%q) = %q, want %q", tt.checkID, got, tt.wantType)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// OCSF CVE extraction edge cases
// ---------------------------------------------------------------------------

func TestExtractCVEs_MultipleSameCVE(t *testing.T) {
	text := "CVE-2023-3519 is referenced twice: see CVE-2023-3519"
	cves := extractCVEs(text)
	if len(cves) != 1 {
		t.Errorf("expected 1 unique CVE, got %d: %v", len(cves), cves)
	}
}

func TestExtractCVEs_NoCVEs(t *testing.T) {
	cves := extractCVEs("No vulnerabilities here")
	if len(cves) != 0 {
		t.Errorf("expected 0 CVEs, got %d: %v", len(cves), cves)
	}
}

func TestExtractCVEs_MultipleDifferentCVEs(t *testing.T) {
	text := "Affected by CVE-2023-3519 and CVE-2024-12345"
	cves := extractCVEs(text)
	if len(cves) != 2 {
		t.Errorf("expected 2 CVEs, got %d: %v", len(cves), cves)
	}
}

// ---------------------------------------------------------------------------
// OCSF: zero DiscoveredAt falls back to now
// ---------------------------------------------------------------------------

func TestRenderOCSF_ZeroDiscoveredAtUsesNow(t *testing.T) {
	ef := enrichment.EnrichedFinding{
		Finding: finding.Finding{
			CheckID:  "test.check",
			Severity: finding.SeverityLow,
			Title:    "Test",
			Asset:    "test.example.com",
			// DiscoveredAt is zero value
		},
	}
	out, err := RenderOCSF(testRun(), []enrichment.EnrichedFinding{ef})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	var m map[string]any
	json.Unmarshal([]byte(lines[1]), &m)
	ts := int64(m["time"].(float64))
	if ts <= 0 {
		t.Error("zero DiscoveredAt should fall back to a positive timestamp (now)")
	}
}

// ---------------------------------------------------------------------------
// OCSF: special characters in finding fields
// ---------------------------------------------------------------------------

func TestRenderOCSF_SpecialCharactersInTitle(t *testing.T) {
	ef := enrichment.EnrichedFinding{
		Finding: finding.Finding{
			CheckID:     "test.check",
			Severity:    finding.SeverityHigh,
			Title:       `SQL injection via "param' OR 1=1--`,
			Description: "Contains <html> and \"quotes\" and\nnewlines",
			Asset:       "test.example.com",
		},
	}
	out, err := RenderOCSF(testRun(), []enrichment.EnrichedFinding{ef})
	if err != nil {
		t.Fatalf("RenderOCSF should handle special characters: %v", err)
	}
	// Verify each line is valid JSON.
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	for i, line := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Errorf("line %d is not valid JSON after special char encoding: %v", i, err)
		}
	}
}

// ---------------------------------------------------------------------------
// OCSF: nil CompletedAt in scan run
// ---------------------------------------------------------------------------

func TestRenderOCSF_NilCompletedAt(t *testing.T) {
	run := testRun()
	run.CompletedAt = nil

	out, err := RenderOCSF(run, nil)
	if err != nil {
		t.Fatalf("RenderOCSF with nil CompletedAt: %v", err)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	var m map[string]any
	json.Unmarshal([]byte(lines[0]), &m)
	unmapped := m["unmapped"].(map[string]any)
	// completed_at should be 0 (int64 zero value from nil pointer).
	if unmapped["completed_at"].(float64) != 0 {
		t.Errorf("expected completed_at 0 for nil CompletedAt, got %v", unmapped["completed_at"])
	}
}

// ---------------------------------------------------------------------------
// OCSF: empty findings list
// ---------------------------------------------------------------------------

func TestRenderOCSF_EmptyFindings(t *testing.T) {
	out, err := RenderOCSF(testRun(), []enrichment.EnrichedFinding{})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	// Only the envelope event should be present.
	if len(lines) != 1 {
		t.Errorf("expected 1 line (envelope only), got %d", len(lines))
	}
}
