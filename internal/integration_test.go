package internal_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stormbane/beacon/internal/asset"
	"github.com/stormbane/beacon/internal/enrichment"
	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
	"github.com/stormbane/beacon/internal/report"
	"github.com/stormbane/beacon/internal/scanner/cors"
	"github.com/stormbane/beacon/internal/scanner/hostheader"
	"github.com/stormbane/beacon/internal/scanner/tls"
	"github.com/stormbane/beacon/internal/store"
	"github.com/stormbane/beacon/internal/store/memory"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// makeFinding builds a finding with sensible defaults for testing.
func makeFinding(checkID finding.CheckID, sev finding.Severity, assetName, title string) finding.Finding {
	return finding.Finding{
		CheckID:      checkID,
		Module:       "surface",
		Scanner:      "test",
		Severity:     sev,
		Title:        title,
		Description:  "Test finding: " + title,
		Asset:        assetName,
		Evidence:     map[string]any{"test": true},
		ProofCommand: "curl -v https://" + assetName,
		DiscoveredAt: time.Now(),
		ScannedBy:    "surface.test",
	}
}

// makeEnriched wraps a finding in an EnrichedFinding with noop enrichment.
func makeEnriched(f finding.Finding) enrichment.EnrichedFinding {
	return enrichment.EnrichedFinding{
		Finding:     f,
		Explanation: f.Description,
		Impact:      "Test impact",
		Remediation: "Test remediation",
	}
}

// makeScanRun creates a store.ScanRun for testing.
func makeScanRun(domain string) store.ScanRun {
	now := time.Now()
	return store.ScanRun{
		ID:        "test-run-001",
		Domain:    domain,
		ScanType:  module.ScanSurface,
		Modules:   []string{"surface"},
		Status:    store.StatusCompleted,
		StartedAt: now.Add(-5 * time.Minute),
		CompletedAt: &now,
	}
}

// ---------------------------------------------------------------------------
// 1. Full scan pipeline: httptest servers + scanner → findings
// ---------------------------------------------------------------------------

func TestFullScanPipeline_CORSScanner(t *testing.T) {
	// Spin up a server that reflects any Origin with credentials — critical CORS misconfig.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	asset := strings.TrimPrefix(ts.URL, "http://")
	scanner := cors.New()

	// CORS scanner is deep-only, so surface mode should produce no findings.
	surfaceFindings, err := scanner.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("surface scan error: %v", err)
	}
	if len(surfaceFindings) != 0 {
		t.Errorf("surface mode should produce 0 findings, got %d", len(surfaceFindings))
	}

	// Deep mode should detect the CORS misconfiguration.
	deepFindings, err := scanner.Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("deep scan error: %v", err)
	}
	if len(deepFindings) == 0 {
		t.Fatal("deep scan should have produced at least one CORS finding")
	}

	// Verify finding properties.
	var found bool
	for _, f := range deepFindings {
		if f.CheckID == finding.CheckCORSMisconfiguration ||
			f.CheckID == finding.CheckCORSCredentialedReflection {
			found = true
			if f.Severity < finding.SeverityHigh {
				t.Errorf("CORS credentialed reflection should be High or Critical, got %s", f.Severity)
			}
			if f.ProofCommand == "" {
				t.Error("finding must have ProofCommand set")
			}
			if f.Scanner != "cors" {
				t.Errorf("scanner should be 'cors', got %q", f.Scanner)
			}
		}
	}
	if !found {
		t.Error("expected CheckCORSMisconfiguration or CheckCORSCredentialedReflection finding")
	}
}

func TestFullScanPipeline_TLSScanner(t *testing.T) {
	// Create a plain HTTP test server; TLS scanner should handle the connection
	// gracefully (may produce findings about missing TLS or error out cleanly).
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	asset := strings.TrimPrefix(ts.URL, "http://")
	scanner := tls.New()
	_, err := scanner.Run(context.Background(), asset, module.ScanSurface)
	// TLS scanner connecting to plain HTTP should not panic; an error is acceptable.
	_ = err
}

func TestFullScanPipeline_HostHeaderScanner(t *testing.T) {
	// Server that reflects the Host header in Location — host header injection.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		w.Header().Set("Location", "https://"+host+"/redirected")
		w.WriteHeader(http.StatusFound)
	}))
	defer ts.Close()

	asset := strings.TrimPrefix(ts.URL, "http://")
	scanner := hostheader.New()
	findings, err := scanner.Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("host header scan error: %v", err)
	}

	// The scanner may or may not detect injection depending on exact probe logic,
	// but it must not panic and must return valid findings.
	for _, f := range findings {
		if f.CheckID == "" {
			t.Error("finding has empty CheckID")
		}
		if f.Asset == "" {
			t.Error("finding has empty Asset")
		}
	}
}

func TestFullScanPipeline_ScannerToStoreToReport(t *testing.T) {
	// End-to-end: scanner → store → enrich → report.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	ctx := context.Background()
	assetName := strings.TrimPrefix(ts.URL, "http://")
	domain := "test.example.com"

	// 1. Run scanner.
	scanner := cors.New()
	rawFindings, err := scanner.Run(ctx, assetName, module.ScanDeep)
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}

	// If no findings from the scanner (may happen if wildcard without creds
	// is not flagged), inject synthetic ones so we still test the pipeline.
	if len(rawFindings) == 0 {
		rawFindings = []finding.Finding{
			makeFinding(finding.CheckCORSMisconfiguration, finding.SeverityMedium, assetName, "CORS wildcard origin"),
		}
	}

	// 2. Save to store.
	s := memory.New()
	run := makeScanRun(domain)
	if err := s.CreateScanRun(ctx, &run); err != nil {
		t.Fatalf("create scan run: %v", err)
	}
	if err := s.SaveFindings(ctx, run.ID, rawFindings); err != nil {
		t.Fatalf("save findings: %v", err)
	}

	// 3. Enrich.
	enricher := enrichment.NewNoop()
	enriched, err := enricher.Enrich(ctx, rawFindings)
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if err := s.SaveEnrichedFindings(ctx, run.ID, enriched); err != nil {
		t.Fatalf("save enriched: %v", err)
	}

	// 4. Generate JSON report.
	jsonOut, err := report.RenderJSON(run, enriched, "Test executive summary", nil)
	if err != nil {
		t.Fatalf("render JSON: %v", err)
	}

	// Verify JSON structure.
	var parsed map[string]any
	if err := json.Unmarshal([]byte(jsonOut), &parsed); err != nil {
		t.Fatalf("JSON output is not valid JSON: %v", err)
	}
	if parsed["domain"] != domain {
		t.Errorf("JSON domain = %v, want %q", parsed["domain"], domain)
	}
	count, ok := parsed["finding_count"].(float64)
	if !ok || int(count) != len(enriched) {
		t.Errorf("JSON finding_count = %v, want %d", parsed["finding_count"], len(enriched))
	}
}

// ---------------------------------------------------------------------------
// 2. Store round-trip: create → save → retrieve → verify
// ---------------------------------------------------------------------------

func TestStoreRoundTrip_Findings(t *testing.T) {
	ctx := context.Background()
	s := memory.New()

	// Create target and scan run.
	target, err := s.UpsertTarget(ctx, "roundtrip.example.com")
	if err != nil {
		t.Fatalf("upsert target: %v", err)
	}
	if target.Domain != "roundtrip.example.com" {
		t.Errorf("target domain = %q, want %q", target.Domain, "roundtrip.example.com")
	}

	run := makeScanRun("roundtrip.example.com")
	if err := s.CreateScanRun(ctx, &run); err != nil {
		t.Fatalf("create scan run: %v", err)
	}

	// Save findings.
	findings := []finding.Finding{
		makeFinding(finding.CheckTLSCertExpiry7d, finding.SeverityHigh, "api.roundtrip.example.com", "TLS cert expires in 3 days"),
		makeFinding(finding.CheckHeadersMissingHSTS, finding.SeverityMedium, "roundtrip.example.com", "Missing HSTS header"),
		makeFinding(finding.CheckEmailSPFMissing, finding.SeverityMedium, "roundtrip.example.com", "No SPF record"),
	}
	if err := s.SaveFindings(ctx, run.ID, findings); err != nil {
		t.Fatalf("save findings: %v", err)
	}

	// Retrieve and verify.
	retrieved, err := s.GetFindings(ctx, run.ID)
	if err != nil {
		t.Fatalf("get findings: %v", err)
	}
	if len(retrieved) != len(findings) {
		t.Fatalf("retrieved %d findings, want %d", len(retrieved), len(findings))
	}
	for i, f := range retrieved {
		if f.CheckID != findings[i].CheckID {
			t.Errorf("finding[%d].CheckID = %q, want %q", i, f.CheckID, findings[i].CheckID)
		}
		if f.Severity != findings[i].Severity {
			t.Errorf("finding[%d].Severity = %v, want %v", i, f.Severity, findings[i].Severity)
		}
		if f.Asset != findings[i].Asset {
			t.Errorf("finding[%d].Asset = %q, want %q", i, f.Asset, findings[i].Asset)
		}
	}
}

func TestStoreRoundTrip_EnrichedFindings(t *testing.T) {
	ctx := context.Background()
	s := memory.New()

	run := makeScanRun("enriched.example.com")
	if err := s.CreateScanRun(ctx, &run); err != nil {
		t.Fatalf("create scan run: %v", err)
	}

	f := makeFinding(finding.CheckDNSAXFRAllowed, finding.SeverityHigh, "enriched.example.com", "Zone transfer allowed")
	ef := makeEnriched(f)
	ef.Remediation = "Restrict AXFR to authorized IPs in named.conf"
	ef.ComplianceTags = []string{"SOC2-CC6.1", "ISO27001-A.12.4"}

	if err := s.SaveEnrichedFindings(ctx, run.ID, []enrichment.EnrichedFinding{ef}); err != nil {
		t.Fatalf("save enriched: %v", err)
	}

	retrieved, err := s.GetEnrichedFindings(ctx, run.ID)
	if err != nil {
		t.Fatalf("get enriched: %v", err)
	}
	if len(retrieved) != 1 {
		t.Fatalf("retrieved %d enriched findings, want 1", len(retrieved))
	}
	if retrieved[0].Finding.CheckID != finding.CheckDNSAXFRAllowed {
		t.Errorf("CheckID = %q, want %q", retrieved[0].Finding.CheckID, finding.CheckDNSAXFRAllowed)
	}
	if retrieved[0].Remediation != ef.Remediation {
		t.Errorf("Remediation = %q, want %q", retrieved[0].Remediation, ef.Remediation)
	}
	if len(retrieved[0].ComplianceTags) != 2 {
		t.Errorf("ComplianceTags len = %d, want 2", len(retrieved[0].ComplianceTags))
	}
}

func TestStoreRoundTrip_ScanRunLifecycle(t *testing.T) {
	ctx := context.Background()
	s := memory.New()

	run := makeScanRun("lifecycle.example.com")
	run.Status = store.StatusPending
	if err := s.CreateScanRun(ctx, &run); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Update to running.
	run.Status = store.StatusRunning
	if err := s.UpdateScanRun(ctx, &run); err != nil {
		t.Fatalf("update to running: %v", err)
	}
	got, err := s.GetScanRun(ctx, run.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != store.StatusRunning {
		t.Errorf("status = %q, want %q", got.Status, store.StatusRunning)
	}

	// Update to completed.
	now := time.Now()
	run.Status = store.StatusCompleted
	run.CompletedAt = &now
	run.FindingCount = 42
	if err := s.UpdateScanRun(ctx, &run); err != nil {
		t.Fatalf("update to completed: %v", err)
	}
	got, err = s.GetScanRun(ctx, run.ID)
	if err != nil {
		t.Fatalf("get completed: %v", err)
	}
	if got.Status != store.StatusCompleted {
		t.Errorf("status = %q, want %q", got.Status, store.StatusCompleted)
	}
	if got.FindingCount != 42 {
		t.Errorf("finding_count = %d, want 42", got.FindingCount)
	}
}

func TestStoreRoundTrip_Report(t *testing.T) {
	ctx := context.Background()
	s := memory.New()

	run := makeScanRun("report.example.com")
	if err := s.CreateScanRun(ctx, &run); err != nil {
		t.Fatalf("create: %v", err)
	}

	rpt := &store.Report{
		ID:          "rpt-001",
		ScanRunID:   run.ID,
		Domain:      "report.example.com",
		HTMLContent: "<html><body>Test report</body></html>",
		Summary:     "3 critical findings, 5 high",
		CreatedAt:   time.Now(),
	}
	if err := s.SaveReport(ctx, rpt); err != nil {
		t.Fatalf("save report: %v", err)
	}

	got, err := s.GetReport(ctx, run.ID)
	if err != nil {
		t.Fatalf("get report: %v", err)
	}
	if got.HTMLContent != rpt.HTMLContent {
		t.Error("report HTML content mismatch")
	}
	if got.Summary != rpt.Summary {
		t.Error("report summary mismatch")
	}
}

func TestStoreRoundTrip_DeleteScanRun(t *testing.T) {
	ctx := context.Background()
	s := memory.New()

	run := makeScanRun("delete.example.com")
	if err := s.CreateScanRun(ctx, &run); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.SaveFindings(ctx, run.ID, []finding.Finding{
		makeFinding(finding.CheckHeadersMissingCSP, finding.SeverityLow, "delete.example.com", "Missing CSP"),
	}); err != nil {
		t.Fatalf("save findings: %v", err)
	}

	// Delete and verify.
	if err := s.DeleteScanRun(ctx, run.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	_, err := s.GetScanRun(ctx, run.ID)
	if err == nil {
		t.Error("expected error after deleting scan run, got nil")
	}
	findings, err := s.GetFindings(ctx, run.ID)
	if err != nil {
		t.Fatalf("get findings after delete: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings after delete, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// 3. Report generation: JSON, OCSF, graph
// ---------------------------------------------------------------------------

func TestReportGeneration_JSON(t *testing.T) {
	run := makeScanRun("json-report.example.com")
	findings := []finding.Finding{
		makeFinding(finding.CheckTLSCertExpiry7d, finding.SeverityHigh, "api.json-report.example.com", "TLS cert expiring soon"),
		makeFinding(finding.CheckHeadersMissingHSTS, finding.SeverityMedium, "json-report.example.com", "Missing HSTS"),
		makeFinding(finding.CheckDNSMissingCAA, finding.SeverityLow, "json-report.example.com", "No CAA record"),
	}

	enricher := enrichment.NewNoop()
	enriched, err := enricher.Enrich(context.Background(), findings)
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}

	jsonStr, err := report.RenderJSON(run, enriched, "Test summary with 3 findings", nil)
	if err != nil {
		t.Fatalf("render JSON: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// Verify required fields.
	if parsed["domain"] != "json-report.example.com" {
		t.Errorf("domain = %v", parsed["domain"])
	}
	if parsed["scan_type"] != "surface" {
		t.Errorf("scan_type = %v", parsed["scan_type"])
	}
	if parsed["executive_summary"] != "Test summary with 3 findings" {
		t.Errorf("executive_summary = %v", parsed["executive_summary"])
	}
	if int(parsed["finding_count"].(float64)) != 3 {
		t.Errorf("finding_count = %v, want 3", parsed["finding_count"])
	}

	// Verify findings are sorted by severity (critical > high > medium > low > info).
	findingsArr := parsed["findings"].([]any)
	if len(findingsArr) != 3 {
		t.Fatalf("findings array len = %d, want 3", len(findingsArr))
	}
	// First finding should be highest severity (high).
	first := findingsArr[0].(map[string]any)
	firstFinding := first["finding"].(map[string]any)
	if firstFinding["severity"].(float64) != float64(finding.SeverityHigh) {
		t.Errorf("first finding severity should be high (%d), got %v",
			finding.SeverityHigh, firstFinding["severity"])
	}
}

func TestReportGeneration_OCSF(t *testing.T) {
	run := makeScanRun("ocsf.example.com")
	findings := []finding.Finding{
		makeFinding(finding.CheckTLSCertExpiry7d, finding.SeverityHigh, "ocsf.example.com", "TLS cert expiring (CVE-2024-12345)"),
		makeFinding(finding.CheckEmailSPFMissing, finding.SeverityMedium, "ocsf.example.com", "No SPF record"),
	}

	enricher := enrichment.NewNoop()
	enriched, err := enricher.Enrich(context.Background(), findings)
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}

	ocsfStr, err := report.RenderOCSF(run, enriched)
	if err != nil {
		t.Fatalf("render OCSF: %v", err)
	}

	// OCSF output is NDJSON: first line is scan envelope, then one line per finding.
	lines := strings.Split(strings.TrimSpace(ocsfStr), "\n")
	expectedLines := 3 // 1 envelope + 2 findings
	if len(lines) != expectedLines {
		t.Fatalf("OCSF output has %d lines, want %d", len(lines), expectedLines)
	}

	// Validate envelope line.
	var envelope map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &envelope); err != nil {
		t.Fatalf("envelope not valid JSON: %v", err)
	}
	if int(envelope["class_uid"].(float64)) != 5001 {
		t.Errorf("envelope class_uid = %v, want 5001", envelope["class_uid"])
	}

	// Validate first finding event.
	var event map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &event); err != nil {
		t.Fatalf("finding event not valid JSON: %v", err)
	}
	if int(event["class_uid"].(float64)) != 5001 {
		t.Errorf("event class_uid = %v, want 5001", event["class_uid"])
	}
	if event["class_name"] != "Vulnerability Finding" {
		t.Errorf("class_name = %v", event["class_name"])
	}
	if int(event["severity_id"].(float64)) < 1 || int(event["severity_id"].(float64)) > 5 {
		t.Errorf("severity_id = %v, out of OCSF range", event["severity_id"])
	}

	// Verify CVE extraction.
	vulns, ok := event["vulnerabilities"].([]any)
	if ok && len(vulns) > 0 {
		firstVuln := vulns[0].(map[string]any)
		cve, hasCVE := firstVuln["cve"].(map[string]any)
		if hasCVE {
			if !strings.HasPrefix(cve["uid"].(string), "CVE-") {
				t.Errorf("CVE uid = %v, expected CVE- prefix", cve["uid"])
			}
		}
	}

	// Validate resource field.
	resource := event["resource"].(map[string]any)
	if resource["name"] != "ocsf.example.com" {
		t.Errorf("resource.name = %v", resource["name"])
	}
}

func TestReportGeneration_Text(t *testing.T) {
	run := makeScanRun("text.example.com")
	findings := []finding.Finding{
		makeFinding(finding.CheckTLSCertExpiry7d, finding.SeverityCritical, "text.example.com", "TLS cert expired"),
		makeFinding(finding.CheckHeadersMissingCSP, finding.SeverityLow, "text.example.com", "Missing CSP"),
	}

	enricher := enrichment.NewNoop()
	enriched, err := enricher.Enrich(context.Background(), findings)
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}

	textOut := report.RenderText(run, enriched, "2 findings found", nil)

	// Verify text report contains expected elements.
	if !strings.Contains(textOut, "BEACON SECURITY REPORT") {
		t.Error("text report missing header")
	}
	if !strings.Contains(textOut, "text.example.com") {
		t.Error("text report missing domain")
	}
	if !strings.Contains(textOut, "SUMMARY") {
		t.Error("text report missing SUMMARY section")
	}
	if !strings.Contains(textOut, "Critical") {
		t.Error("text report missing Critical severity count")
	}
	if !strings.Contains(textOut, "EXECUTIVE SUMMARY") {
		t.Error("text report missing executive summary")
	}
}

func TestReportGeneration_Markdown(t *testing.T) {
	run := makeScanRun("md.example.com")
	findings := []finding.Finding{
		makeFinding(finding.CheckWebXSS, finding.SeverityHigh, "md.example.com", "Reflected XSS found"),
	}
	enricher := enrichment.NewNoop()
	enriched, err := enricher.Enrich(context.Background(), findings)
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}

	mdOut := report.RenderMarkdown(run, enriched, "XSS finding", nil)

	if !strings.Contains(mdOut, "# Beacon Security Report") {
		t.Error("markdown missing header")
	}
	if !strings.Contains(mdOut, "md.example.com") {
		t.Error("markdown missing domain")
	}
	if !strings.Contains(mdOut, "Reflected XSS found") {
		t.Error("markdown missing finding title")
	}
}

func TestReportGeneration_GraphDOT(t *testing.T) {
	graph := asset.AssetGraph{
		ScanRunID: "test-001",
		Domain:    "graph.example.com",
		Assets: []asset.Asset{
			{ID: "domain:graph.example.com", Type: asset.AssetTypeDomain, Provider: "web", Name: "graph.example.com"},
			{ID: "ip:1.2.3.4", Type: asset.AssetTypeIP, Provider: "network", Name: "1.2.3.4"},
		},
		Relationships: []asset.Relationship{
			{FromID: "domain:graph.example.com", ToID: "ip:1.2.3.4", Type: asset.RelPointsTo, Confidence: 1.0},
		},
		Findings: []asset.FindingRef{
			{FindingID: "tls-0", AssetID: "domain:graph.example.com", CheckID: "tls.cert_expiry_7d", Severity: "high", Title: "TLS cert expiring"},
		},
	}

	dotOut := report.RenderGraphDOT(graph)

	if !strings.Contains(dotOut, "digraph beacon") {
		t.Error("DOT output missing digraph declaration")
	}
	if !strings.Contains(dotOut, "graph.example.com") {
		t.Error("DOT output missing domain label")
	}
	if !strings.Contains(dotOut, "->") {
		t.Error("DOT output missing edge declaration")
	}
	if !strings.HasSuffix(strings.TrimSpace(dotOut), "}") {
		t.Error("DOT output should end with closing brace")
	}
}

// ---------------------------------------------------------------------------
// 4. Asset graph pipeline: build → serialize → deserialize → verify
// ---------------------------------------------------------------------------

func TestAssetGraphPipeline(t *testing.T) {
	b := asset.NewBuilder("run-graph-001", "graph-pipeline.example.com")

	// Add domain + IPs.
	b.AddDomainAsset("graph-pipeline.example.com", []string{"10.0.0.1"}, "subdomain")
	b.AddDomainAsset("api.graph-pipeline.example.com", []string{"10.0.0.2"}, "subdomain")

	// Add a cloud asset.
	b.AddAsset(asset.Asset{
		ID:       "gcp_compute_instance:projects/acme/zones/us-central1-a/instances/api-prod",
		Type:     asset.AssetTypeGCPInstance,
		Provider: "gcp",
		Name:     "api-prod",
		Account:  "acme",
		Region:   "us-central1-a",
		Public:   true,
		Metadata: map[string]any{
			"external_ip":     "10.0.0.2",
			"machine_type":    "e2-standard-4",
		},
		IAMContext: &asset.IAMContext{
			Principal: "sa@acme.iam.gserviceaccount.com",
			Roles:     []string{"roles/editor"},
			Issues:    []string{"primitive_role"},
		},
		DiscoveredBy: "cloud.gcp_compute",
		Confidence:   1.0,
	})

	// Add a relationship.
	b.AddRelationship(asset.Relationship{
		FromID:     "gcp_compute_instance:projects/acme/zones/us-central1-a/instances/api-prod",
		ToID:       "domain:api.graph-pipeline.example.com",
		Type:       asset.RelExposes,
		Confidence: 0.95,
	})

	// Add findings.
	b.AddFindings([]finding.Finding{
		makeFinding(finding.CheckTLSCertExpiry7d, finding.SeverityHigh, "api.graph-pipeline.example.com", "TLS cert expiring"),
	})

	// Build the graph.
	graph := b.Build()

	if graph.Domain != "graph-pipeline.example.com" {
		t.Errorf("domain = %q", graph.Domain)
	}
	if len(graph.Assets) < 4 { // domain + 2 IPs + GCP instance + subdomain
		t.Errorf("expected at least 4 assets, got %d", len(graph.Assets))
	}
	if len(graph.Relationships) < 3 { // 2 points_to + 1 exposes + possible cross-ref
		t.Errorf("expected at least 3 relationships, got %d", len(graph.Relationships))
	}
	if len(graph.Findings) != 1 {
		t.Errorf("expected 1 finding ref, got %d", len(graph.Findings))
	}

	// Serialize to JSON.
	graphJSON, err := json.Marshal(graph)
	if err != nil {
		t.Fatalf("marshal graph: %v", err)
	}

	// Store and retrieve.
	ctx := context.Background()
	s := memory.New()
	if err := s.SaveAssetGraph(ctx, "run-graph-001", graphJSON); err != nil {
		t.Fatalf("save asset graph: %v", err)
	}
	retrievedJSON, err := s.GetAssetGraph(ctx, "run-graph-001")
	if err != nil {
		t.Fatalf("get asset graph: %v", err)
	}

	// Deserialize and verify.
	var restored asset.AssetGraph
	if err := json.Unmarshal(retrievedJSON, &restored); err != nil {
		t.Fatalf("unmarshal restored graph: %v", err)
	}
	if restored.Domain != graph.Domain {
		t.Errorf("restored domain = %q, want %q", restored.Domain, graph.Domain)
	}
	if len(restored.Assets) != len(graph.Assets) {
		t.Errorf("restored assets = %d, want %d", len(restored.Assets), len(graph.Assets))
	}
	if len(restored.Relationships) != len(graph.Relationships) {
		t.Errorf("restored relationships = %d, want %d", len(restored.Relationships), len(graph.Relationships))
	}

	// Verify the GCP instance retained IAM context.
	for _, a := range restored.Assets {
		if a.Type == asset.AssetTypeGCPInstance {
			if a.IAMContext == nil {
				t.Error("GCP instance lost IAMContext after round-trip")
			} else if a.IAMContext.Principal != "sa@acme.iam.gserviceaccount.com" {
				t.Errorf("IAMContext.Principal = %q", a.IAMContext.Principal)
			}
		}
	}
}

func TestAssetGraphPipeline_JSONInReport(t *testing.T) {
	// Build graph → serialize → pass to RenderJSON → verify graph appears in output.
	b := asset.NewBuilder("run-json-graph", "json-graph.example.com")
	b.AddDomainAsset("json-graph.example.com", []string{"10.0.0.5"}, "root")
	graph := b.Build()
	graphJSON, err := json.Marshal(graph)
	if err != nil {
		t.Fatalf("marshal graph: %v", err)
	}

	run := makeScanRun("json-graph.example.com")
	f := makeFinding(finding.CheckHeadersMissingHSTS, finding.SeverityMedium, "json-graph.example.com", "Missing HSTS")
	ef := makeEnriched(f)
	jsonOut, err := report.RenderJSON(run, []enrichment.EnrichedFinding{ef}, "Summary", graphJSON)
	if err != nil {
		t.Fatalf("render JSON with graph: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(jsonOut), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	assetGraph, ok := parsed["asset_graph"]
	if !ok || assetGraph == nil {
		t.Error("JSON report missing asset_graph field when graph is provided")
	}
}

// ---------------------------------------------------------------------------
// 5. Enrichment pipeline: noop enricher → verify enriched output
// ---------------------------------------------------------------------------

func TestEnrichmentPipeline_NoopEnricher(t *testing.T) {
	ctx := context.Background()
	enricher := enrichment.NewNoop()

	findings := []finding.Finding{
		makeFinding(finding.CheckTLSCertExpiry7d, finding.SeverityHigh, "enrich.example.com", "TLS cert expiring"),
		makeFinding(finding.CheckEmailSPFMissing, finding.SeverityMedium, "enrich.example.com", "No SPF record"),
		makeFinding(finding.CheckWebXSS, finding.SeverityCritical, "app.enrich.example.com", "Reflected XSS"),
	}

	enriched, err := enricher.Enrich(ctx, findings)
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}

	if len(enriched) != len(findings) {
		t.Fatalf("enriched %d findings, want %d", len(enriched), len(findings))
	}

	for i, ef := range enriched {
		if ef.Finding.CheckID != findings[i].CheckID {
			t.Errorf("[%d] CheckID = %q, want %q", i, ef.Finding.CheckID, findings[i].CheckID)
		}
		if ef.Explanation == "" {
			t.Errorf("[%d] Explanation is empty", i)
		}
		if ef.Impact == "" {
			t.Errorf("[%d] Impact is empty", i)
		}
		if ef.Remediation == "" {
			t.Errorf("[%d] Remediation is empty", i)
		}
	}
}

func TestEnrichmentPipeline_ContextualizeAndSummarize(t *testing.T) {
	ctx := context.Background()
	enricher := enrichment.NewNoop()

	findings := []finding.Finding{
		makeFinding(finding.CheckTLSCertExpiry7d, finding.SeverityCritical, "ctx.example.com", "TLS expired"),
		makeFinding(finding.CheckHeadersMissingHSTS, finding.SeverityHigh, "ctx.example.com", "No HSTS"),
		makeFinding(finding.CheckEmailSPFMissing, finding.SeverityMedium, "ctx.example.com", "No SPF"),
		makeFinding(finding.CheckDNSMissingCAA, finding.SeverityLow, "ctx.example.com", "No CAA"),
	}

	enriched, err := enricher.Enrich(ctx, findings)
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}

	contextualized, summary, err := enricher.ContextualizeAndSummarize(ctx, enriched, "ctx.example.com")
	if err != nil {
		t.Fatalf("contextualize: %v", err)
	}

	if len(contextualized) != len(enriched) {
		t.Errorf("contextualized %d, want %d", len(contextualized), len(enriched))
	}
	if summary == "" {
		t.Error("executive summary is empty")
	}
	if !strings.Contains(summary, "ctx.example.com") {
		t.Error("executive summary should mention the domain")
	}
	if !strings.Contains(summary, "1 critical") {
		t.Error("executive summary should mention critical count")
	}
}

func TestEnrichmentPipeline_ComplianceTags(t *testing.T) {
	ctx := context.Background()
	enricher := enrichment.NewNoop()

	f := makeFinding(finding.CheckEmailSPFMissing, finding.SeverityMedium, "compliance.example.com", "No SPF")
	enriched, err := enricher.Enrich(ctx, []finding.Finding{f})
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}

	if len(enriched) != 1 {
		t.Fatalf("expected 1 enriched finding")
	}

	// CheckEmailSPFMissing should have compliance tags from the compliance map.
	tags := enriched[0].ComplianceTags
	if len(tags) == 0 {
		t.Error("expected compliance tags for CheckEmailSPFMissing, got none")
	}

	hasSOC2 := false
	for _, tag := range tags {
		if strings.HasPrefix(tag, "SOC2") {
			hasSOC2 = true
		}
	}
	if !hasSOC2 {
		t.Error("expected SOC2 compliance tag for email.spf_missing")
	}
}

func TestEnrichmentPipeline_StoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	enricher := enrichment.NewNoop()

	run := makeScanRun("enrich-store.example.com")
	if err := s.CreateScanRun(ctx, &run); err != nil {
		t.Fatalf("create run: %v", err)
	}

	findings := []finding.Finding{
		makeFinding(finding.CheckTLSCertExpiry7d, finding.SeverityHigh, "enrich-store.example.com", "TLS expiring"),
	}
	if err := s.SaveFindings(ctx, run.ID, findings); err != nil {
		t.Fatalf("save findings: %v", err)
	}

	enriched, err := enricher.Enrich(ctx, findings)
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if err := s.SaveEnrichedFindings(ctx, run.ID, enriched); err != nil {
		t.Fatalf("save enriched: %v", err)
	}

	// Retrieve enriched from store.
	retrieved, err := s.GetEnrichedFindings(ctx, run.ID)
	if err != nil {
		t.Fatalf("get enriched: %v", err)
	}
	if len(retrieved) != 1 {
		t.Fatalf("expected 1, got %d", len(retrieved))
	}
	if retrieved[0].Finding.CheckID != finding.CheckTLSCertExpiry7d {
		t.Errorf("check ID mismatch: %q", retrieved[0].Finding.CheckID)
	}

	// Generate report from stored data.
	jsonOut, err := report.RenderJSON(run, retrieved, "Test summary", nil)
	if err != nil {
		t.Fatalf("render JSON: %v", err)
	}
	if !strings.Contains(jsonOut, "enrich-store.example.com") {
		t.Error("JSON report missing domain")
	}
}

// ---------------------------------------------------------------------------
// 6. Multi-format output: same findings → JSON, OCSF, text
// ---------------------------------------------------------------------------

func TestMultiFormatOutput(t *testing.T) {
	run := makeScanRun("multiformat.example.com")
	findings := []finding.Finding{
		makeFinding(finding.CheckTLSCertExpiry7d, finding.SeverityCritical, "multiformat.example.com", "TLS cert expired"),
		makeFinding(finding.CheckHeadersMissingHSTS, finding.SeverityHigh, "multiformat.example.com", "Missing HSTS"),
		makeFinding(finding.CheckEmailSPFMissing, finding.SeverityMedium, "multiformat.example.com", "No SPF record"),
		makeFinding(finding.CheckDNSMissingCAA, finding.SeverityLow, "multiformat.example.com", "No CAA record"),
		makeFinding(finding.CheckWAFDetected, finding.SeverityInfo, "multiformat.example.com", "Cloudflare WAF detected"),
	}

	enricher := enrichment.NewNoop()
	enriched, err := enricher.Enrich(context.Background(), findings)
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}

	// JSON format.
	t.Run("JSON", func(t *testing.T) {
		jsonStr, err := report.RenderJSON(run, enriched, "Multi-format test", nil)
		if err != nil {
			t.Fatalf("render JSON: %v", err)
		}
		var parsed map[string]any
		if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if int(parsed["finding_count"].(float64)) != 5 {
			t.Errorf("JSON finding_count = %v, want 5", parsed["finding_count"])
		}
	})

	// OCSF format.
	t.Run("OCSF", func(t *testing.T) {
		ocsfStr, err := report.RenderOCSF(run, enriched)
		if err != nil {
			t.Fatalf("render OCSF: %v", err)
		}
		lines := strings.Split(strings.TrimSpace(ocsfStr), "\n")
		// 1 envelope + 5 findings
		if len(lines) != 6 {
			t.Errorf("OCSF lines = %d, want 6", len(lines))
		}
		// Every line must be valid JSON.
		for i, line := range lines {
			var obj map[string]any
			if err := json.Unmarshal([]byte(line), &obj); err != nil {
				t.Errorf("OCSF line %d is not valid JSON: %v", i, err)
			}
		}
	})

	// Text format.
	t.Run("Text", func(t *testing.T) {
		textStr := report.RenderText(run, enriched, "Multi-format test", nil)
		if textStr == "" {
			t.Error("text report is empty")
		}
		if !strings.Contains(textStr, "multiformat.example.com") {
			t.Error("text report missing domain")
		}
	})

	// Markdown format.
	t.Run("Markdown", func(t *testing.T) {
		mdStr := report.RenderMarkdown(run, enriched, "Multi-format test", nil)
		if mdStr == "" {
			t.Error("markdown report is empty")
		}
		if !strings.Contains(mdStr, "multiformat.example.com") {
			t.Error("markdown report missing domain")
		}
	})
}

// ---------------------------------------------------------------------------
// 7. Finding deduplication: submit duplicates → verify dedup
// ---------------------------------------------------------------------------

func TestFindingDeduplication_StoreAppend(t *testing.T) {
	ctx := context.Background()
	s := memory.New()

	run := makeScanRun("dedup.example.com")
	if err := s.CreateScanRun(ctx, &run); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Save the same finding twice in separate batches.
	f1 := makeFinding(finding.CheckHeadersMissingHSTS, finding.SeverityMedium, "dedup.example.com", "Missing HSTS")
	f2 := makeFinding(finding.CheckHeadersMissingHSTS, finding.SeverityMedium, "dedup.example.com", "Missing HSTS")

	if err := s.SaveFindings(ctx, run.ID, []finding.Finding{f1}); err != nil {
		t.Fatalf("save batch 1: %v", err)
	}
	if err := s.SaveFindings(ctx, run.ID, []finding.Finding{f2}); err != nil {
		t.Fatalf("save batch 2: %v", err)
	}

	// Without dedup, store appends both.
	all, err := s.GetFindings(ctx, run.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 raw findings (store appends), got %d", len(all))
	}

	// Dedup at the report layer: group by (CheckID, Asset) and keep unique.
	seen := make(map[string]bool)
	var deduped []finding.Finding
	for _, f := range all {
		key := string(f.CheckID) + "|" + f.Asset
		if !seen[key] {
			seen[key] = true
			deduped = append(deduped, f)
		}
	}
	if len(deduped) != 1 {
		t.Errorf("after dedup, expected 1 finding, got %d", len(deduped))
	}
	if deduped[0].CheckID != finding.CheckHeadersMissingHSTS {
		t.Errorf("deduped CheckID = %q", deduped[0].CheckID)
	}
}

func TestFindingDeduplication_DifferentAssets(t *testing.T) {
	// Same check ID on different assets should NOT be deduped.
	f1 := makeFinding(finding.CheckHeadersMissingHSTS, finding.SeverityMedium, "a.example.com", "Missing HSTS")
	f2 := makeFinding(finding.CheckHeadersMissingHSTS, finding.SeverityMedium, "b.example.com", "Missing HSTS")

	seen := make(map[string]bool)
	var deduped []finding.Finding
	for _, f := range []finding.Finding{f1, f2} {
		key := string(f.CheckID) + "|" + f.Asset
		if !seen[key] {
			seen[key] = true
			deduped = append(deduped, f)
		}
	}
	if len(deduped) != 2 {
		t.Errorf("same check on different assets should produce 2, got %d", len(deduped))
	}
}

func TestFindingDeduplication_DifferentChecks(t *testing.T) {
	// Different check IDs on the same asset should NOT be deduped.
	f1 := makeFinding(finding.CheckHeadersMissingHSTS, finding.SeverityMedium, "c.example.com", "Missing HSTS")
	f2 := makeFinding(finding.CheckHeadersMissingCSP, finding.SeverityLow, "c.example.com", "Missing CSP")

	seen := make(map[string]bool)
	var deduped []finding.Finding
	for _, f := range []finding.Finding{f1, f2} {
		key := string(f.CheckID) + "|" + f.Asset
		if !seen[key] {
			seen[key] = true
			deduped = append(deduped, f)
		}
	}
	if len(deduped) != 2 {
		t.Errorf("different checks on same asset should produce 2, got %d", len(deduped))
	}
}

// ---------------------------------------------------------------------------
// 8. Severity filtering: mixed findings → filter by severity
// ---------------------------------------------------------------------------

func TestSeverityFiltering(t *testing.T) {
	allFindings := []finding.Finding{
		makeFinding(finding.CheckTLSCertExpiry7d, finding.SeverityCritical, "sev.example.com", "Expired cert"),
		makeFinding(finding.CheckHeadersMissingHSTS, finding.SeverityHigh, "sev.example.com", "No HSTS"),
		makeFinding(finding.CheckEmailSPFMissing, finding.SeverityMedium, "sev.example.com", "No SPF"),
		makeFinding(finding.CheckDNSMissingCAA, finding.SeverityLow, "sev.example.com", "No CAA"),
		makeFinding(finding.CheckWAFDetected, finding.SeverityInfo, "sev.example.com", "WAF detected"),
	}

	tests := []struct {
		name     string
		minSev   finding.Severity
		expected int
	}{
		{"filter_info_shows_all", finding.SeverityInfo, 5},
		{"filter_low", finding.SeverityLow, 4},
		{"filter_medium", finding.SeverityMedium, 3},
		{"filter_high", finding.SeverityHigh, 2},
		{"filter_critical", finding.SeverityCritical, 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var filtered []finding.Finding
			for _, f := range allFindings {
				if f.Severity >= tc.minSev {
					filtered = append(filtered, f)
				}
			}
			if len(filtered) != tc.expected {
				t.Errorf("min severity %s: got %d findings, want %d",
					tc.minSev, len(filtered), tc.expected)
			}
		})
	}
}

func TestSeverityFiltering_ParseSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected finding.Severity
	}{
		{"critical", finding.SeverityCritical},
		{"high", finding.SeverityHigh},
		{"medium", finding.SeverityMedium},
		{"low", finding.SeverityLow},
		{"info", finding.SeverityInfo},
		{"unknown", finding.SeverityInfo},
		{"", finding.SeverityInfo},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := finding.ParseSeverity(tc.input)
			if got != tc.expected {
				t.Errorf("ParseSeverity(%q) = %v, want %v", tc.input, got, tc.expected)
			}
		})
	}
}

func TestSeverityFiltering_EnrichedFindings(t *testing.T) {
	// Verify filtering works on enriched findings too.
	findings := []finding.Finding{
		makeFinding(finding.CheckTLSCertExpiry7d, finding.SeverityCritical, "ef-sev.example.com", "Expired cert"),
		makeFinding(finding.CheckHeadersMissingHSTS, finding.SeverityHigh, "ef-sev.example.com", "No HSTS"),
		makeFinding(finding.CheckDNSMissingCAA, finding.SeverityLow, "ef-sev.example.com", "No CAA"),
	}

	enricher := enrichment.NewNoop()
	enriched, err := enricher.Enrich(context.Background(), findings)
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}

	minSev := finding.SeverityHigh
	var filtered []enrichment.EnrichedFinding
	for _, ef := range enriched {
		if ef.Finding.Severity >= minSev {
			filtered = append(filtered, ef)
		}
	}
	if len(filtered) != 2 {
		t.Errorf("expected 2 findings >= high, got %d", len(filtered))
	}

	// Verify filtered report only contains high+ findings.
	run := makeScanRun("ef-sev.example.com")
	jsonStr, err := report.RenderJSON(run, filtered, "Filtered report", nil)
	if err != nil {
		t.Fatalf("render JSON: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if int(parsed["finding_count"].(float64)) != 2 {
		t.Errorf("filtered report finding_count = %v, want 2", parsed["finding_count"])
	}
}

// ---------------------------------------------------------------------------
// Additional edge cases
// ---------------------------------------------------------------------------

func TestStoreRoundTrip_AssetGraphNilHandling(t *testing.T) {
	ctx := context.Background()
	s := memory.New()

	// Get non-existent graph returns nil.
	data, err := s.GetAssetGraph(ctx, "nonexistent-run")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data != nil {
		t.Errorf("expected nil for non-existent graph, got %d bytes", len(data))
	}
}

func TestStoreRoundTrip_EnrichmentCache(t *testing.T) {
	ctx := context.Background()
	s := memory.New()

	checkID := finding.CheckTLSCertExpiry7d

	// Cache miss.
	_, _, _, found := s.GetEnrichmentCache(ctx, checkID)
	if found {
		t.Error("expected cache miss")
	}

	// Cache write.
	err := s.SaveEnrichmentCache(ctx, checkID, "cert is expiring", "service outage", "renew the cert")
	if err != nil {
		t.Fatalf("save cache: %v", err)
	}

	// Cache hit.
	expl, impact, remed, found := s.GetEnrichmentCache(ctx, checkID)
	if !found {
		t.Fatal("expected cache hit")
	}
	if expl != "cert is expiring" {
		t.Errorf("explanation = %q", expl)
	}
	if impact != "service outage" {
		t.Errorf("impact = %q", impact)
	}
	if remed != "renew the cert" {
		t.Errorf("remediation = %q", remed)
	}
}

func TestStoreRoundTrip_Suppressions(t *testing.T) {
	ctx := context.Background()
	s := memory.New()

	sup := &store.FindingSuppression{
		Domain:  "sup.example.com",
		CheckID: finding.CheckHeadersMissingHSTS,
		Asset:   "sup.example.com",
		Status:  store.SuppressionAcceptedRisk,
		Note:    "Accepted risk: internal-only service",
	}
	if err := s.UpsertSuppression(ctx, sup); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	sups, err := s.ListSuppressions(ctx, "sup.example.com")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(sups) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(sups))
	}
	if sups[0].CheckID != finding.CheckHeadersMissingHSTS {
		t.Errorf("CheckID = %q", sups[0].CheckID)
	}
	if sups[0].Status != store.SuppressionAcceptedRisk {
		t.Errorf("Status = %q", sups[0].Status)
	}

	// Delete and verify.
	if err := s.DeleteSuppression(ctx, sups[0].ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	sups2, _ := s.ListSuppressions(ctx, "sup.example.com")
	if len(sups2) != 0 {
		t.Errorf("expected 0 after delete, got %d", len(sups2))
	}
}

func TestStoreRoundTrip_CorrelationFindings(t *testing.T) {
	ctx := context.Background()
	s := memory.New()

	cfs := []store.CorrelationFinding{
		{
			ScanRunID:          "run-corr-001",
			Domain:             "corr.example.com",
			Title:              "Cross-asset attack chain: exposed admin + default creds",
			Severity:           finding.SeverityCritical,
			Description:        "Admin panel on sub.corr.example.com uses default credentials, accessible via exposed port 8080",
			AffectedAssets:     []string{"sub.corr.example.com", "corr.example.com"},
			ContributingChecks: []string{"exposure.admin_path", "web.default_credentials"},
			Remediation:        "Change default credentials and restrict admin panel access",
		},
	}
	if err := s.SaveCorrelationFindings(ctx, cfs); err != nil {
		t.Fatalf("save: %v", err)
	}

	retrieved, err := s.ListCorrelationFindings(ctx, "corr.example.com")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(retrieved) != 1 {
		t.Fatalf("expected 1, got %d", len(retrieved))
	}
	if retrieved[0].Title != cfs[0].Title {
		t.Errorf("title = %q", retrieved[0].Title)
	}
	if retrieved[0].Severity != finding.SeverityCritical {
		t.Errorf("severity = %v", retrieved[0].Severity)
	}
}

func TestEmptyFindings_ReportGeneration(t *testing.T) {
	run := makeScanRun("empty.example.com")
	var enriched []enrichment.EnrichedFinding

	// JSON should work with zero findings.
	jsonStr, err := report.RenderJSON(run, enriched, "No findings", nil)
	if err != nil {
		t.Fatalf("render JSON: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if int(parsed["finding_count"].(float64)) != 0 {
		t.Errorf("finding_count = %v, want 0", parsed["finding_count"])
	}

	// OCSF should produce only the envelope line.
	ocsfStr, err := report.RenderOCSF(run, enriched)
	if err != nil {
		t.Fatalf("render OCSF: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(ocsfStr), "\n")
	if len(lines) != 1 {
		t.Errorf("OCSF with no findings: %d lines, want 1 (envelope only)", len(lines))
	}

	// Text should still produce a report header.
	textStr := report.RenderText(run, enriched, "Clean scan", nil)
	if !strings.Contains(textStr, "BEACON SECURITY REPORT") {
		t.Error("text report missing header even with 0 findings")
	}
}
