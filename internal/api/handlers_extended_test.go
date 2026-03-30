package api_test

// Extended HTTP handler tests — covers dashboard, findings, trend, compliance,
// correlations, suppressions, targets, report, and error conditions.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stormbane/beacon/internal/api"
	"github.com/stormbane/beacon/internal/config"
	"github.com/stormbane/beacon/internal/enrichment"
	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
	"github.com/stormbane/beacon/internal/store"
	memstore "github.com/stormbane/beacon/internal/store/memory"
	"github.com/stormbane/beacon/internal/worker"
)

// ── shared test helpers ─────────────────────────────────────────────────────

// newSeededServer creates a test server with pre-seeded data.
func newSeededServer(t *testing.T, apiKey string) (http.Handler, *memstore.Store) {
	t.Helper()
	st := memstore.New()
	cfg := &config.Config{}
	pool := worker.NewPool(0, st, cfg)
	srv := api.New(st, pool, apiKey)
	return srv.Handler(), st
}

// seedCompletedScan adds a completed scan with findings and enriched findings.
func seedCompletedScan(t *testing.T, st *memstore.Store, domain string) string {
	t.Helper()
	ctx := context.Background()

	target, err := st.UpsertTarget(ctx, domain)
	if err != nil {
		t.Fatalf("UpsertTarget: %v", err)
	}

	now := time.Now()
	completedAt := now.Add(1 * time.Minute)
	run := &store.ScanRun{
		ID:           "scan-001",
		TargetID:     target.ID,
		Domain:       domain,
		ScanType:     module.ScanSurface,
		Modules:      []string{"surface"},
		Status:       store.StatusCompleted,
		StartedAt:    now,
		CompletedAt:  &completedAt,
		FindingCount: 3,
	}
	if err := st.CreateScanRun(ctx, run); err != nil {
		t.Fatalf("CreateScanRun: %v", err)
	}

	findings := []finding.Finding{
		{
			CheckID:      finding.CheckTLSCertExpiry30d,
			Module:       "surface",
			Scanner:      "tls",
			Severity:     finding.SeverityHigh,
			Title:        "TLS cert expiring soon",
			Description:  "Certificate expires in 25 days",
			Asset:        "api." + domain,
			ProofCommand: "openssl s_client -connect api." + domain + ":443",
			DiscoveredAt: now,
		},
		{
			CheckID:      finding.CheckHeadersMissingHSTS,
			Module:       "surface",
			Scanner:      "headers",
			Severity:     finding.SeverityMedium,
			Title:        "Missing HSTS header",
			Description:  "Strict-Transport-Security header not set",
			Asset:        domain,
			ProofCommand: "curl -sI https://" + domain + " | grep -i strict",
			DiscoveredAt: now,
		},
		{
			CheckID:      finding.CheckExposureRobotsLeak,
			Module:       "surface",
			Scanner:      "exposure",
			Severity:     finding.SeverityInfo,
			Title:        "Robots.txt disallow leak",
			Description:  "robots.txt reveals hidden paths",
			Asset:        domain,
			ProofCommand: "curl -s https://" + domain + "/robots.txt",
			DiscoveredAt: now,
		},
	}
	if err := st.SaveFindings(ctx, run.ID, findings); err != nil {
		t.Fatalf("SaveFindings: %v", err)
	}

	enriched := []enrichment.EnrichedFinding{
		{
			Finding:     findings[0],
			Explanation: "The TLS certificate is expiring soon.",
			Impact:      "Users will see browser warnings.",
			Remediation: "Renew the certificate.",
		},
		{
			Finding:     findings[1],
			Explanation: "HSTS is not configured.",
			Impact:      "SSL stripping attacks possible.",
			Remediation: "Add Strict-Transport-Security header.",
		},
		{
			Finding:     findings[2],
			Explanation: "Robots.txt reveals paths.",
			Impact:      "Low — informational.",
			Remediation: "Review disallow entries.",
		},
	}
	if err := st.SaveEnrichedFindings(ctx, run.ID, enriched); err != nil {
		t.Fatalf("SaveEnrichedFindings: %v", err)
	}

	return run.ID
}

func deleteJSON(t *testing.T, h http.Handler, path, apiKey string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, path, nil)
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func decodeJSON(t *testing.T, rr *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.NewDecoder(rr.Body).Decode(v); err != nil {
		t.Fatalf("decode response: %v (body: %s)", err, rr.Body.String())
	}
}

// ── Root redirect ────────────────────────────────────────────────────────────

func TestRootRedirectsToUI(t *testing.T) {
	h, _ := newSeededServer(t, "")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("GET / status = %d; want 302", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if loc != "/ui/" {
		t.Errorf("redirect location = %q; want %q", loc, "/ui/")
	}
}

func TestUnknownPathReturns404(t *testing.T) {
	h, _ := newSeededServer(t, "")
	req := httptest.NewRequest(http.MethodGet, "/nonexistent", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("GET /nonexistent status = %d; want 404", rr.Code)
	}
}

// ── Auth middleware ──────────────────────────────────────────────────────────

func TestAuthMiddleware_ConstantTimeComparison(t *testing.T) {
	// Verify that similar-but-wrong tokens are rejected.
	h, _ := newSeededServer(t, "my-secret-api-key")
	rr := getJSON(t, h, "/v1/targets", "my-secret-api-ke") // 1 char short
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("nearly-correct token: status = %d; want 401", rr.Code)
	}
}

func TestAuthMiddleware_EmptyBearerToken(t *testing.T) {
	h, _ := newSeededServer(t, "secret")
	req := httptest.NewRequest(http.MethodGet, "/v1/targets", nil)
	req.Header.Set("Authorization", "Bearer ")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("empty bearer: status = %d; want 401", rr.Code)
	}
}

func TestAuthMiddleware_NoBearerPrefix(t *testing.T) {
	h, _ := newSeededServer(t, "secret")
	req := httptest.NewRequest(http.MethodGet, "/v1/targets", nil)
	req.Header.Set("Authorization", "secret") // no "Bearer " prefix
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("no Bearer prefix: status = %d; want 401", rr.Code)
	}
}

func TestAuthMiddleware_BasicAuthRejected(t *testing.T) {
	h, _ := newSeededServer(t, "secret")
	req := httptest.NewRequest(http.MethodGet, "/v1/targets", nil)
	req.Header.Set("Authorization", "Basic c2VjcmV0") // base64("secret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Basic auth: status = %d; want 401", rr.Code)
	}
}

// ── POST /v1/scans — request validation ─────────────────────────────────────

func TestSubmitScan_InvalidJSON(t *testing.T) {
	h, _ := newSeededServer(t, "")
	req := httptest.NewRequest(http.MethodPost, "/v1/scans", strings.NewReader("{invalid json"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("invalid JSON: status = %d; want 400", rr.Code)
	}
}

func TestSubmitScan_EmptyBody(t *testing.T) {
	h, _ := newSeededServer(t, "")
	req := httptest.NewRequest(http.MethodPost, "/v1/scans", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("empty body: status = %d; want 400", rr.Code)
	}
}

func TestSubmitScan_SurfaceWithPermission(t *testing.T) {
	// Surface scan with permission_confirmed=true is fine (permission is only
	// required for deep scans).
	h, _ := newSeededServer(t, "")
	rr := postJSON(t, h, "/v1/scans", map[string]any{
		"domain":               "example.com",
		"deep":                 false,
		"permission_confirmed": true,
	}, "")
	if rr.Code != http.StatusAccepted {
		t.Errorf("surface with permission: status = %d; want 202", rr.Code)
	}
}

func TestSubmitScan_DeepWithPermission(t *testing.T) {
	h, _ := newSeededServer(t, "")
	rr := postJSON(t, h, "/v1/scans", map[string]any{
		"domain":               "example.com",
		"deep":                 true,
		"permission_confirmed": true,
	}, "")
	if rr.Code != http.StatusAccepted {
		t.Errorf("deep with permission: status = %d; want 202", rr.Code)
	}
}

func TestSubmitScan_ResponseHasCorrectFields(t *testing.T) {
	h, _ := newSeededServer(t, "")
	rr := postJSON(t, h, "/v1/scans", map[string]any{
		"domain": "example.com",
	}, "")

	var resp struct {
		ScanRunID string `json:"scan_run_id"`
		Status    string `json:"status"`
		StreamURL string `json:"stream_url"`
	}
	decodeJSON(t, rr, &resp)

	if resp.ScanRunID == "" {
		t.Error("scan_run_id must not be empty")
	}
	if resp.Status != "pending" {
		t.Errorf("status = %q; want %q", resp.Status, "pending")
	}
	if !strings.Contains(resp.StreamURL, resp.ScanRunID) {
		t.Errorf("stream_url %q should contain scan_run_id %q", resp.StreamURL, resp.ScanRunID)
	}
}

// ── GET /v1/scans?domain= ───────────────────────────────────────────────────

func TestListScans_MissingDomainReturns400(t *testing.T) {
	h, _ := newSeededServer(t, "")
	rr := getJSON(t, h, "/v1/scans", "")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("missing domain: status = %d; want 400", rr.Code)
	}
}

func TestListScans_ReturnsSubmittedScans(t *testing.T) {
	h, _ := newSeededServer(t, "")

	// Submit two scans for the same domain
	postJSON(t, h, "/v1/scans", map[string]any{"domain": "example.com"}, "")
	postJSON(t, h, "/v1/scans", map[string]any{"domain": "example.com"}, "")

	rr := getJSON(t, h, "/v1/scans?domain=example.com", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("list scans: status = %d; want 200", rr.Code)
	}

	var resp struct {
		Scans []struct {
			ID     string `json:"id"`
			Domain string `json:"domain"`
		} `json:"scans"`
	}
	decodeJSON(t, rr, &resp)
	if len(resp.Scans) < 2 {
		t.Errorf("expected at least 2 scans, got %d", len(resp.Scans))
	}
}

func TestListScans_EmptyForUnknownDomain(t *testing.T) {
	h, _ := newSeededServer(t, "")
	rr := getJSON(t, h, "/v1/scans?domain=unknown.example.com", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("unknown domain: status = %d; want 200", rr.Code)
	}

	var resp struct {
		Scans []any `json:"scans"`
	}
	decodeJSON(t, rr, &resp)
	if resp.Scans == nil {
		t.Error("scans should be an empty array, not null")
	}
}

// ── GET /v1/scans/{id} ──────────────────────────────────────────────────────

func TestGetScan_ReturnsRecentLogs(t *testing.T) {
	h, _ := newSeededServer(t, "")

	submitRR := postJSON(t, h, "/v1/scans", map[string]any{"domain": "example.com"}, "")
	var submitResp struct {
		ScanRunID string `json:"scan_run_id"`
	}
	decodeJSON(t, submitRR, &submitResp)

	rr := getJSON(t, h, "/v1/scans/"+submitResp.ScanRunID, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("get scan: status = %d; want 200", rr.Code)
	}

	var resp struct {
		ID         string   `json:"id"`
		Domain     string   `json:"domain"`
		Status     string   `json:"status"`
		ScanType   string   `json:"scan_type"`
		RecentLogs []string `json:"recent_logs"`
	}
	decodeJSON(t, rr, &resp)

	if resp.ID != submitResp.ScanRunID {
		t.Errorf("id = %q; want %q", resp.ID, submitResp.ScanRunID)
	}
	if resp.ScanType != string(module.ScanSurface) {
		t.Errorf("scan_type = %q; want %q", resp.ScanType, module.ScanSurface)
	}
}

// ── GET /v1/scans/{id}/report ───────────────────────────────────────────────

func TestGetReport_HTMLDefault(t *testing.T) {
	h, st := newSeededServer(t, "")
	scanID := seedCompletedScan(t, st, "example.com")

	// Add a report
	report := &store.Report{
		ScanRunID:   scanID,
		Domain:      "example.com",
		HTMLContent: "<html><body>Scan Report</body></html>",
		Summary:     "All clear",
		CreatedAt:   time.Now(),
	}
	st.SaveReport(context.Background(), report)

	rr := getJSON(t, h, "/v1/scans/"+scanID+"/report", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("get report: status = %d; want 200", rr.Code)
	}

	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("default Content-Type = %q; want text/html", ct)
	}
	if !strings.Contains(rr.Body.String(), "Scan Report") {
		t.Error("response body should contain HTML content")
	}
}

func TestGetReport_JSONAccept(t *testing.T) {
	h, st := newSeededServer(t, "")
	scanID := seedCompletedScan(t, st, "example.com")

	report := &store.Report{
		ScanRunID:   scanID,
		Domain:      "example.com",
		HTMLContent: "<html>Report</html>",
		Summary:     "All clear",
		CreatedAt:   time.Now(),
	}
	st.SaveReport(context.Background(), report)

	req := httptest.NewRequest(http.MethodGet, "/v1/scans/"+scanID+"/report", nil)
	req.Header.Set("Accept", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("get report (json): status = %d; want 200", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("JSON Accept → Content-Type = %q; want application/json", ct)
	}
}

// ── GET /v1/targets ─────────────────────────────────────────────────────────

func TestListTargets_ReturnsUpsertedTargets(t *testing.T) {
	h, st := newSeededServer(t, "")
	ctx := context.Background()
	st.UpsertTarget(ctx, "alpha.com")
	st.UpsertTarget(ctx, "beta.com")

	rr := getJSON(t, h, "/v1/targets", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("list targets: status = %d; want 200", rr.Code)
	}

	var resp struct {
		Targets []struct {
			Domain string `json:"domain"`
		} `json:"targets"`
	}
	decodeJSON(t, rr, &resp)
	if len(resp.Targets) != 2 {
		t.Errorf("expected 2 targets, got %d", len(resp.Targets))
	}
}

func TestListTargets_EmptyWhenNoTargets(t *testing.T) {
	h, _ := newSeededServer(t, "")
	rr := getJSON(t, h, "/v1/targets", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("empty targets: status = %d; want 200", rr.Code)
	}
}

// ── GET /v1/targets/{domain}/findings ────────────────────────────────────────

func TestDomainFindings_WithCompletedScan(t *testing.T) {
	h, st := newSeededServer(t, "")
	seedCompletedScan(t, st, "example.com")

	rr := getJSON(t, h, "/v1/targets/example.com/findings", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("domain findings: status = %d; want 200", rr.Code)
	}

	var resp struct {
		Domain   string `json:"domain"`
		ScanID   string `json:"scan_id"`
		Findings []struct {
			CheckID  string `json:"check_id"`
			Title    string `json:"title"`
			Severity string `json:"severity"`
			Asset    string `json:"asset"`
			Scanner  string `json:"scanner"`
		} `json:"findings"`
	}
	decodeJSON(t, rr, &resp)

	if resp.Domain != "example.com" {
		t.Errorf("domain = %q; want %q", resp.Domain, "example.com")
	}
	if resp.ScanID == "" {
		t.Error("scan_id must not be empty for completed scan")
	}
	if len(resp.Findings) != 3 {
		t.Errorf("expected 3 findings, got %d", len(resp.Findings))
	}

	// Verify findings are sorted by severity (high > medium > info)
	if len(resp.Findings) >= 3 {
		if resp.Findings[0].Severity != "high" {
			t.Errorf("first finding severity = %q; want %q", resp.Findings[0].Severity, "high")
		}
		if resp.Findings[1].Severity != "medium" {
			t.Errorf("second finding severity = %q; want %q", resp.Findings[1].Severity, "medium")
		}
		if resp.Findings[2].Severity != "info" {
			t.Errorf("third finding severity = %q; want %q", resp.Findings[2].Severity, "info")
		}
	}
}

func TestDomainFindings_EmptyDomain(t *testing.T) {
	h, _ := newSeededServer(t, "")
	// PathValue("domain") would be empty for /v1/targets//findings
	// The mux would 404 on that pattern. Let's test with an unknown domain.
	rr := getJSON(t, h, "/v1/targets/unknown.com/findings", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("unknown domain findings: status = %d; want 200", rr.Code)
	}

	var resp struct {
		Domain   string `json:"domain"`
		ScanID   string `json:"scan_id"`
		Findings []any  `json:"findings"`
	}
	decodeJSON(t, rr, &resp)
	if len(resp.Findings) != 0 {
		t.Errorf("expected 0 findings for unknown domain, got %d", len(resp.Findings))
	}
}

func TestDomainFindings_FallsBackToRawFindings(t *testing.T) {
	h, st := newSeededServer(t, "")
	ctx := context.Background()

	// Create a completed scan with raw findings but NO enriched findings
	target, _ := st.UpsertTarget(ctx, "raw.example.com")
	now := time.Now()
	completedAt := now.Add(1 * time.Minute)
	run := &store.ScanRun{
		ID:           "scan-raw-001",
		TargetID:     target.ID,
		Domain:       "raw.example.com",
		ScanType:     module.ScanSurface,
		Modules:      []string{"surface"},
		Status:       store.StatusCompleted,
		StartedAt:    now,
		CompletedAt:  &completedAt,
		FindingCount: 1,
	}
	st.CreateScanRun(ctx, run)
	st.SaveFindings(ctx, run.ID, []finding.Finding{
		{
			CheckID:      finding.CheckHeadersMissingCSP,
			Module:       "surface",
			Scanner:      "headers",
			Severity:     finding.SeverityMedium,
			Title:        "Missing CSP",
			Description:  "No Content-Security-Policy header",
			Asset:        "raw.example.com",
			DiscoveredAt: now,
		},
	})

	rr := getJSON(t, h, "/v1/targets/raw.example.com/findings", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("raw findings fallback: status = %d; want 200", rr.Code)
	}

	var resp struct {
		Findings []struct {
			CheckID string `json:"check_id"`
		} `json:"findings"`
	}
	decodeJSON(t, rr, &resp)
	if len(resp.Findings) != 1 {
		t.Errorf("expected 1 raw finding, got %d", len(resp.Findings))
	}
}

// ── GET /v1/targets/{domain}/trend ──────────────────────────────────────────

func TestDomainTrend_ReturnsPoints(t *testing.T) {
	h, st := newSeededServer(t, "")
	seedCompletedScan(t, st, "example.com")

	rr := getJSON(t, h, "/v1/targets/example.com/trend", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("trend: status = %d; want 200", rr.Code)
	}

	var resp struct {
		Domain string `json:"domain"`
		Points []struct {
			Date     string `json:"date"`
			Total    int    `json:"total"`
			ScanType string `json:"scan_type"`
			Status   string `json:"status"`
		} `json:"points"`
	}
	decodeJSON(t, rr, &resp)

	if resp.Domain != "example.com" {
		t.Errorf("domain = %q; want %q", resp.Domain, "example.com")
	}
	if len(resp.Points) == 0 {
		t.Error("expected at least 1 trend point for completed scan")
	}
}

func TestDomainTrend_SkipsPendingRuns(t *testing.T) {
	h, st := newSeededServer(t, "")
	ctx := context.Background()

	target, _ := st.UpsertTarget(ctx, "pending.com")
	// Create a pending (not completed) scan
	run := &store.ScanRun{
		ID:        "scan-pending",
		TargetID:  target.ID,
		Domain:    "pending.com",
		ScanType:  module.ScanSurface,
		Status:    store.StatusPending,
		StartedAt: time.Now(),
	}
	st.CreateScanRun(ctx, run)

	rr := getJSON(t, h, "/v1/targets/pending.com/trend", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("trend pending: status = %d; want 200", rr.Code)
	}

	var resp struct {
		Points []any `json:"points"`
	}
	decodeJSON(t, rr, &resp)
	if len(resp.Points) != 0 {
		t.Errorf("expected 0 trend points for pending scan, got %d", len(resp.Points))
	}
}

func TestDomainTrend_MissingDomain(t *testing.T) {
	// This should test the empty domain path — the router extracts it from path.
	// Since it's a path parameter, an empty string is impossible via normal routing,
	// but we test the unknown domain case.
	h, _ := newSeededServer(t, "")
	rr := getJSON(t, h, "/v1/targets/unknown.example.com/trend", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("trend unknown domain: status = %d; want 200", rr.Code)
	}
}

// ── GET /v1/targets/{domain}/compliance ─────────────────────────────────────

func TestDomainCompliance_WithCompletedScan(t *testing.T) {
	h, st := newSeededServer(t, "")
	seedCompletedScan(t, st, "example.com")

	rr := getJSON(t, h, "/v1/targets/example.com/compliance", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("compliance: status = %d; want 200", rr.Code)
	}

	var resp struct {
		Domain     string         `json:"domain"`
		ScanID     string         `json:"scan_id"`
		Frameworks map[string]any `json:"frameworks"`
	}
	decodeJSON(t, rr, &resp)

	if resp.Domain != "example.com" {
		t.Errorf("domain = %q; want %q", resp.Domain, "example.com")
	}
	if resp.ScanID == "" {
		t.Error("scan_id must not be empty for completed scan")
	}
}

func TestDomainCompliance_NoCompletedScan(t *testing.T) {
	h, _ := newSeededServer(t, "")
	rr := getJSON(t, h, "/v1/targets/unknown.com/compliance", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("compliance no scan: status = %d; want 200", rr.Code)
	}

	var resp struct {
		Domain     string         `json:"domain"`
		ScanID     string         `json:"scan_id"`
		Frameworks map[string]any `json:"frameworks"`
	}
	decodeJSON(t, rr, &resp)
	if resp.ScanID != "" {
		t.Errorf("scan_id should be empty, got %q", resp.ScanID)
	}
}

// ── GET /v1/dashboard ───────────────────────────────────────────────────────

func TestDashboard_WithCompletedScan(t *testing.T) {
	h, st := newSeededServer(t, "")
	seedCompletedScan(t, st, "example.com")

	rr := getJSON(t, h, "/v1/dashboard", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("dashboard: status = %d; want 200", rr.Code)
	}

	var resp struct {
		Targets       int `json:"targets"`
		TotalFindings int `json:"total_findings"`
		Critical      int `json:"critical"`
		High          int `json:"high"`
		Medium        int `json:"medium"`
		Low           int `json:"low"`
		Info          int `json:"info"`
		RecentScans   []struct {
			ID     string `json:"id"`
			Domain string `json:"domain"`
		} `json:"recent_scans"`
	}
	decodeJSON(t, rr, &resp)

	if resp.Targets != 1 {
		t.Errorf("targets = %d; want 1", resp.Targets)
	}
	if resp.TotalFindings != 3 {
		t.Errorf("total_findings = %d; want 3", resp.TotalFindings)
	}
	if resp.High != 1 {
		t.Errorf("high = %d; want 1", resp.High)
	}
	if resp.Medium != 1 {
		t.Errorf("medium = %d; want 1", resp.Medium)
	}
	if resp.Info != 1 {
		t.Errorf("info = %d; want 1", resp.Info)
	}
}

func TestDashboard_Empty(t *testing.T) {
	h, _ := newSeededServer(t, "")
	rr := getJSON(t, h, "/v1/dashboard", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("empty dashboard: status = %d; want 200", rr.Code)
	}

	var resp struct {
		Targets       int   `json:"targets"`
		TotalFindings int   `json:"total_findings"`
		RecentScans   []any `json:"recent_scans"`
	}
	decodeJSON(t, rr, &resp)

	if resp.Targets != 0 {
		t.Errorf("targets = %d; want 0", resp.Targets)
	}
	if resp.TotalFindings != 0 {
		t.Errorf("total_findings = %d; want 0", resp.TotalFindings)
	}
}

// ── GET /v1/correlations ────────────────────────────────────────────────────

func TestListCorrelations_MissingDomain(t *testing.T) {
	h, _ := newSeededServer(t, "")
	rr := getJSON(t, h, "/v1/correlations", "")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("missing domain: status = %d; want 400", rr.Code)
	}
}

func TestListCorrelations_ReturnsEmptyArray(t *testing.T) {
	h, _ := newSeededServer(t, "")
	rr := getJSON(t, h, "/v1/correlations?domain=example.com", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("correlations: status = %d; want 200", rr.Code)
	}

	var resp struct {
		Correlations []any `json:"correlations"`
	}
	decodeJSON(t, rr, &resp)
	if resp.Correlations == nil {
		t.Error("correlations should be an empty array, not null")
	}
}

func TestListCorrelations_WithSeededData(t *testing.T) {
	h, st := newSeededServer(t, "")
	ctx := context.Background()

	st.SaveCorrelationFindings(ctx, []store.CorrelationFinding{
		{
			Domain:      "example.com",
			Title:       "Cross-asset chain",
			Severity:    finding.SeverityHigh,
			Description: "Attack chain spanning multiple assets",
		},
	})

	rr := getJSON(t, h, "/v1/correlations?domain=example.com", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("correlations: status = %d; want 200", rr.Code)
	}

	var resp struct {
		Correlations []struct {
			Title string `json:"title"`
		} `json:"correlations"`
	}
	decodeJSON(t, rr, &resp)
	if len(resp.Correlations) != 1 {
		t.Errorf("expected 1 correlation, got %d", len(resp.Correlations))
	}
}

// ── POST /v1/suppressions ───────────────────────────────────────────────────

func TestUpsertSuppression_ValidRequest(t *testing.T) {
	h, _ := newSeededServer(t, "")
	rr := postJSON(t, h, "/v1/suppressions", map[string]any{
		"domain":   "example.com",
		"check_id": "tls.cert_expiry_30d",
		"asset":    "api.example.com",
		"status":   "accepted_risk",
		"note":     "Known issue, tracked in JIRA-123",
	}, "")
	if rr.Code != http.StatusCreated {
		t.Errorf("upsert suppression: status = %d; want 201", rr.Code)
	}

	var resp struct {
		ID      string `json:"id"`
		Domain  string `json:"domain"`
		CheckID string `json:"check_id"`
		Status  string `json:"status"`
		Note    string `json:"note"`
	}
	decodeJSON(t, rr, &resp)
	if resp.ID == "" {
		t.Error("suppression ID must not be empty")
	}
	if resp.Domain != "example.com" {
		t.Errorf("domain = %q; want %q", resp.Domain, "example.com")
	}
}

func TestUpsertSuppression_MissingDomain(t *testing.T) {
	h, _ := newSeededServer(t, "")
	rr := postJSON(t, h, "/v1/suppressions", map[string]any{
		"check_id": "tls.cert_expiry_30d",
		"status":   "accepted_risk",
	}, "")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("missing domain: status = %d; want 400", rr.Code)
	}
}

func TestUpsertSuppression_MissingCheckID(t *testing.T) {
	h, _ := newSeededServer(t, "")
	rr := postJSON(t, h, "/v1/suppressions", map[string]any{
		"domain": "example.com",
		"status": "accepted_risk",
	}, "")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("missing check_id: status = %d; want 400", rr.Code)
	}
}

func TestUpsertSuppression_InvalidStatus(t *testing.T) {
	h, _ := newSeededServer(t, "")
	rr := postJSON(t, h, "/v1/suppressions", map[string]any{
		"domain":   "example.com",
		"check_id": "tls.cert_expiry_30d",
		"status":   "invalid_status",
	}, "")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("invalid status: status = %d; want 400", rr.Code)
	}
}

func TestUpsertSuppression_AllValidStatuses(t *testing.T) {
	validStatuses := []string{"accepted_risk", "false_positive", "wont_fix"}
	for _, status := range validStatuses {
		t.Run(status, func(t *testing.T) {
			h, _ := newSeededServer(t, "")
			rr := postJSON(t, h, "/v1/suppressions", map[string]any{
				"domain":   "example.com",
				"check_id": "test.check",
				"status":   status,
			}, "")
			if rr.Code != http.StatusCreated {
				t.Errorf("status %q: got %d; want 201", status, rr.Code)
			}
		})
	}
}

func TestUpsertSuppression_InvalidJSON(t *testing.T) {
	h, _ := newSeededServer(t, "")
	req := httptest.NewRequest(http.MethodPost, "/v1/suppressions", strings.NewReader("{bad}"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("invalid JSON: status = %d; want 400", rr.Code)
	}
}

// ── GET /v1/suppressions?domain= ────────────────────────────────────────────

func TestListSuppressions_MissingDomain(t *testing.T) {
	h, _ := newSeededServer(t, "")
	rr := getJSON(t, h, "/v1/suppressions", "")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("missing domain: status = %d; want 400", rr.Code)
	}
}

func TestListSuppressions_ReturnsEmptyArray(t *testing.T) {
	h, _ := newSeededServer(t, "")
	rr := getJSON(t, h, "/v1/suppressions?domain=example.com", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("suppressions: status = %d; want 200", rr.Code)
	}

	var resp struct {
		Suppressions []any `json:"suppressions"`
	}
	decodeJSON(t, rr, &resp)
	if resp.Suppressions == nil {
		t.Error("suppressions should be an empty array, not null")
	}
}

func TestListSuppressions_ReturnsCreatedSuppression(t *testing.T) {
	h, _ := newSeededServer(t, "")

	// Create a suppression
	postJSON(t, h, "/v1/suppressions", map[string]any{
		"domain":   "example.com",
		"check_id": "tls.cert_expiry_30d",
		"status":   "accepted_risk",
	}, "")

	// List suppressions
	rr := getJSON(t, h, "/v1/suppressions?domain=example.com", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("list suppressions: status = %d; want 200", rr.Code)
	}

	var resp struct {
		Suppressions []struct {
			CheckID string `json:"check_id"`
			Status  string `json:"status"`
		} `json:"suppressions"`
	}
	decodeJSON(t, rr, &resp)
	if len(resp.Suppressions) != 1 {
		t.Errorf("expected 1 suppression, got %d", len(resp.Suppressions))
	}
}

// ── DELETE /v1/suppressions/{id} ────────────────────────────────────────────

func TestDeleteSuppression_ReturnsNoContent(t *testing.T) {
	h, _ := newSeededServer(t, "")

	// Create a suppression first
	createRR := postJSON(t, h, "/v1/suppressions", map[string]any{
		"domain":   "example.com",
		"check_id": "tls.cert_expiry_30d",
		"status":   "false_positive",
	}, "")

	var createResp struct {
		ID string `json:"id"`
	}
	decodeJSON(t, createRR, &createResp)

	// Delete it
	rr := deleteJSON(t, h, "/v1/suppressions/"+createResp.ID, "")
	if rr.Code != http.StatusNoContent {
		t.Errorf("delete suppression: status = %d; want 204", rr.Code)
	}

	// Verify it's gone
	listRR := getJSON(t, h, "/v1/suppressions?domain=example.com", "")
	var listResp struct {
		Suppressions []any `json:"suppressions"`
	}
	decodeJSON(t, listRR, &listResp)
	if len(listResp.Suppressions) != 0 {
		t.Errorf("expected 0 suppressions after delete, got %d", len(listResp.Suppressions))
	}
}

// ── GET /v1/playbook/suggestions ─────────────────────────────────────────────

func TestListPlaybookSuggestions_WithSeededData(t *testing.T) {
	h, st := newSeededServer(t, "")
	ctx := context.Background()

	st.SavePlaybookSuggestion(ctx, &store.PlaybookSuggestion{
		Type:           "new",
		TargetPlaybook: "django-misconfig",
		Reasoning:      "Django-specific checks",
		Status:         "pending",
	})

	rr := getJSON(t, h, "/v1/playbook/suggestions", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("suggestions: status = %d; want 200", rr.Code)
	}

	var resp struct {
		Suggestions []struct {
			Type   string `json:"type"`
			Status string `json:"status"`
		} `json:"suggestions"`
	}
	decodeJSON(t, rr, &resp)
	if len(resp.Suggestions) != 1 {
		t.Errorf("expected 1 suggestion, got %d", len(resp.Suggestions))
	}
}

func TestListPlaybookSuggestions_StatusFilter(t *testing.T) {
	h, st := newSeededServer(t, "")
	ctx := context.Background()

	st.SavePlaybookSuggestion(ctx, &store.PlaybookSuggestion{
		Type:   "new",
		Status: "pending",
	})
	st.SavePlaybookSuggestion(ctx, &store.PlaybookSuggestion{
		Type:   "improve",
		Status: "merged",
	})

	// Filter by status
	rr := getJSON(t, h, "/v1/playbook/suggestions?status=pending", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("suggestions filter: status = %d; want 200", rr.Code)
	}

	var resp struct {
		Suggestions []any `json:"suggestions"`
	}
	decodeJSON(t, rr, &resp)
	if len(resp.Suggestions) != 1 {
		t.Errorf("expected 1 filtered suggestion, got %d", len(resp.Suggestions))
	}
}

// ── MaxBytesReader limits ───────────────────────────────────────────────────

func TestSubmitScan_MaxBytesReaderLimit(t *testing.T) {
	h, _ := newSeededServer(t, "")

	// Create a body just over 1 MiB
	bigBody := bytes.Repeat([]byte("x"), 1<<20+100)
	req := httptest.NewRequest(http.MethodPost, "/v1/scans", bytes.NewReader(bigBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("oversized body: status = %d; want 400", rr.Code)
	}
}

func TestUpsertSuppression_MaxBytesReaderLimit(t *testing.T) {
	h, _ := newSeededServer(t, "")

	bigBody := bytes.Repeat([]byte("x"), 1<<20+100)
	req := httptest.NewRequest(http.MethodPost, "/v1/suppressions", bytes.NewReader(bigBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("oversized body: status = %d; want 400", rr.Code)
	}
}

// ── Error response format ───────────────────────────────────────────────────

func TestErrorResponseFormat(t *testing.T) {
	h, _ := newSeededServer(t, "")
	rr := postJSON(t, h, "/v1/scans", map[string]any{}, "")

	var resp struct {
		Error string `json:"error"`
	}
	decodeJSON(t, rr, &resp)
	if resp.Error == "" {
		t.Error("error response should contain an 'error' field with a message")
	}
}

// ── Content-Type header on JSON responses ───────────────────────────────────

func TestJSONResponseContentType(t *testing.T) {
	h, _ := newSeededServer(t, "")
	rr := getJSON(t, h, "/v1/targets", "")
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q; want application/json", ct)
	}
}

// ── Stream endpoint (SSE) ───────────────────────────────────────────────────

func TestStreamScan_UnknownIDReturns404(t *testing.T) {
	h, _ := newSeededServer(t, "")
	rr := getJSON(t, h, "/v1/scans/nonexistent/stream", "")
	if rr.Code != http.StatusNotFound {
		t.Errorf("stream unknown scan: status = %d; want 404", rr.Code)
	}
}

func TestStreamScan_ExistingScanReturnsSSE(t *testing.T) {
	h, _ := newSeededServer(t, "")

	// Submit a scan
	submitRR := postJSON(t, h, "/v1/scans", map[string]any{"domain": "example.com"}, "")
	var submitResp struct {
		ScanRunID string `json:"scan_run_id"`
	}
	decodeJSON(t, submitRR, &submitResp)

	// Request the stream but cancel quickly (otherwise it blocks forever
	// waiting for log lines).
	req := httptest.NewRequest(http.MethodGet, "/v1/scans/"+submitResp.ScanRunID+"/stream", nil)
	ctx, cancel := context.WithTimeout(req.Context(), 100*time.Millisecond)
	defer cancel()
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	// Should have set text/event-stream headers
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/event-stream") {
		t.Errorf("SSE Content-Type = %q; want text/event-stream", ct)
	}
}

// ── Healthz returns no auth ─────────────────────────────────────────────────

func TestHealthz_AlwaysAccessible(t *testing.T) {
	h, _ := newSeededServer(t, "super-secret")
	rr := getJSON(t, h, "/healthz", "") // no auth
	if rr.Code != http.StatusOK {
		t.Errorf("healthz: status = %d; want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "ok") {
		t.Error("healthz should return 'ok'")
	}
}

// ── Multiple scans for same domain create separate targets ──────────────────

func TestMultipleSubmits_SameDomain(t *testing.T) {
	h, _ := newSeededServer(t, "")

	// Submit 3 scans for the same domain
	for range 3 {
		postJSON(t, h, "/v1/scans", map[string]any{"domain": "example.com"}, "")
	}

	// Should only have 1 target
	rr := getJSON(t, h, "/v1/targets", "")
	var resp struct {
		Targets []any `json:"targets"`
	}
	decodeJSON(t, rr, &resp)
	if len(resp.Targets) != 1 {
		t.Errorf("expected 1 target for repeated domain, got %d", len(resp.Targets))
	}

	// Should have 3 scans
	listRR := getJSON(t, h, "/v1/scans?domain=example.com", "")
	var listResp struct {
		Scans []any `json:"scans"`
	}
	decodeJSON(t, listRR, &listResp)
	if len(listResp.Scans) != 3 {
		t.Errorf("expected 3 scans, got %d", len(listResp.Scans))
	}
}
