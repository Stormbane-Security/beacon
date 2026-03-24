package api_test

// HTTP contract tests — derived from the API spec, not the handler implementation.
//
// Contracts tested:
//   - /healthz always returns 200 "ok" with no auth required
//   - All /v1/ routes require Bearer auth when a key is configured
//   - Wrong or missing token → 401
//   - POST /v1/scans missing domain → 400
//   - POST /v1/scans deep=true without permission_confirmed → 400
//   - POST /v1/scans valid request → 202 with scan_run_id
//   - GET /v1/scans/{id} unknown ID → 404
//   - GET /v1/scans/{id}/report before scan completes → 404
//   - GET /v1/playbook/suggestions returns 200 with suggestions array

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stormbane/beacon/internal/api"
	memstore "github.com/stormbane/beacon/internal/store/memory"
	"github.com/stormbane/beacon/internal/worker"
	"github.com/stormbane/beacon/internal/config"
)

// newTestServer builds a real api.Server backed by an in-memory store and a
// zero-worker pool (jobs queue but never execute — safe for handler-only tests).
func newTestServer(t *testing.T, apiKey string) (http.Handler, *memstore.Store) {
	t.Helper()
	st := memstore.New()
	cfg := &config.Config{}
	pool := worker.NewPool(0, st, cfg) // 0 workers — no scans actually run
	srv := api.New(st, pool, apiKey)
	return srv.Handler(), st
}

func postJSON(t *testing.T, h http.Handler, path string, body any, apiKey string) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func getJSON(t *testing.T, h http.Handler, path string, apiKey string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// ── /healthz ─────────────────────────────────────────────────────────────────

func TestHealthzReturns200WithNoAuth(t *testing.T) {
	h, _ := newTestServer(t, "secret")
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	// Deliberately no Authorization header.
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("/healthz status = %d; want 200", rr.Code)
	}
}

// ── auth ──────────────────────────────────────────────────────────────────────

func TestV1RequiresBearerTokenWhenKeyConfigured(t *testing.T) {
	h, _ := newTestServer(t, "secret-key")
	// No Authorization header.
	rr := getJSON(t, h, "/v1/targets", "")
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("missing token: status = %d; want 401", rr.Code)
	}
}

func TestV1RejectsWrongToken(t *testing.T) {
	h, _ := newTestServer(t, "correct-key")
	rr := getJSON(t, h, "/v1/targets", "wrong-key")
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("wrong token: status = %d; want 401", rr.Code)
	}
}

func TestV1AcceptsCorrectToken(t *testing.T) {
	h, _ := newTestServer(t, "correct-key")
	rr := getJSON(t, h, "/v1/targets", "correct-key")
	// /v1/targets may return 200 with empty list — should not be 401.
	if rr.Code == http.StatusUnauthorized {
		t.Errorf("correct token was rejected: got 401")
	}
}

func TestV1IsOpenWhenNoKeyConfigured(t *testing.T) {
	h, _ := newTestServer(t, "") // empty key = open
	rr := getJSON(t, h, "/v1/targets", "")
	if rr.Code == http.StatusUnauthorized {
		t.Errorf("open server rejected request with no token")
	}
}

// ── POST /v1/scans ────────────────────────────────────────────────────────────

func TestSubmitScanMissingDomainReturns400(t *testing.T) {
	h, _ := newTestServer(t, "")
	rr := postJSON(t, h, "/v1/scans", map[string]any{"deep": false}, "")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("missing domain: status = %d; want 400", rr.Code)
	}
}

func TestSubmitScanDeepWithoutPermissionReturns400(t *testing.T) {
	h, _ := newTestServer(t, "")
	rr := postJSON(t, h, "/v1/scans", map[string]any{
		"domain":               "example.com",
		"deep":                 true,
		"permission_confirmed": false,
	}, "")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("deep without permission: status = %d; want 400", rr.Code)
	}
}

func TestSubmitScanValidRequestReturns202(t *testing.T) {
	h, _ := newTestServer(t, "")
	rr := postJSON(t, h, "/v1/scans", map[string]any{
		"domain": "example.com",
		"deep":   false,
	}, "")
	if rr.Code != http.StatusAccepted {
		t.Errorf("valid scan: status = %d; want 202", rr.Code)
	}

	var resp struct {
		ScanRunID string `json:"scan_run_id"`
		Status    string `json:"status"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.ScanRunID == "" {
		t.Error("scan_run_id must not be empty in 202 response")
	}
	if resp.Status == "" {
		t.Error("status must not be empty in 202 response")
	}
}

func TestSubmitScanResponseContainsStreamURL(t *testing.T) {
	h, _ := newTestServer(t, "")
	rr := postJSON(t, h, "/v1/scans", map[string]any{"domain": "example.com"}, "")

	var resp struct {
		ScanRunID string `json:"scan_run_id"`
		StreamURL string `json:"stream_url"`
	}
	json.NewDecoder(rr.Body).Decode(&resp) //nolint:errcheck
	if resp.StreamURL == "" {
		t.Error("202 response must include stream_url")
	}
}

// ── GET /v1/scans/{id} ────────────────────────────────────────────────────────

func TestGetScanUnknownIDReturns404(t *testing.T) {
	h, _ := newTestServer(t, "")
	rr := getJSON(t, h, "/v1/scans/does-not-exist", "")
	if rr.Code != http.StatusNotFound {
		t.Errorf("unknown scan: status = %d; want 404", rr.Code)
	}
}

func TestGetScanReturnsSubmittedScan(t *testing.T) {
	h, _ := newTestServer(t, "")

	// Submit a scan.
	submitRR := postJSON(t, h, "/v1/scans", map[string]any{"domain": "example.com"}, "")
	var submitResp struct {
		ScanRunID string `json:"scan_run_id"`
	}
	json.NewDecoder(submitRR.Body).Decode(&submitResp) //nolint:errcheck

	// Fetch it back.
	rr := getJSON(t, h, "/v1/scans/"+submitResp.ScanRunID, "")
	if rr.Code != http.StatusOK {
		t.Errorf("get submitted scan: status = %d; want 200", rr.Code)
	}

	var scanResp struct {
		ID     string `json:"id"`
		Domain string `json:"domain"`
	}
	json.NewDecoder(rr.Body).Decode(&scanResp) //nolint:errcheck
	if scanResp.Domain != "example.com" {
		t.Errorf("domain = %q; want %q", scanResp.Domain, "example.com")
	}
}

// ── GET /v1/scans/{id}/report ─────────────────────────────────────────────────

func TestGetReportBeforeScanCompletesReturns404(t *testing.T) {
	h, _ := newTestServer(t, "")

	// Submit a scan (workers = 0 so it never completes).
	submitRR := postJSON(t, h, "/v1/scans", map[string]any{"domain": "example.com"}, "")
	var submitResp struct {
		ScanRunID string `json:"scan_run_id"`
	}
	json.NewDecoder(submitRR.Body).Decode(&submitResp) //nolint:errcheck

	rr := getJSON(t, h, "/v1/scans/"+submitResp.ScanRunID+"/report", "")
	if rr.Code != http.StatusNotFound {
		t.Errorf("report before completion: status = %d; want 404", rr.Code)
	}
}

// ── GET /v1/playbook/suggestions ─────────────────────────────────────────────

func TestListPlaybookSuggestionsReturns200WithArray(t *testing.T) {
	h, _ := newTestServer(t, "")
	rr := getJSON(t, h, "/v1/playbook/suggestions", "")
	if rr.Code != http.StatusOK {
		t.Errorf("playbook suggestions: status = %d; want 200", rr.Code)
	}

	var resp struct {
		Suggestions []any `json:"suggestions"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	// Empty list is valid — must be an array, not null.
	if resp.Suggestions == nil {
		t.Error("suggestions field must be a JSON array, not null")
	}
}
