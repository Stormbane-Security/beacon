package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/stormbane/beacon/internal/module"
	"github.com/stormbane/beacon/internal/store"
	"github.com/stormbane/beacon/internal/worker"
)

// ── Submit scan ──────────────────────────────────────────────────────────────

type submitScanRequest struct {
	Domain              string `json:"domain"`
	Deep                bool   `json:"deep"`
	PermissionConfirmed bool   `json:"permission_confirmed"`
}

type submitScanResponse struct {
	ScanRunID string `json:"scan_run_id"`
	Status    string `json:"status"`
	StreamURL string `json:"stream_url"`
}

func (s *Server) handleSubmitScan(w http.ResponseWriter, r *http.Request) {
	var req submitScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Domain == "" {
		jsonError(w, "domain is required", http.StatusBadRequest)
		return
	}
	if req.Deep && !req.PermissionConfirmed {
		jsonError(w, "deep scan requires permission_confirmed: true", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	target, err := s.st.UpsertTarget(ctx, req.Domain)
	if err != nil {
		jsonError(w, "store error", http.StatusInternalServerError)
		return
	}

	scanType := module.ScanSurface
	if req.Deep {
		scanType = module.ScanDeep
	}

	run := &store.ScanRun{
		ID:        uuid.NewString(),
		TargetID:  target.ID,
		Domain:    req.Domain,
		ScanType:  scanType,
		Modules:   []string{"surface"},
		Status:    store.StatusPending,
		StartedAt: time.Now(),
	}
	if err := s.st.CreateScanRun(ctx, run); err != nil {
		jsonError(w, "store error", http.StatusInternalServerError)
		return
	}

	s.pool.Submit(worker.Job{
		ScanRunID:           run.ID,
		Domain:              req.Domain,
		ScanType:            scanType,
		PermissionConfirmed: req.PermissionConfirmed,
		SubmittedAt:         time.Now(),
	})

	jsonOK(w, http.StatusAccepted, submitScanResponse{
		ScanRunID: run.ID,
		Status:    string(store.StatusPending),
		StreamURL: "/v1/scans/" + run.ID + "/stream",
	})
}

// ── Get scan ─────────────────────────────────────────────────────────────────

type scanResponse struct {
	ID           string         `json:"id"`
	Domain       string         `json:"domain"`
	ScanType     string         `json:"scan_type"`
	Status       string         `json:"status"`
	FindingCount int            `json:"finding_count"`
	StartedAt    time.Time      `json:"started_at"`
	CompletedAt  *time.Time     `json:"completed_at,omitempty"`
	Error        string         `json:"error,omitempty"`
	RecentLogs   []string       `json:"recent_logs,omitempty"`
}

func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	run, err := s.st.GetScanRun(r.Context(), id)
	if err != nil {
		jsonError(w, "scan not found", http.StatusNotFound)
		return
	}
	logs := s.pool.Logs(id)
	if len(logs) > 20 {
		logs = logs[len(logs)-20:] // last 20 lines
	}
	jsonOK(w, http.StatusOK, scanResponse{
		ID:           run.ID,
		Domain:       run.Domain,
		ScanType:     string(run.ScanType),
		Status:       string(run.Status),
		FindingCount: run.FindingCount,
		StartedAt:    run.StartedAt,
		CompletedAt:  run.CompletedAt,
		Error:        run.Error,
		RecentLogs:   logs,
	})
}

// ── List scans ────────────────────────────────────────────────────────────────

func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		jsonError(w, "domain query parameter required", http.StatusBadRequest)
		return
	}
	runs, err := s.st.ListScanRuns(r.Context(), domain)
	if err != nil {
		jsonError(w, "store error", http.StatusInternalServerError)
		return
	}
	type listItem struct {
		ID           string     `json:"id"`
		Domain       string     `json:"domain"`
		ScanType     string     `json:"scan_type"`
		Status       string     `json:"status"`
		FindingCount int        `json:"finding_count"`
		StartedAt    time.Time  `json:"started_at"`
		CompletedAt  *time.Time `json:"completed_at,omitempty"`
	}
	items := make([]listItem, len(runs))
	for i, r := range runs {
		items[i] = listItem{
			ID:           r.ID,
			Domain:       r.Domain,
			ScanType:     string(r.ScanType),
			Status:       string(r.Status),
			FindingCount: r.FindingCount,
			StartedAt:    r.StartedAt,
			CompletedAt:  r.CompletedAt,
		}
	}
	jsonOK(w, http.StatusOK, map[string]any{"scans": items})
}

// ── Stream scan (SSE) ────────────────────────────────────────────────────────

func (s *Server) handleStreamScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	// Verify the scan exists
	if _, err := s.st.GetScanRun(r.Context(), id); err != nil {
		jsonError(w, "scan not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx buffering
	w.WriteHeader(http.StatusOK)

	flusher, ok := w.(http.Flusher)
	if !ok {
		return
	}

	// Replay existing log lines first
	for _, line := range s.pool.Logs(id) {
		writeSSE(w, "log", line)
		flusher.Flush()
	}

	// Subscribe for new lines
	ch := s.pool.Subscribe(id)

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case line, open := <-ch:
			if !open {
				writeSSE(w, "done", "")
				flusher.Flush()
				return
			}
			writeSSE(w, "log", line)
			flusher.Flush()
		}
	}
}

func writeSSE(w http.ResponseWriter, event, data string) {
	if event != "" {
		w.Write([]byte("event: " + event + "\n")) //nolint:errcheck
	}
	w.Write([]byte("data: " + data + "\n\n")) //nolint:errcheck
}

// ── Get report ───────────────────────────────────────────────────────────────

func (s *Server) handleGetReport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	rep, err := s.st.GetReport(r.Context(), id)
	if err != nil {
		jsonError(w, "report not found — scan may still be running", http.StatusNotFound)
		return
	}

	accept := r.Header.Get("Accept")
	if accept == "application/json" {
		jsonOK(w, http.StatusOK, rep)
		return
	}

	// Default: serve HTML
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(rep.HTMLContent)) //nolint:errcheck
}

// ── Correlation findings ──────────────────────────────────────────────────────

func (s *Server) handleListCorrelations(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		jsonError(w, "domain query parameter required", http.StatusBadRequest)
		return
	}
	correlations, err := s.st.ListCorrelationFindings(r.Context(), domain)
	if err != nil {
		jsonError(w, "store error", http.StatusInternalServerError)
		return
	}
	if correlations == nil {
		correlations = []store.CorrelationFinding{}
	}
	jsonOK(w, http.StatusOK, map[string]any{"correlations": correlations})
}

// ── Playbook suggestions ──────────────────────────────────────────────────────

func (s *Server) handleListPlaybookSuggestions(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status") // optional filter
	suggestions, err := s.st.ListPlaybookSuggestions(r.Context(), status)
	if err != nil {
		jsonError(w, "store error", http.StatusInternalServerError)
		return
	}
	if suggestions == nil {
		suggestions = []store.PlaybookSuggestion{}
	}
	jsonOK(w, http.StatusOK, map[string]any{"suggestions": suggestions})
}

// ── List targets ──────────────────────────────────────────────────────────────

func (s *Server) handleListTargets(w http.ResponseWriter, r *http.Request) {
	targets, err := s.st.ListTargets(context.Background())
	if err != nil {
		jsonError(w, "store error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, http.StatusOK, map[string]any{"targets": targets})
}

// ── Finding suppressions ──────────────────────────────────────────────────────

type upsertSuppressionRequest struct {
	Domain  string `json:"domain"`
	CheckID string `json:"check_id"`
	Asset   string `json:"asset"`
	Status  string `json:"status"`
	Note    string `json:"note"`
}

func (s *Server) handleUpsertSuppression(w http.ResponseWriter, r *http.Request) {
	var req upsertSuppressionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Domain == "" || req.CheckID == "" {
		jsonError(w, "domain and check_id are required", http.StatusBadRequest)
		return
	}
	status := store.SuppressionStatus(req.Status)
	switch status {
	case store.SuppressionAcceptedRisk, store.SuppressionFalsePositive, store.SuppressionWontFix:
	default:
		jsonError(w, "status must be accepted_risk, false_positive, or wont_fix", http.StatusBadRequest)
		return
	}

	sup := &store.FindingSuppression{
		ID:      uuid.NewString(),
		Domain:  req.Domain,
		CheckID: req.CheckID,
		Asset:   req.Asset,
		Status:  status,
		Note:    req.Note,
	}
	if err := s.st.UpsertSuppression(r.Context(), sup); err != nil {
		jsonError(w, "store error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, http.StatusCreated, sup)
}

func (s *Server) handleListSuppressions(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		jsonError(w, "domain query parameter required", http.StatusBadRequest)
		return
	}
	sups, err := s.st.ListSuppressions(r.Context(), domain)
	if err != nil {
		jsonError(w, "store error", http.StatusInternalServerError)
		return
	}
	if sups == nil {
		sups = []store.FindingSuppression{}
	}
	jsonOK(w, http.StatusOK, map[string]any{"suppressions": sups})
}

func (s *Server) handleDeleteSuppression(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		jsonError(w, "id is required", http.StatusBadRequest)
		return
	}
	if err := s.st.DeleteSuppression(r.Context(), id); err != nil {
		jsonError(w, "store error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── helpers ───────────────────────────────────────────────────────────────────

func jsonOK(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

func jsonError(w http.ResponseWriter, msg string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg}) //nolint:errcheck
}
