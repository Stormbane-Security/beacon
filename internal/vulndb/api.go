package vulndb

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// NewServer returns an HTTP server with all vulndb API routes registered.
func NewServer(db *DB, port int) *http.Server {
	mux := http.NewServeMux()
	h := &apiHandler{db: db}

	mux.HandleFunc("GET /api/cves", h.getCVEs)
	mux.HandleFunc("GET /api/payloads", h.getPayloads)
	mux.HandleFunc("GET /api/fingerprints", h.getFingerprints)
	mux.HandleFunc("GET /api/stats", h.getStats)
	mux.HandleFunc("POST /api/findings", h.postFindings)
	mux.HandleFunc("POST /api/payloads", h.postPayload)
	mux.HandleFunc("POST /api/fingerprints", h.handleSaveFingerprint)

	return &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
}

type apiHandler struct {
	db *DB
}

// GET /api/cves?service=X&version=Y
// GET /api/cves?ecosystem=npm&package=lodash&version=4.17.20
func (h *apiHandler) getCVEs(w http.ResponseWriter, r *http.Request) {
	ecosystem := r.URL.Query().Get("ecosystem")
	pkg := r.URL.Query().Get("package")
	service := r.URL.Query().Get("service")
	version := r.URL.Query().Get("version")

	var (
		cves []CVEEntry
		err  error
	)
	if ecosystem != "" && pkg != "" {
		cves, err = h.db.QueryCVEsByEcosystem(ecosystem, pkg, version)
	} else if service != "" {
		cves, err = h.db.QueryCVEs(service, version)
	} else {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "provide service or ecosystem+package query params",
		})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if cves == nil {
		cves = []CVEEntry{}
	}
	writeJSON(w, http.StatusOK, cves)
}

// GET /api/payloads?service=X&version=Y
func (h *apiHandler) getPayloads(w http.ResponseWriter, r *http.Request) {
	service := r.URL.Query().Get("service")
	version := r.URL.Query().Get("version")
	if service == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "service required"})
		return
	}
	payloads, err := h.db.QueryPayloads(service, version)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if payloads == nil {
		payloads = []VerifiedPayload{}
	}
	writeJSON(w, http.StatusOK, payloads)
}

// GET /api/fingerprints?domain=X
func (h *apiHandler) getFingerprints(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "domain required"})
		return
	}
	fps, err := h.db.QueryFingerprints(domain)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if fps == nil {
		fps = []ServiceFingerprint{}
	}
	writeJSON(w, http.StatusOK, fps)
}

// GET /api/stats
func (h *apiHandler) getStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.db.Stats()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

// POST /api/findings — accepts a JSON body: {"domain":"x","scan_type":"surface","findings":[...]}
func (h *apiHandler) postFindings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain     string          `json:"domain"`
		ScanType   string          `json:"scan_type"`
		Findings   json.RawMessage `json:"findings"`
		DurationMS int64           `json:"duration_ms"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}
	if req.Domain == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "domain required"})
		return
	}
	// Count findings from the raw JSON.
	var arr []json.RawMessage
	if err := json.Unmarshal(req.Findings, &arr); err != nil {
		arr = nil
	}
	sr := ScanResult{
		Domain:       req.Domain,
		ScanType:     req.ScanType,
		FindingCount: len(arr),
		Findings:     string(req.Findings),
		DurationMS:   req.DurationMS,
		ScannedAt:    time.Now(),
	}
	if err := h.db.InsertScanResult(sr); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "ok"})
}

// POST /api/payloads — accepts a VerifiedPayload JSON body.
func (h *apiHandler) postPayload(w http.ResponseWriter, r *http.Request) {
	var p VerifiedPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}
	if p.Service == "" || p.CVEID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "service and cve_id required"})
		return
	}
	if p.LastVerified.IsZero() {
		p.LastVerified = time.Now()
	}
	if p.VerifyCount == 0 {
		p.VerifyCount = 1
	}
	if err := h.db.UpsertPayload(p); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "ok"})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("vulndb: write response: %v", err)
	}
}

func (h *apiHandler) handleSaveFingerprint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var fp ServiceFingerprint
	if err := json.NewDecoder(r.Body).Decode(&fp); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.db.SaveFingerprint(fp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}
