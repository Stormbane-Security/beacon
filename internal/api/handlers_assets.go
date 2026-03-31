package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"sync"

	"github.com/google/uuid"
)

// assetGroup is a view-only grouping of assets that does not affect scan data.
// Users can merge assets into named groups for cleaner dashboards and to
// generate Terraform for a logical resource. Groups can be split (unmerged)
// at any time without data loss.
type assetGroup struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	Domain string   `json:"domain"`
	Assets []string `json:"assets"`
}

// assetGroupStore is an in-memory store for asset groups.
// A production implementation would persist these to the database.
var (
	groupsMu sync.RWMutex
	groups   = map[string]*assetGroup{} // key: group ID
)

// ── POST /v1/asset-groups ──────────────────────────────────────────────────

type createGroupRequest struct {
	Name   string   `json:"name"`
	Domain string   `json:"domain"`
	Assets []string `json:"assets"`
}

func (s *Server) handleCreateAssetGroup(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req createGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Name == "" || req.Domain == "" || len(req.Assets) < 2 {
		jsonError(w, "name, domain, and at least 2 assets are required", http.StatusBadRequest)
		return
	}

	g := &assetGroup{
		ID:     uuid.NewString(),
		Name:   req.Name,
		Domain: req.Domain,
		Assets: req.Assets,
	}

	groupsMu.Lock()
	groups[g.ID] = g
	groupsMu.Unlock()

	jsonOK(w, http.StatusCreated, g)
}

// ── GET /v1/asset-groups ───────────────────────────────────────────────────

func (s *Server) handleListAssetGroups(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		jsonError(w, "domain query parameter required", http.StatusBadRequest)
		return
	}

	groupsMu.RLock()
	var result []*assetGroup
	for _, g := range groups {
		if g.Domain == domain {
			result = append(result, g)
		}
	}
	groupsMu.RUnlock()

	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})

	if result == nil {
		result = []*assetGroup{}
	}
	jsonOK(w, http.StatusOK, map[string]any{"groups": result})
}

// ── PUT /v1/asset-groups/{id} ─────────────────────────────────────────────

type updateGroupRequest struct {
	Name   string   `json:"name"`
	Assets []string `json:"assets"`
}

func (s *Server) handleUpdateAssetGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req updateGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	groupsMu.Lock()
	g, ok := groups[id]
	if !ok {
		groupsMu.Unlock()
		jsonError(w, "group not found", http.StatusNotFound)
		return
	}
	if req.Name != "" {
		g.Name = req.Name
	}
	if len(req.Assets) > 0 {
		g.Assets = req.Assets
	}
	groupsMu.Unlock()

	jsonOK(w, http.StatusOK, g)
}

// ── DELETE /v1/asset-groups/{id} ──────────────────────────────────────────

func (s *Server) handleDeleteAssetGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	groupsMu.Lock()
	_, ok := groups[id]
	if ok {
		delete(groups, id)
	}
	groupsMu.Unlock()

	if !ok {
		jsonError(w, "group not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── POST /v1/export/bosun ─────────────────────────────────────────────────
// Exports findings in Bosun-compatible format for remediation generation.

type bosunExportRequest struct {
	Domain   string   `json:"domain"`
	CheckIDs []string `json:"check_ids"` // optional: filter to specific checks
	GroupID  string   `json:"group_id"`  // optional: export for merged group
}

type bosunFinding struct {
	CheckID  string         `json:"check_id"`
	Severity string         `json:"severity"`
	Title    string         `json:"title"`
	Asset    string         `json:"asset"`
	Evidence map[string]any `json:"evidence"`
}

func (s *Server) handleExportBosun(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req bosunExportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Domain == "" {
		jsonError(w, "domain is required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// Load findings for this domain.
	runs, err := s.st.ListScanRuns(ctx, req.Domain)
	if err != nil {
		jsonError(w, "store error", http.StatusInternalServerError)
		return
	}
	run := mostRecentCompleted(runs)
	if run == nil {
		jsonOK(w, http.StatusOK, map[string]any{"findings": []bosunFinding{}})
		return
	}

	items := loadFindingItems(s, r, run.ID)

	// Filter by group assets if a group ID is specified.
	var groupAssets map[string]bool
	if req.GroupID != "" {
		groupsMu.RLock()
		g, ok := groups[req.GroupID]
		groupsMu.RUnlock()
		if ok {
			groupAssets = make(map[string]bool, len(g.Assets))
			for _, a := range g.Assets {
				groupAssets[a] = true
			}
		}
	}

	// Filter by check IDs if specified.
	checkFilter := make(map[string]bool, len(req.CheckIDs))
	for _, c := range req.CheckIDs {
		checkFilter[c] = true
	}

	var result []bosunFinding
	for _, item := range items {
		if len(checkFilter) > 0 && !checkFilter[item.CheckID] {
			continue
		}
		if groupAssets != nil && !groupAssets[item.Asset] {
			continue
		}

		evidence := map[string]any{}
		if item.Asset != "" {
			evidence["asset"] = item.Asset
		}

		result = append(result, bosunFinding{
			CheckID:  item.CheckID,
			Severity: item.Severity,
			Title:    item.Title,
			Asset:    item.Asset,
			Evidence: evidence,
		})
	}

	if result == nil {
		result = []bosunFinding{}
	}

	jsonOK(w, http.StatusOK, map[string]any{
		"domain":   req.Domain,
		"scan_id":  run.ID,
		"findings": result,
	})
}
