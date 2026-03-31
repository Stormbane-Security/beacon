package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/stormbane/beacon/internal/integration"
	"github.com/stormbane/beacon/internal/project"
)

// ── POST /v1/projects ───────────────────────────────────────────────────────

type createProjectRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Domains     []string `json:"domains"`
}

func (s *Server) handleCreateProject(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req createProjectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		jsonError(w, "name is required", http.StatusBadRequest)
		return
	}

	p := &project.Project{
		Name:        req.Name,
		Description: req.Description,
		Domains:     req.Domains,
	}
	if err := s.projects.Create(p); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, http.StatusCreated, p)
}

// ── GET /v1/projects ────────────────────────────────────────────────────────

func (s *Server) handleListProjects(w http.ResponseWriter, r *http.Request) {
	projects := s.projects.List()
	if projects == nil {
		projects = []*project.Project{}
	}
	jsonOK(w, http.StatusOK, map[string]any{"projects": projects})
}

// ── GET /v1/projects/{id} ──────────────────────────────────────────────────

func (s *Server) handleGetProject(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p, ok := s.projects.Get(id)
	if !ok {
		jsonError(w, "project not found", http.StatusNotFound)
		return
	}
	jsonOK(w, http.StatusOK, p)
}

// ── PUT /v1/projects/{id} ──────────────────────────────────────────────────

func (s *Server) handleUpdateProject(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p, ok := s.projects.Get(id)
	if !ok {
		jsonError(w, "project not found", http.StatusNotFound)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req createProjectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Name != "" {
		p.Name = req.Name
	}
	if req.Description != "" {
		p.Description = req.Description
	}
	if req.Domains != nil {
		p.Domains = req.Domains
	}
	if err := s.projects.Update(p); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, http.StatusOK, p)
}

// ── DELETE /v1/projects/{id} ───────────────────────────────────────────────

func (s *Server) handleDeleteProject(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.projects.Delete(id); err != nil {
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── POST /v1/projects/{id}/integrations ────────────────────────────────────

type addIntegrationRequest struct {
	Type   string            `json:"type"` // "github", "gcp", "aws", "azure"
	Name   string            `json:"name"` // e.g. "org/repo" or "my-gcp-project"
	Config map[string]string `json:"config"`
}

func (s *Server) handleAddIntegration(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req addIntegrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Type == "" || req.Name == "" {
		jsonError(w, "type and name are required", http.StatusBadRequest)
		return
	}

	intg := project.Integration{
		Type:   project.IntegrationType(req.Type),
		Name:   req.Name,
		Config: req.Config,
		Status: "connected",
	}
	if err := s.projects.AddIntegration(projectID, intg); err != nil {
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	}

	// Return the project with the new integration.
	p, _ := s.projects.Get(projectID)
	jsonOK(w, http.StatusCreated, p)
}

// ── DELETE /v1/projects/{id}/integrations/{intgId} ─────────────────────────

func (s *Server) handleRemoveIntegration(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	intgID := r.PathValue("intgId")
	if err := s.projects.RemoveIntegration(projectID, intgID); err != nil {
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── POST /v1/projects/{id}/integrations/{intgId}/sync ─────────────────────

func (s *Server) handleSyncIntegration(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	intgID := r.PathValue("intgId")

	intg, err := s.projects.GetIntegration(projectID, intgID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	}

	switch intg.Type {
	case project.IntegrationGitHub:
		token := intg.Config["token"]
		if token == "" {
			jsonError(w, "GitHub token not configured", http.StatusBadRequest)
			return
		}
		parts := strings.SplitN(intg.Name, "/", 2)
		if len(parts) != 2 {
			jsonError(w, "name must be owner/repo", http.StatusBadRequest)
			return
		}
		owner, repo := parts[0], parts[1]
		branch := intg.Config["branch"]
		if branch == "" {
			branch = "main"
		}

		gh := integration.NewGitHubClient(token)
		resources, err := gh.SyncRepoResources(r.Context(), owner, repo, branch)
		if err != nil {
			intg.Status = "error"
			intg.Error = err.Error()
			s.projects.UpdateIntegration(projectID, *intg)
			jsonError(w, "sync failed: "+err.Error(), http.StatusBadGateway)
			return
		}

		now := timeNow()
		intg.Resources = resources
		intg.Status = "connected"
		intg.LastSync = &now
		intg.Error = ""
		s.projects.UpdateIntegration(projectID, *intg)

		jsonOK(w, http.StatusOK, map[string]any{
			"resources_found": len(resources),
			"integration":     intg,
		})

	default:
		jsonError(w, "sync not yet supported for "+string(intg.Type), http.StatusNotImplemented)
	}
}

// ── GET /v1/projects/{id}/context ─────────────────────────────────────────

func (s *Server) handleProjectContext(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	ctx, err := s.projects.BuildContext(projectID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	}

	// Also include scan findings summary if domains are linked.
	if s.st != nil && len(ctx.Domains) > 0 {
		for _, domain := range ctx.Domains {
			runs, err := s.st.ListScanRuns(r.Context(), domain)
			if err != nil || len(runs) == 0 {
				continue
			}
			// Get the latest completed scan's findings.
			for _, run := range runs {
				if run.Status != "completed" {
					continue
				}
				findings, err := s.st.GetFindings(r.Context(), run.ID)
				if err != nil || len(findings) == 0 {
					continue
				}
				// Convert scan findings to resources for the context.
				for _, f := range findings {
					ctx.ExistingResources = append(ctx.ExistingResources, project.Resource{
						ID:       string(f.CheckID) + ":" + f.Asset,
						Type:     "scan_finding",
						Name:     f.Asset,
						Provider: "scan",
						Source:   "beacon_scan",
						Attrs: map[string]string{
							"check_id": string(f.CheckID),
							"severity": f.Severity.String(),
							"title":    f.Title,
						},
					})
				}
				break // only latest
			}
		}
	}

	jsonOK(w, http.StatusOK, ctx)
}

// ── POST /v1/projects/{id}/plans ──────────────────────────────────────────

type createPlanRequest struct {
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Items       []project.PlanItem  `json:"items"`
	SharedVars  map[string]string   `json:"shared_vars"`
}

func (s *Server) handleCreatePlan(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req createPlanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		jsonError(w, "name is required", http.StatusBadRequest)
		return
	}

	plan := project.Plan{
		Name:        req.Name,
		Description: req.Description,
		Items:       req.Items,
		SharedVars:  req.SharedVars,
	}
	if plan.Items == nil {
		plan.Items = []project.PlanItem{}
	}
	if plan.SharedVars == nil {
		plan.SharedVars = make(map[string]string)
	}

	if err := s.projects.AddPlan(projectID, plan); err != nil {
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	}

	p, _ := s.projects.Get(projectID)
	jsonOK(w, http.StatusCreated, p)
}

// ── GET /v1/projects/{id}/repos ───────────────────────────────────────────
// Lists available GitHub repos for a connected GitHub integration.

func (s *Server) handleListRepos(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	p, ok := s.projects.Get(projectID)
	if !ok {
		jsonError(w, "project not found", http.StatusNotFound)
		return
	}

	// Find the first GitHub integration with a token.
	var token string
	for _, intg := range p.Integrations {
		if intg.Type == project.IntegrationGitHub && intg.Config["token"] != "" {
			token = intg.Config["token"]
			break
		}
	}
	if token == "" {
		jsonError(w, "no GitHub integration with token found", http.StatusBadRequest)
		return
	}

	gh := integration.NewGitHubClient(token)

	org := r.URL.Query().Get("org")
	var repos []integration.Repo
	var err error
	if org != "" {
		repos, err = gh.ListOrgRepos(r.Context(), org)
	} else {
		repos, err = gh.ListRepos(r.Context())
	}
	if err != nil {
		jsonError(w, "GitHub API error: "+err.Error(), http.StatusBadGateway)
		return
	}
	jsonOK(w, http.StatusOK, map[string]any{"repos": repos})
}
