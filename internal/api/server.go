// Package api implements the Beacon HTTP API server.
// All routes are under /v1/. Authentication is via a static API key
// passed in the Authorization: Bearer <key> header.
package api

import (
	"net/http"
	"time"

	"github.com/stormbane/beacon/internal/config"
	"github.com/stormbane/beacon/internal/project"
	"github.com/stormbane/beacon/internal/store"
	"github.com/stormbane/beacon/internal/web"
	"github.com/stormbane/beacon/internal/worker"
)

// timeNow returns the current UTC time. Package-level var for testing.
var timeNow = func() time.Time { return time.Now().UTC() }

// Server holds the dependencies shared across all handlers.
type Server struct {
	st       store.Store
	pool     *worker.Pool
	apiKey   string
	aiCfg    config.AIConfig
	projects *project.Store
}

// New creates a Server and registers all routes on mux.
func New(st store.Store, pool *worker.Pool, apiKey string, opts ...Option) *Server {
	s := &Server{
		st:       st,
		pool:     pool,
		apiKey:   apiKey,
		projects: project.NewStore(),
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Option configures optional Server dependencies.
type Option func(*Server)

// WithAI sets the AI provider configuration for scaffold chat.
func WithAI(ai config.AIConfig) Option {
	return func(s *Server) { s.aiCfg = ai }
}

// Handler returns the root HTTP handler with all routes registered.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Auth middleware wraps all /v1/ routes
	v1 := http.NewServeMux()
	v1.HandleFunc("POST /scans", s.handleSubmitScan)
	v1.HandleFunc("GET /scans", s.handleListScans)
	v1.HandleFunc("GET /scans/{id}", s.handleGetScan)
	v1.HandleFunc("GET /scans/{id}/stream", s.handleStreamScan)
	v1.HandleFunc("GET /scans/{id}/report", s.handleGetReport)
	v1.HandleFunc("GET /targets", s.handleListTargets)
	v1.HandleFunc("GET /targets/{domain}/findings", s.handleDomainFindings)
	v1.HandleFunc("GET /targets/{domain}/trend", s.handleDomainTrend)
	v1.HandleFunc("GET /targets/{domain}/compliance", s.handleDomainCompliance)
	v1.HandleFunc("GET /dashboard", s.handleDashboard)
	v1.HandleFunc("GET /playbook/suggestions", s.handleListPlaybookSuggestions)
	v1.HandleFunc("GET /correlations", s.handleListCorrelations)
	v1.HandleFunc("POST /suppressions", s.handleUpsertSuppression)
	v1.HandleFunc("GET /suppressions", s.handleListSuppressions)
	v1.HandleFunc("DELETE /suppressions/{id}", s.handleDeleteSuppression)

	// Asset groups (view-only merge/split).
	v1.HandleFunc("POST /asset-groups", s.handleCreateAssetGroup)
	v1.HandleFunc("GET /asset-groups", s.handleListAssetGroups)
	v1.HandleFunc("PUT /asset-groups/{id}", s.handleUpdateAssetGroup)
	v1.HandleFunc("DELETE /asset-groups/{id}", s.handleDeleteAssetGroup)

	// Bosun export.
	v1.HandleFunc("POST /export/bosun", s.handleExportBosun)

	// Scaffold catalog and generation.
	v1.HandleFunc("GET /catalog", s.handleCatalog)
	v1.HandleFunc("GET /catalog/{id}", s.handleCatalogEntry)
	v1.HandleFunc("POST /scaffold", s.handleScaffold)
	v1.HandleFunc("POST /scaffold/match", s.handleScaffoldMatch)
	v1.HandleFunc("POST /scaffold/chat", s.handleScaffoldChat)

	// Projects (workspace: integrations, plans, context).
	v1.HandleFunc("POST /projects", s.handleCreateProject)
	v1.HandleFunc("GET /projects", s.handleListProjects)
	v1.HandleFunc("GET /projects/{id}", s.handleGetProject)
	v1.HandleFunc("PUT /projects/{id}", s.handleUpdateProject)
	v1.HandleFunc("DELETE /projects/{id}", s.handleDeleteProject)
	v1.HandleFunc("POST /projects/{id}/integrations", s.handleAddIntegration)
	v1.HandleFunc("DELETE /projects/{id}/integrations/{intgId}", s.handleRemoveIntegration)
	v1.HandleFunc("POST /projects/{id}/integrations/{intgId}/sync", s.handleSyncIntegration)
	v1.HandleFunc("GET /projects/{id}/context", s.handleProjectContext)
	v1.HandleFunc("POST /projects/{id}/plans", s.handleCreatePlan)
	v1.HandleFunc("GET /projects/{id}/repos", s.handleListRepos)

	mux.Handle("/v1/", s.authMiddleware(http.StripPrefix("/v1", v1)))

	// Web UI — served without auth; the browser sends Bearer tokens itself.
	mux.Handle("/ui/", http.StripPrefix("/ui", web.Handler()))
	// Root catch-all: redirect / → /ui/, 404 everything else.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/ui/", http.StatusFound)
			return
		}
		http.NotFound(w, r)
	})

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok")) //nolint:errcheck
	})

	return mux
}
