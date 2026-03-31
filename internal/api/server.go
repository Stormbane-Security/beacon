// Package api implements the Beacon HTTP API server.
// All routes are under /v1/. Authentication is via a static API key
// passed in the Authorization: Bearer <key> header.
package api

import (
	"net/http"

	"github.com/stormbane/beacon/internal/store"
	"github.com/stormbane/beacon/internal/web"
	"github.com/stormbane/beacon/internal/worker"
)

// Server holds the dependencies shared across all handlers.
type Server struct {
	st     store.Store
	pool   *worker.Pool
	apiKey string
}

// New creates a Server and registers all routes on mux.
func New(st store.Store, pool *worker.Pool, apiKey string) *Server {
	return &Server{st: st, pool: pool, apiKey: apiKey}
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
