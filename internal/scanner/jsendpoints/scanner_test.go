package jsendpoints

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stormbane-security/beacon/internal/module"
)

func TestExtractsAPIEndpointsFromJS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><head><script src="/app.js"></script></head><body></body></html>`))
			return
		}
		if r.URL.Path == "/app.js" {
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(`
				const API_BASE = "https://api-internal.staging.example.com:8443/api/v2/users";
				fetch("/api/v1/admin/settings").then(r => r.json());
				const DB_HOST = "192.168.1.50";
				const GRAPHQL = "/graphql";
			`))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	s := New()
	findings, err := s.Run(context.Background(), srv.Listener.Addr().String(), module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected JS endpoint extraction finding, got none")
	}
	if findings[0].CheckID != "js.internal_endpoint" {
		t.Errorf("expected js.internal_endpoint, got %s", findings[0].CheckID)
	}

	endpoints, ok := findings[0].Evidence["endpoints"].([]string)
	if !ok || len(endpoints) == 0 {
		t.Fatal("expected endpoints in evidence")
	}
	t.Logf("found %d endpoints: %v", len(endpoints), endpoints)
}

func TestNoFalsePositiveOnPlainHTML(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><h1>No JS here</h1></body></html>`))
	}))
	defer srv.Close()

	s := New()
	findings, err := s.Run(context.Background(), srv.Listener.Addr().String(), module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings on plain HTML, got %d", len(findings))
	}
}
