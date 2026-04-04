package pathtraversal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane-security/beacon/internal/module"
)

func TestSpringBootTraversal(t *testing.T) {
	// Server that blocks /admin with 403 but allows /..;/admin with 200.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.RawPath
		if path == "" {
			path = r.URL.Path
		}
		if strings.Contains(path, "..") || strings.Contains(path, "%2e") || strings.Contains(path, "%2E") {
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"admin": true, "actuator": "enabled"}`))
			return
		}
		if r.URL.Path == "/admin" || r.URL.Path == "/admin/" {
			w.WriteHeader(403)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	s := New()
	findings, err := s.Run(context.Background(), srv.Listener.Addr().String(), module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected path traversal finding, got none")
	}
	if findings[0].CheckID != "web.path_traversal" {
		t.Errorf("expected web.path_traversal, got %s", findings[0].CheckID)
	}
}

func TestNoTraversalOnSecureServer(t *testing.T) {
	// Server that returns 403 on all paths containing traversal sequences.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" || r.URL.Path == "/admin/" {
			w.WriteHeader(403)
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	s := New()
	findings, err := s.Run(context.Background(), srv.Listener.Addr().String(), module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings on secure server, got %d", len(findings))
	}
}

func TestSurfaceModeSkips(t *testing.T) {
	s := New()
	findings, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings in surface mode, got %d", len(findings))
	}
}
