package iisversion

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stormbane-security/beacon/internal/module"
)

func TestDetectsIISVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Microsoft-IIS/10.0")
		w.Header().Set("X-AspNet-Version", "4.0.30319")
		if r.URL.Path == "/beacon-nonexistent-7f3a.aspx" {
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`<html><body>
				<h2>404 - File or directory not found.</h2>
				<h3>The resource you are looking for might have been removed.</h3>
				<p>Version Information: Microsoft .NET Framework Version:4.0.30319; ASP.NET Version:4.8.4494.0</p>
			</body></html>`))
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	s := New()
	findings, err := s.Run(context.Background(), srv.Listener.Addr().String(), module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected IIS version leak finding, got none")
	}
	if findings[0].CheckID != "web.iis_version_leak" {
		t.Errorf("expected web.iis_version_leak, got %s", findings[0].CheckID)
	}
	t.Logf("finding: %s", findings[0].Title)
}

func TestNoFindingOnNonIIS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	s := New()
	findings, err := s.Run(context.Background(), srv.Listener.Addr().String(), module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings on nginx server, got %d", len(findings))
	}
}
