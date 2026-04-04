package robotsmap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)

func TestRobotsSensitivePaths(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /admin/\nDisallow: /api/internal/\nDisallow: /backup/\n"))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	s := New()
	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckRobotsSensitivePath {
			found = true
			paths, ok := f.Evidence["sensitive_paths"].([]string)
			if !ok || len(paths) < 2 {
				t.Errorf("expected at least 2 sensitive paths, got %v", f.Evidence["sensitive_paths"])
			}
		}
	}
	if !found {
		t.Error("expected CheckRobotsSensitivePath finding")
	}
}

func TestRobotsCrawlDelay(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			_, _ = w.Write([]byte("User-agent: *\nCrawl-delay: 10\nDisallow: /\n"))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	s := New()
	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckRobotsCrawlDelay {
			found = true
		}
	}
	if !found {
		t.Error("expected CheckRobotsCrawlDelay finding")
	}
}

func TestSitemapSensitiveURLs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			w.WriteHeader(404)
		case "/sitemap.xml":
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(`<?xml version="1.0"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/</loc></url>
  <url><loc>https://example.com/admin/dashboard</loc></url>
  <url><loc>https://example.com/api/internal/users</loc></url>
</urlset>`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	s := New()
	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckSitemapSensitiveURL {
			found = true
		}
	}
	if !found {
		t.Error("expected CheckSitemapSensitiveURL finding")
	}
}

func TestNoRobotsOrSitemap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()

	s := New()
	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for missing robots/sitemap, got %d", len(findings))
	}
}
