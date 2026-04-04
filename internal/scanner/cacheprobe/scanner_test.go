package cacheprobe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)

func TestCacheBehaviorDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Cache", "HIT")
		w.Header().Set("Age", "300")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Header().Set("CF-Cache-Status", "HIT")
		w.WriteHeader(200)
		w.Write([]byte("<html><body>Hello</body></html>"))
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	s := New()
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var cacheFound bool
	for _, f := range findings {
		if f.CheckID == finding.CheckCacheBehaviorDetected {
			cacheFound = true
			if !strings.Contains(f.Title, "Cloudflare") {
				t.Errorf("expected Cloudflare vendor detection, got: %s", f.Title)
			}
		}
	}

	if !cacheFound {
		t.Error("expected cache behavior detection finding")
	}
}

func TestPurgeDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PURGE" {
			w.WriteHeader(200)
			w.Write([]byte("purge OK"))
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	s := New()
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var purgeFound bool
	for _, f := range findings {
		if f.CheckID == finding.CheckCachePurgeEnabled {
			purgeFound = true
		}
	}

	if !purgeFound {
		t.Error("expected cache purge finding when PURGE returns 200")
	}
}

func TestPurgeBlocked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PURGE" {
			w.WriteHeader(405)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	s := New()
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if f.CheckID == finding.CheckCachePurgeEnabled {
			t.Error("should not emit purge finding when PURGE returns 405")
		}
	}
}

func TestRiskyVaryHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Vary", "Accept-Encoding, X-Forwarded-Host, X-Forwarded-Proto")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	s := New()
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var varyFound bool
	for _, f := range findings {
		if f.CheckID == finding.CheckCacheVaryRisky {
			varyFound = true
		}
	}

	if !varyFound {
		t.Error("expected risky Vary finding when Vary includes X-Forwarded-Host")
	}
}

func TestSafeVaryHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Vary", "Accept-Encoding, Accept-Language")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	s := New()
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if f.CheckID == finding.CheckCacheVaryRisky {
			t.Error("should not flag safe Vary headers")
		}
	}
}

func TestUnkeyedHeaderPoisoning(t *testing.T) {
	// Simulate a caching server: first request with X-Forwarded-Host gets cached,
	// subsequent requests (without the header) still serve the cached version.
	var cachedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		xfh := r.Header.Get("X-Forwarded-Host")
		w.Header().Set("X-Cache", "HIT")
		w.WriteHeader(200)

		if xfh != "" {
			// First request: poisoning — cache the reflected header
			cachedBody = "<html><base href='http://" + xfh + "/'></html>"
		} else if cachedBody == "" {
			cachedBody = "<html><base href='http://example.com/'></html>"
		}
		// Always serve the cached body (simulating a real CDN cache)
		w.Write([]byte(cachedBody))
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	s := New()

	// Surface mode should not test for cache poisoning
	surfaceFindings, _ := s.Run(context.Background(), asset, module.ScanSurface)
	for _, f := range surfaceFindings {
		if f.CheckID == finding.CheckCachePoisonUnkeyed {
			t.Error("cache poisoning test should not run in surface mode")
		}
	}

	// Reset cache between test runs
	cachedBody = ""

	// Deep mode should detect unkeyed header reflection
	deepFindings, err := s.Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var poisonFound bool
	for _, f := range deepFindings {
		if f.CheckID == finding.CheckCachePoisonUnkeyed {
			poisonFound = true
		}
	}

	if !poisonFound {
		t.Error("expected cache poisoning finding when X-Forwarded-Host is reflected and cached")
	}
}

func TestHostHeaderRouting(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Different Host header → different Server
		if r.Host == "localhost" || strings.HasPrefix(r.Host, "127.0.0.1") {
			w.Header().Set("Server", "Apache/2.4 (Internal)")
			w.WriteHeader(200)
			w.Write([]byte("<html><body>Internal Admin Panel</body></html>"))
			return
		}
		w.Header().Set("Server", "nginx/1.24")
		w.WriteHeader(200)
		w.Write([]byte("<html><body>Public Website Content Here</body></html>"))
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	s := New()

	// Deep mode should detect host routing
	findings, err := s.Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var routingFound bool
	for _, f := range findings {
		if f.CheckID == finding.CheckCacheHostRouting {
			routingFound = true
		}
	}

	if !routingFound {
		t.Error("expected host routing finding when different Host headers route to different backends")
	}
}

func TestNoCacheHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.WriteHeader(200)
		w.Write([]byte("hello"))
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	s := New()
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if f.CheckID == finding.CheckCacheBehaviorDetected {
			t.Error("should not detect cache when no cache headers present")
		}
	}
}

func TestVendorIdentification(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		expected string
	}{
		{"cloudflare", map[string]string{"cf-cache-status": "HIT"}, "Cloudflare"},
		{"cloudfront", map[string]string{"x-cache": "Hit from cloudfront"}, "CloudFront"},
		{"varnish-xcache", map[string]string{"x-cache": "HIT varnish"}, "Varnish"},
		{"varnish-direct", map[string]string{"x-varnish": "12345 67890"}, "Varnish"},
		{"fastly", map[string]string{"x-fastly-request-id": "abc123"}, "Fastly"},
		{"cloudfront-pop", map[string]string{"x-amz-cf-pop": "IAD89"}, "CloudFront"},
		{"nginx-cache", map[string]string{"x-cache-status": "HIT"}, "nginx/proxy_cache"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vendor := identifyCacheVendor(tt.headers)
			if vendor != tt.expected {
				t.Errorf("expected vendor %q, got %q", tt.expected, vendor)
			}
		})
	}
}

func TestCacheableDetection(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		expected bool
	}{
		{"public", map[string]string{"cache-control": "public, max-age=3600"}, true},
		{"no-store", map[string]string{"cache-control": "no-store"}, false},
		{"private", map[string]string{"cache-control": "private"}, false},
		{"age-only", map[string]string{"age": "300"}, true},
		{"x-cache-hit", map[string]string{"x-cache": "HIT"}, true},
		{"x-cache-miss", map[string]string{"x-cache": "MISS"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isCacheable(tt.headers)
			if result != tt.expected {
				t.Errorf("expected cacheable=%v, got %v", tt.expected, result)
			}
		})
	}
}
