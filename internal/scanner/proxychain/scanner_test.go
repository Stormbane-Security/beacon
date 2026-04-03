package proxychain

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)

func TestViaHeaderDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Via", "1.1 varnish, 1.1 cloudfront.amazonaws.com")
		w.Header().Set("Server", "nginx")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	s := New()
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should detect the multi-hop chain and individual hops
	var chainFound bool
	var varnishFound, cloudfrontFound bool
	for _, f := range findings {
		if f.CheckID == finding.CheckProxyChainDetected {
			chainFound = true
		}
		if f.CheckID == finding.CheckProxyHopDetected {
			if strings.Contains(f.Title, "Varnish") {
				varnishFound = true
			}
			if strings.Contains(f.Title, "CloudFront") {
				cloudfrontFound = true
			}
		}
	}

	if !chainFound {
		t.Error("expected proxy chain finding for Via with two hops")
	}
	if !varnishFound {
		t.Error("expected Varnish hop detection from Via header")
	}
	if !cloudfrontFound {
		t.Error("expected CloudFront hop detection from Via header")
	}
}

func TestCacheLayerDetection(t *testing.T) {
	requestCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("X-Cache", "HIT from varnish")
		w.Header().Set("Age", "120")
		w.Header().Set("Server", "nginx")
		w.WriteHeader(200)
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
		if f.CheckID == finding.CheckProxyHopDetected {
			if strings.Contains(f.Title, "Varnish") || strings.Contains(f.Title, "cache") {
				cacheFound = true
			}
		}
	}

	if !cacheFound {
		t.Error("expected cache layer detection from X-Cache header")
	}
}

func TestServerInconsistency(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Server", "nginx/1.24")
		case "/robots.txt":
			w.Header().Set("Server", "Apache/2.4")
		case "/favicon.ico":
			w.Header().Set("Server", "Gunicorn/20.1")
		default:
			w.Header().Set("Server", "nginx/1.24")
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

	// Should detect multiple layers from server header inconsistency
	hopCount := 0
	for _, f := range findings {
		if f.CheckID == finding.CheckProxyHopDetected {
			hopCount++
		}
	}

	if hopCount < 2 {
		t.Errorf("expected 2+ hops from server header inconsistency, got %d", hopCount)
	}
}

func TestXFFEchoDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reflect XFF in response body (insecure debug page)
		xff := r.Header.Get("X-Forwarded-For")
		w.Header().Set("Server", "nginx")
		w.WriteHeader(200)
		w.Write([]byte("Client IP: " + xff))
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	s := New()
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var xffFound bool
	for _, f := range findings {
		if f.CheckID == finding.CheckProxyXFFLeak {
			xffFound = true
		}
	}

	if !xffFound {
		t.Error("expected XFF leak finding when proxy echoes X-Forwarded-For")
	}
}

func TestTraceDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "TRACE" {
			w.WriteHeader(200)
			w.Write([]byte("TRACE / HTTP/1.1\r\nHost: " + r.Host))
			return
		}
		w.Header().Set("Server", "nginx")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	s := New()

	// Surface mode should NOT detect TRACE
	findings, _ := s.Run(context.Background(), asset, module.ScanSurface)
	for _, f := range findings {
		if f.CheckID == finding.CheckProxyTraceEnabled {
			t.Error("TRACE detection should not run in surface mode")
		}
	}

	// Deep mode should detect TRACE
	findings, _ = s.Run(context.Background(), asset, module.ScanDeep)
	var traceFound bool
	for _, f := range findings {
		if f.CheckID == finding.CheckProxyTraceEnabled {
			traceFound = true
		}
	}
	if !traceFound {
		t.Error("expected TRACE finding in deep mode")
	}
}

func TestNoHops(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	s := New()
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Single consistent server header, no Via, no cache headers → no findings
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for plain nginx, got %d", len(findings))
	}
}

func TestH3AltSvcDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", `h3=":443"; ma=86400`)
		w.Header().Set("Server", "nginx")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	s := New()
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var h3Found bool
	for _, f := range findings {
		if f.CheckID == finding.CheckProxyHopDetected && strings.Contains(f.Title, "HTTP/3") {
			h3Found = true
		}
	}

	if !h3Found {
		t.Error("expected HTTP/3 endpoint detection from Alt-Svc header")
	}
}
