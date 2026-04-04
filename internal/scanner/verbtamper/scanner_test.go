package verbtamper

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stormbane-security/beacon/internal/module"
)

func TestVerbTamperBypass(t *testing.T) {
	// Server that blocks GET /admin with 403 but allows POST /admin with 200.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" || r.URL.Path == "/admin/" {
			if r.Method == http.MethodGet {
				w.WriteHeader(403)
				return
			}
			if r.Method == http.MethodPost {
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"admin": true}`))
				return
			}
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
		t.Fatal("expected verb tamper bypass finding, got none")
	}
	if findings[0].CheckID != "web.verb_tamper_auth_bypass" {
		t.Errorf("expected web.verb_tamper_auth_bypass, got %s", findings[0].CheckID)
	}
}

func TestNoBypassOnConsistentServer(t *testing.T) {
	// Server that returns 403 on all methods for /admin.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	if len(findings) != 0 {
		t.Errorf("expected no findings on consistent 403 server, got %d", len(findings))
	}
}

func TestOptionsWithCORSHeaders_NoFalsePositive(t *testing.T) {
	// Server returns 403 on GET /admin but OPTIONS returns 200 with CORS headers.
	// This is standard CORS preflight behavior, not an auth bypass.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" || r.URL.Path == "/admin/" {
			if r.Method == http.MethodGet {
				w.WriteHeader(403)
				return
			}
			if r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Allow-Origin", "*")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				w.WriteHeader(200)
				return
			}
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	s := New()
	findings, err := s.Run(context.Background(), srv.Listener.Addr().String(), module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.CheckID == "web.verb_tamper_auth_bypass" {
			t.Errorf("false positive: OPTIONS with CORS headers should not trigger bypass finding: %s", f.Title)
		}
	}
}

func TestHeadEmptyBody_NoFalsePositive(t *testing.T) {
	// Server returns 403 on GET /admin but HEAD returns 200 with empty body.
	// HEAD with empty body is not evidence of actual auth bypass.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" || r.URL.Path == "/admin/" {
			if r.Method == http.MethodGet {
				w.WriteHeader(403)
				return
			}
			if r.Method == http.MethodHead {
				w.WriteHeader(200)
				return // empty body
			}
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	s := New()
	findings, err := s.Run(context.Background(), srv.Listener.Addr().String(), module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.CheckID == "web.verb_tamper_auth_bypass" {
			t.Errorf("false positive: HEAD with empty body should not trigger bypass finding: %s", f.Title)
		}
	}
}

func TestSurfaceModeSkips(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(403)
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
	if len(findings) != 0 {
		t.Errorf("expected no findings in surface mode, got %d", len(findings))
	}
}
