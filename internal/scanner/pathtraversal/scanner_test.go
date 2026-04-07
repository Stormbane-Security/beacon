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

// TestDoubleEncodingTraversal verifies detection via double-URL-encoded payloads.
// Go's HTTP client decodes one layer (%252f → %2f), so the test server matches
// %2f in RawPath, simulating a proxy that decodes once before forwarding.
func TestDoubleEncodingTraversal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.URL.RawPath
		if raw == "" {
			raw = r.URL.Path
		}
		// After Go's client decodes one layer, %252f becomes %2f in the raw path.
		// A vulnerable backend would decode this again to / and traverse.
		if strings.Contains(raw, "%2f") || strings.Contains(raw, "%2F") ||
			strings.Contains(raw, "%2e") || strings.Contains(raw, "%2E") {
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`web-inf sensitive data`))
			return
		}
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
	if len(findings) == 0 {
		t.Fatal("expected path traversal finding for encoded-slash bypass, got none")
	}
}

// TestBackslashTraversal verifies detection of IIS-style backslash traversal (%5C).
func TestBackslashTraversal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.URL.RawPath
		if raw == "" {
			raw = r.URL.Path
		}
		if strings.Contains(raw, "%5C") || strings.Contains(raw, "%5c") {
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`web.xml configuration file`))
			return
		}
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
	if len(findings) == 0 {
		t.Fatal("expected path traversal finding for backslash bypass, got none")
	}
}

// TestUTF8OverlongTraversal verifies detection via UTF-8 overlong encoding (%c0%ae).
func TestUTF8OverlongTraversal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.URL.RawPath
		if raw == "" {
			raw = r.URL.Path
		}
		if strings.Contains(raw, "%c0%ae") || strings.Contains(raw, "%C0%AE") {
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`root:x:0:0:root`))
			return
		}
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
	if len(findings) == 0 {
		t.Fatal("expected path traversal finding for UTF-8 overlong bypass, got none")
	}
}

// Note: null byte traversal (/..%00/) cannot be tested with Go's httptest
// because Go's HTTP client rejects URLs containing null bytes. This payload
// targets older runtimes (PHP, Ruby) where the kernel null-terminates paths.
// Testing requires a real vulnerable server (e.g. old PHP + Apache).
