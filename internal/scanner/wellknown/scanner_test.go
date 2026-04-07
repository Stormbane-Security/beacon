package wellknown

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)

func TestSecurityTxtFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/security.txt" {
			_, _ = w.Write([]byte("Contact: security@example.com\nExpires: 2027-01-01T00:00:00Z\n"))
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
		if f.CheckID == finding.CheckWellKnownSecurityTxt {
			found = true
		}
	}
	if !found {
		t.Error("expected CheckWellKnownSecurityTxt finding")
	}
}

func TestSecurityTxtMissing(t *testing.T) {
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

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckWellKnownResourceMissing {
			found = true
		}
	}
	if !found {
		t.Error("expected CheckWellKnownResourceMissing finding")
	}
}

func TestWPADExposed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wpad.dat" {
			w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
			_, _ = w.Write([]byte(`function FindProxyForURL(url, host) {
  if (shExpMatch(host, "*.internal.corp")) {
    return "PROXY proxy.internal.corp:8080";
  }
  return "PROXY gateway.corp:3128; DIRECT";
}`))
			return
		}
		if r.URL.Path == "/.well-known/security.txt" {
			_, _ = w.Write([]byte("Contact: security@example.com\n"))
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
		if f.CheckID == finding.CheckWellKnownWPADExposed {
			found = true
			// Verify proxy extraction.
			proxies, _ := f.Evidence["proxies"].([]string)
			if len(proxies) != 2 {
				t.Errorf("expected 2 proxy URLs, got %d: %v", len(proxies), proxies)
			}
		}
	}
	if !found {
		t.Error("expected CheckWellKnownWPADExposed finding when wpad.dat is served")
	}
}

func TestWPADNotFound_NoFinding(t *testing.T) {
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

	for _, f := range findings {
		if f.CheckID == finding.CheckWellKnownWPADExposed {
			t.Error("should not emit WPAD finding when wpad.dat is not found")
		}
	}
}

func TestWPADNonPAC_NoFinding(t *testing.T) {
	// Server returns 200 for /wpad.dat but the content is not a PAC file.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wpad.dat" {
			w.WriteHeader(200)
			_, _ = w.Write([]byte("<html>not a pac file</html>"))
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

	for _, f := range findings {
		if f.CheckID == finding.CheckWellKnownWPADExposed {
			t.Error("should not emit WPAD finding for non-PAC content")
		}
	}
}

func TestAppleAppSiteAssociation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/apple-app-site-association" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"applinks":{"apps":[],"details":[{"appID":"TEAM.com.example.app"}]}}`))
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
		if f.CheckID == finding.CheckWellKnownAppleAppSite {
			found = true
		}
	}
	if !found {
		t.Error("expected CheckWellKnownAppleAppSite finding")
	}
}
