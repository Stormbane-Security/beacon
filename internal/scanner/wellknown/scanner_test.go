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
