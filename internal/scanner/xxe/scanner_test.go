package xxe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

func TestRun_SurfaceMode_ReturnsNil(t *testing.T) {
	s := New()
	findings, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings in surface mode, got %d", len(findings))
	}
}

func TestRun_DeepMode_NoXMLEndpoints_NoFindings(t *testing.T) {
	// Server returns 404 for all paths.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	s := New()
	host := strings.TrimPrefix(ts.URL, "http://")
	findings, err := s.Run(context.Background(), host, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when no XML endpoints exist, got %d", len(findings))
	}
}

func TestRun_DeepMode_XXEDetected(t *testing.T) {
	// Server at /api accepts XML POST and echoes back the body content — simulating
	// a server that resolves and returns XXE entity content.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api" && r.Method == http.MethodPost {
			ct := r.Header.Get("Content-Type")
			if strings.HasPrefix(ct, "application/xml") || strings.HasPrefix(ct, "text/xml") {
				// Simulate XXE: return /etc/passwd-like content
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`<response><data>root:x:0:0:root:/root:/bin/bash</data></response>`))
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	s := New()
	host := strings.TrimPrefix(ts.URL, "http://")
	findings, err := s.Run(context.Background(), host, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var hasXXE bool
	for _, f := range findings {
		if f.CheckID == finding.CheckWebXXE {
			hasXXE = true
			if f.Severity != finding.SeverityCritical {
				t.Errorf("expected SeverityCritical, got %v", f.Severity)
			}
			if f.ProofCommand == "" {
				t.Error("expected non-empty ProofCommand")
			}
		}
	}
	if !hasXXE {
		t.Error("expected CheckWebXXE finding when server echoes XXE indicator")
	}
}

func TestRun_DeepMode_XMLEndpointExists_NoXXE_NoFinding(t *testing.T) {
	// Server accepts XML but does NOT echo entity content.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api" && r.Method == http.MethodPost {
			ct := r.Header.Get("Content-Type")
			if strings.HasPrefix(ct, "application/xml") {
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`<response><status>ok</status></response>`))
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	s := New()
	host := strings.TrimPrefix(ts.URL, "http://")
	findings, err := s.Run(context.Background(), host, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.CheckID == finding.CheckWebXXE {
			t.Error("expected no XXE finding when server does not echo entity content")
		}
	}
}

func TestRun_DeepMode_ProofCommandHasActualURL(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api" && r.Method == http.MethodPost {
			ct := r.Header.Get("Content-Type")
			if strings.HasPrefix(ct, "application/xml") {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`root:x:0:0:root:/root:/bin/bash`))
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	s := New()
	host := strings.TrimPrefix(ts.URL, "http://")
	findings, err := s.Run(context.Background(), host, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.CheckID == finding.CheckWebXXE {
			if strings.Contains(f.ProofCommand, "{asset}") {
				t.Errorf("ProofCommand must not use {asset} placeholder: %s", f.ProofCommand)
			}
			if !strings.Contains(f.ProofCommand, host) {
				t.Errorf("ProofCommand must contain actual host %q: %s", host, f.ProofCommand)
			}
		}
	}
}

func TestRun_ContextCancelled_NoPanic(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	s := New()
	host := strings.TrimPrefix(ts.URL, "http://")
	findings, _ := s.Run(ctx, host, module.ScanDeep)
	_ = findings // must not panic
}
