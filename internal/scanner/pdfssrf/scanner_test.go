package pdfssrf

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stormbane-security/beacon/internal/module"
)

func TestPDFSSRFDetected(t *testing.T) {
	// Server that accepts HTML at /api/pdf and returns a PDF.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/pdf" {
			if r.Method == http.MethodPost {
				w.Header().Set("Content-Type", "application/pdf")
				w.Write([]byte("%PDF-1.4 fake pdf content"))
				return
			}
			// GET/HEAD → 405 (POST-only endpoint)
			w.WriteHeader(405)
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
		t.Fatal("expected PDF SSRF finding, got none")
	}
	if findings[0].CheckID != "web.pdf_ssrf" {
		t.Errorf("expected web.pdf_ssrf, got %s", findings[0].CheckID)
	}
}

func TestNoPDFOnStaticServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()

	s := New()
	findings, err := s.Run(context.Background(), srv.Listener.Addr().String(), module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings on static server, got %d", len(findings))
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
