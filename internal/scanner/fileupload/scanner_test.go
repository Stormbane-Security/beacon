package fileupload

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

func TestRun_DeepMode_NoUploadEndpoints_NoFindings(t *testing.T) {
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
		t.Errorf("expected 0 findings when no upload endpoints, got %d", len(findings))
	}
}

func TestRun_DeepMode_UploadAcceptsPHPDoubleExt_FindingEmitted(t *testing.T) {
	// Server accepts any file upload and returns a URL.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/upload") {
			ct := r.Header.Get("Content-Type")
			if strings.HasPrefix(ct, "multipart/form-data") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"url":"/uploads/beacon_test.php.jpg","filename":"beacon_test.php.jpg"}`))
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
	var hasFileUpload bool
	for _, f := range findings {
		if f.CheckID == finding.CheckWebFileUpload {
			hasFileUpload = true
			if f.ProofCommand == "" {
				t.Error("expected non-empty ProofCommand")
			}
			if strings.Contains(f.ProofCommand, "{asset}") {
				t.Errorf("ProofCommand must not use {asset} placeholder: %s", f.ProofCommand)
			}
		}
	}
	if !hasFileUpload {
		t.Error("expected CheckWebFileUpload finding when server accepts dangerous filename")
	}
}

func TestRun_DeepMode_UploadRejects405_NoFinding(t *testing.T) {
	// Server returns 405 for all uploads.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer ts.Close()

	s := New()
	host := strings.TrimPrefix(ts.URL, "http://")
	findings, err := s.Run(context.Background(), host, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when upload returns 405, got %d", len(findings))
	}
}

func TestRun_DeepMode_UploadReturns200WithoutFileURL_NoFinding(t *testing.T) {
	// Server returns 200 but with a generic message — not a file URL.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
			return
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
		if f.CheckID == finding.CheckWebFileUpload {
			t.Error("expected no finding when server returns 200 without a file URL")
		}
	}
}

func TestBuildMutations_ContainsDangerousFilenames(t *testing.T) {
	mutations := buildMutations()
	if len(mutations) == 0 {
		t.Fatal("expected at least one mutation")
	}
	var hasDoubleExt, hasMIMEConfusion bool
	for _, m := range mutations {
		if strings.Contains(m.filename, ".php.jpg") {
			hasDoubleExt = true
		}
		if m.contentType == "image/gif" && strings.Contains(m.filename, ".php") {
			hasMIMEConfusion = true
		}
	}
	if !hasDoubleExt {
		t.Error("expected a double-extension mutation (.php.jpg)")
	}
	if !hasMIMEConfusion {
		t.Error("expected a MIME confusion mutation (image/gif + .php)")
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
	_ = findings
}
