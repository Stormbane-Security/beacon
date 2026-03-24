package httpmethods

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

// --- optionsAllowed ---

func TestOptionsAllowed_ReturnsAllowHeader(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", "GET, POST, PUT")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := ts.Client()
	got := optionsAllowed(context.Background(), client, ts.URL+"/")
	if got != "GET, POST, PUT" {
		t.Errorf("expected 'GET, POST, PUT', got %q", got)
	}
}

func TestOptionsAllowed_NoAllowHeader_ReturnsEmpty(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	got := optionsAllowed(context.Background(), ts.Client(), ts.URL+"/")
	if got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestOptionsAllowed_ServerUnreachable_ReturnsEmpty(t *testing.T) {
	got := optionsAllowed(context.Background(), &http.Client{}, "http://127.0.0.1:1/")
	if got != "" {
		t.Errorf("expected empty for unreachable server, got %q", got)
	}
}

// --- confirmMethod ---

func TestConfirmMethod_PUT_Returns405_NotConfirmed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer ts.Close()

	ok, code := confirmMethod(context.Background(), ts.Client(), ts.URL+"/", http.MethodPut)
	if ok {
		t.Error("405 should not confirm the method")
	}
	if code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", code)
	}
}

func TestConfirmMethod_PUT_Returns501_NotConfirmed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotImplemented)
	}))
	defer ts.Close()

	ok, _ := confirmMethod(context.Background(), ts.Client(), ts.URL+"/", http.MethodPut)
	if ok {
		t.Error("501 should not confirm the method")
	}
}

func TestConfirmMethod_PUT_Returns201_Confirmed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			w.WriteHeader(http.StatusCreated)
			return
		}
		w.WriteHeader(http.StatusNoContent) // DELETE cleanup
	}))
	defer ts.Close()

	ok, code := confirmMethod(context.Background(), ts.Client(), ts.URL+"/", http.MethodPut)
	if !ok {
		t.Error("201 should confirm PUT method")
	}
	if code != http.StatusCreated {
		t.Errorf("expected 201, got %d", code)
	}
}

func TestConfirmMethod_DELETE_Returns404_Confirmed(t *testing.T) {
	// 404 means the server processed DELETE (resource not found, but method accepted)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	ok, _ := confirmMethod(context.Background(), ts.Client(), ts.URL+"/", http.MethodDelete)
	if !ok {
		t.Error("404 on DELETE should confirm method (server processed it, resource not found)")
	}
}

func TestConfirmMethod_PUT_Returns200_SendsDeleteCleanup(t *testing.T) {
	// A successful PUT (2xx) must be followed by a DELETE to clean up the artifact.
	var deleteCalled atomic.Bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			w.WriteHeader(http.StatusOK)
		case http.MethodDelete:
			deleteCalled.Store(true)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer ts.Close()

	confirmMethod(context.Background(), ts.Client(), ts.URL+"/", http.MethodPut)
	if !deleteCalled.Load() {
		t.Error("expected DELETE cleanup request after successful PUT 2xx, none was sent")
	}
}

func TestConfirmMethod_PUT_Returns404_NoDeleteCleanup(t *testing.T) {
	// PUT that returns 404 means no resource was created — no cleanup needed.
	var deleteCalled atomic.Bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deleteCalled.Store(true)
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	confirmMethod(context.Background(), ts.Client(), ts.URL+"/", http.MethodPut)
	if deleteCalled.Load() {
		t.Error("DELETE cleanup should not be sent when PUT returns 404 (non-2xx)")
	}
}

func TestConfirmMethod_ProbePathIsSafe(t *testing.T) {
	// The probe must target /.beacon-method-probe-xq7z, not the root path.
	var probedPath string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			probedPath = r.URL.Path
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer ts.Close()

	confirmMethod(context.Background(), ts.Client(), ts.URL+"/", http.MethodPut)
	if !strings.Contains(probedPath, ".beacon-method-probe-xq7z") {
		t.Errorf("expected probe path to contain .beacon-method-probe-xq7z, got %q", probedPath)
	}
}

// --- discoverBase ---

func TestDiscoverBase_HTTPSFirst_ReturnsHTTPS(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	base := discoverBase(context.Background(), ts.Client(), strings.TrimPrefix(ts.URL, "https://"))
	if !strings.HasPrefix(base, "https://") {
		t.Errorf("expected https:// base URL, got %q", base)
	}
}

func TestDiscoverBase_UnreachableServer_ReturnsEmpty(t *testing.T) {
	base := discoverBase(context.Background(), &http.Client{}, "127.0.0.1:1")
	if base != "" {
		t.Errorf("expected empty base for unreachable server, got %q", base)
	}
}

func TestDiscoverBase_5xxResponse_ReturnsEmpty(t *testing.T) {
	// 5xx — server treats as unavailable; base should be empty
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	base := discoverBase(context.Background(), ts.Client(), strings.TrimPrefix(ts.URL, "http://"))
	if base != "" {
		t.Errorf("expected empty for 500 response, got %q", base)
	}
}

// --- Run ---

func TestRun_PUTEnabled_FindingEmitted(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.WriteHeader(http.StatusOK)
		case http.MethodOptions:
			w.Header().Set("Allow", "GET, PUT")
			w.WriteHeader(http.StatusOK)
		case http.MethodPut:
			w.WriteHeader(http.StatusCreated)
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer ts.Close()

	s := New()
	host := strings.TrimPrefix(ts.URL, "http://")
	findings, err := s.Run(context.Background(), host, module.ScanSurface)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	var found bool
	for _, f := range findings {
		if f.CheckID == finding.CheckWebDangerousMethodEnabled &&
			strings.Contains(f.Title, "PUT") {
			found = true
		}
	}
	if !found {
		t.Error("expected CheckWebDangerousMethodEnabled for PUT, got none")
	}
}

func TestRun_AllMethodsDisabled_NoFindings(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer ts.Close()

	s := New()
	host := strings.TrimPrefix(ts.URL, "http://")
	findings, err := s.Run(context.Background(), host, module.ScanSurface)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	for _, f := range findings {
		if f.CheckID == finding.CheckWebDangerousMethodEnabled {
			t.Errorf("unexpected finding for disabled methods: %s", f.Title)
		}
	}
}

func TestRun_UnreachableServer_NoFindings(t *testing.T) {
	s := New()
	findings, err := s.Run(context.Background(), "127.0.0.1:1", module.ScanSurface)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for unreachable server, got %d", len(findings))
	}
}
