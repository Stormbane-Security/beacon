package gitlab

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)

func TestCheckPublicRegistration_Enabled(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/users/sign_up" {
			w.WriteHeader(200)
			w.Write([]byte(`<html><body><h1>Sign up</h1><form>Register here</form></body></html>`))
			return
		}
		w.WriteHeader(404)
	}))
	defer ts.Close()

	s := New()
	findings := s.checkPublicRegistration(context.Background(), ts.URL)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].CheckID != finding.CheckGitLabPublicRegistration {
		t.Errorf("wrong check ID: %s", findings[0].CheckID)
	}
}

func TestCheckPublicRegistration_Disabled(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/users/sign_in", http.StatusFound)
	}))
	defer ts.Close()

	s := New()
	findings := s.checkPublicRegistration(context.Background(), ts.URL)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestCheckPrometheusExposed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/-/metrics" {
			w.WriteHeader(200)
			w.Write([]byte("# HELP gitlab_transaction_duration_seconds\n# TYPE gitlab_transaction_duration_seconds histogram\n"))
			return
		}
		w.WriteHeader(404)
	}))
	defer ts.Close()

	s := New()
	findings := s.checkPrometheusExposed(context.Background(), ts.URL)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].CheckID != finding.CheckGitLabPrometheusExposed {
		t.Errorf("wrong check ID: %s", findings[0].CheckID)
	}
}

func TestCheckAPIUnauth_Returns401(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte(`{"message":"401 Unauthorized"}`))
	}))
	defer ts.Close()

	s := New()
	findings := s.checkAPIUnauth(context.Background(), ts.URL)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestCheckAPIUnauth_ReturnsProjects(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`[{"id":1,"path_with_namespace":"org/project"}]`))
	}))
	defer ts.Close()

	s := New()
	findings := s.checkAPIUnauth(context.Background(), ts.URL)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].CheckID != finding.CheckGitLabAPIUnauth {
		t.Errorf("wrong check ID: %s", findings[0].CheckID)
	}
}

func TestSurfaceMode_ReturnsNil(t *testing.T) {
	s := New()
	findings, err := s.Run(context.Background(), "http://localhost", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if findings != nil {
		t.Fatalf("expected nil findings in surface mode, got %d", len(findings))
	}
}
