package aiinfra

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stormbane-security/beacon/internal/module"
)

func TestJupyterDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/kernels" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `[{"id":"abc123","name":"python3","execution_state":"idle","last_activity":"2026-04-01T12:00:00Z"}]`)
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	s := New()
	findings, err := s.Run(context.Background(), srv.Listener.Addr().String(), module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected Jupyter finding, got none")
	}
	if findings[0].CheckID != "ai.jupyter_unauthenticated" {
		t.Errorf("expected ai.jupyter_unauthenticated, got %s", findings[0].CheckID)
	}
}

func TestRayDashboardDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/jobs/" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `[{"submission_id":"ray_job_1","entrypoint":"python train.py","status":"SUCCEEDED"}]`)
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	s := New()
	findings, err := s.Run(context.Background(), srv.Listener.Addr().String(), module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected Ray finding, got none")
	}
	if findings[0].CheckID != "ai.ray_dashboard_unauthenticated" {
		t.Errorf("expected ai.ray_dashboard_unauthenticated, got %s", findings[0].CheckID)
	}
}

func TestMLflowDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/2.0/mlflow/experiments/list" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"experiments":[{"experiment_id":"0","name":"Default","artifact_location":"mlruns/0"}]}`)
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	s := New()
	findings, err := s.Run(context.Background(), srv.Listener.Addr().String(), module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected MLflow finding, got none")
	}
	if findings[0].CheckID != "ai.mlflow_unauthenticated" {
		t.Errorf("expected ai.mlflow_unauthenticated, got %s", findings[0].CheckID)
	}
}

func TestGradioDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/info" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"version":"4.19.0","mode":"blocks","api_prefix":"","gradio_version":"4.19.0"}`)
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	s := New()
	findings, err := s.Run(context.Background(), srv.Listener.Addr().String(), module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected Gradio finding, got none")
	}
	if findings[0].CheckID != "ai.gradio_unauthenticated" {
		t.Errorf("expected ai.gradio_unauthenticated, got %s", findings[0].CheckID)
	}
}

func TestNoFalsePositiveOnCleanServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		fmt.Fprint(w, `{"error":"not found"}`)
	}))
	defer srv.Close()

	s := New()
	findings, err := s.Run(context.Background(), srv.Listener.Addr().String(), module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}
