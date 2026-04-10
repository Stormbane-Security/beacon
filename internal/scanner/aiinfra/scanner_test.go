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
			_, _ = fmt.Fprint(w, `[{"id":"abc123","name":"python3","execution_state":"idle","last_activity":"2026-04-01T12:00:00Z"}]`)
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
		switch r.URL.Path {
		case "/api/jobs/":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `[{"submission_id":"ray_job_1","entrypoint":"python train.py","runtime_env":{},"driver_info":{"pid":1234},"job_id":"01000000","status":"SUCCEEDED"}]`)
		case "/api/version":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"ray_version":"2.9.0","python_version":"3.10.12"}`)
		default:
			w.WriteHeader(404)
		}
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
			_, _ = fmt.Fprint(w, `{"experiments":[{"experiment_id":"0","name":"Default","artifact_location":"mlruns/0"}]}`)
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
			_, _ = fmt.Fprint(w, `{"gradio_version":"4.19.0","mode":"blocks","api_prefix":"","named_endpoints":{"/predict":{}}}`)
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

func TestNoFalsePositiveOnJobsAPI(t *testing.T) {
	// A regular careers/jobs API should not trigger Ray detection
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/jobs/" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"jobs":[{"id":1,"title":"Software Engineer","description":"Join our team to work on ray tracing","location":"NYC"}]}`)
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
	if len(findings) != 0 {
		t.Errorf("expected no findings from regular jobs API, got %d: %v", len(findings), findings[0].Title)
	}
}

func TestNoFalsePositiveOnHTMLPage(t *testing.T) {
	// HTML pages should never trigger findings, even if they contain keywords
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/jobs/" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = fmt.Fprint(w, `<html><body>submission_id entrypoint runtime_env driver_info job_id ray</body></html>`)
			return
		}
		if r.URL.Path == "/info" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = fmt.Fprint(w, `<html><body>gradio_version api_prefix named_endpoints</body></html>`)
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
	if len(findings) != 0 {
		t.Errorf("expected no findings from HTML pages, got %d", len(findings))
	}
}

func TestNoFalsePositiveOnCleanServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		_, _ = fmt.Fprint(w, `{"error":"not found"}`)
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

func TestGradioDetection_InfoEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/info" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"gradio_version":"4.19.2","api_prefix":"/api","named_endpoints":{"predict":"/api/predict"}}`)
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

func TestGradioNegative_NotGradio(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/info" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"status":"ok","version":"1.0"}`)
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
	for _, f := range findings {
		if f.CheckID == "ai.gradio_unauthenticated" {
			t.Error("should NOT detect Gradio on non-Gradio /info response")
		}
	}
}
