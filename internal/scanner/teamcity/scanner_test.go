package teamcity

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)

func TestCheckGuestAccess_Enabled(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/guestAuth/app/rest/server" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			w.Write([]byte(`{"version":"2023.11.4","buildNumber":"147571"}`))
			return
		}
		w.WriteHeader(404)
	}))
	defer ts.Close()

	s := New()
	findings := s.checkGuestAccess(context.Background(), ts.URL)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].CheckID != finding.CheckTeamCityGuestAccess {
		t.Errorf("wrong check ID: %s", findings[0].CheckID)
	}
	if findings[0].Severity != finding.SeverityCritical {
		t.Errorf("expected Critical severity, got %s", findings[0].Severity)
	}
}

func TestCheckGuestAccess_Disabled(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
	}))
	defer ts.Close()

	s := New()
	findings := s.checkGuestAccess(context.Background(), ts.URL)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestCheckBuildConfigsExposed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/guestAuth/app/rest/buildTypes" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			w.Write([]byte(`{"count":2,"buildType":[{"id":"MyProject_Build","name":"Build"}]}`))
			return
		}
		w.WriteHeader(404)
	}))
	defer ts.Close()

	s := New()
	findings := s.checkBuildConfigsExposed(context.Background(), ts.URL)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].CheckID != finding.CheckTeamCityBuildConfigsExposed {
		t.Errorf("wrong check ID: %s", findings[0].CheckID)
	}
}

func TestCheckDebugEndpoint_Exposed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app/rest/debug/jvm/systemProperties" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			w.Write([]byte(`{"property":[{"name":"java.version","value":"17.0.8"},{"name":"db.password","value":"s3cret"}]}`))
			return
		}
		w.WriteHeader(404)
	}))
	defer ts.Close()

	s := New()
	findings := s.checkDebugEndpoint(context.Background(), ts.URL)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].CheckID != finding.CheckTeamCityDebugEndpoint {
		t.Errorf("wrong check ID: %s", findings[0].CheckID)
	}
	if findings[0].Severity != finding.SeverityCritical {
		t.Errorf("expected Critical severity, got %s", findings[0].Severity)
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
