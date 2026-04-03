package jsframework

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)

func TestDetectJQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head>
			<script src="/js/jquery-3.3.1.min.js"></script>
		</head><body>jQuery page</body></html>`))
	}))
	defer srv.Close()

	s := New()
	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}

	detected := false
	vulnerable := false
	for _, f := range findings {
		if f.CheckID == finding.CheckJSFrameworkDetected && f.Evidence["framework"] == "jQuery" {
			detected = true
			if f.Evidence["version"] != "3.3.1" {
				t.Errorf("version = %q, want 3.3.1", f.Evidence["version"])
			}
		}
		if f.CheckID == finding.CheckJSFrameworkVulnerable {
			vulnerable = true
		}
	}
	if !detected {
		t.Error("expected jQuery detected")
	}
	if !vulnerable {
		t.Error("expected jQuery 3.3.1 flagged as vulnerable")
	}
}

func TestDetectAngularJS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html ng-app="myApp"><head>
			<script src="/js/angular-1.8.2.min.js"></script>
		</head><body></body></html>`))
	}))
	defer srv.Close()

	s := New()
	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}

	detected := false
	for _, f := range findings {
		if f.CheckID == finding.CheckJSFrameworkDetected && f.Evidence["framework"] == "AngularJS" {
			detected = true
		}
	}
	if !detected {
		t.Error("expected AngularJS detected")
	}
}

func TestDetectReact(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head></head><body><div id="root" data-reactroot></div></body></html>`))
	}))
	defer srv.Close()

	s := New()
	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}

	detected := false
	for _, f := range findings {
		if f.CheckID == finding.CheckJSFrameworkDetected && f.Evidence["framework"] == "React" {
			detected = true
		}
	}
	if !detected {
		t.Error("expected React detected")
	}
}

func TestNoFramework(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head></head><body>Plain HTML</body></html>`))
	}))
	defer srv.Close()

	s := New()
	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for plain HTML, got %d", len(findings))
	}
}
