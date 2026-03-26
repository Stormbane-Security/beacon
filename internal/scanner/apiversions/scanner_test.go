package apiversions

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane/beacon/internal/module"
)

func TestAPIVersions_ActiveVersionDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintln(w, `{"version":"1"}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for active /api/v1/")
	}
	f := findings[0]
	if f.CheckID != "exposure.api_version" {
		t.Errorf("unexpected check ID: %s", f.CheckID)
	}
	if f.ProofCommand == "" {
		t.Error("ProofCommand should be set")
	}
}

func TestAPIVersions_SoftHTMLResponseSkipped(t *testing.T) {
	// Servers that return HTML for every path (catch-all) must not trigger findings.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintln(w, "<html><body>Welcome</body></html>")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("HTML response should be treated as soft-404, got %d findings", len(findings))
	}
}

func TestAPIVersions_404NotFlagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for 404 responses, got %d", len(findings))
	}
}

func TestAPIVersions_DevEndpointHighSeverity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/dev/", "/api/staging/", "/api/internal/", "/api/beta/", "/api/alpha/":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintln(w, `{"env":"staging"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings for dev/staging/internal/beta/alpha endpoints")
	}
	for _, f := range findings {
		v := fmt.Sprintf("%v", f.Evidence["version"])
		devKeywords := map[string]bool{"dev": true, "staging": true, "internal": true, "beta": true, "alpha": true}
		if devKeywords[v] && f.Severity.String() != "high" {
			t.Errorf("dev/staging endpoint %q should be HIGH severity, got %s", v, f.Severity)
		}
	}
}

func TestAPIVersions_NumberedVersionOnNonStdPort_MediumSeverity(t *testing.T) {
	// httptest always binds a non-standard port, so numbered versions are elevated
	// to Medium (non-standard port = likely internal service unintentionally exposed).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintln(w, `{"ok":true}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for /api/v2/")
	}
	f := findings[0]
	if f.Severity.String() != "medium" {
		t.Errorf("numbered API version on non-standard port should be MEDIUM severity, got %s", f.Severity)
	}
}

func TestAPIVersions_400NotFlagged(t *testing.T) {
	// A 400 from a generic GET probe is too ambiguous — the server may use it as
	// a custom 404 or because our probe lacks required parameters. Not a finding.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, `{"error":"bad request"}`)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("400 responses should not trigger findings, got %d findings", len(findings))
	}
}

func TestAPIVersions_405SkippedNotFlagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("405 responses should not trigger findings, got %d", len(findings))
	}
}

func TestAPIVersions_NonStandardPort_ElevatesSeverity(t *testing.T) {
	// Numbered API version on a non-standard port should be Medium, not Low.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintln(w, `{"version":"1"}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	// httptest always binds a non-standard port, so this exercises the non-standard path.
	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for /api/v1/ on non-standard port")
	}
	f := findings[0]
	if f.Severity.String() != "medium" {
		t.Errorf("numbered API version on non-standard port should be MEDIUM severity, got %s", f.Severity)
	}
	if _, ok := f.Evidence["port"]; !ok {
		t.Error("finding evidence should include 'port' key for non-standard port")
	}
}

func TestAPIVersions_NonStandardPort_TitleIncludesPort(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintln(w, `{"ok":true}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding")
	}
	// Title should mention the port.
	if !strings.Contains(findings[0].Title, ":") {
		t.Errorf("finding title should include port, got: %q", findings[0].Title)
	}
}

func TestParsePort(t *testing.T) {
	cases := []struct{ asset, want string }{
		{"example.com:8080", "8080"},
		{"example.com:443", "443"},
		{"example.com", ""},
		{"127.0.0.1:3000", "3000"},
	}
	for _, c := range cases {
		got := parsePort(c.asset)
		if got != c.want {
			t.Errorf("parsePort(%q) = %q, want %q", c.asset, got, c.want)
		}
	}
}

func TestIsNonStandardPort(t *testing.T) {
	cases := []struct {
		port string
		want bool
	}{
		{"", false},
		{"80", false},
		{"443", false},
		{"8080", true},
		{"3000", true},
		{"8443", true},
	}
	for _, c := range cases {
		got := isNonStandardPort(c.port)
		if got != c.want {
			t.Errorf("isNonStandardPort(%q) = %v, want %v", c.port, got, c.want)
		}
	}
}

func TestAPIVersions_RunsBothModes(t *testing.T) {
	// apiversions runs in surface mode — verify it also runs in deep mode without panic.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	if _, err := New().Run(t.Context(), asset, module.ScanDeep); err != nil {
		t.Fatal(err)
	}
}
