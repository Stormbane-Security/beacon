package cmsplugins

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

// ---------------------------------------------------------------------------
// isNewerOrEqual — version comparison
// ---------------------------------------------------------------------------

func TestIsNewerOrEqual_EqualVersions(t *testing.T) {
	if !isNewerOrEqual("3.18.3", "3.18.3") {
		t.Error("equal versions should be considered newer-or-equal")
	}
}

func TestIsNewerOrEqual_InstalledNewer(t *testing.T) {
	cases := []struct{ installed, threshold string }{
		{"4.0.0", "3.18.3"},
		{"3.19.0", "3.18.3"},
		{"3.18.4", "3.18.3"},
		{"1.0.0", "0.9.9"},
	}
	for _, c := range cases {
		if !isNewerOrEqual(c.installed, c.threshold) {
			t.Errorf("isNewerOrEqual(%q, %q): installed is newer, expected true", c.installed, c.threshold)
		}
	}
}

func TestIsNewerOrEqual_InstalledOlder(t *testing.T) {
	cases := []struct{ installed, threshold string }{
		{"3.18.2", "3.18.3"},
		{"3.17.99", "3.18.3"},
		{"2.99.99", "3.0.0"},
		{"0.9.8", "0.9.9"},
	}
	for _, c := range cases {
		if isNewerOrEqual(c.installed, c.threshold) {
			t.Errorf("isNewerOrEqual(%q, %q): installed is older, expected false", c.installed, c.threshold)
		}
	}
}

func TestIsNewerOrEqual_ShorterInstalledVersion(t *testing.T) {
	// "5" vs "3.18.3": major 5 > 3 → true
	if !isNewerOrEqual("5", "3.18.3") {
		t.Error("major version 5 > 3.18.3 should be newer-or-equal")
	}
}

func TestIsNewerOrEqual_LongerInstalledVersion(t *testing.T) {
	// "3.18.3.1" vs "3.18.3": the extra .1 makes it newer
	if !isNewerOrEqual("3.18.3.1", "3.18.3") {
		t.Error("3.18.3.1 should be newer-or-equal to 3.18.3")
	}
}

// ---------------------------------------------------------------------------
// extractVersion
// ---------------------------------------------------------------------------

func TestExtractVersion_StableTag(t *testing.T) {
	text := "Contributors: Joe\nStable tag: 1.2.3\nSome other line"
	got := extractVersion(text, "Stable tag:")
	if got != "1.2.3" {
		t.Errorf("expected '1.2.3', got %q", got)
	}
}

func TestExtractVersion_NoMatch(t *testing.T) {
	got := extractVersion("no version here", "Stable tag:")
	if got != "" {
		t.Errorf("expected empty string when key not present, got %q", got)
	}
}

func TestExtractVersion_EmptyKey(t *testing.T) {
	got := extractVersion("Stable tag: 2.0", "")
	if got != "" {
		t.Errorf("expected empty string for empty key, got %q", got)
	}
}

func TestExtractVersion_VersionWithNewline(t *testing.T) {
	text := "Stable tag: 4.5.6\nnext line"
	got := extractVersion(text, "Stable tag:")
	if got != "4.5.6" {
		t.Errorf("expected '4.5.6', got %q", got)
	}
}

// ---------------------------------------------------------------------------
// CMS detection — WordPress
// ---------------------------------------------------------------------------

// newTestScanner builds an httptest server and returns the asset string for it.
// handler is called for every inbound request.
func newTestServer(t *testing.T, handler http.HandlerFunc) (asset string, close func()) {
	t.Helper()
	ts := httptest.NewServer(handler)
	return strings.TrimPrefix(ts.URL, "http://"), ts.Close
}

func TestWordPressDetection_PluginFound(t *testing.T) {
	// Serve wp-login.php (triggers WP detection) + a plugin readme.
	readmeBody := "Contributors: author\nStable tag: 4.0.0\nDescription: A plugin.\n"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/wp-login.php":
			// HEAD 200 → WordPress detected
			w.WriteHeader(http.StatusOK)
		case strings.Contains(r.URL.Path, "/wp-content/plugins/elementor/readme.txt"):
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, readmeBody)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	asset := strings.TrimPrefix(ts.URL, "http://")
	s := New()
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var pluginFindings []finding.Finding
	for _, f := range findings {
		if f.CheckID == finding.CheckCMSPluginFound || f.CheckID == finding.CheckCMSPluginVulnerable {
			pluginFindings = append(pluginFindings, f)
		}
	}

	if len(pluginFindings) == 0 {
		t.Error("expected at least one plugin finding when elementor readme is accessible on WordPress")
	}
}

func TestWordPressDetection_VulnerablePlugin(t *testing.T) {
	// elementor knownVulnVer is "3.18.3" — serve version "3.10.0" (older) → High finding.
	readmeBody := "Stable tag: 3.10.0\n"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/wp-login.php":
			w.WriteHeader(http.StatusOK)
		case strings.Contains(r.URL.Path, "/wp-content/plugins/elementor/readme.txt"):
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, readmeBody)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	asset := strings.TrimPrefix(ts.URL, "http://")
	s := New()
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var vulnFindings []finding.Finding
	for _, f := range findings {
		if f.CheckID == finding.CheckCMSPluginVulnerable {
			vulnFindings = append(vulnFindings, f)
		}
	}
	if len(vulnFindings) == 0 {
		t.Error("expected CheckCMSPluginVulnerable finding for elementor v3.10.0 (below vuln threshold 3.18.3)")
	}
	if len(vulnFindings) > 0 && vulnFindings[0].Severity != finding.SeverityHigh {
		t.Errorf("expected SeverityHigh for vulnerable plugin, got %s", vulnFindings[0].Severity)
	}
}

func TestWordPressDetection_PluginAtOrAboveThreshold_InfoOnly(t *testing.T) {
	// elementor v3.18.3 == threshold → Info (not High).
	readmeBody := "Stable tag: 3.18.3\n"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/wp-login.php":
			w.WriteHeader(http.StatusOK)
		case strings.Contains(r.URL.Path, "/wp-content/plugins/elementor/readme.txt"):
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, readmeBody)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	asset := strings.TrimPrefix(ts.URL, "http://")
	s := New()
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if f.CheckID == finding.CheckCMSPluginVulnerable {
			t.Errorf("expected no CheckCMSPluginVulnerable for elementor at the exact threshold version, but got one: %+v", f)
		}
	}
}

// ---------------------------------------------------------------------------
// Drupal detection via X-Drupal-Cache header
// ---------------------------------------------------------------------------

func TestDrupalDetection_ViaHeader(t *testing.T) {
	// Serve X-Drupal-Cache header on the root page + a contrib module.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/":
			w.Header().Set("X-Drupal-Cache", "HIT")
			w.WriteHeader(http.StatusOK)
		case strings.Contains(r.URL.Path, "/modules/contrib/webform/webform.info.yml"):
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "version: 5.0.0\n")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	asset := strings.TrimPrefix(ts.URL, "http://")
	s := New()
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var moduleFindings []finding.Finding
	for _, f := range findings {
		if f.CheckID == finding.CheckCMSPluginFound || f.CheckID == finding.CheckCMSPluginVulnerable {
			moduleFindings = append(moduleFindings, f)
		}
	}
	if len(moduleFindings) == 0 {
		t.Error("expected at least one module finding when Drupal detected via X-Drupal-Cache")
	}
}

// ---------------------------------------------------------------------------
// Unknown CMS → no findings
// ---------------------------------------------------------------------------

func TestUnknownCMS_NoFindings(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Respond 200 to HEAD (so baseURL resolves) but 404 to all CMS probe paths.
		if r.Method == http.MethodHead && r.URL.Path == "/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	asset := strings.TrimPrefix(ts.URL, "http://")
	s := New()
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-CMS server, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Unreachable server → no panic, no findings
// ---------------------------------------------------------------------------

func TestUnreachableServer_NoFindingsNoPanic(t *testing.T) {
	s := New()
	findings, err := s.Run(context.Background(), "127.0.0.1:1", module.ScanSurface)
	_ = err
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for unreachable server, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Context cancellation
// ---------------------------------------------------------------------------

func TestContextCancelled_NoPanic(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	asset := strings.TrimPrefix(ts.URL, "http://")
	s := New()
	findings, _ := s.Run(ctx, asset, module.ScanSurface)
	_ = findings
}
