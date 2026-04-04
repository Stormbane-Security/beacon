package cmsplugins

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
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
			_, _ = fmt.Fprint(w, readmeBody)
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
			_, _ = fmt.Fprint(w, readmeBody)
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

func TestWordPressDetection_PluginAtThreshold_Vulnerable(t *testing.T) {
	// elementor v3.18.3 == threshold → High (exact threshold is vulnerable).
	readmeBody := "Stable tag: 3.18.3\n"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/wp-login.php":
			w.WriteHeader(http.StatusOK)
		case strings.Contains(r.URL.Path, "/wp-content/plugins/elementor/readme.txt"):
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, readmeBody)
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

	var found bool
	for _, f := range findings {
		if f.CheckID == finding.CheckCMSPluginVulnerable {
			found = true
		}
	}
	if !found {
		t.Error("expected CheckCMSPluginVulnerable for elementor at the exact threshold version (3.18.3), but got none")
	}
}

func TestWordPressDetection_PluginAboveThreshold_InfoOnly(t *testing.T) {
	// elementor v3.18.4 > threshold (3.18.3) → Info (not High).
	readmeBody := "Stable tag: 3.18.4\n"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/wp-login.php":
			w.WriteHeader(http.StatusOK)
		case strings.Contains(r.URL.Path, "/wp-content/plugins/elementor/readme.txt"):
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, readmeBody)
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
			t.Errorf("expected no CheckCMSPluginVulnerable for elementor above threshold (v3.18.4), but got one: %+v", f)
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
			_, _ = fmt.Fprint(w, "version: 5.0.0\n")
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
// Ghost detection via /ghost/ admin panel
// ---------------------------------------------------------------------------

func TestGhostDetection(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ghost/":
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, "<html><title>Ghost Admin</title></html>")
		case "/ghost/api/v3/admin/":
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"meta":{"version":"5.0"}}`)
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

	var cmsDetected bool
	for _, f := range findings {
		if strings.Contains(f.Title, "Ghost") {
			cmsDetected = true
			break
		}
	}
	if !cmsDetected {
		t.Error("expected Ghost CMS detection finding when /ghost/ is accessible")
	}
}

// ---------------------------------------------------------------------------
// Strapi detection via /admin/ with strapi branding
// ---------------------------------------------------------------------------

func TestStrapiDetection(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/":
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `<html><title>Strapi Admin</title><script src="/admin/strapi.js"></script></html>`)
		case "/_health":
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"status":"ok"}`)
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

	var cmsDetected bool
	for _, f := range findings {
		if strings.Contains(f.Title, "Strapi") {
			cmsDetected = true
			break
		}
	}
	if !cmsDetected {
		t.Error("expected Strapi CMS detection finding when /admin/ contains 'strapi'")
	}
}

// ---------------------------------------------------------------------------
// Directus detection via /server/info
// ---------------------------------------------------------------------------

func TestDirectusDetection(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/server/info":
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"project":{"project_name":"My Project"}}`)
		case "/server/health":
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"status":"ok"}`)
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

	var cmsDetected bool
	for _, f := range findings {
		if strings.Contains(f.Title, "Directus") {
			cmsDetected = true
			break
		}
	}
	if !cmsDetected {
		t.Error("expected Directus CMS detection finding when /server/info is accessible")
	}
}

// ---------------------------------------------------------------------------
// PrestaShop detection via body content
// ---------------------------------------------------------------------------

func TestPrestaShopDetection(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `<html><meta name="generator" content="PrestaShop"/></html>`)
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

	var cmsDetected bool
	for _, f := range findings {
		if strings.Contains(f.Title, "PrestaShop") {
			cmsDetected = true
			break
		}
	}
	if !cmsDetected {
		t.Error("expected PrestaShop CMS detection when body contains 'prestashop'")
	}
}

// ---------------------------------------------------------------------------
// Magento detection via /magento_version
// ---------------------------------------------------------------------------

func TestMagentoDetection(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/magento_version":
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, "Magento/2.4 (Community)")
		case "/rest/V1/store/storeConfigs":
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `[{"id":1}]`)
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

	var cmsDetected bool
	for _, f := range findings {
		if strings.Contains(f.Title, "Magento") {
			cmsDetected = true
			break
		}
	}
	if !cmsDetected {
		t.Error("expected Magento CMS detection when /magento_version is accessible")
	}
}

// ---------------------------------------------------------------------------
// TYPO3 detection via /typo3/ admin panel
// ---------------------------------------------------------------------------

func TestTypo3Detection(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/typo3/":
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, "<html><title>TYPO3 Login</title></html>")
		case "/typo3conf/":
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, "<html>Directory listing</html>")
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

	var cmsDetected bool
	for _, f := range findings {
		if strings.Contains(f.Title, "TYPO3") {
			cmsDetected = true
			break
		}
	}
	if !cmsDetected {
		t.Error("expected TYPO3 CMS detection when /typo3/ is accessible")
	}
}

// ---------------------------------------------------------------------------
// Moodle detection via /login/index.php with moodle branding
// ---------------------------------------------------------------------------

func TestMoodleDetection(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/index.php":
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `<html><body class="moodle-login">Welcome to Moodle</body></html>`)
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

	var cmsDetected bool
	for _, f := range findings {
		if strings.Contains(f.Title, "Moodle") {
			cmsDetected = true
			break
		}
	}
	if !cmsDetected {
		t.Error("expected Moodle CMS detection when /login/index.php contains 'moodle'")
	}
}

// ---------------------------------------------------------------------------
// Craft CMS detection via /admin/login with craft cms branding
// ---------------------------------------------------------------------------

func TestCraftCMSDetection(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/login":
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `<html><title>Craft CMS - Login</title></html>`)
		case "/cpresources/":
			w.WriteHeader(http.StatusOK)
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

	var cmsDetected bool
	for _, f := range findings {
		if strings.Contains(f.Title, "Craft") {
			cmsDetected = true
			break
		}
	}
	if !cmsDetected {
		t.Error("expected Craft CMS detection when /admin/login contains 'craft cms'")
	}
}

// ---------------------------------------------------------------------------
// CMS admin path probing — Ghost returns accessible admin paths
// ---------------------------------------------------------------------------

func TestGhostDetection_AdminPathProbed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ghost/":
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, "<html>Ghost Admin</html>")
		case "/ghost/api/v3/admin/":
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"meta":{}}`)
		case "/content/images/":
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, "<html>Directory listing</html>")
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

	// Should have CMS detection + at least one admin path finding
	if len(findings) < 2 {
		t.Errorf("expected at least 2 findings (CMS detection + admin paths), got %d", len(findings))
	}

	var hasPathFinding bool
	for _, f := range findings {
		if strings.Contains(f.Title, "path accessible") {
			hasPathFinding = true
			break
		}
	}
	if !hasPathFinding {
		t.Error("expected at least one 'path accessible' finding for Ghost admin paths")
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
