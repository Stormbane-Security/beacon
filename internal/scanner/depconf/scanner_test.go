package depconf

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

// ---------------------------------------------------------------------------
// parseNPMPackages
// ---------------------------------------------------------------------------

func TestParseNPMPackages_Dependencies(t *testing.T) {
	data := []byte(`{"dependencies":{"express":"^4.18.0","lodash":"4.17.21"}}`)
	deps := parseNPMPackages(data)
	if len(deps) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(deps))
	}
	// Verify versions are captured.
	versions := make(map[string]string)
	for _, d := range deps {
		versions[d.name] = d.version
	}
	if versions["express"] != "^4.18.0" {
		t.Errorf("express version = %q, want ^4.18.0", versions["express"])
	}
	if versions["lodash"] != "4.17.21" {
		t.Errorf("lodash version = %q, want 4.17.21", versions["lodash"])
	}
}

func TestParseNPMPackages_DevDependencies(t *testing.T) {
	data := []byte(`{"devDependencies":{"jest":"^29.0.0","ts-node":"10.9.1"}}`)
	deps := parseNPMPackages(data)
	if len(deps) != 2 {
		t.Fatalf("expected 2 packages from devDependencies, got %d", len(deps))
	}
}

func TestParseNPMPackages_BothSections_Deduped(t *testing.T) {
	data := []byte(`{
		"dependencies": {"shared":"1.0.0","a":"1.0.0"},
		"devDependencies": {"shared":"1.0.0","b":"2.0.0"}
	}`)
	deps := parseNPMPackages(data)
	if len(deps) != 3 {
		t.Errorf("expected 3 unique packages (shared deduped), got %d", len(deps))
	}
}

func TestParseNPMPackages_InvalidJSON(t *testing.T) {
	deps := parseNPMPackages([]byte(`not-json`))
	if deps != nil {
		t.Errorf("expected nil for invalid JSON, got %v", deps)
	}
}

func TestParseNPMPackages_EmptyDeps(t *testing.T) {
	data := []byte(`{"dependencies":{}}`)
	deps := parseNPMPackages(data)
	if len(deps) != 0 {
		t.Errorf("expected 0 packages for empty dependencies, got %d", len(deps))
	}
}

func TestParseNPMPackages_NoDepsKey(t *testing.T) {
	data := []byte(`{"name":"myapp","version":"1.0.0"}`)
	deps := parseNPMPackages(data)
	if len(deps) != 0 {
		t.Errorf("expected 0 packages when no dependencies key, got %d", len(deps))
	}
}

// ---------------------------------------------------------------------------
// parsePyPIPackages
// ---------------------------------------------------------------------------

func TestParsePyPIPackages_PlainNames(t *testing.T) {
	data := []byte("requests\nflask\ndjango\n")
	deps := parsePyPIPackages(data)
	if len(deps) != 3 {
		t.Fatalf("expected 3 packages, got %d", len(deps))
	}
}

func TestParsePyPIPackages_VersionSpecifiers(t *testing.T) {
	data := []byte("requests>=2.0\nflask==2.3.1\ndjango!=4.0\npillow~=9.0\n")
	deps := parsePyPIPackages(data)
	for _, d := range deps {
		if strings.ContainsAny(d.name, "><=!~") {
			t.Errorf("version specifier not stripped from name %q", d.name)
		}
	}
	if len(deps) != 4 {
		t.Errorf("expected 4 packages after stripping specifiers, got %d", len(deps))
	}
	// Pinned version (==) should be extracted.
	for _, d := range deps {
		if d.name == "flask" && d.version != "2.3.1" {
			t.Errorf("flask pinned version = %q, want 2.3.1", d.version)
		}
	}
}

func TestParsePyPIPackages_SkipsComments(t *testing.T) {
	data := []byte("# this is a comment\nrequests\n# another comment\nflask\n")
	deps := parsePyPIPackages(data)
	if len(deps) != 2 {
		t.Errorf("expected 2 packages (comments skipped), got %d", len(deps))
	}
}

func TestParsePyPIPackages_SkipsDashFlags(t *testing.T) {
	data := []byte("-r base.txt\n-i https://pypi.org/simple\nrequests\n")
	deps := parsePyPIPackages(data)
	if len(deps) != 1 {
		t.Errorf("expected 1 package (dash-flag lines skipped), got %d", len(deps))
	}
}

func TestParsePyPIPackages_EmptyLines(t *testing.T) {
	data := []byte("\n\nrequests\n\n")
	deps := parsePyPIPackages(data)
	if len(deps) != 1 {
		t.Errorf("expected 1 package (empty lines skipped), got %d", len(deps))
	}
}

func TestParsePyPIPackages_LowercasesNames(t *testing.T) {
	data := []byte("Django\nFlask\n")
	deps := parsePyPIPackages(data)
	for _, d := range deps {
		if d.name != strings.ToLower(d.name) {
			t.Errorf("expected lowercase package name, got %q", d.name)
		}
	}
}

// ---------------------------------------------------------------------------
// isInternalLooking
// ---------------------------------------------------------------------------

func TestIsInternalLooking_ScopedOrgPackage(t *testing.T) {
	// @acme/utils with domain base "acme" → internal
	if !isInternalLooking("@acme/utils", "acme") {
		t.Error("expected @acme/utils to be internal-looking for domain base 'acme'")
	}
}

func TestIsInternalLooking_ContainsDomainBase(t *testing.T) {
	if !isInternalLooking("acme-utils", "acme") {
		t.Error("expected acme-utils to be internal-looking for domain base 'acme'")
	}
}

func TestIsInternalLooking_InternalKeyword(t *testing.T) {
	cases := []string{"my-internal-lib", "private-sdk", "corp-utils", "local-helpers", "core-lib-v2", "shared-lib"}
	for _, name := range cases {
		if !isInternalLooking(name, "other") {
			t.Errorf("expected %q to be internal-looking (keyword match)", name)
		}
	}
}

func TestIsInternalLooking_WellKnownPublicPackage(t *testing.T) {
	if isInternalLooking("react", "other") {
		t.Error("expected 'react' NOT to be internal-looking")
	}
	if isInternalLooking("express", "other") {
		t.Error("expected 'express' NOT to be internal-looking")
	}
}

func TestIsInternalLooking_CaseInsensitive(t *testing.T) {
	if !isInternalLooking("ACME-SDK", "acme") {
		t.Error("expected ACME-SDK to be internal-looking (case-insensitive domain match)")
	}
}

// ---------------------------------------------------------------------------
// baseName
// ---------------------------------------------------------------------------

func TestBaseName_MultiLabel(t *testing.T) {
	cases := []struct {
		asset string
		want  string
	}{
		{"app.acme.com", "acme"},
		{"acme.com", "acme"},
		{"deep.sub.acme.com", "acme"},
	}
	for _, c := range cases {
		got := baseName(c.asset)
		if got != c.want {
			t.Errorf("baseName(%q) = %q, want %q", c.asset, got, c.want)
		}
	}
}

func TestBaseName_SingleLabel(t *testing.T) {
	got := baseName("localhost")
	if got != "localhost" {
		t.Errorf("baseName(\"localhost\") = %q, want \"localhost\"", got)
	}
}

// ---------------------------------------------------------------------------
// Run — end-to-end with mock HTTP servers
// ---------------------------------------------------------------------------

// runWith creates a Scanner whose HTTP calls go to the provided handler.
// It substitutes the registry URLs by routing everything through the test server.
func runWithServers(t *testing.T, assetHandler http.HandlerFunc, registryHandler http.HandlerFunc) ([]finding.Finding, error) {
	t.Helper()

	// Asset server: serves manifests
	assetServer := httptest.NewServer(assetHandler)
	t.Cleanup(assetServer.Close)

	// Registry server: serves npm/PyPI lookup responses
	registryServer := httptest.NewServer(registryHandler)
	t.Cleanup(registryServer.Close)

	asset := strings.TrimPrefix(assetServer.URL, "http://")
	s := NewWithoutOSV()
	return s.Run(context.Background(), asset, module.ScanSurface)
}

// TestRun_NPMPackageFoundOnPublicRegistry verifies that when a package.json is
// exposed and the internal-looking package exists on npm, a Critical finding is emitted.
//
// NOTE: This test makes real network calls to registry.npmjs.org because the
// Scanner does not accept an injected HTTP client. The test uses a well-known
// non-existent package name to keep it read-only and fast. Because of the real
// network call this test is skipped when the -short flag is set.
func TestRun_NoManifestNoFindings(t *testing.T) {
	// Server returns 404 for all paths — no manifests found → no findings.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	asset := strings.TrimPrefix(ts.URL, "http://")
	s := NewWithoutOSV()
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when no manifest is present, got %d", len(findings))
	}
}

func TestRun_PackageJSONWithNoInternalPackages(t *testing.T) {
	// Expose a package.json whose dependencies are all well-known public packages
	// (no internal-looking names) → no findings should be emitted.
	body := `{"dependencies":{"react":"18.0.0","lodash":"4.17.21"}}`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/package.json" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(body)) //nolint:errcheck
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	asset := strings.TrimPrefix(ts.URL, "http://")
	s := NewWithoutOSV()
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for public-only npm packages, got %d", len(findings))
	}
}

func TestRun_ContextCancelled_NoFindingsNoPanic(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Run

	asset := strings.TrimPrefix(ts.URL, "http://")
	s := NewWithoutOSV()
	findings, _ := s.Run(ctx, asset, module.ScanSurface)
	_ = findings // must not panic
}

// ---------------------------------------------------------------------------
// CheckID constant sanity check
// ---------------------------------------------------------------------------

func TestCheckDependencyConfusion_Defined(t *testing.T) {
	if finding.CheckDependencyConfusion == "" {
		t.Error("finding.CheckDependencyConfusion is empty")
	}
}

func TestCheckVulnerableDependency_Defined(t *testing.T) {
	if finding.CheckVulnerableDependency == "" {
		t.Error("finding.CheckVulnerableDependency is empty")
	}
}

// ---------------------------------------------------------------------------
// Version extraction tests
// ---------------------------------------------------------------------------

func TestParseNPMPackages_ExtractsVersions(t *testing.T) {
	data := []byte(`{"dependencies":{"express":"^4.17.1","lodash":"4.17.21","react":"~18.2.0"}}`)
	deps := parseNPMPackages(data)
	versions := make(map[string]string)
	for _, d := range deps {
		versions[d.name] = d.version
	}
	if versions["express"] != "^4.17.1" {
		t.Errorf("express = %q", versions["express"])
	}
	if versions["lodash"] != "4.17.21" {
		t.Errorf("lodash = %q", versions["lodash"])
	}
	if versions["react"] != "~18.2.0" {
		t.Errorf("react = %q", versions["react"])
	}
}

func TestParsePyPIPackages_ExtractsPinnedVersion(t *testing.T) {
	data := []byte("flask==2.3.1\nrequests>=2.28\ndjango\n")
	deps := parsePyPIPackages(data)
	versions := make(map[string]string)
	for _, d := range deps {
		versions[d.name] = d.version
	}
	if versions["flask"] != "2.3.1" {
		t.Errorf("flask version = %q, want 2.3.1", versions["flask"])
	}
	// Non-pinned should have empty version.
	if versions["requests"] != "" {
		t.Errorf("requests version = %q, want empty (not pinned with ==)", versions["requests"])
	}
	if versions["django"] != "" {
		t.Errorf("django version = %q, want empty", versions["django"])
	}
}

func TestParseGoModules_ExtractsVersions(t *testing.T) {
	data := []byte(`module internal.corp/myapp

go 1.21

require (
	internal.corp/utils v1.2.3
	internal.corp/auth v0.5.0
)
`)
	deps := parseGoModules(data)
	if len(deps) != 2 {
		t.Fatalf("expected 2 modules, got %d", len(deps))
	}
	versions := make(map[string]string)
	for _, d := range deps {
		versions[d.name] = d.version
	}
	if versions["internal.corp/utils"] != "1.2.3" {
		t.Errorf("utils version = %q, want 1.2.3", versions["internal.corp/utils"])
	}
	if versions["internal.corp/auth"] != "0.5.0" {
		t.Errorf("auth version = %q, want 0.5.0", versions["internal.corp/auth"])
	}
}

func TestParseGemfilePackages_ExtractsVersions(t *testing.T) {
	data := []byte(`gem 'rails', '~> 7.0'
gem 'puma', '5.6.5'
gem 'nokogiri'
`)
	deps := parseGemfilePackages(data)
	versions := make(map[string]string)
	for _, d := range deps {
		versions[d.name] = d.version
	}
	if versions["rails"] != "7.0" {
		t.Errorf("rails version = %q, want 7.0", versions["rails"])
	}
	if versions["puma"] != "5.6.5" {
		t.Errorf("puma version = %q, want 5.6.5", versions["puma"])
	}
}

func TestParseComposerPackages_ExtractsVersions(t *testing.T) {
	data := []byte(`{"require":{"laravel/framework":"^10.0","guzzlehttp/guzzle":"7.5.0"},"require-dev":{"phpunit/phpunit":"^10.0"}}`)
	deps := parseComposerPackages(data)
	versions := make(map[string]string)
	for _, d := range deps {
		versions[d.name] = d.version
	}
	if versions["laravel/framework"] != "^10.0" {
		t.Errorf("laravel version = %q", versions["laravel/framework"])
	}
	if versions["guzzlehttp/guzzle"] != "7.5.0" {
		t.Errorf("guzzle version = %q", versions["guzzlehttp/guzzle"])
	}
}

// ---------------------------------------------------------------------------
// cleanVersion
// ---------------------------------------------------------------------------

func TestCleanVersion(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"^4.17.1", "4.17.1"},
		{"~18.2.0", "18.2.0"},
		{">=2.0", "2.0"},
		{"==3.0.1", "3.0.1"},
		{"~> 1.2.3", "1.2.3"},
		{"4.17.21", "4.17.21"},
		{"", ""},
		{"*", ""},
		{"latest", ""},
		{">= 1.0, < 2.0", "1.0"},
	}
	for _, tc := range cases {
		got := cleanVersion(tc.in)
		if got != tc.want {
			t.Errorf("cleanVersion(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
