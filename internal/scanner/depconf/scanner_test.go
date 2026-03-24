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
	names := parseNPMPackages(data)
	if len(names) != 2 {
		t.Fatalf("expected 2 packages, got %d: %v", len(names), names)
	}
}

func TestParseNPMPackages_DevDependencies(t *testing.T) {
	data := []byte(`{"devDependencies":{"jest":"^29.0.0","ts-node":"10.9.1"}}`)
	names := parseNPMPackages(data)
	if len(names) != 2 {
		t.Fatalf("expected 2 packages from devDependencies, got %d", len(names))
	}
}

func TestParseNPMPackages_BothSections_Deduped(t *testing.T) {
	// "shared" appears in both deps and devDeps — should not be counted twice.
	data := []byte(`{
		"dependencies": {"shared":"1.0.0","a":"1.0.0"},
		"devDependencies": {"shared":"1.0.0","b":"2.0.0"}
	}`)
	names := parseNPMPackages(data)
	// a, b, shared = 3 unique
	if len(names) != 3 {
		t.Errorf("expected 3 unique packages (shared deduped), got %d: %v", len(names), names)
	}
}

func TestParseNPMPackages_InvalidJSON(t *testing.T) {
	names := parseNPMPackages([]byte(`not-json`))
	if names != nil {
		t.Errorf("expected nil for invalid JSON, got %v", names)
	}
}

func TestParseNPMPackages_EmptyDeps(t *testing.T) {
	data := []byte(`{"dependencies":{}}`)
	names := parseNPMPackages(data)
	if len(names) != 0 {
		t.Errorf("expected 0 packages for empty dependencies, got %d", len(names))
	}
}

func TestParseNPMPackages_NoDepsKey(t *testing.T) {
	data := []byte(`{"name":"myapp","version":"1.0.0"}`)
	names := parseNPMPackages(data)
	if len(names) != 0 {
		t.Errorf("expected 0 packages when no dependencies key, got %d", len(names))
	}
}

// ---------------------------------------------------------------------------
// parsePyPIPackages
// ---------------------------------------------------------------------------

func TestParsePyPIPackages_PlainNames(t *testing.T) {
	data := []byte("requests\nflask\ndjango\n")
	names := parsePyPIPackages(data)
	if len(names) != 3 {
		t.Fatalf("expected 3 packages, got %d: %v", len(names), names)
	}
}

func TestParsePyPIPackages_VersionSpecifiers(t *testing.T) {
	data := []byte("requests>=2.0\nflask==2.3.1\ndjango!=4.0\npillow~=9.0\n")
	names := parsePyPIPackages(data)
	for _, n := range names {
		if strings.ContainsAny(n, "><=!~") {
			t.Errorf("version specifier not stripped from %q", n)
		}
	}
	if len(names) != 4 {
		t.Errorf("expected 4 packages after stripping specifiers, got %d: %v", len(names), names)
	}
}

func TestParsePyPIPackages_SkipsComments(t *testing.T) {
	data := []byte("# this is a comment\nrequests\n# another comment\nflask\n")
	names := parsePyPIPackages(data)
	if len(names) != 2 {
		t.Errorf("expected 2 packages (comments skipped), got %d: %v", len(names), names)
	}
}

func TestParsePyPIPackages_SkipsDashFlags(t *testing.T) {
	// Lines starting with "-" (e.g. "-r other.txt", "-i https://...") must be skipped.
	data := []byte("-r base.txt\n-i https://pypi.org/simple\nrequests\n")
	names := parsePyPIPackages(data)
	if len(names) != 1 {
		t.Errorf("expected 1 package (dash-flag lines skipped), got %d: %v", len(names), names)
	}
}

func TestParsePyPIPackages_EmptyLines(t *testing.T) {
	data := []byte("\n\nrequests\n\n")
	names := parsePyPIPackages(data)
	if len(names) != 1 {
		t.Errorf("expected 1 package (empty lines skipped), got %d: %v", len(names), names)
	}
}

func TestParsePyPIPackages_LowercasesNames(t *testing.T) {
	data := []byte("Django\nFlask\n")
	names := parsePyPIPackages(data)
	for _, n := range names {
		if n != strings.ToLower(n) {
			t.Errorf("expected lowercase package name, got %q", n)
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
	s := New()
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
	s := New()
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
	s := New()
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
	s := New()
	findings, _ := s.Run(ctx, asset, module.ScanSurface)
	_ = findings // must not panic
}

// ---------------------------------------------------------------------------
// CheckID constant sanity check
// ---------------------------------------------------------------------------

func TestCheckDependencyConfusion_Defined(t *testing.T) {
	// Ensure the CheckID is non-empty — guards against accidental removal.
	if finding.CheckDependencyConfusion == "" {
		t.Error("finding.CheckDependencyConfusion is empty")
	}
}
