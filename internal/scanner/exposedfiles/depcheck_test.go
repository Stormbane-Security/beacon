package exposedfiles

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)

// ---------- isDependencyFile ----------

func TestIsDependencyFile(t *testing.T) {
	yes := []string{"/package.json", "/composer.json", "/requirements.txt", "/go.sum", "/Gemfile", "/Gemfile.lock"}
	no := []string{"/.env", "/config.json", "/dump.sql", "/model.onnx"}
	for _, p := range yes {
		if !isDependencyFile(p) {
			t.Errorf("isDependencyFile(%q) = false, want true", p)
		}
	}
	for _, p := range no {
		if isDependencyFile(p) {
			t.Errorf("isDependencyFile(%q) = true, want false", p)
		}
	}
}

// ---------- package.json parser ----------

func TestParsePackageJSON_VulnerableLodash(t *testing.T) {
	body := []byte(`{
		"name": "test-app",
		"dependencies": {
			"lodash": "^4.17.15",
			"express": "^4.18.0"
		},
		"devDependencies": {
			"jest": "^29.0.0"
		}
	}`)
	deps := parsePackageJSON(body)
	if len(deps) != 3 {
		t.Fatalf("expected 3 deps, got %d", len(deps))
	}
	found := false
	for _, d := range deps {
		if d.name == "lodash" {
			found = true
			if d.version != "4.17.15" {
				t.Errorf("lodash version = %q, want 4.17.15", d.version)
			}
		}
	}
	if !found {
		t.Error("lodash not found in parsed deps")
	}
}

func TestParsePackageJSON_InvalidJSON(t *testing.T) {
	deps := parsePackageJSON([]byte("not json at all"))
	if deps != nil {
		t.Errorf("expected nil for invalid JSON, got %v", deps)
	}
}

// ---------- composer.json parser ----------

func TestParseComposerJSON(t *testing.T) {
	body := []byte(`{
		"require": {
			"guzzlehttp/guzzle": "^7.2.0",
			"php": ">=8.0"
		},
		"require-dev": {
			"phpunit/phpunit": "^9.0"
		}
	}`)
	deps := parseComposerJSON(body)
	if len(deps) != 3 {
		t.Fatalf("expected 3 deps, got %d", len(deps))
	}
	found := false
	for _, d := range deps {
		if d.name == "guzzlehttp/guzzle" {
			found = true
			if d.version != "7.2.0" {
				t.Errorf("guzzle version = %q, want 7.2.0", d.version)
			}
		}
	}
	if !found {
		t.Error("guzzlehttp/guzzle not found in parsed deps")
	}
}

// ---------- requirements.txt parser ----------

func TestParseRequirementsTxt(t *testing.T) {
	body := []byte(`# Python dependencies
django==3.2.10
flask==2.1.0
requests==2.28.0
# comment line
gunicorn>=20.1.0
`)
	deps := parseRequirementsTxt(body)
	// Only == pinned versions are parsed (not >= constraints).
	if len(deps) != 3 {
		t.Fatalf("expected 3 deps, got %d: %+v", len(deps), deps)
	}
	for _, d := range deps {
		switch d.name {
		case "django":
			if d.version != "3.2.10" {
				t.Errorf("django version = %q", d.version)
			}
		case "flask":
			if d.version != "2.1.0" {
				t.Errorf("flask version = %q", d.version)
			}
		case "requests":
			if d.version != "2.28.0" {
				t.Errorf("requests version = %q", d.version)
			}
		}
	}
}

// ---------- go.sum parser ----------

func TestParseGoSum(t *testing.T) {
	body := []byte(`golang.org/x/crypto v0.14.0 h1:abc123=
golang.org/x/crypto v0.14.0/go.mod h1:def456=
golang.org/x/net v0.16.0 h1:ghi789=
golang.org/x/net v0.16.0/go.mod h1:jkl012=
`)
	deps := parseGoSum(body)
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps (deduplicated), got %d: %+v", len(deps), deps)
	}
}

// ---------- Gemfile.lock parser ----------

func TestParseGemfileLock(t *testing.T) {
	body := []byte(`GEM
  remote: https://rubygems.org/
  specs:
    rack (2.2.3)
    puma (5.6.2)
    nokogiri (1.13.0)

PLATFORMS
  ruby

DEPENDENCIES
  rack
  puma
`)
	deps := parseGemfileLock(body)
	if len(deps) != 3 {
		t.Fatalf("expected 3 deps, got %d: %+v", len(deps), deps)
	}
	for _, d := range deps {
		switch d.name {
		case "rack":
			if d.version != "2.2.3" {
				t.Errorf("rack version = %q", d.version)
			}
		case "puma":
			if d.version != "5.6.2" {
				t.Errorf("puma version = %q", d.version)
			}
		}
	}
}

// ---------- version comparison ----------

func TestVersionLessThan(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"4.17.15", "4.17.21", true},
		{"4.17.21", "4.17.21", false},
		{"4.18.0", "4.17.21", false},
		{"2.16.0", "2.17.0", true},
		{"0.20.0", "0.21.1", true},
		{"1.0.0", "2.0.0", true},
		{"3.2.10", "3.2.13", true},
		{"3.2.13", "3.2.13", false},
		{"3.3.0", "3.2.13", false},
	}
	for _, tt := range tests {
		a := parseVersion(tt.a)
		b := parseVersion(tt.b)
		if a == nil || b == nil {
			t.Fatalf("parseVersion failed for %q or %q", tt.a, tt.b)
		}
		got := versionLessThan(a, b)
		if got != tt.want {
			t.Errorf("versionLessThan(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestCleanVersionConstraint(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"^4.17.15", "4.17.15"},
		{"~2.1.0", "2.1.0"},
		{">=3.0.0", "3.0.0"},
		{"v1.2.3", "1.2.3"},
		{"1.2.3", "1.2.3"},
		{"<=5.0.0", "5.0.0"},
	}
	for _, tt := range tests {
		got := cleanVersionConstraint(tt.in)
		if got != tt.want {
			t.Errorf("cleanVersionConstraint(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestParseVersion_PreRelease(t *testing.T) {
	v := parseVersion("2.17.0-rc1")
	if v == nil {
		t.Fatal("parseVersion returned nil")
	}
	if v.major != 2 || v.minor != 17 || v.patch != 0 {
		t.Errorf("got %+v, want {2,17,0}", v)
	}
}

func TestParseVersion_Invalid(t *testing.T) {
	for _, s := range []string{"", "abc", "1"} {
		if v := parseVersion(s); v != nil {
			t.Errorf("parseVersion(%q) = %+v, want nil", s, v)
		}
	}
}

// ---------- analyzeDependencies integration ----------

func TestAnalyzeDependencies_PackageJSON(t *testing.T) {
	body := []byte(`{
		"dependencies": {
			"lodash": "4.17.15",
			"express": "4.18.0"
		}
	}`)
	findings := analyzeDependencies("example.com", "/package.json", body)

	// lodash 4.17.15 < 4.17.21 should be flagged
	// express 4.18.0 >= 4.17.3 should NOT be flagged
	foundLodash := false
	for _, f := range findings {
		if strings.Contains(f.Title, "lodash") {
			foundLodash = true
			if f.CheckID != finding.CheckExposureVulnDependency {
				t.Errorf("check ID = %q, want %q", f.CheckID, finding.CheckExposureVulnDependency)
			}
			if f.Confidence != finding.ConfidenceProbable {
				t.Errorf("confidence = %q, want %q", f.Confidence, finding.ConfidenceProbable)
			}
			if f.Severity != finding.SeverityHigh {
				t.Errorf("severity = %q, want %q", f.Severity, finding.SeverityHigh)
			}
			ev := f.Evidence
			if ev["cve"] != "CVE-2021-23337" {
				t.Errorf("CVE = %v, want CVE-2021-23337", ev["cve"])
			}
		}
		if strings.Contains(f.Title, "express") {
			t.Error("express 4.18.0 should NOT be flagged (above safe version)")
		}
	}
	if !foundLodash {
		t.Error("expected finding for vulnerable lodash")
	}
}

func TestAnalyzeDependencies_RequirementsTxt(t *testing.T) {
	body := []byte(`django==3.2.10
flask==2.2.5
requests==2.28.0
`)
	findings := analyzeDependencies("example.com", "/requirements.txt", body)

	// django 3.2.10 < 3.2.13 -> flagged
	// flask 2.2.5 >= 2.2.5 -> NOT flagged
	// requests 2.28.0 < 2.31.0 -> flagged
	foundDjango := false
	foundRequests := false
	for _, f := range findings {
		if strings.Contains(f.Title, "django") || strings.Contains(f.Title, "Django") {
			foundDjango = true
		}
		if strings.Contains(f.Title, "requests") {
			foundRequests = true
		}
		if strings.Contains(f.Title, "flask") || strings.Contains(f.Title, "Flask") {
			t.Error("flask 2.2.5 should NOT be flagged")
		}
	}
	if !foundDjango {
		t.Error("expected finding for vulnerable django")
	}
	if !foundRequests {
		t.Error("expected finding for vulnerable requests")
	}
}

func TestAnalyzeDependencies_GoSum(t *testing.T) {
	body := []byte(`golang.org/x/crypto v0.14.0 h1:abc=
golang.org/x/crypto v0.14.0/go.mod h1:def=
golang.org/x/net v0.17.0 h1:ghi=
golang.org/x/net v0.17.0/go.mod h1:jkl=
`)
	findings := analyzeDependencies("example.com", "/go.sum", body)

	// golang.org/x/crypto 0.14.0 < 0.17.0 -> flagged
	// golang.org/x/net 0.17.0 >= 0.17.0 -> NOT flagged
	foundCrypto := false
	for _, f := range findings {
		if strings.Contains(f.Title, "golang.org/x/crypto") {
			foundCrypto = true
		}
		if strings.Contains(f.Title, "golang.org/x/net") {
			t.Error("golang.org/x/net 0.17.0 should NOT be flagged")
		}
	}
	if !foundCrypto {
		t.Error("expected finding for vulnerable golang.org/x/crypto")
	}
}

func TestAnalyzeDependencies_GemfileLock(t *testing.T) {
	body := []byte(`GEM
  specs:
    rack (2.2.3)
    puma (5.6.2)
    nokogiri (1.14.0)
`)
	findings := analyzeDependencies("example.com", "/Gemfile.lock", body)

	// rack 2.2.3 < 2.2.6.2 -> flagged
	// puma 5.6.2 < 5.6.7 -> flagged
	// nokogiri 1.14.0 >= 1.13.10 -> NOT flagged
	foundRack := false
	foundPuma := false
	for _, f := range findings {
		if strings.Contains(f.Title, "rack") {
			foundRack = true
		}
		if strings.Contains(f.Title, "puma") {
			foundPuma = true
		}
		if strings.Contains(f.Title, "nokogiri") {
			t.Error("nokogiri 1.14.0 should NOT be flagged")
		}
	}
	if !foundRack {
		t.Error("expected finding for vulnerable rack")
	}
	if !foundPuma {
		t.Error("expected finding for vulnerable puma")
	}
}

func TestAnalyzeDependencies_ComposerJSON(t *testing.T) {
	body := []byte(`{
		"require": {
			"guzzlehttp/guzzle": "^7.2.0",
			"php": ">=8.0"
		}
	}`)
	findings := analyzeDependencies("example.com", "/composer.json", body)

	// guzzle 7.2.0 < 7.4.5 -> flagged
	foundGuzzle := false
	for _, f := range findings {
		if strings.Contains(f.Title, "guzzle") {
			foundGuzzle = true
		}
	}
	if !foundGuzzle {
		t.Error("expected finding for vulnerable guzzlehttp/guzzle")
	}
}

func TestAnalyzeDependencies_NoVulns(t *testing.T) {
	body := []byte(`{
		"dependencies": {
			"lodash": "4.17.21",
			"express": "4.18.0"
		}
	}`)
	findings := analyzeDependencies("example.com", "/package.json", body)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for safe versions, got %d", len(findings))
	}
}

func TestAnalyzeDependencies_EmptyBody(t *testing.T) {
	findings := analyzeDependencies("example.com", "/package.json", []byte{})
	if findings != nil {
		t.Errorf("expected nil for empty body, got %v", findings)
	}
}

// ---------- Full scanner integration ----------

func TestExposedFiles_PackageJSON_VulnDeps(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/package.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintln(w, `{
				"name": "test-app",
				"dependencies": {
					"lodash": "4.17.15",
					"axios": "0.19.0"
				}
			}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	results, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}

	// Should have: 1 sensitive_file finding + at least 2 vuln_dependency findings.
	var sensitiveCount, vulnCount int
	for _, f := range results {
		switch f.CheckID {
		case finding.CheckExposureSensitiveFile:
			sensitiveCount++
		case finding.CheckExposureVulnDependency:
			vulnCount++
		}
	}
	if sensitiveCount == 0 {
		t.Error("expected at least 1 sensitive_file finding for package.json")
	}
	if vulnCount < 2 {
		t.Errorf("expected at least 2 vulnerable_dependency findings, got %d", vulnCount)
	}
}

func TestExposedFiles_PackageJSON_NoVulns(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/package.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintln(w, `{
				"name": "safe-app",
				"dependencies": {
					"lodash": "4.17.21",
					"express": "4.19.0"
				}
			}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	results, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range results {
		if f.CheckID == finding.CheckExposureVulnDependency {
			t.Errorf("should not flag safe versions, but got: %s", f.Title)
		}
	}
}
