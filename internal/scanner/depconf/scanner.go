// Package depconf detects dependency confusion and known vulnerable dependencies.
//
// Dependency confusion (also called namespace confusion) occurs when an
// attacker registers a public package with the same name as an internal
// private package. Package managers that check public registries before
// private ones (default behaviour for npm, pip, RubyGems) will pull the
// attacker-controlled public version instead of the legitimate internal one.
//
// This scanner also queries the OSV.dev database to check if any dependency
// with a pinned version has known vulnerabilities.
//
// This scanner:
//  1. Fetches well-known manifest files from the target (package.json,
//     requirements.txt, Gemfile, go.mod, composer.json).
//  2. Extracts dependency names and version constraints.
//  3. Checks whether each internal-looking name exists on the public registry.
//  4. Queries OSV for known vulnerabilities in pinned dependencies.
//
// Surface mode only — all checks are passive HTTP GETs.
package depconf

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/scan"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/osv"
)


func init() {
	scan.Register(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	})
}
const scannerName = "depconf"

// Scanner probes for dependency confusion and vulnerable dependency issues.
type Scanner struct {
	// osvClient is the OSV client for vulnerability lookups.
	// If nil, OSV checking is skipped.
	osvClient *osv.Client
}

// New creates a Scanner with OSV checking enabled.
func New() *Scanner { return &Scanner{osvClient: osv.New()} }

// NewWithoutOSV creates a Scanner with OSV checking disabled (for testing).
func NewWithoutOSV() *Scanner { return &Scanner{} }

// NewWithOSV creates a Scanner with a custom OSV client (for testing).
func NewWithOSV(client *osv.Client) *Scanner { return &Scanner{osvClient: client} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, _ module.ScanType) ([]finding.Finding, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	domainBase := baseName(asset)

	var allPackages []packageRef

	for _, scheme := range []string{"https", "http"} {
		base := scheme + "://" + asset

		// package.json — npm/Node
		if data := fetchManifest(ctx, client, base, "/package.json"); data != nil {
			for _, dep := range parseNPMPackages(data) {
				allPackages = append(allPackages, packageRef{name: dep.name, version: dep.version, ecosystem: "npm", manifest: "/package.json"})
			}
		}

		// requirements.txt — Python/PyPI
		if data := fetchManifest(ctx, client, base, "/requirements.txt"); data != nil {
			for _, dep := range parsePyPIPackages(data) {
				allPackages = append(allPackages, packageRef{name: dep.name, version: dep.version, ecosystem: "pypi", manifest: "/requirements.txt"})
			}
		}

		// go.mod — Go modules
		if data := fetchManifest(ctx, client, base, "/go.mod"); data != nil {
			for _, dep := range parseGoModules(data) {
				allPackages = append(allPackages, packageRef{name: dep.name, version: dep.version, ecosystem: "go", manifest: "/go.mod"})
			}
		}

		// Gemfile — Ruby gems
		if data := fetchManifest(ctx, client, base, "/Gemfile"); data != nil {
			for _, dep := range parseGemfilePackages(data) {
				allPackages = append(allPackages, packageRef{name: dep.name, version: dep.version, ecosystem: "ruby", manifest: "/Gemfile"})
			}
		}

		// composer.json — PHP Composer
		if data := fetchManifest(ctx, client, base, "/composer.json"); data != nil {
			for _, dep := range parseComposerPackages(data) {
				allPackages = append(allPackages, packageRef{name: dep.name, version: dep.version, ecosystem: "composer", manifest: "/composer.json"})
			}
		}

		// Only try the first scheme that works.
		if len(allPackages) > 0 {
			break
		}
	}

	if len(allPackages) == 0 {
		return nil, nil
	}

	// Deduplicate and filter to internal-looking names.
	seen := make(map[string]struct{})
	var candidates []packageRef
	for _, p := range allPackages {
		key := p.ecosystem + ":" + p.name
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		if isInternalLooking(p.name, domainBase) {
			candidates = append(candidates, p)
		}
	}

	// Cap to avoid registry rate-limiting.
	const maxChecks = 20
	if len(candidates) > maxChecks {
		candidates = candidates[:maxChecks]
	}

	var findings []finding.Finding
	for _, p := range candidates {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		var exists bool
		switch p.ecosystem {
		case "npm":
			exists = checkNPM(ctx, client, p.name)
		case "pypi":
			exists = checkPyPI(ctx, client, p.name)
		case "go":
			exists = checkGoProxy(ctx, client, p.name)
		case "ruby":
			exists = checkRubyGems(ctx, client, p.name)
		case "composer":
			exists = checkPackagist(ctx, client, p.name)
		}

		if !exists {
			continue
		}

		var checkID finding.CheckID
		var proofCmd string
		switch p.ecosystem {
		case "npm":
			checkID = finding.CheckDependencyConfusion
			proofCmd = fmt.Sprintf("curl -s https://registry.npmjs.org/%s | jq '.name,.version,.description'", p.name)
		case "pypi":
			checkID = finding.CheckDependencyConfusion
			proofCmd = fmt.Sprintf("curl -s https://pypi.org/pypi/%s/json | jq '.info.name,.info.version,.info.author'", p.name)
		case "go":
			checkID = finding.CheckDependencyConfusionGo
			proofCmd = fmt.Sprintf("curl -sI https://proxy.golang.org/%s/@v/list", p.name)
		case "ruby":
			checkID = finding.CheckDependencyConfusionRuby
			proofCmd = fmt.Sprintf("curl -s https://rubygems.org/api/v1/gems/%s.json | jq '.name,.version,.authors'", p.name)
		case "composer":
			checkID = finding.CheckDependencyConfusionComposer
			proofCmd = fmt.Sprintf("curl -s https://packagist.org/packages/%s.json | jq '.package.name,.package.versions'", p.name)
		default:
			checkID = finding.CheckDependencyConfusion
			proofCmd = fmt.Sprintf("# verify %s exists on public %s registry", p.name, p.ecosystem)
		}

		findings = append(findings, finding.Finding{
			CheckID:  checkID,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityCritical,
			Asset:    asset,
			Title:    fmt.Sprintf("Dependency confusion: %q exists on public %s registry", p.name, p.ecosystem),
			Description: fmt.Sprintf(
				"The package %q appears in %s and is also registered on the public %s registry. "+
					"If this is an internal package name, an attacker may have registered it publicly "+
					"to intercept installs from build systems that check public registries before private ones. "+
					"Verify the public package is legitimate or namespace the internal package to prevent confusion.",
				p.name, p.manifest, p.ecosystem,
			),
			Evidence: map[string]any{
				"package":   p.name,
				"ecosystem": p.ecosystem,
				"manifest":  p.manifest,
			},
			ProofCommand: proofCmd,
			DiscoveredAt: time.Now(),
		})
	}

	// ── OSV vulnerability check ─────────────────────────────────────────
	// Query OSV for all packages with pinned versions (not just internal-looking).
	var osvQueries []osv.PackageQuery
	var osvPackages []packageRef // parallel index for mapping results back
	for _, p := range allPackages {
		ver := cleanVersion(p.version)
		if ver == "" {
			continue
		}
		osvQueries = append(osvQueries, osv.PackageQuery{
			Name:      p.name,
			Version:   ver,
			Ecosystem: p.ecosystem,
		})
		osvPackages = append(osvPackages, p)
	}

	if len(osvQueries) > 0 && s.osvClient != nil {
		results, err := s.osvClient.QueryBatch(ctx, osvQueries)
		if err == nil {
			for i, result := range results {
				if result.Error != "" || len(result.Vulnerabilities) == 0 {
					continue
				}
				p := osvPackages[i]
				for _, vuln := range result.Vulnerabilities {
					var sev finding.Severity
					switch vuln.Severity {
					case "critical":
						sev = finding.SeverityCritical
					case "medium":
						sev = finding.SeverityMedium
					case "low":
						sev = finding.SeverityLow
					default:
						sev = finding.SeverityHigh
					}

					cveIDs := vuln.CVEIDs()
					cveStr := vuln.ID
					if len(cveIDs) > 0 {
						cveStr = cveIDs[0]
					}

					evidence := map[string]any{
						"package":   p.name,
						"version":   cleanVersion(p.version),
						"ecosystem": p.ecosystem,
						"manifest":  p.manifest,
						"osv_id":    vuln.ID,
						"summary":   vuln.Summary,
					}
					if len(cveIDs) > 0 {
						evidence["cve_id"] = cveIDs[0]
					}
					if vuln.FixedVersion != "" {
						evidence["fixed_version"] = vuln.FixedVersion
					}

					findings = append(findings, finding.Finding{
						CheckID:  finding.CheckVulnerableDependency,
						Module:   "surface",
						Scanner:  scannerName,
						Severity: sev,
						Asset:    asset,
						Title:    fmt.Sprintf("Vulnerable dependency: %s@%s (%s)", p.name, cleanVersion(p.version), cveStr),
						Description: fmt.Sprintf(
							"The dependency %s version %s (from %s) has a known vulnerability: %s. %s",
							p.name, cleanVersion(p.version), p.manifest, cveStr, vuln.Summary,
						),
						Evidence:     evidence,
						ProofCommand: fmt.Sprintf("curl -s -X POST https://api.osv.dev/v1/query -d '{\"package\":{\"name\":\"%s\",\"ecosystem\":\"%s\"},\"version\":\"%s\"}' | jq .", p.name, osv.EcosystemName(p.ecosystem), cleanVersion(p.version)),
						DiscoveredAt: time.Now(),
					})
				}
			}
		}
	}

	return findings, nil
}

// cleanVersion extracts a usable version string from a constraint.
// "^4.17.1" → "4.17.1", "~> 1.2.3" → "1.2.3", "==3.0.0" → "3.0.0", "" → "".
func cleanVersion(v string) string {
	v = strings.TrimSpace(v)
	// Strip common constraint prefixes.
	for _, prefix := range []string{"^", "~", ">=", "<=", "==", "!=", "~>", "=", ">", "<"} {
		v = strings.TrimPrefix(v, prefix)
	}
	v = strings.TrimSpace(v)
	// Strip anything after a space or comma (range specifiers like ">= 1.0, < 2.0").
	if idx := strings.IndexAny(v, " ,"); idx > 0 {
		v = v[:idx]
	}
	// Must look like a version (starts with digit).
	if v == "" || v == "*" || v == "latest" {
		return ""
	}
	if v[0] < '0' || v[0] > '9' {
		return ""
	}
	return v
}

// packageRef is a dependency name + version + its ecosystem.
type packageRef struct {
	name      string
	version   string // semver constraint or pinned version (e.g., "^4.17.1", "4.17.1")
	ecosystem string
	manifest  string
}

// fetchManifest fetches a manifest file path from the given base URL.
// Returns nil if the file is absent or the request fails.
func fetchManifest(ctx context.Context, client *http.Client, baseURL, path string) []byte {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+path, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return nil
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil {
		return nil
	}
	return data
}

// depVersion is a package name + version constraint pair.
type depVersion struct {
	name    string
	version string
}

// parseNPMPackages extracts dependency names and version constraints from a package.json.
func parseNPMPackages(data []byte) []depVersion {
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}
	seen := make(map[string]struct{})
	var deps []depVersion
	for name, ver := range pkg.Dependencies {
		if _, ok := seen[name]; !ok {
			seen[name] = struct{}{}
			deps = append(deps, depVersion{name: name, version: ver})
		}
	}
	for name, ver := range pkg.DevDependencies {
		if _, ok := seen[name]; !ok {
			seen[name] = struct{}{}
			deps = append(deps, depVersion{name: name, version: ver})
		}
	}
	return deps
}

// validPackageName returns true when s looks like a valid PyPI package name.
// PEP 508 names are alphanumeric plus hyphens, underscores, and dots.
// Any space, quote, shell metacharacter, or bracket disqualifies the string.
func validPackageName(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') &&
			(c < '0' || c > '9') && c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	return true
}

// parsePyPIPackages extracts package names and version constraints from a requirements.txt.
func parsePyPIPackages(data []byte) []depVersion {
	var deps []depVersion
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		if idx := strings.Index(line, " #"); idx > 0 {
			line = strings.TrimSpace(line[:idx])
		}
		// Extract version constraint before stripping it.
		name := line
		version := ""
		for _, sep := range []string{">=", "<=", "==", "!=", "~=", ">", "<"} {
			if idx := strings.Index(name, sep); idx > 0 {
				version = strings.TrimSpace(name[idx:])
				name = strings.TrimSpace(name[:idx])
				break
			}
		}
		// Strip environment markers.
		if idx := strings.Index(name, ";"); idx > 0 {
			name = strings.TrimSpace(name[:idx])
		}
		if !validPackageName(name) {
			continue
		}
		// For ==pinned versions, extract the exact version for OSV lookup.
		cleanVersion := ""
		if strings.HasPrefix(version, "==") {
			cleanVersion = strings.TrimSpace(version[2:])
		}
		deps = append(deps, depVersion{name: strings.ToLower(name), version: cleanVersion})
	}
	return deps
}

// isInternalLooking returns true when a package name looks like it could be
// an internal/private package rather than a well-known public one.
func isInternalLooking(name, domainBase string) bool {
	lower := strings.ToLower(name)
	base := strings.ToLower(domainBase)

	// Scoped npm package matching the org (@acme/something)
	if strings.HasPrefix(lower, "@"+base+"/") {
		return true
	}
	// Name contains the domain base (e.g. "acme-utils", "acme_internal")
	if base != "" && strings.Contains(lower, base) {
		return true
	}
	// Name contains common internal keywords
	for _, kw := range []string{"internal", "private", "local", "corp", "core-lib", "shared-lib"} {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// checkNPM returns true if the package exists on the public npm registry.
func checkNPM(ctx context.Context, client *http.Client, name string) bool {
	url := "https://registry.npmjs.org/" + name
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// checkPyPI returns true if the package exists on PyPI.
func checkPyPI(ctx context.Context, client *http.Client, name string) bool {
	url := "https://pypi.org/pypi/" + name + "/json"
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// knownGoHosts are well-known public module hosts; modules under these prefixes
// are unlikely to be internal and are skipped during dependency confusion checks.
var knownGoHosts = []string{
	"github.com/", "gitlab.com/", "bitbucket.org/",
	"golang.org/", "google.golang.org/", "go.uber.org/",
	"gopkg.in/", "k8s.io/", "sigs.k8s.io/",
	"cloud.google.com/", "go.opentelemetry.io/",
	"go.etcd.io/", "gonum.org/",
}

// parseGoModules extracts module paths and versions from a go.mod file.
// Only require directives whose module path does not start with a known public
// host are returned — these are candidates for dependency confusion.
// All modules (including public) are stored in goModAllDeps for OSV checking.
func parseGoModules(data []byte) []depVersion {
	var deps []depVersion
	inRequire := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.HasPrefix(line, "require (") || line == "require (" {
			inRequire = true
			continue
		}
		if inRequire && line == ")" {
			inRequire = false
			continue
		}
		var modulePath, moduleVersion string
		if inRequire {
			parts := strings.Fields(line)
			if len(parts) >= 1 {
				modulePath = parts[0]
			}
			if len(parts) >= 2 {
				moduleVersion = strings.TrimPrefix(parts[1], "v")
			}
		} else if strings.HasPrefix(line, "require ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				modulePath = parts[1]
			}
			if len(parts) >= 3 {
				moduleVersion = strings.TrimPrefix(parts[2], "v")
			}
		}
		if modulePath == "" {
			continue
		}
		isPublic := false
		for _, host := range knownGoHosts {
			if strings.HasPrefix(modulePath, host) {
				isPublic = true
				break
			}
		}
		if !isPublic {
			deps = append(deps, depVersion{name: modulePath, version: moduleVersion})
		}
	}
	return deps
}

// gemVersionRe matches gem declarations with optional version: gem 'name', '~> 1.2'
var gemVersionRe = regexp.MustCompile(`(?m)^\s*gem\s+['"]([a-zA-Z0-9._-]+)['"]\s*(?:,\s*['"]([^'"]*)['"]\s*)?`)

// parseGemfilePackages extracts gem names and version constraints from a Gemfile.
func parseGemfilePackages(data []byte) []depVersion {
	matches := gemVersionRe.FindAllStringSubmatch(string(data), -1)
	var deps []depVersion
	for _, m := range matches {
		if len(m) >= 2 && m[1] != "" {
			ver := ""
			if len(m) >= 3 {
				ver = m[2]
			}
			deps = append(deps, depVersion{name: m[1], version: cleanGemVersion(ver)})
		}
	}
	return deps
}

// cleanGemVersion extracts the version number from a gem constraint like "~> 1.2" or "= 3.0.1".
func cleanGemVersion(constraint string) string {
	constraint = strings.TrimSpace(constraint)
	for _, prefix := range []string{"~>", ">=", "<=", "!=", "=", ">", "<"} {
		if strings.HasPrefix(constraint, prefix) {
			return strings.TrimSpace(constraint[len(prefix):])
		}
	}
	return constraint
}

// parseComposerPackages extracts package names and version constraints from a composer.json.
func parseComposerPackages(data []byte) []depVersion {
	var pkg struct {
		Require    map[string]string `json:"require"`
		RequireDev map[string]string `json:"require-dev"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}
	seen := make(map[string]struct{})
	var deps []depVersion
	for name, ver := range pkg.Require {
		if name == "php" || strings.HasPrefix(name, "ext-") {
			continue
		}
		if _, ok := seen[name]; !ok {
			seen[name] = struct{}{}
			deps = append(deps, depVersion{name: name, version: ver})
		}
	}
	for name, ver := range pkg.RequireDev {
		if name == "php" || strings.HasPrefix(name, "ext-") {
			continue
		}
		if _, ok := seen[name]; !ok {
			seen[name] = struct{}{}
			deps = append(deps, depVersion{name: name, version: ver})
		}
	}
	return deps
}

// checkGoProxy returns true if the Go module exists on the public Go module proxy.
func checkGoProxy(ctx context.Context, client *http.Client, modulePath string) bool {
	u := "https://proxy.golang.org/" + modulePath + "/@v/list"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// checkRubyGems returns true if the gem exists on rubygems.org.
func checkRubyGems(ctx context.Context, client *http.Client, name string) bool {
	u := "https://rubygems.org/api/v1/gems/" + name + ".json"
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// checkPackagist returns true if the Composer package exists on packagist.org.
func checkPackagist(ctx context.Context, client *http.Client, name string) bool {
	u := "https://packagist.org/packages/" + name + ".json"
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// baseName returns the first label of a domain, e.g. "acme" from "app.acme.com".
func baseName(asset string) string {
	// Strip to root domain first
	parts := strings.Split(asset, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2]
	}
	return parts[0]
}
