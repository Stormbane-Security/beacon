// Package depconf detects dependency confusion vulnerabilities.
//
// Dependency confusion (also called namespace confusion) occurs when an
// attacker registers a public package with the same name as an internal
// private package. Package managers that check public registries before
// private ones (default behaviour for npm, pip, RubyGems) will pull the
// attacker-controlled public version instead of the legitimate internal one.
//
// This scanner:
//  1. Fetches well-known manifest files from the target (package.json,
//     requirements.txt, Gemfile, go.mod, composer.json).
//  2. Extracts dependency names from each manifest.
//  3. Checks whether each internal-looking name exists on the public registry
//     (npm, PyPI). A public hit on an internal name = dependency confusion risk.
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

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const scannerName = "depconf"

// Scanner probes for dependency confusion vulnerabilities.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, _ module.ScanType) ([]finding.Finding, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	domainBase := baseName(asset)

	var allPackages []packageRef

	for _, scheme := range []string{"https", "http"} {
		base := scheme + "://" + asset

		// package.json — npm/Node
		if data := fetchManifest(ctx, client, base, "/package.json"); data != nil {
			for _, name := range parseNPMPackages(data) {
				allPackages = append(allPackages, packageRef{name: name, ecosystem: "npm", manifest: "/package.json"})
			}
		}

		// requirements.txt — Python/PyPI
		if data := fetchManifest(ctx, client, base, "/requirements.txt"); data != nil {
			for _, name := range parsePyPIPackages(data) {
				allPackages = append(allPackages, packageRef{name: name, ecosystem: "pypi", manifest: "/requirements.txt"})
			}
		}

		// go.mod — Go modules
		if data := fetchManifest(ctx, client, base, "/go.mod"); data != nil {
			for _, name := range parseGoModules(data) {
				allPackages = append(allPackages, packageRef{name: name, ecosystem: "go", manifest: "/go.mod"})
			}
		}

		// Gemfile — Ruby gems
		if data := fetchManifest(ctx, client, base, "/Gemfile"); data != nil {
			for _, name := range parseGemfilePackages(data) {
				allPackages = append(allPackages, packageRef{name: name, ecosystem: "ruby", manifest: "/Gemfile"})
			}
		}

		// composer.json — PHP Composer
		if data := fetchManifest(ctx, client, base, "/composer.json"); data != nil {
			for _, name := range parseComposerPackages(data) {
				allPackages = append(allPackages, packageRef{name: name, ecosystem: "composer", manifest: "/composer.json"})
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

	return findings, nil
}

// packageRef is a dependency name + its ecosystem.
type packageRef struct {
	name      string
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

// parseNPMPackages extracts dependency names from a package.json.
func parseNPMPackages(data []byte) []string {
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}
	seen := make(map[string]struct{})
	var names []string
	for name := range pkg.Dependencies {
		if _, ok := seen[name]; !ok {
			seen[name] = struct{}{}
			names = append(names, name)
		}
	}
	for name := range pkg.DevDependencies {
		if _, ok := seen[name]; !ok {
			seen[name] = struct{}{}
			names = append(names, name)
		}
	}
	return names
}

// validPackageName returns true when s looks like a valid PyPI package name.
// PEP 508 names are alphanumeric plus hyphens, underscores, and dots.
// Any space, quote, shell metacharacter, or bracket disqualifies the string.
func validPackageName(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// parsePyPIPackages extracts package names from a requirements.txt.
func parsePyPIPackages(data []byte) []string {
	var names []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		// Skip blank lines, comments, and pip option flags (e.g. --index-url).
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		// Strip inline comment: "requests  # HTTP library" → "requests"
		if idx := strings.Index(line, " #"); idx > 0 {
			line = strings.TrimSpace(line[:idx])
		}
		// Strip version specifiers: "requests>=2.0" → "requests"
		for _, sep := range []string{">=", "<=", "==", "!=", "~=", ">", "<", ";"} {
			if idx := strings.Index(line, sep); idx > 0 {
				line = strings.TrimSpace(line[:idx])
			}
		}
		// Validate: a real package name contains only [A-Za-z0-9._-].
		// Lines like `echo "# add nexus cli to path"` contain spaces/quotes
		// and must be rejected — they are shell commands, not package names.
		if !validPackageName(line) {
			continue
		}
		names = append(names, strings.ToLower(line))
	}
	return names
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

// parseGoModules extracts private-looking module paths from a go.mod file.
// Only require directives whose module path does not start with a known public
// host are returned — these are candidates for dependency confusion.
func parseGoModules(data []byte) []string {
	var names []string
	inRequire := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		// Block require ( ... )
		if strings.HasPrefix(line, "require (") || line == "require (" {
			inRequire = true
			continue
		}
		if inRequire && line == ")" {
			inRequire = false
			continue
		}
		// Single-line require directive
		var modulePath string
		if inRequire {
			parts := strings.Fields(line)
			if len(parts) >= 1 {
				modulePath = parts[0]
			}
		} else if strings.HasPrefix(line, "require ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				modulePath = parts[1]
			}
		}
		if modulePath == "" {
			continue
		}
		// Skip well-known public hosts.
		isPublic := false
		for _, host := range knownGoHosts {
			if strings.HasPrefix(modulePath, host) {
				isPublic = true
				break
			}
		}
		if !isPublic {
			names = append(names, modulePath)
		}
	}
	return names
}

// gemRe matches gem declarations in a Gemfile: gem 'name' or gem "name"
var gemRe = regexp.MustCompile(`(?m)^\s*gem\s+['"]([a-zA-Z0-9._-]+)['"]`)

// parseGemfilePackages extracts gem names from a Gemfile.
func parseGemfilePackages(data []byte) []string {
	matches := gemRe.FindAllStringSubmatch(string(data), -1)
	var names []string
	for _, m := range matches {
		if len(m) >= 2 && m[1] != "" {
			names = append(names, m[1])
		}
	}
	return names
}

// parseComposerPackages extracts package names from a composer.json require block.
func parseComposerPackages(data []byte) []string {
	var pkg struct {
		Require    map[string]string `json:"require"`
		RequireDev map[string]string `json:"require-dev"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}
	seen := make(map[string]struct{})
	var names []string
	for name := range pkg.Require {
		// Skip PHP platform requirements (php, ext-*)
		if name == "php" || strings.HasPrefix(name, "ext-") {
			continue
		}
		if _, ok := seen[name]; !ok {
			seen[name] = struct{}{}
			names = append(names, name)
		}
	}
	for name := range pkg.RequireDev {
		if name == "php" || strings.HasPrefix(name, "ext-") {
			continue
		}
		if _, ok := seen[name]; !ok {
			seen[name] = struct{}{}
			names = append(names, name)
		}
	}
	return names
}

// checkGoProxy returns true if the Go module exists on the public Go module proxy.
// A 404 from proxy.golang.org means the module name is claimable.
// We return true (exists = claimable) when the proxy returns 404.
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
	// 404 means the module does not exist on the public proxy — claimable.
	return resp.StatusCode == http.StatusNotFound
}

// checkRubyGems returns true if the gem name is claimable on rubygems.org.
// A 404 means the gem does not exist and could be registered by an attacker.
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
	// 404 means the gem does not exist — claimable.
	return resp.StatusCode == http.StatusNotFound
}

// checkPackagist returns true if the Composer package is claimable on packagist.org.
// A 404 means the package does not exist and could be registered by an attacker.
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
	// 404 means the package does not exist — claimable.
	return resp.StatusCode == http.StatusNotFound
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
