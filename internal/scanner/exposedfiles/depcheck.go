package exposedfiles

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/osv"
)

// depcheckOSVClient is the package-level OSV client for dependency checking.
// nil means create a new default client on first use.
var depcheckOSVClient *osv.Client

// SetDepcheckOSVClient overrides the OSV client used by analyzeDependencies (for testing).
func SetDepcheckOSVClient(c *osv.Client) {
	depcheckOSVClient = c
}

func getDepcheckOSVClient() *osv.Client {
	if depcheckOSVClient != nil {
		return depcheckOSVClient
	}
	return osv.New()
}

// isDependencyFile returns true for paths that are package-manager manifests
// whose contents can be parsed for vulnerable dependency versions.
func isDependencyFile(path string) bool {
	switch path {
	case "/package.json", "/composer.json", "/requirements.txt",
		"/go.sum", "/Gemfile", "/Gemfile.lock":
		return true
	}
	return false
}

// analyzeDependencies parses a dependency manifest and checks each dependency
// against a hardcoded list of known-vulnerable packages (offline fallback),
// then queries the OSV.dev database for comprehensive CVE coverage.
// Returns a finding for each match.
func analyzeDependencies(asset, path string, body []byte) []finding.Finding {
	return analyzeDependenciesWithContext(context.Background(), asset, path, body)
}

// analyzeDependenciesCtx is the context-aware version used by the scanner.
func analyzeDependenciesCtx(ctx context.Context, asset, path string, body []byte) []finding.Finding {
	return analyzeDependenciesWithContext(ctx, asset, path, body)
}

func analyzeDependenciesWithContext(ctx context.Context, asset, path string, body []byte) []finding.Finding {
	deps := parseDependencies(path, body)
	if len(deps) == 0 {
		return nil
	}

	// --- Phase 1: hardcoded offline fallback ---
	var findings []finding.Finding
	hardcodedHits := make(map[string]bool) // "name@version" already reported
	for _, d := range deps {
		for _, vuln := range knownVulnerablePackages {
			if !strings.EqualFold(d.name, vuln.Name) {
				continue
			}
			if d.version == "" {
				continue
			}
			installed := parseVersion(d.version)
			if installed == nil {
				continue
			}
			safe := parseVersion(vuln.SafeVersion)
			if safe == nil {
				continue
			}
			if versionLessThan(installed, safe) {
				hardcodedHits[strings.ToLower(d.name)+"@"+d.version] = true
				findings = append(findings, finding.Finding{
					CheckID:    finding.CheckExposureVulnDependency,
					Module:     "surface",
					Scanner:    scannerName,
					Severity:   finding.SeverityHigh,
					Confidence: finding.ConfidenceProbable,
					Title: fmt.Sprintf("Vulnerable dependency: %s %s (< %s)",
						d.name, d.version, vuln.SafeVersion),
					Description: fmt.Sprintf(
						"The exposed dependency manifest %s on %s declares %s at version %s. "+
							"This version is below the safe version %s and is affected by %s (%s). "+
							"An attacker who identifies the running software stack can target this "+
							"known vulnerability.",
						path, asset, d.name, d.version, vuln.SafeVersion,
						vuln.CVE, vuln.Summary),
					Asset: asset,
					Evidence: map[string]any{
						"manifest_path":    path,
						"package":          d.name,
						"installed_version": d.version,
						"safe_version":     vuln.SafeVersion,
						"cve":              vuln.CVE,
					},
					ProofCommand: fmt.Sprintf("curl -s 'https://%s%s' | grep -i '%s'",
						asset, path, d.name),
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	// --- Phase 2: OSV live query for comprehensive coverage ---
	ecosystem := ecosystemForManifest(path)
	if ecosystem == "" {
		return findings
	}

	var queries []osv.PackageQuery
	var queryDeps []dependency
	for _, d := range deps {
		if d.version == "" {
			continue
		}
		queries = append(queries, osv.PackageQuery{
			Name:      d.name,
			Version:   d.version,
			Ecosystem: ecosystem,
		})
		queryDeps = append(queryDeps, d)
	}

	if len(queries) == 0 {
		return findings
	}

	client := getDepcheckOSVClient()
	results, err := client.QueryBatch(ctx, queries)
	if err != nil {
		return findings // OSV unavailable; return hardcoded results only
	}

	seen := make(map[string]bool) // dedupe OSV findings by CVE/OSV ID
	// Also track CVEs already reported by hardcoded list.
	for _, f := range findings {
		if f.Evidence != nil {
			if cve, ok := f.Evidence["cve"].(string); ok {
				seen[cve] = true
			}
		}
	}

	now := time.Now()
	for i, result := range results {
		if result.Error != "" || len(result.Vulnerabilities) == 0 {
			continue
		}
		d := queryDeps[i]

		for _, vuln := range result.Vulnerabilities {
			dedup := vuln.ID
			if cves := vuln.CVEIDs(); len(cves) > 0 {
				dedup = cves[0]
			}
			if seen[dedup] {
				continue
			}
			seen[dedup] = true

			cveIDs := vuln.CVEIDs()
			cveStr := vuln.ID
			if len(cveIDs) > 0 {
				cveStr = strings.Join(cveIDs, ", ")
			}

			severity := finding.ParseSeverity(vuln.Severity)
			if severity == finding.SeverityInfo {
				severity = finding.SeverityHigh // version-matched CVE is at least high
			}

			fixNote := ""
			if vuln.FixedVersion != "" {
				fixNote = fmt.Sprintf(" Fixed in %s.", vuln.FixedVersion)
			}

			evidence := map[string]any{
				"manifest_path":    path,
				"package":          d.name,
				"installed_version": d.version,
				"osv_id":           vuln.ID,
				"cve_ids":          cveIDs,
				"severity":         vuln.Severity,
				"summary":          vuln.Summary,
				"source":           "osv",
			}
			if vuln.FixedVersion != "" {
				evidence["fixed_version"] = vuln.FixedVersion
			}

			findings = append(findings, finding.Finding{
				CheckID:    finding.CheckOSVCVEMatch,
				Module:     "surface",
				Scanner:    scannerName,
				Severity:   severity,
				Confidence: finding.ConfidenceProbable,
				Asset:      asset,
				Title: fmt.Sprintf("OSV: %s affects %s %s",
					cveStr, d.name, d.version),
				Description: fmt.Sprintf(
					"The OSV database reports %s (%s) affecting %s version %s "+
						"declared in the exposed manifest %s on %s.%s %s",
					cveStr, vuln.ID, d.name, d.version,
					path, asset, fixNote, vuln.Summary),
				Evidence: evidence,
				ProofCommand: fmt.Sprintf("curl -s 'https://%s%s' | grep -i '%s'",
					asset, path, d.name),
				DiscoveredAt: now,
			})
		}
	}

	return findings
}

// ecosystemForManifest returns the OSV ecosystem string for a given manifest path.
func ecosystemForManifest(path string) string {
	switch path {
	case "/package.json":
		return "npm"
	case "/composer.json":
		return "Packagist"
	case "/requirements.txt":
		return "PyPI"
	case "/go.sum":
		return "Go"
	case "/Gemfile", "/Gemfile.lock":
		return "RubyGems"
	}
	return ""
}

// dependency is a parsed (name, version) tuple from a manifest file.
type dependency struct {
	name    string
	version string
}

// parseDependencies dispatches to the correct parser based on the manifest path.
func parseDependencies(path string, body []byte) []dependency {
	switch path {
	case "/package.json":
		return parsePackageJSON(body)
	case "/composer.json":
		return parseComposerJSON(body)
	case "/requirements.txt":
		return parseRequirementsTxt(body)
	case "/go.sum":
		return parseGoSum(body)
	case "/Gemfile", "/Gemfile.lock":
		return parseGemfileLock(body)
	}
	return nil
}

// --- package.json parser ---

func parsePackageJSON(body []byte) []dependency {
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(body, &pkg); err != nil {
		return nil
	}
	var deps []dependency
	for name, ver := range pkg.Dependencies {
		deps = append(deps, dependency{name: name, version: cleanVersionConstraint(ver)})
	}
	for name, ver := range pkg.DevDependencies {
		deps = append(deps, dependency{name: name, version: cleanVersionConstraint(ver)})
	}
	return deps
}

// --- composer.json parser ---

func parseComposerJSON(body []byte) []dependency {
	var pkg struct {
		Require    map[string]string `json:"require"`
		RequireDev map[string]string `json:"require-dev"`
	}
	if err := json.Unmarshal(body, &pkg); err != nil {
		return nil
	}
	var deps []dependency
	for name, ver := range pkg.Require {
		deps = append(deps, dependency{name: name, version: cleanVersionConstraint(ver)})
	}
	for name, ver := range pkg.RequireDev {
		deps = append(deps, dependency{name: name, version: cleanVersionConstraint(ver)})
	}
	return deps
}

// --- requirements.txt parser ---

var reqLineRe = regexp.MustCompile(`^([a-zA-Z0-9_.-]+)\s*==\s*([0-9][0-9a-zA-Z._-]*)`)

func parseRequirementsTxt(body []byte) []dependency {
	var deps []dependency
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m := reqLineRe.FindStringSubmatch(line)
		if m != nil {
			deps = append(deps, dependency{name: m[1], version: m[2]})
		}
	}
	return deps
}

// --- go.sum parser ---

var goSumLineRe = regexp.MustCompile(`^([^\s]+)\s+v([0-9][0-9a-zA-Z._-]*)`)

func parseGoSum(body []byte) []dependency {
	seen := make(map[string]bool)
	var deps []dependency
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		m := goSumLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name := m[1]
		ver := strings.TrimSuffix(m[2], "/go.mod")
		key := name + "@" + ver
		if seen[key] {
			continue
		}
		seen[key] = true
		deps = append(deps, dependency{name: name, version: ver})
	}
	return deps
}

// --- Gemfile.lock parser ---

var gemLineRe = regexp.MustCompile(`^\s+([a-zA-Z0-9_-]+)\s+\(([0-9][0-9a-zA-Z._-]*)\)`)

func parseGemfileLock(body []byte) []dependency {
	var deps []dependency
	for _, line := range strings.Split(string(body), "\n") {
		m := gemLineRe.FindStringSubmatch(line)
		if m != nil {
			deps = append(deps, dependency{name: m[1], version: m[2]})
		}
	}
	return deps
}

// --- Version comparison ---

// semver holds a parsed major.minor.patch.extra version. Pre-release suffixes
// are stripped — we only compare numeric components for vulnerability matching.
// The extra field handles 4-part versions like Ruby's "2.2.6.2".
type semver struct {
	major, minor, patch, extra int
}

func parseVersion(s string) *semver {
	s = cleanVersionConstraint(s)
	// Strip pre-release / metadata suffixes (e.g., "2.17.0-rc1").
	if idx := strings.IndexAny(s, "-+"); idx != -1 {
		s = s[:idx]
	}
	parts := strings.SplitN(s, ".", 4)
	if len(parts) < 2 {
		return nil
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil
	}
	patch := 0
	if len(parts) >= 3 {
		patch, _ = strconv.Atoi(parts[2])
	}
	extra := 0
	if len(parts) == 4 {
		extra, _ = strconv.Atoi(parts[3])
	}
	return &semver{major, minor, patch, extra}
}

func versionLessThan(a, b *semver) bool {
	if a.major != b.major {
		return a.major < b.major
	}
	if a.minor != b.minor {
		return a.minor < b.minor
	}
	if a.patch != b.patch {
		return a.patch < b.patch
	}
	return a.extra < b.extra
}

// cleanVersionConstraint strips npm/composer/gem version constraint prefixes
// like ^, ~, >=, <=, =, and leading 'v' so "^4.17.20" becomes "4.17.20".
func cleanVersionConstraint(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimLeft(s, "^~><=!v")
	return s
}

// --- Known vulnerable packages database ---

type vulnPackage struct {
	Name        string // npm, PyPI, Go module, Composer, or Gem package name
	SafeVersion string // first safe version
	CVE         string
	Summary     string
}

var knownVulnerablePackages = []vulnPackage{
	// npm / Node.js
	{Name: "lodash", SafeVersion: "4.17.21", CVE: "CVE-2021-23337", Summary: "prototype pollution via template"},
	{Name: "axios", SafeVersion: "0.21.1", CVE: "CVE-2020-28168", Summary: "SSRF via proxy bypass"},
	{Name: "serialize-javascript", SafeVersion: "3.1.0", CVE: "CVE-2020-7660", Summary: "RCE via crafted object serialization"},
	{Name: "minimist", SafeVersion: "1.2.6", CVE: "CVE-2021-44906", Summary: "prototype pollution"},
	{Name: "express", SafeVersion: "4.17.3", CVE: "CVE-2022-24999", Summary: "open redirect via qs prototype pollution"},
	{Name: "node-fetch", SafeVersion: "2.6.7", CVE: "CVE-2022-0235", Summary: "credential leak via redirect to untrusted origin"},
	{Name: "glob-parent", SafeVersion: "5.1.2", CVE: "CVE-2020-28469", Summary: "ReDoS via crafted glob expression"},
	{Name: "jsonwebtoken", SafeVersion: "9.0.0", CVE: "CVE-2022-23529", Summary: "insecure key handling allows token forgery"},
	{Name: "moment", SafeVersion: "2.29.4", CVE: "CVE-2022-31129", Summary: "ReDoS via crafted date string"},
	{Name: "shell-quote", SafeVersion: "1.7.3", CVE: "CVE-2021-42740", Summary: "command injection via unescaped characters"},
	{Name: "underscore", SafeVersion: "1.13.6", CVE: "CVE-2021-23358", Summary: "arbitrary code execution via template"},
	{Name: "got", SafeVersion: "11.8.5", CVE: "CVE-2022-33987", Summary: "SSRF via redirect to unix socket"},
	{Name: "qs", SafeVersion: "6.10.3", CVE: "CVE-2022-24999", Summary: "prototype pollution"},
	{Name: "path-parse", SafeVersion: "1.0.7", CVE: "CVE-2021-23343", Summary: "ReDoS via crafted path string"},
	{Name: "json5", SafeVersion: "2.2.2", CVE: "CVE-2022-46175", Summary: "prototype pollution via parse"},
	{Name: "semver", SafeVersion: "7.5.2", CVE: "CVE-2022-25883", Summary: "ReDoS via crafted version string"},

	// Java / JVM
	{Name: "log4j", SafeVersion: "2.17.0", CVE: "CVE-2021-44228", Summary: "Log4Shell JNDI injection RCE"},
	{Name: "org.apache.logging.log4j:log4j-core", SafeVersion: "2.17.0", CVE: "CVE-2021-44228", Summary: "Log4Shell JNDI injection RCE"},
	{Name: "spring-core", SafeVersion: "5.3.18", CVE: "CVE-2022-22965", Summary: "Spring4Shell RCE via class loader manipulation"},
	{Name: "org.springframework:spring-core", SafeVersion: "5.3.18", CVE: "CVE-2022-22965", Summary: "Spring4Shell RCE via class loader manipulation"},
	{Name: "com.fasterxml.jackson-databind", SafeVersion: "2.13.2.1", CVE: "CVE-2020-36518", Summary: "denial of service via deeply nested JSON"},
	{Name: "commons-text", SafeVersion: "1.10.0", CVE: "CVE-2022-42889", Summary: "Text4Shell RCE via string interpolation"},
	{Name: "org.apache.commons:commons-text", SafeVersion: "1.10.0", CVE: "CVE-2022-42889", Summary: "Text4Shell RCE via string interpolation"},

	// Python
	{Name: "django", SafeVersion: "3.2.13", CVE: "CVE-2022-28346", Summary: "SQL injection in QuerySet.annotate/aggregate/extra"},
	{Name: "Django", SafeVersion: "3.2.13", CVE: "CVE-2022-28346", Summary: "SQL injection in QuerySet.annotate/aggregate/extra"},
	{Name: "flask", SafeVersion: "2.2.5", CVE: "CVE-2023-30861", Summary: "session cookie leak on cross-domain redirects"},
	{Name: "Flask", SafeVersion: "2.2.5", CVE: "CVE-2023-30861", Summary: "session cookie leak on cross-domain redirects"},
	{Name: "requests", SafeVersion: "2.31.0", CVE: "CVE-2023-32681", Summary: "auth header leak via redirect to different host"},
	{Name: "urllib3", SafeVersion: "1.26.18", CVE: "CVE-2023-45803", Summary: "request body leak on redirect to different origin"},
	{Name: "Jinja2", SafeVersion: "3.1.3", CVE: "CVE-2024-22195", Summary: "XSS via xmlattr filter"},
	{Name: "jinja2", SafeVersion: "3.1.3", CVE: "CVE-2024-22195", Summary: "XSS via xmlattr filter"},
	{Name: "pillow", SafeVersion: "9.3.0", CVE: "CVE-2022-45198", Summary: "denial of service via crafted image"},
	{Name: "Pillow", SafeVersion: "9.3.0", CVE: "CVE-2022-45198", Summary: "denial of service via crafted image"},
	{Name: "paramiko", SafeVersion: "3.4.0", CVE: "CVE-2023-48795", Summary: "Terrapin SSH prefix truncation attack"},
	{Name: "cryptography", SafeVersion: "41.0.6", CVE: "CVE-2023-49083", Summary: "NULL dereference on malformed PKCS7 data"},
	{Name: "setuptools", SafeVersion: "65.5.1", CVE: "CVE-2022-40897", Summary: "ReDoS in package_index"},

	// PHP / Composer
	{Name: "guzzlehttp/guzzle", SafeVersion: "7.4.5", CVE: "CVE-2022-31090", Summary: "auth header leak on redirect to different host"},
	{Name: "symfony/http-kernel", SafeVersion: "5.4.20", CVE: "CVE-2022-24894", Summary: "session fixation via stored session cookie"},
	{Name: "laravel/framework", SafeVersion: "9.32.0", CVE: "CVE-2022-40482", Summary: "auth bypass via cookie forgery"},
	{Name: "monolog/monolog", SafeVersion: "2.8.0", CVE: "CVE-2022-23552", Summary: "code injection via crafted channel name"},

	// Ruby / Gems
	{Name: "rack", SafeVersion: "2.2.6.2", CVE: "CVE-2023-27530", Summary: "denial of service via multipart body"},
	{Name: "rails-html-sanitizer", SafeVersion: "1.4.4", CVE: "CVE-2022-23517", Summary: "XSS via crafted HTML attributes"},
	{Name: "nokogiri", SafeVersion: "1.13.10", CVE: "CVE-2022-23476", Summary: "use-after-free in libxml2 via XML namespace"},
	{Name: "puma", SafeVersion: "5.6.7", CVE: "CVE-2023-40175", Summary: "HTTP request smuggling via chunked transfer"},

	// Go modules
	{Name: "golang.org/x/crypto", SafeVersion: "0.17.0", CVE: "CVE-2023-48795", Summary: "Terrapin SSH prefix truncation attack"},
	{Name: "golang.org/x/net", SafeVersion: "0.17.0", CVE: "CVE-2023-44487", Summary: "HTTP/2 rapid reset DoS"},
	{Name: "golang.org/x/text", SafeVersion: "0.3.8", CVE: "CVE-2022-32149", Summary: "denial of service via crafted Accept-Language header"},
	{Name: "github.com/gin-gonic/gin", SafeVersion: "1.9.1", CVE: "CVE-2023-29401", Summary: "MIME sniff bypass via Content-Type on redirect"},
	{Name: "github.com/go-git/go-git/v5", SafeVersion: "5.11.0", CVE: "CVE-2023-49568", Summary: "arbitrary code execution via crafted gitconfig"},
}
