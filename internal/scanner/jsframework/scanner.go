// Package jsframework detects client-side JavaScript frameworks and their
// versions by analyzing HTML source, script tags, and global JS variables
// exposed in page content. When a version is identified, it is checked
// against a database of known CVEs.
package jsframework

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scan"
)

func init() {
	scan.RegisterWithCheckDecls(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	},
		scan.Check(finding.CheckJSFrameworkDetected, finding.SeverityInfo, finding.ModeSurface),
		scan.Check(finding.CheckJSFrameworkVulnerable, finding.SeverityMedium, finding.ModeSurface),
	)
}

const scannerName = "jsframework"

type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

// frameworkPattern defines a detection rule for a JS framework.
type frameworkPattern struct {
	name       string
	// htmlMatch: substring that appears in the HTML source when the framework is present.
	htmlMatch  string
	// versionRe: regex to extract the version from script URLs or HTML source.
	versionRe  *regexp.Regexp
	// vulnVersions: map of version prefix → CVE description.
	vulnVersions map[string]string
}

var frameworks = []frameworkPattern{
	{
		name:      "React",
		htmlMatch: "data-reactroot",
		versionRe: regexp.MustCompile(`react(?:\.production\.min|\.development)?[.-](\d+\.\d+\.\d+)`),
		vulnVersions: map[string]string{
			"16.0.": "CVE-2018-6341 — XSS via textarea",
			"0.":    "Pre-release React — likely has unfixed XSS vulnerabilities",
		},
	},
	{
		name:      "React",
		htmlMatch: "__NEXT_DATA__",
		versionRe: regexp.MustCompile(`"version"\s*:\s*"(\d+\.\d+\.\d+)"`),
	},
	{
		name:      "Angular",
		htmlMatch: "ng-version=",
		versionRe: regexp.MustCompile(`ng-version="(\d+\.\d+\.\d+)"`),
		vulnVersions: map[string]string{
			"1.":  "AngularJS 1.x — EOL, multiple XSS via template injection (CVE-2022-25869)",
			"2.":  "Angular 2.x — early release, template injection risks",
			"4.":  "Angular 4.x — EOL, upgrade recommended",
			"5.":  "Angular 5.x — EOL, upgrade recommended",
			"6.":  "Angular 6.x — EOL, upgrade recommended",
			"7.":  "Angular 7.x — EOL, upgrade recommended",
			"8.":  "Angular 8.x — EOL, upgrade recommended",
			"9.":  "Angular 9.x — EOL, upgrade recommended",
			"10.": "Angular 10.x — EOL, upgrade recommended",
			"11.": "Angular 11.x — EOL, upgrade recommended",
			"12.": "Angular 12.x — EOL, upgrade recommended",
		},
	},
	{
		name:      "AngularJS",
		htmlMatch: "ng-app",
		versionRe: regexp.MustCompile(`angular[.-](\d+\.\d+\.\d+)`),
		vulnVersions: map[string]string{
			"1.": "AngularJS 1.x — EOL since Dec 2021, multiple XSS via template injection",
		},
	},
	{
		name:      "Vue.js",
		htmlMatch: "data-v-",
		versionRe: regexp.MustCompile(`vue(?:\.min|\.runtime)?[.-](\d+\.\d+\.\d+)`),
		vulnVersions: map[string]string{
			"2.": "Vue 2.x — EOL since Dec 2023",
		},
	},
	{
		name:      "jQuery",
		htmlMatch: "jquery-",
		versionRe: regexp.MustCompile(`jquery[.-](\d+\.\d+\.\d+)`),
		vulnVersions: map[string]string{
			"1.":    "jQuery 1.x — multiple XSS (CVE-2020-11022, CVE-2020-11023)",
			"2.":    "jQuery 2.x — multiple XSS (CVE-2020-11022, CVE-2020-11023)",
			"3.0.":  "jQuery 3.0.x — CVE-2020-11022 XSS",
			"3.1.":  "jQuery 3.1.x — CVE-2020-11022 XSS",
			"3.2.":  "jQuery 3.2.x — CVE-2020-11022 XSS",
			"3.3.":  "jQuery 3.3.x — CVE-2020-11022 XSS",
			"3.4.":  "jQuery 3.4.x — CVE-2020-11022 XSS",
		},
	},
	{
		name:      "Bootstrap",
		htmlMatch: "bootstrap",
		versionRe: regexp.MustCompile(`bootstrap[.-](\d+\.\d+\.\d+)`),
		vulnVersions: map[string]string{
			"3.": "Bootstrap 3.x — XSS in data-target (CVE-2018-14040, CVE-2018-14042)",
			"2.": "Bootstrap 2.x — EOL, multiple XSS",
		},
	},
	{
		name:      "Lodash",
		htmlMatch: "lodash",
		versionRe: regexp.MustCompile(`lodash[.-](\d+\.\d+\.\d+)`),
		vulnVersions: map[string]string{
			"4.17.": "Check for < 4.17.21 — prototype pollution (CVE-2021-23337)",
		},
	},
	{
		name:      "Backbone.js",
		htmlMatch: "backbone",
		versionRe: regexp.MustCompile(`backbone[.-](\d+\.\d+\.\d+)`),
	},
	{
		name:      "Ember.js",
		htmlMatch: "ember",
		versionRe: regexp.MustCompile(`ember[.-](\d+\.\d+\.\d+)`),
	},
	{
		name:      "Svelte",
		htmlMatch: "svelte",
		versionRe: regexp.MustCompile(`svelte[/@](\d+\.\d+\.\d+)`),
	},
	{
		name:      "Next.js",
		htmlMatch: "__NEXT_DATA__",
		versionRe: regexp.MustCompile(`"buildId"\s*:\s*"[^"]+"`),
	},
	{
		name:      "Nuxt.js",
		htmlMatch: "__NUXT__",
		versionRe: regexp.MustCompile(`nuxt[/@](\d+\.\d+\.\d+)`),
	},
}

func (s *Scanner) Run(ctx context.Context, asset string, _ module.ScanType) ([]finding.Finding, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	// Fetch the main page.
	var body string
	for _, scheme := range []string{"https", "http"} {
		url := scheme + "://" + asset + "/"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024)) // 512 KB
		resp.Body.Close()
		if resp.StatusCode == 200 {
			body = string(b)
			break
		}
	}

	if body == "" {
		return nil, nil
	}

	bodyLower := strings.ToLower(body)
	var findings []finding.Finding
	now := time.Now()
	seen := map[string]bool{}

	for _, fw := range frameworks {
		if !strings.Contains(bodyLower, strings.ToLower(fw.htmlMatch)) {
			continue
		}
		if seen[fw.name] {
			continue
		}
		seen[fw.name] = true

		// Try to extract version.
		version := ""
		if fw.versionRe != nil {
			if m := fw.versionRe.FindStringSubmatch(body); len(m) > 1 {
				version = m[1]
			}
		}

		title := fmt.Sprintf("%s detected on %s", fw.name, asset)
		desc := fmt.Sprintf("The page on %s uses %s", asset, fw.name)
		if version != "" {
			title = fmt.Sprintf("%s %s detected on %s", fw.name, version, asset)
			desc = fmt.Sprintf("The page on %s uses %s version %s", asset, fw.name, version)
		}

		findings = append(findings, finding.Finding{
			CheckID:     finding.CheckJSFrameworkDetected,
			Module:      "surface",
			Scanner:     scannerName,
			Severity:    finding.SeverityInfo,
			Asset:       asset,
			Title:       title,
			Description: desc + ".",
			Evidence: map[string]any{
				"framework": fw.name,
				"version":   version,
				"match":     fw.htmlMatch,
			},
			ProofCommand: fmt.Sprintf("curl -s https://%s/ | grep -i '%s'", asset, fw.htmlMatch),
			DiscoveredAt: now,
		})

		// Check for known vulnerable versions.
		if version != "" && fw.vulnVersions != nil {
			for prefix, cveDesc := range fw.vulnVersions {
				if strings.HasPrefix(version, prefix) {
					findings = append(findings, finding.Finding{
						CheckID:  finding.CheckJSFrameworkVulnerable,
						Module:   "surface",
						Scanner:  scannerName,
						Severity: finding.SeverityMedium,
						Asset:    asset,
						Title:    fmt.Sprintf("Vulnerable %s %s on %s", fw.name, version, asset),
						Description: fmt.Sprintf(
							"%s uses %s %s which has known vulnerabilities: %s. "+
								"Update to the latest version to remediate.",
							asset, fw.name, version, cveDesc,
						),
						Evidence: map[string]any{
							"framework": fw.name,
							"version":   version,
							"cve_info":  cveDesc,
						},
						ProofCommand: fmt.Sprintf("curl -s https://%s/ | grep -oP '%s'", asset, fw.versionRe.String()),
						DiscoveredAt: now,
					})
					break
				}
			}
		}
	}

	return findings, nil
}
