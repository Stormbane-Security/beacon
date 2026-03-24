// Package cmsplugins enumerates installed plugins/modules/extensions for
// detected CMS platforms and checks their versions against a curated list of
// known-vulnerable versions.
//
// The scanner self-detects the CMS via HTTP probes so it can be included in
// any playbook (e.g. wordpress, drupal) without needing external context.
// Detection mirrors the classify package signals to stay consistent.
//
// Supported platforms: WordPress, Drupal, Joomla.
package cmsplugins

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const scannerName = "cms-plugins"

// Scanner enumerates CMS plugins and checks for known-vulnerable versions.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

// cmsType is the detected content management system.
type cmsType int

const (
	cmsUnknown   cmsType = iota
	cmsWordPress         // WordPress
	cmsDrupal            // Drupal
	cmsJoomla            // Joomla
)

// pluginCheck describes a single plugin/module to probe.
type pluginCheck struct {
	slug         string // directory name under /wp-content/plugins/, /modules/, etc.
	readmePath   string // relative path to the readme/changelog that contains the version
	versionKey   string // text marker before the version number in the readme (e.g. "Stable tag:")
	knownVulnVer string // most recent version known to be vulnerable (empty = just report presence)
	cveHint      string // representative CVE for context (informational only)
}

// wordpressPlugins is the curated list of high-value WordPress plugins to check.
// Each entry probes /wp-content/plugins/<slug>/<readmePath>.
var wordpressPlugins = []pluginCheck{
	{"elementor", "readme.txt", "Stable tag:", "3.18.3", "CVE-2023-48777"},
	{"contact-form-7", "readme.txt", "Stable tag:", "5.7.6", "CVE-2023-6449"},
	{"woocommerce", "readme.txt", "Stable tag:", "8.2.2", "CVE-2023-44000"},
	{"yoast-seo", "readme.txt", "Stable tag:", "21.4", "CVE-2023-4004"},
	{"wordfence", "readme.txt", "Stable tag:", "", ""},
	{"wp-file-manager", "readme.txt", "Stable tag:", "6.9", "CVE-2020-25213"},
	{"duplicator", "readme.txt", "Stable tag:", "1.5.7.1", "CVE-2023-4677"},
	{"all-in-one-wp-migration", "readme.txt", "Stable tag:", "7.78", "CVE-2023-40004"},
	{"wp-super-cache", "readme.txt", "Stable tag:", "1.7.8", "CVE-2021-24209"},
	{"advanced-custom-fields", "readme.txt", "Stable tag:", "6.2.4", "CVE-2023-40012"},
	{"akismet", "readme.txt", "Stable tag:", "", ""},
	{"jetpack", "readme.txt", "Stable tag:", "12.7", "CVE-2023-2996"},
	{"classic-editor", "readme.txt", "Stable tag:", "", ""},
	{"really-simple-ssl", "readme.txt", "Stable tag:", "7.0.2", "CVE-2023-4996"},
	{"litespeed-cache", "readme.txt", "Stable tag:", "5.6", "CVE-2023-40000"},
}

// drupalModules is the curated list of Drupal core/contrib modules to probe.
var drupalModules = []pluginCheck{
	{"views", "views.info.yml", "version:", "", ""},
	{"webform", "webform.info.yml", "version:", "6.2.0", "CVE-2023-5256"},
	{"token", "token.info.yml", "version:", "", ""},
	{"pathauto", "pathauto.info.yml", "version:", "", ""},
}

// joomlaExtensions probes common Joomla extension paths.
var joomlaExtensions = []pluginCheck{
	{"com_k2", "k2.xml", "version>", "2.11.0", "CVE-2023-23752"},
	{"com_virtuemart", "virtuemart.xml", "version>", "", ""},
}

func (s *Scanner) Run(ctx context.Context, asset string, _ module.ScanType) ([]finding.Finding, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	base := baseURL(ctx, client, asset)
	if base == "" {
		return nil, nil
	}

	cms := detectCMS(ctx, client, base)
	if cms == cmsUnknown {
		return nil, nil
	}

	switch cms {
	case cmsWordPress:
		return probePlugins(ctx, client, asset, base, "/wp-content/plugins/", wordpressPlugins), nil
	case cmsDrupal:
		return probePlugins(ctx, client, asset, base, "/modules/contrib/", drupalModules), nil
	case cmsJoomla:
		return probeJoomla(ctx, client, asset, base, joomlaExtensions), nil
	}
	return nil, nil
}

// baseURL returns the working base URL (https preferred, http fallback).
func baseURL(ctx context.Context, client *http.Client, asset string) string {
	for _, scheme := range []string{"https", "http"} {
		u := scheme + "://" + asset
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, u, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode < 500 {
			return u
		}
	}
	return ""
}

// detectCMS probes key paths and headers to identify the CMS.
func detectCMS(ctx context.Context, client *http.Client, base string) cmsType {
	// WordPress: check for wp-login.php
	if probeExists(ctx, client, base+"/wp-login.php") {
		return cmsWordPress
	}
	// Drupal: check for X-Drupal-Cache header or /core/CHANGELOG.txt
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base, nil)
	if err == nil {
		if resp, err := client.Do(req); err == nil {
			resp.Body.Close()
			if resp.Header.Get("X-Drupal-Cache") != "" || resp.Header.Get("X-Drupal-Dynamic-Cache") != "" {
				return cmsDrupal
			}
		}
	}
	if probeExists(ctx, client, base+"/core/CHANGELOG.txt") {
		return cmsDrupal
	}
	// Joomla: check for /administrator/index.php
	if probeExists(ctx, client, base+"/administrator/index.php") {
		return cmsJoomla
	}
	return cmsUnknown
}

// probeExists returns true if the URL returns a 2xx response.
func probeExists(ctx context.Context, client *http.Client, url string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// probePlugins checks each plugin in the list for existence and optionally version.
func probePlugins(ctx context.Context, client *http.Client, asset, base, prefix string, plugins []pluginCheck) []finding.Finding {
	var findings []finding.Finding

	for _, p := range plugins {
		readmeURL := base + prefix + p.slug + "/" + p.readmePath
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, readmeURL, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<10)) // 8KB
		resp.Body.Close()
		if err != nil {
			continue
		}

		text := string(body)
		version := extractVersion(text, p.versionKey)

		checkID := finding.CheckCMSPluginFound
		severity := finding.SeverityInfo
		title := fmt.Sprintf("CMS plugin detected: %s", p.slug)
		desc := fmt.Sprintf("Plugin %q is installed on %s.", p.slug, asset)

		if version != "" {
			title = fmt.Sprintf("CMS plugin detected: %s v%s", p.slug, version)
			desc = fmt.Sprintf("Plugin %q v%s is installed on %s.", p.slug, version, asset)
		}

		// Check if the detected version is known-vulnerable.
		if p.knownVulnVer != "" && version != "" && !isNewerOrEqual(version, p.knownVulnVer) {
			checkID = finding.CheckCMSPluginVulnerable
			severity = finding.SeverityHigh
			title = fmt.Sprintf("Vulnerable CMS plugin: %s v%s (vuln ≤ %s)", p.slug, version, p.knownVulnVer)
			desc = fmt.Sprintf(
				"Plugin %q v%s on %s is at or below the known-vulnerable version %s.",
				p.slug, version, asset, p.knownVulnVer,
			)
			if p.cveHint != "" {
				desc += fmt.Sprintf(" See %s for a representative CVE.", p.cveHint)
			}
		}

		ev := map[string]any{
			"plugin":  p.slug,
			"version": version,
			"url":     readmeURL,
		}
		if p.cveHint != "" {
			ev["cve_hint"] = p.cveHint
		}

		findings = append(findings, finding.Finding{
			CheckID:      checkID,
			Module:       "surface",
			Scanner:      scannerName,
			Severity:     severity,
			Asset:        asset,
			Title:        title,
			Description:  desc,
			Evidence:     ev,
			DiscoveredAt: time.Now(),
		})
	}

	return findings
}

// probeJoomla probes Joomla extensions which use a different URL structure.
func probeJoomla(ctx context.Context, client *http.Client, asset, base string, exts []pluginCheck) []finding.Finding {
	// Joomla components live at /components/<name>/ or /administrator/components/<name>/
	var findings []finding.Finding
	for _, p := range exts {
		url := base + "/components/" + p.slug + "/" + p.readmePath
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		resp.Body.Close()
		if err != nil {
			continue
		}

		version := extractVersion(string(body), p.versionKey)
		findings = append(findings, finding.Finding{
			CheckID:      finding.CheckCMSPluginFound,
			Module:       "surface",
			Scanner:      scannerName,
			Severity:     finding.SeverityInfo,
			Asset:        asset,
			Title:        fmt.Sprintf("Joomla extension detected: %s v%s", p.slug, version),
			Description:  fmt.Sprintf("Joomla extension %q is installed on %s.", p.slug, asset),
			Evidence:     map[string]any{"extension": p.slug, "version": version, "url": url},
			DiscoveredAt: time.Now(),
		})
	}
	return findings
}

// extractVersion pulls the version string following a marker like "Stable tag: 1.2.3".
func extractVersion(text, key string) string {
	if key == "" {
		return ""
	}
	idx := strings.Index(text, key)
	if idx == -1 {
		return ""
	}
	rest := strings.TrimSpace(text[idx+len(key):])
	// Version ends at first whitespace or newline
	end := strings.IndexAny(rest, " \t\r\n")
	if end == -1 {
		return strings.TrimSpace(rest)
	}
	return strings.TrimSpace(rest[:end])
}

// isNewerOrEqual returns true when installed >= threshold using simple numeric
// dotted-version comparison. Falls back to string comparison on parse failure.
func isNewerOrEqual(installed, threshold string) bool {
	iv := versionParts(installed)
	tv := versionParts(threshold)
	for i := 0; i < len(tv); i++ {
		vi := 0
		if i < len(iv) {
			vi = iv[i]
		}
		if vi > tv[i] {
			return true
		}
		if vi < tv[i] {
			return false
		}
	}
	return true // equal
}

func versionParts(v string) []int {
	var parts []int
	for _, seg := range strings.Split(v, ".") {
		n := 0
		fmt.Sscanf(seg, "%d", &n)
		parts = append(parts, n)
	}
	return parts
}
