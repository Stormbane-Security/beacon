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

	"github.com/stormbane-security/beacon/internal/scan"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)


func init() {
	scan.RegisterWithCheckDecls(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	},
		scan.Check(finding.CheckCMSPluginFound, finding.SeverityInfo, finding.ModeSurface),
		scan.Check(finding.CheckCMSPluginVulnerable, finding.SeverityHigh, finding.ModeSurface),
	)
}
const scannerName = "cms-plugins"

// Scanner enumerates CMS plugins and checks for known-vulnerable versions.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

// cmsType is the detected content management system.
type cmsType int

const (
	cmsUnknown    cmsType = iota
	cmsWordPress          // WordPress
	cmsDrupal             // Drupal
	cmsJoomla             // Joomla
	cmsGhost              // Ghost
	cmsStrapi             // Strapi
	cmsDirectus           // Directus
	cmsPrestaShop         // PrestaShop
	cmsMagento            // Magento / Adobe Commerce
	cmsTypo3              // TYPO3
	cmsMoodle             // Moodle
	cmsCraft              // Craft CMS
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
	{"sitepress-multilingual-cms", "readme.txt", "Stable tag:", "4.6.12", "CVE-2024-6061"}, // WPML SSTI via Twig shortcode — Contributor → RCE
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
	case cmsGhost, cmsStrapi, cmsDirectus, cmsPrestaShop, cmsMagento, cmsTypo3, cmsMoodle, cmsCraft:
		return probeCMSFingerprint(ctx, client, asset, base, cms), nil
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
		_ = resp.Body.Close()
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
			_ = resp.Body.Close()
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
	// Ghost: /ghost/ admin panel or X-Ghost-Cache header
	if probeExists(ctx, client, base+"/ghost/") {
		return cmsGhost
	}
	// Strapi: /admin/ with Strapi branding or /_health endpoint
	if probeBodyContains(ctx, client, base+"/admin/", "strapi") {
		return cmsStrapi
	}
	// Directus: /admin/ with Directus branding or /server/info
	if probeExists(ctx, client, base+"/server/info") {
		return cmsDirectus
	}
	// PrestaShop: /admin*/login or X-Powered-By: PrestaShop
	if probeBodyContains(ctx, client, base, "prestashop") {
		return cmsPrestaShop
	}
	// Magento: /admin or Magento cookie (frontend=...)
	if probeExists(ctx, client, base+"/magento_version") ||
		probeBodyContains(ctx, client, base, "mage-cache") {
		return cmsMagento
	}
	// TYPO3: /typo3/ admin panel
	if probeExists(ctx, client, base+"/typo3/") {
		return cmsTypo3
	}
	// Moodle: /login/index.php with Moodle branding
	if probeBodyContains(ctx, client, base+"/login/index.php", "moodle") {
		return cmsMoodle
	}
	// Craft CMS: /admin/login or X-Powered-By: Craft CMS
	if probeBodyContains(ctx, client, base+"/admin/login", "craft cms") {
		return cmsCraft
	}
	return cmsUnknown
}

// probeBodyContains fetches the URL and returns true if the response body
// contains the given substring (case-insensitive). Returns false on error or non-2xx.
func probeBodyContains(ctx context.Context, client *http.Client, rawURL, substr string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return false
	}
	return strings.Contains(strings.ToLower(string(body)), strings.ToLower(substr))
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
	_ = resp.Body.Close()
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
			_ = resp.Body.Close()
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<10)) // 8KB
		_ = resp.Body.Close()
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
		if p.knownVulnVer != "" && version != "" && isNewerOrEqual(p.knownVulnVer, version) {
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
			_ = resp.Body.Close()
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		_ = resp.Body.Close()
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
		_, _ = fmt.Sscanf(seg, "%d", &n)
		parts = append(parts, n)
	}
	return parts
}

// cmsNames maps cmsType to human-readable names.
var cmsNames = map[cmsType]string{
	cmsGhost:      "Ghost",
	cmsStrapi:     "Strapi",
	cmsDirectus:   "Directus",
	cmsPrestaShop: "PrestaShop",
	cmsMagento:    "Magento",
	cmsTypo3:      "TYPO3",
	cmsMoodle:     "Moodle",
	cmsCraft:      "Craft CMS",
}

// cmsAdminPaths are admin panel and sensitive paths to probe per CMS.
var cmsAdminPaths = map[cmsType][]string{
	cmsGhost: {
		"/ghost/",
		"/ghost/api/v3/admin/",
		"/ghost/api/v4/admin/",
		"/ghost/api/admin/",
		"/content/images/",
	},
	cmsStrapi: {
		"/admin/",
		"/_health",
		"/api/content-type-builder/content-types",
		"/api/users-permissions/roles",
		"/uploads/",
	},
	cmsDirectus: {
		"/admin/",
		"/server/info",
		"/server/health",
		"/items/",
		"/files/",
		"/users/",
	},
	cmsPrestaShop: {
		"/admin/",
		"/api/",
		"/modules/",
		"/install/",
		"/config/settings.inc.php",
		"/config/xml/",
	},
	cmsMagento: {
		"/admin/",
		"/magento_version",
		"/downloader/",
		"/rest/V1/store/storeConfigs",
		"/rest/V1/directory/currency",
		"/static/version.txt",
		"/errors/local.xml",
	},
	cmsTypo3: {
		"/typo3/",
		"/typo3/install.php",
		"/typo3conf/",
		"/typo3conf/localconf.php",
		"/typo3conf/LocalConfiguration.php",
		"/typo3temp/",
		"/fileadmin/",
	},
	cmsMoodle: {
		"/login/index.php",
		"/admin/",
		"/admin/tool/task/scheduledtasks.php",
		"/lib/db/upgrade.php",
		"/theme/",
		"/config.php",
	},
	cmsCraft: {
		"/admin/login",
		"/admin/",
		"/cpresources/",
		"/actions/",
		"/index.php/admin",
	},
}

// probeCMSFingerprint emits a finding for a detected CMS and probes its admin/sensitive paths.
func probeCMSFingerprint(ctx context.Context, client *http.Client, asset, base string, cms cmsType) []finding.Finding {
	name := cmsNames[cms]
	var findings []finding.Finding

	// Emit CMS detection finding
	findings = append(findings, finding.Finding{
		CheckID:  finding.CheckCMSPluginFound,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityInfo,
		Asset:    asset,
		Title:    fmt.Sprintf("CMS detected: %s", name),
		Description: fmt.Sprintf(
			"%s is running %s. CMS-specific attack vectors should be tested "+
				"including admin panel exposure, default credentials, known CVEs, "+
				"and plugin/extension vulnerabilities.",
			asset, name),
		Evidence: map[string]any{
			"cms":   strings.ToLower(name),
			"asset": asset,
		},
		DiscoveredAt: time.Now(),
	})

	// Probe admin and sensitive paths
	paths, ok := cmsAdminPaths[cms]
	if !ok {
		return findings
	}

	for _, path := range paths {
		if ctx.Err() != nil {
			break
		}

		fullURL := base + path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon Security Scanner)")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()

		// Only report accessible paths (2xx)
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			continue
		}

		// Determine severity based on path sensitivity
		sev := finding.SeverityLow
		title := fmt.Sprintf("%s path accessible: %s", name, path)
		desc := fmt.Sprintf(
			"The %s path %s on %s returned HTTP %d.",
			name, path, asset, resp.StatusCode)

		isAdmin := strings.Contains(path, "admin") || strings.Contains(path, "install") ||
			strings.Contains(path, "config") || strings.Contains(path, "users")
		isAPI := strings.Contains(path, "/api/") || strings.Contains(path, "/rest/")

		switch {
		case strings.Contains(path, "install"):
			sev = finding.SeverityCritical
			desc += " The installation script is still accessible — an attacker may be able to reinstall or reconfigure the CMS."
		case strings.Contains(path, "config") && len(body) > 0:
			sev = finding.SeverityHigh
			desc += " Configuration files may contain database credentials, API keys, or other secrets."
		case isAdmin:
			sev = finding.SeverityMedium
			desc += " Admin panel exposure allows brute-force attacks and may reveal version information."
		case isAPI:
			sev = finding.SeverityMedium
			desc += " API endpoints may expose internal data structures or allow unauthorized access."
		}

		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckCMSPluginFound,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: sev,
			Asset:    asset,
			Title:    title,
			Description: desc,
			Evidence: map[string]any{
				"cms":         strings.ToLower(name),
				"path":        path,
				"status_code": resp.StatusCode,
				"body_length": len(body),
			},
			ProofCommand: fmt.Sprintf("curl -sI '%s'", fullURL),
			DiscoveredAt: time.Now(),
		})
	}

	return findings
}
