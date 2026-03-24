// Package exposedfiles actively probes for sensitive configuration files,
// credentials, and secrets exposed over HTTP. It complements the passive
// dorks and historicalurls scanners with direct, authoritative probes.
//
// Surface mode: probes high-confidence, low-false-positive paths.
// Deep mode: probes an extended list including framework-specific paths.
package exposedfiles

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

const scannerName = "exposedfiles"

type sensitiveFile struct {
	path        string
	title       string
	severity    finding.Severity
	deepOnly    bool
	// bodyContains confirms it's real (not a soft 404) by checking for this substring.
	bodyContains string
	// checkID overrides the default "exposure.sensitive_file" check ID.
	// Use for CVE-specific probes that need their own tracking identity.
	checkID string
	// description overrides the default generic description when set.
	description string
}

var targets = []sensitiveFile{
	// Critical — credential / secret files
	{path: "/.env", title: "Exposed .env file", severity: finding.SeverityCritical, bodyContains: "="},
	{path: "/.env.local", title: "Exposed .env.local file", severity: finding.SeverityCritical, bodyContains: "="},
	{path: "/.env.production", title: "Exposed .env.production file", severity: finding.SeverityCritical, bodyContains: "="},
	{path: "/.env.backup", title: "Exposed .env.backup file", severity: finding.SeverityCritical, bodyContains: "="},
	{path: "/config/database.yml", title: "Exposed database config (Rails)", severity: finding.SeverityCritical, bodyContains: "password"},
	{path: "/config/secrets.yml", title: "Exposed secrets file (Rails)", severity: finding.SeverityCritical, bodyContains: "secret"},
	{path: "/app/config/parameters.yml", title: "Exposed Symfony parameters", severity: finding.SeverityCritical, bodyContains: "database"},
	{path: "/.aws/credentials", title: "Exposed AWS credentials file", severity: finding.SeverityCritical, bodyContains: "aws_"},
	{path: "/wp-config.php.bak", title: "Exposed WordPress config backup", severity: finding.SeverityCritical, deepOnly: true},
	{path: "/configuration.php.bak", title: "Exposed Joomla config backup", severity: finding.SeverityCritical, deepOnly: true},
	{path: "/.docker/config.json", title: "Exposed Docker registry credentials", severity: finding.SeverityCritical, bodyContains: "auth"},

	// High — source control exposure
	{path: "/.git/config", title: "Exposed .git/config (repo metadata)", severity: finding.SeverityHigh, bodyContains: "[core]"},
	{path: "/.git/HEAD", title: "Exposed .git/HEAD (Git repository)", severity: finding.SeverityHigh, bodyContains: "ref:"},
	{path: "/.svn/entries", title: "Exposed Subversion repository", severity: finding.SeverityHigh},
	{path: "/.hg/hgrc", title: "Exposed Mercurial repository", severity: finding.SeverityHigh},

	// High — database and backup files
	{path: "/dump.sql", title: "Exposed SQL dump", severity: finding.SeverityHigh, bodyContains: "CREATE"},
	{path: "/backup.sql", title: "Exposed SQL backup", severity: finding.SeverityHigh, bodyContains: "INSERT"},
	{path: "/db.sqlite", title: "Exposed SQLite database", severity: finding.SeverityHigh},
	{path: "/database.sqlite", title: "Exposed SQLite database", severity: finding.SeverityHigh},
	{path: "/data.sqlite", title: "Exposed SQLite database", severity: finding.SeverityHigh},

	// High — package manager / dependency files (reveal software versions)
	{path: "/package.json", title: "Exposed package.json (dependency manifest)", severity: finding.SeverityMedium, bodyContains: "dependencies"},
	{path: "/composer.json", title: "Exposed composer.json (PHP dependencies)", severity: finding.SeverityMedium, bodyContains: "require"},
	{path: "/Gemfile", title: "Exposed Gemfile (Ruby dependencies)", severity: finding.SeverityMedium, bodyContains: "gem"},
	{path: "/requirements.txt", title: "Exposed requirements.txt (Python deps)", severity: finding.SeverityMedium},
	{path: "/go.sum", title: "Exposed go.sum (Go module checksums)", severity: finding.SeverityLow},

	// Medium — application config files
	{path: "/config.json", title: "Exposed config.json", severity: finding.SeverityMedium, bodyContains: "{"},
	{path: "/config.yaml", title: "Exposed config.yaml", severity: finding.SeverityMedium},
	{path: "/config.yml", title: "Exposed config.yml", severity: finding.SeverityMedium},
	{path: "/settings.json", title: "Exposed settings.json", severity: finding.SeverityMedium, bodyContains: "{"},
	{path: "/appsettings.json", title: "Exposed appsettings.json (.NET)", severity: finding.SeverityMedium, bodyContains: "{"},
	{path: "/application.properties", title: "Exposed Spring Boot properties", severity: finding.SeverityMedium, deepOnly: true},
	{path: "/application.yml", title: "Exposed Spring Boot config", severity: finding.SeverityMedium, deepOnly: true},

	// Medium — log files
	{path: "/error.log", title: "Exposed error log", severity: finding.SeverityMedium, deepOnly: true},
	{path: "/access.log", title: "Exposed access log", severity: finding.SeverityMedium, deepOnly: true},
	{path: "/laravel.log", title: "Exposed Laravel log", severity: finding.SeverityMedium, deepOnly: true, bodyContains: "local.ERROR"},
	{path: "/storage/logs/laravel.log", title: "Exposed Laravel log", severity: finding.SeverityMedium, deepOnly: true},
	{path: "/var/log/app.log", title: "Exposed application log", severity: finding.SeverityMedium, deepOnly: true},

	// Info — fingerprinting / metadata
	{path: "/server-status", title: "Apache server-status exposed", severity: finding.SeverityMedium, bodyContains: "Apache"},
	{path: "/server-info", title: "Apache server-info exposed", severity: finding.SeverityMedium, bodyContains: "Apache"},
	{path: "/phpinfo.php", title: "PHP info page exposed", severity: finding.SeverityHigh, bodyContains: "phpinfo"},
	{path: "/info.php", title: "PHP info page exposed", severity: finding.SeverityHigh, bodyContains: "phpinfo"},

	// ── CVE-specific endpoint probes (Oct 2025 – Mar 2026 KEV wave) ──────────
	// HPE OneView — CVE-2025-37164 unauthenticated RCE (CVSS 10.0, KEV-listed).
	// /rest/version is accessible without authentication and returns a JSON object
	// including "currentVersion" that uniquely identifies HPE OneView.
	{
		path: "/rest/version", title: "HPE OneView REST API version exposed (CVE-2025-37164)",
		severity: finding.SeverityCritical, checkID: finding.CheckCVEHPEOneViewRCE,
		bodyContains: "currentVersion",
		description: "The HPE OneView management REST API /rest/version endpoint is accessible without authentication. " +
			"CVE-2025-37164 (CVSS 10.0, KEV-listed Jan 2026) allows pre-authentication remote code execution " +
			"via the /rest/id-pools/executeCommand API. A Metasploit module is publicly available. " +
			"Patch to HPE OneView 11.00 or later immediately.",
	},

	// Ivanti EPMM — CVE-2026-1281 + CVE-2026-1340 pre-auth OS command injection
	// (CVSS 9.8, KEV-listed Feb 2026). The MDM distribution path is uniquely Ivanti
	// EPMM and responds with 200 without authentication.
	{
		path: "/mifs/c/appstore/fob/", title: "Ivanti EPMM MDM endpoint exposed (CVE-2026-1281/1340)",
		severity: finding.SeverityCritical, checkID: finding.CheckCVEIvantiEPMMRCE,
		description: "The Ivanti Endpoint Manager Mobile (EPMM) in-house app distribution endpoint is internet-accessible. " +
			"CVE-2026-1281 and CVE-2026-1340 (CVSS 9.8, KEV-listed Feb 2026) allow pre-authentication OS command " +
			"injection via URL parameters passed to Bash arithmetic expansion. Ransomware operators actively exploit this. " +
			"Apply Ivanti EPMM patches released February 2026 immediately.",
	},

	// Cisco ASA / FTD — CVE-2025-20333 + CVE-2025-20362 chained pre-auth RCE.
	// The AnyConnect SSL VPN login page is unique to Cisco ASA/FTD devices.
	// bodyContains "webvpn" confirms it is genuine Cisco AnyConnect, not a redirect.
	{
		path: "/+CSCOE+/logon.html", title: "Cisco ASA/FTD AnyConnect VPN exposed (CVE-2025-20333/20362)",
		severity: finding.SeverityCritical, checkID: finding.CheckCVECiscoASARCE,
		bodyContains: "webvpn",
		description: "A Cisco Adaptive Security Appliance (ASA) or Firewall Threat Defense (FTD) device with " +
			"AnyConnect SSL VPN is internet-accessible. CVE-2025-20333 (buffer overflow) chained with CVE-2025-20362 " +
			"(unauthenticated URL access) enables pre-authentication remote code execution on unpatched devices. " +
			"Both CVEs are KEV-listed. Apply Cisco security patches for ASA/FTD immediately.",
	},

	// Citrix NetScaler — CVE-2025-5777 (\"CitrixBleed 2\") pre-auth memory leak.
	// The NetScaler Gateway /vpn/index.html login page uniquely identifies this product.
	{
		path: "/vpn/index.html", title: "Citrix NetScaler Gateway login exposed (CVE-2025-5777)",
		severity: finding.SeverityCritical, checkID: finding.CheckCVECitrixBleed2,
		bodyContains: "Citrix",
		description: "A Citrix NetScaler ADC or Gateway login page is internet-accessible. " +
			"CVE-2025-5777 (\"CitrixBleed 2\", CVSS 9.3, KEV-listed) is a pre-authentication memory leak in " +
			"the authentication handler. Sending a crafted POST to /p/u/doAuthentication.do causes the server " +
			"to return stack memory contents including session tokens within the XML response. " +
			"Upgrade to patched NetScaler versions immediately.",
	},

	// ── CVE-specific endpoint probes ──────────────────────────────────────────
	// Each probe targets a specific product version gap (KEV-listed or actively
	// exploited). Bodycontains validates the product is actually running, not
	// just that the path responds (soft-404 guard).

	// CVE-2026-27944 — Nginx-UI unauthenticated backup download + encryption key
	// disclosure. GET /api/backup without credentials returns the full archive and
	// exposes X-Backup-Security header. CVSS 9.8, no auth required.
	{
		path: "/api/backup", title: "Nginx-UI unauthenticated backup endpoint (CVE-2026-27944)",
		severity: finding.SeverityCritical, checkID: finding.CheckCVENginxUIBackup,
		description: "The Nginx-UI /api/backup endpoint is accessible without authentication (CVE-2026-27944, CVSS 9.8). " +
			"It returns the full server configuration backup including SSL private keys and credentials. " +
			"The X-Backup-Security header in the response discloses the decryption key. " +
			"Update Nginx-UI to ≥ 2.3.2 immediately.",
	},

	// CVE-2026-1731 — BeyondTrust Remote Support / PRA pre-auth OS command injection.
	// /appliance/api/info exposes version without authentication; compare against
	// patched builds (RS > 25.3.1, PRA > 24.3.4). CVSS 9.9, KEV-listed Feb 2026.
	{
		path: "/appliance/api/info", title: "BeyondTrust Remote Support version exposed (CVE-2026-1731)",
		severity: finding.SeverityCritical, checkID: finding.CheckCVEBeyondTrustRCE,
		bodyContains: "version",
		description: "The BeyondTrust Remote Support / PRA version API is accessible without authentication. " +
			"CVE-2026-1731 (CVSS 9.9, KEV-listed) allows pre-authentication OS command injection on versions RS ≤ 25.3.1 and PRA ≤ 24.3.4. " +
			"Compare the disclosed version against patched builds and upgrade immediately.",
	},

	// CVE-2025-26399 — SolarWinds Web Help Desk AjaxProxy deserialization RCE.
	// The login page fingerprint confirms WHD; AjaxProxy path confirms exploitability.
	// CVSS 9.8, KEV-listed Mar 2026.
	{
		path: "/helpdesk/WebObjects/Helpdesk.woa/wo/", title: "SolarWinds Web Help Desk exposed (CVE-2025-26399)",
		severity: finding.SeverityCritical, checkID: finding.CheckCVESolarWindsWHD,
		description: "SolarWinds Web Help Desk is internet-accessible. CVE-2025-26399 (CVSS 9.8, KEV-listed Mar 2026) " +
			"exploits unauthenticated Java deserialization in the AjaxProxy component. " +
			"Upgrade to WHD 12.8.7 HF1 or WHD 2026.1 immediately.",
	},

	// CVE-2026-1603 — Ivanti Endpoint Manager auth bypass → credential theft.
	// The /ams/ console path fingerprints Ivanti EPM. CVSS High, KEV-listed Mar 2026.
	{
		path: "/ams/", title: "Ivanti Endpoint Manager console exposed (CVE-2026-1603)",
		severity: finding.SeverityCritical, checkID: finding.CheckCVEIvantiEPMAuthBypass,
		description: "Ivanti Endpoint Manager is internet-accessible. CVE-2026-1603 (KEV-listed Mar 2026) " +
			"allows authentication bypass via a specific API endpoint, exposing Domain Administrator " +
			"and service account credential blobs from the EPM Credential Vault. " +
			"Update to EPM 2024 SU5 or later immediately.",
	},
}

// Scanner actively probes for exposed sensitive files.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	scheme := detectScheme(ctx, client, asset)
	base := scheme + "://" + asset

	var findings []finding.Finding

	for _, t := range targets {
		if t.deepOnly && scanType != module.ScanDeep {
			continue
		}

		u := base + t.path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			if resp != nil {
				resp.Body.Close()
			}
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		// Confirm it's a real file, not a soft 404 or CMS catch-all.
		if t.bodyContains != "" && !strings.Contains(string(body), t.bodyContains) {
			continue
		}

		// Heuristic: if the body is an HTML page, it's almost certainly a soft 404.
		ct := resp.Header.Get("Content-Type")
		if strings.Contains(ct, "text/html") && t.bodyContains == "" {
			continue
		}

		// Store up to 2000 chars so the AI enrichment pipeline and DLP scanner
		// can see actual key/value pairs (most .env files fit in this window).
		snippet := string(body)
		if len(snippet) > 2000 {
			snippet = snippet[:2000] + "…"
		}

		checkID := finding.CheckExposureSensitiveFile
		if t.checkID != "" {
			checkID = t.checkID
		}
		desc := t.description
		if desc == "" {
			desc = fmt.Sprintf(
				"%s is publicly accessible at %s. This file may contain credentials, "+
					"secrets, or configuration data that enables further attacks.",
				t.path, u)
		}

		findings = append(findings, finding.Finding{
			CheckID:      checkID,
			Module:       "surface",
			Scanner:      scannerName,
			Severity:     t.severity,
			Title:        t.title,
			Description:  desc,
			Asset:        asset,
			ProofCommand: fmt.Sprintf("curl -s %s | head -50", u),
			Evidence: map[string]any{
				"url":     u,
				"path":    t.path,
				"snippet": snippet,
			},
		})
	}

	return findings, nil
}

func detectScheme(ctx context.Context, client *http.Client, asset string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+asset, nil)
	if err != nil {
		return "http"
	}
	resp, err := client.Do(req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return "http"
	}
	resp.Body.Close()
	return "https"
}
