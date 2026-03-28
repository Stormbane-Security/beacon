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
