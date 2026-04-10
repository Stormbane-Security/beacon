// Package correlation is a post-scan scanner that detects compound
// vulnerabilities by analyzing the complete set of findings from all other
// scanners. Individual findings that are medium-severity on their own can
// combine into critical attack chains when present on the same asset or
// within the same scan scope.
//
// This scanner runs AFTER all other scanners and receives the full findings
// slice via SetFindings before Run is called.
package correlation

import (
	"context"
	"fmt"
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
		scan.Check(finding.CheckCorrelationAuthBypassViaProxy, finding.SeverityHigh, finding.ModeSurface),
		scan.Check(finding.CheckCorrelationXSSCSRFChain, finding.SeverityCritical, finding.ModeSurface),
		scan.Check(finding.CheckCorrelationTLSSessionHijack, finding.SeverityHigh, finding.ModeSurface),
		scan.Check(finding.CheckCorrelationCloudMetadataChain, finding.SeverityCritical, finding.ModeSurface),
		scan.Check(finding.CheckCorrelationCredentialReuse, finding.SeverityCritical, finding.ModeSurface),
		scan.Check(finding.CheckCorrelationStagingToProd, finding.SeverityHigh, finding.ModeSurface),
		scan.Check(finding.CheckCorrelationSessionHijackChain, finding.SeverityCritical, finding.ModeSurface),
		scan.Check(finding.CheckCorrelationCredentialTheftChain, finding.SeverityCritical, finding.ModeSurface),
		scan.Check(finding.CheckCorrelationFullCompromiseChain, finding.SeverityCritical, finding.ModeSurface),
		scan.Check(finding.CheckCorrelationAuthBypassChain, finding.SeverityHigh, finding.ModeSurface),
		scan.Check(finding.CheckCorrelationCachePoisoningChain, finding.SeverityHigh, finding.ModeSurface),
		scan.Check(finding.CheckCorrelationLateralMovementChain, finding.SeverityCritical, finding.ModeSurface),
		scan.Check(finding.CheckCorrelationDNSRebindingChain, finding.SeverityCritical, finding.ModeSurface),
	)
}

const scannerName = "correlation"

// Scanner detects compound vulnerabilities from the combined findings of
// all other scanners.
type Scanner struct {
	findings []finding.Finding
}

// New returns a new correlation Scanner.
func New() *Scanner { return &Scanner{} }

// Name returns the stable scanner identifier.
func (s *Scanner) Name() string { return scannerName }

// SetFindings provides the full set of findings from all other scanners.
// Must be called before Run.
func (s *Scanner) SetFindings(findings []finding.Finding) {
	s.findings = findings
}

// Run analyzes the complete findings set for dangerous combinations.
// The asset parameter is used as the primary asset for emitted findings.
func (s *Scanner) Run(_ context.Context, asset string, _ module.ScanType) ([]finding.Finding, error) {
	if len(s.findings) == 0 {
		return nil, nil
	}

	now := time.Now()

	// Build lookup indices for fast check-ID and asset queries.
	byCheckID := make(map[string][]finding.Finding)
	byAsset := make(map[string][]finding.Finding)
	for _, f := range s.findings {
		byCheckID[f.CheckID] = append(byCheckID[f.CheckID], f)
		byAsset[f.Asset] = append(byAsset[f.Asset], f)
	}

	var results []finding.Finding

	// Chain 1: Open redirect + OAuth endpoint = token theft risk
	results = append(results, checkAuthBypassViaProxy(byCheckID, asset, now)...)

	// Chain 2: XSS + no CSRF protection = account takeover
	results = append(results, checkXSSCSRFChain(byCheckID, byAsset, asset, now)...)

	// Chain 3: Weak TLS + insecure cookies = session hijack
	results = append(results, checkTLSSessionHijack(byCheckID, byAsset, asset, now)...)

	// Chain 4: SSRF + cloud metadata accessible = IAM takeover
	results = append(results, checkCloudMetadataChain(byCheckID, asset, now)...)

	// Chain 5: Info disclosure + default creds = admin access
	results = append(results, checkCredentialReuse(byCheckID, asset, now)...)

	// Chain 6: Exposed .git + source code = secret extraction
	results = append(results, checkStagingToProdExposure(byCheckID, asset, now)...)

	// Chain 7: CORS misconfig + XSS + missing HttpOnly = session hijack
	results = append(results, checkSessionHijackChain(byCheckID, asset, now)...)

	// Chain 8: Exposed .env/config or .git + database creds = credential theft
	results = append(results, checkCredentialTheftChain(byCheckID, asset, now)...)

	// Chain 9: SQLi + exposed DB or SSRF + cloud metadata = full compromise
	results = append(results, checkFullCompromiseChain(byCheckID, asset, now)...)

	// Chain 10: JWT weak algorithm + no rotation or default creds + admin panel = auth bypass
	results = append(results, checkAuthBypassChain(byCheckID, asset, now)...)

	// Chain 11: Host header injection + cache or unkeyed header + XSS = cache poisoning
	results = append(results, checkCachePoisoningChain(byCheckID, asset, now)...)

	// Chain 12: Unauthenticated service + web app = lateral movement
	results = append(results, checkLateralMovementChain(byCheckID, asset, now)...)

	// Chain 13: DNS rebinding + internal services = network bypass
	results = append(results, checkDNSRebindingChain(byCheckID, asset, now)...)

	return results, nil
}

// hasAny returns true if any of the given check IDs have at least one finding.
func hasAny(byCheckID map[string][]finding.Finding, checkIDs ...string) bool {
	for _, id := range checkIDs {
		if len(byCheckID[id]) > 0 {
			return true
		}
	}
	return false
}

// firstFinding returns the first finding matching any of the given check IDs,
// or a zero-value finding if none match.
func firstFinding(byCheckID map[string][]finding.Finding, checkIDs ...string) finding.Finding {
	for _, id := range checkIDs {
		if fs := byCheckID[id]; len(fs) > 0 {
			return fs[0]
		}
	}
	return finding.Finding{}
}

// assetHasCheckID returns true if any finding for the given asset has the check ID.
func assetHasCheckID(byAsset map[string][]finding.Finding, asset string, checkIDs ...string) bool {
	for _, f := range byAsset[asset] {
		for _, id := range checkIDs {
			if f.CheckID == id {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Chain 1: Open redirect + OAuth endpoint = token theft
// ---------------------------------------------------------------------------

// openRedirectCheckIDs are check IDs indicating an open redirect vulnerability.
var openRedirectCheckIDs = []string{
	finding.CheckWebOpenRedirect,
	finding.CheckOAuthOpenRedirect,
}

func checkAuthBypassViaProxy(byCheckID map[string][]finding.Finding, asset string, now time.Time) []finding.Finding {
	if !hasAny(byCheckID, openRedirectCheckIDs...) {
		return nil
	}

	// Check for any OAuth-related findings that indicate OAuth is in use.
	hasOAuth := false
	for id := range byCheckID {
		if strings.HasPrefix(id, "oauth.") || strings.HasPrefix(id, "auth.") || strings.HasPrefix(id, "saml.") {
			hasOAuth = true
			break
		}
	}
	if !hasOAuth {
		return nil
	}

	redir := firstFinding(byCheckID, openRedirectCheckIDs...)

	return []finding.Finding{{
		CheckID:  finding.CheckCorrelationAuthBypassViaProxy,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Title:    fmt.Sprintf("Attack chain: open redirect + OAuth = token theft on %s", asset),
		Description: fmt.Sprintf(
			"An open redirect vulnerability (%s) was found alongside OAuth/authentication endpoints. "+
				"An attacker can craft a login URL with the redirect pointing to their server, "+
				"capturing the OAuth authorization code or token after the victim authenticates. "+
				"This enables account takeover without any user interaction beyond clicking a link.",
			redir.CheckID),
		Asset:    asset,
		DeepOnly: false,
		Evidence: map[string]any{
			"open_redirect_check": redir.CheckID,
			"open_redirect_asset": redir.Asset,
			"chain_type":          "open_redirect_oauth",
		},
		ProofCommand: fmt.Sprintf("# Verify open redirect:\n%s", redir.ProofCommand),
		DiscoveredAt: now,
	}}
}

// ---------------------------------------------------------------------------
// Chain 2: XSS + no CSRF protection = account takeover
// ---------------------------------------------------------------------------

var xssCheckIDs = []string{
	finding.CheckWebXSS,
	"web.reflected_xss",
	"web.stored_xss",
	"web.dom_xss",
}

var csrfCheckIDs = []string{
	finding.CheckWebCSRFMissing,
}

func checkXSSCSRFChain(byCheckID map[string][]finding.Finding, byAsset map[string][]finding.Finding, asset string, now time.Time) []finding.Finding {
	if !hasAny(byCheckID, xssCheckIDs...) {
		return nil
	}
	if !hasAny(byCheckID, csrfCheckIDs...) {
		return nil
	}

	xss := firstFinding(byCheckID, xssCheckIDs...)
	csrf := firstFinding(byCheckID, csrfCheckIDs...)

	// Check if XSS and CSRF are on the same asset for strongest signal.
	sameAsset := false
	for _, xssID := range xssCheckIDs {
		if assetHasCheckID(byAsset, xss.Asset, csrfCheckIDs...) {
			sameAsset = true
			break
		}
		_ = xssID
	}

	severity := finding.SeverityHigh
	desc := fmt.Sprintf(
		"A cross-site scripting vulnerability (%s on %s) was found alongside missing CSRF protection "+
			"(%s on %s). An attacker can use XSS to execute state-changing actions as the victim "+
			"(password change, email update, admin actions) since no CSRF token prevents cross-origin requests.",
		xss.CheckID, xss.Asset, csrf.CheckID, csrf.Asset)

	if sameAsset {
		severity = finding.SeverityCritical
		desc = fmt.Sprintf(
			"A cross-site scripting vulnerability (%s) and missing CSRF protection (%s) were found on the "+
				"same asset (%s). This is a direct account takeover chain: injected JavaScript can perform "+
				"any state-changing action (password reset, privilege escalation) as the authenticated victim "+
				"without CSRF token validation blocking the request.",
			xss.CheckID, csrf.CheckID, xss.Asset)
	}

	return []finding.Finding{{
		CheckID:     finding.CheckCorrelationXSSCSRFChain,
		Module:      "surface",
		Scanner:     scannerName,
		Severity:    severity,
		Title:       fmt.Sprintf("Attack chain: XSS + missing CSRF = account takeover on %s", asset),
		Description: desc,
		Asset:       asset,
		Evidence: map[string]any{
			"xss_check":   xss.CheckID,
			"xss_asset":   xss.Asset,
			"csrf_check":  csrf.CheckID,
			"csrf_asset":  csrf.Asset,
			"same_asset":  sameAsset,
			"chain_type":  "xss_csrf",
		},
		ProofCommand: fmt.Sprintf("# XSS proof:\n%s\n# CSRF proof:\n%s", xss.ProofCommand, csrf.ProofCommand),
		DiscoveredAt: now,
	}}
}

// ---------------------------------------------------------------------------
// Chain 3: Weak TLS + insecure cookies = session hijack
// ---------------------------------------------------------------------------

var weakTLSCheckIDs = []string{
	finding.CheckTLSProtocolTLS10,
	finding.CheckTLSProtocolTLS11,
	finding.CheckTLSProtocolSSLv2,
	finding.CheckTLSProtocolSSLv3,
	finding.CheckTLSWeakCipher,
	finding.CheckTLSNoPFS,
}

var insecureCookieCheckIDs = []string{
	finding.CheckCookieMissingSecure,
	finding.CheckCookieMissingHTTPOnly,
	finding.CheckCookieMissingSameSite,
}

func checkTLSSessionHijack(byCheckID map[string][]finding.Finding, byAsset map[string][]finding.Finding, asset string, now time.Time) []finding.Finding {
	if !hasAny(byCheckID, weakTLSCheckIDs...) {
		return nil
	}
	if !hasAny(byCheckID, insecureCookieCheckIDs...) {
		return nil
	}

	tls := firstFinding(byCheckID, weakTLSCheckIDs...)
	cookie := firstFinding(byCheckID, insecureCookieCheckIDs...)

	return []finding.Finding{{
		CheckID:  finding.CheckCorrelationTLSSessionHijack,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Title:    fmt.Sprintf("Attack chain: weak TLS + insecure cookies = session hijack on %s", asset),
		Description: fmt.Sprintf(
			"Weak TLS configuration (%s on %s) combined with insecure cookie attributes (%s on %s) "+
				"enables session hijacking. An attacker on the same network can downgrade the TLS "+
				"connection and intercept session cookies that lack Secure/HttpOnly/SameSite flags, "+
				"gaining full access to the victim's authenticated session.",
			tls.CheckID, tls.Asset, cookie.CheckID, cookie.Asset),
		Asset: asset,
		Evidence: map[string]any{
			"tls_check":    tls.CheckID,
			"tls_asset":    tls.Asset,
			"cookie_check": cookie.CheckID,
			"cookie_asset": cookie.Asset,
			"chain_type":   "tls_session_hijack",
		},
		ProofCommand: fmt.Sprintf("# TLS proof:\n%s\n# Cookie proof:\n%s", tls.ProofCommand, cookie.ProofCommand),
		DiscoveredAt: now,
	}}
}

// ---------------------------------------------------------------------------
// Chain 4: SSRF + cloud metadata accessible = IAM takeover
// ---------------------------------------------------------------------------

var ssrfCheckIDs = []string{
	finding.CheckWebSSRF,
	finding.CheckWebPDFSSRF,
	finding.CheckWebSSRFRedirectMetadata,
}

var cloudMetadataCheckIDs = []string{
	finding.CheckCloudMetadataSSRF,
}

func checkCloudMetadataChain(byCheckID map[string][]finding.Finding, asset string, now time.Time) []finding.Finding {
	// Direct cloud metadata SSRF is already critical on its own. But even
	// a generic SSRF finding in the presence of cloud infrastructure is
	// a strong signal that metadata exfiltration is possible.
	if !hasAny(byCheckID, ssrfCheckIDs...) {
		return nil
	}

	// Look for any cloud-related signals that indicate the target runs on
	// a cloud provider where 169.254.169.254 metadata is available.
	hasCloudSignal := hasAny(byCheckID, cloudMetadataCheckIDs...)
	if !hasCloudSignal {
		// Also check for cloud bucket findings as a proxy for cloud hosting.
		for id := range byCheckID {
			if strings.HasPrefix(id, "exposure.cloud") || strings.HasPrefix(id, "iam.") ||
				id == finding.CheckExposureCloudStorage || id == finding.CheckCloudBucketPublic {
				hasCloudSignal = true
				break
			}
		}
	}
	if !hasCloudSignal {
		return nil
	}

	ssrf := firstFinding(byCheckID, ssrfCheckIDs...)

	return []finding.Finding{{
		CheckID:  finding.CheckCorrelationCloudMetadataChain,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("Attack chain: SSRF + cloud infrastructure = IAM credential theft on %s", asset),
		Description: fmt.Sprintf(
			"A server-side request forgery vulnerability (%s on %s) was found on infrastructure with "+
				"cloud provider signals. An attacker can exploit the SSRF to reach the cloud instance "+
				"metadata endpoint (169.254.169.254) and extract IAM credentials, potentially gaining "+
				"full access to the cloud account's resources (S3 buckets, databases, secrets).",
			ssrf.CheckID, ssrf.Asset),
		Asset: asset,
		Evidence: map[string]any{
			"ssrf_check": ssrf.CheckID,
			"ssrf_asset": ssrf.Asset,
			"chain_type": "ssrf_cloud_metadata",
		},
		ProofCommand: fmt.Sprintf("# SSRF proof:\n%s\n# Then attempt metadata access:\ncurl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/", ssrf.ProofCommand),
		DiscoveredAt: now,
	}}
}

// ---------------------------------------------------------------------------
// Chain 5: Info disclosure + default creds = admin access
// ---------------------------------------------------------------------------

var infoDisclosureCheckIDs = []string{
	finding.CheckHeadersServerInfoLeak,
	finding.CheckExposureAdminPath,
	finding.CheckExposureMonitoringPanel,
	finding.CheckExposureCICDPanel,
	finding.CheckExposureSpringActuator,
}

var defaultCredsCheckIDs = []string{
	finding.CheckWebDefaultCredentials,
	finding.CheckPortMinIODefaultCreds,
	finding.CheckPortGrafanaDefaultCreds,
	finding.CheckPortSonarQubeDefaultCreds,
	finding.CheckPortAirflowDefaultCreds,
	finding.CheckPortTomcatDefaultCreds,
	finding.CheckPortPortainerDefaultCreds,
	finding.CheckPortRabbitMQDefaultCreds,
}

func checkCredentialReuse(byCheckID map[string][]finding.Finding, asset string, now time.Time) []finding.Finding {
	if !hasAny(byCheckID, infoDisclosureCheckIDs...) {
		return nil
	}
	if !hasAny(byCheckID, defaultCredsCheckIDs...) {
		return nil
	}

	info := firstFinding(byCheckID, infoDisclosureCheckIDs...)
	creds := firstFinding(byCheckID, defaultCredsCheckIDs...)

	return []finding.Finding{{
		CheckID:  finding.CheckCorrelationCredentialReuse,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("Attack chain: info disclosure + default credentials = admin access on %s", asset),
		Description: fmt.Sprintf(
			"Information disclosure (%s on %s) reveals infrastructure details, and default credentials "+
				"(%s on %s) provide authenticated access. Combined, an attacker can identify the exact "+
				"service version and log in with known default credentials to gain administrative control.",
			info.CheckID, info.Asset, creds.CheckID, creds.Asset),
		Asset: asset,
		Evidence: map[string]any{
			"info_check":  info.CheckID,
			"info_asset":  info.Asset,
			"creds_check": creds.CheckID,
			"creds_asset": creds.Asset,
			"chain_type":  "info_disclosure_default_creds",
		},
		ProofCommand: fmt.Sprintf("# Info disclosure:\n%s\n# Default creds:\n%s", info.ProofCommand, creds.ProofCommand),
		DiscoveredAt: now,
	}}
}

// ---------------------------------------------------------------------------
// Chain 6: Exposed .git + source code = secret extraction
// ---------------------------------------------------------------------------

var gitExposedCheckIDs = []string{
	finding.CheckExposureGitExposed,
}

var sensitiveFileCheckIDs = []string{
	finding.CheckExposureEnvFile,
	finding.CheckExposureSensitiveFile,
	finding.CheckExposureBackupFile,
}

func checkStagingToProdExposure(byCheckID map[string][]finding.Finding, asset string, now time.Time) []finding.Finding {
	if !hasAny(byCheckID, gitExposedCheckIDs...) {
		return nil
	}

	// .git exposure alone is high severity. Combined with env/sensitive files
	// it becomes a confirmed secret extraction chain.
	hasSensitive := hasAny(byCheckID, sensitiveFileCheckIDs...)

	// Also check for staging subdomain exposure as an amplifier.
	hasStaging := hasAny(byCheckID, finding.CheckExposureStagingSubdomain)

	if !hasSensitive && !hasStaging {
		return nil
	}

	git := firstFinding(byCheckID, gitExposedCheckIDs...)

	var secondCheck, secondAsset string
	if hasSensitive {
		f := firstFinding(byCheckID, sensitiveFileCheckIDs...)
		secondCheck = f.CheckID
		secondAsset = f.Asset
	} else {
		f := firstFinding(byCheckID, finding.CheckExposureStagingSubdomain)
		secondCheck = f.CheckID
		secondAsset = f.Asset
	}

	return []finding.Finding{{
		CheckID:  finding.CheckCorrelationStagingToProd,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Title:    fmt.Sprintf("Attack chain: exposed .git + sensitive files = secret extraction on %s", asset),
		Description: fmt.Sprintf(
			"An exposed .git directory (%s on %s) combined with sensitive file exposure (%s on %s) "+
				"enables full source code and secret extraction. An attacker can reconstruct the Git "+
				"repository, extract hardcoded API keys, database credentials, and internal service "+
				"URLs, then use those secrets to pivot into production systems.",
			git.CheckID, git.Asset, secondCheck, secondAsset),
		Asset: asset,
		Evidence: map[string]any{
			"git_check":    git.CheckID,
			"git_asset":    git.Asset,
			"second_check": secondCheck,
			"second_asset": secondAsset,
			"chain_type":   "git_secret_extraction",
		},
		ProofCommand: fmt.Sprintf("# Git exposure:\n%s\n# Sensitive file:\ncurl -sk 'https://%s/.env'", git.ProofCommand, git.Asset),
		DiscoveredAt: now,
	}}
}

// ---------------------------------------------------------------------------
// Chain 7: CORS misconfig + XSS + missing HttpOnly = session hijack
// ---------------------------------------------------------------------------

var corsCheckIDs = []string{
	finding.CheckCORSMisconfiguration,
	finding.CheckCORSNullOrigin,
	finding.CheckCORSPreflightMisconfig,
	finding.CheckCORSCredentialedReflection,
}

func checkSessionHijackChain(byCheckID map[string][]finding.Finding, asset string, now time.Time) []finding.Finding {
	if !hasAny(byCheckID, corsCheckIDs...) {
		return nil
	}
	if !hasAny(byCheckID, xssCheckIDs...) {
		return nil
	}
	if !hasAny(byCheckID, finding.CheckCookieMissingHTTPOnly) {
		return nil
	}

	cors := firstFinding(byCheckID, corsCheckIDs...)
	xss := firstFinding(byCheckID, xssCheckIDs...)
	cookie := firstFinding(byCheckID, finding.CheckCookieMissingHTTPOnly)

	enabledByParts := []string{
		fmt.Sprintf("%s|%s", cors.CheckID, cors.Asset),
		fmt.Sprintf("%s|%s", xss.CheckID, xss.Asset),
		fmt.Sprintf("%s|%s", cookie.CheckID, cookie.Asset),
	}

	return []finding.Finding{{
		CheckID:  finding.CheckCorrelationSessionHijackChain,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("Attack chain: CORS + XSS + missing HttpOnly = session hijack on %s", asset),
		Description: fmt.Sprintf(
			"A CORS misconfiguration (%s on %s) allows cross-origin requests with credentials. "+
				"Combined with a cross-site scripting vulnerability (%s on %s) and session cookies "+
				"missing the HttpOnly flag (%s on %s), an attacker can: (1) host a malicious page that "+
				"makes credentialed cross-origin requests, (2) inject JavaScript via XSS to read "+
				"document.cookie, (3) exfiltrate the session token to their server. This is a complete "+
				"session hijack chain requiring no user interaction beyond visiting a crafted URL.",
			cors.CheckID, cors.Asset, xss.CheckID, xss.Asset, cookie.CheckID, cookie.Asset),
		Asset:      asset,
		EnabledBy:  strings.Join(enabledByParts, ", "),
		ChainDepth: 3,
		Evidence: map[string]any{
			"cors_check":   cors.CheckID,
			"cors_asset":   cors.Asset,
			"xss_check":    xss.CheckID,
			"xss_asset":    xss.Asset,
			"cookie_check": cookie.CheckID,
			"cookie_asset": cookie.Asset,
			"chain_type":   "session_hijack",
		},
		ProofCommand: fmt.Sprintf("# CORS proof:\ncurl -sI -H 'Origin: https://evil.com' '%s'\n# XSS proof:\n%s\n# Cookie proof:\ncurl -sI '%s' | grep -i set-cookie",
			cors.Asset, xss.ProofCommand, cookie.Asset),
		DiscoveredAt: now,
	}}
}

// ---------------------------------------------------------------------------
// Chain 8: Exposed .env/config or .git + secrets = credential theft
// ---------------------------------------------------------------------------

var envExposureCheckIDs = []string{
	finding.CheckExposureEnvFile,
	finding.CheckExposureSensitiveFile,
	finding.CheckExposureBackupFile,
}

func checkCredentialTheftChain(byCheckID map[string][]finding.Finding, asset string, now time.Time) []finding.Finding {
	// Path A: exposed .env/config + database port exposed → direct DB access
	hasEnv := hasAny(byCheckID, envExposureCheckIDs...)
	hasDB := hasAny(byCheckID, finding.CheckPortDatabaseExposed)

	// Path B: exposed .git + sensitive files → credential harvest from repo
	hasGit := hasAny(byCheckID, finding.CheckExposureGitExposed)
	hasSensitive := hasAny(byCheckID, envExposureCheckIDs...)

	if !((hasEnv && hasDB) || (hasGit && hasSensitive)) { //nolint:staticcheck
		return nil
	}

	var primary, secondary finding.Finding
	var chainVariant string
	if hasEnv && hasDB {
		primary = firstFinding(byCheckID, envExposureCheckIDs...)
		secondary = firstFinding(byCheckID, finding.CheckPortDatabaseExposed)
		chainVariant = "env_plus_database"
	} else {
		primary = firstFinding(byCheckID, finding.CheckExposureGitExposed)
		secondary = firstFinding(byCheckID, envExposureCheckIDs...)
		chainVariant = "git_plus_secrets"
	}

	enabledByParts := []string{
		fmt.Sprintf("%s|%s", primary.CheckID, primary.Asset),
		fmt.Sprintf("%s|%s", secondary.CheckID, secondary.Asset),
	}

	var desc string
	if chainVariant == "env_plus_database" {
		desc = fmt.Sprintf(
			"An exposed configuration file (%s on %s) likely contains database credentials, and a "+
				"database port is directly accessible (%s on %s). An attacker can read credentials from "+
				"the exposed file and connect directly to the database for full data exfiltration.",
			primary.CheckID, primary.Asset, secondary.CheckID, secondary.Asset)
	} else {
		desc = fmt.Sprintf(
			"An exposed .git directory (%s on %s) combined with sensitive file exposure (%s on %s) "+
				"enables credential harvesting. An attacker can reconstruct the Git repository history, "+
				"extract hardcoded secrets (API keys, database passwords, cloud credentials), and use "+
				"them to access backend systems.",
			primary.CheckID, primary.Asset, secondary.CheckID, secondary.Asset)
	}

	return []finding.Finding{{
		CheckID:    finding.CheckCorrelationCredentialTheftChain,
		Module:     "surface",
		Scanner:    scannerName,
		Severity:   finding.SeverityCritical,
		Title:      fmt.Sprintf("Attack chain: credential theft via %s on %s", chainVariant, asset),
		Description: desc,
		Asset:      asset,
		EnabledBy:  strings.Join(enabledByParts, ", "),
		ChainDepth: 2,
		Evidence: map[string]any{
			"primary_check":   primary.CheckID,
			"primary_asset":   primary.Asset,
			"secondary_check": secondary.CheckID,
			"secondary_asset": secondary.Asset,
			"chain_variant":   chainVariant,
			"chain_type":      "credential_theft",
		},
		ProofCommand: fmt.Sprintf("# Primary:\n%s\n# Secondary:\n%s", primary.ProofCommand, secondary.ProofCommand),
		DiscoveredAt: now,
	}}
}

// ---------------------------------------------------------------------------
// Chain 9: SQLi + exposed DB or SSRF + cloud metadata = full compromise
// ---------------------------------------------------------------------------

func checkFullCompromiseChain(byCheckID map[string][]finding.Finding, asset string, now time.Time) []finding.Finding {
	// Path A: SQLi + database exposed → data exfiltration
	hasSQLi := hasAny(byCheckID, finding.CheckWebSQLi)
	hasDBExposed := hasAny(byCheckID, finding.CheckPortDatabaseExposed)

	// Path B: SSRF + cloud metadata → IAM credential theft → cloud takeover
	// (This is distinct from chain 4 because it specifically looks for the
	// direct cloud metadata SSRF finding, indicating confirmed exploitation.)
	hasSSRF := hasAny(byCheckID, ssrfCheckIDs...)
	hasCloudMeta := hasAny(byCheckID, finding.CheckCloudMetadataSSRF)

	if !((hasSQLi && hasDBExposed) || (hasSSRF && hasCloudMeta)) { //nolint:staticcheck
		return nil
	}

	var primary, secondary finding.Finding
	var chainVariant string
	if hasSQLi && hasDBExposed {
		primary = firstFinding(byCheckID, finding.CheckWebSQLi)
		secondary = firstFinding(byCheckID, finding.CheckPortDatabaseExposed)
		chainVariant = "sqli_plus_database"
	} else {
		primary = firstFinding(byCheckID, ssrfCheckIDs...)
		secondary = firstFinding(byCheckID, finding.CheckCloudMetadataSSRF)
		chainVariant = "ssrf_plus_cloud_takeover"
	}

	enabledByParts := []string{
		fmt.Sprintf("%s|%s", primary.CheckID, primary.Asset),
		fmt.Sprintf("%s|%s", secondary.CheckID, secondary.Asset),
	}

	var desc string
	if chainVariant == "sqli_plus_database" {
		desc = fmt.Sprintf(
			"A SQL injection vulnerability (%s on %s) combined with a directly accessible database "+
				"(%s on %s) enables complete data exfiltration. The attacker can extract credentials "+
				"via SQLi and then connect directly to the exposed database for bulk data theft, or "+
				"use the SQLi to read/write arbitrary data including other users' credentials.",
			primary.CheckID, primary.Asset, secondary.CheckID, secondary.Asset)
	} else {
		desc = fmt.Sprintf(
			"A server-side request forgery vulnerability (%s on %s) combined with confirmed cloud "+
				"metadata access (%s on %s) enables full cloud account takeover. The attacker can "+
				"extract IAM credentials from the metadata endpoint and use them to access S3 buckets, "+
				"databases, secrets managers, and potentially pivot to other cloud services.",
			primary.CheckID, primary.Asset, secondary.CheckID, secondary.Asset)
	}

	return []finding.Finding{{
		CheckID:    finding.CheckCorrelationFullCompromiseChain,
		Module:     "surface",
		Scanner:    scannerName,
		Severity:   finding.SeverityCritical,
		Title:      fmt.Sprintf("Attack chain: full compromise via %s on %s", chainVariant, asset),
		Description: desc,
		Asset:      asset,
		EnabledBy:  strings.Join(enabledByParts, ", "),
		ChainDepth: 2,
		Evidence: map[string]any{
			"primary_check":   primary.CheckID,
			"primary_asset":   primary.Asset,
			"secondary_check": secondary.CheckID,
			"secondary_asset": secondary.Asset,
			"chain_variant":   chainVariant,
			"chain_type":      "full_compromise",
		},
		ProofCommand: fmt.Sprintf("# Primary:\n%s\n# Secondary:\n%s", primary.ProofCommand, secondary.ProofCommand),
		DiscoveredAt: now,
	}}
}

// ---------------------------------------------------------------------------
// Chain 10: JWT weak algorithm + no rotation OR default creds + admin panel = auth bypass
// ---------------------------------------------------------------------------

var jwtWeakCheckIDs = []string{
	finding.CheckJWTWeakAlg,
	finding.CheckJWTAlgNoneVariant,
	finding.CheckJWTEmptySecret,
	finding.CheckJWTAlgorithmConfusion,
	finding.CheckJWTNoVerification,
}

var jwtNoRotationCheckIDs = []string{
	finding.CheckJWTReplayMissing,
	finding.CheckJWTLongExpiry,
}

func checkAuthBypassChain(byCheckID map[string][]finding.Finding, asset string, now time.Time) []finding.Finding {
	// Path A: JWT weak algorithm + no token rotation → persistent unauth access
	hasJWTWeak := hasAny(byCheckID, jwtWeakCheckIDs...)
	hasNoRotation := hasAny(byCheckID, jwtNoRotationCheckIDs...)

	// Path B: default credentials + admin panel exposed → full app control
	hasDefaultCreds := hasAny(byCheckID, defaultCredsCheckIDs...)
	hasAdminPanel := hasAny(byCheckID, finding.CheckExposureAdminPath, finding.CheckExposureMonitoringPanel, finding.CheckExposureCICDPanel)

	if !((hasJWTWeak && hasNoRotation) || (hasDefaultCreds && hasAdminPanel)) { //nolint:staticcheck
		return nil
	}

	var primary, secondary finding.Finding
	var chainVariant string
	if hasJWTWeak && hasNoRotation {
		primary = firstFinding(byCheckID, jwtWeakCheckIDs...)
		secondary = firstFinding(byCheckID, jwtNoRotationCheckIDs...)
		chainVariant = "jwt_weak_plus_no_rotation"
	} else {
		primary = firstFinding(byCheckID, defaultCredsCheckIDs...)
		secondary = firstFinding(byCheckID, finding.CheckExposureAdminPath, finding.CheckExposureMonitoringPanel, finding.CheckExposureCICDPanel)
		chainVariant = "default_creds_plus_admin"
	}

	enabledByParts := []string{
		fmt.Sprintf("%s|%s", primary.CheckID, primary.Asset),
		fmt.Sprintf("%s|%s", secondary.CheckID, secondary.Asset),
	}

	var desc string
	if chainVariant == "jwt_weak_plus_no_rotation" {
		desc = fmt.Sprintf(
			"A JWT weakness (%s on %s) allows token forgery, and the lack of token rotation "+
				"(%s on %s) means forged tokens remain valid indefinitely. An attacker can craft "+
				"arbitrary JWT tokens with any claims (admin role, any user ID) and maintain "+
				"persistent unauthorized access without detection.",
			primary.CheckID, primary.Asset, secondary.CheckID, secondary.Asset)
	} else {
		desc = fmt.Sprintf(
			"Default credentials (%s on %s) provide initial access, and an exposed admin panel "+
				"(%s on %s) gives full application control. The attacker logs in with known default "+
				"credentials and gains administrative access to manage users, data, and configuration.",
			primary.CheckID, primary.Asset, secondary.CheckID, secondary.Asset)
	}

	return []finding.Finding{{
		CheckID:    finding.CheckCorrelationAuthBypassChain,
		Module:     "surface",
		Scanner:    scannerName,
		Severity:   finding.SeverityHigh,
		Title:      fmt.Sprintf("Attack chain: auth bypass via %s on %s", chainVariant, asset),
		Description: desc,
		Asset:      asset,
		EnabledBy:  strings.Join(enabledByParts, ", "),
		ChainDepth: 2,
		Evidence: map[string]any{
			"primary_check":   primary.CheckID,
			"primary_asset":   primary.Asset,
			"secondary_check": secondary.CheckID,
			"secondary_asset": secondary.Asset,
			"chain_variant":   chainVariant,
			"chain_type":      "auth_bypass",
		},
		ProofCommand: fmt.Sprintf("# Primary:\n%s\n# Secondary:\n%s", primary.ProofCommand, secondary.ProofCommand),
		DiscoveredAt: now,
	}}
}

// ---------------------------------------------------------------------------
// Chain 11: Host header injection + cache OR unkeyed header + XSS = cache poisoning
// ---------------------------------------------------------------------------

func checkCachePoisoningChain(byCheckID map[string][]finding.Finding, asset string, now time.Time) []finding.Finding {
	// Path A: Host header injection + cache detected → mass user redirect
	hasHostInjection := hasAny(byCheckID, finding.CheckHostHeaderInjection)
	hasCache := hasAny(byCheckID, finding.CheckCacheBehaviorDetected, finding.CheckCacheHostRouting)

	// Path B: Unkeyed header + XSS → stored XSS via cache
	hasUnkeyed := hasAny(byCheckID, finding.CheckCachePoisonUnkeyed)
	hasXSS := hasAny(byCheckID, xssCheckIDs...)

	if !((hasHostInjection && hasCache) || (hasUnkeyed && hasXSS)) {  //nolint:staticcheck
		return nil
	}

	var primary, secondary finding.Finding
	var chainVariant string
	if hasHostInjection && hasCache {
		primary = firstFinding(byCheckID, finding.CheckHostHeaderInjection)
		secondary = firstFinding(byCheckID, finding.CheckCacheBehaviorDetected, finding.CheckCacheHostRouting)
		chainVariant = "host_injection_plus_cache"
	} else {
		primary = firstFinding(byCheckID, finding.CheckCachePoisonUnkeyed)
		secondary = firstFinding(byCheckID, xssCheckIDs...)
		chainVariant = "unkeyed_header_plus_xss"
	}

	enabledByParts := []string{
		fmt.Sprintf("%s|%s", primary.CheckID, primary.Asset),
		fmt.Sprintf("%s|%s", secondary.CheckID, secondary.Asset),
	}

	var desc string
	if chainVariant == "host_injection_plus_cache" {
		desc = fmt.Sprintf(
			"A Host header injection vulnerability (%s on %s) combined with a caching layer "+
				"(%s on %s) enables cache poisoning. An attacker can inject a malicious Host header "+
				"that gets cached by the CDN/proxy, causing all subsequent users to be redirected to "+
				"a phishing site or served malicious content. This is a mass-impact attack affecting "+
				"every user who hits the poisoned cache entry.",
			primary.CheckID, primary.Asset, secondary.CheckID, secondary.Asset)
	} else {
		desc = fmt.Sprintf(
			"A cache poisoning vulnerability via unkeyed header (%s on %s) combined with XSS "+
				"(%s on %s) enables stored cross-site scripting through the cache. An attacker "+
				"sends a request with an XSS payload in an unkeyed header, the response containing "+
				"the reflected payload is cached, and every subsequent user receives the cached XSS "+
				"payload — effectively converting reflected XSS into stored XSS at scale.",
			primary.CheckID, primary.Asset, secondary.CheckID, secondary.Asset)
	}

	return []finding.Finding{{
		CheckID:    finding.CheckCorrelationCachePoisoningChain,
		Module:     "surface",
		Scanner:    scannerName,
		Severity:   finding.SeverityHigh,
		Title:      fmt.Sprintf("Attack chain: cache poisoning via %s on %s", chainVariant, asset),
		Description: desc,
		Asset:      asset,
		EnabledBy:  strings.Join(enabledByParts, ", "),
		ChainDepth: 2,
		Evidence: map[string]any{
			"primary_check":   primary.CheckID,
			"primary_asset":   primary.Asset,
			"secondary_check": secondary.CheckID,
			"secondary_asset": secondary.Asset,
			"chain_variant":   chainVariant,
			"chain_type":      "cache_poisoning",
		},
		ProofCommand: fmt.Sprintf("# Primary:\n%s\n# Secondary:\n%s", primary.ProofCommand, secondary.ProofCommand),
		DiscoveredAt: now,
	}}
}

// ---------------------------------------------------------------------------
// Chain 12: Unauthenticated service + web app = lateral movement
// ---------------------------------------------------------------------------

var unauthServiceCheckIDs = []string{
	finding.CheckPortRedisUnauth,
	finding.CheckPortElasticsearchUnauth,
	finding.CheckPortMemcachedUnauth,
	finding.CheckPortCouchDBUnauth,
	finding.CheckPortDockerUnauth,
	finding.CheckPortKubeletUnauth,
	finding.CheckPortPrometheusUnauth,
}

var webVulnCheckIDs = []string{
	finding.CheckWebXSS,
	finding.CheckWebReflectedXSS,
	finding.CheckWebSQLi,
	finding.CheckWebSSRF,
	finding.CheckWebDefaultCredentials,
}

func checkLateralMovementChain(byCheckID map[string][]finding.Finding, asset string, now time.Time) []finding.Finding {
	if !hasAny(byCheckID, unauthServiceCheckIDs...) {
		return nil
	}
	if !hasAny(byCheckID, webVulnCheckIDs...) {
		return nil
	}

	service := firstFinding(byCheckID, unauthServiceCheckIDs...)
	webVuln := firstFinding(byCheckID, webVulnCheckIDs...)

	enabledByParts := []string{
		fmt.Sprintf("%s|%s", webVuln.CheckID, webVuln.Asset),
		fmt.Sprintf("%s|%s", service.CheckID, service.Asset),
	}

	return []finding.Finding{{
		CheckID:  finding.CheckCorrelationLateralMovementChain,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("Attack chain: lateral movement from web vuln to %s on %s", service.CheckID, asset),
		Description: fmt.Sprintf(
			"A web application vulnerability (%s on %s) exists alongside an unauthenticated data store "+
				"(%s on %s). If these services share a network, an attacker can exploit the web vulnerability "+
				"to pivot into the unauthenticated service, reading or modifying data in Redis, Elasticsearch, "+
				"or other backends. SSRF is particularly dangerous here as it enables direct internal access, "+
				"but even XSS/SQLi on the same infrastructure suggests shared-network exposure.",
			webVuln.CheckID, webVuln.Asset, service.CheckID, service.Asset),
		Asset:      asset,
		EnabledBy:  strings.Join(enabledByParts, ", "),
		ChainDepth: 2,
		Evidence: map[string]any{
			"web_vuln_check":  webVuln.CheckID,
			"web_vuln_asset":  webVuln.Asset,
			"service_check":   service.CheckID,
			"service_asset":   service.Asset,
			"chain_type":      "lateral_movement",
		},
		ProofCommand: fmt.Sprintf("# Web vuln:\n%s\n# Unauthenticated service:\n%s", webVuln.ProofCommand, service.ProofCommand),
		DiscoveredAt: now,
	}}
}

// ---------------------------------------------------------------------------
// Chain 13: DNS rebinding + internal services = network bypass
// ---------------------------------------------------------------------------

func checkDNSRebindingChain(byCheckID map[string][]finding.Finding, asset string, now time.Time) []finding.Finding {
	if !hasAny(byCheckID, finding.CheckDNSRebindHostUnvalidated, finding.CheckDNSRebindingVulnerable) {
		return nil
	}

	// Look for any internal service indicators: unauthenticated services,
	// database ports, or SSRF findings that suggest internal reachability.
	hasInternalService := hasAny(byCheckID, unauthServiceCheckIDs...)
	hasDBExposed := hasAny(byCheckID, finding.CheckPortDatabaseExposed)
	hasSSRF := hasAny(byCheckID, ssrfCheckIDs...)

	if !hasInternalService && !hasDBExposed && !hasSSRF {
		return nil
	}

	rebind := firstFinding(byCheckID, finding.CheckDNSRebindHostUnvalidated, finding.CheckDNSRebindingVulnerable)

	var secondary finding.Finding
	if hasInternalService {
		secondary = firstFinding(byCheckID, unauthServiceCheckIDs...)
	} else if hasDBExposed {
		secondary = firstFinding(byCheckID, finding.CheckPortDatabaseExposed)
	} else {
		secondary = firstFinding(byCheckID, ssrfCheckIDs...)
	}

	enabledByParts := []string{
		fmt.Sprintf("%s|%s", rebind.CheckID, rebind.Asset),
		fmt.Sprintf("%s|%s", secondary.CheckID, secondary.Asset),
	}

	return []finding.Finding{{
		CheckID:  finding.CheckCorrelationDNSRebindingChain,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("Attack chain: DNS rebinding + internal services = network bypass on %s", asset),
		Description: fmt.Sprintf(
			"A DNS rebinding vulnerability (%s on %s) allows an attacker to bypass same-origin policy "+
				"and network restrictions. Combined with internal services (%s on %s), the attacker can "+
				"craft a page that initially resolves to their server, then rebinds to an internal IP, "+
				"gaining JavaScript-level access to internal services that should be unreachable from "+
				"the internet. This bypasses firewalls, VPNs, and network segmentation.",
			rebind.CheckID, rebind.Asset, secondary.CheckID, secondary.Asset),
		Asset:      asset,
		EnabledBy:  strings.Join(enabledByParts, ", "),
		ChainDepth: 2,
		Evidence: map[string]any{
			"rebind_check":    rebind.CheckID,
			"rebind_asset":    rebind.Asset,
			"service_check":   secondary.CheckID,
			"service_asset":   secondary.Asset,
			"chain_type":      "dns_rebinding",
		},
		ProofCommand: fmt.Sprintf("# DNS rebinding:\n%s\n# Internal service:\n%s", rebind.ProofCommand, secondary.ProofCommand),
		DiscoveredAt: now,
	}}
}
