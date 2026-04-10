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

		// v2 expanded chains
		scan.Check(finding.CheckCorrelationSSRFCloudIAMChain, finding.SeverityCritical, finding.ModeSurface),
		scan.Check(finding.CheckCorrelationDefaultCredsRCEChain, finding.SeverityCritical, finding.ModeSurface),
		scan.Check(finding.CheckCorrelationInfoDisclosureLateralChain, finding.SeverityCritical, finding.ModeSurface),
		scan.Check(finding.CheckCorrelationJWTAuthBypassChain, finding.SeverityCritical, finding.ModeSurface),
		scan.Check(finding.CheckCorrelationOpenRedirectOAuthChain, finding.SeverityHigh, finding.ModeSurface),
		scan.Check(finding.CheckCorrelationSubdomainTakeoverSessionChain, finding.SeverityCritical, finding.ModeSurface),
		scan.Check(finding.CheckCorrelationWeakTLSCredInterceptChain, finding.SeverityHigh, finding.ModeSurface),
		scan.Check(finding.CheckCorrelationContainerEscapeChain, finding.SeverityCritical, finding.ModeSurface),
		scan.Check(finding.CheckCorrelationEmailSpoofPhishChain, finding.SeverityHigh, finding.ModeSurface),
		scan.Check(finding.CheckCorrelationVersionCVEMatchChain, finding.SeverityHigh, finding.ModeSurface),
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

	// Chain 14: SSRF → cloud metadata → IAM escalation (distinct from chain 4 — requires metadata + SSRF specifically for IAM path)
	results = append(results, checkSSRFCloudIAMChain(byCheckID, asset, now)...)

	// Chain 15: Default creds → admin panel → RCE on same host
	results = append(results, checkDefaultCredsRCEChain(byCheckID, byAsset, asset, now)...)

	// Chain 16: Info disclosure → credential harvest → lateral movement
	results = append(results, checkInfoDisclosureLateralChain(byCheckID, asset, now)...)

	// Chain 17: JWT weakness → forged token → API data access
	results = append(results, checkJWTAuthBypassChain(byCheckID, asset, now)...)

	// Chain 18: Open redirect → OAuth token theft
	results = append(results, checkOpenRedirectOAuthChain(byCheckID, asset, now)...)

	// Chain 19: Subdomain takeover → cookie injection → session hijack
	results = append(results, checkSubdomainTakeoverSessionChain(byCheckID, asset, now)...)

	// Chain 20: Weak TLS + auth service → MitM credential interception
	results = append(results, checkWeakTLSCredInterceptChain(byCheckID, asset, now)...)

	// Chain 21: Container escape → host compromise
	results = append(results, checkContainerEscapeChain(byCheckID, asset, now)...)

	// Chain 22: Email spoofing → phishing → credential harvest
	results = append(results, checkEmailSpoofPhishChain(byCheckID, asset, now)...)

	// Chain 23: Version disclosure → known CVE match
	results = append(results, checkVersionCVEMatchChain(byCheckID, asset, now)...)

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

// ---------------------------------------------------------------------------
// Chain 14: SSRF → Cloud Metadata → IAM Escalation
// Distinct from chain 4: this specifically detects the full escalation path
// where SSRF reaches metadata AND there's evidence of IAM/cloud resources.
// ---------------------------------------------------------------------------

func checkSSRFCloudIAMChain(byCheckID map[string][]finding.Finding, asset string, now time.Time) []finding.Finding {
	if !hasAny(byCheckID, ssrfCheckIDs...) {
		return nil
	}

	// Require direct cloud metadata SSRF evidence (not just generic cloud signals).
	if !hasAny(byCheckID, finding.CheckCloudMetadataSSRF) {
		return nil
	}

	// Look for IAM or cloud resource findings that confirm escalation potential.
	hasIAMSignal := false
	for id := range byCheckID {
		if strings.HasPrefix(id, "iam.") || id == finding.CheckExposureCloudStorage ||
			id == finding.CheckCloudBucketPublic || strings.HasPrefix(id, "exposure.cloud") {
			hasIAMSignal = true
			break
		}
	}
	if !hasIAMSignal {
		return nil
	}

	ssrf := firstFinding(byCheckID, ssrfCheckIDs...)
	meta := firstFinding(byCheckID, finding.CheckCloudMetadataSSRF)

	enabledByParts := []string{
		fmt.Sprintf("%s|%s", ssrf.CheckID, ssrf.Asset),
		fmt.Sprintf("%s|%s", meta.CheckID, meta.Asset),
	}

	return []finding.Finding{{
		CheckID:  finding.CheckCorrelationSSRFCloudIAMChain,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("Attack chain: SSRF → cloud metadata → IAM escalation on %s", asset),
		Description: fmt.Sprintf(
			"SSRF vulnerability (%s on %s) allows accessing the cloud metadata service (%s on %s), "+
				"and IAM/cloud resource findings confirm escalation potential. An attacker can: "+
				"(1) exploit the SSRF to reach 169.254.169.254, (2) extract IAM temporary credentials, "+
				"(3) use those credentials to enumerate and access cloud resources (S3, RDS, Secrets Manager), "+
				"(4) potentially escalate to cloud admin via overly permissive IAM roles.",
			ssrf.CheckID, ssrf.Asset, meta.CheckID, meta.Asset),
		Asset:      asset,
		EnabledBy:  strings.Join(enabledByParts, ", "),
		ChainDepth: 3,
		Evidence: map[string]any{
			"ssrf_check":     ssrf.CheckID,
			"ssrf_asset":     ssrf.Asset,
			"metadata_check": meta.CheckID,
			"metadata_asset": meta.Asset,
			"chain_type":     "ssrf_cloud_iam_escalation",
		},
		ProofCommand: fmt.Sprintf(
			"# Step 1 — SSRF to metadata:\n%s\n"+
				"# Step 2 — Extract IAM credentials:\ncurl -s 'SSRF_ENDPOINT?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/'\n"+
				"# Step 3 — Use stolen creds:\nexport AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...\n"+
				"aws sts get-caller-identity\naws s3 ls",
			ssrf.ProofCommand),
		DiscoveredAt: now,
	}}
}

// ---------------------------------------------------------------------------
// Chain 15: Default Creds → Admin Panel → RCE
// ---------------------------------------------------------------------------

var rceCheckIDs = []string{
	finding.CheckCVELog4Shell,
	finding.CheckCVEN8nRCE,
	finding.CheckCVECraftCMSRCE,
	finding.CheckCVELivewireRCE,
	finding.CheckCVEBeyondTrustRCE,
	finding.CheckCVESolarWindsWHD,
	finding.CheckCVELangflowRCE,
	finding.CheckCVECiscoFMCRCE,
	finding.CheckCVEHPEOneViewRCE,
	finding.CheckCVECiscoASARCE,
	finding.CheckCVEErlangOTPSSH,
}

var adminPanelCheckIDs = []string{
	finding.CheckExposureAdminPath,
	finding.CheckExposureMonitoringPanel,
	finding.CheckExposureCICDPanel,
	finding.CheckExposureSpringActuator,
}

func checkDefaultCredsRCEChain(byCheckID map[string][]finding.Finding, byAsset map[string][]finding.Finding, asset string, now time.Time) []finding.Finding {
	if !hasAny(byCheckID, defaultCredsCheckIDs...) {
		return nil
	}
	if !hasAny(byCheckID, adminPanelCheckIDs...) {
		return nil
	}

	// Look for any RCE-class CVE on same host or any host.
	hasRCE := hasAny(byCheckID, rceCheckIDs...)
	// Also check for generic command injection.
	if !hasRCE {
		for id := range byCheckID {
			if strings.Contains(id, "_rce") || strings.Contains(id, "command_injection") {
				hasRCE = true
				break
			}
		}
	}
	if !hasRCE {
		return nil
	}

	creds := firstFinding(byCheckID, defaultCredsCheckIDs...)
	admin := firstFinding(byCheckID, adminPanelCheckIDs...)

	// Find the RCE finding.
	var rceFinding finding.Finding
	for _, id := range rceCheckIDs {
		if fs := byCheckID[id]; len(fs) > 0 {
			rceFinding = fs[0]
			break
		}
	}
	if rceFinding.CheckID == "" {
		for id, fs := range byCheckID {
			if (strings.Contains(id, "_rce") || strings.Contains(id, "command_injection")) && len(fs) > 0 {
				rceFinding = fs[0]
				break
			}
		}
	}

	enabledByParts := []string{
		fmt.Sprintf("%s|%s", creds.CheckID, creds.Asset),
		fmt.Sprintf("%s|%s", admin.CheckID, admin.Asset),
		fmt.Sprintf("%s|%s", rceFinding.CheckID, rceFinding.Asset),
	}

	// Stronger signal if findings share the same asset.
	sameHost := creds.Asset == admin.Asset || creds.Asset == rceFinding.Asset
	_ = sameHost

	return []finding.Finding{{
		CheckID:  finding.CheckCorrelationDefaultCredsRCEChain,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("Attack chain: default creds → admin panel → RCE on %s", asset),
		Description: fmt.Sprintf(
			"Default credentials (%s on %s) grant access to an admin panel (%s on %s), "+
				"and an RCE vulnerability (%s on %s) exists on the same infrastructure. "+
				"An attacker can: (1) log in with default credentials, (2) access the admin panel "+
				"to gain elevated privileges, (3) exploit the RCE vulnerability for full server compromise "+
				"including reverse shell, data exfiltration, and lateral movement.",
			creds.CheckID, creds.Asset, admin.CheckID, admin.Asset, rceFinding.CheckID, rceFinding.Asset),
		Asset:      asset,
		EnabledBy:  strings.Join(enabledByParts, ", "),
		ChainDepth: 3,
		Evidence: map[string]any{
			"creds_check": creds.CheckID,
			"creds_asset": creds.Asset,
			"admin_check": admin.CheckID,
			"admin_asset": admin.Asset,
			"rce_check":   rceFinding.CheckID,
			"rce_asset":   rceFinding.Asset,
			"chain_type":  "default_creds_admin_rce",
		},
		ProofCommand: fmt.Sprintf(
			"# Step 1 — Default credentials:\n%s\n"+
				"# Step 2 — Admin panel access:\n%s\n"+
				"# Step 3 — RCE exploitation:\n%s",
			creds.ProofCommand, admin.ProofCommand, rceFinding.ProofCommand),
		DiscoveredAt: now,
	}}
}

// ---------------------------------------------------------------------------
// Chain 16: Info Disclosure → Credential Harvest → Lateral Movement
// ---------------------------------------------------------------------------

var infoDisclosureCredsCheckIDs = []string{
	finding.CheckExposureEnvFile,
	finding.CheckExposureGitExposed,
	finding.CheckWebDebugEndpoint,
	finding.CheckExposureSensitiveFile,
	finding.CheckExposureBackupFile,
	finding.CheckPortDjangoDebugMode,
	finding.CheckPortExpressDebugExposed,
}

func checkInfoDisclosureLateralChain(byCheckID map[string][]finding.Finding, asset string, now time.Time) []finding.Finding {
	if !hasAny(byCheckID, infoDisclosureCredsCheckIDs...) {
		return nil
	}

	// Need evidence that the disclosed info leads somewhere: exposed database,
	// unauthenticated services, or multiple services on same infra.
	hasLateralTarget := hasAny(byCheckID, finding.CheckPortDatabaseExposed)
	if !hasLateralTarget {
		hasLateralTarget = hasAny(byCheckID, unauthServiceCheckIDs...)
	}
	if !hasLateralTarget {
		return nil
	}

	disclosure := firstFinding(byCheckID, infoDisclosureCredsCheckIDs...)

	var target finding.Finding
	if hasAny(byCheckID, finding.CheckPortDatabaseExposed) {
		target = firstFinding(byCheckID, finding.CheckPortDatabaseExposed)
	} else {
		target = firstFinding(byCheckID, unauthServiceCheckIDs...)
	}

	enabledByParts := []string{
		fmt.Sprintf("%s|%s", disclosure.CheckID, disclosure.Asset),
		fmt.Sprintf("%s|%s", target.CheckID, target.Asset),
	}

	return []finding.Finding{{
		CheckID:  finding.CheckCorrelationInfoDisclosureLateralChain,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("Attack chain: info disclosure → credential harvest → lateral movement on %s", asset),
		Description: fmt.Sprintf(
			"An exposed configuration source (%s on %s) likely contains database or service credentials, "+
				"and an accessible backend service (%s on %s) provides a lateral movement target. "+
				"An attacker can: (1) fetch the exposed config file to harvest credentials, "+
				"(2) use extracted credentials to authenticate to the backend service, "+
				"(3) access or exfiltrate data from the internal data tier.",
			disclosure.CheckID, disclosure.Asset, target.CheckID, target.Asset),
		Asset:      asset,
		EnabledBy:  strings.Join(enabledByParts, ", "),
		ChainDepth: 3,
		Evidence: map[string]any{
			"disclosure_check": disclosure.CheckID,
			"disclosure_asset": disclosure.Asset,
			"target_check":     target.CheckID,
			"target_asset":     target.Asset,
			"chain_type":       "info_disclosure_lateral_movement",
		},
		ProofCommand: fmt.Sprintf(
			"# Step 1 — Fetch exposed config:\n%s\n"+
				"# Step 2 — Extract credentials from response (look for DATABASE_URL, passwords, API keys)\n"+
				"# Step 3 — Connect to backend:\n%s",
			disclosure.ProofCommand, target.ProofCommand),
		DiscoveredAt: now,
	}}
}

// ---------------------------------------------------------------------------
// Chain 17: JWT Weakness → Authentication Bypass → Data Access
// ---------------------------------------------------------------------------

func checkJWTAuthBypassChain(byCheckID map[string][]finding.Finding, asset string, now time.Time) []finding.Finding {
	if !hasAny(byCheckID, jwtWeakCheckIDs...) {
		return nil
	}

	// Look for API endpoints or auth-related findings that indicate data behind auth.
	hasAuthTarget := false
	for id := range byCheckID {
		if strings.HasPrefix(id, "auth.") || strings.HasPrefix(id, "oauth.") ||
			strings.HasPrefix(id, "exposure.") || id == finding.CheckExposureAdminPath {
			hasAuthTarget = true
			break
		}
	}
	if !hasAuthTarget {
		return nil
	}

	jwt := firstFinding(byCheckID, jwtWeakCheckIDs...)

	algDesc := "weak algorithm"
	switch jwt.CheckID {
	case finding.CheckJWTAlgNoneVariant:
		algDesc = "alg:none accepted"
	case finding.CheckJWTEmptySecret:
		algDesc = "empty signing secret"
	case finding.CheckJWTAlgorithmConfusion:
		algDesc = "algorithm confusion (RS256→HS256)"
	case finding.CheckJWTNoVerification:
		algDesc = "no signature verification"
	}

	return []finding.Finding{{
		CheckID:  finding.CheckCorrelationJWTAuthBypassChain,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("Attack chain: JWT %s → auth bypass → data access on %s", algDesc, asset),
		Description: fmt.Sprintf(
			"JWT implementation vulnerability (%s on %s — %s) allows token forgery. "+
				"With authenticated endpoints detected on the same infrastructure, an attacker can: "+
				"(1) forge a JWT with arbitrary claims (admin role, any user ID), "+
				"(2) present the forged token to bypass authentication, "+
				"(3) access sensitive API endpoints and data as any user including administrators.",
			jwt.CheckID, jwt.Asset, algDesc),
		Asset:      asset,
		ChainDepth: 2,
		Evidence: map[string]any{
			"jwt_check":    jwt.CheckID,
			"jwt_asset":    jwt.Asset,
			"jwt_weakness": algDesc,
			"chain_type":   "jwt_auth_bypass_data_access",
		},
		ProofCommand: fmt.Sprintf(
			"# Step 1 — Confirm JWT weakness:\n%s\n"+
				"# Step 2 — Forge admin token:\n"+
				"python3 -c \"import jwt; print(jwt.encode({'sub':'admin','role':'admin'}, '', algorithm='none'))\"\n"+
				"# Step 3 — Access protected endpoints:\n"+
				"curl -H 'Authorization: Bearer <forged_token>' 'https://%s/api/admin/users'",
			jwt.ProofCommand, jwt.Asset),
		DiscoveredAt: now,
	}}
}

// ---------------------------------------------------------------------------
// Chain 18: Open Redirect → OAuth Token Theft
// ---------------------------------------------------------------------------

func checkOpenRedirectOAuthChain(byCheckID map[string][]finding.Finding, asset string, now time.Time) []finding.Finding {
	if !hasAny(byCheckID, openRedirectCheckIDs...) {
		return nil
	}

	// Specifically look for OAuth findings (not just generic auth).
	hasOAuthFinding := false
	var oauthFinding finding.Finding
	for id, fs := range byCheckID {
		if strings.HasPrefix(id, "oauth.") && len(fs) > 0 {
			hasOAuthFinding = true
			oauthFinding = fs[0]
			break
		}
	}
	if !hasOAuthFinding {
		return nil
	}

	redir := firstFinding(byCheckID, openRedirectCheckIDs...)

	enabledByParts := []string{
		fmt.Sprintf("%s|%s", redir.CheckID, redir.Asset),
		fmt.Sprintf("%s|%s", oauthFinding.CheckID, oauthFinding.Asset),
	}

	return []finding.Finding{{
		CheckID:  finding.CheckCorrelationOpenRedirectOAuthChain,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Title:    fmt.Sprintf("Attack chain: open redirect → OAuth token theft on %s", asset),
		Description: fmt.Sprintf(
			"An open redirect (%s on %s) exists on the same domain as OAuth endpoints (%s on %s). "+
				"An attacker can: (1) craft an OAuth authorization URL with the redirect_uri pointing to "+
				"the open redirect endpoint, (2) the open redirect forwards the authorization code to the "+
				"attacker's server, (3) the attacker exchanges the code for access tokens and takes over "+
				"the victim's account. This works because OAuth providers often only validate the domain, "+
				"not the full redirect path.",
			redir.CheckID, redir.Asset, oauthFinding.CheckID, oauthFinding.Asset),
		Asset:      asset,
		EnabledBy:  strings.Join(enabledByParts, ", "),
		ChainDepth: 2,
		Evidence: map[string]any{
			"redirect_check": redir.CheckID,
			"redirect_asset": redir.Asset,
			"oauth_check":    oauthFinding.CheckID,
			"oauth_asset":    oauthFinding.Asset,
			"chain_type":     "open_redirect_oauth_theft",
		},
		ProofCommand: fmt.Sprintf(
			"# Step 1 — Confirm open redirect:\n%s\n"+
				"# Step 2 — Craft OAuth URL with redirect to open redirect:\n"+
				"# https://%s/oauth/authorize?client_id=...&redirect_uri=https://%s/REDIRECT_ENDPOINT?url=https://attacker.com/steal\n"+
				"# Step 3 — Attacker captures authorization code at their server",
			redir.ProofCommand, oauthFinding.Asset, redir.Asset),
		DiscoveredAt: now,
	}}
}

// ---------------------------------------------------------------------------
// Chain 19: Subdomain Takeover → Cookie Injection → Session Hijack
// ---------------------------------------------------------------------------

var subdomainTakeoverCheckIDs = []string{
	finding.CheckSubdomainTakeover,
	finding.CheckSubdomainNSDelegationTakeover,
}

func checkSubdomainTakeoverSessionChain(byCheckID map[string][]finding.Finding, asset string, now time.Time) []finding.Finding {
	if !hasAny(byCheckID, subdomainTakeoverCheckIDs...) {
		return nil
	}

	// Look for cookie scope issues or any cookie-related findings that indicate
	// cookies are scoped to the parent domain.
	hasCookieScope := hasAny(byCheckID, finding.CheckCookieExcessiveScope,
		finding.CheckCookieMissingSecure, finding.CheckCookieMissingSameSite,
		finding.CheckCookieNoPrefix)

	if !hasCookieScope {
		return nil
	}

	takeover := firstFinding(byCheckID, subdomainTakeoverCheckIDs...)
	cookie := firstFinding(byCheckID, finding.CheckCookieExcessiveScope,
		finding.CheckCookieMissingSecure, finding.CheckCookieMissingSameSite,
		finding.CheckCookieNoPrefix)

	enabledByParts := []string{
		fmt.Sprintf("%s|%s", takeover.CheckID, takeover.Asset),
		fmt.Sprintf("%s|%s", cookie.CheckID, cookie.Asset),
	}

	return []finding.Finding{{
		CheckID:  finding.CheckCorrelationSubdomainTakeoverSessionChain,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("Attack chain: subdomain takeover → session hijack on %s", asset),
		Description: fmt.Sprintf(
			"A subdomain takeover vulnerability (%s on %s) combined with insecure cookie scoping "+
				"(%s on %s) enables session hijacking. An attacker can: (1) claim the dangling subdomain "+
				"by registering it with the cloud provider, (2) serve content from the claimed subdomain, "+
				"(3) set cookies scoped to the parent domain (e.g., Domain=.example.com), "+
				"(4) inject or overwrite session cookies for the main application, "+
				"(5) hijack user sessions on the primary domain.",
			takeover.CheckID, takeover.Asset, cookie.CheckID, cookie.Asset),
		Asset:      asset,
		EnabledBy:  strings.Join(enabledByParts, ", "),
		ChainDepth: 3,
		Evidence: map[string]any{
			"takeover_check": takeover.CheckID,
			"takeover_asset": takeover.Asset,
			"cookie_check":   cookie.CheckID,
			"cookie_asset":   cookie.Asset,
			"chain_type":     "subdomain_takeover_session_hijack",
		},
		ProofCommand: fmt.Sprintf(
			"# Step 1 — Confirm dangling DNS:\n%s\n"+
				"# Step 2 — Claim subdomain with cloud provider\n"+
				"# Step 3 — Serve page that sets: Set-Cookie: session=attacker; Domain=.%s; Path=/\n"+
				"# Step 4 — Victim visits claimed subdomain → cookie set for parent domain",
			takeover.ProofCommand, asset),
		DiscoveredAt: now,
	}}
}

// ---------------------------------------------------------------------------
// Chain 20: Weak TLS + Auth Service → MitM Credential Interception
// ---------------------------------------------------------------------------

var authServiceCheckIDs = []string{
	finding.CheckAuthLoginFormDetected,
	finding.CheckAuthSSOEndpoint,
	finding.CheckAuthMFADetected,
}

func checkWeakTLSCredInterceptChain(byCheckID map[string][]finding.Finding, asset string, now time.Time) []finding.Finding {
	// Need weak TLS (including heartbleed).
	extendedTLSCheckIDs := append(weakTLSCheckIDs, finding.CheckTLSHeartbleed)
	if !hasAny(byCheckID, extendedTLSCheckIDs...) {
		return nil
	}

	// Need evidence that the service handles authentication.
	hasAuth := hasAny(byCheckID, authServiceCheckIDs...)
	if !hasAuth {
		// Also check for OAuth/auth endpoints as auth signal.
		for id := range byCheckID {
			if strings.HasPrefix(id, "oauth.") || strings.HasPrefix(id, "auth.") {
				hasAuth = true
				break
			}
		}
	}
	if !hasAuth {
		return nil
	}

	tls := firstFinding(byCheckID, extendedTLSCheckIDs...)
	var auth finding.Finding
	if hasAny(byCheckID, authServiceCheckIDs...) {
		auth = firstFinding(byCheckID, authServiceCheckIDs...)
	} else {
		// Find first oauth.* or auth.* finding.
		for id, fs := range byCheckID {
			if (strings.HasPrefix(id, "oauth.") || strings.HasPrefix(id, "auth.")) && len(fs) > 0 {
				auth = fs[0]
				break
			}
		}
	}

	enabledByParts := []string{
		fmt.Sprintf("%s|%s", tls.CheckID, tls.Asset),
		fmt.Sprintf("%s|%s", auth.CheckID, auth.Asset),
	}

	tlsDesc := "weak cipher suite"
	switch tls.CheckID {
	case finding.CheckTLSProtocolSSLv3:
		tlsDesc = "SSLv3 protocol support"
	case finding.CheckTLSProtocolSSLv2:
		tlsDesc = "SSLv2 protocol support"
	case finding.CheckTLSProtocolTLS10:
		tlsDesc = "TLS 1.0 protocol support"
	case finding.CheckTLSProtocolTLS11:
		tlsDesc = "TLS 1.1 protocol support"
	case finding.CheckTLSHeartbleed:
		tlsDesc = "Heartbleed vulnerability"
	case finding.CheckTLSNoPFS:
		tlsDesc = "no perfect forward secrecy"
	}

	return []finding.Finding{{
		CheckID:  finding.CheckCorrelationWeakTLSCredInterceptChain,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Title:    fmt.Sprintf("Attack chain: %s → MitM credential interception on %s", tlsDesc, asset),
		Description: fmt.Sprintf(
			"Weak TLS configuration (%s on %s — %s) on a service that handles authentication "+
				"(%s on %s) enables credential interception via man-in-the-middle attack. "+
				"An attacker on the network path can: (1) downgrade the TLS connection exploiting "+
				"the weak configuration, (2) intercept credentials (passwords, tokens, session cookies) "+
				"transmitted over the weakened connection, (3) replay stolen credentials for account access.",
			tls.CheckID, tls.Asset, tlsDesc, auth.CheckID, auth.Asset),
		Asset:      asset,
		EnabledBy:  strings.Join(enabledByParts, ", "),
		ChainDepth: 2,
		Evidence: map[string]any{
			"tls_check":    tls.CheckID,
			"tls_asset":    tls.Asset,
			"tls_weakness": tlsDesc,
			"auth_check":   auth.CheckID,
			"auth_asset":   auth.Asset,
			"chain_type":   "weak_tls_credential_interception",
		},
		ProofCommand: fmt.Sprintf(
			"# Step 1 — Confirm weak TLS:\n%s\n"+
				"# Step 2 — Auth service detected:\n%s\n"+
				"# Step 3 — MitM test (requires network position):\n"+
				"# Use mitmproxy or bettercap to intercept traffic to %s",
			tls.ProofCommand, auth.ProofCommand, tls.Asset),
		DiscoveredAt: now,
	}}
}

// ---------------------------------------------------------------------------
// Chain 21: Container Escape → Host Compromise
// ---------------------------------------------------------------------------

var containerAPICheckIDs = []string{
	finding.CheckPortDockerUnauth,
	finding.CheckPortKubeletUnauth,
	finding.CheckPortK8sAPIExposed,
	finding.CheckPortKubeDashboardExposed,
	finding.CheckPortKubeletReadOnly,
}

var containerFindingCheckIDs = []string{
	finding.CheckContainerRegistryExposed,
	finding.CheckContainerImageUnsigned,
	finding.CheckContainerRegistryAnonymousPush,
	finding.CheckContainerDockerSocketExposed,
}

func checkContainerEscapeChain(byCheckID map[string][]finding.Finding, asset string, now time.Time) []finding.Finding {
	if !hasAny(byCheckID, containerAPICheckIDs...) {
		return nil
	}

	// Look for container-level findings that amplify the escape path.
	hasContainerFinding := hasAny(byCheckID, containerFindingCheckIDs...)
	if !hasContainerFinding {
		// Also accept any container.* finding.
		for id := range byCheckID {
			if strings.HasPrefix(id, "container.") {
				hasContainerFinding = true
				break
			}
		}
	}
	if !hasContainerFinding {
		return nil
	}

	api := firstFinding(byCheckID, containerAPICheckIDs...)

	var containerFinding finding.Finding
	if hasAny(byCheckID, containerFindingCheckIDs...) {
		containerFinding = firstFinding(byCheckID, containerFindingCheckIDs...)
	} else {
		for id, fs := range byCheckID {
			if strings.HasPrefix(id, "container.") && len(fs) > 0 {
				containerFinding = fs[0]
				break
			}
		}
	}

	enabledByParts := []string{
		fmt.Sprintf("%s|%s", api.CheckID, api.Asset),
		fmt.Sprintf("%s|%s", containerFinding.CheckID, containerFinding.Asset),
	}

	return []finding.Finding{{
		CheckID:  finding.CheckCorrelationContainerEscapeChain,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("Attack chain: container escape → host compromise on %s", asset),
		Description: fmt.Sprintf(
			"An exposed container orchestration API (%s on %s) combined with container vulnerabilities "+
				"(%s on %s) enables host compromise. An attacker can: (1) access the unauthenticated "+
				"container API, (2) deploy a privileged container or exploit existing container weaknesses, "+
				"(3) escape the container to the host filesystem via mount or privileged mode, "+
				"(4) compromise all containers on the host and pivot to the underlying infrastructure.",
			api.CheckID, api.Asset, containerFinding.CheckID, containerFinding.Asset),
		Asset:      asset,
		EnabledBy:  strings.Join(enabledByParts, ", "),
		ChainDepth: 3,
		Evidence: map[string]any{
			"api_check":       api.CheckID,
			"api_asset":       api.Asset,
			"container_check": containerFinding.CheckID,
			"container_asset": containerFinding.Asset,
			"chain_type":      "container_escape_host_compromise",
		},
		ProofCommand: fmt.Sprintf(
			"# Step 1 — Access container API:\n%s\n"+
				"# Step 2 — Container finding:\n%s\n"+
				"# Step 3 — Deploy privileged container (Docker example):\n"+
				"# curl -X POST http://%s:2375/containers/create -d '{\"Image\":\"alpine\",\"HostConfig\":{\"Privileged\":true,\"Binds\":[\"/:/mnt\"]}}'\n"+
				"# Step 4 — Access host filesystem at /mnt inside container",
			api.ProofCommand, containerFinding.ProofCommand, api.Asset),
		DiscoveredAt: now,
	}}
}

// ---------------------------------------------------------------------------
// Chain 22: Email Spoofing → Phishing → Credential Harvest
// ---------------------------------------------------------------------------

var emailSpoofCheckIDs = []string{
	finding.CheckEmailDMARCMissing,
	finding.CheckEmailDMARCPolicyNone,
	finding.CheckEmailSPFSoftfail,
	finding.CheckEmailSPFMissing,
	finding.CheckEmailSpoofable,
}

var emailDKIMCheckIDs = []string{
	finding.CheckEmailDKIMMissing,
	finding.CheckEmailDKIMWeakKey,
}

func checkEmailSpoofPhishChain(byCheckID map[string][]finding.Finding, asset string, now time.Time) []finding.Finding {
	if !hasAny(byCheckID, emailSpoofCheckIDs...) {
		return nil
	}
	if !hasAny(byCheckID, emailDKIMCheckIDs...) {
		return nil
	}

	spoof := firstFinding(byCheckID, emailSpoofCheckIDs...)
	dkim := firstFinding(byCheckID, emailDKIMCheckIDs...)

	enabledByParts := []string{
		fmt.Sprintf("%s|%s", spoof.CheckID, spoof.Asset),
		fmt.Sprintf("%s|%s", dkim.CheckID, dkim.Asset),
	}

	return []finding.Finding{{
		CheckID:  finding.CheckCorrelationEmailSpoofPhishChain,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Title:    fmt.Sprintf("Attack chain: email spoofing → phishing → credential harvest on %s", asset),
		Description: fmt.Sprintf(
			"Missing email authentication records (%s on %s) combined with DKIM weakness "+
				"(%s on %s) allows convincing email spoofing. An attacker can: "+
				"(1) send emails that appear to come from your domain (no DMARC/SPF enforcement), "+
				"(2) emails pass recipient checks because DKIM is not configured to reject forgeries, "+
				"(3) craft phishing emails targeting employees with internal-looking password reset links, "+
				"(4) harvest credentials for internal system access.",
			spoof.CheckID, spoof.Asset, dkim.CheckID, dkim.Asset),
		Asset:      asset,
		EnabledBy:  strings.Join(enabledByParts, ", "),
		ChainDepth: 3,
		Evidence: map[string]any{
			"spoof_check": spoof.CheckID,
			"spoof_asset": spoof.Asset,
			"dkim_check":  dkim.CheckID,
			"dkim_asset":  dkim.Asset,
			"chain_type":  "email_spoofing_phishing",
		},
		ProofCommand: fmt.Sprintf(
			"# Step 1 — Confirm missing DMARC/SPF:\n%s\n"+
				"# Step 2 — Confirm missing DKIM:\n%s\n"+
				"# Step 3 — Test email spoofing (authorized testing only):\n"+
				"# swaks --to target@example.com --from ceo@%s --header 'Subject: Urgent Password Reset' --body 'Reset: https://attacker.com/reset'",
			spoof.ProofCommand, dkim.ProofCommand, asset),
		DiscoveredAt: now,
	}}
}

// ---------------------------------------------------------------------------
// Chain 23: Version Disclosure → Known CVE Match
// ---------------------------------------------------------------------------

func checkVersionCVEMatchChain(byCheckID map[string][]finding.Finding, asset string, now time.Time) []finding.Finding {
	// Need service version identification.
	if !hasAny(byCheckID, finding.CheckPortServiceIdentified) {
		return nil
	}

	// Need at least one CVE finding.
	hasCVE := false
	var cveFinding finding.Finding
	for id, fs := range byCheckID {
		if strings.HasPrefix(id, "cve.") && len(fs) > 0 {
			hasCVE = true
			cveFinding = fs[0]
			break
		}
	}
	if !hasCVE {
		return nil
	}

	version := firstFinding(byCheckID, finding.CheckPortServiceIdentified)

	enabledByParts := []string{
		fmt.Sprintf("%s|%s", version.CheckID, version.Asset),
		fmt.Sprintf("%s|%s", cveFinding.CheckID, cveFinding.Asset),
	}

	// Use the CVE finding's severity if available; otherwise default to High.
	severity := finding.SeverityHigh
	if cveFinding.Severity == finding.SeverityCritical {
		severity = finding.SeverityCritical
	}

	return []finding.Finding{{
		CheckID:  finding.CheckCorrelationVersionCVEMatchChain,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: severity,
		Title:    fmt.Sprintf("Attack chain: version disclosure → CVE match (%s) on %s", cveFinding.CheckID, asset),
		Description: fmt.Sprintf(
			"Service version information (%s on %s) disclosed the software version, which matches "+
				"a known vulnerability (%s on %s). The version disclosure enables the attacker to "+
				"confirm the target is running a vulnerable version and select the correct exploit. "+
				"This reduces exploitation from guesswork to a targeted, reliable attack.",
			version.CheckID, version.Asset, cveFinding.CheckID, cveFinding.Asset),
		Asset:      asset,
		EnabledBy:  strings.Join(enabledByParts, ", "),
		ChainDepth: 2,
		Evidence: map[string]any{
			"version_check": version.CheckID,
			"version_asset": version.Asset,
			"cve_check":     cveFinding.CheckID,
			"cve_asset":     cveFinding.Asset,
			"cve_severity":  cveFinding.Severity.String(),
			"chain_type":    "version_disclosure_cve_match",
		},
		ProofCommand: fmt.Sprintf(
			"# Step 1 — Service version disclosure:\n%s\n"+
				"# Step 2 — Matching CVE:\n%s\n"+
				"# Step 3 — Verify with version-specific exploit or nuclei template",
			version.ProofCommand, cveFinding.ProofCommand),
		DiscoveredAt: now,
	}}
}
