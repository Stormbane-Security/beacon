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
