// Package oauth probes for OAuth 2.0 / OIDC / JWT misconfiguration vulnerabilities.
//
// Checks performed (surface mode unless noted):
//   - JWKS endpoint exposure — /.well-known/jwks.json or /oauth/discovery
//   - OIDC discovery document — checks for implicit flow enabled, missing PKCE support
//   - Token endpoint unauthenticated access — POST /oauth/token without credentials
//   - OAuth authorization endpoint — missing state parameter → CSRF risk (deep)
//   - OAuth authorization endpoint — missing PKCE (code_challenge) → auth code interception (deep)
//   - Open redirect in redirect_uri — accepts arbitrary domains (deep)
//   - JWT no-verification — sends a token with an invalid signature (deep)
//
// Client ID strategy:
//   The scanner first tries to discover a real client_id by scanning the target
//   page's HTML for common patterns (clientId, client_id, REACT_APP_CLIENT_ID, etc.).
//   When a real client_id is found, active probes use it and report confidence=high.
//   When only a synthetic fallback is used, findings are annotated confidence=low
//   and the description notes that the server may have rejected the probe before
//   reaching the logic under test.
package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const scannerName = "oauth"

// Scanner probes for OAuth/OIDC/JWT vulnerabilities.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

// wellKnownPaths are standard OIDC/OAuth discovery endpoints.
var wellKnownPaths = []string{
	"/.well-known/openid-configuration",
	"/.well-known/oauth-authorization-server",
	"/oauth/.well-known/openid-configuration",
	"/auth/.well-known/openid-configuration",
	"/realms/master/.well-known/openid-configuration", // Keycloak
	"/oidc/.well-known/openid-configuration",
}

// jwksPaths are well-known JWKS endpoint locations.
var jwksPaths = []string{
	"/.well-known/jwks.json",
	"/oauth/discovery/keys",
	"/oauth2/v1/certs",
	"/api/v1/identity/oidc/.well-known/keys",
}

// tokenEndpointPaths are probed when the OIDC doc doesn't provide token_endpoint.
var tokenEndpointPaths = []string{
	"/oauth/token",
	"/oauth2/token",
	"/auth/token",
	"/connect/token",
	"/token",
	"/api/token",
}

// clientIDPatterns extracts OAuth client IDs from HTML and JavaScript source.
// Ordered from most to least specific to reduce false positives.
var clientIDPatterns = []*regexp.Regexp{
	// Explicit assignments: clientId: "abc", client_id="abc"
	regexp.MustCompile(`(?i)client[_-]?id["'\s]*[:=]["'\s]*([a-zA-Z0-9\-_.@]{8,128})`),
	// Environment variable references baked into bundles
	regexp.MustCompile(`(?i)(?:REACT_APP|VITE|NEXT_PUBLIC)_CLIENT_ID["'\s]*[:=]["'\s]*([a-zA-Z0-9\-_.@]{8,128})`),
	// Common SPA patterns: {clientId:"..."} or clientId = "..."
	regexp.MustCompile(`clientId:\s*["']([a-zA-Z0-9\-_.@]{8,128})["']`),
}

// probeClientID holds the client_id to use for active probes and records
// whether it was discovered from the real application or is a synthetic fallback.
type probeClientID struct {
	id         string
	real       bool   // true = found in app source, false = synthetic fallback
	confidence string // "high" | "low"
}

func syntheticClient() probeClientID {
	return probeClientID{id: "public-client", real: false, confidence: "low"}
}

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
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

	// Try to find a real client_id before probing, so active checks use valid
	// credentials instead of a synthetic fallback that the server will reject
	// before reaching the logic we're actually testing.
	pc := discoverClientID(ctx, client, base)

	var findings []finding.Finding

	// ── Surface-mode checks ──────────────────────────────────────────────────

	// 1. JWKS endpoint exposure
	if f := checkJWKSExposure(ctx, client, asset, base); f != nil {
		findings = append(findings, *f)
	}

	// 2. OIDC discovery document — implicit flow, PKCE support, signing alg, JWKS URI, backchannel
	oidcDoc, authEndpoint := fetchOIDCDocument(ctx, client, base)
	if oidcDoc != nil {
		if f := checkImplicitFlow(asset, oidcDoc); f != nil {
			findings = append(findings, *f)
		}
		if f := checkPKCESupport(asset, oidcDoc); f != nil {
			findings = append(findings, *f)
		}
		if f := checkOIDCWeakSigningAlg(asset, oidcDoc); f != nil {
			findings = append(findings, *f)
		}
		if f := checkOIDCMissingJWKSURI(asset, oidcDoc); f != nil {
			findings = append(findings, *f)
		}
		if f := checkOIDCBackchannelMissing(asset, oidcDoc); f != nil {
			findings = append(findings, *f)
		}
	}

	// 3. Token endpoint — unauthenticated access check (surface mode)
	tokenEndpoint := ""
	if oidcDoc != nil {
		tokenEndpoint = oidcDoc.TokenEndpoint
	}
	if f := checkTokenEndpointAuth(ctx, client, asset, base, tokenEndpoint); f != nil {
		findings = append(findings, *f)
	}

	// 4. Token in URL fragment — check if implicit flow with response_type=token
	// is advertised in the OIDC discovery document (surface mode).
	if oidcDoc != nil {
		if f := checkTokenInFragment(asset, oidcDoc); f != nil {
			findings = append(findings, *f)
		}
	}

	// 5. Token long expiry — probe the token endpoint for expires_in > 24h (surface mode).
	if f := checkTokenLongExpiry(ctx, client, asset, base, tokenEndpoint); f != nil {
		findings = append(findings, *f)
	}

	// ── Deep-mode checks ─────────────────────────────────────────────────────
	// ScanAuthorized implies ScanDeep, so run deep checks for both modes.
	if scanType != module.ScanDeep && scanType != module.ScanAuthorized {
		return findings, nil
	}

	// 4. Missing state parameter on authorization endpoint
	if authEndpoint == "" {
		authEndpoint = discoverAuthEndpoint(ctx, client, base)
	}
	if authEndpoint != "" {
		if f := checkMissingState(ctx, client, asset, authEndpoint, pc); f != nil {
			findings = append(findings, *f)
		}
		if f := checkMissingPKCE(ctx, client, asset, authEndpoint, pc); f != nil {
			findings = append(findings, *f)
		}
		if f := checkOpenRedirect(ctx, client, asset, authEndpoint, pc); f != nil {
			findings = append(findings, *f)
		}
		// 4a. Weak state parameter — checks state entropy if present
		if f := checkWeakState(ctx, client, asset, authEndpoint, pc); f != nil {
			findings = append(findings, *f)
		}
	}

	// 5. OAuth token leak via Referer — implicit flow redirects token in URL
	if f := checkTokenLeakReferer(ctx, client, asset, authEndpoint, pc); f != nil {
		findings = append(findings, *f)
	}

	// 5a. Active implicit flow check — if response_type=token is accepted, the
	// deprecated implicit flow is live (not just advertised in the OIDC doc).
	if authEndpoint != "" {
		if f := checkImplicitFlowAccepted(ctx, client, asset, authEndpoint, pc); f != nil {
			findings = append(findings, *f)
		}
	}

	// 6. Refresh token not rotated — attempt to use the same refresh token twice.
	if f := checkRefreshNotRotated(ctx, client, asset, base, tokenEndpoint); f != nil {
		findings = append(findings, *f)
	}

	// 7. JWT no-verification probe
	if f := checkJWTNoVerification(ctx, client, asset, base); f != nil {
		findings = append(findings, *f)
	}

	return findings, nil
}

// ── Client ID discovery ───────────────────────────────────────────────────────

// discoverClientID fetches the target's main page HTML and scans it for a
// real OAuth client_id. Returns a synthetic fallback when none is found.
func discoverClientID(ctx context.Context, client *http.Client, base string) probeClientID {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base, nil)
	if err != nil {
		return syntheticClient()
	}
	resp, err := client.Do(req)
	if err != nil {
		return syntheticClient()
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512<<10)) // 512 KB cap
	resp.Body.Close()

	if id := matchClientID(string(body)); id != "" {
		return probeClientID{id: id, real: true, confidence: "high"}
	}
	return syntheticClient()
}

// matchClientID returns the first client_id found in src, or "".
func matchClientID(src string) string {
	for _, re := range clientIDPatterns {
		if m := re.FindStringSubmatch(src); len(m) > 1 {
			v := m[1]
			// Reject obvious non-IDs: very short values, pure numbers, common
			// variable names that got captured by the pattern.
			if len(v) < 8 || isLikelyNotClientID(v) {
				continue
			}
			return v
		}
	}
	return ""
}

// isLikelyNotClientID rejects strings that look like variable names or
// HTML attribute values rather than real OAuth client identifiers.
func isLikelyNotClientID(v string) bool {
	lower := strings.ToLower(v)
	// Pure numbers are not client IDs.
	allDigits := true
	for _, c := range v {
		if c < '0' || c > '9' {
			allDigits = false
			break
		}
	}
	if allDigits {
		return true
	}
	// Common variable names / placeholder values.
	placeholders := []string{"clientid", "client_id", "yourclientid", "your-client-id",
		"undefined", "null", "false", "true", "test", "example"}
	for _, p := range placeholders {
		if lower == p {
			return true
		}
	}
	return false
}

// confidenceNote returns a standard evidence annotation and description suffix
// when a synthetic client_id was used.
func confidenceNote(pc probeClientID) (map[string]any, string) {
	ev := map[string]any{"client_id": pc.id, "confidence": pc.confidence}
	note := ""
	if !pc.real {
		note = " Note: this probe used a synthetic client_id (" + pc.id + ") because no real " +
			"client_id was found in the application source. The server may have rejected " +
			"the request before reaching the logic under test — manual verification is recommended."
	}
	return ev, note
}

// ── Token endpoint unauthenticated access ────────────────────────────────────

// checkTokenEndpointAuth probes the OAuth token endpoint without credentials
// and checks whether it leaks information or accepts unauthenticated requests.
// A properly configured token endpoint must return 400 (invalid_request) or
// 401 (unauthorized) for any POST without valid client authentication.
func checkTokenEndpointAuth(ctx context.Context, client *http.Client, asset, base, knownEndpoint string) *finding.Finding {
	endpoints := tokenEndpointPaths
	if knownEndpoint != "" {
		// Probe the discovered endpoint first, then fall through to common paths.
		endpoints = append([]string{strings.TrimPrefix(knownEndpoint, base)}, endpoints...)
	}

	for _, path := range endpoints {
		var u string
		if strings.HasPrefix(path, "http") {
			u = path
		} else {
			u = base + path
		}

		body := url.Values{}
		body.Set("grant_type", "client_credentials")
		// No client_id or client_secret — a valid server must reject this.

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u,
			bytes.NewBufferString(body.Encode()))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		resp.Body.Close()

		// 404/405 = endpoint doesn't exist here, try next path.
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
			continue
		}

		ct := resp.Header.Get("Content-Type")
		bodyStr := string(respBody)
		bodyLower := strings.ToLower(bodyStr)

		// RFC 6749 §5.2 defines the set of error codes a properly configured
		// token endpoint must return when rejecting an unauthenticated request.
		// All of these confirm the server IS enforcing authentication.
		isProperRejection := strings.Contains(bodyLower, "invalid_client") ||
			strings.Contains(bodyLower, "invalid_request") ||
			strings.Contains(bodyLower, "unauthorized_client") ||
			strings.Contains(bodyLower, "client authentication") ||
			// invalid_grant: credential missing or expired — server is checking
			strings.Contains(bodyLower, "invalid_grant") ||
			// 401 Unauthorized always means the server enforces auth
			resp.StatusCode == http.StatusUnauthorized
		if isProperRejection {
			return nil
		}

		// 403 is also acceptable — access denied.
		if resp.StatusCode == http.StatusForbidden {
			return nil
		}

		// 3xx redirects are not OAuth responses — the endpoint is just redirecting
		// (e.g. HTTP→HTTPS or subdomain canonicalisation). Skip entirely.
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			return nil
		}

		// If the response is not JSON/OAuth content, it's likely a protocol-level
		// error (e.g., "plain HTTP request was sent to HTTPS port" from a reverse
		// proxy), not an actual OAuth token endpoint response. Skip to avoid false
		// positives when the HTTP base URL was used for an HTTPS-only server.
		// Use content-type or OAuth-specific JSON keys — not just the word "oauth"
		// which can appear in a redirect Location URL body.
		isOAuthLike := strings.Contains(ct, "application/json") ||
			strings.Contains(ct, "application/x-www-form-urlencoded") ||
			strings.Contains(bodyLower, "grant_type") ||
			strings.Contains(bodyLower, "access_token") ||
			strings.Contains(bodyLower, "invalid_client") ||
			strings.Contains(bodyLower, "invalid_request")
		if !isOAuthLike {
			return nil
		}

		// Only flag 2xx responses or 400s that look like misbehaving OAuth endpoints.
		// A 200 with no credentials is always a misconfiguration.
		// A 400 is suspicious when the body has positive OAuth signals (proving
		// this is an OAuth endpoint) but the server didn't reject with a proper
		// RFC 6749 error code (handled above). We exclude only the specific
		// credential-rejection codes here — NOT the broad string "invalid", which
		// would swallow "invalid_scope" and "invalid_token" (both indicate the
		// server is processing the request without verifying the client identity).
		is400Misconfig := resp.StatusCode == http.StatusBadRequest &&
			!strings.Contains(bodyLower, "invalid_client") &&
			!strings.Contains(bodyLower, "invalid_request") &&
			!strings.Contains(bodyLower, "unauthorized_client") &&
			!strings.Contains(bodyLower, "invalid_grant") &&
			(strings.Contains(bodyLower, "grant_type") ||
				strings.Contains(bodyLower, "access_token") ||
				strings.Contains(bodyLower, "token_type") ||
				strings.Contains(bodyLower, `"error":`) ||
				strings.Contains(bodyLower, "client_id") ||
				strings.Contains(bodyLower, "oauth"))
		if resp.StatusCode == http.StatusOK || is400Misconfig {
			return &finding.Finding{
				CheckID:  finding.CheckOAuthMissingState, // reuse closest check; ideally a dedicated ID
				Module:   "surface",
				Scanner:  scannerName,
				Severity: finding.SeverityHigh,
				Asset:    asset,
				Title:    fmt.Sprintf("OAuth token endpoint accepts unauthenticated requests at %s", u),
				Description: fmt.Sprintf(
					"The OAuth token endpoint at %s responded with HTTP %d to a POST request "+
						"with no client credentials (no client_id or client_secret). "+
						"A correctly configured token endpoint must reject unauthenticated "+
						"requests with HTTP 400 invalid_client or HTTP 401. "+
						"If the endpoint issues tokens without verifying the client, "+
						"any actor can obtain access tokens for any registered client.",
					u, resp.StatusCode,
				),
				Evidence: map[string]any{
					"endpoint":        u,
					"status_code":     resp.StatusCode,
					"content_type":    ct,
					"response_snippet": bodyStr[:min(300, len(bodyStr))],
				},
				ProofCommand:  fmt.Sprintf("curl -s -X POST '%s' -H 'Content-Type: application/x-www-form-urlencoded' -d 'grant_type=client_credentials' | python3 -m json.tool", u),
				DiscoveredAt: time.Now(),
			}
		}
		// If we got a definitive response from this endpoint, don't check more paths.
		return nil
	}
	return nil
}

// ── JWKS, OIDC, and existing checks ──────────────────────────────────────────

func checkJWKSExposure(ctx context.Context, client *http.Client, asset, base string) *finding.Finding {
	for _, path := range jwksPaths {
		u := base + path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			continue
		}
		if !strings.Contains(string(body), `"keys"`) {
			continue
		}

		return &finding.Finding{
			CheckID:  finding.CheckJWKSExposed,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityInfo,
			Asset:    asset,
			Title:    fmt.Sprintf("JWKS endpoint exposed at %s", path),
			Description: fmt.Sprintf(
				"The JWKS (JSON Web Key Set) endpoint at %s is publicly accessible. "+
					"This is expected for public OIDC providers but should be reviewed: "+
					"exposing signing keys enables offline JWT forgery attempts if the key "+
					"algorithm is weak or the key is short.",
				u,
			),
			Evidence:     map[string]any{"url": u, "path": path},
			ProofCommand: fmt.Sprintf("curl -s '%s' | python3 -m json.tool", u),
			DiscoveredAt: time.Now(),
		}
	}
	return nil
}

// oidcDocument is the minimal subset of an OIDC discovery document we parse.
type oidcDocument struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	BackchannelLogoutSupported        *bool    `json:"backchannel_logout_supported"`
}

func fetchOIDCDocument(ctx context.Context, client *http.Client, base string) (*oidcDocument, string) {
	for _, path := range wellKnownPaths {
		u := base + path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			if resp != nil {
				resp.Body.Close()
			}
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		if err != nil {
			continue
		}
		var doc oidcDocument
		if err := json.Unmarshal(body, &doc); err != nil {
			continue
		}
		if doc.AuthorizationEndpoint == "" {
			continue
		}
		return &doc, doc.AuthorizationEndpoint
	}
	return nil, ""
}

func checkImplicitFlow(asset string, doc *oidcDocument) *finding.Finding {
	hasCode := false
	hasImplicit := false
	for _, rt := range doc.ResponseTypesSupported {
		rt = strings.ToLower(rt)
		if rt == "code" {
			hasCode = true
		}
		if rt == "token" || rt == "id_token" {
			hasImplicit = true
		}
	}
	if !hasImplicit || hasCode {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckOIDCImplicitFlow,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityMedium,
		Asset:    asset,
		Title:    "OIDC implicit flow enabled (deprecated)",
		Description: "The OIDC discovery document lists implicit flow (response_type=token or id_token) " +
			"without the authorization code flow. The implicit flow is deprecated in OAuth 2.1 because " +
			"tokens are returned in the URL fragment (visible in browser history, referrer headers, and logs). " +
			"Migrate clients to the authorization code flow with PKCE.",
		Evidence:     map[string]any{"response_types_supported": doc.ResponseTypesSupported},
		DiscoveredAt: time.Now(),
	}
}

func checkPKCESupport(asset string, doc *oidcDocument) *finding.Finding {
	if len(doc.CodeChallengeMethodsSupported) > 0 {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckOAuthMissingPKCE,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityMedium,
		Asset:    asset,
		Title:    "OAuth server does not advertise PKCE support",
		Description: "The OIDC discovery document does not list code_challenge_methods_supported, " +
			"indicating the authorization server may not enforce PKCE. Without PKCE, authorization " +
			"codes can be intercepted by a malicious app on the same device and exchanged for tokens.",
		Evidence:     map[string]any{"code_challenge_methods_supported": doc.CodeChallengeMethodsSupported},
		DiscoveredAt: time.Now(),
	}
}

// checkOIDCWeakSigningAlg emits a finding when the discovery document
// advertises "none" or "RS1" in id_token_signing_alg_values_supported.
func checkOIDCWeakSigningAlg(asset string, doc *oidcDocument) *finding.Finding {
	var weak []string
	for _, alg := range doc.IDTokenSigningAlgValuesSupported {
		if strings.EqualFold(alg, "none") || strings.EqualFold(alg, "RS1") {
			weak = append(weak, alg)
		}
	}
	if len(weak) == 0 {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckOIDCWeakSigningAlg,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Asset:    asset,
		Title:    fmt.Sprintf("OIDC discovery document advertises weak signing algorithm(s): %s", strings.Join(weak, ", ")),
		Description: "The OIDC discovery document lists one or more cryptographically weak or " +
			"completely insecure signing algorithms in id_token_signing_alg_values_supported. " +
			"'none' means the server may accept unsigned ID tokens. 'RS1' (RSA with SHA-1) is " +
			"cryptographically broken. Restrict the list to RS256, RS384, RS512, ES256, or PS256.",
		Evidence: map[string]any{
			"weak_algorithms":                    weak,
			"id_token_signing_alg_values_supported": doc.IDTokenSigningAlgValuesSupported,
		},
		DiscoveredAt: time.Now(),
	}
}

// checkOIDCMissingJWKSURI emits a finding when the discovery document has no
// jwks_uri field. Without a JWKS URI, relying parties cannot retrieve signing
// keys and are more likely to disable signature verification.
func checkOIDCMissingJWKSURI(asset string, doc *oidcDocument) *finding.Finding {
	if doc.JWKSURI != "" {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckOIDCMissingJWKSURI,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Asset:    asset,
		Title:    "OIDC discovery document is missing jwks_uri",
		Description: "The OIDC discovery document does not include a jwks_uri field. " +
			"Without a JWKS URI, relying parties cannot automatically rotate or fetch " +
			"signing keys, increasing the risk that clients will disable or skip " +
			"signature verification entirely. Add a jwks_uri pointing to the server's " +
			"public key set.",
		Evidence:     map[string]any{"issuer": doc.Issuer},
		DiscoveredAt: time.Now(),
	}
}

// checkOIDCBackchannelMissing emits a finding when the discovery document does
// not advertise backchannel_logout_supported. Without backchannel logout,
// sessions at relying parties cannot be terminated when the IdP session ends.
func checkOIDCBackchannelMissing(asset string, doc *oidcDocument) *finding.Finding {
	if doc.BackchannelLogoutSupported != nil {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckOIDCBackchannelMissing,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityMedium,
		Asset:    asset,
		Title:    "OIDC discovery document does not advertise backchannel_logout_supported",
		Description: "The OIDC discovery document does not include the backchannel_logout_supported " +
			"field. Without backchannel logout (RFC 8705), relying party sessions cannot be " +
			"terminated server-to-server when a user logs out at the identity provider. " +
			"This means a user who logs out at the IdP may remain logged in at downstream " +
			"services. Implement backchannel logout to enable centralised session termination.",
		Evidence:     map[string]any{"issuer": doc.Issuer},
		DiscoveredAt: time.Now(),
	}
}

func discoverAuthEndpoint(ctx context.Context, client *http.Client, base string) string {
	candidates := []string{
		"/oauth/authorize",
		"/oauth2/authorize",
		"/auth/authorize",
		"/connect/authorize",
		"/authorize",
		"/oauth/auth",
	}
	for _, path := range candidates {
		u := base + path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u+"?response_type=code&client_id=test", nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusBadRequest ||
			resp.StatusCode == http.StatusUnauthorized {
			return u
		}
	}
	return ""
}

func checkMissingState(ctx context.Context, client *http.Client, asset, authEndpoint string, pc probeClientID) *finding.Finding {
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", pc.id)
	params.Set("redirect_uri", "https://example.com/callback")
	// Intentionally omit state.

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authEndpoint+"?"+params.Encode(), nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	resp.Body.Close()

	bodyStr := strings.ToLower(string(body))
	if resp.StatusCode == http.StatusBadRequest && strings.Contains(bodyStr, "state") {
		return nil // state enforced
	}
	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusOK {
		loc := resp.Header.Get("Location")
		if strings.Contains(strings.ToLower(loc), "error") || strings.Contains(bodyStr, "invalid") {
			return nil
		}
		// Reject if the server bounced us for invalid_client before reaching state validation.
		if strings.Contains(bodyStr, "invalid_client") || strings.Contains(bodyStr, "client not found") {
			return nil // can't conclude — server rejected the client first
		}

		ev, note := confidenceNote(pc)
		ev["endpoint"] = authEndpoint
		ev["status_code"] = resp.StatusCode
		ev["location"] = loc
		return &finding.Finding{
			CheckID:  finding.CheckOAuthMissingState,
			Module:   "deep",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Asset:    asset,
			Title:    fmt.Sprintf("OAuth: state parameter not enforced at %s", authEndpoint),
			Description: "The OAuth authorization endpoint accepted a request without a state parameter. " +
				"The state parameter is the primary CSRF defense for OAuth flows. Without it, an attacker " +
				"can trick a user into authorizing an attacker-controlled application or completing an " +
				"attacker-initiated flow (login CSRF)." + note,
			Evidence:     ev,
			ProofCommand: fmt.Sprintf("curl -sI '%s?response_type=code&client_id=test&redirect_uri=https://example.com/callback' | grep -i 'location\\|HTTP/'", authEndpoint),
			DiscoveredAt: time.Now(),
		}
	}
	return nil
}

func checkMissingPKCE(ctx context.Context, client *http.Client, asset, authEndpoint string, pc probeClientID) *finding.Finding {
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", pc.id)
	params.Set("redirect_uri", "https://example.com/callback")
	params.Set("state", "beaconstate123")
	// Intentionally omit code_challenge / code_challenge_method.

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authEndpoint+"?"+params.Encode(), nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	resp.Body.Close()

	bodyStr := strings.ToLower(string(body))
	if resp.StatusCode == http.StatusBadRequest &&
		(strings.Contains(bodyStr, "code_challenge") || strings.Contains(bodyStr, "pkce")) {
		return nil // PKCE enforced
	}
	// Server rejected the client before reaching PKCE logic — can't conclude.
	if strings.Contains(bodyStr, "invalid_client") || strings.Contains(bodyStr, "client not found") {
		return nil
	}

	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusOK {
		ev, note := confidenceNote(pc)
		ev["endpoint"] = authEndpoint
		ev["status_code"] = resp.StatusCode
		sev := finding.SeverityMedium
		if !pc.real {
			sev = finding.SeverityLow // downgrade when confidence is low
		}
		return &finding.Finding{
			CheckID:  finding.CheckOAuthMissingPKCE,
			Module:   "deep",
			Scanner:  scannerName,
			Severity: sev,
			Asset:    asset,
			Title:    fmt.Sprintf("OAuth: PKCE not enforced at %s", authEndpoint),
			Description: "The OAuth authorization endpoint accepted a code flow request without a " +
				"code_challenge parameter (PKCE). Without PKCE enforcement, authorization codes " +
				"intercepted by a malicious native app or browser extension can be exchanged for " +
				"access tokens without possession of the original code_verifier." + note,
			Evidence:     ev,
			ProofCommand: fmt.Sprintf("curl -sI '%s?response_type=code&client_id=test&redirect_uri=https://example.com/callback&state=test' | grep -i 'location\\|HTTP/'", authEndpoint),
			DiscoveredAt: time.Now(),
		}
	}
	return nil
}

func checkOpenRedirect(ctx context.Context, client *http.Client, asset, authEndpoint string, pc probeClientID) *finding.Finding {
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", pc.id)
	params.Set("redirect_uri", "https://evil.com/steal-tokens")
	params.Set("state", "beacontest")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authEndpoint+"?"+params.Encode(), nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	resp.Body.Close()

	loc := resp.Header.Get("Location")
	bodyStr := string(body)

	if strings.Contains(strings.ToLower(loc), "evil.com") ||
		strings.Contains(bodyStr, "evil.com") {
		ev, note := confidenceNote(pc)
		ev["endpoint"] = authEndpoint
		ev["injected_redirect"] = "https://evil.com/steal-tokens"
		ev["response_location"] = loc
		ev["status_code"] = resp.StatusCode
		return &finding.Finding{
			CheckID:  finding.CheckOAuthOpenRedirect,
			Module:   "deep",
			Scanner:  scannerName,
			Severity: finding.SeverityCritical,
			Asset:    asset,
			Title:    fmt.Sprintf("OAuth: open redirect_uri accepted at %s", authEndpoint),
			Description: "The OAuth authorization endpoint accepted an arbitrary redirect_uri " +
				"(https://evil.com/steal-tokens) without validation. An attacker can craft an " +
				"authorization URL that, upon completion, redirects the victim's authorization code " +
				"or access token to an attacker-controlled server." + note,
			Evidence:     ev,
			ProofCommand: fmt.Sprintf("curl -sI '%s?response_type=code&client_id=test&redirect_uri=https://evil.com/steal-tokens&state=test' | grep -i 'location\\|evil'", authEndpoint),
			DiscoveredAt: time.Now(),
		}
	}
	return nil
}

// checkWeakState probes the authorization endpoint WITH a state parameter and
// inspects the state value the server echoes back (or the one the client would
// send). If the state parameter is too short (< 16 characters) or appears to
// be a simple counter or timestamp, it lacks sufficient entropy for CSRF
// protection.
func checkWeakState(ctx context.Context, client *http.Client, asset, authEndpoint string, pc probeClientID) *finding.Finding {
	// Send a legitimate-looking request with a proper state to get a redirect.
	// Then inspect the Location header for the state parameter the server echoes.
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", pc.id)
	params.Set("redirect_uri", "https://example.com/callback")
	params.Set("state", "a1") // deliberately short — 2 chars

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authEndpoint+"?"+params.Encode(), nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	resp.Body.Close()

	bodyStr := strings.ToLower(string(body))
	loc := resp.Header.Get("Location")

	// If the server rejected the client before reaching state validation, skip.
	if strings.Contains(bodyStr, "invalid_client") || strings.Contains(bodyStr, "client not found") {
		return nil
	}

	// Check if the server accepted the short state without complaint.
	// A secure server should either reject short states or at minimum echo
	// the state back in the redirect. If it redirects with our short state,
	// it accepted a low-entropy CSRF token.
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusOK {
		return nil
	}

	// Check if the 2-char state was echoed in the redirect Location.
	if loc != "" && strings.Contains(loc, "state=a1") {
		ev, note := confidenceNote(pc)
		ev["endpoint"] = authEndpoint
		ev["weak_state"] = "a1"
		ev["state_length"] = 2
		return &finding.Finding{
			CheckID:  finding.CheckOAuthWeakState,
			Module:   "deep",
			Scanner:  scannerName,
			Severity: finding.SeverityMedium,
			Asset:    asset,
			Title:    fmt.Sprintf("OAuth: weak state parameter accepted at %s", authEndpoint),
			Description: "The OAuth authorization endpoint accepted a state parameter with only 2 " +
				"characters of entropy. The state parameter must be a cryptographically random, " +
				"unguessable value of at least 16 characters to prevent CSRF attacks on the OAuth " +
				"flow. Short states, simple counters, or timestamps can be guessed or brute-forced " +
				"by an attacker. Generate state values using a CSPRNG with at least 128 bits (16 bytes) " +
				"of entropy, base64url-encoded." + note,
			Evidence:     ev,
			ProofCommand: fmt.Sprintf("curl -sI '%s?response_type=code&client_id=%s&redirect_uri=https://example.com/callback&state=a1' | grep -i 'location'", authEndpoint, pc.id),
			DiscoveredAt: time.Now(),
		}
	}

	return nil
}

// checkImplicitFlowAccepted sends response_type=token to the authorization
// endpoint and checks if the server actively accepts it (returns a redirect
// with an access token or a consent page). This is distinct from the surface
// check that only examines the OIDC discovery document — this confirms the
// deprecated implicit flow is actually functional.
func checkImplicitFlowAccepted(ctx context.Context, client *http.Client, asset, authEndpoint string, pc probeClientID) *finding.Finding {
	params := url.Values{}
	params.Set("response_type", "token")
	params.Set("client_id", pc.id)
	params.Set("redirect_uri", "https://example.com/callback")
	params.Set("state", "beaconimplicitcheck")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authEndpoint+"?"+params.Encode(), nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	resp.Body.Close()

	loc := resp.Header.Get("Location")
	bodyStr := strings.ToLower(string(body))

	// If the server rejected the client first, we can't conclude anything.
	if strings.Contains(bodyStr, "invalid_client") || strings.Contains(bodyStr, "client not found") {
		return nil
	}

	// The server should reject response_type=token with an error like
	// "unsupported_response_type". If instead it redirects to a login/consent
	// page or returns an access_token, the implicit flow is active.
	if strings.Contains(bodyStr, "unsupported_response_type") ||
		strings.Contains(bodyStr, "response_type") && strings.Contains(bodyStr, "not supported") {
		return nil // properly rejected
	}

	// Evidence of acceptance: redirect with access_token in fragment, or
	// a consent/login page (302/200 without rejection).
	accepted := false
	if strings.Contains(loc, "access_token=") || strings.Contains(loc, "#access_token") {
		accepted = true
	} else if (resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusFound) &&
		!strings.Contains(bodyStr, "error") &&
		!strings.Contains(bodyStr, "invalid") &&
		!strings.Contains(bodyStr, "unsupported") {
		// Server returned a page (likely login/consent) without rejecting
		// the response_type=token — the implicit flow is enabled.
		accepted = true
	}

	if !accepted {
		return nil
	}

	ev, note := confidenceNote(pc)
	ev["endpoint"] = authEndpoint
	ev["response_type"] = "token"
	ev["status_code"] = resp.StatusCode
	ev["location"] = loc

	return &finding.Finding{
		CheckID:  finding.CheckOAuthImplicitAccepted,
		Module:   "deep",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Asset:    asset,
		Title:    fmt.Sprintf("OAuth: implicit flow (response_type=token) accepted at %s", authEndpoint),
		Description: "The OAuth authorization endpoint accepted response_type=token, confirming " +
			"the deprecated implicit flow is actively functional. In the implicit flow, access " +
			"tokens are returned directly in the URL fragment (#access_token=...), exposing them " +
			"in browser history, Referer headers, proxy logs, and browser extensions. " +
			"The implicit flow is deprecated in OAuth 2.1 (draft-ietf-oauth-v2-1-10). " +
			"Migrate all clients to the authorization code flow with PKCE." + note,
		Evidence:     ev,
		ProofCommand: fmt.Sprintf("curl -sI '%s?response_type=token&client_id=%s&redirect_uri=https://example.com/callback&state=test' | grep -i 'location\\|HTTP/'", authEndpoint, pc.id),
		DiscoveredAt: time.Now(),
	}
}

func checkTokenLeakReferer(ctx context.Context, client *http.Client, asset, authEndpoint string, pc probeClientID) *finding.Finding {
	if authEndpoint == "" {
		return nil
	}

	params := url.Values{}
	params.Set("response_type", "token")
	params.Set("client_id", pc.id)
	params.Set("redirect_uri", "https://example.com/callback")
	params.Set("state", "beacontest")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authEndpoint+"?"+params.Encode(), nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	resp.Body.Close()

	loc := resp.Header.Get("Location")
	if loc == "" {
		return nil
	}
	locLower := strings.ToLower(loc)
	if !strings.Contains(locLower, "access_token=") && !strings.Contains(locLower, "#access_token") {
		return nil
	}

	ev, _ := confidenceNote(pc)
	ev["endpoint"] = authEndpoint
	ev["redirect_contains"] = "access_token"
	return &finding.Finding{
		CheckID:  finding.CheckOAuthTokenLeakReferer,
		Module:   "deep",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Asset:    asset,
		Title:    fmt.Sprintf("OAuth token returned in URL (Referer leak risk) at %s", authEndpoint),
		Description: "The OAuth authorization server returned an access token in the redirect URL " +
			"(implicit flow response). Tokens placed in URLs are sent in the Referer header to any " +
			"third-party resources loaded by the redirect target page, and are recorded in browser " +
			"history, server logs, and proxy logs. Migrate to authorization code flow with PKCE.",
		Evidence:     ev,
		ProofCommand: fmt.Sprintf("curl -sI '%s?response_type=token&client_id=test&redirect_uri=https://example.com/callback&state=test' | grep -i 'location\\|access_token'", authEndpoint),
		DiscoveredAt: time.Now(),
	}
}

func checkJWTNoVerification(ctx context.Context, client *http.Client, asset, base string) *finding.Finding {
	// Skip catch-all / wildcard servers that return 200 for any path — all
	// probes would be false positives on such servers.
	if oauthIsCatchAll(ctx, client, base) {
		return nil
	}

	fakeJWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
		".eyJzdWIiOiIxIiwiYWRtaW4iOnRydWUsImlhdCI6MTcwMDAwMDAwMH0" +
		".INVALIDSIGNATUREFORBEACONTEST"

	apiPaths := []string{"/api/v1/user", "/api/user", "/api/me", "/me", "/userinfo", "/profile"}

	for _, path := range apiPaths {
		u := base + path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Authorization", "Bearer "+fakeJWT)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK && len(body) > 10 {
			bodyStr := strings.ToLower(string(body))
			if strings.Contains(bodyStr, "error") || strings.Contains(bodyStr, "invalid") ||
				strings.Contains(bodyStr, "unauthorized") {
				continue
			}
			// Require JSON-like response — non-JSON 200s (HTML status pages, empty
			// bodies, plain text) are not evidence of a JWT bypass. A real user
			// endpoint must return a JSON object or array.
			trimmed := strings.TrimSpace(string(body))
			if !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") {
				continue
			}
			return &finding.Finding{
				CheckID:  finding.CheckJWTNoVerification,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityCritical,
				Asset:    asset,
				Title:    fmt.Sprintf("JWT signature not verified at %s", path),
				Description: fmt.Sprintf(
					"The endpoint at %s returned HTTP 200 when presented with a JWT "+
						"that has an invalid signature. The server is not verifying JWT "+
						"signatures before trusting the token claims. An attacker can forge "+
						"arbitrary JWT tokens (including admin:true) and gain unauthorized access.",
					u,
				),
				Evidence: map[string]any{
					"endpoint":        u,
					"fake_jwt_alg":    "HS256",
					"response_status": resp.StatusCode,
					"response_body":   string(body)[:min(200, len(body))],
				},
				ProofCommand: fmt.Sprintf("curl -s -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwiYWRtaW4iOnRydWV9.INVALIDSIG' '%s' | python3 -m json.tool", u),
				DiscoveredAt: time.Now(),
			}
		}
	}
	return nil
}

// ── New surface / deep checks ─────────────────────────────────────────────────

// checkTokenInFragment emits CheckOAuthTokenInFragment when the OIDC discovery
// document advertises "token" as a supported response_type. This indicates the
// implicit flow is enabled: access tokens are returned in the URL fragment
// (#access_token=…), leaking them into browser history, Referer headers, and
// server logs. This check targets the server-side advertisement, complementing
// checkTokenLeakReferer which requires an active deep-mode probe.
func checkTokenInFragment(asset string, doc *oidcDocument) *finding.Finding {
	var found []string
	for _, rt := range doc.ResponseTypesSupported {
		if strings.ToLower(rt) == "token" {
			found = append(found, rt)
		}
	}
	if len(found) == 0 {
		return nil
	}
	authEndpoint := doc.AuthorizationEndpoint
	return &finding.Finding{
		CheckID:  finding.CheckOAuthTokenInFragment,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Asset:    asset,
		Title:    "OAuth implicit flow advertised: access token returned in URL fragment",
		Description: "The OIDC discovery document lists \"token\" in response_types_supported, " +
			"meaning the server supports the implicit flow (response_type=token). In this flow " +
			"the access token is returned in the URL fragment (#access_token=…). Fragments are " +
			"visible in browser history, Referer headers sent to third-party resources, and " +
			"proxy/server logs. The implicit flow is deprecated in OAuth 2.1. Migrate to " +
			"authorization code flow with PKCE.",
		Evidence: map[string]any{
			"response_types_supported": doc.ResponseTypesSupported,
			"authorization_endpoint":   authEndpoint,
		},
		ProofCommand: fmt.Sprintf("curl -sI '%s?response_type=token&client_id=test&redirect_uri=https://example.com/callback&state=test' | grep -i 'location\\|access_token'", authEndpoint),
		DiscoveredAt: time.Now(),
	}
}

// checkTokenLongExpiry probes the token endpoint with a client_credentials
// grant and emits CheckOAuthTokenLongExpiry when the server responds with an
// access token whose expires_in value exceeds 86400 seconds (24 hours).
// 401/403 responses are silently ignored — those indicate the endpoint is
// correctly protected and the check cannot be completed.
func checkTokenLongExpiry(ctx context.Context, client *http.Client, asset, base, knownEndpoint string) *finding.Finding {
	endpoints := tokenEndpointPaths
	if knownEndpoint != "" {
		endpoints = append([]string{strings.TrimPrefix(knownEndpoint, base)}, endpoints...)
	}

	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	for _, path := range endpoints {
		var u string
		if strings.HasPrefix(path, "http") {
			u = path
		} else {
			u = base + path
		}

		body := url.Values{}
		body.Set("grant_type", "client_credentials")
		body.Set("client_id", "test")
		body.Set("client_secret", "test")

		req, err := http.NewRequestWithContext(probeCtx, http.MethodPost, u,
			bytes.NewBufferString(body.Encode()))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		resp.Body.Close()

		// 401/403 means endpoint is protected — expected, skip.
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			continue
		}
		// 404/405 — endpoint not here, try next.
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
			continue
		}

		if resp.StatusCode != http.StatusOK {
			continue
		}

		// Parse the JSON response for expires_in.
		var tokenResp struct {
			ExpiresIn int64 `json:"expires_in"`
		}
		if err := json.Unmarshal(respBody, &tokenResp); err != nil {
			continue
		}
		if tokenResp.ExpiresIn <= 0 {
			continue
		}
		if tokenResp.ExpiresIn <= 86400 {
			return nil // within acceptable threshold
		}

		hours := tokenResp.ExpiresIn / 3600
		return &finding.Finding{
			CheckID:  finding.CheckOAuthTokenLongExpiry,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityMedium,
			Asset:    asset,
			Title:    fmt.Sprintf("OAuth access token has excessively long expiry (%d hours)", hours),
			Description: fmt.Sprintf(
				"The token endpoint at %s issued an access token with expires_in=%d seconds (~%d hours). "+
					"Access tokens with lifetimes longer than 24 hours increase the window of opportunity "+
					"for an attacker who obtains a token through phishing, XSS, or a data breach. "+
					"Reduce access token lifetime to 15–60 minutes and use refresh tokens for long-lived sessions.",
				u, tokenResp.ExpiresIn, hours,
			),
			Evidence: map[string]any{
				"endpoint":   u,
				"expires_in": tokenResp.ExpiresIn,
				"hours":      hours,
			},
			ProofCommand: fmt.Sprintf("curl -s -X POST '%s' -H 'Content-Type: application/x-www-form-urlencoded' -d 'grant_type=client_credentials&client_id=test&client_secret=test' | python3 -c \"import sys,json; d=json.load(sys.stdin); print('expires_in:', d.get('expires_in'))\"", u),
			DiscoveredAt: time.Now(),
		}
	}
	return nil
}

// checkRefreshNotRotated attempts to use the same refresh token twice against
// the token endpoint. If both requests succeed (HTTP 200), the server is not
// rotating refresh tokens — an attacker who obtains a refresh token can use it
// indefinitely. The check is skipped when no refresh token is discoverable via
// the token endpoint probe.
func checkRefreshNotRotated(ctx context.Context, client *http.Client, asset, base, knownEndpoint string) *finding.Finding {
	endpoints := tokenEndpointPaths
	if knownEndpoint != "" {
		endpoints = append([]string{strings.TrimPrefix(knownEndpoint, base)}, endpoints...)
	}

	// First, attempt to obtain a refresh token by probing the token endpoint.
	// In practice a real refresh token won't be obtained this way, but if the
	// server returns one in a test/demo configuration we will detect it.
	// More practically: check whether the endpoint exposes a refresh_token in
	// its response to a client_credentials grant (misconfigured servers do this).
	var refreshToken string
	var tokenURL string

	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	for _, path := range endpoints {
		var u string
		if strings.HasPrefix(path, "http") {
			u = path
		} else {
			u = base + path
		}

		body := url.Values{}
		body.Set("grant_type", "client_credentials")
		body.Set("client_id", "test")
		body.Set("client_secret", "test")

		req, err := http.NewRequestWithContext(probeCtx, http.MethodPost, u,
			bytes.NewBufferString(body.Encode()))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			continue
		}

		var tokenResp struct {
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.Unmarshal(respBody, &tokenResp); err != nil || tokenResp.RefreshToken == "" {
			continue
		}
		refreshToken = tokenResp.RefreshToken
		tokenURL = u
		break
	}

	if refreshToken == "" {
		return nil // no refresh token available — skip check
	}

	// Use the refresh token twice; if both succeed the server is not rotating.
	successCount := 0
	for range 2 {
		body := url.Values{}
		body.Set("grant_type", "refresh_token")
		body.Set("refresh_token", refreshToken)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL,
			bytes.NewBufferString(body.Encode()))
		if err != nil {
			break
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			break
		}
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			successCount++
		}
	}

	if successCount < 2 {
		return nil
	}

	return &finding.Finding{
		CheckID:  finding.CheckOAuthRefreshNotRotated,
		Module:   "deep",
		Scanner:  scannerName,
		Severity: finding.SeverityMedium,
		Asset:    asset,
		Title:    fmt.Sprintf("OAuth refresh token not rotated at %s", tokenURL),
		Description: "The OAuth token endpoint accepted the same refresh token in two consecutive " +
			"requests. Refresh tokens should be rotated on every use (RFC 6749 §10.4): once a " +
			"refresh token is exchanged for a new access token, the old refresh token must be " +
			"invalidated. Without rotation, a stolen refresh token can be used indefinitely by " +
			"an attacker even after the legitimate user has refreshed their session.",
		Evidence: map[string]any{
			"endpoint":      tokenURL,
			"reuse_success": successCount,
		},
		ProofCommand: fmt.Sprintf("# Obtain refresh_token first, then:\ncurl -s -X POST '%s' -H 'Content-Type: application/x-www-form-urlencoded' -d 'grant_type=refresh_token&refresh_token=<TOKEN>' | python3 -m json.tool", tokenURL),
		DiscoveredAt: time.Now(),
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func baseURL(ctx context.Context, client *http.Client, asset string) string {
	for _, scheme := range []string{"https", "http"} {
		u := scheme + "://" + asset
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		if resp.StatusCode >= 500 {
			continue
		}
		// Reject HTTP responses that indicate the server is HTTPS-only
		// (e.g., "plain HTTP request was sent to HTTPS port" from nginx/Cloudflare).
		// These produce a non-5xx status but are not valid HTTP bases.
		if scheme == "http" {
			bodyLower := strings.ToLower(string(body))
			if strings.Contains(bodyLower, "https port") ||
				strings.Contains(bodyLower, "plain http") ||
				strings.Contains(bodyLower, "use https") {
				continue
			}
		}
		return u
	}
	return ""
}

// oauthIsCatchAll returns true when the server responds HTTP 200 to a path
// that cannot exist on any real application, indicating a wildcard / catch-all
// configuration where JWT probe responses would all be false positives.
func oauthIsCatchAll(ctx context.Context, client *http.Client, base string) bool {
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

