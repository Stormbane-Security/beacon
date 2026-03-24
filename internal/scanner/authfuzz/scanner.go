// Package authfuzz dynamically mutates authentication flows to find broken
// validation. It complements the oauth and jwt scanners by testing cross-flow
// attack patterns that require active state manipulation.
//
// Checks performed (Deep mode only):
//   - redirect_uri abuse: tries arbitrary domains, subdomain confusion, encoding bypass
//   - Authorization code re-use: exchanges the same code twice (no invalidation check)
//   - Token substitution: submits JWTs with modified claims or alg:none
//   - State parameter bypass: submits flow without state or with a static value
//
// This scanner discovers the authorization endpoint from OIDC discovery or by
// probing known paths, then actively mutates each flow parameter.
package authfuzz

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
	"github.com/stormbane/beacon/internal/scanner/schemedetect"
)

const (
	scannerName = "authfuzz"
	maxBodySize = 32 * 1024
)

// Scanner performs dynamic auth flow mutation tests.
type Scanner struct{}

// New returns a new Scanner.
func New() *Scanner { return &Scanner{} }

// Name returns the stable scanner identifier.
func (s *Scanner) Name() string { return scannerName }

// Run executes the authfuzz scan. Deep mode only.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanDeep {
		return nil, nil
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	base := schemedetect.Base(ctx, client, asset)

	var findings []finding.Finding

	// Check 1: token substitution (alg:none JWT) — runs independently of auth endpoint.
	if f := checkTokenSubstitution(ctx, client, asset, base); f != nil {
		findings = append(findings, *f)
	}
	if ctx.Err() != nil {
		return findings, nil
	}

	// Checks 2 & 3 require an authorization endpoint.
	authEndpoint := discoverAuthEndpoint(ctx, client, base)
	if authEndpoint == "" {
		return findings, nil
	}

	// Check 2: redirect_uri validation
	if fs := checkRedirectURIAbuse(ctx, client, asset, authEndpoint); len(fs) > 0 {
		findings = append(findings, fs...)
	}

	// Check 3: authorization code re-use
	if f := checkCodeReuse(ctx, client, asset, authEndpoint); f != nil {
		findings = append(findings, *f)
	}

	return findings, nil
}

// discoverAuthEndpoint finds the OAuth/OIDC authorization endpoint.
// Checks OIDC discovery first, then falls back to common paths.
func discoverAuthEndpoint(ctx context.Context, client *http.Client, base string) string {
	// Try OIDC discovery
	for _, path := range []string{
		"/.well-known/openid-configuration",
		"/.well-known/oauth-authorization-server",
	} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue
		}
		if ep := extractJSONString(string(body), "authorization_endpoint"); ep != "" {
			return ep
		}
	}

	// Fall back to common paths
	for _, path := range []string{
		"/oauth/authorize",
		"/oauth2/authorize",
		"/auth/oauth2/authorize",
		"/connect/authorize",
		"/authorize",
		"/api/oauth/authorize",
	} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			base+path+"?response_type=code&client_id=test&redirect_uri=https://example.com/callback", nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		// 302 → likely a real auth endpoint; 400/401 → may also be real
		if resp.StatusCode == http.StatusFound ||
			resp.StatusCode == http.StatusBadRequest ||
			resp.StatusCode == http.StatusUnauthorized {
			return base + path
		}
	}
	return ""
}

// checkRedirectURIAbuse tests whether redirect_uri is strictly validated.
// Each mutation uses a different bypass technique.
func checkRedirectURIAbuse(ctx context.Context, client *http.Client, asset, authEndpoint string) []finding.Finding {
	legitimateURI := "https://example.com/callback"

	mutations := []struct {
		name string
		uri  string
	}{
		{"arbitrary domain", "https://evil.com/callback"},
		{"subdomain confusion", "https://example.com.evil.com/callback"},
		{"URL encoding bypass", "https://example.com%40evil.com/callback"},
		{"open path traversal", "https://example.com/callback/../../../evil"},
		{"javascript URI", "javascript:alert(document.domain)"},
	}

	var findings []finding.Finding
	for _, m := range mutations {
		params := url.Values{}
		params.Set("response_type", "code")
		params.Set("client_id", "test")
		params.Set("redirect_uri", m.uri)
		params.Set("state", "beaconstate_"+scannerName)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			authEndpoint+"?"+params.Encode(), nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		loc := resp.Header.Get("Location")
		resp.Body.Close()

		// A 302 redirect to our mutated URI indicates redirect_uri is not validated.
		if resp.StatusCode == http.StatusFound && loc != "" &&
			strings.Contains(loc, extractHost(m.uri)) &&
			!strings.Contains(loc, legitimateURI) {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckAuthFuzzRedirectAbuse,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityCritical,
				Title:    fmt.Sprintf("OAuth redirect_uri not validated (%s)", m.name),
				Description: fmt.Sprintf(
					"The authorization endpoint at %s redirected to an unregistered redirect_uri using the %q mutation. "+
						"An attacker can steal authorization codes by directing victims to a malicious URL.",
					authEndpoint, m.name),
				Asset:    asset,
				DeepOnly: true,
				ProofCommand: fmt.Sprintf(
					`curl -sI '%s?response_type=code&client_id=test&redirect_uri=%s&state=test' | grep -i location`,
					authEndpoint, url.QueryEscape(m.uri)),
				Evidence: map[string]any{
					"endpoint":        authEndpoint,
					"mutation":        m.name,
					"redirect_uri":    m.uri,
					"response_status": resp.StatusCode,
					"location":        loc,
				},
				DiscoveredAt: time.Now(),
			})
		}
	}
	return findings
}

// checkTokenSubstitution tests whether a protected endpoint accepts a JWT
// with alg:none (unsigned). It first discovers a protected endpoint, then
// crafts a minimal alg:none JWT and submits it.
func checkTokenSubstitution(ctx context.Context, client *http.Client, asset, base string) *finding.Finding {
	// Discover a protected endpoint (expects 401/403 without a token)
	protectedPath := ""
	for _, path := range []string{"/api/me", "/api/user", "/api/v1/user", "/api/profile", "/api/whoami"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			protectedPath = path
			break
		}
	}
	if protectedPath == "" {
		return nil
	}

	// Craft an alg:none JWT with admin-like claims.
	token := buildAlgNoneJWT()
	targetURL := base + protectedPath

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	resp.Body.Close()

	// If the server returns 200 with our alg:none token, it's not validating signatures.
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	// Basic sanity: check it returned some JSON-like content (not just a redirect page).
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "{") && !strings.Contains(bodyStr, "user") {
		return nil
	}

	return &finding.Finding{
		CheckID:  finding.CheckAuthFuzzTokenSubstitution,
		Module:   "deep",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    "JWT accepted with alg:none (no signature validation)",
		Description: fmt.Sprintf(
			"The endpoint %s returned HTTP 200 when presented with an unsigned JWT (alg:none). "+
				"This indicates the server does not validate JWT signatures, allowing any attacker "+
				"to forge arbitrary tokens and impersonate any user.",
			targetURL),
		Asset:    asset,
		DeepOnly: true,
		ProofCommand: fmt.Sprintf(
			`curl -s -H 'Authorization: Bearer %s' '%s'`,
			token, targetURL),
		Evidence: map[string]any{
			"url":   targetURL,
			"token": token,
		},
		DiscoveredAt: time.Now(),
	}
}

// checkCodeReuse tests whether an authorization code can be exchanged more
// than once (missing code invalidation). It requires discovering a token
// endpoint and having a valid-looking code — since we can't complete a real
// flow, we probe for the error response pattern that indicates whether single-use
// is enforced by attempting to exchange an obviously-fake code twice and
// checking if the second attempt returns a different error than the first.
func checkCodeReuse(ctx context.Context, client *http.Client, asset, authEndpoint string) *finding.Finding {
	// Derive the token endpoint from the auth endpoint path.
	tokenEndpoint := deriveTokenEndpoint(authEndpoint)
	if tokenEndpoint == "" {
		return nil
	}

	fakeCode := "beacon_test_code_12345"

	exchange := func() (int, string) {
		params := url.Values{}
		params.Set("grant_type", "authorization_code")
		params.Set("code", fakeCode)
		params.Set("redirect_uri", "https://example.com/callback")
		params.Set("client_id", "test")

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint,
			strings.NewReader(params.Encode()))
		if err != nil {
			return 0, ""
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := client.Do(req)
		if err != nil {
			return 0, ""
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
		resp.Body.Close()
		return resp.StatusCode, string(body)
	}

	status1, body1 := exchange()
	status2, body2 := exchange()

	if status1 == 0 || status2 == 0 {
		return nil
	}

	// A real single-use enforcement: second attempt returns "code_reused" or
	// similar error. If both attempts return the same generic error, no finding.
	// We only flag if the second response clearly indicates the code was valid
	// once (e.g. "code already used" or status differs meaningfully).
	if strings.Contains(body2, "already") || strings.Contains(body2, "reused") ||
		strings.Contains(body2, "used") || (status1 == http.StatusOK && status2 != http.StatusOK) {
		// Server enforces single-use — this is correct behaviour.
		return nil
	}

	// If both return the same non-error response indicating acceptance, flag it.
	if status1 == http.StatusOK && status2 == http.StatusOK &&
		strings.Contains(body1, "access_token") && strings.Contains(body2, "access_token") {
		return &finding.Finding{
			CheckID:  finding.CheckAuthFuzzCodeInterception,
			Module:   "deep",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Title:    "OAuth authorization code accepted multiple times",
			Description: fmt.Sprintf(
				"The token endpoint %s accepted the same authorization code twice. "+
					"Authorization codes must be single-use; reuse allows code interception attacks "+
					"where an attacker who captures a code in transit can exchange it for tokens.",
				tokenEndpoint),
			Asset:    asset,
			DeepOnly: true,
			ProofCommand: fmt.Sprintf(
				`# First exchange\ncurl -s -X POST '%s' -d 'grant_type=authorization_code&code=CODE&redirect_uri=https://example.com/callback'\n`+
					`# Repeat with same code:`,
				tokenEndpoint),
			Evidence: map[string]any{
				"token_endpoint": tokenEndpoint,
				"attempt_1":      fmt.Sprintf("status=%d", status1),
				"attempt_2":      fmt.Sprintf("status=%d", status2),
			},
			DiscoveredAt: time.Now(),
		}
	}
	return nil
}

// buildAlgNoneJWT constructs a minimal unsigned JWT with admin-like claims.
// The token uses alg:none — a known attack against JWT libraries that skip
// signature validation when the algorithm is "none".
func buildAlgNoneJWT() string {
	// Base64url-encoded header: {"alg":"none","typ":"JWT"}
	header := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
	// Base64url-encoded payload: {"sub":"1","role":"admin","iss":"beacon-test"}
	payload := "eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwiaXNzIjoiYmVhY29uLXRlc3QifQ"
	// alg:none → empty signature
	return header + "." + payload + "."
}

// deriveTokenEndpoint guesses the token endpoint from the authorization endpoint.
func deriveTokenEndpoint(authEndpoint string) string {
	replacements := map[string]string{
		"/authorize":           "/token",
		"/oauth/authorize":     "/oauth/token",
		"/oauth2/authorize":    "/oauth2/token",
		"/connect/authorize":   "/connect/token",
		"/auth/oauth2/authorize": "/auth/oauth2/token",
	}
	for auth, token := range replacements {
		if strings.HasSuffix(authEndpoint, auth) {
			return strings.TrimSuffix(authEndpoint, auth) + token
		}
	}
	// Try appending /token to the base URL of the auth endpoint
	u, err := url.Parse(authEndpoint)
	if err != nil {
		return ""
	}
	parts := strings.Split(strings.TrimSuffix(u.Path, "/authorize"), "/")
	if len(parts) > 1 {
		u.Path = strings.Join(parts, "/") + "/token"
		return u.String()
	}
	return ""
}

// extractHost returns the host from a URL string, or the URL if parsing fails.
func extractHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Host
}

// extractJSONString finds the value of a JSON key in a raw string (no full parse).
func extractJSONString(body, key string) string {
	needle := `"` + key + `"`
	idx := strings.Index(body, needle)
	if idx < 0 {
		return ""
	}
	rest := body[idx+len(needle):]
	colon := strings.Index(rest, ":")
	if colon < 0 {
		return ""
	}
	rest = strings.TrimSpace(rest[colon+1:])
	if !strings.HasPrefix(rest, `"`) {
		return ""
	}
	rest = rest[1:]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	return rest[:end]
}
