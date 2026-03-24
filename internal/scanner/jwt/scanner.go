// Package jwt is a surface-mode scanner that discovers JWT tokens in HTTP
// responses (cookies, body, and Authorization header) and inspects them for
// common weaknesses: insecure algorithms, long-lived expiry, and sensitive data
// embedded in the unencrypted payload.
package jwt

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const scannerName = "jwt"

// jwtPattern matches the three base64url-encoded segments of a JWT.
var jwtPattern = regexp.MustCompile(`[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*`)

// strongAlgorithms is the set of algorithms considered cryptographically sound.
var strongAlgorithms = map[string]bool{
	"RS256": true, "RS384": true, "RS512": true,
	"ES256": true, "ES384": true, "ES512": true,
	"PS256": true, "PS384": true, "PS512": true,
}

// sensitiveDataFields are PII / secret field names that should not appear in an
// observable (unencrypted) token payload.
var sensitiveDataFields = []string{
	"ssn", "email", "phone", "password", "credit", "card",
	"dob", "address", "zip",
}

// sensitiveRoleFields are authorization-bearing field names whose presence in a
// readable token payload is worth flagging.
var sensitiveRoleFields = []string{
	"role", "admin", "is_admin", "permissions", "scope",
}

// Scanner discovers and analyses JWT tokens found in HTTP responses.
type Scanner struct{}

// New returns a new Scanner.
func New() *Scanner { return &Scanner{} }

// Name returns the stable scanner identifier.
func (s *Scanner) Name() string { return scannerName }

// Run fetches the asset root and inspects any JWTs found in the response.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}

	var resp *http.Response
	var err error
	for _, scheme := range []string{"https", "http"} {
		url := scheme + "://" + asset + "/"
		var req *http.Request
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		resp, err = client.Do(req)
		if err != nil {
			continue
		}
		break
	}
	if err != nil || resp == nil {
		return nil, nil
	}
	defer resp.Body.Close()

	// Catch-all / wildcard detection: if the server returns 200 for a random
	// path that cannot exist, all JWT probe responses will be false positives.
	if isCatchAll(ctx, client, resp.Request.URL.Scheme+"://"+asset) {
		return nil, nil
	}

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	bodyStr := string(bodyBytes)

	// Collect JWT candidates from multiple sources.
	var candidates []string

	// Set-Cookie headers.
	for _, cookie := range resp.Header["Set-Cookie"] {
		for _, m := range jwtPattern.FindAllString(cookie, -1) {
			candidates = append(candidates, m)
		}
	}

	// Response body.
	for _, m := range jwtPattern.FindAllString(bodyStr, -1) {
		candidates = append(candidates, m)
	}

	// Authorization header in response (non-standard but seen in some APIs).
	if auth := resp.Header.Get("Authorization"); auth != "" {
		for _, m := range jwtPattern.FindAllString(auth, -1) {
			candidates = append(candidates, m)
		}
	}

	// Deduplicate by header.payload (ignore signature).
	seen := make(map[string]bool)
	var unique []string
	for _, c := range candidates {
		parts := strings.Split(c, ".")
		if len(parts) < 2 {
			continue
		}
		key := parts[0] + "." + parts[1]
		if !seen[key] {
			seen[key] = true
			unique = append(unique, c)
		}
	}

	var findings []finding.Finding
	for _, token := range unique {
		fs := analyseToken(asset, token)
		findings = append(findings, fs...)
	}

	// JWKS key analysis — runs in both surface and deep mode.
	base := "https://" + asset
	jwksFindings := checkJWKSKeys(ctx, client, asset, base)
	if len(jwksFindings) == 0 {
		base = "http://" + asset
		jwksFindings = checkJWKSKeys(ctx, client, asset, base)
	}
	findings = append(findings, jwksFindings...)

	// Algorithm confusion check — deep mode only (sends forged tokens).
	if scanType == module.ScanDeep {
		if base == "http://"+asset {
			// already resolved above; reuse the working base
		} else {
			base = "https://" + asset
		}
		if f := checkAlgorithmConfusion(ctx, client, asset, base); f != nil {
			findings = append(findings, *f)
		}
		if f := checkAudienceMissing(ctx, client, asset, base); f != nil {
			findings = append(findings, *f)
		}
		if f := checkIssuerNotValidated(ctx, client, asset, base); f != nil {
			findings = append(findings, *f)
		}
	}

	return findings, nil
}

// analyseToken decodes a JWT and emits findings for any issues detected.
func analyseToken(asset, token string) []finding.Finding {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil
	}

	// JWE tokens have 5 parts — we cannot inspect the encrypted payload.
	// Still decode the header for algorithm checks but skip payload analysis.
	isJWE := len(parts) == 5

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil
	}

	header := string(headerJSON)

	// RFC 7519 requires the "alg" header. If absent this is not a JWT —
	// it may be a pagination cursor, signed URL, or other base64url triplet.
	// Skip to avoid false positives on non-JWT encoded tokens.
	alg := extractStringField(header, "alg")
	if alg == "" {
		return nil
	}

	// For JWE we cannot read the payload — skip payload-dependent checks.
	if isJWE {
		return nil
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}

	payload := string(payloadJSON)

	var findings []finding.Finding

	// --- Algorithm checks ---

	if strings.EqualFold(alg, "none") {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckJWTWeakAlg,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityCritical,
			Title:    "JWT uses 'none' algorithm – signature verification disabled",
			Description: "A JWT with alg:none carries no signature. Any party can forge arbitrary " +
				"claims by crafting a token and setting alg to 'none'. This completely bypasses " +
				"authentication and authorization controls. Replace with RS256 or ES256 and reject " +
				"any token whose header specifies alg:none on the server side.",
			Asset: asset,
			Evidence: map[string]any{
				"algorithm":    alg,
				"jwt_header":   header,
				"jwt_fragment": truncate(token, 80),
			},
			DiscoveredAt: time.Now(),
		})
	} else if alg != "" && !strongAlgorithms[alg] {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckJWTWeakAlg,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityMedium,
			Title:    fmt.Sprintf("JWT uses weak symmetric algorithm: %s", alg),
			Description: fmt.Sprintf(
				"The JWT is signed with %s, a symmetric (shared-secret) algorithm. If the secret is "+
					"weak, guessable, or reused across services an attacker can forge tokens. Prefer an "+
					"asymmetric algorithm such as RS256 or ES256 so that only the issuer can sign tokens.",
				alg,
			),
			Asset: asset,
			Evidence: map[string]any{
				"algorithm":    alg,
				"jwt_header":   header,
				"jwt_fragment": truncate(token, 80),
			},
			DiscoveredAt: time.Now(),
		})
	}

	// --- Expiry checks ---
	now := time.Now().Unix()
	exp, hasExp := extractIntField(payload, "exp")
	_, hasIat := extractIntField(payload, "iat")

	if !hasExp {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckJWTLongExpiry,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityMedium,
			Title:    "JWT has no expiry (exp claim absent)",
			Description: "The token does not contain an exp claim, meaning it never expires. " +
				"Stolen or leaked tokens remain valid indefinitely. Add a short-lived exp claim " +
				"(e.g. 15 minutes for access tokens) and implement token refresh.",
			Asset: asset,
			Evidence: map[string]any{
				"has_iat":      hasIat,
				"jwt_fragment": truncate(token, 80),
			},
			DiscoveredAt: time.Now(),
		})
	} else if exp-now > 7*24*60*60 {
		daysValid := (exp - now) / 86400
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckJWTLongExpiry,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityMedium,
			Title:    fmt.Sprintf("JWT expiry is excessively long (%d days)", daysValid),
			Description: fmt.Sprintf(
				"The token expires in approximately %d days. Long-lived tokens increase the window of "+
					"opportunity for an attacker who obtains a token through phishing, XSS, or a data breach. "+
					"Reduce token lifetime to 15–60 minutes for access tokens and implement refresh token rotation.",
				daysValid,
			),
			Asset: asset,
			Evidence: map[string]any{
				"exp":          exp,
				"days_valid":   daysValid,
				"jwt_fragment": truncate(token, 80),
			},
			DiscoveredAt: time.Now(),
		})
	}

	// --- Sensitive payload checks ---
	payloadLower := strings.ToLower(payload)

	// PII / secret fields.
	var foundPII []string
	for _, field := range sensitiveDataFields {
		if strings.Contains(payloadLower, `"`+field+`"`) {
			foundPII = append(foundPII, field)
		}
	}
	if len(foundPII) > 0 {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckJWTSensitivePayload,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Title:    fmt.Sprintf("JWT payload contains sensitive PII fields: %s", strings.Join(foundPII, ", ")),
			Description: "The JWT payload is base64-encoded but not encrypted. Anyone who intercepts the " +
				"token – through network eavesdropping, browser storage access, or log files – can decode " +
				"and read the PII contained within. Move sensitive personal data out of the token payload " +
				"or use JWE (JSON Web Encryption) to protect the claims.",
			Asset: asset,
			Evidence: map[string]any{
				"sensitive_fields": foundPII,
				"jwt_fragment":     truncate(token, 80),
			},
			DiscoveredAt: time.Now(),
		})
	}

	// Role / authorisation fields.
	var foundRole []string
	for _, field := range sensitiveRoleFields {
		if strings.Contains(payloadLower, `"`+field+`"`) {
			foundRole = append(foundRole, field)
		}
	}
	if len(foundRole) > 0 {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckJWTSensitivePayload,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityMedium,
			Title:    fmt.Sprintf("JWT payload exposes authorization claims: %s", strings.Join(foundRole, ", ")),
			Description: "The token payload contains authorization-bearing claims (role, permissions, etc.) " +
				"that are readable by anyone who holds the token. While this is common practice, it allows " +
				"an attacker to enumerate privilege levels and craft targeted privilege-escalation attacks. " +
				"Ensure server-side authorization never relies solely on client-supplied token claims without " +
				"re-validating them against an authoritative store.",
			Asset: asset,
			Evidence: map[string]any{
				"role_fields":  foundRole,
				"jwt_fragment": truncate(token, 80),
			},
			DiscoveredAt: time.Now(),
		})
	}

	// --- Encryption check (JWE) ---
	// Build a combined claims map for the helpers below.
	claims := buildClaimsMap(payload)
	if f := checkJWTEncryption(asset, parts, claims); f != nil {
		findings = append(findings, *f)
	}

	// --- Replay / jti check ---
	if f := checkJTIMissing(asset, claims); f != nil {
		findings = append(findings, *f)
	}

	return findings
}

// buildClaimsMap parses the raw JSON payload into a string-keyed map.
// On parse failure it returns an empty map so callers need not handle nil.
func buildClaimsMap(payloadJSON string) map[string]any {
	var m map[string]any
	if err := json.Unmarshal([]byte(payloadJSON), &m); err != nil || m == nil {
		return map[string]any{}
	}
	return m
}

// extractStringField parses a JSON string value for a given key using simple
// string scanning. Handles `"key":"value"` and `"key": "value"`.
func extractStringField(json, key string) string {
	needle := `"` + key + `"`
	idx := strings.Index(json, needle)
	if idx < 0 {
		return ""
	}
	rest := json[idx+len(needle):]
	// Skip optional whitespace and colon.
	rest = strings.TrimLeft(rest, " \t\r\n:")
	rest = strings.TrimLeft(rest, " \t\r\n")
	if len(rest) == 0 || rest[0] != '"' {
		return ""
	}
	rest = rest[1:]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// extractIntField parses a JSON numeric value for the given key.
func extractIntField(jsonStr, key string) (int64, bool) {
	needle := `"` + key + `"`
	idx := strings.Index(jsonStr, needle)
	if idx < 0 {
		return 0, false
	}
	rest := jsonStr[idx+len(needle):]
	rest = strings.TrimLeft(rest, " \t\r\n:")
	rest = strings.TrimLeft(rest, " \t\r\n")

	// Extract the digit sequence (with optional leading minus).
	var num strings.Builder
	for _, ch := range rest {
		if ch == '-' && num.Len() == 0 {
			num.WriteRune(ch)
		} else if ch >= '0' && ch <= '9' {
			num.WriteRune(ch)
		} else {
			break
		}
	}
	if num.Len() == 0 {
		return 0, false
	}
	val, err := strconv.ParseInt(num.String(), 10, 64)
	if err != nil {
		return 0, false
	}
	return val, true
}

// truncate returns at most n characters of s followed by "…" if truncated.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// allSensitiveFields is the union of PII and role fields used by encryption /
// replay checks that need a combined sensitive-field test.
var allSensitiveFields = append(sensitiveDataFields, sensitiveRoleFields...)

// checkJWTEncryption emits a finding when a JWT with sensitive claims is not
// encrypted (not JWE). A standard JWT has 3 parts (2 dots); a JWE has 5 parts
// (4 dots). If the token is a plain JWT AND contains sensitive fields the
// payload is readable by anyone who holds the token.
func checkJWTEncryption(asset string, parts []string, claims map[string]any) *finding.Finding {
	if len(parts) != 3 {
		return nil // JWE or unexpected format — skip
	}
	var found []string
	for _, field := range allSensitiveFields {
		if _, ok := claims[field]; ok {
			found = append(found, field)
		}
	}
	if len(found) == 0 {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckJWTEncryptionMissing,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityMedium,
		Asset:    asset,
		Title:    fmt.Sprintf("JWT with sensitive claims is not encrypted (JWE): %s", strings.Join(found, ", ")),
		Description: "The JWT carries sensitive claims but is not a JSON Web Encryption (JWE) token — " +
			"it has only 3 parts, meaning the payload is base64-encoded but not encrypted. Any party " +
			"with access to the token (via logs, browser storage, or network interception) can decode " +
			"and read these claims. Consider using JWE to encrypt the token payload, or move sensitive " +
			"data out of the token entirely.",
		Evidence: map[string]any{
			"sensitive_fields": found,
			"parts":            len(parts),
		},
		DiscoveredAt: time.Now(),
	}
}

// checkJTIMissing emits a finding when a JWT has no jti (JWT ID) claim.
// Without jti the token cannot be tracked or revoked, and replay attacks are
// trivial because the server has no per-token identifier to check against a
// deny-list.
func checkJTIMissing(asset string, claims map[string]any) *finding.Finding {
	if _, ok := claims["jti"]; ok {
		return nil
	}
	return &finding.Finding{
		CheckID:  finding.CheckJWTReplayMissing,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityMedium,
		Asset:    asset,
		Title:    "JWT is missing jti claim — replay attacks not preventable",
		Description: "The JWT does not contain a jti (JWT ID) claim. Without a unique per-token " +
			"identifier the server cannot maintain a token deny-list or detect replay attacks. " +
			"An attacker who obtains a valid token can reuse it repeatedly until it expires. " +
			"Add a cryptographically random jti to every issued token and check it server-side.",
		Evidence:     map[string]any{},
		DiscoveredAt: time.Now(),
	}
}

// jwksProbePaths are the well-known locations of JWKS documents.
var jwksProbePaths = []string{
	"/.well-known/jwks.json",
	"/oauth/discovery/keys",
	"/oauth2/v1/certs",
	"/api/v1/identity/oidc/.well-known/keys",
}

// jwksDocument is the minimal structure of a JWKS response.
type jwksDocument struct {
	Keys []jwksKey `json:"keys"`
}

type jwksKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"` // RSA modulus, base64url-encoded
	Alg string `json:"alg"`
}

// craftHS256JWT builds a minimal JWT signed with HMAC-SHA256 using keyBytes as
// the secret. This is used in the algorithm confusion probe where an RSA/EC
// public key's raw modulus bytes are used as the HMAC secret — exploiting
// servers that accept HS256 tokens signed with the known public key material.
func craftHS256JWT(keyBytes []byte) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	iat := time.Now().Unix()
	payload := base64.RawURLEncoding.EncodeToString([]byte(
		fmt.Sprintf(`{"sub":"beacon-test","iat":%d}`, iat),
	))
	sigInput := header + "." + payload
	mac := hmac.New(sha256.New, keyBytes)
	mac.Write([]byte(sigInput)) //nolint:errcheck
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return sigInput + "." + sig
}

// checkAlgorithmConfusion fetches the first RSA/EC key from any reachable JWKS
// endpoint and then submits an HS256 JWT (signed with the public key material)
// to common API endpoints. If the server returns 200 the server is vulnerable
// to an algorithm-confusion attack.
func checkAlgorithmConfusion(ctx context.Context, client *http.Client, asset, base string) *finding.Finding {
	// Probe known JWKS paths.
	var keyBytes []byte
	var jwksURL string
	for _, path := range jwksProbePaths {
		u := base + path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue
		}
		var doc jwksDocument
		if err := json.Unmarshal(body, &doc); err != nil || len(doc.Keys) == 0 {
			continue
		}
		// Use the first RSA or EC key with a non-empty modulus / x-coordinate.
		for _, k := range doc.Keys {
			kty := strings.ToUpper(k.Kty)
			if kty == "RSA" && k.N != "" {
				nb, err := base64.RawURLEncoding.DecodeString(k.N)
				if err == nil && len(nb) > 0 {
					keyBytes = nb
					jwksURL = u
					break
				}
			} else if (kty == "EC" || kty == "OKP") && k.N != "" {
				nb, err := base64.RawURLEncoding.DecodeString(k.N)
				if err == nil && len(nb) > 0 {
					keyBytes = nb
					jwksURL = u
					break
				}
			}
		}
		if len(keyBytes) > 0 {
			break
		}
	}
	if len(keyBytes) == 0 {
		return nil // no JWKS or no usable key found
	}

	forgedToken := craftHS256JWT(keyBytes)

	// Submit the forged token to common protected API paths.
	apiPaths := []string{"/api/v1/users", "/api/me", "/profile", "/api/user", "/me"}
	for _, path := range apiPaths {
		u := base + path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Authorization", "Bearer "+forgedToken)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			bodyLower := strings.ToLower(string(body))
			// Skip responses that explicitly contain error indicators.
			if strings.Contains(bodyLower, "unauthorized") ||
				strings.Contains(bodyLower, "invalid") ||
				strings.Contains(bodyLower, "error") {
				continue
			}
			return &finding.Finding{
				CheckID:  finding.CheckJWTAlgorithmConfusion,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityCritical,
				Asset:    asset,
				Title:    fmt.Sprintf("JWT algorithm confusion: RS256 public key accepted as HS256 secret at %s", path),
				Description: "The server accepted a JWT signed with HMAC-SHA256 using the RSA public key " +
					"modulus as the HMAC secret. This is a classic algorithm-confusion attack: the server " +
					"validates HS256 tokens using the public key as the shared secret, which an attacker " +
					"can read from the JWKS endpoint and use to forge arbitrary tokens. " +
					"Fix: explicitly reject HS256/symmetric algorithms on the server and only accept the " +
					"expected asymmetric algorithm (RS256/ES256).",
				Evidence: map[string]any{
					"jwks_url":        jwksURL,
					"endpoint":        u,
					"forged_alg":      "HS256",
					"response_status": resp.StatusCode,
				},
				DiscoveredAt: time.Now(),
			}
		}
	}
	return nil
}

// craftJWT builds a minimal JWT with the given header and payload JSON strings,
// signed with HMAC-SHA256 using keyBytes as the secret. Pass nil keyBytes for
// an unsigned probe (signature will be a dummy value).
func craftJWT(headerJSON, payloadJSON string, keyBytes []byte) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))
	payload := base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))
	sigInput := header + "." + payload
	if len(keyBytes) == 0 {
		return sigInput + ".beacon-test-sig"
	}
	mac := hmac.New(sha256.New, keyBytes)
	mac.Write([]byte(sigInput)) //nolint:errcheck
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return sigInput + "." + sig
}

// apiProbePaths are the common protected API paths used for active token probes.
var apiProbePaths = []string{"/api/v1/users", "/api/me", "/profile", "/api/user", "/me"}

// submitTokenProbe sends token to a set of common API endpoints and returns the
// first URL that responds HTTP 200 without an obvious error body. Returns "" if
// none accepted the token.
func submitTokenProbe(ctx context.Context, client *http.Client, base, token string) string {
	for _, path := range apiProbePaths {
		u := base + path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue
		}
		bodyLower := strings.ToLower(string(body))
		if strings.Contains(bodyLower, "unauthorized") ||
			strings.Contains(bodyLower, "invalid") ||
			strings.Contains(bodyLower, "error") {
			continue
		}
		return u
	}
	return ""
}

// checkAudienceMissing crafts a JWT with a deliberately wrong aud claim and
// submits it to common API endpoints. A 200 response indicates the server does
// not validate the audience claim, allowing cross-service token reuse.
func checkAudienceMissing(ctx context.Context, client *http.Client, asset, base string) *finding.Finding {
	iat := time.Now().Unix()
	token := craftJWT(
		`{"alg":"HS256","typ":"JWT"}`,
		fmt.Sprintf(`{"sub":"beacon-test","aud":"wrong-audience-beacon-test","iat":%d}`, iat),
		[]byte("beacon-test-secret"),
	)
	if endpoint := submitTokenProbe(ctx, client, base, token); endpoint != "" {
		return &finding.Finding{
			CheckID:  finding.CheckJWTAudienceMissing,
			Module:   "deep",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Asset:    asset,
			Title:    fmt.Sprintf("JWT audience (aud) claim not validated at %s", endpoint),
			Description: "The server accepted a JWT whose aud (audience) claim was set to " +
				"\"wrong-audience-beacon-test\" — a value that should never match this service's " +
				"audience. Without aud validation, a token issued for one service can be replayed " +
				"against any other service that shares the same signing secret or trust anchor. " +
				"Fix: verify the aud claim server-side and reject tokens whose audience does not " +
				"exactly match the expected service identifier.",
			Evidence: map[string]any{
				"endpoint":     endpoint,
				"forged_aud":   "wrong-audience-beacon-test",
				"forged_token": truncate(token, 80),
			},
			ProofCommand: fmt.Sprintf(
				`python3 -c "import base64,json,hmac,hashlib; h=base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b'=').decode(); p=base64.urlsafe_b64encode(b'{"sub":"x","aud":"wrong-audience-beacon-test"}').rstrip(b'=').decode(); sig=base64.urlsafe_b64encode(hmac.new(b'beacon-test-secret',f'{h}.{p}'.encode(),hashlib.sha256).digest()).rstrip(b'=').decode(); print(f'{h}.{p}.{sig}')" | xargs -I TOKEN curl -s -H 'Authorization: Bearer TOKEN' '%s'`,
				endpoint,
			),
			DiscoveredAt: time.Now(),
		}
	}
	return nil
}

// checkIssuerNotValidated crafts a JWT with a forged iss claim pointing to an
// attacker-controlled domain and submits it to common API endpoints. A 200
// response indicates the server does not validate the token issuer.
func checkIssuerNotValidated(ctx context.Context, client *http.Client, asset, base string) *finding.Finding {
	iat := time.Now().Unix()
	token := craftJWT(
		`{"alg":"HS256","typ":"JWT"}`,
		fmt.Sprintf(`{"sub":"beacon-test","iss":"https://attacker.beacon-test.example.com","iat":%d}`, iat),
		[]byte("beacon-test-secret"),
	)
	if endpoint := submitTokenProbe(ctx, client, base, token); endpoint != "" {
		return &finding.Finding{
			CheckID:  finding.CheckJWTIssuerNotValidated,
			Module:   "deep",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Asset:    asset,
			Title:    fmt.Sprintf("JWT issuer (iss) claim not validated at %s", endpoint),
			Description: "The server accepted a JWT whose iss (issuer) claim was set to " +
				"\"https://attacker.beacon-test.example.com\" — an attacker-controlled domain that " +
				"should never be trusted by this service. Without iss validation, an attacker can " +
				"issue tokens from their own identity provider and have them accepted by the target " +
				"service. Fix: verify the iss claim server-side and reject tokens whose issuer is not " +
				"in the explicit allow-list of trusted identity providers.",
			Evidence: map[string]any{
				"endpoint":     endpoint,
				"forged_iss":   "https://attacker.beacon-test.example.com",
				"forged_token": truncate(token, 80),
			},
			ProofCommand: fmt.Sprintf(
				`python3 -c "import base64,json,hmac,hashlib; h=base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b'=').decode(); p=base64.urlsafe_b64encode(b'{"sub":"x","iss":"https://attacker.beacon-test.example.com"}').rstrip(b'=').decode(); sig=base64.urlsafe_b64encode(hmac.new(b'beacon-test-secret',f'{h}.{p}'.encode(),hashlib.sha256).digest()).rstrip(b'=').decode(); print(f'{h}.{p}.{sig}')" | xargs -I TOKEN curl -s -H 'Authorization: Bearer TOKEN' '%s'`,
				endpoint,
			),
			DiscoveredAt: time.Now(),
		}
	}
	return nil
}

// checkJWKSKeys probes known JWKS paths on base and analyses every RSA key
// found. It emits CheckJWKSWeakKey for keys shorter than 2048 bits and
// CheckJWKSMissingKID for keys without a kid field.
func checkJWKSKeys(ctx context.Context, client *http.Client, asset, base string) []finding.Finding {
	var findings []finding.Finding

	for _, path := range jwksProbePaths {
		u := base + path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			continue
		}

		var doc jwksDocument
		if err := json.Unmarshal(body, &doc); err != nil || len(doc.Keys) == 0 {
			continue
		}

		for i, key := range doc.Keys {
			// Missing kid check.
			if key.Kid == "" {
				findings = append(findings, finding.Finding{
					CheckID:  finding.CheckJWKSMissingKID,
					Module:   "surface",
					Scanner:  scannerName,
					Severity: finding.SeverityMedium,
					Asset:    asset,
					Title:    fmt.Sprintf("JWKS key at index %d has no kid field (%s)", i, path),
					Description: "A key in the JWKS document does not have a kid (key ID) field. " +
						"Without kid, clients and servers cannot efficiently select the correct " +
						"verification key when multiple keys are present (e.g. during key rotation). " +
						"This can lead to validation failures or force clients to try all keys, " +
						"increasing the risk of accepting a token signed by a retired key.",
					Evidence:     map[string]any{"url": u, "key_index": i, "kty": key.Kty},
					DiscoveredAt: time.Now(),
				})
			}

			// Weak RSA key size check — only applicable to RSA keys.
			if !strings.EqualFold(key.Kty, "RSA") || key.N == "" {
				continue
			}
			nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
			if err != nil {
				continue
			}
			bits := len(nBytes) * 8
			if bits < 2048 {
				findings = append(findings, finding.Finding{
					CheckID:  finding.CheckJWKSWeakKey,
					Module:   "surface",
					Scanner:  scannerName,
					Severity: finding.SeverityHigh,
					Asset:    asset,
					Title:    fmt.Sprintf("JWKS RSA key is only %d bits (minimum 2048 required)", bits),
					Description: fmt.Sprintf(
						"The RSA key at index %d in the JWKS document at %s has a modulus of only %d bits. "+
							"Keys shorter than 2048 bits are considered cryptographically weak and can be "+
							"factored with modern hardware. An attacker who factors the key can forge arbitrary "+
							"JWT tokens. Replace with a 2048-bit or 4096-bit RSA key, or switch to an ECDSA key.",
						i, u, bits,
					),
					Evidence:     map[string]any{"url": u, "key_index": i, "bits": bits, "kid": key.Kid},
					DiscoveredAt: time.Now(),
				})
			}
		}

		// Only analyse the first reachable JWKS endpoint.
		if len(doc.Keys) > 0 {
			break
		}
	}

	return findings
}

// isCatchAll returns true when the server responds 200 to a path that cannot
// exist on any real application — indicating a wildcard / catch-all config
// where all JWT probe responses would be false positives.
func isCatchAll(ctx context.Context, client *http.Client, base string) bool {
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
