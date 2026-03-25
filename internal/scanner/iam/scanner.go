// Package iam detects exposed identity management endpoints and tests for IAM
// security issues.
//
// Surface mode: SCIM exposure, OIDC userinfo leak, OAuth introspect/device/
// dynamic-client endpoints, IdP admin panels, role assignment endpoints.
//
// ScanAuthorized mode: cloud metadata SSRF, LDAP injection.
// Active exploitation probes require ScanAuthorized mode (--authorized flag).
//
// CheckIDs used:
//   - finding.CheckSCIMExposed             = "iam.scim_exposed"
//   - finding.CheckSCIMUnauthenticated     = "iam.scim_unauthenticated"
//   - finding.CheckOIDCUserinfoLeak        = "iam.oidc_userinfo_leak"
//   - finding.CheckOAuthIntrospectExposed  = "iam.token_introspect_exposed"
//   - finding.CheckOAuthDeviceFlowExposed  = "iam.device_auth_flow"
//   - finding.CheckOAuthDynClientReg       = "iam.dynamic_client_reg"
//   - finding.CheckLDAPInjection           = "iam.ldap_injection"
//   - finding.CheckCloudMetadataSSRF       = "iam.cloud_metadata_ssrf"
//   - finding.CheckIdentityProviderExposed = "iam.idp_admin_exposed"
//   - finding.CheckIdentityRoleEscalation  = "iam.role_assignment_exposed"
package iam

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const scannerName = "iam"

// Scanner detects exposed IAM/identity management endpoints and active IAM
// security vulnerabilities.
type Scanner struct{}

// New returns a new IAM scanner.
func New() *Scanner { return &Scanner{} }

// Name returns the scanner identifier.
func (s *Scanner) Name() string { return scannerName }

// scimPaths are SCIM v2 endpoint paths to probe.
var scimPaths = []string{
	"/scim/v2/Users",
	"/scim/v2/Groups",
	"/api/scim/v2/Users",
	"/Users",
}

// introspectPaths are OAuth token introspection endpoint paths.
var introspectPaths = []string{
	"/oauth/introspect",
	"/oauth2/introspect",
	"/connect/introspect",
	"/oauth/tokeninfo",
}

// deviceFlowPaths are OAuth device authorization endpoint paths.
var deviceFlowPaths = []string{
	"/oauth/device_authorization",
	"/oauth2/v1/device/authorize",
}

// dynClientRegPaths are OAuth dynamic client registration endpoint paths.
var dynClientRegPaths = []string{
	"/oauth/register",
	"/connect/register",
}

// idpAdminPaths are IdP admin panel paths to probe.
var idpAdminPaths = []string{
	"/admin/",
	"/api/v2/users",       // Auth0
	"/auth/admin/",        // Keycloak
	"/realms/master/protocol/openid-connect/token", // Keycloak token
	"/pingfederate/app",   // PingFederate
	"/adfs/ls/",           // ADFS
}

// idpAdminSignatures maps each IdP admin path to a body substring that must be
// present before the path is flagged as an exposed admin panel. This prevents
// false positives on catch-all sites that return HTTP 200 for every URL.
var idpAdminSignatures = map[string]string{
	"/admin/":         "keycloak",           // Keycloak admin UI contains "keycloak" in HTML/JS
	"/api/v2/users":   `"user_id"`,          // Auth0 Management API user object
	"/auth/admin/":    "Keycloak",           // Keycloak admin page title
	"/realms/master/protocol/openid-connect/token": "access_token", // Keycloak token response
	"/pingfederate/app":  "PingFederate",    // PingFederate branding
	"/adfs/ls/":          "adfs",            // ADFS page body
}

// roleEndpointPaths are role/RBAC API paths to probe.
var roleEndpointPaths = []string{
	"/api/v1/roles",
	"/api/users/roles",
	"/api/v2/rbac/roles",
}

// ldapInjectionPatterns are LDAP injection payloads.
var ldapInjectionPatterns = []string{
	"*)(&",
	"admin)(|(password=*)",
}

// cloudMetadataURL is the AWS IMDSv1 endpoint used for SSRF testing.
const cloudMetadataURL = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"

// ssrfParamNames are common URL parameter names used for SSRF testing.
var ssrfParamNames = []string{"url", "redirect", "fetch", "next", "target", "dest", "destination", "uri", "link"}

// Run executes the IAM scanner against the given asset.
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

	var findings []finding.Finding

	// ── Surface mode checks ───────────────────────────────────────────────

	// 1. SCIM endpoint exposure
	findings = append(findings, checkSCIM(ctx, client, asset, base)...)

	// 2. OIDC userinfo leak
	if f := checkOIDCUserinfo(ctx, client, asset, base); f != nil {
		findings = append(findings, *f)
	}

	// 3. OAuth token introspection endpoint
	if f := checkIntrospect(ctx, client, asset, base); f != nil {
		findings = append(findings, *f)
	}

	// 4. OAuth device authorization flow
	if f := checkDeviceFlow(ctx, client, asset, base); f != nil {
		findings = append(findings, *f)
	}

	// 5. OAuth dynamic client registration
	if f := checkDynClientReg(ctx, client, asset, base); f != nil {
		findings = append(findings, *f)
	}

	// 6. IdP admin panels
	if f := checkIdPAdmin(ctx, client, asset, base); f != nil {
		findings = append(findings, *f)
	}

	// 7. Role assignment endpoints
	if f := checkRoleEndpoints(ctx, client, asset, base); f != nil {
		findings = append(findings, *f)
	}

	// Exploitation probes require --authorized (beyond --deep).
	if scanType != module.ScanAuthorized {
		return findings, nil
	}

	// ── ScanAuthorized only ────────────────────────────────────────────────────

	// 8. Cloud metadata SSRF
	if f := checkCloudMetadataSSRF(ctx, client, asset, base); f != nil {
		findings = append(findings, *f)
	}

	// 9. LDAP injection
	if f := checkLDAPInjection(ctx, client, asset, base); f != nil {
		findings = append(findings, *f)
	}

	return findings, nil
}

// checkSCIM probes SCIM endpoints and returns findings for unauthenticated or
// authenticated SCIM access.
func checkSCIM(ctx context.Context, client *http.Client, asset, base string) []finding.Finding {
	var findings []finding.Finding
	for _, path := range scimPaths {
		target := base + path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/scim+json, application/json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()

		bodyStr := string(body)

		switch {
		case resp.StatusCode == http.StatusOK &&
			(strings.Contains(bodyStr, `"totalResults"`) || strings.Contains(bodyStr, `"schemas"`)):
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckSCIMUnauthenticated,
				Module:   "surface",
				Scanner:  scannerName,
				Severity: finding.SeverityCritical,
				Title:    "SCIM endpoint accessible without authentication",
				Description: "The SCIM v2 endpoint is returning user or group directory data without " +
					"requiring authentication. An attacker can enumerate all users, groups, emails, " +
					"and roles in the identity directory.",
				Asset: asset,
				ProofCommand: fmt.Sprintf(
					"curl -s -H 'Accept: application/scim+json' '%s'", target),
				Evidence: map[string]any{
					"url":          target,
					"status_code":  resp.StatusCode,
					"body_snippet": truncate(bodyStr, 300),
				},
				DiscoveredAt: time.Now(),
			})

		case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
			// SCIM endpoint exists but requires auth — low-severity exposure.
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckSCIMExposed,
				Module:   "surface",
				Scanner:  scannerName,
				Severity: finding.SeverityInfo,
				Title:    "SCIM endpoint detected (authentication required)",
				Description: "A SCIM v2 endpoint is reachable but returns an authentication challenge. " +
					"The presence of a SCIM endpoint confirms use of a standards-based identity management " +
					"API and may be subject to credential stuffing or brute-force attacks.",
				Asset: asset,
				ProofCommand: fmt.Sprintf(
					"curl -si -H 'Accept: application/scim+json' '%s'", target),
				Evidence: map[string]any{
					"url":         target,
					"status_code": resp.StatusCode,
				},
				DiscoveredAt: time.Now(),
			})
		}
	}
	return findings
}

// checkOIDCUserinfo discovers the userinfo endpoint from the OIDC configuration
// document and tests whether it returns user data without authorization.
func checkOIDCUserinfo(ctx context.Context, client *http.Client, asset, base string) *finding.Finding {
	// Fetch OIDC discovery document.
	oidcURL := base + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, oidcURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var doc struct {
		UserinfoEndpoint string `json:"userinfo_endpoint"`
	}
	if err := json.Unmarshal(body, &doc); err != nil || doc.UserinfoEndpoint == "" {
		return nil
	}

	// Probe userinfo endpoint without Authorization header.
	req2, err := http.NewRequestWithContext(ctx, http.MethodGet, doc.UserinfoEndpoint, nil)
	if err != nil {
		return nil
	}
	req2.Header.Set("Accept", "application/json")
	resp2, err := client.Do(req2)
	if err != nil {
		return nil
	}
	body2, _ := io.ReadAll(io.LimitReader(resp2.Body, 64*1024))
	resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		return nil
	}

	bodyStr := string(body2)
	if strings.Contains(bodyStr, `"sub"`) || strings.Contains(bodyStr, `"email"`) {
		return &finding.Finding{
			CheckID:  finding.CheckOIDCUserinfoLeak,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Title:    "OIDC userinfo endpoint returns user data without authorization",
			Description: "The OIDC userinfo endpoint returned user identity data (sub/email) without " +
				"an Authorization header. This endpoint should require a valid bearer access token. " +
				"An attacker may be able to enumerate user identities.",
			Asset: asset,
			ProofCommand: fmt.Sprintf("curl -s '%s'", doc.UserinfoEndpoint),
			Evidence: map[string]any{
				"discovery_url":    oidcURL,
				"userinfo_url":     doc.UserinfoEndpoint,
				"status_code":      resp2.StatusCode,
				"body_snippet":     truncate(bodyStr, 300),
			},
			DiscoveredAt: time.Now(),
		}
	}
	return nil
}

// checkIntrospect probes OAuth token introspection endpoints.
func checkIntrospect(ctx context.Context, client *http.Client, asset, base string) *finding.Finding {
	for _, path := range introspectPaths {
		target := base + path
		// POST with a dummy token.
		body := strings.NewReader("token=beacon-test-token")
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, body)
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK && strings.Contains(string(respBody), `"active"`) {
			return &finding.Finding{
				CheckID:  finding.CheckOAuthIntrospectExposed,
				Module:   "surface",
				Scanner:  scannerName,
				Severity: finding.SeverityHigh,
				Title:    "OAuth token introspection endpoint accessible without client authentication",
				Description: "The OAuth token introspection endpoint is responding to unauthenticated " +
					"requests. RFC 7662 requires client authentication for introspection. An attacker " +
					"can probe the validity and metadata of arbitrary access tokens.",
				Asset: asset,
				ProofCommand: fmt.Sprintf(
					"curl -s -X POST '%s' -d 'token=test'", target),
				Evidence: map[string]any{
					"url":          target,
					"status_code":  resp.StatusCode,
					"body_snippet": truncate(string(respBody), 300),
				},
				DiscoveredAt: time.Now(),
			}
		}
	}
	return nil
}

// checkDeviceFlow probes OAuth device authorization endpoints.
func checkDeviceFlow(ctx context.Context, client *http.Client, asset, base string) *finding.Finding {
	for _, path := range deviceFlowPaths {
		target := base + path
		body := strings.NewReader("client_id=beacon-test&scope=openid")
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, body)
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK && strings.Contains(string(respBody), `"device_code"`) {
			return &finding.Finding{
				CheckID:  finding.CheckOAuthDeviceFlowExposed,
				Module:   "surface",
				Scanner:  scannerName,
				Severity: finding.SeverityMedium,
				Title:    "OAuth device authorization flow publicly accessible",
				Description: "The OAuth 2.0 device authorization endpoint (RFC 8628) is reachable and " +
					"returns device codes without client authentication. Depending on allowed scopes, " +
					"an attacker may initiate device authorization flows targeting arbitrary users.",
				Asset: asset,
				ProofCommand: fmt.Sprintf(
					"curl -s -X POST '%s' -d 'client_id=test&scope=openid'", target),
				Evidence: map[string]any{
					"url":          target,
					"status_code":  resp.StatusCode,
					"body_snippet": truncate(string(respBody), 300),
				},
				DiscoveredAt: time.Now(),
			}
		}
	}
	return nil
}

// checkDynClientReg probes OAuth dynamic client registration endpoints.
func checkDynClientReg(ctx context.Context, client *http.Client, asset, base string) *finding.Finding {
	payload := []byte(`{"redirect_uris":["https://beacon-test.invalid"]}`)
	for _, path := range dynClientRegPaths {
		target := base + path
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(payload))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()

		if (resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated) &&
			strings.Contains(string(respBody), `"client_id"`) {
			return &finding.Finding{
				CheckID:  finding.CheckOAuthDynClientReg,
				Module:   "surface",
				Scanner:  scannerName,
				Severity: finding.SeverityHigh,
				Title:    "OAuth dynamic client registration open without authentication",
				Description: "The OAuth dynamic client registration endpoint (RFC 7591) allows anyone " +
					"to register a new OAuth client without an initial access token. An attacker can " +
					"register a malicious client to conduct phishing OAuth flows or facilitate token " +
					"theft via open redirect chains.",
				Asset: asset,
				ProofCommand: fmt.Sprintf(
					`curl -s -X POST '%s' -H 'Content-Type: application/json' -d '{"redirect_uris":["https://beacon-test.invalid"]}'`,
					target),
				Evidence: map[string]any{
					"url":          target,
					"status_code":  resp.StatusCode,
					"body_snippet": truncate(string(respBody), 300),
				},
				DiscoveredAt: time.Now(),
			}
		}
	}
	return nil
}

// checkIdPAdmin probes known IdP admin panel paths for unauthenticated access.
// A 200 response alone is not sufficient — the body must also contain an
// IdP-specific signature string to prevent false positives on catch-all sites.
func checkIdPAdmin(ctx context.Context, client *http.Client, asset, base string) *finding.Finding {
	for _, path := range idpAdminPaths {
		target := base + path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "text/html,application/json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK || len(body) == 0 {
			continue
		}

		// Require an IdP-specific signature in the response body to confirm this
		// is actually the admin panel and not a generic catch-all / redirect page.
		sig, hasSig := idpAdminSignatures[path]
		if hasSig && !strings.Contains(strings.ToLower(string(body)), strings.ToLower(sig)) {
			continue
		}

		return &finding.Finding{
			CheckID:  finding.CheckIdentityProviderExposed,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityCritical,
			Title:    "Identity provider admin panel accessible without authentication",
			Description: "An identity provider administrative endpoint is returning HTTP 200 without " +
				"requiring authentication. Admin panels for Okta, Auth0, Keycloak, PingFederate, or " +
				"ADFS provide full control over users, roles, applications, and federation settings.",
			Asset: asset,
			ProofCommand: fmt.Sprintf("curl -si '%s'", target),
			Evidence: map[string]any{
				"url":          target,
				"path":         path,
				"status_code":  resp.StatusCode,
				"body_snippet": truncate(string(body), 200),
			},
			DiscoveredAt: time.Now(),
		}
	}
	return nil
}

// checkRoleEndpoints probes role/RBAC API endpoints for unauthenticated JSON
// array responses.
func checkRoleEndpoints(ctx context.Context, client *http.Client, asset, base string) *finding.Finding {
	for _, path := range roleEndpointPaths {
		target := base + path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()

		bodyStr := strings.TrimSpace(string(body))
		if resp.StatusCode == http.StatusOK && strings.HasPrefix(bodyStr, "[") {
			return &finding.Finding{
				CheckID:  finding.CheckIdentityRoleEscalation,
				Module:   "surface",
				Scanner:  scannerName,
				Severity: finding.SeverityCritical,
				Title:    "Role/RBAC assignment endpoint accessible without authentication",
				Description: "A role or RBAC assignment API endpoint is returning role data as a JSON " +
					"array without authentication. An attacker can enumerate all roles and potentially " +
					"modify role assignments, enabling privilege escalation.",
				Asset: asset,
				ProofCommand: fmt.Sprintf("curl -s -H 'Accept: application/json' '%s'", target),
				Evidence: map[string]any{
					"url":          target,
					"path":         path,
					"status_code":  resp.StatusCode,
					"body_snippet": truncate(bodyStr, 300),
				},
				DiscoveredAt: time.Now(),
			}
		}
	}
	return nil
}

// checkCloudMetadataSSRF tests URL parameters for cloud metadata SSRF by
// injecting the AWS IMDSv1 endpoint.
func checkCloudMetadataSSRF(ctx context.Context, client *http.Client, asset, base string) *finding.Finding {
	// Try each SSRF param on the base URL and common endpoints.
	targetPaths := []string{"/", "/api", "/proxy", "/fetch", "/redirect"}
	for _, path := range targetPaths {
		for _, param := range ssrfParamNames {
			target := fmt.Sprintf("%s%s?%s=%s", base, path, param, cloudMetadataURL)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
			if err != nil {
				continue
			}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
			resp.Body.Close()

			bodyStr := string(body)
			if strings.Contains(bodyStr, "AccessKeyId") ||
				strings.Contains(bodyStr, "SecretAccessKey") ||
				strings.Contains(bodyStr, "Token") && strings.Contains(bodyStr, "Expiration") {
				return &finding.Finding{
					CheckID:  finding.CheckCloudMetadataSSRF,
					Module:   "deep",
					Scanner:  scannerName,
					Severity: finding.SeverityCritical,
					Title:    "Cloud metadata SSRF via URL parameter",
					Description: "A URL parameter caused the server to fetch the AWS instance metadata " +
						"endpoint (169.254.169.254) and the response containing IAM credentials was " +
						"returned to the attacker. This allows full credential theft for the cloud role " +
						"attached to the server.",
					Asset: asset,
					ProofCommand: fmt.Sprintf("curl -s '%s'", target),
					Evidence: map[string]any{
						"url":          target,
						"param":        param,
						"ssrf_target":  cloudMetadataURL,
						"status_code":  resp.StatusCode,
						"body_snippet": truncate(bodyStr, 300),
					},
					DeepOnly: true,
					DiscoveredAt: time.Now(),
				}
			}
		}
	}
	return nil
}

// checkLDAPInjection tests common search/filter endpoints for LDAP injection
// by comparing responses with normal vs injected payloads.
func checkLDAPInjection(ctx context.Context, client *http.Client, asset, base string) *finding.Finding {
	testPaths := []struct {
		path  string
		param string
	}{
		{"/search", "q"},
		{"/api/users", "filter"},
		{"/api/search", "q"},
		{"/users/search", "search"},
	}

	for _, tp := range testPaths {
		// First, get a baseline response with a benign value.
		baselineURL := fmt.Sprintf("%s%s?%s=beacon-test-user", base, tp.path, tp.param)
		baselineReq, err := http.NewRequestWithContext(ctx, http.MethodGet, baselineURL, nil)
		if err != nil {
			continue
		}
		baselineResp, err := client.Do(baselineReq)
		if err != nil {
			continue
		}
		baselineBody, _ := io.ReadAll(io.LimitReader(baselineResp.Body, 64*1024))
		baselineResp.Body.Close()

		// Only test paths that return a 200 to a baseline query.
		if baselineResp.StatusCode != http.StatusOK {
			continue
		}

		for _, payload := range ldapInjectionPatterns {
			injectedURL := fmt.Sprintf("%s%s?%s=%s", base, tp.path, tp.param, payload)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, injectedURL, nil)
			if err != nil {
				continue
			}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
			resp.Body.Close()

			bodyStr := string(respBody)

			// Check for error messages that reveal LDAP internals, or a
			// response that returns significantly more data than the baseline
			// (possible wildcard injection returning all results).
			hasLDAPError := strings.Contains(strings.ToLower(bodyStr), "ldap") ||
				strings.Contains(strings.ToLower(bodyStr), "invalid filter") ||
				strings.Contains(strings.ToLower(bodyStr), "filter syntax") ||
				strings.Contains(strings.ToLower(bodyStr), "javax.naming")

			// Response is much larger than baseline — wildcard may have matched all records.
			significantlyLarger := len(respBody) > len(baselineBody)*3 && len(respBody) > 500

			if (hasLDAPError || significantlyLarger) && resp.StatusCode != http.StatusNotFound {
				return &finding.Finding{
					CheckID:  finding.CheckLDAPInjection,
					Module:   "deep",
					Scanner:  scannerName,
					Severity: finding.SeverityCritical,
					Title:    "LDAP injection in search/filter parameter",
					Description: "A search or filter parameter is vulnerable to LDAP injection. " +
						"The application's response changed significantly when LDAP metacharacters were " +
						"injected, suggesting the input is interpolated directly into an LDAP filter. " +
						"An attacker may enumerate or exfiltrate directory entries.",
					Asset: asset,
					ProofCommand: fmt.Sprintf("curl -s '%s'", injectedURL),
					Evidence: map[string]any{
						"url":              injectedURL,
						"param":            tp.param,
						"payload":          payload,
						"status_code":      resp.StatusCode,
						"baseline_len":     len(baselineBody),
						"injected_len":     len(respBody),
						"ldap_error":       hasLDAPError,
						"body_snippet":     truncate(bodyStr, 300),
					},
					DeepOnly: true,
					DiscoveredAt: time.Now(),
				}
			}
		}
	}
	return nil
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

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
