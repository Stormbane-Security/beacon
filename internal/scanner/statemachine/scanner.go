// Package statemachine implements a business logic state machine analysis scanner.
//
// It maps authentication/authorization state transitions of a web application
// and tests whether intermediate states (email verification, MFA, payment,
// admin approval) can be skipped to reach protected resources directly.
//
// Normal flow:  guest -> register -> verify_email -> logged_in -> admin
// Attack:       Can we skip verify_email? Can we access admin as a regular user?
//
// This differs from the privesc scanner which tests specific endpoints.
// State machine analysis maps the *flow* — whether multi-step authentication
// and authorization processes enforce ordering.
//
// ScanAuthorized only (exploitation-class testing requiring explicit authorization).
package statemachine

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scan" // IsSPA + RenderSPA
	"github.com/stormbane-security/beacon/internal/scanner/authctx"
	"github.com/stormbane-security/beacon/internal/scanner/schemedetect"
)

func init() {
	scan.RegisterWithCheckDecls(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	},
		scan.Check(finding.CheckStateSkipDetected, finding.SeverityHigh, finding.ModeDeep),
		scan.Check(finding.CheckIncompleteAuthFlow, finding.SeverityHigh, finding.ModeDeep),
		scan.Check(finding.CheckStepBypass, finding.SeverityMedium, finding.ModeDeep),
	)
}

const (
	scannerName = "statemachine"
	maxBodySize = 64 * 1024 // 64 KB
)

// postAuthPaths are endpoints that should only be accessible after completing
// a full authentication flow (login + verification + MFA).
var postAuthPaths = []string{
	"/dashboard",
	"/account",
	"/account/settings",
	"/profile",
	"/settings",
	"/admin",
	"/admin/settings",
	"/admin/dashboard",
	"/admin/users",
	"/api/me",
	"/api/v1/me",
	"/api/account",
	"/api/v1/account",
	"/api/profile",
	"/api/v1/profile",
	"/api/dashboard",
	"/api/v1/dashboard",
	"/home",
	"/app",
	"/members",
	"/my-account",
	"/user/settings",
	"/billing",
	"/subscription",
}

// verificationPaths are intermediate steps in the auth flow. If post-auth
// pages are accessible without visiting these, a state skip exists.
var verificationPaths = []string{
	"/verify-email",
	"/verify",
	"/email-verification",
	"/confirm-email",
	"/mfa",
	"/mfa/setup",
	"/mfa/verify",
	"/two-factor",
	"/2fa",
	"/otp",
	"/otp/verify",
}

// premiumPaths are endpoints that should only be accessible after payment.
var premiumPaths = []string{
	"/premium",
	"/pro",
	"/paid",
	"/premium/content",
	"/api/premium",
	"/api/v1/premium",
	"/subscription/manage",
	"/courses",
	"/downloads",
}

// loginIndicators are strings that indicate a response is a login/redirect page
// rather than actual protected content.
var loginIndicators = []string{
	"login", "sign in", "sign-in", "signin", "log in",
	"log-in", "authenticate", "password",
}

// protectedContentIndicators are strings that suggest the response contains
// actual authenticated content rather than a generic error or login page.
var protectedContentIndicators = []string{
	"dashboard", "welcome", "account", "profile", "settings",
	"logout", "sign out", "signout", "my account",
	"subscription", "billing", "admin", "manage",
}

// probeResult records a response from probing an endpoint.
type probeResult struct {
	path       string
	status     int
	bodyHash   string
	bodyLen    int
	body       string
	isProtected bool // true if body looks like authenticated content
	isLogin     bool // true if body looks like a login page
}

// Scanner detects authentication/authorization state machine bypasses.
type Scanner struct{}

// New returns a new Scanner.
func New() *Scanner { return &Scanner{} }

// Name returns the stable scanner identifier.
func (s *Scanner) Name() string { return scannerName }

// Run executes the state machine analysis scan. Only runs in authorized mode.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanAuthorized {
		return nil, nil
	}

	unauthClient := newUnauthClient()
	authClient := authctx.HTTPClient(ctx)
	base := schemedetect.Base(ctx, unauthClient, asset)

	var findings []finding.Finding

	// Strategy 1: Probe post-auth paths without authentication.
	// If they return 200 with protected content, the auth flow can be skipped.
	findings = append(findings, s.testStateSkips(ctx, unauthClient, base, asset)...)

	// Strategy 2: Compare unauthenticated vs authenticated response sets.
	// Endpoints accessible both ways may have broken access control.
	findings = append(findings, s.testIncompleteAuthFlow(ctx, unauthClient, authClient, base, asset)...)

	// Strategy 3: Check if verification/MFA steps can be bypassed by
	// probing whether verification endpoints exist but post-auth content
	// is still accessible without completing them.
	findings = append(findings, s.testStepBypass(ctx, unauthClient, base, asset)...)

	return findings, nil
}

// testStateSkips probes post-auth endpoints without authentication. If any
// return 200 with content that looks like authenticated pages (not login
// redirects), a state skip is detected.
func (s *Scanner) testStateSkips(ctx context.Context, client *http.Client, base, asset string) []finding.Finding {
	var findings []finding.Finding

	for _, path := range postAuthPaths {
		if ctx.Err() != nil {
			break
		}

		result := probe(ctx, client, base+path)
		if result.status == http.StatusOK && result.isProtected && !result.isLogin {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckStateSkipDetected,
				Module:   "authorized",
				Scanner:  scannerName,
				Severity: finding.SeverityHigh,
				Title:    fmt.Sprintf("Auth state skip: %s accessible without authentication on %s", path, asset),
				Description: fmt.Sprintf(
					"The post-authentication endpoint %s on %s returned HTTP 200 with "+
						"authenticated page content when accessed without any authentication. "+
						"The authentication state machine can be bypassed by directly accessing "+
						"protected resources without completing the login flow.",
					path, asset),
				Asset:    asset,
				DeepOnly: true,
				ProofCommand: fmt.Sprintf(
					`curl -sk '%s%s'`, base, path),
				Evidence: map[string]any{
					"url":         base + path,
					"path":        path,
					"status_code": result.status,
					"body_length": result.bodyLen,
					"body_hash":   result.bodyHash,
					"category":    "state_skip",
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings
}

// testIncompleteAuthFlow compares unauthenticated and authenticated response
// sets. If an endpoint returns the same content both ways (same status, similar
// body hash), it suggests the auth check is missing entirely.
func (s *Scanner) testIncompleteAuthFlow(ctx context.Context, unauthClient, authClient *http.Client, base, asset string) []finding.Finding {
	// If both clients are effectively the same (no auth pipeline), skip.
	if unauthClient == authClient {
		return nil
	}

	var findings []finding.Finding

	for _, path := range postAuthPaths {
		if ctx.Err() != nil {
			break
		}

		unauthResult := probe(ctx, unauthClient, base+path)
		authResult := probe(ctx, authClient, base+path)

		// Both return 200 with meaningful content and same body → no auth check.
		if unauthResult.status == http.StatusOK &&
			authResult.status == http.StatusOK &&
			unauthResult.bodyLen > 100 &&
			authResult.bodyLen > 100 &&
			unauthResult.bodyHash == authResult.bodyHash &&
			unauthResult.isProtected {

			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckIncompleteAuthFlow,
				Module:   "authorized",
				Scanner:  scannerName,
				Severity: finding.SeverityHigh,
				Title:    fmt.Sprintf("Incomplete auth flow: %s returns identical content with and without auth on %s", path, asset),
				Description: fmt.Sprintf(
					"The endpoint %s on %s returns identical content (same body hash) "+
						"whether accessed with or without authentication. The auth middleware "+
						"is not differentiating between authenticated and unauthenticated "+
						"requests, suggesting the authentication flow is incomplete or missing.",
					path, asset),
				Asset:    asset,
				DeepOnly: true,
				ProofCommand: fmt.Sprintf(
					`# Compare unauthenticated vs authenticated responses:\ncurl -sk '%s%s' | sha256sum\ncurl -sk -H 'Authorization: Bearer TOKEN' '%s%s' | sha256sum`,
					base, path, base, path),
				Evidence: map[string]any{
					"url":               base + path,
					"path":              path,
					"unauth_status":     unauthResult.status,
					"auth_status":       authResult.status,
					"unauth_body_len":   unauthResult.bodyLen,
					"auth_body_len":     authResult.bodyLen,
					"body_hash_match":   true,
					"body_hash":         unauthResult.bodyHash,
					"category":          "incomplete_auth_flow",
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings
}

// testStepBypass checks for multi-step process bypass. If verification/MFA
// endpoints exist (indicating the app has a multi-step flow) but post-auth
// endpoints are accessible without authentication, the intermediate steps
// can be bypassed.
func (s *Scanner) testStepBypass(ctx context.Context, client *http.Client, base, asset string) []finding.Finding {
	// First, check which verification steps exist on this target.
	var existingSteps []string
	for _, path := range verificationPaths {
		if ctx.Err() != nil {
			return nil
		}

		result := probe(ctx, client, base+path)
		// A verification page exists if it returns 200 or a redirect to login
		// (which means the endpoint is wired up).
		if result.status == http.StatusOK ||
			result.status == http.StatusFound ||
			result.status == http.StatusSeeOther ||
			result.status == http.StatusTemporaryRedirect {
			existingSteps = append(existingSteps, path)
		}
	}

	if len(existingSteps) == 0 {
		return nil
	}

	// Now check if premium/payment-gated paths are accessible without auth.
	var findings []finding.Finding
	for _, path := range premiumPaths {
		if ctx.Err() != nil {
			break
		}

		result := probe(ctx, client, base+path)
		if result.status == http.StatusOK && result.isProtected && !result.isLogin {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckStepBypass,
				Module:   "authorized",
				Scanner:  scannerName,
				Severity: finding.SeverityMedium,
				Title:    fmt.Sprintf("Step bypass: %s accessible without completing %s on %s", path, existingSteps[0], asset),
				Description: fmt.Sprintf(
					"The application has multi-step verification (endpoints: %s) but "+
						"the protected endpoint %s on %s is accessible without completing "+
						"these intermediate steps. An attacker may skip verification, MFA, "+
						"or payment steps to access protected resources directly.",
					strings.Join(existingSteps, ", "), path, asset),
				Asset:    asset,
				DeepOnly: true,
				ProofCommand: fmt.Sprintf(
					`curl -sk '%s%s'`, base, path),
				Evidence: map[string]any{
					"url":                 base + path,
					"path":                path,
					"status_code":         result.status,
					"body_length":         result.bodyLen,
					"body_hash":           result.bodyHash,
					"verification_steps":  existingSteps,
					"category":            "step_bypass",
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings
}

// probe performs a GET request and classifies the response. If the page is a
// SPA (Angular/React/Vue), it renders it in headless Chrome to get the actual
// DOM content for accurate classification.
func probe(ctx context.Context, client *http.Client, url string) probeResult {
	status, body := doRequest(ctx, client, url)

	// If the page looks like a SPA, render it in headless Chrome so that
	// JS-rendered dashboards/admin panels are detected correctly.
	if status == http.StatusOK && scan.IsSPA(body) {
		if rendered, err := scan.RenderSPA(ctx, url); err == nil && rendered != "" {
			body = rendered
		}
	}

	h := sha256.Sum256([]byte(body))
	return probeResult{
		path:        url,
		status:      status,
		bodyHash:    fmt.Sprintf("%x", h[:8]),
		bodyLen:     len(body),
		body:        body,
		isProtected: looksLikeProtectedContent(body),
		isLogin:     looksLikeLoginPage(body),
	}
}

// doRequest performs a GET request and returns status code and body.
func doRequest(ctx context.Context, client *http.Client, rawURL string) (int, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return 0, ""
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	_ = resp.Body.Close()

	return resp.StatusCode, string(body)
}

// looksLikeProtectedContent returns true if the body contains signals typical
// of authenticated/protected content.
func looksLikeProtectedContent(body string) bool {
	if len(body) < 50 {
		return false
	}
	lower := strings.ToLower(body)
	matches := 0
	for _, indicator := range protectedContentIndicators {
		if strings.Contains(lower, indicator) {
			matches++
		}
	}
	return matches >= 2
}

// looksLikeLoginPage returns true if the body appears to be a login/sign-in
// page rather than actual protected content.
func looksLikeLoginPage(body string) bool {
	lower := strings.ToLower(body)
	loginMatches := 0
	for _, indicator := range loginIndicators {
		if strings.Contains(lower, indicator) {
			loginMatches++
		}
	}
	// If there are many login indicators and few protected-content indicators,
	// this is likely a login page.
	protectedMatches := 0
	for _, indicator := range protectedContentIndicators {
		if strings.Contains(lower, indicator) {
			protectedMatches++
		}
	}
	return loginMatches >= 2 && loginMatches > protectedMatches
}

// newUnauthClient creates an HTTP client without auth credentials, with TLS
// verification disabled and redirect following disabled.
func newUnauthClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec
			},
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
