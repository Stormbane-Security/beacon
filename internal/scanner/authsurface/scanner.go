// Package authsurface detects authentication surfaces: login forms, registration
// pages, SSO endpoints, CAPTCHA, and MFA requirements. Findings are emitted for
// Forecast to correlate with harvested credentials.
//
// This runs in surface mode — no active probing, just HTML analysis.
package authsurface

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scan"
)

func init() {
	scan.RegisterWithCheckDecls(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return &Scanner{}
	},
		scan.Check(finding.CheckAuthLoginFormDetected, finding.SeverityInfo, finding.ModeSurface),
		scan.Check(finding.CheckAuthRegistrationOpen, finding.SeverityMedium, finding.ModeSurface),
		scan.Check(finding.CheckAuthSSOEndpoint, finding.SeverityInfo, finding.ModeSurface),
		scan.Check(finding.CheckAuthMFADetected, finding.SeverityInfo, finding.ModeSurface),
	)
}

const scannerName = "authsurface"

type Scanner struct{}

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, _ module.ScanType) ([]finding.Finding, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if sctx, ok := scan.FromContext(ctx); ok {
		client = sctx.HTTPClient()
	}

	scheme := "https"
	if sctx, ok := scan.FromContext(ctx); ok {
		scheme = sctx.Scheme()
	}

	var findings []finding.Finding
	now := time.Now()

	// Probe common login/register paths
	loginPaths := []string{"/", "/login", "/signin", "/auth/login", "/admin", "/wp-login.php",
		"/accounts/login", "/user/login", "/api/auth/login"}
	registerPaths := []string{"/register", "/signup", "/sign-up", "/auth/register",
		"/accounts/signup", "/user/register", "/join"}

	for _, path := range loginPaths {
		body, status := fetchPage(ctx, client, scheme+"://"+asset+path)
		if status == 0 || status >= 400 {
			continue
		}

		lower := strings.ToLower(body)

		// Detect password input = login form
		if strings.Contains(lower, `type="password"`) || strings.Contains(lower, `type='password'`) {
			formAction := extractFormAction(body)
			fields := extractInputNames(body)

			ev := map[string]any{
				"path":         path,
				"form_action":  formAction,
				"input_fields": fields,
			}

			// Check for CAPTCHA
			hasCaptcha := false
			captchaTypes := []string{"recaptcha", "hcaptcha", "turnstile", "captcha"}
			for _, ct := range captchaTypes {
				if strings.Contains(lower, ct) {
					hasCaptcha = true
					ev["captcha_type"] = ct
					break
				}
			}

			// Check for SSO/OAuth buttons
			ssoProviders := detectSSO(lower)
			if len(ssoProviders) > 0 {
				ev["sso_providers"] = ssoProviders
				findings = append(findings, finding.Finding{
					CheckID:      finding.CheckAuthSSOEndpoint,
					Module:       "surface",
					Scanner:      scannerName,
					Severity:     finding.SeverityInfo,
					Title:        fmt.Sprintf("SSO login detected on %s%s (%s)", asset, path, strings.Join(ssoProviders, ", ")),
					Description:  fmt.Sprintf("The login page at %s supports SSO authentication via %s. SSO credentials or test accounts are needed for authenticated scanning.", path, strings.Join(ssoProviders, ", ")),
					Asset:        asset,
					Evidence:     ev,
					DiscoveredAt: now,
				})
			}

			// Emit login form finding
			findings = append(findings, finding.Finding{
				CheckID:     finding.CheckAuthLoginFormDetected,
				Module:      "surface",
				Scanner:     scannerName,
				Severity:    finding.SeverityInfo,
				Title:       fmt.Sprintf("Login form detected at %s%s", asset, path),
				Description: fmt.Sprintf("A password-based login form was found at %s. Credentials are needed to scan the authenticated attack surface behind this login. Fields: %s", path, strings.Join(fields, ", ")),
				Asset:       asset,
				Evidence:    ev,
				ProofCommand: fmt.Sprintf("curl -s '%s://%s%s' | grep -i 'type=\"password\"'", scheme, asset, path),
				DiscoveredAt: now,
			})

			if hasCaptcha {
				findings = append(findings, finding.Finding{
					CheckID:      finding.CheckAuthMFADetected,
					Module:       "surface",
					Scanner:      scannerName,
					Severity:     finding.SeverityInfo,
					Title:        fmt.Sprintf("CAPTCHA detected on login form at %s%s", asset, path),
					Description:  "Login form has CAPTCHA protection. Automated credential testing requires a CAPTCHA solver (2Captcha, AntiCaptcha) or reCAPTCHA test keys for development environments.",
					Asset:        asset,
					Evidence:     ev,
					DiscoveredAt: now,
				})
			}

			break // found login form, don't probe more paths
		}
	}

	// Detect registration pages
	for _, path := range registerPaths {
		body, status := fetchPage(ctx, client, scheme+"://"+asset+path)
		if status == 0 || status >= 400 {
			continue
		}

		lower := strings.ToLower(body)
		if strings.Contains(lower, `type="password"`) &&
			(strings.Contains(lower, "register") || strings.Contains(lower, "sign up") ||
				strings.Contains(lower, "create account") || strings.Contains(lower, "join")) {
			findings = append(findings, finding.Finding{
				CheckID:     finding.CheckAuthRegistrationOpen,
				Module:      "surface",
				Scanner:     scannerName,
				Severity:    finding.SeverityMedium,
				Title:       fmt.Sprintf("Self-registration available at %s%s", asset, path),
				Description: fmt.Sprintf("The application allows self-registration at %s. An ephemeral test account can be created for authenticated scanning. This is also a finding — open registration may be unintended.", path),
				Asset:       asset,
				Evidence:    map[string]any{"path": path, "auto_register_possible": true},
				ProofCommand: fmt.Sprintf("curl -s '%s://%s%s' | grep -i 'register\\|sign.up\\|create.account'", scheme, asset, path),
				DiscoveredAt: now,
			})
			break
		}
	}

	return findings, nil
}

func fetchPage(ctx context.Context, client *http.Client, url string) (string, int) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", 0
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	return string(body), resp.StatusCode
}

func extractFormAction(html string) string {
	lower := strings.ToLower(html)
	idx := strings.Index(lower, "<form")
	if idx < 0 {
		return ""
	}
	rest := html[idx:]
	actionIdx := strings.Index(strings.ToLower(rest), "action=")
	if actionIdx < 0 {
		return ""
	}
	rest = rest[actionIdx+7:]
	quote := rest[0]
	if quote != '"' && quote != '\'' {
		return ""
	}
	end := strings.IndexByte(rest[1:], quote)
	if end < 0 {
		return ""
	}
	return rest[1 : end+1]
}

func extractInputNames(html string) []string {
	var names []string
	lower := strings.ToLower(html)
	for {
		idx := strings.Index(lower, `name="`)
		if idx < 0 {
			break
		}
		rest := lower[idx+6:]
		end := strings.IndexByte(rest, '"')
		if end < 0 {
			break
		}
		name := rest[:end]
		if name != "" && name != "csrf" && name != "_token" {
			names = append(names, name)
		}
		lower = rest[end:]
	}
	return names
}

func detectSSO(html string) []string {
	var providers []string
	ssoSignals := map[string]string{
		"google":     "Google",
		"github":     "GitHub",
		"facebook":   "Facebook",
		"microsoft":  "Microsoft",
		"apple":      "Apple",
		"okta":       "Okta",
		"auth0":      "Auth0",
		"keycloak":   "Keycloak",
		"saml":       "SAML",
		"openid":     "OpenID",
		"metamask":   "MetaMask",
		"walletconnect": "WalletConnect",
	}
	for signal, name := range ssoSignals {
		if strings.Contains(html, signal) && (strings.Contains(html, "login") || strings.Contains(html, "sign")) {
			providers = append(providers, name)
		}
	}
	return providers
}
