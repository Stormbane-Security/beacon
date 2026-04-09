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
	// If HTTPS fails, try HTTP (common in testing and internal networks)
	if _, status := fetchPage(ctx, client, scheme+"://"+asset+"/"); status == 0 && scheme == "https" {
		scheme = "http"
	}

	var findings []finding.Finding
	now := time.Now()

	base := scheme + "://" + asset

	// Use paths from scan context evidence (crawl results) if available,
	// otherwise fetch the main page and extract links + use fallbacks.
	var loginPaths, registerPaths []string

	// Try to get crawl-discovered URLs from context
	if v := ctx.Value(module.CrawlFeedKey); v != nil {
		if ch, ok := v.(chan string); ok {
			for {
				select {
				case url, ok := <-ch:
					if !ok {
						goto drained
					}
					lower := strings.ToLower(url)
					if strings.Contains(lower, "login") || strings.Contains(lower, "signin") ||
						strings.Contains(lower, "auth") || strings.Contains(lower, "admin") {
						if strings.HasPrefix(url, base) {
							loginPaths = append(loginPaths, url[len(base):])
						}
					}
					if strings.Contains(lower, "register") || strings.Contains(lower, "signup") ||
						strings.Contains(lower, "join") || strings.Contains(lower, "create-account") {
						if strings.HasPrefix(url, base) {
							registerPaths = append(registerPaths, url[len(base):])
						}
					}
				default:
					goto drained
				}
			}
		drained:
		}
	}

	// Fetch main page and extract links as supplementary source
	mainBody, mainStatus := fetchPage(ctx, client, base+"/")
	if mainStatus == 200 {
		// If the main page is a SPA, render it to find links and password fields.
		if scan.IsSPA(mainBody) {
			if rendered, err := scan.RenderSPA(ctx, base+"/"); err == nil && rendered != "" {
				mainBody = rendered
			}
		}

		// Extract href links from HTML
		lower := strings.ToLower(mainBody)
		for _, attr := range []string{`href="`, `href='`} {
			idx := 0
			for {
				pos := strings.Index(lower[idx:], attr)
				if pos < 0 {
					break
				}
				start := idx + pos + len(attr)
				quote := lower[start-1]
				end := strings.IndexByte(lower[start:], quote)
				if end < 0 {
					break
				}
				link := mainBody[start : start+end]
				linkLower := strings.ToLower(link)
				if strings.Contains(linkLower, "login") || strings.Contains(linkLower, "signin") ||
					strings.Contains(linkLower, "auth") {
					loginPaths = append(loginPaths, link)
				}
				if strings.Contains(linkLower, "register") || strings.Contains(linkLower, "signup") ||
					strings.Contains(linkLower, "join") {
					registerPaths = append(registerPaths, link)
				}
				idx = start + end
			}
		}

		// If main page itself has a login form, it's the login page
		if hasLoginForm(lower) {
			loginPaths = append([]string{"/"}, loginPaths...)
		}
	}

	// If the main page is a SPA, also probe common hash-fragment login paths.
	// SPAs with client-side routing (Angular, React Router, Vue Router) use
	// hash fragments like /#/login that HTTP GETs cannot distinguish.
	isSPAApp := mainStatus == 200 && scan.IsSPA(mainBody)
	if isSPAApp {
		hashLoginPaths := []string{"#/login", "#/signin", "#/sign-in", "#/auth/login", "#/admin"}
		hashRegisterPaths := []string{"#/register", "#/signup", "#/sign-up", "#/join"}
		loginPaths = append(loginPaths, hashLoginPaths...)
		registerPaths = append(registerPaths, hashRegisterPaths...)
	}

	// Fallback: add common paths if nothing found from crawl/links
	if len(loginPaths) == 0 {
		loginPaths = []string{"/login", "/login.php", "/signin", "/auth/login", "/admin",
			"/wp-login.php", "/accounts/login", "/user/login", "/index.php"}
	}
	if len(registerPaths) == 0 {
		registerPaths = []string{"/register", "/signup", "/sign-up", "/join"}
	}

	// Deduplicate
	loginPaths = dedup(loginPaths)
	registerPaths = dedup(registerPaths)

	for _, path := range loginPaths {
		isHashPath := strings.HasPrefix(path, "#")

		// For hash-fragment paths, fetch the base URL (HTTP ignores fragments).
		fetchURL := scheme + "://" + asset + path
		if isHashPath {
			fetchURL = base + "/"
		}

		body, status := fetchPage(ctx, client, fetchURL)
		if status == 0 || status >= 400 {
			continue
		}

		// If the page looks like a SPA (Angular/React/Vue), render it in
		// headless Chrome to get the actual DOM with login forms that are
		// built client-side by JavaScript. Hash-fragment paths always need
		// rendering since the server returns the same HTML shell for all routes.
		if scan.IsSPA(body) || isHashPath {
			renderURL := base + "/" + path
			if rendered, err := scan.RenderSPA(ctx, renderURL); err == nil && rendered != "" {
				body = rendered
			}
		}

		lower := strings.ToLower(body)

		// Detect login form — use multiple heuristics beyond type="password"
		// because SPAs (Angular Material, React) often use non-standard patterns.
		if hasLoginForm(lower) {
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
			proofCmd := fmt.Sprintf("curl -s '%s://%s%s' | grep -i 'type=\"password\"'", scheme, asset, path)
			if isHashPath {
				// curl ignores URL fragments; suggest using beacon or a browser.
				proofCmd = fmt.Sprintf("beacon scan --host %s --scanners authsurface --no-enrich --no-nmap --yes  # SPA login at %s", asset, path)
			}
			findings = append(findings, finding.Finding{
				CheckID:     finding.CheckAuthLoginFormDetected,
				Module:      "surface",
				Scanner:     scannerName,
				Severity:    finding.SeverityInfo,
				Title:       fmt.Sprintf("Login form detected at %s%s", asset, path),
				Description: fmt.Sprintf("A password-based login form was found at %s. Credentials are needed to scan the authenticated attack surface behind this login. Fields: %s", path, strings.Join(fields, ", ")),
				Asset:       asset,
				Evidence:    ev,
				ProofCommand: proofCmd,
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
		isHashPath := strings.HasPrefix(path, "#")

		fetchURL := scheme + "://" + asset + path
		if isHashPath {
			fetchURL = base + "/"
		}

		body, status := fetchPage(ctx, client, fetchURL)
		if status == 0 || status >= 400 {
			continue
		}

		// SPA rendering for registration pages too.
		if scan.IsSPA(body) || isHashPath {
			renderURL := base + "/" + path
			if rendered, err := scan.RenderSPA(ctx, renderURL); err == nil && rendered != "" {
				body = rendered
			}
		}

		lower := strings.ToLower(body)
		if hasLoginForm(lower) &&
			(strings.Contains(lower, "register") || strings.Contains(lower, "sign up") ||
				strings.Contains(lower, "create account") || strings.Contains(lower, "join")) {
			regProofCmd := fmt.Sprintf("curl -s '%s://%s%s' | grep -i 'register\\|sign.up\\|create.account'", scheme, asset, path)
			if isHashPath {
				regProofCmd = fmt.Sprintf("beacon scan --host %s --scanners authsurface --no-enrich --no-nmap --yes  # SPA registration at %s", asset, path)
			}
			findings = append(findings, finding.Finding{
				CheckID:     finding.CheckAuthRegistrationOpen,
				Module:      "surface",
				Scanner:     scannerName,
				Severity:    finding.SeverityMedium,
				Title:       fmt.Sprintf("Self-registration available at %s%s", asset, path),
				Description: fmt.Sprintf("The application allows self-registration at %s. An ephemeral test account can be created for authenticated scanning. This is also a finding — open registration may be unintended.", path),
				Asset:       asset,
				Evidence:    map[string]any{"path": path, "auto_register_possible": true},
				ProofCommand: regProofCmd,
				DiscoveredAt: now,
			})
			break
		}
	}

	return findings, nil
}

func dedup(ss []string) []string {
	seen := make(map[string]bool, len(ss))
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
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
	seen := make(map[string]bool)
	lower := strings.ToLower(html)

	// Only extract name= attributes from input, select, and textarea elements.
	// This avoids noise from meta tags, divs, and Angular Material components.
	inputTags := []string{"<input", "<select", "<textarea"}
	for _, tag := range inputTags {
		search := lower
		for {
			tagIdx := strings.Index(search, tag)
			if tagIdx < 0 {
				break
			}
			// Find the end of this element's opening tag.
			closeIdx := strings.IndexByte(search[tagIdx:], '>')
			if closeIdx < 0 {
				break
			}
			elem := search[tagIdx : tagIdx+closeIdx]
			// Extract name="..." from within this element.
			nameIdx := strings.Index(elem, `name="`)
			if nameIdx >= 0 {
				rest := elem[nameIdx+6:]
				end := strings.IndexByte(rest, '"')
				if end > 0 {
					name := rest[:end]
					skip := []string{"", "csrf", "_token", "viewport", "description",
						"keywords", "robots", "author", "generator"}
					isSkip := false
					for _, s := range skip {
						if name == s {
							isSkip = true
							break
						}
					}
					if !isSkip && !seen[name] {
						seen[name] = true
						names = append(names, name)
					}
				}
			}
			search = search[tagIdx+closeIdx:]
		}
	}
	return names
}

// hasLoginForm detects login/auth forms using multiple heuristics beyond just
// type="password". SPAs (Angular Material, React, Vue) use varied patterns:
//   - Standard password inputs: type="password"
//   - Angular reactive forms: formcontrolname="password"
//   - Angular template-driven: [(ngmodel)]="password"
//   - Elements with id/name containing password-related words
//   - Form actions pointing to auth endpoints
//   - Buttons with login/sign-in text
func hasLoginForm(lower string) bool {
	// 1. Standard password input (covers React className too since we check lowercase HTML).
	if strings.Contains(lower, `type="password"`) || strings.Contains(lower, `type='password'`) {
		return true
	}

	// 2. Elements with id or name containing password-related words.
	pwFields := []string{"password", "passwd", "pass_word", "user_pass"}
	for _, pw := range pwFields {
		if strings.Contains(lower, `id="`+pw) || strings.Contains(lower, `id='`+pw) ||
			strings.Contains(lower, `name="`+pw) || strings.Contains(lower, `name='`+pw) {
			return true
		}
	}

	// 3. Angular reactive forms and template-driven forms.
	if strings.Contains(lower, `formcontrolname="password"`) ||
		strings.Contains(lower, `formcontrolname='password'`) ||
		strings.Contains(lower, `[(ngmodel)]="password"`) ||
		strings.Contains(lower, `[(ngmodel)]='password'`) {
		return true
	}

	// 4. Form action pointing to auth endpoints combined with a submit-like button.
	authActions := []string{"/login", "/auth", "/api/login", "/signin", "/api/auth", "/session"}
	hasAuthAction := false
	for _, action := range authActions {
		if strings.Contains(lower, `action="`+action) || strings.Contains(lower, `action='`+action) {
			hasAuthAction = true
			break
		}
	}

	// 5. Buttons with login/sign-in text.
	loginButtons := []string{">sign in<", ">log in<", ">login<", ">submit<", ">sign-in<"}
	hasLoginButton := false
	for _, btn := range loginButtons {
		if strings.Contains(lower, btn) {
			hasLoginButton = true
			break
		}
	}

	// A form action to an auth endpoint with a submit button is a login form
	// even without a visible password field (e.g., multi-step login).
	if hasAuthAction && hasLoginButton {
		return true
	}

	return false
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
