// Package auth — pipeline.go orchestrates the authenticated scanning flow:
// detect login → acquire session → provide authenticated client.
//
// The Pipeline tries multiple strategies in priority order:
//  1. User-provided credentials (from AuthConfig)
//  2. Auto-registration (if a registration endpoint was detected)
//  3. Default credentials (admin/admin, etc.)
//
// The result is an authenticated *http.Client that injects the session
// credential into every outbound request, plus metadata about how the
// session was acquired.
package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/config"
	"github.com/stormbane-security/beacon/internal/finding"
)

// LoginForm describes a login form discovered by the authsurface scanner.
// It is extracted from finding.Evidence fields.
type LoginForm struct {
	URL          string   // full URL where the form was found
	Action       string   // form action attribute (POST target)
	Fields       []string // input field names (e.g. ["username", "password"])
	Method       string   // HTTP method (GET or POST)
	HasCAPTCHA   bool
	SSOProviders []string
}

// SessionInfo describes an authenticated session acquired by the pipeline.
type SessionInfo struct {
	Token    string            // bearer token (if token-based auth)
	Cookies  []*http.Cookie    // session cookies
	Headers  map[string]string // auth headers to inject
	Username string
	Source   string // "config", "auto-register", "default-creds"
}

// Pipeline orchestrates the auth flow: detect login → acquire session → recrawl.
type Pipeline struct {
	HTTPClient *http.Client
}

// NewPipeline creates a Pipeline with the given base HTTP client.
// If client is nil, a default client with 15s timeout is used.
func NewPipeline(client *http.Client) *Pipeline {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &Pipeline{HTTPClient: client}
}

// ExtractLoginForms parses authsurface findings into LoginForm structs.
// Looks for findings with CheckID == auth.login_form_detected and extracts
// form metadata from the Evidence map.
func ExtractLoginForms(findings []finding.Finding, scheme, asset string) []LoginForm {
	var forms []LoginForm
	for _, f := range findings {
		if f.CheckID != finding.CheckAuthLoginFormDetected {
			continue
		}
		ev := f.Evidence
		if ev == nil {
			continue
		}

		form := LoginForm{}

		// Extract path → build full URL
		if path, ok := ev["path"].(string); ok {
			form.URL = scheme + "://" + asset + path
		}
		if action, ok := ev["form_action"].(string); ok {
			form.Action = action
		}
		if fields, ok := ev["input_fields"].([]string); ok {
			form.Fields = fields
		} else if fieldsIface, ok := ev["input_fields"].([]interface{}); ok {
			for _, fi := range fieldsIface {
				if s, ok := fi.(string); ok {
					form.Fields = append(form.Fields, s)
				}
			}
		}
		if ct, ok := ev["captcha_type"].(string); ok && ct != "" {
			form.HasCAPTCHA = true
		}
		if sso, ok := ev["sso_providers"].([]string); ok {
			form.SSOProviders = sso
		}

		// Default method is POST for login forms
		form.Method = "POST"

		forms = append(forms, form)
	}
	return forms
}

// HasRegistration checks if authsurface found an open registration endpoint.
func HasRegistration(findings []finding.Finding) bool {
	for _, f := range findings {
		if f.CheckID == finding.CheckAuthRegistrationOpen {
			return true
		}
	}
	return false
}

// AcquireSession attempts to get an authenticated session for the target.
// It tries strategies in priority order:
//  1. User-provided credentials (from auth config)
//  2. Auto-registration (if enabled and registration endpoint found)
//  3. Default credentials (admin/admin, admin/password, etc.)
//
// Returns an authenticated http.Client and session metadata, or nil if no
// auth was possible.
func (p *Pipeline) AcquireSession(
	ctx context.Context,
	asset string,
	scheme string,
	loginForm *LoginForm,
	authCfgs []config.AuthConfig,
	registrationAvailable bool,
) (*http.Client, *SessionInfo, error) {
	baseURL := scheme + "://" + asset

	// Strategy 1: User-provided credentials via AuthConfig.
	if len(authCfgs) > 0 {
		client, session, err := Authenticate(ctx, authCfgs, asset, p.HTTPClient)
		if err != nil {
			// Log but continue to next strategy.
			_ = err
		} else if client != nil {
			info := &SessionInfo{
				Headers:  session.Headers,
				Username: configUsername(authCfgs, asset),
				Source:   "config",
			}
			return client, info, nil
		}
	}

	// If no login form was detected, we can't try auto-register or default creds.
	if loginForm == nil {
		return nil, nil, nil
	}

	// Skip if login form has CAPTCHA — can't automate.
	if loginForm.HasCAPTCHA {
		return nil, nil, fmt.Errorf("login form has CAPTCHA; cannot automate authentication")
	}

	// Strategy 2: Auto-registration (if an open registration endpoint was found).
	if registrationAvailable {
		cookie, err := AutoRegister(ctx, baseURL, p.HTTPClient)
		if err == nil && cookie != "" {
			client := injectHeader(p.HTTPClient, authHeaderKey(cookie), cookie)
			info := &SessionInfo{
				Source:  "auto-register",
				Headers: map[string]string{authHeaderKey(cookie): cookie},
			}
			if strings.HasPrefix(cookie, "Bearer ") {
				info.Token = cookie
			} else {
				// Parse cookies from the raw Set-Cookie value.
				info.Cookies = parseCookieHeader(cookie)
			}
			return client, info, nil
		}
	}

	// Strategy 3: Default credentials.
	client, info, err := TryDefaultCreds(ctx, p.HTTPClient, loginForm, baseURL)
	if err == nil && client != nil {
		return client, info, nil
	}

	return nil, nil, nil
}

// authHeaderKey returns the appropriate header name for injecting the credential.
func authHeaderKey(credential string) string {
	if strings.HasPrefix(credential, "Bearer ") || strings.HasPrefix(credential, "bearer ") {
		return "Authorization"
	}
	return "Cookie"
}

// parseCookieHeader splits a raw cookie string into http.Cookie values.
func parseCookieHeader(raw string) []*http.Cookie {
	var cookies []*http.Cookie
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if eq := strings.IndexByte(part, '='); eq > 0 {
			cookies = append(cookies, &http.Cookie{
				Name:  part[:eq],
				Value: part[eq+1:],
			})
		}
	}
	return cookies
}

// configUsername extracts the username from the first matching AuthConfig.
func configUsername(cfgs []config.AuthConfig, asset string) string {
	for _, c := range cfgs {
		if c.Asset == asset || c.Asset == "*" {
			return c.Username
		}
	}
	return ""
}

// InjectSessionIntoClient creates a new http.Client that injects the session
// credentials from SessionInfo into every outbound request.
func InjectSessionIntoClient(base *http.Client, info *SessionInfo) *http.Client {
	if info == nil {
		return base
	}

	// If we have explicit headers, inject each one.
	if len(info.Headers) > 0 {
		c := base
		for key, value := range info.Headers {
			c = injectHeader(c, key, value)
		}
		return c
	}

	// If we have cookies, use a cookie jar.
	if len(info.Cookies) > 0 {
		jar, _ := cookiejar.New(nil)
		c := *base
		c.Jar = jar
		return &c
	}

	// If we have a bearer token, inject as Authorization header.
	if info.Token != "" {
		return injectHeader(base, "Authorization", info.Token)
	}

	return base
}
