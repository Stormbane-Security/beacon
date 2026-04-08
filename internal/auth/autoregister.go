// Package auth provides authentication for beacon scanners.

package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// AutoRegister attempts to create an ephemeral test account on the target
// by submitting common registration forms. Returns (cookie, error) where
// cookie is the session from the registration response.
//
// This only works on apps with open self-registration. Apps that require
// email verification, admin approval, or CAPTCHA will fail gracefully.
func AutoRegister(ctx context.Context, target string, client *http.Client) (string, error) {
	// Generate random credentials
	randBytes := make([]byte, 8)
	rand.Read(randBytes)
	suffix := hex.EncodeToString(randBytes)
	email := fmt.Sprintf("beacon-test-%s@test.beacon.local", suffix)
	username := fmt.Sprintf("beacon_test_%s", suffix[:8])
	password := fmt.Sprintf("BeaconTest_%s!", suffix)

	// Try common registration endpoints
	registerPaths := []struct {
		path        string
		contentType string
		body        func() string
	}{
		// JSON API registration (modern SPAs)
		{"/api/Users/", "application/json",
			func() string {
				return fmt.Sprintf(`{"email":"%s","password":"%s","passwordRepeat":"%s","securityQuestion":{"id":1,"question":"test"},"securityAnswer":"beacon"}`, email, password, password)
			}},
		{"/api/auth/register", "application/json",
			func() string {
				return fmt.Sprintf(`{"email":"%s","username":"%s","password":"%s"}`, email, username, password)
			}},
		{"/api/register", "application/json",
			func() string {
				return fmt.Sprintf(`{"email":"%s","username":"%s","password":"%s","password_confirm":"%s"}`, email, username, password, password)
			}},
		// Form-based registration (traditional apps)
		{"/register", "application/x-www-form-urlencoded",
			func() string {
				return fmt.Sprintf("email=%s&username=%s&password=%s&password_confirm=%s", url.QueryEscape(email), url.QueryEscape(username), url.QueryEscape(password), url.QueryEscape(password))
			}},
		{"/signup", "application/x-www-form-urlencoded",
			func() string {
				return fmt.Sprintf("email=%s&username=%s&password=%s&password2=%s", url.QueryEscape(email), url.QueryEscape(username), url.QueryEscape(password), url.QueryEscape(password))
			}},
	}

	for _, rp := range registerPaths {
		regURL := target + rp.path
		body := rp.body()

		req, err := http.NewRequestWithContext(ctx, "POST", regURL, strings.NewReader(body))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", rp.contentType)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()

		// Check for successful registration (200, 201, 302)
		if resp.StatusCode == 200 || resp.StatusCode == 201 || resp.StatusCode == 302 {
			// Extract session cookie if set
			cookies := resp.Header["Set-Cookie"]
			if len(cookies) > 0 {
				return cookies[0], nil
			}

			// If JSON response contains a token, use that
			respStr := string(respBody)
			if strings.Contains(respStr, "token") || strings.Contains(respStr, "session") {
				// Try to login with the credentials we just created
				loginCookie, err := loginWithCreds(ctx, target, client, email, username, password)
				if err == nil {
					return loginCookie, nil
				}
			}

			// Registration succeeded but no session — try login
			loginCookie, err := loginWithCreds(ctx, target, client, email, username, password)
			if err == nil {
				return loginCookie, nil
			}
		}
	}

	return "", fmt.Errorf("auto-register failed: no registration endpoint accepted our request")
}

// loginWithCreds attempts to login with the given credentials on common login endpoints.
func loginWithCreds(ctx context.Context, target string, client *http.Client, email, username, password string) (string, error) {
	loginPaths := []struct {
		path        string
		contentType string
		body        string
	}{
		{"/rest/user/login", "application/json", fmt.Sprintf(`{"email":"%s","password":"%s"}`, email, password)},
		{"/api/auth/login", "application/json", fmt.Sprintf(`{"email":"%s","password":"%s"}`, email, password)},
		{"/api/login", "application/json", fmt.Sprintf(`{"username":"%s","password":"%s"}`, username, password)},
		{"/login", "application/x-www-form-urlencoded", fmt.Sprintf("username=%s&password=%s", url.QueryEscape(username), url.QueryEscape(password))},
	}

	for _, lp := range loginPaths {
		loginURL := target + lp.path
		req, err := http.NewRequestWithContext(ctx, "POST", loginURL, strings.NewReader(lp.body))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", lp.contentType)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()

		if resp.StatusCode == 200 || resp.StatusCode == 302 {
			// Check for token in response
			respStr := string(respBody)
			if strings.Contains(respStr, "token") {
				// Extract token (basic JSON parsing)
				if idx := strings.Index(respStr, `"token":"`); idx >= 0 {
					rest := respStr[idx+9:]
					if end := strings.IndexByte(rest, '"'); end >= 0 {
						return "Bearer " + rest[:end], nil
					}
				}
			}
			// Check for session cookie
			cookies := resp.Header["Set-Cookie"]
			if len(cookies) > 0 {
				return cookies[0], nil
			}
		}
	}

	return "", fmt.Errorf("login failed with created credentials")
}

// AutoRegisterResult contains the outcome of an auto-registration attempt.
type AutoRegisterResult struct {
	Success     bool   `json:"success"`
	Email       string `json:"email"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	Cookie      string `json:"cookie,omitempty"`
	Token       string `json:"token,omitempty"`
	RegisterURL string `json:"register_url,omitempty"`
	LoginURL    string `json:"login_url,omitempty"`
	Error       string `json:"error,omitempty"`
}

// TryAutoRegister is the high-level function that attempts auto-registration
// and returns structured results for Forecast.
func TryAutoRegister(ctx context.Context, target string) *AutoRegisterResult {
	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	cookie, err := AutoRegister(ctx, target, client)
	if err != nil {
		return &AutoRegisterResult{Success: false, Error: err.Error()}
	}

	result := &AutoRegisterResult{
		Success: true,
		Cookie:  cookie,
	}

	// The email/username/password are random — extract from the function
	// In a real implementation, these would be returned from AutoRegister
	return result
}
