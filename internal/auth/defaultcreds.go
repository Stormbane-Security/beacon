package auth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

// defaultCredPair is a username/password combination commonly left on web
// applications, IoT devices, and development environments.
type defaultCredPair struct {
	Username string
	Password string
}

// defaultCreds is the list of default credential pairs to try, ordered by
// likelihood. Kept deliberately short to avoid looking like a brute-force
// attack — these are only the most common factory defaults.
var defaultCreds = []defaultCredPair{
	{"admin", "admin"},
	{"admin", "password"},
	{"admin", "admin123"},
	{"admin", "123456"},
	{"root", "root"},
	{"root", "toor"},
	{"test", "test"},
	{"user", "user"},
	{"guest", "guest"},
	{"demo", "demo"},
}

// TryDefaultCreds attempts each default credential pair against the
// discovered login form. If a login succeeds (indicated by a Set-Cookie
// header or a bearer token in the response body), it returns an
// authenticated http.Client and session metadata.
//
// The function uses the field names from the LoginForm to build the POST
// body, so it works regardless of whether the form uses "username",
// "email", "user", etc.
func TryDefaultCreds(
	ctx context.Context,
	base *http.Client,
	form *LoginForm,
	baseURL string,
) (*http.Client, *SessionInfo, error) {
	if form == nil {
		return nil, nil, fmt.Errorf("no login form provided")
	}

	// Determine which fields to use for username and password.
	usernameField, passwordField := guessFields(form.Fields)
	if usernameField == "" || passwordField == "" {
		return nil, nil, fmt.Errorf("cannot determine username/password fields from: %v", form.Fields)
	}

	// Determine the POST target URL.
	loginURL := form.URL
	if form.Action != "" {
		if strings.HasPrefix(form.Action, "http://") || strings.HasPrefix(form.Action, "https://") {
			loginURL = form.Action
		} else {
			loginURL = baseURL + "/" + strings.TrimPrefix(form.Action, "/")
		}
	}

	for _, cred := range defaultCreds {
		client, info, err := tryLogin(ctx, base, loginURL, usernameField, passwordField, cred.Username, cred.Password)
		if err != nil {
			continue
		}
		if client != nil {
			return client, info, nil
		}
	}

	return nil, nil, fmt.Errorf("no default credentials worked")
}

// tryLogin attempts a single login with the given credentials.
// Returns a non-nil client on success.
func tryLogin(
	ctx context.Context,
	base *http.Client,
	loginURL string,
	usernameField, passwordField string,
	username, password string,
) (*http.Client, *SessionInfo, error) {
	data := url.Values{}
	data.Set(usernameField, username)
	data.Set(passwordField, password)

	jar, _ := cookiejar.New(nil)
	client := *base
	client.Jar = jar
	client.Timeout = 10 * time.Second
	client.CheckRedirect = func(_ *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("too many redirects")
		}
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, strings.NewReader(data.Encode()))
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

	// Success indicators:
	// 1. Response sets a session cookie
	// 2. Response contains a bearer token
	// 3. Response is a redirect to a non-login page (302/303 to /dashboard, etc.)

	loginParsed, _ := url.Parse(loginURL)

	// Check jar cookies
	var sessionCookies []*http.Cookie
	if loginParsed != nil {
		sessionCookies = jar.Cookies(loginParsed)
	}

	// Also check direct response cookies
	if len(sessionCookies) == 0 {
		sessionCookies = resp.Cookies()
	}

	if len(sessionCookies) > 0 {
		// Build Cookie header value
		parts := make([]string, 0, len(sessionCookies))
		for _, c := range sessionCookies {
			parts = append(parts, c.Name+"="+c.Value)
		}
		cookieVal := strings.Join(parts, "; ")
		authedClient := injectHeader(base, "Cookie", cookieVal)
		return authedClient, &SessionInfo{
			Cookies:  sessionCookies,
			Headers:  map[string]string{"Cookie": cookieVal},
			Username: username,
			Source:   "default-creds",
		}, nil
	}

	// Check for bearer token in JSON response
	respStr := string(body)
	if resp.StatusCode == 200 || resp.StatusCode == 201 {
		if token := extractToken(respStr); token != "" {
			bearer := "Bearer " + token
			authedClient := injectHeader(base, "Authorization", bearer)
			return authedClient, &SessionInfo{
				Token:    bearer,
				Headers:  map[string]string{"Authorization": bearer},
				Username: username,
				Source:   "default-creds",
			}, nil
		}
	}

	// Check for redirect to non-login page (successful login often redirects)
	if resp.StatusCode == 302 || resp.StatusCode == 303 {
		loc := resp.Header.Get("Location")
		locLower := strings.ToLower(loc)
		if loc != "" &&
			!strings.Contains(locLower, "login") &&
			!strings.Contains(locLower, "error") &&
			!strings.Contains(locLower, "fail") {
			// Redirect to a non-login page suggests success, but we need cookies
			if len(resp.Cookies()) > 0 {
				parts := make([]string, 0)
				for _, c := range resp.Cookies() {
					parts = append(parts, c.Name+"="+c.Value)
				}
				cookieVal := strings.Join(parts, "; ")
				authedClient := injectHeader(base, "Cookie", cookieVal)
				return authedClient, &SessionInfo{
					Cookies:  resp.Cookies(),
					Headers:  map[string]string{"Cookie": cookieVal},
					Username: username,
					Source:   "default-creds",
				}, nil
			}
		}
	}

	return nil, nil, nil
}

// extractToken attempts to extract a bearer token from a JSON response body.
// Handles common patterns like {"token":"..."}, {"access_token":"..."}.
func extractToken(body string) string {
	for _, key := range []string{`"token":"`, `"access_token":"`, `"accessToken":"`, `"jwt":"`} {
		idx := strings.Index(body, key)
		if idx < 0 {
			continue
		}
		rest := body[idx+len(key):]
		end := strings.IndexByte(rest, '"')
		if end > 0 {
			return rest[:end]
		}
	}
	return ""
}

// guessFields identifies the username and password fields from a list of
// input field names. Returns ("", "") if neither can be determined.
func guessFields(fields []string) (usernameField, passwordField string) {
	usernameKeys := []string{"username", "user", "email", "login", "name", "user_name", "userid"}
	passwordKeys := []string{"password", "pass", "passwd", "pwd", "secret", "user_password"}

	for _, f := range fields {
		lower := strings.ToLower(f)
		if usernameField == "" {
			for _, uk := range usernameKeys {
				if lower == uk || strings.Contains(lower, uk) {
					usernameField = f
					break
				}
			}
		}
		if passwordField == "" {
			for _, pk := range passwordKeys {
				if lower == pk || strings.Contains(lower, pk) {
					passwordField = f
					break
				}
			}
		}
	}

	// Fallback: if we have exactly two fields and one is not identified,
	// assume the first is username and second is password.
	if len(fields) == 2 {
		if usernameField == "" && passwordField != "" {
			for _, f := range fields {
				if f != passwordField {
					usernameField = f
					break
				}
			}
		}
		if passwordField == "" && usernameField != "" {
			for _, f := range fields {
				if f != usernameField {
					passwordField = f
					break
				}
			}
		}
		if usernameField == "" && passwordField == "" {
			usernameField = fields[0]
			passwordField = fields[1]
		}
	}

	return usernameField, passwordField
}
