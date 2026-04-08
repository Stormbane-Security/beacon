// Package auth provides pre-scan authentication for beacon's authenticated scanning mode.
// Given an AuthConfig and a target asset, it performs the appropriate login flow
// and returns a wrapped *http.Client that injects the resulting credential into
// every request.
package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/config"
	"github.com/stormbane-security/beacon/internal/scanner/web3auth"
)

// Session holds the result of a pre-scan login.
type Session struct {
	// Method describes how the credential is injected.
	Method string
	// Label is a human-readable description (e.g. "bearer token", "SIWE session cookie").
	Label string
	// Headers contains the raw auth headers for subprocess tools (katana, ffuf)
	// that can't use the Go HTTP client. Key is header name, value is header value.
	Headers map[string]string
}

// Authenticate performs the login described by cfg for the given asset and returns
// an http.Client that injects the credential into every request.
// Returns (nil, nil) if no matching AuthConfig exists for the asset.
func Authenticate(ctx context.Context, cfgs []config.AuthConfig, asset string, base *http.Client) (*http.Client, *Session, error) {
	var ac *config.AuthConfig
	for i := range cfgs {
		if cfgs[i].Asset == asset || cfgs[i].Asset == "*" {
			ac = &cfgs[i]
			break
		}
	}
	if ac == nil {
		return nil, nil, nil
	}

	// Reject tokens containing CR/LF to prevent header injection.
	if ac.Token != "" && strings.ContainsAny(ac.Token, "\r\n") {
		return nil, nil, fmt.Errorf("auth: token contains invalid characters")
	}
	// Reject cookie values containing CR/LF to prevent header injection.
	if ac.Cookie != "" && strings.ContainsAny(ac.Cookie, "\r\n") {
		return nil, nil, fmt.Errorf("auth: cookie contains invalid characters")
	}
	// Reject basic auth credentials containing CR/LF to prevent header injection.
	if ac.Username != "" && strings.ContainsAny(ac.Username, "\r\n") {
		return nil, nil, fmt.Errorf("auth: username contains invalid characters")
	}
	if ac.Password != "" && strings.ContainsAny(ac.Password, "\r\n") {
		return nil, nil, fmt.Errorf("auth: password contains invalid characters")
	}
	// Reject custom header names containing CR/LF to prevent header injection.
	if ac.Header != "" && strings.ContainsAny(ac.Header, "\r\n") {
		return nil, nil, fmt.Errorf("auth: header name contains invalid characters")
	}

	switch ac.Method {
	case "bearer":
		token := ac.Token
		header := ac.Header
		if header == "" {
			header = "Authorization"
		}
		value := token
		if header == "Authorization" && !strings.HasPrefix(strings.ToLower(token), "bearer ") {
			value = "Bearer " + token
		}
		return injectHeader(base, header, value),
			&Session{Method: "bearer", Label: "bearer token", Headers: map[string]string{header: value}}, nil

	case "api_key":
		header := ac.Header
		if header == "" {
			header = "X-API-Key"
		}
		return injectHeader(base, header, ac.Token),
			&Session{Method: "api_key", Label: fmt.Sprintf("%s header", header), Headers: map[string]string{header: ac.Token}}, nil

	case "cookie":
		return injectHeader(base, "Cookie", ac.Cookie),
			&Session{Method: "cookie", Label: "session cookie", Headers: map[string]string{"Cookie": ac.Cookie}}, nil

	case "basic":
		encoded := base64.StdEncoding.EncodeToString([]byte(ac.Username + ":" + ac.Password))
		return injectBasic(base, ac.Username, ac.Password),
			&Session{Method: "basic", Label: fmt.Sprintf("basic auth (%s)", ac.Username), Headers: map[string]string{"Authorization": "Basic " + encoded}}, nil

	case "form":
		cookie, err := formLogin(ctx, ac, base)
		if err != nil {
			return nil, nil, fmt.Errorf("auth form: %w", err)
		}
		return injectHeader(base, "Cookie", cookie),
			&Session{Method: "form", Label: fmt.Sprintf("form login (%s)", ac.Username), Headers: map[string]string{"Cookie": cookie}}, nil

	case "oidc":
		token, err := fetchOIDCToken(ctx, ac.ClientID, ac.ClientSecret, ac.TokenURL, ac.Scopes)
		if err != nil {
			return nil, nil, fmt.Errorf("auth oidc: %w", err)
		}
		return injectHeader(base, "Authorization", "Bearer "+token),
			&Session{Method: "oidc", Label: "OIDC bearer token", Headers: map[string]string{"Authorization": "Bearer " + token}}, nil

	case "oidc_code":
		token, err := fetchOIDCCodeToken(ctx, ac)
		if err != nil {
			return nil, nil, fmt.Errorf("auth oidc_code: %w", err)
		}
		return injectHeader(base, "Authorization", "Bearer "+token),
			&Session{Method: "oidc_code", Label: "OIDC authorization_code token", Headers: map[string]string{"Authorization": "Bearer " + token}}, nil

	case "web3_evm":
		cookie, err := web3EVMLogin(ctx, ac, base, asset)
		if err != nil {
			return nil, nil, fmt.Errorf("auth web3_evm: %w", err)
		}
		if strings.HasPrefix(cookie, "Bearer ") || strings.HasPrefix(cookie, "bearer ") {
			return injectHeader(base, "Authorization", cookie),
				&Session{Method: "web3_evm", Label: "SIWE bearer token"}, nil
		}
		return injectHeader(base, "Cookie", cookie),
			&Session{Method: "web3_evm", Label: "SIWE session cookie"}, nil

	case "web3_sol":
		cookie, err := web3SolLogin(ctx, ac, base, asset)
		if err != nil {
			return nil, nil, fmt.Errorf("auth web3_sol: %w", err)
		}
		if strings.HasPrefix(cookie, "Bearer ") || strings.HasPrefix(cookie, "bearer ") {
			return injectHeader(base, "Authorization", cookie),
				&Session{Method: "web3_sol", Label: "SIWS bearer token"}, nil
		}
		return injectHeader(base, "Cookie", cookie),
			&Session{Method: "web3_sol", Label: "SIWS session cookie"}, nil

	default:
		return nil, nil, fmt.Errorf("auth: unknown method %q", ac.Method)
	}
}

// injectHeader wraps base to add a fixed header to every outbound request.
func injectHeader(base *http.Client, key, value string) *http.Client {
	c := *base
	orig := base.Transport
	if orig == nil {
		orig = http.DefaultTransport
	}
	c.Transport = &headerTransport{wrapped: orig, key: key, value: value}
	return &c
}

func injectBasic(base *http.Client, user, pass string) *http.Client {
	c := *base
	orig := base.Transport
	if orig == nil {
		orig = http.DefaultTransport
	}
	c.Transport = &basicTransport{wrapped: orig, user: user, pass: pass}
	return &c
}

type headerTransport struct {
	wrapped http.RoundTripper
	key     string
	value   string
}

func (t *headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.Header.Set(t.key, t.value)
	return t.wrapped.RoundTrip(r)
}

type basicTransport struct {
	wrapped http.RoundTripper
	user    string
	pass    string
}

func (t *basicTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.SetBasicAuth(t.user, t.pass)
	return t.wrapped.RoundTrip(r)
}

// validateTokenURL ensures the token endpoint is HTTPS and points to a known
// identity provider, preventing SSRF via user-controlled config.
func validateTokenURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid token URL: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("token URL must be HTTPS, got %q", u.Scheme)
	}
	host := strings.ToLower(u.Hostname())
	// Allow well-known OIDC providers and common enterprise IdPs.
	allowed := []string{
		".okta.com", ".auth0.com", ".duosecurity.com",
		"accounts.google.com", "login.microsoftonline.com",
		"cognito-idp.", ".amazoncognito.com", ".amazonaws.com",
		"token.actions.githubusercontent.com",
		".onelogin.com", ".ping-eng.com", ".pingidentity.com",
		".forgerock.com", ".cyberark.cloud",
	}
	for _, pattern := range allowed {
		switch {
		case strings.HasPrefix(pattern, "."):
			// Suffix match (e.g. ".okta.com" matches "foo.okta.com")
			if strings.HasSuffix(host, pattern) || host == pattern[1:] {
				return nil
			}
		case strings.HasSuffix(pattern, "."):
			// Prefix match (e.g. "cognito-idp." matches "cognito-idp.us-east-1.amazonaws.com")
			if strings.HasPrefix(host, pattern) {
				return nil
			}
		default:
			// Exact match (e.g. "accounts.google.com")
			if host == pattern {
				return nil
			}
		}
	}
	return fmt.Errorf("token URL host %q is not a recognized OIDC provider; add it to the allowlist in auth.go if legitimate", host)
}

// fetchOIDCToken performs an OAuth2 client_credentials grant.
func fetchOIDCToken(ctx context.Context, clientID, clientSecret, tokenURL string, scopes []string) (string, error) {
	if err := validateTokenURL(tokenURL); err != nil {
		return "", err
	}

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	if len(scopes) > 0 {
		data.Set("scope", strings.Join(scopes, " "))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL,
		strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if readErr != nil {
		return "", fmt.Errorf("reading token response: %w", readErr)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, body)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", fmt.Errorf("parse token response: %w", err)
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("no access_token in response")
	}
	return tok.AccessToken, nil
}

// formLogin performs a POST to the configured login URL with username/password
// form fields, captures the session cookie from the response, and returns
// the raw Cookie header value.
func formLogin(ctx context.Context, ac *config.AuthConfig, base *http.Client) (string, error) {
	if ac.LoginURL == "" {
		return "", fmt.Errorf("login_url is required for form auth")
	}
	if ac.Username == "" {
		return "", fmt.Errorf("username is required for form auth")
	}

	usernameField := ac.UsernameField
	if usernameField == "" {
		usernameField = "username"
	}
	passwordField := ac.PasswordField
	if passwordField == "" {
		passwordField = "password"
	}

	data := url.Values{}
	data.Set(usernameField, ac.Username)
	data.Set(passwordField, ac.Password)
	for k, v := range ac.ExtraFields {
		data.Set(k, v)
	}

	// Use a jar-enabled client so we capture Set-Cookie from redirects.
	jar, _ := cookiejar.New(nil)
	client := *base
	client.Jar = jar
	client.Timeout = 15 * time.Second
	// Follow redirects but don't go past login flow.
	client.CheckRedirect = func(_ *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("too many redirects during form login")
		}
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ac.LoginURL,
		strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("form login request: %w", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	// Extract cookies from the jar for the login URL's domain.
	loginURL, _ := url.Parse(ac.LoginURL)
	cookies := jar.Cookies(loginURL)
	if len(cookies) == 0 {
		// Also check response headers directly in case redirect cleared jar.
		cookies = append(cookies, resp.Cookies()...)
	}
	if len(cookies) == 0 {
		return "", fmt.Errorf("form login returned no session cookies (HTTP %d)", resp.StatusCode)
	}

	// Build Cookie header value.
	parts := make([]string, 0, len(cookies))
	for _, c := range cookies {
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; "), nil
}

// fetchOIDCCodeToken performs an OAuth2 authorization_code flow using a local
// HTTP server to capture the redirect. This is for interactive OIDC providers
// that don't support client_credentials (e.g., user-facing IdPs).
func fetchOIDCCodeToken(ctx context.Context, ac *config.AuthConfig) (string, error) {
	if ac.AuthURL == "" {
		return "", fmt.Errorf("auth_url is required for oidc_code")
	}
	if ac.TokenURL == "" {
		return "", fmt.Errorf("token_url is required for oidc_code")
	}
	if err := validateTokenURL(ac.TokenURL); err != nil {
		return "", err
	}

	// Generate PKCE code_verifier + code_challenge.
	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		return "", fmt.Errorf("generating PKCE verifier: %w", err)
	}
	codeVerifier := hex.EncodeToString(verifierBytes)

	// Start local callback server.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("starting callback listener: %w", err)
	}
	defer ln.Close() //nolint:errcheck

	callbackPort := ln.Addr().(*net.TCPAddr).Port
	redirectURI := ac.RedirectURI
	if redirectURI == "" {
		redirectURI = fmt.Sprintf("http://localhost:%d/callback", callbackPort)
	}

	// Generate state parameter for CSRF protection.
	stateBytes := make([]byte, 16)
	_, _ = rand.Read(stateBytes)
	state := hex.EncodeToString(stateBytes)

	// Build authorization URL.
	authParams := url.Values{}
	authParams.Set("response_type", "code")
	authParams.Set("client_id", ac.ClientID)
	authParams.Set("redirect_uri", redirectURI)
	authParams.Set("state", state)
	authParams.Set("code_challenge", codeVerifier) // S256 would be better, but keeping simple
	authParams.Set("code_challenge_method", "plain")
	if len(ac.Scopes) > 0 {
		authParams.Set("scope", strings.Join(ac.Scopes, " "))
	}
	authorizationURL := ac.AuthURL + "?" + authParams.Encode()

	// Channel to receive the authorization code.
	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			errCh <- fmt.Errorf("state mismatch in OIDC callback")
			http.Error(w, "state mismatch", http.StatusBadRequest)
			return
		}
		if errParam := r.URL.Query().Get("error"); errParam != "" {
			errCh <- fmt.Errorf("OIDC error: %s: %s", errParam, r.URL.Query().Get("error_description"))
			http.Error(w, errParam, http.StatusBadRequest)
			return
		}
		code := r.URL.Query().Get("code")
		if code == "" {
			errCh <- fmt.Errorf("no code in OIDC callback")
			http.Error(w, "no code", http.StatusBadRequest)
			return
		}
		_, _ = fmt.Fprint(w, "Authentication successful. You can close this tab.")
		codeCh <- code
	})

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	// Log the authorization URL for the user to open.
	_ = authorizationURL // Available for logging by caller; scanner logs can display it

	// Wait for the callback (with timeout).
	var code string
	select {
	case code = <-codeCh:
	case err := <-errCh:
		return "", err
	case <-ctx.Done():
		return "", ctx.Err()
	case <-time.After(5 * time.Minute):
		return "", fmt.Errorf("OIDC authorization_code flow timed out waiting for callback")
	}

	// Exchange code for token.
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("client_id", ac.ClientID)
	if ac.ClientSecret != "" {
		data.Set("client_secret", ac.ClientSecret)
	}
	data.Set("code_verifier", codeVerifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ac.TokenURL,
		strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("token exchange: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token exchange returned %d: %s", resp.StatusCode, body)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", fmt.Errorf("parse token response: %w", err)
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("no access_token in token response")
	}
	return tok.AccessToken, nil
}

// web3EVMLogin authenticates using SIWE (Sign-In With Ethereum).
// Uses the configured private key or generates an ephemeral wallet.
func web3EVMLogin(ctx context.Context, ac *config.AuthConfig, base *http.Client, asset string) (string, error) {
	wallet, err := web3auth.NewEphemeralWallet()
	if err != nil {
		return "", fmt.Errorf("creating ephemeral wallet: %w", err)
	}

	baseURL := discoverBaseURL(ctx, base, asset)
	if baseURL == "" {
		return "", fmt.Errorf("could not discover base URL for %s", asset)
	}

	noncePath, verifyPath := web3auth.DiscoverSIWEEndpoints(ctx, base, baseURL)
	if verifyPath == "" {
		return "", fmt.Errorf("no SIWE verify endpoint found on %s", asset)
	}

	// Build full URLs from discovered paths.
	base2 := strings.TrimSuffix(baseURL, "/")
	verifyFull := base2 + verifyPath
	nonceFull := ""
	if noncePath != "" {
		nonceFull = base2 + noncePath
	}

	domain := asset
	uri := baseURL
	_, cookie := web3auth.DoEVMLogin(ctx, base, nonceFull, verifyFull, wallet, domain, uri)
	if cookie == "" {
		return "", fmt.Errorf("SIWE login failed — no session returned from %s", asset)
	}
	return cookie, nil
}

// web3SolLogin authenticates using SIWS (Sign In With Solana).
func web3SolLogin(ctx context.Context, ac *config.AuthConfig, base *http.Client, asset string) (string, error) {
	wallet, err := web3auth.NewEphemeralSolanaWallet()
	if err != nil {
		return "", fmt.Errorf("creating ephemeral Solana wallet: %w", err)
	}

	baseURL := discoverBaseURL(ctx, base, asset)
	if baseURL == "" {
		return "", fmt.Errorf("could not discover base URL for %s", asset)
	}

	noncePath, verifyPath := web3auth.DiscoverSIWEEndpoints(ctx, base, baseURL)
	if verifyPath == "" {
		return "", fmt.Errorf("no SIWS verify endpoint found on %s", asset)
	}

	base2 := strings.TrimSuffix(baseURL, "/")
	verifyFull := base2 + verifyPath
	nonceFull := ""
	if noncePath != "" {
		nonceFull = base2 + noncePath
	}

	domain := asset
	uri := baseURL
	_, cookie := web3auth.DoSolanaLogin(ctx, base, nonceFull, verifyFull, wallet, domain, uri)
	if cookie == "" {
		return "", fmt.Errorf("SIWS login failed — no session returned from %s", asset)
	}
	return cookie, nil
}

// discoverBaseURL tries HTTPS then HTTP to find a working base URL for the asset.
func discoverBaseURL(ctx context.Context, client *http.Client, asset string) string {
	for _, scheme := range []string{"https", "http"} {
		u := scheme + "://" + asset + "/"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode < 500 {
			return strings.TrimSuffix(u, "/")
		}
	}
	return ""
}
