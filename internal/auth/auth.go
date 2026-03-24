// Package auth provides pre-scan authentication for beacon's authenticated scanning mode.
// Given an AuthConfig and a target asset, it performs the appropriate login flow
// and returns a wrapped *http.Client that injects the resulting credential into
// every request.
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/config"
)

// Session holds the result of a pre-scan login.
type Session struct {
	// Method describes how the credential is injected.
	Method string
	// Label is a human-readable description (e.g. "bearer token", "SIWE session cookie").
	Label string
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
			&Session{Method: "bearer", Label: "bearer token"}, nil

	case "api_key":
		header := ac.Header
		if header == "" {
			header = "X-API-Key"
		}
		return injectHeader(base, header, ac.Token),
			&Session{Method: "api_key", Label: fmt.Sprintf("%s header", header)}, nil

	case "cookie":
		return injectHeader(base, "Cookie", ac.Cookie),
			&Session{Method: "cookie", Label: "session cookie"}, nil

	case "basic":
		return injectBasic(base, ac.Username, ac.Password),
			&Session{Method: "basic", Label: fmt.Sprintf("basic auth (%s)", ac.Username)}, nil

	case "oidc":
		token, err := fetchOIDCToken(ctx, ac.ClientID, ac.ClientSecret, ac.TokenURL, ac.Scopes)
		if err != nil {
			return nil, nil, fmt.Errorf("auth oidc: %w", err)
		}
		return injectHeader(base, "Authorization", "Bearer "+token),
			&Session{Method: "oidc", Label: "OIDC bearer token"}, nil

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

// fetchOIDCToken performs an OAuth2 client_credentials grant.
func fetchOIDCToken(ctx context.Context, clientID, clientSecret, tokenURL string, scopes []string) (string, error) {
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
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
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
