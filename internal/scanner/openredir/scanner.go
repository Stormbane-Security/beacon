// Package openredir implements a deep-mode scanner for open redirect
// vulnerabilities. It discovers redirect-capable parameters by probing common
// parameter names with an external canary domain, then verifies that the
// server actually redirects (3xx with Location header pointing to the canary).
//
// Open redirects enable phishing (victim clicks a trusted-domain link that
// lands on evil.com), OAuth token theft (redirect_uri → attacker), and SSRF
// chains (internal redirect to cloud metadata).
package openredir

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/scan"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)


func init() {
	scan.Register(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	})
}
const (
	scannerName = "openredir"
	canaryDomain = "evil.example.com"
)

// redirectParams are common parameter names that applications use for
// post-action redirects. Ordered by prevalence.
var redirectParams = []string{
	"url",
	"redirect",
	"redirect_url",
	"redirect_uri",
	"return",
	"return_url",
	"returnUrl",
	"returnTo",
	"return_to",
	"next",
	"next_url",
	"dest",
	"destination",
	"target",
	"target_url",
	"rurl",
	"goto",
	"go",
	"out",
	"view",
	"continue",
	"forward",
	"ref",
	"site",
	"to",
	"callback",
	"callback_url",
	"redir",
	"r",
}

// payloads are URL-shaped values that test different redirect bypass techniques.
// Each targets the canary domain using a different encoding or URL scheme trick.
var payloads = []struct {
	value string
	label string
}{
	{"https://" + canaryDomain, "absolute URL"},
	{"//" + canaryDomain, "protocol-relative URL"},
	{"https://" + canaryDomain + "/%2f..", "path-traversal bypass"},
	{"///" + canaryDomain, "triple-slash bypass"},
	{"/\\" + canaryDomain, "backslash bypass"},
	{"https://" + canaryDomain + "@legitimate.com", "at-sign bypass"},
}

// Scanner checks for open redirect vulnerabilities.
type Scanner struct{}

// New returns a new Scanner.
func New() *Scanner { return &Scanner{} }

// Name returns the stable scanner identifier.
func (s *Scanner) Name() string { return scannerName }

// Run executes the open redirect scan. Only runs in deep or authorized mode.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanDeep && scanType != module.ScanAuthorized {
		return nil, nil
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	scheme := detectScheme(ctx, client, asset)
	if scheme == "" {
		return nil, nil
	}

	var findings []finding.Finding
	seen := map[string]bool{} // deduplicate by param name

	for _, param := range redirectParams {
		if seen[param] {
			continue
		}
		for _, payload := range payloads {
			if ctx.Err() != nil {
				return findings, nil
			}

			targetURL := fmt.Sprintf("%s://%s/?%s=%s", scheme, asset, param, url.QueryEscape(payload.value))
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
			if err != nil {
				continue
			}

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			io.Copy(io.Discard, resp.Body) //nolint:errcheck
			resp.Body.Close()

			if !isRedirect(resp.StatusCode) {
				continue
			}

			location := resp.Header.Get("Location")
			if location == "" {
				continue
			}

			if redirectsToCanary(location) {
				seen[param] = true
				findings = append(findings, finding.Finding{
					CheckID:     finding.CheckWebOpenRedirect,
					Module:      "deep",
					Scanner:     scannerName,
					Severity:    finding.SeverityMedium,
					Title:       fmt.Sprintf("Open redirect via ?%s= parameter (%s)", param, payload.label),
					Description: fmt.Sprintf(
						"The parameter %q accepts an external URL and the server responds with a "+
							"3xx redirect to that URL. An attacker can craft a link on the trusted "+
							"domain %s that redirects victims to a phishing site. This also enables "+
							"OAuth token theft if the redirect endpoint is used in an authorization flow, "+
							"and SSRF escalation if internal services follow redirects.",
						param, asset,
					),
					Asset:    asset,
					DeepOnly: true,
					Evidence: map[string]any{
						"parameter":    param,
						"payload":      payload.value,
						"bypass_type":  payload.label,
						"redirect_url": location,
						"status_code":  resp.StatusCode,
						"url":          targetURL,
					},
					ProofCommand: fmt.Sprintf("curl -sI '%s://%s/?%s=%s' | grep -i location",
						scheme, asset, param, url.QueryEscape(payload.value)),
					DiscoveredAt: time.Now(),
				})
				break // found redirect for this param, try next param
			}
		}
	}

	return findings, nil
}

// detectScheme determines whether the asset responds on HTTPS or HTTP.
func detectScheme(ctx context.Context, client *http.Client, asset string) string {
	for _, s := range []string{"https", "http"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, s+"://"+asset+"/", nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		resp.Body.Close()
		return s
	}
	return ""
}

// isRedirect returns true for 3xx status codes.
func isRedirect(status int) bool {
	return status >= 300 && status < 400
}

// redirectsToCanary returns true if the Location header value points to the
// canary domain. Handles both absolute URLs and protocol-relative URLs.
func redirectsToCanary(location string) bool {
	loc := strings.ToLower(location)
	// Absolute URL
	if strings.Contains(loc, canaryDomain) {
		return true
	}
	// Parse and check host
	parsed, err := url.Parse(location)
	if err == nil && strings.Contains(strings.ToLower(parsed.Host), canaryDomain) {
		return true
	}
	return false
}
