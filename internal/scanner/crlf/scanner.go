// Package crlf probes for HTTP response splitting via CRLF injection in
// redirect parameters. Some applications copy a redirect parameter value
// directly into a Location (or other) response header without stripping
// carriage-return or line-feed characters, allowing an attacker to inject
// arbitrary headers into the response.
//
// Deep mode only (active payloads).
package crlf

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const (
	scannerName    = "crlf"
	injectedHeader = "X-CRLF-Injected"
	injectedValue  = "beacon"
	maxBodySize    = 4 * 1024 // 4 KB
)

// redirectParams are the query parameter names commonly used for redirects.
var redirectParams = []string{
	"url", "redirect", "next", "return", "returnUrl",
	"redirect_uri", "callback", "continue", "dest", "target",
}

// probePaths are the URL paths most likely to accept redirect parameters.
var probePaths = []string{
	"/",
	"/login",
	"/logout",
	"/auth",
	"/api/redirect",
	"/oauth/callback",
}

// injectionSuffixes are the CRLF-encoded suffixes appended to the redirect
// value. We try both CRLF and LF-only variants.
var injectionSuffixes = []struct {
	encoded string // percent-encoded sequence
	label   string // human label
}{
	{encoded: "%0d%0a" + injectedHeader + ":" + injectedValue, label: "CRLF"},
	{encoded: "%0a" + injectedHeader + ":" + injectedValue, label: "LF"},
}

// Scanner probes for CRLF injection in HTTP redirect parameters.
type Scanner struct{}

// New returns a new Scanner.
func New() *Scanner { return &Scanner{} }

// Name returns the stable scanner identifier.
func (s *Scanner) Name() string { return scannerName }

// Run executes the CRLF injection scan. Only runs in deep mode.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanDeep {
		return nil, nil
	}

	// Do not follow redirects — we need to inspect raw response headers.
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	scheme := detectScheme(ctx, client, asset)
	base := scheme + "://" + asset

	var findings []finding.Finding

	for _, path := range probePaths {
		for _, param := range redirectParams {
			for _, suffix := range injectionSuffixes {
				// Build URL with injected CRLF sequence.
				// We do NOT use url.Values because that would double-encode the %.
				rawURL := fmt.Sprintf("%s%s?%s=https://beacon-test.invalid%s",
					base, path, param, suffix.encoded)

				req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
				if err != nil {
					continue
				}

				resp, err := client.Do(req)
				if err != nil {
					if resp != nil {
						resp.Body.Close()
					}
					continue
				}
				// Drain and discard body.
				io.Copy(io.Discard, io.LimitReader(resp.Body, maxBodySize)) //nolint:errcheck
				resp.Body.Close()

				// Check whether the injected header appears in the response.
				if resp.Header.Get(injectedHeader) == injectedValue {
					findings = append(findings, finding.Finding{
						CheckID:  finding.CheckWebCRLFInjection,
						Module:   "deep",
						Scanner:  scannerName,
						Severity: finding.SeverityHigh,
						Title: fmt.Sprintf(
							"CRLF Injection via %q parameter on %s (%s variant)",
							param, path, suffix.label),
						Description: fmt.Sprintf(
							"The parameter %q on path %s does not strip carriage-return or "+
								"line-feed characters before including the value in an HTTP response "+
								"header. An attacker can inject arbitrary response headers, enabling "+
								"HTTP response splitting, cache poisoning, and cross-site scripting "+
								"by setting a crafted Set-Cookie or Content-Type header.",
							param, path),
						Asset:    asset,
						DeepOnly: true,
						ProofCommand: fmt.Sprintf(
							`curl -si "https://%s/?redirect=https://example.com%%0d%%0aX-Injected:beacon" | grep X-Injected`,
							asset),
						Evidence: map[string]any{
							"url":              rawURL,
							"path":             path,
							"param":            param,
							"injection_variant": suffix.label,
							"injected_header":  injectedHeader + ": " + injectedValue,
						},
						DiscoveredAt: time.Now(),
					})
					// One finding per path+param is sufficient.
					goto nextParam
				}
			}
		nextParam:
		}
	}

	return findings, nil
}

// detectScheme tries HTTPS first, falling back to HTTP.
func detectScheme(ctx context.Context, client *http.Client, asset string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+asset, nil)
	if err != nil {
		return "http"
	}
	resp, err := client.Do(req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return "http"
	}
	resp.Body.Close()
	return "https"
}
