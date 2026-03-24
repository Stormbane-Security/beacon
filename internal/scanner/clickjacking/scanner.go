// Package clickjacking detects missing clickjacking protections.
// It checks for X-Frame-Options and CSP frame-ancestors directives,
// which prevent the page from being embedded in an iframe on an attacker's site.
// This is a surface-mode check — no payloads, just header inspection.
package clickjacking

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const scannerName = "clickjacking"

// Scanner checks for missing iframe embedding protections.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, _ module.ScanType) ([]finding.Finding, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Try HTTPS first, fall back to HTTP.
	var resp *http.Response
	var scheme string
	for _, sc := range []string{"https", "http"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, sc+"://"+asset, nil)
		if err != nil {
			continue
		}
		r, err := client.Do(req)
		if err != nil {
			if r != nil {
				r.Body.Close()
			}
			continue
		}
		resp = r
		scheme = sc
		break
	}
	if resp == nil {
		return nil, nil
	}
	defer resp.Body.Close()

	// Only check pages that return an HTML response — non-HTML assets
	// (APIs, images, fonts) are not framed and don't need these headers.
	ct := resp.Header.Get("Content-Type")
	if ct != "" && !strings.Contains(ct, "text/html") {
		return nil, nil
	}

	xfo := resp.Header.Get("X-Frame-Options")
	csp := resp.Header.Get("Content-Security-Policy")

	// A CSP with frame-ancestors supersedes X-Frame-Options in modern browsers.
	hasFrameAncestors := strings.Contains(strings.ToLower(csp), "frame-ancestors")
	hasXFO := xfo != ""

	if hasFrameAncestors || hasXFO {
		return nil, nil
	}

	url := scheme + "://" + asset
	return []finding.Finding{{
		CheckID:     "http.clickjacking",
		Module:      "surface",
		Scanner:     scannerName,
		Severity:    finding.SeverityMedium,
		Title:       "Clickjacking protection missing",
		Description: "The page does not set X-Frame-Options or a Content-Security-Policy frame-ancestors directive. An attacker can embed this page in an invisible iframe and trick users into clicking UI elements they cannot see (UI redressing / clickjacking).",
		Asset:        asset,
		ProofCommand: `curl -sI ` + url + ` | grep -i 'x-frame-options\|content-security-policy'`,
		Evidence: map[string]any{
			"url":                 url,
			"x_frame_options":     xfo,
			"csp_frame_ancestors": hasFrameAncestors,
		},
	}}, nil
}
