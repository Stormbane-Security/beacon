// Package verbtamper detects authentication bypass via HTTP method (verb) switching.
//
// Many web applications enforce access control only on specific HTTP methods.
// An endpoint that returns 403 on GET may accept POST, PUT, PATCH, or DELETE
// without authentication — a common access control flaw (OWASP A01:2025).
//
// Deep mode only — sends requests with alternate HTTP methods.
package verbtamper

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/stormbane-security/beacon/internal/scan"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanner/authctx"
	"github.com/stormbane-security/beacon/internal/scanner/schemedetect"
)


func init() {
	scan.Register(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	})
}
const scannerName = "verbtamper"

// targetPaths are common protected paths to test.
var targetPaths = []string{
	"/admin",
	"/admin/",
	"/api/admin",
	"/api/v1/admin",
	"/dashboard",
	"/manage",
	"/management",
	"/internal",
	"/config",
	"/settings",
	"/api/users",
	"/api/v1/users",
}

// alternateMethods to try when GET returns 401/403.
var alternateMethods = []string{
	http.MethodPost,
	http.MethodPut,
	http.MethodPatch,
	http.MethodDelete,
	http.MethodHead,
	http.MethodOptions,
}

type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanDeep && scanType != module.ScanAuthorized {
		return nil, nil
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if c := authctx.HTTPClient(ctx); c != nil {
		client = c
	}

	base := schemedetect.Base(ctx, client, asset)
	var findings []finding.Finding

	for _, path := range targetPaths {
		if ctx.Err() != nil {
			break
		}

		url := base + path

		// Step 1: GET request — look for 401/403 (authentication/authorization wall).
		getReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		getReq.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner)")
		getResp, err := client.Do(getReq)
		if err != nil {
			continue
		}
		io.Copy(io.Discard, getResp.Body)
		getResp.Body.Close()

		// Only test paths that are explicitly blocked (not 404).
		if getResp.StatusCode != 401 && getResp.StatusCode != 403 {
			continue
		}

		// Step 2: Try alternate methods. If any returns 2xx, it's a bypass.
		for _, method := range alternateMethods {
			if ctx.Err() != nil {
				break
			}

			req, err := http.NewRequestWithContext(ctx, method, url, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner)")

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()

			// 2xx response on an alternate method when GET was 401/403 = bypass.
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				findings = append(findings, finding.Finding{
					CheckID:  finding.CheckWebVerbTamperAuthBypass,
					Module:   "deep",
					Scanner:  scannerName,
					Severity: finding.SeverityHigh,
					Title: fmt.Sprintf("Auth bypass via HTTP %s on %s (GET returns %d)",
						method, path, getResp.StatusCode),
					Description: fmt.Sprintf(
						"The endpoint %s returns %d for GET requests but accepts %s "+
							"with a %d response. This indicates the access control middleware only "+
							"enforces authentication/authorization on specific HTTP methods. An "+
							"attacker can bypass the auth wall by switching the request method.",
						url, getResp.StatusCode, method, resp.StatusCode),
					Asset: asset,
					ProofCommand: fmt.Sprintf(
						"curl -s -o /dev/null -w '%%{http_code}' -X %s '%s'", method, url),
					Evidence: map[string]any{
						"url":             url,
						"get_status":      getResp.StatusCode,
						"bypass_method":   method,
						"bypass_status":   resp.StatusCode,
						"body_snippet":    string(body[:min(len(body), 200)]),
					},
					DiscoveredAt: time.Now(),
				})
				break // one bypass per path is enough
			}
		}
	}

	return findings, nil
}
