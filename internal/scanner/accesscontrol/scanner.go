// Package accesscontrol probes for broken access control vulnerabilities by
// testing admin paths without authentication, HTTP method bypass, and path
// traversal bypass techniques. These tests target authorization enforcement
// gaps that allow vertical privilege escalation.
//
// ScanDeep and ScanAuthorized only (active probing of admin endpoints).
package accesscontrol

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/scan"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanner/schemedetect"
)


func init() {
	scan.Register(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	})
}
const (
	scannerName = "accesscontrol"
	maxBodySize = 32 * 1024 // 32 KB
)

// adminPaths are paths typically restricted to administrators.
var adminPaths = []string{
	"/admin",
	"/admin/",
	"/dashboard",
	"/console",
	"/manage",
	"/settings/admin",
	"/administration",
	"/admin/dashboard",
	"/admin/settings",
	"/panel",
	"/cpanel",
	"/management",
	"/internal",
	"/api/admin",
	"/api/v1/admin",
}

// methodBypassMethods are HTTP methods tested when GET returns 403.
var methodBypassMethods = []string{
	http.MethodPost,
	http.MethodPut,
	http.MethodPatch,
	http.MethodOptions,
}

// pathTraversalVariants generates path manipulation variants that may bypass
// path-based authorization middleware.
func pathTraversalVariants(path string) []struct {
	url  string
	desc string
} {
	return []struct {
		url  string
		desc string
	}{
		{url: path + "/../" + lastSegment(path), desc: "dot-dot-slash normalization"},
		{url: "/;" + path, desc: "semicolon path parameter prefix"},
		{url: "/%2e" + path, desc: "URL-encoded dot prefix"},
		{url: path + "/.", desc: "trailing dot"},
		{url: path + "%00", desc: "null byte truncation"},
		{url: path + "%20", desc: "trailing space"},
		{url: strings.ToUpper(path), desc: "case variation"},
	}
}

// Scanner probes for broken access control vulnerabilities.
type Scanner struct{}

// New returns a new Scanner.
func New() *Scanner { return &Scanner{} }

// Name returns the stable scanner identifier.
func (s *Scanner) Name() string { return scannerName }

// Run executes the access control scan. Only runs in deep or authorized mode.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanDeep && scanType != module.ScanAuthorized {
		return nil, nil
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec
			},
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	base := schemedetect.Base(ctx, client, asset)

	var findings []finding.Finding

	for _, path := range adminPaths {
		if ctx.Err() != nil {
			break
		}

		// ── Check 1: Direct unauthenticated access to admin path ──
		u := base + path
		status, body := doRequest(ctx, client, http.MethodGet, u)

		if status == http.StatusOK && looksLikeAdminPage(body) {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckAccessControlVerticalEscalation,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityCritical,
				Title:    fmt.Sprintf("Unauthenticated admin access: %s on %s", path, asset),
				Description: fmt.Sprintf(
					"The admin path %s on %s returned HTTP 200 with admin page content "+
						"without any authentication. An attacker can access administrative "+
						"functionality directly.",
					path, asset),
				Asset:    asset,
				DeepOnly: true,
				ProofCommand: fmt.Sprintf(
					`curl -sk '%s%s'`, base, path),
				Evidence: map[string]any{
					"url":         u,
					"path":        path,
					"status_code": status,
					"body_length": len(body),
				},
				DiscoveredAt: time.Now(),
			})
			continue
		}

		// ── Check 2: HTTP method bypass ──
		// Only test method bypass if GET returned 403 (auth is enforced on GET).
		if status == http.StatusForbidden {
			for _, method := range methodBypassMethods {
				if ctx.Err() != nil {
					break
				}

				bypassStatus, bypassBody := doRequest(ctx, client, method, u)
				if bypassStatus == http.StatusOK && len(bypassBody) > 0 &&
					bypassStatus != status {
					findings = append(findings, finding.Finding{
						CheckID:  finding.CheckAccessControlMethodBypass,
						Module:   "deep",
						Scanner:  scannerName,
						Severity: finding.SeverityHigh,
						Title:    fmt.Sprintf("Access control bypass via %s on %s%s", method, asset, path),
						Description: fmt.Sprintf(
							"The admin path %s on %s returned HTTP 403 for GET but HTTP %d for %s, "+
								"indicating the authorization check only applies to GET requests. "+
								"An attacker can bypass access control by using an alternate HTTP method.",
							path, asset, bypassStatus, method),
						Asset:    asset,
						DeepOnly: true,
						ProofCommand: fmt.Sprintf(
							`curl -sk -X %s '%s%s'`, method, base, path),
						Evidence: map[string]any{
							"url":            u,
							"path":           path,
							"get_status":     status,
							"bypass_method":  method,
							"bypass_status":  bypassStatus,
							"body_length":    len(bypassBody),
						},
						DiscoveredAt: time.Now(),
					})
					// One method bypass per path is enough.
					break
				}
			}
		}

		// ── Check 3: Path traversal bypass ──
		// Only test if GET returned 403 or 401 (there is auth to bypass).
		if status == http.StatusForbidden || status == http.StatusUnauthorized {
			for _, variant := range pathTraversalVariants(path) {
				if ctx.Err() != nil {
					break
				}

				variantURL := base + variant.url
				variantStatus, variantBody := doRequest(ctx, client, http.MethodGet, variantURL)

				if variantStatus == http.StatusOK && len(variantBody) > 0 &&
					variantBody != body {
					findings = append(findings, finding.Finding{
						CheckID:  finding.CheckAccessControlPathTraversalBypass,
						Module:   "deep",
						Scanner:  scannerName,
						Severity: finding.SeverityHigh,
						Title:    fmt.Sprintf("Access control bypass via path traversal (%s) on %s", variant.desc, asset),
						Description: fmt.Sprintf(
							"The admin path %s on %s returned HTTP %d, but the path variant %q "+
								"(%s) returned HTTP %d with different content. The authorization "+
								"middleware can be bypassed through path manipulation.",
							path, asset, status, variant.url, variant.desc, variantStatus),
						Asset:    asset,
						DeepOnly: true,
						ProofCommand: fmt.Sprintf(
							`curl -sk '%s%s'`, base, variant.url),
						Evidence: map[string]any{
							"url":              variantURL,
							"original_path":    path,
							"original_status":  status,
							"variant_path":     variant.url,
							"variant_desc":     variant.desc,
							"variant_status":   variantStatus,
							"variant_body_len": len(variantBody),
						},
						DiscoveredAt: time.Now(),
					})
					// One path traversal bypass per path is enough.
					break
				}
			}
		}
	}

	return findings, nil
}

// doRequest performs an HTTP request with the given method and URL, returning
// the status code and response body as a string.
func doRequest(ctx context.Context, client *http.Client, method, rawURL string) (int, string) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
	if err != nil {
		return 0, ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return 0, ""
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	resp.Body.Close()

	return resp.StatusCode, string(body)
}

// looksLikeAdminPage returns true if the response body contains signals
// typical of an admin interface (not just a redirect page or error message).
func looksLikeAdminPage(body string) bool {
	lower := strings.ToLower(body)
	signals := []string{
		"admin", "dashboard", "management", "settings",
		"configuration", "users", "system", "control panel",
	}
	matches := 0
	for _, sig := range signals {
		if strings.Contains(lower, sig) {
			matches++
		}
	}
	// Require at least 2 signals to avoid false positives on generic pages
	// that mention "admin" in passing.
	return matches >= 2
}

// lastSegment returns the last path segment from a URL path.
func lastSegment(path string) string {
	path = strings.TrimSuffix(path, "/")
	idx := strings.LastIndex(path, "/")
	if idx < 0 {
		return path
	}
	return path[idx+1:]
}
