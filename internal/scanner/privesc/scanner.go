// Package privesc detects broken access control through privilege escalation
// testing. It compares what low-privilege and high-privilege (or unauthenticated
// vs authenticated) users can access, flagging endpoints that should be
// restricted but aren't.
//
// Three detection strategies:
//   - Vertical privesc: admin-only endpoints accessible to low-priv/unauth users
//   - Horizontal privesc (IDOR): user A can access user B's data via ID substitution
//   - Method bypass: restricted endpoints accessible via alternate HTTP methods
//
// ScanAuthorized only (exploitation-class testing requiring explicit authorization).
package privesc

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scan"
	"github.com/stormbane-security/beacon/internal/scanner/schemedetect"
)

func init() {
	scan.RegisterWithCheckDecls(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	},
		scan.Check(finding.CheckPrivescBrokenAccessControl, finding.SeverityCritical, finding.ModeDeep),
		scan.Check(finding.CheckPrivescHorizontalPrivesc, finding.SeverityHigh, finding.ModeDeep),
		scan.Check(finding.CheckPrivescMethodBypass, finding.SeverityHigh, finding.ModeDeep),
	)
}

const (
	scannerName = "privesc"
	maxBodySize = 64 * 1024 // 64 KB
)

// adminEndpoints are paths typically restricted to administrators.
var adminEndpoints = []string{
	"/admin",
	"/admin/",
	"/admin/dashboard",
	"/admin/settings",
	"/admin/users",
	"/dashboard",
	"/console",
	"/manage",
	"/management",
	"/settings/admin",
	"/api/admin",
	"/api/v1/admin",
	"/api/admin/users",
	"/api/v1/admin/users",
	"/api/admin/settings",
	"/internal",
	"/internal/metrics",
	"/panel",
}

// idorEndpoints are API paths with sequential numeric IDs for horizontal
// privilege testing. Each entry has a format string with %s for the ID.
var idorEndpoints = []string{
	"/api/users/%s",
	"/api/v1/users/%s",
	"/api/accounts/%s",
	"/api/v1/accounts/%s",
	"/api/orders/%s",
	"/api/v1/orders/%s",
	"/api/profiles/%s",
	"/api/v1/profiles/%s",
}

// methodBypassMethods are HTTP methods tested when GET returns 403.
var methodBypassMethods = []string{
	http.MethodPost,
	http.MethodPut,
	http.MethodDelete,
	http.MethodPatch,
}

// Scanner detects privilege escalation via access control comparison.
type Scanner struct{}

// New returns a new Scanner.
func New() *Scanner { return &Scanner{} }

// Name returns the stable scanner identifier.
func (s *Scanner) Name() string { return scannerName }

// Run executes the privilege escalation scan. Only runs in authorized mode.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanAuthorized {
		return nil, nil
	}

	client := newClient()
	base := schemedetect.Base(ctx, client, asset)

	var findings []finding.Finding

	// Strategy 1: Vertical privilege escalation — probe admin endpoints
	// without authentication. If the endpoint returns 200 with meaningful
	// content, access control is broken.
	findings = append(findings, s.testVerticalPrivesc(ctx, client, base, asset)...)

	// Strategy 2: Method bypass — for admin endpoints that return 403 on
	// GET, try POST/PUT/DELETE/PATCH.
	findings = append(findings, s.testMethodBypass(ctx, client, base, asset)...)

	// Strategy 3: Horizontal privilege escalation — probe user-scoped
	// endpoints with adjacent IDs.
	findings = append(findings, s.testHorizontalPrivesc(ctx, client, base, asset)...)

	return findings, nil
}

// testVerticalPrivesc probes admin-only endpoints without authentication and
// flags any that return HTTP 200 with substantive content.
func (s *Scanner) testVerticalPrivesc(ctx context.Context, client *http.Client, base, asset string) []finding.Finding {
	var findings []finding.Finding

	for _, path := range adminEndpoints {
		if ctx.Err() != nil {
			break
		}

		u := base + path
		status, body := doRequest(ctx, client, http.MethodGet, u)

		if status == http.StatusOK && len(body) > 0 && looksLikeAdminContent(body) {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckPrivescBrokenAccessControl,
				Module:   "authorized",
				Scanner:  scannerName,
				Severity: finding.SeverityCritical,
				Title:    fmt.Sprintf("Broken access control: admin endpoint %s accessible without authentication on %s", path, asset),
				Description: fmt.Sprintf(
					"The admin endpoint %s on %s returned HTTP 200 with admin page content "+
						"when accessed without authentication. An unprivileged user or "+
						"unauthenticated attacker can access administrative functionality.",
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
					"body_hash":   hashBody(body),
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings
}

// testMethodBypass probes admin endpoints that return 403 on GET with
// alternate HTTP methods to detect method-based access control bypass.
func (s *Scanner) testMethodBypass(ctx context.Context, client *http.Client, base, asset string) []finding.Finding {
	var findings []finding.Finding

	for _, path := range adminEndpoints {
		if ctx.Err() != nil {
			break
		}

		u := base + path
		getStatus, _ := doRequest(ctx, client, http.MethodGet, u)

		// Only test method bypass if GET is explicitly forbidden.
		if getStatus != http.StatusForbidden {
			continue
		}

		for _, method := range methodBypassMethods {
			if ctx.Err() != nil {
				break
			}

			bypassStatus, bypassBody := doRequest(ctx, client, method, u)
			if bypassStatus == http.StatusOK && len(bypassBody) > 0 {
				findings = append(findings, finding.Finding{
					CheckID:  finding.CheckPrivescMethodBypass,
					Module:   "authorized",
					Scanner:  scannerName,
					Severity: finding.SeverityHigh,
					Title:    fmt.Sprintf("Method bypass: %s returns 200 on %s%s (GET returns 403)", method, asset, path),
					Description: fmt.Sprintf(
						"The admin endpoint %s on %s returned HTTP 403 for GET but HTTP %d for %s. "+
							"The access control check only applies to GET requests, allowing "+
							"an attacker to bypass authorization using an alternate HTTP method.",
						path, asset, bypassStatus, method),
					Asset:    asset,
					DeepOnly: true,
					ProofCommand: fmt.Sprintf(
						`curl -sk -X %s '%s%s'`, method, base, path),
					Evidence: map[string]any{
						"url":           u,
						"path":          path,
						"get_status":    getStatus,
						"bypass_method": method,
						"bypass_status": bypassStatus,
						"body_length":   len(bypassBody),
					},
					DiscoveredAt: time.Now(),
				})
				// One method bypass finding per path is sufficient.
				break
			}
		}
	}

	return findings
}

// testHorizontalPrivesc probes user-scoped API endpoints with adjacent
// numeric IDs. If two different IDs return 200 with different content,
// the endpoint lacks per-object authorization.
func (s *Scanner) testHorizontalPrivesc(ctx context.Context, client *http.Client, base, asset string) []finding.Finding {
	var findings []finding.Finding

	seedIDs := []string{"1", "2", "100"}

	for _, epFmt := range idorEndpoints {
		if ctx.Err() != nil {
			break
		}

		for _, seedID := range seedIDs {
			if ctx.Err() != nil {
				break
			}

			path := fmt.Sprintf(epFmt, seedID)
			u := base + path
			status, body := doRequest(ctx, client, http.MethodGet, u)
			if status != http.StatusOK || len(body) == 0 {
				continue
			}

			// Try adjacent ID.
			adjID := adjacentID(seedID)
			adjPath := fmt.Sprintf(epFmt, adjID)
			adjURL := base + adjPath
			adjStatus, adjBody := doRequest(ctx, client, http.MethodGet, adjURL)

			if adjStatus != http.StatusOK || len(adjBody) == 0 {
				continue
			}

			// Both returned 200 — different content means different
			// user's data was returned (not a generic response).
			if adjBody == body {
				continue
			}

			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckPrivescHorizontalPrivesc,
				Module:   "authorized",
				Scanner:  scannerName,
				Severity: finding.SeverityHigh,
				Title:    fmt.Sprintf("Horizontal privesc: IDOR on %s%s", asset, fmt.Sprintf(epFmt, "{id}")),
				Description: fmt.Sprintf(
					"The endpoint %s on %s returns different user data for IDs %s and %s "+
						"without authorization differentiation. An attacker can access other "+
						"users' data by manipulating the ID parameter.",
					fmt.Sprintf(epFmt, "{id}"), asset, seedID, adjID),
				Asset:    asset,
				DeepOnly: true,
				ProofCommand: fmt.Sprintf(
					`curl -sk '%s' && echo '---' && curl -sk '%s'`, u, adjURL),
				Evidence: map[string]any{
					"endpoint":        fmt.Sprintf(epFmt, "{id}"),
					"seed_id":         seedID,
					"adjacent_id":     adjID,
					"seed_status":     status,
					"adjacent_status": adjStatus,
					"seed_body_len":   len(body),
					"adj_body_len":    len(adjBody),
				},
				DiscoveredAt: time.Now(),
			})

			// One finding per endpoint pattern is sufficient.
			goto nextEndpoint
		}
	nextEndpoint:
	}

	return findings
}

// newClient creates an HTTP client with TLS verification disabled and
// redirect following disabled (to see raw responses).
func newClient() *http.Client {
	return &http.Client{
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
}

// doRequest performs an HTTP request and returns the status code and body.
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
	_ = resp.Body.Close()

	return resp.StatusCode, string(body)
}

// hashBody returns a hex-encoded SHA-256 hash of the response body.
func hashBody(body string) string {
	h := sha256.Sum256([]byte(body))
	return fmt.Sprintf("%x", h[:8])
}

// looksLikeAdminContent returns true if the body contains signals typical
// of an admin interface or privileged API response.
func looksLikeAdminContent(body string) bool {
	lower := strings.ToLower(body)
	signals := []string{
		"admin", "dashboard", "management", "settings",
		"configuration", "users", "system", "control panel",
		"privileges", "permissions",
	}
	matches := 0
	for _, sig := range signals {
		if strings.Contains(lower, sig) {
			matches++
		}
	}
	return matches >= 2
}

// adjacentID returns the next numeric ID for horizontal privesc testing.
func adjacentID(id string) string {
	var n int
	if _, err := fmt.Sscanf(id, "%d", &n); err != nil {
		return "2"
	}
	return fmt.Sprintf("%d", n+1)
}

// idPattern matches numeric IDs in URL paths (for future use with crawled endpoints).
var idPattern = regexp.MustCompile(`/\d+(/|$)`)

// ContainsNumericID returns true if the path contains a numeric ID segment.
func ContainsNumericID(path string) bool {
	return idPattern.MatchString(path)
}
