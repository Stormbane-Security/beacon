// Package idor probes for Insecure Direct Object References (IDOR) and
// Broken Object-Level Authorization (BOLA) by manipulating sequential numeric
// IDs in API endpoint paths. When an adjacent ID returns a different resource
// with HTTP 200, the endpoint likely lacks per-object authorization checks.
//
// ScanDeep and ScanAuthorized only (active probing of API endpoints).
package idor

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
	scannerName = "idor"
	maxBodySize = 64 * 1024 // 64 KB
)

// apiPrefixes are common REST API path prefixes to probe for resources with
// sequential numeric IDs.
var apiPrefixes = []string{
	"/api/users/",
	"/api/v1/users/",
	"/api/v2/users/",
	"/api/orders/",
	"/api/v1/orders/",
	"/api/accounts/",
	"/api/v1/accounts/",
	"/api/invoices/",
	"/api/v1/invoices/",
	"/api/profiles/",
	"/api/v1/profiles/",
	"/api/documents/",
	"/api/v1/documents/",
	"/api/items/",
	"/api/v1/items/",
	"/api/messages/",
	"/api/v1/messages/",
	"/api/tickets/",
	"/api/v1/tickets/",
}

// seedIDs are the initial numeric IDs to probe. For each, we also check ID+1
// and ID-1 to detect sequential access.
var seedIDs = []string{"1", "2", "100", "1000"}

// Scanner probes for IDOR/BOLA vulnerabilities via sequential ID manipulation.
type Scanner struct{}

// New returns a new Scanner.
func New() *Scanner { return &Scanner{} }

// Name returns the stable scanner identifier.
func (s *Scanner) Name() string { return scannerName }

// Run executes the IDOR scan. Only runs in deep or authorized mode.
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

	for _, prefix := range apiPrefixes {
		if ctx.Err() != nil {
			break
		}

		for _, seedID := range seedIDs {
			if ctx.Err() != nil {
				break
			}

			seedURL := base + prefix + seedID
			seedStatus, seedBody := fetch(ctx, client, seedURL)
			if seedStatus != http.StatusOK || len(seedBody) == 0 {
				continue
			}

			// Probe adjacent IDs to detect sequential access.
			adjacentIDs := adjacentNumericIDs(seedID)
			for _, adjID := range adjacentIDs {
				adjURL := base + prefix + adjID
				adjStatus, adjBody := fetch(ctx, client, adjURL)
				if adjStatus != http.StatusOK || len(adjBody) == 0 {
					continue
				}

				// Both returned 200 — check that the content differs,
				// indicating a different resource was returned (not a
				// generic response or error page).
				if adjBody == seedBody {
					continue
				}

				// Sequential IDOR confirmed: different content returned for
				// adjacent ID without any auth differentiation.
				findings = append(findings, finding.Finding{
					CheckID:  finding.CheckIDORSequentialID,
					Module:   "deep",
					Scanner:  scannerName,
					Severity: finding.SeverityHigh,
					Title:    fmt.Sprintf("IDOR: sequential ID enumeration on %s%s", asset, prefix),
					Description: fmt.Sprintf(
						"The endpoint %s%s returns different resources for adjacent numeric IDs "+
							"(%s vs %s) with HTTP 200, indicating the server does not enforce "+
							"per-object authorization. An attacker can enumerate all resources by "+
							"iterating through sequential IDs.",
						asset, prefix, seedID, adjID),
					Asset:    asset,
					DeepOnly: true,
					ProofCommand: fmt.Sprintf(
						`curl -sk '%s%s%s' && echo '---' && curl -sk '%s%s%s'`,
						base, prefix, seedID, base, prefix, adjID),
					Evidence: map[string]any{
						"endpoint":         prefix,
						"seed_id":          seedID,
						"adjacent_id":      adjID,
						"seed_status":      seedStatus,
						"adjacent_status":  adjStatus,
						"seed_body_len":    len(seedBody),
						"adjacent_body_len": len(adjBody),
					},
					DiscoveredAt: time.Now(),
				})

				// One finding per prefix is sufficient.
				goto nextPrefix
			}
		}
	nextPrefix:
	}

	// BOLA horizontal access check: probe whether accessing a resource
	// with a different user context returns another user's data. We simulate
	// this by checking if common user-scoped endpoints return data without
	// any session cookie or auth header (zero-auth access).
	bolaEndpoints := []string{
		"/api/me",
		"/api/v1/me",
		"/api/user",
		"/api/v1/user",
		"/api/profile",
		"/api/v1/profile",
		"/api/account",
		"/api/v1/account",
	}

	for _, ep := range bolaEndpoints {
		if ctx.Err() != nil {
			break
		}

		u := base + ep
		status, body := fetch(ctx, client, u)
		if status != http.StatusOK || len(body) == 0 {
			continue
		}

		// Check for user-data signals: JSON response with user-like fields.
		bodyLower := strings.ToLower(body)
		if !containsAny(bodyLower, []string{"email", "username", "user_id", "user_name", "phone", "address"}) {
			continue
		}

		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckBOLAHorizontalAccess,
			Module:   "deep",
			Scanner:  scannerName,
			Severity: finding.SeverityCritical,
			Title:    fmt.Sprintf("BOLA: unauthenticated access to user data on %s%s", asset, ep),
			Description: fmt.Sprintf(
				"The endpoint %s returned HTTP 200 with user profile data (email, username, etc.) "+
					"without any authentication headers or session cookies. An attacker can access "+
					"other users' data by directly requesting this endpoint.",
				u),
			Asset:    asset,
			DeepOnly: true,
			ProofCommand: fmt.Sprintf(
				`curl -sk '%s'`, u),
			Evidence: map[string]any{
				"url":         u,
				"status":      status,
				"body_length": len(body),
			},
			DiscoveredAt: time.Now(),
		})

		// One BOLA finding is enough.
		break
	}

	return findings, nil
}

// fetch performs a GET request and returns the status code and response body.
func fetch(ctx context.Context, client *http.Client, rawURL string) (int, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
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

// adjacentNumericIDs returns the ID+1 and ID-1 variants for a given numeric
// ID string. Returns only valid positive integers.
func adjacentNumericIDs(id string) []string {
	var n int
	if _, err := fmt.Sscanf(id, "%d", &n); err != nil {
		return nil
	}
	var result []string
	if n > 1 {
		result = append(result, fmt.Sprintf("%d", n-1))
	}
	result = append(result, fmt.Sprintf("%d", n+1))
	return result
}

// containsAny returns true if body contains any of the given substrings.
func containsAny(body string, signals []string) bool {
	for _, sig := range signals {
		if strings.Contains(body, sig) {
			return true
		}
	}
	return false
}
