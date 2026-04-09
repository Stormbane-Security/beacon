// Package racecondition detects Time-of-Check-Time-of-Use (TOCTOU) race
// conditions by sending concurrent identical requests and looking for
// inconsistent responses that indicate non-atomic state operations.
//
// Common vulnerable operations:
//   - Coupon/discount redemption (apply same code twice concurrently)
//   - Account balance transfers (debit same amount concurrently)
//   - Vote/like counting (increment same counter concurrently)
//   - Registration (create same username concurrently)
//   - File upload (overwrite same file concurrently)
//
// The scanner identifies state-changing endpoints from crawl results and
// hardcoded common paths, then sends concurrent requests using a sync
// barrier (the "single-packet attack" technique) and checks for response
// inconsistencies.
//
// Authorized mode only — sends many concurrent POST requests that could
// affect application state and availability.
package racecondition

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scan"
	"github.com/stormbane-security/beacon/internal/scanner/authctx"
	"github.com/stormbane-security/beacon/internal/scanner/schemedetect"
)

func init() {
	scan.RegisterWithCheckDecls(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	},
		scan.Check(finding.CheckWebRaceCondition, finding.SeverityCritical, finding.ModeDeep),
		scan.Check(finding.CheckWebRaceNoIdempotency, finding.SeverityMedium, finding.ModeDeep),
	)
}

const scannerName = "racecondition"

// concurrency is the number of simultaneous requests in the race burst.
const concurrency = 10

// raceTarget describes an endpoint to test for race conditions.
type raceTarget struct {
	path        string
	method      string
	contentType string
	body        string
	description string
}

// hardcodedTargets are common race-prone API patterns.
var hardcodedTargets = []raceTarget{
	{"/api/redeem", http.MethodPost, "application/json", `{"code":"BEACON-RACE-TEST"}`, "coupon/code redemption"},
	{"/api/v1/redeem", http.MethodPost, "application/json", `{"code":"BEACON-RACE-TEST"}`, "coupon/code redemption"},
	{"/api/transfer", http.MethodPost, "application/json", `{"amount":1,"to":"test"}`, "balance transfer"},
	{"/api/v1/transfer", http.MethodPost, "application/json", `{"amount":1,"to":"test"}`, "balance transfer"},
	{"/api/vote", http.MethodPost, "application/json", `{"id":"1"}`, "vote/like"},
	{"/api/like", http.MethodPost, "application/json", `{"id":"1"}`, "vote/like"},
	{"/api/apply", http.MethodPost, "application/json", `{"id":"1"}`, "action application"},
	{"/api/checkout", http.MethodPost, "application/json", `{}`, "checkout"},
	{"/api/purchase", http.MethodPost, "application/json", `{}`, "purchase"},
	{"/api/withdraw", http.MethodPost, "application/json", `{"amount":1}`, "withdrawal"},
	{"/api/v1/withdraw", http.MethodPost, "application/json", `{"amount":1}`, "withdrawal"},
	{"/api/claim", http.MethodPost, "application/json", `{"id":"1"}`, "reward claim"},
	{"/api/v1/claim", http.MethodPost, "application/json", `{"id":"1"}`, "reward claim"},
	{"/api/register", http.MethodPost, "application/json", `{"username":"beacon-race-test","password":"test"}`, "user registration"},
	{"/api/v1/register", http.MethodPost, "application/json", `{"username":"beacon-race-test","password":"test"}`, "user registration"},
	{"/api/coupon", http.MethodPost, "application/json", `{"code":"BEACON-RACE-TEST"}`, "coupon application"},
	{"/api/v1/coupon", http.MethodPost, "application/json", `{"code":"BEACON-RACE-TEST"}`, "coupon application"},
	{"/api/verify", http.MethodPost, "application/json", `{"token":"test"}`, "verification"},
	{"/api/confirm", http.MethodPost, "application/json", `{"id":"1"}`, "confirmation"},
	{"/api/approve", http.MethodPost, "application/json", `{"id":"1"}`, "approval"},
}

// racePronePaths are URL path fragments that indicate state-changing endpoints
// worth testing when discovered via crawl results.
var racePronePaths = []string{
	"/transfer", "/purchase", "/checkout", "/redeem", "/vote",
	"/apply", "/coupon", "/register", "/verify", "/confirm",
	"/approve", "/claim", "/withdraw", "/like", "/subscribe",
	"/order", "/payment", "/deposit", "/reward", "/bonus",
}

// idempotencyHeaders are HTTP response headers that indicate the server
// implements idempotency protection.
var idempotencyHeaders = []string{
	"idempotency-key",
	"x-idempotency-key",
	"x-request-id",
	"x-idempotent-replayed",
}

// result captures the status code, body hash, and key headers of a single
// concurrent request.
type result struct {
	status   int
	bodyHash string
	bodyLen  int
	headers  http.Header
}

// Scanner tests endpoints for race conditions via concurrent request bursts.
type Scanner struct{}

// New returns a new race condition scanner.
func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanAuthorized {
		return nil, nil
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	authenticated := authctx.IsAuthenticated(ctx)
	if authenticated {
		client = authctx.HTTPClient(ctx)
	}

	base := schemedetect.Base(ctx, client, asset)

	// Build target list: hardcoded targets + crawl-discovered endpoints.
	targets := make([]raceTarget, len(hardcodedTargets))
	copy(targets, hardcodedTargets)
	targets = append(targets, discoverFromCrawlFeed(ctx)...)

	// Deduplicate by path+method.
	targets = deduplicateTargets(targets)

	var findings []finding.Finding

	for _, target := range targets {
		if ctx.Err() != nil {
			break
		}

		targetURL := base + target.path

		// Step 1: Baseline — send one request to check if endpoint exists.
		baseline, err := sendRequest(ctx, client, target.method, targetURL, target.contentType, target.body)
		if err != nil {
			continue
		}

		// Skip endpoints that don't exist or aren't accepting requests.
		if baseline.status == 404 || baseline.status == 405 {
			continue
		}

		// Check for idempotency headers in baseline response.
		hasIdempotency := checkIdempotencyHeaders(baseline.headers)

		visibility := finding.VisibilityPublic
		if authenticated {
			visibility = finding.VisibilityAuthenticated
		}

		// Step 2: Race test — send N concurrent identical requests using a
		// sync barrier (all goroutines wait, then release simultaneously).
		results := make([]result, concurrency)
		var wg sync.WaitGroup
		gate := make(chan struct{}) // Closed to release all goroutines simultaneously.

		for i := range concurrency {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				<-gate // Block until gate is closed (broadcast release).

				r, err := sendRequest(ctx, client, target.method, targetURL, target.contentType, target.body)
				if err != nil {
					return
				}
				results[idx] = r
			}(i)
		}

		// Small delay to let goroutines reach the gate, then release all at once.
		time.Sleep(10 * time.Millisecond)
		close(gate)
		wg.Wait()

		// Step 3: Analyze results.
		successCount := 0
		var statusCodes []int
		for _, r := range results {
			if r.status >= 200 && r.status < 300 {
				successCount++
			}
			if r.status > 0 {
				statusCodes = append(statusCodes, r.status)
			}
		}

		// Heuristic 1: Multiple successes on a state-changing endpoint.
		// If we sent N concurrent requests and got >= 3 successes, the
		// operation is likely not atomic.
		if successCount >= 3 {
			findings = append(findings, finding.Finding{
				CheckID:    finding.CheckWebRaceCondition,
				Module:     "deep",
				Scanner:    scannerName,
				Severity:   finding.SeverityHigh,
				Visibility: visibility,
				Title: fmt.Sprintf("Potential race condition on %s (%d/%d concurrent successes)",
					target.path, successCount, concurrency),
				Description: fmt.Sprintf(
					"The endpoint %s accepted %d out of %d concurrent identical requests with "+
						"success responses (2xx). For state-changing operations like %s, only one "+
						"request should succeed. Multiple successes indicate the operation is not "+
						"atomic, creating a Time-of-Check-Time-of-Use (TOCTOU) race condition. "+
						"This can be exploited to redeem coupons multiple times, double-spend "+
						"balances, or inflate vote counts.",
					targetURL, successCount, concurrency, target.description),
				Asset: asset,
				ProofCommand: fmt.Sprintf(
					"for i in $(seq 1 10); do curl -s -o /dev/null -w '%%{http_code}\\n' -X %s '%s' -H 'Content-Type: %s' -d '%s' & done; wait",
					target.method, targetURL, target.contentType, target.body),
				Evidence: map[string]any{
					"url":           targetURL,
					"method":        target.method,
					"concurrency":   concurrency,
					"success_count": successCount,
					"status_codes":  statusCodes,
					"operation":     target.description,
				},
				DiscoveredAt: time.Now(),
			})
			continue // Already flagged via success count heuristic.
		}

		// Heuristic 2: Response divergence — identical concurrent requests
		// produce different status codes or different body hashes.
		if diff := detectResponseDivergence(results); diff != nil {
			findings = append(findings, finding.Finding{
				CheckID:    finding.CheckWebRaceCondition,
				Module:     "deep",
				Scanner:    scannerName,
				Severity:   finding.SeverityHigh,
				Visibility: visibility,
				Title: fmt.Sprintf("Response divergence on %s — potential race condition",
					target.path),
				Description: fmt.Sprintf(
					"Sending %d identical concurrent requests to %s produced inconsistent responses: "+
						"%s. For a state-changing operation like %s, divergent responses to identical "+
						"requests indicate non-atomic processing — a classic Time-of-Check-Time-of-Use "+
						"(TOCTOU) race condition.",
					concurrency, targetURL, diff.summary, target.description),
				Asset: asset,
				ProofCommand: fmt.Sprintf(
					"for i in $(seq 1 10); do curl -s -w '\\nHTTP_CODE:%%{http_code}\\n' -X %s '%s' -H 'Content-Type: %s' -d '%s' & done; wait",
					target.method, targetURL, target.contentType, target.body),
				Evidence: map[string]any{
					"url":                targetURL,
					"method":             target.method,
					"concurrency":        concurrency,
					"status_codes":       statusCodes,
					"unique_statuses":    diff.uniqueStatuses,
					"unique_body_hashes": diff.uniqueBodies,
					"divergence_summary": diff.summary,
					"operation":          target.description,
				},
				DiscoveredAt: time.Now(),
			})
			continue
		}

		// Heuristic 3: No idempotency protection on a state-changing
		// endpoint that accepts POST. This is a weaker signal (Medium)
		// because the endpoint may implement server-side deduplication
		// without advertising it via headers.
		if !hasIdempotency && baseline.status >= 200 && baseline.status < 300 {
			findings = append(findings, finding.Finding{
				CheckID:    finding.CheckWebRaceNoIdempotency,
				Module:     "deep",
				Scanner:    scannerName,
				Severity:   finding.SeverityMedium,
				Visibility: visibility,
				Title: fmt.Sprintf("No idempotency protection on state-changing endpoint %s",
					target.path),
				Description: fmt.Sprintf(
					"The state-changing endpoint %s (%s) returns successful responses but does not "+
						"include idempotency headers (Idempotency-Key, X-Request-Id, X-Idempotent-Replayed). "+
						"Without idempotency protection, concurrent or retried requests to operations "+
						"like %s may be processed multiple times, enabling race condition exploitation. "+
						"Implement server-side idempotency keys to ensure each operation executes exactly once.",
					targetURL, target.method, target.description),
				Asset: asset,
				ProofCommand: fmt.Sprintf(
					"curl -v -X %s '%s' -H 'Content-Type: %s' -d '%s' 2>&1 | grep -i idempotency",
					target.method, targetURL, target.contentType, target.body),
				Evidence: map[string]any{
					"url":                    targetURL,
					"method":                 target.method,
					"baseline_status":        baseline.status,
					"idempotency_headers":    false,
					"operation":              target.description,
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings, nil
}

// sendRequest sends a single HTTP request and returns a result with status,
// body hash, and headers.
func sendRequest(ctx context.Context, client *http.Client, method, targetURL, contentType, body string) (result, error) {
	req, err := http.NewRequestWithContext(ctx, method, targetURL,
		bytes.NewBufferString(body))
	if err != nil {
		return result{}, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner)")

	resp, err := client.Do(req)
	if err != nil {
		return result{}, err
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()

	h := sha256.Sum256(respBody)
	return result{
		status:   resp.StatusCode,
		bodyHash: fmt.Sprintf("%x", h[:8]),
		bodyLen:  len(respBody),
		headers:  resp.Header,
	}, nil
}

// checkIdempotencyHeaders returns true if the response contains any known
// idempotency-related header.
func checkIdempotencyHeaders(headers http.Header) bool {
	for _, h := range idempotencyHeaders {
		if headers.Get(h) != "" {
			return true
		}
	}
	return false
}

// fallbackTargets are common state-changing endpoints tested when no crawl
// results are available (e.g. --scanners racecondition mode). These cover the
// most common race-prone patterns in web applications.
var fallbackTargets = []raceTarget{
	{"/api/transfer", http.MethodPost, "application/json", `{"amount":1,"to":"test"}`, "balance transfer"},
	{"/api/purchase", http.MethodPost, "application/json", `{}`, "purchase"},
	{"/api/checkout", http.MethodPost, "application/json", `{}`, "checkout"},
	{"/api/vote", http.MethodPost, "application/json", `{"id":"1"}`, "vote/like"},
	{"/api/like", http.MethodPost, "application/json", `{"id":"1"}`, "vote/like"},
	{"/api/apply", http.MethodPost, "application/json", `{"id":"1"}`, "action application"},
	{"/register", http.MethodPost, "application/json", `{"username":"beacon-race-test","password":"test"}`, "user registration"},
	{"/signup", http.MethodPost, "application/json", `{"username":"beacon-race-test","password":"test"}`, "user registration"},
	{"/login", http.MethodPost, "application/json", `{"username":"test","password":"test"}`, "login"},
	{"/api/redeem", http.MethodPost, "application/json", `{"code":"BEACON-RACE-TEST"}`, "coupon/code redemption"},
	{"/api/claim", http.MethodPost, "application/json", `{"id":"1"}`, "reward claim"},
	{"/api/coupon", http.MethodPost, "application/json", `{"code":"BEACON-RACE-TEST"}`, "coupon application"},
}

// discoverFromCrawlFeed drains the crawl feed channel and returns race
// targets for any POST-capable endpoints found at race-prone paths.
// When no crawl feed is available, returns fallback targets so the scanner
// still has endpoints to test in --scanners mode.
func discoverFromCrawlFeed(ctx context.Context) []raceTarget {
	v := ctx.Value(module.CrawlFeedKey)
	if v == nil {
		return fallbackTargets
	}
	ch, ok := v.(chan string)
	if !ok {
		return fallbackTargets
	}

	var targets []raceTarget
	seen := make(map[string]bool)

	for {
		select {
		case rawURL, ok := <-ch:
			if !ok {
				if len(targets) == 0 {
					return fallbackTargets
				}
				return targets
			}
			parsed, err := url.Parse(rawURL)
			if err != nil {
				continue
			}
			path := parsed.Path
			if path == "" || path == "/" {
				continue
			}
			// Only test endpoints that look race-prone.
			if !isRacePronePath(path) {
				continue
			}
			if seen[path] {
				continue
			}
			seen[path] = true
			targets = append(targets, raceTarget{
				path:        path,
				method:      http.MethodPost,
				contentType: "application/json",
				body:        `{"test":"beacon-race"}`,
				description: "crawl-discovered endpoint",
			})
		default:
			if len(targets) == 0 {
				return fallbackTargets
			}
			return targets
		}
	}
}

// isRacePronePath checks if a URL path contains any race-prone path fragment.
func isRacePronePath(path string) bool {
	lower := strings.ToLower(path)
	for _, p := range racePronePaths {
		if strings.Contains(lower, p) {
			return true
		}
	}
	// Also match any POST-capable /api/* endpoint.
	if strings.HasPrefix(lower, "/api/") || strings.HasPrefix(lower, "/api/v") {
		return true
	}
	return false
}

// deduplicateTargets removes duplicate targets with the same path+method.
func deduplicateTargets(targets []raceTarget) []raceTarget {
	seen := make(map[string]bool)
	var out []raceTarget
	for _, t := range targets {
		key := t.method + " " + t.path
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, t)
	}
	return out
}

// divergence captures information about inconsistent responses.
type divergence struct {
	uniqueStatuses int
	uniqueBodies   int
	summary        string
}

// detectResponseDivergence checks if concurrent identical requests produced
// different status codes or response body hashes. Returns nil if all responses
// are consistent (no race condition signal).
func detectResponseDivergence(results []result) *divergence {
	statusSet := make(map[int]struct{})
	bodySet := make(map[string]struct{})
	validCount := 0

	for _, r := range results {
		if r.status == 0 {
			continue // Request failed entirely.
		}
		validCount++
		statusSet[r.status] = struct{}{}
		bodySet[r.bodyHash] = struct{}{}
	}

	// Need at least 3 valid responses to draw conclusions.
	if validCount < 3 {
		return nil
	}

	uniqueStatuses := len(statusSet)
	uniqueBodies := len(bodySet)

	// If all statuses and body hashes are identical, no divergence.
	if uniqueStatuses <= 1 && uniqueBodies <= 1 {
		return nil
	}

	var summary string
	switch {
	case uniqueStatuses > 1 && uniqueBodies > 1:
		summary = fmt.Sprintf("%d different status codes and %d different response bodies across %d responses",
			uniqueStatuses, uniqueBodies, validCount)
	case uniqueStatuses > 1:
		summary = fmt.Sprintf("%d different status codes across %d responses",
			uniqueStatuses, validCount)
	default:
		summary = fmt.Sprintf("%d different response bodies across %d responses",
			uniqueBodies, validCount)
	}

	return &divergence{
		uniqueStatuses: uniqueStatuses,
		uniqueBodies:   uniqueBodies,
		summary:        summary,
	}
}
