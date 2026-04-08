// Package racecondition detects Time-of-Check-Time-of-Use (TOCTOU) race
// conditions by sending concurrent identical requests and looking for
// inconsistent responses that indicate non-atomic state operations.
//
// Common vulnerable operations:
//   - Coupon/discount redemption (apply same code twice concurrently)//   - Account balance transfers (debit same amount concurrently)
//   - Vote/like counting (increment same counter concurrently)
//   - Registration (create same username concurrently)
//   - File upload (overwrite same file concurrently)
//
// The scanner identifies state-changing endpoints (POST to common paths) and
// sends concurrent requests, checking if all succeed when only one should.
//
// Deep mode only — sends concurrent POST requests.
package racecondition

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
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
		scan.Check(finding.CheckWebRaceCondition, finding.SeverityCritical, finding.ModeDeep),
	)
}
const scannerName = "racecondition"

// concurrency is the number of simultaneous requests.
const concurrency = 10

// raceTarget describes an endpoint to test for race conditions.
type raceTarget struct {
	path        string
	method      string
	contentType string
	body        string
	description string
}

var raceTargets = []raceTarget{
	{"/api/redeem", http.MethodPost, "application/json", `{"code":"BEACON-RACE-TEST"}`, "coupon/code redemption"},
	{"/api/v1/redeem", http.MethodPost, "application/json", `{"code":"BEACON-RACE-TEST"}`, "coupon/code redemption"},
	{"/api/transfer", http.MethodPost, "application/json", `{"amount":1,"to":"test"}`, "balance transfer"},
	{"/api/v1/transfer", http.MethodPost, "application/json", `{"amount":1,"to":"test"}`, "balance transfer"},
	{"/api/vote", http.MethodPost, "application/json", `{"id":"1"}`, "vote/like"},
	{"/api/like", http.MethodPost, "application/json", `{"id":"1"}`, "vote/like"},
	{"/api/apply", http.MethodPost, "application/json", `{"id":"1"}`, "action application"},
	{"/api/checkout", http.MethodPost, "application/json", `{}`, "checkout"},
	{"/api/withdraw", http.MethodPost, "application/json", `{"amount":1}`, "withdrawal"},
	{"/api/v1/withdraw", http.MethodPost, "application/json", `{"amount":1}`, "withdrawal"},
	{"/api/claim", http.MethodPost, "application/json", `{"id":"1"}`, "reward claim"},
	{"/api/v1/claim", http.MethodPost, "application/json", `{"id":"1"}`, "reward claim"},
	{"/api/register", http.MethodPost, "application/json", `{"username":"beacon-race-test","password":"test"}`, "user registration"},
	{"/api/v1/register", http.MethodPost, "application/json", `{"username":"beacon-race-test","password":"test"}`, "user registration"},
	{"/api/coupon", http.MethodPost, "application/json", `{"code":"BEACON-RACE-TEST"}`, "coupon application"},
	{"/api/v1/coupon", http.MethodPost, "application/json", `{"code":"BEACON-RACE-TEST"}`, "coupon application"},
}

// result captures the status code and body of a single concurrent request.
type result struct {
	status int
	body   string
}

type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanDeep && scanType != module.ScanAuthorized {
		return nil, nil
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if c := authctx.HTTPClient(ctx); c != nil {
		client = c
	}

	base := schemedetect.Base(ctx, client, asset)
	var findings []finding.Finding

	for _, target := range raceTargets {
		if ctx.Err() != nil {
			break
		}

		url := base + target.path

		// Step 1: Check if endpoint exists by sending one request.
		probeReq, err := http.NewRequestWithContext(ctx, target.method, url,
			bytes.NewBufferString(target.body))
		if err != nil {
			continue
		}
		probeReq.Header.Set("Content-Type", target.contentType)
		probeReq.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner)")
		probeResp, err := client.Do(probeReq)
		if err != nil {
			continue
		}
		_, _ = io.Copy(io.Discard, probeResp.Body)
		_ = probeResp.Body.Close()

		// Skip endpoints that don't exist or aren't accepting requests.
		if probeResp.StatusCode == 404 || probeResp.StatusCode == 405 {
			continue
		}

		// Step 2: Send concurrent requests and collect responses.
		results := make([]result, concurrency)
		var wg sync.WaitGroup
		gate := make(chan struct{}) // Closed to release all goroutines simultaneously.

		for i := range concurrency {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				<-gate // Block until gate is closed (broadcast release).

				req, err := http.NewRequestWithContext(ctx, target.method, url,
					bytes.NewBufferString(target.body))
				if err != nil {
					return
				}
				req.Header.Set("Content-Type", target.contentType)
				req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner)")
				resp, err := client.Do(req)
				if err != nil {
					return
				}
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
				_ = resp.Body.Close()
				results[idx] = result{status: resp.StatusCode, body: string(body)}
			}(i)
		}

		// Small delay to let goroutines reach the gate, then release all at once.
		time.Sleep(10 * time.Millisecond)
		close(gate)
		wg.Wait()

		// Step 3: Analyze results. If all concurrent requests got 2xx when
		// only one should succeed, it suggests a race condition.
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

		// Heuristic 1: if we sent N concurrent requests and got more than 1
		// success (for an endpoint that should be idempotent-once), flag it.
		// We require at least 3 successes to reduce false positives.
		if successCount >= 3 {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckWebRaceCondition,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityHigh,
				Title: fmt.Sprintf("Potential race condition on %s (%d/%d concurrent successes)",
					target.path, successCount, concurrency),
				Description: fmt.Sprintf(
					"The endpoint %s accepted %d out of %d concurrent identical requests with "+
						"success responses (2xx). For state-changing operations like %s, only one "+
						"request should succeed. Multiple successes indicate the operation is not "+
						"atomic, creating a Time-of-Check-Time-of-Use (TOCTOU) race condition. "+
						"This can be exploited to redeem coupons multiple times, double-spend "+
						"balances, or inflate vote counts.",
					url, successCount, concurrency, target.description),
				Asset: asset,
				ProofCommand: fmt.Sprintf(
					"for i in $(seq 1 10); do curl -s -o /dev/null -w '%%{http_code}\\n' -X %s '%s' -H 'Content-Type: %s' -d '%s' & done; wait",
					target.method, url, target.contentType, target.body),
				Evidence: map[string]any{
					"url":             url,
					"method":          target.method,
					"concurrency":     concurrency,
					"success_count":   successCount,
					"status_codes":    statusCodes,
					"operation":       target.description,
				},
				DiscoveredAt: time.Now(),
			})
			continue // Already flagged via success count heuristic.
		}

		// Heuristic 2: response divergence — if identical concurrent requests
		// produce different status codes or different bodies, the server has
		// non-deterministic state handling indicative of a race condition.
		if diff := detectResponseDivergence(results); diff != nil {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckWebRaceCondition,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityHigh,
				Title: fmt.Sprintf("Response divergence on %s — potential race condition",
					target.path),
				Description: fmt.Sprintf(
					"Sending %d identical concurrent requests to %s produced inconsistent responses: "+
						"%s. For a state-changing operation like %s, divergent responses to identical "+
						"requests indicate non-atomic processing — a classic Time-of-Check-Time-of-Use "+
						"(TOCTOU) race condition.",
					concurrency, url, diff.summary, target.description),
				Asset: asset,
				ProofCommand: fmt.Sprintf(
					"for i in $(seq 1 10); do curl -s -w '\\nHTTP_CODE:%%{http_code}\\n' -X %s '%s' -H 'Content-Type: %s' -d '%s' & done; wait",
					target.method, url, target.contentType, target.body),
				Evidence: map[string]any{
					"url":                url,
					"method":             target.method,
					"concurrency":        concurrency,
					"status_codes":       statusCodes,
					"unique_statuses":    diff.uniqueStatuses,
					"unique_bodies":      diff.uniqueBodies,
					"divergence_summary": diff.summary,
					"operation":          target.description,
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings, nil
}

// divergence captures information about inconsistent responses.
type divergence struct {
	uniqueStatuses int
	uniqueBodies   int
	summary        string
}

// detectResponseDivergence checks if concurrent identical requests produced
// different status codes or response bodies. Returns nil if all responses are
// consistent (no race condition signal).
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
		// Normalize body for comparison: trim whitespace and limit length.
		body := r.body
		if len(body) > 512 {
			body = body[:512]
		}
		bodySet[body] = struct{}{}
	}

	// Need at least 3 valid responses to draw conclusions.
	if validCount < 3 {
		return nil
	}

	uniqueStatuses := len(statusSet)
	uniqueBodies := len(bodySet)

	// If all statuses and bodies are identical, no divergence.
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
