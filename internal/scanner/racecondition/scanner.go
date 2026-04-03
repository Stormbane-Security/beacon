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
	scan.Register(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	})
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
		io.Copy(io.Discard, probeResp.Body)
		probeResp.Body.Close()

		// Skip endpoints that don't exist or aren't accepting requests.
		if probeResp.StatusCode == 404 || probeResp.StatusCode == 405 {
			continue
		}

		// Step 2: Send concurrent requests and collect responses.
		type result struct {
			status int
			body   string
		}
		results := make([]result, concurrency)
		var wg sync.WaitGroup
		var gate sync.Mutex
		gate.Lock() // Hold gate closed until all goroutines are ready.

		for i := range concurrency {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				gate.Lock()   // Wait for gate to open.
				gate.Unlock() // All goroutines read-unlock simultaneously.

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
				resp.Body.Close()
				results[idx] = result{status: resp.StatusCode, body: string(body)}
			}(i)
		}

		// Small delay to let goroutines reach the gate, then release all at once.
		time.Sleep(10 * time.Millisecond)
		gate.Unlock()
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

		// Heuristic: if we sent 10 concurrent requests and got more than 1
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
		}
	}

	return findings, nil
}
