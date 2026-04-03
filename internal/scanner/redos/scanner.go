// Package redos detects Regular Expression Denial of Service (ReDoS)// vulnerabilities by injecting payloads that trigger catastrophic backtracking
// in common server-side regex patterns (email, URL, numeric validators).
// Deep mode only — sends active payloads to the target.
package redos

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/scan"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)


func init() {
	scan.Register(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	})
}
const scannerName = "redos"

// Scanner probes for ReDoS vulnerabilities via timing-based detection.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

// payload defines a ReDoS test vector targeting a common regex pattern.
type payload struct {
	name    string // human-readable label (e.g. "email regex")
	value   string // the evil input
	benign  string // harmless baseline input for timing comparison
}

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType == module.ScanSurface {
		return nil, nil
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec
			},
		},
	}

	// ReDoS payloads — each targets a commonly deployed regex pattern.
	// The "evil" input triggers exponential backtracking while the "benign"
	// input matches the same regex instantly, providing a timing baseline.
	payloads := []payload{
		{
			name:   "email regex",
			value:  strings.Repeat("a", 30) + "!",
			benign: "test@example.com",
		},
		{
			name:   "URL regex",
			value:  "http://" + strings.Repeat("a", 30),
			benign: "http://example.com",
		},
		{
			name:   "numeric regex",
			value:  strings.Repeat("1", 30) + "a",
			benign: "12345",
		},
	}

	// Common query parameters where user input is likely validated by regex.
	params := []string{"q", "search", "email", "url", "input"}

	var findings []finding.Finding

	for _, scheme := range []string{"https", "http"} {
		baseURL := scheme + "://" + asset

		// First verify the target is reachable.
		if !s.isReachable(ctx, client, baseURL) {
			continue
		}

		for _, param := range params {
			for _, p := range payloads {
				select {
				case <-ctx.Done():
					return findings, nil
				default:
				}

				f := s.testPayload(ctx, client, baseURL, asset, param, p)
				if f != nil {
					findings = append(findings, *f)
				}
			}
		}

		// If we got results on this scheme, stop.
		if len(findings) > 0 {
			break
		}
	}

	return findings, nil
}

// isReachable checks whether the base URL responds within a reasonable time.
func (s *Scanner) isReachable(ctx context.Context, client *http.Client, baseURL string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/", nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon Security Scanner)")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	return true
}

// testPayload sends a benign request to measure baseline timing, then sends
// the evil payload and compares response times. A finding is returned if the
// evil payload causes a response time >5s while the baseline is <1s.
func (s *Scanner) testPayload(ctx context.Context, client *http.Client, baseURL, asset, param string, p payload) *finding.Finding {
	now := time.Now()

	// Measure baseline with benign input.
	benignURL := fmt.Sprintf("%s/?%s=%s", baseURL, param, url.QueryEscape(p.benign))
	baselineMs, err := s.measureResponseTime(ctx, client, benignURL)
	if err != nil {
		return nil
	}

	// Skip if baseline is already slow (>1 second) — unreliable comparison.
	if baselineMs > 1000 {
		return nil
	}

	// Send evil payload.
	evilURL := fmt.Sprintf("%s/?%s=%s", baseURL, param, url.QueryEscape(p.value))
	evilMs, err := s.measureResponseTime(ctx, client, evilURL)
	if err != nil && evilMs <= 5000 {
		return nil
	}

	// Flag if evil response took >5 seconds and baseline was <1 second.
	if evilMs > 5000 {
		return &finding.Finding{
			CheckID:  finding.CheckWebReDoS,
			Module:   "deep",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Asset:    asset,
			Title:    fmt.Sprintf("ReDoS: %s parameter %q causes %dms delay (%s backtracking)", asset, param, evilMs, p.name),
			Description: fmt.Sprintf(
				"Injecting a %s backtracking payload into the %q query parameter caused the server to respond in %dms "+
					"(baseline: %dms with benign input). This indicates a vulnerable regular expression that can be exploited "+
					"for denial of service. An attacker can send a small number of requests with crafted input to exhaust "+
					"server CPU, causing service degradation or outage for all users.",
				p.name, param, evilMs, baselineMs,
			),
			Evidence: map[string]any{
				"parameter":    param,
				"payload_type": p.name,
				"evil_input":   truncate(p.value, 64),
				"benign_input": p.benign,
				"evil_ms":      evilMs,
				"baseline_ms":  baselineMs,
				"url":          evilURL,
				"threshold_ms": 5000,
			},
			ProofCommand: fmt.Sprintf(
				"# Measure baseline:\ntime curl -so /dev/null '%s'\n# Measure evil payload (should take >5s):\ntime curl -so /dev/null '%s'",
				benignURL, evilURL,
			),
			DiscoveredAt: now,
		}
	}

	return nil
}

// measureResponseTime sends a GET request and returns the total elapsed time in milliseconds.
func (s *Scanner) measureResponseTime(ctx context.Context, client *http.Client, targetURL string) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon Security Scanner)")

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		return elapsed, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()

	return elapsed, nil
}

// truncate limits a string to maxLen characters.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
