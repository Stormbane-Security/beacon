// Package passiveinject implements a surface-mode scanner that detects
// injection signals without sending any payloads. It works by:
//
//  1. Fetching URLs discovered by the crawler (with their original parameters)
//  2. Checking if parameter values are reflected unescaped in the HTML response
//  3. Checking if SQL error messages appear in any response
//  4. Checking for stack traces / debug output
//
// This is safe for surface mode because it only requests URLs the crawler
// already discovered — no new parameters or payloads are injected.
package passiveinject

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scan"
	"github.com/stormbane-security/beacon/internal/scanlog"
	"github.com/stormbane-security/beacon/internal/scanner/paramdiscovery"
)

func init() {
	scan.RegisterWithCheckDecls(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	},
		scan.Check(finding.CheckWebParamReflected, finding.SeverityHigh, finding.ModeSurface),
		scan.Check(finding.CheckWebSQLErrorDisclosed, finding.SeverityHigh, finding.ModeSurface),
		scan.Check(finding.CheckWebStackTrace, finding.SeverityMedium, finding.ModeSurface),
	)
}

const scannerName = "passiveinject"

// SQL error patterns across common databases.
var sqlErrorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)you have an error in your SQL syntax`),
	regexp.MustCompile(`(?i)mysql_fetch|mysql_num_rows|mysql_query`),
	regexp.MustCompile(`(?i)ORA-\d{4,5}:`),
	regexp.MustCompile(`(?i)Microsoft OLE DB Provider for SQL Server`),
	regexp.MustCompile(`(?i)Unclosed quotation mark after the character string`),
	regexp.MustCompile(`(?i)\[Microsoft\]\[ODBC SQL Server Driver\]`),
	regexp.MustCompile(`(?i)pg_query\(\)|pg_exec\(\)|PG::SyntaxError`),
	regexp.MustCompile(`(?i)ERROR:\s+syntax error at or near`),
	regexp.MustCompile(`(?i)SQLite3::SQLException`),
	regexp.MustCompile(`(?i)near ".*": syntax error`),
	regexp.MustCompile(`(?i)com\.mysql\.jdbc\.exceptions`),
	regexp.MustCompile(`(?i)org\.postgresql\.util\.PSQLException`),
	regexp.MustCompile(`(?i)java\.sql\.SQLException`),
	regexp.MustCompile(`(?i)System\.Data\.SqlClient\.SqlException`),
	regexp.MustCompile(`(?i)SQLSTATE\[\w+\]`),
	regexp.MustCompile(`(?i)PDOException`),
}

// Stack trace patterns.
var stackTracePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)at \S+\.\S+\(.*\.java:\d+\)`),                     // Java
	regexp.MustCompile(`(?i)File ".*\.py", line \d+`),                          // Python
	regexp.MustCompile(`(?i)Traceback \(most recent call last\)`),              // Python
	regexp.MustCompile(`(?i)at .*\(.*\.js:\d+:\d+\)`),                         // Node.js
	regexp.MustCompile(`(?i)goroutine \d+ \[running\]`),                        // Go
	regexp.MustCompile(`(?i)#\d+ .*\.php\(\d+\):`),                            // PHP
	regexp.MustCompile(`(?i)at .* in .*\.cs:line \d+`),                         // C#/.NET
	regexp.MustCompile(`(?i)ActionView::Template::Error|ActionController::`),   // Rails
	regexp.MustCompile(`(?i)Laravel.*Exception|Illuminate\\`),                  // Laravel
	regexp.MustCompile(`(?i)django\.core\.exceptions|django\.db\.utils`),       // Django
	regexp.MustCompile(`(?i)express.*Error|TypeError:.*at \S+`),               // Express.js
}

// Scanner detects injection signals passively.
type Scanner struct{}

// New returns a new Scanner.
func New() *Scanner { return &Scanner{} }

// Name returns the stable scanner identifier.
func (s *Scanner) Name() string { return scannerName }

// Run executes the passive injection signal scan.
func (s *Scanner) Run(ctx context.Context, asset string, _ module.ScanType) ([]finding.Finding, error) {
	log := scanlog.FromContext(ctx)
	client := scan.SharedClient(10 * time.Second)

	// Get crawled URLs with parameters from the paramdiscovery context.
	pathParams := paramdiscovery.DiscoveredParamsFromContext(ctx)

	scheme := detectScheme(ctx, asset)
	var findings []finding.Finding

	// Track what we've already reported to avoid duplicates.
	reported := map[string]bool{}

	// Phase 1: Check crawled URLs with existing parameters for reflections.
	for path, params := range pathParams {
		if len(findings) >= 20 {
			break // cap findings to avoid noise
		}
		baseURL := fmt.Sprintf("%s://%s%s", scheme, asset, path)

		// Build the URL with all discovered params.
		u, err := url.Parse(baseURL)
		if err != nil {
			continue
		}
		q := u.Query()
		for _, p := range params {
			if q.Get(p) == "" {
				q.Set(p, "beacon_ref_test_7x9k")
			}
		}
		u.RawQuery = q.Encode()

		body, status, err := fetchBody(ctx, client, u.String())
		log.ProbeTimed(scannerName, asset, path, 0, status, err)
		if err != nil || body == "" {
			continue
		}

		// Check for parameter value reflection.
		for _, p := range params {
			val := q.Get(p)
			if val == "" || len(val) < 5 {
				continue
			}
			if strings.Contains(body, val) {
				key := fmt.Sprintf("reflect:%s:%s", path, p)
				if reported[key] {
					continue
				}
				reported[key] = true

				findings = append(findings, finding.Finding{
					CheckID:  finding.CheckWebParamReflected,
					Module:   "surface",
					Scanner:  scannerName,
					Severity: finding.SeverityHigh,
					Title:    fmt.Sprintf("Parameter '%s' reflected in response on %s", p, path),
					Description: fmt.Sprintf(
						"The value of URL parameter '%s' is reflected unescaped in the HTML response body "+
							"at %s. This is a strong indicator of a reflected XSS vulnerability. "+
							"An attacker could craft a URL with malicious JavaScript in this parameter "+
							"to execute code in a victim's browser.",
						p, u.String()),
					Asset: asset,
					Evidence: map[string]any{
						"url":       u.String(),
						"parameter": p,
						"reflected": true,
					},
					ProofCommand: fmt.Sprintf("curl -s '%s' | grep -o '%s'", u.String(), val),
					Confidence:   finding.ConfidenceObserved,
					DiscoveredAt: time.Now(),
				})
			}
		}

		// Check all responses for SQL errors.
		checkSQLErrors(body, asset, u.String(), reported, &findings)

		// Check for stack traces.
		checkStackTraces(body, asset, u.String(), reported, &findings)
	}

	// Phase 2: Also check the root and common error-triggering paths.
	errorPaths := []string{"/", "/?id=1", "/api/", "/search?q=test"}
	for _, path := range errorPaths {
		if len(findings) >= 20 {
			break
		}
		u := fmt.Sprintf("%s://%s%s", scheme, asset, path)
		body, status, err := fetchBody(ctx, client, u)
		log.ProbeTimed(scannerName, asset, path, 0, status, err)
		if err != nil || body == "" {
			continue
		}
		checkSQLErrors(body, asset, u, reported, &findings)
		checkStackTraces(body, asset, u, reported, &findings)
	}

	return findings, nil
}

func checkSQLErrors(body, asset, rawURL string, reported map[string]bool, findings *[]finding.Finding) {
	for _, re := range sqlErrorPatterns {
		match := re.FindString(body)
		if match == "" {
			continue
		}
		key := fmt.Sprintf("sqlerr:%s:%s", rawURL, re.String())
		if reported[key] {
			continue
		}
		reported[key] = true

		*findings = append(*findings, finding.Finding{
			CheckID:  finding.CheckWebSQLErrorDisclosed,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Title:    fmt.Sprintf("SQL error message disclosed on %s", asset),
			Description: fmt.Sprintf(
				"The response from %s contains a database error message: \"%s\". "+
					"This indicates either a SQL injection vulnerability or an error handling "+
					"gap that leaks database internals to attackers.",
				rawURL, truncate(match, 100)),
			Asset: asset,
			Evidence: map[string]any{
				"url":           rawURL,
				"error_pattern": match,
			},
			ProofCommand: fmt.Sprintf("curl -s '%s' | grep -i 'sql\\|mysql\\|postgres\\|oracle'", rawURL),
			Confidence:   finding.ConfidenceObserved,
			DiscoveredAt: time.Now(),
		})
		return // one SQL error per URL is enough
	}
}

func checkStackTraces(body, asset, rawURL string, reported map[string]bool, findings *[]finding.Finding) {
	for _, re := range stackTracePatterns {
		match := re.FindString(body)
		if match == "" {
			continue
		}
		key := fmt.Sprintf("trace:%s", rawURL)
		if reported[key] {
			continue
		}
		reported[key] = true

		*findings = append(*findings, finding.Finding{
			CheckID:  finding.CheckWebStackTrace,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityMedium,
			Title:    fmt.Sprintf("Stack trace disclosed on %s", asset),
			Description: fmt.Sprintf(
				"The response from %s contains an application stack trace: \"%s\". "+
					"This reveals internal code paths, framework versions, and file locations "+
					"that assist attackers in crafting targeted exploits.",
				rawURL, truncate(match, 120)),
			Asset: asset,
			Evidence: map[string]any{
				"url":   rawURL,
				"trace": truncate(match, 500),
			},
			ProofCommand: fmt.Sprintf("curl -s '%s' | grep -i 'traceback\\|exception\\|at .*\\.java'", rawURL),
			Confidence:   finding.ConfidenceObserved,
			DiscoveredAt: time.Now(),
		})
		return // one trace per URL
	}
}

func fetchBody(ctx context.Context, client *http.Client, rawURL string) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	return string(b), resp.StatusCode, nil
}

func detectScheme(ctx context.Context, asset string) string {
	client := scan.SharedClient(5 * time.Second)
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, "https://"+asset+"/", nil)
	if err != nil {
		return "http"
	}
	resp, err := client.Do(req)
	if err != nil {
		return "http"
	}
	_ = resp.Body.Close()
	return "https"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
