// Package errordisclosure detects information leakage through verbose error
// responses. It triggers error conditions by requesting non-existent paths,
// sending malformed input, and probing debug endpoints — then inspects
// responses for stack traces, framework internals, database errors, and
// debug mode indicators.
//
// Surface mode only — all probes are safe GET/POST requests that any web
// crawler might send. No exploitation payloads.
package errordisclosure

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
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
		scan.Check(finding.CheckWebDebugEndpoint, finding.SeverityHigh, finding.ModeSurface),
		scan.Check(finding.CheckWebErrorInfoLeak, finding.SeverityMedium, finding.ModeSurface),
	)
}
const (
	scannerName = "errordisclosure"
	maxBodyRead = 64 * 1024
)

// errorPaths trigger error responses on common frameworks.
var errorPaths = []string{
	"/does-not-exist-beacon-probe-404",
	"/%00",                // null byte → parser errors
	"/..%252f",            // double-encoded traversal → framework error
	"/?id=1'",             // SQL-like input → error page
	"/api/v1/",            // API root → may expose framework info
	"/api/v1/data",        // common data endpoint → may throw on empty request
	"/api/data",           // common data endpoint
	"/undefined",          // common 404
	"/test.php",           // PHP errors
	"/test.asp",           // ASP errors
	"/test.jsp",           // JSP errors
}

// debugPaths are endpoints that reveal debug/diagnostic info when left enabled.
var debugPaths = []string{
	"/debug",
	"/debug/vars",
	"/debug/pprof/",
	"/_debug",
	"/phpinfo.php",
	"/server-info",
	"/server-status",
	"/elmah.axd",
	"/__debug__/",
	"/_profiler/",
	"/actuator/env",
	"/actuator/configprops",
	"/actuator/trace",
	"/actuator/httptrace",
}

// stackTracePatterns match language-specific stack trace signatures.
var stackTracePatterns = []*regexp.Regexp{
	// Java
	regexp.MustCompile(`(?i)at\s+[\w.$]+\.\w+\([\w.]+:\d+\)`),
	regexp.MustCompile(`(?i)java\.\w+\.[\w.]+Exception`),
	regexp.MustCompile(`(?i)javax?\.\w+\.\w+`),
	regexp.MustCompile(`(?i)org\.springframework\.\w+`),
	// Python
	regexp.MustCompile(`(?i)Traceback \(most recent call last\)`),
	regexp.MustCompile(`(?i)File "[\w/\\.]+", line \d+`),
	// PHP
	regexp.MustCompile(`(?i)Fatal error:.*on line \d+`),
	regexp.MustCompile(`(?i)Stack trace:#\d+`),
	regexp.MustCompile(`(?i)<b>Warning</b>:.*on line <b>\d+</b>`),
	// .NET/C#
	regexp.MustCompile(`(?i)System\.\w+Exception:`),
	regexp.MustCompile(`(?i)at \w+\.\w+\.\w+\(.*\) in [\w\\/:]+:\d+`),
	regexp.MustCompile(`(?i)Server Error in '/' Application`),
	// Ruby
	regexp.MustCompile(`(?i)\w+Error:.*\n.*\.rb:\d+`),
	// Node.js
	regexp.MustCompile(`(?i)at \w+ \([\w/\\.]+:\d+:\d+\)`),
	regexp.MustCompile(`(?i)at Object\.<anonymous> \(`),
	// Go
	regexp.MustCompile(`goroutine \d+ \[`),
	regexp.MustCompile(`(?i)\.go:\d+`),
}

// errorKeywords indicate verbose error responses (case-insensitive check).
var errorKeywords = []string{
	"stack trace",
	"debug mode",
	"debug = true",
	"debug=true",
	"django.core",
	"werkzeug debugger",
	"laravel",
	"symfony profiler",
	"internal server error",
	"database error",
	"sql syntax",
	"sqlstate",
	"syntax error at or near",
	"uncaught exception",
	"unhandled exception",
	"application error",
	"detailed error",
	"exception details",
	"connection string",
	"password=",
	"db_password",
	"secret_key",
	"app_key",
}

// debugKeywords identify debug/diagnostic endpoint content.
var debugKeywords = []string{
	"cmdline",
	"memstats",
	"goroutines",
	"phpinfo()",
	"php version",
	"configuration file",
	"server_software",
	"document_root",
	"server_admin",
	"spring boot",
	"active profiles",
	"elmah",
	"debug toolbar",
	"profiler",
}

type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	// Surface mode only — safe probes.
	if scanType != module.ScanSurface && scanType != module.ScanDeep && scanType != module.ScanAuthorized {
		return nil, nil
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if c := authctx.HTTPClient(ctx); c != nil {
		client = c
	}

	base := schemedetect.Base(ctx, client, asset)

	var findings []finding.Finding

	// Check error paths for stack traces and verbose errors.
	for _, path := range errorPaths {
		f := s.probeErrorPath(ctx, client, base, path, asset)
		if f != nil {
			findings = append(findings, *f)
			break // one finding is enough proof
		}
	}

	// Check debug endpoints.
	for _, path := range debugPaths {
		f := s.probeDebugPath(ctx, client, base, path, asset)
		if f != nil {
			findings = append(findings, *f)
			break // one finding is enough
		}
	}

	return findings, nil
}

func (s *Scanner) probeErrorPath(ctx context.Context, client *http.Client, base, path, asset string) *finding.Finding {
	url := base + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "text/html, application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner)")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, int64(maxBodyRead)))
	bodyStr := string(body)
	bodyLower := strings.ToLower(bodyStr)

	// Check for stack trace patterns.
	for _, re := range stackTracePatterns {
		if match := re.FindString(bodyStr); match != "" {
			return &finding.Finding{
				CheckID:  finding.CheckWebErrorInfoLeak,
				Module:   "surface",
				Scanner:  scannerName,
				Severity: finding.SeverityMedium,
				Title:    fmt.Sprintf("Stack trace exposed in error response at %s", path),
				Description: "The server returns a stack trace or framework exception details in its " +
					"error response. This reveals internal implementation details (file paths, " +
					"class names, line numbers, framework version) that help attackers map the " +
					"application internals and craft targeted exploits.",
				Asset: asset,
				ProofCommand: fmt.Sprintf("curl -si '%s'", url),
				Evidence: map[string]any{
					"url":           url,
					"status":        resp.StatusCode,
					"matched":       match,
					"response_size": len(body),
				},
				DiscoveredAt: time.Now(),
			}
		}
	}

	// Check for verbose error keywords.
	for _, kw := range errorKeywords {
		if strings.Contains(bodyLower, kw) {
			// Filter false positives: generic 404 pages often say "internal server error"
			// in a template — require at least 2 keywords or a high-value keyword.
			if kw == "internal server error" && countKeywordMatches(bodyLower) < 2 {
				continue
			}
			return &finding.Finding{
				CheckID:  finding.CheckWebErrorInfoLeak,
				Module:   "surface",
				Scanner:  scannerName,
				Severity: finding.SeverityMedium,
				Title:    fmt.Sprintf("Verbose error information disclosed at %s", path),
				Description: "The server error response contains detailed error information " +
					"(database errors, framework names, configuration details) that reveals " +
					"internal implementation details. This information helps attackers " +
					"identify the technology stack and potential attack vectors.",
				Asset: asset,
				ProofCommand: fmt.Sprintf("curl -si '%s'", url),
				Evidence: map[string]any{
					"url":           url,
					"status":        resp.StatusCode,
					"keyword_match": kw,
					"response_size": len(body),
				},
				DiscoveredAt: time.Now(),
			}
		}
	}

	return nil
}

func (s *Scanner) probeDebugPath(ctx context.Context, client *http.Client, base, path, asset string) *finding.Finding {
	url := base + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "text/html, application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner)")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	// Debug endpoints should not return 200 on production systems.
	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, int64(maxBodyRead)))
	bodyLower := strings.ToLower(string(body))

	// Must contain debug-specific content, not just a 200 from a catch-all.
	for _, kw := range debugKeywords {
		if strings.Contains(bodyLower, kw) {
			return &finding.Finding{
				CheckID:  finding.CheckWebDebugEndpoint,
				Module:   "surface",
				Scanner:  scannerName,
				Severity: finding.SeverityHigh,
				Title:    fmt.Sprintf("Debug/diagnostic endpoint exposed at %s", path),
				Description: "A debug or diagnostic endpoint is accessible in the production environment. " +
					"These endpoints expose sensitive internal state (memory usage, environment " +
					"variables, configuration, profiling data) and should be disabled or restricted " +
					"to internal networks in production.",
				Asset: asset,
				ProofCommand: fmt.Sprintf("curl -si '%s'", url),
				Evidence: map[string]any{
					"url":           url,
					"status":        resp.StatusCode,
					"keyword_match": kw,
					"response_size": len(body),
				},
				DiscoveredAt: time.Now(),
			}
		}
	}

	return nil
}

// countKeywordMatches returns how many errorKeywords appear in the body.
func countKeywordMatches(bodyLower string) int {
	count := 0
	for _, kw := range errorKeywords {
		if strings.Contains(bodyLower, kw) {
			count++
		}
	}
	return count
}
