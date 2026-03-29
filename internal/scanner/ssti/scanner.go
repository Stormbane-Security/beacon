// Package ssti probes for Server-Side Template Injection in HTTP parameters.
// It sends mathematical expression payloads in common query parameters and
// checks whether the server evaluates them — a reliable signal that user
// input flows into a template engine without sanitisation.
//
// Active exploitation probes require ScanAuthorized mode (--authorized flag).
// ScanAuthorized only (active payloads).
package ssti

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const (
	scannerName = "ssti"
	maxBodySize = 32 * 1024 // 32 KB
)

// probePaths are the URL paths injected with template payloads.
var probePaths = []string{
	"/",
	"/search",
	"/api/v1/search",
	"/render",
	"/template",
	"/preview",
	"/api/render",
	"/api/preview",
}

// probeParams are the query parameter names used for injection.
var probeParams = []string{
	"q", "query", "search", "name", "input",
	"text", "template", "content", "message", "subject", "body",
}

// payload pairs a template expression with its expected evaluated output.
type payload struct {
	expr    string
	expect  string
	engine  string
}

var payloads = []payload{
	{expr: "{{7*7}}", expect: "49", engine: "Jinja2/Twig"},
	{expr: "${7*7}", expect: "49", engine: "FreeMarker/EL"},
	{expr: "<%= 7*7 %>", expect: "49", engine: "ERB/JSP"},
	{expr: "#{7*7}", expect: "49", engine: "Ruby/Pebble"},
	{expr: "{{7*'7'}}", expect: "7777777", engine: "Jinja2"},
	// Polyglot payload — triggers across multiple template engines simultaneously.
	// If any engine evaluates the embedded expression, "49" appears in the response.
	{expr: `${{<%[%'"}}%\`, expect: "49", engine: "Polyglot"},
	// Engine-specific additional payloads
	{expr: "${7*7}", expect: "49", engine: "Java EL"},
}

// wordBoundary49 matches "49" as a standalone word (not part of a longer number).
var wordBoundary49 = regexp.MustCompile(`\b49\b`)

// wordBoundary7777777 matches "7777777" as a standalone word.
var wordBoundary7777777 = regexp.MustCompile(`\b7777777\b`)

// Scanner probes for server-side template injection vulnerabilities.
type Scanner struct{}

// New returns a new Scanner.
func New() *Scanner { return &Scanner{} }

// Name returns the stable scanner identifier.
func (s *Scanner) Name() string { return scannerName }

// Run executes the SSTI scan. Only runs in deep mode.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	// Exploitation probes require --authorized (beyond --deep).
	if scanType != module.ScanAuthorized {
		return nil, nil
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	scheme := detectScheme(ctx, client, asset)
	base := scheme + "://" + asset

	var findings []finding.Finding

	for _, path := range probePaths {
		// Cheap pre-check: skip paths that return 404.
		if isNotFound(ctx, client, base+path) {
			continue
		}

		for _, param := range probeParams {
			for _, p := range payloads {
				u := base + path + "?" + param + "=" + url.QueryEscape(p.expr)
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
				if err != nil {
					continue
				}

				resp, err := client.Do(req)
				if err != nil {
					continue
				}

				body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
				resp.Body.Close()

				if resp.StatusCode == http.StatusNotFound {
					continue
				}

				bodyStr := string(body)
				if !evaluatedInBody(p.expect, bodyStr) {
					continue
				}

				// Delta check: fetch the page without injection and count
				// baseline occurrences. Only flag if the injected response
				// has MORE occurrences — handles pages that naturally contain
				// "49" (e.g. "49 results") without false-positive suppression.
				baselineCount := baselineOccurrences(ctx, client, base+path, p.expect)
				injectedCount := countOccurrences(p.expect, bodyStr)
				if injectedCount <= baselineCount {
					continue
				}

				findings = append(findings, finding.Finding{
					CheckID:  finding.CheckWebSSTI,
					Module:   "deep",
					Scanner:  scannerName,
					Severity: finding.SeverityCritical,
					Title:    fmt.Sprintf("Server-Side Template Injection (%s) via parameter %q", p.engine, param),
					Description: fmt.Sprintf(
						"The parameter %q on path %s evaluates template expressions. "+
							"The payload %q was reflected as %q, indicating the application renders "+
							"user input through a %s template engine. An attacker can use this to "+
							"execute arbitrary code on the server.",
						param, path, p.expr, p.expect, p.engine),
					Asset:    asset,
					DeepOnly: true,
					ProofCommand: fmt.Sprintf(
						`curl -s "https://%s/search?q={{7*7}}" | grep -o '\b49\b'`, asset),
					Evidence: map[string]any{
						"url":     u,
						"path":    path,
						"param":   param,
						"payload": p.expr,
						"expect":  p.expect,
						"engine":  p.engine,
					},
					DiscoveredAt: time.Now(),
				})

				// One finding per path+param combo is enough.
				break
			}
		}
	}

	return findings, nil
}

// evaluatedInBody returns true when the expected math result appears in the
// response body as a standalone token (word-boundary match).
func evaluatedInBody(expect, body string) bool {
	switch expect {
	case "49":
		return wordBoundary49.MatchString(body)
	case "7777777":
		return wordBoundary7777777.MatchString(body)
	default:
		return strings.Contains(body, expect)
	}
}

// isNotFound returns true when the path returns HTTP 404.
func isNotFound(ctx context.Context, client *http.Client, rawURL string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusNotFound
}

// baselineOccurrences fetches the path without injection and returns the number
// of times expect appears in the response body (using the same word-boundary
// rules as evaluatedInBody). Returns 0 on any error.
func baselineOccurrences(ctx context.Context, client *http.Client, rawURL, expect string) int {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	resp.Body.Close()
	return countOccurrences(expect, string(body))
}

// countOccurrences returns the number of word-boundary matches of expect in body.
func countOccurrences(expect, body string) int {
	switch expect {
	case "49":
		return len(wordBoundary49.FindAllString(body, -1))
	case "7777777":
		return len(wordBoundary7777777.FindAllString(body, -1))
	default:
		return strings.Count(body, expect)
	}
}

// detectScheme tries HTTPS first, falling back to HTTP.
func detectScheme(ctx context.Context, client *http.Client, asset string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+asset, nil)
	if err != nil {
		return "http"
	}
	resp, err := client.Do(req)
	if err != nil {
		return "http"
	}
	resp.Body.Close()
	return "https"
}
