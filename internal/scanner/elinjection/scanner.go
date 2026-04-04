// Package elinjection probes for Expression Language injection in Java-based
// web applications. It detects SpEL (Spring Expression Language), OGNL
// (Object-Graph Navigation Language), and JSP/JSF EL injection by sending
// mathematical expression payloads and checking for evaluated results in the
// response body.
//
// The scanner first gates on Java detection: it checks for JSESSIONID cookies,
// Apache-Coyote/Tomcat server headers, and X-Powered-By: Servlet indicators.
// If no Java signals are found, the scanner exits early.
//
// ScanDeep and ScanAuthorized only (active injection payloads).
package elinjection

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/scan"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanner/schemedetect"
)


func init() {
	scan.RegisterWithCheckDecls(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	},
		scan.Check(finding.CheckWebELInjection, finding.SeverityCritical, finding.ModeDeep),
		scan.Check(finding.CheckWebOGNLInjection, finding.SeverityCritical, finding.ModeDeep),
		scan.Check(finding.CheckWebSpELInjection, finding.SeverityCritical, finding.ModeDeep),
	)
}
const (
	scannerName = "elinjection"
	maxBodySize = 32 * 1024 // 32 KB
)

// probePaths are URL paths to test for EL injection.
var probePaths = []string{
	"/",
	"/search",
	"/login",
	"/api/v1/search",
	"/api/v1/query",
	"/query",
	"/action",
	"/process",
	"/submit",
}

// probeParams are query parameter names used for injection in GET requests.
var probeParams = []string{
	"q", "query", "search", "input", "name",
	"value", "text", "data", "param", "expression",
	"filter", "id", "action",
}

// headerInjectionPoints are HTTP headers where EL payloads may be evaluated.
var headerInjectionPoints = []string{
	"User-Agent",
	"Referer",
}

// payload pairs an EL expression with its expected evaluated output, the
// engine it targets, and the corresponding check ID.
type payload struct {
	expr    string
	expect  string
	engine  string
	checkID finding.CheckID
}

// payloads are the EL injection test expressions. The math expressions
// use 7*7=49 which is unlikely to appear naturally in page content.
var payloads = []payload{
	// SpEL (Spring Expression Language)
	{expr: "${7*7}", expect: "49", engine: "SpEL", checkID: finding.CheckWebSpELInjection},
	{expr: "#{7*7}", expect: "49", engine: "SpEL", checkID: finding.CheckWebSpELInjection},
	{expr: "${T(java.lang.Runtime)}", expect: "java.lang.Runtime", engine: "SpEL", checkID: finding.CheckWebSpELInjection},

	// OGNL (Object-Graph Navigation Language — Struts, Confluence)
	{expr: "%{7*7}", expect: "49", engine: "OGNL", checkID: finding.CheckWebOGNLInjection},
	{expr: "${#context}", expect: "OgnlContext", engine: "OGNL", checkID: finding.CheckWebOGNLInjection},

	// JSP/JSF EL (generic Java Expression Language)
	{expr: "${7*7}", expect: "49", engine: "Java EL", checkID: finding.CheckWebELInjection},
	{expr: "#{7*7}", expect: "49", engine: "Java EL", checkID: finding.CheckWebELInjection},
}

// wordBoundary49 matches "49" as a standalone token (not part of a larger number).
var wordBoundary49 = regexp.MustCompile(`\b49\b`)

// javaSignals are HTTP response indicators that the target runs a Java stack.
var javaSignals = []string{
	"jsessionid",
	"apache-coyote",
	"tomcat",
	"x-powered-by: servlet",
	"x-powered-by: jsp",
	"jboss",
	"wildfly",
	"glassfish",
	"weblogic",
	"jetty",
}

// Scanner probes for Expression Language injection vulnerabilities.
type Scanner struct{}

// New returns a new Scanner.
func New() *Scanner { return &Scanner{} }

// Name returns the stable scanner identifier.
func (s *Scanner) Name() string { return scannerName }

// Run executes the EL injection scan. Only runs in deep or authorized mode.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanDeep && scanType != module.ScanAuthorized {
		return nil, nil
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec
			},
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	base := schemedetect.Base(ctx, client, asset)

	// ── Java detection gate ─────────────────────────────────────────────
	// Only probe for EL injection if the target shows Java indicators.
	if !isJavaTarget(ctx, client, base) {
		return nil, nil
	}

	var findings []finding.Finding

	// ── Query parameter injection ───────────────────────────────────────
	for _, path := range probePaths {
		if ctx.Err() != nil {
			break
		}

		// Skip paths that return 404.
		if isNotFound(ctx, client, base+path) {
			continue
		}

		// Measure baseline occurrence count for "49" on this path.
		baselineCount := countBaseline49(ctx, client, base+path)

		for _, param := range probeParams {
			for _, p := range payloads {
				if ctx.Err() != nil {
					break
				}

				u := base + path + "?" + param + "=" + url.QueryEscape(p.expr)
				status, body := doGet(ctx, client, u)
				if status == http.StatusNotFound || len(body) == 0 {
					continue
				}

				if !containsExpected(p.expect, body) {
					continue
				}

				// Delta check: only flag if the injected response has MORE
				// occurrences than the baseline to avoid false positives.
				if p.expect == "49" {
					injectedCount := len(wordBoundary49.FindAllString(body, -1))
					if injectedCount <= baselineCount {
						continue
					}
				}

				findings = append(findings, finding.Finding{
					CheckID:  p.checkID,
					Module:   "deep",
					Scanner:  scannerName,
					Severity: finding.SeverityCritical,
					Title:    fmt.Sprintf("%s injection via parameter %q on %s%s", p.engine, param, asset, path),
					Description: fmt.Sprintf(
						"The parameter %q on path %s evaluates %s expressions. "+
							"The payload %q was evaluated and %q appeared in the response, "+
							"indicating user input flows into the expression evaluation engine. "+
							"An attacker can use this to execute arbitrary code on the server.",
						param, path, p.engine, p.expr, p.expect),
					Asset:    asset,
					DeepOnly: true,
					ProofCommand: fmt.Sprintf(
						`curl -sk '%s%s?%s=%s'`, base, path, param, url.QueryEscape(p.expr)),
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

				// One finding per path+param is enough.
				goto nextParam
			}
		nextParam:
		}
	}

	// ── Header injection ────────────────────────────────────────────────
	// Inject EL payloads in User-Agent and Referer headers.
	for _, path := range probePaths {
		if ctx.Err() != nil {
			break
		}

		if isNotFound(ctx, client, base+path) {
			continue
		}

		baselineCount := countBaseline49(ctx, client, base+path)

		for _, header := range headerInjectionPoints {
			for _, p := range payloads {
				if ctx.Err() != nil {
					break
				}

				u := base + path
				status, body := doGetWithHeader(ctx, client, u, header, p.expr)
				if status == http.StatusNotFound || len(body) == 0 {
					continue
				}

				if !containsExpected(p.expect, body) {
					continue
				}

				if p.expect == "49" {
					injectedCount := len(wordBoundary49.FindAllString(body, -1))
					if injectedCount <= baselineCount {
						continue
					}
				}

				findings = append(findings, finding.Finding{
					CheckID:  p.checkID,
					Module:   "deep",
					Scanner:  scannerName,
					Severity: finding.SeverityCritical,
					Title:    fmt.Sprintf("%s injection via %s header on %s%s", p.engine, header, asset, path),
					Description: fmt.Sprintf(
						"The %s header on path %s is evaluated as a %s expression. "+
							"The payload %q injected in the %s header produced %q in the "+
							"response body. An attacker can execute arbitrary code on the server "+
							"by sending a crafted %s header.",
						header, path, p.engine, p.expr, header, p.expect, header),
					Asset:    asset,
					DeepOnly: true,
					ProofCommand: fmt.Sprintf(
						`curl -sk -H '%s: %s' '%s%s'`, header, p.expr, base, path),
					Evidence: map[string]any{
						"url":     u,
						"path":    path,
						"header":  header,
						"payload": p.expr,
						"expect":  p.expect,
						"engine":  p.engine,
					},
					DiscoveredAt: time.Now(),
				})

				// One finding per path+header is enough.
				goto nextHeader
			}
		nextHeader:
		}
	}

	// ── POST body injection ─────────────────────────────────────────────
	for _, path := range probePaths {
		if ctx.Err() != nil {
			break
		}

		if isNotFound(ctx, client, base+path) {
			continue
		}

		baselineCount := countBaseline49(ctx, client, base+path)

		for _, param := range probeParams {
			for _, p := range payloads {
				if ctx.Err() != nil {
					break
				}

				u := base + path
				postBody := param + "=" + url.QueryEscape(p.expr)
				status, body := doPost(ctx, client, u, postBody)
				if status == http.StatusNotFound || len(body) == 0 {
					continue
				}

				if !containsExpected(p.expect, body) {
					continue
				}

				if p.expect == "49" {
					injectedCount := len(wordBoundary49.FindAllString(body, -1))
					if injectedCount <= baselineCount {
						continue
					}
				}

				findings = append(findings, finding.Finding{
					CheckID:  p.checkID,
					Module:   "deep",
					Scanner:  scannerName,
					Severity: finding.SeverityCritical,
					Title:    fmt.Sprintf("%s injection via POST %q on %s%s", p.engine, param, asset, path),
					Description: fmt.Sprintf(
						"The POST parameter %q on path %s evaluates %s expressions. "+
							"The payload %q was evaluated and %q appeared in the response, "+
							"indicating server-side expression evaluation of user-controlled input.",
						param, path, p.engine, p.expr, p.expect),
					Asset:    asset,
					DeepOnly: true,
					ProofCommand: fmt.Sprintf(
						`curl -sk -X POST -d '%s=%s' '%s%s'`, param, url.QueryEscape(p.expr), base, path),
					Evidence: map[string]any{
						"url":     u,
						"path":    path,
						"param":   param,
						"method":  "POST",
						"payload": p.expr,
						"expect":  p.expect,
						"engine":  p.engine,
					},
					DiscoveredAt: time.Now(),
				})

				// One finding per path+param POST is enough.
				goto nextPostParam
			}
		nextPostParam:
		}
	}

	return findings, nil
}

// isJavaTarget probes the root of the target for Java application indicators:
// JSESSIONID cookie, Apache-Coyote/Tomcat server header, Servlet X-Powered-By.
func isJavaTarget(ctx context.Context, client *http.Client, base string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/", nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024)) //nolint:errcheck
	_ = resp.Body.Close()

	// Check response headers.
	headerStr := strings.ToLower(fmt.Sprintf("%v", resp.Header))
	for _, sig := range javaSignals {
		if strings.Contains(headerStr, sig) {
			return true
		}
	}

	// Check cookies for JSESSIONID.
	for _, cookie := range resp.Cookies() {
		if strings.EqualFold(cookie.Name, "JSESSIONID") {
			return true
		}
	}

	return false
}

// isNotFound returns true when the path returns HTTP 404.
func isNotFound(ctx context.Context, client *http.Client, rawURL string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner/1.0)")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024)) //nolint:errcheck
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusNotFound
}

// doGet performs a GET request and returns the status code and body string.
func doGet(ctx context.Context, client *http.Client, rawURL string) (int, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return 0, ""
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	_ = resp.Body.Close()

	return resp.StatusCode, string(body)
}

// doGetWithHeader performs a GET request with a custom header value and returns
// the status code and body string.
func doGetWithHeader(ctx context.Context, client *http.Client, rawURL, header, value string) (int, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner/1.0)")
	req.Header.Set(header, value)

	resp, err := client.Do(req)
	if err != nil {
		return 0, ""
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	_ = resp.Body.Close()

	return resp.StatusCode, string(body)
}

// doPost performs a POST request with form-encoded body and returns the status
// code and body string.
func doPost(ctx context.Context, client *http.Client, rawURL, postBody string) (int, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, strings.NewReader(postBody))
	if err != nil {
		return 0, ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner/1.0)")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return 0, ""
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	_ = resp.Body.Close()

	return resp.StatusCode, string(body)
}

// containsExpected checks whether the expected evaluation result is present
// in the response body, using word-boundary matching for numeric results.
func containsExpected(expect, body string) bool {
	switch expect {
	case "49":
		return wordBoundary49.MatchString(body)
	default:
		return strings.Contains(body, expect)
	}
}

// countBaseline49 fetches the path without injection and counts baseline
// occurrences of "49" with word-boundary matching.
func countBaseline49(ctx context.Context, client *http.Client, rawURL string) int {
	_, body := doGet(ctx, client, rawURL)
	return len(wordBoundary49.FindAllString(body, -1))
}
