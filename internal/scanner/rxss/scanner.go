// Package rxss implements a deep-mode scanner for reflected cross-site scripting
// (XSS) vulnerabilities. It injects canary strings into URL parameters discovered
// from crawl results and common fallback lists, then checks whether the canary
// appears unescaped in the HTML response body. When a reflection is confirmed,
// context-specific payloads are tested to verify exploitability.
package rxss

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scan"
	"github.com/stormbane-security/beacon/internal/scanner/authctx"
	"github.com/stormbane-security/beacon/internal/scanner/paramdiscovery"
)

func init() {
	scan.RegisterWithCheckDecls(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	},
		scan.Check(finding.CheckWebReflectedXSS, finding.SeverityHigh, finding.ModeDeep),
	)
}

const (
	scannerName = "rxss"
	canary      = "beacon<xss>7f3a"
	maxBodySize = 128 * 1024 // 128 KB
	maxParams   = 50
)

// fallbackParams are common parameter names tested when crawl results provide
// no discovered parameters.
var fallbackParams = []string{
	"q", "search", "query", "id", "name", "page", "redirect", "url", "next",
	"callback", "file", "path", "lang", "ref", "s", "keyword", "term", "input",
	"value", "data", "msg", "error", "text", "user", "email", "username",
	"token", "action", "type", "category", "sort", "order", "limit", "offset",
	"filter", "format", "template", "view", "mode", "tab", "step", "return",
	"continue", "target", "dest", "go", "redir", "out", "site", "feed", "tag", "p",
}

// contextPayload describes a context-specific XSS payload.
type contextPayload struct {
	name    string // human-readable context description
	payload string // injected string
	context string // html, attribute, javascript
}

var contextPayloads = []contextPayload{
	{name: "HTML tag injection", payload: `<img src=x onerror=alert(1)>`, context: "html"},
	{name: "Attribute breakout", payload: `" onmouseover="alert(1)`, context: "attribute"},
	{name: "JavaScript string breakout", payload: `';alert(1)//`, context: "javascript"},
}

// Scanner checks for reflected XSS vulnerabilities.
type Scanner struct{}

// New returns a new Scanner.
func New() *Scanner { return &Scanner{} }

// Name returns the stable scanner identifier.
func (s *Scanner) Name() string { return scannerName }

// Run executes the reflected XSS scan. Only runs in deep or authorized mode.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanDeep && scanType != module.ScanAuthorized {
		return nil, nil
	}

	ac := authctx.HTTPClient(ctx)
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: ac.Transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if client.Transport == nil {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		}
	}

	scheme := detectScheme(ctx, client, asset)

	// Build path→params map from discovered parameters + fallback.
	pathParams := buildPathParams(ctx)

	var findings []finding.Finding

	// Phase 1: Filter to reachable paths to avoid wasting the test budget
	// on 404s. Then test high-value params breadth-first across paths.
	highValueParams := []string{"q", "search", "query", "s", "keyword", "name",
		"id", "input", "text", "msg", "error", "redirect", "url", "callback"}
	tested := 0

	// Discover which paths are reachable (avoid 404 budget waste)
	reachable := make(map[string]bool)
	for path := range pathParams {
		base := scheme + "://" + asset + path
		if s.pathReachable(ctx, client, base) {
			reachable[path] = true
		}
	}

	// Test discovered params first (highest priority — user's app-specific params)
	discovered := paramdiscovery.DiscoveredParamsFromContext(ctx)
	for path, params := range discovered {
		if !reachable[path] || tested >= maxParams {
			continue
		}
		base := scheme + "://" + asset + path
		for _, param := range params {
			if tested >= maxParams {
				break
			}
			tested++
			fs := s.testParam(ctx, client, base, param)
			if len(fs) > 0 {
				findings = append(findings, fs...)
				break
			}
		}
	}

	// Then test high-value params breadth-first across all reachable paths.
	for path := range pathParams {
		if !reachable[path] || tested >= maxParams {
			continue
		}
		base := scheme + "://" + asset + path
		for _, param := range highValueParams {
			if tested >= maxParams {
				break
			}
			tested++
			fs := s.testParam(ctx, client, base, param)
			if len(fs) > 0 {
				findings = append(findings, fs...)
				break
			}
		}
	}

	// Phase 2: Depth — remaining fallback params on reachable paths.
	hvSet := make(map[string]bool)
	for _, p := range highValueParams {
		hvSet[p] = true
	}
	for path, params := range pathParams {
		if !reachable[path] || tested >= maxParams {
			continue
		}
		base := scheme + "://" + asset + path
		for _, param := range params {
			if hvSet[param] {
				continue
			}
			if tested >= maxParams {
				break
			}
			tested++
			fs := s.testParam(ctx, client, base, param)
			if len(fs) > 0 {
				findings = append(findings, fs...)
				break
			}
		}
	}

	return findings, nil
}

// testParam injects the canary into the given parameter via GET and POST,
// then escalates with context-specific payloads if the canary reflects.
func (s *Scanner) testParam(ctx context.Context, client *http.Client, baseURL, param string) []finding.Finding {
	var findings []finding.Finding

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		body, reqURL, err := s.inject(ctx, client, method, baseURL, param, canary)
		if err != nil {
			continue
		}

		if !strings.Contains(body, canary) {
			continue
		}

		// Canary reflected — try context-specific payloads.
		var confirmed bool
		for _, cp := range contextPayloads {
			payloadBody, payloadURL, payloadErr := s.inject(ctx, client, method, baseURL, param, cp.payload)
			if payloadErr != nil {
				continue
			}

			if !strings.Contains(payloadBody, cp.payload) {
				continue
			}

			// Full payload reflected — confirmed XSS.
			confirmed = true
			sev := finding.SeverityHigh
			if cp.context == "javascript" {
				sev = finding.SeverityCritical
			}

			snippet := extractSnippet(payloadBody, cp.payload, 80)

			evidence := map[string]any{
				"parameter":   param,
				"method":      method,
				"payload":     cp.payload,
				"context":     cp.context,
				"url":         payloadURL,
				"reflected":   snippet,
				"confidence":  "verified",
			}

			findings = append(findings, finding.Finding{
				CheckID:     finding.CheckWebReflectedXSS,
				Module:      "deep",
				Scanner:     scannerName,
				Severity:    sev,
				Title:       fmt.Sprintf("Reflected XSS via %s parameter %q (%s context)", method, param, cp.context),
				Description: fmt.Sprintf("The parameter %q reflects user input without encoding in %s context. "+
					"The payload %q was fully reflected in the response body, confirming exploitable cross-site scripting. "+
					"An attacker can craft a URL that executes arbitrary JavaScript in the victim's browser session.", param, cp.context, cp.payload),
				Asset:        extractAsset(baseURL),
				DeepOnly:     true,
				Evidence:     evidence,
				ProofCommand: buildProofCommand(method, baseURL, param, cp.payload),
				DiscoveredAt: time.Now(),
			})
		}

		// If no context-specific payload confirmed, emit a lower-confidence
		// finding for the canary reflection alone.
		if !confirmed {
			snippet := extractSnippet(body, canary, 80)
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckWebReflectedXSS,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityHigh,
				Title:    fmt.Sprintf("Reflected XSS candidate via %s parameter %q (canary reflected)", method, param),
				Description: fmt.Sprintf("The parameter %q reflects the canary string %q without HTML encoding. "+
					"Context-specific payloads were not fully reflected, but the unencoded reflection indicates "+
					"a likely XSS vulnerability that may be exploitable with alternate payloads.", param, canary),
				Asset:    extractAsset(baseURL),
				DeepOnly: true,
				Evidence: map[string]any{
					"parameter":  param,
					"method":     method,
					"canary":     canary,
					"url":        reqURL,
					"reflected":  snippet,
					"confidence": "probable",
				},
				ProofCommand: buildProofCommand(method, baseURL, param, canary),
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings
}

// inject sends a request with the payload in the given parameter and returns
// the response body as a string.
func (s *Scanner) inject(ctx context.Context, client *http.Client, method, baseURL, param, payload string) (string, string, error) {
	var req *http.Request
	var err error
	var reqURL string

	switch method {
	case http.MethodGet:
		u, parseErr := url.Parse(baseURL)
		if parseErr != nil {
			return "", "", parseErr
		}
		q := u.Query()
		q.Set(param, payload)
		u.RawQuery = q.Encode()
		reqURL = u.String()
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)

	case http.MethodPost:
		reqURL = baseURL
		form := url.Values{}
		form.Set(param, payload)
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, reqURL, strings.NewReader(form.Encode()))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}

	default:
		return "", "", fmt.Errorf("unsupported method: %s", method)
	}

	if err != nil {
		return "", "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	return string(body), reqURL, nil
}

// probePaths are common pages that accept user input and may reflect it.
var probePaths = []string{
	"/", "/search", "/search.php", "/login", "/register", "/contact",
	"/feedback", "/comment", "/profile", "/callback", "/redirect",
	"/api/search", "/api/v1/search", "/index.php",
}

// buildPathParams merges crawl-discovered parameters with the fallback list.
// Discovered params are placed first so they get priority before maxParams.
// Returns a map of path → parameter names.
func buildPathParams(ctx context.Context) map[string][]string {
	result := make(map[string][]string)
	discovered := paramdiscovery.DiscoveredParamsFromContext(ctx)

	// If we have discovered params, put them first on their respective paths,
	// then backfill with fallback params.
	if len(discovered) > 0 {
		for path, params := range discovered {
			seen := make(map[string]bool)
			var merged []string
			for _, p := range params {
				if !seen[p] {
					merged = append(merged, p)
					seen[p] = true
				}
			}
			for _, p := range fallbackParams {
				if !seen[p] {
					merged = append(merged, p)
					seen[p] = true
				}
			}
			result[path] = merged
		}
	}

	// Always add probe paths with fallback params so we test common
	// vulnerable endpoints even without crawl results.
	for _, path := range probePaths {
		if _, ok := result[path]; !ok {
			result[path] = append([]string{}, fallbackParams...)
		}
	}

	return result
}

// pathReachable does a quick HEAD/GET to check if the path returns a non-404 response.
func (s *Scanner) pathReachable(ctx context.Context, client *http.Client, baseURL string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	_ = resp.Body.Close()
	return resp.StatusCode < 400
}

// detectScheme tries HTTPS first, falling back to HTTP.
func detectScheme(ctx context.Context, client *http.Client, asset string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, "https://"+asset, nil)
	if err != nil {
		return "http"
	}
	resp, err := client.Do(req)
	if err != nil {
		return "http"
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	_ = resp.Body.Close()
	return "https"
}

// extractSnippet returns a substring of body centered on the first occurrence
// of needle, with up to margin characters on each side.
func extractSnippet(body, needle string, margin int) string {
	idx := strings.Index(body, needle)
	if idx < 0 {
		return ""
	}
	start := idx - margin
	if start < 0 {
		start = 0
	}
	end := idx + len(needle) + margin
	if end > len(body) {
		end = len(body)
	}
	return body[start:end]
}

// extractAsset pulls the host (with port) from a URL string.
func extractAsset(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Host
}

// buildProofCommand returns a curl command that reproduces the injection.
func buildProofCommand(method, baseURL, param, payload string) string {
	if method == http.MethodPost {
		return fmt.Sprintf("curl -si -X POST -d '%s=%s' '%s'",
			param, url.QueryEscape(payload), baseURL)
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return fmt.Sprintf("curl -si '%s?%s=%s'", baseURL, param, url.QueryEscape(payload))
	}
	q := u.Query()
	q.Set(param, payload)
	u.RawQuery = q.Encode()
	return fmt.Sprintf("curl -si '%s'", u.String())
}
