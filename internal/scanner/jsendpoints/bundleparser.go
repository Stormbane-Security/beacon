// Package jsendpoints — deep parser for webpack/vite/rollup JavaScript bundles.
//
// ParseBundle extracts API routes, WebSocket endpoints, hardcoded secrets,
// internal URLs, and source map references from minified JS bundle content.
// These are passive extractions from content the server already serves.
package jsendpoints

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// ── Types ──────────────────────────────────────────────────────────────────

// BundleFindings holds all extracted artifacts from a JS bundle.
type BundleFindings struct {
	APIEndpoints     []APIEndpoint
	WebSockets       []string
	HardcodedSecrets []Secret
	InternalURLs     []string
	SourceMaps       []string
}

// APIEndpoint is an API route extracted from JS source.
type APIEndpoint struct {
	Method string // GET, POST, PUT, DELETE, or "" if unknown
	Path   string // URL or path
	Source string // which JS file it was found in
}

// Secret is a hardcoded credential found in JS source.
type Secret struct {
	Type  string // "aws_key", "jwt", "api_key", "firebase", "generic_token"
	Value string // the matched secret (truncated for display)
	Line  string // surrounding context
}

// ── API endpoint extraction patterns ───────────────────────────────────────

// fetchPattern matches fetch("url") and fetch('url').
var fetchPattern = regexp.MustCompile("fetch\\s*\\(\\s*[\"']([^\"'\\s]{4,})[\"']")

// axiosPattern matches axios.get/post/put/delete/patch("url").
var axiosPattern = regexp.MustCompile("axios\\s*\\.\\s*(get|post|put|delete|patch)\\s*\\(\\s*[\"']([^\"'\\s]{4,})[\"']")

// xhrPattern matches xhr.open("METHOD", "url").
var xhrPattern = regexp.MustCompile("\\.open\\s*\\(\\s*[\"'](GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)[\"']\\s*,\\s*[\"']([^\"'\\s]{4,})[\"']")

// jqueryAjaxPattern matches $.ajax({url: "..."}).
var jqueryAjaxPattern = regexp.MustCompile("\\$\\s*\\.\\s*ajax\\s*\\(\\s*\\{[^}]*url\\s*:\\s*[\"']([^\"'\\s]{4,})[\"']")

// jqueryMethodPattern matches $.get/$.post("url").
var jqueryMethodPattern = regexp.MustCompile("\\$\\s*\\.\\s*(get|post)\\s*\\(\\s*[\"']([^\"'\\s]{4,})[\"']")

// restAPIPattern matches REST-style API paths: /api/v1/something.
var restAPIPattern = regexp.MustCompile("[\"'](/api/v[0-9]+/[a-zA-Z0-9/_-]+)[\"']")

// graphqlQueryPattern matches GraphQL query/mutation strings.

// graphqlEndpointPattern matches GraphQL endpoint URLs.
var graphqlEndpointPattern = regexp.MustCompile("[\"']((?:https?://[^\"'\\s]+)?/graphql(?:ql)?)[\"']")

// ── WebSocket patterns ─────────────────────────────────────────────────────

var wsPattern = regexp.MustCompile("new\\s+WebSocket\\s*\\(\\s*[\"'](wss?://[^\"'\\s]+)[\"']")

// Also match ws URLs in string literals without WebSocket constructor.
var wsURLPattern = regexp.MustCompile("[\"'](wss?://[a-zA-Z0-9._-]+(?::\\d+)?/[^\"'\\s]*)[\"']")

// ── Hardcoded secret patterns ──────────────────────────────────────────────

type secretPattern struct {
	name string
	re   *regexp.Regexp
}

var secretPatterns = []secretPattern{
	{"aws_key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"jwt", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*`)},
	{"api_key", regexp.MustCompile("(?i)api[_-]?key[\"':\\s]*[=:]\\s*[\"'][A-Za-z0-9]{20,}[\"']")},
	{"firebase", regexp.MustCompile("(?i)apiKey[\"':\\s]*[=:]\\s*[\"']AIza[A-Za-z0-9_-]{35}[\"']")},
	{"generic_token", regexp.MustCompile("(?i)(?:secret|token|password|auth)[_-]?(?:key)?[\"':\\s]*[=:]\\s*[\"'][A-Za-z0-9/+=]{20,}[\"']")},
	{"private_key", regexp.MustCompile(`-----BEGIN (?:RSA |EC )?PRIVATE KEY-----`)},
	{"github_token", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{36,}`)},
	{"slack_token", regexp.MustCompile(`xox[bpras]-[0-9]{10,}-[A-Za-z0-9-]+`)},
}

// ── Internal URL patterns ──────────────────────────────────────────────────

var internalURLPattern = regexp.MustCompile(
	"[\"']" +
		"(https?://" +
		"(?:localhost|127\\.0\\.0\\.1|0\\.0\\.0\\.0|" +
		"10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|" +
		"172\\.(?:1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}|" +
		"192\\.168\\.\\d{1,3}\\.\\d{1,3}|" +
		"[a-zA-Z0-9._-]+\\.(?:internal|local|dev|staging|test|localhost))" +
		"(?::\\d+)?" +
		"(?:/[^\"'\\s]*)?)" +
		"[\"']")

// ── Source map patterns ────────────────────────────────────────────────────

var sourceMapPattern = regexp.MustCompile(`//[#@]\s*sourceMappingURL\s*=\s*(\S+)`)

// ── ParseBundle ────────────────────────────────────────────────────────────

// ParseBundle extracts security-relevant artifacts from JS bundle content.
// source identifies the JS file for attribution.
func ParseBundle(jsContent string, source string) *BundleFindings {
	bf := &BundleFindings{}

	// --- API endpoints ---
	seenEndpoints := make(map[string]bool)

	addEndpoint := func(method, path string) {
		key := method + "|" + path
		if seenEndpoints[key] {
			return
		}
		seenEndpoints[key] = true
		bf.APIEndpoints = append(bf.APIEndpoints, APIEndpoint{
			Method: method,
			Path:   path,
			Source: source,
		})
	}

	// fetch("url")
	for _, m := range fetchPattern.FindAllStringSubmatch(jsContent, 100) {
		addEndpoint("", m[1])
	}

	// axios.get/post/put/delete("url")
	for _, m := range axiosPattern.FindAllStringSubmatch(jsContent, 100) {
		addEndpoint(strings.ToUpper(m[1]), m[2])
	}

	// xhr.open("METHOD", "url")
	for _, m := range xhrPattern.FindAllStringSubmatch(jsContent, 100) {
		addEndpoint(m[1], m[2])
	}

	// $.ajax({url: "..."})
	for _, m := range jqueryAjaxPattern.FindAllStringSubmatch(jsContent, 50) {
		addEndpoint("", m[1])
	}

	// $.get/$.post("url")
	for _, m := range jqueryMethodPattern.FindAllStringSubmatch(jsContent, 50) {
		addEndpoint(strings.ToUpper(m[1]), m[2])
	}

	// /api/v1/... paths
	for _, m := range restAPIPattern.FindAllStringSubmatch(jsContent, 100) {
		addEndpoint("", m[1])
	}

	// GraphQL endpoints
	for _, m := range graphqlEndpointPattern.FindAllStringSubmatch(jsContent, 20) {
		addEndpoint("POST", m[1])
	}

	// --- WebSocket endpoints ---
	seenWS := make(map[string]bool)
	for _, m := range wsPattern.FindAllStringSubmatch(jsContent, 20) {
		if !seenWS[m[1]] {
			seenWS[m[1]] = true
			bf.WebSockets = append(bf.WebSockets, m[1])
		}
	}
	for _, m := range wsURLPattern.FindAllStringSubmatch(jsContent, 20) {
		if !seenWS[m[1]] {
			seenWS[m[1]] = true
			bf.WebSockets = append(bf.WebSockets, m[1])
		}
	}

	// --- Hardcoded secrets ---
	seenSecrets := make(map[string]bool)
	for _, sp := range secretPatterns {
		matches := sp.re.FindAllString(jsContent, 10)
		for _, match := range matches {
			if seenSecrets[match] {
				continue
			}
			seenSecrets[match] = true

			// Truncate for display safety.
			display := match
			if len(display) > 40 {
				display = display[:20] + "..." + display[len(display)-10:]
			}

			bf.HardcodedSecrets = append(bf.HardcodedSecrets, Secret{
				Type:  sp.name,
				Value: display,
			})
		}
	}

	// --- Internal URLs ---
	seenInternal := make(map[string]bool)
	for _, m := range internalURLPattern.FindAllStringSubmatch(jsContent, 50) {
		u := m[1]
		if !seenInternal[u] {
			seenInternal[u] = true
			bf.InternalURLs = append(bf.InternalURLs, u)
		}
	}

	// --- Source maps ---
	for _, m := range sourceMapPattern.FindAllStringSubmatch(jsContent, 10) {
		bf.SourceMaps = append(bf.SourceMaps, m[1])
	}

	return bf
}

// ParseBundleFromURL fetches a JS file and parses it for security artifacts.
func ParseBundleFromURL(ctx context.Context, client *http.Client, jsURL string) *BundleFindings {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jsURL, nil)
	if err != nil {
		return &BundleFindings{}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner)")

	resp, err := client.Do(req)
	if err != nil {
		return &BundleFindings{}
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		return &BundleFindings{}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024)) // 5MB max
	if err != nil {
		return &BundleFindings{}
	}

	return ParseBundle(string(body), jsURL)
}

// HasFindings returns true if any artifacts were extracted.
func (bf *BundleFindings) HasFindings() bool {
	return len(bf.APIEndpoints) > 0 ||
		len(bf.WebSockets) > 0 ||
		len(bf.HardcodedSecrets) > 0 ||
		len(bf.InternalURLs) > 0 ||
		len(bf.SourceMaps) > 0
}

// Merge combines another BundleFindings into this one.
func (bf *BundleFindings) Merge(other *BundleFindings) {
	bf.APIEndpoints = append(bf.APIEndpoints, other.APIEndpoints...)
	bf.WebSockets = append(bf.WebSockets, other.WebSockets...)
	bf.HardcodedSecrets = append(bf.HardcodedSecrets, other.HardcodedSecrets...)
	bf.InternalURLs = append(bf.InternalURLs, other.InternalURLs...)
	bf.SourceMaps = append(bf.SourceMaps, other.SourceMaps...)
}
