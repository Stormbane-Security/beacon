// Package paramdiscovery extracts parameter names from crawl results so that
// web vulnerability scanners can probe discovered parameters instead of relying
// on hardcoded wordlists.
package paramdiscovery

import (
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// ── HTML form extraction ────────────────────────────────────────────────────

// inputNameRe matches <input ... name="paramName" ...> in HTML.
var inputNameRe = regexp.MustCompile(`(?i)<(?:input|select|textarea)\b[^>]*\bname\s*=\s*["']([^"']+)["']`)

// ExtractParams extracts parameter names from HTML form inputs (<input>,
// <select>, <textarea> elements with a name attribute).
func ExtractParams(htmlBody string) []string {
	matches := inputNameRe.FindAllStringSubmatch(htmlBody, -1)
	seen := make(map[string]struct{}, len(matches))
	var params []string
	for _, m := range matches {
		name := m[1]
		if _, ok := seen[name]; !ok {
			seen[name] = struct{}{}
			params = append(params, name)
		}
	}
	sort.Strings(params)
	return params
}

// ── URL query string extraction ─────────────────────────────────────────────

// ExtractFromURLs parses query parameters from each URL and groups them by
// path. The returned map keys are URL paths; values are deduplicated sorted
// parameter name slices.
func ExtractFromURLs(urls []string) map[string][]string {
	result := make(map[string]map[string]struct{})
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		path := u.Path
		if path == "" {
			path = "/"
		}
		for key := range u.Query() {
			if result[path] == nil {
				result[path] = make(map[string]struct{})
			}
			result[path][key] = struct{}{}
		}
	}

	out := make(map[string][]string, len(result))
	for path, paramSet := range result {
		params := make([]string, 0, len(paramSet))
		for p := range paramSet {
			params = append(params, p)
		}
		sort.Strings(params)
		out[path] = params
	}
	return out
}

// ── JSON key extraction ─────────────────────────────────────────────────────

// ExtractFromJSON extracts top-level and nested key names from a JSON object or
// array. These keys are potential API parameters.
func ExtractFromJSON(jsonBody string) []string {
	var raw any
	if err := json.Unmarshal([]byte(jsonBody), &raw); err != nil {
		return nil
	}

	seen := make(map[string]struct{})
	extractKeys(raw, seen)

	params := make([]string, 0, len(seen))
	for k := range seen {
		params = append(params, k)
	}
	sort.Strings(params)
	return params
}

// extractKeys recursively walks a decoded JSON value and collects object keys.
func extractKeys(v any, seen map[string]struct{}) {
	switch val := v.(type) {
	case map[string]any:
		for key, child := range val {
			seen[key] = struct{}{}
			extractKeys(child, seen)
		}
	case []any:
		for _, item := range val {
			extractKeys(item, seen)
		}
	}
}

// ── JavaScript fetch/axios parameter extraction ─────────────────────────────

// jsParamPatterns match common JavaScript patterns where parameter names appear
// in fetch, axios, XMLHttpRequest, and $.ajax calls.
var jsParamPatterns = []*regexp.Regexp{
	// Object literal keys in fetch/axios body or params: { key: value }
	// Matches: { foo: "bar", baz: 123 }
	regexp.MustCompile(`(?:params|data|body|payload|query)\s*[:=]\s*\{([^}]+)\}`),
	// URLSearchParams.append("name", value) or .set("name", value)
	regexp.MustCompile(`\.(?:append|set)\s*\(\s*["']([^"']+)["']`),
	// Direct query string building: "?param=" + value or "&param=" + value
	regexp.MustCompile(`[?&](\w{2,})=["']\s*\+`),
	// Also: "param=" + value (standalone)
	regexp.MustCompile(`["'](\w{2,})=["']\s*\+`),
	// Template literal query params: `?param=${value}` or `&param=${value}`
	regexp.MustCompile(`[?&](\w{2,})=\$\{`),
	// $.param, $.get, $.post with object keys
	regexp.MustCompile(`\$\.(?:get|post|ajax|param)\s*\([^{]*\{([^}]+)\}`),
}

// objectKeyRe extracts keys from JS object literal fragments: key: or "key": or 'key':
var objectKeyRe = regexp.MustCompile(`(?:^|[,{\s])["']?(\w+)["']?\s*:`)

// ExtractFromJS extracts parameter names from JavaScript source code by looking
// for patterns in fetch, axios, XMLHttpRequest, and jQuery AJAX calls.
func ExtractFromJS(jsBody string) []string {
	seen := make(map[string]struct{})

	for _, pat := range jsParamPatterns {
		matches := pat.FindAllStringSubmatch(jsBody, -1)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			captured := m[1]

			// If it looks like an object literal fragment, extract keys from it.
			if strings.Contains(captured, ":") {
				keys := objectKeyRe.FindAllStringSubmatch(captured, -1)
				for _, k := range keys {
					name := k[1]
					if isLikelyParamName(name) {
						seen[name] = struct{}{}
					}
				}
			} else {
				// Direct capture (e.g., URLSearchParams.append("name", ...))
				name := strings.TrimSpace(captured)
				if isLikelyParamName(name) {
					seen[name] = struct{}{}
				}
			}
		}
	}

	params := make([]string, 0, len(seen))
	for p := range seen {
		params = append(params, p)
	}
	sort.Strings(params)
	return params
}

// jsReserved contains JavaScript keywords that should not be treated as
// parameter names.
var jsReserved = map[string]struct{}{
	"var": {}, "let": {}, "const": {}, "function": {}, "return": {},
	"if": {}, "else": {}, "for": {}, "while": {}, "do": {},
	"switch": {}, "case": {}, "break": {}, "continue": {}, "new": {},
	"this": {}, "true": {}, "false": {}, "null": {}, "undefined": {},
	"typeof": {}, "instanceof": {}, "delete": {}, "void": {},
	"try": {}, "catch": {}, "finally": {}, "throw": {},
	"class": {}, "extends": {}, "super": {}, "import": {}, "export": {},
	"default": {}, "async": {}, "await": {}, "yield": {},
}

// isLikelyParamName returns true if the string looks like a plausible HTTP
// parameter name (not a JS keyword, not too short, alphanumeric with underscores).
func isLikelyParamName(s string) bool {
	if len(s) < 2 || len(s) > 64 {
		return false
	}
	if _, reserved := jsReserved[s]; reserved {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
