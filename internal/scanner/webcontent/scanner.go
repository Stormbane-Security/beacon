// Package webcontent performs passive analysis of web page content:
// JavaScript file scanning, cookie security, CSP quality, and WAF detection.
// All checks are unauthenticated HTTP requests — no login required.
package webcontent

import (
	"context"
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
)


func init() {
	scan.RegisterWithCheckDecls(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	},
		scan.Check(finding.CheckCSPUnsafeEval, finding.SeverityMedium, finding.ModeSurface),
		scan.Check(finding.CheckCSPUnsafeInline, finding.SeverityMedium, finding.ModeSurface),
		scan.Check(finding.CheckCSPWildcardSource, finding.SeverityHigh, finding.ModeSurface),
		scan.Check(finding.CheckCookieMissingHTTPOnly, finding.SeverityMedium, finding.ModeSurface),
		scan.Check(finding.CheckCookieMissingSameSite, finding.SeverityLow, finding.ModeSurface),
		scan.Check(finding.CheckCookieMissingSecure, finding.SeverityMedium, finding.ModeSurface),
		scan.Check(finding.CheckHeadersServerInfoLeak, finding.SeverityLow, finding.ModeSurface),
		scan.Check(finding.CheckJSAPIKeyInSourceMap, finding.SeverityHigh, finding.ModeSurface),
		scan.Check(finding.CheckJSAPIKeyInURL, finding.SeverityHigh, finding.ModeSurface),
		scan.Check(finding.CheckJSHardcodedSecret, finding.SeverityCritical, finding.ModeSurface),
		scan.Check(finding.CheckJSInternalEndpoint, finding.SeverityMedium, finding.ModeSurface),
		scan.Check(finding.CheckJSSourceMapExposed, finding.SeverityMedium, finding.ModeSurface),
		scan.Check(finding.CheckSecretInResponseHeader, finding.SeverityHigh, finding.ModeSurface),
		scan.Check(finding.CheckWAFNotDetected, finding.SeverityInfo, finding.ModeSurface),
		scan.Check(finding.CheckJSExternalServiceRef, finding.SeverityInfo, finding.ModeSurface),
	)
}
const scannerName = "webcontent"

// secretPatterns matches common hardcoded secrets in JavaScript source.
// Keys are a human-readable label; values are the compiled regex.
// cspWildcardRe matches a wildcard (*) in script-src or default-src directives.
var cspWildcardRe = regexp.MustCompile(`(?i)(script-src|default-src)[^;]*\s\*(?:\s|;|$)`)

// genericPwdValueRe extracts the quoted value from a Generic Password match
// so we can filter out non-secret values like HTML attribute values and i18n keys.
var genericPwdValueRe = regexp.MustCompile(`[=:]\s*['` + "`" + `"]([^'"` + "`" + `\s]+)`)

// genericPwdFalsePositives is the set of values that look like a password
// assignment but are not credentials: HTML input type/autocomplete hints,
// the keyword itself used as an i18n label, etc.
var genericPwdFalsePositives = map[string]bool{
	"password":          true,
	"Password":          true,
	"passwd":            true,
	"pwd":               true,
	"current-password":  true,
	"new-password":      true,
	"one-time-code":     true,
	"off":               true,
	"username,password": true,
}

// genericPwdPlaceholderRe matches placeholder/template values that are not
// real credentials: %word%, {word}, <word>, {{word}}, $VAR_NAME style tokens.
var genericPwdPlaceholderRe = regexp.MustCompile(`^(%[^%]+%|\{[^}]+\}|<[^>]+>|\$[A-Z_]+|YOUR_|EXAMPLE|REPLACE|CHANGEME|TODO|FIXME|REDACTED|FILTERED)`)

// firebaseKeyRe matches Firebase API keys (AIzaSy...) which are intentionally
// public client-side identifiers, not secrets. Used to exclude them from the
// broader "Google API Key" pattern.
var firebaseKeyRe = regexp.MustCompile(`AIzaSy[A-Za-z0-9\-_]{33}`)

// oauthSecretIdentifierRe matches values that are snake_case or camelCase
// identifiers rather than actual secret values. Used to filter false positives
// from the "OAuth Client Secret" pattern (e.g. clientsecret:"twitter_clientsecret").
var oauthSecretIdentifierRe = regexp.MustCompile(`^[a-z][a-z0-9]*([_-][a-z0-9]+)+$`)

// isAWSKeyInBase64Blob returns true if the match at idx is embedded inside
// a longer base64-encoded blob (10+ surrounding chars are base64 alphabet).
func isAWSKeyInBase64Blob(content string, idx, matchLen int) bool {
	const window = 10
	start := idx - window
	if start < 0 {
		start = 0
	}
	end := idx + matchLen + window
	if end > len(content) {
		end = len(content)
	}
	base64Chars := 0
	totalChars := 0
	for i := start; i < end; i++ {
		if i >= idx && i < idx+matchLen {
			continue
		}
		c := content[i]
		totalChars++
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' {
			base64Chars++
		}
	}
	return totalChars >= 6 && float64(base64Chars)/float64(totalChars) > 0.85
}

// hasAWSKeyWordBoundary returns true if the char before idx is not alphanumeric.
func hasAWSKeyWordBoundary(content string, idx int) bool {
	if idx == 0 {
		return true
	}
	c := content[idx-1]
	return !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/')
}

var jsScriptSrcRe = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+\.js[^"']*)["']`)

var secretPatterns = map[string]*regexp.Regexp{
	"AWS Access Key":           regexp.MustCompile(`AKIA[A-Z0-9]{16}`),
	"AWS Secret Key":           regexp.MustCompile(`(?i)aws.{0,20}secret.{0,20}['"` + "`" + `][0-9a-zA-Z/+]{40}`),
	"GitHub Token":             regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`),
	"Stripe Secret Key":        regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`),
	"Stripe Publishable Key":   regexp.MustCompile(`pk_live_[0-9a-zA-Z]{24,}`),
	"Slack Token":              regexp.MustCompile(`xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}`),
	"SendGrid API Key":         regexp.MustCompile(`SG\.[0-9a-zA-Z\-_]{22}\.[0-9a-zA-Z\-_]{43}`),
	"Twilio Account SID":       regexp.MustCompile(`AC[a-f0-9]{32}`),
	"Google API Key":           regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
	"Private Key":              regexp.MustCompile(`-----BEGIN (RSA |EC )?PRIVATE KEY-----`),
	"Generic API Key":          regexp.MustCompile(`(?i)(api[_-]?key|apikey|api[_-]?secret)['"` + "`" + `\s]*[=:]\s*['"` + "`" + `][0-9a-zA-Z\-_]{20,}`),
	"Generic Password":         regexp.MustCompile(`(?i)(password|passwd|pwd)['"` + "`" + `\s]*[=:]\s*['"` + "`" + `][^'"` + "`" + `\s]{8,}['"` + "`" + `]`),
	"OpenAI API Key":           regexp.MustCompile(`sk-[A-Za-z0-9]{48}`),
	"Anthropic API Key":        regexp.MustCompile(`sk-ant-[A-Za-z0-9\-_]{93}`),
	// Firebase API Keys are intentionally client-side, domain-restricted identifiers —
	// not secrets. Google's documentation explicitly states they are safe to embed in
	// browser code. Detected via externalServiceRefs instead.
	// "Firebase API Key":       regexp.MustCompile(`AIzaSy[A-Za-z0-9\-_]{33}`),
	"Mailgun API Key":          regexp.MustCompile(`key-[a-f0-9]{32}`),
	"OAuth Client Secret":      regexp.MustCompile(`(?i)client[_-]?secret['"` + "`" + `\s]*[=:]\s*['"` + "`" + `][0-9a-zA-Z\-_.]{16,}`),
}

// apiKeyURLParamRe matches URL query parameters that carry API keys or tokens.
// It captures the full URL and the parameter name for evidence.
var apiKeyURLParamRe = regexp.MustCompile(`(?i)(https?://[^\s"'` + "`" + `]+\?[^\s"'` + "`" + `]*(?:api[_-]?key|apikey|key|token|access[_-]?token|secret|api-key)=([^\s&"'` + "`" + `]+))`)

// apiKeyParamNameRe extracts the specific parameter name from a matched URL fragment.
var apiKeyParamNameRe = regexp.MustCompile(`(?i)\b(api[_-]?key|apikey|key|token|access[_-]?token|secret|api-key)=`)

// apiKeyMatch holds a matched API key in a URL.
type apiKeyMatch struct {
	url       string
	paramName string
}

// publicKeyDomains lists domains where API keys in URLs are intentionally
// public client-side identifiers, not secrets. These are designed to be
// embedded in browser JS and only grant write/ingest access, not read access.
var publicKeyDomains = []string{
	".ingest.sentry.io",   // Sentry DSN — public error reporting key
	"sentry.io/api/",      // Sentry legacy DSN format
	"browser-intake-",     // Datadog RUM — public client token
	"plausible.io/api/",   // Plausible analytics — public site ID
	"cdn.segment.com",     // Segment analytics.js — public write key
	".posthog.com/capture", // PostHog — public project key
	".algolia.net",        // Algolia search — public search-only key
	".typesense.org",      // Typesense search — public search-only key
}

// checkAPIKeyInURLs scans JS content for URL query parameters containing API keys.
func checkAPIKeyInURLs(body string) []apiKeyMatch {
	matches := apiKeyURLParamRe.FindAllStringSubmatch(body, -1)
	seen := make(map[string]struct{})
	var results []apiKeyMatch
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		fullURL := m[1]
		if _, ok := seen[fullURL]; ok {
			continue
		}
		seen[fullURL] = struct{}{}

		// Skip URLs on domains where keys are intentionally public.
		urlLower := strings.ToLower(fullURL)
		isPublic := false
		for _, domain := range publicKeyDomains {
			if strings.Contains(urlLower, domain) {
				isPublic = true
				break
			}
		}
		if isPublic {
			continue
		}

		// Extract the parameter name.
		paramMatch := apiKeyParamNameRe.FindStringSubmatch(fullURL)
		paramName := "key"
		if len(paramMatch) >= 2 {
			paramName = paramMatch[1]
		}
		results = append(results, apiKeyMatch{url: fullURL, paramName: paramName})
	}
	return results
}

// internalEndpointPatterns matches internal/development API endpoints in JS.
var internalEndpointPatterns = []*regexp.Regexp{
	regexp.MustCompile(`https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)[/\w.-]*`),
	regexp.MustCompile(`https?://[\w-]+\.internal[/\w.-]*`),
	regexp.MustCompile(`https?://[\w-]+\.local(?:host)?[/\w.-]*`),
	regexp.MustCompile(`https?://(?:dev|staging|test|uat|qa)[\w.-]+\.[a-z]{2,}[/\w.-]*`),
}

// wafSignatures maps WAF/CDN vendor names to header patterns.
var wafSignatures = map[string][]string{
	"Cloudflare":    {"cf-ray", "cf-cache-status", "server:cloudflare"},
	"AWS CloudFront": {"x-amz-cf-id", "x-amz-cf-pop", "via:cloudfront"},
	"Akamai":        {"x-akamai-transformed", "akamai-origin-hop"},
	"Fastly":        {"x-served-by", "x-cache:hit, miss", "fastly-restarts"},
	"Sucuri":        {"x-sucuri-id", "x-sucuri-cache"},
	"Imperva":       {"x-iinfo", "incap-ses"},
	"Nginx WAF":     {"x-nginx-cache", "server:nginx"},
	"AWS WAF":       {"x-amzn-requestid", "x-amzn-trace-id"},
}

type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, _ module.ScanType) ([]finding.Finding, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	var findings []finding.Finding

	// Fetch the main page to analyze headers and discover JS files
	targetURL := "https://" + asset
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon Security Scanner)")

	resp, err := client.Do(req)
	if err != nil {
		// Try HTTP fallback
		targetURL = "http://" + asset
		req2, err2 := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
		if err2 != nil {
			return nil, nil // invalid URL — unreachable
		}
		resp, err = client.Do(req2)
		if err != nil {
			return nil, nil // unreachable, not a finding
		}
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB
	if err != nil {
		return nil, err
	}

	// Cookie security analysis
	findings = append(findings, analyzeCookies(asset, resp)...)

	// CSP quality analysis
	findings = append(findings, analyzeCSP(asset, resp)...)

	// Response header secret detection
	findings = append(findings, analyzeResponseHeaders(asset, resp)...)

	// Server header info leak detection
	if f := detectServerInfoLeak(asset, resp); f != nil {
		findings = append(findings, *f)
	}

	// WAF detection
	if wafFinding := detectWAF(asset, resp); wafFinding != nil {
		findings = append(findings, *wafFinding)
	}

	// JavaScript analysis: find script src URLs and scan each.
	// Also discover additional JS chunks from Next.js manifests and webpack
	// chunk references for deeper coverage of SPA bundles.
	jsURLs := extractJSURLs(targetURL, string(body))

	// Discover Next.js build manifest chunks if this is a Next.js app.
	extraChunks := discoverNextJSChunks(ctx, client, targetURL, string(body))
	for _, chunk := range extraChunks {
		// Add only new URLs not already in the initial set.
		dupe := false
		for _, existing := range jsURLs {
			if existing == chunk {
				dupe = true
				break
			}
		}
		if !dupe {
			jsURLs = append(jsURLs, chunk)
		}
	}

	// Cap total JS files to prevent runaway scanning on huge apps.
	const maxJSFiles = 100
	if len(jsURLs) > maxJSFiles {
		jsURLs = jsURLs[:maxJSFiles]
	}

	for _, jsURL := range jsURLs {
		jsFindings := analyzeJS(ctx, client, asset, jsURL)
		findings = append(findings, jsFindings...)
	}

	return findings, nil
}

// headerSecretPatterns matches API keys or tokens that should never appear in
// HTTP response headers (e.g., echoed back from the server or misconfigured proxy).
var headerSecretPatterns = map[string]*regexp.Regexp{
	"AWS Access Key":    regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	"GitHub Token":      regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`),
	"Stripe Secret Key": regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`),
	"Generic API Key":   regexp.MustCompile(`(?i)(api[_-]?key|apikey)[=:\s]+[0-9a-zA-Z\-_]{20,}`),
}

// analyzeResponseHeaders scans HTTP response headers for leaked secrets or
// API keys that should never appear in server responses.
func analyzeResponseHeaders(asset string, resp *http.Response) []finding.Finding {
	var findings []finding.Finding
	now := time.Now()

	for name, values := range resp.Header {
		for _, val := range values {
			for label, pattern := range headerSecretPatterns {
				if match := pattern.FindString(val); match != "" {
					findings = append(findings, finding.Finding{
						CheckID:  finding.CheckSecretInResponseHeader,
						Module:   "surface",
						Scanner:  scannerName,
						Severity: finding.SeverityHigh,
						Asset:    asset,
						Title:    fmt.Sprintf("Secret leaked in HTTP response header: %s (%s)", name, label),
						Description: fmt.Sprintf(
							"The HTTP response header %q contains what appears to be a %s. "+
								"Secrets in response headers are visible to any browser, proxy, or CDN "+
								"that handles the response. Rotate the credential immediately.",
							name, label,
						),
						Evidence: map[string]any{
							"header_name":  name,
							"secret_type":  label,
							"redacted_val": redactHeader(val, match),
						},
						DiscoveredAt: now,
					})
				}
			}
		}
	}
	return findings
}

// redactHeader returns the header value with the matched secret partially masked.
func redactHeader(val, match string) string {
	if len(match) <= 8 {
		return strings.Repeat("*", len(match))
	}
	return match[:4] + strings.Repeat("*", len(match)-8) + match[len(match)-4:]
}

func analyzeCookies(asset string, resp *http.Response) []finding.Finding {
	var findings []finding.Finding
	now := time.Now()

	for _, cookie := range resp.Cookies() {
		// Only care about likely session/auth cookies
		name := strings.ToLower(cookie.Name)
		isSession := strings.Contains(name, "session") ||
			strings.Contains(name, "auth") ||
			strings.Contains(name, "token") ||
			strings.Contains(name, "sid") ||
			name == "remember_me" || name == "_session_id"

		if !isSession {
			continue // only check cookies that look like session/auth tokens
		}

		if !cookie.Secure {
			findings = append(findings, finding.Finding{
				CheckID:      finding.CheckCookieMissingSecure,
				Module:       "surface",
				Scanner:      scannerName,
				Severity:     finding.SeverityMedium,
				Title:        fmt.Sprintf("Cookie '%s' missing Secure flag", cookie.Name),
				Description:  fmt.Sprintf("The cookie '%s' on %s does not have the Secure flag set. It can be transmitted over unencrypted HTTP connections, exposing session data.", cookie.Name, asset),
				Asset:        asset,
				Evidence:     map[string]any{"cookie_name": cookie.Name},
				ProofCommand: fmt.Sprintf("curl -sI https://%s | grep -i 'set-cookie' | grep -i '%s' | grep -iv 'secure'", asset, cookie.Name),
				DiscoveredAt: now,
			})
		}

		if !cookie.HttpOnly {
			findings = append(findings, finding.Finding{
				CheckID:      finding.CheckCookieMissingHTTPOnly,
				Module:       "surface",
				Scanner:      scannerName,
				Severity:     finding.SeverityMedium,
				Title:        fmt.Sprintf("Cookie '%s' missing HttpOnly flag", cookie.Name),
				Description:  fmt.Sprintf("The cookie '%s' on %s does not have the HttpOnly flag. JavaScript can read it, making session hijacking via XSS easier.", cookie.Name, asset),
				Asset:        asset,
				Evidence:     map[string]any{"cookie_name": cookie.Name},
				ProofCommand: fmt.Sprintf("curl -sI https://%s | grep -i 'set-cookie' | grep -i '%s' | grep -iv 'httponly'", asset, cookie.Name),
				DiscoveredAt: now,
			})
		}

		if cookie.SameSite == 0 || cookie.SameSite == http.SameSiteDefaultMode || cookie.SameSite == http.SameSiteNoneMode {
			findings = append(findings, finding.Finding{
				CheckID:      finding.CheckCookieMissingSameSite,
				Module:       "surface",
				Scanner:      scannerName,
				Severity:     finding.SeverityLow,
				Title:        fmt.Sprintf("Cookie '%s' missing SameSite attribute", cookie.Name),
				Description:  fmt.Sprintf("The cookie '%s' on %s has no SameSite attribute or is set to None. This increases CSRF attack risk.", cookie.Name, asset),
				Asset:        asset,
				Evidence:     map[string]any{"cookie_name": cookie.Name, "samesite": cookie.SameSite},
				ProofCommand: fmt.Sprintf("curl -sI https://%s | grep -i 'set-cookie' | grep -i '%s' | grep -iv 'samesite=strict\\|samesite=lax'", asset, cookie.Name),
				DiscoveredAt: now,
			})
		}
	}

	return findings
}

func analyzeCSP(asset string, resp *http.Response) []finding.Finding {
	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" {
		return nil // missing CSP is covered by nuclei headers check
	}

	var findings []finding.Finding
	now := time.Now()
	cspLower := strings.ToLower(csp)

	if strings.Contains(cspLower, "unsafe-inline") {
		findings = append(findings, finding.Finding{
			CheckID:      finding.CheckCSPUnsafeInline,
			Module:       "surface",
			Scanner:      scannerName,
			Severity:     finding.SeverityMedium,
			Title:        "Content Security Policy allows 'unsafe-inline'",
			Description:  fmt.Sprintf("The CSP on %s includes 'unsafe-inline', which allows inline JavaScript and CSS. This defeats the primary purpose of CSP as an XSS mitigation.", asset),
			Asset:        asset,
			Evidence:     map[string]any{"csp": csp},
			ProofCommand: fmt.Sprintf("curl -sI 'https://%s/' | grep -i content-security-policy | grep -i unsafe-inline", asset),
			DiscoveredAt: now,
		})
	}

	if strings.Contains(cspLower, "unsafe-eval") {
		findings = append(findings, finding.Finding{
			CheckID:      finding.CheckCSPUnsafeEval,
			Module:       "surface",
			Scanner:      scannerName,
			Severity:     finding.SeverityMedium,
			Title:        "Content Security Policy allows 'unsafe-eval'",
			Description:  fmt.Sprintf("The CSP on %s includes 'unsafe-eval', allowing dynamic code execution via eval(). This can be exploited in XSS attacks.", asset),
			Asset:        asset,
			Evidence:     map[string]any{"csp": csp},
			ProofCommand: fmt.Sprintf("curl -sI 'https://%s/' | grep -i content-security-policy | grep -i unsafe-eval", asset),
			DiscoveredAt: now,
		})
	}

	// Check for wildcard sources in script-src or default-src.
	// Extract the matching directive name and value for precise evidence.
	if m := cspWildcardRe.FindString(csp); m != "" {
		// Determine which directive contained the wildcard.
		directive := "script-src"
		if strings.HasPrefix(strings.ToLower(m), "default-src") {
			directive = "default-src"
		}
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckCSPWildcardSource,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Title:    fmt.Sprintf("CSP %s allows wildcard script source on %s", directive, asset),
			Description: fmt.Sprintf(
				"The CSP on %s uses a wildcard (*) in %s, allowing scripts to be loaded "+
					"from any origin. This defeats CSP as an XSS mitigation — an attacker "+
					"who can load a script from any host can bypass the policy entirely. "+
					"Replace the wildcard with explicit trusted origins.",
				asset, directive),
			Asset: asset,
			Evidence: map[string]any{
				"directive": directive,
				"matched":   m,
				"csp":       csp,
			},
			ProofCommand: fmt.Sprintf(
				"curl -sI 'https://%s/' | grep -i content-security-policy | grep -oE '(%s)[^;]*\\*[^;]*'",
				asset, directive),
			DiscoveredAt: now,
		})
	}

	return findings
}

// serverVersionRe matches a version number like "2.4.58" or "1.25.3" in a header value.
var serverVersionRe = regexp.MustCompile(`\d+\.\d+(?:\.\d+)?`)

// detectServerInfoLeak checks whether the Server or X-Powered-By headers
// reveal specific software names and version numbers. Exposing this information
// lets attackers target known CVEs for the exact version running.
func detectServerInfoLeak(asset string, resp *http.Response) *finding.Finding {
	var leaks []string
	evidence := map[string]any{}

	server := resp.Header.Get("Server")
	if server != "" && serverVersionRe.MatchString(server) {
		leaks = append(leaks, "Server: "+server)
		evidence["server"] = server
	}

	xpb := resp.Header.Get("X-Powered-By")
	if xpb != "" {
		leaks = append(leaks, "X-Powered-By: "+xpb)
		evidence["x_powered_by"] = xpb
	}

	xav := resp.Header.Get("X-AspNet-Version")
	if xav != "" {
		leaks = append(leaks, "X-AspNet-Version: "+xav)
		evidence["x_aspnet_version"] = xav
	}

	xav2 := resp.Header.Get("X-AspNetMvc-Version")
	if xav2 != "" {
		leaks = append(leaks, "X-AspNetMvc-Version: "+xav2)
		evidence["x_aspnetmvc_version"] = xav2
	}

	if len(leaks) == 0 {
		return nil
	}

	return &finding.Finding{
		CheckID:  finding.CheckHeadersServerInfoLeak,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityLow,
		Title:    fmt.Sprintf("Server version information leaked via HTTP headers on %s", asset),
		Description: fmt.Sprintf(
			"The following HTTP response headers reveal server software and version information: %s. "+
				"Attackers use this to identify exact software versions and target known CVEs. "+
				"Configure your web server to suppress or genericize these headers.",
			strings.Join(leaks, ", ")),
		Asset:        asset,
		Evidence:     evidence,
		ProofCommand: fmt.Sprintf("curl -sI 'https://%s' | grep -iE 'server:|x-powered-by:|x-aspnet'", asset),
		DiscoveredAt: time.Now(),
	}
}

func detectWAF(asset string, resp *http.Response) *finding.Finding {
	// Collect all header key:value pairs in lowercase for matching
	var headers []string
	for k, vs := range resp.Header {
		for _, v := range vs {
			headers = append(headers, strings.ToLower(k)+":"+strings.ToLower(v))
		}
	}
	headerStr := strings.Join(headers, "\n")

	for _, sigs := range wafSignatures {
		for _, sig := range sigs {
			if strings.Contains(headerStr, strings.ToLower(sig)) {
				// WAF detected — this is informational, not a finding
				return nil
			}
		}
	}

	// No WAF signature found — this is an observation, not a vulnerability.
	// Absence of a WAF is common and doesn't indicate a specific risk.
	return &finding.Finding{
		CheckID:      finding.CheckWAFNotDetected,
		Module:       "surface",
		Scanner:      scannerName,
		Severity:     finding.SeverityInfo,
		Title:        "No WAF or CDN detected",
		Description:  fmt.Sprintf("%s does not appear to have a Web Application Firewall or CDN in front of it. This means malicious traffic reaches your servers directly with no filtering layer.", asset),
		Asset:        asset,
		Evidence:     map[string]any{"headers_checked": len(resp.Header)},
		DiscoveredAt: time.Now(),
	}
}

func analyzeJS(ctx context.Context, client *http.Client, asset, jsURL string) []finding.Finding {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jsURL, nil)
	if err != nil {
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	if resp.StatusCode != 200 {
		_ = resp.Body.Close()
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	src, err := io.ReadAll(io.LimitReader(resp.Body, 512<<10)) // 512KB max per file
	if err != nil {
		return nil
	}

	srcStr := string(src)
	var findings []finding.Finding
	now := time.Now()

	// Check for hardcoded secrets — find ALL matches per pattern so a file with
	// multiple keys produces one finding per key, not just the first.
	seenMatches := make(map[string]struct{}) // dedup identical matches within the same file
	for label, pattern := range secretPatterns {
		indices := pattern.FindAllStringIndex(srcStr, -1)
		for _, loc := range indices {
			match := srcStr[loc[0]:loc[1]]
			if match == "" {
				continue
			}
			// AWS Access Key: reject matches inside base64 blobs or without
			// a word boundary before AKIA.
			if label == "AWS Access Key" {
				if !hasAWSKeyWordBoundary(srcStr, loc[0]) {
					continue
				}
				if isAWSKeyInBase64Blob(srcStr, loc[0], loc[1]-loc[0]) {
					continue
				}
			}
			// Dedup identical raw matches (same key appearing multiple times in the file).
			if _, already := seenMatches[label+":"+match]; already {
				continue
			}
			seenMatches[label+":"+match] = struct{}{}

			// Firebase API keys (AIzaSy...) are public client-side identifiers, not
			// secrets. They also match the broader "Google API Key" pattern (AIza...).
			// Exclude them from Google API Key detection.
			if label == "Google API Key" && firebaseKeyRe.MatchString(match) {
				continue // Firebase key — intentionally public, not a secret
			}
			if label == "Generic API Key" {
				// If the value portion of this match contains a more-specific credential,
				// suppress the generic label — it will be (or was) captured more precisely.
				suppressed := false
				for specific, re := range secretPatterns {
					if specific == "Generic API Key" || specific == "Generic Password" {
						continue
					}
					if re.FindString(match) != "" {
						suppressed = true
						break
					}
				}
				if suppressed {
					continue
				}
				// Extract the quoted value and reject env-var references — patterns like
				// apiKey: "NEXT_PUBLIC_SOME_SERVICE_API_KEY" where the "value" is itself
				// an uppercase_underscore variable name, not an actual credential.
				if sub := genericPwdValueRe.FindStringSubmatch(match); sub != nil {
					val := sub[1]
					isEnvVarRef := true
					for _, c := range val {
						if (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' {
							isEnvVarRef = false
							break
						}
					}
					if isEnvVarRef {
						continue // e.g. NEXT_PUBLIC_API_KEY, REACT_APP_TOKEN — not a real value
					}
				}
			}
			// Generic Password: filter out common non-secret values — the keyword
			// "password" itself (as an i18n label or HTML attribute), autocomplete
			// hints like "current-password", field type specifiers, etc.
			if label == "Generic Password" {
				if sub := genericPwdValueRe.FindStringSubmatch(match); sub != nil {
					val := sub[1]
					// Skip known false-positive values (input type names, autocomplete hints).
					if genericPwdFalsePositives[val] {
						continue
					}
					// Skip placeholder/template tokens: %filtered%, {PASSWORD}, $SECRET, etc.
					if genericPwdPlaceholderRe.MatchString(val) {
						continue
					}
					// Skip values that are all lowercase ASCII words — likely a JS property
					// name or i18n key rather than a credential (e.g. password:"text").
					allLowerWord := true
					for _, c := range val {
						if (c < 'a' || c > 'z') && c != '-' && c != '_' {
							allLowerWord = false
							break
						}
					}
					if allLowerWord {
						continue
					}
				}
			}
			// OAuth Client Secret: reject values that are snake_case identifiers like
			// "twitter_clientsecret" or "google_client_secret" — config key names, not
			// actual secret values. Real OAuth secrets are random alphanumeric strings.
			if label == "OAuth Client Secret" {
				if sub := genericPwdValueRe.FindStringSubmatch(match); sub != nil {
					val := sub[1]
					if oauthSecretIdentifierRe.MatchString(val) {
						continue
					}
					// Also reject if the value contains common config words that indicate
					// it's a label/key name rather than an actual secret.
					valLower := strings.ToLower(val)
					if strings.Contains(valLower, "secret") || strings.Contains(valLower, "client") ||
						strings.Contains(valLower, "config") || strings.Contains(valLower, "setting") {
						continue
					}
				}
			}
			// Redact the actual value in the finding
			redacted := match
			if len(redacted) > 12 {
				redacted = redacted[:8] + "..." + redacted[len(redacted)-4:]
			}
			// Detect cross-origin JS: the file is hosted on a different domain than
			// the scanned asset (e.g. a CDN or third-party vendor). The credential is
			// still exposed to visitors of the asset regardless of where the file lives.
			jsHost := jsURL
			if u, err := url.Parse(jsURL); err == nil {
				jsHost = u.Host
			}
			crossOrigin := jsHost != asset && jsHost != "www."+asset
			desc := fmt.Sprintf("A %s appears to be hardcoded in a JavaScript file at %s. This credential is exposed to anyone who visits %s.", label, jsURL, asset)
			if crossOrigin {
				desc = fmt.Sprintf(
					"A %s appears to be hardcoded in a JavaScript file hosted at %s (a third-party dependency of %s). "+
						"Because %s loads this script, the credential is delivered to every visitor's browser regardless of where the file is hosted. "+
						"The owning team for %s should be notified.",
					label, jsURL, asset, asset, jsHost)
			}
			ev := map[string]any{"js_url": jsURL, "pattern": label, "match_redacted": redacted, "match_full": match}
			if crossOrigin {
				ev["loaded_by"] = asset
				ev["hosted_on"] = jsHost
				ev["cross_origin"] = true
			}
			findings = append(findings, finding.Finding{
				CheckID:     finding.CheckJSHardcodedSecret,
				Module:      "surface",
				Scanner:     scannerName,
				Severity:    finding.SeverityCritical,
				Title:       fmt.Sprintf("Hardcoded %s found in JavaScript", label),
				Description: desc,
				Asset:       asset,
				Evidence:    ev,
				// Use a shell-safe proof command — the internal Go regex contains single
				// quotes and backticks that would break shell quoting. Instead use a
				// keyword-context grep that avoids those characters entirely.
				ProofCommand: fmt.Sprintf("curl -s '%s' | grep -oiE '.{0,20}%s.{0,60}'",
					jsURL, secretProofKeyword(label)),
				DiscoveredAt: now,
			})
		}
	}

	// Check for exposed source maps — //# sourceMappingURL= in JS reveals original source
	smFindings := checkSourceMapExposed(ctx, client, asset, jsURL, srcStr)
	findings = append(findings, smFindings...)

	// Check for internal endpoints
	for _, pattern := range internalEndpointPatterns {
		if match := pattern.FindString(srcStr); match != "" {
			findings = append(findings, finding.Finding{
				CheckID:      finding.CheckJSInternalEndpoint,
				Module:       "surface",
				Scanner:      scannerName,
				Severity:     finding.SeverityMedium,
				Title:        "Internal API endpoint exposed in JavaScript",
				Description:  fmt.Sprintf("An internal or development API endpoint (%s) is referenced in a publicly accessible JavaScript file at %s.", match, jsURL),
				Asset:        asset,
				Evidence:     map[string]any{"js_url": jsURL, "endpoint": match},
				ProofCommand: fmt.Sprintf("curl -s '%s' | grep -oE 'https?://[a-zA-Z0-9._/-]+'", jsURL),
				DiscoveredAt: now,
			})
		}
	}

	// Extract external service references — API endpoints, RPC providers, SaaS
	// integrations discovered in the JS bundle. These reveal the application's
	// backend dependencies and infrastructure.
	svcFindings := extractServiceReferences(asset, jsURL, srcStr, now)
	findings = append(findings, svcFindings...)

	// Check for API keys passed as URL query parameters in JS code
	for _, akm := range checkAPIKeyInURLs(srcStr) {
		redactedURL := akm.url
		if len(redactedURL) > 80 {
			redactedURL = redactedURL[:40] + "..." + redactedURL[len(redactedURL)-30:]
		}
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckJSAPIKeyInURL,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Asset:    asset,
			Title:    fmt.Sprintf("API key passed in URL query parameter (%s=) in JavaScript", akm.paramName),
			Description: fmt.Sprintf(
				"A JavaScript file at %s contains a URL with an API key or token passed as the query parameter %q. "+
					"Keys in URLs are logged by proxies, CDNs, browser history, and server access logs, "+
					"making them significantly easier to leak than header-based credentials. "+
					"Move the credential to an Authorization header or server-side configuration.",
				jsURL, akm.paramName,
			),
			Evidence: map[string]any{
				"js_url":     jsURL,
				"url_found":  redactedURL,
				"param_name": akm.paramName,
			},
			ProofCommand: fmt.Sprintf("curl -s '%s' | grep -oiE 'https?://[^\"'\\''\\s]+%s=[^\"'\\''\\s]+'", jsURL, akm.paramName),
			DiscoveredAt: now,
		})
	}

	return findings
}

// secretProofKeyword returns a shell-safe grep keyword for the given secret
// label. The full Go regex patterns contain single quotes and backticks that
// break shell quoting when embedded in a proof command. This maps each label
// to a simple alphanumeric keyword that grep can match without quoting issues.
func secretProofKeyword(label string) string {
	keywords := map[string]string{
		"Generic Password":         "password",
		"Generic API Key":          "apikey",
		"AWS Secret Key":           "aws_secret",
		"GitHub Token":             "ghp_",
		"Stripe Secret Key":        "sk_live_",
		"Stripe Publishable Key":   "pk_live_",
		"Slack Token":              "xoxb-",
		"SendGrid API Key":         "SG\\.",
		"Twilio Account SID":       "AC[a-f0-9]",
		"Google API Key":           "AIza",
		"Private Key":              "PRIVATE KEY",
		"OpenAI API Key":           "sk-[A-Za-z0-9]",
		"Anthropic API Key":        "sk-ant-",
		"Mailgun API Key":          "key-[a-f0-9]",
	}
	if kw, ok := keywords[label]; ok {
		return kw
	}
	// Fallback: use first word of label, lowercased.
	parts := strings.Fields(strings.ToLower(label))
	if len(parts) > 0 {
		return parts[0]
	}
	return "secret"
}

// checkSourceMapExposed looks for a //# sourceMappingURL= comment in JS source
// and probes the referenced .js.map URL. If the map file is publicly accessible,
// it exposes original (pre-minified) source code including comments, variable names,
// and internal paths — significantly aiding an attacker's reverse engineering.
// It also checks the source map content for API keys in URLs.
func checkSourceMapExposed(ctx context.Context, client *http.Client, asset, jsURL, src string) []finding.Finding {
	const marker = "//# sourceMappingURL="
	idx := strings.LastIndex(src, marker)
	if idx == -1 {
		return nil
	}
	mapRef := strings.TrimSpace(src[idx+len(marker):])
	// Trim any trailing newline or comment
	if nl := strings.IndexAny(mapRef, "\r\n"); nl >= 0 {
		mapRef = mapRef[:nl]
	}
	if mapRef == "" || strings.HasPrefix(mapRef, "data:") {
		return nil // inline data URI — not an external file
	}

	// Resolve to absolute URL
	mapURL := mapRef
	if !strings.HasPrefix(mapURL, "http") {
		// Relative to the JS file's URL
		if slash := strings.LastIndex(jsURL, "/"); slash >= 0 {
			mapURL = jsURL[:slash+1] + mapRef
		} else {
			mapURL = jsURL + ".map"
		}
	}

	// Use GET instead of HEAD so we can also inspect the source map content.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, mapURL, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		return nil
	}

	mapBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB max
	if err != nil {
		return nil
	}

	var findings []finding.Finding
	now := time.Now()

	findings = append(findings, finding.Finding{
		CheckID:  finding.CheckJSSourceMapExposed,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityMedium,
		Asset:    asset,
		Title:    fmt.Sprintf("JavaScript source map publicly accessible: %s", mapURL),
		Description: fmt.Sprintf(
			"The source map file at %s is publicly accessible. Source maps contain the original "+
				"(pre-minification) JavaScript source code, including original variable names, "+
				"comments, internal file paths, and business logic. This significantly reduces "+
				"the effort required for an attacker to reverse-engineer the application. "+
				"Remove source map files from production or restrict access to them.",
			mapURL,
		),
		Evidence:     map[string]any{"js_url": jsURL, "map_url": mapURL},
		DiscoveredAt: now,
	})

	// Check source map content for API keys in URLs
	for _, akm := range checkAPIKeyInURLs(string(mapBody)) {
		redactedURL := akm.url
		if len(redactedURL) > 80 {
			redactedURL = redactedURL[:40] + "..." + redactedURL[len(redactedURL)-30:]
		}
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckJSAPIKeyInSourceMap,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Asset:    asset,
			Title:    fmt.Sprintf("API key in URL query parameter (%s=) found in source map", akm.paramName),
			Description: fmt.Sprintf(
				"The publicly accessible source map at %s contains a URL with an API key or token "+
					"passed as the query parameter %q. Source maps expose the original pre-minified source, "+
					"and credentials embedded in URLs are logged by proxies, CDNs, and access logs. "+
					"Remove the source map from production and rotate the exposed credential.",
				mapURL, akm.paramName,
			),
			Evidence: map[string]any{
				"js_url":     jsURL,
				"map_url":    mapURL,
				"url_found":  redactedURL,
				"param_name": akm.paramName,
			},
			ProofCommand: fmt.Sprintf("curl -s '%s' | grep -oiE 'https?://[^\"\\s]+%s=[^\"\\s]+'", mapURL, akm.paramName),
			DiscoveredAt: now,
		})
	}

	return findings
}

// ── Next.js / Webpack Chunk Discovery ──────────────────────────────────────

// nextBuildIDRe extracts the Next.js build ID from __NEXT_DATA__ in the HTML.
var nextBuildIDRe = regexp.MustCompile(`"buildId"\s*:\s*"([a-zA-Z0-9_-]+)"`)

// nextChunkRefRe matches chunk file references in Next.js manifests.
// Patterns: "static/chunks/1234-hash.js", "pages/index-hash.js"
var nextChunkRefRe = regexp.MustCompile(`"((?:static/chunks|pages|app)/[^"]+\.js)"`)

// discoverNextJSChunks finds additional JavaScript files by probing Next.js
// build manifests and extracting chunk references. This discovers JS bundles
// that aren't directly linked in <script> tags but are lazy-loaded by the app.
func discoverNextJSChunks(ctx context.Context, client *http.Client, baseURL, html string) []string {
	// Extract the build ID from __NEXT_DATA__ JSON in the HTML.
	buildIDMatch := nextBuildIDRe.FindStringSubmatch(html)
	if len(buildIDMatch) < 2 {
		return nil // Not a Next.js app or build ID not found
	}
	buildID := buildIDMatch[1]

	// Determine the origin URL for constructing absolute paths.
	origin := baseURL
	if u, err := url.Parse(baseURL); err == nil {
		origin = u.Scheme + "://" + u.Host
	}

	// Probe the _buildManifest.js — this lists all page chunks.
	manifestURL := origin + "/_next/static/" + buildID + "/_buildManifest.js"
	manifestBody := fetchJSBody(ctx, client, manifestURL)

	var chunks []string
	seen := make(map[string]bool)

	// Extract chunk references from the manifest.
	for _, match := range nextChunkRefRe.FindAllStringSubmatch(manifestBody, 200) {
		if len(match) < 2 {
			continue
		}
		chunkPath := match[1]
		chunkURL := origin + "/_next/" + chunkPath
		if !seen[chunkURL] {
			seen[chunkURL] = true
			chunks = append(chunks, chunkURL)
		}
	}

	// Also look for chunk references in the HTML itself — Next.js inlines
	// some chunk URLs in script tags with data-nscript or in the
	// __NEXT_DATA__ props.
	for _, match := range nextChunkRefRe.FindAllStringSubmatch(html, 200) {
		if len(match) < 2 {
			continue
		}
		chunkPath := match[1]
		chunkURL := origin + "/_next/" + chunkPath
		if !seen[chunkURL] {
			seen[chunkURL] = true
			chunks = append(chunks, chunkURL)
		}
	}

	return chunks
}

// fetchJSBody fetches a JS file and returns the body as a string.
func fetchJSBody(ctx context.Context, client *http.Client, jsURL string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jsURL, nil)
	if err != nil {
		return ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
	return string(body)
}

// extractJSURLs finds script src URLs in HTML.
func extractJSURLs(baseURL, html string) []string {
	matches := jsScriptSrcRe.FindAllStringSubmatch(html, 50) // cap at 50 JS files

	seen := make(map[string]struct{})
	var urls []string
	// Compute scheme+host prefix for resolving relative paths.
	baseOrigin := baseURL
	if u, err := url.Parse(baseURL); err == nil {
		baseOrigin = u.Scheme + "://" + u.Host
	}

	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		url := m[1]
		if strings.HasPrefix(url, "//") {
			url = "https:" + url
		} else if strings.HasPrefix(url, "/") {
			url = baseOrigin + url
		}
		if _, ok := seen[url]; !ok && strings.HasPrefix(url, "http") {
			seen[url] = struct{}{}
			urls = append(urls, url)
		}
	}
	return urls
}

// ── External Service Reference Extraction ──────────────────────────────────

// serviceRef maps a domain pattern to a human-readable service name and category.
type serviceRef struct {
	domain   string // substring match against URL host
	service  string // human-readable name
	category string // blockchain, payments, analytics, auth, ai, cdn, cloud, messaging, database
}

// knownServices is a catalog of external API/service domains. When a JS bundle
// references one of these, it reveals the application's backend dependencies.
var knownServices = []serviceRef{
	// Blockchain / Web3
	{domain: "helius-rpc.com", service: "Helius RPC (Solana)", category: "blockchain"},
	{domain: "solana.com", service: "Solana RPC", category: "blockchain"},
	{domain: "mainnet.infura.io", service: "Infura (Ethereum)", category: "blockchain"},
	{domain: "alchemy.com", service: "Alchemy", category: "blockchain"},
	{domain: "moralis.io", service: "Moralis", category: "blockchain"},
	{domain: "quicknode.com", service: "QuickNode", category: "blockchain"},
	{domain: "chainstack.com", service: "Chainstack", category: "blockchain"},
	{domain: "etherscan.io/api", service: "Etherscan API", category: "blockchain"},

	// Payments
	{domain: "api.stripe.com", service: "Stripe API", category: "payments"},
	{domain: "js.stripe.com", service: "Stripe.js", category: "payments"},
	{domain: "api.paypal.com", service: "PayPal API", category: "payments"},
	{domain: "checkout.razorpay.com", service: "Razorpay", category: "payments"},

	// Auth / Identity
	{domain: ".auth0.com", service: "Auth0", category: "auth"},
	{domain: ".okta.com", service: "Okta", category: "auth"},
	{domain: ".clerk.dev", service: "Clerk", category: "auth"},
	{domain: "cognito-idp.", service: "AWS Cognito", category: "auth"},
	{domain: ".supabase.co/auth", service: "Supabase Auth", category: "auth"},
	{domain: ".firebaseauth.com", service: "Firebase Auth", category: "auth"},

	// AI / ML
	{domain: "api.openai.com", service: "OpenAI API", category: "ai"},
	{domain: "api.anthropic.com", service: "Anthropic API", category: "ai"},
	{domain: "api.cohere.ai", service: "Cohere API", category: "ai"},
	{domain: "api.replicate.com", service: "Replicate API", category: "ai"},
	{domain: "api-inference.huggingface.co", service: "HuggingFace Inference", category: "ai"},

	// Cloud / Infrastructure
	{domain: ".amazonaws.com", service: "AWS API", category: "cloud"},
	{domain: ".supabase.co", service: "Supabase", category: "cloud"},
	{domain: ".firebaseio.com", service: "Firebase Realtime DB", category: "cloud"},
	{domain: "firestore.googleapis.com", service: "Cloud Firestore", category: "cloud"},
	{domain: ".appwrite.io", service: "Appwrite", category: "cloud"},
	{domain: ".convex.cloud", service: "Convex", category: "cloud"},
	{domain: ".neon.tech", service: "Neon (Postgres)", category: "database"},
	{domain: ".planetscale.com", service: "PlanetScale", category: "database"},

	// Analytics / Monitoring
	{domain: "api.segment.io", service: "Segment", category: "analytics"},
	{domain: "api.mixpanel.com", service: "Mixpanel", category: "analytics"},
	{domain: "api.amplitude.com", service: "Amplitude", category: "analytics"},
	{domain: ".sentry.io/api", service: "Sentry", category: "monitoring"},
	{domain: ".ingest.sentry.io", service: "Sentry", category: "monitoring"},
	{domain: "api.datadoghq.com", service: "Datadog", category: "monitoring"},

	// Messaging / Communication
	{domain: "api.sendgrid.com", service: "SendGrid", category: "messaging"},
	{domain: "api.twilio.com", service: "Twilio", category: "messaging"},
	{domain: "hooks.slack.com", service: "Slack Webhook", category: "messaging"},
	{domain: "discord.com/api", service: "Discord API", category: "messaging"},

	// Search
	{domain: ".algolia.net", service: "Algolia", category: "search"},
	{domain: ".typesense.org", service: "Typesense", category: "search"},
	{domain: ".meilisearch.com", service: "Meilisearch", category: "search"},
}

// jsURLExtractRe matches http/https URLs in JS source code.
var jsURLExtractRe = regexp.MustCompile(`https?://[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}(?:/[^\s"'` + "`" + `<>)\]},;]*)?`)

// extractServiceReferences scans a JS file for URLs that reference known
// external services and APIs. Each discovered service produces an informational
// finding that reveals the application's backend dependencies.
func extractServiceReferences(asset, jsURL, src string, now time.Time) []finding.Finding {
	urls := jsURLExtractRe.FindAllString(src, 500)
	if len(urls) == 0 {
		return nil
	}

	// Deduplicate by service name — one finding per service per JS file.
	seen := make(map[string]bool)
	var findings []finding.Finding

	for _, rawURL := range urls {
		lower := strings.ToLower(rawURL)
		for _, svc := range knownServices {
			if !strings.Contains(lower, svc.domain) {
				continue
			}
			if seen[svc.service] {
				continue
			}
			seen[svc.service] = true

			// Extract env var references from surrounding context.
			envVars := extractEnvVarRefs(src, rawURL)

			ev := map[string]any{
				"js_url":   jsURL,
				"url":      rawURL,
				"service":  svc.service,
				"category": svc.category,
			}
			if len(envVars) > 0 {
				ev["env_vars"] = envVars
			}

			desc := fmt.Sprintf(
				"A JavaScript file at %s references %s (%s). "+
					"This reveals that the application integrates with %s — "+
					"an attacker can use this to map backend dependencies, identify "+
					"potential pivot points, and target service-specific attacks.",
				jsURL, svc.service, svc.category, svc.service)

			findings = append(findings, finding.Finding{
				CheckID:      finding.CheckJSExternalServiceRef,
				Module:       "surface",
				Scanner:      scannerName,
				Severity:     finding.SeverityInfo,
				Title:        fmt.Sprintf("External service reference: %s (%s)", svc.service, svc.category),
				Description:  desc,
				Asset:        asset,
				Evidence:     ev,
				ProofCommand: fmt.Sprintf("curl -s '%s' | grep -o '%s[^\"]*'", jsURL, svc.domain),
				DiscoveredAt: now,
			})
		}
	}
	return findings
}

// envVarRefRe matches environment variable references near a URL in JS code:
// process.env.VAR, ${...env...VAR}, import.meta.env.VAR, etc.
var envVarRefRe = regexp.MustCompile(`(?:process\.env\.|import\.meta\.env\.|\$\{[^}]*env[^}]*\}|[A-Z][A-Z0-9_]{5,}_(?:KEY|SECRET|TOKEN|URL|API|ID))`)

// extractEnvVarRefs finds environment variable references near a URL in the source.
func extractEnvVarRefs(src, nearURL string) []string {
	idx := strings.Index(src, nearURL)
	if idx == -1 {
		return nil
	}
	// Look at 200 chars before and after the URL for env var refs.
	start := idx - 200
	if start < 0 {
		start = 0
	}
	end := idx + len(nearURL) + 200
	if end > len(src) {
		end = len(src)
	}
	context := src[start:end]

	matches := envVarRefRe.FindAllString(context, 10)
	seen := make(map[string]bool)
	var unique []string
	for _, m := range matches {
		if !seen[m] {
			seen[m] = true
			unique = append(unique, m)
		}
	}
	return unique
}
