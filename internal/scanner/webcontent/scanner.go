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

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const scannerName = "webcontent"

// secretPatterns matches common hardcoded secrets in JavaScript source.
// Keys are a human-readable label; values are the compiled regex.
// cspWildcardRe matches a wildcard (*) in script-src or default-src directives.
var cspWildcardRe = regexp.MustCompile(`(?i)(script-src|default-src)[^;]*\*`)

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

var secretPatterns = map[string]*regexp.Regexp{
	"AWS Access Key":           regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`),
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
	"Firebase API Key":         regexp.MustCompile(`AIzaSy[A-Za-z0-9\-_]{33}`),
	"Mailgun API Key":          regexp.MustCompile(`key-[a-f0-9]{32}`),
	"OAuth Client Secret":      regexp.MustCompile(`(?i)client[_-]?secret['"` + "`" + `\s]*[=:]\s*['"` + "`" + `][0-9a-zA-Z\-_.]{16,}`),
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
		req2, err2 := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+asset, nil)
		if err2 != nil {
			return nil, nil // invalid URL — unreachable
		}
		resp, err = client.Do(req2)
		if err != nil {
			return nil, nil // unreachable, not a finding
		}
	}
	defer resp.Body.Close()

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

	// WAF detection
	if wafFinding := detectWAF(asset, resp); wafFinding != nil {
		findings = append(findings, *wafFinding)
	}

	// JavaScript analysis: find script src URLs and scan each
	jsURLs := extractJSURLs(targetURL, string(body))
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

		if cookie.SameSite == http.SameSiteDefaultMode || cookie.SameSite == http.SameSiteNoneMode {
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

	// No WAF signature found
	return &finding.Finding{
		CheckID:      finding.CheckWAFNotDetected,
		Module:       "surface",
		Scanner:      scannerName,
		Severity:     finding.SeverityMedium,
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
		resp.Body.Close()
		return nil
	}
	defer resp.Body.Close()

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
		matches := pattern.FindAllString(srcStr, -1)
		for _, match := range matches {
			if match == "" {
				continue
			}
			// Dedup identical raw matches (same key appearing multiple times in the file).
			if _, already := seenMatches[label+":"+match]; already {
				continue
			}
			seenMatches[label+":"+match] = struct{}{}

			// Dedup: skip less-specific patterns when a more-specific one covers the
			// same credential value. Firebase keys (AIzaSy...) also match "Google API
			// Key" (AIza...) and, when in apiKey=... context, "Generic API Key".
			if label == "Google API Key" && secretPatterns["Firebase API Key"].MatchString(match) {
				continue // reported as Firebase API Key
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
						if !((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
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
						if !((c >= 'a' && c <= 'z') || c == '-' || c == '_') {
							allLowerWord = false
							break
						}
					}
					if allLowerWord {
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
			ev := map[string]any{"js_url": jsURL, "pattern": label, "match_redacted": redacted}
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
	if f := checkSourceMapExposed(ctx, client, asset, jsURL, srcStr); f != nil {
		findings = append(findings, *f)
	}

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
		"Firebase API Key":         "AIzaSy",
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
func checkSourceMapExposed(ctx context.Context, client *http.Client, asset, jsURL, src string) *finding.Finding {
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

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, mapURL, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}

	return &finding.Finding{
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
		DiscoveredAt: time.Now(),
	}
}

// extractJSURLs finds script src URLs in HTML.
func extractJSURLs(baseURL, html string) []string {
	pattern := regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+\.js[^"']*)["']`)
	matches := pattern.FindAllStringSubmatch(html, 50) // cap at 50 JS files

	seen := make(map[string]struct{})
	var urls []string
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		url := m[1]
		if strings.HasPrefix(url, "//") {
			url = "https:" + url
		} else if strings.HasPrefix(url, "/") {
			// relative path — prepend base
			if idx := strings.Index(baseURL[8:], "/"); idx >= 0 {
				url = baseURL[:8+idx] + url
			} else {
				url = baseURL + url
			}
		}
		if _, ok := seen[url]; !ok && strings.HasPrefix(url, "http") {
			seen[url] = struct{}{}
			urls = append(urls, url)
		}
	}
	return urls
}
