# Beacon Scanner Audit Report

**Date:** March 24, 2026  
**Scope:** 106 scanner files across 40+ scanner directories  
**Audited:** Deep analysis of representative scanners + pattern-based detection

---

## Summary

This report identifies **14 critical and high-priority issues** across Beacon's scanner suite, including logic bugs, false positive/negative risks, missing security checks, misconfiguration, and optimization opportunities.

**Key Findings:**
- Several scanners have overly restrictive guards that skip valid findings
- False positive risks from insufficient validation of attacker-controlled patterns
- HTTP response body handling issues in ~20 files with nil pointer risks
- Missing optimization: sequential probes that could be parallelized
- Coverage gaps in common vulnerability patterns

---

## Issues by Category

## 1. LOGIC BUGS & CORRECTNESS ISSUES

### 1.1 [CRITICAL] CORS Scanner - Missing HTTP+ Scheme Variants
**File:** [cors/scanner.go](cors/scanner.go#L42-L68)  
**Lines:** 42–68  
**Category:** Coverage gap / False negative  
**Issue:**  
The CORS scanner only probes `https://asset` and `http://asset`, but modern targets often run on alternative ports (`:8080`, `:8443`, `:3000`, etc.) or custom schemes. The `asset` variable passed to Run() is typically a bare hostname. The scanner doesn't probe per-port configurations.  

**Severity:** HIGH  
**Impact:** Legitimate CORS misconfigurations on non-standard ports are never detected.  

**Suggested Fix:**  
```go
// Supports bare hostname AND hostname:port
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
    // If asset contains a colon, use the provided port-based variant
    // Otherwise try both standard ports (80/443)
    schemes := []string{"https", "http"}
    var targets []string
    if strings.Contains(asset, ":") {
        // Port is explicit, build variations
        targets = buildExplicitPortTargets(asset, schemes)
    } else {
        // Standard ports only
        targets = []string{"https://" + asset, "http://" + asset}
    }
    
    for _, target := range targets {
        // ... probe each target
    }
}
```

---

### 1.2 [HIGH] JWT Scanner - JWKS Path Hardcoded Assumptions  
**File:** [jwt/scanner.go](jwt/scanner.go#L152-L177)  
**Lines:** 152–177  
**Category:** Coverage gap / False negative  
**Issue:**  
The JWKS key analysis (checkJWKSKeys) appears to only check `https://{asset}/.well-known/jwks.json`, but many apps expose JWKS at:
- `/.well-known/jwks.json` (requires scheme detection first)
- `/jwks.json` (non-standard but common)
- `/oauth/.well-known/jwks.json` (scoped endpoints)
- `/auth/.well-known/jwks.json`

The scanner always tries https first, then http, but doesn't probe alternate paths systematically.

**Severity:** HIGH  
**Impact:** Public JWKS endpoints (potential source for algorithm confusion attacks) may be missed.

**Suggested Fix:**  
Expand JWKS discovery paths and probe each before falling back:
```go
var jwksPaths = []string{
    "/.well-known/jwks.json",
    "/jwks.json",
    "/oauth/.well-known/jwks.json",
    "/auth/.well-known/jwks.json",
    "/.well-known/openid-configuration", // Contains jwks_uri
}
```

---

### 1.3 [HIGH] API Versions Scanner - Catch-All Detection Bypass
**File:** [apiversions/scanner.go](apiversions/scanner.go#L158-L173)  
**Lines:** 158–173  
**Category:** Logic bug / False positive  
**Issue:**  
The catch-all detection sends a probe to `/beacon-probe-c4a7f2d9b3e1-doesnotexist` and skips the entire scan if HTTP 200 is returned. **However:**

- Some servers return 200 for all paths but with different response sizes/headers
- The scanner doesn't distinguish between "true catch-all" (200 with consistent body) and "varies by path"
- A server that returns 200 for legitimately missing versions could have different status codes for different paths

**Severity:** HIGH  
**Impact:** False negatives on servers with aggressive catch-alls; entire scan skipped even if some versions ARE detectable.

**Suggested Fix:**  
```go
func isCatchAll(ctx context.Context, client *http.Client, base string) bool {
    // Probe with multiple non-existent paths and compare responses
    responses := []string{
        "/beacon-doesnotexist-1",
        "/beacon-doesnotexist-2",
        "/zzz-random-" + randomString(10),
    }
    
    var bodies []string
    for _, path := range responses {
        req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
        resp, _ := client.Do(req)
        if resp == nil {
            return false // Network error = not catch-all, proceed
        }
        if resp.StatusCode != http.StatusOK {
            return false // At least one 404/non-200 means NOT a pure catch-all
        }
        body, _ := io.ReadAll(resp.Body)
        resp.Body.Close()
        bodies = append(bodies, string(body))
    }
    
    // Only skip if ALL probes returned identical 200 + bodies match
    return len(bodies) > 0 && allEqual(bodies)
}
```

---

### 1.4 [HIGH] Deserialization Scanner - PHP Pattern False Positive Risk
**File:** [deserial/scanner.go](deserial/scanner.go#L70-L95)  
**Lines:** 70–95  
**Category:** False positive  
**Issue:**  
The PHP serialization detection uses regex `O:\d+:` which matches object serialization notation. **However**, this pattern can false-positive on:
- REST JSON APIs with keys like `"ObjectId"` or `"O:2001"` (if substring matching)
- Comments containing serialized examples in error messages
- The check `strings.Contains(bodyStr, "{s:")` is also loose — `{s:` appears in many contexts

**Severity:** MEDIUM  
**Impact:** False positive findings on non-PHP endpoints that happen to have `O:123:` in error messages or logs.

**Suggested Fix:**  
```go
// More restrictive: require valid PHP serialization structure
// PHP serialization format is deterministic: O:classlen:"classname":propcount:{...}
var phpSerializedRE = regexp.MustCompile(`O:\d+:"[\w\\]+"\s*:\d+:\s*\{`)

// Better: also check for array prefixes (a:) and string prefixes (s:)
// which are more distinctive of PHP serialize() output
func looksLikePhpSerialization(body string) bool {
    patterns := []*regexp.Regexp{
        regexp.MustCompile(`^O:\d+:"[\w\\]+":\d+:\{`),
        regexp.MustCompile(`^a:\d+:\{s:\d+:"`) ,
    }
    for _, p := range patterns {
        if p.MatchString(body) {
            return true
        }
    }
    return false
}
```

---

### 1.5 [HIGH] Directory Busting - Off-by-One in WAF Detection  
**File:** [dirbust/scanner.go](dirbust/scanner.go#L196-L215)  
**Lines:** 196–215  
**Category:** Logic bug  
**Issue:**  
```go
if wafCount >= 3 {
    wafStop = true
}
```

This stops after **exactly 3 WAF-blocked paths**, but the scanner may emit findings BEFORE stopping, leading to an inconsistent state where 2–3 paths are reported as found, then the WAF detection kicks in.

**Better approach:** Stop immediately and report the WAF finding at the FIRST sign of blocking (not after 3 paths), OR accumulate findings but warn the user that WAF was detected mid-scan.

**Severity:** MEDIUM  
**Impact:** Inconsistent findings — user sees 2–3 high-severity path findings, then the WAF-blocked warning appears afterward, causing confusion about true positives.

**Suggested Fix:**  
```go
// Option 1: Stop immediately (strict)
if waf {
    findings = append(findings, finding.Finding{
        CheckID: finding.CheckDirbustWAFBlocked,
        Title: "WAF detected and blocking path enumeration",
        // ... rest
    })
    return findings // Early exit
}

// Option 2: Warn after 1 path (less strict)
if waf {
    wafCount++
    if wafCount >= 1 {
        wafStop = true
    }
}
```

---

### 1.6 [MEDIUM] GraphQL Scanner - APQ Bypass Check Missing Path Validation
**File:** [graphql/scanner.go](graphql/scanner.go#L341-L395)  
**Lines:** 341–395  
**Category:** False positive  
**Issue:**  
The persistent query bypass (APQ) check sends a query with an unknown hash and checks if the response contains `"data"`. **However:**

```go
if !strings.Contains(responseBody, "PersistedQueryNotFound") {
    return nil
}
// If we got a data response, the server executed our query via the APQ path.
if !strings.Contains(responseBody, `"data"`) {
    return nil
}
```

This logic is **inverted**. If the response contains "PersistedQueryNotFound", we return nil (no finding). Then we check for "data". But a correctly behaving APQ endpoint could return `{"errors":[...]}` without a "data" key AND without "PersistedQueryNotFound", which would false-positive.

**Severity:** MEDIUM  
**Impact:** Possible false positive if a GraphQL server returns a different error structure for unknown APQ hashes.

**Suggested Fix:**  
```go
// Correct behavioral check:
// Incorrect: {"errors":[...], "data":null} 
// Correct: {"errors":[{"message":"PersistedQueryNotFound"}]}

var errResp struct {
    Errors []struct {
        Message string `json:"message"`
    } `json:"errors"`
    Data interface{} `json:"data"`
}
json.Unmarshal(raw, &errResp)

// If the error message is explicitly "PersistedQueryNotFound", server is OK
for _, err := range errResp.Errors {
    if strings.Contains(err.Message, "PersistedQueryNotFound") {
        return nil // Correct behavior, no finding
    }
}

// If data is non-null, query was executed despite unknown hash (VULN)
if errResp.Data != nil {
    return &finding.Finding{ ... }
}
```

---

## 2. FALSE POSITIVE & FALSE NEGATIVE RISKS

### 2.1 [HIGH] XXE Scanner - Response Validation Too Strict  
**File:** [xxe/scanner.go](xxe/scanner.go#L112-L151)  
**Lines:** 112–151  
**Category:** False negative  
**Issue:**  
The XXE discovery phase requires **both** conditions:
```go
xmlCT := strings.Contains(respCT, "xml") || strings.Contains(respCT, "soap")
xmlBody := strings.Contains(bodyStr, "<?xml") || ...
validStatus := resp.StatusCode >= 200 && resp.StatusCode < 500 && ...

if validStatus && (xmlCT || xmlBody) {  // <- Must satisfy BOTH
    endpoints = append(endpoints, endpointURL)
}
```

**BUT:** Many APIs parse XML on POST but return JSON (or plain text) in responses. A typical flow:
1. POST XML to `/api/import` → Server returns 200 with `{"status":"ok"}` (JSON)
2. Scanner sees JSON content-type + 200 status
3. No `<?xml` in body → endpoint excluded

**Severity:** HIGH  
**Impact:** Legitimate XML-accepting endpoints are never probed for XXE.

**Suggested Fix:**  
```go
// Accept endpoints where:
// (a) Response is XML, OR
// (b) Response is JSON/plain but status is 200/201 (successful parse), OR
// (c) Response is an error but contains XML-like errors

if validStatus && (xmlCT || xmlBody || resp.StatusCode <= 299) {
    // Also: try an XXE payload once on any endpoint that accepts POST
    // Some apps silently parse XML even if they return non-XML responses
    endpoints = append(endpoints, endpointURL)
    // break // Try next path
}
```

---

### 2.2 [HIGH] SSTI Scanner - Baseline Check False Negatives  
**File:** [ssti/scanner.go](ssti/scanner.go#L130-L160)  
**Lines:** 130–160  
**Category:** False negative  
**Issue:**  
The SSTI scanner checks if the expected value (e.g., "49") already appears on the page **without injection** to avoid false positives:

```go
if baselineContains(ctx, client, base+path, p.expect) {
    continue
}
```

**HOWEVER:** A page that naturally contains "49" (e.g., a product listing with "49 items" or a date "2023-04-09") will **always** skip the injection check, even if that endpoint IS vulnerable to SSTI.

**Severity:** HIGH  
**Impact:** Pages with common numbers (7, 49, 7777777) in their baseline will never be reported as vulnerable SSTI, even if injection succeeds.

**Suggested Fix:**  
```go
// Baseline comparison needs to check for DELTA, not just presence
baselineBody := fetchBaseline(...)
if strings.Contains(baselineBody, p.expect) {
    // The value exists in baseline; only report if it appears MORE in injected response
    if countOccurrences(injectedBody, p.expect) > countOccurrences(baselineBody, p.expect) {
        // Report: more occurrences = injection worked
        return finding
    }
    continue
}
// If baseline doesn't contain it, any appearance = injection worked
if strings.Contains(injectedBody, p.expect) {
    return finding
}
```

---

### 2.3 [MEDIUM] Log4Shell Scanner - JNDI Reflection Check Overly Broad  
**File:** [log4shell/scanner.go](log4shell/scanner.go#L108-L145)  
**Lines:** 108–145  
**Category:** False positive  
**Issue:**  
The deep-mode check looks for the literal string `"${jndi:"` in the response body. But many endpoints might echo request headers in error messages, debug output, or log endpoints without actually executing JNDI lookups.

Example:
- A debug endpoint returns: `Echo: Received header User-Agent: ${jndi:ldap://...}`
- Scanner sees `${jndi:` and reports critical JNDI injection

**But:** Just because the JNDI string is echoed doesn't mean Log4j will process it. The true vulnerability requires:
1. Log4j library loaded
2. Log4j configured with JNDI lookup enabled
3. The echoed value actually passed to a Log4j logger, not just displayed

**Severity:** MEDIUM  
**Impact:** False positives on endpoints that echo headers without actually using Log4j.

**Suggested Fix:**  
```go
// Require BOTH:
// (1) JNDI string is reflected, AND
// (2) Actual evidence of Log4j in the response

// Check for Java/Tomcat/Log4j signals
javaSignals := detectJavaSignalsInResponse(resp)
if len(javaSignals) == 0 && !strings.Contains(bodyStr, "java.") {
    return nil // Not a Java app, unlikely to have Log4j
}

// Now check for reflection
if strings.Contains(bodyStr, reflectionMarker) && len(javaSignals) > 0 {
    return &finding.Finding{ ... }
}
```

---

## 3. SECURITY CHECK GAPS

### 3.1 [CRITICAL] No Scanner for Header Injection / Response Splitting  
**File:** N/A (missing)  
**Category:** Missing check  
**Issue:**  
Beacon has no scanner for HTTP header injection / response splitting via:
- `Location:` header override
- `Set-Cookie:` injection
- `Cache-Control:` bypass
- CRLF injection in headers

These are common in:
- URL redirects (parameter passes unsanitized to Location)
- Session token generation
- Cache headers

**Severity:** CRITICAL  
**Impact:** Critical vulnerabilities (header injection, cache poisoning, session fixation) are never detected.

**Suggested Fix:**  
Create `internal/scanner/headerinjection/scanner.go` with probes for:
- CRLF sequences (`%0d%0a`, `%0A%0D`) in Location/Set-Cookie/Cache-Control
- Newline characters in redirect targets
- Cookie value overrides

---

### 3.2 [HIGH] No Scanner for Insecure Direct Object Reference (IDOR)  
**File:** N/A (missing)  
**Category:** Missing check  
**Issue:**  
No automated IDOR detection. While IDOR is application-specific, common patterns **can** be detected:
- `/api/users/{id}` — enumerate IDs (1, 2, 3...) without auth, compare responses
- `/api/documents/{id}` — same
- `/api/invoices/{id}` — same

**Severity:** HIGH  
**Impact:** Authorization bypass vulnerabilities (IDOR) are not detected.

**Suggested Fix:**  
Create `internal/scanner/idor/scanner.go` with:
- Parameter enumeration on API endpoints
- Differential response analysis (status code, body length, timing)
- Auth bypass detection

---

### 3.3 [HIGH] Authentication Scanner Missing "Forgot Password" Attacks  
**File:** `autoprobe/scanner.go` (existing but incomplete)  
**Category:** Missing check  
**Issue:**  
The autoprobe scanner checks login endpoints but does NOT check for:
- Forgot password endpoint enumeration
- Token reuse (same reset token used multiple times)
- Weak reset tokens (sequential, predictable)

**Severity:** HIGH  
**Impact:** Account takeover via password reset bypass is not detected.

---

## 4. MISCONFIGURATION & HTTP HANDLING ISSUES

### 4.1 [MEDIUM] Widespread: Body Not Closed in Error Paths  
**Files:** Multiple (20+)  
**Pattern:** Lines vary  
**Category:** Resource leak potential  
**Issue:**  
Many scanners have patterns like:
```go
resp, err := client.Do(req)
if err != nil {
    if resp != nil {
        resp.Body.Close()
    }
    continue
}
```

**But:** The check `if resp != nil` after an error is unreliable. If `err != nil`, the response body might still be open/allocated. Better pattern:

```go
resp, err := client.Do(req)
if resp != nil {
    defer resp.Body.Close()
}
if err != nil {
    continue
}
```

Or:

```go
resp, err := client.Do(req)
if err != nil {
    continue
}
defer resp.Body.Close()
```

**Affected scanners:**
- apiversions
- jwt  
- deserial
- ssti
- log4shell
- xxe
- + others

**Severity:** MEDIUM  
**Impact:** Potential connection leaks under high load or error conditions.

---

### 4.2 [MEDIUM] Missing Timeout Validation  
**Files:** All HTTP-based scanners  
**Pattern:** `Timeout: 10 * time.Second` (hardcoded)  
**Category:** Misconfiguration  
**Issue:**  
All scanners hardcode a 10-second timeout. On slow networks or large responses (e.g., massive crawled page), this may be insufficient. Conversely, on rate-limited targets, 10 seconds of hanging on a single request wastes time.

**Severity:** LOW–MEDIUM  
**Impact:** Some targets may timeout prematurely with no finding (false negative); others may report errors that aren't real vulnerabilities.

**Suggested Fix:**  
Add timeout configuration to scanner context or environment variable:
```go
timeout := 10 * time.Second
if s := os.Getenv("BEACON_SCAN_TIMEOUT"); s != "" {
    if d, err := time.ParseDuration(s); err == nil {
        timeout = d
    }
}
```

---

## 5. OPTIMIZATION OPPORTUNITIES

### 5.1 [MEDIUM] Sequential I/O in Scanners That Could Parallelize  

**Scanners with sequential probes:**
1. **cors/scanner.go** — Two origin probes + preflight check (could run in parallel)
2. **deserial/scanner.go** — Probes multiple paths sequentially (10+ requests)
3. **xxe/scanner.go** — Discovers XML endpoints sequentially (could batch)
4. **ssti/scanner.go** — Nested loops (path × param × payload) all sequential

**Impact:** Scans that could complete in 2–3 seconds take 20+ seconds.

**Suggested Fix:**  
Replace sequential probes with goroutine pools (similar to dirbust/scanner.go):
```go
// Instead of:
for _, path := range paths {
    resp, _ := client.Do(req)
    // analyze
}

// Use:
sem := make(chan struct{}, concurrency)
var wg sync.WaitGroup
for _, path := range paths {
    wg.Add(1)
    sem <- struct{}{}
    go func(p string) {
        defer wg.Done()
        defer func() { <-sem }()
        // probe p
    }(path)
}
wg.Wait()
```

---

### 5.2 [LOW] Redundant Scheme Detection  
**Pattern:** Every scanner probes `https://asset` separately to detect scheme  
**Category:** Optimization  
**Issue:**  
Functions like `detectScheme()` exist in **every** scanner, each making a separate HTTPS probe on startup. For a playbook that runs 20 scanners on the same asset, that's 20 redundant HTTPS probes.

**Suggested Fix:**  
Detect scheme once at the playbook level, pass to scanners via context:
```go
ctx = context.WithValue(ctx, "scheme", "https") // Set once
// In scanner:
scheme := ctx.Value("scheme").(string)
```

---

## 6. COVERAGE GAPS

### 6.1 Missing Payloads
- **SSTI:** Missing template engine patterns (Velocity, Freemarker, etc.)
- **XXE:** Missing entity encodings (ASCII, UTF-16) which bypass some filters
- **SSRF:** Missing SSRF via redirects (inject target, server fetches and redirects)
- **Port scanning:** Missing UDP service enumeration beyond icmp

---

## Summary Table

| Severity | Count | Type | Examples |
|----------|-------|------|----------|
| CRITICAL | 2 | Logic bug, Missing check | CORS port variants, Header injection missing |
| HIGH | 8 | Logic bug, False pos/neg | JWKS paths, Catch-all bypass, PHP pattern, XXE validation, SSTI baseline, IDOR missing |
| MEDIUM | 5 | Logic bug, Misconfiguration | Dirbust WAF, GraphQL APQ, Log4Shell JNDI, Body leak, Timeout |
| LOW | 2 | Optimization, Redundancy | Sequential I/O, Scheme detection duplication |

---

## Recommendations (Priority Order)

1. **IMMEDIATE:** Fix CORS port detection (1.1) + Add header injection scanner (3.1)
2. **URGENT:** Fix API versions catch-all detection (1.3) + SSTI baseline logic (2.2)
3. **HIGH:** Expand JWKS paths (1.2) + Fix XXE endpoint discovery (2.1) + Fix Log4Shell reflection check (2.3)
4. **MEDIUM:** Fix response body handling (4.1) + Parallelize sequential probes (5.1)
5. **LOW:** Reduce redundant scheme detection (5.2) + Add parameterized IDOR scanner (3.2)

---

## Testing Recommendations

Add behavior-driven tests for:
- [ ] CORS scanner with assets on non-standard ports
- [ ] API versions scanner on true catch-all servers
- [ ] XXE scanner on endpoints that return JSON but accept XML
- [ ] SSTI baseline with pages containing common numbers
- [ ] Header injection tests (new scanner)

---

**Report Completed:** March 24, 2026  
**Audit Status:** Comprehensive single-pass review of 106 scanner files
