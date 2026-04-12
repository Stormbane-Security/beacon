package portscan

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/stormbane-security/beacon/internal/scan"
)

// Version extraction helpers for common service banners.
// Each function returns (product, version). Version may be empty when
// the banner identifies the product but omits a version number.

// ExtractHTTPServerVersion parses the Server header for product and version.
// Returns (product, version) e.g. ("nginx", "1.25.3") or ("Apache", "2.4.58").
func ExtractHTTPServerVersion(serverHeader string) (string, string) {
	if serverHeader == "" {
		return "", ""
	}
	serverHeader = strings.TrimSpace(serverHeader)

	// Common patterns:
	//   nginx/1.25.3
	//   Apache/2.4.58 (Ubuntu)
	//   Microsoft-IIS/10.0
	//   openresty/1.21.4.2
	//   LiteSpeed
	//   Caddy
	//   cloudflare

	// Try "product/version" format first.
	if idx := strings.IndexByte(serverHeader, '/'); idx > 0 {
		product := serverHeader[:idx]
		rest := serverHeader[idx+1:]
		// Version ends at space or end of string.
		version := rest
		if sp := strings.IndexAny(rest, " \t("); sp > 0 {
			version = rest[:sp]
		}
		return product, strings.TrimSpace(version)
	}

	// No slash — product name only (e.g. "cloudflare", "LiteSpeed", "Caddy").
	product := serverHeader
	if sp := strings.IndexAny(product, " \t"); sp > 0 {
		product = product[:sp]
	}
	return product, ""
}

// ExtractSSHVersion parses an SSH banner for product and version.
// SSH-2.0-OpenSSH_9.6 → ("OpenSSH", "9.6")
// SSH-2.0-dropbear_2022.83 → ("dropbear", "2022.83")
func ExtractSSHVersion(banner string) (string, string) {
	// parseSSHVersion already extracts the software field like "OpenSSH_9.6p1"
	sw := parseSSHVersion(banner)
	if sw == "" {
		return "", ""
	}

	// Split on underscore: product_version
	if idx := strings.IndexByte(sw, '_'); idx > 0 {
		product := sw[:idx]
		version := sw[idx+1:]
		// Strip patch suffix for clean version (e.g. "9.6p1" → "9.6p1", keep it)
		return product, version
	}

	// No underscore — treat whole thing as product.
	return sw, ""
}

// ExtractSMTPVersion parses an SMTP 220 banner for product and version.
// "220 mail.example.com ESMTP Postfix (Ubuntu)" → ("Postfix", "")
// "220 mail.example.com ESMTP Exim 4.97.1 ..." → ("Exim", "4.97.1")
// "220 mail.example.com Microsoft ESMTP MAIL Service" → ("Microsoft ESMTP MAIL Service", "")
func ExtractSMTPVersion(banner string) (string, string) {
	if !strings.HasPrefix(banner, "220") {
		return "", ""
	}

	lower := strings.ToLower(banner)

	// Exim: "Exim 4.97.1"
	if idx := strings.Index(lower, "exim"); idx >= 0 {
		rest := banner[idx:]
		return extractProductVersion(rest)
	}

	// Postfix
	if strings.Contains(lower, "postfix") {
		return "Postfix", ""
	}

	// Sendmail: "Sendmail 8.17.2"
	if idx := strings.Index(lower, "sendmail"); idx >= 0 {
		rest := banner[idx:]
		return extractProductVersion(rest)
	}

	// Microsoft ESMTP
	if strings.Contains(lower, "microsoft") {
		return "Microsoft ESMTP", ""
	}

	// Haraka
	if strings.Contains(lower, "haraka") {
		return "Haraka", ""
	}

	return "", ""
}

// ExtractFTPVersion parses an FTP 220 banner for product and version.
// "220 (vsFTPd 3.0.5)" → ("vsFTPd", "3.0.5")
// "220 ProFTPD 1.3.6 Server (hostname)" → ("ProFTPD", "1.3.6")
// "220 FileZilla Server 1.8.1" → ("FileZilla Server", "1.8.1")
func ExtractFTPVersion(banner string) (string, string) {
	fv := parseFTPVersion(banner)
	if fv == "" {
		return "", ""
	}
	return extractProductVersion(fv)
}

// extractProductVersion splits "Product X.Y.Z extra" into ("Product", "X.Y.Z").
// Handles multi-word product names before the version number.
var versionRe = regexp.MustCompile(`^(.+?)\s+(\d[\d.]+\S*)`)

func extractProductVersion(s string) (string, string) {
	s = strings.TrimSpace(s)
	m := versionRe.FindStringSubmatch(s)
	if m != nil {
		return strings.TrimSpace(m[1]), m[2]
	}
	// No version found — return the whole string as product.
	return s, ""
}

// extractJSONField does a lightweight extraction of a top-level string field
// from a JSON object without a full unmarshal. Returns "" when the field is
// missing or the body is not JSON.
func extractJSONField(body, field string) string {
	// Look for "field":"value" or "field": "value".
	needle := `"` + field + `"`
	idx := strings.Index(body, needle)
	if idx < 0 {
		return ""
	}
	rest := body[idx+len(needle):]
	// Skip optional whitespace and colon.
	rest = strings.TrimLeft(rest, " \t\r\n")
	if len(rest) == 0 || rest[0] != ':' {
		return ""
	}
	rest = strings.TrimLeft(rest[1:], " \t\r\n")
	if len(rest) == 0 || rest[0] != '"' {
		return ""
	}
	rest = rest[1:] // skip opening quote
	end := strings.IndexByte(rest, '"')
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// versionBefore parses two dot-separated version strings and returns true when
// a < b. Each segment is compared numerically when possible, lexicographically
// otherwise. Missing trailing segments are treated as 0 (e.g. "2.7" < "2.7.1").
func versionBefore(a, b string) bool {
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")
	maxLen := len(aParts)
	if len(bParts) > maxLen {
		maxLen = len(bParts)
	}
	for i := 0; i < maxLen; i++ {
		av, bv := 0, 0
		if i < len(aParts) {
			// Strip non-numeric suffix (e.g. "3rc1" → 3).
			numStr := aParts[i]
			for j, c := range numStr {
				if c < '0' || c > '9' {
					numStr = numStr[:j]
					break
				}
			}
			_, _ = fmt.Sscanf(numStr, "%d", &av)
		}
		if i < len(bParts) {
			numStr := bParts[i]
			for j, c := range numStr {
				if c < '0' || c > '9' {
					numStr = numStr[:j]
					break
				}
			}
			_, _ = fmt.Sscanf(numStr, "%d", &bv)
		}
		if av < bv {
			return true
		}
		if av > bv {
			return false
		}
	}
	return false // equal
}

// parseErlangOTPVersion extracts an OTP version from an SSH banner.
// Erlang SSH banners look like "SSH-2.0-Erlang/OTP" (no version) or
// "SSH-2.0-Erlang-OTP_27.3.2" or similar patterns.
// Returns the OTP version string (e.g. "27.3.2") or "".
func parseErlangOTPVersion(banner string) string {
	lower := strings.ToLower(banner)
	// Pattern: Erlang/OTP followed by space or underscore then version.
	for _, prefix := range []string{"erlang/otp_", "erlang-otp_", "erlang/otp ", "erlang-otp "} {
		if idx := strings.Index(lower, prefix); idx >= 0 {
			rest := banner[idx+len(prefix):]
			// Version is digits and dots until space or end.
			end := strings.IndexAny(rest, " \t\r\n")
			if end < 0 {
				end = len(rest)
			}
			ver := strings.TrimSpace(rest[:end])
			if ver != "" && ver[0] >= '0' && ver[0] <= '9' {
				return ver
			}
		}
	}
	return ""
}

// parseWebLogicVersion extracts the WebLogic version from console login page HTML.
// Looks for patterns like "WebLogic Server Version: 12.2.1.4.0" or
// "WebLogic Server 14.1.1.0" in the page body.
var weblogicVersionRe = regexp.MustCompile(`(?i)WebLogic\s+(?:Server\s+)?(?:Version:?\s*)?(\d+\.\d+[\d.]*)`)

func parseWebLogicVersion(body string) string {
	m := weblogicVersionRe.FindStringSubmatch(body)
	if m != nil {
		return m[1]
	}
	return ""
}

// parseSaltVersion extracts the Salt version from the Salt API root response.
// The Salt API typically returns JSON with a "return" field containing version info.
var saltVersionRe = regexp.MustCompile(`(?i)(?:salt|version)["\s:]*(\d+\.\d+[\d.]*)`)

func parseSaltVersion(body string) string {
	m := saltVersionRe.FindStringSubmatch(body)
	if m != nil {
		return m[1]
	}
	return ""
}

// extractTomcatVersion extracts the Apache Tomcat version from an HTTP response
// body. Tomcat error pages typically contain "Apache Tomcat/9.0.30" or similar.
var tomcatVersionRe = regexp.MustCompile(`(?i)Apache Tomcat/(\d+\.\d+[\d.]*)`)

func extractTomcatVersion(body string) string {
	m := tomcatVersionRe.FindStringSubmatch(body)
	if m != nil {
		return m[1]
	}
	return ""
}

// ExtractHTTPTitle extracts the content of the <title> tag from an HTML body.
// Returns "" if no title is found.
func ExtractHTTPTitle(body string) string {
	// Case-insensitive search for <title> ... </title>.
	lower := strings.ToLower(body)
	start := strings.Index(lower, "<title")
	if start < 0 {
		return ""
	}
	// Skip past the opening tag (handle <title> or <title attr="...">).
	gt := strings.IndexByte(lower[start:], '>')
	if gt < 0 {
		return ""
	}
	contentStart := start + gt + 1
	end := strings.Index(lower[contentStart:], "</title>")
	if end < 0 {
		return ""
	}
	title := strings.TrimSpace(body[contentStart : contentStart+end])
	// Collapse whitespace and limit length.
	title = strings.Join(strings.Fields(title), " ")
	if len(title) > 200 {
		title = title[:200] + "..."
	}
	return title
}

// enrichHTTPEvidence makes a quick HTTP GET to host:port/ and adds
// "http_title", "server_product", and "server_version" to the evidence map
// when available. Called for HTTP service_identified findings to provide
// useful fingerprint data without a dedicated probe match.
func enrichHTTPEvidence(ctx context.Context, host string, port int, useTLS bool, ev map[string]any) {
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	u := fmt.Sprintf("%s://%s:%d/", scheme, host, port)
	client := scan.SharedClient(httpTimeout)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer func() { _ = resp.Body.Close() }()

	// Extract Server header.
	if server := resp.Header.Get("Server"); server != "" {
		ev["server_header"] = server
		product, version := ExtractHTTPServerVersion(server)
		if product != "" {
			ev["server_product"] = product
		}
		if version != "" {
			ev["server_version"] = version
		}
	}

	// Read body for title extraction (limit to 16KB to avoid large downloads).
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	if err != nil || len(body) == 0 {
		return
	}
	if title := ExtractHTTPTitle(string(body)); title != "" {
		ev["http_title"] = title
	}
}

// parseMemcachedVersion extracts the version from a Memcached stats response.
// The response contains lines like "STAT version 1.6.22\r\n".
func parseMemcachedVersion(statsResp string) string {
	for _, line := range strings.Split(statsResp, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "STAT version ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "STAT version "))
		}
	}
	return ""
}

// parseGhostVersion extracts the Ghost CMS version from a meta tag or API response.
// Looks for content="Ghost X.Y.Z" in meta tags or "version":"X.Y.Z" in JSON.
func parseGhostVersion(body string) string {
	// Try meta tag: <meta name="generator" content="Ghost 5.82">
	lower := strings.ToLower(body)
	if idx := strings.Index(lower, "content=\"ghost "); idx >= 0 {
		rest := body[idx+len("content=\"Ghost "):]
		if end := strings.IndexByte(rest, '"'); end > 0 && end < 20 {
			return strings.TrimSpace(rest[:end])
		}
	}
	// Try JSON field from API response.
	if ver := parseJSONStringField(body, "version"); ver != "" {
		return ver
	}
	return ""
}

// parseXMLKeyValue extracts the text content of a Splunk-style XML key element:
// <s:key name="version">9.2.1</s:key>
// Returns the value string or "" if not found.
func parseXMLKeyValue(body, keyName string) string {
	needle := `name="` + keyName + `">`
	idx := strings.Index(body, needle)
	if idx < 0 {
		// Try without namespace prefix.
		needle = `name="` + keyName + `">`
		idx = strings.Index(strings.ToLower(body), strings.ToLower(needle))
		if idx < 0 {
			return ""
		}
	}
	rest := body[idx+len(needle):]
	end := strings.Index(rest, "<")
	if end <= 0 || end > 40 {
		return ""
	}
	return strings.TrimSpace(rest[:end])
}
