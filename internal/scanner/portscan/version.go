package portscan

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
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
func enrichHTTPEvidence(ctx context.Context, host string, port int, ev map[string]any) {
	// Try HTTPS first if port is TLS-capable, otherwise plain HTTP.
	useTLS := isTLSCapable(ctx, host, port)
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	u := fmt.Sprintf("%s://%s:%d/", scheme, host, port)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		DialContext:     (&net.Dialer{Timeout: dialTimeout}).DialContext,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Timeout:   httpTimeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

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
