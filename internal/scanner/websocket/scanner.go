// Package websocket detects Cross-Site WebSocket Hijacking (CSWSH).
// When a WebSocket server does not validate the Origin header, any webpage
// can open a WebSocket connection to it using a victim user's cookies.
// This is the WebSocket equivalent of CSRF.
//
// Detection: send a WebSocket upgrade request with a forged Origin header.
// If the server completes the handshake (101 Switching Protocols), it is
// vulnerable — it trusts any origin. This check requires no authentication
// and no message payload.
package websocket

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const scannerName = "websocket"

// candidatePaths are common WebSocket endpoint paths.
var candidatePaths = []string{
	"/ws",
	"/websocket",
	"/socket",
	"/socket.io/",
	"/cable",
	"/api/ws",
	"/api/websocket",
	"/live",
	"/events",
	"/stream",
}

// Scanner probes for WebSocket CSWSH vulnerabilities.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanDeep {
		return nil, nil
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		// Do not follow redirects — a 101 must come directly.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	scheme := "https"
	var sessionCookies []string
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+asset, nil)
	if resp, err := client.Do(req); err != nil {
		scheme = "http"
	} else {
		for _, c := range resp.Cookies() {
			if looksLikeSessionCookie(c) {
				sessionCookies = append(sessionCookies, c.Name)
			}
		}
		resp.Body.Close()
	}

	wsScheme := "ws"
	if scheme == "https" {
		wsScheme = "wss"
	}

	// Skip catch-all servers that return 200 for any path — WS probes would
	// all be false positives on such servers.
	if isCatchAll(ctx, client, scheme+"://"+asset) {
		return nil, nil
	}

	var findings []finding.Finding

	for _, path := range candidatePaths {
		wsURL := wsScheme + "://" + asset + path
		httpURL := scheme + "://" + asset + path

		f := probeCWSH(ctx, client, httpURL, wsURL, asset, sessionCookies)
		if f != nil {
			findings = append(findings, *f)
		}
	}

	return findings, nil
}

// isCatchAll returns true when the server responds HTTP 200 to a path that
// cannot exist on any real application, indicating a wildcard / catch-all
// config where all path-based probes would be false positives.
func isCatchAll(ctx context.Context, client *http.Client, base string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/beacon-probe-c4a7f2d9b3e1-doesnotexist", nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// looksLikeSessionCookie returns true when a cookie's name matches common
// session / auth token patterns. These indicate the site uses cookie-based
// authentication, which makes CSWSH exploitable for session hijacking.
func looksLikeSessionCookie(c *http.Cookie) bool {
	name := strings.ToLower(c.Name)
	sessionNames := []string{
		"session", "sess", "sid", "jsessionid", "phpsessid",
		"asp.net_sessionid", "connect.sid", "laravel_session",
		"ci_session", "rack.session", "auth", "token", "jwt",
		"access_token", "id_token", "remember_me", "logged_in",
		"user_id", "uid", "identity",
	}
	for _, s := range sessionNames {
		if name == s || strings.HasPrefix(name, s+"_") || strings.HasSuffix(name, "_"+s) {
			return true
		}
	}
	// HttpOnly cookies on authenticated sites are almost always session tokens.
	return c.HttpOnly
}

// probeCWSH sends a WebSocket upgrade with a forged Origin.
// Returns a finding if the server accepts the handshake, nil otherwise.
func probeCWSH(ctx context.Context, client *http.Client, httpURL, wsURL, asset string, sessionCookies []string) *finding.Finding {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, httpURL, nil)
	if err != nil {
		return nil
	}

	// WebSocket upgrade headers
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==") // RFC 6455 example key
	req.Header.Set("Origin", "https://evil-beacon-probe.example.com")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 512)) //nolint:errcheck

	// 101 = server completed the WebSocket handshake with our forged Origin.
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil
	}

	severity := finding.SeverityLow
	var description string
	if len(sessionCookies) > 0 {
		severity = finding.SeverityHigh
		description = fmt.Sprintf(
			"The WebSocket endpoint accepted an upgrade request from an untrusted Origin "+
				"(evil-beacon-probe.example.com). Session cookies were detected on this domain (%s), "+
				"which means a malicious webpage can open a WebSocket connection using a victim's "+
				"authenticated session — reading and writing messages on their behalf. "+
				"The server must validate the Origin header against an allowlist.",
			strings.Join(sessionCookies, ", "))
	} else {
		description = "The WebSocket endpoint accepted an upgrade request from an untrusted Origin " +
			"(evil-beacon-probe.example.com). No session cookies were detected on this domain, " +
			"suggesting this may be a public/unauthenticated endpoint. Impact is limited unless " +
			"authentication is handled client-side (e.g. bearer tokens sent in WS messages). " +
			"The server should still validate the Origin header to prevent unintended cross-origin access."
	}

	return &finding.Finding{
		CheckID:     "websocket.cswsh",
		Module:      "surface",
		Scanner:     scannerName,
		Severity:    severity,
		Title:       fmt.Sprintf("Cross-Site WebSocket Hijacking (CSWSH) at %s", wsURL),
		Description: description,
		Asset:       asset,
		ProofCommand: fmt.Sprintf(
			// wscat is the clearest proof — it performs a real WebSocket handshake.
			// The --http1.1 curl fallback is needed because HTTP/2 servers ignore
			// the Upgrade header and respond with their normal HTTP handler.
			`npx wscat --connect %s --header "Origin: https://evil-beacon-probe.example.com"`+
				"\n# curl fallback (requires HTTP/1.1 — HTTP/2 servers won't upgrade):\n"+
				`curl -si --http1.1 -H "Connection: Upgrade" -H "Upgrade: websocket" -H "Sec-WebSocket-Version: 13" `+
				`-H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" -H "Origin: https://evil-beacon-probe.example.com" %s | head -5`,
			wsURL, httpURL),
		Evidence: map[string]any{
			"url":             wsURL,
			"forged_origin":   "https://evil-beacon-probe.example.com",
			"response_code":   resp.StatusCode,
			"session_cookies": sessionCookies,
		},
	}
}
