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
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // SHA-1 required by RFC 6455 WebSocket protocol
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/scan"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)


func init() {
	scan.RegisterWithCheckDecls(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	},
		scan.Check(finding.CheckWebSocketCSWSH, finding.SeverityHigh, finding.ModeDeep),
		scan.Check(finding.CheckWebSocketMsgInjection, finding.SeverityHigh, finding.ModeDeep),
	)
}
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
	if scanType != module.ScanDeep && scanType != module.ScanAuthorized {
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+asset, nil)
	if err != nil {
		scheme = "http"
	} else if resp, err := client.Do(req); err != nil {
		scheme = "http"
	} else {
		for _, c := range resp.Cookies() {
			if looksLikeSessionCookie(c) {
				sessionCookies = append(sessionCookies, c.Name)
			}
		}
		_ = resp.Body.Close()
	}

	wsScheme := "ws"
	if scheme == "https" {
		wsScheme = "wss"
	}

	// Skip catch-all servers that return 200 for any path — WS probes would
	// all be false positives on such servers.
	baseline := scan.DetectCatchAll(ctx, client, scheme+"://"+asset)
	if baseline.IsCatchAll {
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

		// Probe for WebSocket message injection (XSS via echo).
		if f := probeMsgInjection(ctx, scheme, asset, path); f != nil {
			findings = append(findings, *f)
		}
	}

	return findings, nil
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
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 512)) //nolint:errcheck

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
		CheckID:     finding.CheckWebSocketCSWSH,
		Module:      "deep",
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
		DiscoveredAt: time.Now(),
	}
}

// xssPayload is the injection string we send over the WebSocket. If the server
// echoes it back without sanitization, it indicates a message injection flaw
// that could lead to XSS when the content is rendered in a browser.
const xssPayload = `<img src=x onerror=alert('beacon-ws-probe')>`

// probeMsgInjection performs a raw WebSocket upgrade handshake, sends an XSS
// payload, and checks if the server echoes it back unsanitized.
func probeMsgInjection(ctx context.Context, scheme, asset, path string) *finding.Finding {
	host := asset
	port := "443"
	if scheme == "http" {
		port = "80"
	}
	if h, p, err := net.SplitHostPort(asset); err == nil {
		host = h
		port = p
	}

	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(dialCtx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))

	// Generate a random WebSocket key.
	keyBytes := make([]byte, 16)
	_, _ = rand.Read(keyBytes)
	wsKey := base64.StdEncoding.EncodeToString(keyBytes)

	// Send HTTP/1.1 upgrade request.
	httpURL := scheme + "://" + asset + path
	upgradeReq := fmt.Sprintf(
		"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Connection: Upgrade\r\n"+
			"Upgrade: websocket\r\n"+
			"Sec-WebSocket-Version: 13\r\n"+
			"Sec-WebSocket-Key: %s\r\n"+
			"\r\n",
		path, asset, wsKey)
	if _, err := conn.Write([]byte(upgradeReq)); err != nil {
		return nil
	}

	// Read the HTTP response.
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		return nil
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil
	}

	// Verify the Sec-WebSocket-Accept header (RFC 6455 section 4.2.2).
	expectedAccept := computeAcceptKey(wsKey)
	if resp.Header.Get("Sec-WebSocket-Accept") != expectedAccept {
		return nil
	}

	// Send a text frame with the XSS payload.
	if err := writeWSTextFrame(conn, []byte(xssPayload)); err != nil {
		return nil
	}

	// Read a response frame.
	echoData, err := readWSFrame(conn)
	if err != nil {
		return nil
	}

	echoStr := string(echoData)

	// Check if the server echoed the payload without sanitization.
	if !strings.Contains(echoStr, "<img") && !strings.Contains(echoStr, "onerror") {
		return nil
	}

	wsScheme := "ws"
	if scheme == "https" {
		wsScheme = "wss"
	}
	wsURL := wsScheme + "://" + asset + path

	return &finding.Finding{
		CheckID:  finding.CheckWebSocketMsgInjection,
		Module:   "deep",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Title:    fmt.Sprintf("WebSocket message injection (XSS echo) at %s", wsURL),
		Description: fmt.Sprintf(
			"The WebSocket endpoint at %s echoes user-supplied messages without sanitization. "+
				"The injected payload %q was reflected back verbatim. If these messages are rendered "+
				"in a browser (e.g., chat, dashboard, log viewer), this enables cross-site scripting (XSS) "+
				"attacks via WebSocket message injection.", httpURL, xssPayload),
		Asset: asset,
		ProofCommand: fmt.Sprintf(
			`echo '%s' | npx wscat --connect %s`,
			xssPayload, wsURL),
		Evidence: map[string]any{
			"url":       wsURL,
			"payload":   xssPayload,
			"echo":      echoStr,
			"sanitized": false,
		},
		DiscoveredAt: time.Now(),
	}
}

// computeAcceptKey computes the Sec-WebSocket-Accept value per RFC 6455 section 4.2.2.
func computeAcceptKey(key string) string {
	const websocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	h := sha1.New() //nolint:gosec // SHA-1 required by RFC 6455
	_, _ = h.Write([]byte(key + websocketGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// writeWSTextFrame writes a masked WebSocket text frame (opcode 0x1).
func writeWSTextFrame(conn net.Conn, payload []byte) error {
	// Frame: FIN=1, opcode=text(0x1), MASK=1 (client must mask per RFC 6455).
	frame := []byte{0x81} // FIN + text opcode

	pLen := len(payload)
	switch {
	case pLen <= 125:
		frame = append(frame, byte(pLen)|0x80) // Set MASK bit
	case pLen <= 65535:
		frame = append(frame, 126|0x80)
		frame = append(frame, byte(pLen>>8), byte(pLen))
	default:
		frame = append(frame, 127|0x80)
		lenBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(lenBytes, uint64(pLen))
		frame = append(frame, lenBytes...)
	}

	// Masking key (4 random bytes).
	mask := make([]byte, 4)
	_, _ = rand.Read(mask)
	frame = append(frame, mask...)

	// Mask the payload.
	masked := make([]byte, pLen)
	for i := range payload {
		masked[i] = payload[i] ^ mask[i%4]
	}
	frame = append(frame, masked...)

	_, err := conn.Write(frame)
	return err
}

// readWSFrame reads a single WebSocket frame and returns the payload.
func readWSFrame(conn net.Conn) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	masked := (header[1] & 0x80) != 0
	length := int64(header[1] & 0x7F)

	switch length {
	case 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(conn, ext); err != nil {
			return nil, err
		}
		length = int64(binary.BigEndian.Uint16(ext))
	case 127:
		ext := make([]byte, 8)
		if _, err := io.ReadFull(conn, ext); err != nil {
			return nil, err
		}
		length = int64(binary.BigEndian.Uint64(ext))
	}

	// Limit read to prevent memory exhaustion.
	if length > 65536 {
		return nil, fmt.Errorf("frame too large: %d bytes", length)
	}

	var mask []byte
	if masked {
		mask = make([]byte, 4)
		if _, err := io.ReadFull(conn, mask); err != nil {
			return nil, err
		}
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}

	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}

	return payload, nil
}
