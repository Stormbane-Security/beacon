// Package wsfuzz performs active WebSocket message fuzzing to detect injection
// vulnerabilities, authentication bypass, and missing origin validation.
//
// Mode: ScanAuthorized — sends active injection payloads via WebSocket
// connections. Requires explicit authorization because payloads may trigger
// server-side effects (SQL queries, command execution, XSS storage).
package wsfuzz

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

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scan"
)

func init() {
	scan.RegisterWithCheckDecls(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	},
		scan.Check(finding.CheckWebSocketInjection, finding.SeverityHigh, finding.ModeDeep),
		scan.Check(finding.CheckWebSocketAuthBypass, finding.SeverityCritical, finding.ModeDeep),
		scan.Check(finding.CheckWebSocketNoOriginCheck, finding.SeverityMedium, finding.ModeSurface),
	)
}

const scannerName = "wsfuzz"

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
	"/chat",
	"/feed",
	"/notifications",
}

// injectionPayloads are fuzz strings sent over WebSocket to detect injection.
type injectionPayload struct {
	name    string
	payload string
	// indicators are strings in the response that suggest the injection hit.
	indicators []string
}

var injectionPayloads = []injectionPayload{
	{
		name:    "SQLi",
		payload: `{"id": "1' OR 1=1-- -"}`,
		indicators: []string{
			"sql", "syntax", "mysql", "postgresql", "sqlite", "oracle",
			"ORA-", "SQLSTATE", "unclosed quotation", "unterminated",
			"query", "database", "column", "table",
		},
	},
	{
		name:    "XSS",
		payload: `{"msg": "<script>alert(1)</script>"}`,
		indicators: []string{
			"<script>", "alert(1)", "onerror", "xss",
		},
	},
	{
		name:    "Command Injection",
		payload: `{"cmd": "; cat /etc/passwd"}`,
		indicators: []string{
			"root:", "/bin/sh", "/bin/bash", "nobody", "daemon",
			"command not found", "sh:", "bash:",
		},
	},
	{
		name:    "Path Traversal",
		payload: `{"file": "../../../etc/passwd"}`,
		indicators: []string{
			"root:", "/bin/sh", "no such file", "permission denied",
		},
	},
}

// Scanner performs WebSocket message fuzzing.
type Scanner struct{}

// New returns a new wsfuzz Scanner.
func New() *Scanner { return &Scanner{} }

// Name returns the scanner identifier.
func (s *Scanner) Name() string { return scannerName }

// Run executes WebSocket fuzzing. Authorized mode runs all injection payloads.
// Deep mode runs origin and auth bypass checks. Surface mode only checks origin.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	scheme := "http"
	wsScheme := "ws"

	// Quick HTTPS check.
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+asset, nil); err == nil {
		if resp, err := client.Do(req); err == nil {
			_ = resp.Body.Close()
			scheme = "https"
			wsScheme = "wss"
		}
	}

	var findings []finding.Finding

	for _, path := range candidatePaths {
		wsURL := wsScheme + "://" + asset + path

		// Surface-safe: check if WebSocket accepts any Origin.
		if f := probeNoOriginCheck(ctx, scheme, asset, path, wsURL); f != nil {
			findings = append(findings, *f)
		}

		if scanType != module.ScanDeep && scanType != module.ScanAuthorized {
			continue
		}

		// Deep: check auth bypass — connect without cookies/auth.
		if f := probeAuthBypass(ctx, scheme, asset, path, wsURL); f != nil {
			findings = append(findings, *f)
		}

		if scanType != module.ScanAuthorized {
			continue
		}

		// Authorized: fuzz with injection payloads.
		for _, payload := range injectionPayloads {
			if f := probeInjection(ctx, scheme, asset, path, wsURL, payload); f != nil {
				findings = append(findings, *f)
				break // One injection finding per endpoint is sufficient.
			}
		}
	}

	return findings, nil
}

// probeNoOriginCheck sends a WebSocket upgrade with a forged Origin header
// and checks if the server completes the handshake without validating Origin.
func probeNoOriginCheck(ctx context.Context, scheme, asset, path, wsURL string) *finding.Finding {
	conn, wsKey, err := dialWebSocket(ctx, scheme, asset, path, "https://evil-attacker.example.com", nil)
	if err != nil {
		return nil
	}
	defer func() { _ = conn.Close() }()

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

	// Verify the handshake is valid.
	expectedAccept := computeAcceptKey(wsKey)
	if resp.Header.Get("Sec-WebSocket-Accept") != expectedAccept {
		return nil
	}

	return &finding.Finding{
		CheckID:  finding.CheckWebSocketNoOriginCheck,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityMedium,
		Asset:    asset,
		Title:    fmt.Sprintf("WebSocket accepts any Origin header at %s", wsURL),
		Description: fmt.Sprintf(
			"The WebSocket endpoint at %s completed the upgrade handshake with a forged "+
				"Origin header (evil-attacker.example.com) without rejecting it. Any webpage "+
				"can open a WebSocket connection to this endpoint using a victim's cookies, "+
				"enabling cross-site WebSocket hijacking (CSWSH). The server should validate "+
				"the Origin header against an allowlist of trusted domains.",
			wsURL),
		ProofCommand: fmt.Sprintf(
			`curl -si --http1.1 -H "Connection: Upgrade" -H "Upgrade: websocket" `+
				`-H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" `+
				`-H "Origin: https://evil-attacker.example.com" %s://%s%s | head -5`,
			scheme, asset, path),
		Evidence: map[string]any{
			"url":           wsURL,
			"forged_origin": "https://evil-attacker.example.com",
			"response_code": resp.StatusCode,
		},
		DiscoveredAt: time.Now(),
	}
}

// probeAuthBypass connects to a WebSocket endpoint without any auth
// headers/cookies and sends a message. If the server responds with data
// (not an error/close), the endpoint has no authentication.
func probeAuthBypass(ctx context.Context, scheme, asset, path, wsURL string) *finding.Finding {
	conn, wsKey, err := dialWebSocket(ctx, scheme, asset, path, scheme+"://"+asset, nil)
	if err != nil {
		return nil
	}
	defer func() { _ = conn.Close() }()

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		return nil
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil
	}

	expectedAccept := computeAcceptKey(wsKey)
	if resp.Header.Get("Sec-WebSocket-Accept") != expectedAccept {
		return nil
	}

	// Send a benign message without any auth context.
	testMsg := `{"type":"ping","data":"beacon-auth-test"}`
	if err := writeWSTextFrame(conn, []byte(testMsg)); err != nil {
		return nil
	}

	// Read response — if we get data back, no auth required.
	echoData, err := readWSFrame(conn)
	if err != nil {
		return nil
	}

	echoStr := string(echoData)
	if len(echoStr) == 0 {
		return nil
	}

	// Check for auth rejection messages — these mean auth IS enforced.
	lower := strings.ToLower(echoStr)
	if strings.Contains(lower, "unauthorized") ||
		strings.Contains(lower, "forbidden") ||
		strings.Contains(lower, "authentication required") ||
		strings.Contains(lower, "not authenticated") ||
		strings.Contains(lower, "invalid token") ||
		strings.Contains(lower, "access denied") {
		return nil
	}

	return &finding.Finding{
		CheckID:  finding.CheckWebSocketAuthBypass,
		Module:   "deep",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Asset:    asset,
		Title:    fmt.Sprintf("WebSocket accepts messages without authentication at %s", wsURL),
		Description: fmt.Sprintf(
			"The WebSocket endpoint at %s accepted a connection and processed a message "+
				"without any authentication headers, cookies, or tokens. An unauthenticated "+
				"attacker can connect and interact with the WebSocket API, potentially "+
				"accessing sensitive data or performing unauthorized actions. Response: %s",
			wsURL, firstN(echoStr, 200)),
		ProofCommand: fmt.Sprintf(
			`echo '{"type":"ping"}' | npx wscat --connect %s --no-check`, wsURL),
		Evidence: map[string]any{
			"url":             wsURL,
			"message_sent":    testMsg,
			"response":        firstN(echoStr, 500),
			"authenticated":   false,
			"no_cookies_sent": true,
		},
		DiscoveredAt: time.Now(),
	}
}

// probeInjection connects to a WebSocket endpoint, sends a normal message to
// establish a baseline, then sends an injection payload and compares responses.
func probeInjection(ctx context.Context, scheme, asset, path, wsURL string, payload injectionPayload) *finding.Finding {
	// First get a baseline response.
	baselineResp, err := sendWSMessage(ctx, scheme, asset, path, `{"data":"normal-test-value"}`)
	if err != nil {
		return nil
	}

	// Now send the injection payload.
	injResp, err := sendWSMessage(ctx, scheme, asset, path, payload.payload)
	if err != nil {
		return nil
	}

	injLower := strings.ToLower(injResp)

	// Check if the response contains injection indicators.
	var matchedIndicator string
	for _, indicator := range payload.indicators {
		if strings.Contains(injLower, strings.ToLower(indicator)) {
			matchedIndicator = indicator
			break
		}
	}

	if matchedIndicator == "" {
		// Also check for generic error differences — a stack trace or error
		// that wasn't in the baseline suggests the injection hit something.
		baselineLower := strings.ToLower(baselineResp)
		hasNewError := false
		errorIndicators := []string{"error", "exception", "traceback", "stack trace", "internal server"}
		for _, ei := range errorIndicators {
			if strings.Contains(injLower, ei) && !strings.Contains(baselineLower, ei) {
				hasNewError = true
				matchedIndicator = ei + " (new error vs baseline)"
				break
			}
		}
		if !hasNewError {
			return nil
		}
	}

	return &finding.Finding{
		CheckID:  finding.CheckWebSocketInjection,
		Module:   "deep",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Asset:    asset,
		Title:    fmt.Sprintf("WebSocket %s injection detected at %s", payload.name, wsURL),
		Description: fmt.Sprintf(
			"The WebSocket endpoint at %s responded differently to a %s injection payload "+
				"compared to a normal message. The response contained the indicator %q, "+
				"suggesting the injected content was processed without proper sanitization. "+
				"Payload sent: %s",
			wsURL, payload.name, matchedIndicator, payload.payload),
		ProofCommand: fmt.Sprintf(
			`echo '%s' | npx wscat --connect %s`, payload.payload, wsURL),
		Evidence: map[string]any{
			"url":               wsURL,
			"injection_type":    payload.name,
			"payload":           payload.payload,
			"matched_indicator": matchedIndicator,
			"baseline_response": firstN(baselineResp, 200),
			"injection_response": firstN(injResp, 200),
		},
		DiscoveredAt: time.Now(),
	}
}

// sendWSMessage opens a fresh WebSocket connection, sends a text message,
// and returns the response.
func sendWSMessage(ctx context.Context, scheme, asset, path, message string) (string, error) {
	conn, wsKey, err := dialWebSocket(ctx, scheme, asset, path, scheme+"://"+asset, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		return "", err
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		return "", fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	expectedAccept := computeAcceptKey(wsKey)
	if resp.Header.Get("Sec-WebSocket-Accept") != expectedAccept {
		return "", fmt.Errorf("invalid Sec-WebSocket-Accept")
	}

	if err := writeWSTextFrame(conn, []byte(message)); err != nil {
		return "", err
	}

	data, err := readWSFrame(conn)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// dialWebSocket performs a raw TCP connection and sends a WebSocket upgrade
// request. Returns the connection (before reading the response), the WS key,
// and any error.
func dialWebSocket(ctx context.Context, scheme, asset, path, origin string, extraHeaders map[string]string) (net.Conn, string, error) {
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
		return nil, "", err
	}
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))

	// Generate a random WebSocket key.
	keyBytes := make([]byte, 16)
	_, _ = rand.Read(keyBytes)
	wsKey := base64.StdEncoding.EncodeToString(keyBytes)

	var sb strings.Builder
	fmt.Fprintf(&sb,
		"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Connection: Upgrade\r\n"+
			"Upgrade: websocket\r\n"+
			"Sec-WebSocket-Version: 13\r\n"+
			"Sec-WebSocket-Key: %s\r\n"+
			"Origin: %s\r\n",
		path, asset, wsKey, origin)

	for k, v := range extraHeaders {
		fmt.Fprintf(&sb, "%s: %s\r\n", k, v)
	}
	sb.WriteString("\r\n")

	if _, err := conn.Write([]byte(sb.String())); err != nil {
		_ = conn.Close()
		return nil, "", err
	}

	return conn, wsKey, nil
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
	frame := []byte{0x81} // FIN + text opcode
	pLen := len(payload)
	switch {
	case pLen <= 125:
		frame = append(frame, byte(pLen)|0x80)
	case pLen <= 65535:
		frame = append(frame, 126|0x80)
		frame = append(frame, byte(pLen>>8), byte(pLen))
	default:
		frame = append(frame, 127|0x80)
		lenBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(lenBytes, uint64(pLen))
		frame = append(frame, lenBytes...)
	}

	mask := make([]byte, 4)
	_, _ = rand.Read(mask)
	frame = append(frame, mask...)

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

// firstN returns the first n characters of s, or s if shorter.
func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
