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
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+asset, nil)
	if resp, err := client.Do(req); err != nil {
		scheme = "http"
	} else {
		resp.Body.Close()
	}

	wsScheme := "ws"
	if scheme == "https" {
		wsScheme = "wss"
	}

	var findings []finding.Finding

	for _, path := range candidatePaths {
		wsURL := wsScheme + "://" + asset + path
		httpURL := scheme + "://" + asset + path

		f := probeCWSH(ctx, client, httpURL, wsURL, asset)
		if f != nil {
			findings = append(findings, *f)
		}
	}

	return findings, nil
}

// probeCWSH sends a WebSocket upgrade with a forged Origin.
// Returns a finding if the server accepts the handshake, nil otherwise.
func probeCWSH(ctx context.Context, client *http.Client, httpURL, wsURL, asset string) *finding.Finding {
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
		if resp != nil {
			resp.Body.Close()
		}
		return nil
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 512)) //nolint:errcheck

	// 101 = server completed the WebSocket handshake with our forged Origin.
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil
	}

	return &finding.Finding{
		CheckID:  "websocket.cswsh",
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Title:    fmt.Sprintf("Cross-Site WebSocket Hijacking (CSWSH) at %s", wsURL),
		Description: "The WebSocket endpoint accepted an upgrade request from an untrusted Origin " +
			"(evil-beacon-probe.example.com). Any malicious webpage can open a WebSocket connection " +
			"to this endpoint using a victim user's session cookies, reading and writing messages " +
			"on their behalf. The server must validate the Origin header against an allowlist.",
		Asset: asset,
		ProofCommand: fmt.Sprintf(
			`curl -si -H "Connection: Upgrade" -H "Upgrade: websocket" -H "Sec-WebSocket-Version: 13" `+
				`-H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" -H "Origin: https://evil-beacon-probe.example.com" %s`,
			httpURL),
		Evidence: map[string]any{
			"url":           wsURL,
			"forged_origin": "https://evil-beacon-probe.example.com",
			"response_code": resp.StatusCode,
		},
	}
}
