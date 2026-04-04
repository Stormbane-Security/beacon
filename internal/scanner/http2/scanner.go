// Package http2 detects HTTP/2 CONTINUATION frame flood vulnerability
// (CVE-2024-27316, CVE-2024-24549, CVE-2024-30255, CVE-2024-28182).
// Sends an HTTP/2 request with excessive CONTINUATION frames to check if
// the server properly limits header processing.
package http2

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scan"
)

func init() {
	scan.RegisterWithCheckDecls(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	},
		scan.Check(finding.CheckHTTP2ContinuationFlood, finding.SeverityHigh, finding.ModeDeep),
	)
}

const scannerName = "http2check"

type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	// Deep mode only — sends active probes.
	if scanType != module.ScanDeep && scanType != module.ScanAuthorized {
		return nil, nil
	}

	// Check if the server supports HTTP/2 via ALPN.
	supportsH2, err := checkALPN(ctx, asset)
	if err != nil || !supportsH2 {
		return nil, nil
	}

	// Send a raw HTTP/2 connection with excessive CONTINUATION frames.
	vulnerable, err := probeContinuationFlood(ctx, asset)
	if err != nil || !vulnerable {
		return nil, nil
	}

	return []finding.Finding{{
		CheckID:  finding.CheckHTTP2ContinuationFlood,
		Module:   "deep",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Asset:    asset,
		Title:    fmt.Sprintf("HTTP/2 CONTINUATION flood vulnerability on %s", asset),
		Description: fmt.Sprintf(
			"%s accepted an excessive number of HTTP/2 CONTINUATION frames without "+
				"closing the connection or sending a GOAWAY. This indicates vulnerability "+
				"to CVE-2024-27316 (Apache httpd), CVE-2024-24549 (Tomcat), "+
				"CVE-2024-30255 (Envoy), or CVE-2024-28182 (nghttp2). "+
				"An attacker can exhaust server memory by sending endless CONTINUATION frames.",
			asset,
		),
		Evidence: map[string]any{
			"cves": []string{"CVE-2024-27316", "CVE-2024-24549", "CVE-2024-30255", "CVE-2024-28182"},
		},
		ProofCommand: fmt.Sprintf("curl -v --http2 https://%s/ 2>&1 | grep -i 'ALPN'", asset),
		DiscoveredAt: time.Now(),
	}}, nil
}

// checkALPN negotiates TLS with ALPN to check for h2 support.
func checkALPN(ctx context.Context, asset string) (bool, error) {
	d := &tls.Dialer{
		Config: &tls.Config{
			NextProtos:         []string{"h2", "http/1.1"},
			InsecureSkipVerify: true,
		},
	}

	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	conn, err := d.DialContext(dialCtx, "tcp", asset+":443")
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()

	tlsConn := conn.(*tls.Conn)
	return tlsConn.ConnectionState().NegotiatedProtocol == "h2", nil
}

// probeContinuationFlood sends a raw HTTP/2 connection preface followed by
// excessive CONTINUATION frames. If the server doesn't drop the connection
// after a reasonable number, it's vulnerable.
func probeContinuationFlood(ctx context.Context, asset string) (bool, error) {
	dialCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	d := &tls.Dialer{
		Config: &tls.Config{
			NextProtos:         []string{"h2"},
			InsecureSkipVerify: true,
		},
	}

	conn, err := d.DialContext(dialCtx, "tcp", asset+":443")
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.(*tls.Conn)

	// HTTP/2 connection preface.
	preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	if _, err := conn.Write(preface); err != nil {
		return false, err
	}

	// SETTINGS frame (empty, type=0x04, flags=0x00, stream=0, length=0).
	settingsFrame := []byte{0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00}
	if _, err := conn.Write(settingsFrame); err != nil {
		return false, err
	}

	// HEADERS frame (type=0x01) WITHOUT END_HEADERS flag (flags=0x00),
	// on stream 1. Minimal HPACK-encoded :method GET, :path /.
	hpackPayload := []byte{0x82, 0x84, 0x86, 0x41, 0x8a, 0x08, 0x9d, 0x5c, 0x0b, 0x81, 0x70, 0xdc, 0x78, 0x0f, 0x03}
	headersFrame := make([]byte, 9+len(hpackPayload))
	headersFrame[0] = byte(len(hpackPayload) >> 16)
	headersFrame[1] = byte(len(hpackPayload) >> 8)
	headersFrame[2] = byte(len(hpackPayload))
	headersFrame[3] = 0x01 // HEADERS type
	headersFrame[4] = 0x00 // No END_HEADERS
	headersFrame[8] = 0x01 // Stream ID = 1
	copy(headersFrame[9:], hpackPayload)
	if _, err := conn.Write(headersFrame); err != nil {
		return false, err
	}

	// Send CONTINUATION frames (type=0x09) without END_HEADERS.
	// A safe server should reject after a few. We send 50.
	continuationPayload := []byte{0x40, 0x84, 0x62, 0x86, 0x21, 0x44, 0x86, 0x62, 0x86, 0x21, 0x44}
	for i := 0; i < 50; i++ {
		contFrame := make([]byte, 9+len(continuationPayload))
		contFrame[0] = byte(len(continuationPayload) >> 16)
		contFrame[1] = byte(len(continuationPayload) >> 8)
		contFrame[2] = byte(len(continuationPayload))
		contFrame[3] = 0x09 // CONTINUATION type
		contFrame[4] = 0x00 // No END_HEADERS
		contFrame[8] = 0x01 // Stream ID = 1
		copy(contFrame[9:], continuationPayload)
		if _, err := conn.Write(contFrame); err != nil {
			// Connection closed — server properly rejected.
			return false, nil
		}
	}

	// If we got here, send one final CONTINUATION with END_HEADERS.
	finalFrame := make([]byte, 9)
	finalFrame[3] = 0x09 // CONTINUATION type
	finalFrame[4] = 0x04 // END_HEADERS
	finalFrame[8] = 0x01 // Stream ID = 1
	if _, err := conn.Write(finalFrame); err != nil {
		return false, nil
	}

	// Try to read response — if we get data back, the server accepted all frames.
	buf := make([]byte, 256)
	_ = conn.(net.Conn).SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		// Timeout or close — check if we got a GOAWAY.
		return false, nil
	}
	// If we got a response after 50 CONTINUATION frames, the server is vulnerable.
	_ = n
	return true, nil
}
