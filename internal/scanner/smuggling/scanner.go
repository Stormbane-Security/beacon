// Package smuggling detects HTTP request smuggling vulnerabilities using
// timing-based probes. Deep mode only.
//
// HTTP request smuggling occurs when a front-end proxy and back-end server
// disagree on how to parse a request body containing both Content-Length and
// Transfer-Encoding headers. The disagreement lets an attacker "smuggle" a
// prefix of a second HTTP request into the TCP stream, which the back-end
// appends to the next legitimate user's request. This can bypass security
// controls, poison request routing, hijack sessions, and achieve SSRF.
//
// Detection approach (timing-based, read-only):
//   - CL.TE: send a POST where Content-Length > actual chunked body. If the
//     back-end uses Transfer-Encoding, it finishes reading at the zero-chunk
//     but the front-end (using Content-Length) keeps the connection open,
//     leaving the back-end waiting → measurable read timeout.
//   - TE.CL: send a POST where Transfer-Encoding is chunked but Content-Length
//     is smaller than the full chunked body. If the back-end uses
//     Content-Length it reads only part of the body and the front-end (using
//     TE) is still waiting for us to terminate the stream → timeout.
//
// This scanner does NOT actually smuggle a request prefix (which would affect
// other users). It only causes the server to hold the connection briefly.
package smuggling

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const (
	scannerName = "smuggling"
	checkID     = finding.CheckWebHTTPRequestSmuggling
)

// Timing thresholds — variables so that tests can override them to avoid
// multi-second waits.
var (
	probeTimeout = 6 * time.Second
	baselineMax  = 2 * time.Second // skip target if baseline is already slow
	smuggleDelay = 4 * time.Second // if response takes longer than this, flag it
)

// dialConnFunc is the function used to establish TCP (optionally TLS) connections.
// Tests replace this to inject mock servers without modifying production code paths.
var dialConnFunc = dialConn

// Scanner probes for HTTP request smuggling via timing-based detection.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanDeep {
		return nil, nil
	}

	// Determine host:port and whether to use TLS.
	host, port, useTLS := resolveTarget(ctx, asset)
	if host == "" {
		return nil, nil
	}

	// Establish baseline response time with a normal GET.
	baseline := measureBaseline(ctx, host, port, asset, useTLS)
	if baseline < 0 || baseline > baselineMax {
		return nil, nil // target unreachable or already too slow for timing
	}

	var findings []finding.Finding

	scheme := "https"
	if !useTLS {
		scheme = "http"
	}
	targetURL := scheme + "://" + asset + "/"

	// CL.TE probe
	if vulnerable, elapsed := probeCLTE(ctx, host, port, asset, useTLS); vulnerable {
		findings = append(findings, finding.Finding{
			CheckID:  checkID,
			Module:   "deep",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Asset:    asset,
			Title:    fmt.Sprintf("HTTP request smuggling (CL.TE) detected on %s", asset),
			Description: "The server appears vulnerable to CL.TE request smuggling: the front-end proxy " +
				"uses Content-Length while the back-end uses Transfer-Encoding. An attacker can prepend " +
				"an arbitrary HTTP request prefix to the next user's TCP stream, bypassing WAF rules, " +
				"poisoning request routing, or hijacking authenticated sessions.",
			ProofCommand: fmt.Sprintf(
				"# CL.TE timing probe — connection should hang for ~%ds if vulnerable:\n"+
					"python3 -c \"\nimport socket, ssl, time\n"+
					"host='%s'\n"+
					"payload=('POST / HTTP/1.1\\r\\nHost: %s\\r\\n"+
					"Content-Type: application/x-www-form-urlencoded\\r\\n"+
					"Content-Length: 11\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n"+
					"0\\r\\n\\r\\nX')\n"+
					"ctx=ssl.create_default_context()\n"+
					"c=ctx.wrap_socket(socket.create_connection((host,443)),server_hostname=host)\n"+
					"c.send(payload.encode()); t=time.time()\n"+
					"try: c.recv(4096)\nexcept: pass\n"+
					"print(f'elapsed: {time.time()-t:.1f}s (>4s = vulnerable)')\n\"",
				int(smuggleDelay.Seconds()), asset, asset),
			Evidence: map[string]any{
				"type":             "CL.TE",
				"url":              targetURL,
				"baseline_ms":      baseline.Milliseconds(),
				"probe_elapsed_ms": elapsed.Milliseconds(),
			},
			DiscoveredAt: time.Now(),
		})
	}

	// TE.CL probe
	if vulnerable, elapsed := probeTECL(ctx, host, port, asset, useTLS); vulnerable {
		sev := finding.SeverityHigh
		if len(findings) > 0 {
			sev = finding.SeverityCritical // both variants confirmed
		}
		findings = append(findings, finding.Finding{
			CheckID:  checkID,
			Module:   "deep",
			Scanner:  scannerName,
			Severity: sev,
			Asset:    asset,
			Title:    fmt.Sprintf("HTTP request smuggling (TE.CL) detected on %s", asset),
			Description: "The server appears vulnerable to TE.CL request smuggling: the front-end proxy " +
				"uses Transfer-Encoding while the back-end uses Content-Length. An attacker can smuggle " +
				"arbitrary HTTP headers or a full request prefix into the back-end's request pipeline.",
			ProofCommand: fmt.Sprintf(
				"# TE.CL timing probe — connection should hang for ~%ds if vulnerable:\n"+
					"python3 -c \"\nimport socket, ssl, time\n"+
					"host='%s'\n"+
					"payload=('POST / HTTP/1.1\\r\\nHost: %s\\r\\n"+
					"Content-Type: application/x-www-form-urlencoded\\r\\n"+
					"Content-Length: 3\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n"+
					"1\\r\\nZ\\r\\n0\\r\\n\\r\\n')\n"+
					"ctx=ssl.create_default_context()\n"+
					"c=ctx.wrap_socket(socket.create_connection((host,443)),server_hostname=host)\n"+
					"c.send(payload.encode()); t=time.time()\n"+
					"try: c.recv(4096)\nexcept: pass\n"+
					"print(f'elapsed: {time.time()-t:.1f}s (>4s = vulnerable)')\n\"",
				int(smuggleDelay.Seconds()), asset, asset),
			Evidence: map[string]any{
				"type":             "TE.CL",
				"url":              targetURL,
				"baseline_ms":      baseline.Milliseconds(),
				"probe_elapsed_ms": elapsed.Milliseconds(),
			},
			DiscoveredAt: time.Now(),
		})
	}

	// TE.TE obfuscation probes — test Transfer-Encoding variants that some
	// proxies fail to normalise, causing one side to see chunked and the other
	// to fall back to Content-Length.
	teObfuscations := []struct {
		label string
		value string
	}{
		{"xchunked", "xchunked"},
		{"chunked-space", "chunked "},
		{"tab-chunked", " \tchunked"},
		{"chunked-cap", "Chunked"},
	}
	for _, te := range teObfuscations {
		if vulnerable, elapsed := probeTETEObfuscation(ctx, host, port, asset, useTLS, te.value); vulnerable {
			findings = append(findings, finding.Finding{
				CheckID:  checkID,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityHigh,
				Asset:    asset,
				Title:    fmt.Sprintf("HTTP request smuggling (TE.TE obfuscation %q) detected on %s", te.label, asset),
				Description: fmt.Sprintf(
					"The server appears vulnerable to TE.TE request smuggling via Transfer-Encoding "+
						"obfuscation. The header value %q caused the front-end and back-end to "+
						"disagree on chunked transfer encoding parsing. One server processes the "+
						"obfuscated TE header while the other falls back to Content-Length, enabling "+
						"request smuggling.", te.value),
				ProofCommand: fmt.Sprintf(
					"# TE.TE obfuscation timing probe — connection should hang for ~%ds if vulnerable:\n"+
						"python3 -c \"\nimport socket, ssl, time\n"+
						"host='%s'\n"+
						"payload=('POST / HTTP/1.1\\r\\nHost: %s\\r\\n"+
						"Content-Type: application/x-www-form-urlencoded\\r\\n"+
						"Content-Length: 11\\r\\nTransfer-Encoding: %s\\r\\n\\r\\n"+
						"0\\r\\n\\r\\nX')\n"+
						"ctx=ssl.create_default_context()\n"+
						"c=ctx.wrap_socket(socket.create_connection((host,443)),server_hostname=host)\n"+
						"c.send(payload.encode()); t=time.time()\n"+
						"try: c.recv(4096)\nexcept: pass\n"+
						"print(f'elapsed: {time.time()-t:.1f}s (>4s = vulnerable)')\n\"",
					int(smuggleDelay.Seconds()), asset, asset, te.value),
				Evidence: map[string]any{
					"type":             "TE.TE",
					"obfuscation":      te.label,
					"te_value":         te.value,
					"url":              targetURL,
					"baseline_ms":      baseline.Milliseconds(),
					"probe_elapsed_ms": elapsed.Milliseconds(),
				},
				DiscoveredAt: time.Now(),
			})
			// One TE.TE finding is sufficient.
			break
		}
	}

	return findings, nil
}

// probeTETEObfuscation sends a smuggling probe with an obfuscated
// Transfer-Encoding value. If one hop recognises the TE value and the other
// doesn't, they'll disagree on body framing — producing a measurable timeout.
// The probe is sent twice; both must time out to be flagged.
func probeTETEObfuscation(ctx context.Context, host, port, asset string, useTLS bool, teValue string) (bool, time.Duration) {
	body := "0\r\n\r\nX"
	raw := fmt.Sprintf(
		"POST / HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Type: application/x-www-form-urlencoded\r\n"+
			"Content-Length: %d\r\n"+
			"Transfer-Encoding: %s\r\n"+
			"\r\n"+
			"%s",
		asset, len(body)+5, teValue, body,
	)
	hits := 0
	var lastElapsed time.Duration
	for i := 0; i < 2; i++ {
		start := time.Now()
		err := sendRaw(ctx, host, port, useTLS, raw, probeTimeout, nil)
		lastElapsed = time.Since(start)
		if isTimeoutError(err) && lastElapsed >= smuggleDelay {
			hits++
		}
	}
	return hits >= 2, lastElapsed
}

// resolveTarget finds a reachable host:port for the asset and returns
// whether TLS should be used. Returns ("", 0, false) if unreachable.
func resolveTarget(ctx context.Context, asset string) (string, string, bool) {
	// Prefer HTTPS.
	for _, entry := range []struct {
		port   string
		useTLS bool
	}{
		{"443", true},
		{"80", false},
	} {
		conn, err := dialConnFunc(ctx, asset, entry.port, entry.useTLS)
		if err != nil {
			continue
		}
		conn.Close()
		return asset, entry.port, entry.useTLS
	}
	return "", "", false
}

// measureBaseline times a simple GET request to establish a latency reference.
func measureBaseline(ctx context.Context, host, port, asset string, useTLS bool) time.Duration {
	start := time.Now()
	req := buildRawGET(asset)
	if err := sendRaw(ctx, host, port, useTLS, req, 3*time.Second, nil); err != nil {
		return -1
	}
	return time.Since(start)
}

// probeCLTE sends the CL.TE smuggling probe and returns (vulnerable, elapsed).
// The probe has Content-Length > chunked body length, causing the back-end
// (if it uses TE) to process the zero-chunk and then wait for more data.
// The probe is sent twice; both must time out to be flagged, reducing false
// positives from transient network delays.
func probeCLTE(ctx context.Context, host, port, asset string, useTLS bool) (bool, time.Duration) {
	// Body: zero-chunk terminator followed by a stray byte.
	// Content-Length is set LARGER than the actual chunked body (len+5) so that
	// a CL-aware front-end considers the request incomplete and holds the
	// connection open waiting for more bytes that never arrive.
	// A TE-aware back-end sees the 0-chunk, considers the request complete, and
	// forwards it — but the front-end's open connection causes a timeout from
	// our perspective, which is the timing signal we measure.
	body := "0\r\n\r\nX"
	raw := fmt.Sprintf(
		"POST / HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Type: application/x-www-form-urlencoded\r\n"+
			"Content-Length: %d\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"\r\n"+
			"%s",
		asset, len(body)+5, body,
	)
	// Two independent probes required — a single network timeout is too noisy.
	hits := 0
	var lastElapsed time.Duration
	for i := 0; i < 2; i++ {
		start := time.Now()
		err := sendRaw(ctx, host, port, useTLS, raw, probeTimeout, nil)
		lastElapsed = time.Since(start)
		if isTimeoutError(err) && lastElapsed >= smuggleDelay {
			hits++
		}
	}
	return hits >= 2, lastElapsed
}

// probeTECL sends the TE.CL smuggling probe and returns (vulnerable, elapsed).
// Content-Length is smaller than the chunked body, so a CL-aware back-end
// reads only part of the request and waits for the next request — causing
// the front-end (TE-aware) to hold our connection open while it waits for us
// to send the terminating chunk.
// The probe is sent twice; both must time out to be flagged.
func probeTECL(ctx context.Context, host, port, asset string, useTLS bool) (bool, time.Duration) {
	// Chunked body: 1-byte chunk "Z" + terminating chunk.
	// Content-Length: 3 — covers only "1\r\n" (3 bytes of the first chunk-size line).
	// A CL back-end reads 3 bytes and then waits for the next request header line,
	// but the front-end (TE) is still holding our TCP stream for the 0-chunk.
	body := "1\r\nZ\r\n0\r\n\r\n"
	raw := fmt.Sprintf(
		"POST / HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Type: application/x-www-form-urlencoded\r\n"+
			"Content-Length: 3\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"\r\n"+
			"%s",
		asset, body,
	)
	hits := 0
	var lastElapsed time.Duration
	for i := 0; i < 2; i++ {
		start := time.Now()
		err := sendRaw(ctx, host, port, useTLS, raw, probeTimeout, nil)
		lastElapsed = time.Since(start)
		if isTimeoutError(err) && lastElapsed >= smuggleDelay {
			hits++
		}
	}
	return hits >= 2, lastElapsed
}

// buildRawGET returns a minimal HTTP/1.1 GET request string.
func buildRawGET(asset string) string {
	return fmt.Sprintf(
		"GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		asset,
	)
}

// sendRaw opens a TCP (optionally TLS) connection, writes the raw request,
// and reads until EOF or deadline. Returns nil on clean read, error otherwise.
func sendRaw(ctx context.Context, host, port string, useTLS bool, raw string, timeout time.Duration, _ []byte) error {
	conn, err := dialConnFunc(ctx, host, port, useTLS)
	if err != nil {
		return err
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}

	if _, err := conn.Write([]byte(raw)); err != nil {
		return err
	}

	// Drain the response — we only care about timing/timeout.
	// Cap at 64 KB to prevent a runaway server from consuming unbounded memory.
	const maxResponseBytes = 64 << 10
	br := bufio.NewReader(conn)
	var totalRead int
	for {
		line, err := br.ReadString('\n')
		totalRead += len(line)
		if totalRead > maxResponseBytes {
			return nil // read enough to confirm connectivity; not a timeout
		}
		if err != nil {
			return err
		}
	}
}

// dialConn opens a TCP connection, wrapping it with TLS when requested.
func dialConn(ctx context.Context, host, port string, useTLS bool) (net.Conn, error) {
	d := &net.Dialer{Timeout: 5 * time.Second}
	addr := net.JoinHostPort(host, port)
	if !useTLS {
		return d.DialContext(ctx, "tcp", addr)
	}
	tlsCfg := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: false, //nolint:gosec // We want real TLS validation here
	}
	rawConn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(rawConn, tlsCfg)
	tlsConn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	if err := tlsConn.Handshake(); err != nil {
		rawConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

// isTimeoutError returns true when err is a network timeout.
func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	netErr, ok := err.(net.Error)
	return ok && netErr.Timeout()
}

// stripScheme is kept for potential future use.
func stripScheme(s string) string {
	if idx := strings.Index(s, "://"); idx != -1 {
		return s[idx+3:]
	}
	return s
}

// Ensure stripScheme is used (avoids "declared and not used" if only called internally).
var _ = stripScheme
