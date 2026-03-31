package smuggling

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

// ---------------------------------------------------------------------------
// Test helpers: save/restore package-level globals so tests are isolated.
// ---------------------------------------------------------------------------

type savedGlobals struct {
	dialConnFunc func(context.Context, string, string, bool) (net.Conn, error)
	probeTimeout time.Duration
	baselineMax  time.Duration
	smuggleDelay time.Duration
}

func saveGlobals() savedGlobals {
	return savedGlobals{
		dialConnFunc: dialConnFunc,
		probeTimeout: probeTimeout,
		baselineMax:  baselineMax,
		smuggleDelay: smuggleDelay,
	}
}

func restoreGlobals(s savedGlobals) {
	dialConnFunc = s.dialConnFunc
	probeTimeout = s.probeTimeout
	baselineMax = s.baselineMax
	smuggleDelay = s.smuggleDelay
}

// setFastTimings reduces the timing thresholds so that tests complete quickly.
// probeTimeout is the read deadline; smuggleDelay is the threshold for calling
// a probe "vulnerable". A vulnerable server holds the connection open past
// smuggleDelay, and the probe times out at probeTimeout.
func setFastTimings() {
	probeTimeout = 300 * time.Millisecond
	baselineMax = 200 * time.Millisecond
	smuggleDelay = 100 * time.Millisecond
}

// ---------------------------------------------------------------------------
// TCP test servers: simulate vulnerable and non-vulnerable HTTP servers at
// the raw TCP level. The smuggling scanner uses raw TCP, not net/http, so we
// must operate at that layer.
// ---------------------------------------------------------------------------

// startTCPServer starts a TCP listener that calls handler for each accepted
// connection. Returns the listener and a cleanup function.
func startTCPServer(t *testing.T, handler func(net.Conn)) (net.Listener, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start TCP listener: %v", err)
	}

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				// Listener closed.
				select {
				case <-ctx.Done():
					return
				default:
					return
				}
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				handler(c)
			}(conn)
		}
	}()

	cleanup := func() {
		cancel()
		ln.Close()
		wg.Wait()
	}
	return ln, cleanup
}

// largeBody returns a response body exceeding 64 KB, which is the threshold
// at which sendRaw stops reading and returns nil. This is necessary for
// measureBaseline to succeed (it requires sendRaw to return nil).
func largeBody() string {
	// 66 KB of newline-terminated lines to exceed the 64 KB cap in sendRaw.
	line := strings.Repeat("X", 1023) + "\n"
	var sb strings.Builder
	for i := 0; i < 68; i++ {
		sb.WriteString(line)
	}
	return sb.String()
}

// normalHTTPResponse returns an HTTP/1.1 200 response with a body exceeding
// 64 KB so that sendRaw returns nil (success) rather than io.EOF.
func normalHTTPResponse() string {
	body := largeBody()
	return fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
}

// readRequest reads the first line of the incoming request to determine the
// HTTP method. Returns the full raw request header and the method.
func readRequest(conn net.Conn) string {
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)) //nolint:errcheck
	reader := bufio.NewReader(conn)
	line, _ := reader.ReadString('\n')
	// Drain remaining headers.
	for {
		l, err := reader.ReadString('\n')
		_ = l
		if err != nil || l == "\r\n" {
			break
		}
	}
	return line
}

// normalHandler reads the incoming request and immediately responds with a
// large body so sendRaw returns nil.
func normalHandler(conn net.Conn) {
	readRequest(conn)
	conn.Write([]byte(normalHTTPResponse())) //nolint:errcheck
}

// hangHandler reads the incoming request, then holds the connection open
// without responding, simulating a vulnerable server that gets stuck due
// to CL/TE disagreement. The connection is held until the client times out
// or the connection is closed externally.
func hangHandler(conn net.Conn) {
	readRequest(conn)
	// Hold connection open — do not respond or close. The caller's probe
	// timeout will fire, producing the timing signal.
	time.Sleep(2 * time.Second)
}

// vulnerableHandler simulates a server that is vulnerable to smuggling:
// - GET requests (baseline) receive a normal large response
// - POST requests (probes) hang, simulating the CL/TE disagreement
func vulnerableHandler(conn net.Conn) {
	reqLine := readRequest(conn)
	if strings.HasPrefix(reqLine, "GET") {
		conn.Write([]byte(normalHTTPResponse())) //nolint:errcheck
		return
	}
	// POST probe — hang to simulate smuggling vulnerability.
	time.Sleep(2 * time.Second)
}

// connectionResetHandler immediately closes the connection without reading
// or writing, simulating a connection reset.
func connectionResetHandler(conn net.Conn) {
	// Set TCP linger to 0 to trigger RST instead of FIN.
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetLinger(0) //nolint:errcheck
	}
	// Close immediately — the client sees "connection reset by peer".
}

// makeDialer returns a dialConnFunc that always connects to the given listener,
// ignoring the host, port, and TLS parameters. This lets the probes think
// they're talking to the real target but actually hit our test server.
func makeDialer(ln net.Listener) func(context.Context, string, string, bool) (net.Conn, error) {
	return func(ctx context.Context, host, port string, useTLS bool) (net.Conn, error) {
		d := &net.Dialer{Timeout: 1 * time.Second}
		return d.DialContext(ctx, "tcp", ln.Addr().String())
	}
}

// extractHostPort returns the host and port from a listener address.
func extractHostPort(ln net.Listener) (string, string) {
	addr := ln.Addr().String()
	host, port, _ := net.SplitHostPort(addr)
	return host, port
}

// ---------------------------------------------------------------------------
// probeCLTE behavior tests
// ---------------------------------------------------------------------------

func TestProbeCLTE_VulnerableServer_ReturnsTrue(t *testing.T) {
	saved := saveGlobals()
	defer restoreGlobals(saved)
	setFastTimings()

	ln, cleanup := startTCPServer(t, hangHandler)
	defer cleanup()

	dialConnFunc = makeDialer(ln)
	host, port := extractHostPort(ln)

	vulnerable, elapsed := probeCLTE(context.Background(), host, port, "test.example.com", false)
	if !vulnerable {
		t.Errorf("probeCLTE should report vulnerable when server hangs, elapsed=%v", elapsed)
	}
	if elapsed < smuggleDelay {
		t.Errorf("elapsed (%v) should be >= smuggleDelay (%v)", elapsed, smuggleDelay)
	}
}

func TestProbeCLTE_NormalServer_ReturnsFalse(t *testing.T) {
	saved := saveGlobals()
	defer restoreGlobals(saved)
	setFastTimings()

	ln, cleanup := startTCPServer(t, normalHandler)
	defer cleanup()

	dialConnFunc = makeDialer(ln)
	host, port := extractHostPort(ln)

	vulnerable, _ := probeCLTE(context.Background(), host, port, "test.example.com", false)
	if vulnerable {
		t.Error("probeCLTE should not report vulnerable when server responds normally")
	}
}

func TestProbeCLTE_ConnectionReset_ReturnsFalse(t *testing.T) {
	saved := saveGlobals()
	defer restoreGlobals(saved)
	setFastTimings()

	ln, cleanup := startTCPServer(t, connectionResetHandler)
	defer cleanup()

	dialConnFunc = makeDialer(ln)
	host, port := extractHostPort(ln)

	vulnerable, _ := probeCLTE(context.Background(), host, port, "test.example.com", false)
	if vulnerable {
		t.Error("probeCLTE should not report vulnerable when connection is immediately reset")
	}
}

func TestProbeCLTE_ContextCancelled_ReturnsFalse(t *testing.T) {
	saved := saveGlobals()
	defer restoreGlobals(saved)
	setFastTimings()

	ln, cleanup := startTCPServer(t, hangHandler)
	defer cleanup()

	dialConnFunc = makeDialer(ln)
	host, port := extractHostPort(ln)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	vulnerable, _ := probeCLTE(ctx, host, port, "test.example.com", false)
	if vulnerable {
		t.Error("probeCLTE should not report vulnerable when context is already cancelled")
	}
}

// TestProbeCLTE_SingleTimeout_ReturnsFalse verifies that a single timeout
// (intermittent network issue) does not trigger a finding — both probes must
// time out.
func TestProbeCLTE_SingleTimeout_ReturnsFalse(t *testing.T) {
	saved := saveGlobals()
	defer restoreGlobals(saved)
	setFastTimings()

	var mu sync.Mutex
	callCount := 0

	ln, cleanup := startTCPServer(t, func(conn net.Conn) {
		mu.Lock()
		callCount++
		n := callCount
		mu.Unlock()

		if n == 1 {
			// First probe iteration: hang to simulate a transient timeout.
			hangHandler(conn)
		} else {
			// Second probe iteration: respond normally — not a timeout.
			normalHandler(conn)
		}
	})
	defer cleanup()

	dialConnFunc = makeDialer(ln)
	host, port := extractHostPort(ln)

	vulnerable, _ := probeCLTE(context.Background(), host, port, "test.example.com", false)
	if vulnerable {
		t.Error("probeCLTE should not report vulnerable when only one of two probes times out")
	}
}

// ---------------------------------------------------------------------------
// probeTECL behavior tests
// ---------------------------------------------------------------------------

func TestProbeTECL_VulnerableServer_ReturnsTrue(t *testing.T) {
	saved := saveGlobals()
	defer restoreGlobals(saved)
	setFastTimings()

	ln, cleanup := startTCPServer(t, hangHandler)
	defer cleanup()

	dialConnFunc = makeDialer(ln)
	host, port := extractHostPort(ln)

	vulnerable, elapsed := probeTECL(context.Background(), host, port, "test.example.com", false)
	if !vulnerable {
		t.Errorf("probeTECL should report vulnerable when server hangs, elapsed=%v", elapsed)
	}
	if elapsed < smuggleDelay {
		t.Errorf("elapsed (%v) should be >= smuggleDelay (%v)", elapsed, smuggleDelay)
	}
}

func TestProbeTECL_NormalServer_ReturnsFalse(t *testing.T) {
	saved := saveGlobals()
	defer restoreGlobals(saved)
	setFastTimings()

	ln, cleanup := startTCPServer(t, normalHandler)
	defer cleanup()

	dialConnFunc = makeDialer(ln)
	host, port := extractHostPort(ln)

	vulnerable, _ := probeTECL(context.Background(), host, port, "test.example.com", false)
	if vulnerable {
		t.Error("probeTECL should not report vulnerable when server responds normally")
	}
}

func TestProbeTECL_ConnectionReset_ReturnsFalse(t *testing.T) {
	saved := saveGlobals()
	defer restoreGlobals(saved)
	setFastTimings()

	ln, cleanup := startTCPServer(t, connectionResetHandler)
	defer cleanup()

	dialConnFunc = makeDialer(ln)
	host, port := extractHostPort(ln)

	vulnerable, _ := probeTECL(context.Background(), host, port, "test.example.com", false)
	if vulnerable {
		t.Error("probeTECL should not report vulnerable when connection is immediately reset")
	}
}

func TestProbeTECL_ContextCancelled_ReturnsFalse(t *testing.T) {
	saved := saveGlobals()
	defer restoreGlobals(saved)
	setFastTimings()

	ln, cleanup := startTCPServer(t, hangHandler)
	defer cleanup()

	dialConnFunc = makeDialer(ln)
	host, port := extractHostPort(ln)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	vulnerable, _ := probeTECL(ctx, host, port, "test.example.com", false)
	if vulnerable {
		t.Error("probeTECL should not report vulnerable when context is already cancelled")
	}
}

// ---------------------------------------------------------------------------
// probeTETEObfuscation behavior tests
// ---------------------------------------------------------------------------

func TestProbeTETEObfuscation_VulnerableServer_ReturnsTrue(t *testing.T) {
	saved := saveGlobals()
	defer restoreGlobals(saved)
	setFastTimings()

	ln, cleanup := startTCPServer(t, hangHandler)
	defer cleanup()

	dialConnFunc = makeDialer(ln)
	host, port := extractHostPort(ln)

	// Test each obfuscation variant.
	variants := []struct {
		label string
		value string
	}{
		{"xchunked", "xchunked"},
		{"chunked-space", "chunked "},
		{"tab-chunked", " \tchunked"},
		{"chunked-cap", "Chunked"},
	}

	for _, v := range variants {
		t.Run(v.label, func(t *testing.T) {
			vulnerable, elapsed := probeTETEObfuscation(context.Background(), host, port, "test.example.com", false, v.value)
			if !vulnerable {
				t.Errorf("probeTETEObfuscation(%q) should report vulnerable when server hangs, elapsed=%v", v.value, elapsed)
			}
		})
	}
}

func TestProbeTETEObfuscation_NormalServer_ReturnsFalse(t *testing.T) {
	saved := saveGlobals()
	defer restoreGlobals(saved)
	setFastTimings()

	ln, cleanup := startTCPServer(t, normalHandler)
	defer cleanup()

	dialConnFunc = makeDialer(ln)
	host, port := extractHostPort(ln)

	variants := []struct {
		label string
		value string
	}{
		{"xchunked", "xchunked"},
		{"chunked-space", "chunked "},
		{"tab-chunked", " \tchunked"},
		{"chunked-cap", "Chunked"},
	}

	for _, v := range variants {
		t.Run(v.label, func(t *testing.T) {
			vulnerable, _ := probeTETEObfuscation(context.Background(), host, port, "test.example.com", false, v.value)
			if vulnerable {
				t.Errorf("probeTETEObfuscation(%q) should not report vulnerable when server responds normally", v.value)
			}
		})
	}
}

func TestProbeTETEObfuscation_ConnectionReset_ReturnsFalse(t *testing.T) {
	saved := saveGlobals()
	defer restoreGlobals(saved)
	setFastTimings()

	ln, cleanup := startTCPServer(t, connectionResetHandler)
	defer cleanup()

	dialConnFunc = makeDialer(ln)
	host, port := extractHostPort(ln)

	vulnerable, _ := probeTETEObfuscation(context.Background(), host, port, "test.example.com", false, "xchunked")
	if vulnerable {
		t.Error("probeTETEObfuscation should not report vulnerable when connection is reset")
	}
}

// ---------------------------------------------------------------------------
// Full Run() integration tests
// ---------------------------------------------------------------------------

func TestRun_DeepMode_VulnerableServer_EmitsCLTEFinding(t *testing.T) {
	saved := saveGlobals()
	defer restoreGlobals(saved)
	setFastTimings()

	// vulnerableHandler responds normally to GET (baseline) but hangs on POST (probes).
	ln, cleanup := startTCPServer(t, vulnerableHandler)
	defer cleanup()

	dialConnFunc = makeDialer(ln)

	// The asset is the listener address — the dialer routes all connections
	// to our test server regardless.
	host, port := extractHostPort(ln)
	asset := net.JoinHostPort(host, port)

	s := New()
	findings, err := s.Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least 1 smuggling finding against a hanging server, got 0")
	}

	// All findings must reference the correct check ID and scanner name.
	for _, f := range findings {
		if f.CheckID != finding.CheckWebHTTPRequestSmuggling {
			t.Errorf("unexpected check ID: %s", f.CheckID)
		}
		if f.Scanner != "smuggling" {
			t.Errorf("expected scanner 'smuggling', got %q", f.Scanner)
		}
		if f.Module != "deep" {
			t.Errorf("expected module 'deep', got %q", f.Module)
		}
		if f.ProofCommand == "" {
			t.Error("ProofCommand must be set")
		}
		if f.Asset != asset {
			t.Errorf("expected asset %q, got %q", asset, f.Asset)
		}
	}

	// Check that at least one finding mentions CL.TE.
	foundCLTE := false
	for _, f := range findings {
		if strings.Contains(f.Title, "CL.TE") {
			foundCLTE = true
			if f.Severity != finding.SeverityHigh {
				t.Errorf("CL.TE finding should be High severity, got %s", f.Severity)
			}
			ev, ok := f.Evidence["type"].(string)
			if !ok || ev != "CL.TE" {
				t.Errorf("CL.TE finding evidence type should be 'CL.TE', got %v", f.Evidence["type"])
			}
			break
		}
	}
	if !foundCLTE {
		t.Error("expected at least one CL.TE finding")
	}
}

func TestRun_DeepMode_VulnerableServer_BothCLTEAndTECL_TECLIsCritical(t *testing.T) {
	saved := saveGlobals()
	defer restoreGlobals(saved)
	setFastTimings()

	// vulnerableHandler responds normally to GET (baseline) but hangs on POST.
	ln, cleanup := startTCPServer(t, vulnerableHandler)
	defer cleanup()

	dialConnFunc = makeDialer(ln)

	host, port := extractHostPort(ln)
	asset := net.JoinHostPort(host, port)

	s := New()
	findings, err := s.Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	// When both CL.TE and TE.CL are detected, TE.CL should be Critical.
	var foundCLTE, foundTECL bool
	for _, f := range findings {
		if strings.Contains(f.Title, "CL.TE") {
			foundCLTE = true
		}
		if strings.Contains(f.Title, "TE.CL") && !strings.Contains(f.Title, "TE.TE") {
			foundTECL = true
			if f.Severity != finding.SeverityCritical {
				t.Errorf("TE.CL finding should be Critical when CL.TE is also present, got %s", f.Severity)
			}
		}
	}
	if !foundCLTE {
		t.Error("expected CL.TE finding")
	}
	if !foundTECL {
		t.Error("expected TE.CL finding")
	}
}

func TestRun_DeepMode_NormalServer_NoFindings(t *testing.T) {
	saved := saveGlobals()
	defer restoreGlobals(saved)
	setFastTimings()

	ln, cleanup := startTCPServer(t, normalHandler)
	defer cleanup()

	dialConnFunc = makeDialer(ln)

	host, port := extractHostPort(ln)
	asset := net.JoinHostPort(host, port)

	s := New()
	findings, err := s.Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings against a normal server, got %d: %v", len(findings), findings)
	}
}

func TestRun_DeepMode_ConnectionReset_NoFindings(t *testing.T) {
	saved := saveGlobals()
	defer restoreGlobals(saved)
	setFastTimings()

	ln, cleanup := startTCPServer(t, connectionResetHandler)
	defer cleanup()

	dialConnFunc = makeDialer(ln)

	host, port := extractHostPort(ln)
	asset := net.JoinHostPort(host, port)

	s := New()
	findings, err := s.Run(context.Background(), asset, module.ScanDeep)
	// Connection reset may cause errors; we only care that there are no false positives.
	_ = err
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when connections reset, got %d", len(findings))
	}
}

// TestRun_DeepMode_VulnerableServer_TETEFinding verifies that TE.TE obfuscation
// findings include the correct evidence fields.
func TestRun_DeepMode_VulnerableServer_TETEFinding(t *testing.T) {
	saved := saveGlobals()
	defer restoreGlobals(saved)
	setFastTimings()

	ln, cleanup := startTCPServer(t, vulnerableHandler)
	defer cleanup()

	dialConnFunc = makeDialer(ln)

	host, port := extractHostPort(ln)
	asset := net.JoinHostPort(host, port)

	s := New()
	findings, err := s.Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	foundTETE := false
	for _, f := range findings {
		if strings.Contains(f.Title, "TE.TE") {
			foundTETE = true
			if f.Severity != finding.SeverityHigh {
				t.Errorf("TE.TE finding should be High severity, got %s", f.Severity)
			}
			ev, ok := f.Evidence["type"].(string)
			if !ok || ev != "TE.TE" {
				t.Errorf("TE.TE finding evidence type should be 'TE.TE', got %v", f.Evidence["type"])
			}
			// TE.TE findings must include the obfuscation label and te_value.
			if _, ok := f.Evidence["obfuscation"]; !ok {
				t.Error("TE.TE finding must include 'obfuscation' in Evidence")
			}
			if _, ok := f.Evidence["te_value"]; !ok {
				t.Error("TE.TE finding must include 'te_value' in Evidence")
			}
			break
		}
	}
	if !foundTETE {
		t.Error("expected at least one TE.TE obfuscation finding against a hanging server")
	}
}

// ---------------------------------------------------------------------------
// Baseline too slow: server responds slowly, scanner should skip probing
// ---------------------------------------------------------------------------

func TestRun_DeepMode_SlowBaseline_NoFindings(t *testing.T) {
	saved := saveGlobals()
	defer restoreGlobals(saved)
	setFastTimings()
	// Make baselineMax zero so any positive baseline exceeds the threshold,
	// causing Run() to skip all probes.
	baselineMax = 0

	ln, cleanup := startTCPServer(t, vulnerableHandler)
	defer cleanup()

	dialConnFunc = makeDialer(ln)

	host, port := extractHostPort(ln)
	asset := net.JoinHostPort(host, port)

	s := New()
	findings, err := s.Run(context.Background(), asset, module.ScanDeep)
	_ = err
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when baseline exceeds threshold, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// sendRaw behavior tests
// ---------------------------------------------------------------------------

func TestSendRaw_NormalServer_ReturnsNil(t *testing.T) {
	saved := saveGlobals()
	defer restoreGlobals(saved)

	// normalHandler sends >64 KB, so sendRaw hits the read cap and returns nil.
	ln, cleanup := startTCPServer(t, normalHandler)
	defer cleanup()

	dialConnFunc = makeDialer(ln)
	host, port := extractHostPort(ln)

	err := sendRaw(context.Background(), host, port, false, buildRawGET("test.example.com"), 2*time.Second, nil)
	if err != nil {
		t.Errorf("sendRaw against a normal server (>64KB response) should return nil, got: %v", err)
	}
}

func TestSendRaw_HangingServer_ReturnsTimeout(t *testing.T) {
	saved := saveGlobals()
	defer restoreGlobals(saved)

	ln, cleanup := startTCPServer(t, hangHandler)
	defer cleanup()

	dialConnFunc = makeDialer(ln)
	host, port := extractHostPort(ln)

	err := sendRaw(context.Background(), host, port, false, buildRawGET("test.example.com"), 200*time.Millisecond, nil)
	if !isTimeoutError(err) {
		t.Errorf("sendRaw against a hanging server should return timeout error, got: %v", err)
	}
}

func TestSendRaw_ConnectionReset_ReturnsNonTimeoutError(t *testing.T) {
	saved := saveGlobals()
	defer restoreGlobals(saved)

	ln, cleanup := startTCPServer(t, connectionResetHandler)
	defer cleanup()

	dialConnFunc = makeDialer(ln)
	host, port := extractHostPort(ln)

	err := sendRaw(context.Background(), host, port, false, buildRawGET("test.example.com"), 1*time.Second, nil)
	if err == nil {
		t.Error("sendRaw against a reset connection should return an error")
	}
	if isTimeoutError(err) {
		t.Error("sendRaw against a reset connection should not be a timeout")
	}
}

// TestSendRaw_LargeResponse_CappedAt64KB verifies that sendRaw stops reading
// after 64 KB and returns nil (not a timeout), preventing unbounded memory use.
func TestSendRaw_LargeResponse_CappedAt64KB(t *testing.T) {
	saved := saveGlobals()
	defer restoreGlobals(saved)

	ln, cleanup := startTCPServer(t, func(conn net.Conn) {
		// Read request.
		buf := make([]byte, 4096)
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)) //nolint:errcheck
		conn.Read(buf)                                                //nolint:errcheck

		// Send a large response exceeding 64 KB.
		header := "HTTP/1.1 200 OK\r\nContent-Length: 131072\r\n\r\n"
		conn.Write([]byte(header)) //nolint:errcheck
		// Write lines of data past the 64 KB cap.
		line := strings.Repeat("X", 1023) + "\n"
		for i := 0; i < 200; i++ {
			conn.Write([]byte(line)) //nolint:errcheck
		}
	})
	defer cleanup()

	dialConnFunc = makeDialer(ln)
	host, port := extractHostPort(ln)

	err := sendRaw(context.Background(), host, port, false, buildRawGET("test.example.com"), 2*time.Second, nil)
	if err != nil {
		t.Errorf("sendRaw should return nil after reading 64 KB cap, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// measureBaseline behavior tests
// ---------------------------------------------------------------------------

func TestMeasureBaseline_NormalServer_ReturnsPositiveDuration(t *testing.T) {
	saved := saveGlobals()
	defer restoreGlobals(saved)

	ln, cleanup := startTCPServer(t, normalHandler)
	defer cleanup()

	dialConnFunc = makeDialer(ln)
	host, port := extractHostPort(ln)

	d := measureBaseline(context.Background(), host, port, "test.example.com", false)
	if d < 0 {
		t.Errorf("measureBaseline should return positive duration for a reachable server, got %v", d)
	}
}

func TestMeasureBaseline_Unreachable_ReturnsNegative(t *testing.T) {
	saved := saveGlobals()
	defer restoreGlobals(saved)

	// Dial function that always fails.
	dialConnFunc = func(ctx context.Context, host, port string, useTLS bool) (net.Conn, error) {
		return nil, fmt.Errorf("connection refused")
	}

	d := measureBaseline(context.Background(), "nohost", "1", "nohost", false)
	if d >= 0 {
		t.Errorf("measureBaseline should return negative duration for unreachable host, got %v", d)
	}
}

// ---------------------------------------------------------------------------
// resolveTarget behavior tests
// ---------------------------------------------------------------------------

func TestResolveTarget_Reachable_ReturnsHostPort(t *testing.T) {
	saved := saveGlobals()
	defer restoreGlobals(saved)

	ln, cleanup := startTCPServer(t, normalHandler)
	defer cleanup()

	dialConnFunc = makeDialer(ln)

	host, port, useTLS := resolveTarget(context.Background(), "test.example.com")
	if host == "" {
		t.Error("resolveTarget should return a non-empty host for a reachable server")
	}
	// The port returned is from the first matching entry (443 or 80); since our
	// dialer ignores the actual port, we get whichever the code tries first.
	_ = port
	// Since our dialer ignores TLS, the scanner will think port 443 with TLS
	// succeeded first.
	_ = useTLS
}

func TestResolveTarget_Unreachable_ReturnsEmpty(t *testing.T) {
	saved := saveGlobals()
	defer restoreGlobals(saved)

	dialConnFunc = func(ctx context.Context, host, port string, useTLS bool) (net.Conn, error) {
		return nil, fmt.Errorf("connection refused")
	}

	host, _, _ := resolveTarget(context.Background(), "unreachable.example.com")
	if host != "" {
		t.Errorf("resolveTarget should return empty host for unreachable server, got %q", host)
	}
}

// ---------------------------------------------------------------------------
// Probe request content verification — ensure the raw payloads contain
// the expected headers for each probe type.
// ---------------------------------------------------------------------------

// capturingHandler records the raw bytes received on the connection and then
// responds normally.
func capturingHandler(captured *[]byte, mu *sync.Mutex) func(net.Conn) {
	return func(conn net.Conn) {
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)) //nolint:errcheck
		reader := bufio.NewReader(conn)
		var buf []byte
		for {
			line, err := reader.ReadBytes('\n')
			buf = append(buf, line...)
			if err != nil {
				break
			}
		}
		mu.Lock()
		*captured = append(*captured, buf...)
		mu.Unlock()
		conn.Write([]byte(normalHTTPResponse())) //nolint:errcheck
	}
}

func TestProbeCLTE_PayloadContainsCLAndTE(t *testing.T) {
	saved := saveGlobals()
	defer restoreGlobals(saved)
	setFastTimings()

	var captured []byte
	var mu sync.Mutex

	ln, cleanup := startTCPServer(t, capturingHandler(&captured, &mu))
	defer cleanup()

	dialConnFunc = makeDialer(ln)
	host, port := extractHostPort(ln)

	probeCLTE(context.Background(), host, port, "test.example.com", false)

	mu.Lock()
	raw := string(captured)
	mu.Unlock()

	if !strings.Contains(raw, "Content-Length:") {
		t.Error("CL.TE probe payload must contain Content-Length header")
	}
	if !strings.Contains(raw, "Transfer-Encoding: chunked") {
		t.Error("CL.TE probe payload must contain Transfer-Encoding: chunked header")
	}
	if !strings.Contains(raw, "POST / HTTP/1.1") {
		t.Error("CL.TE probe should use POST method")
	}
	if !strings.Contains(raw, "Host: test.example.com") {
		t.Error("CL.TE probe should include Host header with asset name")
	}
}

func TestProbeTECL_PayloadContainsCLAndTE(t *testing.T) {
	saved := saveGlobals()
	defer restoreGlobals(saved)
	setFastTimings()

	var captured []byte
	var mu sync.Mutex

	ln, cleanup := startTCPServer(t, capturingHandler(&captured, &mu))
	defer cleanup()

	dialConnFunc = makeDialer(ln)
	host, port := extractHostPort(ln)

	probeTECL(context.Background(), host, port, "test.example.com", false)

	mu.Lock()
	raw := string(captured)
	mu.Unlock()

	if !strings.Contains(raw, "Content-Length: 3") {
		t.Error("TE.CL probe payload must contain Content-Length: 3")
	}
	if !strings.Contains(raw, "Transfer-Encoding: chunked") {
		t.Error("TE.CL probe payload must contain Transfer-Encoding: chunked header")
	}
	if !strings.Contains(raw, "POST / HTTP/1.1") {
		t.Error("TE.CL probe should use POST method")
	}
}

func TestProbeTETEObfuscation_PayloadContainsObfuscatedTE(t *testing.T) {
	saved := saveGlobals()
	defer restoreGlobals(saved)
	setFastTimings()

	var captured []byte
	var mu sync.Mutex

	ln, cleanup := startTCPServer(t, capturingHandler(&captured, &mu))
	defer cleanup()

	dialConnFunc = makeDialer(ln)
	host, port := extractHostPort(ln)

	probeTETEObfuscation(context.Background(), host, port, "test.example.com", false, "xchunked")

	mu.Lock()
	raw := string(captured)
	mu.Unlock()

	if !strings.Contains(raw, "Transfer-Encoding: xchunked") {
		t.Errorf("TE.TE probe should use obfuscated TE value 'xchunked', got raw: %s", raw)
	}
	if !strings.Contains(raw, "Content-Length:") {
		t.Error("TE.TE probe payload must contain Content-Length header")
	}
}

// ---------------------------------------------------------------------------
// Finding evidence and proof command completeness
// ---------------------------------------------------------------------------

func TestRun_DeepMode_Findings_HaveProofCommandWithAsset(t *testing.T) {
	saved := saveGlobals()
	defer restoreGlobals(saved)
	setFastTimings()

	ln, cleanup := startTCPServer(t, vulnerableHandler)
	defer cleanup()

	dialConnFunc = makeDialer(ln)

	host, port := extractHostPort(ln)
	asset := net.JoinHostPort(host, port)

	s := New()
	findings, err := s.Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	for _, f := range findings {
		if f.ProofCommand == "" {
			t.Errorf("finding %q must have ProofCommand set", f.Title)
		}
		if !strings.Contains(f.ProofCommand, asset) {
			t.Errorf("ProofCommand should contain asset %q, got: %s", asset, f.ProofCommand)
		}
	}
}

func TestRun_DeepMode_Findings_EvidenceHasURL(t *testing.T) {
	saved := saveGlobals()
	defer restoreGlobals(saved)
	setFastTimings()

	ln, cleanup := startTCPServer(t, vulnerableHandler)
	defer cleanup()

	dialConnFunc = makeDialer(ln)

	host, port := extractHostPort(ln)
	asset := net.JoinHostPort(host, port)

	s := New()
	findings, err := s.Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	for _, f := range findings {
		url, ok := f.Evidence["url"].(string)
		if !ok || url == "" {
			t.Errorf("finding %q must have 'url' in Evidence", f.Title)
		}
		baselineMs, ok := f.Evidence["baseline_ms"]
		if !ok {
			t.Errorf("finding %q must have 'baseline_ms' in Evidence", f.Title)
		}
		_ = baselineMs
		probeMs, ok := f.Evidence["probe_elapsed_ms"]
		if !ok {
			t.Errorf("finding %q must have 'probe_elapsed_ms' in Evidence", f.Title)
		}
		_ = probeMs
	}
}

// ---------------------------------------------------------------------------
// buildRawGET tests
// ---------------------------------------------------------------------------

func TestBuildRawGET_ContainsRequiredHeaders(t *testing.T) {
	raw := buildRawGET("test.example.com")
	if !strings.Contains(raw, "GET / HTTP/1.1\r\n") {
		t.Error("buildRawGET must produce a GET request line")
	}
	if !strings.Contains(raw, "Host: test.example.com\r\n") {
		t.Error("buildRawGET must include Host header")
	}
	if !strings.Contains(raw, "Connection: close\r\n") {
		t.Error("buildRawGET must include Connection: close")
	}
	if !strings.HasSuffix(raw, "\r\n\r\n") {
		t.Error("buildRawGET must end with blank line (double CRLF)")
	}
}
