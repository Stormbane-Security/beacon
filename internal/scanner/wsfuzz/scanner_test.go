package wsfuzz

import (
	"crypto/sha1" //nolint:gosec
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)

// upgradeHandler performs a raw WebSocket upgrade handshake and immediately closes.
func upgradeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Upgrade") != "websocket" {
		http.NotFound(w, r)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	conn, bufrw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()

	key := r.Header.Get("Sec-WebSocket-Key")
	accept := wsAccept(key)

	_, _ = fmt.Fprintf(bufrw,
		"HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Accept: %s\r\n"+
			"\r\n", accept)
	_ = bufrw.Flush()
}

// echoHandler upgrades and echoes one WebSocket message back.
func echoHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Upgrade") != "websocket" {
		http.NotFound(w, r)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	conn, bufrw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	key := r.Header.Get("Sec-WebSocket-Key")
	accept := wsAccept(key)

	_, _ = fmt.Fprintf(bufrw,
		"HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Accept: %s\r\n"+
			"\r\n", accept)
	_ = bufrw.Flush()

	// Read one frame and echo it back unmasked.
	data, err := readWSFrame(conn)
	if err != nil {
		return
	}

	frame := []byte{0x81} // FIN + text
	pLen := len(data)
	if pLen <= 125 {
		frame = append(frame, byte(pLen))
	} else if pLen <= 65535 {
		frame = append(frame, 126, byte(pLen>>8), byte(pLen))
	}
	frame = append(frame, data...)
	_, _ = conn.Write(frame)
}

// sqlErrorHandler upgrades and returns a SQL error regardless of input.
func sqlErrorHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Upgrade") != "websocket" {
		http.NotFound(w, r)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	conn, bufrw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	key := r.Header.Get("Sec-WebSocket-Key")
	accept := wsAccept(key)

	_, _ = fmt.Fprintf(bufrw,
		"HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Accept: %s\r\n"+
			"\r\n", accept)
	_ = bufrw.Flush()

	// Read one frame.
	data, err := readWSFrame(conn)
	if err != nil {
		return
	}

	// If the message contains a SQL injection pattern, return SQL error.
	msg := string(data)
	var response string
	if strings.Contains(msg, "OR 1=1") {
		response = `{"error":"mysql syntax error near '1=1-- -' at line 1"}`
	} else {
		response = `{"status":"ok","data":[]}`
	}

	frame := []byte{0x81}
	pLen := len(response)
	if pLen <= 125 {
		frame = append(frame, byte(pLen))
	} else if pLen <= 65535 {
		frame = append(frame, 126, byte(pLen>>8), byte(pLen))
	}
	frame = append(frame, []byte(response)...)
	_, _ = conn.Write(frame)
}

func wsAccept(key string) string {
	const guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	h := sha1.New() //nolint:gosec
	_, _ = h.Write([]byte(key + guid))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// ---------------------------------------------------------------------------
// No Origin Check
// ---------------------------------------------------------------------------

func TestProbeNoOriginCheck_AcceptsAnyOrigin_FindingEmitted(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", upgradeHandler)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	_, port, _ := net.SplitHostPort(asset)

	f := probeNoOriginCheck(t.Context(), "http", asset, "/ws", "ws://"+asset+"/ws")
	if f == nil {
		t.Fatalf("expected finding for no origin check on port %s, got nil", port)
	}
	if f.CheckID != finding.CheckWebSocketNoOriginCheck {
		t.Errorf("expected CheckWebSocketNoOriginCheck, got %s", f.CheckID)
	}
	if f.Severity != finding.SeverityMedium {
		t.Errorf("expected Medium severity, got %v", f.Severity)
	}
}

func TestProbeNoOriginCheck_NoWSEndpoint_NoFinding(t *testing.T) {
	// Server returns 404, no WebSocket.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	f := probeNoOriginCheck(t.Context(), "http", asset, "/ws", "ws://"+asset+"/ws")
	if f != nil {
		t.Errorf("expected no finding for non-WS endpoint, got: %s", f.Title)
	}
}

// ---------------------------------------------------------------------------
// Auth Bypass
// ---------------------------------------------------------------------------

func TestProbeAuthBypass_NoAuthRequired_FindingEmitted(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", echoHandler)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	f := probeAuthBypass(t.Context(), "http", asset, "/ws", "ws://"+asset+"/ws")
	if f == nil {
		t.Fatal("expected auth bypass finding for echo server, got nil")
	}
	if f.CheckID != finding.CheckWebSocketAuthBypass {
		t.Errorf("expected CheckWebSocketAuthBypass, got %s", f.CheckID)
	}
	if f.Severity != finding.SeverityCritical {
		t.Errorf("expected Critical severity, got %v", f.Severity)
	}
}

func TestProbeAuthBypass_NoWSEndpoint_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	f := probeAuthBypass(t.Context(), "http", asset, "/ws", "ws://"+asset+"/ws")
	if f != nil {
		t.Errorf("expected no finding for non-WS endpoint, got: %s", f.Title)
	}
}

// ---------------------------------------------------------------------------
// Injection
// ---------------------------------------------------------------------------

func TestProbeInjection_SQLi_FindingEmitted(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", sqlErrorHandler)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	payload := injectionPayloads[0] // SQLi
	f := probeInjection(t.Context(), "http", asset, "/ws", "ws://"+asset+"/ws", payload)
	if f == nil {
		t.Fatal("expected injection finding for SQL error response, got nil")
	}
	if f.CheckID != finding.CheckWebSocketInjection {
		t.Errorf("expected CheckWebSocketInjection, got %s", f.CheckID)
	}
	if f.Severity != finding.SeverityHigh {
		t.Errorf("expected High severity, got %v", f.Severity)
	}
	if f.Evidence["injection_type"] != "SQLi" {
		t.Errorf("expected injection_type=SQLi, got %v", f.Evidence["injection_type"])
	}
}

func TestProbeInjection_NoVulnerability_NoFinding(t *testing.T) {
	// Echo server returns exactly what was sent — but none of the indicators
	// for SQLi would match on `{"data":"normal-test-value"}` echoed back.
	// Actually the baseline and injection both echo, so we need a server that
	// returns a static response regardless.
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			http.NotFound(w, r)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

		key := r.Header.Get("Sec-WebSocket-Key")
		accept := wsAccept(key)
		_, _ = fmt.Fprintf(bufrw,
			"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept)
		_ = bufrw.Flush()

		// Read one frame, always return same safe response.
		_, _ = readWSFrame(conn)
		resp := `{"status":"ok"}`
		frame := append([]byte{0x81, byte(len(resp))}, []byte(resp)...)
		_, _ = conn.Write(frame)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	payload := injectionPayloads[0] // SQLi
	f := probeInjection(t.Context(), "http", asset, "/ws", "ws://"+asset+"/ws", payload)
	if f != nil {
		t.Errorf("expected no injection finding for safe server, got: %s", f.Title)
	}
}

// ---------------------------------------------------------------------------
// Full Run integration
// ---------------------------------------------------------------------------

func TestRun_SurfaceMode_OnlyOriginCheck(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", upgradeHandler)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.CheckID == finding.CheckWebSocketInjection {
			t.Error("injection checks should not run in surface mode")
		}
		if f.CheckID == finding.CheckWebSocketAuthBypass {
			t.Error("auth bypass checks should not run in surface mode")
		}
	}
}

func TestRun_Unreachable_NoFindings(t *testing.T) {
	findings, err := New().Run(t.Context(), "127.0.0.1:1", module.ScanAuthorized)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for unreachable host, got %d", len(findings))
	}
}

func TestRun_AuthorizedMode_AllChecks(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", sqlErrorHandler)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanAuthorized)
	if err != nil {
		t.Fatal(err)
	}

	checkIDs := make(map[string]bool)
	for _, f := range findings {
		checkIDs[f.CheckID] = true
	}

	// Should have origin check at minimum (the endpoint upgrades).
	if !checkIDs[finding.CheckWebSocketNoOriginCheck] {
		t.Error("expected websocket.no_origin_check finding")
	}
}
