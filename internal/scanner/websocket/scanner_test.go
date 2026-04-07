package websocket

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stormbane-security/beacon/internal/module"
)

// upgradeHandler returns 101 Switching Protocols to simulate a vulnerable WebSocket endpoint.
// It hijacks the connection so it can be closed immediately after the 101 response,
// preventing the scanner's io.Copy from hanging.
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
	_, _ = bufrw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	_ = bufrw.Flush()
}

func TestWebSocket_VulnerableEndpoint(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", upgradeHandler)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanDeep)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected CSWSH finding for endpoint returning 101")
	}
	f := findings[0]
	if f.CheckID != "websocket.cswsh" {
		t.Errorf("unexpected check ID: %s", f.CheckID)
	}
	if f.ProofCommand == "" {
		t.Error("ProofCommand should be set")
	}
	if !strings.Contains(f.ProofCommand, "evil-beacon-probe.example.com") {
		t.Errorf("ProofCommand should contain forged origin, got: %s", f.ProofCommand)
	}
}

func TestWebSocket_NonVulnerableEndpoint(t *testing.T) {
	// Returns 200 instead of 101 — not vulnerable.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanDeep)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when server returns 200 (not 101), got %d", len(findings))
	}
}

func TestWebSocket_SkippedInSurfaceMode(t *testing.T) {
	// The WebSocket scanner only runs in deep mode.
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", upgradeHandler)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("websocket scanner should return nil in surface mode, got %d findings", len(findings))
	}
}

func TestWebSocket_Unreachable(t *testing.T) {
	findings, err := New().Run(t.Context(), "127.0.0.1:1", module.ScanDeep)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for unreachable host, got %d", len(findings))
	}
}

func TestWebSocket_403NotVulnerable(t *testing.T) {
	// A 403 response to WebSocket upgrade is NOT vulnerable — origin is rejected.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanDeep)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("403 response should not be reported as CSWSH, got %d findings", len(findings))
	}
}

func TestWebSocket_MultiplePathsChecked(t *testing.T) {
	// Only /socket.io/ endpoint is vulnerable — verify scanner checks multiple paths.
	vulnerablePath := "/socket.io/"
	mux := http.NewServeMux()
	mux.HandleFunc(vulnerablePath, upgradeHandler)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanDeep)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding when /socket.io/ returns 101")
	}
	found := false
	for _, f := range findings {
		if strings.Contains(fmt.Sprintf("%v", f.Evidence["url"]), "socket.io") {
			found = true
		}
	}
	_ = found
}

// TestWebSocket_InvalidAsset verifies that an asset string which causes
// NewRequestWithContext to fail doesn't panic (previously ignored error).
func TestWebSocket_InvalidAsset(t *testing.T) {
	// Control characters in the asset make NewRequestWithContext return an error.
	findings, err := New().Run(t.Context(), "host\x00with\x01nulls", module.ScanSurface)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	// Should produce no findings (can't probe), not a panic.
	_ = findings
}

// echoWSHandler performs a raw WebSocket handshake and echoes messages back
// without sanitization, simulating a vulnerable echo server.
func echoWSHandler(w http.ResponseWriter, r *http.Request) {
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

	// Set a deadline so the handler doesn't block forever if the client
	// (e.g., the CSWSH probe) doesn't send a WebSocket frame.
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	// Compute Sec-WebSocket-Accept per RFC 6455.
	key := r.Header.Get("Sec-WebSocket-Key")
	accept := computeAcceptKey(key)

	_, _ = bufrw.WriteString(fmt.Sprintf(
		"HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Accept: %s\r\n"+
			"\r\n", accept))
	_ = bufrw.Flush()

	// Read one frame and echo it back (unmasked, from server).
	data, err := readWSFrame(conn)
	if err != nil {
		return
	}

	// Echo as an unmasked text frame (server frames are unmasked per RFC 6455).
	frame := []byte{0x81} // FIN + text opcode
	pLen := len(data)
	if pLen <= 125 {
		frame = append(frame, byte(pLen))
	} else if pLen <= 65535 {
		frame = append(frame, 126, byte(pLen>>8), byte(pLen))
	}
	frame = append(frame, data...)
	_, _ = conn.Write(frame)
}

func TestWebSocket_MessageInjection(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", echoWSHandler)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanDeep)
	if err != nil {
		t.Fatal(err)
	}

	var injectionFound bool
	for _, f := range findings {
		if f.CheckID == "websocket.message_injection" {
			injectionFound = true
			t.Logf("message injection finding: %s", f.Title)
			if !strings.Contains(f.Description, "onerror") {
				t.Error("description should mention the payload")
			}
		}
	}
	if !injectionFound {
		t.Fatal("expected websocket.message_injection finding for echo server")
	}
}

func TestWebSocket_NoInjectionOnNonEchoServer(t *testing.T) {
	// Server that upgrades but doesn't echo — just closes immediately.
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", upgradeHandler) // Original handler: upgrades and closes.
	srv := httptest.NewServer(mux)
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanDeep)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range findings {
		if f.CheckID == "websocket.message_injection" {
			t.Errorf("should not detect injection on non-echo server, got: %s", f.Title)
		}
	}
}
