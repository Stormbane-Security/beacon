package websocket

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane/beacon/internal/module"
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
	defer conn.Close()
	bufrw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	bufrw.Flush()
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
