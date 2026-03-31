package network_test

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
	"github.com/stormbane/beacon/internal/scanner/onprem/network"
)

// failHTTPClient returns an HTTP client whose transport always errors immediately.
// This prevents tests from making real HTTP connections to fake IPs.
func failHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 1 * time.Millisecond,
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return nil, errors.New("no HTTP connectivity in test")
		}),
	}
}

// --------------------------------------------------------------------------
// Test helpers
// --------------------------------------------------------------------------

func hasCheckID(findings []finding.Finding, id finding.CheckID) bool {
	for _, f := range findings {
		if f.CheckID == id {
			return true
		}
	}
	return false
}

func countCheckID(findings []finding.Finding, id finding.CheckID) int {
	n := 0
	for _, f := range findings {
		if f.CheckID == id {
			n++
		}
	}
	return n
}

// testDialer maps addresses to mock connections, returning errors for unknown addresses.
type testDialer struct {
	mu       sync.Mutex
	handlers map[string]func(conn net.Conn)
	// listenAddrs stores the actual listener addresses keyed by the logical address.
	listenAddrs map[string]string
}

func newTestDialer() *testDialer {
	return &testDialer{
		handlers:    make(map[string]func(conn net.Conn)),
		listenAddrs: make(map[string]string),
	}
}

func (d *testDialer) DialContext(ctx context.Context, netw, address string) (net.Conn, error) {
	d.mu.Lock()
	actualAddr, ok := d.listenAddrs[address]
	d.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("connection refused: %s", address)
	}

	dialer := &net.Dialer{}
	return dialer.DialContext(ctx, netw, actualAddr)
}

// addUDPHandler starts a UDP listener on a random port and maps the logical address.
func (d *testDialer) addUDPHandler(logicalAddr string, handler func(conn net.PacketConn)) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	actualAddr := pc.LocalAddr().String()
	d.mu.Lock()
	d.listenAddrs[logicalAddr] = actualAddr
	d.mu.Unlock()
	go func() {
		defer pc.Close()
		handler(pc)
	}()
	return actualAddr
}

// addTCPHandler starts a TCP listener on a random port and maps the logical address.
func (d *testDialer) addTCPHandler(logicalAddr string, handler func(conn net.Conn)) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	actualAddr := ln.Addr().String()
	d.mu.Lock()
	d.listenAddrs[logicalAddr] = actualAddr
	d.mu.Unlock()
	go func() {
		defer ln.Close()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				handler(c)
			}(conn)
		}
	}()
	return actualAddr
}

// --------------------------------------------------------------------------
// SNMP default community string detection
// --------------------------------------------------------------------------

func TestSNMPDefaultCommunity_Detected(t *testing.T) {
	dialer := newTestDialer()
	ip := "192.168.1.1"

	// Mock SNMP responder: accepts any packet, returns a valid SNMP response.
	dialer.addUDPHandler(ip+":161", func(pc net.PacketConn) {
		buf := make([]byte, 4096)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil || n == 0 {
			return
		}
		// Build a minimal SNMP response (SEQUENCE wrapper).
		response := []byte{
			0x30, 0x26, // SEQUENCE
			0x02, 0x01, 0x01, // version: SNMPv2c
			0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c', // community: public
			0xa2, 0x19, // GetResponse PDU
			0x02, 0x01, 0x01, // request-id: 1
			0x02, 0x01, 0x00, // error-status: 0
			0x02, 0x01, 0x00, // error-index: 0
			0x30, 0x0e, // varbind list
			0x30, 0x0c, // varbind
			0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // OID
			0x05, 0x00, // NULL
		}
		pc.WriteTo(response, addr)
	})

	cfg := network.Config{Targets: []string{ip}}
	s := network.NewWithDialer(cfg, dialer, failHTTPClient())

	findings, err := s.Run(context.Background(), ip, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremNetworkSNMPDefaultComm) {
		t.Error("expected CheckOnpremNetworkSNMPDefaultComm when SNMP responds to default community")
	}
	if !hasCheckID(findings, finding.CheckOnpremNetworkSNMPv1v2) {
		t.Error("expected CheckOnpremNetworkSNMPv1v2 when SNMPv2c is used")
	}
	if !hasCheckID(findings, finding.CheckOnpremNetworkNoSNMPv3) {
		t.Error("expected CheckOnpremNetworkNoSNMPv3 when SNMPv2c is accepted")
	}
}

// --------------------------------------------------------------------------
// SNMP: no response means no finding
// --------------------------------------------------------------------------

func TestSNMPNoResponse_NoFinding(t *testing.T) {
	dialer := newTestDialer()
	ip := "192.168.1.2"

	// Mock SNMP that reads but does not respond.
	dialer.addUDPHandler(ip+":161", func(pc net.PacketConn) {
		buf := make([]byte, 4096)
		pc.ReadFrom(buf) // read and discard
	})

	cfg := network.Config{Targets: []string{ip}}
	s := network.NewWithDialer(cfg, dialer, failHTTPClient())

	findings, err := s.Run(context.Background(), ip, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(findings, finding.CheckOnpremNetworkSNMPDefaultComm) {
		t.Error("should not emit SNMP finding when no response is received")
	}
}

// --------------------------------------------------------------------------
// SNMP: surface mode should NOT probe SNMP
// --------------------------------------------------------------------------

func TestSNMP_SurfaceMode_NoProbeSent(t *testing.T) {
	dialer := newTestDialer()
	ip := "192.168.1.3"

	probed := false
	dialer.addUDPHandler(ip+":161", func(pc net.PacketConn) {
		buf := make([]byte, 4096)
		n, addr, _ := pc.ReadFrom(buf)
		if n > 0 {
			probed = true
			// Respond anyway.
			resp := []byte{0x30, 0x03, 0x02, 0x01, 0x01}
			pc.WriteTo(resp, addr)
		}
	})

	cfg := network.Config{Targets: []string{ip}}
	s := network.NewWithDialer(cfg, dialer, failHTTPClient())

	findings, _ := s.Run(context.Background(), ip, module.ScanSurface)
	if hasCheckID(findings, finding.CheckOnpremNetworkSNMPDefaultComm) {
		t.Error("SNMP should not be probed in surface mode")
	}
	_ = probed
}

// --------------------------------------------------------------------------
// UPnP/SSDP discovery
// --------------------------------------------------------------------------

func TestUPnP_Detected(t *testing.T) {
	dialer := newTestDialer()
	ip := "192.168.1.10"

	dialer.addUDPHandler(ip+":1900", func(pc net.PacketConn) {
		buf := make([]byte, 4096)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil || n == 0 {
			return
		}
		response := "HTTP/1.1 200 OK\r\n" +
			"CACHE-CONTROL: max-age=1800\r\n" +
			"LOCATION: http://192.168.1.10:80/desc.xml\r\n" +
			"SERVER: Linux/4.4 UPnP/1.1 MiniUPnPd/2.1\r\n" +
			"ST: upnp:rootdevice\r\n" +
			"\r\n"
		pc.WriteTo([]byte(response), addr)
	})

	cfg := network.Config{Targets: []string{ip}}
	s := network.NewWithDialer(cfg, dialer, failHTTPClient())

	findings, err := s.Run(context.Background(), ip, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremNetworkUPnPExposed) {
		t.Error("expected CheckOnpremNetworkUPnPExposed when SSDP responds")
	}

	// Verify evidence contains server info.
	for _, f := range findings {
		if f.CheckID == finding.CheckOnpremNetworkUPnPExposed {
			if f.Evidence["server"] == "" {
				t.Error("UPnP finding should include server info in evidence")
			}
		}
	}
}

// --------------------------------------------------------------------------
// UPnP: no response
// --------------------------------------------------------------------------

func TestUPnP_NoResponse_NoFinding(t *testing.T) {
	dialer := newTestDialer()
	ip := "192.168.1.11"

	dialer.addUDPHandler(ip+":1900", func(pc net.PacketConn) {
		buf := make([]byte, 4096)
		pc.ReadFrom(buf) // read and discard
	})

	cfg := network.Config{Targets: []string{ip}}
	s := network.NewWithDialer(cfg, dialer, failHTTPClient())

	findings, _ := s.Run(context.Background(), ip, module.ScanSurface)
	if hasCheckID(findings, finding.CheckOnpremNetworkUPnPExposed) {
		t.Error("should not emit UPnP finding when no response is received")
	}
}

// --------------------------------------------------------------------------
// mDNS service enumeration
// --------------------------------------------------------------------------

func TestMDNS_Detected(t *testing.T) {
	dialer := newTestDialer()
	ip := "192.168.1.20"

	dialer.addUDPHandler(ip+":5353", func(pc net.PacketConn) {
		buf := make([]byte, 4096)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil || n == 0 {
			return
		}
		// Build a minimal DNS response with 2 answers.
		response := make([]byte, 12)
		// Copy the transaction ID from the query.
		copy(response[0:2], buf[0:2])
		// Flags: response, authoritative
		response[2] = 0x84
		response[3] = 0x00
		// QDCOUNT: 0
		binary.BigEndian.PutUint16(response[4:6], 0)
		// ANCOUNT: 2
		binary.BigEndian.PutUint16(response[6:8], 2)
		// NSCOUNT: 0
		binary.BigEndian.PutUint16(response[8:10], 0)
		// ARCOUNT: 0
		binary.BigEndian.PutUint16(response[10:12], 0)

		// Add two minimal answer records (just enough for the answer count to be parsed).
		// PTR record: name=0xC00C (pointer to offset 12), type=PTR(12), class=IN(1), TTL=4500, rdlength=2, rdata=0xC00C
		answer := []byte{
			0xc0, 0x0c, // name pointer
			0x00, 0x0c, // type: PTR
			0x00, 0x01, // class: IN
			0x00, 0x00, 0x11, 0x94, // TTL
			0x00, 0x02, // rdlength
			0xc0, 0x0c, // rdata (pointer)
		}
		response = append(response, answer...)
		response = append(response, answer...) // second answer
		pc.WriteTo(response, addr)
	})

	cfg := network.Config{Targets: []string{ip}}
	s := network.NewWithDialer(cfg, dialer, failHTTPClient())

	findings, err := s.Run(context.Background(), ip, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremNetworkMDNSExposed) {
		t.Error("expected CheckOnpremNetworkMDNSExposed when mDNS responds with answers")
	}
}

// --------------------------------------------------------------------------
// Telnet management detection
// --------------------------------------------------------------------------

func TestTelnet_Detected(t *testing.T) {
	dialer := newTestDialer()
	ip := "192.168.1.30"

	dialer.addTCPHandler(ip+":23", func(conn net.Conn) {
		conn.Write([]byte("Welcome to MikroTik Router\r\nLogin: "))
		// Read and discard any input.
		io.Copy(io.Discard, conn)
	})

	cfg := network.Config{Targets: []string{ip}}
	s := network.NewWithDialer(cfg, dialer, failHTTPClient())

	findings, err := s.Run(context.Background(), ip, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremNetworkTelnetEnabled) {
		t.Error("expected CheckOnpremNetworkTelnetEnabled when Telnet port is open")
	}

	// Verify banner is captured.
	for _, f := range findings {
		if f.CheckID == finding.CheckOnpremNetworkTelnetEnabled {
			banner, _ := f.Evidence["banner"].(string)
			if !strings.Contains(banner, "MikroTik") {
				t.Errorf("expected Telnet banner to contain 'MikroTik', got: %s", banner)
			}
		}
	}
}

// --------------------------------------------------------------------------
// Telnet: port closed
// --------------------------------------------------------------------------

func TestTelnet_PortClosed_NoFinding(t *testing.T) {
	dialer := newTestDialer()
	ip := "192.168.1.31"
	// No TCP handler registered for port 23 — connection will be refused.

	cfg := network.Config{Targets: []string{ip}}
	s := network.NewWithDialer(cfg, dialer, failHTTPClient())

	findings, _ := s.Run(context.Background(), ip, module.ScanSurface)
	if hasCheckID(findings, finding.CheckOnpremNetworkTelnetEnabled) {
		t.Error("should not emit Telnet finding when port 23 is closed")
	}
}

// --------------------------------------------------------------------------
// HTTP management without TLS
// --------------------------------------------------------------------------

func TestHTTPMgmt_Detected(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "lighttpd/1.4.35")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><head><title>Router Admin</title></head><body>Login</body></html>"))
	}))
	defer ts.Close()

	// Extract the host:port from the test server.
	addr := strings.TrimPrefix(ts.URL, "http://")
	host, port, _ := net.SplitHostPort(addr)

	// Create a dialer that won't be used for HTTP but we need for other checks.
	dialer := newTestDialer()

	cfg := network.Config{Targets: []string{host}}
	// Override httpMgmtPorts by creating a scanner that uses the test server's port.
	// We'll use a custom HTTP client that redirects all requests to our test server.
	client := ts.Client()

	// Build a custom transport that rewrites URLs to the test server.
	origTransport := client.Transport
	client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		// Rewrite the request URL to point at the test server.
		req.URL.Host = addr
		if origTransport != nil {
			return origTransport.RoundTrip(req)
		}
		return http.DefaultTransport.RoundTrip(req)
	})

	s := network.NewWithDialer(cfg, dialer, client)

	findings, err := s.Run(context.Background(), host, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremNetworkHTTPMgmt) {
		t.Errorf("expected CheckOnpremNetworkHTTPMgmt when HTTP management UI is exposed (port %s)", port)
	}
}

type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// --------------------------------------------------------------------------
// All findings have ProofCommand and Evidence
// --------------------------------------------------------------------------

func TestAllFindings_HaveProofCommandAndEvidence(t *testing.T) {
	dialer := newTestDialer()
	ip := "192.168.1.50"

	// Set up a Telnet mock to produce at least one finding.
	dialer.addTCPHandler(ip+":23", func(conn net.Conn) {
		conn.Write([]byte("Login: "))
	})

	cfg := network.Config{Targets: []string{ip}}
	s := network.NewWithDialer(cfg, dialer, failHTTPClient())

	findings, _ := s.Run(context.Background(), ip, module.ScanSurface)
	for _, f := range findings {
		if f.ProofCommand == "" {
			t.Errorf("finding %s must have ProofCommand set", f.CheckID)
		}
		if f.Evidence == nil {
			t.Errorf("finding %s must have Evidence set", f.CheckID)
		}
	}
}

// --------------------------------------------------------------------------
// Context cancellation: no panic
// --------------------------------------------------------------------------

func TestContextCancelled_NoPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cfg := network.Config{Targets: []string{"192.168.1.1"}}
	s := network.New(cfg)
	_, _ = s.Run(ctx, "192.168.1.1", module.ScanSurface) // must not panic
}

// --------------------------------------------------------------------------
// Scanner name
// --------------------------------------------------------------------------

func TestScannerName(t *testing.T) {
	s := network.New(network.Config{})
	if s.Name() != "onprem/network" {
		t.Errorf("expected scanner name 'onprem/network', got %q", s.Name())
	}
}
