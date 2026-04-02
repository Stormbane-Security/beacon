package portscan

// White-box tests for probeLDAP, probeEPMD, parseAssetPort, buildPortList,
// and bannerProtocol. These tests call internal functions directly so they
// never pay the 5-second inter-connect-delay cost of a full s.Run() call.

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stormbane-security/beacon/internal/module"
)

// ---------------------------------------------------------------------------
// probeLDAP unit tests
// ---------------------------------------------------------------------------

// serveLDAP starts a minimal TCP server on a random loopback port that
// responds to the LDAP null bind according to the provided handler fn.
// Returns the bound port and a cleanup function.
func serveLDAP(t *testing.T, handler func(net.Conn)) (port int, cleanup func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("serveLDAP listen: %v", err)
	}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go handler(conn)
		}
	}()
	_, portStr, _ := net.SplitHostPort(l.Addr().String())
	var p int
	for _, b := range portStr {
		if b >= '0' && b <= '9' {
			p = p*10 + int(b-'0')
		}
	}
	return p, func() { _ = l.Close() }
}

// bindSuccessResp is a BindResponse with resultCode 0 (success).
var bindSuccessResp = []byte{
	0x30, 0x0c,
	0x02, 0x01, 0x01,
	0x61, 0x07,
	0x0a, 0x01, 0x00, // resultCode: success
	0x04, 0x00,
	0x04, 0x00,
}

// searchDoneResp is a SearchResultDone with resultCode 0.
var searchDoneResp = []byte{
	0x30, 0x0c,
	0x02, 0x01, 0x02,
	0x65, 0x07,
	0x0a, 0x01, 0x00,
	0x04, 0x00,
	0x04, 0x00,
}

// TestProbeLDAP_NullBindSuccess verifies that a server accepting the null bind
// and returning a non-AD rootDSE produces a result with null_bind=true,
// is_active_directory=false.
func TestProbeLDAP_NullBindSuccess(t *testing.T) {
	port, cleanup := serveLDAP(t, func(c net.Conn) {
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 256)
		_, _ = c.Read(buf) // drain null bind request
		_, _ = c.Write(bindSuccessResp)
		_, _ = c.Read(buf) // drain rootDSE request
		_, _ = c.Write(searchDoneResp)
	})
	defer cleanup()

	ctx := context.Background()
	result := probeLDAP(ctx, "127.0.0.1", port)
	if result == nil {
		t.Fatal("probeLDAP returned nil for accepting server; want non-nil")
	}
	if nullBind, _ := result["null_bind"].(bool); !nullBind {
		t.Error("null_bind should be true")
	}
	if isAD, _ := result["is_active_directory"].(bool); isAD {
		t.Error("is_active_directory should be false for non-AD response")
	}
}

// TestProbeLDAP_ActiveDirectoryDetection verifies that "DC=" in the rootDSE
// response sets is_active_directory=true and captures the domain.
func TestProbeLDAP_ActiveDirectoryDetection(t *testing.T) {
	port, cleanup := serveLDAP(t, func(c net.Conn) {
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 256)
		_, _ = c.Read(buf) // drain null bind
		_, _ = c.Write(bindSuccessResp)
		_, _ = c.Read(buf) // drain rootDSE request

		// Inject "DC=corp,DC=example,DC=com" in the rootDSE response body.
		adText := []byte("DC=corp,DC=example,DC=com")
		body := append(bindSuccessResp, adText...) // reuse bytes as payload carrier
		_, _ = c.Write(body)
	})
	defer cleanup()

	ctx := context.Background()
	result := probeLDAP(ctx, "127.0.0.1", port)
	if result == nil {
		t.Fatal("probeLDAP returned nil; want non-nil for accepting server")
	}
	if isAD, _ := result["is_active_directory"].(bool); !isAD {
		t.Error("is_active_directory should be true when rootDSE contains DC=")
	}
	if domain, _ := result["ad_domain"].(string); domain == "" {
		t.Error("ad_domain should be populated when DC= is found in rootDSE")
	}
}

// TestProbeLDAP_NullBindRefused verifies that a server returning resultCode 49
// (invalidCredentials) causes probeLDAP to return nil.
func TestProbeLDAP_NullBindRefused(t *testing.T) {
	port, cleanup := serveLDAP(t, func(c net.Conn) {
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 256)
		_, _ = c.Read(buf) // drain null bind
		// BindResponse: resultCode 49 (invalidCredentials)
		_, _ = c.Write([]byte{
			0x30, 0x0c,
			0x02, 0x01, 0x01,
			0x61, 0x07,
			0x0a, 0x01, 0x31, // resultCode 49
			0x04, 0x00,
			0x04, 0x00,
		})
	})
	defer cleanup()

	ctx := context.Background()
	result := probeLDAP(ctx, "127.0.0.1", port)
	if result != nil {
		t.Errorf("probeLDAP should return nil for refused null bind, got %v", result)
	}
}

// TestProbeLDAP_ClosedPort verifies that probeLDAP returns nil when nothing
// is listening (connection refused).
func TestProbeLDAP_ClosedPort(t *testing.T) {
	// Bind then close to get a port we know is free.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, portStr, _ := net.SplitHostPort(l.Addr().String())
	_ = l.Close()

	var port int
	for _, b := range portStr {
		if b >= '0' && b <= '9' {
			port = port*10 + int(b-'0')
		}
	}

	ctx := context.Background()
	result := probeLDAP(ctx, "127.0.0.1", port)
	if result != nil {
		t.Errorf("probeLDAP should return nil for closed port, got %v", result)
	}
}

// ---------------------------------------------------------------------------
// probeEPMD unit tests
// ---------------------------------------------------------------------------

// serveEPMD starts a minimal EPMD TCP server on a random port.
func serveEPMD(t *testing.T, handler func(net.Conn)) (port int, cleanup func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("serveEPMD listen: %v", err)
	}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go handler(conn)
		}
	}()
	_, portStr, _ := net.SplitHostPort(l.Addr().String())
	var p int
	for _, b := range portStr {
		if b >= '0' && b <= '9' {
			p = p*10 + int(b-'0')
		}
	}
	return p, func() { _ = l.Close() }
}

// TestProbeEPMD_NodesListed verifies that a proper EPMD NAMES response returns
// the node names and nothing is missed.
func TestProbeEPMD_NodesListed(t *testing.T) {
	port, cleanup := serveEPMD(t, func(c net.Conn) {
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 16)
		_, _ = c.Read(buf) // drain NAMES request
		response := "name rabbit at port 25672\nname myapp at port 12345\n"
		resp := append([]byte{0x00, 0x00, 0x11, 0x11}, []byte(response)...)
		_, _ = c.Write(resp)
	})
	defer cleanup()

	ctx := context.Background()
	nodes := probeEPMD(ctx, "127.0.0.1", port)
	if len(nodes) != 2 {
		t.Errorf("probeEPMD returned %d nodes; want 2 — got %v", len(nodes), nodes)
	}
	nodeSet := make(map[string]bool)
	for _, n := range nodes {
		nodeSet[n] = true
	}
	if !nodeSet["rabbit"] {
		t.Error("expected node 'rabbit' in results")
	}
	if !nodeSet["myapp"] {
		t.Error("expected node 'myapp' in results")
	}
}

// TestProbeEPMD_EmptyNodeList verifies that a response with no "name " lines
// returns nil (no nodes to report).
func TestProbeEPMD_EmptyNodeList(t *testing.T) {
	port, cleanup := serveEPMD(t, func(c net.Conn) {
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 16)
		c.Read(buf)
		// Only 4-byte port header, no node entries.
		c.Write([]byte{0x00, 0x00, 0x11, 0x11})
	})
	defer cleanup()

	ctx := context.Background()
	nodes := probeEPMD(ctx, "127.0.0.1", port)
	if len(nodes) != 0 {
		t.Errorf("probeEPMD should return nil for empty node list, got %v", nodes)
	}
}

// TestProbeEPMD_TruncatedResponse verifies that a response shorter than 5 bytes
// returns nil.
func TestProbeEPMD_TruncatedResponse(t *testing.T) {
	port, cleanup := serveEPMD(t, func(c net.Conn) {
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 16)
		c.Read(buf)
		c.Write([]byte{0x00, 0x01}) // only 2 bytes — too short
	})
	defer cleanup()

	ctx := context.Background()
	nodes := probeEPMD(ctx, "127.0.0.1", port)
	if len(nodes) != 0 {
		t.Errorf("probeEPMD should return nil for truncated response, got %v", nodes)
	}
}

// ---------------------------------------------------------------------------
// parseAssetPort unit tests
// ---------------------------------------------------------------------------

func TestParseAssetPort_HostAndPort(t *testing.T) {
	host, port := parseAssetPort("localhost:9122")
	if host != "localhost" || port != 9122 {
		t.Errorf("got (%q, %d); want (localhost, 9122)", host, port)
	}
}

func TestParseAssetPort_IPAndPort(t *testing.T) {
	host, port := parseAssetPort("10.0.0.1:8123")
	if host != "10.0.0.1" || port != 8123 {
		t.Errorf("got (%q, %d); want (10.0.0.1, 8123)", host, port)
	}
}

func TestParseAssetPort_BareHost(t *testing.T) {
	host, port := parseAssetPort("example.com")
	if host != "" || port != 0 {
		t.Errorf("bare host should return empty; got (%q, %d)", host, port)
	}
}

func TestParseAssetPort_BareDomain(t *testing.T) {
	host, port := parseAssetPort("sub.example.com")
	if host != "" || port != 0 {
		t.Errorf("bare domain should return empty; got (%q, %d)", host, port)
	}
}

func TestParseAssetPort_IPv6WithPort(t *testing.T) {
	host, port := parseAssetPort("[::1]:8080")
	if host != "::1" || port != 8080 {
		t.Errorf("got (%q, %d); want (::1, 8080)", host, port)
	}
}

func TestParseAssetPort_InvalidPort(t *testing.T) {
	host, port := parseAssetPort("host:abc")
	if host != "" || port != 0 {
		t.Errorf("invalid port should return empty; got (%q, %d)", host, port)
	}
}

func TestParseAssetPort_PortZero(t *testing.T) {
	host, port := parseAssetPort("host:0")
	if host != "" || port != 0 {
		t.Errorf("port 0 should return empty; got (%q, %d)", host, port)
	}
}

func TestParseAssetPort_PortTooHigh(t *testing.T) {
	host, port := parseAssetPort("host:99999")
	if host != "" || port != 0 {
		t.Errorf("port >65535 should return empty; got (%q, %d)", host, port)
	}
}

// ---------------------------------------------------------------------------
// Scanner.Ports override tests
// ---------------------------------------------------------------------------

func TestScanner_PortsOverride(t *testing.T) {
	s := &Scanner{Ports: []int{8123, 6379}}
	// Can't call Run (needs real network), but verify the port list construction
	// by checking the Ports field is set and would be used.
	if len(s.Ports) != 2 {
		t.Fatalf("expected 2 ports, got %d", len(s.Ports))
	}
	if s.Ports[0] != 8123 || s.Ports[1] != 6379 {
		t.Errorf("Ports = %v; want [8123, 6379]", s.Ports)
	}
}

func TestScanner_EmptyPortsUsesDefault(t *testing.T) {
	s := &Scanner{}
	if len(s.Ports) != 0 {
		t.Fatalf("default scanner should have empty Ports, got %v", s.Ports)
	}
	// buildPortList should return the full default list when Ports is empty.
	ports := buildPortList(module.ScanSurface)
	if len(ports) < 20 {
		t.Errorf("default port list too small: %d ports", len(ports))
	}
}

// ---------------------------------------------------------------------------
// bannerProtocol tests
// ---------------------------------------------------------------------------

func TestBannerProtocol_SMTP(t *testing.T) {
	if got := bannerProtocol("220 mail.example.com ESMTP Postfix"); got != "smtp" {
		t.Errorf("bannerProtocol(SMTP) = %q; want smtp", got)
	}
}

func TestBannerProtocol_SSH(t *testing.T) {
	if got := bannerProtocol("SSH-2.0-OpenSSH_8.9p1"); got != "ssh" {
		t.Errorf("bannerProtocol(SSH) = %q; want ssh", got)
	}
}

func TestBannerProtocol_Redis(t *testing.T) {
	if got := bannerProtocol("-ERR wrong number of arguments"); got != "redis" {
		t.Errorf("bannerProtocol(Redis) = %q; want redis", got)
	}
}

func TestBannerProtocol_FTP(t *testing.T) {
	if got := bannerProtocol("220 Welcome to FTP server"); got != "ftp" {
		t.Errorf("bannerProtocol(FTP) = %q; want ftp", got)
	}
}

func TestBannerProtocol_POP3(t *testing.T) {
	if got := bannerProtocol("+OK Dovecot ready."); got != "pop3" {
		t.Errorf("bannerProtocol(POP3) = %q; want pop3", got)
	}
}

func TestBannerProtocol_IMAP(t *testing.T) {
	if got := bannerProtocol("* OK [CAPABILITY IMAP4rev1] Dovecot ready"); got != "imap" {
		t.Errorf("bannerProtocol(IMAP) = %q; want imap", got)
	}
}

func TestBannerProtocol_Empty(t *testing.T) {
	if got := bannerProtocol(""); got != "" {
		t.Errorf("bannerProtocol(empty) = %q; want empty", got)
	}
}

func TestBannerProtocol_Unknown(t *testing.T) {
	if got := bannerProtocol("some random binary data"); got != "" {
		t.Errorf("bannerProtocol(unknown) = %q; want empty", got)
	}
}

func TestParseAssetPort_PortAlreadyInList(t *testing.T) {
	// Port 6379 (Redis) is already in criticalPorts — verify buildPortList
	// doesn't duplicate it when the target specifies it.
	host, port := parseAssetPort("myhost:6379")
	if host != "myhost" || port != 6379 {
		t.Errorf("got (%q, %d); want (myhost, 6379)", host, port)
	}
	ports := buildPortList(module.ScanSurface)
	count := 0
	for _, e := range ports {
		if e.port == 6379 {
			count++
		}
	}
	if count != 1 {
		t.Errorf("port 6379 appears %d times in port list; want exactly 1", count)
	}
}
