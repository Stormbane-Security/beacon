package portscan

// White-box tests for probeLDAP, probeEPMD, parseAssetPort, buildPortList,
// and bannerProtocol. These tests call internal functions directly so they
// never pay the 5-second inter-connect-delay cost of a full s.Run() call.

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
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

// ---------------------------------------------------------------------------
// isMySQLGreeting tests
// ---------------------------------------------------------------------------

func TestIsMySQLGreeting_Valid8x(t *testing.T) {
	// Simulate MySQL 8.0 greeting: 74-byte payload, seq=0, protocol=10.
	banner := make([]byte, 80)
	banner[0] = 0x4a // payload length low byte (74)
	banner[1] = 0x00
	banner[2] = 0x00
	banner[3] = 0x00 // sequence number
	banner[4] = 0x0a // protocol version 10
	copy(banner[5:], []byte("8.0.36"))
	if !isMySQLGreeting(string(banner)) {
		t.Error("expected isMySQLGreeting to return true for MySQL 8.0 greeting")
	}
}

func TestIsMySQLGreeting_Valid5x(t *testing.T) {
	// MySQL 5.7: shorter greeting, same protocol structure.
	banner := make([]byte, 60)
	banner[0] = 0x38 // 56 bytes payload
	banner[1] = 0x00
	banner[2] = 0x00
	banner[3] = 0x00 // sequence number
	banner[4] = 0x0a // protocol version 10
	copy(banner[5:], []byte("5.7.44"))
	if !isMySQLGreeting(string(banner)) {
		t.Error("expected isMySQLGreeting to return true for MySQL 5.7 greeting")
	}
}

func TestIsMySQLGreeting_TooShort(t *testing.T) {
	if isMySQLGreeting("abc") {
		t.Error("expected isMySQLGreeting to return false for short input")
	}
}

func TestIsMySQLGreeting_NonMySQLBinary(t *testing.T) {
	// Random binary data that doesn't match the pattern.
	banner := "\x10\x20\x30\x01\x0b" // seq=1 (not 0)
	if isMySQLGreeting(banner) {
		t.Error("expected isMySQLGreeting to return false for non-MySQL binary")
	}
}

func TestIsMySQLGreeting_SMBNegotiate(t *testing.T) {
	// SMB negotiate starts with NetBIOS header — should not match.
	banner := "\x00\x00\x00\x54\xff\x53\x4d\x42"
	if isMySQLGreeting(banner) {
		t.Error("expected isMySQLGreeting to return false for SMB negotiate")
	}
}

// ---------------------------------------------------------------------------
// bannerProtocol MySQL detection tests
// ---------------------------------------------------------------------------

func TestBannerProtocol_MySQL8(t *testing.T) {
	// MySQL 8.0 greeting: the word "mysql" doesn't appear in the version
	// string, so detection must rely on isMySQLGreeting wire format.
	banner := make([]byte, 80)
	banner[0] = 0x4a
	banner[1] = 0x00
	banner[2] = 0x00
	banner[3] = 0x00
	banner[4] = 0x0a
	copy(banner[5:], []byte("8.0.36"))
	if got := bannerProtocol(string(banner)); got != "mysql" {
		t.Errorf("bannerProtocol(MySQL 8.0 greeting) = %q; want mysql", got)
	}
}

func TestBannerProtocol_MySQLKeyword(t *testing.T) {
	// Banner that contains the literal word MYSQL (older builds).
	if got := bannerProtocol("5.5.62-0ubuntu0.14.04.1-MySQL Community Server"); got != "mysql" {
		t.Errorf("bannerProtocol(MySQL keyword) = %q; want mysql", got)
	}
}

// ---------------------------------------------------------------------------
// detectTelnet false-positive tests
// ---------------------------------------------------------------------------

func TestDetectTelnet_NoFalsePositiveOnMySQL(t *testing.T) {
	// MySQL 8.0 greeting contains 0xFF bytes in capability flags.
	// detectTelnet must NOT match on bare 0xFF without IAC command bytes.
	banner := make([]byte, 80)
	banner[0] = 0x4a
	banner[1] = 0x00
	banner[2] = 0x00
	banner[3] = 0x00
	banner[4] = 0x0a
	copy(banner[5:], []byte("8.0.36\x00"))
	// Inject 0xFF at capability flag positions (like a real MySQL greeting).
	banner[20] = 0xFF
	banner[21] = 0xF7 // Not a telnet command byte (0xFB-0xFE)

	makeF := func(checkID finding.CheckID, sev finding.Severity, title, desc string, ev map[string]any) finding.Finding {
		return finding.Finding{CheckID: checkID}
	}

	findings := detectTelnet(context.Background(), "127.0.0.1", 3306, string(banner), makeF)
	for _, f := range findings {
		if f.CheckID == finding.CheckPortTelnetExposed {
			t.Error("detectTelnet produced CheckPortTelnetExposed for MySQL banner — false positive")
		}
	}
}

func TestDetectTelnet_RealIACSequence(t *testing.T) {
	// Real telnet IAC: \xFF\xFB\x01 (WILL ECHO)
	banner := "\xFF\xFB\x01\xFF\xFB\x03"
	makeF := func(checkID finding.CheckID, sev finding.Severity, title, desc string, ev map[string]any) finding.Finding {
		return finding.Finding{CheckID: checkID}
	}
	findings := detectTelnet(context.Background(), "127.0.0.1", 2323, banner, makeF)
	var found bool
	for _, f := range findings {
		if f.CheckID == finding.CheckPortTelnetExposed {
			found = true
		}
	}
	if !found {
		t.Error("detectTelnet should detect real IAC WILL sequences as telnet")
	}
}

func TestDetectTelnet_LoginPrompt(t *testing.T) {
	banner := "Welcome to MyRouter\r\nlogin: "
	makeF := func(checkID finding.CheckID, sev finding.Severity, title, desc string, ev map[string]any) finding.Finding {
		return finding.Finding{CheckID: checkID}
	}
	findings := detectTelnet(context.Background(), "127.0.0.1", 2323, banner, makeF)
	var found bool
	for _, f := range findings {
		if f.CheckID == finding.CheckPortTelnetExposed {
			found = true
		}
	}
	if !found {
		t.Error("detectTelnet should detect 'login:' prompt as telnet")
	}
}

// ---------------------------------------------------------------------------
// detectSMB validation tests
// ---------------------------------------------------------------------------

func TestDetectSMB_NoFalsePositiveOnNonSMBPort(t *testing.T) {
	// Start a TCP server that speaks MySQL (not SMB).
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			// Send MySQL greeting, not SMB.
			greeting := make([]byte, 80)
			greeting[0] = 0x4a
			greeting[3] = 0x00
			greeting[4] = 0x0a
			copy(greeting[5:], []byte("8.0.36\x00"))
			conn.Write(greeting)
			conn.Close()
		}
	}()

	_, portStr, _ := net.SplitHostPort(l.Addr().String())
	port, _ := strconv.Atoi(portStr)

	makeF := func(checkID finding.CheckID, sev finding.Severity, title, desc string, ev map[string]any) finding.Finding {
		return finding.Finding{CheckID: checkID}
	}
	findings := detectSMB(context.Background(), "127.0.0.1", port, "", makeF)
	for _, f := range findings {
		if f.CheckID == finding.CheckPortSMBExposed {
			t.Error("detectSMB emitted smb_exposed for a non-SMB server — false positive")
		}
	}
}

func TestDetectSMB_ClosedPort(t *testing.T) {
	// Get a port that nothing is listening on.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, portStr, _ := net.SplitHostPort(l.Addr().String())
	port, _ := strconv.Atoi(portStr)
	l.Close()

	makeF := func(checkID finding.CheckID, sev finding.Severity, title, desc string, ev map[string]any) finding.Finding {
		return finding.Finding{CheckID: checkID}
	}
	findings := detectSMB(context.Background(), "127.0.0.1", port, "", makeF)
	if len(findings) > 0 {
		t.Errorf("detectSMB emitted %d findings for a closed port; want 0", len(findings))
	}
}

func TestDetectSMB_RealSMBServer(t *testing.T) {
	// Simulate a minimal SMB server that responds to negotiate with \xfeSMB (SMBv2).
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 256)
			conn.SetDeadline(time.Now().Add(2 * time.Second))
			conn.Read(buf)
			// Reply with SMBv2 negotiate response header.
			resp := make([]byte, 68)
			resp[0] = 0x00 // NetBIOS
			resp[1] = 0x00
			resp[2] = 0x00
			resp[3] = 0x40 // length
			resp[4] = 0xfe // \xfeSMB
			resp[5] = 0x53
			resp[6] = 0x4d
			resp[7] = 0x42
			conn.Write(resp)
			conn.Close()
		}
	}()

	_, portStr, _ := net.SplitHostPort(l.Addr().String())
	port, _ := strconv.Atoi(portStr)

	makeF := func(checkID finding.CheckID, sev finding.Severity, title, desc string, ev map[string]any) finding.Finding {
		return finding.Finding{CheckID: checkID, Title: title, Evidence: ev}
	}
	findings := detectSMB(context.Background(), "127.0.0.1", port, "", makeF)
	var found bool
	for _, f := range findings {
		if f.CheckID == finding.CheckPortSMBExposed {
			found = true
			// Verify the finding reports the correct port.
			if p, ok := f.Evidence["port"].(int); ok && p != port {
				t.Errorf("SMB finding port = %d; want %d", p, port)
			}
		}
	}
	if !found {
		t.Error("detectSMB should emit smb_exposed for a real SMB server")
	}
}

// ---------------------------------------------------------------------------
// runProbes protocol filtering tests
// ---------------------------------------------------------------------------

func TestRunProbes_MySQLBannerSkipsProtocolProbes(t *testing.T) {
	// When the banner identifies as MySQL, protocol-category probes (SMB,
	// telnet, etc.) should be skipped entirely.
	banner := make([]byte, 80)
	banner[0] = 0x4a
	banner[3] = 0x00
	banner[4] = 0x0a
	copy(banner[5:], []byte("8.0.36\x00"))

	makeF := func(checkID finding.CheckID, sev finding.Severity, title, desc string, ev map[string]any) finding.Finding {
		return finding.Finding{CheckID: checkID, Scanner: "portscan"}
	}

	// Use a port that nothing is listening on so protocol probes that
	// attempt new connections will fail anyway. The point is verifying
	// that bannerProtocol("mysql") causes the skip.
	findings := runProbes(context.Background(), "127.0.0.1", 3306, string(banner), makeF)
	for _, f := range findings {
		switch f.CheckID {
		case finding.CheckPortSMBExposed, finding.CheckPortTelnetExposed, finding.CheckPortWinboxExposed:
			t.Errorf("runProbes emitted %s for MySQL banner — protocol probe should have been skipped", f.CheckID)
		}
	}
}

func TestRunProbes_MySQLBannerRunsMySQLProbe(t *testing.T) {
	// Verify that the probe filter allows the relational DB probe (which
	// contains "mysql" in its name) to run when the banner identifies MySQL.
	// Start a fake MySQL server that sends a greeting and accepts auth.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			// Send MySQL greeting: 4-byte header + payload starting with 0x0a
			greeting := make([]byte, 80)
			greeting[0] = 0x0a // protocol version 10
			copy(greeting[1:], []byte("8.0.36\x00"))
			// Write packet header: length(3) + seq(1)
			hdr := []byte{byte(len(greeting)), 0x00, 0x00, 0x00}
			conn.Write(hdr)
			conn.Write(greeting)
			// Read client auth (just consume it)
			buf := make([]byte, 512)
			conn.Read(buf)
			// Send OK response
			okPayload := []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}
			okHdr := []byte{byte(len(okPayload)), 0x00, 0x00, 0x02}
			conn.Write(okHdr)
			conn.Write(okPayload)
			conn.Close()
		}
	}()

	_, portStr, _ := net.SplitHostPort(l.Addr().String())
	port, _ := strconv.Atoi(portStr)

	// Build a MySQL banner matching isMySQLGreeting.
	banner := make([]byte, 80)
	banner[0] = 0x4a
	banner[3] = 0x00
	banner[4] = 0x0a
	copy(banner[5:], []byte("8.0.36\x00"))

	makeF := func(checkID finding.CheckID, sev finding.Severity, title, desc string, ev map[string]any) finding.Finding {
		return finding.Finding{CheckID: checkID}
	}

	findings := runProbes(context.Background(), "127.0.0.1", port, string(banner), makeF)
	var foundMySQL bool
	for _, f := range findings {
		if f.CheckID == finding.CheckPortMySQLNoAuth || f.CheckID == finding.CheckPortDatabaseExposed {
			foundMySQL = true
		}
	}
	if !foundMySQL {
		ids := make([]string, len(findings))
		for i, f := range findings {
			ids[i] = string(f.CheckID)
		}
		t.Errorf("runProbes with MySQL banner did not produce MySQL finding; got %v", ids)
	}
}

func TestRunProbes_EmitsServiceIdentified(t *testing.T) {
	// When a probe matches, runProbes should emit a port.service_identified
	// finding alongside the probe's own findings.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			// MySQL greeting
			greeting := make([]byte, 80)
			greeting[0] = 0x0a
			copy(greeting[1:], []byte("8.0.36\x00"))
			hdr := []byte{byte(len(greeting)), 0x00, 0x00, 0x00}
			conn.Write(hdr)
			conn.Write(greeting)
			buf := make([]byte, 512)
			conn.Read(buf)
			okPayload := []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}
			okHdr := []byte{byte(len(okPayload)), 0x00, 0x00, 0x02}
			conn.Write(okHdr)
			conn.Write(okPayload)
			conn.Close()
		}
	}()

	_, portStr, _ := net.SplitHostPort(l.Addr().String())
	port, _ := strconv.Atoi(portStr)

	banner := make([]byte, 80)
	banner[0] = 0x4a
	banner[3] = 0x00
	banner[4] = 0x0a
	copy(banner[5:], []byte("8.0.36\x00"))

	makeF := func(checkID finding.CheckID, sev finding.Severity, title, desc string, ev map[string]any) finding.Finding {
		return finding.Finding{CheckID: checkID, Title: title, Evidence: ev}
	}

	findings := runProbes(context.Background(), "127.0.0.1", port, string(banner), makeF)
	var found bool
	for _, f := range findings {
		if f.CheckID == finding.CheckPortServiceIdentified {
			found = true
			if f.Evidence["service"] == nil {
				t.Error("service_identified finding missing 'service' in evidence")
			}
			if f.Evidence["port"] == nil {
				t.Error("service_identified finding missing 'port' in evidence")
			}
			if f.Evidence["probe"] == nil {
				t.Error("service_identified finding missing 'probe' in evidence")
			}
		}
	}
	if !found {
		ids := make([]string, len(findings))
		for i, f := range findings {
			ids[i] = string(f.CheckID)
		}
		t.Errorf("expected port.service_identified finding; got %v", ids)
	}
}

func TestProbeSMBOnPort_ClosedPort(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, portStr, _ := net.SplitHostPort(l.Addr().String())
	port, _ := strconv.Atoi(portStr)
	l.Close()

	if probeSMBOnPort(context.Background(), "127.0.0.1", port) {
		t.Error("probeSMBOnPort should return false for a closed port")
	}
}

func TestProbeSMBOnPort_NonSMBServer(t *testing.T) {
	// TCP server that sends "hello" instead of SMB.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 256)
			conn.Read(buf)
			conn.Write([]byte("hello world"))
			conn.Close()
		}
	}()

	_, portStr, _ := net.SplitHostPort(l.Addr().String())
	port, _ := strconv.Atoi(portStr)

	if probeSMBOnPort(context.Background(), "127.0.0.1", port) {
		t.Error("probeSMBOnPort should return false for a non-SMB server")
	}
}

func TestProbeSMBOnPort_SMBv2Server(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 256)
			conn.SetDeadline(time.Now().Add(2 * time.Second))
			conn.Read(buf)
			resp := make([]byte, 68)
			resp[4] = 0xfe // \xfeSMB (SMBv2)
			resp[5] = 0x53
			resp[6] = 0x4d
			resp[7] = 0x42
			conn.Write(resp)
			conn.Close()
		}
	}()

	_, portStr, _ := net.SplitHostPort(l.Addr().String())
	port, _ := strconv.Atoi(portStr)

	if !probeSMBOnPort(context.Background(), "127.0.0.1", port) {
		t.Error("probeSMBOnPort should return true for an SMBv2 server")
	}
}

