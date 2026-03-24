package portscan

// White-box tests for probeLDAP, probeEPMD, and SMTP buildFindings logic.
// These tests call internal functions directly so they never pay the 5-second
// inter-connect-delay cost of a full s.Run() call against localhost.

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stormbane/beacon/internal/finding"
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
	return p, func() { l.Close() }
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
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 256)
		c.Read(buf) // drain null bind request
		c.Write(bindSuccessResp)
		c.Read(buf) // drain rootDSE request
		c.Write(searchDoneResp)
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
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 256)
		c.Read(buf) // drain null bind
		c.Write(bindSuccessResp)
		c.Read(buf) // drain rootDSE request

		// Inject "DC=corp,DC=example,DC=com" in the rootDSE response body.
		adText := []byte("DC=corp,DC=example,DC=com")
		body := append(bindSuccessResp, adText...) // reuse bytes as payload carrier
		c.Write(body)
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
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 256)
		c.Read(buf) // drain null bind
		// BindResponse: resultCode 49 (invalidCredentials)
		c.Write([]byte{
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
	l.Close()

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
	return p, func() { l.Close() }
}

// TestProbeEPMD_NodesListed verifies that a proper EPMD NAMES response returns
// the node names and nothing is missed.
func TestProbeEPMD_NodesListed(t *testing.T) {
	port, cleanup := serveEPMD(t, func(c net.Conn) {
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 16)
		c.Read(buf) // drain NAMES request
		response := "name rabbit at port 25672\nname myapp at port 12345\n"
		resp := append([]byte{0x00, 0x00, 0x11, 0x11}, []byte(response)...)
		c.Write(resp)
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
// SMTP buildFindings logic tests (white-box, via buildFindings directly)
// ---------------------------------------------------------------------------

// TestBuildFindings_SMTPExImBanner verifies that an Exim SMTP banner on port 25
// produces CheckPortExImVulnerable (Critical), not the generic SMTP check.
func TestBuildFindings_SMTPExImBanner(t *testing.T) {
	entry := portEntry{port: 25, service: "smtp"}
	banner := "220 mail.example.com ESMTP Exim 4.96 Mon, 01 Jan 2025 00:00:00 +0000"

	findings := buildFindings(context.Background(), "1.2.3.4", entry, banner)
	if len(findings) == 0 {
		t.Fatal("buildFindings returned no findings for Exim SMTP banner")
	}
	got := findings[0].CheckID
	if got != finding.CheckPortExImVulnerable {
		t.Errorf("CheckID = %q; want CheckPortExImVulnerable", got)
	}
	if findings[0].Severity != finding.SeverityCritical {
		t.Errorf("severity = %v; want Critical", findings[0].Severity)
	}
	// Must NOT emit the generic SMTP check alongside.
	for _, f := range findings {
		if f.CheckID == finding.CheckPortSMTPExposed {
			t.Error("must not emit CheckPortSMTPExposed alongside Exim-specific check")
		}
	}
}

// TestBuildFindings_SMTPGenericBanner verifies that a non-Exim banner triggers
// CheckPortSMTPExposed (Medium), not the Exim check.
func TestBuildFindings_SMTPGenericBanner(t *testing.T) {
	entry := portEntry{port: 25, service: "smtp"}
	banner := "220 mail.example.com ESMTP Postfix (Ubuntu)"

	findings := buildFindings(context.Background(), "1.2.3.4", entry, banner)
	if len(findings) == 0 {
		t.Fatal("buildFindings returned no findings for Postfix SMTP banner")
	}
	got := findings[0].CheckID
	if got != finding.CheckPortSMTPExposed {
		t.Errorf("CheckID = %q; want CheckPortSMTPExposed", got)
	}
	if findings[0].Severity != finding.SeverityMedium {
		t.Errorf("severity = %v; want Medium", findings[0].Severity)
	}
	for _, f := range findings {
		if f.CheckID == finding.CheckPortExImVulnerable {
			t.Error("must not emit CheckPortExImVulnerable for Postfix banner")
		}
	}
}

// TestBuildFindings_SMTPNoBanner verifies that an empty banner on port 25
// produces no SMTP findings (the scanner requires a banner to avoid false positives
// on port-forwards that don't speak SMTP).
func TestBuildFindings_SMTPNoBanner(t *testing.T) {
	entry := portEntry{port: 25, service: "smtp"}
	findings := buildFindings(context.Background(), "1.2.3.4", entry, "")
	for _, f := range findings {
		if f.CheckID == finding.CheckPortSMTPExposed || f.CheckID == finding.CheckPortExImVulnerable {
			t.Errorf("got SMTP finding %q for empty banner — should not fire without banner", f.CheckID)
		}
	}
}

// TestBuildFindings_ExImCaseInsensitive verifies the Exim detection is
// case-insensitive (banner says "EXIM" uppercase).
func TestBuildFindings_ExImCaseInsensitive(t *testing.T) {
	entry := portEntry{port: 587, service: "smtp-submission"}
	banner := "220 smtp.example.com ESMTP EXIM 4.98"

	findings := buildFindings(context.Background(), "1.2.3.4", entry, banner)
	if len(findings) == 0 {
		t.Fatal("buildFindings returned no findings for uppercase EXIM banner")
	}
	if findings[0].CheckID != finding.CheckPortExImVulnerable {
		t.Errorf("CheckID = %q; want CheckPortExImVulnerable for uppercase 'EXIM'", findings[0].CheckID)
	}
}
