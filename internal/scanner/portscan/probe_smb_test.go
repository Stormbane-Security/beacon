package portscan

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
)

// mockSMB2Server accepts one connection, handles SMB2 Negotiate + Session Setup,
// and returns an NTLMSSP_CHALLENGE with the provided domain/hostname/version info.
func mockSMB2Server(t *testing.T, domain, hostname, dnsDomain, dnsHostname string, osMajor, osMinor byte, osBuild uint16, signingRequired bool) (string, int, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	done := make(chan struct{})

	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

		// Read SMB2 Negotiate Request.
		buf := make([]byte, 512)
		n, err := conn.Read(buf)
		if err != nil || n < 68 {
			return
		}

		// Send SMB2 Negotiate Response.
		negResp := buildMockSMB2NegotiateResponse(signingRequired)
		_, _ = conn.Write(negResp)

		// Read SMB2 Session Setup Request.
		buf2 := make([]byte, 1024)
		n2, err := conn.Read(buf2)
		if err != nil || n2 < 68 {
			return
		}

		// Send SMB2 Session Setup Response with NTLMSSP_CHALLENGE.
		sessResp := buildMockSMB2SessionSetupResponse(domain, hostname, dnsDomain, dnsHostname, osMajor, osMinor, osBuild)
		_, _ = conn.Write(sessResp)
	}()

	cleanup := func() {
		_ = ln.Close()
		<-done
	}
	return addr.IP.String(), addr.Port, cleanup
}

// buildMockSMB2NegotiateResponse returns a minimal SMB2 Negotiate Response.
func buildMockSMB2NegotiateResponse(signingRequired bool) []byte {
	// We need: NetBIOS(4) + SMB2Header(64) + NegotiateResponse(65 min).
	// Total = 4 + 64 + 65 = 133, but we need security buffer space too.
	// Use a fixed-size response with an empty security buffer for simplicity.
	respBodyLen := 65 // minimum negotiate response body
	totalLen := 64 + respBodyLen
	pkt := make([]byte, 4+totalLen)

	// NetBIOS header.
	binary.BigEndian.PutUint32(pkt[0:4], uint32(totalLen))
	pkt[0] = 0x00

	off := 4

	// SMB2 header.
	pkt[off+0] = 0xfe
	pkt[off+1] = 0x53
	pkt[off+2] = 0x4d
	pkt[off+3] = 0x42
	binary.LittleEndian.PutUint16(pkt[off+4:off+6], 64) // StructureSize
	// Status: success (0).
	binary.LittleEndian.PutUint16(pkt[off+12:off+14], 1) // CreditResponse

	// Negotiate Response body.
	boff := off + 64
	binary.LittleEndian.PutUint16(pkt[boff:boff+2], 65) // StructureSize

	// Security mode at boff+2.
	secMode := uint16(0x01) // signing enabled
	if signingRequired {
		secMode = 0x03 // signing enabled + required
	}
	binary.LittleEndian.PutUint16(pkt[boff+2:boff+4], secMode)

	// Dialect revision at boff+4.
	binary.LittleEndian.PutUint16(pkt[boff+4:boff+6], 0x0311) // SMB 3.1.1

	// Server GUID at boff+8 (16 bytes) — fill with recognizable pattern.
	for i := 0; i < 16; i++ {
		pkt[boff+8+i] = byte(0x10 + i)
	}

	// Capabilities at boff+24 (4 bytes).
	binary.LittleEndian.PutUint32(pkt[boff+24:boff+28], 0x40) // SMB2_GLOBAL_CAP_ENCRYPTION

	// SecurityBufferOffset at boff+56 (points past body, no actual SPNEGO token).
	binary.LittleEndian.PutUint16(pkt[boff+56:boff+58], uint16(64+respBodyLen))
	binary.LittleEndian.PutUint16(pkt[boff+58:boff+60], 0) // SecurityBufferLength = 0

	return pkt
}

// buildMockSMB2SessionSetupResponse returns an SMB2 Session Setup Response
// with STATUS_MORE_PROCESSING_REQUIRED and an NTLMSSP_CHALLENGE containing
// the specified domain/hostname/version in AV_PAIRs.
func buildMockSMB2SessionSetupResponse(domain, hostname, dnsDomain, dnsHostname string, osMajor, osMinor byte, osBuild uint16) []byte {
	// Build NTLMSSP_CHALLENGE message.
	ntlmChallenge := buildNTLMSSPChallenge(domain, hostname, dnsDomain, dnsHostname, osMajor, osMinor, osBuild)

	// Wrap in minimal SPNEGO response (just raw NTLMSSP for simplicity —
	// our parser scans for NTLMSSP signature, so it handles both).
	secBlob := ntlmChallenge

	setupBodyFixed := 8 // Session Setup Response fixed body: StructureSize(2) + SessionFlags(2) + SecurityBufferOffset(2) + SecurityBufferLength(2)
	// Actually the fixed part is: StructureSize(2) + SessionFlags(2) + SecurityBufferOffset(2) + SecurityBufferLength(2) = 8
	// But MS-SMB2 says the fixed part is 8 bytes (StructureSize=9 with 1 byte variable).
	// Let's use the proper layout: StructureSize(2) + SessionFlags(2) + SecurityBufferOffset(2) + SecurityBufferLength(2)
	// SecurityBufferOffset is from start of SMB2 header = 64 + 8 = 72
	// Total = NetBIOS(4) + SMB2Header(64) + SessionSetupRespFixed(8) + secBlob

	totalSMB := 64 + setupBodyFixed + len(secBlob)
	pkt := make([]byte, 4+totalSMB)

	// NetBIOS.
	binary.BigEndian.PutUint32(pkt[0:4], uint32(totalSMB))
	pkt[0] = 0x00

	off := 4

	// SMB2 header.
	pkt[off+0] = 0xfe
	pkt[off+1] = 0x53
	pkt[off+2] = 0x4d
	pkt[off+3] = 0x42
	binary.LittleEndian.PutUint16(pkt[off+4:off+6], 64) // StructureSize
	// Status: STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016.
	binary.LittleEndian.PutUint32(pkt[off+8:off+12], 0xC0000016)
	binary.LittleEndian.PutUint16(pkt[off+12:off+14], 1) // CreditResponse
	pkt[off+16] = 0x01                                    // Command: SESSION_SETUP
	pkt[off+17] = 0x00

	// Session Setup Response body.
	boff := off + 64
	binary.LittleEndian.PutUint16(pkt[boff:boff+2], 9) // StructureSize (MS-SMB2: 9)
	// SessionFlags at boff+2: 0.
	// SecurityBufferOffset at boff+4.
	binary.LittleEndian.PutUint16(pkt[boff+4:boff+6], uint16(64+setupBodyFixed))
	binary.LittleEndian.PutUint16(pkt[boff+6:boff+8], uint16(len(secBlob)))

	// Copy security blob.
	copy(pkt[boff+setupBodyFixed:], secBlob)

	return pkt
}

// buildNTLMSSPChallenge creates an NTLMSSP_CHALLENGE message with the given info.
func buildNTLMSSPChallenge(domain, hostname, dnsDomain, dnsHostname string, osMajor, osMinor byte, osBuild uint16) []byte {
	// Build AV_PAIR list.
	avPairs := buildAVPairs(domain, hostname, dnsDomain, dnsHostname)

	// Target name in UTF-16LE.
	targetName := encodeUTF16LE(domain)

	// NTLMSSP_CHALLENGE layout:
	// Signature(8) + MessageType(4) + TargetNameFields(8) + NegotiateFlags(4) +
	// ServerChallenge(8) + Reserved(8) + TargetInfoFields(8) + Version(8) +
	// Payload (TargetName + TargetInfo)
	fixedLen := 8 + 4 + 8 + 4 + 8 + 8 + 8 + 8 // = 56
	payloadOffset := fixedLen
	targetNameOff := payloadOffset
	targetInfoOff := targetNameOff + len(targetName)

	totalLen := fixedLen + len(targetName) + len(avPairs)
	msg := make([]byte, totalLen)

	// Signature.
	copy(msg[0:8], []byte("NTLMSSP\x00"))
	// MessageType: 2 (CHALLENGE).
	binary.LittleEndian.PutUint32(msg[8:12], 2)

	// TargetName fields.
	binary.LittleEndian.PutUint16(msg[12:14], uint16(len(targetName)))
	binary.LittleEndian.PutUint16(msg[14:16], uint16(len(targetName)))
	binary.LittleEndian.PutUint32(msg[16:20], uint32(targetNameOff))

	// NegotiateFlags.
	flags := uint32(0x00028233) // UNICODE | OEM | REQUEST_TARGET | NTLM | TARGET_INFO | VERSION
	binary.LittleEndian.PutUint32(msg[20:24], flags)

	// ServerChallenge (8 bytes) — arbitrary.
	for i := 0; i < 8; i++ {
		msg[24+i] = byte(i + 1)
	}

	// Reserved (8 bytes) — zero.

	// TargetInfo fields at offset 40.
	binary.LittleEndian.PutUint16(msg[40:42], uint16(len(avPairs)))
	binary.LittleEndian.PutUint16(msg[42:44], uint16(len(avPairs)))
	binary.LittleEndian.PutUint32(msg[44:48], uint32(targetInfoOff))

	// Version at offset 48.
	msg[48] = osMajor
	msg[49] = osMinor
	binary.LittleEndian.PutUint16(msg[50:52], osBuild)
	msg[55] = 0x0f // NTLM revision 15

	// Payload.
	copy(msg[targetNameOff:], targetName)
	copy(msg[targetInfoOff:], avPairs)

	return msg
}

// buildAVPairs builds an NTLM AV_PAIR list.
func buildAVPairs(domain, hostname, dnsDomain, dnsHostname string) []byte {
	var pairs []byte
	addPair := func(id uint16, val string) {
		encoded := encodeUTF16LE(val)
		p := make([]byte, 4+len(encoded))
		binary.LittleEndian.PutUint16(p[0:2], id)
		binary.LittleEndian.PutUint16(p[2:4], uint16(len(encoded)))
		copy(p[4:], encoded)
		pairs = append(pairs, p...)
	}
	if domain != "" {
		addPair(0x0001, domain) // MsvAvNbDomainName
	}
	if hostname != "" {
		addPair(0x0002, hostname) // MsvAvNbComputerName
	}
	if dnsDomain != "" {
		addPair(0x0003, dnsDomain) // MsvAvDnsDomainName
	}
	if dnsHostname != "" {
		addPair(0x0004, dnsHostname) // MsvAvDnsComputerName
	}
	// MsvAvEOL
	pairs = append(pairs, 0x00, 0x00, 0x00, 0x00)
	return pairs
}

// encodeUTF16LE encodes a Go string to UTF-16 LE bytes.
func encodeUTF16LE(s string) []byte {
	runes := []rune(s)
	buf := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(buf[i*2:i*2+2], uint16(r))
	}
	return buf
}

func TestProbeSMBInfo_FullNegotiation(t *testing.T) {
	host, port, cleanup := mockSMB2Server(t,
		"CONTOSO", "DC01", "contoso.local", "dc01.contoso.local",
		10, 0, 17763, // Windows Server 2019
		true, // signing required
	)
	defer cleanup()

	info := ProbeSMBInfo(context.Background(), host, port)
	if info == nil {
		t.Fatal("ProbeSMBInfo returned nil for mock SMB2 server")
	}

	if info.SMBVersion != "SMB 3.1.1" {
		t.Errorf("SMBVersion = %q; want %q", info.SMBVersion, "SMB 3.1.1")
	}
	if !info.SigningReq {
		t.Error("SigningReq = false; want true")
	}
	if !info.Encryption {
		t.Error("Encryption = false; want true")
	}
	if info.Domain != "CONTOSO" {
		t.Errorf("Domain = %q; want %q", info.Domain, "CONTOSO")
	}
	if info.Hostname != "DC01" {
		t.Errorf("Hostname = %q; want %q", info.Hostname, "DC01")
	}
	if info.DNSDomain != "contoso.local" {
		t.Errorf("DNSDomain = %q; want %q", info.DNSDomain, "contoso.local")
	}
	if info.DNSHostname != "dc01.contoso.local" {
		t.Errorf("DNSHostname = %q; want %q", info.DNSHostname, "dc01.contoso.local")
	}
	if info.OS == "" {
		t.Error("OS is empty; want Windows version string")
	}
	if info.ServerGUID == "" {
		t.Error("ServerGUID is empty; want non-empty GUID")
	}
}

func TestProbeSMBInfo_SigningNotRequired(t *testing.T) {
	host, port, cleanup := mockSMB2Server(t,
		"WORKGROUP", "FILESVR", "workgroup", "filesvr.workgroup",
		6, 1, 7601, // Windows 7
		false, // signing not required
	)
	defer cleanup()

	info := ProbeSMBInfo(context.Background(), host, port)
	if info == nil {
		t.Fatal("ProbeSMBInfo returned nil")
	}
	if info.SigningReq {
		t.Error("SigningReq = true; want false")
	}
	if info.Domain != "WORKGROUP" {
		t.Errorf("Domain = %q; want %q", info.Domain, "WORKGROUP")
	}
	if info.Hostname != "FILESVR" {
		t.Errorf("Hostname = %q; want %q", info.Hostname, "FILESVR")
	}
}

func TestDetectSMBInfo_EmitsFindings(t *testing.T) {
	host, port, cleanup := mockSMB2Server(t,
		"TESTDOM", "SRV01", "testdom.corp", "srv01.testdom.corp",
		10, 0, 20348, // Server 2022
		false, // signing not required
	)
	defer cleanup()

	makeF := func(checkID finding.CheckID, severity finding.Severity, title, description string, evidence map[string]any) finding.Finding {
		return finding.Finding{
			CheckID:     checkID,
			Severity:    severity,
			Title:       title,
			Description: description,
			Evidence:    evidence,
		}
	}

	findings := detectSMBInfo(context.Background(), host, port, "", makeF)

	var hasOSDiscovery, hasSigningNotReq bool
	for _, f := range findings {
		switch f.CheckID {
		case finding.CheckPortSMBOSDiscovery:
			hasOSDiscovery = true
			if f.Evidence["domain"] != "TESTDOM" {
				t.Errorf("OS discovery domain = %v; want TESTDOM", f.Evidence["domain"])
			}
			if f.Evidence["hostname"] != "SRV01" {
				t.Errorf("OS discovery hostname = %v; want SRV01", f.Evidence["hostname"])
			}
			if f.Evidence["smb_version"] != "SMB 3.1.1" {
				t.Errorf("OS discovery smb_version = %v; want SMB 3.1.1", f.Evidence["smb_version"])
			}
		case finding.CheckPortSMBSigningNotReq:
			hasSigningNotReq = true
		}
	}
	if !hasOSDiscovery {
		t.Error("detectSMBInfo did not emit port.smb_os_discovery finding")
	}
	if !hasSigningNotReq {
		t.Error("detectSMBInfo did not emit port.smb_signing_not_required finding")
	}
}

func TestDetectSMBInfo_SigningRequired_NoSigningFinding(t *testing.T) {
	host, port, cleanup := mockSMB2Server(t,
		"SECURE", "DC02", "secure.corp", "dc02.secure.corp",
		10, 0, 20348,
		true, // signing required
	)
	defer cleanup()

	makeF := func(checkID finding.CheckID, severity finding.Severity, title, description string, evidence map[string]any) finding.Finding {
		return finding.Finding{
			CheckID:     checkID,
			Severity:    severity,
			Title:       title,
			Description: description,
			Evidence:    evidence,
		}
	}

	findings := detectSMBInfo(context.Background(), host, port, "", makeF)

	for _, f := range findings {
		if f.CheckID == finding.CheckPortSMBSigningNotReq {
			t.Error("detectSMBInfo emitted signing_not_required finding when signing IS required")
		}
	}
}

func TestProbeSMBInfo_ClosedPort(t *testing.T) {
	// Get a port that's not listening.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	info := ProbeSMBInfo(context.Background(), "127.0.0.1", port)
	if info != nil {
		t.Error("ProbeSMBInfo should return nil for a closed port")
	}
}

func TestProbeSMBInfo_NonSMBServer(t *testing.T) {
	// Start a TCP server that sends non-SMB data.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	port := ln.Addr().(*net.TCPAddr).Port

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		// Read request and send HTTP response.
		buf := make([]byte, 512)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	}()

	info := ProbeSMBInfo(context.Background(), "127.0.0.1", port)
	if info != nil {
		t.Error("ProbeSMBInfo should return nil for a non-SMB server")
	}
}

func TestWindowsVersionString(t *testing.T) {
	tests := []struct {
		major, minor byte
		build        uint16
		want         string
	}{
		{10, 0, 22631, "Windows 11 (build 22631)"},
		{10, 0, 20348, "Windows Server 2022 (build 20348)"},
		{10, 0, 17763, "Windows Server 2019 / Windows 10 (build 17763)"},
		{10, 0, 14393, "Windows 10 / Server 2016 (build 14393)"},
		{6, 3, 9600, "Windows 8.1 / Server 2012 R2 (build 9600)"},
		{6, 2, 9200, "Windows 8 / Server 2012 (build 9200)"},
		{6, 1, 7601, "Windows 7 / Server 2008 R2 (build 7601)"},
		{6, 0, 6002, "Windows Vista / Server 2008 (build 6002)"},
		{5, 1, 2600, "Windows XP (build 2600)"},
		{5, 2, 3790, "Windows Server 2003 (build 3790)"},
	}
	for _, tt := range tests {
		got := windowsVersionString(tt.major, tt.minor, tt.build)
		if got != tt.want {
			t.Errorf("windowsVersionString(%d, %d, %d) = %q; want %q", tt.major, tt.minor, tt.build, got, tt.want)
		}
	}
}

func TestSMBDialectString(t *testing.T) {
	tests := []struct {
		dialect uint16
		want    string
	}{
		{0x0202, "SMB 2.0.2"},
		{0x0210, "SMB 2.1"},
		{0x0300, "SMB 3.0"},
		{0x0302, "SMB 3.0.2"},
		{0x0311, "SMB 3.1.1"},
		{0x0999, "SMB 0x0999"},
	}
	for _, tt := range tests {
		got := smbDialectString(tt.dialect)
		if got != tt.want {
			t.Errorf("smbDialectString(0x%04x) = %q; want %q", tt.dialect, got, tt.want)
		}
	}
}

func TestDecodeUTF16LE(t *testing.T) {
	input := []byte{0x48, 0x00, 0x65, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x6f, 0x00}
	got := decodeUTF16LE(input)
	if got != "Hello" {
		t.Errorf("decodeUTF16LE = %q; want %q", got, "Hello")
	}
}

func TestParseAVPairs(t *testing.T) {
	info := &SMBInfo{}
	pairs := buildAVPairs("TESTDOM", "HOST01", "testdom.local", "host01.testdom.local")
	parseAVPairs(pairs, info)

	if info.Domain != "TESTDOM" {
		t.Errorf("Domain = %q; want TESTDOM", info.Domain)
	}
	if info.Hostname != "HOST01" {
		t.Errorf("Hostname = %q; want HOST01", info.Hostname)
	}
	if info.DNSDomain != "testdom.local" {
		t.Errorf("DNSDomain = %q; want testdom.local", info.DNSDomain)
	}
	if info.DNSHostname != "host01.testdom.local" {
		t.Errorf("DNSHostname = %q; want host01.testdom.local", info.DNSHostname)
	}
}
