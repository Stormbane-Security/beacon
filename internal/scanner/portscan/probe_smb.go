package portscan

// Native SMB OS discovery probe — replaces nmap's smb-os-discovery NSE script.
// Performs SMB2 Negotiate + NTLMSSP Session Setup to extract OS, domain,
// hostname, and SMB version from the NTLMSSP_CHALLENGE response.

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/stormbane-security/beacon/internal/finding"
)

// SMBInfo holds OS and version information extracted from SMB negotiation.
type SMBInfo struct {
	OS           string // e.g. "Windows Server 2019 Standard 17763"
	Domain       string // NetBIOS domain name, e.g. "CONTOSO"
	Hostname     string // NetBIOS computer name, e.g. "DC01"
	DNSDomain    string // DNS domain name, e.g. "contoso.local"
	DNSHostname  string // DNS computer name, e.g. "dc01.contoso.local"
	SMBVersion   string // e.g. "SMB 3.1.1"
	SigningReq   bool   // signing required by server
	Encryption   bool   // encryption supported
	NativeOS     string // raw OS string from SMB1 session setup
	NativeLanman string // raw LAN Manager string from SMB1
	ServerGUID   string // hex-encoded server GUID from SMB2 negotiate
}

func init() {
	registerProbe(ServiceProbe{
		Name:         "smb-info",
		Category:     ProbeCatProtocol,
		DefaultPorts: []int{445, 139},
		Detect:       detectSMBInfo,
	})
}

// ProbeSMBInfo performs an SMB2 negotiate + NTLMSSP session setup and returns
// OS/version/domain info. Returns nil if the target is not an SMB server.
func ProbeSMBInfo(ctx context.Context, host string, port int) *SMBInfo {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	info := &SMBInfo{}

	// ── Step 1: SMB2 Negotiate ──────────────────────────────────────────
	negReq := smb2NegotiateRequest()
	if _, err := conn.Write(negReq); err != nil {
		return nil
	}

	negResp := make([]byte, 1024)
	n, err := conn.Read(negResp)
	if err != nil || n < 72 {
		return nil
	}

	// Validate NetBIOS + SMB2 header.
	// NetBIOS header is 4 bytes, then SMB2 magic \xfeSMB at offset 4.
	if n < 68 || negResp[4] != 0xfe || negResp[5] != 0x53 || negResp[6] != 0x4d || negResp[7] != 0x42 {
		// Not SMB2 — try reading as SMBv1 response to the multi-dialect packet.
		// If the server chose SMBv1 (\xffSMB), we note that but can't do SMB2 session setup.
		if n >= 8 && negResp[4] == 0xff && negResp[5] == 0x53 && negResp[6] == 0x4d && negResp[7] == 0x42 {
			info.SMBVersion = "SMB 1.0"
			return info
		}
		return nil
	}

	// Parse SMB2 Negotiate Response.
	// SMB2 header is 64 bytes starting at offset 4 (after NetBIOS 4-byte header).
	// Negotiate Response structure starts at offset 4+64 = 68.
	hdrOff := 4 // NetBIOS header length
	respOff := hdrOff + 64

	if n < respOff+65 {
		return nil
	}

	// Dialect revision at offset 4 in negotiate response body.
	dialect := binary.LittleEndian.Uint16(negResp[respOff+4 : respOff+6])
	info.SMBVersion = smbDialectString(dialect)

	// Security mode at offset 2 in negotiate response body.
	secMode := binary.LittleEndian.Uint16(negResp[respOff+2 : respOff+4])
	info.SigningReq = secMode&0x02 != 0 // NEGOTIATE_SIGNING_REQUIRED

	// Server GUID at offset 8 (16 bytes).
	if n >= respOff+24 {
		guid := negResp[respOff+8 : respOff+24]
		info.ServerGUID = fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
			binary.LittleEndian.Uint32(guid[0:4]),
			binary.LittleEndian.Uint16(guid[4:6]),
			binary.LittleEndian.Uint16(guid[6:8]),
			binary.BigEndian.Uint16(guid[8:10]),
			guid[10:16])
	}

	// Capabilities at offset 24 (4 bytes).
	if n >= respOff+28 {
		caps := binary.LittleEndian.Uint32(negResp[respOff+24 : respOff+28])
		info.Encryption = caps&0x40 != 0 // SMB2_GLOBAL_CAP_ENCRYPTION
	}

	// The Negotiate Response may contain a security buffer (SPNEGO token with
	// the server's preferred mechanism list). We don't need to parse it — we
	// proceed directly to Session Setup with NTLMSSP_NEGOTIATE to get the
	// NTLMSSP_CHALLENGE with domain/hostname/OS info.

	// ── Step 2: SMB2 Session Setup with NTLMSSP_NEGOTIATE ───────────────
	sessReq := smb2SessionSetupNTLMSSPNegotiate()
	if _, err := conn.Write(sessReq); err != nil {
		return info
	}

	sessResp := make([]byte, 2048)
	sn, err := conn.Read(sessResp)
	if err != nil || sn < 72 {
		return info
	}

	// Validate SMB2 header in response.
	if sessResp[4] != 0xfe || sessResp[5] != 0x53 || sessResp[6] != 0x4d || sessResp[7] != 0x42 {
		return info
	}

	// Status should be STATUS_MORE_PROCESSING_REQUIRED (0xC0000016).
	status := binary.LittleEndian.Uint32(sessResp[hdrOff+8 : hdrOff+12])
	if status != 0xC0000016 {
		return info
	}

	// Session Setup Response: security buffer offset and length.
	sessRespOff := hdrOff + 64
	if sn < sessRespOff+8 {
		return info
	}
	sesSecBufOffset := binary.LittleEndian.Uint16(sessResp[sessRespOff+4 : sessRespOff+6])
	sesSecBufLen := binary.LittleEndian.Uint16(sessResp[sessRespOff+6 : sessRespOff+8])

	sesSecBufStart := int(sesSecBufOffset) + hdrOff
	sesSecBufEnd := sesSecBufStart + int(sesSecBufLen)
	if sesSecBufEnd > sn || sesSecBufStart >= sesSecBufEnd {
		return info
	}

	secBlob := sessResp[sesSecBufStart:sesSecBufEnd]

	// Parse the NTLMSSP_CHALLENGE from the security blob.
	parseNTLMSSPChallenge(secBlob, info)

	return info
}

// parseNTLMSSPChallenge extracts domain, hostname, and OS version from an
// NTLMSSP_CHALLENGE message. The message may be wrapped in SPNEGO/ASN.1.
func parseNTLMSSPChallenge(blob []byte, info *SMBInfo) {
	// Find the NTLMSSP signature in the blob (it may be wrapped in SPNEGO).
	ntlmSig := []byte("NTLMSSP\x00")
	idx := -1
	for i := 0; i <= len(blob)-8; i++ {
		if blob[i] == 'N' && blob[i+1] == 'T' && blob[i+2] == 'L' &&
			blob[i+3] == 'M' && blob[i+4] == 'S' && blob[i+5] == 'S' &&
			blob[i+6] == 'P' && blob[i+7] == 0 {
			idx = i
			break
		}
	}
	if idx < 0 {
		return
	}
	_ = ntlmSig

	msg := blob[idx:]
	if len(msg) < 32 {
		return
	}

	// Message type at offset 8 (should be 2 = NTLMSSP_CHALLENGE).
	msgType := binary.LittleEndian.Uint32(msg[8:12])
	if msgType != 2 {
		return
	}

	// TargetName at offset 12: length(2), maxlength(2), offset(4).
	if len(msg) < 20 {
		return
	}
	targetNameLen := binary.LittleEndian.Uint16(msg[12:14])
	targetNameOffset := binary.LittleEndian.Uint32(msg[16:20])
	if int(targetNameOffset)+int(targetNameLen) <= len(msg) && targetNameLen > 0 {
		info.Domain = decodeUTF16LE(msg[targetNameOffset : targetNameOffset+uint32(targetNameLen)])
	}

	// NTLMv2 negotiate flags at offset 20.
	// OS Version at offset 48 (8 bytes): major(1), minor(1), build(2), revision(4).
	if len(msg) >= 56 {
		major := msg[48]
		minor := msg[49]
		build := binary.LittleEndian.Uint16(msg[50:52])
		if major > 0 || minor > 0 || build > 0 {
			info.OS = windowsVersionString(major, minor, build)
		}
	}

	// TargetInfo (AV_PAIR list) at offset 40: length(2), maxlength(2), offset(4).
	if len(msg) < 48 {
		return
	}
	tiLen := binary.LittleEndian.Uint16(msg[40:42])
	tiOffset := binary.LittleEndian.Uint32(msg[44:48])
	if tiLen == 0 || int(tiOffset)+int(tiLen) > len(msg) {
		return
	}

	parseAVPairs(msg[tiOffset:int(tiOffset)+int(tiLen)], info)
}

// parseAVPairs walks the NTLM AV_PAIR list and extracts domain/hostname info.
func parseAVPairs(data []byte, info *SMBInfo) {
	offset := 0
	for offset+4 <= len(data) {
		avID := binary.LittleEndian.Uint16(data[offset : offset+2])
		avLen := binary.LittleEndian.Uint16(data[offset+2 : offset+4])
		offset += 4
		if int(avLen) > len(data)-offset {
			break
		}
		val := data[offset : offset+int(avLen)]
		switch avID {
		case 0x0000: // MsvAvEOL
			return
		case 0x0001: // MsvAvNbDomainName
			info.Domain = decodeUTF16LE(val)
		case 0x0002: // MsvAvNbComputerName
			info.Hostname = decodeUTF16LE(val)
		case 0x0003: // MsvAvDnsDomainName
			info.DNSDomain = decodeUTF16LE(val)
		case 0x0004: // MsvAvDnsComputerName
			info.DNSHostname = decodeUTF16LE(val)
		}
		offset += int(avLen)
	}
}

// decodeUTF16LE decodes a UTF-16 LE byte slice to a Go string.
func decodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u16s := make([]uint16, len(b)/2)
	for i := range u16s {
		u16s[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	runes := utf16.Decode(u16s)
	return strings.TrimRight(string(runes), "\x00")
}

// windowsVersionString maps major.minor.build to a human-readable Windows version.
func windowsVersionString(major, minor byte, build uint16) string {
	switch {
	case major == 10 && minor == 0 && build >= 22000:
		return fmt.Sprintf("Windows 11 (build %d)", build)
	case major == 10 && minor == 0 && build >= 20348:
		return fmt.Sprintf("Windows Server 2022 (build %d)", build)
	case major == 10 && minor == 0 && build >= 17763:
		return fmt.Sprintf("Windows Server 2019 / Windows 10 (build %d)", build)
	case major == 10 && minor == 0:
		return fmt.Sprintf("Windows 10 / Server 2016 (build %d)", build)
	case major == 6 && minor == 3:
		return fmt.Sprintf("Windows 8.1 / Server 2012 R2 (build %d)", build)
	case major == 6 && minor == 2:
		return fmt.Sprintf("Windows 8 / Server 2012 (build %d)", build)
	case major == 6 && minor == 1:
		return fmt.Sprintf("Windows 7 / Server 2008 R2 (build %d)", build)
	case major == 6 && minor == 0:
		return fmt.Sprintf("Windows Vista / Server 2008 (build %d)", build)
	case major == 5 && minor == 1:
		return fmt.Sprintf("Windows XP (build %d)", build)
	case major == 5 && minor == 2:
		return fmt.Sprintf("Windows Server 2003 (build %d)", build)
	default:
		return fmt.Sprintf("Windows %d.%d (build %d)", major, minor, build)
	}
}

// smbDialectString returns a human-readable string for an SMB2 dialect revision.
func smbDialectString(dialect uint16) string {
	switch dialect {
	case 0x0202:
		return "SMB 2.0.2"
	case 0x0210:
		return "SMB 2.1"
	case 0x0300:
		return "SMB 3.0"
	case 0x0302:
		return "SMB 3.0.2"
	case 0x0311:
		return "SMB 3.1.1"
	default:
		return fmt.Sprintf("SMB 0x%04x", dialect)
	}
}

// smb2NegotiateRequest builds an SMB2 Negotiate Request with dialects
// 2.0.2, 2.1, 3.0, 3.0.2, 3.1.1.
func smb2NegotiateRequest() []byte {
	// SMB2 header (64 bytes) + Negotiate Request body.
	// Dialects: 0x0202, 0x0210, 0x0300, 0x0302, 0x0311 (5 dialects × 2 bytes = 10 bytes).
	//
	// Negotiate Request structure (36 bytes fixed + dialect array):
	//   StructureSize: 36
	//   DialectCount: 5
	//   SecurityMode: 1 (NEGOTIATE_SIGNING_ENABLED)
	//   Reserved: 0
	//   Capabilities: 0
	//   ClientGuid: 0 (16 bytes)
	//   ClientStartTime / NegotiateContextOffset: 0 (8 bytes)

	bodyLen := 36 + 10 // negotiate body + 5 dialects
	totalLen := 64 + bodyLen
	pkt := make([]byte, 4+totalLen) // 4 = NetBIOS header

	// NetBIOS session header.
	binary.BigEndian.PutUint32(pkt[0:4], uint32(totalLen))
	pkt[0] = 0x00 // session message type

	off := 4 // start of SMB2 header

	// SMB2 header.
	pkt[off+0] = 0xfe // magic
	pkt[off+1] = 0x53 // 'S'
	pkt[off+2] = 0x4d // 'M'
	pkt[off+3] = 0x42 // 'B'
	binary.LittleEndian.PutUint16(pkt[off+4:off+6], 64) // StructureSize
	// Command: Negotiate (0x0000) — already zero.
	// CreditCharge, Status, Flags, NextCommand, MessageId, etc. — all zero.
	binary.LittleEndian.PutUint16(pkt[off+12:off+14], 1) // CreditRequest = 1

	// Negotiate Request body at offset 4+64 = 68.
	boff := off + 64
	binary.LittleEndian.PutUint16(pkt[boff:boff+2], 36)  // StructureSize
	binary.LittleEndian.PutUint16(pkt[boff+2:boff+4], 5)  // DialectCount
	binary.LittleEndian.PutUint16(pkt[boff+4:boff+6], 1)  // SecurityMode: SIGNING_ENABLED
	// Reserved(2), Capabilities(4), ClientGuid(16), ClientStartTime(8) — all zero.

	// Dialects at boff+36.
	doff := boff + 36
	binary.LittleEndian.PutUint16(pkt[doff:doff+2], 0x0202)
	binary.LittleEndian.PutUint16(pkt[doff+2:doff+4], 0x0210)
	binary.LittleEndian.PutUint16(pkt[doff+4:doff+6], 0x0300)
	binary.LittleEndian.PutUint16(pkt[doff+6:doff+8], 0x0302)
	binary.LittleEndian.PutUint16(pkt[doff+8:doff+10], 0x0311)

	return pkt
}

// smb2SessionSetupNTLMSSPNegotiate builds an SMB2 Session Setup request
// carrying an NTLMSSP_NEGOTIATE token (wrapped in a minimal SPNEGO initiator).
func smb2SessionSetupNTLMSSPNegotiate() []byte {
	// NTLMSSP_NEGOTIATE message (type 1).
	ntlmNeg := []byte{
		'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00, // Signature
		0x01, 0x00, 0x00, 0x00, // MessageType: 1 (NEGOTIATE)
		// NegotiateFlags: NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_NEGOTIATE_OEM |
		//   NTLMSSP_REQUEST_TARGET | NTLMSSP_NEGOTIATE_NTLM |
		//   NTLMSSP_NEGOTIATE_ALWAYS_SIGN | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY |
		//   NTLMSSP_NEGOTIATE_VERSION
		0x97, 0x82, 0x08, 0xe2,
		// DomainNameFields: Len=0, MaxLen=0, Offset=0
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// WorkstationFields: Len=0, MaxLen=0, Offset=0
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// Version: 10.0.19041 (Windows 10)
		0x0a, 0x00, 0x63, 0x4a, 0x00, 0x00, 0x00, 0x0f,
	}

	// Wrap in minimal GSS-API/SPNEGO initiator token:
	// OID 1.2.840.113554.1.2.2 (NTLMSSP) or use raw NTLMSSP.
	// Many SMB servers accept raw NTLMSSP without SPNEGO wrapping,
	// but for better compatibility, wrap in SPNEGO.
	spnego := buildSPNEGOInit(ntlmNeg)

	// SMB2 Session Setup Request.
	// StructureSize: 25, Flags: 0, SecurityMode: 1, Capabilities: 0,
	// Channel: 0, PreviousSessionId: 0.
	// SecurityBufferOffset: 88 (64 header + 24 fixed body, but StructureSize=25
	// and buffer starts at offset 24 from body start, so offset from SMB2 header = 64+24 = 88).
	setupBodyFixed := 24
	totalBody := setupBodyFixed + len(spnego)
	totalLen := 64 + totalBody
	pkt := make([]byte, 4+totalLen)

	// NetBIOS header.
	binary.BigEndian.PutUint32(pkt[0:4], uint32(totalLen))
	pkt[0] = 0x00

	off := 4 // SMB2 header start

	// SMB2 header.
	pkt[off+0] = 0xfe
	pkt[off+1] = 0x53
	pkt[off+2] = 0x4d
	pkt[off+3] = 0x42
	binary.LittleEndian.PutUint16(pkt[off+4:off+6], 64)           // StructureSize
	binary.LittleEndian.PutUint16(pkt[off+12:off+14], 1)          // CreditRequest
	pkt[off+16] = 0x01                                             // Command: SESSION_SETUP (1)
	pkt[off+17] = 0x00

	// Session Setup Request body.
	boff := off + 64
	binary.LittleEndian.PutUint16(pkt[boff:boff+2], 25)                        // StructureSize
	// Flags(1), SecurityMode(1) at boff+2, boff+3
	pkt[boff+3] = 0x01 // SecurityMode: SIGNING_ENABLED
	// Capabilities(4), Channel(4), PreviousSessionId(8) — zero.
	// SecurityBufferOffset: relative to start of SMB2 header.
	binary.LittleEndian.PutUint16(pkt[boff+12:boff+14], uint16(64+setupBodyFixed)) // SecurityBufferOffset
	binary.LittleEndian.PutUint16(pkt[boff+14:boff+16], uint16(len(spnego)))       // SecurityBufferLength

	// Copy SPNEGO token.
	copy(pkt[boff+setupBodyFixed:], spnego)

	return pkt
}

// buildSPNEGOInit wraps an NTLMSSP token in a minimal SPNEGO NegotiateToken
// (Application [0] / NegTokenInit) that most SMB servers accept.
func buildSPNEGOInit(ntlmToken []byte) []byte {
	// OID for NTLMSSP: 1.3.6.1.4.1.311.2.2.10
	// Simplified: use the SPNEGO OID (1.2.840.113554.1.2.2) wrapped structure.
	//
	// Rather than a full ASN.1 encoder, build the fixed structure that Windows
	// and Samba both accept. The mechType list contains only NTLMSSP.

	// NTLMSSP OID: 1.3.6.1.4.1.311.2.2.10 — DER encoded
	ntlmOID := []byte{0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}

	// mechTypeList sequence
	mechTypeList := asn1Wrap(0x30, ntlmOID)

	// mechToken [2] OCTET STRING
	mechToken := asn1Wrap(0x04, ntlmToken)
	mechTokenCtx := asn1Wrap(0xa2, mechToken)

	// NegTokenInit sequence
	mechListCtx := asn1Wrap(0xa0, mechTypeList)
	negTokenInit := asn1Wrap(0x30, append(mechListCtx, mechTokenCtx...))

	// NegotiateToken [0]
	negToken := asn1Wrap(0xa0, negTokenInit)

	// SPNEGO OID: 1.2.840.113554.1.2.2
	spnegoOID := []byte{0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}

	// Application [0] IMPLICIT SEQUENCE { OID, NegotiateToken }
	inner := append(spnegoOID, negToken...)
	return asn1Wrap(0x60, inner)
}

// asn1Wrap wraps data in a single ASN.1 TLV with the given tag.
func asn1Wrap(tag byte, data []byte) []byte {
	l := len(data)
	if l < 0x80 {
		return append([]byte{tag, byte(l)}, data...)
	}
	if l <= 0xff {
		return append([]byte{tag, 0x81, byte(l)}, data...)
	}
	return append([]byte{tag, 0x82, byte(l >> 8), byte(l)}, data...)
}

// detectSMBInfo is the probe detection function registered in the probe pipeline.
func detectSMBInfo(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	info := ProbeSMBInfo(ctx, host, port)
	if info == nil {
		return nil
	}

	var findings []finding.Finding

	// Build evidence map with all extracted information.
	ev := map[string]any{
		"port":    port,
		"service": "smb",
	}
	if info.SMBVersion != "" {
		ev["smb_version"] = info.SMBVersion
	}
	if info.OS != "" {
		ev["os"] = info.OS
	}
	if info.Domain != "" {
		ev["domain"] = info.Domain
	}
	if info.Hostname != "" {
		ev["hostname"] = info.Hostname
	}
	if info.DNSDomain != "" {
		ev["dns_domain"] = info.DNSDomain
	}
	if info.DNSHostname != "" {
		ev["dns_hostname"] = info.DNSHostname
	}
	if info.ServerGUID != "" {
		ev["server_guid"] = info.ServerGUID
	}
	ev["signing_required"] = info.SigningReq
	ev["encryption_supported"] = info.Encryption
	if info.NativeOS != "" {
		ev["native_os"] = info.NativeOS
	}
	if info.NativeLanman != "" {
		ev["native_lanman"] = info.NativeLanman
	}

	// Build a descriptive title.
	parts := []string{}
	if info.OS != "" {
		parts = append(parts, info.OS)
	}
	if info.Domain != "" {
		parts = append(parts, "domain="+info.Domain)
	}
	if info.Hostname != "" {
		parts = append(parts, "host="+info.Hostname)
	}
	if info.SMBVersion != "" {
		parts = append(parts, info.SMBVersion)
	}
	title := fmt.Sprintf("SMB OS discovery on port %d", port)
	if len(parts) > 0 {
		title = fmt.Sprintf("SMB OS discovery on port %d: %s", port, strings.Join(parts, ", "))
	}

	desc := fmt.Sprintf("Native SMB protocol negotiation revealed system information on port %d. ", port)
	if info.OS != "" {
		desc += fmt.Sprintf("OS: %s. ", info.OS)
	}
	if info.Domain != "" && info.Hostname != "" {
		desc += fmt.Sprintf("Domain: %s, Hostname: %s. ", info.Domain, info.Hostname)
	}
	if info.SMBVersion != "" {
		desc += fmt.Sprintf("Protocol: %s. ", info.SMBVersion)
	}
	desc += "This information can be used for OS fingerprinting and Active Directory reconnaissance."

	ev["proof_command"] = fmt.Sprintf("smbclient -N -L //%s -p %d", host, port)

	findings = append(findings, makeF(
		finding.CheckPortSMBOSDiscovery,
		finding.SeverityInfo,
		title,
		desc,
		ev,
	))

	// SMB signing not required — relay attack risk.
	if !info.SigningReq {
		findings = append(findings, makeF(
			finding.CheckPortSMBSigningNotReq,
			finding.SeverityHigh,
			fmt.Sprintf("SMB signing not required on port %d", port),
			"SMB message signing is not required by the server. "+
				"This allows man-in-the-middle and SMB relay attacks where an attacker "+
				"intercepts authentication and relays it to another host. "+
				"NTLM relay attacks (e.g. ntlmrelayx) can escalate to domain admin "+
				"when SMB signing is disabled. "+
				"Enable mandatory signing: Group Policy → Microsoft network server: "+
				"Digitally sign communications (always) = Enabled.",
			map[string]any{
				"port":             port,
				"service":          "smb",
				"signing_required": false,
				"smb_version":      info.SMBVersion,
				"proof_command":    fmt.Sprintf("nmap --script smb2-security-mode -p %d %s", port, host),
			},
		))
	}

	return findings
}
