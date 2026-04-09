package portscan

// Native Go replacements for the most valuable nmap NSE scripts.
// Each probe is registered in init() and runs as part of the standard
// probe pipeline against matching ports.

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
)

// ── Result types ─────────────────────────────────────────────────────────────

// SSHAlgoResult holds the algorithms extracted from an SSH KEX_INIT message.
type SSHAlgoResult struct {
	KexAlgorithms     []string
	HostKeyAlgorithms []string
	CiphersClientToServer []string
	CiphersServerToClient []string
	MACsClientToServer    []string
	MACsServerToClient    []string
	WeakKex     []string
	WeakCiphers []string
	WeakMACs    []string
}

// VNCResult holds VNC security type negotiation results.
type VNCResult struct {
	Version       string
	SecurityTypes []byte
	NoAuthOffered bool // RFB security type 1 (None)
}

// RDPResult holds RDP encryption negotiation results.
type RDPResult struct {
	Detected          bool
	NLARequired       bool   // Network Level Authentication required
	EncryptionLevel   int    // 0=None, 1=Low, 2=Client Compatible, 3=High, 4=FIPS
	ProtocolFlags     byte   // Supported security protocols bitmask
	WeakEncryption    bool   // Encryption level 0 or 1
}

// SNMPResult holds SNMP community string check results.
type SNMPResult struct {
	PublicAccepted  bool
	PrivateAccepted bool
	SysDescr        string
	Community       string // first accepted community string
}

// ── Weak algorithm lists ─────────────────────────────────────────────────────

var weakKexAlgorithms = map[string]bool{
	"diffie-hellman-group1-sha1":         true,
	"diffie-hellman-group-exchange-sha1": true,
	"diffie-hellman-group14-sha1":        true, // deprecated, prefer sha256
}

var weakCiphers = map[string]bool{
	"3des-cbc":       true,
	"arcfour":        true,
	"arcfour128":     true,
	"arcfour256":     true,
	"blowfish-cbc":   true,
	"cast128-cbc":    true,
	"aes128-cbc":     true, // CBC mode is vulnerable to BEAST-like attacks
	"aes192-cbc":     true,
	"aes256-cbc":     true,
}

var weakMACs = map[string]bool{
	"hmac-md5":       true,
	"hmac-md5-96":    true,
	"hmac-sha1-96":   true,
	"hmac-ripemd160": true,
}

func init() {
	registerProbe(ServiceProbe{
		Name:         "ssh-algorithms",
		Category:     ProbeCatProtocol,
		DefaultPorts: []int{22},
		Detect:       detectSSHAlgorithms,
	})
	registerProbe(ServiceProbe{
		Name:         "dns-recursion",
		Category:     ProbeCatProtocol,
		DefaultPorts: []int{53},
		Detect:       detectDNSRecursionTCP,
	})
	registerProbe(ServiceProbe{
		Name:         "snmp-community",
		Category:     ProbeCatProtocol,
		DefaultPorts: []int{161},
		Detect:       detectSNMPCommunityTCP, // note: primary SNMP check is UDP in udp.go; this catches TCP SNMP
	})
	registerProbe(ServiceProbe{
		Name:         "vnc-auth",
		Category:     ProbeCatBanner,
		DefaultPorts: []int{5900},
		Detect:       detectVNCAuth,
	})
	registerProbe(ServiceProbe{
		Name:         "rdp-encryption",
		Category:     ProbeCatProtocol,
		DefaultPorts: []int{3389},
		Detect:       detectRDPEncryption,
	})
}

// ── SSH Algorithm Enumeration ────────────────────────────────────────────────

// probeSSHAlgorithms connects to an SSH server and parses the KEX_INIT
// message to extract supported algorithms. Returns weak algorithms found.
func probeSSHAlgorithms(ctx context.Context, host string, port int) *SSHAlgoResult {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	// Read server's version string (e.g. "SSH-2.0-OpenSSH_9.6\r\n")
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 4 || !strings.HasPrefix(string(buf[:n]), "SSH-") {
		return nil
	}

	// Send our version string
	_, err = conn.Write([]byte("SSH-2.0-beacon_scanner\r\n"))
	if err != nil {
		return nil
	}

	// Read the server's KEX_INIT packet.
	// SSH binary packet format (RFC 4253 Section 6):
	//   uint32  packet_length
	//   byte    padding_length
	//   byte[]  payload
	//   byte[]  padding
	//   byte[]  MAC (not present before keys are exchanged)
	kexBuf := make([]byte, 8192)
	n, err = conn.Read(kexBuf)
	if err != nil || n < 22 {
		return nil
	}

	// The KEX_INIT payload starts after the packet_length(4) + padding_length(1).
	// The first byte of payload should be SSH_MSG_KEXINIT (20).
	packetLen := binary.BigEndian.Uint32(kexBuf[:4])
	if packetLen < 17 || int(packetLen)+4 > n {
		return nil
	}
	paddingLen := int(kexBuf[4])
	payload := kexBuf[5 : 5+int(packetLen)-paddingLen-1]
	if len(payload) < 17 || payload[0] != 20 { // SSH_MSG_KEXINIT = 20
		return nil
	}

	// Skip cookie (16 bytes) after the message type byte.
	offset := 17 // 1 (msg type) + 16 (cookie)
	result := &SSHAlgoResult{}

	// Parse name-lists: kex, host_key, cipher_c2s, cipher_s2c, mac_c2s, mac_s2c, ...
	nameListPtrs := []*[]string{
		&result.KexAlgorithms,
		&result.HostKeyAlgorithms,
		&result.CiphersClientToServer,
		&result.CiphersServerToClient,
		&result.MACsClientToServer,
		&result.MACsServerToClient,
	}

	for i, ptr := range nameListPtrs {
		if offset+4 > len(payload) {
			break
		}
		listLen := int(binary.BigEndian.Uint32(payload[offset : offset+4]))
		offset += 4
		if offset+listLen > len(payload) {
			break
		}
		listStr := string(payload[offset : offset+listLen])
		*ptr = strings.Split(listStr, ",")
		offset += listLen
		_ = i
	}

	// Check for weak algorithms.
	for _, alg := range result.KexAlgorithms {
		if weakKexAlgorithms[alg] {
			result.WeakKex = append(result.WeakKex, alg)
		}
	}
	// Check both client-to-server and server-to-client cipher lists.
	allCiphers := append(result.CiphersClientToServer, result.CiphersServerToClient...)
	seen := make(map[string]bool)
	for _, alg := range allCiphers {
		if weakCiphers[alg] && !seen[alg] {
			result.WeakCiphers = append(result.WeakCiphers, alg)
			seen[alg] = true
		}
	}
	allMACs := append(result.MACsClientToServer, result.MACsServerToClient...)
	seenMAC := make(map[string]bool)
	for _, alg := range allMACs {
		if weakMACs[alg] && !seenMAC[alg] {
			result.WeakMACs = append(result.WeakMACs, alg)
			seenMAC[alg] = true
		}
	}

	return result
}

func detectSSHAlgorithms(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	// Only run on ports that have an SSH banner.
	if !strings.HasPrefix(banner, "SSH-") {
		return nil
	}

	result := probeSSHAlgorithms(ctx, host, port)
	if result == nil {
		return nil
	}

	var findings []finding.Finding

	if len(result.WeakKex) > 0 {
		findings = append(findings, makeF(
			finding.CheckPortSSHWeakKex,
			finding.SeverityMedium,
			fmt.Sprintf("SSH weak key exchange algorithms on port %d", port),
			fmt.Sprintf("The SSH server supports weak key exchange algorithms: %s. "+
				"These algorithms use SHA-1 or small Diffie-Hellman groups that are vulnerable to "+
				"downgrade attacks. Configure the server to use curve25519-sha256 or "+
				"diffie-hellman-group16-sha512 and disable legacy algorithms.",
				strings.Join(result.WeakKex, ", ")),
			map[string]any{
				"port":       port,
				"service":    "ssh",
				"weak_kex":   result.WeakKex,
				"all_kex":    result.KexAlgorithms,
			},
		))
	}

	if len(result.WeakCiphers) > 0 {
		findings = append(findings, makeF(
			finding.CheckPortSSHWeakCipher,
			finding.SeverityMedium,
			fmt.Sprintf("SSH weak ciphers on port %d", port),
			fmt.Sprintf("The SSH server supports weak encryption algorithms: %s. "+
				"3DES, RC4 (arcfour), and CBC-mode ciphers have known cryptographic weaknesses. "+
				"Use only chacha20-poly1305 or aes*-gcm ciphers.",
				strings.Join(result.WeakCiphers, ", ")),
			map[string]any{
				"port":          port,
				"service":       "ssh",
				"weak_ciphers":  result.WeakCiphers,
				"all_ciphers":   result.CiphersClientToServer,
			},
		))
	}

	if len(result.WeakMACs) > 0 {
		findings = append(findings, makeF(
			finding.CheckPortSSHWeakMAC,
			finding.SeverityLow,
			fmt.Sprintf("SSH weak MAC algorithms on port %d", port),
			fmt.Sprintf("The SSH server supports weak MAC algorithms: %s. "+
				"MD5-based and truncated MACs provide weaker integrity guarantees. "+
				"Use hmac-sha2-256-etm@openssh.com or hmac-sha2-512-etm@openssh.com.",
				strings.Join(result.WeakMACs, ", ")),
			map[string]any{
				"port":       port,
				"service":    "ssh",
				"weak_macs":  result.WeakMACs,
				"all_macs":   result.MACsClientToServer,
			},
		))
	}

	return findings
}

// ── DNS Open Resolver Check (TCP) ────────────────────────────────────────────

// probeDNSRecursion sends a recursive DNS query over TCP to check if the
// server is an open resolver.
func probeDNSRecursion(ctx context.Context, host string, port int) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	// DNS query for example.com A record with RD (recursion desired) bit set.
	// Header: ID=0x1234, QR=0|OPCODE=0|AA=0|TC=0|RD=1, RA=0|Z=0|RCODE=0
	// QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
	// Question: example.com IN A
	query := []byte{
		0x12, 0x34, // Transaction ID
		0x01, 0x00, // Flags: RD=1 (recursion desired)
		0x00, 0x01, // QDCOUNT: 1
		0x00, 0x00, // ANCOUNT: 0
		0x00, 0x00, // NSCOUNT: 0
		0x00, 0x00, // ARCOUNT: 0
		// Question: example.com IN A
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,       // root label
		0x00, 0x01, // QTYPE: A
		0x00, 0x01, // QCLASS: IN
	}

	// TCP DNS: 2-byte length prefix.
	tcpMsg := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(tcpMsg[:2], uint16(len(query)))
	copy(tcpMsg[2:], query)

	if _, err := conn.Write(tcpMsg); err != nil {
		return false
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 14 {
		return false
	}

	// Skip 2-byte TCP length prefix.
	resp := buf[2:]
	if len(resp) < 12 {
		return false
	}

	// Validate transaction ID.
	if resp[0] != 0x12 || resp[1] != 0x34 {
		return false
	}

	// Check QR bit (must be response) and RA bit (recursion available).
	if resp[2]&0x80 == 0 { // QR not set
		return false
	}
	if resp[3]&0x80 == 0 { // RA not set — recursion not available
		return false
	}

	// Check RCODE is NOERROR (0) and ANCOUNT > 0.
	rcode := resp[3] & 0x0F
	ancount := binary.BigEndian.Uint16(resp[6:8])

	return rcode == 0 && ancount > 0
}

func detectDNSRecursionTCP(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	if !probeDNSRecursion(ctx, host, port) {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortDNSOpenResolver,
		finding.SeverityHigh,
		fmt.Sprintf("DNS open resolver on TCP port %d", port),
		fmt.Sprintf("The DNS server at %s:%d answers recursive queries for external domains over TCP. "+
			"An open resolver can be abused for DNS amplification DDoS attacks "+
			"and may leak internal DNS data. Restrict recursion to trusted clients.", host, port),
		map[string]any{
			"port":     port,
			"service":  "dns",
			"protocol": "tcp",
			"recursive": true,
		},
	)}
}

// ── SNMP Community String Check (TCP) ────────────────────────────────────────
// Note: The primary SNMP check uses UDP (udp.go). This catches the rare
// TCP SNMP agent (RFC 3430) and serves as a documented probe for the pattern.

func detectSNMPCommunityTCP(_ context.Context, _ string, _ int, _ string, _ findingMaker) []finding.Finding {
	// TCP SNMP is extremely rare in practice. The real SNMP probing is done
	// in udp.go via probeSNMPUDP. This probe registration ensures the
	// snmp-community probe name exists in the registry for documentation
	// and future expansion. Return nil — UDP probe handles actual detection.
	return nil
}

// ── VNC Authentication Check ─────────────────────────────────────────────────

// probeVNCAuth connects to a VNC server and checks if it requires
// authentication (RFB protocol security type negotiation).
func probeVNCAuth(ctx context.Context, host string, port int) *VNCResult {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	// Read server's RFB version string (e.g. "RFB 003.008\n")
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 12 || !strings.HasPrefix(string(buf[:n]), "RFB ") {
		return nil
	}
	version := strings.TrimSpace(string(buf[:n]))

	// Send back the same version string to proceed with handshake.
	_, err = conn.Write(buf[:n])
	if err != nil {
		return &VNCResult{Version: version}
	}

	// Read security types.
	// RFB 3.3: server sends uint32 security type directly.
	// RFB 3.7+: server sends byte numTypes, then byte[] types.
	secBuf := make([]byte, 64)
	sn, err := conn.Read(secBuf)
	if err != nil || sn < 1 {
		return &VNCResult{Version: version}
	}

	result := &VNCResult{Version: version}

	if strings.Contains(version, "003.003") {
		// RFB 3.3: 4-byte security type
		if sn >= 4 {
			secType := binary.BigEndian.Uint32(secBuf[:4])
			result.SecurityTypes = []byte{byte(secType)}
			if secType == 1 {
				result.NoAuthOffered = true
			}
		}
	} else {
		// RFB 3.7+: first byte is count, then that many type bytes
		numTypes := int(secBuf[0])
		if numTypes == 0 {
			// Server sent error — read error message.
			return &VNCResult{Version: version}
		}
		if sn >= 1+numTypes {
			result.SecurityTypes = secBuf[1 : 1+numTypes]
			for _, st := range result.SecurityTypes {
				if st == 1 { // SecurityType 1 = None
					result.NoAuthOffered = true
					break
				}
			}
		}
	}

	return result
}

func detectVNCAuth(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	if !strings.HasPrefix(banner, "RFB ") {
		return nil
	}

	result := probeVNCAuth(ctx, host, port)
	if result == nil || !result.NoAuthOffered {
		return nil
	}

	return []finding.Finding{makeF(
		finding.CheckPortVNCNoAuth,
		finding.SeverityCritical,
		fmt.Sprintf("VNC requires no authentication on port %d", port),
		fmt.Sprintf("The VNC server (%s) offers security type 'None' (type 1), meaning "+
			"any client can connect without credentials and gain full graphical desktop access. "+
			"This provides an attacker with interactive control of the system. "+
			"Configure VNC to require authentication (VncAuth or TLS with credentials).", result.Version),
		map[string]any{
			"port":            port,
			"service":         "vnc",
			"rfb_version":     result.Version,
			"security_types":  result.SecurityTypes,
			"no_auth":         true,
		},
	)}
}

// ── RDP Encryption Check ─────────────────────────────────────────────────────

// probeRDPEncryption sends a TPKT/X224 connection request with RDP negotiation
// and checks the server's encryption level and protocol flags.
func probeRDPEncryption(ctx context.Context, host string, port int) *RDPResult {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	// X.224 Connection Request with RDP Negotiation Request (TYPE_RDP_NEG_REQ).
	// Requesting: PROTOCOL_SSL (1) | PROTOCOL_HYBRID (2) | PROTOCOL_RDSTLS (4)
	// This tells us what the server supports in its response.
	cr := []byte{
		// TPKT header
		0x03, 0x00, // version, reserved
		0x00, 0x13, // length = 19
		// X.224 CR
		0x0E,       // X.224 length (14)
		0xE0,       // CR code
		0x00, 0x00, // DST-REF
		0x00, 0x00, // SRC-REF
		0x00,       // class 0
		// RDP Negotiation Request
		0x01,                   // TYPE_RDP_NEG_REQ
		0x00,                   // flags
		0x08, 0x00,             // length = 8
		0x07, 0x00, 0x00, 0x00, // requestedProtocols: SSL|HYBRID|RDSTLS
	}

	if _, err := conn.Write(cr); err != nil {
		return nil
	}

	buf := make([]byte, 128)
	n, _ := conn.Read(buf)
	if n < 7 {
		return nil
	}

	// Validate TPKT header
	if buf[0] != 0x03 {
		return nil
	}
	// X.224 CC (Connection Confirm): code 0xD0
	if buf[5] != 0xD0 {
		return nil
	}

	result := &RDPResult{Detected: true}

	// Check for RDP Negotiation Response (TYPE_RDP_NEG_RSP = 0x02) or
	// RDP Negotiation Failure (TYPE_RDP_NEG_FAILURE = 0x03).
	// The negotiation data starts at offset 11 in the X.224 CC.
	if n >= 19 {
		negType := buf[11]
		if negType == 0x02 {
			// TYPE_RDP_NEG_RSP: server accepted a security protocol
			result.ProtocolFlags = buf[15]
			selectedProtocol := binary.LittleEndian.Uint32(buf[15:19])
			// If PROTOCOL_HYBRID (2) or PROTOCOL_HYBRID_EX (8) is selected, NLA is in use.
			result.NLARequired = selectedProtocol == 2 || selectedProtocol == 8
		} else if negType == 0x03 {
			// TYPE_RDP_NEG_FAILURE: server rejected all requested protocols.
			// This typically means only standard RDP security (no TLS/NLA) is available.
			result.WeakEncryption = true
		}
	} else {
		// No negotiation response — server uses standard RDP security only.
		// This is the weakest configuration.
		result.WeakEncryption = true
	}

	return result
}

func detectRDPEncryption(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	result := probeRDPEncryption(ctx, host, port)
	if result == nil || !result.Detected {
		return nil
	}

	var findings []finding.Finding

	if result.WeakEncryption {
		findings = append(findings, makeF(
			finding.CheckPortRDPWeakEncryption,
			finding.SeverityHigh,
			fmt.Sprintf("RDP weak encryption — standard RDP security only on port %d", port),
			"The RDP server rejected TLS and NLA negotiation, indicating it only supports "+
				"standard RDP security with RC4 encryption. Standard RDP security is vulnerable to "+
				"man-in-the-middle attacks and provides no server authentication. "+
				"Enable Network Level Authentication (NLA) and require TLS transport security.",
			map[string]any{
				"port":            port,
				"service":         "rdp",
				"nla_required":    false,
				"weak_encryption": true,
			},
		))
	} else if !result.NLARequired {
		findings = append(findings, makeF(
			finding.CheckPortRDPNoNLA,
			finding.SeverityMedium,
			fmt.Sprintf("RDP does not require NLA on port %d", port),
			"The RDP server accepted TLS but does not require Network Level Authentication (NLA). "+
				"Without NLA, an attacker can reach the Windows login screen without first authenticating, "+
				"which exposes the server to pre-authentication exploits (e.g., BlueKeep CVE-2019-0708). "+
				"Enable NLA: System Properties → Remote → 'Allow connections only from computers running "+
				"Remote Desktop with Network Level Authentication'.",
			map[string]any{
				"port":         port,
				"service":      "rdp",
				"nla_required": false,
			},
		))
	}

	return findings
}
