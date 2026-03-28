package portscan

// UDP service probing — pure Go, no root required.
//
// UDP is fundamentally different from TCP: there is no connection handshake,
// so a non-response may mean filtered, closed, or simply no reply needed.
// We only emit findings when we receive a protocol-valid positive response.
// Each probe sends a minimal well-formed request and checks for a specific
// response pattern within a short deadline (udpTimeout).
//
// Services probed:
//   - NTP (123/UDP):    version request + monlist amplification check
//   - SNMP (161/UDP):   GetRequest with "public" community string
//   - TFTP (69/UDP):    Read Request for a non-existent file
//   - SSDP (1900/UDP):  UPnP M-SEARCH discovery request
//   - IKE (500/UDP):    IKEv2 SA_INIT initiation header
//   - NetBIOS-NS (137/UDP): Name Service status query
//   - STUN (3478/UDP):  Binding Request
//   - mDNS (5353/UDP):  DNS-SD service discovery query
//   - RADIUS (1812/UDP): Access-Request with empty credentials
//
// All UDP probes use a 2-second timeout. False negatives (filtered → no
// response) are acceptable — better than false positives from unreliable UDP.

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
)

const udpTimeout = 2 * time.Second

// RunUDP runs all UDP probes against host and returns any findings.
// It is called from Scanner.Run() after the TCP connect phase.
func runUDP(ctx context.Context, host string) []finding.Finding {
	var findings []finding.Finding

	// NTP
	if ntpFs := probeNTP(ctx, host); len(ntpFs) > 0 {
		findings = append(findings, ntpFs...)
	}
	// SNMP
	if snmpFs := probeSNMPUDP(ctx, host); len(snmpFs) > 0 {
		findings = append(findings, snmpFs...)
	}
	// TFTP
	if tftpF := probeTFTP(ctx, host); tftpF != nil {
		findings = append(findings, *tftpF)
	}
	// SSDP/UPnP
	if ssdpF := probeSSDPUDP(ctx, host); ssdpF != nil {
		findings = append(findings, *ssdpF)
	}
	// IKE/IPSec
	if ikeF := probeIKEUDP(ctx, host); ikeF != nil {
		findings = append(findings, *ikeF)
	}
	// NetBIOS Name Service
	if nbF := probeNetBIOSNS(ctx, host); nbF != nil {
		findings = append(findings, *nbF)
	}
	// STUN
	if stunF := probeSTUN(ctx, host); stunF != nil {
		findings = append(findings, *stunF)
	}
	// mDNS
	if mdnsF := probeMDNS(ctx, host); mdnsF != nil {
		findings = append(findings, *mdnsF)
	}
	// RADIUS
	if radiusF := probeRADIUS(ctx, host); radiusF != nil {
		findings = append(findings, *radiusF)
	}

	return findings
}

// dialUDP opens a UDP socket to host:port and sets a deadline.
// Returns the connection and a cancel function; caller must close conn.
func dialUDP(ctx context.Context, host string, port int) (*net.UDPConn, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(udpTimeout)
	}
	if time.Until(deadline) > udpTimeout {
		deadline = time.Now().Add(udpTimeout)
	}

	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, itoa(port)))
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(deadline) //nolint:errcheck
	return conn, nil
}

// ── NTP ─────────────────────────────────────────────────────────────────────

// ntpMode3Request is an NTP v4 client request (LI=0, VN=4, Mode=3).
var ntpMode3Request = [48]byte{0x23} // byte 0: 0x23 = 0b00100011 (LI=0, VN=4, Mode=3)

// ntpMode7Request is an NTP mode 7 implementation-specific command for the
// monlist function (REQ_MON_GETLIST, code 42 / 0x2A).
// Sending this and receiving a response confirms CVE-2013-5211 (NTP amplification).
var ntpMode7Request = [8]byte{
	0x17, // LI=0, VN=2, Mode=7
	0x00, // Response=0, More=0, Version=2, Reserved=0
	0x03, // AuthSeq
	0x2a, // Request code: REQ_MON_GETLIST (42)
	0x00, 0x00, 0x00, 0x00, // Data length + count
}

func probeNTP(ctx context.Context, host string) []finding.Finding {
	conn, err := dialUDP(ctx, host, 123)
	if err != nil {
		return nil
	}
	defer conn.Close()

	if _, err := conn.Write(ntpMode3Request[:]); err != nil {
		return nil
	}
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	// NTP response: byte 0 has mode = 4 (server) or 5 (broadcast).
	// Bits [0:2] are mode. Accept mode 4 or 5.
	if err != nil || n < 4 {
		return nil
	}
	mode := buf[0] & 0x07
	if mode != 4 && mode != 5 {
		return nil
	}

	now := time.Now()
	var findings []finding.Finding
	findings = append(findings, finding.Finding{
		CheckID:  finding.CheckPortNTPExposed,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityMedium,
		Asset:    host,
		Title:    "NTP server exposed on UDP 123",
		Description: "A Network Time Protocol (NTP) server is publicly accessible on UDP port 123. " +
			"Internet-facing NTP servers may be exploited as DDoS amplification sources (up to 500× " +
			"amplification via the monlist command). They can also leak internal hostnames via the " +
			"peer list and disclose server information. Restrict NTP to known clients or use a GPS/PPS " +
			"reference and restrict monlist.",
		Evidence:    map[string]any{"port": 123, "service": "ntp", "protocol": "udp"},
		DiscoveredAt: now,
	})

	// Check for NTP monlist amplification (CVE-2013-5211).
	// Re-dial so we get a fresh deadline.
	conn2, err := dialUDP(ctx, host, 123)
	if err == nil {
		defer conn2.Close()
		if _, err := conn2.Write(ntpMode7Request[:]); err == nil {
			monBuf := make([]byte, 512)
			n2, err := conn2.Read(monBuf)
			// Mode 7 response has byte 0 = 0x97 (response bit set, mode=7)
			if err == nil && n2 > 8 && (monBuf[0]&0x80) != 0 && (monBuf[0]&0x07) == 7 {
				findings = append(findings, finding.Finding{
					CheckID:  finding.CheckPortNTPAmplification,
					Module:   "surface",
					Scanner:  scannerName,
					Severity: finding.SeverityCritical,
					Asset:    host,
					Title:    "NTP monlist enabled — DDoS amplification source (CVE-2013-5211)",
					Description: "The NTP server's monlist command (mode 7, REQ_MON_GETLIST) is enabled and responding. " +
						"CVE-2013-5211: An attacker can spoof a victim's source IP and send a 48-byte monlist request; " +
						"the NTP server replies with up to 600 client IP records (~500× amplification factor). " +
						"This makes the server a high-value DDoS amplification source. " +
						"Disable monlist in ntp.conf: 'restrict default noquery' and 'disable monitor'.",
					Evidence:    map[string]any{"port": 123, "service": "ntp", "protocol": "udp", "amplification": "monlist"},
					DiscoveredAt: now,
				})
			}
		}
	}

	return findings
}

// ── SNMP ────────────────────────────────────────────────────────────────────

// snmpPublicGetRequest is an SNMPv2c GetRequest for sysDescr (OID 1.3.6.1.2.1.1.1.0)
// with community string "public".
//
// Wire format (40 bytes):
//   30 26                                     SEQUENCE
//     02 01 01                                Integer: version=1 (SNMPv2c)
//     04 06 70 75 62 6c 69 63                 OctetString: "public"
//     a0 19                                   GetRequest PDU
//       02 01 01                              Integer: requestID=1
//       02 01 00                              Integer: errorStatus=0
//       02 01 00                              Integer: errorIndex=0
//       30 0e                                 VarBindList
//         30 0c                               VarBind
//           06 08 2b 06 01 02 01 01 01 00     OID: 1.3.6.1.2.1.1.1.0
//           05 00                             Null
var snmpPublicGetRequest = []byte{
	0x30, 0x26,
	0x02, 0x01, 0x01,
	0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
	0xa0, 0x19,
	0x02, 0x01, 0x01,
	0x02, 0x01, 0x00,
	0x02, 0x01, 0x00,
	0x30, 0x0e,
	0x30, 0x0c,
	0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,
	0x05, 0x00,
}

func probeSNMPUDP(ctx context.Context, host string) []finding.Finding {
	conn, err := dialUDP(ctx, host, 161)
	if err != nil {
		return nil
	}
	defer conn.Close()

	if _, err := conn.Write(snmpPublicGetRequest); err != nil {
		return nil
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	// SNMP GetResponse starts with 0x30 (SEQUENCE) and contains 0xa2 (GetResponse PDU).
	if err != nil || n < 5 || buf[0] != 0x30 {
		return nil
	}
	// Check for GetResponse PDU tag (0xa2) anywhere in first 30 bytes.
	hasGetResponse := false
	for i := 0; i < n && i < 30; i++ {
		if buf[i] == 0xa2 {
			hasGetResponse = true
			break
		}
	}
	if !hasGetResponse {
		return nil
	}

	return []finding.Finding{{
		CheckID:  finding.CheckPortSNMPPublicCommunity,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Asset:    host,
		Title:    "SNMP 'public' community string accepted on UDP 161",
		Description: "The SNMP agent on UDP 161 accepts the default 'public' community string, " +
			"enabling unauthenticated read access to the entire SNMP MIB. " +
			"This exposes: interface statistics, routing tables, ARP cache, running processes, " +
			"installed software, and hardware inventory — a complete network topology map. " +
			"Disable SNMPv1/v2c entirely and migrate to SNMPv3 with authentication and encryption, " +
			"or restrict the community string and apply firewall rules.",
		Evidence:    map[string]any{"port": 161, "service": "snmp", "protocol": "udp", "community": "public"},
		DiscoveredAt: time.Now(),
	}}
}

// ── TFTP ────────────────────────────────────────────────────────────────────

// tftpRRQ is a TFTP Read Request for a non-existent file "missing" in octet mode.
// Format: opcode(2) + filename + NUL + mode + NUL
// We expect either a DATA packet (opcode 3) or an ERROR packet (opcode 5) —
// either response confirms a live TFTP server.
var tftpRRQ = []byte{
	0x00, 0x01, // Opcode: RRQ
	'm', 'i', 's', 's', 'i', 'n', 'g', 0x00, // Filename: "missing\0"
	'o', 'c', 't', 'e', 't', 0x00, // Mode: "octet\0"
}

func probeTFTP(ctx context.Context, host string) *finding.Finding {
	conn, err := dialUDP(ctx, host, 69)
	if err != nil {
		return nil
	}
	defer conn.Close()

	if _, err := conn.Write(tftpRRQ); err != nil {
		return nil
	}
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	// TFTP response: opcode in first 2 bytes.
	// Opcode 3 = DATA, opcode 5 = ERROR — both indicate a TFTP server.
	if err != nil || n < 4 {
		return nil
	}
	opcode := (uint16(buf[0]) << 8) | uint16(buf[1])
	if opcode != 3 && opcode != 5 {
		return nil
	}

	f := finding.Finding{
		CheckID:  finding.CheckPortTFTPAnonymous,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Asset:    host,
		Title:    "TFTP server accessible without authentication on UDP 69",
		Description: "A TFTP (Trivial File Transfer Protocol) server is responding on UDP 69 without authentication. " +
			"TFTP has no access control — any client can read or write files. " +
			"TFTP servers are used for network device configuration backups (Cisco IOS, Juniper, etc.) " +
			"and PXE/BOOTP booting; exposed TFTP allows reading device configurations containing credentials. " +
			"Restrict TFTP access to known management IPs or disable if not needed.",
		Evidence:    map[string]any{"port": 69, "service": "tftp", "protocol": "udp"},
		DiscoveredAt: time.Now(),
	}
	return &f
}

// ── SSDP / UPnP ──────────────────────────────────────────────────────────────

// ssdpMSearch is a UPnP Simple Service Discovery Protocol M-SEARCH request.
// Sending this to a unicast address (not multicast) tests if the device responds
// to direct SSDP queries — which means it's accessible from the internet.
var ssdpMSearch = []byte("M-SEARCH * HTTP/1.1\r\n" +
	"HOST: 239.255.255.250:1900\r\n" +
	"MAN: \"ssdp:discover\"\r\n" +
	"MX: 1\r\n" +
	"ST: ssdp:all\r\n\r\n")

func probeSSDPUDP(ctx context.Context, host string) *finding.Finding {
	conn, err := dialUDP(ctx, host, 1900)
	if err != nil {
		return nil
	}
	defer conn.Close()

	if _, err := conn.Write(ssdpMSearch); err != nil {
		return nil
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	resp := string(buf[:n])
	if err != nil || !strings.Contains(resp, "HTTP/1.1") {
		return nil
	}

	ev := map[string]any{"port": 1900, "service": "ssdp", "protocol": "udp"}

	// CVE-2012-5958: libupnp ≤ 1.6.17 SSDP SUBSCRIBE buffer overflow → pre-auth RCE.
	// The Server: header in the SSDP response often identifies the SDK version.
	// "Portable SDK for UPnP devices/1.6.17" or earlier is vulnerable.
	if libupnpVer := parseLibupnpVersion(resp); libupnpVer != "" {
		ev["libupnp_version"] = libupnpVer
		if isLibupnpVulnerable(libupnpVer) {
			return &finding.Finding{
				CheckID:  finding.CheckCVELibupnpSSDPRCE,
				Module:   "surface",
				Scanner:  scannerName,
				Severity: finding.SeverityCritical,
				Asset:    host,
				Title:    fmt.Sprintf("libupnp %s vulnerable to CVE-2012-5958 (pre-auth RCE via SSDP)", libupnpVer),
				Description: fmt.Sprintf(
					"The SSDP response identifies libupnp %s (\"Portable SDK for UPnP devices\"). "+
						"libupnp ≤ 1.6.17 contains a buffer overflow in the SSDP SUBSCRIBE and NOTIFY "+
						"request handlers (CVE-2012-5958, CVSS 10.0). An attacker on the network can "+
						"send a crafted SSDP packet to trigger pre-authentication remote code execution "+
						"as root on the embedded device. Affected vendors include Belkin, D-Link, "+
						"Linksys, Netgear, Sony, and hundreds of others. Upgrade the device firmware.",
					libupnpVer,
				),
				Evidence: ev,
				ProofCommand: fmt.Sprintf(
					"# Send SSDP M-SEARCH and read Server header:\n"+
						"echo -e 'M-SEARCH * HTTP/1.1\\r\\nHOST: 239.255.255.250:1900\\r\\nMAN: \"ssdp:discover\"\\r\\nMX: 1\\r\\nST: ssdp:all\\r\\n\\r\\n' | nc -u %s 1900",
					host),
				DiscoveredAt: time.Now(),
			}
		}
	}

	f := finding.Finding{
		CheckID:  finding.CheckPortSSDPExposed,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Asset:    host,
		Title:    "SSDP/UPnP server accessible on UDP 1900",
		Description: "A UPnP/SSDP device is responding to unicast M-SEARCH requests on UDP 1900. " +
			"SSDP/UPnP is a LAN-only protocol that should never be accessible from the internet. " +
			"Internet-facing UPnP is exploited for: port mapping attacks (opening firewall holes), " +
			"CVE-2020-12695 (CallStranger SSRF/DDoS via SUBSCRIBE callbacks), and IoT device compromise. " +
			"Block UDP 1900 at the network perimeter and disable UPnP on routers and IoT devices.",
		Evidence:     ev,
		DiscoveredAt: time.Now(),
	}
	return &f
}

// parseLibupnpVersion extracts the libupnp SDK version from an SSDP response.
// The Server: header format is: "OS/version UPnP/1.0 Portable SDK for UPnP devices/X.Y.Z"
func parseLibupnpVersion(resp string) string {
	const marker = "portable sdk for upnp devices/"
	lower := strings.ToLower(resp)
	idx := strings.Index(lower, marker)
	if idx == -1 {
		return ""
	}
	rest := resp[idx+len(marker):]
	// Read until whitespace, CR, or end of line.
	end := strings.IndexAny(rest, " \t\r\n")
	if end == -1 {
		return rest
	}
	return rest[:end]
}

// isLibupnpVulnerable returns true when the libupnp version is ≤ 1.6.17
// (CVE-2012-5958 SSDP SUBSCRIBE buffer overflow).
func isLibupnpVulnerable(ver string) bool {
	parts := strings.Split(ver, ".")
	if len(parts) < 2 {
		return false
	}
	maj, min, patch := 0, 0, 0
	fmt.Sscanf(parts[0], "%d", &maj)
	fmt.Sscanf(parts[1], "%d", &min)
	if len(parts) >= 3 {
		fmt.Sscanf(parts[2], "%d", &patch)
	}
	if maj != 1 {
		return false
	}
	if min < 6 {
		return true
	}
	if min == 6 {
		return patch <= 17
	}
	return false
}

// ── IKE / IPSec ──────────────────────────────────────────────────────────────

// ikeV2SAInit is a minimal IKEv2 SA_INIT header (28 bytes).
// A live IKE server will respond with either a valid SA_INIT or an error notify,
// both of which confirm an IKE/IPSec endpoint. The Responder SPI is zeroed as
// required for the initial exchange.
var ikeV2SAInit = []byte{
	// Initiator SPI (8 bytes, non-zero)
	0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
	// Responder SPI (8 bytes, must be zero for initial)
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// Next payload: SA (0x21), Version: 2.0 (0x20)
	0x21, 0x20,
	// Exchange type: SA_INIT (0x22), Flags: Initiator (0x08)
	0x22, 0x08,
	// Message ID: 0
	0x00, 0x00, 0x00, 0x00,
	// Length: 28 (header only — will get INVALID_SYNTAX but confirms IKE endpoint)
	0x00, 0x00, 0x00, 0x1c,
}

func probeIKEUDP(ctx context.Context, host string) *finding.Finding {
	conn, err := dialUDP(ctx, host, 500)
	if err != nil {
		return nil
	}
	defer conn.Close()

	if _, err := conn.Write(ikeV2SAInit); err != nil {
		return nil
	}
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	// IKE response: must be ≥ 28 bytes and responder SPI (bytes 8-15) must
	// match our initiator SPI, OR the response SPI field (bytes 0-7) is non-zero.
	// Accept any response ≥ 28 bytes as confirmation of an IKE endpoint.
	if err != nil || n < 28 {
		return nil
	}

	f := finding.Finding{
		CheckID:  finding.CheckPortIKEExposed,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityMedium,
		Asset:    host,
		Title:    "IKE/IPSec VPN endpoint exposed on UDP 500",
		Description: "An IKEv2/IPSec VPN endpoint is responding on UDP 500. " +
			"While VPN endpoints are expected on corporate gateways, internet-facing IKE can be probed for: " +
			"vendor fingerprinting via IKEv1 Vendor ID (VID) payloads, " +
			"aggressive mode pre-shared key hash capture, " +
			"and exploitation of IKE daemon vulnerabilities. " +
			"Known critical CVEs: CVE-2023-46805/CVE-2024-21887 (Ivanti ICS/Pulse Secure IKE bypass). " +
			"Ensure IKE is on the latest patched version and restrict to known peer IP ranges.",
		Evidence:    map[string]any{"port": 500, "service": "ike", "protocol": "udp"},
		DiscoveredAt: time.Now(),
	}
	return &f
}

// ── NetBIOS Name Service ──────────────────────────────────────────────────────

// netbiosNSQuery is a NetBIOS Name Service Node Status Request (unicast).
// If the target responds, Windows NBNS name resolution is exposed on the internet.
// The "name" queried is the wildcard "*\x00\x00..." (15 zeros + type byte 0x00).
var netbiosNSQuery = []byte{
	0x00, 0x01, // Transaction ID
	0x00, 0x00, // Flags: standard query
	0x00, 0x01, // Questions: 1
	0x00, 0x00, // Answer RRs: 0
	0x00, 0x00, // Authority RRs: 0
	0x00, 0x00, // Additional RRs: 0
	// Encoded NetBIOS name: "*" wildcard (32 bytes Level-1 encoded)
	0x20,
	0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
	0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
	0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
	0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
	0x00, // Root label
	0x00, 0x21, // Type: NBSTAT (node status)
	0x00, 0x01, // Class: IN
}

func probeNetBIOSNS(ctx context.Context, host string) *finding.Finding {
	conn, err := dialUDP(ctx, host, 137)
	if err != nil {
		return nil
	}
	defer conn.Close()

	if _, err := conn.Write(netbiosNSQuery); err != nil {
		return nil
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	// Response: first 2 bytes match our transaction ID (0x00, 0x01)
	// and flags byte 2 has the response bit set (0x80).
	if err != nil || n < 12 || buf[0] != 0x00 || buf[1] != 0x01 {
		return nil
	}
	// Check response flag (bit 15 of flags field)
	if buf[2]&0x80 == 0 {
		return nil
	}

	f := finding.Finding{
		CheckID:  finding.CheckPortNetBIOSNSExposed,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Asset:    host,
		Title:    "NetBIOS Name Service exposed on UDP 137",
		Description: "The Windows NetBIOS Name Service (NBNS) is responding to queries on UDP 137. " +
			"NBNS is a legacy Windows name resolution protocol that should never be internet-accessible. " +
			"An exposed NBNS service leaks: computer name, workgroup/domain name, MAC address, " +
			"and running services. It is also vulnerable to spoofing attacks. " +
			"Block UDP/TCP 137-139 at the network perimeter.",
		Evidence:    map[string]any{"port": 137, "service": "netbios-ns", "protocol": "udp"},
		DiscoveredAt: time.Now(),
	}
	return &f
}

// ── STUN ─────────────────────────────────────────────────────────────────────

// stunBindingRequest is a minimal STUN Binding Request (RFC 5389).
// The Magic Cookie (0x2112A442) is required by RFC 5389.
// A STUN Binding Success Response (0x0101) confirms a STUN server.
var stunBindingRequest = []byte{
	0x00, 0x01, // Type: Binding Request
	0x00, 0x00, // Message Length: 0 (no attributes)
	// Magic Cookie (RFC 5389)
	0x21, 0x12, 0xa4, 0x42,
	// Transaction ID (12 random bytes)
	0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
}

func probeSTUN(ctx context.Context, host string) *finding.Finding {
	conn, err := dialUDP(ctx, host, 3478)
	if err != nil {
		return nil
	}
	defer conn.Close()

	if _, err := conn.Write(stunBindingRequest); err != nil {
		return nil
	}
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	// STUN Binding Success Response: type = 0x0101
	// STUN Error Response: type = 0x0111
	// Either confirms a STUN server.
	if err != nil || n < 4 {
		return nil
	}
	msgType := (uint16(buf[0]) << 8) | uint16(buf[1])
	if msgType != 0x0101 && msgType != 0x0111 {
		return nil
	}

	f := finding.Finding{
		CheckID:  finding.CheckPortSTUNExposed,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityMedium,
		Asset:    host,
		Title:    "STUN server exposed on UDP 3478",
		Description: "A STUN (Session Traversal Utilities for NAT) server is accessible on UDP 3478. " +
			"Exposed STUN servers are used by WebRTC applications for NAT traversal and can expose the " +
			"real source IP address of clients behind NAT. If the server also supports TURN (relay), " +
			"attackers may abuse it as a free UDP relay for malicious traffic. " +
			"Restrict STUN/TURN access to your application's WebRTC clients only.",
		Evidence:    map[string]any{"port": 3478, "service": "stun", "protocol": "udp"},
		DiscoveredAt: time.Now(),
	}
	return &f
}

// ── mDNS ─────────────────────────────────────────────────────────────────────

// mdnsQuery is a DNS query for _services._dns-sd._udp.local PTR records (DNS-SD).
// This is the standard mDNS service discovery query.
// Any unicast response from an internet host confirms mDNS is misconfigured
// (mDNS should only respond on link-local multicast, never to internet unicast).
var mdnsQuery = []byte{
	0x00, 0x00, // Transaction ID: 0 (mDNS uses 0)
	0x00, 0x00, // Flags: standard query
	0x00, 0x01, // Questions: 1
	0x00, 0x00, // Answer RRs: 0
	0x00, 0x00, // Authority RRs: 0
	0x00, 0x00, // Additional RRs: 0
	// "_services._dns-sd._udp.local"
	0x09, '_', 's', 'e', 'r', 'v', 'i', 'c', 'e', 's',
	0x07, '_', 'd', 'n', 's', '-', 's', 'd',
	0x04, '_', 'u', 'd', 'p',
	0x05, 'l', 'o', 'c', 'a', 'l',
	0x00,        // Root label
	0x00, 0x0c, // Type: PTR
	0x00, 0x01, // Class: IN
}

func probeMDNS(ctx context.Context, host string) *finding.Finding {
	conn, err := dialUDP(ctx, host, 5353)
	if err != nil {
		return nil
	}
	defer conn.Close()

	if _, err := conn.Write(mdnsQuery); err != nil {
		return nil
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	// Any DNS response (QR bit set = 0x8000 in flags) is a positive signal.
	if err != nil || n < 12 {
		return nil
	}
	flags := (uint16(buf[2]) << 8) | uint16(buf[3])
	if flags&0x8000 == 0 {
		return nil // Not a response
	}

	f := finding.Finding{
		CheckID:  finding.CheckPortMDNSExposed,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityMedium,
		Asset:    host,
		Title:    "mDNS/Bonjour service discovery responding from internet (UDP 5353)",
		Description: "The host is responding to mDNS (Multicast DNS / Bonjour) queries on UDP 5353 from a " +
			"unicast internet source. mDNS is a link-local protocol (RFC 6762) that should only " +
			"respond to multicast queries on the local network segment, never to unicast queries from " +
			"the internet. An internet-facing mDNS service leaks internal service names, hostnames, " +
			"and network topology. Disable mDNS on internet-facing interfaces.",
		Evidence:    map[string]any{"port": 5353, "service": "mdns", "protocol": "udp"},
		DiscoveredAt: time.Now(),
	}
	return &f
}

// radiusAccessRequest is a minimal RADIUS Access-Request packet (RFC 2865).
// Code=1 (Access-Request), ID=1, Length=20 (header only, no attributes),
// Authenticator=16 zero bytes. Any RADIUS server will respond with
// Access-Reject (code 3) or Access-Challenge (code 11) even to an empty request,
// confirming the service is reachable.
var radiusAccessRequest = []byte{
	0x01,       // Code: Access-Request
	0x01,       // Identifier: 1
	0x00, 0x14, // Length: 20 (just the header)
	// Authenticator: 16 bytes (zeros — acceptable for server detection)
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

// probeRADIUS sends a minimal RADIUS Access-Request to UDP/1812 and returns
// a finding if any valid RADIUS response is received. Any response
// (Access-Reject, Access-Challenge, etc.) confirms a RADIUS server is listening.
// RADIUS servers reachable from the internet are a high-severity finding because
// they authenticate VPN, WiFi (802.1X/WPA-Enterprise), and network device access.
func probeRADIUS(ctx context.Context, host string) *finding.Finding {
	conn, err := dialUDP(ctx, host, 1812)
	if err != nil {
		return nil
	}
	defer conn.Close()

	if _, err := conn.Write(radiusAccessRequest); err != nil {
		return nil
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil || n < 4 {
		return nil
	}
	// Valid RADIUS response codes: 2=Access-Accept, 3=Access-Reject,
	// 11=Access-Challenge, 5=Accounting-Response
	code := buf[0]
	if code != 2 && code != 3 && code != 11 && code != 5 {
		return nil
	}

	f := finding.Finding{
		CheckID:  finding.CheckPortRADIUSExposed,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Asset:    host,
		Title:    "RADIUS authentication server reachable from internet (UDP 1812)",
		Description: "A RADIUS authentication server (RFC 2865) is responding to UDP/1812 from the " +
			"internet. RADIUS is used for VPN authentication, WPA-Enterprise WiFi (802.1X), " +
			"and network device (switch/router) login. Internet-exposed RADIUS servers are " +
			"vulnerable to offline dictionary attacks against captured Access-Request packets, " +
			"amplification abuse, and CVE-2024-3596 (RADIUS/MD5 Blast RADIUS — forge any response). " +
			"RADIUS should only be reachable from NAS devices on internal networks. " +
			"Implement firewall rules to block UDP/1812 from all external sources.",
		Evidence:    map[string]any{"port": 1812, "service": "radius", "protocol": "udp", "response_code": int(code)},
		ProofCommand: fmt.Sprintf("echo -n | nc -u -w1 %s 1812 | xxd | head", host),
		DiscoveredAt: time.Now(),
	}
	return &f
}

// itoa converts an int to a string decimal representation.
// Used to avoid importing strconv just for JoinHostPort.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 10)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	if neg {
		buf = append([]byte{'-'}, buf...)
	}
	return string(buf)
}
