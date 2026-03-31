// Package network implements an on-premise network discovery scanner.
// It probes LAN targets for SNMP default community strings, UPnP/SSDP
// exposure, mDNS service enumeration, Telnet management interfaces, and
// HTTP management UIs without TLS.
package network

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const scannerName = "onprem/network"

// Config holds network discovery parameters.
type Config struct {
	Targets []string // IP addresses or CIDR ranges to scan
}

// Scanner probes network targets for common on-premise misconfigurations.
type Scanner struct {
	cfg Config
	// dialer allows tests to override the default dialer for UDP/TCP.
	dialer netDialer
	// httpClient allows tests to override the HTTP client.
	httpClient *http.Client
}

// netDialer abstracts net.Dialer for testing.
type netDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// New returns a new Scanner with the given configuration.
func New(cfg Config) *Scanner {
	return &Scanner{
		cfg:    cfg,
		dialer: &net.Dialer{Timeout: 5 * time.Second},
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// NewWithDialer returns a Scanner with a custom dialer and HTTP client (for testing).
func NewWithDialer(cfg Config, d netDialer, client *http.Client) *Scanner {
	s := &Scanner{
		cfg:        cfg,
		dialer:     d,
		httpClient: client,
	}
	if s.httpClient == nil {
		s.httpClient = &http.Client{Timeout: 5 * time.Second}
	}
	return s
}

// Name returns the stable scanner identifier.
func (s *Scanner) Name() string { return scannerName }

// --------------------------------------------------------------------------
// Run
// --------------------------------------------------------------------------

// Run executes the network discovery scanner.
// Surface mode: UPnP, mDNS, Telnet, HTTP management (passive/non-intrusive).
// Deep mode: adds SNMP probing with default community strings.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	targets := s.cfg.Targets
	if len(targets) == 0 {
		targets = []string{asset}
	}

	var findings []finding.Finding

	for _, target := range targets {
		ips := expandTarget(target)
		for _, ip := range ips {
			select {
			case <-ctx.Done():
				return findings, nil
			default:
			}

			// Surface-mode checks.
			findings = append(findings, s.checkUPnP(ctx, ip)...)
			findings = append(findings, s.checkMDNS(ctx, ip)...)
			findings = append(findings, s.checkTelnet(ctx, ip)...)
			findings = append(findings, s.checkHTTPMgmt(ctx, ip)...)

			// Deep-mode checks.
			if scanType == module.ScanDeep || scanType == module.ScanAuthorized {
				findings = append(findings, s.checkSNMP(ctx, ip)...)
			}
		}
	}

	return findings, nil
}

// --------------------------------------------------------------------------
// SNMP default community string check (Deep)
// --------------------------------------------------------------------------

// buildSNMPGetNextPacket builds a minimal SNMPv2c GET-NEXT request.
// This is a raw BER-encoded SNMP packet targeting OID 1.3.6.1.2.1.1.1.0
// (sysDescr) with the provided community string.
func buildSNMPGetNextPacket(community string) []byte {
	// OID 1.3.6.1.2.1.1.1.0 encoded.
	oid := []byte{0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00}

	// VarBind: SEQUENCE { OID, NULL }
	varBind := append([]byte{0x30, byte(len(oid) + 2)}, oid...)
	varBind = append(varBind, 0x05, 0x00) // NULL value

	// VarBindList: SEQUENCE { VarBind }
	varBindList := append([]byte{0x30, byte(len(varBind))}, varBind...)

	// PDU: GetNextRequest (0xA1)
	// request-id (INTEGER 1), error-status (0), error-index (0), varbindlist
	requestID := []byte{0x02, 0x01, 0x01}        // INTEGER 1
	errorStatus := []byte{0x02, 0x01, 0x00}      // INTEGER 0
	errorIndex := []byte{0x02, 0x01, 0x00}       // INTEGER 0
	pduContent := append(requestID, errorStatus...)
	pduContent = append(pduContent, errorIndex...)
	pduContent = append(pduContent, varBindList...)
	pdu := append([]byte{0xa1, byte(len(pduContent))}, pduContent...)

	// Version: INTEGER 1 (SNMPv2c)
	version := []byte{0x02, 0x01, 0x01}

	// Community: OCTET STRING
	communityBytes := []byte(community)
	communityField := append([]byte{0x04, byte(len(communityBytes))}, communityBytes...)

	// Message: SEQUENCE { version, community, PDU }
	msgContent := append(version, communityField...)
	msgContent = append(msgContent, pdu...)
	msg := append([]byte{0x30, byte(len(msgContent))}, msgContent...)

	return msg
}

func (s *Scanner) checkSNMP(ctx context.Context, ip string) []finding.Finding {
	var findings []finding.Finding

	communities := []string{"public", "private"}
	for _, community := range communities {
		conn, err := s.dialer.DialContext(ctx, "udp", net.JoinHostPort(ip, "161"))
		if err != nil {
			continue
		}

		packet := buildSNMPGetNextPacket(community)
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, err = conn.Write(packet)
		if err != nil {
			conn.Close()
			continue
		}

		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		conn.Close()
		if err != nil {
			continue
		}

		if n > 2 && buf[0] == 0x30 {
			// Valid SNMP response received — default community accepted.
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckOnpremNetworkSNMPDefaultComm,
				Scanner:  scannerName,
				Severity: finding.SeverityCritical,
				Title:    fmt.Sprintf("SNMP default community string '%s' accepted on %s", community, ip),
				Description: fmt.Sprintf(
					"Host %s accepts SNMP GET-NEXT requests with the default community "+
						"string '%s'. An attacker can enumerate the device's configuration, "+
						"interfaces, ARP table, and routing information.",
					ip, community,
				),
				Asset:        ip,
				ProofCommand: fmt.Sprintf("snmpwalk -v2c -c %s %s 1.3.6.1.2.1.1", community, ip),
				Evidence: map[string]any{
					"ip":              ip,
					"community":       community,
					"response_length": n,
				},
				DiscoveredAt: time.Now(),
			})

			// Also emit SNMPv1/v2c finding since we're using v2c.
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckOnpremNetworkSNMPv1v2,
				Scanner:  scannerName,
				Severity: finding.SeverityHigh,
				Title:    fmt.Sprintf("SNMPv1/v2c in use on %s (cleartext community strings)", ip),
				Description: fmt.Sprintf(
					"Host %s uses SNMPv2c which sends community strings in cleartext. "+
						"Migrate to SNMPv3 with authentication and encryption.",
					ip,
				),
				Asset:        ip,
				ProofCommand: fmt.Sprintf("snmpwalk -v2c -c %s %s 1.3.6.1.2.1.1", community, ip),
				Evidence: map[string]any{
					"ip":          ip,
					"snmp_version": "v2c",
				},
				DiscoveredAt: time.Now(),
			})

			// Emit no-SNMPv3 advisory.
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckOnpremNetworkNoSNMPv3,
				Scanner:  scannerName,
				Severity: finding.SeverityMedium,
				Title:    fmt.Sprintf("SNMPv3 not in use on %s", ip),
				Description: fmt.Sprintf(
					"Host %s accepted an SNMPv2c request, suggesting SNMPv3 with "+
						"authentication and privacy is not enforced. SNMPv3 should be "+
						"configured to prevent eavesdropping and spoofing.",
					ip,
				),
				Asset:        ip,
				ProofCommand: fmt.Sprintf("snmpwalk -v3 -l authPriv -u testuser %s 1.3.6.1.2.1.1", ip),
				Evidence: map[string]any{
					"ip":             ip,
					"snmpv3_missing": true,
				},
				DiscoveredAt: time.Now(),
			})

			break // one community match is enough
		}
	}

	return findings
}

// --------------------------------------------------------------------------
// UPnP/SSDP discovery (Surface)
// --------------------------------------------------------------------------

var ssdpDiscover = "M-SEARCH * HTTP/1.1\r\n" +
	"HOST: 239.255.255.250:1900\r\n" +
	"MAN: \"ssdp:discover\"\r\n" +
	"MX: 2\r\n" +
	"ST: ssdp:all\r\n" +
	"\r\n"

func (s *Scanner) checkUPnP(ctx context.Context, ip string) []finding.Finding {
	var findings []finding.Finding

	conn, err := s.dialer.DialContext(ctx, "udp", net.JoinHostPort(ip, "1900"))
	if err != nil {
		return findings
	}

	conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = conn.Write([]byte(ssdpDiscover))
	if err != nil {
		conn.Close()
		return findings
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	conn.Close()
	if err != nil {
		return findings
	}

	response := string(buf[:n])
	if strings.Contains(response, "HTTP/1.1 200") || strings.Contains(response, "LOCATION:") || strings.Contains(response, "location:") {
		// Extract device info from response.
		server := extractHeader(response, "SERVER")
		location := extractHeader(response, "LOCATION")

		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckOnpremNetworkUPnPExposed,
			Scanner:  scannerName,
			Severity: finding.SeverityMedium,
			Title:    fmt.Sprintf("UPnP/SSDP service exposed on %s", ip),
			Description: fmt.Sprintf(
				"Host %s responds to SSDP M-SEARCH discovery. UPnP-enabled devices "+
					"can be exploited for port forwarding manipulation, DNS rebinding, "+
					"and information disclosure. Server: %s",
				ip, server,
			),
			Asset:        ip,
			ProofCommand: fmt.Sprintf("echo -e 'M-SEARCH * HTTP/1.1\\r\\nHOST: %s:1900\\r\\nMAN: \"ssdp:discover\"\\r\\nMX: 2\\r\\nST: ssdp:all\\r\\n\\r\\n' | nc -u -w2 %s 1900", ip, ip),
			Evidence: map[string]any{
				"ip":       ip,
				"server":   server,
				"location": location,
				"response": truncate(response, 1024),
			},
			DiscoveredAt: time.Now(),
		})
	}

	return findings
}

// --------------------------------------------------------------------------
// mDNS service enumeration (Surface)
// --------------------------------------------------------------------------

func (s *Scanner) checkMDNS(ctx context.Context, ip string) []finding.Finding {
	var findings []finding.Finding

	conn, err := s.dialer.DialContext(ctx, "udp", net.JoinHostPort(ip, "5353"))
	if err != nil {
		return findings
	}

	// Build a minimal mDNS query for _services._dns-sd._udp.local.
	query := buildMDNSQuery("_services._dns-sd._udp.local")

	conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = conn.Write(query)
	if err != nil {
		conn.Close()
		return findings
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	conn.Close()
	if err != nil {
		return findings
	}

	if n > 12 {
		// Parse the DNS response to check for answers.
		answerCount := binary.BigEndian.Uint16(buf[6:8])
		if answerCount > 0 {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckOnpremNetworkMDNSExposed,
				Scanner:  scannerName,
				Severity: finding.SeverityLow,
				Title:    fmt.Sprintf("mDNS service advertising on %s", ip),
				Description: fmt.Sprintf(
					"Host %s responds to mDNS queries, advertising %d services. "+
						"mDNS exposes internal service names, hostnames, and port numbers "+
						"to anyone on the local network segment.",
					ip, answerCount,
				),
				Asset:        ip,
				ProofCommand: fmt.Sprintf("dig @%s -p 5353 _services._dns-sd._udp.local PTR +short", ip),
				Evidence: map[string]any{
					"ip":            ip,
					"answer_count":  answerCount,
					"response_size": n,
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings
}

// buildMDNSQuery creates a minimal DNS query packet for the given name.
func buildMDNSQuery(name string) []byte {
	// DNS header: ID=0, QR=0, OPCODE=0, QDCOUNT=1
	header := []byte{
		0x00, 0x00, // Transaction ID
		0x00, 0x00, // Flags: standard query
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answers: 0
		0x00, 0x00, // Authority: 0
		0x00, 0x00, // Additional: 0
	}

	// Encode the query name.
	var qname []byte
	parts := strings.Split(name, ".")
	for _, part := range parts {
		qname = append(qname, byte(len(part)))
		qname = append(qname, []byte(part)...)
	}
	qname = append(qname, 0x00) // terminator

	// QTYPE=PTR (12), QCLASS=IN (1)
	qtype := []byte{0x00, 0x0c, 0x00, 0x01}

	pkt := append(header, qname...)
	pkt = append(pkt, qtype...)
	return pkt
}

// --------------------------------------------------------------------------
// Telnet management detection (Surface)
// --------------------------------------------------------------------------

func (s *Scanner) checkTelnet(ctx context.Context, ip string) []finding.Finding {
	var findings []finding.Finding

	conn, err := s.dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, "23"))
	if err != nil {
		return findings
	}
	defer conn.Close()

	// Read the banner (if any) with a short timeout.
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)

	banner := ""
	if n > 0 {
		banner = strings.TrimSpace(string(buf[:n]))
	}

	findings = append(findings, finding.Finding{
		CheckID:  finding.CheckOnpremNetworkTelnetEnabled,
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Title:    fmt.Sprintf("Telnet management interface on %s:23", ip),
		Description: fmt.Sprintf(
			"Host %s has Telnet (port 23) open. Telnet transmits credentials "+
				"in cleartext, enabling eavesdropping and credential theft. "+
				"Replace with SSH.",
			ip,
		),
		Asset:        ip,
		ProofCommand: fmt.Sprintf("nc -zv %s 23", ip),
		Evidence: map[string]any{
			"ip":     ip,
			"port":   23,
			"banner": truncate(banner, 256),
		},
		DiscoveredAt: time.Now(),
	})

	return findings
}

// --------------------------------------------------------------------------
// HTTP management without TLS (Surface)
// --------------------------------------------------------------------------

// httpMgmtPorts are common management UI ports to check for HTTP (no TLS).
var httpMgmtPorts = []int{80, 8080, 8443, 443}

func (s *Scanner) checkHTTPMgmt(ctx context.Context, ip string) []finding.Finding {
	var findings []finding.Finding

	for _, port := range httpMgmtPorts {
		url := fmt.Sprintf("http://%s:%d/", ip, port)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			continue
		}
		body := make([]byte, 4096)
		n, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		copy(body, n)
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 500 {
			serverHeader := resp.Header.Get("Server")
			title := extractHTMLTitle(string(body[:len(n)]))

			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckOnpremNetworkHTTPMgmt,
				Scanner:  scannerName,
				Severity: finding.SeverityMedium,
				Title:    fmt.Sprintf("HTTP management UI on %s:%d (no TLS)", ip, port),
				Description: fmt.Sprintf(
					"Host %s has a management web interface on port %d over plain HTTP. "+
						"Credentials and session tokens are transmitted in cleartext. "+
						"Enable HTTPS/TLS on the management interface.",
					ip, port,
				),
				Asset:        ip,
				ProofCommand: fmt.Sprintf("curl -sI http://%s:%d/", ip, port),
				Evidence: map[string]any{
					"ip":          ip,
					"port":        port,
					"status_code": resp.StatusCode,
					"server":      serverHeader,
					"title":       title,
				},
				DiscoveredAt: time.Now(),
			})
			break // one finding per host is sufficient
		}
	}

	return findings
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

// expandTarget converts a target string (IP or CIDR) into individual IPs.
// For single IPs, returns a one-element slice. For CIDRs, expands up to 256
// addresses to avoid overwhelming large ranges.
func expandTarget(target string) []string {
	if !strings.Contains(target, "/") {
		return []string{target}
	}
	_, ipNet, err := net.ParseCIDR(target)
	if err != nil {
		return []string{target}
	}

	var ips []string
	for ip := dupIP(ipNet.IP.To4()); ipNet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
		if len(ips) >= 256 {
			break
		}
	}
	return ips
}

func dupIP(ip net.IP) net.IP {
	d := make(net.IP, len(ip))
	copy(d, ip)
	return d
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// extractHeader extracts a header value from an HTTP-like response string.
func extractHeader(response, header string) string {
	lower := strings.ToLower(header)
	for _, line := range strings.Split(response, "\r\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 && strings.ToLower(strings.TrimSpace(parts[0])) == lower {
			return strings.TrimSpace(parts[1])
		}
	}
	return ""
}

// extractHTMLTitle extracts the <title> content from HTML.
func extractHTMLTitle(html string) string {
	lower := strings.ToLower(html)
	start := strings.Index(lower, "<title>")
	if start < 0 {
		return ""
	}
	start += len("<title>")
	end := strings.Index(lower[start:], "</title>")
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(html[start : start+end])
}

// truncate limits a string to maxLen characters.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
