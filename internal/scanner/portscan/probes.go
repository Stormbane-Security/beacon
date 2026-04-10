package portscan

import (
	"context"
	"fmt"
	"strings"
	"time"
	"net"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/scanlog"
)

// findingMaker creates a finding with common fields pre-populated.
// buildFindings passes this into each probe so probes don't need to know
// about the asset, module name, or timestamp.
type findingMaker func(
	checkID finding.CheckID,
	severity finding.Severity,
	title, description string,
	evidence map[string]any,
) finding.Finding

// ProbeCategory classifies how a probe detects a service. Used for
// pre-filtering so we don't waste time running HTTP probes against a
// service that sent a Redis banner.
type ProbeCategory int

const (
	// ProbeCatBanner identifies services by examining the passive banner only.
	ProbeCatBanner ProbeCategory = iota
	// ProbeCatProtocol sends protocol-specific bytes and checks the response.
	ProbeCatProtocol
	// ProbeCatHTTP makes HTTP requests (GET/POST to known paths).
	ProbeCatHTTP
	// ProbeCatTLS inspects TLS certificates, ALPN, or probes inside a TLS tunnel.
	ProbeCatTLS
)

// ServiceProbe defines a single service detection probe. Each probe knows
// how to identify one service regardless of which port it's running on.
type ServiceProbe struct {
	// Name is a human-readable identifier (e.g. "redis", "clickhouse").
	Name string

	// Category controls pre-filtering. An HTTP probe won't run against a
	// port that sent a Redis banner, and vice versa.
	Category ProbeCategory

	// DefaultPorts lists the well-known ports for this service. Used for
	// port list construction — these ports are always scanned during
	// discovery even when the target doesn't specify a port.
	DefaultPorts []int

	// Detect runs the probe against host:port and returns any findings.
	// banner is the passive banner read on connect (may be empty).
	// makeF creates findings with common fields pre-populated.
	// Returns nil if the service is not detected.
	Detect func(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding
}

// probeRegistry holds all registered service probes. buildFindings iterates
// this list for every open port.
var probeRegistry []ServiceProbe

// registerProbe adds a probe to the global registry. Called from init()
// functions in probe implementation files.
func registerProbe(p ServiceProbe) {
	probeRegistry = append(probeRegistry, p)
}

// bannerProtocol returns a short protocol label when the banner clearly
// identifies a well-known service. Returns "" when unrecognised.
// This lets runProbes skip protocol probes (e.g. Redis) when the port
// already announced itself as a different service (e.g. SMTP).
func bannerProtocol(banner string) string {
	if banner == "" {
		return ""
	}
	upper := strings.ToUpper(banner)
	switch {
	case strings.HasPrefix(upper, "220 ") && strings.Contains(upper, "SMTP"):
		return "smtp"
	case strings.HasPrefix(upper, "+OK"):
		return "pop3"
	case strings.HasPrefix(upper, "* OK") && strings.Contains(upper, "IMAP"):
		return "imap"
	case strings.HasPrefix(banner, "SSH-"):
		return "ssh"
	case strings.HasPrefix(banner, "+REDIS") || strings.HasPrefix(banner, "-ERR") || strings.HasPrefix(banner, "$"):
		return "redis"
	case strings.HasPrefix(upper, "220 ") && strings.Contains(upper, "FTP"):
		return "ftp"
	case strings.Contains(upper, "MYSQL") || isMySQLGreeting(banner):
		return "mysql"
	}
	return ""
}

// isMySQLGreeting checks if the banner looks like a MySQL protocol greeting.
// MySQL wire protocol: 3-byte length + 1-byte sequence (0x00) + 1-byte
// protocol version (0x0a). The version string follows as a NUL-terminated
// ASCII string. The old heuristic (banner[0] < 32) missed MySQL 8.0+ where
// the greeting packet is typically 70-120 bytes long (first byte 0x46-0x78).
func isMySQLGreeting(banner string) bool {
	if len(banner) < 6 {
		return false
	}
	b := []byte(banner)
	// Sequence number 0 + protocol version 10 (0x0a) is the MySQL handshake.
	return b[3] == 0x00 && b[4] == 0x0a
}

// runProbes iterates all registered probes against an open port and returns
// the combined findings. Pre-filters by category to avoid pointless work.
func runProbes(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	bannerHTTP := looksLikeHTTP(banner)
	hasBanner := banner != ""
	bannerProto := bannerProtocol(banner)

	// When no banner was received, the service might be HTTP (which doesn't
	// send data until a request arrives) or a protocol service that waits for
	// the client to speak first. Do a quick HTTP check: one request (~5s max)
	// versus running ~35 protocol probes serially (~175s of timeouts).
	if !hasBanner {
		if quickHTTPCheck(ctx, host, port) {
			bannerHTTP = true
		} else if proto := quickProtocolCheck(ctx, host, port); proto != "" {
			// Identified a non-HTTP protocol via quick handshake (Redis PING,
			// MySQL greeting, etc.). This prevents 100+ protocol probes from
			// timing out against an already-identified service.
			bannerProto = proto
		}
		// Either way, we now know something about the port. Enable pre-filtering
		// so HTTP probes are skipped on non-HTTP ports (and vice versa). Without
		// this, all ~116 probes run serially against every no-banner port.
		hasBanner = true
	}

	// Check if port speaks TLS (cached — one handshake per host:port).
	// TLS probes are skipped entirely on non-TLS ports, saving 5s+ per probe.
	portIsTLS := isTLSCapable(ctx, host, port)

	// Capture JA3S fingerprint for TLS-enabled ports (uses cache, no extra handshake).
	var ja3s *JA3SResult
	if portIsTLS {
		ja3s = JA3SFingerprint(ctx, host, port)
	}

	// Split probes into protocol (run in parallel) and non-protocol (run after).
	var protocolProbes, otherProbes []ServiceProbe
	for _, probe := range probeRegistry {
		// Skip TLS probes on non-TLS ports — avoids 5s handshake timeout per probe.
		if probe.Category == ProbeCatTLS && !portIsTLS {
			continue
		}
		if hasBanner {
			if probe.Category == ProbeCatHTTP && !bannerHTTP {
				continue
			}
			if probe.Category == ProbeCatProtocol && bannerHTTP {
				continue
			}
			if probe.Category == ProbeCatProtocol && bannerProto != "" && !strings.Contains(probe.Name, bannerProto) {
				continue
			}
		}
		if probe.Category == ProbeCatProtocol {
			protocolProbes = append(protocolProbes, probe)
		} else {
			otherProbes = append(otherProbes, probe)
		}
	}

	var findings []finding.Finding
	identified := false

	// Run protocol probes in parallel — each opens its own TCP connection,
	// sends a handshake, and checks the response. A port runs one service,
	// so once any probe identifies it, cancel the rest via context.
	// Limit concurrency to avoid tripping IDS port-scan signatures.
	const maxProbeParallel = 5
	if len(protocolProbes) > 0 {
		type probeResult struct {
			probe    ServiceProbe
			findings []finding.Finding
		}
		// Cancel remaining probes once one identifies the service.
		probeCtx, probeCancel := context.WithCancel(ctx)
		defer probeCancel()
		resultCh := make(chan probeResult, len(protocolProbes))
		sem := make(chan struct{}, maxProbeParallel)
		for _, p := range protocolProbes {
			go func(probe ServiceProbe) {
				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-probeCtx.Done():
					resultCh <- probeResult{probe: probe}
					return
				}
				probeStart := time.Now()
				fs := probe.Detect(probeCtx, host, port, banner, makeF)
				scanlog.FromContext(ctx).ProbeTimed(scannerName, fmt.Sprintf("%s:%d", host, port), probe.Name, time.Since(probeStart), len(fs), nil)
				resultCh <- probeResult{probe: probe, findings: fs}
			}(p)
		}
		for range protocolProbes {
			pr := <-resultCh
			if len(pr.findings) > 0 {
				findings = append(findings, pr.findings...)
				if !identified {
					identified = true
					probeCancel() // cancel remaining protocol probes
					service := pr.probe.Name
					version := ""
					if ev := pr.findings[0].Evidence; ev != nil {
						if s, ok := ev["service"].(string); ok && s != "" {
							service = s
						}
						if v, ok := ev["version"].(string); ok && v != "" {
							version = v
						}
					}
					ev := map[string]any{
						"port":    port,
						"service": service,
						"probe":   pr.probe.Name,
					}
					if version != "" {
						ev["version"] = version
					}
					if banner != "" {
						ev["banner"] = banner
					}
					title := fmt.Sprintf("%s identified on port %d", service, port)
					if version != "" {
						title = fmt.Sprintf("%s %s identified on port %d", service, version, port)
					}
					findings = append(findings, makeF(
						finding.CheckPortServiceIdentified,
						finding.SeverityInfo,
						title,
						fmt.Sprintf("Wire-protocol probe confirmed %s is running on port %d. "+
							"This identification is based on active protocol handshake, not port number assumption.", service, port),
						ev,
					))
				}
			}
		}
	}

	// Run banner and HTTP probes sequentially (they're I/O-light or
	// already filtered to the correct category).
	// Skip DB probes if we already identified the service as a specific DB
	// (e.g., don't try MySQL/PostgreSQL/MSSQL on a port we know is MongoDB).
	identifiedService := ""
	if identified {
		identifiedService = "protocol-probe" // protocol probes already found something
	}
	for _, probe := range otherProbes {
		// Skip relational DB probes if service was already identified
		// (e.g., don't try MySQL/PostgreSQL/MSSQL on a port we know is MongoDB/Redis)
		if identifiedService != "" && probe.Name == "mysql-postgres-mssql-oracle" {
			continue
		}
		// Skip exploit playbook probes that don't match the identified service.
		// Exploit probes have names like "redis-exploit", "consul-exploit" etc.
		// If we already know the service (e.g., "couchdb"), skip "redis-exploit".
		if identifiedService != "" && strings.HasSuffix(probe.Name, "-exploit") {
			svcPrefix := strings.TrimSuffix(probe.Name, "-exploit")
			if !strings.Contains(identifiedService, svcPrefix) {
				continue
			}
		}
		probeStart := time.Now()
		fs := probe.Detect(ctx, host, port, banner, makeF)
		scanlog.FromContext(ctx).ProbeTimed(scannerName, fmt.Sprintf("%s:%d", host, port), probe.Name, time.Since(probeStart), len(fs), nil)
		if len(fs) > 0 {
			findings = append(findings, fs...)
			identifiedService = probe.Name
			if !identified {
				identified = true
				service := probe.Name
				version := ""
				if ev := fs[0].Evidence; ev != nil {
					if s, ok := ev["service"].(string); ok && s != "" {
						service = s
					}
					if v, ok := ev["version"].(string); ok && v != "" {
						version = v
					}
				}
				ev := map[string]any{
					"port":    port,
					"service": service,
					"probe":   probe.Name,
				}
				if version != "" {
					ev["version"] = version
				}
				if banner != "" {
					ev["banner"] = banner
				}
				// For HTTP-category probes, enrich with Server header and page title.
				if probe.Category == ProbeCatHTTP {
					enrichHTTPEvidence(ctx, host, port, ev)
				}
				title := fmt.Sprintf("%s identified on port %d", service, port)
				if version != "" {
					title = fmt.Sprintf("%s %s identified on port %d", service, version, port)
				}
				findings = append(findings, makeF(
					finding.CheckPortServiceIdentified,
					finding.SeverityInfo,
					title,
					fmt.Sprintf("Wire-protocol probe confirmed %s is running on port %d. "+
						"This identification is based on active protocol handshake, not port number assumption.", service, port),
					ev,
				))
			}
		}
	}

	// Fallback: if HTTP was confirmed but no specific probe matched, emit a
	// generic "http" service identification. This ensures the postexploit
	// chain can route HTTP-based exploit modules (apache-rce, spring4shell,
	// etc.) even on non-standard ports with no recognized web application.
	if !identified && bannerHTTP {
		ev := map[string]any{
			"port":    port,
			"service": "http",
			"probe":   "http-fallback",
		}
		if banner != "" {
			ev["banner"] = banner
		}
		// Extract HTTP title and Server header version for the fallback HTTP finding.
		enrichHTTPEvidence(ctx, host, port, ev)
		findings = append(findings, makeF(
			finding.CheckPortServiceIdentified,
			finding.SeverityInfo,
			fmt.Sprintf("http identified on port %d", port),
			fmt.Sprintf("HTTP service confirmed on port %d via active probe, but no specific "+
				"web application was identified.", port),
			ev,
		))
	}

	// Enrich all service_identified findings with JA3S / cert evidence and
	// emit TLS-specific findings (weak cipher, expired cert) when applicable.
	if ja3s != nil {
		tlsEv := TLSInfoEvidence(ja3s)

		// Merge JA3S evidence into every service_identified finding for this port.
		for i := range findings {
			if findings[i].CheckID == finding.CheckPortServiceIdentified {
				for k, v := range tlsEv {
					findings[i].Evidence[k] = v
				}
			}
		}

		// Check: server negotiated a weak / insecure cipher suite.
		if isWeakCipherSuite(ja3s.CipherSuite) {
			name := cipherSuiteName(ja3s.CipherSuite)
			findings = append(findings, makeF(
				finding.CheckTLSWeakCipherNegotiated,
				finding.SeverityHigh,
				fmt.Sprintf("Weak TLS cipher negotiated on port %d: %s", port, name),
				fmt.Sprintf("The server on port %d negotiated cipher suite %s (0x%04X) which is "+
					"considered insecure. An attacker on the network path may be able to "+
					"decrypt or tamper with traffic.", port, name, ja3s.CipherSuite),
				map[string]any{
					"port":            port,
					"cipher_suite":    name,
					"cipher_suite_id": ja3s.CipherSuite,
					"tls_version":     tlsVersionName(ja3s.TLSVersion),
					"ja3s_hash":       ja3s.Hash,
					"proof_command":   fmt.Sprintf("openssl s_client -connect %s:%d", host, port),
				},
			))
		}

		// Check: certificate has expired.
		if !ja3s.NotAfter.IsZero() && ja3s.NotAfter.Before(time.Now()) {
			findings = append(findings, makeF(
				finding.CheckTLSExpiredCertDetected,
				finding.SeverityHigh,
				fmt.Sprintf("Expired TLS certificate on port %d", port),
				fmt.Sprintf("The TLS certificate on port %d expired on %s. Expired certificates "+
					"cause browser warnings, break automated clients, and indicate the service "+
					"may be unmaintained.", port, ja3s.NotAfter.Format("2006-01-02")),
				map[string]any{
					"port":           port,
					"cert_cn":        ja3s.ServerName,
					"cert_issuer":    ja3s.Issuer,
					"cert_not_after": ja3s.NotAfter.Format(time.RFC3339),
					"ja3s_hash":      ja3s.Hash,
					"proof_command":  fmt.Sprintf("openssl s_client -connect %s:%d | openssl x509 -noout -dates", host, port),
				},
			))
		}
	}

	return findings
}

// quickProtocolCheck sends lightweight protocol handshakes concurrently to
// identify non-HTTP services that don't send a banner on connect. This prevents
// 100+ protocol probes from timing out against already-identifiable services.
// Returns the protocol name (e.g., "redis", "mysql") or "" if unknown.
// All checks run in parallel with a short timeout, so worst case is ~1.5s.
func quickProtocolCheck(ctx context.Context, host string, port int) string {
	addr := fmt.Sprintf("%s:%d", host, port)
	const quickTimeout = 1500 * time.Millisecond
	dialer := &net.Dialer{Timeout: quickTimeout}

	type checkResult struct {
		proto string
	}
	ch := make(chan checkResult, 6)

	// Redis: send PING, expect +PONG
	go func() {
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			ch <- checkResult{}
			return
		}
		_ = conn.SetDeadline(time.Now().Add(quickTimeout))
		_, _ = conn.Write([]byte("PING\r\n"))
		buf := make([]byte, 64)
		n, _ := conn.Read(buf)
		_ = conn.Close()
		resp := string(buf[:n])
		if strings.HasPrefix(resp, "+PONG") || strings.HasPrefix(resp, "-NOAUTH") || strings.HasPrefix(resp, "-ERR") {
			ch <- checkResult{"redis"}
			return
		}
		ch <- checkResult{}
	}()

	// MySQL: connect and read greeting packet (server sends it first)
	go func() {
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			ch <- checkResult{}
			return
		}
		_ = conn.SetDeadline(time.Now().Add(quickTimeout))
		buf := make([]byte, 128)
		n, _ := conn.Read(buf)
		_ = conn.Close()
		if n > 4 && buf[3] == 0x00 && buf[4] == 0x0a {
			ch <- checkResult{"mysql"}
			return
		}
		ch <- checkResult{}
	}()

	// PostgreSQL: send SSLRequest, check for 'N' or 'S' response
	go func() {
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			ch <- checkResult{}
			return
		}
		_ = conn.SetDeadline(time.Now().Add(quickTimeout))
		_, _ = conn.Write([]byte{0, 0, 0, 8, 4, 210, 22, 47})
		buf := make([]byte, 8)
		n, _ := conn.Read(buf)
		_ = conn.Close()
		if n >= 1 && (buf[0] == 'N' || buf[0] == 'S') {
			ch <- checkResult{"postgres"}
			return
		}
		ch <- checkResult{}
	}()

	// SMTP: wait for 220 banner
	go func() {
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			ch <- checkResult{}
			return
		}
		_ = conn.SetDeadline(time.Now().Add(quickTimeout))
		buf := make([]byte, 128)
		n, _ := conn.Read(buf)
		_ = conn.Close()
		if n > 3 && strings.HasPrefix(string(buf[:n]), "220 ") {
			ch <- checkResult{"smtp"}
			return
		}
		ch <- checkResult{}
	}()

	// MongoDB: send isMaster command, check for valid BSON response
	go func() {
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			ch <- checkResult{}
			return
		}
		_ = conn.SetDeadline(time.Now().Add(quickTimeout))
		// MongoDB OP_MSG: isMaster command (minimal wire protocol v2 message)
		// Header: length(4) + requestID(4) + responseTo(4) + opCode=2013(4)
		// flagBits(4) + section kind=0(1) + BSON document
		isMasterDoc := []byte{
			// BSON document: {"isMaster": 1, "$db": "admin"}
			0x27, 0x00, 0x00, 0x00, // doc length = 39
			0x10,                                           // type: int32
			0x69, 0x73, 0x4d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00, // "isMaster\0"
			0x01, 0x00, 0x00, 0x00, // value: 1
			0x02,                                     // type: string
			0x24, 0x64, 0x62, 0x00,                   // "$db\0"
			0x06, 0x00, 0x00, 0x00,                   // string length = 6
			0x61, 0x64, 0x6d, 0x69, 0x6e, 0x00,      // "admin\0"
			0x00, // document terminator
		}
		msgLen := 4 + 4 + 4 + 4 + 4 + 1 + len(isMasterDoc) // header + flagBits + section kind + doc
		msg := make([]byte, msgLen)
		// Little-endian length
		msg[0] = byte(msgLen)
		msg[1] = byte(msgLen >> 8)
		msg[2] = byte(msgLen >> 16)
		msg[3] = byte(msgLen >> 24)
		// requestID = 1
		msg[4] = 0x01
		// responseTo = 0 (bytes 8-11 already zero)
		// opCode = 2013 (OP_MSG)
		msg[12] = 0xdd
		msg[13] = 0x07
		// flagBits = 0 (bytes 16-19 already zero)
		// section kind = 0
		msg[20] = 0x00
		copy(msg[21:], isMasterDoc)

		_, _ = conn.Write(msg)
		buf := make([]byte, 256)
		n, _ := conn.Read(buf)
		_ = conn.Close()
		// MongoDB response: valid if length >= 16, opCode is 2013 (OP_MSG) or 1 (OP_REPLY)
		if n >= 16 {
			opCode := uint32(buf[12]) | uint32(buf[13])<<8 | uint32(buf[14])<<16 | uint32(buf[15])<<24
			if opCode == 2013 || opCode == 1 {
				ch <- checkResult{"mongodb"}
				return
			}
		}
		ch <- checkResult{}
	}()

	// SSH: wait for "SSH-" banner (some SSH servers are slow to send)
	go func() {
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			ch <- checkResult{}
			return
		}
		_ = conn.SetDeadline(time.Now().Add(quickTimeout))
		buf := make([]byte, 64)
		n, _ := conn.Read(buf)
		_ = conn.Close()
		if n >= 4 && strings.HasPrefix(string(buf[:n]), "SSH-") {
			ch <- checkResult{"ssh"}
			return
		}
		ch <- checkResult{}
	}()

	// Collect results — return first positive match, or "" after all finish
	for i := 0; i < 6; i++ {
		r := <-ch
		if r.proto != "" {
			return r.proto
		}
	}
	return ""
}
