// Package portscan implements a pure-Go TCP connect port scanner with service
// identification and unauthenticated-access probing for high-value services.
// No external binaries are required.
package portscan

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const scannerName = "portscan"

// timeouts for the various probe stages.
const (
	dialTimeout   = 3 * time.Second
	bannerTimeout = 2 * time.Second
	httpTimeout   = 5 * time.Second
)

// defaultConcurrency is the number of ports probed simultaneously.
// 5 is a conservative ceiling that keeps concurrent SYN packets below the
// threshold most IDS/IPS engines use to trigger port-scan signatures
// (typically 10–15 half-open connections per second from a single source).
// Deep mode uses the same limit; the larger port list naturally takes longer.
const defaultConcurrency = 5

// interConnectDelay is the pause between acquiring the semaphore and dialling.
// Spreading connects by 50 ms per slot avoids the burst of simultaneous SYN
// packets that triggers stateful IDS engines even at low concurrency.
const interConnectDelay = 50 * time.Millisecond

// portEntry describes a single port that the scanner knows about.
type portEntry struct {
	port        int
	service     string
	criticalOnly bool // included in surface (critical) scan, not just deep
}

// criticalPorts are always scanned (surface + deep). Ordered by impact.
var criticalPorts = []portEntry{
	{6379, "redis", true},
	{9200, "elasticsearch", true},
	{2375, "docker", true},
	{10250, "kubelet", true},
	{27017, "mongodb", true},
	{9090, "prometheus", true},
	{5432, "postgresql", true},
	{3306, "mysql", true},
	{3389, "rdp", true},
	{5900, "vnc", true},
	{23, "telnet", true},
}

// highPorts are included in surface scans alongside critical ports.
var highPorts = []portEntry{
	{21, "ftp", false},
	{22, "ssh", false},
	{445, "smb", false},
	{1433, "mssql", false},
	{1521, "oracle", false},
	{2376, "docker-tls", false},
	{2379, "etcd", false},
	{5672, "amqp", false},
	{5985, "winrm-http", false},
	{5986, "winrm-https", false},
	{6443, "k8s-api", false},
	{8001, "k8s-proxy", false},
	{8089, "splunk-mgmt", false},
	{8160, "juniper-adf", false},  // Juniper PTX On-Box Anomaly Detection Framework (CVE-2026-21902)
	{11434, "ollama", false},      // Ollama LLM inference server (no auth by default)
	{1883, "mqtt", false},         // MQTT broker (plaintext, often no auth)
	{5060, "sip", false},          // SIP VoIP server
	{554, "rtsp", false},          // RTSP video streams / IP cameras
	{631, "ipp", false},           // IPP network printing
	{3260, "iscsi", false},        // iSCSI storage target
	{502, "modbus", false},        // Modbus TCP SCADA/ICS
	{830, "netconf", false},       // NETCONF network device management
	{8291, "winbox", false},       // MikroTik Winbox management
	{623, "ipmi", false},          // IPMI/BMC server management
	{8443, "https-alt", false},    // HTTPS alt (network device web UIs)
	{8200, "vault", false},
	{8500, "consul", false},
	{5601, "kibana", false},
	{5984, "couchdb", false},
	{9042, "cassandra", false},
	{9092, "kafka", false},
	{11211, "memcached", false},
	{8888, "jupyter", false},
	{9300, "elasticsearch-transport", false},
	{15672, "rabbitmq-mgmt", false},
	{28017, "mongodb-http", false},
	// Email servers — SMTP (submission) and IMAP exposed to internet
	{25, "smtp", false},           // SMTP MTA port — banner reveals software/version
	{587, "smtp-submission", false}, // SMTP submission — often auth-required
	{143, "imap", false},          // IMAP mail access
	{993, "imaps", false},         // IMAP over TLS
	{110, "pop3", false},          // POP3 mail access
	{995, "pop3s", false},         // POP3 over TLS
	// Directory services — LDAP/AD/Kerberos exposed to internet is critical
	{389, "ldap", false},          // LDAP — null bind reveals domain info
	{636, "ldaps", false},         // LDAP over TLS
	{88, "kerberos", false},       // Kerberos KDC — confirms AD domain controller
	{3268, "gc", false},           // AD Global Catalog
	{3269, "gc-ssl", false},       // AD Global Catalog over TLS
	// Erlang/OTP ecosystem
	{4369, "epmd", false},         // Erlang Port Mapper Daemon — lists all Erlang nodes unauthenticated
	// DNS servers
	{53, "dns", false},            // DNS server — open resolver test, version disclosure
	// WINS / NetBIOS name service
	{1512, "wins", false},         // WINS server — Samba CVE-2025-10230 context
}

// extendedPorts are added in deep mode only.
var extendedPorts = []portEntry{
	{2181, "zookeeper", false},
	{4567, "sinatra", false},
	{4848, "glassfish-admin", false},
	{7001, "weblogic", false}, // also in webServicePorts; CVE-2026-21962 CVSS 10.0 warrants deep coverage
	{7474, "neo4j", false},
	{8080, "http-alt", false},
	{8086, "influxdb", false},
	// 8443 is already in highPorts; no duplicate here.
	{9000, "sonarqube", false},
	{9001, "minio-console", false},
	{9043, "websphere-admin", false},
	{9091, "prometheus-pushgateway", false},
	{9100, "jetdirect", false},    // JetDirect/PJL raw print — also used for Prometheus node-exporter
	// Port 9200 is shared by Elasticsearch and OpenSearch; already declared above as "elasticsearch".
	{2049, "nfs", false},
	{111, "rpcbind", false},
	{4200, "angular-dev", false},
	{5000, "flask-dev", false},
	{3000, "node-dev", false},
	{16686, "jaeger-ui", false},
	{5173, "vite-dev", false},     // Vite dev server — common in staging/CI
	{7860, "gradio", false},       // Gradio ML demo server
	{3001, "anythingllm", false},  // AnythingLLM (default port)
	{10000, "webmin", false},      // Webmin server management
	{19999, "netdata", false},     // Netdata monitoring
	{55000, "wazuh-api", false},   // Wazuh security platform API
	{9401, "veeam-mgmt", false},   // Veeam Backup & Replication
	{9419, "veeam-catalog", false}, // Veeam Catalog Service
	// ── Industrial Control Systems (ICS/SCADA/OT) ──────────────────────────
	{102, "s7comm", false},        // Siemens S7 PLC (COTP/ISO-on-TCP) — CRITICAL, any exposure
	{44818, "ethernet-ip", false}, // EtherNet/IP (Rockwell/Allen-Bradley) PLCs — CRITICAL
	{20000, "dnp3", false},        // DNP3 electric utility SCADA — CRITICAL
	{47808, "bacnet", false},      // BACnet building automation — HIGH
	// ── Telecom / VoIP ─────────────────────────────────────────────────────
	{5038, "asterisk-ami", false}, // Asterisk Manager Interface — plaintext admin API
	{4569, "iax2", false},         // IAX2 (Inter-Asterisk eXchange) VoIP
	// ── Network device management ───────────────────────────────────────────
	{8728, "routeros-api", false}, // MikroTik RouterOS API (plaintext)
	{264, "checkpoint-topology", false}, // Check Point FW-1 topology / cpstat discovery
	{179, "bgp", false},               // BGP routing protocol — internet-facing router exposure
}

// Scanner is a pure-Go TCP connect port scanner.
// When nmapBin is set, nmap is run after the TCP connect scan for service
// version detection and NSE script checks.
type Scanner struct {
	nmapBin string
}

// New returns a new Scanner without nmap integration.
func New() *Scanner { return &Scanner{} }

// NewWithNmap returns a Scanner that runs nmap against confirmed open ports
// after the pure-Go TCP connect phase. nmapBin must be an absolute path to
// the nmap binary (e.g. "/usr/bin/nmap"). Pass "" to disable nmap.
func NewWithNmap(nmapBin string) *Scanner { return &Scanner{nmapBin: nmapBin} }

// AllKnownPorts returns the set of all port numbers covered by the static port
// lists (critical + high + extended). Used by the AI port advisor to avoid
// re-suggesting ports that are already scanned by default.
func AllKnownPorts() []int {
	all := append(append(criticalPorts, highPorts...), extendedPorts...)
	ports := make([]int, 0, len(all))
	for _, e := range all {
		ports = append(ports, e.port)
	}
	return ports
}

// Name returns the scanner identifier.
func (s *Scanner) Name() string { return scannerName }

// Run executes the port scan against asset, returning all findings.
// Surface mode scans the top 30 most impactful ports (critical + high).
// Deep mode scans all 50+ ports including the extended list.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	ports := buildPortList(scanType)

	type result struct {
		entry portEntry
		open  bool
		banner string
	}

	results := make(chan result, len(ports))
	sem := make(chan struct{}, defaultConcurrency)
	var wg sync.WaitGroup

	for _, entry := range ports {
		// Stagger goroutine launches before starting each one. Placing the delay
		// here (not inside the goroutine) ensures SYN packets are spread across
		// time even when multiple semaphore slots are available simultaneously.
		// At 50 ms per port with 30 ports this adds ~1.5 s overhead — acceptable
		// for a scan that would otherwise fire 30 near-simultaneous SYNs.
		select {
		case <-ctx.Done():
			goto collectResults
		case <-time.After(interConnectDelay):
		}

		wg.Add(1)
		go func(e portEntry) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			open, banner := probePort(ctx, asset, e.port)
			results <- result{entry: e, open: open, banner: banner}
		}(entry)
	}

collectResults:
	go func() {
		wg.Wait()
		close(results)
	}()

	var findings []finding.Finding
	openPorts := make(map[int]string)
	for r := range results {
		if !r.open {
			continue
		}
		openPorts[r.entry.port] = r.entry.service
		fs := buildFindings(ctx, asset, r.entry, r.banner)
		findings = append(findings, fs...)
		// Emit a service-discovered hint for web-like services on non-standard ports.
		// The surface module picks these up to schedule a full per-port classify pass.
		if hint := EmitPortServiceDiscovered(asset, r.entry.port, r.entry.service, r.banner); hint != nil {
			findings = append(findings, *hint)
		}
	}

	// Run nmap against confirmed open ports for service version + NSE scripts.
	// Nmap results supplement (not replace) the pure-Go scan findings — Go TCP
	// findings are always emitted regardless of whether nmap is available.
	if nmapFs := s.runNmap(ctx, asset, openPorts, scanType); len(nmapFs) > 0 {
		findings = append(findings, nmapFs...)
	}

	// Run UDP probes for services not reachable via TCP connect.
	if ctx.Err() == nil {
		if udpFs := runUDP(ctx, asset); len(udpFs) > 0 {
			findings = append(findings, udpFs...)
		}
	}

	return findings, nil
}

// buildPortList assembles the ordered port list for the given scan type.
func buildPortList(scanType module.ScanType) []portEntry {
	ports := make([]portEntry, 0, len(criticalPorts)+len(highPorts)+len(extendedPorts))
	ports = append(ports, criticalPorts...)
	ports = append(ports, highPorts...)
	if scanType == module.ScanDeep {
		ports = append(ports, extendedPorts...)
	}
	return ports
}

// probePort attempts a TCP connection to host:port.
// Returns (open, banner). The banner may be empty.
func probePort(ctx context.Context, host string, port int) (bool, string) {
	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, ""
	}
	defer conn.Close()

	// Attempt a passive banner grab: set a short read deadline and read whatever
	// the server sends before we've said anything.
	_ = conn.SetDeadline(time.Now().Add(bannerTimeout))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	banner := strings.TrimSpace(string(buf[:n]))
	return true, banner
}

// buildFindings interprets an open port and returns the appropriate findings.
// For high-value services it performs a deeper probe; others are flagged on
// connectivity alone.
func buildFindings(ctx context.Context, asset string, entry portEntry, banner string) []finding.Finding {
	port := entry.port
	service := entry.service
	now := time.Now()

	makeF := func(
		checkID finding.CheckID,
		severity finding.Severity,
		title, description string,
		evidence map[string]any,
	) finding.Finding {
		return finding.Finding{
			CheckID:      checkID,
			Module:       "surface",
			Scanner:      scannerName,
			Severity:     severity,
			Title:        title,
			Description:  description,
			Asset:        asset,
			Evidence:     evidence,
			DiscoveredAt: now,
		}
	}

	switch port {

	// ── Unauthenticated datastore probes ──────────────────────────────────────

	case 6379: // Redis
		unauth, redisVersion := probeRedis(ctx, asset, port)
		if unauth {
			ev := map[string]any{"port": port, "service": service, "authenticated": false, "banner": banner}
			if redisVersion != "" {
				ev["redis_version"] = redisVersion
			}
			findings := []finding.Finding{makeF(
				finding.CheckPortRedisUnauth,
				finding.SeverityCritical,
				fmt.Sprintf("Unauthenticated Redis exposed on port %d", port),
				"A Redis instance is accepting connections without authentication. "+
					"An attacker can read, write, or delete all cached data, potentially "+
					"achieving remote code execution via CONFIG SET and cron jobs.",
				ev,
			)}
			// CVE-2025-49844: unauthenticated RCE via Lua scripting in unpatched versions.
			if redisVersion != "" && isVulnerableRedis(redisVersion) {
				cveEv := map[string]any{"port": port, "service": service, "redis_version": redisVersion, "cve": "CVE-2025-49844"}
				findings = append(findings, makeF(
					finding.CheckPortRedisVulnerableCVE2025,
					finding.SeverityCritical,
					fmt.Sprintf("Redis %s is vulnerable to CVE-2025-49844 (unauthenticated RCE)", redisVersion),
					"CVE-2025-49844 (CVSS 9.8) allows an unauthenticated attacker to execute arbitrary commands "+
						"on the Redis server via crafted Lua scripts. Patched in 7.2.11, 7.4.6, 8.0.4, 8.2.2. "+
						"Combined with unauthenticated access, this enables full server compromise without credentials.",
					cveEv,
				))
			}
			return findings
		}

	case 9200: // Elasticsearch or OpenSearch — both use port 9200
		body, ok := probeHTTPBody(ctx, asset, port, false, "/")
		if ok {
			// Distinguish OpenSearch from Elasticsearch via the root response.
			// OpenSearch includes "distribution":"opensearch" in the version object.
			// Fall back to "Elasticsearch" label when not identifiable.
			serviceName := "Elasticsearch"
			serviceLabel := "Unauthenticated Elasticsearch"
			description := "An Elasticsearch cluster is accessible without credentials. " +
				"All indexed data can be read, modified, or deleted by anyone with network access."
			if strings.Contains(strings.ToLower(body), "opensearch") {
				serviceName = "OpenSearch"
				serviceLabel = "Unauthenticated OpenSearch"
				description = "An OpenSearch cluster is accessible without credentials. " +
					"All indexed data can be read, modified, or deleted by anyone with network access."
			}
			return []finding.Finding{makeF(
				finding.CheckPortElasticsearchUnauth,
				finding.SeverityCritical,
				fmt.Sprintf("%s exposed on port %d", serviceLabel, port),
				description,
				map[string]any{"port": port, "service": serviceName, "authenticated": false, "banner": banner},
			)}
		}

	case 9090: // Prometheus
		unauth := probeHTTP(ctx, asset, port, false, "/api/v1/targets")
		if unauth {
			return []finding.Finding{makeF(
				finding.CheckPortPrometheusUnauth,
				finding.SeverityCritical,
				fmt.Sprintf("Unauthenticated Prometheus exposed on port %d", port),
				"A Prometheus metrics server is accessible without authentication. "+
					"Internal infrastructure topology, host names, and service metadata are exposed.",
				map[string]any{"port": port, "service": service, "authenticated": false, "banner": banner},
			)}
		}

	case 2375: // Docker daemon (plain HTTP)
		unauth := probeHTTP(ctx, asset, port, false, "/v1.24/version")
		if unauth {
			return []finding.Finding{makeF(
				finding.CheckPortDockerUnauth,
				finding.SeverityCritical,
				fmt.Sprintf("Unauthenticated Docker daemon exposed on port %d", port),
				"The Docker daemon API is reachable over plain TCP without TLS or authentication. "+
					"A remote attacker can spawn privileged containers and gain full host control.",
				map[string]any{"port": port, "service": service, "authenticated": false, "banner": banner},
			)}
		}

	case 10250: // Kubelet
		unauth := probeHTTP(ctx, asset, port, true, "/pods")
		if unauth {
			return []finding.Finding{makeF(
				finding.CheckPortKubeletUnauth,
				finding.SeverityCritical,
				fmt.Sprintf("Unauthenticated Kubelet API exposed on port %d", port),
				"The Kubernetes Kubelet API is reachable without authentication. "+
					"An attacker can enumerate running pods and execute commands inside containers.",
				map[string]any{"port": port, "service": service, "authenticated": false, "banner": banner},
			)}
		}

	case 11211: // Memcached
		unauth := probeMemcached(ctx, asset, port)
		if unauth {
			return []finding.Finding{makeF(
				finding.CheckPortMemcachedUnauth,
				finding.SeverityCritical,
				fmt.Sprintf("Unauthenticated Memcached exposed on port %d", port),
				"A Memcached instance is accessible without authentication. "+
					"Cache contents (which may include session tokens or PII) can be read or poisoned.",
				map[string]any{"port": port, "service": service, "authenticated": false, "banner": banner},
			)}
		}

	case 8888: // Jupyter
		exposed := probeJupyter(ctx, asset, port)
		if exposed {
			return []finding.Finding{makeF(
				finding.CheckPortJupyterExposed,
				finding.SeverityCritical,
				fmt.Sprintf("Jupyter Notebook exposed on port %d", port),
				"A Jupyter Notebook server is publicly accessible. "+
					"Jupyter provides arbitrary code execution and full filesystem access to the server.",
				map[string]any{"port": port, "service": service, "authenticated": false, "banner": banner},
			)}
		}

	case 5984: // CouchDB
		unauth := probeHTTP(ctx, asset, port, false, "/_all_dbs")
		if unauth {
			return []finding.Finding{makeF(
				finding.CheckPortCouchDBUnauth,
				finding.SeverityCritical,
				fmt.Sprintf("Unauthenticated CouchDB exposed on port %d", port),
				"A CouchDB instance is accessible without authentication. "+
					"All databases and their documents can be read, modified, or deleted.",
				map[string]any{"port": port, "service": service, "authenticated": false, "banner": banner},
			)}
		}

	case 27017: // MongoDB
		unauth := probeMongoDB(ctx, asset, port)
		if unauth {
			return []finding.Finding{makeF(
				finding.CheckPortDatabaseExposed,
				finding.SeverityCritical,
				fmt.Sprintf("Unauthenticated MongoDB exposed on port %d", port),
				"A MongoDB instance is accepting connections without authentication. "+
					"All collections and documents are readable and writable by any network client.",
				map[string]any{"port": port, "service": service, "authenticated": false, "banner": banner},
			)}
		}

	// ── Critical exposure — open = finding ───────────────────────────────────

	case 3389: // RDP
		return []finding.Finding{makeF(
			finding.CheckPortRDPExposed,
			finding.SeverityCritical,
			fmt.Sprintf("RDP (Remote Desktop) exposed on port %d", port),
			"Remote Desktop Protocol is publicly accessible. "+
				"RDP has a history of critical vulnerabilities (BlueKeep, DejaBlue) and is a top ransomware entry vector.",
			map[string]any{"port": port, "service": service, "banner": banner},
		)}

	case 5900: // VNC
		return []finding.Finding{makeF(
			finding.CheckPortVNCExposed,
			finding.SeverityCritical,
			fmt.Sprintf("VNC exposed on port %d", port),
			"A VNC remote desktop server is publicly accessible. "+
				"VNC is frequently deployed without authentication and provides full graphical desktop access.",
			map[string]any{"port": port, "service": service, "banner": banner},
		)}

	// ── SSH ───────────────────────────────────────────────────────────────────

	case 22:
		ev := map[string]any{"port": port, "service": service, "banner": banner}
		sv := parseSSHVersion(banner)
		if sv != "" {
			ev["ssh_software"] = sv
		}
		// Vendor detection via SSH banner.
		// These are Info-level identification findings; the playbook engine uses
		// them to trigger network-device-specific scan modules.
		var netDevFindings []finding.Finding
		lsv := strings.ToLower(sv + " " + banner)
		switch {
		case strings.Contains(lsv, "cisco"):
			netDevFindings = append(netDevFindings, makeF(
				finding.CheckNetDeviceCiscoDetected,
				finding.SeverityInfo,
				"Cisco network device identified via SSH banner",
				"The SSH banner indicates this is a Cisco IOS, NX-OS, or ASA device. "+
					"Cisco network equipment commonly has SSH/Telnet management, SNMP, and HTTP management interfaces. "+
					"Check for default credentials, known CVEs, and unnecessary management protocol exposure.",
				ev,
			))
		case strings.Contains(lsv, "junos") || strings.Contains(lsv, "juniper"):
			netDevFindings = append(netDevFindings, makeF(
				finding.CheckNetDeviceJuniperDetected,
				finding.SeverityInfo,
				"Juniper JunOS network device identified via SSH banner",
				"The SSH banner indicates this is a Juniper Networks device running JunOS. "+
					"Check for NETCONF (port 830), J-Web management interface, and SNMP exposure.",
				ev,
			))
		case strings.Contains(lsv, "rosssh") || strings.Contains(lsv, "mikrotik"):
			netDevFindings = append(netDevFindings, makeF(
				finding.CheckNetDeviceMikroTikDetected,
				finding.SeverityInfo,
				"MikroTik RouterOS device identified via SSH banner",
				"The SSH banner (ROSSSH) indicates this is a MikroTik RouterOS device. "+
					"Check for Winbox protocol on port 8291, web management on port 80/8080, and API on port 8728. "+
					"MikroTik CVE-2018-14847 (Winbox credential disclosure) is widely exploited.",
				ev,
			))
		case strings.Contains(lsv, "flowssh") || strings.Contains(lsv, "fortigate") || strings.Contains(lsv, "fortigatessh"):
			netDevFindings = append(netDevFindings, makeF(
				finding.CheckNetDeviceFortinetDetected,
				finding.SeverityInfo,
				"Fortinet FortiGate device identified via SSH banner",
				"The SSH banner indicates this is a Fortinet FortiGate firewall. "+
					"Check for SSL VPN at /remote/login, web management at /login, and FortiOS CVEs.",
				ev,
			))
		case strings.Contains(lsv, "huawei") || strings.Contains(lsv, "vrp"):
			netDevFindings = append(netDevFindings, makeF(
				finding.CheckNetDeviceHuaweiDetected,
				finding.SeverityInfo,
				"Huawei VRP network device identified via SSH banner",
				"The SSH banner indicates this is a Huawei network device running VRP. "+
					"Check for web management interface (eNSP/iMaster) and NETCONF on port 830.",
				ev,
			))
		case strings.Contains(lsv, "erlang"):
			// CVE-2025-32433: Erlang/OTP SSH pre-auth unauthenticated RCE — CVSS 10.0, KEV-listed.
			// The Erlang SSH daemon allows unauthenticated execution before authentication completes.
			// Banner format: "SSH-2.0-Erlang/OTP"
			netDevFindings = append(netDevFindings, makeF(
				finding.CheckCVEErlangOTPSSH,
				finding.SeverityCritical,
				"Erlang/OTP SSH server detected — CVE-2025-32433 unauthenticated RCE",
				"The SSH banner indicates this server runs Erlang/OTP's built-in SSH daemon. "+
					"CVE-2025-32433 (CVSS 10.0, KEV-listed) allows unauthenticated pre-auth remote code execution "+
					"on unpatched Erlang/OTP versions prior to OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. "+
					"RabbitMQ, CouchDB, Riak, and custom Erlang services commonly use this SSH implementation. "+
					"Update Erlang/OTP immediately and restrict SSH access to trusted networks.",
				ev,
			))
		}

		sshFinding := makeF(
			finding.CheckPortSSHExposed,
			finding.SeverityHigh,
			fmt.Sprintf("SSH exposed on port %d", port),
			"SSH is publicly accessible. While SSH itself is secure when properly configured, "+
				"public exposure increases the attack surface for brute-force and credential-stuffing attacks.",
			ev,
		)
		return append(netDevFindings, sshFinding)

	// ── Telnet ────────────────────────────────────────────────────────────────

	case 23:
		ev := map[string]any{"port": port, "service": service, "banner": banner}
		// Vendor identification from Telnet banner.
		lb := strings.ToLower(banner)
		if strings.Contains(lb, "user access verification") || strings.Contains(lb, "cisco ios") || strings.Contains(lb, "cisco nexus") {
			return []finding.Finding{
				makeF(finding.CheckNetDeviceCiscoDetected, finding.SeverityInfo,
					"Cisco network device identified via Telnet banner",
					"The Telnet banner contains 'User Access Verification', indicating a Cisco IOS or NX-OS device. "+
						"Telnet transmits credentials in plaintext. CVE-2023-20198 (CVSS 10.0) targets Cisco IOS XE web UI. "+
						"Disable Telnet and use SSH only.",
					ev),
				makeF(finding.CheckPortTelnetExposed, finding.SeverityHigh,
					fmt.Sprintf("Telnet exposed on port %d", port),
					"Telnet transmits all data including credentials in plaintext.",
					ev),
			}
		}
		if strings.Contains(lb, "mikrotik") {
			return []finding.Finding{
				makeF(finding.CheckNetDeviceMikroTikDetected, finding.SeverityInfo,
					"MikroTik RouterOS device identified via Telnet banner",
					"The Telnet banner identifies this as a MikroTik RouterOS device. "+
						"Default credentials (admin/<empty>) are extremely common. CVE-2018-14847 allows credential extraction via Winbox.",
					ev),
				makeF(finding.CheckPortTelnetExposed, finding.SeverityHigh,
					fmt.Sprintf("Telnet exposed on port %d", port),
					"Telnet transmits all data including credentials in plaintext.",
					ev),
			}
		}
		// Check for GNU telnetd version — CVE-2026-32746 affects GNU telnetd ≤ 2.7.
		// The banner typically includes "GNU telnetd X.Y" from the inetutils package.
		if ver := parseGNUTelnetdVersion(banner); ver != "" {
			ev["telnetd_version"] = ver
			if isVulnerableGNUTelnetd(ver) {
				return []finding.Finding{
					makeF(
						finding.CheckPortTelnetdVulnerable,
						finding.SeverityCritical,
						fmt.Sprintf("GNU telnetd %s exposed — vulnerable to pre-auth RCE (CVE-2026-32746)", ver),
						fmt.Sprintf(
							"GNU telnetd %s is internet-accessible and vulnerable to CVE-2026-32746 (CVSS 9.8). "+
								"A stack buffer overflow in the LINEMODE SLC option handler allows an unauthenticated attacker "+
								"to achieve remote code execution as root before the login prompt. "+
								"GNU inetutils ≤ 2.7 is affected. Disable telnet and use SSH instead.",
							ver),
						ev,
					),
					makeF(
						finding.CheckPortTelnetExposed,
						finding.SeverityHigh,
						fmt.Sprintf("Telnet exposed on port %d", port),
						"Telnet transmits all data including credentials in plaintext.",
						map[string]any{"port": port, "service": service, "banner": banner},
					),
				}
			}
		}
		return []finding.Finding{makeF(
			finding.CheckPortTelnetExposed,
			finding.SeverityHigh,
			fmt.Sprintf("Telnet exposed on port %d", port),
			"Telnet transmits all data including credentials in plaintext. "+
				"Any network observer can capture authentication credentials and session content.",
			ev,
		)}

	// ── Ollama LLM inference server ───────────────────────────────────────────
	case 11434:
		ev := map[string]any{"port": port, "service": service, "banner": banner}
		// Probe /api/tags — returns model list without authentication on default installs.
		if body, ok := probeHTTPBody(ctx, asset, port, false, "/api/tags"); ok && strings.Contains(body, "models") {
			snippet := body
			if len(snippet) > 200 {
				snippet = snippet[:200] + "…"
			}
			ev["api_tags_snippet"] = snippet
			return []finding.Finding{makeF(
				finding.CheckPortOllamaExposed,
				finding.SeverityHigh,
				fmt.Sprintf("Ollama LLM inference server exposed on port %d (unauthenticated)", port),
				"An Ollama local LLM inference server is publicly accessible on port 11434 without authentication. "+
					"The /api/tags endpoint lists all installed AI models. The /api/generate and /api/chat endpoints "+
					"allow arbitrary model inference. Approximately 12,000 Ollama instances are exposed on the internet. "+
					"Ollama is designed for localhost use only — restrict access with a firewall or bind to 127.0.0.1.",
				ev,
			)}
		}
		return nil

	// ── MQTT (IoT message broker) ─────────────────────────────────────────────
	case 1883, 8883:
		tlsFlag := port == 8883
		if isMQTT := probeMQTT(ctx, asset, port, tlsFlag); isMQTT {
			return []finding.Finding{makeF(
				finding.CheckPortMQTTExposed,
				finding.SeverityHigh,
				fmt.Sprintf("MQTT broker exposed on port %d", port),
				"An MQTT message broker is publicly accessible. MQTT brokers used in IoT deployments "+
					"often lack authentication (no username/password required). "+
					"An unauthenticated MQTT broker allows anyone to subscribe to all topics, "+
					"intercept device telemetry, and publish commands to connected devices. "+
					"Restrict access with IP allowlisting and enforce TLS + username/password authentication.",
				map[string]any{"port": port, "service": service, "banner": banner},
			)}
		}

	// ── SIP (VoIP / PBX) ─────────────────────────────────────────────────────
	case 5060, 5061:
		if sipInfo := probeSIP(ctx, asset, port); sipInfo != "" {
			return []finding.Finding{makeF(
				finding.CheckPortSIPExposed,
				finding.SeverityMedium,
				fmt.Sprintf("SIP server exposed on port %d", port),
				"A SIP (Session Initiation Protocol) server is publicly accessible. "+
					"Exposed SIP servers are targeted for toll fraud, eavesdropping, and credential brute-force. "+
					"Restrict access to known IP ranges or use a SIP proxy with authentication.",
				map[string]any{"port": port, "service": service, "sip_response": sipInfo, "banner": banner},
			)}
		}

	// ── RTSP (IP cameras / streaming media) ────────────────────────────────
	case 554:
		if rtspInfo := probeRTSP(ctx, asset, port); rtspInfo != "" {
			return []finding.Finding{makeF(
				finding.CheckPortRTSPExposed,
				finding.SeverityMedium,
				fmt.Sprintf("RTSP server exposed on port %d", port),
				"An RTSP (Real Time Streaming Protocol) server is publicly accessible. "+
					"This commonly indicates an internet-exposed IP camera or video streaming system. "+
					"Many RTSP servers have no authentication or use default credentials. "+
					"Restrict access to prevent unauthorized video surveillance access.",
				map[string]any{"port": port, "service": service, "rtsp_response": rtspInfo, "banner": banner},
			)}
		}

	// ── IPP (network printing) ────────────────────────────────────────────────
	case 631:
		if body, ok := probeHTTPBody(ctx, asset, port, false, "/"); ok &&
			(strings.Contains(strings.ToLower(body), "cups") || strings.Contains(strings.ToLower(body), "ipp")) {
			return []finding.Finding{makeF(
				finding.CheckPortIPPExposed,
				finding.SeverityMedium,
				fmt.Sprintf("IPP/CUPS printer exposed on port %d", port),
				"An IPP (Internet Printing Protocol) server is publicly accessible. "+
					"Internet-exposed printers can be exploited for arbitrary file reads via print job manipulation, "+
					"used as proxies for internal network access (CUPS SSRF), and may expose document queues. "+
					"CVE-2024-47176 (CUPS RCE via crafted UDP packet) affects CUPS < 2.4.11.",
				map[string]any{"port": port, "service": service, "banner": banner},
			)}
		}

	// ── iSCSI (block storage) ─────────────────────────────────────────────────
	case 3260:
		if isISCSI := probeISCSI(ctx, asset, port); isISCSI {
			return []finding.Finding{makeF(
				finding.CheckPortISCSIExposed,
				finding.SeverityHigh,
				fmt.Sprintf("iSCSI target exposed on port %d", port),
				"An iSCSI storage target is publicly accessible. "+
					"iSCSI provides direct block-level access to storage. An internet-exposed iSCSI target "+
					"allows any initiator to mount the storage volume and access raw disk data, "+
					"potentially reading or destroying entire databases and filesystems. "+
					"Restrict access to trusted initiator IQNs and bind to private network interfaces only.",
				map[string]any{"port": port, "service": service, "banner": banner},
			)}
		}

	// ── Modbus TCP (industrial control systems / SCADA) ───────────────────────
	case 502:
		if isModbus := probeModbus(ctx, asset, port); isModbus {
			return []finding.Finding{makeF(
				finding.CheckPortModbusExposed,
				finding.SeverityCritical,
				fmt.Sprintf("Modbus TCP SCADA/ICS device exposed on port %d", port),
				"A Modbus TCP industrial control system device is publicly accessible. "+
					"Modbus has no built-in authentication or encryption. "+
					"An attacker can read sensor values, write control registers, and issue commands "+
					"to industrial equipment (PLCs, RTUs, HMIs) without any credentials. "+
					"This is a critical OT/SCADA exposure that can cause physical damage or safety incidents. "+
					"Isolate industrial devices from internet access immediately.",
				map[string]any{"port": port, "service": service, "banner": banner},
			)}
		}

	// ── NETCONF (network device management) ──────────────────────────────────
	case 830:
		return []finding.Finding{makeF(
			finding.CheckPortNetconfExposed,
			finding.SeverityHigh,
			fmt.Sprintf("NETCONF network management port exposed on port %d", port),
			"NETCONF (RFC 6241) is a network device management protocol for reading and modifying "+
				"device configuration. An internet-accessible NETCONF port indicates a network device "+
				"(router, switch, firewall) with management access exposed to the internet. "+
				"NETCONF runs over SSH — check for weak credentials and known CVEs for the device vendor.",
			map[string]any{"port": port, "service": service, "banner": banner},
		)}

	// ── MikroTik Winbox ──────────────────────────────────────────────────────
	case 8291:
		return []finding.Finding{makeF(
			finding.CheckPortWinboxExposed,
			finding.SeverityHigh,
			fmt.Sprintf("MikroTik Winbox management port exposed on port %d", port),
			"MikroTik RouterOS Winbox management protocol is publicly accessible. "+
				"CVE-2018-14847 (Winbox credential disclosure without authentication — CVSS 9.1) "+
				"allowed unauthenticated attackers to read the RouterOS password database via port 8291. "+
				"This was widely exploited and over 2 million devices were affected. "+
				"Even on patched devices, Winbox exposure enables brute-force attacks on admin credentials. "+
				"Restrict Winbox to trusted management IPs via IP firewall filter rules.",
			map[string]any{"port": port, "service": service, "banner": banner},
		)}

	// ── Juniper PTX Anomaly Detection Framework (CVE-2026-21902) ─────────────
	case 8160:
		return []finding.Finding{makeF(
			finding.CheckPortJuniperAnomalyExposed,
			finding.SeverityCritical,
			"Juniper PTX anomaly detection port exposed (CVE-2026-21902)",
			"TCP port 8160 (Juniper On-Box Anomaly Detection Framework) is internet-accessible. "+
				"CVE-2026-21902 (CVSS 9.8) allows an unauthenticated attacker to execute arbitrary code as root "+
				"by sending crafted requests to this port. "+
				"This port should only be reachable from internal processes. "+
				"Apply the Junos OS Evolved patch or restrict access with firewall filters immediately.",
			map[string]any{"port": port, "service": service, "banner": banner},
		)}

	// ── FTP ───────────────────────────────────────────────────────────────────

	case 21:
		ev := map[string]any{"port": port, "service": service, "banner": banner}
		fv := parseFTPVersion(banner)
		if fv != "" {
			ev["ftp_software"] = fv
		}
		// CVE-2025-47812: Wing FTP Server ≤ 7.4.3 pre-auth RCE (CISA KEV, CVSS 9.9).
		if wingVer := parseWingFTPVersion(banner); wingVer != "" {
			ev["wing_ftp_version"] = wingVer
			if isVulnerableWingFTP(wingVer) {
				return []finding.Finding{makeF(
					finding.CheckPortFTPWingRCE,
					finding.SeverityCritical,
					fmt.Sprintf("Wing FTP Server %s is vulnerable to CVE-2025-47812 (pre-auth RCE)", wingVer),
					"CVE-2025-47812 (CVSS 9.9, CISA KEV) is a pre-authentication remote code execution "+
						"vulnerability in Wing FTP Server ≤ 7.4.3. An unauthenticated attacker can execute "+
						"arbitrary OS commands as the service account. Upgrade to 7.4.4 or later immediately.",
					ev,
				)}
			}
		}
		// Active check: attempt anonymous FTP login (USER anonymous / PASS test@test.com).
		if probeFTPAnonymous(ctx, asset, port) {
			evAnon := map[string]any{"port": port, "service": service, "anonymous_login": true, "banner": banner}
			if fv != "" {
				evAnon["ftp_software"] = fv
			}
			return []finding.Finding{makeF(
				finding.CheckPortFTPAnonymous,
				finding.SeverityHigh,
				fmt.Sprintf("FTP anonymous login accepted on port %d", port),
				"The FTP server permits anonymous access (USER anonymous / PASS anonymous). "+
					"An unauthenticated attacker can list directories and potentially read or write files. "+
					"FTP anonymous login is often enabled for public file distribution but is frequently "+
					"misconfigured to expose internal files. Disable anonymous access or restrict write permissions.",
				evAnon,
			)}
		}
		return []finding.Finding{makeF(
			finding.CheckPortFTPExposed,
			finding.SeverityMedium,
			fmt.Sprintf("FTP exposed on port %d", port),
			"FTP transmits credentials and file content in plaintext. "+
				"Anonymous FTP access is common; even authenticated FTP is trivially intercepted.",
			ev,
		)}

	// ── SMB ───────────────────────────────────────────────────────────────────

	case 445:
		// Active check: attempt SMBv1 null session (anonymous unauthenticated access).
		if probeSMBNullSession(ctx, asset) {
			return []finding.Finding{
				makeF(
					finding.CheckPortSMBNullSession,
					finding.SeverityCritical,
					"SMB null session accepted — unauthenticated share enumeration possible",
					"The SMB server accepted a null session (empty username and password). "+
						"An unauthenticated attacker can enumerate shares, users, and domain information "+
						"via NetShareEnum, NetUserEnum, and similar MSRPC calls. "+
						"Null sessions are a prerequisite for many lateral-movement and password-spray attacks. "+
						"Disable null sessions via: Group Policy → Network access: Restrict anonymous access to Named Pipes and Shares.",
					map[string]any{"port": port, "service": service, "null_session": true},
				),
				makeF(
					finding.CheckPortSMBExposed,
					finding.SeverityHigh,
					fmt.Sprintf("SMB exposed on port %d", port),
					"SMB is publicly accessible. Null session accepted — see separate finding.",
					map[string]any{"port": port, "service": service, "banner": banner},
				),
			}
		}
		return []finding.Finding{makeF(
			finding.CheckPortSMBExposed,
			finding.SeverityHigh,
			fmt.Sprintf("SMB exposed on port %d", port),
			"Server Message Block (SMB) is publicly accessible. "+
				"SMB has been the vector for major ransomware campaigns (WannaCry, NotPetya) and enables lateral movement.",
			map[string]any{"port": port, "service": service, "banner": banner},
		)}

	// ── Databases ─────────────────────────────────────────────────────────────

	case 3306, 5432, 1433, 1521:
		dbNames := map[int]string{
			3306: "MySQL",
			5432: "PostgreSQL",
			1433: "Microsoft SQL Server",
			1521: "Oracle Database",
		}
		dbName := dbNames[port]
		return []finding.Finding{makeF(
			finding.CheckPortDatabaseExposed,
			finding.SeverityHigh,
			fmt.Sprintf("%s database exposed on port %d", dbName, port),
			fmt.Sprintf("A %s database is directly accessible from the internet. "+
				"Databases should never be exposed publicly; this enables brute-force attacks and "+
				"exploitation of database-engine vulnerabilities.", dbName),
			map[string]any{"port": port, "service": service, "banner": banner},
		)}

	// ── Kubernetes API ────────────────────────────────────────────────────────

	case 6443, 8001:
		k8sNames := map[int]string{
			6443: "Kubernetes API server",
			8001: "kubectl proxy",
		}
		k8sName := k8sNames[port]
		return []finding.Finding{makeF(
			finding.CheckPortK8sAPIExposed,
			finding.SeverityHigh,
			fmt.Sprintf("%s exposed on port %d", k8sName, port),
			fmt.Sprintf("The %s is publicly reachable. "+
				"Misconfigured RBAC or anonymous access on the Kubernetes API allows full cluster compromise.", k8sName),
			map[string]any{"port": port, "service": service, "banner": banner},
		)}

	// ── Windows Remote Management ─────────────────────────────────────────────

	case 5985, 5986:
		schemeName := "HTTP"
		if port == 5986 {
			schemeName = "HTTPS"
		}
		return []finding.Finding{makeF(
			finding.CheckPortWinRMExposed,
			finding.SeverityHigh,
			fmt.Sprintf("WinRM (%s) exposed on port %d", schemeName, port),
			"Windows Remote Management (WinRM/WSMan) is publicly accessible. "+
				"WinRM enables remote PowerShell execution and is a primary lateral-movement path for attackers "+
				"who obtain Windows credentials. Exposure is unusual for internet-facing hosts.",
			map[string]any{"port": port, "service": service, "banner": banner},
		)}

	// ── Message queues / streaming ────────────────────────────────────────────

	case 5672:
		return []finding.Finding{makeF(
			finding.CheckPortAMQPExposed,
			finding.SeverityHigh,
			fmt.Sprintf("AMQP (RabbitMQ) exposed on port %d", port),
			"An AMQP message broker (commonly RabbitMQ) is publicly accessible. "+
				"AMQP brokers often have no authentication by default and may expose "+
				"application messages, task queues, and internal service communication.",
			map[string]any{"port": port, "service": service, "banner": banner},
		)}

	case 9092:
		return []finding.Finding{makeF(
			finding.CheckPortKafkaExposed,
			finding.SeverityHigh,
			fmt.Sprintf("Apache Kafka broker exposed on port %d", port),
			"An Apache Kafka broker is publicly accessible. Kafka without authentication "+
				"allows anyone to read, write, or delete messages from any topic — potentially "+
				"exposing event streams containing sensitive application data.",
			map[string]any{"port": port, "service": service, "banner": banner},
		)}

	case 2181:
		return []finding.Finding{makeF(
			finding.CheckPortZooKeeperExposed,
			finding.SeverityHigh,
			fmt.Sprintf("Apache ZooKeeper exposed on port %d", port),
			"Apache ZooKeeper is publicly accessible. ZooKeeper stores distributed configuration "+
				"and coordination data for services like Kafka, HBase, and Hadoop. Unauthenticated access "+
				"allows reading and modifying cluster configuration, enabling service disruption or data extraction.",
			map[string]any{"port": port, "service": service, "banner": banner},
		)}

	// ── Databases (additional) ────────────────────────────────────────────────

	case 9042:
		return []finding.Finding{makeF(
			finding.CheckPortDatabaseExposed,
			finding.SeverityHigh,
			fmt.Sprintf("Apache Cassandra exposed on port %d", port),
			"An Apache Cassandra database is publicly accessible on its native CQL port. "+
				"Cassandra without authentication allows full read/write access to all keyspaces and tables.",
			map[string]any{"port": port, "service": "cassandra", "banner": banner},
		)}

	// ── Monitoring / observability ────────────────────────────────────────────

	case 8086:
		unauth := probeHTTP(ctx, asset, port, false, "/ping")
		if unauth {
			return []finding.Finding{makeF(
				finding.CheckPortInfluxDBExposed,
				finding.SeverityHigh,
				fmt.Sprintf("InfluxDB exposed on port %d", port),
				"An InfluxDB time-series database is publicly accessible. Without authentication, "+
					"all stored metrics data can be read, modified, or deleted.",
				map[string]any{"port": port, "service": service, "authenticated": false, "banner": banner},
			)}
		}

	case 8089:
		unauth := probeHTTP(ctx, asset, port, true, "/services/server/info")
		if unauth {
			return []finding.Finding{makeF(
				finding.CheckPortSplunkMgmtExposed,
				finding.SeverityHigh,
				fmt.Sprintf("Splunk management API exposed on port %d", port),
				"The Splunk management REST API is publicly accessible. This port provides administrative "+
					"access to all Splunk configuration, search capabilities, and log data.",
				map[string]any{"port": port, "service": service, "authenticated": false, "banner": banner},
			)}
		}

	// ── Industrial Control Systems ────────────────────────────────────────────

	case 102: // Siemens S7comm (COTP/ISO-on-TCP)
		// TCP 102 should never be internet-accessible. Any response confirms a
		// Siemens PLC is reachable without authentication.
		return []finding.Finding{makeF(
			finding.CheckPortS7CommExposed,
			finding.SeverityCritical,
			fmt.Sprintf("Siemens S7 PLC accessible on port %d (COTP/S7comm)", port),
			"TCP port 102 (Siemens S7comm over COTP/ISO-on-TCP) is internet-accessible. "+
				"This is a direct connection to a Siemens S7-300/400/1200/1500 Programmable Logic Controller. "+
				"S7comm has no built-in authentication in older PLC series — an attacker can read all process "+
				"data, write control values, and modify PLC logic. Stuxnet targeted Siemens S7 PLCs via this "+
				"protocol. Any internet-exposed S7 PLC should be treated as a critical infrastructure emergency. "+
				"Air-gap or firewall this port immediately.",
			map[string]any{"port": port, "service": service, "banner": banner},
		)}

	case 44818: // EtherNet/IP (Rockwell/Allen-Bradley)
		return []finding.Finding{makeF(
			finding.CheckPortEtherNetIPExposed,
			finding.SeverityCritical,
			fmt.Sprintf("Rockwell EtherNet/IP PLC accessible on port %d", port),
			"TCP port 44818 (EtherNet/IP — Allen-Bradley/Rockwell Automation industrial protocol) is "+
				"internet-accessible. EtherNet/IP provides direct access to Rockwell CompactLogix, ControlLogix, "+
				"MicroLogix, and other PLCs. An attacker can enumerate device identity, read/write process tags, "+
				"and halt production operations. No authentication is required for `List Identity` queries. "+
				"This port must never be internet-facing — apply firewall rules immediately.",
			map[string]any{"port": port, "service": service, "banner": banner},
		)}

	case 20000: // DNP3 (electric utility SCADA)
		return []finding.Finding{makeF(
			finding.CheckPortDNP3Exposed,
			finding.SeverityCritical,
			fmt.Sprintf("DNP3 electric utility SCADA accessible on port %d", port),
			"TCP port 20000 (DNP3 — Distributed Network Protocol 3) is internet-accessible. "+
				"DNP3 is used in electric power distribution, water treatment, and oil/gas SCADA systems. "+
				"An attacker with network access can send unsolicited control commands to RTUs and substations. "+
				"ICS-CERT has issued multiple advisories on internet-exposed DNP3. "+
				"This is a critical infrastructure exposure — air-gap immediately.",
			map[string]any{"port": port, "service": service, "banner": banner},
		)}

	case 47808: // BACnet (building automation)
		return []finding.Finding{makeF(
			finding.CheckPortBACnetExposed,
			finding.SeverityHigh,
			fmt.Sprintf("BACnet building automation protocol accessible on port %d", port),
			"TCP/UDP port 47808 (BACnet/IP) is internet-accessible. BACnet controls building automation "+
				"systems including HVAC, lighting, access control, and fire systems. An attacker can discover "+
				"devices, read sensor values, and potentially control building systems. BACnet/IP has no "+
				"authentication in the base protocol. Restrict to internal building management networks.",
			map[string]any{"port": port, "service": service, "banner": banner},
		)}

	// ── Asterisk / FreePBX Manager Interface ─────────────────────────────────

	case 5038: // Asterisk AMI
		// Asterisk sends a banner on connect: "Asterisk Call Manager/X.Y\r\n"
		ev := map[string]any{"port": port, "service": service}
		if strings.Contains(banner, "Asterisk") || strings.Contains(banner, "Call Manager") {
			ev["banner"] = banner
			return []finding.Finding{makeF(
				finding.CheckPortAsteriskAMIExposed,
				finding.SeverityHigh,
				"Asterisk Manager Interface (AMI) exposed",
				"The Asterisk PBX Manager Interface is internet-accessible. AMI is a plaintext "+
					"administrative API that provides control over calls, channels, queues, and the Asterisk "+
					"dialplan. Without authentication or with weak credentials it enables eavesdropping, "+
					"call hijacking, and toll fraud. AMI should never be internet-facing.",
				ev,
			)}
		}

	// ── JetDirect / PJL raw print port ───────────────────────────────────────

	case 9100: // JetDirect / PJL — NOTE: also used by Prometheus node-exporter on different services
		// Send a PJL status query. Printers respond with model info; node-exporter does not.
		if body, ok := probeHTTPBody(ctx, asset, port, false, "/metrics"); ok && strings.Contains(body, "node_") {
			// Prometheus node-exporter — emit generic service finding but not printer finding
			break
		}
		return []finding.Finding{makeF(
			finding.CheckPortJetDirectExposed,
			finding.SeverityMedium,
			fmt.Sprintf("JetDirect/PJL printer raw print port exposed on port %d", port),
			"TCP port 9100 (HP JetDirect/PJL raw print port) is internet-accessible. "+
				"Attackers can submit rogue print jobs, execute PJL commands to read stored print jobs, "+
				"change device configuration, or exploit printer-specific vulnerabilities. "+
				"PJL `INFO ID` commands reveal printer model and firmware version without authentication. "+
				"Printers and MFPs should never have port 9100 internet-accessible.",
			map[string]any{"port": port, "service": service, "banner": banner},
		)}

	// ── MikroTik RouterOS API ─────────────────────────────────────────────────

	case 8728: // MikroTik RouterOS API (plaintext)
		return []finding.Finding{makeF(
			finding.CheckPortMikroTikAPIExposed,
			finding.SeverityHigh,
			fmt.Sprintf("MikroTik RouterOS API exposed on port %d", port),
			"The MikroTik RouterOS API service is internet-accessible. The RouterOS API on port 8728 "+
				"provides programmatic access to all router configuration including firewall rules, routing, "+
				"user accounts, and VPN settings. Default credentials (admin/<empty>) are common. "+
				"CVE-2023-30799 allows privilege escalation from admin to superadmin via this interface. "+
				"Restrict to trusted management IPs immediately.",
			map[string]any{"port": port, "service": service, "banner": banner},
		)}

	// ── Check Point FW-1 topology protocol ───────────────────────────────────

	case 264: // Check Point cpstat / topology
		return []finding.Finding{makeF(
			finding.CheckPortCheckPointExposed,
			finding.SeverityHigh,
			fmt.Sprintf("Check Point FW-1 topology port exposed on port %d", port),
			"TCP port 264 (Check Point FW-1 topology/cpstat protocol) is internet-accessible. "+
				"This port is used by Check Point SmartConsole and management tools to discover firewall "+
				"topology. Exposure can leak firewall cluster object names, IP addresses, and version "+
				"information. CVE-2024-24919 (Check Point CloudGuard arbitrary file read) affects devices "+
				"with this and related management ports exposed. Restrict to management network only.",
			map[string]any{"port": port, "service": service, "banner": banner},
		)}

	// ── Vite dev server ───────────────────────────────────────────────────────
	case 5173:
		if probeHTTP(ctx, asset, port, false, "/__vite_ping") {
			var findings []finding.Finding

			// CVE-2025-30208: /@fs/ path traversal with double-? query confusion.
			// Vite's ensureServingAccess() checks for ?import in the query string
			// via a regex that is confused by a trailing bare ?. Sending
			// /@fs/etc/passwd?import&raw?? causes Vite to return the file contents
			// as a JS module: export default "root:x:0:0:...\n".
			if body, ok := probeHTTPBody(ctx, asset, port, false, "/@fs/etc/passwd?import&raw??"); ok &&
				strings.Contains(body, "export default") && strings.Contains(body, "root:") {
				findings = append(findings, finding.Finding{
					CheckID:  finding.CheckCVEViteFileRead,
					Module:   "surface",
					Scanner:  scannerName,
					Severity: finding.SeverityCritical,
					Title:    fmt.Sprintf("CVE-2025-30208: Vite dev server arbitrary file read on port %d", port),
					Description: fmt.Sprintf(
						"The Vite development server on %s:%d is vulnerable to CVE-2025-30208 — "+
							"a path traversal that bypasses the /@fs/ allowlist by exploiting a regex "+
							"confusion via a double-question-mark in the query string. "+
							"The probe retrieved /etc/passwd as a JS module. "+
							"Affects Vite < 6.2.4 / < 6.1.3 / < 6.0.12 / < 5.4.15 / < 4.5.10. "+
							"Upgrade Vite and never expose dev servers publicly.",
						asset, port,
					),
					Asset: asset,
					Evidence: map[string]any{
						"url":          fmt.Sprintf("http://%s:%d/@fs/etc/passwd?import&raw??", asset, port),
						"body_excerpt": body[:min(len(body), 256)],
					},
					ProofCommand: fmt.Sprintf(
						"curl -s 'http://%s:%d/@fs/etc/passwd?import&raw??'",
						asset, port,
					),
					DiscoveredAt: now,
				})
			}

			findings = append(findings, makeF(
				finding.CheckPortDevServerExposed,
				finding.SeverityHigh,
				fmt.Sprintf("Vite development server exposed on port %d", port),
				"A Vite JavaScript development server is publicly accessible. Development servers "+
					"expose unminified source code, internal file paths, environment variables embedded in code, "+
					"and the /__vite_ping health endpoint. Production deployments should never expose dev servers.",
				map[string]any{"port": port, "service": service, "banner": banner},
			))
			return findings
		}

	// ── ingress-nginx admission webhook (CVE-2025-1974, IngressNightmare) ────
	// The ingress-nginx admission controller webhook listens on port 8443 and
	// processes AdmissionReview requests without requiring network policy or
	// client-certificate authentication. Internet exposure allows pre-auth RCE
	// via a crafted nginx configuration directive embedded in an Ingress object.
	// Probe: POST a stub AdmissionReview — legitimate webhook responses contain
	// "AdmissionReview" or "admission.k8s.io" even for malformed requests.
	case 8443:
		if body := probeIngressAdmissionWebhook(ctx, asset, port); body != "" {
			return []finding.Finding{{
				CheckID:  finding.CheckCVEIngressNightmare,
				Module:   "surface",
				Scanner:  scannerName,
				Severity: finding.SeverityCritical,
				Title:    fmt.Sprintf("CVE-2025-1974 (IngressNightmare): ingress-nginx admission webhook exposed on port %d", port),
				Description: fmt.Sprintf(
					"%s has the ingress-nginx admission controller webhook accessible on port %d. "+
						"CVE-2025-1974 allows an unauthenticated attacker to send a crafted AdmissionReview "+
						"request containing a malicious nginx configuration directive, achieving remote code "+
						"execution in the ingress-nginx pod. The webhook should never be internet-accessible — "+
						"restrict port 8443 to the Kubernetes API server CIDR only via NetworkPolicy.",
					asset, port,
				),
				Asset: asset,
				Evidence: map[string]any{
					"port":          port,
					"service":       "ingress-nginx-admission-webhook",
					"response_body": body[:min(len(body), 256)],
				},
				ProofCommand: fmt.Sprintf(
					`curl -sk -X POST https://%s:%d/admission -H 'Content-Type: application/json' `+
						`-d '{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview"}'`,
					asset, port,
				),
				DiscoveredAt: now,
			}}
		}

	// ── Gradio ML demo server ─────────────────────────────────────────────────
	case 7860:
		if body, ok := probeHTTPBody(ctx, asset, port, false, "/info"); ok && strings.Contains(body, "gradio") {
			return []finding.Finding{makeF(
				finding.CheckPortGradioExposed,
				finding.SeverityHigh,
				fmt.Sprintf("Gradio ML demo server exposed on port %d", port),
				"A Gradio machine learning demo server is publicly accessible. Gradio deployments often "+
					"run ML models with no authentication, accept arbitrary inputs, and can be exploited for "+
					"SSRF, prompt injection, or unauthorized model access.",
				map[string]any{"port": port, "service": service, "banner": banner},
			)}
		}

	// ── Webmin ────────────────────────────────────────────────────────────────
	case 10000:
		if probeHTTP(ctx, asset, port, true, "/session_login.cgi") {
			return []finding.Finding{makeF(
				finding.CheckPortWebminExposed,
				finding.SeverityHigh,
				fmt.Sprintf("Webmin server management panel exposed on port %d", port),
				"Webmin is publicly accessible. Webmin provides web-based Unix/Linux system administration "+
					"and has a history of critical vulnerabilities. CVE-2019-15107 allowed unauthenticated RCE "+
					"and CVE-2022-0824 allowed unauthenticated file read. Restrict to trusted networks.",
				map[string]any{"port": port, "service": service, "banner": banner},
			)}
		}

	// ── Wazuh security platform API ───────────────────────────────────────────
	case 55000:
		if body, ok := probeHTTPBody(ctx, asset, port, true, "/"); ok && strings.Contains(body, "wazuh") {
			return []finding.Finding{makeF(
				finding.CheckPortWazuhAPIExposed,
				finding.SeverityHigh,
				fmt.Sprintf("Wazuh security platform API exposed on port %d", port),
				"The Wazuh SIEM/XDR REST API is publicly accessible. The Wazuh manager API controls "+
					"all security agents and has access to security alerts, compliance data, and agent commands. "+
					"Unauthorized access allows reading security alerts, disabling agents, and pivoting to managed endpoints.",
				map[string]any{"port": port, "service": service, "banner": banner},
			)}
		}

	// ── Veeam Backup & Replication ────────────────────────────────────────────
	case 9401, 9419:
		portDesc := map[int]string{
			9401: "Veeam Backup & Replication Enterprise Manager",
			9419: "Veeam Catalog Service",
		}
		if probeHTTP(ctx, asset, port, true, "/api/v1/serverInfo") {
			return []finding.Finding{makeF(
				finding.CheckCVEVeeamBackupExposed,
				finding.SeverityCritical,
				fmt.Sprintf("%s exposed on port %d", portDesc[port], port),
				"A Veeam Backup & Replication service is publicly accessible. "+
					"CVE-2025-23120 (CVSS 9.9, KEV-listed) allows unauthenticated remote code execution on "+
					"Veeam Backup & Replication servers via deserialization. Veeam stores backup credentials "+
					"for all protected infrastructure — compromise allows full domain credential extraction. "+
					"Restrict to trusted backup networks immediately.",
				map[string]any{"port": port, "service": service, "banner": banner},
			)}
		}
	case 25, 587: // SMTP / submission
		// Active check: open relay test — does the server forward mail between
		// two external domains without authentication?
		if probeSMTPOpenRelay(ctx, asset, port) {
			return []finding.Finding{makeF(
				finding.CheckPortSMTPOpenRelay,
				finding.SeverityHigh,
				fmt.Sprintf("SMTP open relay — server forwards external mail without authentication on port %d", port),
				"The SMTP server accepted MAIL FROM and RCPT TO commands for two unrelated external domains "+
					"without requiring authentication. This makes it an open mail relay that can be abused to send "+
					"spam and phishing emails with a legitimate IP reputation. Open relays damage domain reputation, "+
					"cause IP blacklisting, and violate most acceptable-use policies. "+
					"Configure the MTA to require AUTH for outbound relay or restrict relay to trusted IPs.",
				map[string]any{"port": port, "service": service, "banner": banner,
					"proof": fmt.Sprintf("telnet %s %d → EHLO test → MAIL FROM:<a@external1.com> → RCPT TO:<b@external2.com>", asset, port)},
			)}
		}
		// Banner grab is already done above; parse for software/version.
		// Any internet-facing SMTP port warrants a finding.
		if banner != "" {
			var f finding.Finding
			lbanner := strings.ToLower(banner)
			switch {
			case strings.Contains(lbanner, "exim"):
				f = makeF(
					finding.CheckPortExImVulnerable,
					finding.SeverityCritical,
					fmt.Sprintf("Exim MTA exposed on port %d — check for CVE-2025-26794", port),
					"Exim SMTP server is internet-accessible. CVE-2025-26794 (CVSS 9.8) is an unauthenticated SQL injection "+
						"in Exim 4.98 before 4.98.1 via the ETRN serialization path. Verify version from banner and update immediately.",
					map[string]any{"port": port, "service": service, "banner": banner},
				)
			default:
				f = makeF(
					finding.CheckPortSMTPExposed,
					finding.SeverityMedium,
					fmt.Sprintf("SMTP server exposed on port %d", port),
					"An SMTP server is publicly accessible. The banner may reveal internal hostnames, MTA software, and version. "+
						"Internet-facing SMTP is expected for mail delivery (port 25) but should be version-hardened. "+
						"Submission port 587 should require authentication (AUTH PLAIN/LOGIN over TLS only).",
					map[string]any{"port": port, "service": service, "banner": banner},
				)
			}
			return []finding.Finding{f}
		}

	case 143, 993: // IMAP / IMAPS
		if banner != "" || port == 993 {
			return []finding.Finding{makeF(
				finding.CheckPortIMAPExposed,
				finding.SeverityMedium,
				fmt.Sprintf("IMAP server exposed on port %d", port),
				"An IMAP mail server is publicly accessible. Internet-facing IMAP allows credential brute-force and "+
					"may expose mailbox contents if authentication is bypassed. Restrict to VPN access where possible.",
				map[string]any{"port": port, "service": service, "banner": banner},
			)}
		}

	case 110, 995: // POP3 / POP3S
		if banner != "" || port == 995 {
			return []finding.Finding{makeF(
				finding.CheckPortPOP3Exposed,
				finding.SeverityMedium,
				fmt.Sprintf("POP3 server exposed on port %d", port),
				"A POP3 mail server is publicly accessible. POP3 is a legacy protocol; modern deployments should use IMAP or "+
					"restrict mail access behind a VPN. Exposed POP3 enables credential stuffing and brute-force attacks.",
				map[string]any{"port": port, "service": service, "banner": banner},
			)}
		}

	case 389, 636: // LDAP / LDAPS
		// Attempt a null bind to retrieve rootDSE — reveals AD domain info without credentials.
		if ldapInfo := probeLDAP(ctx, asset, port); ldapInfo != nil {
			if isAD, _ := ldapInfo["is_active_directory"].(bool); isAD {
				return []finding.Finding{makeF(
					finding.CheckPortActiveDirectoryExposed,
					finding.SeverityCritical,
					fmt.Sprintf("Active Directory domain controller exposed via LDAP on port %d", port),
					"An Active Directory domain controller is accessible from the internet via LDAP. "+
						"The rootDSE responds to anonymous queries revealing the AD domain name, DC hostname, "+
						"and forest functional level. An internet-facing DC enables Kerberoasting, AS-REP roasting, "+
						"LDAP injection attacks, and NTLM relay. This is a critical security misconfiguration.",
					ldapInfo,
				)}
			}
			return []finding.Finding{makeF(
				finding.CheckPortLDAPExposed,
				finding.SeverityHigh,
				fmt.Sprintf("LDAP server accessible on port %d — anonymous rootDSE query succeeded", port),
				"An LDAP directory server is accessible from the internet and responds to anonymous queries. "+
					"The rootDSE reveals server software, naming contexts, and supported SASL mechanisms. "+
					"LDAP CVE-2025-26663 (CVSS 9.8) affects Windows LDAP and allows unauthenticated RCE.",
				ldapInfo,
			)}
		}
		if port == 636 {
			// LDAPS with no probe success — still report TLS LDAP exposure
			return []finding.Finding{makeF(
				finding.CheckPortLDAPExposed,
				finding.SeverityHigh,
				fmt.Sprintf("LDAPS server accessible on port %d", port),
				"An LDAP server with TLS is accessible from the internet. "+
					"Restrict LDAP access to internal networks and VPN clients only.",
				map[string]any{"port": port, "service": service},
			)}
		}

	case 88: // Kerberos
		return []finding.Finding{makeF(
			finding.CheckPortKerberosExposed,
			finding.SeverityHigh,
			"Kerberos KDC exposed on port 88",
			"A Kerberos Key Distribution Center (KDC) is accessible from the internet, indicating an Active Directory "+
				"domain controller is internet-exposed. This enables AS-REP roasting (accounts without pre-auth), "+
				"Kerberoasting (SPN enumeration), and brute-force of domain accounts without account lockout on older configs. "+
				"AD domain controllers should never be directly internet-accessible.",
			map[string]any{"port": port, "service": service, "banner": banner},
		)}

	case 3268, 3269: // AD Global Catalog
		return []finding.Finding{makeF(
			finding.CheckPortGlobalCatalogExposed,
			finding.SeverityHigh,
			fmt.Sprintf("Active Directory Global Catalog exposed on port %d", port),
			"An Active Directory Global Catalog port is accessible from the internet. "+
				"Global Catalog servers answer forest-wide LDAP queries. Exposure confirms an AD DC is internet-reachable. "+
				"Restrict to internal network access only.",
			map[string]any{"port": port, "service": service},
		)}

	case 4369: // Erlang Port Mapper Daemon (EPMD)
		if nodes := probeEPMD(ctx, asset, port); len(nodes) > 0 {
			return []finding.Finding{makeF(
				finding.CheckPortEPMDExposed,
				finding.SeverityHigh,
				fmt.Sprintf("Erlang EPMD listing %d node(s) without authentication on port 4369", len(nodes)),
				"The Erlang Port Mapper Daemon (EPMD) is accessible from the internet and lists all running Erlang "+
					"nodes with their names and ports without authentication. Exposed nodes may include RabbitMQ, "+
					"CouchDB, or custom Erlang applications that accept unauthenticated inter-node connections. "+
					"CVE-2025-32433 affects Erlang/OTP SSH (port 22) with CVSS 10.0; EPMD exposure reveals the full cluster topology.",
				map[string]any{"port": port, "service": service, "nodes": nodes},
			)}
		}

	case 53: // DNS
		// Report DNS server exposure; active open-resolver test is done separately
		// to avoid generating DNS queries to external domains without confirmation.
		return []finding.Finding{makeF(
			finding.CheckPortDNSVersionExposed,
			finding.SeverityLow,
			"DNS server exposed on TCP port 53",
			"A DNS server is accessible on TCP port 53. TCP DNS is used for zone transfers (AXFR) and large responses. "+
				"Open recursive resolvers enable amplification DDoS attacks. Check if AXFR is allowed (covered by dns scanner). "+
				"CVE-2025-40778 (BIND 9 cache poisoning, CVSS 8.6) affects BIND 9.11–9.21.",
			map[string]any{"port": port, "service": service},
		)}

	case 1512: // WINS
		return []finding.Finding{makeF(
			finding.CheckPortWINSExposed,
			finding.SeverityHigh,
			"WINS server exposed on port 1512",
			"A Windows Internet Name Service (WINS) server is accessible from the internet. "+
				"CVE-2025-10230 (CVSS 10.0) is an unauthenticated RCE in Samba WINS hook command injection — "+
				"affects Samba AD DCs with 'wins support = yes' and 'wins hook' configured. "+
				"WINS is a legacy NetBIOS name resolution service and should not be internet-accessible.",
			map[string]any{"port": port, "service": service},
		)}

	case 111: // rpcbind / portmapper
		return []finding.Finding{makeF(
			finding.CheckPortRPCBindExposed,
			finding.SeverityMedium,
			"RPC portmapper exposed on port 111",
			"The Sun RPC portmapper is accessible from the internet. It responds to DUMP requests with a list of all "+
				"registered RPC services (NFS, NIS, lockd, mountd, etc.) and their ports — without authentication. "+
				"If NFS mountd is registered, NFS exports may be enumerable and mountable without credentials.",
			map[string]any{"port": port, "service": service},
		)}

	// ── BGP (routing infrastructure) ─────────────────────────────────────────

	case 179: // BGP
		return []finding.Finding{makeF(
			finding.CheckPortBGPExposed,
			finding.SeverityHigh,
			"BGP port 179 accessible from internet",
			"The Border Gateway Protocol (BGP) port is reachable from the internet. BGP is the core internet routing "+
				"protocol; internet-facing BGP sessions should only be established with known peers. "+
				"Exposed BGP allows session hijacking, route injection, and BGP hijacking attacks. "+
				"Restrict port 179 to known BGP peer IP addresses with firewall rules.",
			map[string]any{"port": port, "service": service, "banner": banner},
		)}

	// ── Kibana ────────────────────────────────────────────────────────────────

	case 5601: // Kibana
		if body, ok := probeHTTPBody(ctx, asset, port, false, "/api/status"); ok {
			ev := map[string]any{"port": port, "service": service, "banner": banner}
			// Extract version from {"version":{"number":"8.16.1",...},...}
			if kibanaVer := parseJSONStringField(body, "number"); kibanaVer != "" {
				ev["kibana_version"] = kibanaVer
				if isVulnerableKibana(kibanaVer) {
					return []finding.Finding{makeF(
						finding.CheckPortKibanaVulnerable,
						finding.SeverityCritical,
						fmt.Sprintf("Kibana %s is vulnerable to CVE-2025-25015 (prototype pollution RCE)", kibanaVer),
						"CVE-2025-25015 (CVSS 9.9) is a prototype pollution vulnerability in Kibana 8.15.0–8.17.2 "+
							"that allows an unauthenticated attacker to achieve remote code execution. "+
							"Upgrade to Kibana 8.17.3 or later immediately. "+
							"Kibana should also not be directly internet-accessible.",
						ev,
					)}
				}
			}
		}

	// ── MinIO console ─────────────────────────────────────────────────────────

	case 9001: // MinIO console
		if probeMinIODefaultCreds(ctx, asset, port) {
			return []finding.Finding{makeF(
				finding.CheckPortMinIODefaultCreds,
				finding.SeverityCritical,
				fmt.Sprintf("MinIO console accepts default credentials (minioadmin:minioadmin) on port %d", port),
				"The MinIO object storage web console is accessible with the factory-default credentials "+
					"minioadmin/minioadmin. An attacker can read, write, or delete all stored objects and "+
					"reconfigure the MinIO cluster. Change the root credentials immediately via environment "+
					"variables MINIO_ROOT_USER and MINIO_ROOT_PASSWORD.",
				map[string]any{"port": port, "service": service, "authenticated": true, "default_creds": true},
			)}
		}

	}

	// No structured check for this service — return nothing.
	return nil
}

// webServicePorts are ports that host HTTP services and warrant their own
// classify + playbook matching pass in the surface module.
// Non-standard HTTP ports on the same host may be running completely different
// software (e.g. Grafana on :3000 alongside nginx on :80) — each should be
// fingerprinted and scanned independently.
var webServicePorts = map[int]string{
	3000:  "node/grafana",
	3001:  "node-alt",
	4200:  "angular-dev",
	5000:  "flask-dev",
	5601:  "kibana",
	7474:  "neo4j-browser",
	8001:  "k8s-proxy",
	8080:  "http-alt",
	8081:  "http-alt-2",
	8200:  "vault",
	8086:  "influxdb",
	8089:  "splunk-mgmt",
	8443:  "https-alt",
	8500:  "consul",
	8888:  "jupyter",
	9000:  "sonarqube",
	11434: "ollama",
	9001:  "minio-console",
	9090:  "prometheus",
	9091:  "prometheus-pushgateway",
	9200:  "elasticsearch",
	15672: "rabbitmq-mgmt",
	16686: "jaeger-ui",
	4848:  "glassfish-admin",
	7001:  "weblogic",
	9043:  "websphere-admin",
	5173:  "vite-dev",
	7860:  "gradio",
	10000: "webmin",
	55000: "wazuh-api",
	9401:  "veeam-mgmt",
	9419:  "veeam-catalog",
}

// EmitPortServiceDiscovered returns a CheckPortServiceDiscovered finding when
// an open port hosts an HTTP service that deserves its own fingerprint pass.
// The surface module extracts these findings and schedules host:port as assets.
func EmitPortServiceDiscovered(asset string, port int, service, banner string) *finding.Finding {
	if _, ok := webServicePorts[port]; !ok {
		return nil
	}
	f := finding.Finding{
		CheckID:  finding.CheckPortServiceDiscovered,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityInfo,
		Asset:    asset,
		Title:    fmt.Sprintf("Web service discovered on %s port %d (%s)", asset, port, service),
		Description: fmt.Sprintf(
			"Port %d on %s is open and hosts an HTTP service (%s). "+
				"This port will be fingerprinted and scanned independently from the default HTTP port, "+
				"as it may be running different software with its own vulnerabilities.",
			port, asset, service,
		),
		Evidence: map[string]any{
			"port":       port,
			"service":    service,
			"banner":     banner,
			"port_asset": fmt.Sprintf("%s:%d", asset, port),
		},
	}
	return &f
}

// ── Service-specific probes ───────────────────────────────────────────────────

// probeRedis sends a Redis PING command, checks for +PONG, then queries
// INFO server to extract the server version. Returns (unauthenticated, version).
// version is "" when not readable (e.g. auth required or connection issue).
func probeRedis(ctx context.Context, host string, port int) (bool, string) {
	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(bannerTimeout))
	// RESP inline PING
	_, err = conn.Write([]byte("*1\r\n$4\r\nPING\r\n"))
	if err != nil {
		return false, ""
	}
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	if !strings.Contains(string(buf[:n]), "+PONG") {
		return false, ""
	}
	// Server is unauthenticated — query INFO server for version.
	_ = conn.SetDeadline(time.Now().Add(bannerTimeout))
	_, err = conn.Write([]byte("*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n"))
	if err != nil {
		return true, ""
	}
	info := make([]byte, 4096)
	n, _ = conn.Read(info)
	version := parseRedisVersion(string(info[:n]))
	return true, version
}

// parseRedisVersion extracts the version from an INFO server response.
// Looks for "redis_version:x.y.z" in the bulk string reply.
func parseRedisVersion(info string) string {
	const prefix = "redis_version:"
	idx := strings.Index(info, prefix)
	if idx < 0 {
		return ""
	}
	rest := info[idx+len(prefix):]
	end := strings.IndexAny(rest, "\r\n")
	if end < 0 {
		return strings.TrimSpace(rest)
	}
	return strings.TrimSpace(rest[:end])
}

// isVulnerableRedis returns true when the Redis version is affected by
// CVE-2025-49844 (unauthenticated RCE via Lua scripting, CVSS 9.8).
// Affected: < 7.2.11, < 7.4.6, < 8.0.4, < 8.2.2.
// Patched:  7.2.11+, 7.4.6+, 8.0.4+, 8.2.2+.
func isVulnerableRedis(version string) bool {
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 2 {
		return false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return false
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}
	patch := 0
	if len(parts) == 3 {
		patch, _ = strconv.Atoi(parts[2])
	}
	switch {
	case major == 7 && minor == 2:
		return patch < 11
	case major == 7 && minor == 4:
		return patch < 6
	case major == 8 && minor == 0:
		return patch < 4
	case major == 8 && minor == 2:
		return patch < 2
	case major < 7:
		return true // all older majors unpatched
	default:
		return false
	}
}

// probeHTTP sends a plain-HTTP GET and returns true if the server responds 200.
// If useTLS is true it uses HTTPS with TLS verification disabled.
// probeHTTPBody makes a GET request and returns (body, true) on HTTP 200,
// ("", false) otherwise. Used when the response body is needed to distinguish
// between services that share a port (e.g. Elasticsearch vs OpenSearch on 9200).
func probeHTTPBody(ctx context.Context, host string, port int, useTLS bool, path string) (string, bool) {
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%d%s", scheme, host, port, path)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		DialContext:     (&net.Dialer{Timeout: dialTimeout}).DialContext,
	}
	client := &http.Client{
		Timeout:   httpTimeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", false
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", true // connected but couldn't read body
	}
	return string(b), true
}

func probeHTTP(ctx context.Context, host string, port int, useTLS bool, path string) bool {
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%d%s", scheme, host, port, path)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // intentional for security probe
		DialContext: (&net.Dialer{Timeout: dialTimeout}).DialContext,
	}
	client := &http.Client{
		Timeout:   httpTimeout,
		Transport: transport,
		// Do not follow redirects — a 302 to /login means auth is required.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// probeIngressAdmissionWebhook probes port 8443 for an exposed ingress-nginx
// admission controller webhook (CVE-2025-1974, IngressNightmare). It POSTs a
// minimal AdmissionReview JSON and returns the response body if the endpoint
// looks like a Kubernetes admission webhook (body contains "AdmissionReview"
// or "admission.k8s.io"). Returns "" when no webhook is detected.
func probeIngressAdmissionWebhook(ctx context.Context, host string, port int) string {
	url := fmt.Sprintf("https://%s:%d/admission", host, port)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		DialContext:     (&net.Dialer{Timeout: dialTimeout}).DialContext,
	}
	client := &http.Client{
		Timeout:   httpTimeout,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	body := `{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","request":{}}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url,
		strings.NewReader(body))
	if err != nil {
		return ""
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return ""
	}
	s := string(b)
	if strings.Contains(s, "AdmissionReview") || strings.Contains(s, "admission.k8s.io") ||
		strings.Contains(s, "admission") && strings.Contains(s, "ingress") {
		return s
	}
	return ""
}

// probeMemcached sends the ASCII stats command and checks for STAT in the response.
func probeMemcached(ctx context.Context, host string, port int) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(bannerTimeout))
	_, err = conn.Write([]byte("stats\r\n"))
	if err != nil {
		return false
	}
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	return strings.Contains(string(buf[:n]), "STAT ")
}

// probeJupyter does an HTTP GET / and checks for "jupyter" in the response body.
func probeJupyter(ctx context.Context, host string, port int) bool {
	url := fmt.Sprintf("http://%s:%d/", host, port)
	transport := &http.Transport{
		DialContext: (&net.Dialer{Timeout: dialTimeout}).DialContext,
	}
	client := &http.Client{
		Timeout:   httpTimeout,
		Transport: transport,
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(body)), "jupyter")
}

// probeMongoDB sends the MongoDB OP_MSG "hello" wire-protocol message and
// checks that the response starts with a valid MongoDB wire-protocol header.
//
// Wire format: MsgHeader (16 bytes) + OP_MSG body.
// We send a minimal isMaster/hello request and check whether the response
// carries a BSON document with { ok: 1 }.
func probeMongoDB(ctx context.Context, host string, port int) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(bannerTimeout))

	// Build a minimal OP_MSG hello.
	// BSON document: { isMaster: 1 }
	// Encoding: int32 len + elements + 0x00 terminator
	//   "\x13\x00\x00\x00"               -- doc len = 19
	//   "\x10"                            -- type int32
	//   "isMaster\x00"                   -- key
	//   "\x01\x00\x00\x00"               -- value 1
	//   "\x00"                            -- terminator
	bsonDoc := []byte{
		0x13, 0x00, 0x00, 0x00, // document length = 19
		0x10,                                           // type: int32
		0x69, 0x73, 0x4d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00, // "isMaster\0"
		0x01, 0x00, 0x00, 0x00, // value: 1
		0x00, // terminator
	}

	// OP_MSG header + flagBits (0) + section kind 0 + BSON body
	// MsgHeader: messageLength(4) requestID(4) responseTo(4) opCode(4)
	// OP_MSG opCode = 2013 (0x07DD)
	const opMsg = 2013
	flagBits := []byte{0x00, 0x00, 0x00, 0x00}
	sectionKind := []byte{0x00} // kind 0 = body

	body := append(flagBits, sectionKind...)
	body = append(body, bsonDoc...)

	headerLen := 16 + len(body)
	header := make([]byte, 16)
	binary.LittleEndian.PutUint32(header[0:4], uint32(headerLen))
	binary.LittleEndian.PutUint32(header[4:8], 1)    // requestID
	binary.LittleEndian.PutUint32(header[8:12], 0)   // responseTo
	binary.LittleEndian.PutUint32(header[12:16], opMsg)

	msg := append(header, body...)
	if _, err := conn.Write(msg); err != nil {
		return false
	}

	// Read the 16-byte response header and check opCode is OP_MSG (2013).
	respHeader := make([]byte, 16)
	if _, err := io.ReadFull(conn, respHeader); err != nil {
		return false
	}
	respOpCode := binary.LittleEndian.Uint32(respHeader[12:16])
	// A valid MongoDB response returns OP_MSG (2013) or the legacy OP_REPLY (1).
	return respOpCode == opMsg || respOpCode == 1
}

// probeMQTT sends a minimal MQTT CONNECT packet and checks for a CONNACK response.
// Returns true when the server responds with the MQTT 0x20 CONNACK fixed header,
// confirming an MQTT broker — regardless of whether it accepts the connection.
func probeMQTT(ctx context.Context, host string, port int, useTLS bool) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: dialTimeout}
	var conn net.Conn
	var err error
	if useTLS {
		tlsCfg := &tls.Config{InsecureSkipVerify: true} //nolint:gosec
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(bannerTimeout))

	// MQTT 3.1.1 CONNECT packet (minimal — empty client ID, no auth).
	// Fixed header: 0x10 (CONNECT), remaining length 12.
	// Variable header: protocol name "MQTT" (4 bytes), level 4, connect flags 0x00, keepalive 60.
	// Payload: client ID length 0x00 0x00 (empty).
	connect := []byte{
		0x10, 0x0c, // Fixed header: CONNECT, remaining length 12
		0x00, 0x04, 'M', 'Q', 'T', 'T', // Protocol name
		0x04,       // Protocol level 4 (MQTT 3.1.1)
		0x00,       // Connect flags: no auth, no will
		0x00, 0x3c, // Keep-alive: 60 seconds
		0x00, 0x00, // Client ID length: 0 (empty)
	}
	if _, err := conn.Write(connect); err != nil {
		return false
	}
	buf := make([]byte, 4)
	n, _ := conn.Read(buf)
	// CONNACK fixed header is 0x20; any CONNACK (accepted or refused) confirms MQTT.
	return n >= 2 && buf[0] == 0x20
}

// probeSIP sends a SIP OPTIONS request and checks for a SIP/2.0 response line.
// Returns the response status line on success (e.g. "SIP/2.0 200 OK"), "" otherwise.
func probeSIP(ctx context.Context, host string, port int) string {
	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(bannerTimeout))

	req := fmt.Sprintf(
		"OPTIONS sip:%s SIP/2.0\r\n"+
			"Via: SIP/2.0/TCP %s:%d;branch=z9hG4bKbeacon\r\n"+
			"From: <sip:beacon@%s>;tag=beacon\r\n"+
			"To: <sip:%s>\r\n"+
			"Call-ID: beacon-probe@%s\r\n"+
			"CSeq: 1 OPTIONS\r\n"+
			"Max-Forwards: 1\r\n"+
			"Content-Length: 0\r\n\r\n",
		host, host, port, host, host, host,
	)
	if _, err := conn.Write([]byte(req)); err != nil {
		return ""
	}
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	resp := strings.TrimSpace(string(buf[:n]))
	if strings.HasPrefix(resp, "SIP/2.0") {
		// Return just the first line (status line).
		if idx := strings.Index(resp, "\r\n"); idx > 0 {
			return resp[:idx]
		}
		return resp
	}
	return ""
}

// probeRTSP sends an RTSP OPTIONS request and checks for an RTSP/1.0 response.
// Returns the response status line on success (e.g. "RTSP/1.0 200 OK"), "" otherwise.
func probeRTSP(ctx context.Context, host string, port int) string {
	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(bannerTimeout))

	req := fmt.Sprintf("OPTIONS rtsp://%s:%d/ RTSP/1.0\r\nCSeq: 1\r\n\r\n", host, port)
	if _, err := conn.Write([]byte(req)); err != nil {
		return ""
	}
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	resp := strings.TrimSpace(string(buf[:n]))
	if strings.HasPrefix(resp, "RTSP/1.0") {
		if idx := strings.Index(resp, "\r\n"); idx > 0 {
			return resp[:idx]
		}
		return resp
	}
	return ""
}

// probeISCSI sends a minimal iSCSI Login Request PDU and checks that the
// response carries the iSCSI Login Response opcode (0x23), confirming an iSCSI target.
func probeISCSI(ctx context.Context, host string, port int) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(bannerTimeout))

	// Minimal iSCSI Login Request (48-byte header, empty data segment).
	// Opcode 0x03 (Login Request) | Immediate + Final bit (0x43).
	pdu := make([]byte, 48)
	pdu[0] = 0x43  // opcode 0x03 | I-bit | Final-bit
	pdu[1] = 0x87  // Transit=1, Continue=0, CSG=0 (SecurityNegotiation), NSG=3 (FullFeaturePhase)
	pdu[2] = 0x00  // Version-max
	pdu[3] = 0x00  // Version-min
	// Remaining bytes zero: empty header digest, data length 0, ISID, TSIH, ITT, CID, etc.
	if _, err := conn.Write(pdu); err != nil {
		return false
	}
	buf := make([]byte, 48)
	n, _ := conn.Read(buf)
	// iSCSI Login Response opcode is 0x23.
	return n >= 1 && (buf[0]&0x3f) == 0x23
}

// probeModbus sends a minimal Modbus TCP Read Holding Registers request and
// checks that the response is a valid Modbus TCP frame (matching transaction ID
// and protocol identifier 0x0000). Returns true when a Modbus device is confirmed.
func probeModbus(ctx context.Context, host string, port int) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(bannerTimeout))

	// Modbus TCP ADU: Transaction ID (0x0001) | Protocol ID (0x0000) |
	// Length (0x0006) | Unit ID (0x01) | FC 0x03 (Read Holding Registers) |
	// Starting Address (0x0000) | Quantity (0x0001)
	req := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01}
	if _, err := conn.Write(req); err != nil {
		return false
	}
	buf := make([]byte, 16)
	n, _ := conn.Read(buf)
	// Valid Modbus TCP response: transaction ID echo (bytes 0-1) + protocol ID 0x0000 (bytes 2-3).
	return n >= 4 && buf[0] == 0x00 && buf[1] == 0x01 && buf[2] == 0x00 && buf[3] == 0x00
}

// serviceNucleiTagMap maps open port numbers to Nuclei template tags.
// When Phase A discovers these ports, the tags are added to the Nuclei run so
// service-specific CVE and misconfiguration templates fire automatically.
var serviceNucleiTagMap = map[int][]string{
	6379:  {"redis"},
	9200:  {"elasticsearch"},
	9300:  {"elasticsearch"},
	2375:  {"docker"},
	10250: {"kubernetes", "kubelet"},
	6443:  {"kubernetes"},
	8001:  {"kubernetes"},
	27017: {"mongodb"},
	9090:  {"prometheus"},
	9091:  {"prometheus"},
	9100:  {"node-exporter"},
	5432:  {"postgresql"},
	3306:  {"mysql"},
	1433:  {"mssql"},
	3389:  {"rdp"},
	5900:  {"vnc"},
	21:    {"ftp"},
	23:    {"telnet"},
	445:   {"smb"},
	11211: {"memcached"},
	5984:  {"couchdb"},
	8888:  {"jupyter"},
	11434: {"ollama"},
	1883:  {"mqtt"},
	8883:  {"mqtt"},
	5060:  {"sip"},
	554:   {"rtsp"},
	502:   {"modbus", "scada"},
	8291:  {"mikrotik", "winbox"},
	5601:  {"kibana"},
	7474:  {"neo4j"},
	9000:  {"sonarqube"},
	4848:  {"glassfish"},
	7001:  {"weblogic"},
	9043:  {"websphere"},
	2376:  {"docker"},
	2379:  {"etcd"},
	8200:  {"vault"},
	8500:  {"consul"},
	15672: {"rabbitmq"},
	16686: {"jaeger"},
	5672:  {"rabbitmq", "amqp"},
	5985:  {"winrm"},
	5986:  {"winrm"},
	8080:  {"http"},
	8086:  {"influxdb"},
	8089:  {"splunk"},
	8443:  {"ssl"},
	9042:  {"cassandra"},
	9092:  {"kafka"},
	2181:  {"zookeeper"},
}

// ServiceNucleiTags returns deduplicated Nuclei template tags for the given
// open port map. Called by the surface module after Phase A to augment the
// Nuclei template run with service-specific CVE checks.
func ServiceNucleiTags(openPorts map[int]string) []string {
	seen := make(map[string]bool)
	var tags []string
	for port := range openPorts {
		for _, tag := range serviceNucleiTagMap[port] {
			if !seen[tag] {
				seen[tag] = true
				tags = append(tags, tag)
			}
		}
	}
	return tags
}

// ── Banner version parsers ────────────────────────────────────────────────────

// parseSSHVersion extracts the software identifier from an SSH banner.
// SSH banners follow RFC 4253: "SSH-protoversion-softwareversion[ comment]"
// Examples:
//   - "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5" → "OpenSSH_9.6p1"
//   - "SSH-2.0-dropbear_2022.83"                  → "dropbear_2022.83"
//   - "SSH-1.99-Cisco-1.25"                        → "Cisco-1.25"
func parseSSHVersion(banner string) string {
	if !strings.HasPrefix(banner, "SSH-") {
		return ""
	}
	// Format: SSH-<proto>-<software>[ <comment>]
	// Skip "SSH-" prefix then split on "-" twice to reach software field.
	rest := banner[4:] // strip "SSH-"
	idx := strings.Index(rest, "-")
	if idx == -1 {
		return ""
	}
	software := rest[idx+1:] // everything after proto version
	// Trim optional comment (separated by space)
	if sp := strings.IndexByte(software, ' '); sp != -1 {
		software = software[:sp]
	}
	return software
}

// parseFTPVersion extracts the server software string from an FTP 220 banner.
// Examples:
//   - "220 ProFTPD 1.3.6 Server (hostname)"  → "ProFTPD 1.3.6"
//   - "220 (vsFTPd 3.0.3)"                    → "vsFTPd 3.0.3"
//   - "220 FileZilla Server 1.8.1"            → "FileZilla Server 1.8.1"
//   - "220 Microsoft FTP Service"             → "Microsoft FTP Service"
func parseFTPVersion(banner string) string {
	if !strings.HasPrefix(banner, "220") {
		return ""
	}
	// Strip the "220 " or "220-" prefix
	rest := strings.TrimSpace(banner[3:])
	rest = strings.TrimLeft(rest, "- ")
	// Strip surrounding parentheses: "(vsFTPd 3.0.3)" → "vsFTPd 3.0.3"
	rest = strings.Trim(rest, "()")
	rest = strings.TrimSpace(rest)
	// Drop anything after a " Server" or " server" suffix that includes hostname
	if idx := strings.Index(strings.ToLower(rest), " server "); idx != -1 {
		rest = rest[:idx]
	}
	return rest
}

// parseJSONStringField does a lightweight scan of a JSON body for the first
// occurrence of "key":"value" and returns the value string. It avoids a full
// json.Unmarshal to stay allocation-light for the common hot path.
func parseJSONStringField(body, key string) string {
	needle := `"` + key + `":"`
	idx := strings.Index(body, needle)
	if idx < 0 {
		return ""
	}
	rest := body[idx+len(needle):]
	end := strings.IndexByte(rest, '"')
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// isVulnerableKibana returns true when the Kibana version falls in the range
// 8.15.0–8.17.2 affected by CVE-2025-25015 (prototype pollution → RCE, CVSS 9.9).
// Patched in 8.17.3.
func isVulnerableKibana(version string) bool {
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 3 {
		return false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil || major != 8 {
		return false
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}
	patch, err := strconv.Atoi(parts[2])
	if err != nil {
		return false
	}
	// Vulnerable: 8.15.0 ≤ version ≤ 8.17.2
	if minor < 15 || minor > 17 {
		return false
	}
	if minor == 17 && patch >= 3 {
		return false // patched
	}
	return true
}

// probeMinIODefaultCreds attempts to log in to the MinIO console with the
// factory-default credentials minioadmin/minioadmin via the /api/v1/login
// JSON endpoint. Returns true if the server accepts the credentials.
func probeMinIODefaultCreds(ctx context.Context, host string, port int) bool {
	url := fmt.Sprintf("http://%s:%d/api/v1/login", host, port)
	body := strings.NewReader(`{"accessKey":"minioadmin","secretKey":"minioadmin"}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{
		Timeout: httpTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	// 200 with a session token means credentials were accepted.
	if resp.StatusCode != http.StatusOK {
		return false
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return strings.Contains(string(b), "token") || strings.Contains(string(b), "sessionId")
}

// parseWingFTPVersion extracts the version number from a Wing FTP Server banner.
// Wing FTP banners look like: "220 Wing FTP Server 7.4.2 ready." or
// "220-Wing FTP Server 7.4.3". Returns "" if not a Wing FTP banner.
func parseWingFTPVersion(banner string) string {
	lower := strings.ToLower(banner)
	const marker = "wing ftp server "
	idx := strings.Index(lower, marker)
	if idx < 0 {
		return ""
	}
	rest := banner[idx+len(marker):]
	// Extract version: digits and dots only.
	end := strings.IndexFunc(rest, func(r rune) bool {
		return r != '.' && (r < '0' || r > '9')
	})
	if end == 0 {
		return ""
	}
	if end < 0 {
		return strings.TrimSpace(rest)
	}
	return strings.TrimSpace(rest[:end])
}

// isVulnerableWingFTP returns true when the Wing FTP Server version is ≤ 7.4.3,
// which is vulnerable to CVE-2025-47812 (pre-auth RCE, CVSS 9.9, CISA KEV).
// Patched in version 7.4.4.
func isVulnerableWingFTP(version string) bool {
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 2 {
		return false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return false
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}
	patch := 0
	if len(parts) == 3 {
		patch, _ = strconv.Atoi(parts[2])
	}
	if major < 7 {
		return true
	}
	if major == 7 && minor < 4 {
		return true
	}
	if major == 7 && minor == 4 && patch <= 3 {
		return true
	}
	return false
}

// parseGNUTelnetdVersion extracts the version string from a GNU inetutils
// telnetd banner. GNU telnetd announces itself as "GNU telnetd X.Y" in the
// initial connection banner (negotiation phase). Returns "" if not GNU telnetd.
// Example: "GNU telnetd 2.5" → "2.5"
func parseGNUTelnetdVersion(banner string) string {
	lower := strings.ToLower(banner)
	const prefix = "gnu telnetd "
	idx := strings.Index(lower, prefix)
	if idx < 0 {
		return ""
	}
	rest := banner[idx+len(prefix):]
	// Extract version: take up to the first whitespace or end of string.
	end := strings.IndexAny(rest, " \t\r\n")
	if end < 0 {
		return strings.TrimSpace(rest)
	}
	return strings.TrimSpace(rest[:end])
}

// isVulnerableGNUTelnetd returns true when the GNU telnetd version is ≤ 2.7,
// which is vulnerable to CVE-2026-32746 (pre-auth stack buffer overflow in
// the LINEMODE SLC option handler, CVSS 9.8).
func isVulnerableGNUTelnetd(ver string) bool {
	parts := strings.SplitN(ver, ".", 2)
	if len(parts) == 0 {
		return false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return false
	}
	if major < 2 {
		return true
	}
	if major > 2 {
		return false
	}
	// major == 2: check minor
	if len(parts) < 2 {
		return true // bare "2" with no minor assumed ≤ 2.7
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}
	return minor <= 7
}

// probeLDAP attempts an LDAP null bind and rootDSE query.
// Returns a map of discovered attributes on success, or nil if the probe fails.
// Detecting an Active Directory DC vs generic LDAP:
//   - AD DCs include "domainControllerFunctionality" in rootDSE
//   - "defaultNamingContext" reveals the AD domain name
func probeLDAP(ctx context.Context, host string, port int) map[string]any {
	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := net.Dialer{}
	dialCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	conn, err := dialer.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))

	// LDAP null bind request (LDAPMessage with BindRequest, empty DN, empty password).
	// BER encoding: SEQUENCE { INTEGER 1, [APPLICATION 0] { INTEGER 3, OCTET_STRING "", [0] "" } }
	nullBind := []byte{
		0x30, 0x0c, // SEQUENCE, length 12
		0x02, 0x01, 0x01, // INTEGER 1 (messageID)
		0x60, 0x07, // BindRequest (APPLICATION 0), length 7
		0x02, 0x01, 0x03, // INTEGER 3 (version)
		0x04, 0x00, // OCTET STRING "" (DN)
		0x80, 0x00, // [0] "" (simple auth, empty password)
	}
	if _, err := conn.Write(nullBind); err != nil {
		return nil
	}

	// Read bind response — expect success (resultCode 0).
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 7 {
		return nil
	}
	// Check for BindResponse (APPLICATION 1) with resultCode 0 (success).
	// Simplified check: look for 0x61 (BindResponse tag) and 0x00 (success) in response.
	found := false
	for i := 0; i < n-1; i++ {
		if buf[i] == 0x61 { // BindResponse
			// resultCode is in the body; 0x0a 0x01 0x00 = ENUMERATED 0 (success)
			for j := i; j < n-2; j++ {
				if buf[j] == 0x0a && buf[j+1] == 0x01 && buf[j+2] == 0x00 {
					found = true
					break
				}
			}
		}
	}
	if !found {
		return nil
	}

	// Now send a searchRequest for rootDSE (base="", scope=baseObject, filter=(objectClass=*))
	// requesting: namingContexts, defaultNamingContext, dnsHostName, domainControllerFunctionality
	rootDSEReq := []byte{
		0x30, 0x59, // SEQUENCE, length 89
		0x02, 0x01, 0x02, // INTEGER 2 (messageID)
		0x63, 0x54, // SearchRequest (APPLICATION 3), length 84
		0x04, 0x00, // baseObject: "" (rootDSE)
		0x0a, 0x01, 0x00, // scope: baseObject (0)
		0x0a, 0x01, 0x00, // derefAliases: neverDerefAliases (0)
		0x02, 0x01, 0x00, // sizeLimit: 0
		0x02, 0x01, 0x00, // timeLimit: 0
		0x01, 0x01, 0x00, // typesOnly: false
		0x87, 0x0b, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x43, 0x6c, 0x61, 0x73, 0x73, // filter: (objectClass=*)
		0x30, 0x34, // attributes SEQUENCE
		0x04, 0x0f, 0x6e, 0x61, 0x6d, 0x69, 0x6e, 0x67, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x73, 0x00, // "namingContexts" (padded)
		0x04, 0x16, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x4e, 0x61, 0x6d, 0x69, 0x6e, 0x67, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x00, 0x00,
		0x04, 0x0b, 0x64, 0x6e, 0x73, 0x48, 0x6f, 0x73, 0x74, 0x4e, 0x61, 0x6d, 0x65, 0x00, // "dnsHostName"
	}
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	_, _ = conn.Write(rootDSEReq)

	// Read rootDSE response — parse text content from response.
	rbuf := make([]byte, 4096)
	rn, _ := conn.Read(rbuf)
	if rn == 0 {
		// Null bind succeeded even if rootDSE failed — still report LDAP exposure.
		return map[string]any{"port": 389, "service": "ldap", "null_bind": true, "is_active_directory": false}
	}

	responseText := string(rbuf[:rn])
	result := map[string]any{
		"port":       port,
		"service":    "ldap",
		"null_bind":  true,
		"is_active_directory": false,
	}

	// Detect AD-specific strings in the response.
	if strings.Contains(responseText, "DC=") {
		result["is_active_directory"] = true
		// Extract defaultNamingContext (e.g. "DC=corp,DC=example,DC=com").
		if idx := strings.Index(responseText, "DC="); idx >= 0 {
			end := idx + 60
			if end > rn {
				end = rn
			}
			candidate := responseText[idx:end]
			if nl := strings.IndexAny(candidate, "\x00\n\r "); nl > 0 {
				candidate = candidate[:nl]
			}
			result["ad_domain"] = candidate
		}
	}
	if strings.Contains(responseText, "domainControllerFunctionality") {
		result["is_active_directory"] = true
	}
	if strings.Contains(responseText, "dnsHostName") {
		result["has_dns_hostname"] = true
	}

	return result
}

// probeEPMD sends an Erlang Port Mapper Daemon NAMES request and returns
// the list of registered node names. Returns nil if the probe fails.
func probeEPMD(ctx context.Context, host string, port int) []string {
	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := net.Dialer{}
	dialCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	conn, err := dialer.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	// EPMD NAMES request: 2-byte big-endian length prefix + 1 byte type (0x6e = NAMES_REQ).
	req := []byte{0x00, 0x01, 0x6e}
	if _, err := conn.Write(req); err != nil {
		return nil
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 5 {
		return nil
	}

	// Response: 4-byte EPMD port (big-endian), then "name <node> at port <port>\n" entries.
	response := string(buf[4:n])
	if !strings.Contains(response, "name ") {
		return nil
	}

	var nodes []string
	for _, line := range strings.Split(response, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "name ") {
			// Format: "name rabbit at port 25672"
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				nodes = append(nodes, parts[1])
			}
		}
	}
	return nodes
}

// ── FTP anonymous login probe ─────────────────────────────────────────────────

// probeFTPAnonymous attempts an FTP anonymous login.
// Returns true when the server accepts USER anonymous + PASS anonymous (230 reply).
func probeFTPAnonymous(ctx context.Context, host string, port int) bool {
	d := &net.Dialer{Timeout: dialTimeout}
	conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck

	buf := make([]byte, 256)
	// Read the banner (220 reply).
	n, err := conn.Read(buf)
	if err != nil || n < 3 || string(buf[:3]) != "220" {
		return false
	}

	// Send USER anonymous.
	if _, err := fmt.Fprintf(conn, "USER anonymous\r\n"); err != nil {
		return false
	}
	conn.SetDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck
	n, err = conn.Read(buf)
	if err != nil || n < 3 {
		return false
	}
	code := string(buf[:3])
	// 331 = password required, 230 = logged in already (very permissive).
	if code != "331" && code != "230" {
		return false
	}
	if code == "230" {
		return true // Logged in without a password
	}

	// Send PASS anonymous.
	if _, err := fmt.Fprintf(conn, "PASS anonymous@beacon.test\r\n"); err != nil {
		return false
	}
	conn.SetDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck
	n, err = conn.Read(buf)
	if err != nil || n < 3 {
		return false
	}
	// 230 = login successful.
	return string(buf[:3]) == "230"
}

// ── SMB null session probe ────────────────────────────────────────────────────

// probeSMBNullSession attempts an SMB null session negotiation.
// Sends SMBv1 Negotiate + SessionSetupAndX with empty credentials.
// Returns true when the server accepts the unauthenticated session (action flag bit 0 = guest/null).
func probeSMBNullSession(ctx context.Context, host string) bool {
	d := &net.Dialer{Timeout: dialTimeout}
	conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:445", host))
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck

	// SMBv1 Negotiate Request — asks for NTLM dialect.
	// NetBIOS Session header (4 bytes) + SMB header (32 bytes) + Negotiate payload.
	negotiate := []byte{
		// NetBIOS session header
		0x00,       // type: Session Message
		0x00, 0x00, 0x54, // length: 84 bytes
		// SMB header
		0xff, 0x53, 0x4d, 0x42, // protocol: \xffSMB
		0x72,                   // command: Negotiate (0x72)
		0x00, 0x00, 0x00, 0x00, // status: 0
		0x18,                   // flags: caseless, canonical
		0x01, 0x28,             // flags2: Unicode, NTLM
		0x00, 0x00,             // PID high
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // signature
		0x00, 0x00,             // reserved
		0x00, 0x00,             // TID
		0xff, 0xfe,             // PID
		0x00, 0x00,             // UID
		0x40, 0x00,             // MID
		// Negotiate request parameters
		0x00,       // WordCount: 0
		0x26, 0x00, // ByteCount: 38
		// Dialects
		0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00, // "NT LM 0.12"
		0x02, 0x53, 0x4d, 0x42, 0x20, 0x32, 0x2e, 0x30, 0x30, 0x32, 0x00,       // "SMB 2.002"
		0x02, 0x53, 0x4d, 0x42, 0x20, 0x32, 0x2e, 0x3f, 0x3f, 0x3f, 0x00,       // "SMB 2.???"
	}

	if _, err := conn.Write(negotiate); err != nil {
		return false
	}
	resp := make([]byte, 256)
	n, err := conn.Read(resp)
	// Valid SMB Negotiate response has \xffSMB at offset 4.
	if err != nil || n < 36 || string(resp[4:8]) != "\xffSMB" {
		return false
	}
	// Status must be 0 (success).
	if resp[9] != 0 || resp[10] != 0 || resp[11] != 0 || resp[12] != 0 {
		return false
	}

	// SMBv1 Session Setup AndX with null credentials (empty password, empty username).
	sessionSetup := []byte{
		// NetBIOS session header
		0x00,
		0x00, 0x00, 0x4a, // length: 74
		// SMB header
		0xff, 0x53, 0x4d, 0x42, // \xffSMB
		0x73,                   // command: Session Setup AndX (0x73)
		0x00, 0x00, 0x00, 0x00, // status: 0
		0x18,
		0x01, 0x20,
		0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00, // TID
		0xff, 0xfe, // PID
		0x00, 0x00, // UID
		0x41, 0x00, // MID
		// Parameters (WordCount=13)
		0x0d,
		0xff,       // AndXCommand: no further commands
		0x00,       // reserved
		0x00, 0x00, // AndXOffset
		0xff, 0xff, // MaxBufferSize
		0x02, 0x00, // MaxMpxCount
		0x01, 0x00, // VcNumber
		0x00, 0x00, 0x00, 0x00, // SessionKey
		0x01, 0x00, // OEMPasswordLen: 1 (null byte)
		0x00, 0x00, // UnicodePasswordLen: 0
		0x00, 0x00, 0x00, 0x00, // reserved
		0x40, 0x00, 0x00, 0x00, // Capabilities
		// Data
		0x16, 0x00, // ByteCount: 22
		0x00,                                           // OEM password: null byte
		// Account: empty string (null terminated)
		0x00, 0x00,
		// PrimaryDomain: "WORKGROUP\0" in UTF-16LE
		0x57, 0x00, 0x4f, 0x00, 0x52, 0x00, 0x4b, 0x00,
		0x47, 0x00, 0x52, 0x00, 0x4f, 0x00, 0x55, 0x00,
		0x50, 0x00, 0x00, 0x00,
	}

	if _, err := conn.Write(sessionSetup); err != nil {
		return false
	}
	conn.SetDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck
	resp2 := make([]byte, 256)
	n2, err := conn.Read(resp2)
	if err != nil || n2 < 36 {
		return false
	}
	// Status must be 0 (NT_STATUS_SUCCESS).
	if resp2[9] != 0 || resp2[10] != 0 || resp2[11] != 0 || resp2[12] != 0 {
		return false
	}
	// Action flags at offset 41 (WordCount area of Session Setup response).
	// Bit 0 set = guest/null session accepted.
	if n2 > 41 {
		return resp2[41]&0x01 != 0
	}
	// If we got a success status with no action byte, treat as null session.
	return true
}

// ── SMTP open relay probe ─────────────────────────────────────────────────────

// probeSMTPOpenRelay tests whether the SMTP server relays mail for arbitrary
// external senders to external recipients — the definition of an open relay.
// Returns true when the server accepts both MAIL FROM and RCPT TO for
// external addresses without authentication.
func probeSMTPOpenRelay(ctx context.Context, host string, port int) bool {
	d := &net.Dialer{Timeout: dialTimeout}
	conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(8 * time.Second)) //nolint:errcheck

	readLine := func() string {
		buf := make([]byte, 512)
		n, _ := conn.Read(buf)
		return strings.TrimSpace(string(buf[:n]))
	}
	send := func(cmd string) string {
		conn.SetDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck
		fmt.Fprintf(conn, "%s\r\n", cmd)                 //nolint:errcheck
		return readLine()
	}

	// Read banner.
	banner := readLine()
	if !strings.HasPrefix(banner, "220") {
		return false
	}

	// EHLO — use a plausible test domain.
	ehlo := send("EHLO beacon-relay-test.example.com")
	if !strings.HasPrefix(ehlo, "250") {
		send("HELO beacon-relay-test.example.com")
	}

	// MAIL FROM external address.
	mailFrom := send("MAIL FROM:<relay-test@beacon-probe.example.com>")
	if !strings.HasPrefix(mailFrom, "250") {
		send("RSET")
		return false
	}

	// RCPT TO a different external domain — relay if accepted.
	rcptTo := send("RCPT TO:<relay-test@beacon-probe-dest.example.com>")
	accepted := strings.HasPrefix(rcptTo, "250") || strings.HasPrefix(rcptTo, "251")

	send("RSET")
	return accepted
}
