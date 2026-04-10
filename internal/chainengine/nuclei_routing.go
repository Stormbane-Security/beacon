package chainengine

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/exploit"
	"github.com/stormbane-security/beacon/internal/finding"
)

// nucleiTagToService maps nuclei template tags to the exploit playbook
// service name. When a nuclei finding contains one of these tags, the
// chain engine can route it to the matching exploit playbook.
var nucleiTagToService = map[string]string{
	// Databases
	"redis":         "redis",
	"mongodb":       "mongodb",
	"mysql":         "mysql",
	"postgresql":    "postgresql",
	"elasticsearch": "elasticsearch",
	"couchdb":       "couchdb",
	"memcached":     "memcached",
	"cassandra":     "cassandra",
	"influxdb":      "influxdb",
	"clickhouse":    "clickhouse",
	"neo4j":         "neo4j",

	// Message queues
	"rabbitmq": "rabbitmq",
	"activemq": "activemq",
	"kafka":    "kafka",
	"mqtt":     "mqtt",
	"nats":     "nats",

	// CI/CD
	"jenkins":  "jenkins",
	"gitlab":   "gitlab",
	"teamcity": "teamcity",
	"drone":    "drone",

	// Infrastructure
	"consul":     "consul",
	"vault":      "vault",
	"docker":     "docker",
	"kubernetes": "kubernetes",
	"etcd":       "etcd",
	"grafana":    "grafana",
	"prometheus": "prometheus",
	"kibana":     "kibana",

	// Web servers
	"tomcat":   "tomcat",
	"apache":   "apache",
	"nginx":    "nginx",
	"spring":   "spring-actuator",
	"sonarqube": "sonarqube",
	"minio":    "minio",

	// AI/ML
	"jupyter": "jupyter",
	"airflow": "airflow",
	"ollama":  "ollama",
	"mlflow":  "mlflow",
	"gradio":  "gradio",

	// CMS / web frameworks
	"wordpress": "wordpress",
	"joomla":    "joomla",
	"drupal":    "drupal",
	"ghost":     "ghost",
	"nextcloud": "nextcloud",
	"django":    "django",
	"laravel":   "laravel",
	"rails":     "rails",
	"fastapi":   "fastapi",

	// Admin panels
	"webmin":     "webmin",
	"splunk":     "splunk",
	"zabbix":     "zabbix",
	"phpmyadmin": "phpmyadmin",
	"jboss":      "jboss",
	"wildfly":    "jboss",
	"coldfusion": "coldfusion",

	// Infrastructure
	"zookeeper":  "zookeeper",
	"hazelcast":  "hazelcast",
	"nacos":      "nacos",
	"nifi":       "nifi",
	"proxmox":    "proxmox",
	"mikrotik":   "mikrotik",
	"kubelet":    "kubelet",

	// Network services
	"rdp":     "rdp",
	"vnc":     "vnc",
	"ftp":     "ftp",
	"ssh":     "ssh",
	"telnet":  "telnet",
	"smtp":    "smtp",
	"snmp":    "snmp",
	"ldap":    "ldap",
	"dns":     "dns",
}

// nucleiTemplateToServiceMap maps specific nuclei template IDs (often CVEs)
// to the exploit playbook service name. This takes priority over tag-based
// matching for known high-impact vulnerabilities.
var nucleiTemplateToServiceMap = map[string]string{
	"CVE-2023-46604": "activemq",      // ActiveMQ RCE
	"CVE-2021-44228": "log4shell",     // Log4Shell
	"CVE-2022-22965": "spring4shell",  // Spring4Shell
	"CVE-2020-1938":  "tomcat",        // GhostCat
	"CVE-2024-3400":  "paloalto",      // PAN-OS RCE
	"CVE-2023-27524": "superset",      // Superset SECRET_KEY
	"CVE-2023-42793": "teamcity",      // TeamCity auth bypass
	"CVE-2021-22205": "gitlab",        // GitLab RCE
	"CVE-2019-11510": "pulse_vpn",     // Pulse Secure file read
	"CVE-2023-22515": "confluence",    // Confluence admin create
	"CVE-2024-21887": "ivanti",        // Ivanti Connect Secure RCE
	"CVE-2023-22518": "confluence",    // Confluence data destruction
	"CVE-2022-26134": "confluence",    // Confluence OGNL injection
	"CVE-2023-20198": "cisco_ios_xe",  // Cisco IOS XE web UI
	"CVE-2023-3519":  "citrix",        // Citrix ADC RCE
	"CVE-2023-4966":  "citrix",        // CitrixBleed
	"CVE-2024-1709":  "screenconnect", // ScreenConnect auth bypass
	"CVE-2023-27997": "fortios",       // FortiOS XORtigate SSL VPN heap overflow RCE
	"CVE-2024-21762": "fortios",       // FortiOS SSL VPN out-of-bounds write RCE
	"CVE-2023-0669":  "goanywhere",    // GoAnywhere MFT pre-auth deserialization RCE
	"CVE-2023-34362": "moveit",        // MOVEit Transfer SQL injection (CL0P)

	// CVE-specific exploit chains — these route to playbooks that have
	// cve_exploits entries with targeted payloads.
	"CVE-2015-1427":  "elasticsearch",    // Groovy sandbox escape RCE
	"CVE-2014-3120":  "elasticsearch",    // MVEL script RCE
	"CVE-2024-23897": "jenkins",          // CLI args4j file read
	"CVE-2019-1003000": "jenkins",        // Pipeline Groovy sandbox bypass
	"CVE-2017-12617": "tomcat",           // PUT method JSP RCE
	"CVE-2021-43798": "grafana",          // Plugin path traversal
	"CVE-2022-29153": "consul",           // SSRF via service registration
	"CVE-2022-22963": "spring-actuator",  // Spring Cloud Function SpEL RCE
	"CVE-2023-28432": "minio",            // Environment variable disclosure

	// Redis CVE exploit chains
	"CVE-2022-0543":  "redis",            // Lua sandbox escape RCE (Debian/Ubuntu)
	"CVE-2023-28856": "redis",            // HINCR command auth bypass
	"CVE-2023-45145": "redis",            // Unix socket race condition

	// MongoDB CVE exploit chains
	"CVE-2017-2604":  "mongodb",          // Auth bypass via wire protocol
	"CVE-2024-7553":  "mongodb",          // BSON deserialization RCE

	// MySQL CVE exploit chains
	"CVE-2012-2122":  "mysql",            // memcmp timing auth bypass
	"CVE-2016-6662":  "mysql",            // Config file manipulation via logging

	// PostgreSQL CVE exploit chains
	"CVE-2019-9193":  "postgresql",       // COPY TO/FROM PROGRAM RCE
	"CVE-2023-39417": "postgresql",       // Extension script injection

	// Memcached CVE exploit chains
	"CVE-2021-22890": "memcached",        // UDP amplification DDoS
	"CVE-2019-11596": "memcached",        // Null pointer crash

	// CouchDB CVE exploit chains
	"CVE-2022-24706": "couchdb",          // Erlang cookie RCE
	"CVE-2017-12635": "couchdb",          // Privilege escalation via user creation

	// Docker / container runtime CVE exploit chains
	"CVE-2019-5736":  "docker",           // runc container escape
	"CVE-2020-15257": "docker",           // containerd host networking escape

	// Kibana CVE exploit chains
	"CVE-2019-7609":  "kibana",           // Timelion prototype pollution RCE
	"CVE-2021-22145": "kibana",           // Security API info disclosure

	// RabbitMQ / Erlang CVE exploit chains
	"CVE-2022-37026": "rabbitmq",         // Erlang/OTP auth bypass
	"CVE-2022-31008": "rabbitmq",         // Credential leak in management UI
	"CVE-2023-46118": "rabbitmq",         // HTTP API DoS

	// Vault CVE exploit chains
	"CVE-2023-25000": "vault",            // PKI engine SSRF

	// Prometheus CVE exploit chains
	"CVE-2021-29622": "prometheus",       // Open redirect

	// GitLab CVE exploit chains (additional)
	"CVE-2023-7028":  "gitlab",           // Account takeover via password reset
	"CVE-2021-22214": "gitlab",           // CI lint SSRF

	// Airflow CVE exploit chains
	"CVE-2020-11978": "airflow",          // Example DAG RCE
	"CVE-2022-40127": "airflow",          // Config endpoint info disclosure

	// SonarQube CVE exploit chains
	"CVE-2024-47910": "sonarqube",        // SSRF

	// Nginx CVE exploit chains
	"CVE-2021-23017": "nginx",            // DNS resolver off-by-one RCE
	"CVE-2017-7529":  "nginx",            // Integer overflow info disclosure

	// Apache httpd CVE exploit chains
	"CVE-2021-41773": "apache",           // Path traversal
	"CVE-2021-42013": "apache",           // Path traversal bypass

	// etcd CVE exploit chains
	"CVE-2020-15115": "etcd",             // Auth bypass via lease revoke
	"CVE-2023-32082": "etcd",             // LeaseTimeToLive info leak

	// Jupyter CVE exploit chains
	"CVE-2023-44461": "jupyter",          // Server SSRF
	"CVE-2020-26215": "jupyter",          // Open redirect

	// Portainer CVE exploit chains
	"CVE-2023-47108": "portainer",        // OTEL DoS
	"CVE-2022-36326": "portainer",        // Unauthorized API access

	// Drone CI CVE exploit chains
	"CVE-2021-33681": "drone",            // SSRF via clone URL

	// ArgoCD CVE exploit chains
	"CVE-2022-29165": "argocd",           // JWT auth bypass
	"CVE-2024-28175": "argocd",           // XSS via application name

	// NATS CVE exploit chains
	"CVE-2023-47090": "nats",             // Auth bypass
	"CVE-2022-29946": "nats",             // Account takeover

	// === Additional CVE routes (all playbook cve_exploits) ===
	// VNC
	"CVE-2006-2369": "vnc",              // RealVNC auth bypass
	"CVE-2019-15681": "vnc",             // TightVNC info leak
	// FTP
	"CVE-2011-2523": "ftp",              // vsftpd backdoor
	"CVE-2015-3306": "ftp",              // ProFTPD mod_copy
	// SNMP
	"CVE-2012-6151": "snmp",             // Net-SNMP AgentX DoS
	"CVE-2017-6742":  "snmp",            // Cisco SNMP RCE
	// JBoss
	"CVE-2015-7501": "jboss",            // JMXInvokerServlet deser
	"CVE-2017-12149": "jboss",           // InvokerTransformer deser
	// Joomla
	"CVE-2015-8562": "joomla",           // Session object injection
	"CVE-2023-23752": "joomla",          // Unauth info disclosure
	// WordPress
	"CVE-2017-8295": "wordpress",        // Host header password reset
	"CVE-2019-8942": "wordpress",        // Crop-image RCE
	// Jenkins (additional)
	"CVE-2018-1000861": "jenkins",       // Stapler RCE
	// phpMyAdmin
	"CVE-2018-12613": "phpmyadmin",      // LFI
	// MikroTik
	"CVE-2018-14847": "mikrotik",        // Winbox file read
	"CVE-2023-32154": "mikrotik",        // IPv6 RCE
	// Laravel
	"CVE-2018-15133": "laravel",         // APP_KEY deser
	"CVE-2021-3129":  "laravel",         // Ignition RCE
	// K8s Dashboard
	"CVE-2018-18264": "k8s_dashboard",   // Skip auth
	"CVE-2020-8565":  "k8s_dashboard",   // Log sanitization
	// RDP
	"CVE-2019-0708": "rdp",              // BlueKeep
	"CVE-2019-1181": "rdp",              // DejaBlue
	// SMTP
	"CVE-2019-10149": "smtp",            // Exim RCE
	"CVE-2020-28018": "smtp",            // Exim use-after-free
	// Django
	"CVE-2019-14234": "django",          // JSONField SQLi
	"CVE-2021-35042": "django",          // order_by SQLi
	// Webmin
	"CVE-2019-15107": "webmin",          // Password reset RCE
	"CVE-2019-15231": "webmin",          // Package updates RCE
	// InfluxDB
	"CVE-2019-20933": "influxdb",        // Auth bypass
	// Rails
	"CVE-2019-5418": "rails",            // Accept header file read
	"CVE-2020-8163": "rails",            // Render injection RCE
	// DNS
	"CVE-2020-1350": "dns",              // SIGRed
	"CVE-2021-25216": "dns",             // BIND GSS-TSIG
	// Pulse VPN
	"CVE-2021-22893": "pulse_vpn",       // Auth bypass RCE
	// LDAP
	"CVE-2021-27928": "ldap",            // MariaDB LDAP bypass
	"CVE-2023-2136":  "ldap",            // OpenLDAP DoS
	// Nacos
	"CVE-2021-29441": "nacos",           // User-Agent auth bypass
	"CVE-2023-34465": "nacos",           // JWT hardcoded
	// Neo4j
	"CVE-2021-34371": "neo4j",           // Bolt Java deser
	"CVE-2023-23926": "neo4j",           // APOC RCE
	// Cassandra
	"CVE-2021-44521": "cassandra",       // UDF sandbox escape
	// Log4Shell (additional)
	"CVE-2021-45046": "log4shell",       // Bypass
	// Zabbix
	"CVE-2022-23131": "zabbix",          // SAML auth bypass
	"CVE-2024-22120": "zabbix",          // Time-based SQLi
	"CVE-2024-36466": "zabbix",          // Session hijack
	// Express
	"CVE-2022-24999": "express",         // qs prototype pollution
	"CVE-2024-29041": "express",         // Open redirect
	// Proxmox
	"CVE-2022-35508": "proxmox",         // Auth bypass
	// Hazelcast
	"CVE-2022-36437": "hazelcast",       // Session fixation
	// Ghost
	"CVE-2022-41654": "ghost",           // Membership bypass
	"CVE-2023-40028": "ghost",           // File read
	// MQTT
	"CVE-2023-0809": "mqtt",             // Mosquitto crash
	"CVE-2023-3028": "mqtt",             // Mosquitto auth bypass
	// Confluence (additional)
	"CVE-2023-22527": "confluence",      // Template injection RCE
	// Kafka
	"CVE-2023-25194": "kafka",           // JNDI injection
	"CVE-2024-31141": "kafka",           // Config traversal
	// Apache (additional)
	"CVE-2023-25690": "apache",          // HTTP smuggling
	"CVE-2023-43622": "apache",          // HTTP/2 DoS
	// ColdFusion
	"CVE-2023-26360": "coldfusion",      // Deser RCE
	"CVE-2024-20767": "coldfusion",      // File read
	// Gitea
	"CVE-2023-27581": "gitea",           // Command injection
	// Superset (additional)
	"CVE-2023-36388": "superset",        // Auth bypass
	// NiFi
	"CVE-2023-34468": "nifi",            // H2 URL injection RCE
	// ZooKeeper
	"CVE-2023-44981": "zookeeper",       // SASL bypass
	"CVE-2019-0201":  "zookeeper",       // getACL bypass
	// Splunk
	"CVE-2023-46214": "splunk",          // XSL RCE
	// ClickHouse
	"CVE-2023-47118": "clickhouse",      // Heap buffer overflow
	// Nextcloud
	"CVE-2023-48239": "nextcloud",       // SSRF via preview
	// SSH (additional)
	"CVE-2023-48795": "ssh",             // Terrapin
	"CVE-2024-6387":  "ssh",             // RegreSSHion
	// MLflow
	"CVE-2023-6014": "mlflow",           // Auth bypass
	"CVE-2023-6831": "mlflow",           // Path traversal
	"CVE-2024-27132": "mlflow",          // RCE
	// Docker (additional)
	"CVE-2024-21626": "docker",          // runc escape
	// FastAPI
	"CVE-2024-24762": "fastapi",         // multipart ReDoS
	// TeamCity (additional)
	"CVE-2024-27198": "teamcity",        // Admin auth bypass
	// Ollama
	"CVE-2024-37032": "ollama",          // Path traversal
	// Gradio
	"CVE-2024-6507": "gradio",           // Path traversal
	// Kubelet
	"CVE-2024-9042": "kubelet",          // Windows node RCE
	// Kubernetes (additional)
	"CVE-2025-1974": "kubernetes",       // IngressNightmare
	// Tomcat (additional)
	"CVE-2025-24813": "tomcat",          // Partial PUT deser
}

// nucleiTemplateToService maps a nuclei finding to the exploit playbook
// service name. It checks template ID first (for CVE-specific routing),
// then falls back to tag-based matching. Returns "" if no mapping exists.
func nucleiTemplateToService(f finding.Finding) string {
	// 1. Check template ID (highest priority — CVE-specific routing).
	if tmplID, ok := f.Evidence["template_id"].(string); ok && tmplID != "" {
		if svc, ok := nucleiTemplateToServiceMap[tmplID]; ok {
			return svc
		}
		// Also check if the template ID contains a CVE prefix that maps.
		tmplUpper := strings.ToUpper(tmplID)
		if strings.HasPrefix(tmplUpper, "CVE-") {
			if svc, ok := nucleiTemplateToServiceMap[tmplUpper]; ok {
				return svc
			}
		}
	}

	// 2. Check tags (broader matching).
	if tags, ok := f.Evidence["tags"].([]string); ok {
		for _, tag := range tags {
			tag = strings.ToLower(tag)
			if svc, ok := nucleiTagToService[tag]; ok {
				return svc
			}
		}
	}

	return ""
}

// isExploitableNucleiTemplate returns true if the nuclei finding represents
// a vulnerability that has a corresponding exploit playbook. This is the
// Matches predicate for the nuclei-to-exploit chain.
func isExploitableNucleiTemplate(f finding.Finding) bool {
	return nucleiTemplateToService(f) != ""
}

// extractHostPort parses the target host and port from a nuclei finding's
// evidence fields. It tries matched_at first, then falls back to the Asset.
func extractHostPort(f finding.Finding) (host string, port int) {
	// Try matched_at (most specific).
	if matchedAt, ok := f.Evidence["matched_at"].(string); ok && matchedAt != "" {
		if h, p := parseHostPort(matchedAt); h != "" {
			return h, p
		}
	}

	// Fall back to Asset field.
	if f.Asset != "" {
		if h, p := parseHostPort(f.Asset); h != "" {
			return h, p
		}
		// Asset might be bare hostname.
		return f.Asset, 0
	}

	return "", 0
}

// parseHostPort extracts host and port from a URL or host:port string.
func parseHostPort(raw string) (string, int) {
	// Try as URL first.
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err == nil && u.Hostname() != "" {
			host := u.Hostname()
			if p := u.Port(); p != "" {
				port, _ := strconv.Atoi(p)
				return host, port
			}
			// Infer port from scheme.
			switch u.Scheme {
			case "https":
				return host, 443
			case "http":
				return host, 80
			}
			return host, 0
		}
	}

	// Try as host:port.
	h, p, err := net.SplitHostPort(raw)
	if err == nil {
		port, _ := strconv.Atoi(p)
		return h, port
	}

	return raw, 0
}

// lookupPlaybook finds the exploit playbook matching the given service name.
func lookupPlaybook(service string) *exploit.Playbook {
	for _, pb := range exploit.Playbooks() {
		if pb.Service == service {
			return pb
		}
	}
	return nil
}

// nucleiToExploitChain routes nuclei CVE findings to the appropriate
// exploit playbook based on the service/technology detected.
var nucleiToExploitChain = Chain{
	Name:        "nuclei_to_exploit",
	Description: "Route nuclei CVE/vulnerability detections to exploit playbooks for post-exploitation",
	Matches: func(f finding.Finding) bool {
		return f.Scanner == "nuclei" && isExploitableNucleiTemplate(f)
	},
	Execute: func(ctx context.Context, e *Engine, trigger finding.Finding) []finding.Finding {
		moduleName := safetyModuleName("nuclei_to_exploit")
		if err := exploit.CheckSafety(moduleName, e.maxSafety); err != nil {
			log.Printf("[chain] safety gate blocked nuclei_to_exploit: %v", err)
			return nil
		}

		service := nucleiTemplateToService(trigger)
		if service == "" {
			return nil
		}

		pb := lookupPlaybook(service)
		if pb == nil {
			log.Printf("[chain] nuclei_to_exploit: no playbook found for service %q", service)
			return nil
		}

		host, port := extractHostPort(trigger)
		if host == "" {
			log.Printf("[chain] nuclei_to_exploit: could not extract host from finding")
			return nil
		}

		// Use first default port from playbook if nuclei didn't provide one.
		if port == 0 && len(pb.DefaultPorts) > 0 {
			port = pb.DefaultPorts[0]
		}

		templateID, _ := trigger.Evidence["template_id"].(string)
		log.Printf("[chain] WARNING: executing nuclei_to_exploit — routing %s to %s playbook against %s:%d",
			templateID, service, host, port)

		makeF := func(checkID finding.CheckID, severity finding.Severity, title, description string, evidence map[string]any) finding.Finding {
			if evidence == nil {
				evidence = make(map[string]any)
			}
			evidence["chain"] = fmt.Sprintf("nuclei(%s) → %s exploit", templateID, service)
			evidence["nuclei_template_id"] = templateID
			evidence["triggered_by"] = trigger.CheckID
			return finding.Finding{
				CheckID:      checkID,
				Module:       "chainengine",
				Scanner:      "chain:nuclei_to_exploit:" + service,
				Severity:     severity,
				Title:        title,
				Description:  description,
				Asset:        trigger.Asset,
				Evidence:     evidence,
				Confidence:   finding.ConfidenceVerified,
				Visibility:   finding.VisibilityAuthenticated,
				EnabledBy:    enabledByRef(trigger),
				ChainDepth:   trigger.ChainDepth + 1,
				DiscoveredAt: time.Now(),
			}
		}

		// Try CVE-specific exploit first — these are surgical, targeted
		// payloads that don't require auth or generic service enumeration.
		if cveFindings := exploit.RunCVEExploit(ctx, pb, templateID, host, port, makeF); len(cveFindings) > 0 {
			return cveFindings
		}

		// Fall back to generic service exploitation (auth + enumeration steps).
		results := exploit.Run(ctx, pb, host, port, makeF, true)

		// If no exploit findings were produced but we did match, emit a
		// routing finding so the user knows the chain was attempted.
		if len(results) == 0 {
			return nil
		}

		return results
	},
}
