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
	"wordpress":  "wordpress",
	"joomla":     "joomla",
	"drupal":     "drupal",
	"ghost":      "ghost",
	"nextcloud":  "nextcloud",
	"django":     "django",
	"laravel":    "laravel",
	"rails":      "rails",
	"fastapi":    "fastapi",
	"craftcms":   "craftcms",
	"magento":    "magento",
	"vbulletin":  "vbulletin",
	"owncloud":   "owncloud",
	"roundcube":  "roundcube",
	"openfire":   "openfire",

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

	// Network appliances / firewalls
	"fortios":    "fortios",
	"fortigate":  "fortios",
	"fortinet":   "fortios",
	"paloalto":   "paloalto",
	"pan-os":     "paloalto",
	"citrix":     "citrix",
	"netscaler":  "citrix",
	"ivanti":     "ivanti",
	"sonicwall":  "sonicwall",
	"sophos":     "fortios",
	"checkpoint": "fortios",
	"f5":         "fortios",
	"bigip":      "fortios",
	"juniper":    "cisco_ios_xe",
	"barracuda":  "barracuda",

	// Microsoft
	"exchange":   "exchange",
	"sharepoint": "sharepoint",
	"outlook":    "outlook",

	// VMware
	"vmware":     "vmware",
	"vcenter":    "vmware",
	"esxi":       "vmware",

	// Other services
	"weblogic":    "jboss",
	"struts":      "apache",
	"shiro":       "shiro",
	"telerik":     "telerik",
	"zimbra":      "zimbra",
	"saltstack":   "saltstack",
	"sysaid":      "sysaid",
	"crushftp":    "crushftp",
	"geoserver":   "geoserver",
	"sap":         "sap",
	"veeam":       "veeam",
	"keycloak":    "keycloak",
	"harbor":      "harbor",
	"n8n":         "n8n",
	"langflow":    "langflow",
	"nextjs":      "nextjs",
	"dlink":       "dlink",
	"hikvision":   "hikvision",
	"manageengine": "manageengine",
	"solarwinds":  "solarwinds",
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

	// === 165 additional CVE routes from checkids.go ===

	// JBoss / Java EE application servers
	"CVE-2010-0738":  "jboss",            // JBoss JMX Console unauth invoke RCE
	"CVE-2016-5983":  "jboss",            // IBM WebSphere admin console deser RCE
	"CVE-2017-1000486": "jboss",          // Primefaces EL injection (JSF/Java EE)
	"CVE-2017-10271": "jboss",            // WebLogic wls-wsat XXE RCE
	"CVE-2019-2725":  "jboss",            // WebLogic /_async/ pre-auth deser RCE
	"CVE-2020-14882": "jboss",            // WebLogic admin console auth bypass
	"CVE-2020-7961":  "jboss",            // Liferay Portal Java deser RCE

	// Apache httpd / PHP-CGI
	"CVE-2012-1823":  "apache",           // PHP-CGI query string arg injection RCE
	"CVE-2018-1335":  "apache",           // Apache Tika Server cmd injection RCE
	"CVE-2024-4577":  "apache",           // PHP CGI Windows arg injection RCE
	"CVE-2024-27316": "apache",           // HTTP/2 CONTINUATION frame DoS
	"CVE-2023-44487": "apache",           // HTTP/2 rapid reset DoS

	// Apache Struts
	"CVE-2017-5638":  "apache",           // Struts 2 OGNL injection RCE (Equifax)
	"CVE-2023-50164": "apache",           // Struts S2-066 file upload path traversal RCE

	// Apache Solr
	"CVE-2019-17558": "apache",           // Solr unauth admin API Velocity SSTI RCE

	// Apache Unomi
	"CVE-2020-13942": "apache",           // Apache Unomi MVEL/OGNL RCE

	// Apache OFBiz
	"CVE-2023-49070": "apache",           // OFBiz pre-auth XML-RPC deser RCE
	"CVE-2023-51467": "apache",           // OFBiz auth bypass
	"CVE-2024-45195": "apache",           // OFBiz force browsing auth bypass

	// Rails
	"CVE-2013-0156":  "rails",            // Rails XML parameter parsing RCE

	// Spring
	"CVE-2016-4977":  "spring-actuator",  // Spring OAuth2 SpEL injection

	// Telnet
	"CVE-2011-4862":  "telnet",           // BSD telnetd Kerberos encrypt overflow RCE
	"CVE-2026-32746": "telnet",           // GNU telnetd pre-auth stack overflow

	// SSH
	"CVE-2014-0224":  "ssh",              // OpenSSL CCS injection MitM (generic TLS)
	"CVE-2018-15473": "ssh",              // OpenSSH username enumeration
	"CVE-2024-3094":  "ssh",              // XZ Utils backdoor → sshd RCE
	"CVE-2025-32433": "ssh",              // Erlang/OTP SSH pre-auth RCE

	// SMTP / Exim
	"CVE-2018-6789":  "smtp",             // Exim base64d heap overflow RCE
	"CVE-2025-26794": "smtp",             // Exim < 4.98.1 SQL injection

	// DNS / NTP
	"CVE-2013-5211":  "dns",              // NTP monlist DDoS amplification

	// Cisco IOS XE / ASA / NX-OS / FMC
	"CVE-2018-0171":  "cisco_ios_xe",     // Cisco Smart Install unauth config RW
	"CVE-2023-20269": "cisco_ios_xe",     // Cisco ASA/FTD SSL VPN brute-force
	"CVE-2024-20353": "cisco_ios_xe",     // Cisco ASA/FTD web mgmt DoS (ArcaneDoor)
	"CVE-2024-20359": "cisco_ios_xe",     // Cisco ASA persistent implant (ArcaneDoor)
	"CVE-2024-20399": "cisco_ios_xe",     // Cisco NX-OS CLI injection
	"CVE-2025-20333": "cisco_ios_xe",     // Cisco ASA/FTD pre-auth RCE

	// Cisco FMC
	"CVE-2026-20131": "cisco_ios_xe",     // Cisco FMC pre-auth Java deser RCE

	// Kubernetes
	"CVE-2018-1002105": "kubernetes",     // K8s API server WebSocket priv esc

	// FortiOS / FortiProxy / FortiManager / FortiWeb
	"CVE-2018-13379": "fortios",          // FortiOS SSL VPN cred file read
	"CVE-2022-40684": "fortios",          // FortiOS/FortiProxy header auth bypass
	"CVE-2024-55591": "fortios",          // FortiOS WebSocket auth bypass
	"CVE-2024-47575": "fortios",          // FortiManager FortiJump unauth RCE
	"CVE-2023-48788": "fortios",          // FortiClient EMS SQLi RCE
	"CVE-2025-64446": "fortios",          // FortiWeb path traversal auth bypass
	"CVE-2026-24858": "fortios",          // FortiOS FortiCloud SSO auth bypass

	// ColdFusion
	"CVE-2018-15961": "coldfusion",       // ColdFusion FCKEditor file upload RCE

	// Palo Alto Networks
	"CVE-2019-1579":  "paloalto",         // PAN-OS GlobalProtect unauth RCE
	"CVE-2024-0012":  "paloalto",         // PAN-OS mgmt auth bypass
	"CVE-2024-9463":  "paloalto",         // Expedition OS cmd injection
	"CVE-2024-9474":  "paloalto",         // PAN-OS mgmt priv esc

	// Citrix
	"CVE-2019-19781": "citrix",           // Citrix ADC/Gateway unauth info leak
	"CVE-2023-48365": "citrix",           // Qlik Sense tunneling auth bypass (similar appliance)
	"CVE-2025-5777":  "citrix",           // Citrix NetScaler memory disclosure

	// Ivanti
	"CVE-2023-46805": "ivanti",           // Ivanti Connect Secure path traversal auth bypass
	"CVE-2024-21893": "ivanti",           // Ivanti CS/PS SAML SSRF auth bypass
	"CVE-2025-0282":  "ivanti",           // Ivanti CS stack overflow pre-auth RCE
	"CVE-2023-35078": "ivanti",           // Ivanti EPMM unauth API access
	"CVE-2023-35081": "ivanti",           // Ivanti EPMM path traversal
	"CVE-2026-1281":  "ivanti",           // Ivanti EPMM MDM pre-auth cmd injection
	"CVE-2026-1603":  "ivanti",           // Ivanti EPM auth bypass

	// Confluence (additional)
	"CVE-2019-11580": "confluence",       // Atlassian Crowd pdkinstall (Atlassian ecosystem)

	// Drupal
	"CVE-2014-3704":  "drupal",           // Drupalgeddon1 SQL injection
	"CVE-2018-7600":  "drupal",           // Drupalgeddon2 RCE

	// WordPress (additional)
	"CVE-2023-28121": "wordpress",        // WooCommerce Payments auth bypass
	"CVE-2023-2982":  "wordpress",        // MiniOrange Social Login auth bypass
	"CVE-2023-32243": "wordpress",        // Elementor Pro RCE
	"CVE-2023-6875":  "wordpress",        // POST SMTP Mailer auth bypass
	"CVE-2024-27956": "wordpress",        // WP-Automatic SQLi
	"CVE-2024-2876":  "wordpress",        // Email Subscribers SQLi

	// Gitea
	"CVE-2022-30781": "gitea",            // Gitea shell cmd injection

	// TeamCity (additional)
	"CVE-2024-27199": "teamcity",         // TeamCity path-traversal auth bypass

	// Airflow (additional)
	"CVE-2024-39877": "airflow",          // Airflow DAG author code execution

	// Kibana (additional)
	"CVE-2025-25015": "kibana",           // Kibana prototype pollution RCE

	// Redis (additional)
	"CVE-2025-49844": "redis",            // Redis unauth RCE

	// Laravel
	"CVE-2025-54068": "laravel",          // Laravel Livewire pre-auth RCE

	// Nginx
	"CVE-2026-27944": "nginx",            // Nginx-UI unauth backup + key disclosure

	// FTP (additional)
	"CVE-2025-47812": "ftp",              // Wing FTP Server pre-auth RCE

	// === Network appliances / firewalls (no dedicated playbook — nearest match) ===

	// Juniper (route to cisco_ios_xe — similar network appliance)
	"CVE-2023-36844": "cisco_ios_xe",     // Juniper J-Web PHP env injection RCE
	"CVE-2024-21591": "cisco_ios_xe",     // Juniper J-Web type confusion RCE
	"CVE-2026-21902": "cisco_ios_xe",     // Juniper PTX pre-auth RCE

	// Sophos Firewall
	"CVE-2022-3236":  "fortios",          // Sophos Firewall auth bypass/RCE (similar appliance)

	// Check Point
	"CVE-2024-24919": "fortios",          // Check Point CloudGuard file read (similar appliance)

	// F5 BIG-IP
	"CVE-2020-5902":  "fortios",          // F5 BIG-IP TMUI RCE
	"CVE-2022-1388":  "fortios",          // F5 BIG-IP iControl REST RCE
	"CVE-2023-46747": "fortios",          // F5 BIG-IP config utility auth bypass

	// === Microsoft products ===

	// Exchange
	"CVE-2021-26855": "exchange",         // ProxyLogon SSRF
	"CVE-2021-34473": "exchange",         // ProxyShell

	// SharePoint
	"CVE-2023-24955": "sharepoint",       // SharePoint RCE
	"CVE-2023-29357": "sharepoint",       // SharePoint JWT none-alg auth bypass
	"CVE-2024-38094": "sharepoint",       // SharePoint deser RCE

	// Outlook
	"CVE-2024-21413": "outlook",          // Outlook moniker link RCE

	// Office
	"CVE-2023-36884": "outlook",          // Office HTML RCE (Storm-0978)

	// === VMware ===
	"CVE-2021-21985": "vmware",           // vCenter unauth RCE
	"CVE-2022-22954": "vmware",           // Workspace ONE SSTI RCE
	"CVE-2023-34048": "vmware",           // vCenter OOB write RCE
	"CVE-2024-22252": "vmware",           // VMware UHCI UAF VM escape
	"CVE-2024-37085": "vmware",           // ESXi AD auth bypass
	"CVE-2021-22054": "vmware",           // Omnissa Workspace ONE SSRF

	// === ManageEngine ===
	"CVE-2020-10189": "manageengine",     // Desktop Central pre-auth RCE
	"CVE-2021-40539": "manageengine",     // ADSelfService Plus auth bypass RCE
	"CVE-2021-44077": "manageengine",     // ServiceDesk Plus file upload RCE
	"CVE-2022-47966": "manageengine",     // SAML pre-auth RCE

	// === SolarWinds ===
	"CVE-2020-10148": "solarwinds",       // SolarWinds Orion auth bypass
	"CVE-2025-26399": "solarwinds",       // SolarWinds Web Help Desk RCE

	// === SonicWall ===
	"CVE-2021-20028": "sonicwall",        // SonicWall SMA pre-auth SQLi

	// === Barracuda ===
	"CVE-2023-2868":  "barracuda",        // Barracuda ESG pre-auth cmd injection

	// === IoT / embedded devices ===

	// D-Link
	"CVE-2019-16920": "dlink",            // D-Link HNAP unauth cmd injection
	"CVE-2024-10914": "dlink",            // D-Link NAS cmd injection
	"CVE-2024-3273":  "dlink",            // D-Link NAS backdoor + cmd injection

	// Hikvision
	"CVE-2017-7921":  "hikvision",        // Hikvision IP camera ISAPI unauth

	// TP-Link
	"CVE-2023-1389":  "tplink",           // TP-Link Omada auth bypass + RCE

	// Telesquare
	"CVE-2024-29269": "telesquare",       // Telesquare firmware cmd injection

	// === UPnP / generic network ===
	"CVE-2012-5958":  "upnp",             // libupnp SSDP buffer overflow RCE

	// === SMB ===
	"CVE-2017-0144":  "smb",              // EternalBlue SMBv1 RCE

	// === Intel AMT ===
	"CVE-2017-5689":  "amt",              // Intel AMT empty-digest auth bypass

	// === Apache Shiro ===
	"CVE-2016-4437":  "shiro",            // Apache Shiro rememberMe deser RCE

	// === IIS ===
	"CVE-2015-1635":  "iis",              // IIS HTTP.sys Range header DoS/RCE

	// === Rejetto HFS ===
	"CVE-2014-6287":  "hfs",              // Rejetto HFS RCE

	// === OX AppSuite ===
	"CVE-2016-4047":  "ox_appsuite",      // OX AppSuite SSRF

	// === DotNetNuke ===
	"CVE-2017-0929":  "dotnetnuke",       // DNN path traversal machineKey RCE

	// === Telerik ===
	"CVE-2019-18935": "telerik",          // Telerik RadAsyncUpload pre-auth deser
	"CVE-2024-6327":  "telerik",          // Telerik Report Server deser RCE

	// === MobileIron ===
	"CVE-2020-15505": "mobileiron",       // MobileIron MDM RCE

	// === vBulletin ===
	"CVE-2020-17496": "vbulletin",        // vBulletin PHP eval RCE

	// === WSO2 ===
	"CVE-2022-29464": "wso2",             // WSO2 file upload RCE

	// === Magento / Adobe Commerce ===
	"CVE-2022-24086": "magento",          // Magento template injection RCE

	// === Oracle E-Business Suite ===
	"CVE-2022-21587": "oracle_ebs",       // Oracle EBS RF.jsp file read

	// === Zimbra ===
	"CVE-2022-37042": "zimbra",           // Zimbra mboximport auth bypass RCE

	// === SaltStack ===
	"CVE-2021-25281": "saltstack",        // SaltStack API auth bypass

	// === Accellion FTA ===
	"CVE-2021-27101": "accellion",        // Accellion FTA data extortion

	// === Openfire ===
	"CVE-2023-32315": "openfire",         // Openfire path traversal auth bypass

	// === ownCloud ===
	"CVE-2023-49103": "owncloud",         // ownCloud phpinfo() credential leak

	// === SysAid ===
	"CVE-2023-47246": "sysaid",           // SysAid path traversal WAR upload RCE

	// === Pulse VPN (additional) ===
	// (already have pulse_vpn in existing table)

	// === File transfer appliances ===

	// CrushFTP
	"CVE-2024-4040":  "crushftp",         // CrushFTP VFS sandbox escape RCE

	// Cleo Harmony
	"CVE-2024-50623": "cleo",             // Cleo Harmony file upload RCE
	"CVE-2024-55956": "cleo",             // Cleo Harmony autorun file execution

	// Progress Kemp LoadMaster
	"CVE-2024-1212":  "loadmaster",       // Kemp LoadMaster cmd injection

	// === Roundcube ===
	"CVE-2023-43770": "roundcube",        // Roundcube XSS → victim RCE

	// === JumpServer ===
	"CVE-2023-42820": "jumpserver",       // JumpServer MFA auth bypass

	// === GeoServer ===
	"CVE-2024-36401": "geoserver",        // GeoServer eval injection RCE

	// === pgAdmin ===
	"CVE-2024-3116":  "pgadmin",          // pgAdmin validate binary path cmd injection

	// === CUPS ===
	"CVE-2024-47176": "cups",             // CUPS cups-browsed RCE

	// === Next.js ===
	"CVE-2025-29927": "nextjs",           // Next.js middleware auth bypass

	// === Vite ===
	"CVE-2025-30208": "vite",             // Vite dev server file read

	// === SAP NetWeaver ===
	"CVE-2025-31324": "sap",              // SAP NetWeaver file upload RCE

	// === Craft CMS ===
	"CVE-2025-32432": "craftcms",         // Craft CMS pre-auth code injection

	// === HPE OneView ===
	"CVE-2025-37164": "hpe",              // HPE OneView pre-auth RCE

	// === Veeam ===
	"CVE-2025-23120": "veeam",            // Veeam B&R unauth deser RCE

	// === n8n ===
	"CVE-2026-21858": "n8n",              // n8n pre-auth RCE
	"CVE-2025-68613": "n8n",              // n8n pre-auth RCE (alternate CVE)

	// === BeyondTrust ===
	"CVE-2026-1731":  "beyondtrust",      // BeyondTrust pre-auth cmd injection

	// === Langflow ===
	"CVE-2026-33017": "langflow",         // Langflow AI pipeline pre-auth RCE

	// === Keycloak ===
	"CVE-2026-3047":  "keycloak",         // Keycloak SAML signature bypass

	// === Harbor ===
	"CVE-2026-4404":  "harbor",           // Harbor default admin credentials

	// === MCP Server ===
	"CVE-2026-27825": "mcp",              // MCP server unauth SSRF/RCE

	// === Open WebUI ===
	"CVE-2024-1520":  "openwebui",        // Open WebUI cmd injection

	// === aiohttp ===
	"CVE-2024-23334": "aiohttp",          // aiohttp path traversal

	// === curl ===
	"CVE-2023-38545": "curl",             // curl SOCKS5 heap overflow

	// === WinRAR ===
	"CVE-2023-40477": "winrar",           // WinRAR recovery volume RCE

	// === PyArrow ===
	"CVE-2023-47248": "pyarrow",          // PyArrow IPC deser RCE

	// === js2py ===
	"CVE-2024-28397": "js2py",            // js2py sandbox escape RCE

	// === glibc ===
	"CVE-2024-2961":  "glibc",            // glibc iconv buffer overflow RCE

	// === git ===
	"CVE-2024-32002": "git",              // git recursive clone symlink RCE

	// === systemd ===
	"CVE-2023-26604": "systemd",          // systemd less pager traversal

	// === Samba / WINS ===
	"CVE-2025-10230": "samba",            // Samba WINS server exposure
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
