package portscan

import (
	"context"
	"fmt"
	"strings"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/scanlog"
)

// CVEVersionRule defines a version-range check for a specific CVE.
// When a service's version falls within [MinVersion, MaxVersion), the rule matches.
type CVEVersionRule struct {
	CheckID     finding.CheckID
	CVE         string // e.g. "CVE-2024-6387"
	Service     string // normalized service name (lowercase)
	Description string
	MinVersion  string           // empty = any version below MaxVersion
	MaxVersion  string           // versions < this are vulnerable
	Severity    finding.Severity
}

// cveVersionRules is the built-in CVE version database. Each rule maps a
// service+version range to a known CVE. This allows beacon to emit CVE
// findings from extracted version strings without nuclei or nmap.
var cveVersionRules = []CVEVersionRule{
	// ── Web Servers ────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEApacheTraversal2021,
		CVE:         "CVE-2021-41773",
		Service:     "apache",
		Description: "Apache 2.4.49 path traversal — arbitrary file read via URL-encoded dot-segments",
		MinVersion:  "2.4.49",
		MaxVersion:  "2.4.50",
		Severity:    finding.SeverityHigh,
	},
	{
		CheckID:     finding.CheckCVEApacheTraversalBypass2021,
		CVE:         "CVE-2021-42013",
		Service:     "apache",
		Description: "Apache 2.4.49–2.4.50 double-encoding path traversal bypass → RCE",
		MinVersion:  "2.4.49",
		MaxVersion:  "2.4.51",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVENginxRangeInfoLeak,
		CVE:         "CVE-2017-7529",
		Service:     "nginx",
		Description: "nginx integer overflow in Range header leaks memory contents",
		MinVersion:  "",
		MaxVersion:  "1.13.3",
		Severity:    finding.SeverityHigh,
	},
	{
		CheckID:     finding.CheckCVENginxResolverRCE,
		CVE:         "CVE-2021-23017",
		Service:     "nginx",
		Description: "nginx DNS resolver off-by-one write → remote code execution",
		MinVersion:  "",
		MaxVersion:  "1.21.0",
		Severity:    finding.SeverityCritical,
	},

	// ── Databases ──────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEMySQLAuthBypass2012,
		CVE:         "CVE-2012-2122",
		Service:     "mysql",
		Description: "MySQL memcmp timing auth bypass — ~1/256 chance per login attempt",
		MinVersion:  "5.1.0",
		MaxVersion:  "5.1.63",
		Severity:    finding.SeverityHigh,
	},
	{
		CheckID:     finding.CheckCVEMySQLAuthBypass2012,
		CVE:         "CVE-2012-2122",
		Service:     "mysql",
		Description: "MySQL 5.5.x memcmp timing auth bypass — ~1/256 chance per login attempt",
		MinVersion:  "5.5.0",
		MaxVersion:  "5.5.24",
		Severity:    finding.SeverityHigh,
	},
	{
		CheckID:     finding.CheckCVEPostgreSQLCopyRCE2019,
		CVE:         "CVE-2019-9193",
		Service:     "postgresql",
		Description: "PostgreSQL COPY TO/FROM PROGRAM — authenticated RCE via SQL",
		MinVersion:  "9.3.0",
		MaxVersion:  "11.3",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEElasticsearchGroovyRCE,
		CVE:         "CVE-2015-1427",
		Service:     "elasticsearch",
		Description: "Elasticsearch Groovy sandbox escape → unauthenticated RCE",
		MinVersion:  "",
		MaxVersion:  "1.4.3",
		Severity:    finding.SeverityCritical,
	},

	// ── CI/CD ──────────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEJenkinsCLIFileRead,
		CVE:         "CVE-2024-23897",
		Service:     "jenkins",
		Description: "Jenkins args4j @file CLI arbitrary file read",
		MinVersion:  "",
		MaxVersion:  "2.442",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEGitLabRCE,
		CVE:         "CVE-2021-22205",
		Service:     "gitlab",
		Description: "GitLab ExifTool pre-auth RCE — arbitrary command execution",
		MinVersion:  "",
		MaxVersion:  "13.10.3",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVETeamCityRPC2,
		CVE:         "CVE-2023-42793",
		Service:     "teamcity",
		Description: "TeamCity /RPC2 wildcard bypass → admin token creation",
		MinVersion:  "",
		MaxVersion:  "2023.05.4",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVETeamCityAuthBypass,
		CVE:         "CVE-2024-27198",
		Service:     "teamcity",
		Description: "TeamCity REST API path-confusion auth bypass → admin access",
		MinVersion:  "",
		MaxVersion:  "2023.11.4",
		Severity:    finding.SeverityCritical,
	},

	// ── Infrastructure ─────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEGrafanaPathTraversal,
		CVE:         "CVE-2021-43798",
		Service:     "grafana",
		Description: "Grafana plugin path traversal → arbitrary file read",
		MinVersion:  "8.0.0",
		MaxVersion:  "8.3.1",
		Severity:    finding.SeverityHigh,
	},
	{
		CheckID:     finding.CheckCVEVaultPKISSRF,
		CVE:         "CVE-2023-25000",
		Service:     "vault",
		Description: "HashiCorp Vault PKI engine SSRF",
		MinVersion:  "",
		MaxVersion:  "1.13.1",
		Severity:    finding.SeverityHigh,
	},
	{
		CheckID:     finding.CheckCVEConsulSSRF2022,
		CVE:         "CVE-2022-29153",
		Service:     "consul",
		Description: "Consul HTTP API SSRF via redirect-traffic-to",
		MinVersion:  "",
		MaxVersion:  "1.9.17",
		Severity:    finding.SeverityHigh,
	},

	// ── SSH ────────────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEOpenSSHRegreSSHion,
		CVE:         "CVE-2024-6387",
		Service:     "openssh",
		Description: "OpenSSH signal handler race condition → unauthenticated RCE",
		MinVersion:  "8.5",
		MaxVersion:  "9.8",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEOpenSSHUsernameEnum,
		CVE:         "CVE-2018-15473",
		Service:     "openssh",
		Description: "OpenSSH username enumeration via malformed auth packet",
		MinVersion:  "",
		MaxVersion:  "7.8",
		Severity:    finding.SeverityMedium,
	},
	{
		CheckID:     finding.CheckCVEOpenSSHTerrapin,
		CVE:         "CVE-2023-48795",
		Service:     "openssh",
		Description: "Terrapin SSH prefix truncation attack — downgrade handshake integrity",
		MinVersion:  "",
		MaxVersion:  "9.6",
		Severity:    finding.SeverityMedium,
	},

	// ── Container ──────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVERuncContainerEscape,
		CVE:         "CVE-2019-5736",
		Service:     "runc",
		Description: "runc container escape → host root compromise",
		MinVersion:  "",
		MaxVersion:  "1.0.1",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVERuncContainerEscape,
		CVE:         "CVE-2019-5736",
		Service:     "docker",
		Description: "Docker runc container escape → host root compromise (runc < 1.0.1)",
		MinVersion:  "",
		MaxVersion:  "19.3.0",
		Severity:    finding.SeverityCritical,
	},

	// ── Message Queues ─────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEActiveMQRCE,
		CVE:         "CVE-2023-46604",
		Service:     "activemq",
		Description: "Apache ActiveMQ ClassInfo deserialization → pre-auth RCE",
		MinVersion:  "",
		MaxVersion:  "5.15.16",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEActiveMQRCE,
		CVE:         "CVE-2023-46604",
		Service:     "activemq",
		Description: "Apache ActiveMQ 5.16.x ClassInfo deserialization → pre-auth RCE",
		MinVersion:  "5.16.0",
		MaxVersion:  "5.16.7",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEActiveMQRCE,
		CVE:         "CVE-2023-46604",
		Service:     "activemq",
		Description: "Apache ActiveMQ 5.17.x ClassInfo deserialization → pre-auth RCE",
		MinVersion:  "5.17.0",
		MaxVersion:  "5.17.6",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEActiveMQRCE,
		CVE:         "CVE-2023-46604",
		Service:     "activemq",
		Description: "Apache ActiveMQ 5.18.x ClassInfo deserialization → pre-auth RCE",
		MinVersion:  "5.18.0",
		MaxVersion:  "5.18.3",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVERedisLuaSandboxEscape,
		CVE:         "CVE-2022-0543",
		Service:     "redis",
		Description: "Redis on Debian/Ubuntu Lua sandbox escape → RCE",
		MinVersion:  "5.0.0",
		MaxVersion:  "7.0.0",
		Severity:    finding.SeverityCritical,
	},

	// ── CMS / Network Appliance ────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEFortiOSXORtigateRCE,
		CVE:         "CVE-2023-27997",
		Service:     "fortios",
		Description: "FortiOS SSL VPN heap overflow → pre-auth RCE (XORtigate)",
		MinVersion:  "6.0.0",
		MaxVersion:  "7.2.5",
		Severity:    finding.SeverityCritical,
	},

	// ── Additional high-impact CVEs ────────────────────────────────────

	// Apache Tomcat partial PUT → deserialization RCE
	{
		CheckID:     finding.CheckCVETomcatPartialPUT,
		CVE:         "CVE-2025-24813",
		Service:     "tomcat",
		Description: "Apache Tomcat partial PUT on .session path → deserialization RCE",
		MinVersion:  "9.0.0",
		MaxVersion:  "9.0.99",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVETomcatPartialPUT,
		CVE:         "CVE-2025-24813",
		Service:     "tomcat",
		Description: "Apache Tomcat 10.1.x partial PUT on .session path → deserialization RCE",
		MinVersion:  "10.1.0",
		MaxVersion:  "10.1.35",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVETomcatPartialPUT,
		CVE:         "CVE-2025-24813",
		Service:     "tomcat",
		Description: "Apache Tomcat 11.x partial PUT on .session path → deserialization RCE",
		MinVersion:  "11.0.0",
		MaxVersion:  "11.0.3",
		Severity:    finding.SeverityCritical,
	},

	// Spring4Shell
	{
		CheckID:     finding.CheckCVESpring4Shell,
		CVE:         "CVE-2022-22965",
		Service:     "spring",
		Description: "Spring MVC classloader manipulation → RCE via class.module.classLoader",
		MinVersion:  "5.3.0",
		MaxVersion:  "5.3.18",
		Severity:    finding.SeverityCritical,
	},

	// vsFTPd backdoor
	{
		CheckID:     finding.CheckPortFTPVsftpdBackdoor,
		CVE:         "CVE-2011-2523",
		Service:     "vsftpd",
		Description: "vsFTPd 2.3.4 supply-chain backdoor — smiley :) trigger opens shell on port 6200",
		MinVersion:  "2.3.4",
		MaxVersion:  "2.3.5",
		Severity:    finding.SeverityCritical,
	},

	// Confluence OGNL RCE
	{
		CheckID:     finding.CheckCVEConfluenceOGNL,
		CVE:         "CVE-2022-26134",
		Service:     "confluence",
		Description: "Confluence OGNL injection → pre-auth RCE",
		MinVersion:  "1.3.0",
		MaxVersion:  "7.18.1",
		Severity:    finding.SeverityCritical,
	},

	// Confluence setup wizard bypass
	{
		CheckID:     finding.CheckCVEConfluenceSetup,
		CVE:         "CVE-2023-22515",
		Service:     "confluence",
		Description: "Confluence setup wizard accessible → unauthenticated admin creation",
		MinVersion:  "8.0.0",
		MaxVersion:  "8.5.2",
		Severity:    finding.SeverityCritical,
	},

	// Log4Shell (generic Java services reporting Log4j version)
	{
		CheckID:     finding.CheckCVELog4Shell,
		CVE:         "CVE-2021-44228",
		Service:     "log4j",
		Description: "Log4j JNDI injection → unauthenticated RCE",
		MinVersion:  "2.0.0",
		MaxVersion:  "2.15.0",
		Severity:    finding.SeverityCritical,
	},

	// Exchange ProxyLogon
	{
		CheckID:     finding.CheckCVEExchangeProxyLogon,
		CVE:         "CVE-2021-26855",
		Service:     "exchange",
		Description: "Exchange ProxyLogon SSRF → pre-auth RCE chain",
		MinVersion:  "15.0.0",
		MaxVersion:  "15.2.792",
		Severity:    finding.SeverityCritical,
	},

	// vCenter
	{
		CheckID:     finding.CheckCVEvCenterExposed,
		CVE:         "CVE-2021-21985",
		Service:     "vcenter",
		Description: "VMware vCenter VSAN Health Check plugin RCE",
		MinVersion:  "6.5.0",
		MaxVersion:  "7.0.3",
		Severity:    finding.SeverityCritical,
	},

	// F5 BIG-IP iControl REST auth bypass
	{
		CheckID:     finding.CheckCVEF5BigIPAuthBypass,
		CVE:         "CVE-2022-1388",
		Service:     "bigip",
		Description: "F5 BIG-IP iControl REST unauthenticated RCE",
		MinVersion:  "13.0.0",
		MaxVersion:  "17.0.1",
		Severity:    finding.SeverityCritical,
	},

	// F5 BIG-IP TMUI RCE
	{
		CheckID:     finding.CheckCVEF5BigIPTMUI,
		CVE:         "CVE-2020-5902",
		Service:     "bigip",
		Description: "F5 BIG-IP TMUI RCE via /tmui/login.jsp path traversal",
		MinVersion:  "11.6.0",
		MaxVersion:  "16.0.1",
		Severity:    finding.SeverityCritical,
	},

	// FortiOS auth bypass
	{
		CheckID:     finding.CheckCVEFortiOSAuthBypass,
		CVE:         "CVE-2022-40684",
		Service:     "fortios",
		Description: "FortiOS/FortiProxy HTTP header auth bypass → admin access",
		MinVersion:  "7.0.0",
		MaxVersion:  "7.2.2",
		Severity:    finding.SeverityCritical,
	},

	// FortiOS SSL VPN RCE
	{
		CheckID:     finding.CheckCVEFortiOSSSLVPN,
		CVE:         "CVE-2024-21762",
		Service:     "fortios",
		Description: "FortiOS SSL VPN out-of-bounds write → unauthenticated RCE",
		MinVersion:  "6.0.0",
		MaxVersion:  "7.4.3",
		Severity:    finding.SeverityCritical,
	},

	// Citrix Bleed
	{
		CheckID:     finding.CheckCVECitrixBleed,
		CVE:         "CVE-2023-4966",
		Service:     "netscaler",
		Description: "Citrix NetScaler OIDC session token memory leak",
		MinVersion:  "12.1.0",
		MaxVersion:  "14.1.9",
		Severity:    finding.SeverityCritical,
	},

	// SaltStack API auth bypass
	{
		CheckID:     finding.CheckCVESaltStackAPI,
		CVE:         "CVE-2021-25281",
		Service:     "salt",
		Description: "SaltStack API auth bypass + path traversal → RCE",
		MinVersion:  "3002.0",
		MaxVersion:  "3003.0",
		Severity:    finding.SeverityCritical,
	},

	// WebLogic console bypass
	{
		CheckID:     finding.CheckCVEWebLogicConsole,
		CVE:         "CVE-2020-14882",
		Service:     "weblogic",
		Description: "Oracle WebLogic admin console auth bypass → RCE",
		MinVersion:  "10.3.6",
		MaxVersion:  "14.1.2",
		Severity:    finding.SeverityCritical,
	},

	// Jenkins CLI deserialization (older)
	{
		CheckID:     finding.CheckCVEJenkinsCLIJavaDeser,
		CVE:         "CVE-2017-1000353",
		Service:     "jenkins",
		Description: "Jenkins CLI Java deserialization RCE",
		MinVersion:  "",
		MaxVersion:  "2.56",
		Severity:    finding.SeverityCritical,
	},

	// Kibana prototype pollution RCE
	{
		CheckID:     finding.CheckPortKibanaVulnerable,
		CVE:         "CVE-2025-25015",
		Service:     "kibana",
		Description: "Kibana prototype pollution → RCE",
		MinVersion:  "8.15.0",
		MaxVersion:  "8.17.3",
		Severity:    finding.SeverityCritical,
	},

	// Redis CVE-2025 RCE
	{
		CheckID:     finding.CheckPortRedisVulnerableCVE2025,
		CVE:         "CVE-2025-49844",
		Service:     "redis",
		Description: "Redis unauthenticated RCE",
		MinVersion:  "7.0.0",
		MaxVersion:  "7.2.11",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckPortRedisVulnerableCVE2025,
		CVE:         "CVE-2025-49844",
		Service:     "redis",
		Description: "Redis 7.4.x unauthenticated RCE",
		MinVersion:  "7.4.0",
		MaxVersion:  "7.4.6",
		Severity:    finding.SeverityCritical,
	},

	// Openfire path traversal auth bypass
	{
		CheckID:     finding.CheckCVEOpenfire,
		CVE:         "CVE-2023-32315",
		Service:     "openfire",
		Description: "Openfire path traversal on setup pages → auth bypass",
		MinVersion:  "3.10.0",
		MaxVersion:  "4.7.5",
		Severity:    finding.SeverityCritical,
	},

	// VMware Workspace ONE SSTI
	{
		CheckID:     finding.CheckCVEVMwareWorkspaceONE,
		CVE:         "CVE-2022-22954",
		Service:     "workspace-one",
		Description: "VMware Workspace ONE Access FreeMarker SSTI → RCE",
		MinVersion:  "20.10.0",
		MaxVersion:  "22.09.1",
		Severity:    finding.SeverityCritical,
	},

	// Erlang/OTP SSH pre-auth RCE
	{
		CheckID:     finding.CheckCVEErlangOTPSSH,
		CVE:         "CVE-2025-32433",
		Service:     "erlang",
		Description: "Erlang/OTP SSH pre-auth unauthenticated RCE (OTP 26.x)",
		MinVersion:  "",
		MaxVersion:  "26.2.5.11",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEErlangOTPSSH,
		CVE:         "CVE-2025-32433",
		Service:     "erlang",
		Description: "Erlang/OTP SSH pre-auth unauthenticated RCE (OTP 27.x)",
		MinVersion:  "27.0",
		MaxVersion:  "27.3.3",
		Severity:    finding.SeverityCritical,
	},

	// Erlang/OTP auth bypass
	{
		CheckID:     finding.CheckCVEErlangOTPAuthBypass,
		CVE:         "CVE-2022-37026",
		Service:     "erlang",
		Description: "Erlang/OTP client certificate validation bypass",
		MinVersion:  "",
		MaxVersion:  "24.3.4.5",
		Severity:    finding.SeverityCritical,
	},

	// Gitea command injection
	{
		CheckID:     finding.CheckCVEGiteaCMDInjection,
		CVE:         "CVE-2022-30781",
		Service:     "gitea",
		Description: "Gitea shell command injection in repository management",
		MinVersion:  "",
		MaxVersion:  "1.16.7",
		Severity:    finding.SeverityCritical,
	},

	// Airflow DAG author code execution
	{
		CheckID:     finding.CheckCVEAirflowDAGRCE,
		CVE:         "CVE-2024-39877",
		Service:     "airflow",
		Description: "Airflow DAG author code execution via malicious dags",
		MinVersion:  "",
		MaxVersion:  "2.10.0",
		Severity:    finding.SeverityHigh,
	},

	// Superset default secret key
	{
		CheckID:     finding.CheckCVESupersetDefaultKey,
		CVE:         "CVE-2023-27524",
		Service:     "superset",
		Description: "Apache Superset default SECRET_KEY allows session forgery",
		MinVersion:  "",
		MaxVersion:  "2.1.1",
		Severity:    finding.SeverityHigh,
	},

	// MLflow auth bypass
	{
		CheckID:     finding.CheckCVEMLflowAuthBypass,
		CVE:         "CVE-2023-6014",
		Service:     "mlflow",
		Description: "MLflow unauthenticated account creation",
		MinVersion:  "",
		MaxVersion:  "2.8.0",
		Severity:    finding.SeverityCritical,
	},

	// pgAdmin validate RCE
	{
		CheckID:     finding.CheckCVEpgAdminValidateRCE,
		CVE:         "CVE-2024-3116",
		Service:     "pgadmin",
		Description: "pgAdmin validate binary path → command injection RCE",
		MinVersion:  "",
		MaxVersion:  "8.5",
		Severity:    finding.SeverityCritical,
	},

	// ManageEngine SAML RCE
	{
		CheckID:     finding.CheckCVEManageEngineSAML,
		CVE:         "CVE-2022-47966",
		Service:     "manageengine",
		Description: "ManageEngine SAML pre-auth RCE via SAML endpoint",
		MinVersion:  "",
		MaxVersion:  "13000",
		Severity:    finding.SeverityCritical,
	},

	// Zimbra auth bypass
	{
		CheckID:     finding.CheckCVEZimbraAuthBypass,
		CVE:         "CVE-2022-37042",
		Service:     "zimbra",
		Description: "Zimbra mboximport auth bypass → RCE",
		MinVersion:  "8.8.0",
		MaxVersion:  "9.0.1",
		Severity:    finding.SeverityCritical,
	},

	// ── ClickHouse ─────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEClickHouseHeapOverflow,
		CVE:         "CVE-2023-47118",
		Service:     "clickhouse",
		Description: "ClickHouse native protocol heap buffer overflow via crafted query",
		MinVersion:  "",
		MaxVersion:  "23.8.7",
		Severity:    finding.SeverityHigh,
	},
	{
		CheckID:     finding.CheckCVEClickHouseCodeInjection,
		CVE:         "CVE-2022-44013",
		Service:     "clickhouse",
		Description: "ClickHouse code injection via crafted query parameter",
		MinVersion:  "",
		MaxVersion:  "22.8.11",
		Severity:    finding.SeverityHigh,
	},

	// ── NATS ───────────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVENATSAuthBypass,
		CVE:         "CVE-2023-47090",
		Service:     "nats",
		Description: "NATS Server auth bypass on protected subjects",
		MinVersion:  "",
		MaxVersion:  "2.9.22",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVENATSAccountTakeover,
		CVE:         "CVE-2022-29946",
		Service:     "nats",
		Description: "NATS Server account takeover via import/export validation flaw",
		MinVersion:  "",
		MaxVersion:  "2.8.2",
		Severity:    finding.SeverityCritical,
	},

	// ── Nextcloud ──────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVENextcloudSSRFPreview,
		CVE:         "CVE-2023-48239",
		Service:     "nextcloud",
		Description: "Nextcloud preview endpoint SSRF → cloud metadata/internal service access",
		MinVersion:  "",
		MaxVersion:  "27.1.1",
		Severity:    finding.SeverityHigh,
	},
	{
		CheckID:     finding.CheckCVENextcloudInfoLeak,
		CVE:         "CVE-2023-25817",
		Service:     "nextcloud",
		Description: "Nextcloud server information leak via preview endpoint",
		MinVersion:  "",
		MaxVersion:  "24.0.8",
		Severity:    finding.SeverityMedium,
	},

	// ── Gradio ─────────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEGradioPathTraversal,
		CVE:         "CVE-2024-6507",
		Service:     "gradio",
		Description: "Gradio arbitrary file read via path traversal on upload endpoint",
		MinVersion:  "",
		MaxVersion:  "4.20",
		Severity:    finding.SeverityCritical,
	},

	// ── Veeam ──────────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEVeeamBackupRCE,
		CVE:         "CVE-2024-40711",
		Service:     "veeam",
		Description: "Veeam Backup & Replication unauthenticated RCE via deserialization",
		MinVersion:  "",
		MaxVersion:  "12.2",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEVeeamCredDisclosure,
		CVE:         "CVE-2023-27532",
		Service:     "veeam",
		Description: "Veeam Backup credential disclosure via unprotected API endpoint",
		MinVersion:  "",
		MaxVersion:  "12.0",
		Severity:    finding.SeverityCritical,
	},

	// ── Apache Tika ────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEApacheTikaRCE,
		CVE:         "CVE-2018-1335",
		Service:     "tika",
		Description: "Apache Tika Server X-Tika-OCR* header command injection → RCE",
		MinVersion:  "1.7",
		MaxVersion:  "1.18",
		Severity:    finding.SeverityCritical,
	},

	// ══════════════════════════════════════════════════════════════════
	// Auto-generated version rules from checkids.go CVE comments
	// ══════════════════════════════════════════════════════════════════

	// ── Keycloak ───────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEKeycloakSAMLBypass,
		CVE:         "CVE-2026-3047",
		Service:     "keycloak",
		Description: "Keycloak SAML signature validation bypass → auth bypass",
		MinVersion:  "",
		MaxVersion:  "26.0.6",
		Severity:    finding.SeverityCritical,
	},

	// ── Consul (additional branches) ──────────────────────────────────
	{
		CheckID:     finding.CheckCVEConsulSSRF2022,
		CVE:         "CVE-2022-29153",
		Service:     "consul",
		Description: "Consul 1.10.x HTTP API SSRF via redirect-traffic-to",
		MinVersion:  "1.10.0",
		MaxVersion:  "1.10.10",
		Severity:    finding.SeverityHigh,
	},
	{
		CheckID:     finding.CheckCVEConsulSSRF2022,
		CVE:         "CVE-2022-29153",
		Service:     "consul",
		Description: "Consul 1.11.x HTTP API SSRF via redirect-traffic-to",
		MinVersion:  "1.11.0",
		MaxVersion:  "1.11.5",
		Severity:    finding.SeverityHigh,
	},

	// ── Elasticsearch (additional) ────────────────────────────────────
	{
		CheckID:     finding.CheckCVEElasticsearchMVELRCE,
		CVE:         "CVE-2014-3120",
		Service:     "elasticsearch",
		Description: "Elasticsearch MVEL script RCE via /_search",
		MinVersion:  "",
		MaxVersion:  "1.2",
		Severity:    finding.SeverityCritical,
	},

	// ── Jenkins (additional) ──────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEJenkinsSandboxBypass,
		CVE:         "CVE-2019-1003000",
		Service:     "jenkins",
		Description: "Jenkins Pipeline Groovy sandbox bypass → RCE",
		MinVersion:  "",
		MaxVersion:  "2.154",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEJenkinsStaplerRCE,
		CVE:         "CVE-2018-1000861",
		Service:     "jenkins",
		Description: "Jenkins Stapler URL routing pre-auth RCE via ACL bypass",
		MinVersion:  "",
		MaxVersion:  "2.154",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEJenkinsCLIHTTPDeser,
		CVE:         "CVE-2016-9299",
		Service:     "jenkins",
		Description: "Jenkins CLI HTTP deserialization RCE",
		MinVersion:  "",
		MaxVersion:  "2.32",
		Severity:    finding.SeverityCritical,
	},

	// ── Tomcat (additional) ───────────────────────────────────────────
	{
		CheckID:     finding.CheckCVETomcatPutRCE,
		CVE:         "CVE-2017-12617",
		Service:     "tomcat",
		Description: "Apache Tomcat PUT method JSP upload → RCE",
		MinVersion:  "7.0.0",
		MaxVersion:  "7.0.82",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVETomcatPutRCE,
		CVE:         "CVE-2017-12617",
		Service:     "tomcat",
		Description: "Apache Tomcat 8.0.x PUT method JSP upload → RCE",
		MinVersion:  "8.0.0",
		MaxVersion:  "8.0.47",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVETomcatPutRCE,
		CVE:         "CVE-2017-12617",
		Service:     "tomcat",
		Description: "Apache Tomcat 8.5.x PUT method JSP upload → RCE",
		MinVersion:  "8.5.0",
		MaxVersion:  "8.5.23",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVETomcatJMXRCE,
		CVE:         "CVE-2016-8735",
		Service:     "tomcat",
		Description: "Tomcat JMX port RCE via Java deserialization",
		MinVersion:  "6.0.0",
		MaxVersion:  "6.0.48",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVETomcatJMXRCE,
		CVE:         "CVE-2016-8735",
		Service:     "tomcat",
		Description: "Tomcat 7.x JMX port RCE via Java deserialization",
		MinVersion:  "7.0.0",
		MaxVersion:  "7.0.73",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVETomcatJMXRCE,
		CVE:         "CVE-2016-8735",
		Service:     "tomcat",
		Description: "Tomcat 8.0.x JMX port RCE via Java deserialization",
		MinVersion:  "8.0.0",
		MaxVersion:  "8.0.39",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVETomcatJMXRCE,
		CVE:         "CVE-2016-8735",
		Service:     "tomcat",
		Description: "Tomcat 8.5.x JMX port RCE via Java deserialization",
		MinVersion:  "8.5.0",
		MaxVersion:  "8.5.8",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVETomcatGhostCat,
		CVE:         "CVE-2020-1938",
		Service:     "tomcat",
		Description: "Apache Tomcat AJP connector Ghostcat file read/inclusion",
		MinVersion:  "6.0.0",
		MaxVersion:  "6.0.54",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVETomcatGhostCat,
		CVE:         "CVE-2020-1938",
		Service:     "tomcat",
		Description: "Apache Tomcat 7.x AJP connector Ghostcat file read/inclusion",
		MinVersion:  "7.0.0",
		MaxVersion:  "7.0.100",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVETomcatGhostCat,
		CVE:         "CVE-2020-1938",
		Service:     "tomcat",
		Description: "Apache Tomcat 8.5.x AJP connector Ghostcat file read/inclusion",
		MinVersion:  "8.5.0",
		MaxVersion:  "8.5.51",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVETomcatGhostCat,
		CVE:         "CVE-2020-1938",
		Service:     "tomcat",
		Description: "Apache Tomcat 9.x AJP connector Ghostcat file read/inclusion",
		MinVersion:  "9.0.0",
		MaxVersion:  "9.0.31",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVETomcatAuthBypass2024,
		CVE:         "CVE-2024-52316",
		Service:     "tomcat",
		Description: "Apache Tomcat authentication bypass",
		MinVersion:  "9.0.0",
		MaxVersion:  "9.0.97",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVETomcatDoSBypass,
		CVE:         "CVE-2023-28709",
		Service:     "tomcat",
		Description: "Apache Tomcat incomplete fix for DoS bypass",
		MinVersion:  "8.5.0",
		MaxVersion:  "8.5.88",
		Severity:    finding.SeverityHigh,
	},
	{
		CheckID:     finding.CheckCVETomcatDoSBypass,
		CVE:         "CVE-2023-28709",
		Service:     "tomcat",
		Description: "Apache Tomcat 9.x incomplete fix for DoS bypass",
		MinVersion:  "9.0.0",
		MaxVersion:  "9.0.74",
		Severity:    finding.SeverityHigh,
	},
	{
		CheckID:     finding.CheckCVETomcatDoSBypass,
		CVE:         "CVE-2023-28709",
		Service:     "tomcat",
		Description: "Apache Tomcat 10.1.x incomplete fix for DoS bypass",
		MinVersion:  "10.1.0",
		MaxVersion:  "10.1.8",
		Severity:    finding.SeverityHigh,
	},
	{
		CheckID:     finding.CheckCVETomcatDoSBypass,
		CVE:         "CVE-2023-28709",
		Service:     "tomcat",
		Description: "Apache Tomcat 11.x incomplete fix for DoS bypass",
		MinVersion:  "11.0.0",
		MaxVersion:  "11.0.0",
		Severity:    finding.SeverityHigh,
	},

	// ── Spring Cloud ──────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVESpringCloudFunctionRCE,
		CVE:         "CVE-2022-22963",
		Service:     "spring",
		Description: "Spring Cloud Function SpEL RCE via routing-expression header",
		MinVersion:  "3.0.0",
		MaxVersion:  "3.2.3",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVESpringCloudGatewaySpEL,
		CVE:         "CVE-2022-22947",
		Service:     "spring",
		Description: "Spring Cloud Gateway SpEL code injection",
		MinVersion:  "3.0.0",
		MaxVersion:  "3.1.1",
		Severity:    finding.SeverityCritical,
	},

	// ── Redis (additional) ────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVERedisHINCRAuthBypass,
		CVE:         "CVE-2023-28856",
		Service:     "redis",
		Description: "Redis HINCR command auth bypass",
		MinVersion:  "",
		MaxVersion:  "6.2.12",
		Severity:    finding.SeverityHigh,
	},
	{
		CheckID:     finding.CheckCVERedisHINCRAuthBypass,
		CVE:         "CVE-2023-28856",
		Service:     "redis",
		Description: "Redis 7.x HINCR command auth bypass",
		MinVersion:  "7.0.0",
		MaxVersion:  "7.0.11",
		Severity:    finding.SeverityHigh,
	},
	{
		CheckID:     finding.CheckCVERedisSocketRace,
		CVE:         "CVE-2023-45145",
		Service:     "redis",
		Description: "Redis Unix socket race condition privilege escalation",
		MinVersion:  "",
		MaxVersion:  "7.0.15",
		Severity:    finding.SeverityHigh,
	},
	{
		CheckID:     finding.CheckCVERedisSocketRace,
		CVE:         "CVE-2023-45145",
		Service:     "redis",
		Description: "Redis 7.2.x Unix socket race condition privilege escalation",
		MinVersion:  "7.2.0",
		MaxVersion:  "7.2.4",
		Severity:    finding.SeverityHigh,
	},
	{
		CheckID:     finding.CheckPortRedisVulnerableCVE2025,
		CVE:         "CVE-2025-49844",
		Service:     "redis",
		Description: "Redis 8.0.x unauthenticated RCE",
		MinVersion:  "8.0.0",
		MaxVersion:  "8.0.4",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckPortRedisVulnerableCVE2025,
		CVE:         "CVE-2025-49844",
		Service:     "redis",
		Description: "Redis 8.2.x unauthenticated RCE",
		MinVersion:  "8.2.0",
		MaxVersion:  "8.2.2",
		Severity:    finding.SeverityCritical,
	},

	// ── MongoDB ────────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEMongoDBAuthBypass2017,
		CVE:         "CVE-2017-2604",
		Service:     "mongodb",
		Description: "MongoDB auth bypass via crafted wire protocol",
		MinVersion:  "",
		MaxVersion:  "3.6.0",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEMongoDBBSONRCE,
		CVE:         "CVE-2024-7553",
		Service:     "mongodb",
		Description: "MongoDB BSON deserialization RCE",
		MinVersion:  "",
		MaxVersion:  "6.0.16",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEMongoDBBSONRCE,
		CVE:         "CVE-2024-7553",
		Service:     "mongodb",
		Description: "MongoDB 7.0.x BSON deserialization RCE",
		MinVersion:  "7.0.0",
		MaxVersion:  "7.0.12",
		Severity:    finding.SeverityCritical,
	},

	// ── MySQL (additional) ────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEMySQLConfigManip,
		CVE:         "CVE-2016-6662",
		Service:     "mysql",
		Description: "MySQL config file manipulation via logging → RCE",
		MinVersion:  "",
		MaxVersion:  "5.7.15",
		Severity:    finding.SeverityHigh,
	},

	// ── PostgreSQL (additional) ───────────────────────────────────────
	{
		CheckID:     finding.CheckCVEPostgreSQLExtInjection,
		CVE:         "CVE-2023-39417",
		Service:     "postgresql",
		Description: "PostgreSQL extension script @extowner@ injection",
		MinVersion:  "",
		MaxVersion:  "14.9",
		Severity:    finding.SeverityHigh,
	},
	{
		CheckID:     finding.CheckCVEPostgreSQLExtInjection,
		CVE:         "CVE-2023-39417",
		Service:     "postgresql",
		Description: "PostgreSQL 15.x extension script @extowner@ injection",
		MinVersion:  "15.0",
		MaxVersion:  "15.4",
		Severity:    finding.SeverityHigh,
	},

	// ── Memcached ──────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEMemcachedNullCrash,
		CVE:         "CVE-2019-11596",
		Service:     "memcached",
		Description: "Memcached null pointer dereference crash",
		MinVersion:  "",
		MaxVersion:  "1.5.14",
		Severity:    finding.SeverityHigh,
	},

	// ── etcd ───────────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEEtcdAuthBypass,
		CVE:         "CVE-2020-15115",
		Service:     "etcd",
		Description: "etcd auth bypass via lease revoke",
		MinVersion:  "",
		MaxVersion:  "3.3.23",
		Severity:    finding.SeverityHigh,
	},
	{
		CheckID:     finding.CheckCVEEtcdAuthBypass,
		CVE:         "CVE-2020-15115",
		Service:     "etcd",
		Description: "etcd 3.4.x auth bypass via lease revoke",
		MinVersion:  "3.4.0",
		MaxVersion:  "3.4.10",
		Severity:    finding.SeverityHigh,
	},
	{
		CheckID:     finding.CheckCVEEtcdLeaseInfoLeak,
		CVE:         "CVE-2023-32082",
		Service:     "etcd",
		Description: "etcd LeaseTimeToLive leaks attached keys",
		MinVersion:  "",
		MaxVersion:  "3.5.9",
		Severity:    finding.SeverityMedium,
	},

	// ── RabbitMQ ───────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVERabbitMQCredLeak,
		CVE:         "CVE-2022-31008",
		Service:     "rabbitmq",
		Description: "RabbitMQ credential leak via management UI connections",
		MinVersion:  "",
		MaxVersion:  "3.11.0",
		Severity:    finding.SeverityHigh,
	},
	{
		CheckID:     finding.CheckCVERabbitMQHTTPDoS,
		CVE:         "CVE-2023-46118",
		Service:     "rabbitmq",
		Description: "RabbitMQ DoS via HTTP API",
		MinVersion:  "",
		MaxVersion:  "3.11.24",
		Severity:    finding.SeverityMedium,
	},
	{
		CheckID:     finding.CheckCVERabbitMQHTTPDoS,
		CVE:         "CVE-2023-46118",
		Service:     "rabbitmq",
		Description: "RabbitMQ 3.12.x DoS via HTTP API",
		MinVersion:  "3.12.0",
		MaxVersion:  "3.12.5",
		Severity:    finding.SeverityMedium,
	},

	// ── Jupyter ────────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEJupyterSSRF,
		CVE:         "CVE-2023-44461",
		Service:     "jupyter",
		Description: "Jupyter Server SSRF via /api/contents",
		MinVersion:  "",
		MaxVersion:  "2.7.2",
		Severity:    finding.SeverityHigh,
	},
	{
		CheckID:     finding.CheckCVEJupyterOpenRedirect,
		CVE:         "CVE-2020-26215",
		Service:     "jupyter",
		Description: "Jupyter Notebook open redirect via /login?next=",
		MinVersion:  "",
		MaxVersion:  "6.1.5",
		Severity:    finding.SeverityMedium,
	},

	// ── Portainer ──────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEPortainerOTELDoS,
		CVE:         "CVE-2023-47108",
		Service:     "portainer",
		Description: "Portainer OTEL DoS",
		MinVersion:  "",
		MaxVersion:  "2.19.2",
		Severity:    finding.SeverityMedium,
	},
	{
		CheckID:     finding.CheckCVEPortainerUnauthAPI,
		CVE:         "CVE-2022-36326",
		Service:     "portainer",
		Description: "Portainer unauthorized API access — list stacks",
		MinVersion:  "",
		MaxVersion:  "2.16.0",
		Severity:    finding.SeverityHigh,
	},

	// ── Drone CI ───────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEDroneSSRF,
		CVE:         "CVE-2021-33681",
		Service:     "drone",
		Description: "Drone CI SSRF via clone URL",
		MinVersion:  "",
		MaxVersion:  "2.0",
		Severity:    finding.SeverityHigh,
	},

	// ── ArgoCD ─────────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEArgoCDJWTBypass,
		CVE:         "CVE-2022-29165",
		Service:     "argocd",
		Description: "ArgoCD auth bypass via crafted JWT (2.1.x)",
		MinVersion:  "2.1.0",
		MaxVersion:  "2.1.15",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEArgoCDJWTBypass,
		CVE:         "CVE-2022-29165",
		Service:     "argocd",
		Description: "ArgoCD auth bypass via crafted JWT (2.2.x)",
		MinVersion:  "2.2.0",
		MaxVersion:  "2.2.9",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEArgoCDJWTBypass,
		CVE:         "CVE-2022-29165",
		Service:     "argocd",
		Description: "ArgoCD auth bypass via crafted JWT (2.3.x)",
		MinVersion:  "2.3.0",
		MaxVersion:  "2.3.4",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEArgoCDXSS,
		CVE:         "CVE-2024-28175",
		Service:     "argocd",
		Description: "ArgoCD XSS via application name (2.9.x)",
		MinVersion:  "2.9.0",
		MaxVersion:  "2.9.9",
		Severity:    finding.SeverityMedium,
	},
	{
		CheckID:     finding.CheckCVEArgoCDXSS,
		CVE:         "CVE-2024-28175",
		Service:     "argocd",
		Description: "ArgoCD XSS via application name (2.10.x)",
		MinVersion:  "2.10.0",
		MaxVersion:  "2.10.4",
		Severity:    finding.SeverityMedium,
	},

	// ── NATS (additional branches) ────────────────────────────────────
	{
		CheckID:     finding.CheckCVENATSAuthBypass,
		CVE:         "CVE-2023-47090",
		Service:     "nats",
		Description: "NATS Server 2.10.x auth bypass on protected subjects",
		MinVersion:  "2.10.0",
		MaxVersion:  "2.10.2",
		Severity:    finding.SeverityCritical,
	},

	// ── CouchDB ────────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVECouchDBErlangCookie,
		CVE:         "CVE-2022-24706",
		Service:     "couchdb",
		Description: "CouchDB default Erlang cookie → RCE",
		MinVersion:  "",
		MaxVersion:  "3.2.2",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVECouchDBPrivEsc,
		CVE:         "CVE-2017-12635",
		Service:     "couchdb",
		Description: "CouchDB duplicate roles JSON → admin creation",
		MinVersion:  "",
		MaxVersion:  "2.1.1",
		Severity:    finding.SeverityCritical,
	},

	// ── containerd ─────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEContainerdHostNetEscape,
		CVE:         "CVE-2020-15257",
		Service:     "containerd",
		Description: "containerd host networking namespace escape (1.3.x)",
		MinVersion:  "",
		MaxVersion:  "1.3.9",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEContainerdHostNetEscape,
		CVE:         "CVE-2020-15257",
		Service:     "containerd",
		Description: "containerd 1.4.x host networking namespace escape",
		MinVersion:  "1.4.0",
		MaxVersion:  "1.4.3",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEContainerdRuncEscape,
		CVE:         "CVE-2024-21626",
		Service:     "runc",
		Description: "runc working directory BUILDKIT escape → host filesystem access",
		MinVersion:  "",
		MaxVersion:  "1.1.12",
		Severity:    finding.SeverityHigh,
	},

	// ── Kibana (additional) ───────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEKibanaTimelionRCE,
		CVE:         "CVE-2019-7609",
		Service:     "kibana",
		Description: "Kibana Timelion prototype pollution → RCE (5.x)",
		MinVersion:  "5.0.0",
		MaxVersion:  "5.6.15",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEKibanaTimelionRCE,
		CVE:         "CVE-2019-7609",
		Service:     "kibana",
		Description: "Kibana 6.x Timelion prototype pollution → RCE",
		MinVersion:  "6.0.0",
		MaxVersion:  "6.6.1",
		Severity:    finding.SeverityCritical,
	},

	// ── Prometheus ─────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEPrometheusOpenRedirect,
		CVE:         "CVE-2021-29622",
		Service:     "prometheus",
		Description: "Prometheus open redirect via /new/..;/graph (2.26.x)",
		MinVersion:  "2.23.0",
		MaxVersion:  "2.26.1",
		Severity:    finding.SeverityMedium,
	},
	{
		CheckID:     finding.CheckCVEPrometheusOpenRedirect,
		CVE:         "CVE-2021-29622",
		Service:     "prometheus",
		Description: "Prometheus 2.27.x open redirect via /new/..;/graph",
		MinVersion:  "2.27.0",
		MaxVersion:  "2.27.1",
		Severity:    finding.SeverityMedium,
	},

	// ── GitLab (additional) ───────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEGitLabAccountTakeover,
		CVE:         "CVE-2023-7028",
		Service:     "gitlab",
		Description: "GitLab CE/EE password reset account takeover",
		MinVersion:  "16.1.0",
		MaxVersion:  "16.7.2",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEGitLabCILintSSRF,
		CVE:         "CVE-2021-22214",
		Service:     "gitlab",
		Description: "GitLab CE/EE CI lint SSRF via include directive",
		MinVersion:  "10.5.0",
		MaxVersion:  "14.0.9",
		Severity:    finding.SeverityHigh,
	},
	{
		CheckID:     finding.CheckCVEGitLabProjectImportRCE,
		CVE:         "CVE-2023-2478",
		Service:     "gitlab",
		Description: "GitLab project import RCE",
		MinVersion:  "15.10.0",
		MaxVersion:  "15.11.6",
		Severity:    finding.SeverityCritical,
	},

	// ── Airflow (additional) ──────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEAirflowExampleDAGRCE,
		CVE:         "CVE-2020-11978",
		Service:     "airflow",
		Description: "Airflow example_bash_operator DAG command injection → RCE",
		MinVersion:  "",
		MaxVersion:  "1.10.11",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEAirflowConfigInfoLeak,
		CVE:         "CVE-2022-40127",
		Service:     "airflow",
		Description: "Airflow /api/v1/config info disclosure",
		MinVersion:  "",
		MaxVersion:  "2.4.0",
		Severity:    finding.SeverityHigh,
	},
	{
		CheckID:     finding.CheckCVEAirflowExperimentalAPI,
		CVE:         "CVE-2020-13927",
		Service:     "airflow",
		Description: "Airflow experimental REST API auth bypass",
		MinVersion:  "",
		MaxVersion:  "1.10.11",
		Severity:    finding.SeverityCritical,
	},

	// ── SonarQube ──────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVESonarQubeSSRF,
		CVE:         "CVE-2024-47910",
		Service:     "sonarqube",
		Description: "SonarQube SSRF",
		MinVersion:  "",
		MaxVersion:  "10.3",
		Severity:    finding.SeverityHigh,
	},

	// ── nginx (additional branches) ───────────────────────────────────
	{
		CheckID:     finding.CheckCVENginxResolverRCE,
		CVE:         "CVE-2021-23017",
		Service:     "nginx",
		Description: "nginx 1.20.x DNS resolver off-by-one → RCE",
		MinVersion:  "1.20.0",
		MaxVersion:  "1.20.1",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVENginxRangeInfoLeak,
		CVE:         "CVE-2017-7529",
		Service:     "nginx",
		Description: "nginx 1.12.x integer overflow Range header info leak",
		MinVersion:  "1.12.0",
		MaxVersion:  "1.12.1",
		Severity:    finding.SeverityHigh,
	},

	// ── Apache httpd (additional) ─────────────────────────────────────
	{
		CheckID:     finding.CheckCVEApacheHTTPSmuggling,
		CVE:         "CVE-2023-25690",
		Service:     "apache",
		Description: "Apache HTTP Server mod_proxy HTTP request smuggling",
		MinVersion:  "",
		MaxVersion:  "2.4.56",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEApacheH2DoS,
		CVE:         "CVE-2023-43622",
		Service:     "apache",
		Description: "Apache HTTP Server HTTP/2 initial settings frame DoS",
		MinVersion:  "",
		MaxVersion:  "2.4.58",
		Severity:    finding.SeverityHigh,
	},
	{
		CheckID:     finding.CheckCVEApacheHTTPDSSRF,
		CVE:         "CVE-2024-38476",
		Service:     "apache",
		Description: "Apache httpd mod_proxy SSRF",
		MinVersion:  "",
		MaxVersion:  "2.4.60",
		Severity:    finding.SeverityCritical,
	},

	// ── Exim ───────────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEEximRCE2019,
		CVE:         "CVE-2019-10149",
		Service:     "exim",
		Description: "Exim local part expansion → RCE",
		MinVersion:  "4.87",
		MaxVersion:  "4.92",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEEximHeapOverflow,
		CVE:         "CVE-2018-6789",
		Service:     "exim",
		Description: "Exim base64d() off-by-one heap overflow → pre-auth RCE",
		MinVersion:  "",
		MaxVersion:  "4.90.1",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEEximUseAfterFree,
		CVE:         "CVE-2020-28018",
		Service:     "exim",
		Description: "Exim TLS use-after-free → pre-auth RCE",
		MinVersion:  "",
		MaxVersion:  "4.94.2",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckPortExImVulnerable,
		CVE:         "CVE-2025-26794",
		Service:     "exim",
		Description: "Exim SQL injection",
		MinVersion:  "",
		MaxVersion:  "4.98.1",
		Severity:    finding.SeverityCritical,
	},

	// ── ProFTPD ────────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEProFTPDModCopy,
		CVE:         "CVE-2015-3306",
		Service:     "proftpd",
		Description: "ProFTPD mod_copy SITE CPFR/CPTO unauthenticated file read/write",
		MinVersion:  "1.3.5",
		MaxVersion:  "1.3.6",
		Severity:    finding.SeverityCritical,
	},

	// ── Confluence (additional) ───────────────────────────────────────
	{
		CheckID:     finding.CheckCVEConfluenceRestore,
		CVE:         "CVE-2023-22518",
		Service:     "confluence",
		Description: "Confluence restore endpoint accessible → unauthenticated DB restore → RCE",
		MinVersion:  "",
		MaxVersion:  "8.5.2",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEConfluenceTemplateRCE,
		CVE:         "CVE-2023-22527",
		Service:     "confluence",
		Description: "Confluence Data Center template injection → pre-auth RCE",
		MinVersion:  "",
		MaxVersion:  "8.5.4",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEConfluenceOGNLInjection,
		CVE:         "CVE-2021-26084",
		Service:     "confluence",
		Description: "Confluence OGNL injection in action URLs → pre-auth RCE",
		MinVersion:  "",
		MaxVersion:  "7.13.0",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEConfluenceWidgetTraversal,
		CVE:         "CVE-2019-3396",
		Service:     "confluence",
		Description: "Confluence Widget Connector path traversal → RCE",
		MinVersion:  "",
		MaxVersion:  "6.15.2",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEConfluencePreAuthFileRead,
		CVE:         "CVE-2021-26085",
		Service:     "confluence",
		Description: "Confluence pre-auth arbitrary file read via /s/ servlet",
		MinVersion:  "",
		MaxVersion:  "7.13.0",
		Severity:    finding.SeverityMedium,
	},
	{
		CheckID:     finding.CheckCVEConfluenceTemplateInj,
		CVE:         "CVE-2023-22522",
		Service:     "confluence",
		Description: "Confluence template injection via user input → authenticated RCE",
		MinVersion:  "",
		MaxVersion:  "8.5.3",
		Severity:    finding.SeverityHigh,
	},
	{
		CheckID:     finding.CheckCVEConfluenceAuthRCE,
		CVE:         "CVE-2023-22505",
		Service:     "confluence",
		Description: "Atlassian Confluence authenticated RCE via macro",
		MinVersion:  "",
		MaxVersion:  "8.3.2",
		Severity:    finding.SeverityHigh,
	},

	// ── Log4j (additional) ────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVELog4ShellBypass,
		CVE:         "CVE-2021-45046",
		Service:     "log4j",
		Description: "Log4j thread context bypass of 2.15.0 fix",
		MinVersion:  "2.0.0",
		MaxVersion:  "2.17.0",
		Severity:    finding.SeverityCritical,
	},

	// ── Roundcube ──────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVERoundcube,
		CVE:         "CVE-2023-43770",
		Service:     "roundcube",
		Description: "Roundcube stored XSS → victim RCE (1.4.x)",
		MinVersion:  "",
		MaxVersion:  "1.4.14",
		Severity:    finding.SeverityHigh,
	},
	{
		CheckID:     finding.CheckCVERoundcube,
		CVE:         "CVE-2023-43770",
		Service:     "roundcube",
		Description: "Roundcube 1.5.x stored XSS → victim RCE",
		MinVersion:  "1.5.0",
		MaxVersion:  "1.5.4",
		Severity:    finding.SeverityHigh,
	},
	{
		CheckID:     finding.CheckCVERoundcube,
		CVE:         "CVE-2023-43770",
		Service:     "roundcube",
		Description: "Roundcube 1.6.x stored XSS → victim RCE",
		MinVersion:  "1.6.0",
		MaxVersion:  "1.6.3",
		Severity:    finding.SeverityHigh,
	},

	// ── TeamCity (additional) ─────────────────────────────────────────
	{
		CheckID:     finding.CheckCVETeamCityDirTraversal,
		CVE:         "CVE-2024-27199",
		Service:     "teamcity",
		Description: "TeamCity alternate path-traversal auth bypass via ;/../",
		MinVersion:  "",
		MaxVersion:  "2023.11.4",
		Severity:    finding.SeverityHigh,
	},

	// ── Webmin ─────────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEWebminPasswordResetRCE,
		CVE:         "CVE-2019-15107",
		Service:     "webmin",
		Description: "Webmin unauthenticated RCE via password_change.cgi backdoor",
		MinVersion:  "",
		MaxVersion:  "1.930",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEWebminPackageUpdatesRCE,
		CVE:         "CVE-2019-15231",
		Service:     "webmin",
		Description: "Webmin package-updates module command injection RCE",
		MinVersion:  "",
		MaxVersion:  "1.920",
		Severity:    finding.SeverityCritical,
	},

	// ── Splunk ─────────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVESplunkXSLRCE,
		CVE:         "CVE-2023-46214",
		Service:     "splunk",
		Description: "Splunk Enterprise RCE via XSLT stylesheet upload (9.0.x)",
		MinVersion:  "9.0.0",
		MaxVersion:  "9.0.7",
		Severity:    finding.SeverityHigh,
	},
	{
		CheckID:     finding.CheckCVESplunkXSLRCE,
		CVE:         "CVE-2023-46214",
		Service:     "splunk",
		Description: "Splunk Enterprise 9.1.x RCE via XSLT stylesheet upload",
		MinVersion:  "9.1.0",
		MaxVersion:  "9.1.2",
		Severity:    finding.SeverityHigh,
	},

	// ── Zabbix ─────────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEZabbixSAMLAuthBypass,
		CVE:         "CVE-2022-23131",
		Service:     "zabbix",
		Description: "Zabbix SAML SSO auth bypass (5.4.x)",
		MinVersion:  "5.4.0",
		MaxVersion:  "5.4.9",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEZabbixSAMLAuthBypass,
		CVE:         "CVE-2022-23131",
		Service:     "zabbix",
		Description: "Zabbix 6.0.0 SAML SSO auth bypass",
		MinVersion:  "6.0.0",
		MaxVersion:  "6.0.1",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEZabbixTimeSQLi,
		CVE:         "CVE-2024-22120",
		Service:     "zabbix",
		Description: "Zabbix audit log time-based SQL injection (6.0.x)",
		MinVersion:  "6.0.0",
		MaxVersion:  "6.0.28",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEZabbixTimeSQLi,
		CVE:         "CVE-2024-22120",
		Service:     "zabbix",
		Description: "Zabbix 6.4.x audit log time-based SQL injection",
		MinVersion:  "6.4.0",
		MaxVersion:  "6.4.13",
		Severity:    finding.SeverityCritical,
	},

	// ── phpMyAdmin ─────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEPhpMyAdminLFI,
		CVE:         "CVE-2018-12613",
		Service:     "phpmyadmin",
		Description: "phpMyAdmin local file inclusion via target parameter",
		MinVersion:  "4.8.0",
		MaxVersion:  "4.8.2",
		Severity:    finding.SeverityHigh,
	},

	// ── OFBiz ──────────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEOFBizXMLRPCDeser2021,
		CVE:         "CVE-2021-26295",
		Service:     "ofbiz",
		Description: "OFBiz XML-RPC deserialization RCE",
		MinVersion:  "",
		MaxVersion:  "17.12.06",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEOFBizAuthBypass,
		CVE:         "CVE-2023-51467",
		Service:     "ofbiz",
		Description: "Apache OFBiz auth bypass via empty/invalid username-password",
		MinVersion:  "",
		MaxVersion:  "18.12.11",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEOFBizPreAuthRCE,
		CVE:         "CVE-2023-49070",
		Service:     "ofbiz",
		Description: "Apache OFBiz pre-auth XML-RPC deserialization → RCE",
		MinVersion:  "",
		MaxVersion:  "18.12.10",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEOFBizForceBrowsing,
		CVE:         "CVE-2024-45195",
		Service:     "ofbiz",
		Description: "Apache OFBiz direct request force browsing auth bypass",
		MinVersion:  "",
		MaxVersion:  "18.12.16",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEOFBizDirTraversal2024,
		CVE:         "CVE-2024-32113",
		Service:     "ofbiz",
		Description: "OFBiz directory traversal + RCE",
		MinVersion:  "",
		MaxVersion:  "18.12.13",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEOFBizDirTraversal2024Q2,
		CVE:         "CVE-2024-36104",
		Service:     "ofbiz",
		Description: "Apache OFBiz directory traversal via view name",
		MinVersion:  "",
		MaxVersion:  "18.12.14",
		Severity:    finding.SeverityCritical,
	},

	// ── Solr ───────────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVESolrDeserial,
		CVE:         "CVE-2019-0192",
		Service:     "solr",
		Description: "Apache Solr Config API Jmx deserialization RCE",
		MinVersion:  "",
		MaxVersion:  "7.0",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVESolrAuthBypass,
		CVE:         "CVE-2024-45216",
		Service:     "solr",
		Description: "Apache Solr auth bypass via /solr path confusion",
		MinVersion:  "",
		MaxVersion:  "9.7.0",
		Severity:    finding.SeverityCritical,
	},

	// ── Drupal ─────────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEDrupalgeddon1,
		CVE:         "CVE-2014-3704",
		Service:     "drupal",
		Description: "Drupal 7.x SQL injection via form API → unauthenticated admin",
		MinVersion:  "7.0",
		MaxVersion:  "7.32",
		Severity:    finding.SeverityHigh,
	},
	{
		CheckID:     finding.CheckCVEDrupalgeddon2,
		CVE:         "CVE-2018-7600",
		Service:     "drupal",
		Description: "Drupal RCE (Drupalgeddon2)",
		MinVersion:  "7.0",
		MaxVersion:  "7.58",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEDrupalgeddon2,
		CVE:         "CVE-2018-7600",
		Service:     "drupal",
		Description: "Drupal 8.x RCE (Drupalgeddon2)",
		MinVersion:  "8.0.0",
		MaxVersion:  "8.5.1",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEDrupalgeddon3,
		CVE:         "CVE-2018-7602",
		Service:     "drupal",
		Description: "Drupal Drupalgeddon 3 authenticated RCE",
		MinVersion:  "7.0",
		MaxVersion:  "7.59",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEDrupalgeddon3,
		CVE:         "CVE-2018-7602",
		Service:     "drupal",
		Description: "Drupal 8.x Drupalgeddon 3 authenticated RCE",
		MinVersion:  "8.0.0",
		MaxVersion:  "8.5.3",
		Severity:    finding.SeverityCritical,
	},

	// ── Joomla ─────────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEJoomlaObjectInjection,
		CVE:         "CVE-2015-8562",
		Service:     "joomla",
		Description: "Joomla PHP object injection via HTTP User-Agent → RCE",
		MinVersion:  "1.5.0",
		MaxVersion:  "3.4.6",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEJoomlaSQLi2017,
		CVE:         "CVE-2017-8917",
		Service:     "joomla",
		Description: "Joomla com_fields SQL injection",
		MinVersion:  "3.7.0",
		MaxVersion:  "3.7.1",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEJoomlaInfoDisclosure,
		CVE:         "CVE-2023-23752",
		Service:     "joomla",
		Description: "Joomla REST API auth bypass → DB creds + secret key leak",
		MinVersion:  "4.0.0",
		MaxVersion:  "4.2.8",
		Severity:    finding.SeverityHigh,
	},

	// ── Jira ───────────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEJiraSeraphAuthBypass,
		CVE:         "CVE-2022-0540",
		Service:     "jira",
		Description: "Atlassian Jira Seraph auth bypass via InsightAssetActions",
		MinVersion:  "",
		MaxVersion:  "8.22.6",
		Severity:    finding.SeverityCritical,
	},

	// ── Bitbucket ──────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEBitbucketCmdInjection,
		CVE:         "CVE-2022-36804",
		Service:     "bitbucket",
		Description: "Atlassian Bitbucket Server/DC command injection",
		MinVersion:  "7.0.0",
		MaxVersion:  "8.3.1",
		Severity:    finding.SeverityCritical,
	},

	// ── MLflow (additional) ───────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEMLflowRCE,
		CVE:         "CVE-2024-27132",
		Service:     "mlflow",
		Description: "MLflow recipe parameter injection → OS command execution",
		MinVersion:  "",
		MaxVersion:  "2.11.3",
		Severity:    finding.SeverityHigh,
	},
	{
		CheckID:     finding.CheckCVEMLflowPathTraversal,
		CVE:         "CVE-2023-6831",
		Service:     "mlflow",
		Description: "MLflow arbitrary file read via artifact path traversal",
		MinVersion:  "",
		MaxVersion:  "2.9.2",
		Severity:    finding.SeverityHigh,
	},
	{
		CheckID:     finding.CheckCVEMLflowLFI,
		CVE:         "CVE-2023-1177",
		Service:     "mlflow",
		Description: "MLflow local file inclusion via artifact endpoints",
		MinVersion:  "",
		MaxVersion:  "2.2.1",
		Severity:    finding.SeverityCritical,
	},

	// ── RocketMQ ───────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVERocketMQRCE,
		CVE:         "CVE-2023-33246",
		Service:     "rocketmq",
		Description: "Apache RocketMQ RCE via broker config update",
		MinVersion:  "",
		MaxVersion:  "5.1.1",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVERocketMQCmdExec,
		CVE:         "CVE-2023-37582",
		Service:     "rocketmq",
		Description: "Apache RocketMQ command execution via namesrv",
		MinVersion:  "",
		MaxVersion:  "5.1.2",
		Severity:    finding.SeverityCritical,
	},

	// ── PyLoad ─────────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEPyLoadRCE,
		CVE:         "CVE-2023-0297",
		Service:     "pyload",
		Description: "pyLoad pre-auth RCE via eval in /flash/addcrypted2",
		MinVersion:  "",
		MaxVersion:  "0.5.0",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEPyloadCmdInj,
		CVE:         "CVE-2024-21644",
		Service:     "pyload",
		Description: "pyLoad /flash/addcrypted2 command injection → pre-auth RCE",
		MinVersion:  "",
		MaxVersion:  "0.5.1",
		Severity:    finding.SeverityCritical,
	},

	// ── Cacti ──────────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVECactiCmdInj,
		CVE:         "CVE-2022-46169",
		Service:     "cacti",
		Description: "Cacti unauthenticated command injection",
		MinVersion:  "",
		MaxVersion:  "1.2.23",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVECactiRealtimeRCE,
		CVE:         "CVE-2024-29895",
		Service:     "cacti",
		Description: "Cacti cmd_realtime.php unauthenticated command injection",
		MinVersion:  "",
		MaxVersion:  "1.2.27",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVECactiFileWrite,
		CVE:         "CVE-2024-25641",
		Service:     "cacti",
		Description: "Cacti arbitrary file write via import",
		MinVersion:  "",
		MaxVersion:  "1.2.26",
		Severity:    finding.SeverityCritical,
	},

	// ── CrushFTP ───────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVECrushFTPVFS,
		CVE:         "CVE-2024-4040",
		Service:     "crushftp",
		Description: "CrushFTP VFS sandbox escape (10.x)",
		MinVersion:  "",
		MaxVersion:  "10.7.1",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVECrushFTPVFS,
		CVE:         "CVE-2024-4040",
		Service:     "crushftp",
		Description: "CrushFTP 11.x VFS sandbox escape",
		MinVersion:  "11.0.0",
		MaxVersion:  "11.1.0",
		Severity:    finding.SeverityCritical,
	},

	// ── Ollama ─────────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEOllamaPathTraversal,
		CVE:         "GHSA-q3jj-7xxq-6mgr",
		Service:     "ollama",
		Description: "Ollama directory traversal via model blob endpoint",
		MinVersion:  "",
		MaxVersion:  "0.1.47",
		Severity:    finding.SeverityHigh,
	},

	// ── GoAnywhere ─────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEGoAnywhereRCE,
		CVE:         "CVE-2023-0669",
		Service:     "goanywhere",
		Description: "GoAnywhere MFT pre-auth deserialization → RCE",
		MinVersion:  "",
		MaxVersion:  "7.1.2",
		Severity:    finding.SeverityCritical,
	},

	// ── GeoServer ──────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEGeoServerEval,
		CVE:         "CVE-2024-36401",
		Service:     "geoserver",
		Description: "GeoServer OGC filter eval injection (2.23.x)",
		MinVersion:  "",
		MaxVersion:  "2.23.6",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEGeoServerEval,
		CVE:         "CVE-2024-36401",
		Service:     "geoserver",
		Description: "GeoServer 2.24.x OGC filter eval injection",
		MinVersion:  "2.24.0",
		MaxVersion:  "2.24.4",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEGeoServerSQLi,
		CVE:         "CVE-2023-25157",
		Service:     "geoserver",
		Description: "GeoServer OGC filter SQL injection",
		MinVersion:  "",
		MaxVersion:  "2.23.1",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEGeoServerRCE,
		CVE:         "CVE-2022-24816",
		Service:     "geoserver",
		Description: "GeoServer evaluate property name RCE (2.20.x)",
		MinVersion:  "",
		MaxVersion:  "2.20.4",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEGeoServerRCE,
		CVE:         "CVE-2022-24816",
		Service:     "geoserver",
		Description: "GeoServer 2.21.x evaluate property name RCE",
		MinVersion:  "2.21.0",
		MaxVersion:  "2.21.1",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEGeoServerSSRF,
		CVE:         "CVE-2023-43795",
		Service:     "geoserver",
		Description: "GeoServer WPS SSRF (2.23.x)",
		MinVersion:  "",
		MaxVersion:  "2.23.3",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEGeoServerSSRF,
		CVE:         "CVE-2023-43795",
		Service:     "geoserver",
		Description: "GeoServer 2.24.x WPS SSRF",
		MinVersion:  "2.24.0",
		MaxVersion:  "2.24.1",
		Severity:    finding.SeverityCritical,
	},

	// ── Kubernetes ─────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEKubernetesPrivEsc,
		CVE:         "CVE-2018-1002105",
		Service:     "kubernetes",
		Description: "Kubernetes API server WebSocket upgrade priv esc → cluster admin",
		MinVersion:  "",
		MaxVersion:  "1.12.3",
		Severity:    finding.SeverityCritical,
	},

	// ── vCenter (additional) ──────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEVCenterAnalyticsRCE,
		CVE:         "CVE-2021-22005",
		Service:     "vcenter",
		Description: "vCenter Analytics upload RCE",
		MinVersion:  "6.7.0",
		MaxVersion:  "7.0.3",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEvCenterOOBWrite,
		CVE:         "CVE-2023-34048",
		Service:     "vcenter",
		Description: "VMware vCenter DCE/RPC out-of-bounds write → pre-auth RCE",
		MinVersion:  "",
		MaxVersion:  "8.0.2",
		Severity:    finding.SeverityCritical,
	},

	// ── Workspace ONE (additional) ────────────────────────────────────
	{
		CheckID:     finding.CheckCVEVMwareWSOneAuthBypass,
		CVE:         "CVE-2022-31656",
		Service:     "workspace-one",
		Description: "VMware Workspace ONE Access auth bypass via token manipulation",
		MinVersion:  "",
		MaxVersion:  "22.09.1",
		Severity:    finding.SeverityCritical,
	},

	// ── Django ─────────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEDjangoJSONFieldSQLi,
		CVE:         "CVE-2019-14234",
		Service:     "django",
		Description: "Django JSONField/HStoreField SQL injection via key transforms",
		MinVersion:  "1.11.0",
		MaxVersion:  "1.11.23",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEDjangoJSONFieldSQLi,
		CVE:         "CVE-2019-14234",
		Service:     "django",
		Description: "Django 2.1.x JSONField/HStoreField SQL injection",
		MinVersion:  "2.1.0",
		MaxVersion:  "2.1.11",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEDjangoJSONFieldSQLi,
		CVE:         "CVE-2019-14234",
		Service:     "django",
		Description: "Django 2.2.x JSONField/HStoreField SQL injection",
		MinVersion:  "2.2.0",
		MaxVersion:  "2.2.4",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEDjangoOrderBySQLi,
		CVE:         "CVE-2021-35042",
		Service:     "django",
		Description: "Django QuerySet.order_by() SQL injection",
		MinVersion:  "3.1.0",
		MaxVersion:  "3.1.13",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEDjangoOrderBySQLi,
		CVE:         "CVE-2021-35042",
		Service:     "django",
		Description: "Django 3.2.x QuerySet.order_by() SQL injection",
		MinVersion:  "3.2.0",
		MaxVersion:  "3.2.5",
		Severity:    finding.SeverityCritical,
	},

	// ── Express.js ────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEExpressOpenRedirect,
		CVE:         "CVE-2024-29041",
		Service:     "express",
		Description: "Express open redirect via crafted URL",
		MinVersion:  "",
		MaxVersion:  "4.19.2",
		Severity:    finding.SeverityMedium,
	},
	{
		CheckID:     finding.CheckCVEExpressQSProtoPollution,
		CVE:         "CVE-2022-24999",
		Service:     "express",
		Description: "qs prototype pollution via __proto__ key",
		MinVersion:  "",
		MaxVersion:  "4.17.3",
		Severity:    finding.SeverityHigh,
	},

	// ── Laravel ────────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVELaravelIgnitionRCE,
		CVE:         "CVE-2021-3129",
		Service:     "laravel",
		Description: "Laravel Ignition execute-solution RCE via phar deserialization",
		MinVersion:  "2.0.0",
		MaxVersion:  "2.5.2",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVELaravelAppKeyRCE,
		CVE:         "CVE-2018-15133",
		Service:     "laravel",
		Description: "Laravel APP_KEY deserialization RCE via XSRF token",
		MinVersion:  "",
		MaxVersion:  "5.6.30",
		Severity:    finding.SeverityCritical,
	},

	// ── Ghost ──────────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEGhostMembershipBypass,
		CVE:         "CVE-2022-41654",
		Service:     "ghost",
		Description: "Ghost membership tier bypass",
		MinVersion:  "",
		MaxVersion:  "4.48.8",
		Severity:    finding.SeverityHigh,
	},
	{
		CheckID:     finding.CheckCVEGhostFileRead,
		CVE:         "CVE-2023-40028",
		Service:     "ghost",
		Description: "Ghost arbitrary file read via symlinked theme",
		MinVersion:  "",
		MaxVersion:  "5.59.1",
		Severity:    finding.SeverityMedium,
	},

	// ── Nacos ──────────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVENacosAuthBypass,
		CVE:         "CVE-2021-29441",
		Service:     "nacos",
		Description: "Nacos auth bypass via User-Agent header spoofing",
		MinVersion:  "",
		MaxVersion:  "2.0.0",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVENacosJWTHardcoded,
		CVE:         "CVE-2023-34465",
		Service:     "nacos",
		Description: "Nacos hardcoded JWT secret key",
		MinVersion:  "",
		MaxVersion:  "2.2.1",
		Severity:    finding.SeverityCritical,
	},

	// ── NiFi ───────────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVENiFiH2RCE,
		CVE:         "CVE-2023-34468",
		Service:     "nifi",
		Description: "Apache NiFi H2 database URL injection RCE",
		MinVersion:  "",
		MaxVersion:  "1.22.0",
		Severity:    finding.SeverityCritical,
	},

	// ── Neo4j ──────────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVENeo4jJavaDeserial,
		CVE:         "CVE-2021-34371",
		Service:     "neo4j",
		Description: "Neo4j Bolt Java deserialization RCE",
		MinVersion:  "",
		MaxVersion:  "3.5.30",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVENeo4jAPOCRCE,
		CVE:         "CVE-2023-23926",
		Service:     "neo4j",
		Description: "Neo4j APOC library arbitrary code execution",
		MinVersion:  "",
		MaxVersion:  "4.4.19",
		Severity:    finding.SeverityCritical,
	},

	// ── Cassandra ──────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVECassandraUDFEscape,
		CVE:         "CVE-2021-44521",
		Service:     "cassandra",
		Description: "Cassandra UDF sandbox escape via Nashorn",
		MinVersion:  "3.0.0",
		MaxVersion:  "3.0.26",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVECassandraUDFEscape,
		CVE:         "CVE-2021-44521",
		Service:     "cassandra",
		Description: "Cassandra 3.11.x UDF sandbox escape",
		MinVersion:  "3.11.0",
		MaxVersion:  "3.11.12",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVECassandraUDFEscape,
		CVE:         "CVE-2021-44521",
		Service:     "cassandra",
		Description: "Cassandra 4.0.x UDF sandbox escape",
		MinVersion:  "4.0.0",
		MaxVersion:  "4.0.2",
		Severity:    finding.SeverityCritical,
	},

	// ── InfluxDB ───────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEInfluxDBAuthBypass,
		CVE:         "CVE-2019-20933",
		Service:     "influxdb",
		Description: "InfluxDB authentication bypass via JWT empty secret",
		MinVersion:  "",
		MaxVersion:  "1.7.9",
		Severity:    finding.SeverityCritical,
	},

	// ── ZooKeeper ──────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEZooKeeperSASLBypass,
		CVE:         "CVE-2023-44981",
		Service:     "zookeeper",
		Description: "Apache ZooKeeper SASL quorum peer auth bypass",
		MinVersion:  "",
		MaxVersion:  "3.9.1",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEZooKeeperGetACLBypass,
		CVE:         "CVE-2019-0201",
		Service:     "zookeeper",
		Description: "Apache ZooKeeper getACL auth bypass on specific znodes",
		MinVersion:  "",
		MaxVersion:  "3.4.14",
		Severity:    finding.SeverityMedium,
	},

	// ── Kafka ──────────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEKafkaJNDIInjection,
		CVE:         "CVE-2023-25194",
		Service:     "kafka",
		Description: "Kafka Connect JNDI injection via SASL JAAS config",
		MinVersion:  "2.3.0",
		MaxVersion:  "3.4.0",
		Severity:    finding.SeverityHigh,
	},
	{
		CheckID:     finding.CheckCVEKafkaConfigTraversal,
		CVE:         "CVE-2024-31141",
		Service:     "kafka",
		Description: "Kafka Clients config provider path traversal",
		MinVersion:  "2.3.0",
		MaxVersion:  "3.7.1",
		Severity:    finding.SeverityMedium,
	},

	// ── MariaDB ────────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEMariaDBLDAPAuthBypass,
		CVE:         "CVE-2021-27928",
		Service:     "mysql",
		Description: "MariaDB LDAP auth plugin bypass → RCE",
		MinVersion:  "10.2.0",
		MaxVersion:  "10.2.37",
		Severity:    finding.SeverityHigh,
	},

	// ── Mosquitto ──────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEMosquittoCrash,
		CVE:         "CVE-2023-0809",
		Service:     "mosquitto",
		Description: "Eclipse Mosquitto crafted packet crash",
		MinVersion:  "",
		MaxVersion:  "2.0.16",
		Severity:    finding.SeverityMedium,
	},

	// ── VNC ────────────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEVNCRealVNCAuthBypass,
		CVE:         "CVE-2006-2369",
		Service:     "realvnc",
		Description: "RealVNC auth bypass via security type selection",
		MinVersion:  "4.1.0",
		MaxVersion:  "4.1.2",
		Severity:    finding.SeverityHigh,
	},
	{
		CheckID:     finding.CheckCVEVNCTightVNCInfoLeak,
		CVE:         "CVE-2019-15681",
		Service:     "tightvnc",
		Description: "TightVNC heap info leak via clipboard handler",
		MinVersion:  "",
		MaxVersion:  "2.8.11",
		Severity:    finding.SeverityHigh,
	},

	// ── Superset (additional) ─────────────────────────────────────────
	{
		CheckID:     finding.CheckCVESupersetAuthBypass,
		CVE:         "CVE-2023-36388",
		Service:     "superset",
		Description: "Apache Superset REST API auth bypass on specific endpoints",
		MinVersion:  "",
		MaxVersion:  "2.1.1",
		Severity:    finding.SeverityMedium,
	},

	// ── aiohttp ────────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEAiohttpPathTraversal,
		CVE:         "CVE-2024-23334",
		Service:     "aiohttp",
		Description: "aiohttp static file path traversal via follow_symlinks",
		MinVersion:  "",
		MaxVersion:  "3.9.2",
		Severity:    finding.SeverityHigh,
	},

	// ── curl ───────────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVECurlSOCKS5Overflow,
		CVE:         "CVE-2023-38545",
		Service:     "curl",
		Description: "curl SOCKS5 proxy hostname heap overflow",
		MinVersion:  "",
		MaxVersion:  "8.4.0",
		Severity:    finding.SeverityCritical,
	},

	// ── XZ Utils ───────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEXZUtilsBackdoor,
		CVE:         "CVE-2024-3094",
		Service:     "xz",
		Description: "XZ Utils embedded backdoor in liblzma → sshd RCE",
		MinVersion:  "5.6.0",
		MaxVersion:  "5.6.2",
		Severity:    finding.SeverityCritical,
	},

	// ── systemd ────────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVESystemdLessTraversal,
		CVE:         "CVE-2023-26604",
		Service:     "systemd",
		Description: "systemd wall message path traversal via less pager",
		MinVersion:  "",
		MaxVersion:  "247",
		Severity:    finding.SeverityHigh,
	},

	// ── git ────────────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEGitCloneRCE,
		CVE:         "CVE-2024-32002",
		Service:     "git",
		Description: "git recursive clone symlink RCE",
		MinVersion:  "",
		MaxVersion:  "2.45.1",
		Severity:    finding.SeverityCritical,
	},

	// ── JumpServer ─────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEJumpServerAuthBypass,
		CVE:         "CVE-2023-42820",
		Service:     "jumpserver",
		Description: "JumpServer auth bypass via MFA token prediction",
		MinVersion:  "",
		MaxVersion:  "3.6.5",
		Severity:    finding.SeverityCritical,
	},

	// ── Zimbra (additional) ───────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEZimbraCPIOUploadRCE,
		CVE:         "CVE-2022-41352",
		Service:     "zimbra",
		Description: "Zimbra unrestricted file upload via cpio extraction",
		MinVersion:  "8.8.0",
		MaxVersion:  "9.0.1",
		Severity:    finding.SeverityCritical,
	},

	// ── FortiOS (additional) ──────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEFortiOSSSLVPNHeapOverflow,
		CVE:         "CVE-2022-42475",
		Service:     "fortios",
		Description: "FortiOS SSL VPN heap overflow → pre-auth RCE",
		MinVersion:  "6.0.0",
		MaxVersion:  "7.2.3",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEFortiOSCredLeak,
		CVE:         "CVE-2018-13379",
		Service:     "fortios",
		Description: "FortiOS SSL VPN credential file read (5.6.x)",
		MinVersion:  "5.6.3",
		MaxVersion:  "5.6.8",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEFortiOSCredLeak,
		CVE:         "CVE-2018-13379",
		Service:     "fortios",
		Description: "FortiOS 6.0.x SSL VPN credential file read",
		MinVersion:  "6.0.0",
		MaxVersion:  "6.0.5",
		Severity:    finding.SeverityCritical,
	},

	// ── Veeam (additional) ────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEVeeamAgentRCE,
		CVE:         "CVE-2024-29849",
		Service:     "veeam",
		Description: "Veeam Agent for Windows authentication bypass RCE",
		MinVersion:  "",
		MaxVersion:  "6.2",
		Severity:    finding.SeverityCritical,
	},

	// ── UniFi ──────────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEUniFiLog4Shell,
		CVE:         "CVE-2021-44228",
		Service:     "unifi",
		Description: "Log4Shell in UniFi Network",
		MinVersion:  "",
		MaxVersion:  "6.5.54",
		Severity:    finding.SeverityCritical,
	},

	// ── Harbor ─────────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEHarborDefaultCreds,
		CVE:         "CVE-2026-4404",
		Service:     "harbor",
		Description: "Harbor default admin:Harbor12345 credentials",
		MinVersion:  "",
		MaxVersion:  "2.15.1",
		Severity:    finding.SeverityCritical,
	},

	// ── Zabbix (session forge) ────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEZabbixSessionForge,
		CVE:         "CVE-2024-36466",
		Service:     "zabbix",
		Description: "Zabbix session cookie forgery + API auth bypass",
		MinVersion:  "6.0.0",
		MaxVersion:  "6.0.28",
		Severity:    finding.SeverityCritical,
	},

	// ── Hazelcast ──────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEHazelcastSessionFixation,
		CVE:         "CVE-2022-36437",
		Service:     "hazelcast",
		Description: "Hazelcast session fixation via predictable session IDs",
		MinVersion:  "",
		MaxVersion:  "5.2.0",
		Severity:    finding.SeverityCritical,
	},

	// ── MikroTik ───────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEMikroTikWinboxRead,
		CVE:         "CVE-2018-14847",
		Service:     "mikrotik",
		Description: "MikroTik Winbox arbitrary file read",
		MinVersion:  "",
		MaxVersion:  "6.43",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEMikroTikPrivEsc,
		CVE:         "CVE-2023-30799",
		Service:     "mikrotik",
		Description: "MikroTik RouterOS privilege escalation to super-admin",
		MinVersion:  "",
		MaxVersion:  "6.49.7",
		Severity:    finding.SeverityCritical,
	},

	// ── Proxmox ────────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEProxmoxAuthBypass,
		CVE:         "CVE-2022-35508",
		Service:     "proxmox",
		Description: "Proxmox VE authentication bypass",
		MinVersion:  "",
		MaxVersion:  "7.2.7",
		Severity:    finding.SeverityCritical,
	},

	// ── MinIO ──────────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEMinIOEnvDisclosure,
		CVE:         "CVE-2023-28432",
		Service:     "minio",
		Description: "MinIO unauthenticated MINIO_SECRET_KEY leak",
		MinVersion:  "",
		MaxVersion:  "2023.3.20",
		Severity:    finding.SeverityHigh,
	},

	// ── K8s Dashboard ──────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEK8sDashboardSkipAuth,
		CVE:         "CVE-2018-18264",
		Service:     "kubernetes-dashboard",
		Description: "K8s Dashboard --enable-skip-login auth bypass",
		MinVersion:  "",
		MaxVersion:  "1.10.1",
		Severity:    finding.SeverityHigh,
	},

	// ── libupnp ────────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVELibupnpSSDPRCE,
		CVE:         "CVE-2012-5958",
		Service:     "libupnp",
		Description: "libupnp SSDP SUBSCRIBE buffer overflow → RCE",
		MinVersion:  "",
		MaxVersion:  "1.6.18",
		Severity:    finding.SeverityCritical,
	},

	// ── Nextcloud (additional) ────────────────────────────────────────
	{
		CheckID:     finding.CheckCVENextcloudSSRFPreview,
		CVE:         "CVE-2023-48239",
		Service:     "nextcloud",
		Description: "Nextcloud 24.x preview SSRF → cloud metadata access",
		MinVersion:  "24.0.0",
		MaxVersion:  "24.0.12",
		Severity:    finding.SeverityHigh,
	},
	{
		CheckID:     finding.CheckCVENextcloudInfoLeak,
		CVE:         "CVE-2023-25817",
		Service:     "nextcloud",
		Description: "Nextcloud 24.x server info leak via preview endpoint",
		MinVersion:  "24.0.0",
		MaxVersion:  "24.0.8",
		Severity:    finding.SeverityMedium,
	},

	// ── Veeam Backup (additional) ────────────────────────────────────
	{
		CheckID:     finding.CheckCVEVeeamBackupExposed,
		CVE:         "CVE-2025-23120",
		Service:     "veeam",
		Description: "Veeam B&R unauthenticated RCE via deserialization",
		MinVersion:  "",
		MaxVersion:  "12.3",
		Severity:    finding.SeverityCritical,
	},

	// ── FortiOS XORtigate (additional branches) ──────────────────────
	{
		CheckID:     finding.CheckCVEFortiOSXORtigateRCE,
		CVE:         "CVE-2023-27997",
		Service:     "fortios",
		Description: "FortiOS 7.0.x SSL VPN heap overflow (XORtigate)",
		MinVersion:  "7.0.0",
		MaxVersion:  "7.0.12",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEFortiOSXORtigateRCE,
		CVE:         "CVE-2023-27997",
		Service:     "fortios",
		Description: "FortiOS 6.4.x SSL VPN heap overflow (XORtigate)",
		MinVersion:  "6.4.0",
		MaxVersion:  "6.4.13",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEFortiOSXORtigateRCE,
		CVE:         "CVE-2023-27997",
		Service:     "fortios",
		Description: "FortiOS 6.2.x SSL VPN heap overflow (XORtigate)",
		MinVersion:  "6.2.0",
		MaxVersion:  "6.2.15",
		Severity:    finding.SeverityCritical,
	},

	// ── WebLogic (additional) ─────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEWebLogicAsync,
		CVE:         "CVE-2019-2725",
		Service:     "weblogic",
		Description: "Oracle WebLogic /_async/ endpoint pre-auth deserialization RCE",
		MinVersion:  "10.3.6",
		MaxVersion:  "12.2.2",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEWebLogicWLSWSAT,
		CVE:         "CVE-2017-10271",
		Service:     "weblogic",
		Description: "Oracle WebLogic wls-wsat pre-auth XXE → RCE",
		MinVersion:  "10.3.6",
		MaxVersion:  "12.2.2",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEWebLogicT3Deser,
		CVE:         "CVE-2016-3510",
		Service:     "weblogic",
		Description: "WebLogic T3 protocol deserialization RCE",
		MinVersion:  "10.3.6",
		MaxVersion:  "12.2.2",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEWebLogicT3JRMP,
		CVE:         "CVE-2017-3248",
		Service:     "weblogic",
		Description: "WebLogic T3 JRMP deserialization RCE",
		MinVersion:  "10.3.6",
		MaxVersion:  "12.2.2",
		Severity:    finding.SeverityCritical,
	},

	// ── Exchange (additional) ─────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEExchangeProxyShell,
		CVE:         "CVE-2021-34473",
		Service:     "exchange",
		Description: "Exchange ProxyShell — version from X-OWA-Version",
		MinVersion:  "15.0.0",
		MaxVersion:  "15.2.922",
		Severity:    finding.SeverityCritical,
	},
	{
		CheckID:     finding.CheckCVEExchangeViewStateRCE,
		CVE:         "CVE-2020-0688",
		Service:     "exchange",
		Description: "Exchange static ViewState key RCE",
		MinVersion:  "15.0.0",
		MaxVersion:  "15.2.659",
		Severity:    finding.SeverityHigh,
	},

	// ── FortiOS Auth Bypass (additional branches) ────────────────────
	{
		CheckID:     finding.CheckCVEFortiOSAuthBypass,
		CVE:         "CVE-2022-40684",
		Service:     "fortios",
		Description: "FortiOS 7.2.x HTTP header auth bypass → admin access",
		MinVersion:  "7.2.0",
		MaxVersion:  "7.2.2",
		Severity:    finding.SeverityCritical,
	},

	// ── F5 BIG-IP (additional) ────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEF5BigIPConfigBypass,
		CVE:         "CVE-2023-46747",
		Service:     "bigip",
		Description: "F5 BIG-IP config utility auth bypass via AJP request smuggling",
		MinVersion:  "",
		MaxVersion:  "17.1.1",
		Severity:    finding.SeverityCritical,
	},

	// ── ScreenConnect ──────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEScreenConnectBypass,
		CVE:         "CVE-2024-1709",
		Service:     "screenconnect",
		Description: "ConnectWise ScreenConnect setup wizard auth bypass",
		MinVersion:  "",
		MaxVersion:  "23.9.8",
		Severity:    finding.SeverityCritical,
	},

	// ── Expedition ─────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEExpeditionRCE,
		CVE:         "CVE-2024-9463",
		Service:     "expedition",
		Description: "Palo Alto Expedition unauthenticated OS command injection",
		MinVersion:  "",
		MaxVersion:  "1.2.96",
		Severity:    finding.SeverityCritical,
	},

	// ── ProgressLoadMaster ────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEProgressLoadMaster,
		CVE:         "CVE-2024-1212",
		Service:     "loadmaster",
		Description: "Progress Kemp LoadMaster unauthenticated command injection",
		MinVersion:  "",
		MaxVersion:  "7.2.59.2",
		Severity:    finding.SeverityCritical,
	},

	// ── FortiClient EMS ───────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEFortiClientEMSSQLi,
		CVE:         "CVE-2023-48788",
		Service:     "forticlient",
		Description: "FortiClient EMS DASTelemetryRequest SQL injection → RCE",
		MinVersion:  "",
		MaxVersion:  "7.2.3",
		Severity:    finding.SeverityCritical,
	},

	// ── Qlik Sense ────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVEQlikSenseTunneling,
		CVE:         "CVE-2023-48365",
		Service:     "qlik",
		Description: "Qlik Sense Enterprise HTTP request tunneling auth bypass",
		MinVersion:  "",
		MaxVersion:  "14.159",
		Severity:    finding.SeverityCritical,
	},

	// ── CUPS ───────────────────────────────────────────────────────────
	{
		CheckID:     finding.CheckCVECUPSRCE,
		CVE:         "CVE-2024-47176",
		Service:     "cups",
		Description: "CUPS cups-browsed binds on UDP 631 → attacker-controlled PPD → RCE",
		MinVersion:  "",
		MaxVersion:  "2.0.1",
		Severity:    finding.SeverityCritical,
	},

	// ── Veeam Backup RCE (wave 5) ────────────────────────────────────
	{
		CheckID:     finding.CheckCVEVeeamBackupRCE,
		CVE:         "CVE-2024-40711",
		Service:     "veeam",
		Description: "Veeam Backup & Replication 12.x unauthenticated RCE",
		MinVersion:  "12.0",
		MaxVersion:  "12.2",
		Severity:    finding.SeverityCritical,
	},
}

// serviceAliases maps common banner product names to our canonical service names.
var serviceAliases = map[string]string{
	"apache":              "apache",
	"httpd":               "apache",
	"apache httpd":        "apache",
	"apache/httpd":        "apache",
	"nginx":               "nginx",
	"openresty":           "nginx",
	"openssh":             "openssh",
	"dropbear":            "dropbear",
	"mysql":               "mysql",
	"mariadb":             "mysql",
	"postgresql":          "postgresql",
	"postgres":            "postgresql",
	"redis":               "redis",
	"elasticsearch":       "elasticsearch",
	"elastic":             "elasticsearch",
	"jenkins":             "jenkins",
	"gitlab":              "gitlab",
	"gitlab-ce":           "gitlab",
	"gitlab-ee":           "gitlab",
	"teamcity":            "teamcity",
	"grafana":             "grafana",
	"vault":               "vault",
	"consul":              "consul",
	"docker":              "docker",
	"runc":                "runc",
	"activemq":            "activemq",
	"fortios":             "fortios",
	"fortigate":           "fortios",
	"tomcat":              "tomcat",
	"apache tomcat":       "tomcat",
	"spring":              "spring",
	"spring-boot":         "spring",
	"vsftpd":              "vsftpd",
	"confluence":          "confluence",
	"log4j":               "log4j",
	"exchange":            "exchange",
	"vcenter":             "vcenter",
	"bigip":               "bigip",
	"big-ip":              "bigip",
	"netscaler":           "netscaler",
	"citrix":              "netscaler",
	"salt":                "salt",
	"saltstack":           "salt",
	"weblogic":            "weblogic",
	"kibana":              "kibana",
	"openfire":            "openfire",
	"workspace-one":       "workspace-one",
	"clickhouse":          "clickhouse",
	"nats":                "nats",
	"nats-server":         "nats",
	"nextcloud":           "nextcloud",
	"gradio":              "gradio",
	"veeam":               "veeam",
	"veeam backup":        "veeam",
	"tika":                "tika",
	"apache tika":         "tika",
	"erlang":              "erlang",
	"erlang/otp":          "erlang",
	"gitea":               "gitea",
	"airflow":             "airflow",
	"superset":            "superset",
	"mlflow":              "mlflow",
	"pgadmin":             "pgadmin",
	"manageengine":        "manageengine",
	"zimbra":              "zimbra",
	"microsoft-iis":       "iis",
	"proftpd":             "proftpd",
	"filezilla server":    "filezilla",
	"exim":                "exim",
	"postfix":             "postfix",
	"vsftp":               "vsftpd",
	"keycloak":            "keycloak",
	"roundcube":           "roundcube",
	"webmin":              "webmin",
	"splunk":              "splunk",
	"splunk enterprise":   "splunk",
	"zabbix":              "zabbix",
	"phpmyadmin":          "phpmyadmin",
	"jboss":               "jboss",
	"wildfly":             "jboss",
	"ofbiz":               "ofbiz",
	"apache ofbiz":        "ofbiz",
	"solr":                "solr",
	"apache solr":         "solr",
	"drupal":              "drupal",
	"joomla":              "joomla",
	"jira":                "jira",
	"atlassian jira":      "jira",
	"bitbucket":           "bitbucket",
	"argocd":              "argocd",
	"argo cd":             "argocd",
	"drone":               "drone",
	"drone ci":            "drone",
	"portainer":           "portainer",
	"jupyter":             "jupyter",
	"jupyter notebook":    "jupyter",
	"jupyter server":      "jupyter",
	"couchdb":             "couchdb",
	"apache couchdb":      "couchdb",
	"containerd":          "containerd",
	"prometheus":          "prometheus",
	"sonarqube":           "sonarqube",
	"django":              "django",
	"express":             "express",
	"express.js":          "express",
	"laravel":             "laravel",
	"ghost":               "ghost",
	"ghost cms":           "ghost",
	"nacos":               "nacos",
	"nifi":                "nifi",
	"apache nifi":         "nifi",
	"neo4j":               "neo4j",
	"cassandra":           "cassandra",
	"apache cassandra":    "cassandra",
	"influxdb":            "influxdb",
	"zookeeper":           "zookeeper",
	"apache zookeeper":    "zookeeper",
	"kafka":               "kafka",
	"apache kafka":        "kafka",
	"rabbitmq":            "rabbitmq",
	"etcd":                "etcd",
	"memcached":           "memcached",
	"mongodb":             "mongodb",
	"mongod":              "mongodb",
	"mosquitto":           "mosquitto",
	"eclipse mosquitto":   "mosquitto",
	"realvnc":             "realvnc",
	"tightvnc":            "tightvnc",
	"aiohttp":             "aiohttp",
	"curl":                "curl",
	"libcurl":             "curl",
	"xz":                  "xz",
	"xz-utils":            "xz",
	"systemd":             "systemd",
	"git":                 "git",
	"jumpserver":          "jumpserver",
	"goanywhere":          "goanywhere",
	"geoserver":           "geoserver",
	"kubernetes":          "kubernetes",
	"k8s":                 "kubernetes",
	"kubernetes-dashboard": "kubernetes-dashboard",
	"crushftp":            "crushftp",
	"ollama":              "ollama",
	"rocketmq":            "rocketmq",
	"apache rocketmq":     "rocketmq",
	"pyload":              "pyload",
	"cacti":               "cacti",
	"proxmox":             "proxmox",
	"proxmox ve":          "proxmox",
	"minio":               "minio",
	"mikrotik":            "mikrotik",
	"routeros":            "mikrotik",
	"unifi":               "unifi",
	"harbor":              "harbor",
	"hazelcast":           "hazelcast",
	"libupnp":             "libupnp",
	"screenconnect":       "screenconnect",
	"connectwise":         "screenconnect",
	"expedition":          "expedition",
	"loadmaster":          "loadmaster",
	"kemp loadmaster":     "loadmaster",
	"forticlient":         "forticlient",
	"forticlient ems":     "forticlient",
	"qlik":                "qlik",
	"qlik sense":          "qlik",
	"cups":                "cups",
	"cups-browsed":        "cups",
}

// normalizeService maps a raw service/product name to the canonical form
// used in CVE version rules.
func normalizeService(raw string) string {
	lower := strings.ToLower(strings.TrimSpace(raw))
	if mapped, ok := serviceAliases[lower]; ok {
		return mapped
	}
	return lower
}

// CheckVersionCVEs checks an extracted service version against the built-in
// CVE version database and returns findings for all matching rules.
func CheckVersionCVEs(service, version string, makeF findingMaker) []finding.Finding {
	return CheckVersionCVEsCtx(context.Background(), service, version, makeF)
}

// CheckVersionCVEsCtx checks a service+version against the built-in CVE
// version database and returns findings for matched rules. When a scanlog
// logger is present in ctx, it emits detailed debug logs for each rule.
func CheckVersionCVEsCtx(ctx context.Context, service, version string, makeF findingMaker) []finding.Finding {
	sl := scanlog.FromContext(ctx)

	if service == "" || version == "" {
		return nil
	}

	canonical := normalizeService(service)
	// Strip common prefixes/suffixes from version strings.
	version = cleanVersion(version)
	if version == "" {
		return nil
	}

	sl.CVEVersionCheckStart(canonical, version)

	var results []finding.Finding
	seen := make(map[finding.CheckID]bool) // deduplicate: one finding per CheckID
	rulesChecked := 0
	matchedCount := 0

	for _, rule := range cveVersionRules {
		if rule.Service != canonical {
			continue
		}
		rulesChecked++
		if seen[rule.CheckID] {
			sl.CVEVersionRuleEvaluated(canonical, version, rule.CVE, string(rule.CheckID), false, "duplicate check_id")
			continue
		}
		if !versionInRange(version, rule.MinVersion, rule.MaxVersion) {
			sl.CVEVersionRuleEvaluated(canonical, version, rule.CVE, string(rule.CheckID), false,
				fmt.Sprintf("version %s not in range %s", version, formatRange(rule.MinVersion, rule.MaxVersion)))
			continue
		}

		sl.CVEVersionRuleEvaluated(canonical, version, rule.CVE, string(rule.CheckID), true,
			fmt.Sprintf("version %s in range %s", version, formatRange(rule.MinVersion, rule.MaxVersion)))
		matchedCount++
		seen[rule.CheckID] = true
		f := makeF(
			rule.CheckID,
			rule.Severity,
			fmt.Sprintf("%s: %s %s", rule.CVE, service, version),
			fmt.Sprintf("%s — detected %s version %s which falls in the vulnerable range %s. %s",
				rule.CVE, service, version, formatRange(rule.MinVersion, rule.MaxVersion), rule.Description),
			map[string]any{
				"cve":               rule.CVE,
				"service":           service,
				"version":           version,
				"vulnerable_range":  formatRange(rule.MinVersion, rule.MaxVersion),
				"detection_method":  "version_match",
			},
		)
		f.Confidence = finding.ConfidenceProbable
		results = append(results, f)
	}

	sl.CVEVersionCheckComplete(canonical, version, rulesChecked, matchedCount)
	return results
}

// cleanVersion strips common prefixes/suffixes from version strings to get
// a clean X.Y.Z form. Examples:
//   - "v1.2.3" → "1.2.3"
//   - "9.6p1" → "9.6" (keep for comparison, p1 is stripped by versionBefore)
//   - "2.4.49-2ubuntu4" → "2.4.49"
func cleanVersion(v string) string {
	v = strings.TrimSpace(v)
	// Strip leading "v" or "V".
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	// Strip everything after a hyphen (distro suffixes like "-2ubuntu4").
	if idx := strings.IndexByte(v, '-'); idx > 0 {
		v = v[:idx]
	}
	// Strip everything after a plus sign (build metadata like "+dfsg").
	if idx := strings.IndexByte(v, '+'); idx > 0 {
		v = v[:idx]
	}
	return v
}

// versionInRange returns true if ver is >= min (if min != "") AND < max.
// Uses the existing versionBefore helper from version.go.
func versionInRange(ver, min, max string) bool {
	if min != "" {
		// ver must be >= min, i.e., NOT (ver < min)
		if versionBefore(ver, min) {
			return false
		}
	}
	// ver must be < max
	if max != "" {
		if !versionBefore(ver, max) {
			return false
		}
	}
	return true
}

// formatRange produces a human-readable version range string.
func formatRange(min, max string) string {
	if min == "" {
		return fmt.Sprintf("< %s", max)
	}
	return fmt.Sprintf(">= %s, < %s", min, max)
}
