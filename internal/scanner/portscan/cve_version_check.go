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
