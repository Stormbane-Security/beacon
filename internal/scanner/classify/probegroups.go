package classify

import (
	"strings"

	"github.com/stormbane-security/beacon/internal/playbook"
)

// probeGroup defines a set of technology-specific paths to probe, gated by a
// trigger function that checks whether Evidence signals suggest the technology
// might be present. This replaces the previous approach of probing all ~200
// paths blindly, which produced massive false positive rates on catch-all
// sites (SPAs, Framer, Vercel).
//
// Progressive probing pipeline:
//  1. Free signals: HTTP headers, TLS, DNS → initial Evidence (0 extra requests)
//  2. Root page body: HTML patterns, meta generator, scripts (already fetched)
//  3. Triggered groups: only probe paths whose triggers matched (10-30 requests)
//  4. Deep mode: probe all groups regardless of triggers (full coverage)
type probeGroup struct {
	name    string
	trigger func(e *playbook.Evidence) bool
	paths   []string
}

// alwaysTrue is a trigger that always fires — used for universal high-value paths.
func alwaysTrue(_ *playbook.Evidence) bool { return true }

// hasFramework returns a trigger that fires when Evidence.Framework matches.
func hasFramework(names ...string) func(*playbook.Evidence) bool {
	return func(e *playbook.Evidence) bool {
		fl := strings.ToLower(e.Framework)
		for _, n := range names {
			if strings.Contains(fl, n) {
				return true
			}
		}
		return false
	}
}

// hasCookie returns a trigger that fires when any of the named cookies are present.
func hasCookie(names ...string) func(*playbook.Evidence) bool {
	return func(e *playbook.Evidence) bool {
		for _, cn := range e.CookieNames {
			cl := strings.ToLower(cn)
			for _, n := range names {
				if strings.Contains(cl, n) {
					return true
				}
			}
		}
		return false
	}
}

// hasServer returns a trigger that fires when the Server header contains a substring.
func hasServer(substrs ...string) func(*playbook.Evidence) bool {
	return func(e *playbook.Evidence) bool {
		sl := strings.ToLower(e.Headers["server"])
		for _, s := range substrs {
			if strings.Contains(sl, s) {
				return true
			}
		}
		return false
	}
}

// hasHeader returns a trigger that fires when any of the named headers exist.
func hasHeader(keys ...string) func(*playbook.Evidence) bool {
	return func(e *playbook.Evidence) bool {
		for _, k := range keys {
			if _, ok := e.Headers[k]; ok {
				return true
			}
		}
		return false
	}
}

// hasBody returns a trigger that fires when Body512 contains any substring.
func hasBody(substrs ...string) func(*playbook.Evidence) bool {
	return func(e *playbook.Evidence) bool {
		bl := strings.ToLower(e.Body512)
		for _, s := range substrs {
			if strings.Contains(bl, s) {
				return true
			}
		}
		return false
	}
}

// hasTitle returns a trigger that fires when the page title contains a substring.
func hasTitle(substrs ...string) func(*playbook.Evidence) bool {
	return func(e *playbook.Evidence) bool {
		tl := strings.ToLower(e.Title)
		for _, s := range substrs {
			if strings.Contains(tl, s) {
				return true
			}
		}
		return false
	}
}

// hasProxy returns a trigger that fires when ProxyType matches.
func hasProxy(names ...string) func(*playbook.Evidence) bool {
	return func(e *playbook.Evidence) bool {
		pl := strings.ToLower(e.ProxyType)
		for _, n := range names {
			if strings.Contains(pl, n) {
				return true
			}
		}
		return false
	}
}

// anyOf combines multiple triggers — fires if ANY trigger returns true.
func anyOf(triggers ...func(*playbook.Evidence) bool) func(*playbook.Evidence) bool {
	return func(e *playbook.Evidence) bool {
		for _, t := range triggers {
			if t(e) {
				return true
			}
		}
		return false
	}
}

// probeGroups defines all technology-specific path groups with their triggers.
// Each group is only probed when its trigger function returns true, reducing
// the typical probe count from ~200 to ~10-30 per asset.
var probeGroups = []probeGroup{
	// ── Always probe: universal high-value paths ────────────────────────────
	// These are probed on every asset because they're either auth discovery
	// endpoints or extremely high-value security findings.
	{
		name:    "universal",
		trigger: alwaysTrue,
		paths: []string{
			"/.well-known/openid-configuration",
			"/.well-known/oauth-authorization-server",
			"/swagger.json", "/openapi.json",
			"/graphql",
			"/robots.txt",
			"/metrics",           // Prometheus metrics (exposed = info leak)
			"/server-status",     // Apache mod_status
			"/stats",             // HAProxy stats / Envoy admin (body-checked)
			"/debug/pprof/",      // Go pprof
			"/healthz",           // K8s health
			"/wp-login.php",      // WordPress (massively common)
		},
	},

	// ── Java / Spring Boot ──────────────────────────────────────────────────
	{
		name: "java",
		trigger: anyOf(
			hasCookie("jsessionid"),
			hasServer("tomcat", "jetty", "wildfly", "jboss", "weblogic", "websphere"),
			hasHeader("x-powered-by"), // often "Servlet/3.1" or similar
			hasBody("jsessionid", "j_spring_security", "javax.", "struts"),
			hasFramework("spring", "java"),
		),
		paths: []string{
			"/actuator", "/actuator/health", "/actuator/env", "/actuator/mappings",
			"/j_spring_security_check",
			"/manager/html", "/manager/status", "/host-manager/html", // Tomcat
			"/console/",   // WebLogic
			"/identity/",  // Oracle Identity Manager
		},
	},

	// ── PHP ──────────────────────────────────────────────────────────────────
	{
		name: "php",
		trigger: anyOf(
			hasCookie("phpsessid"),
			hasHeader("x-powered-by"), // often "PHP/8.x"
			hasServer("apache", "nginx"), // common PHP servers
			hasBody(".php", "phpmyadmin", "laravel", "wordpress", "drupal", "craft"),
			hasFramework("laravel", "wordpress", "drupal", "symfony", "craft"),
		),
		paths: []string{
			"/phpmyadmin", "/phpmyadmin/", "/adminer", "/adminer.php", "/pma", "/mysql",
			"/info.php", "/phpinfo.php", "/apc.php",
			"/wp-json", "/wp-admin",
			"/telescope", "/horizon", "/_ignition", "/livewire/update", "/livewire/upload-file",
			"/sites/default",                       // Drupal
			"/actions/users/login",                 // Craft CMS
			"/index.php?p=admin/login",             // Craft CMS
			"/_profiler/", "/_wdt/",                // Symfony
			"/api_jsonrpc.php",                     // Zabbix
			"/cgi-bin/webauth.pl",                  // Juniper J-Web
		},
	},

	// ── Python ───────────────────────────────────────────────────────────────
	{
		name: "python",
		trigger: anyOf(
			hasServer("gunicorn", "uvicorn", "waitress", "hypercorn", "daphne"),
			hasBody("csrfmiddlewaretoken", "django", "flask", "fastapi"),
			hasFramework("django", "flask", "fastapi"),
		),
		paths: []string{
			"/docs", "/redoc",             // FastAPI
			"/__debug__/",                 // Django Debug Toolbar
			"/api/v1/health", "/api/v1/dags", // Airflow
			"/api/kernels", "/api/contents",  // Jupyter
		},
	},

	// ── Node.js ──────────────────────────────────────────────────────────────
	{
		name: "nodejs",
		trigger: anyOf(
			hasServer("express", "node", "next", "koa"),
			hasHeader("x-powered-by"), // "Express"
			hasBody("__next", "__nuxt", "express", "node_modules"),
			hasFramework("nextjs", "nuxt", "express", "sveltekit"),
		),
		paths: []string{
			"/_next/static/chunks/main.js", "/_next/static/chunks/webpack.js",
			"/__vite_ping",
			"/__health",
			"/api/v1/settings", "/api/v1/workflows", // n8n
			"/api/status-page/heartbeat",             // Uptime Kuma
			"/ghost", "/ghost/api",                   // Ghost CMS
		},
	},

	// ── Ruby ─────────────────────────────────────────────────────────────────
	{
		name: "ruby",
		trigger: anyOf(
			hasCookie("_session_id"),
			hasServer("puma", "passenger", "unicorn", "thin"),
			hasBody("ruby", "rails", "sinatra"),
			hasFramework("rails", "ruby"),
		),
		paths: []string{
			"/rails/info/properties", "/rails/info", "/cable",
		},
	},

	// ── .NET / IIS ───────────────────────────────────────────────────────────
	{
		name: "dotnet",
		trigger: anyOf(
			hasCookie("asp.net_sessionid"),
			hasServer("microsoft-iis", "kestrel"),
			hasHeader("x-aspnet-version", "x-powered-by"),
			hasBody("__viewstate", "asp.net", ".aspx"),
		),
		paths: []string{
			"/elmah.axd", "/trace.axd",
			"/helpdesk/WebObjects/Helpdesk.woa/", // SolarWinds
		},
	},

	// ── Keycloak / OAuth / OIDC ─────────────────────────────────────────────
	{
		name: "auth",
		trigger: anyOf(
			hasBody("keycloak", "oauth", "openid", "saml", "auth0", "okta"),
			hasTitle("keycloak", "login", "sign in"),
		),
		paths: []string{
			"/auth/realms", "/realms", "/auth/admin",
			"/oauth/authorize", "/oauth2/authorize",
		},
	},

	// ── HashiCorp (Vault, Consul) ───────────────────────────────────────────
	{
		name: "hashicorp",
		trigger: anyOf(
			hasBody("vault", "consul", "hashicorp"),
			hasTitle("vault", "consul"),
			hasServer("vault"),
		),
		paths: []string{
			"/v1/sys/health", "/v1/sys/seal-status",
			"/v1/catalog/nodes", "/v1/status/leader",
		},
	},

	// ── Monitoring / Observability ───────────────────────────────────────────
	{
		name: "monitoring",
		trigger: anyOf(
			hasTitle("grafana", "prometheus", "kibana", "jaeger", "zipkin", "nagios", "zabbix", "wazuh"),
			hasBody("grafana", "prometheus", "kibana", "jaeger", "elastic"),
			hasServer("grafana"),
		),
		paths: []string{
			"/api/health",                  // Grafana
			"/targets",                     // Prometheus
			"/api/v1/status/buildinfo",     // Prometheus
			"/api/v1/alerts",               // Prometheus / Alertmanager
			"/app/home", "/app/kibana",     // Kibana
			"/api/traces", "/api/services", // Jaeger
			"/api/v2/traces",               // Zipkin
			"/loki/api/v1/labels",          // Loki
			"/tempo/api/traces",            // Tempo
			"/vmui",                        // VictoriaMetrics
			"/nagios/", "/nagios/cgi-bin/status.cgi",
			"/api/v2/manager/info",         // Wazuh
		},
	},

	// ── Elasticsearch / OpenSearch ───────────────────────────────────────────
	{
		name: "elasticsearch",
		trigger: anyOf(
			hasBody("lucene_version", "elasticsearch", "opensearch"),
			hasTitle("kibana", "elasticsearch"),
			hasServer("elasticsearch"),
		),
		paths: []string{
			"/_cat/indices", "/_cluster/health", "/_nodes",
		},
	},

	// ── ClickHouse ───────────────────────────────────────────────────────────
	{
		name:    "clickhouse",
		trigger: anyOf(hasTitle("clickhouse"), hasBody("clickhouse"), hasServer("clickhouse")),
		paths:   []string{"/play"},
	},

	// ── CI/CD (GitLab, ArgoCD, TeamCity, Jenkins) ───────────────────────────
	{
		name: "cicd",
		trigger: anyOf(
			hasTitle("gitlab", "argocd", "teamcity", "jenkins", "gitea", "forgejo"),
			hasBody("gitlab", "argocd", "teamcity", "jenkins"),
			hasServer("gitlab"),
		),
		paths: []string{
			"/-/health", "/-/readiness", "/-/healthy", "/lab",
			"/api/v1/applications",  // ArgoCD
			"/app/rest/server",      // TeamCity
			"/api/v1/version",       // Gitea/Forgejo
		},
	},

	// ── Container / Docker / K8s ────────────────────────────────────────────
	{
		name: "container",
		trigger: anyOf(
			hasTitle("portainer", "harbor", "rancher"),
			hasBody("portainer", "harbor", "docker", "kubernetes"),
		),
		paths: []string{
			"/api/settings", "/api/status",    // Portainer
			"/api/v2.0/systeminfo",            // Harbor
			"/clusters",                       // K8s
		},
	},

	// ── AI / LLM ────────────────────────────────────────────────────────────
	{
		name: "ai",
		trigger: anyOf(
			hasBody("openai", "ollama", "langflow", "llm", "gpt", "model"),
			hasTitle("ollama", "langflow"),
		),
		paths: []string{
			"/v1/models", "/v1/chat/completions",
			"/api/generate", "/api/tags",       // Ollama
			"/api/v1/version", "/api/v1/flows", // Langflow
		},
	},

	// ── Databases ────────────────────────────────────────────────────────────
	{
		name: "database",
		trigger: anyOf(
			hasTitle("couchdb", "neo4j", "minio", "pgadmin", "adminer"),
			hasBody("couchdb", "neo4j", "minio"),
			hasServer("couchdb"),
		),
		paths: []string{
			"/_utils", "/_all_dbs",         // CouchDB
			"/db/neo4j/tx", "/browser/",    // Neo4j
			"/minio/health/live", "/minio/health/cluster",
			"/pgadmin4", "/pgadmin4/", "/pgadmin",
		},
	},

	// ── Message queues ───────────────────────────────────────────────────────
	{
		name: "messaging",
		trigger: anyOf(
			hasTitle("rabbitmq", "kafka"),
			hasBody("rabbitmq", "kafka", "amqp"),
		),
		paths: []string{
			"/api/overview", // RabbitMQ
			"/topics", "/v3/clusters",
		},
	},

	// ── Infrastructure management ───────────────────────────────────────────
	{
		name: "infra",
		trigger: anyOf(
			hasTitle("proxmox", "cloudstack", "openshift", "openstack", "ansible", "sonarqube", "sentry"),
			hasBody("proxmox", "cloudstack", "openshift", "openstack", "ansible"),
		),
		paths: []string{
			"/api2/json", "/api2/json/version",  // Proxmox
			"/client/api",                       // CloudStack
			"/apis/apps.openshift.io/v1",        // OpenShift
			"/identity/v3",                      // OpenStack Keystone
			"/dashboard/auth/login/",            // OpenStack Horizon
			"/api/v2/ping",                      // Ansible AWX
			"/api/system/status",                // SonarQube
			"/api/0/internal/health",            // Sentry
		},
	},

	// ── Hasura / GraphQL engines ────────────────────────────────────────────
	{
		name: "hasura",
		trigger: anyOf(
			hasBody("hasura", "graphql"),
			hasTitle("hasura"),
		),
		paths: []string{
			"/v1/graphql", "/v1/metadata", "/console",
		},
	},

	// ── Traefik ──────────────────────────────────────────────────────────────
	{
		name:    "traefik",
		trigger: hasProxy("traefik"),
		paths: []string{
			"/api/rawdata", "/api/overview", "/api/entrypoints", "/dashboard",
		},
	},

	// ── Envoy ────────────────────────────────────────────────────────────────
	{
		name:    "envoy",
		trigger: hasProxy("envoy"),
		paths:   []string{"/config_dump", "/stats"},
	},

	// ── Splunk ───────────────────────────────────────────────────────────────
	{
		name:    "splunk",
		trigger: anyOf(hasTitle("splunk"), hasBody("splunk")),
		paths:   []string{"/services/server/info", "/en-US/account/login"},
	},

	// ── Sonatype Nexus ──────────────────────────────────────────────────────
	{
		name:    "nexus",
		trigger: anyOf(hasTitle("nexus"), hasBody("nexus")),
		paths:   []string{"/service/rest/v1/status"},
	},

	// ── Web3 / IPFS ─────────────────────────────────────────────────────────
	{
		name:    "web3",
		trigger: anyOf(hasBody("ipfs", "web3", "ethereum", "blockchain")),
		paths:   []string{"/api/v0/id", "/api/v0/version"},
	},

	// ── VPN / Security appliances (CVE probes) ──────────────────────────────
	// These are high-value CVE paths. They're gated on signals that suggest
	// the target IS a VPN/firewall appliance, not a random web app.
	{
		name: "vpn_appliance",
		trigger: anyOf(
			hasTitle("vpn", "ssl vpn", "globalprotect", "anyconnect", "fortigate", "fortiweb",
				"netscaler", "citrix", "pulse", "ivanti", "sonicwall", "checkpoint", "palo alto"),
			hasBody("vpn", "globalprotect", "anyconnect", "/remote/login", "fortinet",
				"netscaler", "citrix gateway", "pulse secure", "ivanti connect"),
			hasServer("big-ip", "bigip"),
		),
		paths: []string{
			"/vpn/index.html", "/p/u/doAuthentication.do",           // Citrix
			"/remote/login",                                          // FortiGate
			"/api/v2.0/",                                             // FortiWeb
			"/+CSCOE+/logon.html",                                    // Cisco ASA
			"/dana-na/auth/url_default/welcome.cgi", "/dana-na/",     // Ivanti/Pulse
			"/global-protect/login.esp", "/php/login.php",            // Palo Alto
			"/tmui/login.jsp", "/mgmt/shared/authn/login",           // F5 BIG-IP
			"/auth.html",                                             // SonicWall
			"/clients/MyCRL",                                         // Check Point
			"/mifs/c/appstore/fob/", "/mifs/c/aftstore/fob/",        // Ivanti EPMM
			"/ams/",                                                   // Ivanti EPM
			"/appliance/api/info",                                     // BeyondTrust
			"/catalog-portal/ui",                                      // VMware Workspace ONE
		},
	},

	// ── Enterprise web apps (CVE probes) ────────────────────────────────────
	{
		name: "enterprise_web",
		trigger: anyOf(
			hasTitle("sap", "weblogic", "hpe oneview"),
			hasBody("sap", "netweaver", "weblogic", "hpe"),
			hasServer("oracle", "sap"),
		),
		paths: []string{
			"/developmentserver/metadatauploader", "/irj/portal", // SAP
			"/rest/version", // HPE OneView
		},
	},

	// ── IoT / Camera / Router ───────────────────────────────────────────────
	{
		name: "iot",
		trigger: anyOf(
			hasTitle("hikvision", "dahua", "dlink", "d-link", "netgear", "mikrotik", "tp-link",
				"unifi", "ubiquiti", "router"),
			hasBody("hikvision", "isapi", "hnap", "mikrotik"),
			hasServer("hikvision", "thttpd", "boa", "goahead", "mini_httpd"),
		),
		paths: []string{
			"/ISAPI/System/deviceInfo",  // Hikvision
			"/cgi-bin/snapshot.cgi",     // Generic IP camera
			"/HNAP1/",                   // D-Link
			"/currentsetting.htm",       // Netgear
			"/webfig/",                  // MikroTik
			"/manage/account/login",     // UniFi
			"/level/15/exec/-/show/version", // Cisco IOS
		},
	},

	// ── Misc: InfluxDB, Cassandra, Veeam, etc. ─────────────────────────────
	{
		name: "misc",
		trigger: anyOf(
			hasTitle("influxdb", "veeam", "mattermost", "rocket.chat", "home assistant", "netbox", "outline"),
			hasBody("influxdb", "veeam", "mattermost"),
			hasServer("influxdb"),
		),
		paths: []string{
			"/ping", "/query", "/health",     // InfluxDB
			"/api/v0/ops/node/status",        // Cassandra Reaper
			"/api/v1/serverInfo",             // Veeam
			"/api/v4/system/ping",            // Mattermost
			"/api/v1/info",                   // Rocket.Chat
			"/api/",                          // Home Assistant
			"/api/status/",                   // Netbox
			"/api/auth.info",                 // Outline
		},
	},

	// ── Apache / Nginx debug ────────────────────────────────────────────────
	{
		name: "webserver_debug",
		trigger: anyOf(
			hasServer("apache", "nginx"),
		),
		paths: []string{
			"/server-info",
			"/nginx_status",
			"/error_log",
		},
	},

	// ── MCP server (Model Context Protocol) ─────────────────────────────────
	{
		name:    "mcp",
		trigger: anyOf(hasBody("mcp", "model context protocol")),
		paths:   []string{"/sse"},
	},

	// ── Redis Insight ───────────────────────────────────────────────────────
	{
		name:    "redis",
		trigger: anyOf(hasTitle("redis"), hasBody("redis")),
		paths:   []string{"/api/info"},
	},

	// ── Nginx-UI ────────────────────────────────────────────────────────────
	{
		name:    "nginx_ui",
		trigger: anyOf(hasTitle("nginx ui"), hasBody("nginx-ui")),
		paths:   []string{"/api/backup"},
	},
}

// selectProbePaths returns the subset of paths to probe based on Evidence
// signals. In surface mode, only triggered groups are probed. Returns the
// combined deduplicated path list.
func selectProbePaths(e *playbook.Evidence) []string {
	seen := make(map[string]bool)
	var paths []string

	for _, g := range probeGroups {
		if !g.trigger(e) {
			continue
		}
		for _, p := range g.paths {
			if !seen[p] {
				seen[p] = true
				paths = append(paths, p)
			}
		}
	}

	return paths
}
