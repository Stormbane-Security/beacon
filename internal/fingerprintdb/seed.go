package fingerprintdb

import "github.com/stormbane/beacon/internal/store"

// BuiltinRules returns a copy of the builtin fingerprint rules for use in
// auto-generated integration tests. Each rule defines a signal→field mapping
// that can be reversed into a test fixture.
func BuiltinRules() []store.FingerprintRule {
	cp := make([]store.FingerprintRule, len(builtinRules))
	copy(cp, builtinRules)
	return cp
}

// builtinRules seeds the database with common fingerprint patterns.
// These are extracted from fingerprintTech() and represent the highest-
// confidence, most universally applicable patterns.
// New patterns should be added here and seeded — not hardcoded in Go logic.
var builtinRules = []store.FingerprintRule{
	// ── Cloud providers (header signals) ──────────────────────────────────
	{SignalType: "header", SignalKey: "cf-ray", SignalValue: "", Field: "proxy_type", Value: "cloudflare", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "header", SignalKey: "cf-ray", SignalValue: "", Field: "cloud_provider", Value: "cloudflare", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "header", SignalKey: "x-vercel-id", SignalValue: "", Field: "proxy_type", Value: "vercel", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "header", SignalKey: "x-vercel-id", SignalValue: "", Field: "cloud_provider", Value: "vercel", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "header", SignalKey: "x-nf-request-id", SignalValue: "", Field: "cloud_provider", Value: "netlify", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "header", SignalKey: "x-amz-cf-id", SignalValue: "", Field: "cloud_provider", Value: "aws", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "header", SignalKey: "x-amzn-requestid", SignalValue: "", Field: "cloud_provider", Value: "aws", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "header", SignalKey: "x-azure-ref", SignalValue: "", Field: "cloud_provider", Value: "azure", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "header", SignalKey: "x-goog-request-id", SignalValue: "", Field: "cloud_provider", Value: "gcp", Source: "builtin", Status: "active", Confidence: 1.0},

	// ── Proxy / API gateway (header signals) ──────────────────────────────
	{SignalType: "header", SignalKey: "x-envoy-upstream-service-time", SignalValue: "", Field: "proxy_type", Value: "envoy", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "header", SignalKey: "x-kong-request-id", SignalValue: "", Field: "proxy_type", Value: "kong", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "header", SignalKey: "x-amz-apigw-id", SignalValue: "", Field: "proxy_type", Value: "aws_api_gateway", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "header", SignalKey: "apim-request-id", SignalValue: "", Field: "proxy_type", Value: "azure_apim", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "header", SignalKey: "x-apigee-fault-code", SignalValue: "", Field: "proxy_type", Value: "apigee", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "header", SignalKey: "x-tyk-api-expires", SignalValue: "", Field: "proxy_type", Value: "tyk", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "header", SignalKey: "x-kubernetes-pf-flowschema-uid", SignalValue: "", Field: "infra_layer", Value: "kubernetes", Source: "builtin", Status: "active", Confidence: 1.0},

	// ── Server header patterns ─────────────────────────────────────────────
	{SignalType: "server", SignalKey: "", SignalValue: "nginx", Field: "proxy_type", Value: "nginx", Source: "builtin", Status: "active", Confidence: 0.9},
	{SignalType: "server", SignalKey: "", SignalValue: "apache", Field: "proxy_type", Value: "apache", Source: "builtin", Status: "active", Confidence: 0.9},
	{SignalType: "server", SignalKey: "", SignalValue: "caddy", Field: "proxy_type", Value: "caddy", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "server", SignalKey: "", SignalValue: "traefik", Field: "proxy_type", Value: "traefik", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "server", SignalKey: "", SignalValue: "litespeed", Field: "proxy_type", Value: "litespeed", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "server", SignalKey: "", SignalValue: "iis", Field: "proxy_type", Value: "iis", Source: "builtin", Status: "active", Confidence: 1.0},

	// ── Framework detection (x-powered-by header) ─────────────────────────
	{SignalType: "header", SignalKey: "x-powered-by", SignalValue: "php", Field: "framework", Value: "php", Source: "builtin", Status: "active", Confidence: 0.9},
	{SignalType: "header", SignalKey: "x-powered-by", SignalValue: "asp.net", Field: "framework", Value: "aspnet", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "header", SignalKey: "x-powered-by", SignalValue: "express", Field: "framework", Value: "express", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "header", SignalKey: "x-powered-by", SignalValue: "next.js", Field: "framework", Value: "nextjs", Source: "builtin", Status: "active", Confidence: 1.0},

	// ── Framework detection (body patterns) ───────────────────────────────
	{SignalType: "body", SignalKey: "", SignalValue: "__next_data__", Field: "framework", Value: "nextjs", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "body", SignalKey: "", SignalValue: "__nuxt__", Field: "framework", Value: "nuxt", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "body", SignalKey: "", SignalValue: "__sveltekit", Field: "framework", Value: "sveltekit", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "body", SignalKey: "", SignalValue: "whitelabel error page", Field: "framework", Value: "spring-boot", Source: "builtin", Status: "active", Confidence: 0.95},
	{SignalType: "body", SignalKey: "", SignalValue: "x-application-context", Field: "framework", Value: "spring-boot", Source: "builtin", Status: "active", Confidence: 0.9},
	{SignalType: "body", SignalKey: "", SignalValue: "data-astro-", Field: "framework", Value: "astro", Source: "builtin", Status: "active", Confidence: 1.0},

	// ── Auth system (body patterns) ────────────────────────────────────────
	{SignalType: "body", SignalKey: "", SignalValue: "okta.com", Field: "auth_system", Value: "okta", Source: "builtin", Status: "active", Confidence: 0.9},
	{SignalType: "body", SignalKey: "", SignalValue: "auth0.com", Field: "auth_system", Value: "auth0", Source: "builtin", Status: "active", Confidence: 0.95},
	{SignalType: "body", SignalKey: "", SignalValue: "cognito", Field: "auth_system", Value: "cognito", Source: "builtin", Status: "active", Confidence: 0.85},
	{SignalType: "body", SignalKey: "", SignalValue: "window.ethereum", Field: "auth_system", Value: "web3_wallet", Source: "builtin", Status: "active", Confidence: 0.95},
	{SignalType: "body", SignalKey: "", SignalValue: "window.solana", Field: "auth_system", Value: "solana_wallet", Source: "builtin", Status: "active", Confidence: 0.95},

	// ── Auth system (path signals) ─────────────────────────────────────────
	{SignalType: "path", SignalKey: "", SignalValue: "/.well-known/openid-configuration", Field: "auth_system", Value: "oidc", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "path", SignalKey: "", SignalValue: "/auth/realms", Field: "auth_system", Value: "keycloak", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "path", SignalKey: "", SignalValue: "/saml", Field: "auth_system", Value: "saml", Source: "builtin", Status: "active", Confidence: 0.85},

	// ── Backend services (path signals) ───────────────────────────────────
	{SignalType: "path", SignalKey: "", SignalValue: "/actuator", Field: "backend_services", Value: "spring-boot", Source: "builtin", Status: "active", Confidence: 0.95},
	{SignalType: "path", SignalKey: "", SignalValue: "/v1/sys/health", Field: "backend_services", Value: "vault", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "path", SignalKey: "", SignalValue: "/_cat/indices", Field: "backend_services", Value: "elasticsearch", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "path", SignalKey: "", SignalValue: "/api/kernels", Field: "backend_services", Value: "jupyter", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "path", SignalKey: "", SignalValue: "/api/v1/dags", Field: "backend_services", Value: "airflow", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "path", SignalKey: "", SignalValue: "/v1/graphql", Field: "backend_services", Value: "hasura", Source: "builtin", Status: "active", Confidence: 0.9},
	{SignalType: "path", SignalKey: "", SignalValue: "/api/health", Field: "backend_services", Value: "grafana", Source: "builtin", Status: "active", Confidence: 0.8},

	// ── CNAME-based cloud detection ────────────────────────────────────────
	{SignalType: "cname", SignalKey: "", SignalValue: ".cloudfront.net", Field: "cloud_provider", Value: "aws", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "cname", SignalKey: "", SignalValue: ".azurefd.net", Field: "cloud_provider", Value: "azure", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "cname", SignalKey: "", SignalValue: ".fastly.net", Field: "proxy_type", Value: "fastly", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "cname", SignalKey: "", SignalValue: ".akamaiedge.net", Field: "proxy_type", Value: "akamai", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "cname", SignalKey: "", SignalValue: ".netlify.app", Field: "cloud_provider", Value: "netlify", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "cname", SignalKey: "", SignalValue: ".vercel.app", Field: "cloud_provider", Value: "vercel", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "cname", SignalKey: "", SignalValue: ".heroku.com", Field: "cloud_provider", Value: "heroku", Source: "builtin", Status: "active", Confidence: 1.0},

	// ── Cookie-based framework detection ──────────────────────────────────
	{SignalType: "cookie", SignalKey: "", SignalValue: "jsessionid", Field: "framework", Value: "java", Source: "builtin", Status: "active", Confidence: 0.9},
	{SignalType: "cookie", SignalKey: "", SignalValue: "phpsessid", Field: "framework", Value: "php", Source: "builtin", Status: "active", Confidence: 0.9},
	{SignalType: "cookie", SignalKey: "", SignalValue: "asp.net_sessionid", Field: "framework", Value: "aspnet", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "cookie", SignalKey: "", SignalValue: "laravel_session", Field: "framework", Value: "laravel", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "cookie", SignalKey: "", SignalValue: "django", Field: "framework", Value: "django", Source: "builtin", Status: "active", Confidence: 0.85},

	// ── Backend services — new Wave 2/3 services ───────────────────────────
	{SignalType: "header", SignalKey: "x-artifactory-id", SignalValue: "", Field: "backend_services", Value: "artifactory", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "path", SignalKey: "", SignalValue: "/artifactory/api/system/ping", Field: "backend_services", Value: "artifactory", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "path", SignalKey: "", SignalValue: "/service/rest/v1/status", Field: "backend_services", Value: "nexus", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "body", SignalKey: "", SignalValue: "nexus repository", Field: "backend_services", Value: "nexus", Source: "builtin", Status: "active", Confidence: 0.95},
	{SignalType: "path", SignalKey: "", SignalValue: "/nacos/v1/cs/configs", Field: "backend_services", Value: "nacos", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "body", SignalKey: "", SignalValue: "nacos server", Field: "backend_services", Value: "nacos", Source: "builtin", Status: "active", Confidence: 0.95},
	{SignalType: "path", SignalKey: "", SignalValue: "/v1/catalog/nodes", Field: "backend_services", Value: "consul", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "header", SignalKey: "x-consul-index", SignalValue: "", Field: "backend_services", Value: "consul", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "body", SignalKey: "", SignalValue: "\"grpc_server_reflection_version\"", Field: "backend_services", Value: "grpc", Source: "builtin", Status: "active", Confidence: 0.95},
	{SignalType: "header", SignalKey: "content-type", SignalValue: "application/grpc", Field: "backend_services", Value: "grpc", Source: "builtin", Status: "active", Confidence: 1.0},

	// ── Wireless management infrastructure ────────────────────────────────────
	{SignalType: "body", SignalKey: "", SignalValue: "unifi network", Field: "backend_services", Value: "unifi", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "body", SignalKey: "", SignalValue: "network.unifi", Field: "backend_services", Value: "unifi", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "path", SignalKey: "", SignalValue: "/manage/account/login", Field: "backend_services", Value: "unifi", Source: "builtin", Status: "active", Confidence: 0.95},
	{SignalType: "body", SignalKey: "", SignalValue: "omada controller", Field: "backend_services", Value: "omada", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "body", SignalKey: "", SignalValue: "aruba instant", Field: "backend_services", Value: "aruba-instant", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "body", SignalKey: "", SignalValue: "aruba networks", Field: "backend_services", Value: "aruba", Source: "builtin", Status: "active", Confidence: 0.9},
	{SignalType: "body", SignalKey: "", SignalValue: "luci", Field: "backend_services", Value: "openwrt", Source: "builtin", Status: "active", Confidence: 0.9},
	{SignalType: "body", SignalKey: "", SignalValue: "openwrt", Field: "backend_services", Value: "openwrt", Source: "builtin", Status: "active", Confidence: 1.0},

	// ── Framework detection — Python ──────────────────────────────────────────
	{SignalType: "header", SignalKey: "server", SignalValue: "werkzeug", Field: "framework", Value: "flask", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "header", SignalKey: "server", SignalValue: "uvicorn", Field: "framework", Value: "fastapi", Source: "builtin", Status: "active", Confidence: 0.9},
	{SignalType: "header", SignalKey: "server", SignalValue: "hypercorn", Field: "framework", Value: "fastapi", Source: "builtin", Status: "active", Confidence: 0.85},
	{SignalType: "header", SignalKey: "server", SignalValue: "daphne", Field: "framework", Value: "django", Source: "builtin", Status: "active", Confidence: 0.9},
	{SignalType: "header", SignalKey: "server", SignalValue: "gunicorn", Field: "framework", Value: "python", Source: "builtin", Status: "active", Confidence: 0.85},
	{SignalType: "path", SignalKey: "", SignalValue: "/docs", Field: "framework", Value: "fastapi", Source: "builtin", Status: "active", Confidence: 0.7},
	{SignalType: "path", SignalKey: "", SignalValue: "/redoc", Field: "framework", Value: "fastapi", Source: "builtin", Status: "active", Confidence: 0.7},

	// ── Framework detection — Go ──────────────────────────────────────────────
	{SignalType: "header", SignalKey: "x-powered-by", SignalValue: "gin", Field: "framework", Value: "gin", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "header", SignalKey: "x-powered-by", SignalValue: "fiber", Field: "framework", Value: "fiber", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "header", SignalKey: "x-powered-by", SignalValue: "echo", Field: "framework", Value: "echo", Source: "builtin", Status: "active", Confidence: 1.0},

	// ── Framework detection — Elixir/Erlang ──────────────────────────────────
	{SignalType: "header", SignalKey: "server", SignalValue: "cowboy", Field: "framework", Value: "phoenix", Source: "builtin", Status: "active", Confidence: 0.85},
	{SignalType: "cookie", SignalKey: "", SignalValue: "_phoenix_flash", Field: "framework", Value: "phoenix", Source: "builtin", Status: "active", Confidence: 1.0},

	// ── Enterprise private cloud — OpenStack ──────────────────────────────────
	{SignalType: "path", SignalKey: "", SignalValue: "/identity/v3", Field: "backend_services", Value: "openstack-keystone", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "path", SignalKey: "", SignalValue: "/v2.0/tokens", Field: "backend_services", Value: "openstack-keystone", Source: "builtin", Status: "active", Confidence: 0.9},
	{SignalType: "body", SignalKey: "", SignalValue: "openstack dashboard", Field: "backend_services", Value: "openstack-horizon", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "body", SignalKey: "", SignalValue: "powered by openstack", Field: "backend_services", Value: "openstack", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "header", SignalKey: "x-openstack-request-id", SignalValue: "", Field: "backend_services", Value: "openstack", Source: "builtin", Status: "active", Confidence: 1.0},

	// ── Enterprise private cloud — Proxmox ────────────────────────────────────
	{SignalType: "body", SignalKey: "", SignalValue: "proxmox virtual environment", Field: "backend_services", Value: "proxmox", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "path", SignalKey: "", SignalValue: "/api2/json", Field: "backend_services", Value: "proxmox", Source: "builtin", Status: "active", Confidence: 0.95},
	{SignalType: "body", SignalKey: "", SignalValue: "pvemanagerversion", Field: "backend_services", Value: "proxmox", Source: "builtin", Status: "active", Confidence: 1.0},

	// ── Enterprise private cloud — CloudStack ─────────────────────────────────
	{SignalType: "path", SignalKey: "", SignalValue: "/client/api", Field: "backend_services", Value: "cloudstack", Source: "builtin", Status: "active", Confidence: 0.95},
	{SignalType: "body", SignalKey: "", SignalValue: "cloudstack", Field: "backend_services", Value: "cloudstack", Source: "builtin", Status: "active", Confidence: 0.85},

	// ── Red Hat — OpenShift ───────────────────────────────────────────────────
	{SignalType: "header", SignalKey: "x-openshift-token", SignalValue: "", Field: "backend_services", Value: "openshift", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "body", SignalKey: "", SignalValue: "openshift web console", Field: "backend_services", Value: "openshift", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "path", SignalKey: "", SignalValue: "/apis/apps.openshift.io", Field: "backend_services", Value: "openshift", Source: "builtin", Status: "active", Confidence: 1.0},

	// ── Red Hat — Ansible/AWX ─────────────────────────────────────────────────
	{SignalType: "path", SignalKey: "", SignalValue: "/api/v2/ping", Field: "backend_services", Value: "ansible-awx", Source: "builtin", Status: "active", Confidence: 0.9},
	{SignalType: "body", SignalKey: "", SignalValue: "ansible tower", Field: "backend_services", Value: "ansible-awx", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "body", SignalKey: "", SignalValue: "awx", Field: "backend_services", Value: "ansible-awx", Source: "builtin", Status: "active", Confidence: 0.8},

	// ── Monitoring — Jaeger ───────────────────────────────────────────────────
	{SignalType: "path", SignalKey: "", SignalValue: "/api/traces", Field: "backend_services", Value: "jaeger", Source: "builtin", Status: "active", Confidence: 0.9},
	{SignalType: "path", SignalKey: "", SignalValue: "/api/services", Field: "backend_services", Value: "jaeger", Source: "builtin", Status: "active", Confidence: 0.85},
	{SignalType: "body", SignalKey: "", SignalValue: "jaeger ui", Field: "backend_services", Value: "jaeger", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "body", SignalKey: "", SignalValue: "jaeger-ui", Field: "backend_services", Value: "jaeger", Source: "builtin", Status: "active", Confidence: 1.0},

	// ── Monitoring — Zipkin ───────────────────────────────────────────────────
	{SignalType: "path", SignalKey: "", SignalValue: "/api/v2/traces", Field: "backend_services", Value: "zipkin", Source: "builtin", Status: "active", Confidence: 0.9},
	{SignalType: "body", SignalKey: "", SignalValue: "zipkin", Field: "backend_services", Value: "zipkin", Source: "builtin", Status: "active", Confidence: 0.8},

	// ── Monitoring — Grafana Loki ─────────────────────────────────────────────
	{SignalType: "path", SignalKey: "", SignalValue: "/loki/api/v1/labels", Field: "backend_services", Value: "loki", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "path", SignalKey: "", SignalValue: "/loki/api/v1/query", Field: "backend_services", Value: "loki", Source: "builtin", Status: "active", Confidence: 1.0},

	// ── Monitoring — Grafana Tempo ────────────────────────────────────────────
	{SignalType: "path", SignalKey: "", SignalValue: "/api/traces", Field: "backend_services", Value: "tempo", Source: "builtin", Status: "active", Confidence: 0.8},
	{SignalType: "path", SignalKey: "", SignalValue: "/tempo/api/traces", Field: "backend_services", Value: "tempo", Source: "builtin", Status: "active", Confidence: 1.0},

	// ── Monitoring — VictoriaMetrics ──────────────────────────────────────────
	{SignalType: "path", SignalKey: "", SignalValue: "/vmui", Field: "backend_services", Value: "victoriametrics", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "body", SignalKey: "", SignalValue: "victoriametrics", Field: "backend_services", Value: "victoriametrics", Source: "builtin", Status: "active", Confidence: 1.0},

	// ── Monitoring — Nagios ───────────────────────────────────────────────────
	{SignalType: "path", SignalKey: "", SignalValue: "/nagios/", Field: "backend_services", Value: "nagios", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "body", SignalKey: "", SignalValue: "nagios core", Field: "backend_services", Value: "nagios", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "body", SignalKey: "", SignalValue: "nagios xi", Field: "backend_services", Value: "nagios", Source: "builtin", Status: "active", Confidence: 1.0},

	// ── Container registries — Harbor ─────────────────────────────────────────
	{SignalType: "path", SignalKey: "", SignalValue: "/api/v2.0/systeminfo", Field: "backend_services", Value: "harbor", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "body", SignalKey: "", SignalValue: "harbor", Field: "backend_services", Value: "harbor", Source: "builtin", Status: "active", Confidence: 0.75},
	{SignalType: "header", SignalKey: "x-harbor-csrf-token", SignalValue: "", Field: "backend_services", Value: "harbor", Source: "builtin", Status: "active", Confidence: 1.0},

	// ── Container registries — Quay ───────────────────────────────────────────
	{SignalType: "path", SignalKey: "", SignalValue: "/api/v1/discovery", Field: "backend_services", Value: "quay", Source: "builtin", Status: "active", Confidence: 0.9},
	{SignalType: "body", SignalKey: "", SignalValue: "quay.io", Field: "backend_services", Value: "quay", Source: "builtin", Status: "active", Confidence: 0.9},

	// ── CI/CD — ArgoCD ────────────────────────────────────────────────────────
	{SignalType: "path", SignalKey: "", SignalValue: "/api/v1/applications", Field: "backend_services", Value: "argocd", Source: "builtin", Status: "active", Confidence: 0.9},
	{SignalType: "body", SignalKey: "", SignalValue: "argo cd", Field: "backend_services", Value: "argocd", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "body", SignalKey: "", SignalValue: "argocd", Field: "backend_services", Value: "argocd", Source: "builtin", Status: "active", Confidence: 0.9},

	// ── CI/CD — TeamCity ──────────────────────────────────────────────────────
	{SignalType: "path", SignalKey: "", SignalValue: "/app/rest/server", Field: "backend_services", Value: "teamcity", Source: "builtin", Status: "active", Confidence: 0.95},
	{SignalType: "body", SignalKey: "", SignalValue: "teamcity", Field: "backend_services", Value: "teamcity", Source: "builtin", Status: "active", Confidence: 0.85},

	// ── CI/CD — Drone CI ──────────────────────────────────────────────────────
	{SignalType: "path", SignalKey: "", SignalValue: "/api/user", Field: "backend_services", Value: "drone", Source: "builtin", Status: "active", Confidence: 0.6},
	{SignalType: "body", SignalKey: "", SignalValue: "drone", Field: "backend_services", Value: "drone", Source: "builtin", Status: "active", Confidence: 0.7},

	// ── Databases — CouchDB ───────────────────────────────────────────────────
	{SignalType: "header", SignalKey: "server", SignalValue: "couchdb", Field: "backend_services", Value: "couchdb", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "path", SignalKey: "", SignalValue: "/_utils", Field: "backend_services", Value: "couchdb", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "body", SignalKey: "", SignalValue: "\"couchdb\"", Field: "backend_services", Value: "couchdb", Source: "builtin", Status: "active", Confidence: 0.95},

	// ── Databases — Neo4j ─────────────────────────────────────────────────────
	{SignalType: "path", SignalKey: "", SignalValue: "/db/neo4j/tx", Field: "backend_services", Value: "neo4j", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "body", SignalKey: "", SignalValue: "neo4j browser", Field: "backend_services", Value: "neo4j", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "body", SignalKey: "", SignalValue: "neo4j_version", Field: "backend_services", Value: "neo4j", Source: "builtin", Status: "active", Confidence: 1.0},

	// ── Databases — RabbitMQ management UI ────────────────────────────────────
	{SignalType: "path", SignalKey: "", SignalValue: "/api/overview", Field: "backend_services", Value: "rabbitmq", Source: "builtin", Status: "active", Confidence: 0.8},
	{SignalType: "body", SignalKey: "", SignalValue: "rabbitmq management", Field: "backend_services", Value: "rabbitmq", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "body", SignalKey: "", SignalValue: "rabbitmq_version", Field: "backend_services", Value: "rabbitmq", Source: "builtin", Status: "active", Confidence: 1.0},

	// ── Databases — MinIO ─────────────────────────────────────────────────────
	{SignalType: "header", SignalKey: "server", SignalValue: "minio", Field: "backend_services", Value: "minio", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "path", SignalKey: "", SignalValue: "/minio/health/live", Field: "backend_services", Value: "minio", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "header", SignalKey: "x-minio-deployment-id", SignalValue: "", Field: "backend_services", Value: "minio", Source: "builtin", Status: "active", Confidence: 1.0},

	// ── Databases — MongoDB Express ───────────────────────────────────────────
	{SignalType: "body", SignalKey: "", SignalValue: "mongo express", Field: "backend_services", Value: "mongo-express", Source: "builtin", Status: "active", Confidence: 1.0},

	// ── Web3 — Ethereum nodes (Geth/Nethermind/Besu) ──────────────────────────
	{SignalType: "header", SignalKey: "content-type", SignalValue: "application/json", Field: "backend_services", Value: "ethereum-rpc", Source: "builtin", Status: "active", Confidence: 0.3},
	{SignalType: "body", SignalKey: "", SignalValue: "\"jsonrpc\"", Field: "backend_services", Value: "jsonrpc", Source: "builtin", Status: "active", Confidence: 0.7},

	// ── Web3 — IPFS gateway ───────────────────────────────────────────────────
	{SignalType: "header", SignalKey: "x-ipfs-path", SignalValue: "", Field: "backend_services", Value: "ipfs", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "header", SignalKey: "x-ipfs-gateway", SignalValue: "", Field: "backend_services", Value: "ipfs", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "path", SignalKey: "", SignalValue: "/api/v0/id", Field: "backend_services", Value: "ipfs", Source: "builtin", Status: "active", Confidence: 1.0},

	// ── Cloud providers — DigitalOcean ────────────────────────────────────────
	{SignalType: "cname", SignalKey: "", SignalValue: ".digitaloceanspaces.com", Field: "cloud_provider", Value: "digitalocean", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "cname", SignalKey: "", SignalValue: ".ondigitalocean.app", Field: "cloud_provider", Value: "digitalocean", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "header", SignalKey: "x-do-app-origin", SignalValue: "", Field: "cloud_provider", Value: "digitalocean", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "header", SignalKey: "x-do-orig-status", SignalValue: "", Field: "cloud_provider", Value: "digitalocean", Source: "builtin", Status: "active", Confidence: 1.0},

	// ── Cloud providers — Hetzner ─────────────────────────────────────────────
	{SignalType: "cname", SignalKey: "", SignalValue: ".hetzner.cloud", Field: "cloud_provider", Value: "hetzner", Source: "builtin", Status: "active", Confidence: 1.0},

	// ── Cloud providers — Linode/Akamai Connected Cloud ───────────────────────
	{SignalType: "cname", SignalKey: "", SignalValue: ".linodeobjects.com", Field: "cloud_provider", Value: "linode", Source: "builtin", Status: "active", Confidence: 1.0},

	// ── Cloud providers — Render ──────────────────────────────────────────────
	{SignalType: "cname", SignalKey: "", SignalValue: ".onrender.com", Field: "cloud_provider", Value: "render", Source: "builtin", Status: "active", Confidence: 1.0},

	// ── Cloud providers — Railway ─────────────────────────────────────────────
	{SignalType: "cname", SignalKey: "", SignalValue: ".railway.app", Field: "cloud_provider", Value: "railway", Source: "builtin", Status: "active", Confidence: 1.0},

	// ── Cloud providers — Fly.io ──────────────────────────────────────────────
	{SignalType: "header", SignalKey: "fly-request-id", SignalValue: "", Field: "cloud_provider", Value: "fly", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "cname", SignalKey: "", SignalValue: ".fly.dev", Field: "cloud_provider", Value: "fly", Source: "builtin", Status: "active", Confidence: 1.0},

	// ── Strapi CMS ────────────────────────────────────────────────────────────
	{SignalType: "header", SignalKey: "x-powered-by", SignalValue: "strapi", Field: "backend_services", Value: "strapi", Source: "builtin", Status: "active", Confidence: 1.0},

	// ── Mattermost ────────────────────────────────────────────────────────────
	{SignalType: "header", SignalKey: "x-version-id", SignalValue: "", Field: "backend_services", Value: "mattermost", Source: "builtin", Status: "active", Confidence: 0.7},
	{SignalType: "body", SignalKey: "", SignalValue: "mattermost", Field: "backend_services", Value: "mattermost", Source: "builtin", Status: "active", Confidence: 0.85},

	// ── SonarQube ─────────────────────────────────────────────────────────────
	{SignalType: "path", SignalKey: "", SignalValue: "/api/system/status", Field: "backend_services", Value: "sonarqube", Source: "builtin", Status: "active", Confidence: 0.9},
	{SignalType: "body", SignalKey: "", SignalValue: "sonarqube", Field: "backend_services", Value: "sonarqube", Source: "builtin", Status: "active", Confidence: 0.9},

	// ── Sentry self-hosted ────────────────────────────────────────────────────
	{SignalType: "path", SignalKey: "", SignalValue: "/api/0/internal/health", Field: "backend_services", Value: "sentry", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "body", SignalKey: "", SignalValue: "sentry_dsn", Field: "backend_services", Value: "sentry", Source: "builtin", Status: "active", Confidence: 0.9},

	// ── GitLab Runner ─────────────────────────────────────────────────────────
	{SignalType: "path", SignalKey: "", SignalValue: "/api/v4/runners", Field: "backend_services", Value: "gitlab", Source: "builtin", Status: "active", Confidence: 0.9},
}
