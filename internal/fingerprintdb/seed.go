package fingerprintdb

import "github.com/stormbane/beacon/internal/store"

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
}
