package playbook

// CloudContext holds metadata from an authenticated cloud scan that was
// cross-referenced to this asset by IP match. Populated by the multi-module
// scan pipeline after the cloud module runs.
type CloudContext struct {
	Provider       string            `json:"provider"`                  // "gcp", "aws", "azure"
	InstanceID     string            `json:"instance_id"`               // GCP: instance name; AWS: i-xxxx; Azure: VM name
	ResourceType   string            `json:"resource_type"`             // "compute_instance", "gke_cluster", "eks_cluster", "sql_instance", etc.
	Project        string            `json:"project"`                   // GCP: project ID; AWS: account ID; Azure: subscription ID
	Region         string            `json:"region"`                    // e.g. "us-central1", "us-east-1"
	Zone           string            `json:"zone,omitempty"`            // GCP zone (e.g. "us-central1-a")
	Tags           map[string]string `json:"tags,omitempty"`            // GCP labels / AWS tags / Azure tags
	IAMRoles       []string          `json:"iam_roles,omitempty"`       // IAM roles/permissions attached to this resource
	ContainerImage string            `json:"container_image,omitempty"` // running container image:tag if applicable
	ResourceSnapshot string          `json:"resource_snapshot,omitempty"` // full JSON of cloud resource (for Bosun IaC generation)
}

// Evidence is the set of observable facts collected about a single asset
// before playbook matching. Collected by internal/scanner/classify.
type Evidence struct {
	// Network
	IP     string
	IPv6   string // AAAA record address (e.g. "2606:4700::6810:84e5"), empty if no AAAA
	ASNOrg string // e.g. "CLOUDFLARENET", "AMAZON-02"
	ASNNum string // e.g. "AS13335"

	// DNS
	Hostname    string
	CNAMEChain  []string // all CNAMEs in resolution chain
	DNSSuffix   string   // last part of hostname, e.g. ".cloudfront.net"

	// HTTP
	Scheme     string            // "https" or "http" — whichever succeeded during classify probe
	Headers   map[string]string // lower-case header names → values
	Title     string            // <title> content
	Body512   string            // first 512 bytes of response body (for quick pattern match)
	StatusCode int

	// TLS
	CertSANs   []string // Subject Alternative Names from TLS cert
	CertIssuer string

	// Paths that returned non-404 (checked during evidence collection)
	RespondingPaths []string

	// RobotsTxtPaths holds Disallow entries from /robots.txt.
	// These often reveal hidden admin paths, API routes, and internal tooling.
	// In deep mode they are unioned into the dirbust path list.
	RobotsTxtPaths []string

	// FaviconHash is an FNV-1a hash of the base64-encoded /favicon.ico bytes.
	// Identical hashes across assets indicate the same software/product,
	// enabling asset correlation and technology identification.
	FaviconHash string

	// ServiceVersions holds extracted software/version strings keyed by role.
	// Populated from HTTP headers (Server, X-Powered-By, X-AspNet-Version, etc.)
	// and TCP service banners (SSH, FTP). Used for version-aware playbook matching
	// and to give the enricher concrete version context.
	//
	// Example keys: "web_server", "powered_by", "aspnet_version", "ssh_software", "ftp_software"
	ServiceVersions map[string]string

	// DNS Intelligence — collected passively via classify.Collect().
	// These feed into playbook matching and give the AI enricher full DNS context.
	TXTRecords []string // all TXT records for the domain apex (raw values)
	NSRecords  []string // authoritative nameservers from NS query
	SOARecord  string   // SOA MNAME — primary authoritative nameserver
	SPFIPs     []string // ip4:/ip6: CIDR blocks authorized directly in the SPF record

	// JARMFingerprint is a TLS server fingerprint computed from multiple custom
	// ClientHello probes sent to the asset's HTTPS port. Different TLS implementations
	// (nginx, Apache, IIS, CDN edges, etc.) produce distinct fingerprints, enabling
	// server identification even when version banners are stripped.
	// Returns "" when the asset has no TLS or the connection consistently fails.
	JARMFingerprint string

	// WAF / IDS — populated from wafdetect Phase A findings.
	// Gives playbooks and the AI enricher concrete WAF context.
	WAFVendor string // detected WAF vendor: "Cloudflare", "AWS WAF", "Imperva Incapsula", ""
	IDSVendor string // detected IDS/NGFW vendor: "Palo Alto NGFW", "Check Point", ""

	// AI / LLM signals — populated by the aidetect scanner.
	// Used to trigger the ai_llm playbook and to guide the aillm active scanner.
	AIEndpoints []string // paths confirmed to accept LLM/chat requests
	LLMProvider string   // detected provider: "openai", "anthropic", "workers_ai", "generic"
	HasAISSE    bool     // server-sent event streaming (typical of LLM token streaming)
	HasAgentTools bool   // tool-use / function-calling patterns detected in responses

	// Technology fingerprinting — populated by classify scanner.
	// Used for playbook matching and AI enrichment context.
	CloudProvider  string   // "aws", "azure", "gcp", "cloudflare", "vercel", "heroku", "netlify", ""
	ProxyType      string   // vendor/product: "envoy", "nginx", "traefik", "kong", "haproxy", "caddy", "varnish", "squid", "ats", "akamai", "fastly", "aws_api_gateway", "azure_apim", "apigee", "linkerd", "f5", "citrix", ...
	InfraLayer     string   // role of the infrastructure layer: "cdn_edge", "api_gateway", "load_balancer", "service_mesh", "reverse_proxy"
	Framework      string   // "nextjs", "nuxt", "sveltekit", "rails", "django", "spring", "laravel", "express", ""
	AuthSystem     string   // "okta", "auth0", "keycloak", "cognito", "saml", "ldap", ""
	CookieNames    []string // session cookie names (fingerprint without values, e.g. ["JSESSIONID", "PHPSESSID"])
	IsServerless   bool     // true when Lambda/Vercel/Netlify/CF Workers signals detected
	IsKubernetes   bool     // true when k8s API server or k8s ingress signals detected
	IsReverseProxy bool     // true when proxy/gateway layer detected in front of app

	// Web3 signals — populated by classify and web3detect scanners.
	Web3Signals       []string // ["ethers.js", "wagmi", "window.ethereum", "infura_rpc"]
	ContractAddresses []string // EVM addresses found in page source/JS (0x... format, validated length)

	// Extended HTTP signals — populated by classify scanner.
	AuthScheme   string   // auth scheme from WWW-Authenticate: "basic", "bearer", "negotiate", "ntlm", "digest", "aws"
	HTTP2Enabled bool     // server negotiated HTTP/2
	VendorSignals []string // third-party vendors from CSP + <script src>: ["stripe","sentry","newrelic"]

	// Extended DNS signals — populated by classify scanner.
	MXRecords  []string // mail exchanger hostnames (raw, e.g. "aspmx.l.google.com")
	MXProvider string   // inferred email provider: "google", "microsoft", "proofpoint", "mimecast", "mailgun", ""
	AAAARecords []string // IPv6 addresses resolved for this hostname
	HasDMARC   bool     // _dmarc TXT record exists
	DMARCPolicy string  // DMARC p= tag value: "none", "quarantine", "reject", ""

	// SRVRecords holds service discovery results from DNS SRV lookups.
	// Keys are the query name (e.g. "_sip._tcp", "_ldap._tcp"), values are
	// "host:port" strings. Reveals internal services like AD, XMPP, SIP, Exchange.
	SRVRecords map[string][]string

	// FaviconProduct is the product name identified by matching the FaviconHash
	// against a known hash database (e.g. "Grafana", "Jenkins", "Kibana").
	// Empty when the hash is unknown or no favicon was fetched.
	FaviconProduct string

	// Discovery hints — subdomains of the root domain found in the page source.
	// Populated by classify scanner using the full 8KB response body.
	// Used by the surface module to queue new assets missed by passive enumeration.
	SubdomainsInBody []string

	// SoftNotFound indicates the asset returns HTTP 200 for nonexistent paths
	// (catch-all / SPA pattern). When true, path-based findings must rely on
	// body content matching rather than status code alone.
	SoftNotFound bool
	// SoftNotFoundHash is the SHA-256 hash of the canary-path response body,
	// used to detect when a probed path returns the same content as the catch-all.
	SoftNotFoundHash [32]byte

	// BackendServices is a deduplicated list of named backend services inferred
	// from RespondingPaths. Populated by classify after path probing completes.
	// Examples: "Spring Boot", "HashiCorp Vault", "Keycloak", "Elasticsearch".
	// Used by topology rendering and the AI analysis prompt for richer context.
	BackendServices []string

	// PhaseACheckIDs holds check IDs from Phase A scanner findings (wafdetect,
	// portscan, aidetect). Populated by the surface module after Phase A completes
	// and before the second playbook-matching pass. Enables playbooks to match on
	// SSH-banner detections and port discoveries (e.g. "netdev.mikrotik_detected",
	// "port.checkpoint_topology") that the classify scanner cannot observe.
	PhaseACheckIDs []string

	// ClassificationSource records how the tech-stack classification was determined.
	// "" = fully deterministic rules; "ai:high" / "ai:medium" / "ai:low" = AI-inferred
	// at the named confidence tier. Displayed in the TUI with an [AI] badge and
	// carried into findings so analysts know which were AI-guided.
	ClassificationSource string

	// OSVersion is the detected operating system and version.
	// Examples: "Ubuntu 22.04", "Amazon Linux 2", "Windows Server 2022"
	// Populated from SSH banners, cloud instance metadata, or Shodan data.
	OSVersion string

	// RuntimeVersion is the detected application runtime and version.
	// Examples: "Node.js 18.12.0", "Python 3.11.2", "Java 17.0.5"
	// Populated from HTTP headers (X-Powered-By), error pages, or cloud metadata.
	RuntimeVersion string

	// CloudCtx is injected after the cloud module runs and cross-references
	// this asset's IP against cloud instance IPs. Nil when no cross-reference
	// was found or when no cloud scan was performed.
	CloudCtx *CloudContext

	// ── Advanced fingerprinting signals ─────────────────────────────────────

	// HeaderOrder records the order in which the server returns HTTP response
	// headers. Different server implementations (nginx, Apache, IIS, Caddy, etc.)
	// return headers in characteristic orders, enabling identification even when
	// Server headers are stripped. Only the first 20 header names are stored.
	HeaderOrder []string

	// HTTPMethods maps HTTP method names to the status codes returned when that
	// method is sent to the root path. Different servers respond differently to
	// OPTIONS, TRACE, DELETE, etc., creating a behavioral fingerprint.
	HTTPMethods map[string]int

	// ErrorPageSignature is a technology hint derived from the default error page
	// (404 response body). Different frameworks produce distinctive error pages
	// that reveal server identity even without Server/X-Powered-By headers.
	ErrorPageSignature string

	// SecurityTxtPresent indicates /.well-known/security.txt was found.
	// SecurityTxtContact holds the extracted Contact: field if present.
	SecurityTxtPresent bool
	SecurityTxtContact string

	// VCSExposed records which version control system is exposed, if any.
	// Values: "git", "svn", "hg", "bzr", "" (empty = none detected).
	// A non-empty value means the VCS metadata directory is web-accessible.
	VCSExposed string

	// SourceMapsExposed is true when JavaScript source maps (.map files) are
	// accessible, potentially revealing unminified source code and internal paths.
	SourceMapsExposed bool

	// WellKnownPaths tracks .well-known URIs that responded successfully.
	// Keys are the path (e.g. "security.txt", "change-password"), values are
	// brief content summaries or "present".
	WellKnownPaths map[string]string

	// SitemapURLs holds URLs extracted from /sitemap.xml. These often reveal
	// application structure, API endpoints, and content hierarchies that
	// passive crawling misses.
	SitemapURLs []string

	// DNSProvider is the hosting provider inferred from NS records.
	// Values: "cloudflare", "aws_route53", "gcp_cloud_dns", "azure_dns",
	// "godaddy", "namecheap", "dnsimple", "ns1", "cloudns", "hetzner", ""
	DNSProvider string

	// CAARecords holds Certification Authority Authorization DNS records.
	// These specify which CAs are allowed to issue certificates for the domain.
	CAARecords []string

	// CHAOSVersion is the DNS server software version from CHAOS TXT query
	// for version.bind. Reveals BIND version, PowerDNS, etc.
	CHAOSVersion string

	// GRPCReflection is true when gRPC server reflection is enabled,
	// allowing enumeration of all available services and methods.
	GRPCReflection bool

	// WebSocketEndpoints lists paths where WebSocket upgrade was accepted.
	WebSocketEndpoints []string

	// ExternalServices lists named external API/SaaS dependencies discovered
	// in JavaScript bundles (e.g. "Stripe API", "Helius RPC (Solana)", "Auth0").
	// Populated by the webcontent scanner via enrichEvidenceFromFindings.
	// Other scanners can use this to target service-specific attack patterns.
	ExternalServices []string

	// ── Attack-path context for Forecast convergence ────────────────────────

	// PortServices is a structured per-port service fingerprint aggregated from
	// portscan findings. Forecast uses this to build the service graph, match
	// CVEs by exact product+version, and model lateral movement paths.
	// Populated by the surface module after portscan completes.
	PortServices map[int]PortServiceInfo

	// ContainerInfo holds container runtime metadata when the asset is running
	// inside a container. Enables Forecast to trace from running service →
	// container image → registry → source repo → CI/CD pipeline.
	ContainerInfo *ContainerInfo

	// CICDSignals lists CI/CD system indicators found in HTTP responses,
	// headers, or exposed config. Forecast uses these to map deployment
	// pipelines and trace code-to-infrastructure paths.
	// Examples: "jenkins", "github_actions", "gitlab_ci", "argocd", "tekton"
	CICDSignals []string

	// DeploymentContext describes the orchestration/deployment environment.
	// Populated from cloud metadata, K8s API responses, or Docker API headers.
	DeploymentContext *DeploymentContext

	// DataStoreConnections lists backend data stores this asset connects to,
	// discovered via environment variables, config files, or API responses.
	// Forecast uses these to model data-flow paths and blast radius.
	DataStoreConnections []DataStoreConnection

	// CredentialExposures summarizes types of credential exposure found on this
	// asset (not the credential values themselves). Forecast uses these to model
	// which other assets/services become reachable through credential reuse.
	CredentialExposures []CredentialExposure

	// NetworkAdjacency lists other hosts/services reachable from this asset,
	// discovered via container network inspection, ARP tables, route tables,
	// or service mesh config. Forecast uses this for lateral movement modeling.
	NetworkAdjacency []NetworkAdjacent

	// ExposedAPISchemas lists API schema endpoints found (OpenAPI/Swagger,
	// GraphQL introspection, gRPC reflection). These reveal the full API
	// surface and enable Forecast to generate targeted exploit payloads.
	ExposedAPISchemas []APISchemaInfo
}

// PortServiceInfo is a structured fingerprint for a single port's service.
type PortServiceInfo struct {
	Service    string `json:"service"`              // canonical service name: "redis", "nginx", "postgresql"
	Product    string `json:"product,omitempty"`     // product banner: "nginx/1.14.2", "Redis server v=7.4.1"
	Version    string `json:"version,omitempty"`     // extracted version: "1.14.2", "7.4.1"
	OSHint     string `json:"os_hint,omitempty"`     // OS hint from banner: "Ubuntu", "Alpine", "Debian"
	AuthStatus string `json:"auth_status,omitempty"` // "no_auth", "default_creds", "auth_required", "auth_bypass"
	TLS        bool   `json:"tls,omitempty"`         // true if TLS is negotiated on this port
	Protocol   string `json:"protocol,omitempty"`    // "tcp" or "udp"
	Banner     string `json:"banner,omitempty"`      // raw banner (truncated to 256 bytes)
	CVEs       []string `json:"cves,omitempty"`      // known CVEs for this exact product+version
}

// ContainerInfo holds container runtime metadata.
type ContainerInfo struct {
	Runtime  string `json:"runtime"`            // "docker", "containerd", "podman", "cri-o"
	ImageRef string `json:"image_ref,omitempty"` // image reference: "nginx:1.14.2-alpine", "redis:7-alpine"
	ImageID  string `json:"image_id,omitempty"`  // image digest if available
	Labels   map[string]string `json:"labels,omitempty"` // container labels / k8s annotations
}

// DeploymentContext describes the deployment/orchestration environment.
type DeploymentContext struct {
	Platform   string `json:"platform"`              // "kubernetes", "docker_compose", "ecs", "lambda", "bare_metal"
	Namespace  string `json:"namespace,omitempty"`    // k8s namespace
	Cluster    string `json:"cluster,omitempty"`      // k8s/ECS cluster name
	Network    string `json:"network,omitempty"`      // Docker network name, VPC ID
	ServiceMesh string `json:"service_mesh,omitempty"` // "istio", "linkerd", "consul_connect"
}

// DataStoreConnection represents a backend data store this asset connects to.
type DataStoreConnection struct {
	Type     string `json:"type"`               // "postgresql", "mysql", "redis", "mongodb", "s3", "dynamodb"
	Host     string `json:"host,omitempty"`     // host:port if discovered
	Database string `json:"database,omitempty"` // database/bucket name if known
	Source   string `json:"source"`             // how discovered: "env_var", "config_file", "api_response"
}

// CredentialExposure describes a type of credential exposure without the value.
type CredentialExposure struct {
	Type      string `json:"type"`                // "no_auth", "default_creds", "hardcoded_key", "env_leak"
	Service   string `json:"service"`             // which service: "redis", "tomcat", "aws_s3"
	GrantsAccessTo string `json:"grants_access_to,omitempty"` // what this credential unlocks: "redis://internal:6379"
}

// NetworkAdjacent represents a host/service reachable from this asset.
type NetworkAdjacent struct {
	Host       string `json:"host"`
	Port       int    `json:"port,omitempty"`
	Service    string `json:"service,omitempty"`
	Discovered string `json:"discovered"` // how: "arp_table", "docker_network", "k8s_api", "route_table", "dns_ptr"
}

// APISchemaInfo describes an exposed API schema endpoint.
type APISchemaInfo struct {
	Type     string `json:"type"`     // "openapi", "swagger", "graphql", "grpc_reflection", "wsdl"
	Path     string `json:"path"`     // URL path where schema was found
	Version  string `json:"version,omitempty"` // API version if extractable
}
