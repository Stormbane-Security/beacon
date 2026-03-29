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
	ASNOrg string // e.g. "CLOUDFLARENET", "AMAZON-02"
	ASNNum string // e.g. "AS13335"

	// DNS
	Hostname    string
	CNAMEChain  []string // all CNAMEs in resolution chain
	DNSSuffix   string   // last part of hostname, e.g. ".cloudfront.net"

	// HTTP
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
}
