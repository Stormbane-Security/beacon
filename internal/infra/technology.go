package infra

// Technology is a canonical identifier for any piece of infrastructure.
// Format: lowercase, hyphen-separated (e.g., "cloud-run", "next-js").
// These are stable identifiers — once assigned, they never change.
type Technology string

// Category classifies a Technology into its functional role.
type Category string

const (
	CategoryPlatform   Category = "platform"   // where workloads run
	CategoryServer     Category = "server"      // HTTP servers, reverse proxies, load balancers
	CategoryFramework  Category = "framework"   // application frameworks
	CategoryDatabase   Category = "database"    // data stores (SQL, NoSQL, cache, search)
	CategoryAuth       Category = "auth"        // authentication and identity systems
	CategoryCloud      Category = "cloud"       // cloud providers
	CategoryCICD       Category = "cicd"        // CI/CD platforms and runners
	CategoryMessaging  Category = "messaging"   // message brokers and event streaming
	CategoryMonitoring Category = "monitoring"  // observability, logging, alerting
	CategoryCDN        Category = "cdn"         // content delivery networks
	CategoryRuntime    Category = "runtime"     // language runtimes (PHP, Node, Python, Java)
	CategoryContainer  Category = "container"   // container runtimes and orchestrators
	CategoryWeb3       Category = "web3"        // blockchain, wallets, DeFi
	CategorySecurity   Category = "security"    // security tools (WAF, IDS, vault)
	CategoryGateway    Category = "gateway"     // API gateways
)

// InfraLayer describes the network-layer role of a technology.
type InfraLayer string

const (
	LayerCDNEdge      InfraLayer = "cdn_edge"
	LayerAPIGateway   InfraLayer = "api_gateway"
	LayerLoadBalancer InfraLayer = "load_balancer"
	LayerServiceMesh  InfraLayer = "service_mesh"
	LayerReverseProxy InfraLayer = "reverse_proxy"
	LayerOrigin       InfraLayer = "origin"
)

// TechMeta holds metadata about a technology. This is the central
// registry entry — everything Beacon and Drydock need to know about
// a technology in one place.
type TechMeta struct {
	// ID is the canonical identifier (e.g., "nginx", "next-js", "gke").
	ID Technology

	// Name is the human-readable display name (e.g., "NGINX", "Next.js", "GKE").
	Name string

	// Category is the primary functional classification.
	Category Category

	// Layer is the infrastructure layer (only set for server/proxy/CDN types).
	Layer InfraLayer

	// Vendor is the company or project that maintains this technology.
	Vendor string

	// CloudProvider is set when this technology is specific to a cloud provider.
	// Empty for cloud-agnostic technologies.
	CloudProvider Technology

	// OpenSource indicates whether this is an open-source project.
	OpenSource bool

	// DefaultPorts lists the TCP ports this technology typically listens on.
	DefaultPorts []int

	// DockerImage is the canonical container image (e.g., "nginx:latest").
	// Used by Drydock for container-based scenarios.
	DockerImage string

	// HelmChart is the canonical Helm chart reference (e.g., "bitnami/nginx").
	// Used by Drydock for Kubernetes-based scenarios.
	HelmChart string

	// Aliases are alternative names that map to this technology
	// (e.g., "node" → "nodejs", "pg" → "postgresql").
	Aliases []string

	// Tags are free-form labels for filtering (e.g., "managed", "serverless", "oss").
	Tags []string
}

// Registry is the global technology catalog. All technologies known to the
// Stormbane ecosystem are registered here. Beacon uses this for fingerprint
// matching; Drydock uses it for scenario validation and image resolution.
var Registry = map[Technology]*TechMeta{}

// Register adds a technology to the global registry.
// Panics on duplicate IDs (catches mistakes at init time).
func Register(m *TechMeta) {
	if _, exists := Registry[m.ID]; exists {
		panic("infra: duplicate technology ID: " + string(m.ID))
	}
	Registry[m.ID] = m
	for _, alias := range m.Aliases {
		if _, exists := Registry[Technology(alias)]; exists {
			panic("infra: alias collides with existing ID: " + alias)
		}
		Registry[Technology(alias)] = m
	}
}

// Lookup returns the TechMeta for a given ID or alias, or nil if not found.
func Lookup(id string) *TechMeta {
	return Registry[Technology(id)]
}

// ByCategory returns all technologies in a given category.
func ByCategory(cat Category) []*TechMeta {
	seen := map[Technology]bool{}
	var result []*TechMeta
	for _, m := range Registry {
		if m.Category == cat && !seen[m.ID] {
			seen[m.ID] = true
			result = append(result, m)
		}
	}
	return result
}

// ByCloud returns all technologies specific to a cloud provider.
func ByCloud(provider Technology) []*TechMeta {
	seen := map[Technology]bool{}
	var result []*TechMeta
	for _, m := range Registry {
		if m.CloudProvider == provider && !seen[m.ID] {
			seen[m.ID] = true
			result = append(result, m)
		}
	}
	return result
}
