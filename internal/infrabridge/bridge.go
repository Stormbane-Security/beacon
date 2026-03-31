// Package infrabridge connects Beacon to the shared stormbane/infra module.
// It provides convenience functions for looking up technology metadata and
// mapping between Beacon's internal identifiers and infra's canonical types.
//
// Beacon's existing detection logic (classify.go, fingerprintdb) stays
// in place — this bridge lets new code reference canonical IDs and metadata
// without duplicating the taxonomy.
package infrabridge

import (
	"github.com/stormbane/infra"
)

// Tech returns the canonical Technology ID for a string.
// This is a typed alias that lets callers use infra.Technology
// values without importing infra directly.
func Tech(id string) infra.Technology {
	return infra.Technology(id)
}

// LookupTech returns metadata for a technology by ID or alias.
// Returns nil if not found.
func LookupTech(id string) *infra.TechMeta {
	return infra.Lookup(id)
}

// LookupResource returns metadata for a cloud resource type.
// Format: "provider.service_resource" (e.g., "aws.ec2_instance").
// Returns nil if not found.
func LookupResource(rt string) *infra.ResourceMeta {
	return infra.LookupResource(rt)
}

// TerraformType returns the Terraform resource type for a cloud resource.
// Returns empty string if the resource type is not in the catalog.
func TerraformType(rt string) string {
	r := infra.LookupResource(rt)
	if r == nil {
		return ""
	}
	return r.TerraformType
}

// CLIDescribe returns the CLI command template for inspecting a cloud resource.
// Returns empty string if the resource type is not in the catalog.
func CLIDescribe(rt string) string {
	r := infra.LookupResource(rt)
	if r == nil {
		return ""
	}
	return r.CLIDescribe
}

// DefaultPorts returns the default ports for a technology.
// Returns nil if the technology is not in the catalog.
func DefaultPorts(id string) []int {
	m := infra.Lookup(id)
	if m == nil {
		return nil
	}
	return m.DefaultPorts
}

// ProviderName returns the human-readable name for a cloud provider.
// Returns the ID string itself if not found in the catalog.
func ProviderName(provider string) string {
	m := infra.Lookup(provider)
	if m == nil {
		return provider
	}
	return m.Name
}

// Re-export the canonical cloud provider constants for convenience.
const (
	AWS   = infra.AWS
	GCP   = infra.GCP
	Azure = infra.Azure

	Cloudflare   = infra.Cloudflare
	Vercel       = infra.Vercel
	Netlify      = infra.Netlify
	Heroku       = infra.Heroku
	DigitalOcean = infra.DigitalOcean
	Fly          = infra.Fly
	Railway      = infra.Railway
	Render       = infra.Render
)

// Re-export InfraLayer constants.
const (
	LayerCDNEdge      = infra.LayerCDNEdge
	LayerAPIGateway   = infra.LayerAPIGateway
	LayerLoadBalancer = infra.LayerLoadBalancer
	LayerServiceMesh  = infra.LayerServiceMesh
	LayerReverseProxy = infra.LayerReverseProxy
	LayerOrigin       = infra.LayerOrigin
)

// Re-export key technology constants that Beacon scanners reference frequently.
const (
	// Servers & proxies
	Nginx   = infra.Nginx
	Apache  = infra.Apache
	Caddy   = infra.Caddy
	Traefik = infra.Traefik
	Envoy   = infra.Envoy
	HAProxy = infra.HAProxy
	Kong    = infra.Kong

	// Frameworks
	NextJS  = infra.NextJS
	Django  = infra.Django
	Spring  = infra.Spring
	Laravel = infra.Laravel
	Express = infra.Express
	Flask   = infra.Flask
	FastAPI = infra.FastAPI

	// Databases
	PostgreSQL    = infra.PostgreSQL
	MySQL         = infra.MySQL
	Redis         = infra.Redis
	MongoDB       = infra.MongoDB
	Elasticsearch = infra.Elasticsearch

	// Auth
	Keycloak = infra.Keycloak
	Auth0    = infra.Auth0
	Okta     = infra.Okta
	Vault    = infra.Vault

	// Containers
	Kubernetes = infra.Kubernetes
	Docker     = infra.Docker

	// CI/CD
	Jenkins       = infra.Jenkins
	GitLabCI      = infra.GitLabCI
	TeamCity      = infra.TeamCity
	GitHubActions = infra.GitHubActions

	// Monitoring
	Prometheus = infra.Prometheus
	Grafana    = infra.Grafana

	// Web3
	Ethereum = infra.Ethereum
	Bitcoin  = infra.Bitcoin
	Solana   = infra.Solana
)
