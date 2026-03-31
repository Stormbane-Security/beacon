package infra

// ResourceType is a canonical identifier for a cloud resource type.
// Format: provider.service_resource (e.g., "aws.ec2_instance", "gcp.gke_cluster").
type ResourceType string

// ResourceMeta holds metadata about a cloud resource type.
type ResourceMeta struct {
	// Type is the canonical identifier.
	Type ResourceType

	// Name is the human-readable display name.
	Name string

	// Provider is the cloud provider (aws, gcp, azure).
	Provider Technology

	// Service is the cloud service this resource belongs to (e.g., "ec2", "s3", "gke").
	Service string

	// Category classifies the resource (compute, storage, database, network, security, etc.).
	Category ResourceCategory

	// CLIDescribe is the CLI command to inspect this resource type.
	// Used by Beacon for ProofCommand generation.
	CLIDescribe string

	// TerraformType is the Terraform resource type (e.g., "aws_instance", "google_container_cluster").
	// Used by Drydock for Terraform-based provisioning and Beacon for IaC scanning.
	TerraformType string

	// ARNPattern is the ARN format for AWS resources (e.g., "arn:aws:ec2:{region}:{account}:instance/{id}").
	// Empty for non-AWS resources.
	ARNPattern string
}

// ResourceCategory classifies cloud resources by function.
type ResourceCategory string

const (
	ResCompute    ResourceCategory = "compute"
	ResStorage    ResourceCategory = "storage"
	ResDatabase   ResourceCategory = "database"
	ResNetwork    ResourceCategory = "network"
	ResSecurity   ResourceCategory = "security"
	ResIdentity   ResourceCategory = "identity"
	ResContainer  ResourceCategory = "container"
	ResServerless ResourceCategory = "serverless"
	ResMessaging  ResourceCategory = "messaging"
	ResMonitoring ResourceCategory = "monitoring"
	ResCDN        ResourceCategory = "cdn"
	ResCache      ResourceCategory = "cache"
	ResSearch     ResourceCategory = "search"
	ResCICD       ResourceCategory = "cicd"
	ResRegistry   ResourceCategory = "registry"
)

// ResourceRegistry is the global catalog of cloud resource types.
var ResourceRegistry = map[ResourceType]*ResourceMeta{}

// RegisterResource adds a cloud resource type to the global registry.
func RegisterResource(m *ResourceMeta) {
	if _, exists := ResourceRegistry[m.Type]; exists {
		panic("infra: duplicate resource type: " + string(m.Type))
	}
	ResourceRegistry[m.Type] = m
}

// LookupResource returns the ResourceMeta for a given type, or nil.
func LookupResource(rt string) *ResourceMeta {
	return ResourceRegistry[ResourceType(rt)]
}
