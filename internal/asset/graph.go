// Package asset defines the normalized security asset graph that Beacon emits
// for consumption by downstream systems (Bosun IaC remediator, SIEM integrations).
//
// The graph contains four entity types:
//   - Asset: any discovered resource (domain, IP, cloud resource, repo, cluster)
//   - Relationship: directional edge between two assets
//   - FindingRef: lightweight reference to a finding attached to an asset
//   - IaCReference: deterministic match between an asset and a Terraform resource
//
// Probabilistic asset correlation ("this domain is probably this GCP instance")
// is represented as a Relationship with type=candidate_same_as and confidence<0.9.
// Confirmed correlation (IP match) results in the assets sharing aliases.
package asset

import (
	"time"
)

// AssetGraph is the top-level output document emitted by beacon scan --format graph.
type AssetGraph struct {
	ScanRunID     string         `json:"scan_run_id"`
	Domain        string         `json:"domain"`        // root scan target
	GeneratedAt   time.Time      `json:"generated_at"`
	Assets        []Asset        `json:"assets"`
	Relationships []Relationship `json:"relationships"`
	Findings      []FindingRef   `json:"findings"`
	IaCReferences []IaCReference `json:"iac_references"`
}

// AssetType categorizes the kind of resource an asset represents.
type AssetType string

const (
	// Network / web
	AssetTypeDomain      AssetType = "domain"
	AssetTypeSubdomain   AssetType = "subdomain"
	AssetTypeIP          AssetType = "ip"
	AssetTypeAPIEndpoint AssetType = "api_endpoint"

	// GCP
	AssetTypeGCPProject        AssetType = "gcp_project"
	AssetTypeGCPInstance       AssetType = "gcp_compute_instance"
	AssetTypeGCPBucket         AssetType = "gcp_storage_bucket"
	AssetTypeGCPCluster        AssetType = "gcp_gke_cluster"
	AssetTypeGCPServiceAccount AssetType = "gcp_service_account"
	AssetTypeGCPLoadBalancer   AssetType = "gcp_load_balancer"

	// AWS
	AssetTypeAWSAccount    AssetType = "aws_account"
	AssetTypeAWSEC2        AssetType = "aws_ec2_instance"
	AssetTypeAWSS3         AssetType = "aws_s3_bucket"
	AssetTypeAWSEKS        AssetType = "aws_eks_cluster"
	AssetTypeAWSIAMUser    AssetType = "aws_iam_user"
	AssetTypeAWSIAMRole    AssetType = "aws_iam_role"
	AssetTypeAWSELB        AssetType = "aws_load_balancer"

	// Azure
	AssetTypeAzureSubscription  AssetType = "azure_subscription"
	AssetTypeAzureVM            AssetType = "azure_vm"
	AssetTypeAzureBlobContainer AssetType = "azure_blob_container"
	AssetTypeAzureAKS           AssetType = "azure_aks_cluster"

	// Source control / CI
	AssetTypeGitHubRepo     AssetType = "github_repo"
	AssetTypeGitHubWorkflow AssetType = "github_workflow"

	// Infrastructure as Code
	AssetTypeTerraformModule   AssetType = "terraform_module"
	AssetTypeTerraformResource AssetType = "terraform_resource"

	// Kubernetes
	AssetTypeK8sCluster   AssetType = "k8s_cluster"
	AssetTypeK8sNamespace AssetType = "k8s_namespace"
	AssetTypeK8sWorkload  AssetType = "k8s_workload"
)

// RelationshipType describes the semantic direction of an edge.
type RelationshipType string

const (
	RelManages         RelationshipType = "manages"           // repo/terraform → cloud resource
	RelExposes         RelationshipType = "exposes"           // service → API / port
	RelDeploysTo       RelationshipType = "deploys_to"        // workflow → cluster/project
	RelUses            RelationshipType = "uses"              // workload → identity
	RelAccesses        RelationshipType = "accesses"          // identity → resource
	RelBelongsTo       RelationshipType = "belongs_to"        // subdomain → domain
	RelPointsTo        RelationshipType = "points_to"         // domain/CNAME → IP/service
	RelLikelySameAs    RelationshipType = "likely_same_as"    // high-confidence cross-scan match
	RelCandidateSameAs RelationshipType = "candidate_same_as" // probabilistic match — Bosun resolves
)

// Asset is a single discovered resource node in the graph.
type Asset struct {
	// ID is a stable, globally unique identifier.
	// Format: "<type>:<provider-specific-path>"
	// Examples:
	//   "domain:api.example.com"
	//   "gcp_compute_instance:projects/acme/zones/us-central1-a/instances/api-prod-1"
	//   "aws_s3_bucket:acme-prod-exports:us-east-1:123456789012"
	ID string `json:"id"`

	// Type categorizes the resource.
	Type AssetType `json:"type"`

	// Provider is the origin platform: "gcp", "aws", "azure", "github", "web", "dns", "k8s"
	Provider string `json:"provider"`

	// Name is the human-readable short name (bucket name, domain, instance name).
	Name string `json:"name"`

	// Aliases are alternative IDs that refer to the same physical resource.
	// Set when cross-scan matching confirms two asset records are the same thing.
	Aliases []string `json:"aliases,omitempty"`

	// Account is the cloud account/project/subscription that owns this resource.
	Account string `json:"account,omitempty"`

	// Region is the geographic region (us-central1, us-east-1, eastus).
	Region string `json:"region,omitempty"`

	// Labels are cloud resource labels/tags (key:value pairs).
	Labels map[string]string `json:"labels,omitempty"`

	// Public indicates the resource is accessible from the public internet.
	Public bool `json:"public,omitempty"`

	// Metadata holds provider-specific additional fields.
	Metadata map[string]any `json:"metadata,omitempty"`

	// Fingerprint holds technology stack signals observed on this asset.
	Fingerprint *AssetFingerprint `json:"fingerprint,omitempty"`

	// IAMContext holds identity and access management state for cloud resources.
	IAMContext *IAMContext `json:"iam_context,omitempty"`

	// DiscoveredBy is the scanner or module that first found this asset.
	DiscoveredBy string `json:"discovered_by"`

	// Confidence is how certain we are this asset belongs to the scan target.
	Confidence float64 `json:"confidence"`

	// DiscoveredAt is when this asset was first observed.
	DiscoveredAt time.Time `json:"discovered_at"`
}

// AssetFingerprint captures confirmed technology signals for an asset,
// combining deterministic HTTP evidence with cloud metadata and source code evidence.
type AssetFingerprint struct {
	// Tech is the list of confirmed technologies running on this asset.
	Tech []TechSignal `json:"tech,omitempty"`

	// ConfirmedSignals are the raw evidence items that established the fingerprint.
	// Multiple sources for the same technology increase confidence.
	ConfirmedSignals []ConfirmedSignal `json:"confirmed_signals,omitempty"`
}

// TechSignal is a single identified technology component.
type TechSignal struct {
	Name       string  `json:"name"`
	Version    string  `json:"version,omitempty"`
	Confidence float64 `json:"confidence"`
}

// ConfirmedSignal is one piece of evidence confirming a technology.
type ConfirmedSignal struct {
	// Source: "http_header", "cloud_metadata_label", "github_dockerfile",
	//         "github_workflow", "cloud_instance_metadata", "dns_record"
	Source     string  `json:"source"`
	Value      string  `json:"value"`
	Confidence float64 `json:"confidence"`
}

// IAMContext captures the effective identity and access state for a cloud resource.
// Used by AI attack path analysis to understand blast radius.
type IAMContext struct {
	// Principal is the identity bound to this resource (service account email, IAM role ARN, etc.)
	Principal string `json:"principal,omitempty"`

	// Roles are the raw role bindings (roles/editor, arn:aws:iam::aws:policy/AdministratorAccess)
	Roles []string `json:"roles,omitempty"`

	// DenyRules are active deny policies that restrict the roles above.
	DenyRules []string `json:"deny_rules,omitempty"`

	// EffectivePermissions is the computed set of allowed permissions after applying deny rules.
	// Empty when the full policy evaluation was not performed.
	EffectivePermissions []string `json:"effective_permissions,omitempty"`

	// Issues are the specific IAM misconfigurations detected.
	// Values: "primitive_role", "wildcard_resource", "wildcard_action",
	//         "user_managed_key", "key_age_exceeded", "no_mfa", "root_access_key"
	Issues []string `json:"issues,omitempty"`
}

// Relationship is a directed edge in the asset graph.
type Relationship struct {
	FromID string           `json:"from_id"`
	ToID   string           `json:"to_id"`
	Type   RelationshipType `json:"type"`

	// Confidence is 1.0 for deterministic matches, <0.9 for probabilistic.
	Confidence float64 `json:"confidence"`

	// Evidence holds the raw signals that established this relationship.
	Evidence map[string]any `json:"evidence,omitempty"`

	// Signals is a human-readable list of signals for probabilistic matches.
	// Example: ["ip_asn_match:0.85", "tech_stack_alignment:0.80", "name_similarity:0.70"]
	Signals []string `json:"signals,omitempty"`
}

// FindingRef is a lightweight finding reference attached to an asset.
// The full finding detail lives in the scan run's finding store.
type FindingRef struct {
	FindingID      string   `json:"finding_id"`
	AssetID        string   `json:"asset_id"`
	CheckID        string   `json:"check_id"`
	Severity       string   `json:"severity"`
	Title          string   `json:"title"`
	ProofCommand   string   `json:"proof_command,omitempty"`
	ComplianceTags []string `json:"compliance_tags,omitempty"`
}

// IaCReference is a deterministic match between a cloud asset and a Terraform resource.
// Only set when Beacon found an exact name match in scanned Terraform files.
// Probabilistic IaC mapping is Bosun's job.
type IaCReference struct {
	AssetID  string `json:"asset_id"`
	Repo     string `json:"repo"`
	File     string `json:"file"`
	Line     int    `json:"line,omitempty"`
	Resource string `json:"resource,omitempty"` // terraform resource address e.g. "google_storage_bucket.exports"
	// Confidence is always 1.0 for deterministic name matches.
	Confidence float64 `json:"confidence"`
	// Method: "name_match", "ip_match", "arn_match", "project_id_match"
	Method string `json:"method"`
}
