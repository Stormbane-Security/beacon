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
	AssetTypeGitHubPackage  AssetType = "github_package"
	AssetTypeJenkinsServer  AssetType = "jenkins_server"
	AssetTypeGitLabInstance AssetType = "gitlab_instance"
	AssetTypeTeamCityServer AssetType = "teamcity_server"

	// Infrastructure as Code
	AssetTypeTerraformModule   AssetType = "terraform_module"
	AssetTypeTerraformResource AssetType = "terraform_resource"

	// Kubernetes
	AssetTypeK8sCluster   AssetType = "k8s_cluster"
	AssetTypeK8sNamespace AssetType = "k8s_namespace"
	AssetTypeK8sWorkload  AssetType = "k8s_workload"

	// On-prem — Proxmox VE
	AssetTypeProxmoxNode      AssetType = "proxmox_node"
	AssetTypeProxmoxVM        AssetType = "proxmox_vm"
	AssetTypeProxmoxContainer AssetType = "proxmox_container"
	AssetTypeProxmoxStorage   AssetType = "proxmox_storage"

	// On-prem — Docker
	AssetTypeDockerHost      AssetType = "docker_host"
	AssetTypeDockerContainer AssetType = "docker_container"
	AssetTypeDockerImage     AssetType = "docker_image"
	AssetTypeDockerNetwork   AssetType = "docker_network"
	AssetTypeDockerVolume    AssetType = "docker_volume"

	// On-prem — VMware
	AssetTypeVMwareHost      AssetType = "vmware_host"
	AssetTypeVMwareVM        AssetType = "vmware_vm"
	AssetTypeVMwareDatastore AssetType = "vmware_datastore"

	// On-prem — libvirt/KVM
	AssetTypeLibvirtHost   AssetType = "libvirt_host"
	AssetTypeLibvirtDomain AssetType = "libvirt_domain"

	// On-prem — Network devices
	AssetTypeNetworkDevice AssetType = "network_device"
	AssetTypeNetworkSwitch AssetType = "network_switch"
	AssetTypeNetworkRouter AssetType = "network_router"
	AssetTypeNetworkAP     AssetType = "network_access_point"

	// On-prem — NAS appliances
	AssetTypeNASAppliance AssetType = "nas_appliance"
	AssetTypeNASShare     AssetType = "nas_share"
)

// RelationshipType describes the semantic direction of an edge.
type RelationshipType string

const (
	RelManages         RelationshipType = "manages"           // repo/terraform → cloud resource
	RelExposes         RelationshipType = "exposes"           // service → API / port
	RelDeploysTo       RelationshipType = "deploys_to"        // workflow → cluster/project
	RelPublishes       RelationshipType = "publishes"         // workflow → package/registry
	RelDeployedFrom    RelationshipType = "deployed_from"     // k8s workload/cloud instance → package
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

	// --- Lifecycle fields (populated by Forecast across scans) ---

	// FirstSeen is the earliest scan that discovered this asset.
	// Within a single Beacon scan this equals DiscoveredAt. Forecast
	// carries it forward across scans.
	FirstSeen time.Time `json:"first_seen,omitempty"`

	// LastSeen is the most recent scan that observed this asset.
	LastSeen time.Time `json:"last_seen,omitempty"`

	// Status tracks the asset's lifecycle state.
	Status AssetStatus `json:"status,omitempty"`

	// --- Criticality and ownership ---

	// Criticality indicates the business impact tier of this asset.
	// Set by Forecast from cloud tags, manual classification, or AI inference.
	Criticality AssetCriticality `json:"criticality,omitempty"`

	// Owners are the inferred owners of this asset.
	// Sources: CODEOWNERS, cloud resource tags, commit history, IAM bindings.
	Owners []OwnerRef `json:"owners,omitempty"`

	// Services are the network services discovered running on this asset.
	// Populated by port scanning and HTTP probing.
	Services []Service `json:"services,omitempty"`
}

// AssetStatus tracks where an asset is in its lifecycle.
type AssetStatus string

const (
	AssetStatusActive       AssetStatus = "active"        // seen in most recent scan
	AssetStatusInactive     AssetStatus = "inactive"      // not seen in last scan, seen before
	AssetStatusDecommission AssetStatus = "decommissioned" // confirmed removed (cloud API says deleted)
	AssetStatusNew          AssetStatus = "new"            // first time seen in this scan
)

// AssetCriticality indicates the business impact tier.
type AssetCriticality string

const (
	CriticalityP0 AssetCriticality = "p0" // production customer-facing, auth, payments
	CriticalityP1 AssetCriticality = "p1" // production internal, CI/CD, data pipeline
	CriticalityP2 AssetCriticality = "p2" // staging, development, non-critical
	CriticalityP3 AssetCriticality = "p3" // sandbox, test, ephemeral
)

// OwnerRef identifies an owner of an asset.
type OwnerRef struct {
	// Type is the source of the ownership signal.
	Type OwnerType `json:"type"`

	// Identity is the owner identifier (email, team name, GitHub handle).
	Identity string `json:"identity"`

	// Source describes where this ownership was inferred from.
	Source string `json:"source,omitempty"`

	// Confidence is how certain we are about this ownership (0.0–1.0).
	Confidence float64 `json:"confidence"`
}

// OwnerType categorizes how ownership was determined.
type OwnerType string

const (
	OwnerCodeowners  OwnerType = "codeowners"   // from CODEOWNERS file
	OwnerCloudTag    OwnerType = "cloud_tag"    // from cloud resource tags (owner, team, etc.)
	OwnerCommitFreq  OwnerType = "commit_freq"  // most frequent committer to related repo
	OwnerIAMBinding  OwnerType = "iam_binding"  // from cloud IAM role bindings
	OwnerManual      OwnerType = "manual"       // explicitly set by user in Forecast
)

// Service represents a network service discovered on an asset.
type Service struct {
	// Port is the TCP/UDP port number.
	Port int `json:"port"`

	// Protocol is "tcp" or "udp".
	Protocol string `json:"protocol"`

	// ServiceName is the identified service (http, ssh, mysql, redis, etc.).
	ServiceName string `json:"service_name"`

	// Version is the detected version string (if available).
	Version string `json:"version,omitempty"`

	// Banner is the raw service banner (first N bytes).
	Banner string `json:"banner,omitempty"`

	// TLS indicates whether the service uses TLS.
	TLS bool `json:"tls,omitempty"`

	// State is whether the port is open, filtered, or closed.
	State string `json:"state"` // "open", "filtered", "closed"
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
