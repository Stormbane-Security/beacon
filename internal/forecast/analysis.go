package forecast

import (
	"time"

	"github.com/stormbane/beacon/internal/asset"
)

// ── Drift Detection ──────────────────────────────────────────────────────

// DriftReport captures temporal changes between two scan runs.
// Forecast generates this by comparing consecutive ScanReports for the same domain.
type DriftReport struct {
	// ProjectID identifies the Forecast project.
	ProjectID string `json:"project_id"`

	// Domain is the root scan target.
	Domain string `json:"domain"`

	// BaselineScanID is the earlier scan run.
	BaselineScanID string `json:"baseline_scan_id"`

	// CurrentScanID is the later scan run.
	CurrentScanID string `json:"current_scan_id"`

	// GeneratedAt is when this drift report was computed.
	GeneratedAt time.Time `json:"generated_at"`

	// Findings captures finding-level drift.
	Findings FindingDrift `json:"findings"`

	// Assets captures asset-level drift.
	Assets AssetDrift `json:"assets"`

	// RiskDelta is the overall risk score change (positive = worse).
	RiskDelta float64 `json:"risk_delta"`

	// Summary is an AI-generated natural language drift summary.
	Summary string `json:"summary,omitempty"`
}

// FindingDrift groups finding changes between scans.
type FindingDrift struct {
	// New findings not present in baseline.
	New []DriftFinding `json:"new,omitempty"`

	// Resolved findings present in baseline but absent in current.
	Resolved []DriftFinding `json:"resolved,omitempty"`

	// Recurring findings present in both scans.
	Recurring []DriftFinding `json:"recurring,omitempty"`

	// Regressed findings that were resolved but reappeared.
	Regressed []DriftFinding `json:"regressed,omitempty"`

	// SeverityShifts are findings whose severity changed between scans.
	SeverityShifts []SeverityShift `json:"severity_shifts,omitempty"`
}

// DriftFinding is a finding annotated with drift context.
type DriftFinding struct {
	CheckID  string `json:"check_id"`
	Asset    string `json:"asset"`
	Severity string `json:"severity"`
	Title    string `json:"title"`

	// FirstSeen is when this finding was first observed across all scans.
	FirstSeen time.Time `json:"first_seen"`

	// ScanCount is how many consecutive scans this finding has appeared in.
	ScanCount int `json:"scan_count,omitempty"`
}

// SeverityShift records a finding whose severity changed between scans.
type SeverityShift struct {
	CheckID      string `json:"check_id"`
	Asset        string `json:"asset"`
	PrevSeverity string `json:"prev_severity"`
	CurrSeverity string `json:"curr_severity"`
	Reason       string `json:"reason,omitempty"`
}

// AssetDrift groups asset changes between scans.
type AssetDrift struct {
	// Added assets discovered in current but not baseline.
	Added []DriftAsset `json:"added,omitempty"`

	// Removed assets present in baseline but absent in current.
	Removed []DriftAsset `json:"removed,omitempty"`

	// Changed assets whose properties differ between scans.
	Changed []AssetChange `json:"changed,omitempty"`
}

// DriftAsset is an asset annotated with drift context.
type DriftAsset struct {
	ID       string          `json:"id"`
	Type     asset.AssetType `json:"type"`
	Name     string          `json:"name"`
	Provider string          `json:"provider"`
}

// AssetChange describes how a specific asset changed between scans.
type AssetChange struct {
	AssetID string `json:"asset_id"`

	// FieldChanges lists which fields changed.
	FieldChanges []FieldChange `json:"field_changes"`
}

// FieldChange records a single field change on an asset.
type FieldChange struct {
	Field    string `json:"field"`
	OldValue string `json:"old_value"`
	NewValue string `json:"new_value"`
}

// ── Attack Path Analysis ─────────────────────────────────────────────────

// AttackPath represents a chain of exploitable findings that, together,
// create a path from an entry point to a high-value target.
// Forecast's AI layer identifies these by traversing the asset graph.
type AttackPath struct {
	// ID is a stable identifier for this attack path.
	ID string `json:"id"`

	// ProjectID identifies the Forecast project.
	ProjectID string `json:"project_id"`

	// GeneratedAt is when this path was identified.
	GeneratedAt time.Time `json:"generated_at"`

	// Severity is the composite severity of the full path.
	Severity string `json:"severity"`

	// Title is a short description of the attack path.
	Title string `json:"title"`

	// Description is a detailed narrative of how the attack progresses.
	Description string `json:"description"`

	// Steps are the ordered sequence of exploits/pivots.
	Steps []AttackStep `json:"steps"`

	// EntryPoint is the initial asset where the attacker gains access.
	EntryPoint string `json:"entry_point"`

	// Target is the high-value asset the attacker reaches.
	Target string `json:"target"`

	// TargetCriticality is the business criticality of the target asset.
	TargetCriticality asset.AssetCriticality `json:"target_criticality,omitempty"`

	// BlastRadius lists all assets reachable if this path is exploited.
	BlastRadius []string `json:"blast_radius,omitempty"`

	// RiskScore is a composite score (0-100) reflecting exploitability and impact.
	RiskScore float64 `json:"risk_score"`

	// Mitigations are recommended actions to break this attack path.
	Mitigations []Mitigation `json:"mitigations,omitempty"`
}

// AttackStep is a single hop in an attack path.
type AttackStep struct {
	// Order is the step number in the sequence (1-based).
	Order int `json:"order"`

	// AssetID is the asset involved in this step.
	AssetID string `json:"asset_id"`

	// FindingID is the exploited finding (if any).
	FindingID string `json:"finding_id,omitempty"`

	// CheckID is the check that identified the vulnerability.
	CheckID string `json:"check_id,omitempty"`

	// Technique describes the action taken (e.g., "exploit SSRF", "pivot via IAM role").
	Technique string `json:"technique"`

	// Privilege describes the access level gained after this step.
	Privilege PrivilegeLevel `json:"privilege"`

	// Confidence is how certain we are this step is exploitable (0.0-1.0).
	Confidence float64 `json:"confidence"`
}

// PrivilegeLevel describes the access level gained at an attack step.
type PrivilegeLevel string

const (
	PrivNone        PrivilegeLevel = "none"
	PrivRead        PrivilegeLevel = "read"
	PrivWrite       PrivilegeLevel = "write"
	PrivExecute     PrivilegeLevel = "execute"
	PrivAdmin       PrivilegeLevel = "admin"
	PrivRoot        PrivilegeLevel = "root"
	PrivCloudAdmin  PrivilegeLevel = "cloud_admin"
)

// Mitigation is a recommended action to break an attack path.
type Mitigation struct {
	// Step is which attack step this mitigation addresses (0 = path-level).
	Step int `json:"step"`

	// Action is what to do.
	Action string `json:"action"`

	// Priority indicates how effective this mitigation is at breaking the path.
	Priority MitigationPriority `json:"priority"`

	// Effort estimates the implementation effort.
	Effort MitigationEffort `json:"effort"`
}

// MitigationPriority indicates how effective a mitigation is.
type MitigationPriority string

const (
	MitigationCritical MitigationPriority = "critical" // breaks the path entirely
	MitigationHigh     MitigationPriority = "high"     // significantly raises the bar
	MitigationMedium   MitigationPriority = "medium"   // reduces blast radius
	MitigationLow      MitigationPriority = "low"      // defense in depth
)

// MitigationEffort estimates implementation complexity.
type MitigationEffort string

const (
	EffortTrivial MitigationEffort = "trivial" // config change, < 1 hour
	EffortLow     MitigationEffort = "low"     // small code/infra change, < 1 day
	EffortMedium  MitigationEffort = "medium"  // significant change, < 1 week
	EffortHigh    MitigationEffort = "high"    // architectural change, > 1 week
)

// ── Ownership Mapping ────────────────────────────────────────────────────

// OwnershipMap aggregates ownership signals across assets and findings.
// Forecast builds this by combining Beacon's OwnerRef data with external sources
// (CODEOWNERS, cloud tags, IAM bindings, commit history).
type OwnershipMap struct {
	// ProjectID identifies the Forecast project.
	ProjectID string `json:"project_id"`

	// GeneratedAt is when this ownership map was computed.
	GeneratedAt time.Time `json:"generated_at"`

	// Owners are the resolved owner entries.
	Owners []ResolvedOwner `json:"owners"`

	// UnownedAssets are assets with no ownership signal.
	UnownedAssets []string `json:"unowned_assets,omitempty"`

	// ConflictingOwnership are assets with contradictory ownership signals.
	ConflictingOwnership []OwnershipConflict `json:"conflicting_ownership,omitempty"`
}

// ResolvedOwner represents a confirmed owner with their asset and finding portfolio.
type ResolvedOwner struct {
	// Identity is the owner identifier (email, team name, GitHub handle).
	Identity string `json:"identity"`

	// Type categorizes how ownership was determined.
	Type asset.OwnerType `json:"type"`

	// Assets are the asset IDs owned by this entity.
	Assets []string `json:"assets"`

	// FindingCounts summarizes open findings across owned assets.
	FindingCounts SeverityCounts `json:"finding_counts"`

	// Confidence is the aggregate ownership confidence (0.0-1.0).
	Confidence float64 `json:"confidence"`

	// Sources lists the distinct sources that contributed to this ownership.
	Sources []string `json:"sources,omitempty"`
}

// SeverityCounts tallies findings by severity.
type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// OwnershipConflict records contradictory ownership signals for an asset.
type OwnershipConflict struct {
	// AssetID is the contested asset.
	AssetID string `json:"asset_id"`

	// Candidates are the conflicting ownership claims.
	Candidates []OwnerCandidate `json:"candidates"`
}

// OwnerCandidate is one party claiming ownership of an asset.
type OwnerCandidate struct {
	Identity   string          `json:"identity"`
	Type       asset.OwnerType `json:"type"`
	Source     string          `json:"source"`
	Confidence float64         `json:"confidence"`
}

// ── Change Impact Simulation ─────────────────────────────────────────────

// ImpactSimulation models the security impact of a proposed infrastructure change
// before it is applied. Forecast runs this by replaying the change against the
// current asset graph and finding state.
type ImpactSimulation struct {
	// ID is a unique identifier for this simulation.
	ID string `json:"id"`

	// ProjectID identifies the Forecast project.
	ProjectID string `json:"project_id"`

	// GeneratedAt is when this simulation was computed.
	GeneratedAt time.Time `json:"generated_at"`

	// Change describes the proposed change being simulated.
	Change ProposedChange `json:"change"`

	// Impact summarizes the security consequences.
	Impact ImpactSummary `json:"impact"`

	// AffectedAttackPaths lists attack paths created, broken, or modified.
	AffectedAttackPaths []AttackPathImpact `json:"affected_attack_paths,omitempty"`

	// ComplianceImpact lists compliance controls affected by this change.
	ComplianceImpact []ComplianceImpact `json:"compliance_impact,omitempty"`

	// Recommendation is the AI's verdict on whether to proceed.
	Recommendation ImpactRecommendation `json:"recommendation"`
}

// ProposedChange describes an infrastructure change to simulate.
type ProposedChange struct {
	// Type categorizes the change.
	Type ProposedChangeType `json:"type"`

	// Source identifies where the change comes from (PR URL, Terraform plan, manual).
	Source string `json:"source"`

	// Description explains the change in natural language.
	Description string `json:"description"`

	// AffectedAssets lists asset IDs directly modified by this change.
	AffectedAssets []string `json:"affected_assets"`

	// Changes are the specific field-level modifications.
	Changes []FieldChange `json:"changes,omitempty"`
}

// ProposedChangeType categorizes the kind of infrastructure change.
type ProposedChangeType string

const (
	ChangeTypeTerraformPlan  ProposedChangeType = "terraform_plan"
	ChangeTypeFirewallRule   ProposedChangeType = "firewall_rule"
	ChangeTypeIAMPolicy      ProposedChangeType = "iam_policy"
	ChangeTypeDNSRecord      ProposedChangeType = "dns_record"
	ChangeTypeTLSConfig      ProposedChangeType = "tls_config"
	ChangeTypeServiceDeploy  ProposedChangeType = "service_deploy"
	ChangeTypeNetworkChange  ProposedChangeType = "network_change"
	ChangeTypeAccessControl  ProposedChangeType = "access_control"
)

// ImpactSummary captures the overall security impact of a change.
type ImpactSummary struct {
	// RiskDelta is the change in overall risk score (positive = worse).
	RiskDelta float64 `json:"risk_delta"`

	// NewExposures are assets or services newly exposed by this change.
	NewExposures []ExposureChange `json:"new_exposures,omitempty"`

	// ClosedExposures are assets or services no longer exposed.
	ClosedExposures []ExposureChange `json:"closed_exposures,omitempty"`

	// AffectedAssetCount is the total number of assets impacted.
	AffectedAssetCount int `json:"affected_asset_count"`

	// AffectedOwners lists the owners whose assets are impacted.
	AffectedOwners []string `json:"affected_owners,omitempty"`
}

// ExposureChange describes a new or closed exposure resulting from a change.
type ExposureChange struct {
	AssetID     string `json:"asset_id"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

// AttackPathImpact describes how a proposed change affects an existing attack path.
type AttackPathImpact struct {
	// AttackPathID references the affected attack path.
	AttackPathID string `json:"attack_path_id"`

	// Effect describes the impact on this path.
	Effect AttackPathEffect `json:"effect"`

	// Description explains how the path is affected.
	Description string `json:"description"`
}

// AttackPathEffect categorizes the impact on an attack path.
type AttackPathEffect string

const (
	PathCreated    AttackPathEffect = "created"     // change introduces a new attack path
	PathBroken     AttackPathEffect = "broken"      // change breaks an existing path
	PathShortened  AttackPathEffect = "shortened"   // change reduces steps needed
	PathLengthened AttackPathEffect = "lengthened"   // change adds steps needed
	PathUnchanged  AttackPathEffect = "unchanged"   // change doesn't affect this path
)

// ComplianceImpact describes how a change affects compliance posture.
type ComplianceImpact struct {
	// Framework is the compliance framework (SOC2, PCI, NIST, HIPAA).
	Framework string `json:"framework"`

	// Control is the specific control affected.
	Control string `json:"control"`

	// Effect is whether compliance improves or degrades.
	Effect ComplianceEffect `json:"effect"`

	// Description explains the impact.
	Description string `json:"description"`
}

// ComplianceEffect categorizes the compliance impact.
type ComplianceEffect string

const (
	ComplianceImproved ComplianceEffect = "improved"
	ComplianceDegraded ComplianceEffect = "degraded"
	ComplianceNeutral  ComplianceEffect = "neutral"
)

// ImpactRecommendation is the AI's verdict on a proposed change.
type ImpactRecommendation string

const (
	RecommendProceed        ImpactRecommendation = "proceed"          // safe to apply
	RecommendProceedCaution ImpactRecommendation = "proceed_caution"  // safe but monitor closely
	RecommendReview         ImpactRecommendation = "review"           // needs human review
	RecommendBlock          ImpactRecommendation = "block"            // should not be applied
)
