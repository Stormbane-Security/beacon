package forecast

import "time"

// ScanRequest is what Forecast sends to Beacon to request a targeted re-scan.
// This enables the feedback loop: Forecast analyzes scan results, identifies
// gaps or changes, and tells Beacon exactly what to re-scan.
type ScanRequest struct {
	// RequestID is a unique identifier for this request.
	RequestID string `json:"request_id"`

	// ProjectID identifies the Forecast project.
	ProjectID string `json:"project_id"`

	// Priority determines scan queue ordering.
	Priority ScanPriority `json:"priority"`

	// Reason explains why Forecast is requesting this scan.
	Reason string `json:"reason"`

	// Targets are the specific assets or domains to scan.
	Targets []ScanTarget `json:"targets"`

	// Mode is the requested scan depth.
	Mode string `json:"mode"` // "surface", "deep", "authorized"

	// Modules restricts which scan modules to run (empty = all).
	Modules []string `json:"modules,omitempty"`

	// FocusChecks restricts which check IDs to run (empty = all).
	FocusChecks []string `json:"focus_checks,omitempty"`

	// Deadline is the latest time this scan should start.
	Deadline *time.Time `json:"deadline,omitempty"`

	// CallbackURL is where to POST the ScanReport when done.
	CallbackURL string `json:"callback_url,omitempty"`

	// Context provides additional information for the scan.
	Context *ScanContext `json:"context,omitempty"`
}

// ScanPriority determines scan queue ordering.
type ScanPriority string

const (
	PriorityCritical ScanPriority = "critical" // drift on critical finding — scan immediately
	PriorityHigh     ScanPriority = "high"     // compliance deadline or new asset discovered
	PriorityNormal   ScanPriority = "normal"   // scheduled re-scan
	PriorityLow      ScanPriority = "low"      // background validation
)

// ScanTarget describes a specific asset or domain to scan.
type ScanTarget struct {
	// Asset is the hostname, IP, or cloud resource ID to scan.
	Asset string `json:"asset"`

	// Type is the asset type hint (optional).
	Type string `json:"type,omitempty"`

	// PreviousFindings lists check IDs previously found on this asset.
	// Beacon can use this to prioritize relevant scanners.
	PreviousFindings []string `json:"previous_findings,omitempty"`

	// ExpectedTech lists technologies previously fingerprinted on this asset.
	// Beacon can use this to select targeted playbooks.
	ExpectedTech []string `json:"expected_tech,omitempty"`
}

// ScanContext provides additional information from Forecast's world model
// that helps Beacon make better scanning decisions.
type ScanContext struct {
	// KnownAssets lists assets Forecast already knows about in this domain.
	// Beacon can skip discovery for these and focus on scanning.
	KnownAssets []string `json:"known_assets,omitempty"`

	// RecentChanges describes what changed since the last scan.
	RecentChanges []Change `json:"recent_changes,omitempty"`

	// ComplianceDeadline is the next compliance audit date (if any).
	ComplianceDeadline *time.Time `json:"compliance_deadline,omitempty"`

	// ComplianceFramework is the target framework (SOC2, PCI, CIS, etc.).
	ComplianceFramework string `json:"compliance_framework,omitempty"`
}

// Change describes a detected change that triggered a re-scan.
type Change struct {
	// Type is what changed.
	Type ChangeType `json:"type"`

	// Asset is which asset changed.
	Asset string `json:"asset"`

	// Description explains the change.
	Description string `json:"description"`

	// DetectedAt is when the change was detected.
	DetectedAt time.Time `json:"detected_at"`
}

// ChangeType categorizes what kind of change triggered a re-scan.
type ChangeType string

const (
	ChangeNewAsset        ChangeType = "new_asset"         // new asset discovered by another scan
	ChangeConfigDrift     ChangeType = "config_drift"      // cloud config changed (terraform plan drift)
	ChangeFindingResolved ChangeType = "finding_resolved"  // previously-open finding no longer reproduces
	ChangeFindingNew      ChangeType = "finding_new"       // new finding type on existing asset
	ChangeCertExpiry      ChangeType = "cert_expiry"       // certificate approaching expiry
	ChangeDependencyUpdate ChangeType = "dependency_update" // upstream dependency version changed
	ChangeOwnershipChange ChangeType = "ownership_change"  // CODEOWNERS or cloud tag change
)

// ScanAcknowledgment is Beacon's response to a ScanRequest.
type ScanAcknowledgment struct {
	// RequestID echoes the request.
	RequestID string `json:"request_id"`

	// Status indicates whether the scan was accepted.
	Status AckStatus `json:"status"`

	// ScanRunID is the ID of the scan run (if accepted).
	ScanRunID string `json:"scan_run_id,omitempty"`

	// EstimatedCompletionAt is Beacon's estimate of when the scan will finish.
	EstimatedCompletionAt *time.Time `json:"estimated_completion_at,omitempty"`

	// Reason explains why the scan was rejected (if applicable).
	Reason string `json:"reason,omitempty"`
}

// AckStatus is the status of a scan acknowledgment.
type AckStatus string

const (
	AckAccepted AckStatus = "accepted"
	AckQueued   AckStatus = "queued"
	AckRejected AckStatus = "rejected" // e.g., scan mode not authorized
)
