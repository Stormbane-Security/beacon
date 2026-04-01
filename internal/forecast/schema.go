// Package forecast defines the data contract between Beacon and Forecast.
//
// Beacon is a single-scan, single-operator tool. Forecast is the multi-scan,
// multi-domain orchestration layer that aggregates data from many Beacon runs
// to provide:
//   - Temporal drift detection (new/resolved findings over time)
//   - Cross-domain attack path analysis
//   - Compliance posture mapping (SOC2, CIS, PCI, HIPAA)
//   - Remediation orchestration via Bosun
//   - Ownership mapping (CODEOWNERS, cloud tags, commit history)
//   - Change impact simulation
//
// The ScanReport is the primary data transfer object. Beacon serializes this
// and POST /v1/scans to Forecast after each scan. Forecast may also request
// re-scans via the ScanRequest type.
package forecast

import (
	"time"

	"github.com/stormbane-security/beacon/internal/asset"
	"github.com/stormbane-security/beacon/internal/finding"
)

// ScanReport is the complete payload Beacon sends to Forecast after a scan.
// It contains everything Forecast needs to update its world model for this domain.
type ScanReport struct {
	// Version is the schema version for forward compatibility.
	Version string `json:"version"`

	// Metadata about the scan run.
	Scan ScanMeta `json:"scan"`

	// Findings are the enriched security findings with duplicate flags.
	Findings []Finding `json:"findings"`

	// Assets is the full asset graph — nodes, edges, and IaC references.
	Assets AssetSnapshot `json:"assets"`

	// ScannerMetrics records per-scanner performance data.
	ScannerMetrics []ScannerMetric `json:"scanner_metrics,omitempty"`

	// DiscoverySources records which discovery source found each asset.
	DiscoverySources []DiscoverySource `json:"discovery_sources,omitempty"`
}

// ScanMeta contains metadata about the scan execution.
type ScanMeta struct {
	// RunID is the unique scan run identifier.
	RunID string `json:"run_id"`

	// Domain is the root scan target.
	Domain string `json:"domain"`

	// Targets lists all targets if multi-target scan.
	Targets []string `json:"targets,omitempty"`

	// Mode is the scan mode: "surface", "deep", or "authorized".
	Mode string `json:"mode"`

	// Modules lists which scan modules were executed.
	Modules []string `json:"modules"`

	// StartedAt is when the scan began.
	StartedAt time.Time `json:"started_at"`

	// CompletedAt is when the scan finished.
	CompletedAt time.Time `json:"completed_at"`

	// DurationMs is total wall-clock time in milliseconds.
	DurationMs int64 `json:"duration_ms"`

	// BeaconVersion identifies the Beacon build that produced this report.
	BeaconVersion string `json:"beacon_version"`

	// TotalFindings is the raw count before filtering/enrichment.
	TotalFindings int `json:"total_findings"`

	// TotalAssets is the number of discovered assets.
	TotalAssets int `json:"total_assets"`
}

// Finding is a single security finding with enrichment and duplicate metadata.
// This is the Forecast-facing representation — richer than Beacon's internal type.
type Finding struct {
	// Core finding data
	CheckID     string `json:"check_id"`
	Module      string `json:"module"`
	Scanner     string `json:"scanner"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Asset       string `json:"asset"`

	// Evidence and reproduction
	Evidence     map[string]any `json:"evidence,omitempty"`
	ProofCommand string         `json:"proof_command,omitempty"`

	// Scan mode metadata
	DeepOnly bool   `json:"deep_only,omitempty"`
	ScanMode string `json:"scan_mode,omitempty"` // "surface" or "deep"

	// Enrichment (from AI or cache)
	Explanation             string   `json:"explanation,omitempty"`
	Impact                  string   `json:"impact,omitempty"`
	Remediation             string   `json:"remediation,omitempty"`
	TechSpecificRemediation string   `json:"tech_specific_remediation,omitempty"`
	TerraformFix            string   `json:"terraform_fix,omitempty"`
	ComplianceTags          []string `json:"compliance_tags,omitempty"`
	MitigatedBy             string   `json:"mitigated_by,omitempty"`
	CrossAssetNote          string   `json:"cross_asset_note,omitempty"`

	// Duplicate detection (Beacon flags, Forecast resolves)
	DuplicateOf         string  `json:"duplicate_of,omitempty"`
	DuplicateConfidence float64 `json:"duplicate_confidence,omitempty"`

	// Delta status from previous scan comparison
	DeltaStatus string `json:"delta_status,omitempty"` // "new", "recurring", "resolved"

	// Timestamps
	DiscoveredAt time.Time `json:"discovered_at"`
}

// AssetSnapshot is the full asset topology at scan time.
type AssetSnapshot struct {
	// Assets are the discovered resource nodes.
	Assets []asset.Asset `json:"assets"`

	// Relationships are the directed edges between assets.
	Relationships []asset.Relationship `json:"relationships"`

	// FindingRefs link findings to their asset nodes.
	FindingRefs []asset.FindingRef `json:"finding_refs"`

	// IaCReferences are deterministic Terraform → cloud asset matches.
	IaCReferences []asset.IaCReference `json:"iac_references"`
}

// ScannerMetric records per-scanner performance for Forecast's ROI analysis.
type ScannerMetric struct {
	ScannerName string `json:"scanner_name"`
	Asset       string `json:"asset"`
	DurationMs  int64  `json:"duration_ms"`
	FindingsCritical int `json:"findings_critical"`
	FindingsHigh     int `json:"findings_high"`
	FindingsMedium   int `json:"findings_medium"`
	FindingsLow      int `json:"findings_low"`
	FindingsInfo     int `json:"findings_info"`
	ErrorCount       int `json:"error_count"`
	Skipped          bool `json:"skipped"`
}

// DiscoverySource records which source found an asset.
type DiscoverySource struct {
	Asset  string `json:"asset"`
	Source string `json:"source"` // "subdomain", "passivedns", "ai_advisor", "playbook", "root"
}

// CurrentSchemaVersion is the current version of the Forecast ingestion schema.
const CurrentSchemaVersion = "1"

// NewScanReport creates a ScanReport with the current schema version.
func NewScanReport() *ScanReport {
	return &ScanReport{
		Version: CurrentSchemaVersion,
	}
}

// FindingFromBeacon converts a Beacon finding.Finding to a Forecast Finding.
func FindingFromBeacon(f finding.Finding) Finding {
	scanMode := "surface"
	if f.DeepOnly {
		scanMode = "deep"
	}
	return Finding{
		CheckID:             string(f.CheckID),
		Module:              f.Module,
		Scanner:             f.Scanner,
		Severity:            f.Severity.String(),
		Title:               f.Title,
		Description:         f.Description,
		Asset:               f.Asset,
		Evidence:            f.Evidence,
		ProofCommand:        f.ProofCommand,
		DeepOnly:            f.DeepOnly,
		ScanMode:            scanMode,
		DuplicateOf:         f.DuplicateOf,
		DuplicateConfidence: f.DuplicateConfidence,
		DiscoveredAt:        f.DiscoveredAt,
	}
}
