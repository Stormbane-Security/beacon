package module

import (
	"context"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/playbook"
)

// Input holds all possible inputs for any module.
// Each module uses only the fields relevant to its InputType.
type Input struct {
	// Domain — used by: Surface
	Domain string

	// ExtraCIDRs is an optional list of CIDR ranges (e.g. "203.0.113.0/24") to
	// enumerate and probe in addition to BGP-discovered ranges. Useful when the
	// target org owns IP space that isn't announced via BGP or is on a shared ASN.
	// Used by: Surface
	ExtraCIDRs []string

	// Peers are the other root domains in the same multi-asset scan session.
	// Empty for single-asset scans. Used for cross-asset fingerprinting (shared
	// TLS SANs, shared IPs, shared software stacks).
	// Used by: Surface
	Peers []string

	// GitHub — used by: GitHub/CI module (Phase 2)
	GitHubOrg   string
	GitHubRepo  string
	GitHubToken string

	// IaC — used by: IaC module (Phase 2)
	IaCRepoPath string

	// Cloud — used by: Cloud module.
	// Set CloudEnabled to true to run cloud posture checks using ambient
	// credentials (ADC, AWS env vars, Azure DefaultAzureCredential).
	// Override individual fields to use non-default credentials.
	CloudEnabled        bool
	AWSProfile          string
	GCPCredentialsFile  string
	AzureSubscriptionID string

	// Kubernetes — used by: Kubernetes module (Phase 3)
	KubeconfigPath string

	// PermissionConfirmed must be true for deep scans.
	// This is a legal/ethical safeguard: the user confirms they own
	// or have permission to actively probe the target.
	PermissionConfirmed bool

	// ScanRunID is the ID of the current scan run, used for audit records.
	// Set by the pipeline before passing Input to modules.
	ScanRunID string

	// Progress is an optional callback for real-time scan progress updates.
	// Called from multiple goroutines; the implementation must be goroutine-safe.
	// A nil Progress is valid and silently drops all events.
	Progress ProgressFunc

	// PauseCheck is called between assets. If the scan has been paused by the
	// user it blocks until Resume is called. If ctx is cancelled while paused
	// it returns immediately. A nil PauseCheck is valid and does nothing.
	PauseCheck func(ctx context.Context)
}

// ProgressEvent carries a snapshot of scan progress at a pipeline milestone.
type ProgressEvent struct {
	// Phase is one of: "discovering", "discovery_done", "scanning", "scanner_start",
	// "scanner_done", "fingerprint", "asset_done".
	Phase        string
	StatusMsg    string // human-readable status line, used during "discovering" phase
	AssetsTotal  int    // 0 = unknown (during discovery); populated after discovery_done
	AssetsDone   int    // number of assets fully scanned so far
	ActiveAsset  string // asset currently being scanned
	ScannerName  string // scanner currently starting ("scanner_start" / "scanner_done")
	ScannerCmd   string // human-readable command description for the scanner
	FindingCount int               // running total of findings accumulated so far
	FindingDelta int               // findings added by the last completed scanner
	NewFindings  []finding.Finding // actual findings from the last completed scanner (scanner_done only)
	AssetNames      []string          // full list of discovered assets (discovery_done only)
	Evidence        playbook.Evidence // fingerprint evidence (fingerprint phase only)
	// DiscoveredAssets is populated on the "unconfirmed_assets" phase.
	// Each entry is an asset whose domain ownership could not be automatically
	// confirmed. The TUI presents these in the Discovered Assets panel so the
	// operator can review evidence and decide whether to authorise a deep scan.
	DiscoveredAssets []DiscoveredAsset
}

// ProgressFunc is called at each scan milestone.
// Implementations must be goroutine-safe.
type ProgressFunc func(ProgressEvent)

// DiscoveredAsset represents an IP or hostname found during scanning whose
// ownership by the target domain has not yet been confirmed. Surface-mode
// passive scans always run against these (unsolicited observation is safe).
// Deep scans require explicit typed operator confirmation.
type DiscoveredAsset struct {
	Asset         string   // bare IP or hostname discovered
	DiscoveredVia string   // "bgp", "bgp_ptr", "cdn_origin", "ghactions_deploy", etc.
	Relationship  string   // human-readable: why this asset appeared in the scan
	Confirmed     bool     // true = auto-confirmed as belonging to RootDomain
	Evidence      []string // PTR record, TLS SAN, HTTP probe, CNAME — used to confirm/deny
	RootDomain    string   // the scan target this was discovered under
	BoundHostname string   // hostname to use as Host: header when probing (non-empty for CDN origins)
}
