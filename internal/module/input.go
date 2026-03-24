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

	// GitHub — used by: GitHub/CI module (Phase 2)
	GitHubOrg   string
	GitHubRepo  string
	GitHubToken string

	// IaC — used by: IaC module (Phase 2)
	IaCRepoPath string

	// Cloud — used by: Cloud module (Phase 3)
	AWSProfile         string
	GCPCredentialsFile string
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
	AssetNames   []string          // full list of discovered assets (discovery_done only)
	Evidence     playbook.Evidence // fingerprint evidence (fingerprint phase only)
}

// ProgressFunc is called at each scan milestone.
// Implementations must be goroutine-safe.
type ProgressFunc func(ProgressEvent)
