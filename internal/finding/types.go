package finding

import "time"

// Finding is the canonical normalized finding produced by any scanner.
// All scanners return []Finding regardless of the underlying tool.
type Finding struct {
	CheckID      CheckID        `json:"check_id"`
	Module       string         `json:"module"`        // "surface", "github", "iac", etc.
	Scanner      string         `json:"scanner"`       // "nuclei", "email", "testssl", etc.
	Severity     Severity       `json:"severity"`
	Title        string         `json:"title"`
	Description  string         `json:"description"`
	Asset        string         `json:"asset"`         // subdomain or IP this applies to
	Evidence     map[string]any `json:"evidence"`      // raw tool output
	ProofCommand string         `json:"proof_command"` // copy-paste shell command that reproduces/confirms this finding
	DeepOnly     bool           `json:"deep_only"`     // only produced in deep scans
	DiscoveredAt time.Time      `json:"discovered_at"`

	// ScannedBy identifies the scanner or module that produced this finding.
	// Format: "module.scanner", e.g. "surface.wafdetect", "github.actions", "web3.contract"
	ScannedBy string `json:"scanned_by,omitempty"`

	// DuplicateOf references another finding's key (check_id|asset|title) that
	// this finding likely duplicates. Set by the dedup pass after all scanners
	// complete. Beacon flags but does not merge — Forecast resolves with full context.
	DuplicateOf string `json:"duplicate_of,omitempty"`

	// DuplicateConfidence is how certain we are this is a duplicate (0.0–1.0).
	// Only meaningful when DuplicateOf is non-empty.
	DuplicateConfidence float64 `json:"duplicate_confidence,omitempty"`

	// EnabledBy references the CheckID+Asset of a prerequisite finding that
	// made this finding possible. Used to model exploit chains where one
	// vulnerability enables exploitation of another.
	// Format: "check_id|asset" (e.g. "web.command_injection|app.example.com").
	EnabledBy string `json:"enabled_by,omitempty"`

	// ChainDepth tracks how many hops from the initial entry point this
	// finding is. Depth 0 = direct scan finding, 1 = first pivot, etc.
	ChainDepth int `json:"chain_depth,omitempty"`
}

// Meta returns the CheckMeta for this finding's CheckID.
func (f Finding) Meta() CheckMeta {
	return Meta(f.CheckID)
}
