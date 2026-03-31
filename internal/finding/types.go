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
}

// Meta returns the CheckMeta for this finding's CheckID.
func (f Finding) Meta() CheckMeta {
	return Meta(f.CheckID)
}
