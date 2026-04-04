package scan

import (
	"github.com/stormbane-security/beacon/internal/finding"
)

// CheckDecl declares a check ID that a scanner emits, along with its
// severity and scan mode. Used with RegisterWithChecks to self-document
// which findings a scanner produces.
//
// Example:
//
//	func init() {
//	    scan.RegisterWithChecks("cors", corsFactory,
//	        scan.Check("web.cors_wildcard_origin", finding.SeverityHigh, finding.ModeDeep),
//	        scan.Check("web.cors_null_origin", finding.SeverityHigh, finding.ModeDeep),
//	    )
//	}
type CheckDecl struct {
	ID       finding.CheckID
	Severity finding.Severity
	Mode     finding.ScanMode
}

// Check creates a CheckDecl for use with RegisterWithChecks.
func Check(id finding.CheckID, severity finding.Severity, mode finding.ScanMode) CheckDecl {
	return CheckDecl{ID: id, Severity: severity, Mode: mode}
}

// RegisteredChecks returns all check declarations from all scanners that
// used RegisterWithChecks. Returns a flat slice of CheckDecl.
func RegisteredChecks() []CheckDecl {
	mu.RLock()
	defer mu.RUnlock()
	var all []CheckDecl
	for _, reg := range registry {
		all = append(all, reg.checks...)
	}
	return all
}

// MergeChecksIntoRegistry adds all scanner-declared checks into the
// finding.Registry map. Existing entries are NOT overwritten — scanner
// declarations only fill gaps. This allows gradual migration from the
// hand-maintained Registry to scanner self-declaration.
func MergeChecksIntoRegistry() {
	for _, decl := range RegisteredChecks() {
		if _, exists := finding.Registry[decl.ID]; !exists {
			finding.Registry[decl.ID] = finding.CheckMeta{
				CheckID:         decl.ID,
				DefaultSeverity: decl.Severity,
				Mode:            decl.Mode,
			}
		}
	}
}
