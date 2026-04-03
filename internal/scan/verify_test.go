package scan_test

import (
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/scan"

	// Blank-import all scanner packages to trigger init() registration.
	// This test runs as part of `go test ./internal/scan/` and verifies
	// that all scanner-declared check IDs have Registry entries.
	_ "github.com/stormbane-security/beacon/internal/scanner/cors"
	_ "github.com/stormbane-security/beacon/internal/scanner/jwt"
)

func TestRegisteredCheckIDsHaveRegistryEntries(t *testing.T) {
	// Merge scanner-declared checks first
	scan.MergeChecksIntoRegistry()

	for _, decl := range scan.RegisteredChecks() {
		if _, ok := finding.Registry[decl.ID]; !ok {
			t.Errorf("scanner-declared check %q has no entry in finding.Registry", decl.ID)
		}
	}
}
