package scan

import (
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
)

func TestRegisterWithCheckDecls(t *testing.T) {
	// Reset registry for test isolation.
	mu.Lock()
	saved := registry
	registry = map[string]*registration{}
	mu.Unlock()
	defer func() {
		mu.Lock()
		registry = saved
		mu.Unlock()
	}()

	RegisterWithCheckDecls("testscanner", func(_ ScannerConfig) Scanner {
		return &stubScanner{name: "testscanner"}
	},
		Check("test.check_one", finding.SeverityHigh, finding.ModeDeep),
		Check("test.check_two", finding.SeverityInfo, finding.ModeSurface),
	)

	checks := RegisteredChecks()
	if len(checks) != 2 {
		t.Fatalf("RegisteredChecks() = %d, want 2", len(checks))
	}
	if checks[0].ID != "test.check_one" {
		t.Errorf("checks[0].ID = %q, want test.check_one", checks[0].ID)
	}
	if checks[0].Severity != finding.SeverityHigh {
		t.Errorf("checks[0].Severity = %d, want High", checks[0].Severity)
	}

	// Verify CheckIDs also returns the string IDs
	ids := CheckIDs()
	if len(ids["testscanner"]) != 2 {
		t.Errorf("CheckIDs[testscanner] = %v, want 2 entries", ids["testscanner"])
	}
}

func TestMergeChecksIntoRegistry(t *testing.T) {
	mu.Lock()
	saved := registry
	registry = map[string]*registration{}
	mu.Unlock()
	defer func() {
		mu.Lock()
		registry = saved
		mu.Unlock()
	}()

	// Register a scanner with a new check ID not in the existing Registry
	RegisterWithCheckDecls("mergescanner", func(_ ScannerConfig) Scanner {
		return &stubScanner{name: "mergescanner"}
	},
		Check("test.merge_only", finding.SeverityCritical, finding.ModeDeep),
	)

	// Verify it's not in Registry yet
	if _, ok := finding.Registry["test.merge_only"]; ok {
		t.Fatal("test.merge_only should not be in Registry before merge")
	}

	MergeChecksIntoRegistry()

	meta, ok := finding.Registry["test.merge_only"]
	if !ok {
		t.Fatal("test.merge_only not found in Registry after merge")
	}
	if meta.DefaultSeverity != finding.SeverityCritical {
		t.Errorf("severity = %d, want Critical", meta.DefaultSeverity)
	}

	// Clean up
	delete(finding.Registry, "test.merge_only")
}
