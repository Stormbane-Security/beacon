package surface

import (
	"testing"

	"github.com/stormbane-security/beacon/internal/playbook"
)

// TestAllPlaybookScanners_RegisteredInModule verifies that every scanner name
// referenced in any embedded playbook (surface or deep) has a corresponding
// entry in the module's scanner map. A mismatch means the playbook references
// a scanner that will silently never run.
func TestAllPlaybookScanners_RegisteredInModule(t *testing.T) {
	m, err := New(Config{})
	if err != nil {
		t.Fatalf("surface.New: %v", err)
	}

	reg, err := playbook.Load()
	if err != nil {
		t.Fatalf("playbook.Load: %v", err)
	}

	for _, pb := range reg.All() {
		for _, name := range pb.Surface.Scanners {
			if _, ok := m.scanners[name]; !ok {
				t.Errorf("playbook %q references surface scanner %q which is not registered in the module scanner map", pb.Name, name)
			}
		}
		for _, name := range pb.Deep.Scanners {
			if _, ok := m.scanners[name]; !ok {
				t.Errorf("playbook %q references deep scanner %q which is not registered in the module scanner map", pb.Name, name)
			}
		}
	}
}

// TestSecheaders_InBaselineSurface verifies secheaders is wired into the
// baseline surface scanner list specifically (not just any playbook).
func TestSecheaders_InBaselineSurface(t *testing.T) {
	reg, err := playbook.Load()
	if err != nil {
		t.Fatalf("playbook.Load: %v", err)
	}

	baseline := reg.Get("baseline")
	if baseline == nil {
		t.Fatal("baseline playbook not found")
	}

	for _, s := range baseline.Surface.Scanners {
		if s == "secheaders" {
			return
		}
	}
	t.Error("secheaders scanner is not in baseline.yaml surface scanners — it will not run on most assets")
}
