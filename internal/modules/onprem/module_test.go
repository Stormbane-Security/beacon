package onprem

import (
	"context"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)

func TestModule_Name(t *testing.T) {
	m := New()
	if m.Name() != "onprem" {
		t.Errorf("Name() = %q; want onprem", m.Name())
	}
}

func TestModule_RequiredInputs(t *testing.T) {
	m := New()
	inputs := m.RequiredInputs()
	if len(inputs) != 1 || inputs[0] != module.InputOnPrem {
		t.Errorf("RequiredInputs() = %v; want [InputOnPrem]", inputs)
	}
}

func TestRegisteredScanners_NotEmpty(t *testing.T) {
	names := RegisteredScanners()
	if len(names) == 0 {
		t.Error("expected at least one registered on-prem scanner")
	}
}

func TestRegisteredScanners_Sorted(t *testing.T) {
	names := RegisteredScanners()
	for i := 1; i < len(names); i++ {
		if names[i] < names[i-1] {
			t.Errorf("scanners not sorted: %v", names)
			break
		}
	}
}

func TestScannerHasConfig_Proxmox(t *testing.T) {
	if scannerHasConfig("proxmox", module.Input{}) {
		t.Error("proxmox should require ProxmoxEndpoint")
	}
	if !scannerHasConfig("proxmox", module.Input{ProxmoxEndpoint: "https://pve:8006"}) {
		t.Error("proxmox should accept non-empty ProxmoxEndpoint")
	}
}

func TestScannerHasConfig_Docker(t *testing.T) {
	if scannerHasConfig("docker", module.Input{}) {
		t.Error("docker should require DockerEndpoint")
	}
	if !scannerHasConfig("docker", module.Input{DockerEndpoint: "unix:///var/run/docker.sock"}) {
		t.Error("docker should accept non-empty DockerEndpoint")
	}
}

func TestScannerHasConfig_Network(t *testing.T) {
	if scannerHasConfig("network", module.Input{}) {
		t.Error("network should require NetworkTargets")
	}
	if !scannerHasConfig("network", module.Input{NetworkTargets: []string{"192.168.1.0/24"}}) {
		t.Error("network should accept non-empty NetworkTargets")
	}
}

func TestScannerHasConfig_Unknown(t *testing.T) {
	if scannerHasConfig("nonexistent", module.Input{}) {
		t.Error("unknown scanner should return false")
	}
}

func TestModule_NoConfig_ReturnsNil(t *testing.T) {
	m := New()
	findings, err := m.Run(context.Background(), module.Input{}, module.ScanDeep)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings with no config, got %d", len(findings))
	}
}

func TestModule_MockScanner(t *testing.T) {
	registerScanner("test-onprem", func(ctx context.Context, inp module.Input, scanType module.ScanType) ([]finding.Finding, error) {
		return []finding.Finding{{
			CheckID:  "onprem.test",
			Module:   "onprem",
			Scanner:  "test-onprem",
			Severity: finding.SeverityInfo,
			Title:    "test finding",
		}}, nil
	})
	defer func() {
		scannersMu.Lock()
		delete(scanners, "test-onprem")
		scannersMu.Unlock()
	}()

	// scannerHasConfig won't match "test-onprem", so add a config override
	// by directly using a known scanner name with config.
	// Instead, test that the scanner registry works by checking it's listed.
	names := RegisteredScanners()
	var found bool
	for _, n := range names {
		if n == "test-onprem" {
			found = true
		}
	}
	if !found {
		t.Error("test-onprem not found in registered scanners")
	}
}
