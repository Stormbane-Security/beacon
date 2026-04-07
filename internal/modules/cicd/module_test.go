package cicd

import (
	"context"
	"testing"

	"github.com/stormbane-security/beacon/internal/module"
)

func TestModule_Name(t *testing.T) {
	m := New()
	if m.Name() != "cicd" {
		t.Errorf("Name() = %q; want cicd", m.Name())
	}
}

func TestModule_RequiredInputs(t *testing.T) {
	m := New()
	inputs := m.RequiredInputs()
	if len(inputs) != 1 || inputs[0] != module.InputDomain {
		t.Errorf("RequiredInputs() = %v; want [InputDomain]", inputs)
	}
}

func TestModule_SkipsSurfaceMode(t *testing.T) {
	m := New()
	findings, err := m.Run(context.Background(), module.Input{Domain: "example.com"}, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings in surface mode, got %d", len(findings))
	}
}

func TestModule_RequiresDomain(t *testing.T) {
	m := New()
	_, err := m.Run(context.Background(), module.Input{}, module.ScanDeep)
	if err == nil {
		t.Error("expected error when domain is empty")
	}
}
