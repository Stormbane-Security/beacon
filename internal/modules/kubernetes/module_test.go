package kubernetes

import (
	"context"
	"testing"

	"github.com/stormbane-security/beacon/internal/module"
)

func TestModule_Name(t *testing.T) {
	m := New()
	if m.Name() != "kubernetes" {
		t.Errorf("Name() = %q; want kubernetes", m.Name())
	}
}

func TestModule_RequiredInputs(t *testing.T) {
	m := New()
	inputs := m.RequiredInputs()
	if len(inputs) != 1 || inputs[0] != module.InputKubernetes {
		t.Errorf("RequiredInputs() = %v; want [InputKubernetes]", inputs)
	}
}

func TestModule_RunReturnsNil(t *testing.T) {
	m := New()
	findings, err := m.Run(context.Background(), module.Input{}, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	if findings != nil {
		t.Errorf("stub module should return nil findings, got %d", len(findings))
	}
}
