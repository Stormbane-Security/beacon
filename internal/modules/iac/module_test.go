package iac

import (
	"context"
	"testing"

	"github.com/stormbane-security/beacon/internal/module"
)

func TestModule_Name(t *testing.T) {
	m := New()
	if m.Name() != "iac" {
		t.Errorf("Name() = %q; want iac", m.Name())
	}
}

func TestModule_RequiredInputs(t *testing.T) {
	m := New()
	inputs := m.RequiredInputs()
	if len(inputs) != 1 || inputs[0] != module.InputIaC {
		t.Errorf("RequiredInputs() = %v; want [InputIaC]", inputs)
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
