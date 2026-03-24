// Package iac is a Phase 2 stub for the Infrastructure-as-Code scan module.
// It will scan Terraform and Kubernetes manifests using trivy.
package iac

import (
	"context"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Name() string                       { return "iac" }
func (m *Module) Tier() module.PricingTier           { return module.TierPro }
func (m *Module) RequiredInputs() []module.InputType { return []module.InputType{module.InputIaC} }

func (m *Module) Run(_ context.Context, _ module.Input, _ module.ScanType) ([]finding.Finding, error) {
	// Phase 2: implement trivy IaC scanning
	return nil, nil
}
