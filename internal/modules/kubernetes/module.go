// Package kubernetes is a Phase 3 stub for the Kubernetes scan module.
// It will audit clusters using kube-bench and kubescape.
package kubernetes

import (
	"context"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Name() string                       { return "kubernetes" }
func (m *Module) Tier() module.PricingTier           { return module.TierPremium }
func (m *Module) RequiredInputs() []module.InputType {
	return []module.InputType{module.InputKubernetes}
}

func (m *Module) Run(_ context.Context, _ module.Input, _ module.ScanType) ([]finding.Finding, error) {
	// Phase 3: implement kube-bench + kubescape scanning
	return nil, nil
}
