// Package cloud is a Phase 3 stub for the Cloud Posture scan module.
// It will scan AWS, GCP, and Azure environments using prowler.
package cloud

import (
	"context"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Name() string                       { return "cloud" }
func (m *Module) RequiredInputs() []module.InputType { return []module.InputType{module.InputCloud} }

func (m *Module) Run(_ context.Context, _ module.Input, _ module.ScanType) ([]finding.Finding, error) {
	// Phase 3: implement prowler-based cloud posture scanning
	return nil, nil
}
