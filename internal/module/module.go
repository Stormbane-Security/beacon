package module

import (
	"context"

	"github.com/stormbane/beacon/internal/finding"
)

// PricingTier controls which modules a user can run.
type PricingTier int

const (
	TierFree    PricingTier = iota // Surface passive scan
	TierBasic                      // + GitHub/CI
	TierPro                        // + IaC
	TierPremium                    // + Cloud + Kubernetes
)

// InputType declares what kind of input a module requires.
type InputType string

const (
	InputDomain     InputType = "domain"
	InputGitHub     InputType = "github"
	InputIaC        InputType = "iac"
	InputCloud      InputType = "cloud"
	InputKubernetes InputType = "kubernetes"
)

// ScanType controls depth: surface is passive-only, deep adds active probing.
type ScanType string

const (
	ScanSurface ScanType = "surface"
	ScanDeep    ScanType = "deep"
)

// Module is the interface every scan module must implement.
type Module interface {
	// Name returns the stable module identifier (e.g., "surface", "github").
	Name() string

	// Tier returns the minimum pricing tier required to run this module.
	Tier() PricingTier

	// RequiredInputs returns the input types this module needs populated.
	RequiredInputs() []InputType

	// Run executes the module against the given input and returns findings.
	// Scanners within a module run concurrently. The module is responsible
	// for respecting ctx cancellation and scan type constraints.
	Run(ctx context.Context, input Input, scanType ScanType) ([]finding.Finding, error)
}
