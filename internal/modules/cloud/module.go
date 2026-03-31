// Package cloud implements the Beacon cloud posture scan module.
// It runs authenticated checks against GCP, AWS, and Azure using the
// credentials provided in the scan Input.
//
// Build tags control which providers are compiled into the binary:
//
//	default (no tags)      → all providers included
//	-tags no_cloud         → no cloud providers (smallest binary)
//	-tags no_cloud_aws     → exclude AWS only
//	-tags no_cloud_gcp     → exclude GCP only
//	-tags no_cloud_azure   → exclude Azure only
//
// Individual scanner packages (internal/scanner/cloud/aws, etc.) do NOT
// need build tags — they are only reachable through the provider files in
// this package, so excluding a provider file here is sufficient to exclude
// its entire SDK dependency tree from the binary.
package cloud

import (
	"context"
	"fmt"
	"log"
	"sort"
	"sync"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

// providerFunc runs a cloud provider's scanner and returns findings.
type providerFunc func(ctx context.Context, inp module.Input, scanType module.ScanType) ([]finding.Finding, error)

var (
	providersMu sync.RWMutex
	providers   = map[string]providerFunc{}
)

// registerProvider is called by provider_*.go init() functions to register
// a cloud provider scanner. Only providers whose files pass build tag
// constraints will be registered.
func registerProvider(name string, fn providerFunc) {
	providersMu.Lock()
	defer providersMu.Unlock()
	providers[name] = fn
}

// RegisteredProviders returns the names of all compiled-in cloud providers.
// Useful for diagnostics and the --help output.
func RegisteredProviders() []string {
	providersMu.RLock()
	defer providersMu.RUnlock()
	names := make([]string, 0, len(providers))
	for name := range providers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Module runs cloud posture checks across registered providers.
type Module struct{}

// New creates a cloud module.
func New() *Module { return &Module{} }

// Name implements module.Module.
func (m *Module) Name() string { return "cloud" }

// RequiredInputs implements module.Module.
func (m *Module) RequiredInputs() []module.InputType { return []module.InputType{module.InputCloud} }

// Run implements module.Module.
// It runs whichever cloud scanners are compiled in and have credentials available.
func (m *Module) Run(ctx context.Context, inp module.Input, scanType module.ScanType) ([]finding.Finding, error) {
	providersMu.RLock()
	defer providersMu.RUnlock()

	if len(providers) == 0 {
		return nil, fmt.Errorf("no cloud providers compiled in (binary built with cloud exclusion tags)")
	}

	var all []finding.Finding

	// Run providers in sorted order for deterministic output.
	names := make([]string, 0, len(providers))
	for name := range providers {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		fn := providers[name]
		findings, err := fn(ctx, inp, scanType)
		if err != nil {
			log.Printf("[cloud] %s scanner error: %v", name, err)
			continue
		}
		all = append(all, findings...)
	}

	return all, nil
}
