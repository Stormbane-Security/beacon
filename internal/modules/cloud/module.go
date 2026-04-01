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

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
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
// It runs whichever cloud scanners are compiled in and have credentials
// available. All providers run concurrently; individual provider errors
// are logged but do not abort the module.
func (m *Module) Run(ctx context.Context, inp module.Input, scanType module.ScanType) ([]finding.Finding, error) {
	providersMu.RLock()
	defer providersMu.RUnlock()

	if len(providers) == 0 {
		return nil, fmt.Errorf("no cloud providers compiled in (binary built with cloud exclusion tags)")
	}

	// Snapshot provider names for deterministic final ordering.
	names := make([]string, 0, len(providers))
	for name := range providers {
		names = append(names, name)
	}
	sort.Strings(names)

	type result struct {
		name     string
		findings []finding.Finding
		err      error
	}

	results := make([]result, len(names))
	var wg sync.WaitGroup
	for i, name := range names {
		wg.Add(1)
		go func(idx int, provName string, fn providerFunc) {
			defer wg.Done()
			findings, err := fn(ctx, inp, scanType)
			results[idx] = result{name: provName, findings: findings, err: err}
		}(i, name, providers[name])
	}
	wg.Wait()

	var all []finding.Finding
	for _, r := range results {
		if r.err != nil {
			log.Printf("[cloud] %s scanner error: %v", r.name, r.err)
			continue
		}
		all = append(all, r.findings...)
	}

	return all, nil
}
