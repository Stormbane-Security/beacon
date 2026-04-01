// Package onprem implements the Beacon on-premises infrastructure scan module.
// It runs authenticated checks against hypervisors, container engines,
// orchestrators, network devices, and NAS appliances using credentials
// provided in the scan Input.
//
// Build tags control which scanners are compiled into the binary:
//
//	default (no tags)          → all scanners included
//	-tags no_onprem            → no on-prem scanners
//	-tags no_onprem_proxmox    → exclude Proxmox only
//	-tags no_onprem_docker     → exclude Docker only
//	-tags no_onprem_kubernetes → exclude Kubernetes only
//	-tags no_onprem_vmware     → exclude VMware only
//	-tags no_onprem_network    → exclude network discovery only
//	-tags no_onprem_nas        → exclude NAS only
//	-tags no_onprem_libvirt    → exclude libvirt only
package onprem

import (
	"context"
	"fmt"
	"log"
	"sort"
	"sync"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)

// scannerFunc runs an on-prem scanner and returns findings.
type scannerFunc func(ctx context.Context, inp module.Input, scanType module.ScanType) ([]finding.Finding, error)

var (
	scannersMu sync.RWMutex
	scanners   = map[string]scannerFunc{}
)

// registerScanner is called by scanner_*.go init() functions.
func registerScanner(name string, fn scannerFunc) {
	scannersMu.Lock()
	defer scannersMu.Unlock()
	scanners[name] = fn
}

// RegisteredScanners returns the names of all compiled-in on-prem scanners.
func RegisteredScanners() []string {
	scannersMu.RLock()
	defer scannersMu.RUnlock()
	names := make([]string, 0, len(scanners))
	for name := range scanners {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Module runs on-prem infrastructure checks across registered scanners.
type Module struct{}

// New creates an on-prem module.
func New() *Module { return &Module{} }

// Name implements module.Module.
func (m *Module) Name() string { return "onprem" }

// RequiredInputs implements module.Module.
func (m *Module) RequiredInputs() []module.InputType { return []module.InputType{module.InputOnPrem} }

// Run implements module.Module.
// It runs whichever on-prem scanners are compiled in and have
// configuration available. All scanners run concurrently.
func (m *Module) Run(ctx context.Context, inp module.Input, scanType module.ScanType) ([]finding.Finding, error) {
	scannersMu.RLock()
	defer scannersMu.RUnlock()

	if len(scanners) == 0 {
		return nil, fmt.Errorf("no on-prem scanners compiled in")
	}

	// Only run scanners that have configuration provided.
	active := map[string]scannerFunc{}
	for name, fn := range scanners {
		if scannerHasConfig(name, inp) {
			active[name] = fn
		}
	}

	if len(active) == 0 {
		return nil, nil // no on-prem targets configured
	}

	names := make([]string, 0, len(active))
	for name := range active {
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
		go func(idx int, scanName string, fn scannerFunc) {
			defer wg.Done()
			findings, err := fn(ctx, inp, scanType)
			results[idx] = result{name: scanName, findings: findings, err: err}
		}(i, name, active[name])
	}
	wg.Wait()

	var all []finding.Finding
	for _, r := range results {
		if r.err != nil {
			log.Printf("[onprem] %s scanner error: %v", r.name, r.err)
			continue
		}
		all = append(all, r.findings...)
	}

	return all, nil
}

// scannerHasConfig returns true if the scanner has enough configuration to run.
func scannerHasConfig(name string, inp module.Input) bool {
	switch name {
	case "proxmox":
		return inp.ProxmoxEndpoint != ""
	case "docker":
		return inp.DockerEndpoint != ""
	case "kubernetes":
		return inp.KubeconfigPath != ""
	case "vmware":
		return inp.VMwareEndpoint != ""
	case "libvirt":
		return inp.LibvirtEndpoint != ""
	case "network":
		return len(inp.NetworkTargets) > 0
	case "nas":
		return inp.NASEndpoint != ""
	default:
		return false
	}
}
