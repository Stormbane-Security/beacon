package scan

import (
	"fmt"
	"sort"
	"sync"
)

// ScannerConfig provides scanner factories with access to API keys,
// binary paths, and other configuration needed at construction time.
type ScannerConfig interface {
	// Get returns the value for a named config key, or "" if unset.
	// Keys use dot-separated namespaces: "shodan.api_key", "nmap.bin", etc.
	Get(key string) string
}

// Factory creates a Scanner instance given configuration.
// Factories are registered via Register() in scanner init() functions.
type Factory func(cfg ScannerConfig) Scanner

// registration holds a factory and its metadata.
type registration struct {
	factory  Factory
	checkIDs []string
	checks   []CheckDecl
}

var (
	mu       sync.RWMutex
	registry = map[string]*registration{}
)

// Register adds a scanner factory to the global registry.
// Called from scanner init() functions. Panics on duplicate names.
//
//	func init() {
//	    scan.Register("cors", func(cfg scan.ScannerConfig) scan.Scanner {
//	        return New()
//	    })
//	}
func Register(name string, factory Factory) {
	mu.Lock()
	defer mu.Unlock()
	if _, exists := registry[name]; exists {
		panic(fmt.Sprintf("scan: duplicate scanner registration: %q", name))
	}
	registry[name] = &registration{factory: factory}
}

// RegisterWithChecks adds a scanner factory along with the check IDs it produces.
// This enables R3 (check ID codegen) — the registry becomes the source of truth
// for which scanners emit which findings.
//
//	func init() {
//	    scan.RegisterWithChecks("cors", corsFactory,
//	        "web.cors_wildcard_origin",
//	        "web.cors_null_origin",
//	    )
//	}
func RegisterWithChecks(name string, factory Factory, checkIDs ...string) {
	mu.Lock()
	defer mu.Unlock()
	if _, exists := registry[name]; exists {
		panic(fmt.Sprintf("scan: duplicate scanner registration: %q", name))
	}
	registry[name] = &registration{factory: factory, checkIDs: checkIDs}
}

// Build creates all registered scanners using the given config.
// Returns a map from scanner name to Scanner instance.
func Build(cfg ScannerConfig) map[string]Scanner {
	mu.RLock()
	defer mu.RUnlock()
	scanners := make(map[string]Scanner, len(registry))
	for name, reg := range registry {
		scanners[name] = reg.factory(cfg)
	}
	return scanners
}

// Names returns the sorted list of all registered scanner names.
func Names() []string {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// RegisterWithCheckDecls adds a scanner factory with fully typed check
// declarations (ID + severity + mode). These declarations are merged into
// finding.Registry at startup via MergeChecksIntoRegistry.
//
//	func init() {
//	    scan.RegisterWithCheckDecls("cors", corsFactory,
//	        scan.Check("web.cors_wildcard_origin", finding.SeverityHigh, finding.ModeDeep),
//	    )
//	}
func RegisterWithCheckDecls(name string, factory Factory, checks ...CheckDecl) {
	mu.Lock()
	defer mu.Unlock()
	if _, exists := registry[name]; exists {
		panic(fmt.Sprintf("scan: duplicate scanner registration: %q", name))
	}
	ids := make([]string, len(checks))
	for i, c := range checks {
		ids[i] = string(c.ID)
	}
	registry[name] = &registration{factory: factory, checkIDs: ids, checks: checks}
}

// CheckIDs returns all check IDs registered by all scanners, keyed by
// scanner name. Only includes scanners registered with RegisterWithChecks.
func CheckIDs() map[string][]string {
	mu.RLock()
	defer mu.RUnlock()
	result := make(map[string][]string)
	for name, reg := range registry {
		if len(reg.checkIDs) > 0 {
			result[name] = reg.checkIDs
		}
	}
	return result
}

// Registered returns the number of registered scanners.
func Registered() int {
	mu.RLock()
	defer mu.RUnlock()
	return len(registry)
}

// Has returns true if a scanner with the given name is registered.
func Has(name string) bool {
	mu.RLock()
	defer mu.RUnlock()
	_, ok := registry[name]
	return ok
}

// MapConfig adapts a simple map[string]string into a ScannerConfig.
type MapConfig map[string]string

func (m MapConfig) Get(key string) string { return m[key] }
