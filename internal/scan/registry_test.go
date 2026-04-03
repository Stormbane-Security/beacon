package scan

import (
	"testing"
)

func TestRegistryBuildAndNames(t *testing.T) {
	// Reset registry for test isolation.
	mu.Lock()
	saved := registry
	registry = map[string]*registration{}
	mu.Unlock()
	defer func() {
		mu.Lock()
		registry = saved
		mu.Unlock()
	}()

	Register("alpha", func(cfg ScannerConfig) Scanner {
		return &stubScanner{name: "alpha"}
	})
	RegisterWithChecks("beta", func(cfg ScannerConfig) Scanner {
		return &stubScanner{name: "beta"}
	}, "web.beta_check")

	if Registered() != 2 {
		t.Fatalf("Registered() = %d, want 2", Registered())
	}

	names := Names()
	if len(names) != 2 || names[0] != "alpha" || names[1] != "beta" {
		t.Errorf("Names() = %v, want [alpha beta]", names)
	}

	cfg := MapConfig{"key": "val"}
	scanners := Build(cfg)
	if len(scanners) != 2 {
		t.Fatalf("Build() returned %d scanners, want 2", len(scanners))
	}
	if scanners["alpha"].Name() != "alpha" {
		t.Errorf("alpha scanner name = %q", scanners["alpha"].Name())
	}

	checks := CheckIDs()
	if len(checks) != 1 {
		t.Fatalf("CheckIDs() returned %d entries, want 1", len(checks))
	}
	if checks["beta"][0] != "web.beta_check" {
		t.Errorf("beta check IDs = %v", checks["beta"])
	}
}

func TestRegistryDuplicatePanics(t *testing.T) {
	mu.Lock()
	saved := registry
	registry = map[string]*registration{}
	mu.Unlock()
	defer func() {
		mu.Lock()
		registry = saved
		mu.Unlock()
	}()

	Register("dup", func(cfg ScannerConfig) Scanner { return &stubScanner{name: "dup"} })

	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on duplicate registration")
		}
	}()
	Register("dup", func(cfg ScannerConfig) Scanner { return &stubScanner{name: "dup"} })
}

func TestMapConfig(t *testing.T) {
	cfg := MapConfig{"shodan.api_key": "test123"}
	if cfg.Get("shodan.api_key") != "test123" {
		t.Error("MapConfig.Get failed")
	}
	if cfg.Get("missing") != "" {
		t.Error("MapConfig.Get should return empty for missing keys")
	}
}

func TestHas(t *testing.T) {
	mu.Lock()
	saved := registry
	registry = map[string]*registration{}
	mu.Unlock()
	defer func() {
		mu.Lock()
		registry = saved
		mu.Unlock()
	}()

	Register("exists", func(cfg ScannerConfig) Scanner { return &stubScanner{name: "exists"} })

	if !Has("exists") {
		t.Error("Has(exists) should be true")
	}
	if Has("nope") {
		t.Error("Has(nope) should be false")
	}
}
