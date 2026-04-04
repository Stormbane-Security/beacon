package cloud

import (
	"testing"

	"github.com/stormbane-security/beacon/internal/module"
)

func TestModule_Name(t *testing.T) {
	m := New()
	if m.Name() != "cloud" {
		t.Errorf("Name() = %q; want cloud", m.Name())
	}
}

func TestModule_RequiredInputs(t *testing.T) {
	m := New()
	inputs := m.RequiredInputs()
	if len(inputs) != 1 || inputs[0] != module.InputCloud {
		t.Errorf("RequiredInputs() = %v; want [InputCloud]", inputs)
	}
}

func TestRegisteredProviders_NotEmpty(t *testing.T) {
	names := RegisteredProviders()
	if len(names) == 0 {
		t.Error("expected at least one registered cloud provider")
	}
}

func TestRegisteredProviders_Sorted(t *testing.T) {
	names := RegisteredProviders()
	for i := 1; i < len(names); i++ {
		if names[i] < names[i-1] {
			t.Errorf("providers not sorted: %v", names)
			break
		}
	}
}

func TestRegisteredProviders_KnownProviders(t *testing.T) {
	names := RegisteredProviders()
	expected := map[string]bool{"aws": false, "gcp": false, "azure": false}
	for _, n := range names {
		if _, ok := expected[n]; ok {
			expected[n] = true
		}
	}
	for name, found := range expected {
		if !found {
			t.Errorf("expected provider %q to be registered", name)
		}
	}
}
