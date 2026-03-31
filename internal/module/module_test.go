package module

import (
	"context"
	"testing"

	"github.com/stormbane/beacon/internal/finding"
)

// stubModule is a minimal Module implementation for registry tests.
type stubModule struct {
	name     string
	required []InputType
}

func (s *stubModule) Name() string              { return s.name }
func (s *stubModule) RequiredInputs() []InputType { return s.required }
func (s *stubModule) Run(_ context.Context, _ Input, _ ScanType) ([]finding.Finding, error) {
	return nil, nil
}

// saveAndRestoreRegistry snapshots the global registry and returns a cleanup
// function that restores it. Every test that calls Register must use this.
func saveAndRestoreRegistry(t *testing.T) {
	t.Helper()
	prev := registered
	t.Cleanup(func() { registered = prev })
	registered = nil
}

// ---------- inputSatisfied tests ----------

func TestInputSatisfied_Domain(t *testing.T) {
	tests := []struct {
		name  string
		input Input
		want  bool
	}{
		{"domain set", Input{Domain: "example.com"}, true},
		{"domain empty", Input{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inputSatisfied([]InputType{InputDomain}, tt.input)
			if got != tt.want {
				t.Errorf("inputSatisfied(InputDomain, %+v) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestInputSatisfied_GitHub(t *testing.T) {
	tests := []struct {
		name  string
		input Input
		want  bool
	}{
		{"org set", Input{GitHubOrg: "stormbane"}, true},
		{"repo set", Input{GitHubRepo: "stormbane/beacon"}, true},
		{"both set", Input{GitHubOrg: "stormbane", GitHubRepo: "beacon"}, true},
		{"neither set", Input{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inputSatisfied([]InputType{InputGitHub}, tt.input)
			if got != tt.want {
				t.Errorf("inputSatisfied(InputGitHub, %+v) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestInputSatisfied_IaC(t *testing.T) {
	tests := []struct {
		name  string
		input Input
		want  bool
	}{
		{"path set", Input{IaCRepoPath: "/tmp/repo"}, true},
		{"path empty", Input{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inputSatisfied([]InputType{InputIaC}, tt.input)
			if got != tt.want {
				t.Errorf("inputSatisfied(InputIaC, %+v) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestInputSatisfied_Cloud(t *testing.T) {
	tests := []struct {
		name  string
		input Input
		want  bool
	}{
		{"cloud enabled", Input{CloudEnabled: true}, true},
		{"aws profile", Input{AWSProfile: "default"}, true},
		{"gcp creds", Input{GCPCredentialsFile: "/tmp/creds.json"}, true},
		{"azure sub", Input{AzureSubscriptionID: "sub-123"}, true},
		{"nothing set", Input{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inputSatisfied([]InputType{InputCloud}, tt.input)
			if got != tt.want {
				t.Errorf("inputSatisfied(InputCloud, %+v) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestInputSatisfied_Kubernetes(t *testing.T) {
	tests := []struct {
		name  string
		input Input
		want  bool
	}{
		{"kubeconfig set", Input{KubeconfigPath: "/home/user/.kube/config"}, true},
		{"kubeconfig empty", Input{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inputSatisfied([]InputType{InputKubernetes}, tt.input)
			if got != tt.want {
				t.Errorf("inputSatisfied(InputKubernetes, %+v) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestInputSatisfied_MultipleRequirements(t *testing.T) {
	// Module requires both Domain and GitHub — both must be satisfied.
	required := []InputType{InputDomain, InputGitHub}

	tests := []struct {
		name  string
		input Input
		want  bool
	}{
		{"both satisfied", Input{Domain: "example.com", GitHubOrg: "stormbane"}, true},
		{"only domain", Input{Domain: "example.com"}, false},
		{"only github", Input{GitHubOrg: "stormbane"}, false},
		{"neither", Input{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inputSatisfied(required, tt.input)
			if got != tt.want {
				t.Errorf("inputSatisfied(%v, %+v) = %v, want %v", required, tt.input, got, tt.want)
			}
		})
	}
}

func TestInputSatisfied_EmptyRequirements(t *testing.T) {
	// A module with no required inputs is always satisfied.
	got := inputSatisfied(nil, Input{})
	if !got {
		t.Error("inputSatisfied(nil, empty) should return true")
	}
}

// ---------- Register / All / Get tests ----------

func TestRegister_And_All(t *testing.T) {
	saveAndRestoreRegistry(t)

	if len(All()) != 0 {
		t.Fatal("registry should start empty in test")
	}

	m1 := &stubModule{name: "alpha", required: []InputType{InputDomain}}
	m2 := &stubModule{name: "beta", required: []InputType{InputGitHub}}
	Register(m1)
	Register(m2)

	all := All()
	if len(all) != 2 {
		t.Fatalf("All() returned %d modules, want 2", len(all))
	}
	if all[0].Name() != "alpha" || all[1].Name() != "beta" {
		t.Errorf("All() = [%s, %s], want [alpha, beta]", all[0].Name(), all[1].Name())
	}
}

func TestGet_Found(t *testing.T) {
	saveAndRestoreRegistry(t)

	Register(&stubModule{name: "surface", required: []InputType{InputDomain}})
	Register(&stubModule{name: "github", required: []InputType{InputGitHub}})

	m, err := Get("github")
	if err != nil {
		t.Fatalf("Get(github): unexpected error: %v", err)
	}
	if m.Name() != "github" {
		t.Errorf("Get(github).Name() = %s, want github", m.Name())
	}
}

func TestGet_NotFound(t *testing.T) {
	saveAndRestoreRegistry(t)

	_, err := Get("nonexistent")
	if err == nil {
		t.Fatal("Get(nonexistent) should return error")
	}
}

func TestGet_EmptyRegistry(t *testing.T) {
	saveAndRestoreRegistry(t)

	_, err := Get("anything")
	if err == nil {
		t.Fatal("Get on empty registry should return error")
	}
}

// ---------- ForInputs tests ----------

func TestForInputs_FiltersCorrectly(t *testing.T) {
	saveAndRestoreRegistry(t)

	Register(&stubModule{name: "surface", required: []InputType{InputDomain}})
	Register(&stubModule{name: "github", required: []InputType{InputGitHub}})
	Register(&stubModule{name: "cloud", required: []InputType{InputCloud}})
	Register(&stubModule{name: "combo", required: []InputType{InputDomain, InputGitHub}})

	// Input with domain only — should match "surface" only.
	mods := ForInputs(Input{Domain: "example.com"})
	if len(mods) != 1 || mods[0].Name() != "surface" {
		names := moduleNames(mods)
		t.Errorf("ForInputs(domain only) = %v, want [surface]", names)
	}

	// Input with domain + github — should match "surface", "github", and "combo".
	mods = ForInputs(Input{Domain: "example.com", GitHubOrg: "stormbane"})
	if len(mods) != 3 {
		names := moduleNames(mods)
		t.Errorf("ForInputs(domain+github) = %v, want [surface, github, combo]", names)
	}

	// Input with nothing — should match nothing.
	mods = ForInputs(Input{})
	if len(mods) != 0 {
		names := moduleNames(mods)
		t.Errorf("ForInputs(empty) = %v, want []", names)
	}
}

func TestForInputs_ModuleWithNoRequirements(t *testing.T) {
	saveAndRestoreRegistry(t)

	Register(&stubModule{name: "universal", required: nil})

	// A module with no requirements should match any input, even empty.
	mods := ForInputs(Input{})
	if len(mods) != 1 || mods[0].Name() != "universal" {
		names := moduleNames(mods)
		t.Errorf("ForInputs(empty) with universal module = %v, want [universal]", names)
	}
}

func moduleNames(mods []Module) []string {
	names := make([]string, len(mods))
	for i, m := range mods {
		names[i] = m.Name()
	}
	return names
}
