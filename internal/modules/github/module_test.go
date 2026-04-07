package github

import (
	"testing"

	"github.com/stormbane-security/beacon/internal/module"
)

func TestModule_Name(t *testing.T) {
	m := New("")
	if m.Name() != "github" {
		t.Errorf("Name() = %q; want github", m.Name())
	}
}

func TestModule_RequiredInputs(t *testing.T) {
	m := New("")
	inputs := m.RequiredInputs()
	if len(inputs) != 1 || inputs[0] != module.InputGitHub {
		t.Errorf("RequiredInputs() = %v; want [InputGitHub]", inputs)
	}
}

func TestResolveTarget_FullSlug(t *testing.T) {
	inp := module.Input{GitHubRepo: "org/repo"}
	target, err := resolveTarget(inp)
	if err != nil {
		t.Fatal(err)
	}
	if target != "org/repo" {
		t.Errorf("resolveTarget() = %q; want org/repo", target)
	}
}

func TestResolveTarget_OrgAndRepo(t *testing.T) {
	inp := module.Input{GitHubOrg: "myorg", GitHubRepo: "myrepo"}
	target, err := resolveTarget(inp)
	if err != nil {
		t.Fatal(err)
	}
	if target != "myorg/myrepo" {
		t.Errorf("resolveTarget() = %q; want myorg/myrepo", target)
	}
}

func TestResolveTarget_MissingOrg(t *testing.T) {
	inp := module.Input{GitHubRepo: "repo-only"}
	_, err := resolveTarget(inp)
	if err == nil {
		t.Error("expected error when org missing and repo is not a full slug")
	}
}

func TestResolveTarget_MissingRepo(t *testing.T) {
	inp := module.Input{GitHubOrg: "myorg"}
	_, err := resolveTarget(inp)
	if err == nil {
		t.Error("expected error when repo is empty")
	}
}

func TestResolveOrg_Direct(t *testing.T) {
	inp := module.Input{GitHubOrg: "myorg"}
	if org := resolveOrg(inp); org != "myorg" {
		t.Errorf("resolveOrg() = %q; want myorg", org)
	}
}

func TestResolveOrg_FromSlug(t *testing.T) {
	inp := module.Input{GitHubRepo: "owner/repo"}
	if org := resolveOrg(inp); org != "owner" {
		t.Errorf("resolveOrg() = %q; want owner", org)
	}
}

func TestResolveOrg_Empty(t *testing.T) {
	inp := module.Input{}
	if org := resolveOrg(inp); org != "" {
		t.Errorf("resolveOrg() = %q; want empty", org)
	}
}
