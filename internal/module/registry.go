package module

import "fmt"

var registered []Module

// Register adds a module to the global registry.
// Call from each module's init() function.
func Register(m Module) {
	registered = append(registered, m)
}

// All returns every registered module.
func All() []Module {
	return registered
}

// ForTier returns modules available at or below the given pricing tier.
func ForTier(tier PricingTier) []Module {
	var out []Module
	for _, m := range registered {
		if m.Tier() <= tier {
			out = append(out, m)
		}
	}
	return out
}

// ForInputs returns modules whose required inputs are all satisfied by the given input.
func ForInputs(input Input) []Module {
	var out []Module
	for _, m := range registered {
		if inputSatisfied(m.RequiredInputs(), input) {
			out = append(out, m)
		}
	}
	return out
}

// Get returns a module by name, or an error if not found.
func Get(name string) (Module, error) {
	for _, m := range registered {
		if m.Name() == name {
			return m, nil
		}
	}
	return nil, fmt.Errorf("module %q not registered", name)
}

func inputSatisfied(required []InputType, input Input) bool {
	for _, t := range required {
		switch t {
		case InputDomain:
			if input.Domain == "" {
				return false
			}
		case InputGitHub:
			if input.GitHubOrg == "" && input.GitHubRepo == "" {
				return false
			}
		case InputIaC:
			if input.IaCRepoPath == "" {
				return false
			}
		case InputCloud:
			if input.AWSProfile == "" && input.GCPCredentialsFile == "" && input.AzureSubscriptionID == "" {
				return false
			}
		case InputKubernetes:
			if input.KubeconfigPath == "" {
				return false
			}
		}
	}
	return true
}
