package recon

import (
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Scope defines in-scope and out-of-scope patterns for a bug bounty program.
// Patterns support wildcards: *.example.com matches any subdomain of example.com.
type Scope struct {
	InScope    []string `yaml:"in_scope" json:"in_scope"`
	OutOfScope []string `yaml:"out_of_scope" json:"out_of_scope"`
}

// IsInScope returns true if domain matches at least one in-scope pattern
// and does not match any out-of-scope pattern.
func (s *Scope) IsInScope(domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false
	}

	// Strip scheme if present (handle URLs passed as domains).
	domain = stripScheme(domain)
	// Strip port if present.
	if idx := strings.LastIndex(domain, ":"); idx > 0 {
		domain = domain[:idx]
	}
	// Strip trailing path.
	if idx := strings.Index(domain, "/"); idx > 0 {
		domain = domain[:idx]
	}

	// Check out-of-scope first — explicit exclusions take priority.
	for _, pattern := range s.OutOfScope {
		if matchPattern(strings.ToLower(pattern), domain) {
			return false
		}
	}

	// Check in-scope.
	for _, pattern := range s.InScope {
		if matchPattern(strings.ToLower(pattern), domain) {
			return true
		}
	}

	return false
}

// FilterInScope returns only the targets that pass the scope check.
func (s *Scope) FilterInScope(targets []string) []string {
	var out []string
	for _, t := range targets {
		if s.IsInScope(t) {
			out = append(out, t)
		}
	}
	return out
}

// matchPattern checks if domain matches a glob-style pattern.
// Supports:
//   - *.example.com  — matches any subdomain of example.com (and example.com itself)
//   - example.com    — exact match
//   - *.api.example.com — matches sub.api.example.com
func matchPattern(pattern, domain string) bool {
	if pattern == domain {
		return true
	}

	if strings.HasPrefix(pattern, "*.") {
		// Wildcard: *.example.com
		suffix := pattern[1:] // .example.com
		base := pattern[2:]   // example.com

		// Match the base domain itself.
		if domain == base {
			return true
		}
		// Match any subdomain.
		if strings.HasSuffix(domain, suffix) {
			return true
		}
	}

	return false
}

// stripScheme removes http:// or https:// from a string.
func stripScheme(s string) string {
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	return s
}

// LoadScopeFile reads a .scope.yaml file and returns the scope definition.
// The file format is:
//
//	in_scope:
//	  - "*.example.com"
//	  - "api.example.com"
//	out_of_scope:
//	  - "staging.example.com"
//	  - "*.internal.example.com"
func LoadScopeFile(path string) (*Scope, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Scope
	if err := yaml.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// FindScopeFile searches for a .scope.yaml file in the current directory
// and then in ~/.beacon/. Returns the path if found, or empty string.
func FindScopeFile() string {
	// Current directory.
	if _, err := os.Stat(".scope.yaml"); err == nil {
		return ".scope.yaml"
	}

	// ~/.beacon/.scope.yaml
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	p := filepath.Join(homeDir, ".beacon", ".scope.yaml")
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return ""
}

// ScopeFromPatterns creates a Scope from explicit in-scope and out-of-scope
// pattern slices. Useful when constructing scope from bug bounty platform data.
func ScopeFromPatterns(inScope, outOfScope []string) *Scope {
	return &Scope{
		InScope:    inScope,
		OutOfScope: outOfScope,
	}
}
