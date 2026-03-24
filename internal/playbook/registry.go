package playbook

import (
	"embed"
	"fmt"
	"io/fs"
	"path/filepath"
)

//go:embed playbooks/*.yaml
var playbookFS embed.FS

// Registry holds all loaded playbooks indexed by name.
type Registry struct {
	playbooks []*Playbook
	byName    map[string]*Playbook
}

// Load reads all YAML files from the embedded playbooks/ directory
// and returns a populated Registry.
func Load() (*Registry, error) {
	r := &Registry{
		byName: make(map[string]*Playbook),
	}

	entries, err := fs.ReadDir(playbookFS, "playbooks")
	if err != nil {
		return nil, fmt.Errorf("read playbooks dir: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}

		data, err := playbookFS.ReadFile("playbooks/" + entry.Name())
		if err != nil {
			return nil, fmt.Errorf("read playbook %s: %w", entry.Name(), err)
		}

		p, err := ParsePlaybook(data)
		if err != nil {
			return nil, fmt.Errorf("parse playbook %s: %w", entry.Name(), err)
		}
		if p.Name == "" {
			return nil, fmt.Errorf("playbook %s has no name", entry.Name())
		}
		if _, exists := r.byName[p.Name]; exists {
			return nil, fmt.Errorf("duplicate playbook name %q in %s", p.Name, entry.Name())
		}

		r.playbooks = append(r.playbooks, p)
		r.byName[p.Name] = p
	}

	return r, nil
}

// Match returns all playbooks that apply to the given asset evidence.
// The baseline playbook (match: always) is always first if present.
func (r *Registry) Match(e Evidence) []*Playbook {
	var matched []*Playbook
	// Baseline first
	if b, ok := r.byName["baseline"]; ok && b.Matches(e) {
		matched = append(matched, b)
	}
	for _, p := range r.playbooks {
		if p.Name == "baseline" {
			continue
		}
		if p.Matches(e) {
			matched = append(matched, p)
		}
	}
	return matched
}

// All returns every registered playbook.
func (r *Registry) All() []*Playbook {
	return r.playbooks
}

// Get returns a playbook by name, or nil if not found.
func (r *Registry) Get(name string) *Playbook {
	return r.byName[name]
}
