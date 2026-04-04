// Package nuclei implements a native Go engine for parsing and executing
// Nuclei YAML templates. This replaces the subprocess-based scanner for
// template execution while maintaining compatibility with the upstream
// nuclei-templates repository format.
//
// Templates are loaded from disk, indexed by tags/product/vendor metadata,
// and selected using a three-tier strategy:
//   - always: generic checks that run on every HTTP target (~500 templates)
//   - signal: checks that run when weak tech signals are present (~3000)
//   - targeted: checks that run on confirmed tech matches (~5500)
package nuclei

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Template represents a parsed Nuclei YAML template.
type Template struct {
	ID   string       `yaml:"id"`
	Info TemplateInfo `yaml:"info"`
	HTTP []HTTPBlock  `yaml:"http"`

	Variables map[string]string `yaml:"variables"`

	// Path is the filesystem path this template was loaded from (not in YAML).
	Path string `yaml:"-"`
}

// TemplateInfo contains metadata about the template.
type TemplateInfo struct {
	Name           string         `yaml:"name"`
	Author         string         `yaml:"author"`
	Severity       string         `yaml:"severity"`
	Description    string         `yaml:"description"`
	Impact         string         `yaml:"impact"`
	Remediation    string         `yaml:"remediation"`
	Reference      StringSlice    `yaml:"reference"`
	Classification Classification `yaml:"classification"`
	Metadata       Metadata       `yaml:"metadata"`
	Tags           string         `yaml:"tags"`
}

// Classification holds CVE/CWE/CVSS metadata.
type Classification struct {
	CVSSMetrics    string  `yaml:"cvss-metrics"`
	CVSSScore      float64 `yaml:"cvss-score"`
	CVEID          string  `yaml:"cve-id"`
	CWEID          string  `yaml:"cwe-id"`
	EPSSScore      float64 `yaml:"epss-score"`
	EPSSPercentile float64 `yaml:"epss-percentile"`
	CPE            string  `yaml:"cpe"`
}

// Metadata holds arbitrary key-value metadata from template info.
type Metadata struct {
	Verified    bool        `yaml:"verified"`
	MaxRequest  int         `yaml:"max-request"`
	Vendor      string      `yaml:"vendor"`
	Product     string      `yaml:"product"`
	ShodanQuery StringSlice `yaml:"shodan-query"`
	FOFAQuery   string      `yaml:"fofa-query"`
}

// HTTPBlock represents one HTTP request block in a template.
type HTTPBlock struct {
	// Simple request format
	Method string      `yaml:"method"`
	Path   StringSlice `yaml:"path"`

	// Raw request format (overrides Method/Path)
	Raw StringSlice `yaml:"raw"`

	// Headers for simple requests
	Headers map[string]string `yaml:"headers"`

	// Body for simple requests
	Body string `yaml:"body"`

	// Attack type for payloads
	Attack   string              `yaml:"attack"`
	Payloads map[string][]string `yaml:"payloads"`

	// Matching
	MatchersCondition string    `yaml:"matchers-condition"` // "and" (default) or "or"
	Matchers          []Matcher `yaml:"matchers"`

	// Extraction
	Extractors []Extractor `yaml:"extractors"`

	// Flow control
	StopAtFirstMatch bool `yaml:"stop-at-first-match"`
	Redirects        bool `yaml:"redirects"`
	MaxRedirects     int  `yaml:"max-redirects"`
	HostRedirects    bool `yaml:"host-redirects"`
}

// Matcher defines a condition that must be met for a template to fire.
type Matcher struct {
	Type      string      `yaml:"type"`      // word, regex, status, dsl, size
	Part      string      `yaml:"part"`      // body, header, all, raw (default: body)
	Name      string      `yaml:"name"`      // optional label for the match
	Words     []string    `yaml:"words"`     // for type=word
	Regex     []string    `yaml:"regex"`     // for type=regex
	Status    []int       `yaml:"status"`    // for type=status
	DSL       []string    `yaml:"dsl"`       // for type=dsl
	Size      []int       `yaml:"size"`      // for type=size
	Condition string      `yaml:"condition"` // "and" (default) or "or"
	Negative  bool        `yaml:"negative"`  // invert match result
	Group     int         `yaml:"group"`     // regex capture group
	Internal  bool        `yaml:"internal"`  // don't report as finding
	CaseInsensitive bool `yaml:"case-insensitive"`
}

// Extractor pulls data from the response for reporting or chaining.
type Extractor struct {
	Type     string   `yaml:"type"`      // regex, json, xpath, kval, dsl
	Part     string   `yaml:"part"`      // body, header, all (default: body)
	Name     string   `yaml:"name"`      // output variable name
	Regex    []string `yaml:"regex"`     // for type=regex
	Group    int      `yaml:"group"`     // regex capture group
	JSON     []string `yaml:"json"`      // for type=json (JMESPath)
	KVal     []string `yaml:"kval"`      // for type=kval (header keys)
	DSL      []string `yaml:"dsl"`       // for type=dsl
	Internal bool     `yaml:"internal"`  // don't include in output
}

// StringSlice handles YAML fields that can be either a string or a list.
type StringSlice []string

func (s *StringSlice) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		*s = []string{value.Value}
		return nil
	case yaml.SequenceNode:
		var slice []string
		if err := value.Decode(&slice); err != nil {
			return err
		}
		*s = slice
		return nil
	default:
		return fmt.Errorf("expected string or list, got %v", value.Kind)
	}
}

// TagList returns the parsed tags from the comma-separated tags string.
func (t *Template) TagList() []string {
	if t.Info.Tags == "" {
		return nil
	}
	parts := strings.Split(t.Info.Tags, ",")
	tags := make([]string, 0, len(parts))
	for _, p := range parts {
		if tag := strings.TrimSpace(p); tag != "" {
			tags = append(tags, tag)
		}
	}
	return tags
}

// HasTag checks if the template has a specific tag.
func (t *Template) HasTag(tag string) bool {
	for _, tt := range t.TagList() {
		if strings.EqualFold(tt, tag) {
			return true
		}
	}
	return false
}

// ParseTemplate parses a single Nuclei template from YAML bytes.
func ParseTemplate(data []byte) (*Template, error) {
	var tmpl Template
	if err := yaml.Unmarshal(data, &tmpl); err != nil {
		return nil, fmt.Errorf("parse template: %w", err)
	}
	if tmpl.ID == "" {
		return nil, fmt.Errorf("parse template: missing id")
	}
	if len(tmpl.HTTP) == 0 {
		return nil, fmt.Errorf("parse template %s: no http blocks", tmpl.ID)
	}
	return &tmpl, nil
}

// LoadTemplate reads and parses a template from a file path.
func LoadTemplate(path string) (*Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load template %s: %w", path, err)
	}
	tmpl, err := ParseTemplate(data)
	if err != nil {
		return nil, fmt.Errorf("load template %s: %w", path, err)
	}
	tmpl.Path = path
	return tmpl, nil
}

// LoadTemplatesDir recursively loads all .yaml templates from a directory.
// Templates that fail to parse are silently skipped (logged to errFn if set).
func LoadTemplatesDir(dir string, errFn func(path string, err error)) ([]*Template, error) {
	var templates []*Template

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable dirs
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml") {
			return nil
		}

		tmpl, loadErr := LoadTemplate(path)
		if loadErr != nil {
			if errFn != nil {
				errFn(path, loadErr)
			}
			return nil // skip unparseable templates
		}
		templates = append(templates, tmpl)
		return nil
	})

	return templates, err
}
