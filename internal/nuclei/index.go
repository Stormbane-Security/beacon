package nuclei

import (
	"strings"
	"sync"
)

// Tier classifies how eagerly a template should be run.
type Tier int

const (
	// TierAlways — generic checks that run on every HTTP target regardless
	// of detected technology. Exposures, misconfigurations, common paths.
	TierAlways Tier = iota

	// TierSignal — checks that run when weak tech signals are present.
	// E.g., "java" headers detected → run all Java CVE templates.
	TierSignal

	// TierTargeted — checks that run only on confirmed product+version match.
	// E.g., Apache 2.4.49 detected → run CVE-2021-41773.
	TierTargeted
)

// alwaysTags are Nuclei tags that classify a template into TierAlways.
// These are generic checks useful against any HTTP target.
var alwaysTags = map[string]bool{
	"exposure":      true,
	"config":        true,
	"misconfig":     true,
	"misconfiguration": true,
	"generic":       true,
	"takeover":      true,
	"token":         true,
	"disclosure":    true,
	"unauth":        true,
	"default-login": true,
	"backup":        true,
	"debug":         true,
	"info-leak":     true,
	"exposed-panel": true,
}

// alwaysCategories are directory categories that classify templates as TierAlways.
var alwaysCategories = map[string]bool{
	"exposures":      true,
	"exposed-panels": true,
	"misconfiguration": true,
	"takeovers":      true,
	"default-logins": true,
	"technologies":   true,
}

// dangerousTags are excluded from all scans regardless of tier.
var dangerousTags = map[string]bool{
	"dos":         true,
	"crash":       true,
	"destructive": true,
	"fuzz":        true,
	"intrusive":   true,
}

// Index provides fast lookup and tier-based selection of templates.
type Index struct {
	mu sync.RWMutex

	// All loaded templates
	all []*Template

	// Templates organized by tier
	always   []*Template
	signal   []*Template
	targeted []*Template

	// Lookup maps
	byID      map[string]*Template
	byTag     map[string][]*Template
	byProduct map[string][]*Template
	byVendor  map[string][]*Template
	byCVE     map[string]*Template
}

// NewIndex creates an empty index.
func NewIndex() *Index {
	return &Index{
		byID:      make(map[string]*Template),
		byTag:     make(map[string][]*Template),
		byProduct: make(map[string][]*Template),
		byVendor:  make(map[string][]*Template),
		byCVE:     make(map[string]*Template),
	}
}

// LoadDir loads all templates from a directory and indexes them.
func (idx *Index) LoadDir(dir string) (loaded, skipped int, err error) {
	templates, err := LoadTemplatesDir(dir, func(path string, err error) {
		skipped++
	})
	if err != nil {
		return 0, skipped, err
	}

	idx.mu.Lock()
	defer idx.mu.Unlock()

	for _, tmpl := range templates {
		if idx.isExcluded(tmpl) {
			skipped++
			continue
		}
		idx.indexTemplate(tmpl)
		loaded++
	}

	return loaded, skipped, nil
}

// Add adds a single template to the index.
func (idx *Index) Add(tmpl *Template) {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	if !idx.isExcluded(tmpl) {
		idx.indexTemplate(tmpl)
	}
}

func (idx *Index) isExcluded(tmpl *Template) bool {
	for _, tag := range tmpl.TagList() {
		if dangerousTags[tag] {
			return true
		}
	}
	return false
}

func (idx *Index) indexTemplate(tmpl *Template) {
	idx.all = append(idx.all, tmpl)
	idx.byID[tmpl.ID] = tmpl

	// Index by tags
	for _, tag := range tmpl.TagList() {
		tag = strings.ToLower(tag)
		idx.byTag[tag] = append(idx.byTag[tag], tmpl)
	}

	// Index by product/vendor from metadata
	if p := strings.ToLower(tmpl.Info.Metadata.Product); p != "" {
		idx.byProduct[p] = append(idx.byProduct[p], tmpl)
	}
	if v := strings.ToLower(tmpl.Info.Metadata.Vendor); v != "" {
		idx.byVendor[v] = append(idx.byVendor[v], tmpl)
	}

	// Index by CVE
	if cve := tmpl.Info.Classification.CVEID; cve != "" {
		idx.byCVE[strings.ToUpper(cve)] = tmpl
	}

	// Classify tier
	tier := idx.classifyTier(tmpl)
	switch tier {
	case TierAlways:
		idx.always = append(idx.always, tmpl)
	case TierSignal:
		idx.signal = append(idx.signal, tmpl)
	case TierTargeted:
		idx.targeted = append(idx.targeted, tmpl)
	}
}

// classifyTier determines which tier a template belongs to.
func (idx *Index) classifyTier(tmpl *Template) Tier {
	tags := tmpl.TagList()

	// Check if it's an "always" template by tags
	for _, tag := range tags {
		if alwaysTags[strings.ToLower(tag)] {
			return TierAlways
		}
	}

	// Check if it's "always" by category (based on file path)
	if tmpl.Path != "" {
		pathLower := strings.ToLower(tmpl.Path)
		for cat := range alwaysCategories {
			if strings.Contains(pathLower, "/"+cat+"/") {
				return TierAlways
			}
		}
	}

	// If it has a specific product+vendor in metadata, it's targeted
	if tmpl.Info.Metadata.Product != "" || tmpl.Info.Classification.CPE != "" {
		return TierTargeted
	}

	// If it has a CVE ID, it's targeted (needs specific product)
	if tmpl.Info.Classification.CVEID != "" {
		return TierTargeted
	}

	// Everything else is signal-based
	return TierSignal
}

// SelectTemplates returns templates appropriate for the given signals.
// Signals are Nuclei tags collected from classify + portscan (e.g., "apache",
// "nginx", "php", "java", "wordpress").
//
// Selection strategy:
//   - Always: all TierAlways templates run regardless of signals
//   - Signal: TierSignal templates run if ANY of their tags match a signal
//   - Targeted: TierTargeted templates run if product/vendor/tag matches a signal
//   - Unknown: if signals is empty, run Always + ALL Signal + ALL Targeted
//     (because we can't exclude anything we're uncertain about)
func (idx *Index) SelectTemplates(signals []string) []*Template {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	// Start with all "always" templates
	seen := make(map[string]bool)
	var selected []*Template

	for _, t := range idx.always {
		if !seen[t.ID] {
			seen[t.ID] = true
			selected = append(selected, t)
		}
	}

	// If no signals, include everything — we can't rule anything out
	if len(signals) == 0 {
		for _, t := range idx.signal {
			if !seen[t.ID] {
				seen[t.ID] = true
				selected = append(selected, t)
			}
		}
		for _, t := range idx.targeted {
			if !seen[t.ID] {
				seen[t.ID] = true
				selected = append(selected, t)
			}
		}
		return selected
	}

	// Build signal set for fast lookup
	signalSet := make(map[string]bool, len(signals))
	for _, s := range signals {
		signalSet[strings.ToLower(s)] = true
	}

	// Signal tier: include if any tag matches a signal
	for _, t := range idx.signal {
		if seen[t.ID] {
			continue
		}
		if idx.matchesSignal(t, signalSet) {
			seen[t.ID] = true
			selected = append(selected, t)
		}
	}

	// Targeted tier: include if product/vendor/tag matches
	for _, t := range idx.targeted {
		if seen[t.ID] {
			continue
		}
		if idx.matchesSignal(t, signalSet) {
			seen[t.ID] = true
			selected = append(selected, t)
		}
	}

	return selected
}

// matchesSignal checks if a template matches any of the provided signals.
func (idx *Index) matchesSignal(tmpl *Template, signals map[string]bool) bool {
	// Check tags
	for _, tag := range tmpl.TagList() {
		if signals[strings.ToLower(tag)] {
			return true
		}
	}

	// Check product
	if p := strings.ToLower(tmpl.Info.Metadata.Product); p != "" && signals[p] {
		return true
	}

	// Check vendor
	if v := strings.ToLower(tmpl.Info.Metadata.Vendor); v != "" && signals[v] {
		return true
	}

	// Check CVE tag patterns (e.g., signal "apache" matches template with tag "apache")
	return false
}

// ByTag returns all templates with a specific tag.
func (idx *Index) ByTag(tag string) []*Template {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return idx.byTag[strings.ToLower(tag)]
}

// ByProduct returns all templates for a specific product.
func (idx *Index) ByProduct(product string) []*Template {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return idx.byProduct[strings.ToLower(product)]
}

// ByCVE returns the template for a specific CVE ID.
func (idx *Index) ByCVE(cveID string) *Template {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return idx.byCVE[strings.ToUpper(cveID)]
}

// Stats returns counts for each tier.
func (idx *Index) Stats() (total, always, signal, targeted int) {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return len(idx.all), len(idx.always), len(idx.signal), len(idx.targeted)
}

// All returns all loaded templates.
func (idx *Index) All() []*Template {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	result := make([]*Template, len(idx.all))
	copy(result, idx.all)
	return result
}
