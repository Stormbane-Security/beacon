package nuclei

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)

// Engine is the native Nuclei template execution engine.
// It loads, indexes, and executes Nuclei YAML templates without requiring
// the nuclei binary.
type Engine struct {
	index    *Index
	loaded   bool
	loadOnce sync.Once
	loadErr  error

	// TemplateDir is the path to the nuclei-templates directory.
	TemplateDir string

	// Concurrency controls how many templates execute in parallel per target.
	Concurrency int
}

// NewEngine creates a new Nuclei template engine.
func NewEngine(templateDir string) *Engine {
	return &Engine{
		index:       NewIndex(),
		TemplateDir: templateDir,
		Concurrency: 25,
	}
}

// Load indexes all templates from the configured directory.
// Safe to call multiple times; only loads once.
func (e *Engine) Load() error {
	e.loadOnce.Do(func() {
		if e.TemplateDir == "" {
			e.loadErr = fmt.Errorf("nuclei engine: no template directory configured")
			return
		}
		loaded, skipped, err := e.index.LoadDir(e.TemplateDir + "/http")
		if err != nil {
			e.loadErr = fmt.Errorf("nuclei engine: load templates: %w", err)
			return
		}
		log.Printf("[nuclei-engine] loaded %d templates, skipped %d", loaded, skipped)
		total, always, signal, targeted := e.index.Stats()
		log.Printf("[nuclei-engine] tiers: always=%d signal=%d targeted=%d total=%d", always, signal, targeted, total)
		e.loaded = true
	})
	return e.loadErr
}

// Index returns the template index for inspection.
func (e *Engine) Index() *Index {
	return e.index
}

// Scan executes selected templates against a target and returns findings.
// signals are Nuclei tags from classify/portscan (e.g., "apache", "php", "wordpress").
func (e *Engine) Scan(ctx context.Context, target string, scanType module.ScanType, signals []string) ([]finding.Finding, error) {
	if err := e.Load(); err != nil {
		return nil, err
	}

	// Select templates based on signals and scan type
	templates := e.index.SelectTemplates(signals)

	// Filter by scan type — only run exploitation templates in deep/authorized mode
	templates = filterByScanType(templates, scanType)

	if len(templates) == 0 {
		return nil, nil
	}

	// Build base URL
	baseURL := target
	if !strings.Contains(baseURL, "://") {
		baseURL = "https://" + baseURL
	}

	// Execute templates concurrently
	type result struct {
		findings []finding.Finding
	}

	sem := make(chan struct{}, e.Concurrency)
	resultCh := make(chan result, len(templates))

	var wg sync.WaitGroup
	for _, tmpl := range templates {
		wg.Add(1)
		go func(t *Template) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
				defer func() { <-sem }()
			}

			client := clientForBlock(t)
			execResults, err := executeTemplate(ctx, t, baseURL, client)
			if err != nil {
				return
			}

			var findings []finding.Finding
			for _, er := range execResults {
				if !er.Matched {
					continue
				}
				f := resultToFinding(t, er, target)
				findings = append(findings, f)
			}
			if len(findings) > 0 {
				resultCh <- result{findings: findings}
			}
		}(tmpl)
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	var allFindings []finding.Finding
	for r := range resultCh {
		allFindings = append(allFindings, r.findings...)
	}

	return allFindings, nil
}

// ScanWithTags runs templates matching specific Nuclei tags (for playbook integration).
func (e *Engine) ScanWithTags(ctx context.Context, target string, tags []string) ([]finding.Finding, error) {
	if err := e.Load(); err != nil {
		return nil, err
	}

	// Collect templates matching any of the specified tags
	seen := make(map[string]bool)
	var templates []*Template
	for _, tag := range tags {
		for _, t := range e.index.ByTag(tag) {
			if !seen[t.ID] {
				seen[t.ID] = true
				templates = append(templates, t)
			}
		}
	}

	if len(templates) == 0 {
		return nil, nil
	}

	baseURL := target
	if !strings.Contains(baseURL, "://") {
		baseURL = "https://" + baseURL
	}

	sem := make(chan struct{}, e.Concurrency)
	type result struct {
		findings []finding.Finding
	}
	resultCh := make(chan result, len(templates))

	var wg sync.WaitGroup
	for _, tmpl := range templates {
		wg.Add(1)
		go func(t *Template) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
				defer func() { <-sem }()
			}

			client := clientForBlock(t)
			execResults, err := executeTemplate(ctx, t, baseURL, client)
			if err != nil {
				return
			}

			var findings []finding.Finding
			for _, er := range execResults {
				if er.Matched {
					findings = append(findings, resultToFinding(t, er, target))
				}
			}
			if len(findings) > 0 {
				resultCh <- result{findings: findings}
			}
		}(tmpl)
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	var allFindings []finding.Finding
	for r := range resultCh {
		allFindings = append(allFindings, r.findings...)
	}

	return allFindings, nil
}

// resultToFinding converts an ExecuteResult into a beacon Finding.
func resultToFinding(tmpl *Template, er ExecuteResult, asset string) finding.Finding {
	checkID := finding.MapNucleiTemplate(tmpl.ID)
	sev := finding.ParseSeverity(tmpl.Info.Severity)

	evidence := map[string]any{
		"template_id": tmpl.ID,
		"matched_at":  er.MatchedAt,
	}
	if er.MatcherName != "" {
		evidence["matcher_name"] = er.MatcherName
	}
	if len(er.Extractions) > 0 {
		evidence["extracted_results"] = er.Extractions
	}
	if tmpl.Info.Classification.CVEID != "" {
		evidence["cve"] = tmpl.Info.Classification.CVEID
	}
	if tmpl.Info.Classification.CWEID != "" {
		evidence["cwe"] = tmpl.Info.Classification.CWEID
	}
	if tmpl.Info.Classification.CVSSScore > 0 {
		evidence["cvss_score"] = tmpl.Info.Classification.CVSSScore
	}
	if tmpl.Info.Metadata.Product != "" {
		evidence["product"] = tmpl.Info.Metadata.Product
	}
	if tmpl.Info.Metadata.Vendor != "" {
		evidence["vendor"] = tmpl.Info.Metadata.Vendor
	}

	// Build proof command
	proof := buildProofCommand(tmpl, er)

	return finding.Finding{
		CheckID:      checkID,
		Module:       "surface",
		Scanner:      "nuclei-engine",
		Severity:     sev,
		Title:        tmpl.Info.Name,
		Description:  tmpl.Info.Description,
		Asset:        asset,
		Evidence:     evidence,
		ProofCommand: proof,
		DiscoveredAt: time.Now(),
	}
}

func buildProofCommand(tmpl *Template, er ExecuteResult) string {
	if er.MatchedAt == "" {
		return ""
	}

	// For simple GET requests, curl is sufficient
	if len(tmpl.HTTP) > 0 {
		block := tmpl.HTTP[0]
		if len(block.Raw) > 0 {
			// Raw request — just curl the matched URL
			return fmt.Sprintf("curl -sk '%s'", er.MatchedAt)
		}
		method := strings.ToUpper(block.Method)
		if method == "" || method == "GET" {
			return fmt.Sprintf("curl -sk '%s'", er.MatchedAt)
		}
		return fmt.Sprintf("curl -sk -X %s '%s'", method, er.MatchedAt)
	}
	return fmt.Sprintf("curl -sk '%s'", er.MatchedAt)
}

// filterByScanType removes exploitation-class templates for surface scans.
func filterByScanType(templates []*Template, scanType module.ScanType) []*Template {
	if scanType == module.ScanAuthorized {
		return templates // everything allowed
	}

	exploitTags := map[string]bool{
		"rce":    true,
		"sqli":   true,
		"xss":    true,
		"ssrf":   true,
		"lfi":    true,
		"exploit": true,
		"cve":    true,
	}

	// In surface mode, only allow safe detection templates
	if scanType == module.ScanSurface {
		var safe []*Template
		for _, t := range templates {
			isExploit := false
			for _, tag := range t.TagList() {
				if exploitTags[strings.ToLower(tag)] {
					isExploit = true
					break
				}
			}
			// Allow exposure/config/misconfig/panel detection in surface
			if !isExploit {
				safe = append(safe, t)
			}
		}
		return safe
	}

	// ScanDeep — allow active probing but block exploitation-class templates.
	// CVE templates are exploitation-class: they send specific exploit payloads
	// targeting known vulnerabilities and should require Authorized mode.
	deepBlockedTags := map[string]bool{
		"exploit": true,
		"rce":     true,
		"cve":     true,
	}
	var filtered []*Template
	for _, t := range templates {
		blocked := false
		for _, tag := range t.TagList() {
			if deepBlockedTags[strings.ToLower(tag)] {
				blocked = true
				break
			}
		}
		if !blocked {
			filtered = append(filtered, t)
		}
	}
	return filtered
}

// clientForBlock creates an HTTP client appropriate for the template's first block.
func clientForBlock(tmpl *Template) *http.Client {
	if len(tmpl.HTTP) == 0 {
		return newHTTPClient(false, 0)
	}
	block := tmpl.HTTP[0]
	return newHTTPClient(block.Redirects || block.HostRedirects, block.MaxRedirects)
}
