// Package report builds the HTML security report from enriched scan results.
package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/enrichment"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/store"
	"github.com/stormbane-security/beacon/internal/visibility"
)

// Input is everything the report builder needs to produce a Report.
type Input struct {
	ScanRun          store.ScanRun
	EnrichedFindings []enrichment.EnrichedFinding
	ExecutiveSummary string
	// Suppressions is the list of active suppressions for the domain.
	// Suppressed findings are shown collapsed at the bottom of the report.
	Suppressions []store.FindingSuppression
}

// Build applies the visibility filter and renders the HTML report.
func Build(in Input) (*store.Report, error) {
	suppressed := make(map[string]bool, len(in.Suppressions))
	for _, s := range in.Suppressions {
		suppressed[visibility.SuppressionKey(s.CheckID, s.Asset)] = true
	}
	view := visibility.Filter(in.EnrichedFindings, in.ExecutiveSummary, suppressed)

	// Count unique assets across visible findings.
	assetSet := make(map[string]bool)
	for _, ef := range view.VisibleFindings {
		assetSet[ef.Finding.Asset] = true
	}

	// Identify chain/correlation findings.
	var chains []enrichment.EnrichedFinding
	for _, ef := range view.VisibleFindings {
		id := string(ef.Finding.CheckID)
		if strings.HasPrefix(id, "chain.") || strings.HasPrefix(id, "correlation.") {
			chains = append(chains, ef)
		}
	}

	// Generate top recommendations from the executive summary.
	recs := generateRecommendations(view.VisibleFindings)

	data := templateData{
		Domain:          in.ScanRun.Domain,
		ScanType:        in.ScanRun.ScanType,
		Modules:         in.ScanRun.Modules,
		StartedAt:       in.ScanRun.StartedAt,
		CompletedAt:     completedAt(in.ScanRun),
		View:            view,
		SeverityCounts:  view.SeverityCounts,
		TotalFindings:   view.SeverityCounts.Total,
		UniqueAssets:    len(assetSet),
		ChainCount:      len(chains),
		Chains:          chains,
		Recommendations: recs,
	}

	html, err := render(data)
	if err != nil {
		return nil, fmt.Errorf("render report: %w", err)
	}

	return &store.Report{
		ScanRunID:   in.ScanRun.ID,
		Domain:      in.ScanRun.Domain,
		HTMLContent: html,
		Summary:     in.ExecutiveSummary,
		CreatedAt:   time.Now(),
	}, nil
}

// SeverityLabel returns a human-readable severity string.
func SeverityLabel(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical:
		return "Critical"
	case finding.SeverityHigh:
		return "High"
	case finding.SeverityMedium:
		return "Medium"
	case finding.SeverityLow:
		return "Low"
	default:
		return "Info"
	}
}

func completedAt(run store.ScanRun) time.Time {
	if run.CompletedAt != nil {
		return *run.CompletedAt
	}
	return time.Now()
}

// generateRecommendations produces up to 5 actionable recommendations based on
// the findings, prioritized by severity.
func generateRecommendations(findings []enrichment.EnrichedFinding) []string {
	var recs []string

	critCount := 0
	highCount := 0
	hasTLS := false
	hasAuth := false
	hasExposure := false
	for _, ef := range findings {
		switch ef.Finding.Severity {
		case finding.SeverityCritical:
			critCount++
		case finding.SeverityHigh:
			highCount++
		}
		id := string(ef.Finding.CheckID)
		if strings.HasPrefix(id, "tls.") {
			hasTLS = true
		}
		if strings.Contains(id, "default_cred") || strings.Contains(id, "auth") {
			hasAuth = true
		}
		if strings.Contains(id, "exposed") || strings.Contains(id, "disclosure") || strings.Contains(id, "info_leak") {
			hasExposure = true
		}
	}

	if critCount > 0 {
		recs = append(recs, fmt.Sprintf("Remediate %d critical finding(s) immediately — these represent active exploitation risk.", critCount))
	}
	if highCount > 0 {
		recs = append(recs, fmt.Sprintf("Address %d high-severity finding(s) within the next sprint cycle.", highCount))
	}
	if hasTLS {
		recs = append(recs, "Review and upgrade TLS configuration: disable deprecated protocols, rotate weak certificates, and enforce HSTS.")
	}
	if hasAuth {
		recs = append(recs, "Rotate all default or weak credentials and enforce multi-factor authentication on administrative interfaces.")
	}
	if hasExposure {
		recs = append(recs, "Remove or restrict access to exposed configuration files, debug endpoints, and information disclosure paths.")
	}

	if len(recs) == 0 {
		recs = append(recs, "Continue regular scanning to maintain visibility into the attack surface.")
	}
	if len(recs) > 5 {
		recs = recs[:5]
	}
	return recs
}

// templateData is passed to the HTML template.
type templateData struct {
	Domain          string
	ScanType        module.ScanType
	Modules         []string
	StartedAt       time.Time
	CompletedAt     time.Time
	View            visibility.ReportView
	SeverityCounts  visibility.SeverityCount
	TotalFindings   int
	UniqueAssets    int
	ChainCount      int
	Chains          []enrichment.EnrichedFinding
	Recommendations []string
}
