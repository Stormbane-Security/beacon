// Package report builds the HTML security report from enriched scan results.
package report

import (
	"fmt"
	"time"

	"github.com/stormbane/beacon/internal/enrichment"
	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
	"github.com/stormbane/beacon/internal/store"
	"github.com/stormbane/beacon/internal/visibility"
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

	data := templateData{
		Domain:          in.ScanRun.Domain,
		ScanType:        in.ScanRun.ScanType,
		Modules:         in.ScanRun.Modules,
		StartedAt:       in.ScanRun.StartedAt,
		CompletedAt:     completedAt(in.ScanRun),
		View:            view,
		SeverityCounts:  view.SeverityCounts,
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

// SeverityLabel returns a human-readable severity string with an emoji badge.
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

// templateData is passed to the HTML template.
type templateData struct {
	Domain         string
	ScanType       module.ScanType
	Modules        []string
	StartedAt      time.Time
	CompletedAt    time.Time
	View           visibility.ReportView
	SeverityCounts visibility.SeverityCount
}
