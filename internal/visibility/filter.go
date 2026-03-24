// Package visibility implements the conversion-driven finding filter.
// All findings are always stored. This package controls what is shown
// in the report based on the user's tier.
package visibility

import (
	"github.com/stormbane/beacon/internal/enrichment"
	"github.com/stormbane/beacon/internal/finding"
)

// Tier is kept for SaaS-layer use only. The open-source tool always shows all findings.
// The SaaS service uses this to gate findings per subscription plan.
type Tier int

const (
	TierFree Tier = iota
	TierPaid
)

// ReportView is the filtered view of findings returned for report rendering.
type ReportView struct {
	// VisibleFindings are fully shown (low conversion value or top 1-3 high value).
	VisibleFindings []enrichment.EnrichedFinding

	// SuppressedFindings are findings marked as false-positive / accepted-risk.
	// Shown collapsed at the bottom of the report for audit purposes.
	SuppressedFindings []enrichment.EnrichedFinding

	// SeverityCounts covers active (non-suppressed) findings only.
	SeverityCounts SeverityCount

	// ExecutiveSummary is the AI-generated summary for the report header.
	ExecutiveSummary string
}

// SeverityCount holds the count of findings per severity level.
type SeverityCount struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
	Total    int
}

// SuppressionKey returns the map key for a (checkID, asset) suppression.
// Use asset="" for domain-wide suppressions that apply to all assets.
func SuppressionKey(checkID, asset string) string {
	return checkID + "|" + asset
}

// Filter applies suppression rules and returns a ReportView with all active findings visible.
// All findings are always shown — pricing gating is handled by the SaaS layer, not this tool.
//
// suppressed is a set of SuppressionKey values for findings that should be
// moved to ReportView.SuppressedFindings and excluded from severity counts.
// Pass nil for no suppression filtering.
func Filter(all []enrichment.EnrichedFinding, summary string, suppressed map[string]bool) ReportView {
	view := ReportView{}

	var active []enrichment.EnrichedFinding
	for _, ef := range all {
		key := SuppressionKey(ef.Finding.CheckID, ef.Finding.Asset)
		domainKey := SuppressionKey(ef.Finding.CheckID, "")
		if suppressed[key] || suppressed[domainKey] {
			view.SuppressedFindings = append(view.SuppressedFindings, ef)
		} else {
			active = append(active, ef)
		}
	}

	// All active findings are shown in full.
	view.VisibleFindings = active
	view.ExecutiveSummary = summary

	for _, ef := range active {
		view.SeverityCounts.Total++
		switch ef.Finding.Severity {
		case finding.SeverityCritical:
			view.SeverityCounts.Critical++
		case finding.SeverityHigh:
			view.SeverityCounts.High++
		case finding.SeverityMedium:
			view.SeverityCounts.Medium++
		case finding.SeverityLow:
			view.SeverityCounts.Low++
		default:
			view.SeverityCounts.Info++
		}
	}

	return view
}

// firstSentence returns the first sentence of a string.
func firstSentence(s string) string {
	for i, ch := range s {
		if ch == '.' || ch == '!' || ch == '?' {
			return s[:i+1]
		}
	}
	if len(s) > 120 {
		return s[:120] + "..."
	}
	return s
}
