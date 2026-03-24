package visibility_test

// Tests for the visibility filter.
//
//   All findings are always shown in full.
//   Executive summary is always populated when provided.
//   Suppressed findings move to SuppressedFindings and are excluded from severity counts.
//   Empty input produces zero counts and empty slices.

import (
	"testing"

	"github.com/stormbane/beacon/internal/enrichment"
	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/visibility"
)

// ef builds a minimal EnrichedFinding from a known CheckID.
func ef(checkID finding.CheckID, title, explanation string) enrichment.EnrichedFinding {
	meta := finding.Meta(checkID)
	return enrichment.EnrichedFinding{
		Finding: finding.Finding{
			CheckID:  checkID,
			Severity: meta.DefaultSeverity,
			Title:    title,
			Asset:    "example.com",
		},
		Explanation: explanation,
	}
}

// ─── All findings visible ─────────────────────────────────────────────────────

func TestFilter_AllFindingsVisibleInFull(t *testing.T) {
	findings := []enrichment.EnrichedFinding{
		ef(finding.CheckEmailDMARCMissing, "DMARC", "DMARC missing."),
		ef(finding.CheckExposureEnvFile, ".env", ".env exposed."),
		ef(finding.CheckHeadersMissingReferrerPolicy, "Headers", "Headers missing."),
	}

	view := visibility.Filter(findings, "summary", nil)

	if len(view.VisibleFindings) != 3 {
		t.Errorf("VisibleFindings = %d; want 3 (all findings shown)", len(view.VisibleFindings))
	}
}

func TestFilter_ExecutiveSummaryPopulated(t *testing.T) {
	const summary = "Your domain has 3 critical findings."
	view := visibility.Filter(nil, summary, nil)

	if view.ExecutiveSummary != summary {
		t.Errorf("ExecutiveSummary = %q; want %q", view.ExecutiveSummary, summary)
	}
}

// ─── Severity counts ──────────────────────────────────────────────────────────

func TestFilter_SeverityCountsCorrect(t *testing.T) {
	findings := []enrichment.EnrichedFinding{
		ef(finding.CheckTLSCertExpiry7d, "Expiry 7d", "Cert expires soon."),        // Critical
		ef(finding.CheckEmailDMARCMissing, "DMARC", "DMARC missing."),              // High
		ef(finding.CheckEmailSPFSoftfail, "SPF Softfail", "SPF softfail."),         // Medium
		ef(finding.CheckEmailMTASTSMissing, "MTA-STS", "MTA-STS missing."),         // Low
		ef(finding.CheckWebTechDetected, "Tech Detected", "Tech fingerprint."),     // Info
	}

	view := visibility.Filter(findings, "", nil)

	if view.SeverityCounts.Critical != 1 {
		t.Errorf("Critical = %d; want 1", view.SeverityCounts.Critical)
	}
	if view.SeverityCounts.High != 1 {
		t.Errorf("High = %d; want 1", view.SeverityCounts.High)
	}
	if view.SeverityCounts.Medium != 1 {
		t.Errorf("Medium = %d; want 1", view.SeverityCounts.Medium)
	}
	if view.SeverityCounts.Low != 1 {
		t.Errorf("Low = %d; want 1", view.SeverityCounts.Low)
	}
	if view.SeverityCounts.Info != 1 {
		t.Errorf("Info = %d; want 1", view.SeverityCounts.Info)
	}
	if view.SeverityCounts.Total != 5 {
		t.Errorf("Total = %d; want 5", view.SeverityCounts.Total)
	}
}

// ─── Suppression ─────────────────────────────────────────────────────────────

func TestFilter_SuppressedFindingExcludedFromVisibleAndCounts(t *testing.T) {
	findings := []enrichment.EnrichedFinding{
		ef(finding.CheckEmailDMARCMissing, "DMARC", "DMARC missing."),
		ef(finding.CheckExposureEnvFile, ".env", ".env exposed."),
	}
	suppressed := map[string]bool{
		visibility.SuppressionKey(string(finding.CheckExposureEnvFile), "example.com"): true,
	}

	view := visibility.Filter(findings, "", suppressed)

	if len(view.VisibleFindings) != 1 {
		t.Errorf("VisibleFindings = %d; want 1 (suppressed finding excluded)", len(view.VisibleFindings))
	}
	if len(view.SuppressedFindings) != 1 {
		t.Errorf("SuppressedFindings = %d; want 1", len(view.SuppressedFindings))
	}
	if view.SeverityCounts.Total != 1 {
		t.Errorf("SeverityCounts.Total = %d; want 1 (suppressed finding not counted)", view.SeverityCounts.Total)
	}
}

func TestFilter_DomainWideSuppression(t *testing.T) {
	// Domain-wide suppression (asset="") applies to all assets.
	findings := []enrichment.EnrichedFinding{
		ef(finding.CheckEmailDMARCMissing, "DMARC A", "DMARC missing."),
		{
			Finding: finding.Finding{
				CheckID:  finding.CheckEmailDMARCMissing,
				Severity: finding.SeverityHigh,
				Title:    "DMARC B",
				Asset:    "mail.example.com",
			},
		},
	}
	suppressed := map[string]bool{
		visibility.SuppressionKey(string(finding.CheckEmailDMARCMissing), ""): true,
	}

	view := visibility.Filter(findings, "", suppressed)

	if len(view.VisibleFindings) != 0 {
		t.Errorf("VisibleFindings = %d; want 0 (domain-wide suppression applies to all assets)", len(view.VisibleFindings))
	}
	if len(view.SuppressedFindings) != 2 {
		t.Errorf("SuppressedFindings = %d; want 2", len(view.SuppressedFindings))
	}
}

// ─── Empty input ──────────────────────────────────────────────────────────────

func TestFilter_EmptyFindingsProducesZeroCounts(t *testing.T) {
	view := visibility.Filter(nil, "", nil)

	if view.SeverityCounts.Total != 0 {
		t.Errorf("Total = %d; want 0 for empty input", view.SeverityCounts.Total)
	}
	if len(view.VisibleFindings) != 0 {
		t.Errorf("VisibleFindings = %d; want 0 for empty input", len(view.VisibleFindings))
	}
	if len(view.SuppressedFindings) != 0 {
		t.Errorf("SuppressedFindings = %d; want 0 for empty input", len(view.SuppressedFindings))
	}
}
