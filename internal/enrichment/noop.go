package enrichment

import (
	"context"
	"fmt"

	"github.com/stormbane/beacon/internal/finding"
)

// NoopEnricher passes raw findings through unchanged.
// Used for local development and tests — no API key required.
type NoopEnricher struct{}

func NewNoop() *NoopEnricher { return &NoopEnricher{} }

func (n *NoopEnricher) Enrich(_ context.Context, findings []finding.Finding) ([]EnrichedFinding, error) {
	out := make([]EnrichedFinding, len(findings))
	for i, f := range findings {
		out[i] = EnrichedFinding{
			Finding:        f,
			Explanation:    f.Description,
			Impact:         "(AI enrichment not configured — set BEACON_ANTHROPIC_API_KEY)",
			Remediation:    "(AI enrichment not configured — set BEACON_ANTHROPIC_API_KEY)",
			ComplianceTags: finding.ComplianceTags(f.CheckID),
		}
	}
	return out, nil
}

func (n *NoopEnricher) AnalyzeAttackPaths(_ context.Context, _ []EnrichedFinding, _ string) (string, error) {
	return "(AI enrichment not configured — set BEACON_ANTHROPIC_API_KEY for attack-path analysis)", nil
}

func (n *NoopEnricher) GenerateFollowUpProbes(_ context.Context, _ []EnrichedFinding, _ string) ([]FollowUpProbe, error) {
	return nil, nil
}

func (n *NoopEnricher) EnrichFingerprints(_ context.Context, _ []FingerprintInput) (*FingerprintResult, error) {
	return &FingerprintResult{}, nil
}

func (n *NoopEnricher) ContextualizeAndSummarize(_ context.Context, enriched []EnrichedFinding, domain string) ([]EnrichedFinding, string, error) {
	critical, high, medium, low := 0, 0, 0, 0
	for _, e := range enriched {
		switch e.Finding.Severity {
		case finding.SeverityCritical:
			critical++
		case finding.SeverityHigh:
			high++
		case finding.SeverityMedium:
			medium++
		case finding.SeverityLow:
			low++
		}
	}
	summary := fmt.Sprintf(
		"Beacon scanned %s and found %d critical, %d high, %d medium, and %d low severity issues. "+
			"Configure an Anthropic API key (BEACON_ANTHROPIC_API_KEY) for AI-generated explanations and remediation guidance.",
		domain, critical, high, medium, low,
	)
	return enriched, summary, nil
}
