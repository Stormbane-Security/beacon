package enrichment_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stormbane/beacon/internal/enrichment"
	"github.com/stormbane/beacon/internal/finding"
)

func TestNoopEnricher_ComplianceTagsPopulatedForKnownCheck(t *testing.T) {
	// CheckEmailSPFMissing has a compliance mapping — Enrich must propagate it.
	findings := []finding.Finding{
		{
			CheckID:     finding.CheckEmailSPFMissing,
			Asset:       "example.com",
			Description: "SPF record is missing",
		},
	}

	out, err := enrichment.NewNoop().Enrich(context.Background(), findings)
	if err != nil {
		t.Fatalf("Enrich returned unexpected error: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 enriched finding, got %d", len(out))
	}

	tags := out[0].ComplianceTags
	if len(tags) == 0 {
		t.Fatal("ComplianceTags is empty; want non-empty for CheckEmailSPFMissing")
	}

	found := false
	for _, tag := range tags {
		if tag == "SOC2-CC6.1" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("ComplianceTags = %v; want slice containing 'SOC2-CC6.1'", tags)
	}
}

func TestNoopEnricher_ComplianceTagsNilForUnmappedCheck(t *testing.T) {
	// CheckHeadersMissingReferrerPolicy has no compliance mapping — tags must be nil/empty.
	findings := []finding.Finding{
		{
			CheckID:     finding.CheckHeadersMissingReferrerPolicy,
			Asset:       "example.com",
			Description: "Referrer-Policy header missing",
		},
	}

	out, err := enrichment.NewNoop().Enrich(context.Background(), findings)
	if err != nil {
		t.Fatalf("Enrich returned unexpected error: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 enriched finding, got %d", len(out))
	}

	if len(out[0].ComplianceTags) != 0 {
		t.Errorf("ComplianceTags = %v; want nil/empty for unmapped check", out[0].ComplianceTags)
	}
}

func TestNoopEnricher_ExplanationIsDescription(t *testing.T) {
	desc := "SPF record is missing, which allows anyone to spoof your domain"
	findings := []finding.Finding{
		{
			CheckID:     finding.CheckEmailSPFMissing,
			Asset:       "example.com",
			Description: desc,
		},
	}

	out, err := enrichment.NewNoop().Enrich(context.Background(), findings)
	if err != nil {
		t.Fatalf("Enrich returned unexpected error: %v", err)
	}
	if out[0].Explanation != desc {
		t.Errorf("Explanation = %q; want description %q", out[0].Explanation, desc)
	}
}

func TestNoopEnricher_ImpactContainsAPIKeyHint(t *testing.T) {
	findings := []finding.Finding{
		{
			CheckID:     finding.CheckEmailSPFMissing,
			Asset:       "example.com",
			Description: "SPF missing",
		},
	}

	out, err := enrichment.NewNoop().Enrich(context.Background(), findings)
	if err != nil {
		t.Fatalf("Enrich returned unexpected error: %v", err)
	}

	impact := out[0].Impact
	if !strings.Contains(impact, "BEACON_ANTHROPIC_API_KEY") {
		t.Errorf("Impact = %q; want string containing 'BEACON_ANTHROPIC_API_KEY'", impact)
	}
}

func TestNoopEnricher_RemediationContainsAPIKeyHint(t *testing.T) {
	findings := []finding.Finding{
		{
			CheckID:     finding.CheckEmailSPFMissing,
			Asset:       "example.com",
			Description: "SPF missing",
		},
	}

	out, err := enrichment.NewNoop().Enrich(context.Background(), findings)
	if err != nil {
		t.Fatalf("Enrich returned unexpected error: %v", err)
	}

	remediation := out[0].Remediation
	if !strings.Contains(remediation, "BEACON_ANTHROPIC_API_KEY") {
		t.Errorf("Remediation = %q; want string containing 'BEACON_ANTHROPIC_API_KEY'", remediation)
	}
}

func TestNoopEnricher_MultipleFindingsPreservePerFindingTags(t *testing.T) {
	// Mix of mapped and unmapped checks — each must get its own (correct) tags.
	findings := []finding.Finding{
		{
			CheckID:     finding.CheckEmailSPFMissing,
			Asset:       "example.com",
			Description: "SPF missing",
		},
		{
			CheckID:     finding.CheckDLPCreditCard,
			Asset:       "example.com",
			Description: "Credit card number found in HTTP response",
		},
		{
			CheckID:     finding.CheckHeadersMissingReferrerPolicy,
			Asset:       "example.com",
			Description: "Referrer-Policy missing",
		},
	}

	out, err := enrichment.NewNoop().Enrich(context.Background(), findings)
	if err != nil {
		t.Fatalf("Enrich returned unexpected error: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("expected 3 enriched findings, got %d", len(out))
	}

	// SPF: must have SOC2-CC6.1
	spfTags := out[0].ComplianceTags
	hasSPFTag := false
	for _, tag := range spfTags {
		if tag == "SOC2-CC6.1" {
			hasSPFTag = true
		}
	}
	if !hasSPFTag {
		t.Errorf("finding[0] (SPF): ComplianceTags = %v; want 'SOC2-CC6.1'", spfTags)
	}

	// DLP credit card: must have PCI-3.4
	dlpTags := out[1].ComplianceTags
	hasPCITag := false
	for _, tag := range dlpTags {
		if tag == "PCI-3.4" {
			hasPCITag = true
		}
	}
	if !hasPCITag {
		t.Errorf("finding[1] (DLP credit card): ComplianceTags = %v; want 'PCI-3.4'", dlpTags)
	}

	// Referrer-Policy: must have nil/empty tags
	if len(out[2].ComplianceTags) != 0 {
		t.Errorf("finding[2] (Referrer-Policy): ComplianceTags = %v; want nil/empty", out[2].ComplianceTags)
	}
}
