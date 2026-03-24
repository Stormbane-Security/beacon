package enrichment

// Tests for applyContextualResponse — in package enrichment (not enrichment_test)
// so the unexported function is accessible.

import (
	"strings"
	"testing"

	"github.com/stormbane/beacon/internal/finding"
)

// makeEnrichedFinding builds a minimal EnrichedFinding for test use.
func makeEnrichedFinding(checkID, asset string) EnrichedFinding {
	return EnrichedFinding{
		Finding: finding.Finding{
			CheckID: finding.CheckID(checkID),
			Asset:   asset,
		},
		Explanation: "original explanation",
		Impact:      "original impact",
		Remediation: "original remediation",
	}
}

// buildJSON is a small helper that constructs a valid contextual JSON response.
func buildJSON(summary, attackNarrative, remediationRoadmap string, findings []map[string]any) string {
	b := strings.Builder{}
	b.WriteString(`{"summary":`)
	b.WriteString(jsonStr(summary))
	if attackNarrative != "" {
		b.WriteString(`,"attack_narrative":`)
		b.WriteString(jsonStr(attackNarrative))
	}
	if remediationRoadmap != "" {
		b.WriteString(`,"remediation_roadmap":`)
		b.WriteString(jsonStr(remediationRoadmap))
	}
	if len(findings) > 0 {
		b.WriteString(`,"findings":[`)
		for i, f := range findings {
			if i > 0 {
				b.WriteString(",")
			}
			b.WriteString("{")
			first := true
			for k, v := range f {
				if !first {
					b.WriteString(",")
				}
				first = false
				b.WriteString(jsonStr(k))
				b.WriteString(":")
				switch val := v.(type) {
				case string:
					b.WriteString(jsonStr(val))
				case bool:
					if val {
						b.WriteString("true")
					} else {
						b.WriteString("false")
					}
				case []string:
					b.WriteString("[")
					for j, s := range val {
						if j > 0 {
							b.WriteString(",")
						}
						b.WriteString(jsonStr(s))
					}
					b.WriteString("]")
				}
			}
			b.WriteString("}")
		}
		b.WriteString("]")
	}
	b.WriteString("}")
	return b.String()
}

// jsonStr encodes a Go string as a JSON string literal (minimal, no unicode escapes needed).
func jsonStr(s string) string {
	b := strings.Builder{}
	b.WriteByte('"')
	for _, c := range s {
		switch c {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestApplyContextualResponse_NewFieldsParsedCorrectly(t *testing.T) {
	enriched := []EnrichedFinding{makeEnrichedFinding("email.spf_missing", "example.com")}

	text := buildJSON(
		"Executive summary here.",
		"The attacker first exploited SPF, then pivoted.",
		"Step 1: fix SPF. Step 2: enable DMARC.",
		nil,
	)

	_, summary, err := applyContextualResponse(enriched, text)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(summary, "Executive summary here.") {
		t.Errorf("summary missing executive summary text; got: %q", summary)
	}
	if !strings.Contains(summary, "## Attack Narrative") {
		t.Errorf("summary missing '## Attack Narrative' section; got: %q", summary)
	}
	if !strings.Contains(summary, "The attacker first exploited SPF") {
		t.Errorf("summary missing attack narrative content; got: %q", summary)
	}
	if !strings.Contains(summary, "## Remediation Roadmap") {
		t.Errorf("summary missing '## Remediation Roadmap' section; got: %q", summary)
	}
	if !strings.Contains(summary, "Step 1: fix SPF") {
		t.Errorf("summary missing remediation roadmap content; got: %q", summary)
	}
}

func TestApplyContextualResponse_ComplianceTagsApplied(t *testing.T) {
	enriched := []EnrichedFinding{makeEnrichedFinding("email.spf_missing", "example.com")}

	text := buildJSON("summary", "", "", []map[string]any{
		{
			"check_id":        "email.spf_missing",
			"asset":           "example.com",
			"compliance_tags": []string{"SOC2-CC6.1", "PCI-3.4"},
		},
	})

	out, _, err := applyContextualResponse(enriched, text)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out))
	}

	tags := out[0].ComplianceTags
	if len(tags) != 2 {
		t.Fatalf("expected 2 compliance tags, got %v", tags)
	}
	found61, found34 := false, false
	for _, tag := range tags {
		if tag == "SOC2-CC6.1" {
			found61 = true
		}
		if tag == "PCI-3.4" {
			found34 = true
		}
	}
	if !found61 {
		t.Errorf("ComplianceTags missing 'SOC2-CC6.1'; got %v", tags)
	}
	if !found34 {
		t.Errorf("ComplianceTags missing 'PCI-3.4'; got %v", tags)
	}
}

func TestApplyContextualResponse_TechSpecificRemediationApplied(t *testing.T) {
	enriched := []EnrichedFinding{makeEnrichedFinding("exposure.cloud_storage", "bucket.example.com")}

	wantRemediation := "Run: aws s3api put-bucket-acl --bucket mybucket --acl private"
	text := buildJSON("summary", "", "", []map[string]any{
		{
			"check_id":                 "exposure.cloud_storage",
			"asset":                    "bucket.example.com",
			"tech_specific_remediation": wantRemediation,
		},
	})

	out, _, err := applyContextualResponse(enriched, text)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out[0].TechSpecificRemediation != wantRemediation {
		t.Errorf("TechSpecificRemediation = %q; want %q", out[0].TechSpecificRemediation, wantRemediation)
	}
}

func TestApplyContextualResponse_OmitSetToTrue(t *testing.T) {
	enriched := []EnrichedFinding{makeEnrichedFinding("headers.missing_csp", "example.com")}

	text := buildJSON("summary", "", "", []map[string]any{
		{
			"check_id": "headers.missing_csp",
			"asset":    "example.com",
			"omit":     true,
		},
	})

	out, _, err := applyContextualResponse(enriched, text)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !out[0].Omit {
		t.Errorf("expected Omit=true, got false")
	}
}

func TestApplyContextualResponse_MitigatedBySet(t *testing.T) {
	enriched := []EnrichedFinding{makeEnrichedFinding("tls.cert_expiry_30d", "api.example.com")}

	wantMitigatedBy := "Cloudflare automatic certificate renewal is active"
	text := buildJSON("summary", "", "", []map[string]any{
		{
			"check_id":     "tls.cert_expiry_30d",
			"asset":        "api.example.com",
			"mitigated_by": wantMitigatedBy,
		},
	})

	out, _, err := applyContextualResponse(enriched, text)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out[0].MitigatedBy != wantMitigatedBy {
		t.Errorf("MitigatedBy = %q; want %q", out[0].MitigatedBy, wantMitigatedBy)
	}
}

func TestApplyContextualResponse_CrossAssetNoteSet(t *testing.T) {
	enriched := []EnrichedFinding{makeEnrichedFinding("dns.axfr_allowed", "ns1.example.com")}

	wantNote := "Combined with open Redis on api.example.com, attacker can enumerate and pivot"
	text := buildJSON("summary", "", "", []map[string]any{
		{
			"check_id":         "dns.axfr_allowed",
			"asset":            "ns1.example.com",
			"cross_asset_note": wantNote,
		},
	})

	out, _, err := applyContextualResponse(enriched, text)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out[0].CrossAssetNote != wantNote {
		t.Errorf("CrossAssetNote = %q; want %q", out[0].CrossAssetNote, wantNote)
	}
}

func TestApplyContextualResponse_GracefulFallbackOnInvalidJSON(t *testing.T) {
	enriched := []EnrichedFinding{
		makeEnrichedFinding("email.spf_missing", "example.com"),
		makeEnrichedFinding("tls.weak_cipher", "example.com"),
	}

	rawText := "not json at all"
	out, summary, err := applyContextualResponse(enriched, rawText)

	// Must not error.
	if err != nil {
		t.Errorf("expected no error on invalid JSON, got: %v", err)
	}
	// Summary must be the raw text.
	if summary != rawText {
		t.Errorf("summary = %q; want raw text %q", summary, rawText)
	}
	// Findings must be returned unchanged.
	if len(out) != len(enriched) {
		t.Fatalf("expected %d findings, got %d", len(enriched), len(out))
	}
	for i, ef := range out {
		if ef.Explanation != enriched[i].Explanation {
			t.Errorf("finding[%d].Explanation changed unexpectedly: got %q", i, ef.Explanation)
		}
		if ef.Omit {
			t.Errorf("finding[%d].Omit should be false on fallback", i)
		}
		if len(ef.ComplianceTags) != 0 {
			t.Errorf("finding[%d].ComplianceTags should be empty on fallback", i)
		}
	}
}

func TestApplyContextualResponse_GracefulFallbackOnPartialJSON(t *testing.T) {
	// JSON has summary but no findings array.
	enriched := []EnrichedFinding{makeEnrichedFinding("email.spf_missing", "example.com")}

	text := `{"summary": "partial response with no findings key"}`
	out, _, err := applyContextualResponse(enriched, text)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 finding returned, got %d", len(out))
	}
	// Finding must be unchanged — no compliance tags injected.
	if len(out[0].ComplianceTags) != 0 {
		t.Errorf("ComplianceTags should be empty when JSON has no findings; got %v", out[0].ComplianceTags)
	}
	if out[0].Omit {
		t.Errorf("Omit should be false when JSON has no findings entry")
	}
	if out[0].Explanation != enriched[0].Explanation {
		t.Errorf("Explanation changed unexpectedly: got %q", out[0].Explanation)
	}
}

func TestApplyContextualResponse_MatchingByCheckIDAndAsset(t *testing.T) {
	// Two findings with the same check_id but different assets must each receive
	// their own data — no cross-contamination.
	enriched := []EnrichedFinding{
		makeEnrichedFinding("email.spf_missing", "example.com"),
		makeEnrichedFinding("email.spf_missing", "other.com"),
	}

	text := buildJSON("summary", "", "", []map[string]any{
		{
			"check_id":        "email.spf_missing",
			"asset":           "example.com",
			"compliance_tags": []string{"SOC2-CC6.1"},
			"mitigated_by":    "Mitigated for example.com",
		},
		{
			"check_id":        "email.spf_missing",
			"asset":           "other.com",
			"compliance_tags": []string{"PCI-3.4"},
			"mitigated_by":    "Mitigated for other.com",
		},
	})

	out, _, err := applyContextualResponse(enriched, text)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(out))
	}

	// example.com finding
	ef0 := out[0]
	if ef0.MitigatedBy != "Mitigated for example.com" {
		t.Errorf("finding[0] (example.com) MitigatedBy = %q; want 'Mitigated for example.com'", ef0.MitigatedBy)
	}
	if len(ef0.ComplianceTags) != 1 || ef0.ComplianceTags[0] != "SOC2-CC6.1" {
		t.Errorf("finding[0] (example.com) ComplianceTags = %v; want [SOC2-CC6.1]", ef0.ComplianceTags)
	}

	// other.com finding
	ef1 := out[1]
	if ef1.MitigatedBy != "Mitigated for other.com" {
		t.Errorf("finding[1] (other.com) MitigatedBy = %q; want 'Mitigated for other.com'", ef1.MitigatedBy)
	}
	if len(ef1.ComplianceTags) != 1 || ef1.ComplianceTags[0] != "PCI-3.4" {
		t.Errorf("finding[1] (other.com) ComplianceTags = %v; want [PCI-3.4]", ef1.ComplianceTags)
	}
}

func TestApplyContextualResponse_EmptyFindingsSlice(t *testing.T) {
	text := buildJSON("Summary for an empty scan.", "Narrative.", "Roadmap.", nil)

	out, summary, err := applyContextualResponse(nil, text)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected empty output slice, got %v", out)
	}
	// The summary should still be assembled from the JSON fields.
	if !strings.Contains(summary, "Summary for an empty scan.") {
		t.Errorf("summary = %q; expected executive summary text", summary)
	}
	if !strings.Contains(summary, "## Attack Narrative") {
		t.Errorf("summary = %q; expected attack narrative section", summary)
	}
	if !strings.Contains(summary, "## Remediation Roadmap") {
		t.Errorf("summary = %q; expected remediation roadmap section", summary)
	}
}
