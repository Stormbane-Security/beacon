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
			"check_id":     "headers.missing_csp",
			"asset":        "example.com",
			"omit":         true,
			"mitigated_by": "WAF enforces CSP via response rewriting",
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

func TestApplyContextualResponse_OmitIgnoredWithoutMitigatedBy(t *testing.T) {
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
	if out[0].Omit {
		t.Errorf("expected Omit=false when mitigated_by is empty, got true")
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

// ---------------------------------------------------------------------------
// Edge case tests
// ---------------------------------------------------------------------------

func TestApplyContextualResponseMissingFields(t *testing.T) {
	enriched := []EnrichedFinding{
		makeEnrichedFinding("cors.wildcard", "api.example.com"),
		makeEnrichedFinding("tls.weak_cipher", "web.example.com"),
	}

	// Response has findings entries but some are missing fields:
	// - First finding has no "explanation" (which isn't even a contextual field,
	//   but we verify the function handles sparse JSON without panicking).
	// - Second finding has null-like empty strings for compliance_tags.
	rawJSON := `{
		"summary": "Test summary",
		"findings": [
			{
				"check_id": "cors.wildcard",
				"asset": "api.example.com",
				"mitigated_by": "WAF blocks it"
			},
			{
				"check_id": "tls.weak_cipher",
				"asset": "web.example.com",
				"compliance_tags": null,
				"cross_asset_note": ""
			}
		]
	}`

	out, summary, err := applyContextualResponse(enriched, rawJSON)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(out))
	}

	// First finding should have MitigatedBy set, no panic from missing fields.
	if out[0].MitigatedBy != "WAF blocks it" {
		t.Errorf("finding[0].MitigatedBy = %q; want %q", out[0].MitigatedBy, "WAF blocks it")
	}
	// Original explanation should be preserved since contextual response doesn't overwrite it.
	if out[0].Explanation != "original explanation" {
		t.Errorf("finding[0].Explanation = %q; want %q (should be unchanged)", out[0].Explanation, "original explanation")
	}

	// Second finding should handle null compliance_tags gracefully.
	if out[1].ComplianceTags != nil && len(out[1].ComplianceTags) != 0 {
		t.Errorf("finding[1].ComplianceTags = %v; want nil or empty for null input", out[1].ComplianceTags)
	}
	if out[1].CrossAssetNote != "" {
		t.Errorf("finding[1].CrossAssetNote = %q; want empty string", out[1].CrossAssetNote)
	}

	// Summary should still be populated.
	if !strings.Contains(summary, "Test summary") {
		t.Errorf("summary = %q; want to contain 'Test summary'", summary)
	}
}

func TestApplyContextualResponseExtraFields(t *testing.T) {
	enriched := []EnrichedFinding{
		makeEnrichedFinding("dns.axfr_allowed", "ns1.example.com"),
	}

	// Response includes unknown extra fields that don't map to any struct field.
	// json.Unmarshal should silently ignore them.
	rawJSON := `{
		"summary": "Summary with extra fields",
		"unknown_top_level_field": "should be ignored",
		"severity_override": 99,
		"findings": [
			{
				"check_id": "dns.axfr_allowed",
				"asset": "ns1.example.com",
				"mitigated_by": "Firewall restricts zone transfers",
				"extra_field_1": "ignored value",
				"extra_nested": {"foo": "bar"},
				"extra_array": [1, 2, 3]
			}
		]
	}`

	out, summary, err := applyContextualResponse(enriched, rawJSON)
	if err != nil {
		t.Fatalf("unexpected error on extra fields: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out))
	}

	// Known fields should still be parsed correctly.
	if out[0].MitigatedBy != "Firewall restricts zone transfers" {
		t.Errorf("MitigatedBy = %q; want %q", out[0].MitigatedBy, "Firewall restricts zone transfers")
	}
	if !strings.Contains(summary, "Summary with extra fields") {
		t.Errorf("summary = %q; want to contain 'Summary with extra fields'", summary)
	}
}

func TestEnrichFindingsEmptySlice(t *testing.T) {
	// Directly test the early-return path in Enrich for empty input.
	// The Enrich method on ClaudeEnricher returns (nil, nil) for empty input,
	// which means no API calls are made.
	// We can't easily construct a full ClaudeEnricher without a real API key,
	// but applyContextualResponse with empty enriched slice should be safe.
	out, summary, err := applyContextualResponse([]EnrichedFinding{}, `{"summary":"empty"}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected 0 findings, got %d", len(out))
	}
	if !strings.Contains(summary, "empty") {
		t.Errorf("summary = %q; want to contain 'empty'", summary)
	}

	// Also test with nil slice.
	out2, _, err2 := applyContextualResponse(nil, `{"summary":"nil input"}`)
	if err2 != nil {
		t.Fatalf("unexpected error with nil: %v", err2)
	}
	if len(out2) != 0 {
		t.Errorf("expected 0 findings for nil input, got %d", len(out2))
	}
}

func TestExtractJSONArrayMalformed(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "truncated JSON",
			input: `[{"a":1`,
		},
		{
			name:  "trailing garbage after valid array",
			input: `[{"a":1}]GARBAGE`,
		},
		{
			name:  "no JSON at all",
			input: `This is just plain text with no brackets or braces.`,
		},
		{
			name:  "empty string",
			input: ``,
		},
		{
			name:  "only opening bracket",
			input: `[`,
		},
		{
			name:  "only closing bracket",
			input: `]`,
		},
		{
			name:  "markdown fence with truncated JSON inside",
			input: "```json\n[{\"check_id\": \"test\"\n```",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// extractJSONArray must not panic on any malformed input.
			result := extractJSONArray(tt.input)
			// The result is a best-effort extraction; we just verify no panic.
			_ = result
		})
	}

	// Verify trailing garbage is stripped: extractJSONArray finds outermost [ ... ]
	// so trailing text after ] should be removed.
	result := extractJSONArray(`[{"a":1}]GARBAGE`)
	if result != `[{"a":1}]` {
		t.Errorf("trailing garbage not stripped: got %q; want %q", result, `[{"a":1}]`)
	}

	// Verify plain text with no array markers returns whatever is left after trimming.
	result2 := extractJSONArray(`Just plain text`)
	// Since there's no [ or ], the function returns the trimmed text as-is.
	if result2 != "Just plain text" {
		t.Errorf("no-array input: got %q; want %q", result2, "Just plain text")
	}
}
