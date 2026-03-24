package enrichment

import (
	"testing"

	"github.com/stormbane/beacon/internal/finding"
)

// ── extractJSONArray ──────────────────────────────────────────────────────────

func TestExtractJSONArray_PlainJSON(t *testing.T) {
	input := `[{"check_id":"foo","explanation":"bar"}]`
	got := extractJSONArray(input)
	if got != input {
		t.Errorf("plain JSON should pass through unchanged, got %q", got)
	}
}

func TestExtractJSONArray_MarkdownCodeFence(t *testing.T) {
	input := "```json\n[{\"check_id\":\"foo\",\"explanation\":\"bar\"}]\n```"
	got := extractJSONArray(input)
	if got != `[{"check_id":"foo","explanation":"bar"}]` {
		t.Errorf("expected unwrapped JSON, got %q", got)
	}
}

func TestExtractJSONArray_GenericCodeFence(t *testing.T) {
	input := "```\n[{\"check_id\":\"foo\"}]\n```"
	got := extractJSONArray(input)
	if got != `[{"check_id":"foo"}]` {
		t.Errorf("expected unwrapped JSON, got %q", got)
	}
}

func TestExtractJSONArray_LeadingProse(t *testing.T) {
	input := "Here is the JSON you requested:\n[{\"check_id\":\"foo\"}]\nEnd."
	got := extractJSONArray(input)
	if got != `[{"check_id":"foo"}]` {
		t.Errorf("expected extracted array, got %q", got)
	}
}

// ── looksLikeRawJSON ──────────────────────────────────────────────────────────

func TestLooksLikeRawJSON_JSONArray(t *testing.T) {
	if !looksLikeRawJSON(`[{"check_id":"foo"}]`) {
		t.Error("expected true for JSON array")
	}
}

func TestLooksLikeRawJSON_CodeFence(t *testing.T) {
	if !looksLikeRawJSON("```json\n[{}]\n```") {
		t.Error("expected true for code fence")
	}
}

func TestLooksLikeRawJSON_HumanText(t *testing.T) {
	if looksLikeRawJSON("This domain has no SPF record configured.") {
		t.Error("expected false for plain prose")
	}
}

func TestLooksLikeRawJSON_EmptyString(t *testing.T) {
	if looksLikeRawJSON("") {
		t.Error("expected false for empty string")
	}
}

// ── parseEnrichedResponse ────────────────────────────────────────────────────

var testFindings = []finding.Finding{
	{CheckID: "email.spoofable", Title: "Domain spoofable", Description: "No SPF or DMARC."},
	{CheckID: "tls.weak_cipher", Title: "Weak cipher", Description: "RC4 in use."},
}

func TestParseEnrichedResponse_HappyPath(t *testing.T) {
	text := `[
		{"check_id":"email.spoofable","explanation":"SPF missing","impact":"Phishing","remediation":"Add SPF"},
		{"check_id":"tls.weak_cipher","explanation":"RC4 deprecated","impact":"Decryption","remediation":"Disable RC4"}
	]`
	out, err := parseEnrichedResponse(testFindings, text)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 results, got %d", len(out))
	}
	if out[0].Explanation != "SPF missing" {
		t.Errorf("wrong explanation for email.spoofable: %q", out[0].Explanation)
	}
	if out[1].Remediation != "Disable RC4" {
		t.Errorf("wrong remediation for tls.weak_cipher: %q", out[1].Remediation)
	}
}

func TestParseEnrichedResponse_MarkdownFence_Parsed(t *testing.T) {
	// Claude wraps its JSON in a code fence — must be unwrapped and parsed correctly.
	text := "```json\n[{\"check_id\":\"email.spoofable\",\"explanation\":\"SPF missing\",\"impact\":\"Phishing\",\"remediation\":\"Add SPF\"}]\n```"
	out, err := parseEnrichedResponse(testFindings[:1], text)
	if err != nil {
		t.Fatal(err)
	}
	if out[0].Explanation != "SPF missing" {
		t.Errorf("markdown fence not stripped: Explanation = %q", out[0].Explanation)
	}
}

func TestParseEnrichedResponse_ParseFailure_FallsBackToDescription(t *testing.T) {
	// Complete garbage — must NOT store raw text as explanation.
	text := "Sorry, I can't help with that."
	out, err := parseEnrichedResponse(testFindings, text)
	if err != nil {
		t.Fatal(err)
	}
	for _, ef := range out {
		if looksLikeRawJSON(ef.Explanation) {
			t.Errorf("fallback must not store raw JSON/text; got: %q", ef.Explanation)
		}
		// Must fall back to the finding's own Description, not raw response text.
		if ef.Explanation != ef.Finding.Description {
			t.Errorf("expected Description fallback %q, got %q", ef.Finding.Description, ef.Explanation)
		}
	}
}

func TestParseEnrichedResponse_JSONBlobFallback_NotRawJSON(t *testing.T) {
	// The exact scenario from the bug: Claude returns a full JSON array from a
	// DIFFERENT scan instead of the expected format. Must fall back cleanly.
	text := `[{"check_id":"asset.passive_dns","explanation":"stormbane.net data here"}]`
	// But testFindings ask for email.spoofable — check_ids don't match.
	// Even if parsing succeeds, unmapped findings must get their Description, not raw text.
	out, err := parseEnrichedResponse(testFindings, text)
	if err != nil {
		t.Fatal(err)
	}
	for _, ef := range out {
		if looksLikeRawJSON(ef.Explanation) {
			t.Errorf("must not store raw JSON as explanation; got: %q", ef.Explanation)
		}
	}
}

func TestParseEnrichedResponse_UnmatchedCheckID_FallsBackToDescription(t *testing.T) {
	// Claude returns valid JSON but for wrong check IDs — unmatched findings must
	// use their own Description, not empty string and not raw JSON.
	text := `[{"check_id":"some.other.check","explanation":"unrelated","impact":"","remediation":""}]`
	out, err := parseEnrichedResponse(testFindings, text)
	if err != nil {
		t.Fatal(err)
	}
	for _, ef := range out {
		if ef.Explanation == "" {
			t.Errorf("unmatched finding should fall back to Description, not empty string")
		}
		if looksLikeRawJSON(ef.Explanation) {
			t.Error("unmatched finding must not have raw JSON explanation")
		}
	}
}
