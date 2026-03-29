package enrichment

import (
	"strings"
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

// ── safe template function ──────────────────────────────────────────────────

func TestSafe_UnicodeMultibyteTruncation(t *testing.T) {
	// Build a string of 520 multi-byte runes (each is 3 bytes in UTF-8).
	// Truncating at byte 512 would slice mid-rune and produce invalid UTF-8.
	input := strings.Repeat("\u4e16", 520) // 520 Chinese characters
	safeFn := safeFuncs["safe"].(func(string) string)
	result := safeFn(input)

	// Must contain exactly 512 runes + ellipsis.
	runes := []rune(result)
	if runes[len(runes)-1] != '…' {
		t.Errorf("expected trailing ellipsis, got rune %q", runes[len(runes)-1])
	}
	if len(runes) != 513 { // 512 + ellipsis
		t.Errorf("expected 513 runes (512 + ellipsis), got %d", len(runes))
	}

	// The result must be valid UTF-8 — Go strings from []rune always are,
	// but verify no replacement characters snuck in.
	if strings.ContainsRune(result, '\uFFFD') {
		t.Error("result contains U+FFFD replacement character — truncation broke UTF-8")
	}
}

func TestSafe_NewlinesCollapsed(t *testing.T) {
	safeFn := safeFuncs["safe"].(func(string) string)
	input := "line1\nline2\r\nline3\rline4"
	result := safeFn(input)
	if strings.ContainsAny(result, "\r\n") {
		t.Errorf("newlines not collapsed: %q", result)
	}
	if result != "line1 line2 line3 line4" {
		t.Errorf("unexpected result: %q", result)
	}
}

func TestSafe_ControlCharsRemoved(t *testing.T) {
	safeFn := safeFuncs["safe"].(func(string) string)
	// Include a bell (0x07) and null (0x00) character.
	input := "hello\x07world\x00end"
	result := safeFn(input)
	if result != "helloworldend" {
		t.Errorf("control chars not removed: %q", result)
	}
}

func TestSafe_TabPreserved(t *testing.T) {
	safeFn := safeFuncs["safe"].(func(string) string)
	input := "col1\tcol2"
	result := safeFn(input)
	if result != "col1\tcol2" {
		t.Errorf("tab should be preserved: %q", result)
	}
}

func TestSafe_ShortStringUnchanged(t *testing.T) {
	safeFn := safeFuncs["safe"].(func(string) string)
	input := "short string"
	result := safeFn(input)
	if result != input {
		t.Errorf("short string should pass through unchanged: %q", result)
	}
}

func TestSafe_EmptyString(t *testing.T) {
	safeFn := safeFuncs["safe"].(func(string) string)
	result := safeFn("")
	if result != "" {
		t.Errorf("empty string should return empty: %q", result)
	}
}

// ── sanitize function ────────────────────────────────────────────────────────

func TestSanitize_TruncatesByRuneCount(t *testing.T) {
	// 20 multi-byte runes, limit to 10.
	input := strings.Repeat("\u00e9", 20) // é is 2 bytes each
	result := sanitize(input, 10)
	runes := []rune(result)
	// 10 runes + ellipsis
	if len(runes) != 11 {
		t.Errorf("expected 11 runes (10 + ellipsis), got %d", len(runes))
	}
	if runes[len(runes)-1] != '…' {
		t.Errorf("expected trailing ellipsis")
	}
}

func TestSanitize_RemovesNewlinesAndControlChars(t *testing.T) {
	input := "line1\nline2\x00end"
	result := sanitize(input, 100)
	if strings.ContainsAny(result, "\n\x00") {
		t.Errorf("newlines/control chars not removed: %q", result)
	}
	if result != "line1 line2end" {
		t.Errorf("unexpected result: %q", result)
	}
}

func TestSanitize_ShortStringUnchanged(t *testing.T) {
	result := sanitize("hello", 100)
	if result != "hello" {
		t.Errorf("short string should pass through: %q", result)
	}
}

// ── looksLikeRawJSON edge cases ──────────────────────────────────────────────

func TestLooksLikeRawJSON_WhitespaceBeforeJSON(t *testing.T) {
	if !looksLikeRawJSON("  [{\"key\":\"val\"}]") {
		t.Error("expected true for whitespace-prefixed JSON array")
	}
}

func TestLooksLikeRawJSON_SingleOpenBrace(t *testing.T) {
	// A string starting with "{" alone (not "[{") is not raw JSON in our definition.
	if looksLikeRawJSON("{\"key\":\"val\"}") {
		t.Error("expected false for JSON object (not array)")
	}
}

// ── parseEnrichedResponse edge cases ─────────────────────────────────────────

func TestParseEnrichedResponse_EmptyFindingsSlice(t *testing.T) {
	text := `[{"check_id":"foo","explanation":"bar","impact":"baz","remediation":"fix"}]`
	out, err := parseEnrichedResponse(nil, text)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Errorf("expected empty output for nil findings, got %d", len(out))
	}
}

func TestParseEnrichedResponse_EmptyJSONArray(t *testing.T) {
	out, err := parseEnrichedResponse(testFindings, "[]")
	if err != nil {
		t.Fatal(err)
	}
	// All findings should fall back to their Description.
	for _, ef := range out {
		if ef.Explanation != ef.Finding.Description {
			t.Errorf("expected Description fallback, got %q", ef.Explanation)
		}
	}
}

func TestParseEnrichedResponse_TerraformFixParsed(t *testing.T) {
	text := `[{"check_id":"email.spoofable","explanation":"e","impact":"i","remediation":"r","terraform_fix":"resource {}"}]`
	out, err := parseEnrichedResponse(testFindings, text)
	if err != nil {
		t.Fatal(err)
	}
	if out[0].TerraformFix != "resource {}" {
		t.Errorf("TerraformFix not parsed: %q", out[0].TerraformFix)
	}
}
