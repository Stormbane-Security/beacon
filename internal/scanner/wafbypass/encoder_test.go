package wafbypass

import (
	"strings"
	"testing"
)

func TestAllEncoders_ReturnsAll(t *testing.T) {
	encoders := AllEncoders()
	if len(encoders) != 12 {
		t.Errorf("expected 12 encoders, got %d", len(encoders))
	}
	// Every encoder must have a name, description, and encode function.
	for _, enc := range encoders {
		if enc.Name == "" {
			t.Error("encoder has empty name")
		}
		if enc.Description == "" {
			t.Errorf("encoder %q has empty description", enc.Name)
		}
		if enc.Encode == nil {
			t.Errorf("encoder %q has nil Encode func", enc.Name)
		}
	}
}

func TestEncodePayload_ProducesVariants(t *testing.T) {
	variants := EncodePayload("' OR 1=1-- -")
	if len(variants) == 0 {
		t.Fatal("EncodePayload should produce at least one variant")
	}
	for _, v := range variants {
		if v.Encoded == v.Original {
			t.Errorf("encoder %q produced identical output", v.Encoder)
		}
		if v.Encoder == "" {
			t.Error("variant has empty encoder name")
		}
	}
}

func TestDoubleURLEncode(t *testing.T) {
	result := encodeDoubleURL("' OR 1=1")
	// Double encoded should not contain a raw single quote
	if strings.Contains(result, "'") {
		t.Error("double URL encode should not contain raw single quote")
	}
	// Should contain %25 (the encoding of %)
	if !strings.Contains(result, "%25") {
		t.Error("double URL encode should contain %25 (encoded percent)")
	}
}

func TestUnicodeEscape(t *testing.T) {
	result := encodeUnicodeEscape("<script>alert(1)</script>")
	if strings.Contains(result, "<") || strings.Contains(result, ">") {
		t.Error("unicode escape should not contain raw angle brackets")
	}
	if !strings.Contains(result, `\u003c`) {
		t.Error("expected \\u003c for <")
	}
	if !strings.Contains(result, `\u003e`) {
		t.Error("expected \\u003e for >")
	}
}

func TestHTMLEntity(t *testing.T) {
	result := encodeHTMLEntity("<script>")
	if strings.Contains(result, "<") {
		t.Error("HTML entity encode should not contain raw <")
	}
	if !strings.Contains(result, "&#60;") {
		t.Error("expected &#60; for <")
	}
}

func TestMixedCase(t *testing.T) {
	result := encodeMixedCase("<script>")
	lower := strings.ToLower(result)
	if lower != strings.ToLower("<script>") {
		t.Errorf("mixed case changed content: got %q", result)
	}
	// Should not be all lowercase or all uppercase
	if result == strings.ToLower(result) && result == strings.ToUpper(result) {
		// only if the input has letters
		t.Error("mixed case should alternate case on letters")
	}
}

func TestNullByte(t *testing.T) {
	result := encodeNullByte("<script>")
	if !strings.HasPrefix(result, "%00") {
		t.Error("null byte encode should prepend %00")
	}
}

func TestSQLComment(t *testing.T) {
	result := encodeSQLComment("UNION SELECT 1,2,3")
	if !strings.Contains(result, "/**/") {
		t.Error("SQL comment encoder should insert /**/ into keywords")
	}
	// Original SQL meaning should be preserved (after removing comments)
	cleaned := strings.ReplaceAll(result, "/**/", "")
	if strings.ToUpper(cleaned) != "UNION SELECT 1,2,3" {
		t.Errorf("SQL comment encoding corrupted payload: %q -> cleaned: %q", result, cleaned)
	}
}

func TestWhitespaceSub(t *testing.T) {
	result := encodeWhitespaceSub("OR 1=1")
	if strings.Contains(result, " ") {
		t.Error("whitespace sub should replace all spaces")
	}
	// Should contain one of the alternatives
	hasAlt := strings.Contains(result, "\t") || strings.Contains(result, "\n") || strings.Contains(result, "/**/")
	if !hasAlt {
		t.Error("whitespace sub should use tab, newline, or SQL comment")
	}
}

func TestJSONSmuggle(t *testing.T) {
	result := encodeJSONSmuggle("' OR 1=1")
	if !strings.HasPrefix(result, `{"q":"`) {
		t.Error("JSON smuggle should wrap in JSON object")
	}
	if !strings.HasSuffix(result, `"}`) {
		t.Error("JSON smuggle should end with closing brace")
	}
}

func TestMultipartWrap(t *testing.T) {
	result := encodeMultipartWrap("test payload")
	if !strings.Contains(result, "Content-Disposition: form-data") {
		t.Error("multipart wrap should contain Content-Disposition header")
	}
	if !strings.Contains(result, "test payload") {
		t.Error("multipart wrap should contain the payload")
	}
}

func TestParamPollution(t *testing.T) {
	result := encodeParamPollution("' OR 1=1")
	if !strings.HasPrefix(result, "q=harmless&q=") {
		t.Error("param pollution should duplicate parameter with clean value first")
	}
}

func TestSQLCaseVariation(t *testing.T) {
	result := encodeSQLCaseVariation("UNION SELECT")
	// Should not be all uppercase anymore
	if result == "UNION SELECT" {
		t.Error("SQL case variation should change case of keywords")
	}
	// Case-insensitive comparison should still match
	if strings.ToUpper(result) != "UNION SELECT" {
		t.Errorf("SQL case variation corrupted content: %q", result)
	}
}

func TestHexEncodeSQL(t *testing.T) {
	result := encodeHexSQL("' OR 1=1")
	if strings.Contains(result, "'") {
		t.Error("hex encode should replace single quotes")
	}
	if !strings.Contains(result, "0x27") {
		t.Error("hex encode should use 0x27 for single quote")
	}
}

func TestEncodePayload_XSSPayload(t *testing.T) {
	variants := EncodePayload("<script>alert(1)</script>")
	if len(variants) == 0 {
		t.Fatal("should produce variants for XSS payload")
	}
	// At least unicode, html entity, mixed case, null byte should produce variants
	encoderNames := make(map[string]bool)
	for _, v := range variants {
		encoderNames[v.Encoder] = true
	}
	expected := []string{"unicode_escape", "html_entity", "mixed_case", "null_byte"}
	for _, name := range expected {
		if !encoderNames[name] {
			t.Errorf("expected encoder %q to produce a variant for XSS payload", name)
		}
	}
}
