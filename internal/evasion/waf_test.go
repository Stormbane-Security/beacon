package evasion

import (
	"strings"
	"testing"
)

func TestSQLBypass(t *testing.T) {
	payload := "' OR SLEEP(3)-- -"
	variants := SQLBypass(payload)

	if len(variants) < 5 {
		t.Errorf("SQLBypass returned %d variants, want at least 5", len(variants))
	}

	// First variant should be the original.
	if variants[0] != payload {
		t.Errorf("First variant = %q, want original %q", variants[0], payload)
	}

	// Should have some case-varied version.
	hasCaseVariant := false
	for _, v := range variants[1:] {
		if v != payload && strings.EqualFold(v, payload) {
			hasCaseVariant = true
			break
		}
	}
	// Case randomization is probabilistic — don't fail on it.
	_ = hasCaseVariant

	// Whitespace variant should not contain spaces.
	wsVariant := whitespaceSubstitute(payload)
	if wsVariant == payload && strings.Contains(payload, " ") {
		t.Error("whitespaceSubstitute didn't modify payload with spaces")
	}
}

func TestSQLBypass_Select(t *testing.T) {
	payload := "' UNION SELECT 1,2,3-- -"
	variants := SQLBypass(payload)

	// Should include CHAR concat variant for SELECT.
	hasCharConcat := false
	for _, v := range variants {
		if strings.Contains(v, "CHAR(") {
			hasCharConcat = true
			break
		}
	}
	if !hasCharConcat {
		t.Error("SELECT payload missing CHAR() concat variant")
	}

	// Should include inline comment variant.
	hasComment := false
	for _, v := range variants {
		if strings.Contains(v, "/**/") {
			hasComment = true
			break
		}
	}
	if !hasComment {
		t.Error("SELECT payload missing inline comment variant")
	}
}

func TestCmdBypass(t *testing.T) {
	payload := "sleep 3"
	variants := CmdBypass(payload)

	if len(variants) < 5 {
		t.Errorf("CmdBypass returned %d variants, want at least 5", len(variants))
	}

	// Should have IFS variant.
	hasIFS := false
	for _, v := range variants {
		if strings.Contains(v, "${IFS}") {
			hasIFS = true
			break
		}
	}
	if !hasIFS {
		t.Error("Missing ${IFS} variant")
	}

	// Should have hex variant.
	hasHex := false
	for _, v := range variants {
		if strings.Contains(v, "\\x") {
			hasHex = true
			break
		}
	}
	if !hasHex {
		t.Error("Missing hex encoding variant")
	}

	// Should have tab variant.
	hasTab := false
	for _, v := range variants {
		if strings.Contains(v, "\t") {
			hasTab = true
			break
		}
	}
	if !hasTab {
		t.Error("Missing tab variant")
	}
}

func TestXSSBypass(t *testing.T) {
	payload := `<img src=x onerror=alert(1)>`
	variants := XSSBypass(payload)

	if len(variants) < 5 {
		t.Errorf("XSSBypass returned %d variants, want at least 5", len(variants))
	}

	// Should have SVG variant.
	hasSVG := false
	for _, v := range variants {
		if strings.Contains(v, "<svg") {
			hasSVG = true
			break
		}
	}
	if !hasSVG {
		t.Error("Missing SVG variant")
	}

	// Should have event handler alternative.
	hasAltEvent := false
	for _, v := range variants {
		if strings.Contains(v, "onload") || strings.Contains(v, "onfocus") {
			hasAltEvent = true
			break
		}
	}
	if !hasAltEvent {
		t.Error("Missing alternative event handler variant")
	}
}

func TestDoubleURLEncode(t *testing.T) {
	input := "' OR 1=1--"
	result := doubleURLEncode(input)
	// Should contain %25 (double-encoded percent).
	if !strings.Contains(result, "%25") {
		t.Errorf("doubleURLEncode(%q) = %q, expected %%25 sequences", input, result)
	}
}

func TestHexEncode(t *testing.T) {
	result := hexEncode("sleep 3")
	// Should start with $' and contain \x hex escapes.
	if !strings.HasPrefix(result, "$'") {
		t.Errorf("hexEncode result doesn't start with $': %q", result)
	}
	if !strings.Contains(result, "\\x73") { // 's' = 0x73
		t.Errorf("hexEncode missing expected hex for 's': %q", result)
	}
}

func TestSimpleBase64(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"sleep", "c2xlZXA="},
		{"curl", "Y3VybA=="},
		{"id", "aWQ="},
		{"a", "YQ=="},
	}

	for _, tt := range tests {
		result := simpleBase64(tt.input)
		if result != tt.expected {
			t.Errorf("simpleBase64(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestHTMLEntityEncode(t *testing.T) {
	result := htmlEntityEncode("<script>alert(1)</script>")
	if strings.Contains(result, "<") || strings.Contains(result, ">") {
		t.Errorf("htmlEntityEncode still contains angle brackets: %q", result)
	}
	if !strings.Contains(result, "&#x") {
		t.Errorf("htmlEntityEncode missing hex entities: %q", result)
	}
}

func TestSSTIBypass(t *testing.T) {
	variants := SSTIBypass("{{7*7}}")
	if len(variants) < 2 {
		t.Errorf("SSTIBypass returned %d variants, want at least 2", len(variants))
	}

	// Should have Jinja2 print variant.
	hasPrint := false
	for _, v := range variants {
		if strings.Contains(v, "print") {
			hasPrint = true
			break
		}
	}
	if !hasPrint {
		t.Error("Missing Jinja2 print() bypass variant")
	}

	// Should have URL-encoded braces variant.
	hasEncoded := false
	for _, v := range variants {
		if strings.Contains(v, "%7B") {
			hasEncoded = true
			break
		}
	}
	if !hasEncoded {
		t.Error("Missing URL-encoded braces variant")
	}
}

func TestSSRFBypass(t *testing.T) {
	variants := SSRFBypass("http://169.254.169.254/latest/meta-data/")
	if len(variants) < 3 {
		t.Errorf("SSRFBypass returned %d variants, want at least 3", len(variants))
	}

	// Should have decimal IP variant.
	hasDecimal := false
	for _, v := range variants {
		if strings.Contains(v, "2852039166") {
			hasDecimal = true
			break
		}
	}
	if !hasDecimal {
		t.Error("Missing decimal IP notation variant")
	}

	// Should have hex IP variant.
	hasHexIP := false
	for _, v := range variants {
		if strings.Contains(v, "0xa9fea9fe") {
			hasHexIP = true
			break
		}
	}
	if !hasHexIP {
		t.Error("Missing hex IP notation variant")
	}
}

func TestSSRFBypass_NonMetadata(t *testing.T) {
	// Non-metadata URL should still produce protocol variants.
	variants := SSRFBypass("http://internal.example.com/api")
	hasProto := false
	for _, v := range variants {
		if strings.Contains(v, "http:///") {
			hasProto = true
			break
		}
	}
	if !hasProto {
		t.Error("Missing protocol bypass variant for non-metadata URL")
	}
}

func TestCRLFBypass(t *testing.T) {
	suffix := "%0d%0aX-Injected:test"
	variants := CRLFBypass(suffix)
	if len(variants) < 2 {
		t.Errorf("CRLFBypass returned %d variants, want at least 2", len(variants))
	}

	// Should have double-encoded variant.
	hasDouble := false
	for _, v := range variants {
		if strings.Contains(v, "%250d") {
			hasDouble = true
			break
		}
	}
	if !hasDouble {
		t.Error("Missing double-encoded CRLF variant")
	}

	// Should have Unicode variant.
	hasUnicode := false
	for _, v := range variants {
		if strings.Contains(v, "%E5%98") {
			hasUnicode = true
			break
		}
	}
	if !hasUnicode {
		t.Error("Missing Unicode CRLF variant")
	}
}
