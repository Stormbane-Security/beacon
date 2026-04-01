package enrichment

import "testing"

func TestSanitizeAIField_StripHTMLTags(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"<script>alert('xss')</script>", "alert('xss')"},
		{"<b>bold</b> text", "bold text"},
		{"<a href='http://evil.com'>click</a>", "click"},
		{"<img src=x onerror=alert(1)>", ""},
		{"no tags here", "no tags here"},
		{"<div><p>nested</p></div>", "nested"},
	}
	for _, tt := range tests {
		got := sanitizeAIField(tt.input)
		if got != tt.want {
			t.Errorf("sanitizeAIField(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSanitizeAIField_StripJavascriptURIs(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"javascript:alert(1)", "alert(1)"},
		{"JavaScript:void(0)", "void(0)"},
		{"JAVASCRIPT:exploit()", "exploit()"},
		{"click javascript:here", "click here"},
		{"no uri here", "no uri here"},
	}
	for _, tt := range tests {
		got := sanitizeAIField(tt.input)
		if got != tt.want {
			t.Errorf("sanitizeAIField(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSanitizeAIField_StripHTMLEntities(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// The regex matches numeric HTML entities (&#60; &#x3C;) but not
		// named entities (&lt; &gt;). This is intentional — named entities
		// are safe text in AI responses and don't indicate injection.
		{"&#60;img&#62;", "img"},
		{"&#x3C;div&#x3E;", "div"},
		{"normal text", "normal text"},
		{"a &#xFF; b", "a  b"},
		// Named entities are preserved (not stripped).
		{"&lt;script&gt;", "&lt;script&gt;"},
	}
	for _, tt := range tests {
		got := sanitizeAIField(tt.input)
		if got != tt.want {
			t.Errorf("sanitizeAIField(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSanitizeAIField_PreservesNormalText(t *testing.T) {
	inputs := []string{
		"This is a normal remediation step.",
		"Update the TLS configuration to disable SSLv2 and SSLv3.",
		"Run: openssl s_client -connect example.com:443",
		"Step 1: Check the config\nStep 2: Apply the fix",
		"Contains special chars: @#$%^&*()[]{}|\\",
	}
	for _, input := range inputs {
		got := sanitizeAIField(input)
		if got != input {
			t.Errorf("sanitizeAIField(%q) = %q, want input preserved", input, got)
		}
	}
}

func TestSanitizeAIField_EmptyString(t *testing.T) {
	got := sanitizeAIField("")
	if got != "" {
		t.Errorf("sanitizeAIField(%q) = %q, want empty", "", got)
	}
}

func TestSanitizeAIField_CombinedAttack(t *testing.T) {
	// A string combining multiple attack vectors.
	input := `<script>javascript:alert(&#60;1&#62;)</script>`
	got := sanitizeAIField(input)
	// Processing order: tags first, then entities, then javascript: URIs.
	// After stripping tags: "javascript:alert(&#60;1&#62;)"
	// After stripping numeric entities: "javascript:alert(1)"
	// After stripping javascript: URIs: "alert(1)"
	if got != "alert(1)" {
		t.Errorf("sanitizeAIField(combined attack) = %q, want %q", got, "alert(1)")
	}
}

func TestSanitizeAIField_NumericEntityWithoutSemicolon(t *testing.T) {
	// The regex matches numeric entities with or without trailing semicolon.
	input := "data &#60 more"
	got := sanitizeAIField(input)
	if got != "data  more" {
		t.Errorf("sanitizeAIField(%q) = %q, want %q", input, got, "data  more")
	}
}
