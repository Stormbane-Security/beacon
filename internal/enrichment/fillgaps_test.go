package enrichment

import (
	"testing"
)

func TestParseFillGapsResponse_ValidJSON(t *testing.T) {
	input := `{
		"proposed_rules": [{
			"signal_type": "header",
			"signal_key": "x-powered-by",
			"signal_value": "express",
			"field": "framework",
			"value": "express",
			"confidence": 0.9,
			"reasoning": "X-Powered-By header reveals Express.js"
		}],
		"missed_technologies": [{
			"asset": "example.com",
			"technology": "Express.js",
			"evidence": "X-Powered-By: Express",
			"security_relevance": "Framework fingerprinting"
		}]
	}`

	result, err := parseFillGapsResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.ProposedRules) != 1 {
		t.Fatalf("expected 1 proposed rule, got %d", len(result.ProposedRules))
	}
	r := result.ProposedRules[0]
	if r.SignalType != "header" {
		t.Errorf("signal_type = %q, want %q", r.SignalType, "header")
	}
	if r.Field != "framework" {
		t.Errorf("field = %q, want %q", r.Field, "framework")
	}
	if r.Confidence != 0.9 {
		t.Errorf("confidence = %f, want 0.9", r.Confidence)
	}
	if len(result.MissedTechnologies) != 1 {
		t.Fatalf("expected 1 missed technology, got %d", len(result.MissedTechnologies))
	}
	if result.MissedTechnologies[0].Technology != "Express.js" {
		t.Errorf("missed technology = %q, want %q", result.MissedTechnologies[0].Technology, "Express.js")
	}
}

func TestParseFillGapsResponse_InvalidSignalType(t *testing.T) {
	input := `{
		"proposed_rules": [{
			"signal_type": "invalid",
			"signal_key": "x-custom",
			"signal_value": "foo",
			"field": "framework",
			"value": "bar",
			"confidence": 0.8,
			"reasoning": "test"
		}],
		"missed_technologies": []
	}`

	result, err := parseFillGapsResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.ProposedRules) != 0 {
		t.Errorf("expected invalid signal_type to be filtered out, got %d rules", len(result.ProposedRules))
	}
}

func TestParseFillGapsResponse_InvalidField(t *testing.T) {
	input := `{
		"proposed_rules": [{
			"signal_type": "header",
			"signal_key": "x-custom",
			"signal_value": "foo",
			"field": "unknown",
			"value": "bar",
			"confidence": 0.8,
			"reasoning": "test"
		}],
		"missed_technologies": []
	}`

	result, err := parseFillGapsResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.ProposedRules) != 0 {
		t.Errorf("expected invalid field to be filtered out, got %d rules", len(result.ProposedRules))
	}
}

func TestParseFillGapsResponse_EmptySignalValue(t *testing.T) {
	input := `{
		"proposed_rules": [{
			"signal_type": "header",
			"signal_key": "x-custom",
			"signal_value": "",
			"field": "framework",
			"value": "bar",
			"confidence": 0.8,
			"reasoning": "test"
		}],
		"missed_technologies": []
	}`

	result, err := parseFillGapsResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.ProposedRules) != 0 {
		t.Errorf("expected empty signal_value to be filtered out, got %d rules", len(result.ProposedRules))
	}
}

func TestParseFillGapsResponse_EmptyValue(t *testing.T) {
	input := `{
		"proposed_rules": [{
			"signal_type": "header",
			"signal_key": "x-custom",
			"signal_value": "foo",
			"field": "framework",
			"value": "",
			"confidence": 0.8,
			"reasoning": "test"
		}],
		"missed_technologies": []
	}`

	result, err := parseFillGapsResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.ProposedRules) != 0 {
		t.Errorf("expected empty value to be filtered out, got %d rules", len(result.ProposedRules))
	}
}

func TestParseFillGapsResponse_ConfidenceClampedZero(t *testing.T) {
	input := `{
		"proposed_rules": [{
			"signal_type": "body",
			"signal_key": "pattern",
			"signal_value": "django",
			"field": "framework",
			"value": "django",
			"confidence": 0,
			"reasoning": "test"
		}],
		"missed_technologies": []
	}`

	result, err := parseFillGapsResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.ProposedRules) != 1 {
		t.Fatalf("expected 1 proposed rule, got %d", len(result.ProposedRules))
	}
	if result.ProposedRules[0].Confidence != 0.3 {
		t.Errorf("confidence = %f, want 0.3 (clamped from 0)", result.ProposedRules[0].Confidence)
	}
}

func TestParseFillGapsResponse_ConfidenceClampedNegative(t *testing.T) {
	input := `{
		"proposed_rules": [{
			"signal_type": "cookie",
			"signal_key": "session",
			"signal_value": "rails",
			"field": "framework",
			"value": "rails",
			"confidence": -0.5,
			"reasoning": "test"
		}],
		"missed_technologies": []
	}`

	result, err := parseFillGapsResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.ProposedRules) != 1 {
		t.Fatalf("expected 1 proposed rule, got %d", len(result.ProposedRules))
	}
	if result.ProposedRules[0].Confidence != 0.3 {
		t.Errorf("confidence = %f, want 0.3 (clamped from -0.5)", result.ProposedRules[0].Confidence)
	}
}

func TestParseFillGapsResponse_ConfidenceClampedAboveOne(t *testing.T) {
	input := `{
		"proposed_rules": [{
			"signal_type": "server",
			"signal_key": "server",
			"signal_value": "nginx",
			"field": "proxy_type",
			"value": "nginx",
			"confidence": 1.5,
			"reasoning": "test"
		}],
		"missed_technologies": []
	}`

	result, err := parseFillGapsResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.ProposedRules) != 1 {
		t.Fatalf("expected 1 proposed rule, got %d", len(result.ProposedRules))
	}
	if result.ProposedRules[0].Confidence != 0.3 {
		t.Errorf("confidence = %f, want 0.3 (clamped from 1.5)", result.ProposedRules[0].Confidence)
	}
}

func TestParseFillGapsResponse_ConfidencePreserved(t *testing.T) {
	input := `{
		"proposed_rules": [{
			"signal_type": "path",
			"signal_key": "/api",
			"signal_value": "graphql",
			"field": "backend_services",
			"value": "graphql",
			"confidence": 0.85,
			"reasoning": "test"
		}],
		"missed_technologies": []
	}`

	result, err := parseFillGapsResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.ProposedRules) != 1 {
		t.Fatalf("expected 1 proposed rule, got %d", len(result.ProposedRules))
	}
	if result.ProposedRules[0].Confidence != 0.85 {
		t.Errorf("confidence = %f, want 0.85 (preserved)", result.ProposedRules[0].Confidence)
	}
}

func TestParseFillGapsResponse_MalformedJSON(t *testing.T) {
	input := `this is not json at all`

	result, err := parseFillGapsResponse(input)
	if err != nil {
		t.Fatalf("malformed JSON should not return error, got: %v", err)
	}
	if len(result.ProposedRules) != 0 {
		t.Errorf("expected no proposed rules for malformed JSON, got %d", len(result.ProposedRules))
	}
}

func TestParseFillGapsResponse_MarkdownCodeFence(t *testing.T) {
	input := "Here is the analysis:\n```json\n" + `{
		"proposed_rules": [{
			"signal_type": "cname",
			"signal_key": "cdn",
			"signal_value": "cloudfront",
			"field": "cloud_provider",
			"value": "aws",
			"confidence": 0.95,
			"reasoning": "CNAME points to cloudfront.net"
		}],
		"missed_technologies": []
	}` + "\n```\nEnd of response."

	result, err := parseFillGapsResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.ProposedRules) != 1 {
		t.Fatalf("expected 1 proposed rule from code-fenced JSON, got %d", len(result.ProposedRules))
	}
	if result.ProposedRules[0].SignalType != "cname" {
		t.Errorf("signal_type = %q, want %q", result.ProposedRules[0].SignalType, "cname")
	}
}

func TestParseFillGapsResponse_MixedValidAndInvalid(t *testing.T) {
	input := `{
		"proposed_rules": [
			{
				"signal_type": "header",
				"signal_key": "x-powered-by",
				"signal_value": "express",
				"field": "framework",
				"value": "express",
				"confidence": 0.9,
				"reasoning": "valid rule"
			},
			{
				"signal_type": "invalid_type",
				"signal_key": "x-custom",
				"signal_value": "foo",
				"field": "framework",
				"value": "bar",
				"confidence": 0.8,
				"reasoning": "invalid signal type"
			},
			{
				"signal_type": "body",
				"signal_key": "pattern",
				"signal_value": "rails",
				"field": "unknown_field",
				"value": "rails",
				"confidence": 0.7,
				"reasoning": "invalid field"
			},
			{
				"signal_type": "cookie",
				"signal_key": "session",
				"signal_value": "",
				"field": "framework",
				"value": "flask",
				"confidence": 0.6,
				"reasoning": "empty signal value"
			},
			{
				"signal_type": "server",
				"signal_key": "server",
				"signal_value": "nginx",
				"field": "proxy_type",
				"value": "nginx",
				"confidence": 0.85,
				"reasoning": "second valid rule"
			}
		],
		"missed_technologies": [
			{
				"asset": "example.com",
				"technology": "Redis",
				"evidence": "redis error page in body",
				"security_relevance": "backend exposure"
			}
		]
	}`

	result, err := parseFillGapsResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.ProposedRules) != 2 {
		t.Errorf("expected 2 valid proposed rules, got %d", len(result.ProposedRules))
	}
	if len(result.MissedTechnologies) != 1 {
		t.Errorf("expected 1 missed technology, got %d", len(result.MissedTechnologies))
	}
	if result.MissedTechnologies[0].Asset != "example.com" {
		t.Errorf("missed technology asset = %q, want %q", result.MissedTechnologies[0].Asset, "example.com")
	}
}

func TestParseFillGapsResponse_AllSignalTypes(t *testing.T) {
	validTypes := []string{"header", "body", "server", "cookie", "path", "cname"}
	for _, st := range validTypes {
		input := `{"proposed_rules": [{"signal_type": "` + st + `", "signal_key": "k", "signal_value": "v", "field": "framework", "value": "x", "confidence": 0.8, "reasoning": "test"}], "missed_technologies": []}`
		result, err := parseFillGapsResponse(input)
		if err != nil {
			t.Fatalf("signal_type %q: unexpected error: %v", st, err)
		}
		if len(result.ProposedRules) != 1 {
			t.Errorf("signal_type %q: expected 1 rule, got %d", st, len(result.ProposedRules))
		}
	}
}

func TestParseFillGapsResponse_AllFields(t *testing.T) {
	validFields := []string{"framework", "proxy_type", "auth_system", "cloud_provider", "infra_layer", "backend_services"}
	for _, f := range validFields {
		input := `{"proposed_rules": [{"signal_type": "header", "signal_key": "k", "signal_value": "v", "field": "` + f + `", "value": "x", "confidence": 0.8, "reasoning": "test"}], "missed_technologies": []}`
		result, err := parseFillGapsResponse(input)
		if err != nil {
			t.Fatalf("field %q: unexpected error: %v", f, err)
		}
		if len(result.ProposedRules) != 1 {
			t.Errorf("field %q: expected 1 rule, got %d", f, len(result.ProposedRules))
		}
	}
}

func TestParseFillGapsResponse_ValuesLowercased(t *testing.T) {
	input := `{
		"proposed_rules": [{
			"signal_type": "Header",
			"signal_key": "X-Powered-By",
			"signal_value": "Express",
			"field": "framework",
			"value": "Express",
			"confidence": 0.9,
			"reasoning": "test"
		}],
		"missed_technologies": []
	}`

	result, err := parseFillGapsResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Validation is case-insensitive: "Header" should be accepted and
	// stored as lowercase "header".
	if len(result.ProposedRules) != 1 {
		t.Fatalf("expected 1 proposed rule (case-insensitive match), got %d", len(result.ProposedRules))
	}
	if result.ProposedRules[0].SignalType != "header" {
		t.Errorf("expected signal_type lowercased to 'header', got %q", result.ProposedRules[0].SignalType)
	}
	if result.ProposedRules[0].Value != "express" {
		t.Errorf("expected value lowercased to 'express', got %q", result.ProposedRules[0].Value)
	}
}

func TestParseFillGapsResponse_EmptyRulesAndTechnologies(t *testing.T) {
	input := `{"proposed_rules": [], "missed_technologies": []}`

	result, err := parseFillGapsResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.ProposedRules) != 0 {
		t.Errorf("expected 0 proposed rules, got %d", len(result.ProposedRules))
	}
	if len(result.MissedTechnologies) != 0 {
		t.Errorf("expected 0 missed technologies, got %d", len(result.MissedTechnologies))
	}
}

func TestParseFillGapsResponse_ConfidenceExactlyOne(t *testing.T) {
	input := `{
		"proposed_rules": [{
			"signal_type": "header",
			"signal_key": "k",
			"signal_value": "v",
			"field": "framework",
			"value": "x",
			"confidence": 1.0,
			"reasoning": "test"
		}],
		"missed_technologies": []
	}`

	result, err := parseFillGapsResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.ProposedRules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(result.ProposedRules))
	}
	if result.ProposedRules[0].Confidence != 1.0 {
		t.Errorf("confidence = %f, want 1.0 (exactly at boundary)", result.ProposedRules[0].Confidence)
	}
}
