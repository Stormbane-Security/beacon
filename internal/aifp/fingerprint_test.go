package aifp

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/playbook"
	"github.com/stormbane/beacon/internal/store"
)

// ── NeedsClassification ──────────────────────────────────────────────────────

func TestNeedsClassification_AllEmpty(t *testing.T) {
	ev := &playbook.Evidence{}
	if !NeedsClassification(ev) {
		t.Error("expected true when all classification fields are empty")
	}
}

func TestNeedsClassification_FrameworkSet(t *testing.T) {
	ev := &playbook.Evidence{Framework: "nextjs"}
	if NeedsClassification(ev) {
		t.Error("expected false when Framework is set")
	}
}

func TestNeedsClassification_ProxySet(t *testing.T) {
	ev := &playbook.Evidence{ProxyType: "traefik"}
	if NeedsClassification(ev) {
		t.Error("expected false when ProxyType is set")
	}
}

func TestNeedsClassification_CloudSet(t *testing.T) {
	ev := &playbook.Evidence{CloudProvider: "aws"}
	if NeedsClassification(ev) {
		t.Error("expected false when CloudProvider is set")
	}
}

func TestNeedsClassification_AuthSet(t *testing.T) {
	ev := &playbook.Evidence{AuthSystem: "auth0"}
	if NeedsClassification(ev) {
		t.Error("expected false when AuthSystem is set")
	}
}

func TestNeedsClassification_BackendServicesSet(t *testing.T) {
	ev := &playbook.Evidence{BackendServices: []string{"elasticsearch"}}
	if NeedsClassification(ev) {
		t.Error("expected false when BackendServices is non-empty")
	}
}

// ── MergeInto ────────────────────────────────────────────────────────────────

func TestMergeInto_FillsEmptyFields(t *testing.T) {
	r := &ClassifyResult{
		Framework:     "django",
		ProxyType:     "nginx",
		CloudProvider: "gcp",
		AuthSystem:    "okta",
		InfraLayer:    "reverse_proxy",
		IsKubernetes:  true,
		IsServerless:  false,
		IsReverseProxy: true,
		BackendServices: []string{"postgresql"},
		Confidence:    "high",
	}
	ev := &playbook.Evidence{}
	r.MergeInto(ev)

	if ev.Framework != "django" {
		t.Errorf("Framework not merged: got %q", ev.Framework)
	}
	if ev.ProxyType != "nginx" {
		t.Errorf("ProxyType not merged: got %q", ev.ProxyType)
	}
	if ev.CloudProvider != "gcp" {
		t.Errorf("CloudProvider not merged: got %q", ev.CloudProvider)
	}
	if ev.AuthSystem != "okta" {
		t.Errorf("AuthSystem not merged: got %q", ev.AuthSystem)
	}
	if ev.InfraLayer != "reverse_proxy" {
		t.Errorf("InfraLayer not merged: got %q", ev.InfraLayer)
	}
	if !ev.IsKubernetes {
		t.Error("IsKubernetes not merged")
	}
	if !ev.IsReverseProxy {
		t.Error("IsReverseProxy not merged")
	}
	if len(ev.BackendServices) != 1 || ev.BackendServices[0] != "postgresql" {
		t.Errorf("BackendServices not merged: got %v", ev.BackendServices)
	}
	if ev.ClassificationSource != "ai:high" {
		t.Errorf("ClassificationSource not set: got %q", ev.ClassificationSource)
	}
}

func TestMergeInto_NeverOverwritesDeterministic(t *testing.T) {
	r := &ClassifyResult{
		Framework:     "nextjs",
		CloudProvider: "aws",
		Confidence:    "high",
	}
	ev := &playbook.Evidence{
		Framework:            "rails",  // already set by deterministic rules
		CloudProvider:        "azure",  // already set
		ClassificationSource: "deterministic",
	}
	r.MergeInto(ev)

	if ev.Framework != "rails" {
		t.Errorf("Framework should not be overwritten: got %q", ev.Framework)
	}
	if ev.CloudProvider != "azure" {
		t.Errorf("CloudProvider should not be overwritten: got %q", ev.CloudProvider)
	}
	// ClassificationSource already set — should not be overwritten.
	if ev.ClassificationSource != "deterministic" {
		t.Errorf("ClassificationSource should not be overwritten: got %q", ev.ClassificationSource)
	}
}

func TestMergeInto_BackendServicesDeduplicated(t *testing.T) {
	r := &ClassifyResult{
		BackendServices: []string{"redis", "postgresql", "redis"}, // redis duplicated
		Confidence:      "medium",
	}
	ev := &playbook.Evidence{
		BackendServices: []string{"postgresql"}, // already has postgresql
	}
	r.MergeInto(ev)

	// Should have postgresql (existing) + redis (new). No duplicates.
	if len(ev.BackendServices) != 2 {
		t.Errorf("expected 2 backend services, got %d: %v", len(ev.BackendServices), ev.BackendServices)
	}
}

func TestMergeInto_IsServerlessOnlySetToTrue(t *testing.T) {
	r := &ClassifyResult{IsServerless: false}
	ev := &playbook.Evidence{IsServerless: true}
	r.MergeInto(ev)
	if !ev.IsServerless {
		t.Error("IsServerless should not be cleared by AI result with false")
	}
}

// ── UnknownTechFinding ────────────────────────────────────────────────────────

func TestUnknownTechFinding_HighConfidenceWithRules_ReturnsNil(t *testing.T) {
	r := &ClassifyResult{
		Confidence: "high",
		Framework:  "nextjs",
		ProposedRules: []store.FingerprintRule{
			{SignalType: "header", SignalKey: "x-nextjs", Field: "framework", Value: "nextjs", Confidence: 0.9},
		},
	}
	if f := r.UnknownTechFinding("api.example.com"); f != nil {
		t.Error("expected nil finding for high confidence with proposed rules")
	}
}

func TestUnknownTechFinding_MediumConfidence_ReturnsFinding(t *testing.T) {
	r := &ClassifyResult{
		Confidence:  "medium",
		Framework:   "django",
		ProposedRules: []store.FingerprintRule{
			{SignalType: "header", SignalKey: "server", Field: "framework", Value: "django", Confidence: 0.75},
		},
	}
	f := r.UnknownTechFinding("api.example.com")
	if f == nil {
		t.Fatal("expected a finding for medium confidence")
	}
	if f.CheckID != finding.CheckAIFPUnknownTech {
		t.Errorf("wrong CheckID: %s", f.CheckID)
	}
	if f.Severity != finding.SeverityInfo {
		t.Errorf("expected info severity, got %s", f.Severity)
	}
	if !strings.Contains(f.Title, "medium") {
		t.Errorf("title should mention confidence tier: %s", f.Title)
	}
	if f.Asset != "api.example.com" {
		t.Errorf("wrong asset: %s", f.Asset)
	}
	if !strings.Contains(f.ProofCommand, "beacon fingerprints") {
		t.Errorf("ProofCommand should mention fingerprints: %s", f.ProofCommand)
	}
}

func TestUnknownTechFinding_HighConfidenceNoRules_ReturnsFinding(t *testing.T) {
	// High confidence but no proposed rules → still emit the finding.
	r := &ClassifyResult{
		Confidence: "high",
		Framework:  "express",
	}
	f := r.UnknownTechFinding("app.example.com")
	if f == nil {
		t.Error("expected a finding when no proposed rules were saved")
	}
}

func TestUnknownTechFinding_NoTech_ShowsUnknown(t *testing.T) {
	r := &ClassifyResult{Confidence: "low"}
	f := r.UnknownTechFinding("mystery.example.com")
	if f == nil {
		t.Fatal("expected finding even with no tech detected")
	}
	if !strings.Contains(f.Title, "unknown") {
		t.Errorf("title should say 'unknown' when no tech: %s", f.Title)
	}
}

// ── Classify (via mock ChatFn) ────────────────────────────────────────────────

func TestClassify_ValidResponse_ParsedCorrectly(t *testing.T) {
	resp := `{
		"framework": "nextjs",
		"proxy_type": "cloudflare",
		"cloud_provider": "vercel",
		"auth_system": "",
		"infra_layer": "cdn_edge",
		"backend_services": ["redis"],
		"is_kubernetes": false,
		"is_serverless": true,
		"is_reverse_proxy": true,
		"confidence": "high",
		"signals": ["x-nextjs-cache header detected", "cf-ray header present"],
		"explanation": "Vercel-hosted Next.js behind Cloudflare CDN.",
		"suggested_scanners": ["jwt", "cors"],
		"proposed_rules": [
			{
				"signal_type": "header",
				"signal_key": "x-nextjs-cache",
				"signal_value": "",
				"field": "framework",
				"value": "nextjs",
				"confidence": 0.95
			}
		]
	}`

	chat := func(_ context.Context, _ string) (string, error) { return resp, nil }
	c := NewClassifier(chat, nil)
	ev := &playbook.Evidence{
		Headers:    map[string]string{"x-nextjs-cache": "HIT", "cf-ray": "abc123"},
		StatusCode: 200,
	}
	result, err := c.Classify(context.Background(), ev)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Framework != "nextjs" {
		t.Errorf("Framework: got %q, want nextjs", result.Framework)
	}
	if result.ProxyType != "cloudflare" {
		t.Errorf("ProxyType: got %q, want cloudflare", result.ProxyType)
	}
	if !result.IsServerless {
		t.Error("expected IsServerless=true")
	}
	if result.Confidence != "high" {
		t.Errorf("Confidence: got %q, want high", result.Confidence)
	}
	if len(result.SuggestedScanners) != 2 {
		t.Errorf("expected 2 suggested scanners, got %d", len(result.SuggestedScanners))
	}
	if len(result.ProposedRules) != 1 {
		t.Errorf("expected 1 proposed rule, got %d", len(result.ProposedRules))
	}
	if result.ProposedRules[0].Source != "ai" {
		t.Errorf("ProposedRule.Source: got %q, want ai", result.ProposedRules[0].Source)
	}
	if result.ProposedRules[0].Status != "pending" {
		t.Errorf("ProposedRule.Status: got %q, want pending", result.ProposedRules[0].Status)
	}
}

func TestClassify_WithMarkdownFences_ParsedCorrectly(t *testing.T) {
	resp := "```json\n{\"framework\": \"rails\", \"confidence\": \"medium\", \"proposed_rules\": []}\n```"
	chat := func(_ context.Context, _ string) (string, error) { return resp, nil }
	c := NewClassifier(chat, nil)
	ev := &playbook.Evidence{StatusCode: 200}
	result, err := c.Classify(context.Background(), ev)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Framework != "rails" {
		t.Errorf("Framework: got %q, want rails", result.Framework)
	}
}

func TestClassify_ChatError_PropagatesError(t *testing.T) {
	chat := func(_ context.Context, _ string) (string, error) {
		return "", errors.New("API timeout")
	}
	c := NewClassifier(chat, nil)
	ev := &playbook.Evidence{}
	_, err := c.Classify(context.Background(), ev)
	if err == nil {
		t.Fatal("expected error when chat fails")
	}
	if !strings.Contains(err.Error(), "aifp.Classify") {
		t.Errorf("error should be wrapped with aifp.Classify: %v", err)
	}
}

func TestClassify_MalformedJSON_ReturnsError(t *testing.T) {
	chat := func(_ context.Context, _ string) (string, error) {
		return "this is not json at all", nil
	}
	c := NewClassifier(chat, nil)
	ev := &playbook.Evidence{}
	_, err := c.Classify(context.Background(), ev)
	if err == nil {
		t.Fatal("expected error for no JSON object in response")
	}
}

func TestClassify_StoreNil_NoRulePersistenceAttempted(t *testing.T) {
	// With st=nil, proposed rules should still be returned but not persisted.
	// This test ensures no nil-dereference panic occurs.
	resp := `{"framework": "spring", "confidence": "high", "proposed_rules": [
		{"signal_type": "header", "signal_key": "x-spring", "field": "framework", "value": "spring", "confidence": 0.9}
	]}`
	chat := func(_ context.Context, _ string) (string, error) { return resp, nil }
	c := NewClassifier(chat, nil) // nil store
	ev := &playbook.Evidence{}
	result, err := c.Classify(context.Background(), ev)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.ProposedRules) != 1 {
		t.Errorf("expected 1 proposed rule in result even with nil store, got %d", len(result.ProposedRules))
	}
}

func TestClassify_StorePersistsRules(t *testing.T) {
	var saved []*store.FingerprintRule
	fakeStore := &fakeStore{upsert: func(r *store.FingerprintRule) {
		saved = append(saved, r)
	}}
	resp := `{"framework": "laravel", "confidence": "high", "proposed_rules": [
		{"signal_type": "cookie", "signal_value": "laravel_session", "field": "framework", "value": "laravel", "confidence": 0.92},
		{"signal_type": "header", "signal_key": "x-powered-by", "signal_value": "PHP", "field": "framework", "value": "php", "confidence": 0.8}
	]}`
	chat := func(_ context.Context, _ string) (string, error) { return resp, nil }
	c := NewClassifier(chat, fakeStore)
	ev := &playbook.Evidence{}
	result, err := c.Classify(context.Background(), ev)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.ProposedRules) != 2 {
		t.Errorf("expected 2 proposed rules, got %d", len(result.ProposedRules))
	}
	if len(saved) != 2 {
		t.Errorf("expected 2 rules persisted to store, got %d", len(saved))
	}
	for _, r := range saved {
		if r.Source != "ai" {
			t.Errorf("rule Source should be 'ai', got %q", r.Source)
		}
		if r.Status != "pending" {
			t.Errorf("rule Status should be 'pending', got %q", r.Status)
		}
		if r.CreatedAt.IsZero() {
			t.Error("rule CreatedAt should be set")
		}
	}
}

func TestClassify_ProposedRule_MissingFieldDropped(t *testing.T) {
	// Rule with empty Field should be skipped.
	resp := `{"framework": "flask", "confidence": "medium", "proposed_rules": [
		{"signal_type": "header", "signal_key": "x-flask", "signal_value": "flask", "field": "", "value": "flask", "confidence": 0.8}
	]}`
	chat := func(_ context.Context, _ string) (string, error) { return resp, nil }
	c := NewClassifier(chat, nil)
	ev := &playbook.Evidence{}
	result, err := c.Classify(context.Background(), ev)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.ProposedRules) != 0 {
		t.Errorf("expected 0 proposed rules (empty Field dropped), got %d", len(result.ProposedRules))
	}
}

// ── parseClassifyResponse helpers ────────────────────────────────────────────

func TestParseClassifyResponse_EmptyStringError(t *testing.T) {
	_, err := parseClassifyResponse("")
	if err == nil {
		t.Error("expected error for empty string")
	}
}

func TestParseClassifyResponse_OnlyBraces(t *testing.T) {
	result, err := parseClassifyResponse("{}")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Framework != "" {
		t.Errorf("expected empty framework for minimal JSON, got %q", result.Framework)
	}
}

// ── buildClassifyPrompt signal coverage ──────────────────────────────────────

func TestBuildClassifyPrompt_IncludesAllSignals(t *testing.T) {
	ev := &playbook.Evidence{
		StatusCode:      200,
		Headers:         map[string]string{"x-powered-by": "PHP/8.1"},
		Title:           "My App",
		Body512:         "<html>laravel",
		CertSANs:        []string{"api.example.com"},
		CertIssuer:      "Let's Encrypt",
		CNAMEChain:      []string{"example.com.cdn.cloudflare.net"},
		ASNOrg:          "CLOUDFLARENET",
		RespondingPaths: []string{"/api/v1"},
		ServiceVersions: map[string]string{"web_server": "nginx/1.24"},
		CookieNames:     []string{"PHPSESSID"},
		JARMFingerprint: "1234abcd5678efgh",
		FaviconHash:     "fnv1a:abc123",
		DNSSuffix:       ".example.com",
		// Already identified fields — should appear in prompt.
		Framework:     "laravel",
		ProxyType:     "cloudflare",
		CloudProvider: "aws",
	}
	prompt := buildClassifyPrompt(ev)

	checks := []string{
		"HTTP status: 200",
		"x-powered-by",
		"Page title: My App",
		"laravel",
		"TLS SAN: api.example.com",
		"Let's Encrypt",
		"cloudflare.net",
		"CLOUDFLARENET",
		"/api/v1",
		"nginx/1.24",
		"PHPSESSID",
		"JARM:",
		"Favicon hash",
		"DNS suffix:",
		"Already identified framework: laravel",
		"Already identified proxy: cloudflare",
		"Already identified cloud: aws",
	}
	for _, want := range checks {
		if !strings.Contains(prompt, want) {
			t.Errorf("prompt missing signal %q", want)
		}
	}
}

func TestBuildClassifyPrompt_TruncatesLongBody(t *testing.T) {
	long := strings.Repeat("A", 600)
	ev := &playbook.Evidence{Body512: long}
	prompt := buildClassifyPrompt(ev)
	// Body should be truncated to 300 chars + ellipsis.
	if strings.Contains(prompt, long) {
		t.Error("long body should be truncated in prompt")
	}
	if !strings.Contains(prompt, "…") {
		t.Error("truncated body should end with ellipsis")
	}
}

// ── fakeStore ────────────────────────────────────────────────────────────────

// fakeStore is a minimal store.Store implementation for testing rule persistence.
type fakeStore struct {
	upsert          func(r *store.FingerprintRule)
	savePlaybook    func(s *store.PlaybookSuggestion)
	store.Store // embed to satisfy interface; panics on any other call
}

func (f *fakeStore) UpsertFingerprintRule(_ context.Context, r *store.FingerprintRule) error {
	if f.upsert != nil {
		f.upsert(r)
	}
	return nil
}

func (f *fakeStore) SavePlaybookSuggestion(_ context.Context, s *store.PlaybookSuggestion) error {
	if f.savePlaybook != nil {
		f.savePlaybook(s)
	}
	return nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

func TestStripFences_BacktickJSON(t *testing.T) {
	input := "```json\n{\"key\": \"val\"}\n```"
	got := stripFences(input)
	if got != `{"key": "val"}` {
		t.Errorf("unexpected result: %q", got)
	}
}

func TestStripFences_BacktickNoLang(t *testing.T) {
	input := "```\n{\"key\": \"val\"}\n```"
	got := stripFences(input)
	if got != `{"key": "val"}` {
		t.Errorf("unexpected result: %q", got)
	}
}

func TestStripFences_NoFences_Unchanged(t *testing.T) {
	input := `{"key": "val"}`
	got := stripFences(input)
	if got != input {
		t.Errorf("no-fence input should be unchanged, got %q", got)
	}
}

func TestTrunc_ShortString_Unchanged(t *testing.T) {
	if got := trunc("hello", 10); got != "hello" {
		t.Errorf("unexpected: %q", got)
	}
}

func TestTrunc_LongString_Truncated(t *testing.T) {
	s := strings.Repeat("x", 20)
	got := trunc(s, 10)
	if len(got) > 15 { // 10 chars + ellipsis "…" (3 bytes)
		t.Errorf("string not truncated: %q", got)
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("truncated string should end with ellipsis: %q", got)
	}
}

// ── parseSeverity edge cases ──────────────────────────────────────────────────

func TestParseSeverity_AllValues(t *testing.T) {
	cases := []struct {
		input string
		want  finding.Severity
	}{
		{"critical", finding.SeverityCritical},
		{"CRITICAL", finding.SeverityCritical},
		{"high", finding.SeverityHigh},
		{"medium", finding.SeverityMedium},
		{"low", finding.SeverityLow},
		{"info", finding.SeverityInfo},
		{"unknown", finding.SeverityInfo},
		{"", finding.SeverityInfo},
	}
	for _, tc := range cases {
		got := parseSeverity(tc.input)
		if got != tc.want {
			t.Errorf("parseSeverity(%q): got %v, want %v", tc.input, got, tc.want)
		}
	}
}

// Ensure time is set on proposed rules saved to store.
func TestClassify_ProposedRuleCreatedAt_Set(t *testing.T) {
	before := time.Now()
	resp := `{"framework": "express", "confidence": "high", "proposed_rules": [
		{"signal_type": "header", "signal_key": "x-powered-by", "signal_value": "Express", "field": "framework", "value": "express", "confidence": 0.9}
	]}`
	chat := func(_ context.Context, _ string) (string, error) { return resp, nil }
	c := NewClassifier(chat, nil)
	result, _ := c.Classify(context.Background(), &playbook.Evidence{})
	if len(result.ProposedRules) == 0 {
		t.Fatal("expected at least 1 proposed rule")
	}
	after := time.Now()
	r := result.ProposedRules[0]
	if r.CreatedAt.Before(before) || r.CreatedAt.After(after) {
		t.Errorf("rule CreatedAt not set correctly: %v", r.CreatedAt)
	}
}

// ── deterministicConfirms ─────────────────────────────────────────────────────

func TestDeterministicConfirms_FrameworkMatch(t *testing.T) {
	r := &store.FingerprintRule{Field: "framework", Value: "nextjs"}
	ev := &playbook.Evidence{Framework: "nextjs"}
	if !deterministicConfirms(r, ev) {
		t.Error("expected match when framework values agree (case-insensitive)")
	}
}

func TestDeterministicConfirms_FrameworkCaseInsensitive(t *testing.T) {
	r := &store.FingerprintRule{Field: "framework", Value: "NextJS"}
	ev := &playbook.Evidence{Framework: "nextjs"}
	if !deterministicConfirms(r, ev) {
		t.Error("expected case-insensitive match")
	}
}

func TestDeterministicConfirms_FrameworkMismatch(t *testing.T) {
	r := &store.FingerprintRule{Field: "framework", Value: "rails"}
	ev := &playbook.Evidence{Framework: "nextjs"}
	if deterministicConfirms(r, ev) {
		t.Error("expected no match when framework values differ")
	}
}

func TestDeterministicConfirms_FrameworkEmpty(t *testing.T) {
	r := &store.FingerprintRule{Field: "framework", Value: "nextjs"}
	ev := &playbook.Evidence{Framework: ""}
	if deterministicConfirms(r, ev) {
		t.Error("expected no match when ev.Framework is empty (deterministic didn't identify it)")
	}
}

func TestDeterministicConfirms_ProxyType(t *testing.T) {
	r := &store.FingerprintRule{Field: "proxy_type", Value: "nginx"}
	ev := &playbook.Evidence{ProxyType: "nginx"}
	if !deterministicConfirms(r, ev) {
		t.Error("expected match for proxy_type")
	}
}

func TestDeterministicConfirms_CloudProvider(t *testing.T) {
	r := &store.FingerprintRule{Field: "cloud_provider", Value: "aws"}
	ev := &playbook.Evidence{CloudProvider: "AWS"}
	if !deterministicConfirms(r, ev) {
		t.Error("expected case-insensitive match for cloud_provider")
	}
}

func TestDeterministicConfirms_AuthSystem(t *testing.T) {
	r := &store.FingerprintRule{Field: "auth_system", Value: "auth0"}
	ev := &playbook.Evidence{AuthSystem: "auth0"}
	if !deterministicConfirms(r, ev) {
		t.Error("expected match for auth_system")
	}
}

func TestDeterministicConfirms_InfraLayer(t *testing.T) {
	r := &store.FingerprintRule{Field: "infra_layer", Value: "cdn_edge"}
	ev := &playbook.Evidence{InfraLayer: "cdn_edge"}
	if !deterministicConfirms(r, ev) {
		t.Error("expected match for infra_layer")
	}
}

func TestDeterministicConfirms_BackendServices_Match(t *testing.T) {
	r := &store.FingerprintRule{Field: "backend_services", Value: "redis"}
	ev := &playbook.Evidence{BackendServices: []string{"postgresql", "redis"}}
	if !deterministicConfirms(r, ev) {
		t.Error("expected match when value is in BackendServices list")
	}
}

func TestDeterministicConfirms_BackendServices_NoMatch(t *testing.T) {
	r := &store.FingerprintRule{Field: "backend_services", Value: "mongodb"}
	ev := &playbook.Evidence{BackendServices: []string{"postgresql", "redis"}}
	if deterministicConfirms(r, ev) {
		t.Error("expected no match when value not in BackendServices list")
	}
}

func TestDeterministicConfirms_EmptyRuleValue(t *testing.T) {
	r := &store.FingerprintRule{Field: "framework", Value: ""}
	ev := &playbook.Evidence{Framework: "nextjs"}
	if deterministicConfirms(r, ev) {
		t.Error("expected no match when rule Value is empty")
	}
}

func TestDeterministicConfirms_UnknownField(t *testing.T) {
	r := &store.FingerprintRule{Field: "unknown_field", Value: "whatever"}
	ev := &playbook.Evidence{Framework: "nextjs"}
	if deterministicConfirms(r, ev) {
		t.Error("expected no match for unknown field")
	}
}

// ── Confidence boost + tier escalation ────────────────────────────────────────

func TestClassify_ConfidenceBoost_AgreementBoostsRule(t *testing.T) {
	// The AI proposes framework=nextjs; ev already has Framework=nextjs from
	// deterministic rules. Agreement should boost the rule confidence by 15%.
	resp := `{
		"framework": "nextjs",
		"confidence": "medium",
		"proposed_rules": [
			{"signal_type": "header", "signal_key": "x-nextjs-cache", "signal_value": "HIT",
			 "field": "framework", "value": "nextjs", "confidence": 0.80}
		]
	}`
	chat := func(_ context.Context, _ string) (string, error) { return resp, nil }
	c := NewClassifier(chat, nil)
	ev := &playbook.Evidence{Framework: "nextjs"} // deterministic already identified it
	result, err := c.Classify(context.Background(), ev)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.ProposedRules) == 0 {
		t.Fatal("expected proposed rules")
	}
	boosted := result.ProposedRules[0].Confidence
	if boosted <= 0.80 {
		t.Errorf("expected confidence boosted above 0.80, got %.3f", boosted)
	}
	// 0.80 * 1.15 = 0.92 — check it's close.
	want := 0.80 * 1.15
	if boosted < want-0.001 || boosted > want+0.001 {
		t.Errorf("expected boosted confidence ~%.3f, got %.3f", want, boosted)
	}
}

func TestClassify_ConfidenceBoost_CapAt1(t *testing.T) {
	// A rule starting at confidence 0.95 should not exceed 1.0 after boost.
	resp := `{
		"framework": "rails",
		"confidence": "high",
		"proposed_rules": [
			{"signal_type": "cookie", "signal_value": "_session_id",
			 "field": "framework", "value": "rails", "confidence": 0.95}
		]
	}`
	chat := func(_ context.Context, _ string) (string, error) { return resp, nil }
	c := NewClassifier(chat, nil)
	ev := &playbook.Evidence{Framework: "rails"}
	result, _ := c.Classify(context.Background(), ev)
	if result.ProposedRules[0].Confidence > 1.0 {
		t.Errorf("confidence should not exceed 1.0, got %.3f", result.ProposedRules[0].Confidence)
	}
}

func TestClassify_TierEscalation_TwoConfirmedRulesPromoteMediumToHigh(t *testing.T) {
	// Two rules that agree with deterministic findings → medium → high.
	resp := `{
		"framework": "django",
		"proxy_type": "nginx",
		"confidence": "medium",
		"proposed_rules": [
			{"signal_type": "header", "signal_key": "x-frame-options", "signal_value": "DENY",
			 "field": "framework", "value": "django", "confidence": 0.82},
			{"signal_type": "header", "signal_key": "server", "signal_value": "nginx",
			 "field": "proxy_type", "value": "nginx", "confidence": 0.85}
		]
	}`
	chat := func(_ context.Context, _ string) (string, error) { return resp, nil }
	c := NewClassifier(chat, nil)
	ev := &playbook.Evidence{Framework: "django", ProxyType: "nginx"}
	result, err := c.Classify(context.Background(), ev)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Confidence != "high" {
		t.Errorf("expected confidence escalated to 'high', got %q", result.Confidence)
	}
}

func TestClassify_TierEscalation_OneConfirmedRuleNoEscalation(t *testing.T) {
	// Only one confirmed rule — stays at medium.
	resp := `{
		"framework": "django",
		"confidence": "medium",
		"proposed_rules": [
			{"signal_type": "header", "signal_key": "x-frame-options", "signal_value": "DENY",
			 "field": "framework", "value": "django", "confidence": 0.82}
		]
	}`
	chat := func(_ context.Context, _ string) (string, error) { return resp, nil }
	c := NewClassifier(chat, nil)
	ev := &playbook.Evidence{Framework: "django"}
	result, _ := c.Classify(context.Background(), ev)
	if result.Confidence != "medium" {
		t.Errorf("expected confidence to stay 'medium' with 1 confirmed rule, got %q", result.Confidence)
	}
}

func TestClassify_TierEscalation_AlreadyHighStaysHigh(t *testing.T) {
	// High confidence is never downgraded by the escalation logic.
	resp := `{
		"framework": "nextjs",
		"confidence": "high",
		"proposed_rules": [
			{"signal_type": "header", "signal_key": "x-nextjs-cache", "signal_value": "HIT",
			 "field": "framework", "value": "nextjs", "confidence": 0.9},
			{"signal_type": "header", "signal_key": "cf-ray", "signal_value": "",
			 "field": "proxy_type", "value": "cloudflare", "confidence": 0.88}
		]
	}`
	chat := func(_ context.Context, _ string) (string, error) { return resp, nil }
	c := NewClassifier(chat, nil)
	ev := &playbook.Evidence{Framework: "nextjs", ProxyType: "cloudflare"}
	result, _ := c.Classify(context.Background(), ev)
	if result.Confidence != "high" {
		t.Errorf("expected 'high' to be preserved, got %q", result.Confidence)
	}
}

func TestClassify_TierEscalation_LowNeverEscalated(t *testing.T) {
	// Low confidence is not escalated even with 2+ confirmed rules
	// (the escalation only applies when base is medium).
	resp := `{
		"framework": "nextjs",
		"confidence": "low",
		"proposed_rules": [
			{"signal_type": "header", "signal_key": "x-nextjs-cache", "signal_value": "HIT",
			 "field": "framework", "value": "nextjs", "confidence": 0.9},
			{"signal_type": "header", "signal_key": "cf-ray", "signal_value": "",
			 "field": "proxy_type", "value": "cloudflare", "confidence": 0.88}
		]
	}`
	chat := func(_ context.Context, _ string) (string, error) { return resp, nil }
	c := NewClassifier(chat, nil)
	ev := &playbook.Evidence{Framework: "nextjs", ProxyType: "cloudflare"}
	result, _ := c.Classify(context.Background(), ev)
	if result.Confidence != "low" {
		t.Errorf("expected 'low' to be unchanged, got %q", result.Confidence)
	}
}

func TestClassify_NoBoost_WhenNoAgreement(t *testing.T) {
	// AI proposes framework=nextjs but ev has Framework="" → no deterministic
	// confirmation → no boost.
	resp := `{
		"framework": "nextjs",
		"confidence": "medium",
		"proposed_rules": [
			{"signal_type": "header", "signal_key": "x-nextjs-cache", "signal_value": "HIT",
			 "field": "framework", "value": "nextjs", "confidence": 0.80}
		]
	}`
	chat := func(_ context.Context, _ string) (string, error) { return resp, nil }
	c := NewClassifier(chat, nil)
	ev := &playbook.Evidence{} // deterministic found nothing
	result, _ := c.Classify(context.Background(), ev)
	if result.ProposedRules[0].Confidence != 0.80 {
		t.Errorf("expected confidence unchanged at 0.80, got %.3f", result.ProposedRules[0].Confidence)
	}
}

// ── buildProposedPlaybook ─────────────────────────────────────────────────────

func TestBuildProposedPlaybook_LowConfidenceReturnsNil(t *testing.T) {
	r := &ClassifyResult{
		Confidence:        "low",
		Framework:         "nextjs",
		SuggestedScanners: []string{"jwt"},
	}
	if buildProposedPlaybook(r) != nil {
		t.Error("expected nil for low confidence")
	}
}

func TestBuildProposedPlaybook_NoTechPartsReturnsNil(t *testing.T) {
	// All classification fields empty → no meaningful playbook name.
	r := &ClassifyResult{
		Confidence:        "high",
		SuggestedScanners: []string{"jwt"},
	}
	if buildProposedPlaybook(r) != nil {
		t.Error("expected nil when no tech parts resolved")
	}
}

func TestBuildProposedPlaybook_NoSuggestedScannersReturnsNil(t *testing.T) {
	r := &ClassifyResult{
		Confidence: "high",
		Framework:  "nextjs",
		// no suggested scanners
	}
	if buildProposedPlaybook(r) != nil {
		t.Error("expected nil when no suggested scanners")
	}
}

func TestBuildProposedPlaybook_LowConfidenceRulesStillProducesPlaybook(t *testing.T) {
	// Low-confidence proposed rules are excluded from the YAML match conditions,
	// but the high-level Framework field still produces a framework_contains clause,
	// so the playbook is not nil.
	r := &ClassifyResult{
		Confidence:        "medium",
		Framework:         "nextjs",
		SuggestedScanners: []string{"jwt"},
		Signals:           []string{"x-nextjs header"},
		Explanation:       "Next.js detected.",
		ProposedRules: []store.FingerprintRule{
			{SignalType: "header", SignalKey: "x-nextjs", SignalValue: "HIT",
				Field: "framework", Value: "nextjs", Confidence: 0.5}, // below 0.75 threshold
		},
	}
	sugg := buildProposedPlaybook(r)
	if sugg == nil {
		t.Fatal("expected non-nil: Framework field always produces a match condition")
	}
	if !strings.Contains(sugg.SuggestedYAML, "framework_contains") {
		t.Errorf("expected framework_contains in YAML despite low-confidence rules:\n%s", sugg.SuggestedYAML)
	}
}

func TestBuildProposedPlaybook_ValidResult(t *testing.T) {
	r := &ClassifyResult{
		Confidence:        "high",
		Framework:         "nextjs",
		SuggestedScanners: []string{"jwt", "cors"},
		Signals:           []string{"x-nextjs-cache header"},
		Explanation:       "Vercel-hosted Next.js.",
	}
	sugg := buildProposedPlaybook(r)
	if sugg == nil {
		t.Fatal("expected non-nil suggestion")
	}
	if sugg.Status != "pending" {
		t.Errorf("expected status=pending, got %q", sugg.Status)
	}
	if sugg.SuggestionKind != "playbook" {
		t.Errorf("expected kind=playbook, got %q", sugg.SuggestionKind)
	}
	if sugg.Priority != "high" {
		t.Errorf("expected priority=high, got %q", sugg.Priority)
	}
	if sugg.TargetPlaybook != "nextjs" {
		t.Errorf("expected target=nextjs, got %q", sugg.TargetPlaybook)
	}
	if sugg.Type != "new" {
		t.Errorf("expected type=new, got %q", sugg.Type)
	}
	if sugg.SuggestedYAML == "" {
		t.Error("expected non-empty YAML")
	}
	if sugg.Reasoning == "" {
		t.Error("expected non-empty Reasoning")
	}
	if sugg.CreatedAt.IsZero() {
		t.Error("expected CreatedAt to be set")
	}
}

func TestBuildProposedPlaybook_PlaybookNameSanitized(t *testing.T) {
	// Tech name with spaces/dashes/slashes should be snake_cased.
	r := &ClassifyResult{
		Confidence:        "medium",
		Framework:         "Ruby on Rails",
		SuggestedScanners: []string{"cors"},
		Signals:           []string{"x-rails header"},
		Explanation:       "Ruby on Rails app.",
	}
	sugg := buildProposedPlaybook(r)
	if sugg == nil {
		t.Fatal("expected non-nil suggestion")
	}
	if sugg.TargetPlaybook != "ruby_on_rails" {
		t.Errorf("expected sanitized name 'ruby_on_rails', got %q", sugg.TargetPlaybook)
	}
}

// ── buildPlaybookYAML ─────────────────────────────────────────────────────────

func TestBuildPlaybookYAML_EmptyWhenNoMatchConditions(t *testing.T) {
	r := &ClassifyResult{} // nothing set
	yaml := buildPlaybookYAML("unknown", r)
	if yaml != "" {
		t.Errorf("expected empty string when no match conditions, got:\n%s", yaml)
	}
}

func TestBuildPlaybookYAML_FrameworkMatchCondition(t *testing.T) {
	r := &ClassifyResult{
		Framework:         "nextjs",
		SuggestedScanners: []string{"jwt"},
		Confidence:        "high",
		Signals:           []string{"x-nextjs-cache"},
		Explanation:       "Next.js detected.",
	}
	yaml := buildPlaybookYAML("nextjs", r)
	if !strings.Contains(yaml, `framework_contains: "nextjs"`) {
		t.Errorf("expected framework_contains in YAML, got:\n%s", yaml)
	}
	if !strings.Contains(yaml, "surface:") {
		t.Errorf("expected surface section in YAML, got:\n%s", yaml)
	}
	if !strings.Contains(yaml, "jwt") {
		t.Errorf("expected jwt in surface scanners, got:\n%s", yaml)
	}
}

func TestBuildPlaybookYAML_DeepOnlyScannerInDeepSection(t *testing.T) {
	r := &ClassifyResult{
		Framework:         "nextjs",
		SuggestedScanners: []string{"ratelimit", "smuggling"}, // deep-only
		Confidence:        "high",
		Signals:           []string{"x-nextjs-cache"},
		Explanation:       "Next.js detected.",
	}
	yaml := buildPlaybookYAML("nextjs", r)
	if !strings.Contains(yaml, "deep:") {
		t.Errorf("expected deep section for deep-only scanners, got:\n%s", yaml)
	}
	// deep-only scanners should NOT appear in surface section.
	surfaceIdx := strings.Index(yaml, "surface:")
	deepIdx := strings.Index(yaml, "deep:")
	if surfaceIdx >= 0 && deepIdx >= 0 && surfaceIdx < deepIdx {
		surfaceSection := yaml[surfaceIdx:deepIdx]
		if strings.Contains(surfaceSection, "ratelimit") {
			t.Error("ratelimit (deep-only) should not appear in surface section")
		}
	}
}

func TestBuildPlaybookYAML_SurfaceOnlyScannerNotInDeep(t *testing.T) {
	r := &ClassifyResult{
		Framework:         "django",
		SuggestedScanners: []string{"dlp", "webcontent"}, // surface-only
		Confidence:        "medium",
		Signals:           []string{"x-django"},
		Explanation:       "Django detected.",
	}
	yaml := buildPlaybookYAML("django", r)
	if strings.Contains(yaml, "deep:") {
		t.Errorf("surface-only scanners should not produce a deep section:\n%s", yaml)
	}
	if !strings.Contains(yaml, "surface:") {
		t.Errorf("expected surface section for surface-only scanners:\n%s", yaml)
	}
}

func TestBuildPlaybookYAML_ProposedRuleHeaderInMatchSection(t *testing.T) {
	r := &ClassifyResult{
		Confidence:        "high",
		SuggestedScanners: []string{"jwt"},
		Signals:           []string{"x-powered-by: Express"},
		Explanation:       "Express.js.",
		ProposedRules: []store.FingerprintRule{
			{SignalType: "header", SignalKey: "x-powered-by", SignalValue: "Express",
				Field: "framework", Value: "express", Confidence: 0.9},
		},
	}
	// No high-level framework/proxy fields set → only rule-based match conditions.
	yaml := buildPlaybookYAML("express", r)
	if !strings.Contains(yaml, `name: "x-powered-by"`) {
		t.Errorf("expected header name in YAML, got:\n%s", yaml)
	}
	if !strings.Contains(yaml, `contains: "Express"`) {
		t.Errorf("expected header contains in YAML, got:\n%s", yaml)
	}
}

func TestBuildPlaybookYAML_LowConfidenceRulesExcluded(t *testing.T) {
	r := &ClassifyResult{
		Framework:         "nextjs", // provides a match condition via framework_contains
		SuggestedScanners: []string{"jwt"},
		Confidence:        "medium",
		Signals:           []string{},
		Explanation:       "Next.js.",
		ProposedRules: []store.FingerprintRule{
			{SignalType: "body", SignalValue: "some-weak-signal",
				Field: "framework", Value: "nextjs", Confidence: 0.5}, // below 0.75
		},
	}
	yaml := buildPlaybookYAML("nextjs", r)
	if strings.Contains(yaml, "some-weak-signal") {
		t.Errorf("low-confidence rules should be excluded from YAML:\n%s", yaml)
	}
}

func TestBuildPlaybookYAML_CookieRuleUsesSetCookieHeader(t *testing.T) {
	r := &ClassifyResult{
		Confidence:        "high",
		SuggestedScanners: []string{"cors"},
		Signals:           []string{"laravel_session cookie"},
		Explanation:       "Laravel detected via session cookie.",
		ProposedRules: []store.FingerprintRule{
			{SignalType: "cookie", SignalValue: "laravel_session",
				Field: "framework", Value: "laravel", Confidence: 0.9},
		},
	}
	yaml := buildPlaybookYAML("laravel", r)
	if !strings.Contains(yaml, `name: "set-cookie"`) {
		t.Errorf("cookie signal should map to set-cookie header in YAML:\n%s", yaml)
	}
	if !strings.Contains(yaml, `contains: "laravel_session"`) {
		t.Errorf("expected cookie value in YAML:\n%s", yaml)
	}
}

func TestBuildPlaybookYAML_AllSignalTypes(t *testing.T) {
	// Verify each signal_type produces the expected match clause.
	cases := []struct {
		rule    store.FingerprintRule
		wantKey string
	}{
		{store.FingerprintRule{SignalType: "body", SignalValue: "wp-content", Field: "framework", Value: "wordpress", Confidence: 0.9}, "body_contains"},
		{store.FingerprintRule{SignalType: "title", SignalValue: "WordPress", Field: "framework", Value: "wordpress", Confidence: 0.9}, "title_contains"},
		{store.FingerprintRule{SignalType: "path", SignalValue: "/wp-login.php", Field: "framework", Value: "wordpress", Confidence: 0.9}, "path_responds"},
		{store.FingerprintRule{SignalType: "cname", SignalValue: ".wpengine.com", Field: "proxy_type", Value: "wpengine", Confidence: 0.9}, "cname_contains"},
		{store.FingerprintRule{SignalType: "dns_suffix", SignalValue: ".vercel.app", Field: "cloud_provider", Value: "vercel", Confidence: 0.9}, "dns_suffix"},
		{store.FingerprintRule{SignalType: "asn_org", SignalValue: "CLOUDFLARENET", Field: "proxy_type", Value: "cloudflare", Confidence: 0.9}, "asn_org_contains"},
	}
	for _, tc := range cases {
		r := &ClassifyResult{
			Confidence:        "high",
			SuggestedScanners: []string{"cors"},
			Signals:           []string{tc.rule.SignalValue},
			Explanation:       "Test.",
			ProposedRules:     []store.FingerprintRule{tc.rule},
		}
		yaml := buildPlaybookYAML("test", r)
		if !strings.Contains(yaml, tc.wantKey) {
			t.Errorf("signal_type=%q: expected %q in YAML:\n%s", tc.rule.SignalType, tc.wantKey, yaml)
		}
	}
}

func TestClassify_StoreReceivesPlaybookSuggestion(t *testing.T) {
	// When the classifier produces medium+ confidence with scanners,
	// it should persist a PlaybookSuggestion via the store.
	var saved *store.PlaybookSuggestion
	fs := &fakeStore{
		savePlaybook: func(s *store.PlaybookSuggestion) { saved = s },
	}
	resp := `{
		"framework": "nextjs",
		"confidence": "high",
		"signals": ["x-nextjs-cache header"],
		"explanation": "Next.js behind Vercel.",
		"suggested_scanners": ["jwt", "cors"],
		"proposed_rules": [
			{"signal_type": "header", "signal_key": "x-nextjs-cache", "signal_value": "HIT",
			 "field": "framework", "value": "nextjs", "confidence": 0.92}
		]
	}`
	chat := func(_ context.Context, _ string) (string, error) { return resp, nil }
	c := NewClassifier(chat, fs)
	_, err := c.Classify(context.Background(), &playbook.Evidence{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if saved == nil {
		t.Fatal("expected PlaybookSuggestion to be saved to store")
	}
	if saved.Status != "pending" {
		t.Errorf("expected status=pending, got %q", saved.Status)
	}
	if saved.SuggestedYAML == "" {
		t.Error("expected non-empty YAML in saved suggestion")
	}
}

func TestClassify_LowConfidenceNoPlaybookSaved(t *testing.T) {
	saved := false
	fs := &fakeStore{
		savePlaybook: func(_ *store.PlaybookSuggestion) { saved = true },
	}
	resp := `{
		"framework": "nextjs",
		"confidence": "low",
		"signals": ["weak signal"],
		"explanation": "Uncertain.",
		"suggested_scanners": ["jwt"],
		"proposed_rules": []
	}`
	chat := func(_ context.Context, _ string) (string, error) { return resp, nil }
	c := NewClassifier(chat, fs)
	_, err := c.Classify(context.Background(), &playbook.Evidence{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if saved {
		t.Error("low confidence should not trigger PlaybookSuggestion persistence")
	}
}

// ── trunc: UTF-8 safety ──────────────────────────────────────────────────────

func TestTrunc_MultiByte_DoesNotSplitRune(t *testing.T) {
	// "日本語テスト" is 6 runes but 18 bytes. Truncating to 3 runes should
	// produce valid UTF-8, not a broken byte sequence.
	s := "日本語テスト"
	got := trunc(s, 3)
	if got != "日本語…" {
		t.Errorf("expected '日本語…', got %q", got)
	}
	// Verify the result is valid UTF-8.
	for i, r := range got {
		if r == '\uFFFD' {
			t.Errorf("invalid UTF-8 at byte %d", i)
		}
	}
}

func TestTrunc_MultiByte_ExactLength_NoTruncation(t *testing.T) {
	s := "日本語" // 3 runes
	got := trunc(s, 3)
	if got != s {
		t.Errorf("string with exact rune count should not be truncated: got %q", got)
	}
}

func TestTrunc_MixedASCIIAndMultiByte(t *testing.T) {
	s := "abc日本語def"
	got := trunc(s, 5) // "abc日本" + "…"
	if got != "abc日本…" {
		t.Errorf("expected 'abc日本…', got %q", got)
	}
}

func TestTrunc_EmptyString(t *testing.T) {
	got := trunc("", 10)
	if got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestTrunc_ZeroLimit(t *testing.T) {
	got := trunc("hello", 0)
	if got != "…" {
		t.Errorf("expected just ellipsis for zero limit, got %q", got)
	}
}

// ── stripFences edge cases ───────────────────────────────────────────────────

func TestStripFences_NestedFences(t *testing.T) {
	// Outer fences should be stripped; inner content preserved.
	input := "```json\n{\"nested\": \"```value```\"}\n```"
	got := stripFences(input)
	// After stripping ```json ... ```, we get the inner content.
	if !strings.Contains(got, "nested") {
		t.Errorf("nested content should be preserved: %q", got)
	}
}

func TestStripFences_UnclosedFence(t *testing.T) {
	// Opening fence with no closing fence — should return everything after the fence marker.
	input := "```json\n{\"key\": \"val\"}"
	got := stripFences(input)
	if !strings.Contains(got, "key") {
		t.Errorf("unclosed fence should still return content after marker: %q", got)
	}
}

func TestStripFences_EmptyString(t *testing.T) {
	got := stripFences("")
	if got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestStripFences_OnlyFenceMarkers(t *testing.T) {
	input := "```json\n```"
	got := stripFences(input)
	if got != "" {
		t.Errorf("expected empty string between fences, got %q", got)
	}
}

// ── nonEmpty edge cases ──────────────────────────────────────────────────────

func TestNonEmpty_AllEmpty(t *testing.T) {
	got := nonEmpty("", "", "")
	if len(got) != 0 {
		t.Errorf("expected empty slice, got %v", got)
	}
}

func TestNonEmpty_Mixed(t *testing.T) {
	got := nonEmpty("", "a", "", "b", "")
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("expected [a b], got %v", got)
	}
}

// ── MergeInto: BackendServices with empty strings ────────────────────────────

func TestMergeInto_BackendServicesFiltersEmptyStrings(t *testing.T) {
	r := &ClassifyResult{
		BackendServices: []string{"", "redis", ""},
		Confidence:      "medium",
	}
	ev := &playbook.Evidence{}
	r.MergeInto(ev)
	for _, s := range ev.BackendServices {
		if s == "" {
			t.Error("empty strings should be filtered from BackendServices")
		}
	}
	if len(ev.BackendServices) != 1 || ev.BackendServices[0] != "redis" {
		t.Errorf("expected [redis], got %v", ev.BackendServices)
	}
}

// ── MergeInto: ClassificationSource not set when Confidence is empty ─────────

func TestMergeInto_NoConfidence_NoClassificationSource(t *testing.T) {
	r := &ClassifyResult{Framework: "flask", Confidence: ""}
	ev := &playbook.Evidence{}
	r.MergeInto(ev)
	if ev.ClassificationSource != "" {
		t.Errorf("expected empty ClassificationSource when Confidence is empty, got %q", ev.ClassificationSource)
	}
}

// ── UnknownTechFinding: DiscoveredAt is set ──────────────────────────────────

func TestUnknownTechFinding_DiscoveredAtSet(t *testing.T) {
	before := time.Now()
	r := &ClassifyResult{Confidence: "low", Framework: "express"}
	f := r.UnknownTechFinding("api.example.com")
	after := time.Now()
	if f == nil {
		t.Fatal("expected non-nil finding")
	}
	if f.DiscoveredAt.Before(before) || f.DiscoveredAt.After(after) {
		t.Errorf("DiscoveredAt out of range: %v", f.DiscoveredAt)
	}
}

// ── UnknownTechFinding: Evidence fields ──────────────────────────────────────

func TestUnknownTechFinding_EvidenceContainsExpectedKeys(t *testing.T) {
	r := &ClassifyResult{
		Confidence:  "medium",
		Framework:   "django",
		Explanation: "Django detected via CSRF cookie.",
	}
	f := r.UnknownTechFinding("app.example.com")
	if f == nil {
		t.Fatal("expected non-nil finding")
	}
	if f.Evidence["ai_classification"] != "django" {
		t.Errorf("expected ai_classification=django, got %v", f.Evidence["ai_classification"])
	}
	if f.Evidence["confidence"] != "medium" {
		t.Errorf("expected confidence=medium, got %v", f.Evidence["confidence"])
	}
	if f.Evidence["explanation"] != "Django detected via CSRF cookie." {
		t.Errorf("expected explanation in evidence, got %v", f.Evidence["explanation"])
	}
}

// ── buildClassifyPrompt: nil maps don't panic ────────────────────────────────

func TestBuildClassifyPrompt_NilMaps_NoPanic(t *testing.T) {
	ev := &playbook.Evidence{
		Headers:         nil,
		ServiceVersions: nil,
		StatusCode:      0,
	}
	// Should not panic.
	prompt := buildClassifyPrompt(ev)
	if prompt == "" {
		t.Error("expected non-empty prompt even with nil maps")
	}
}

// ── buildPlaybookYAML: mixed surface and deep scanners ───────────────────────

func TestBuildPlaybookYAML_MixedSurfaceAndDeepScanners(t *testing.T) {
	r := &ClassifyResult{
		Framework:         "nextjs",
		SuggestedScanners: []string{"jwt", "dlp", "smuggling", "cors"},
		Confidence:        "high",
		Signals:           []string{"x-nextjs-cache"},
		Explanation:       "Next.js detected.",
	}
	yaml := buildPlaybookYAML("nextjs", r)

	// jwt and cors are general → appear in both surface and deep.
	// dlp is surface-only → only in surface.
	// smuggling is deep-only → only in deep.
	if !strings.Contains(yaml, "surface:") {
		t.Error("expected surface section")
	}
	if !strings.Contains(yaml, "deep:") {
		t.Error("expected deep section")
	}

	// Verify smuggling is in deep but not surface.
	surfaceIdx := strings.Index(yaml, "surface:")
	deepIdx := strings.Index(yaml, "deep:")
	if surfaceIdx >= 0 && deepIdx > surfaceIdx {
		surfaceSection := yaml[surfaceIdx:deepIdx]
		if strings.Contains(surfaceSection, "smuggling") {
			t.Error("smuggling (deep-only) should not appear in surface section")
		}
		deepSection := yaml[deepIdx:]
		if !strings.Contains(deepSection, "smuggling") {
			t.Error("smuggling should appear in deep section")
		}
		// dlp should be in surface but not deep.
		if !strings.Contains(surfaceSection, "dlp") {
			t.Error("dlp (surface-only) should appear in surface section")
		}
		if strings.Contains(deepSection, "dlp") {
			t.Error("dlp (surface-only) should not appear in deep section")
		}
	}
}

// ── buildPlaybookYAML: header_present (key only, no value) ───────────────────

func TestBuildPlaybookYAML_HeaderKeyOnly_HeaderPresent(t *testing.T) {
	r := &ClassifyResult{
		Confidence:        "high",
		SuggestedScanners: []string{"cors"},
		Signals:           []string{"x-custom-header"},
		Explanation:       "Custom header detected.",
		ProposedRules: []store.FingerprintRule{
			{SignalType: "header", SignalKey: "x-custom-header", SignalValue: "",
				Field: "framework", Value: "custom", Confidence: 0.9},
		},
	}
	yaml := buildPlaybookYAML("custom", r)
	if !strings.Contains(yaml, `header_present: "x-custom-header"`) {
		t.Errorf("expected header_present for key-only header rule:\n%s", yaml)
	}
}

// ── Classify: context cancellation ───────────────────────────────────────────

func TestClassify_ContextCancelled_ReturnsError(t *testing.T) {
	chat := func(ctx context.Context, _ string) (string, error) {
		return "", ctx.Err()
	}
	c := NewClassifier(chat, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	_, err := c.Classify(ctx, &playbook.Evidence{})
	if err == nil {
		t.Fatal("expected error when context is cancelled")
	}
}

// ── parseClassifyResponse: JSON embedded in prose ────────────────────────────

func TestParseClassifyResponse_JSONEmbeddedInProse(t *testing.T) {
	// LLM sometimes returns prose around JSON. The parser should extract it.
	input := `Here is my analysis:
{"framework": "express", "confidence": "high", "proposed_rules": []}
Hope that helps!`
	result, err := parseClassifyResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Framework != "express" {
		t.Errorf("expected framework=express, got %q", result.Framework)
	}
}

// ── parseClassifyResponse: multiple JSON objects picks outer ─────────────────

func TestParseClassifyResponse_NestedBraces(t *testing.T) {
	// Nested JSON should still parse correctly — parser uses first { and last }.
	input := `{"framework": "rails", "confidence": "high", "proposed_rules": [{"signal_type": "header", "signal_key": "x-rails", "signal_value": "", "field": "framework", "value": "rails", "confidence": 0.9}]}`
	result, err := parseClassifyResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Framework != "rails" {
		t.Errorf("expected framework=rails, got %q", result.Framework)
	}
	if len(result.ProposedRules) != 1 {
		t.Errorf("expected 1 proposed rule, got %d", len(result.ProposedRules))
	}
}

// ── Classify: proposed rule with missing SignalType is dropped ────────────────

func TestClassify_ProposedRule_MissingSignalTypeDropped(t *testing.T) {
	resp := `{"framework": "flask", "confidence": "medium", "proposed_rules": [
		{"signal_type": "", "signal_key": "x-flask", "signal_value": "flask", "field": "framework", "value": "flask", "confidence": 0.8}
	]}`
	chat := func(_ context.Context, _ string) (string, error) { return resp, nil }
	c := NewClassifier(chat, nil)
	result, err := c.Classify(context.Background(), &playbook.Evidence{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.ProposedRules) != 0 {
		t.Errorf("expected 0 proposed rules (empty SignalType dropped), got %d", len(result.ProposedRules))
	}
}

// ── Classify: proposed rule with missing Value is dropped ────────────────────

func TestClassify_ProposedRule_MissingValueDropped(t *testing.T) {
	resp := `{"framework": "flask", "confidence": "medium", "proposed_rules": [
		{"signal_type": "header", "signal_key": "x-flask", "signal_value": "flask", "field": "framework", "value": "", "confidence": 0.8}
	]}`
	chat := func(_ context.Context, _ string) (string, error) { return resp, nil }
	c := NewClassifier(chat, nil)
	result, err := c.Classify(context.Background(), &playbook.Evidence{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.ProposedRules) != 0 {
		t.Errorf("expected 0 proposed rules (empty Value dropped), got %d", len(result.ProposedRules))
	}
}
