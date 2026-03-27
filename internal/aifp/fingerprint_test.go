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
	upsert func(r *store.FingerprintRule)
	store.Store // embed to satisfy interface; panics on any other call
}

func (f *fakeStore) UpsertFingerprintRule(_ context.Context, r *store.FingerprintRule) error {
	if f.upsert != nil {
		f.upsert(r)
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
