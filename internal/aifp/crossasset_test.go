package aifp

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stormbane/beacon/internal/finding"
)

// ── Analyze: empty findings shortcircuit ──────────────────────────────────────

func TestAnalyze_EmptyFindings_NoAICall(t *testing.T) {
	called := false
	chat := func(_ context.Context, _ string) (string, error) {
		called = true
		return "", nil
	}
	a := NewCrossAnalyzer(chat)
	result, err := a.Analyze(context.Background(), nil, "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if called {
		t.Error("AI should not be called for empty findings")
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.CrossFindings) != 0 || result.Summary != "" {
		t.Error("empty findings should produce empty result")
	}
}

// ── Analyze: valid AI response ────────────────────────────────────────────────

func TestAnalyze_ValidResponse_CrossFindingsPerAsset(t *testing.T) {
	resp := `{
		"summary": "Auth bypass found across login and API assets.",
		"attack_chains": ["Step 1 (login.example.com): jwt.alg_none → Step 2 (api.example.com): cors.wildcard_origin → Full account takeover"],
		"cross_findings": [
			{
				"assets": ["login.example.com", "api.example.com"],
				"check_id": "cross.shared_jwt_weakness",
				"severity": "critical",
				"title": "Shared JWT weakness across auth and API",
				"description": "Both assets accept alg=none JWTs, enabling cross-service token reuse."
			}
		],
		"additional_scans": {
			"login.example.com": ["cors", "ratelimit"]
		}
	}`
	chat := func(_ context.Context, _ string) (string, error) { return resp, nil }
	a := NewCrossAnalyzer(chat)

	findings := []finding.Finding{
		makeFinding("jwt.alg_none", "login.example.com", finding.SeverityHigh, "JWT alg=none"),
		makeFinding("cors.wildcard_origin", "api.example.com", finding.SeverityHigh, "CORS wildcard"),
	}
	result, err := a.Analyze(context.Background(), findings, "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Summary preserved.
	if result.Summary != "Auth bypass found across login and API assets." {
		t.Errorf("unexpected Summary: %q", result.Summary)
	}

	// Attack chains.
	if len(result.AttackChains) != 1 {
		t.Errorf("expected 1 attack chain, got %d", len(result.AttackChains))
	}

	// One cross-finding emitted per involved asset → 2 findings for 2 assets.
	if len(result.CrossFindings) != 2 {
		t.Errorf("expected 2 cross findings (one per asset), got %d", len(result.CrossFindings))
	}

	// Verify per-asset assignment.
	assets := map[string]bool{}
	for _, f := range result.CrossFindings {
		assets[f.Asset] = true
		if f.CheckID != "cross.shared_jwt_weakness" {
			t.Errorf("wrong CheckID: %s", f.CheckID)
		}
		if f.Severity != finding.SeverityCritical {
			t.Errorf("wrong Severity: %s", f.Severity)
		}
		if f.Module != "aifp" {
			t.Errorf("wrong Module: %s", f.Module)
		}
		if f.Scanner != "crossasset" {
			t.Errorf("wrong Scanner: %s", f.Scanner)
		}
		// Evidence must include involved_assets and attack_chains.
		if _, ok := f.Evidence["involved_assets"]; !ok {
			t.Error("finding evidence missing involved_assets")
		}
		if _, ok := f.Evidence["attack_chains"]; !ok {
			t.Error("finding evidence missing attack_chains")
		}
		if !strings.Contains(f.ProofCommand, "beacon scan --domain example.com") {
			t.Errorf("ProofCommand should reference root domain: %s", f.ProofCommand)
		}
		if f.DiscoveredAt.IsZero() {
			t.Error("DiscoveredAt not set")
		}
	}
	if !assets["login.example.com"] {
		t.Error("expected cross finding for login.example.com")
	}
	if !assets["api.example.com"] {
		t.Error("expected cross finding for api.example.com")
	}

	// Additional scans returned.
	if scans, ok := result.AdditionalScans["login.example.com"]; !ok {
		t.Error("expected additional scans for login.example.com")
	} else if len(scans) != 2 {
		t.Errorf("expected 2 additional scanners, got %d", len(scans))
	}
}

// ── Analyze: cross finding with missing title is dropped ────────────────────

func TestAnalyze_CrossFindingMissingTitle_Dropped(t *testing.T) {
	resp := `{
		"summary": "test",
		"cross_findings": [
			{"assets": ["a.example.com", "b.example.com"], "check_id": "cross.foo", "severity": "high", "title": "", "description": "no title"}
		]
	}`
	chat := func(_ context.Context, _ string) (string, error) { return resp, nil }
	a := NewCrossAnalyzer(chat)
	findings := []finding.Finding{makeFinding("check.a", "a.example.com", finding.SeverityHigh, "A")}
	result, _ := a.Analyze(context.Background(), findings, "example.com")
	if len(result.CrossFindings) != 0 {
		t.Errorf("cross finding with empty title should be dropped, got %d", len(result.CrossFindings))
	}
}

// ── Analyze: cross finding with no assets is dropped ────────────────────────

func TestAnalyze_CrossFindingNoAssets_Dropped(t *testing.T) {
	resp := `{
		"summary": "test",
		"cross_findings": [
			{"assets": [], "check_id": "cross.foo", "severity": "high", "title": "Foo", "description": "no assets"}
		]
	}`
	chat := func(_ context.Context, _ string) (string, error) { return resp, nil }
	a := NewCrossAnalyzer(chat)
	findings := []finding.Finding{makeFinding("check.a", "a.example.com", finding.SeverityHigh, "A")}
	result, _ := a.Analyze(context.Background(), findings, "example.com")
	if len(result.CrossFindings) != 0 {
		t.Errorf("cross finding with no assets should be dropped, got %d", len(result.CrossFindings))
	}
}

// ── Analyze: missing check_id falls back to default ─────────────────────────

func TestAnalyze_CrossFindingMissingCheckID_UsesDefault(t *testing.T) {
	resp := `{
		"summary": "test",
		"cross_findings": [
			{"assets": ["a.example.com"], "check_id": "", "severity": "medium", "title": "Shared config", "description": "desc"}
		]
	}`
	chat := func(_ context.Context, _ string) (string, error) { return resp, nil }
	a := NewCrossAnalyzer(chat)
	findings := []finding.Finding{makeFinding("check.a", "a.example.com", finding.SeverityHigh, "A")}
	result, _ := a.Analyze(context.Background(), findings, "example.com")
	if len(result.CrossFindings) == 0 {
		t.Fatal("expected at least one cross finding")
	}
	if result.CrossFindings[0].CheckID != finding.CheckAIFPCrossAsset {
		t.Errorf("expected default CheckID %s, got %s", finding.CheckAIFPCrossAsset, result.CrossFindings[0].CheckID)
	}
}

// ── Analyze: AI chat error propagated ────────────────────────────────────────

func TestAnalyze_ChatError_ReturnsError(t *testing.T) {
	chat := func(_ context.Context, _ string) (string, error) {
		return "", errors.New("connection refused")
	}
	a := NewCrossAnalyzer(chat)
	findings := []finding.Finding{makeFinding("check.a", "a.example.com", finding.SeverityHigh, "A")}
	_, err := a.Analyze(context.Background(), findings, "example.com")
	if err == nil {
		t.Fatal("expected error when chat fails")
	}
	if !strings.Contains(err.Error(), "aifp.CrossAnalyzer") {
		t.Errorf("error should be wrapped with package prefix: %v", err)
	}
}

// ── Analyze: malformed JSON falls back to summary ────────────────────────────

func TestAnalyze_MalformedJSON_FallsBackToSummary(t *testing.T) {
	chat := func(_ context.Context, _ string) (string, error) {
		return "The AI is down for maintenance.", nil
	}
	a := NewCrossAnalyzer(chat)
	findings := []finding.Finding{makeFinding("check.a", "a.example.com", finding.SeverityHigh, "A")}
	result, err := a.Analyze(context.Background(), findings, "example.com")
	if err != nil {
		t.Fatalf("expected graceful degradation, got error: %v", err)
	}
	if result.Summary == "" {
		t.Error("fallback should populate Summary from raw response")
	}
	if len(result.CrossFindings) != 0 {
		t.Error("malformed response should yield no cross findings")
	}
}

// ── buildCrossAssetPrompt deduplication ──────────────────────────────────────

func TestBuildCrossAssetPrompt_DeduplicatesByAssetAndCheckID(t *testing.T) {
	findings := []finding.Finding{
		makeFinding("jwt.alg_none", "a.example.com", finding.SeverityHigh, "JWT alg=none"),
		makeFinding("jwt.alg_none", "a.example.com", finding.SeverityHigh, "JWT alg=none"), // duplicate
		makeFinding("cors.wildcard", "b.example.com", finding.SeverityMedium, "CORS wildcard"),
	}
	prompt := buildCrossAssetPrompt(findings, "example.com")

	// JWT entry should appear exactly once.
	count := strings.Count(prompt, "jwt.alg_none")
	if count != 1 {
		t.Errorf("expected jwt.alg_none to appear exactly once, got %d", count)
	}
}

func TestBuildCrossAssetPrompt_SkipsInfoSeverity(t *testing.T) {
	findings := []finding.Finding{
		makeFinding("info.check", "a.example.com", finding.SeverityInfo, "Info finding"),
		makeFinding("high.check", "a.example.com", finding.SeverityHigh, "High finding"),
	}
	prompt := buildCrossAssetPrompt(findings, "example.com")

	if strings.Contains(prompt, "info.check") {
		t.Error("info severity findings should be excluded from prompt")
	}
	if !strings.Contains(prompt, "high.check") {
		t.Error("high severity findings should be included in prompt")
	}
}

func TestBuildCrossAssetPrompt_TruncatesTitles(t *testing.T) {
	longTitle := strings.Repeat("X", 100)
	findings := []finding.Finding{
		makeFinding("check.long", "a.example.com", finding.SeverityHigh, longTitle),
	}
	prompt := buildCrossAssetPrompt(findings, "example.com")
	if strings.Contains(prompt, longTitle) {
		t.Error("title longer than 80 chars should be truncated in prompt")
	}
}

func TestBuildCrossAssetPrompt_SortsAssets(t *testing.T) {
	findings := []finding.Finding{
		makeFinding("check.z", "z.example.com", finding.SeverityHigh, "Z"),
		makeFinding("check.a", "a.example.com", finding.SeverityHigh, "A"),
		makeFinding("check.m", "m.example.com", finding.SeverityHigh, "M"),
	}
	prompt := buildCrossAssetPrompt(findings, "example.com")
	posA := strings.Index(prompt, "a.example.com")
	posM := strings.Index(prompt, "m.example.com")
	posZ := strings.Index(prompt, "z.example.com")
	if posA > posM || posM > posZ {
		t.Error("assets should appear in alphabetical order in prompt")
	}
}

func TestBuildCrossAssetPrompt_IncludesRootDomain(t *testing.T) {
	findings := []finding.Finding{makeFinding("check.a", "a.example.com", finding.SeverityHigh, "A")}
	prompt := buildCrossAssetPrompt(findings, "example.com")
	if !strings.Contains(prompt, `"example.com"`) {
		t.Error("prompt should reference the root domain")
	}
}

func TestBuildCrossAssetPrompt_EmptyAfterInfoFilter(t *testing.T) {
	// If all findings are info-only, the prompt still gets built (body is empty).
	findings := []finding.Finding{
		makeFinding("info.a", "a.example.com", finding.SeverityInfo, "Info"),
	}
	prompt := buildCrossAssetPrompt(findings, "example.com")
	// Prompt should still be valid JSON instruction, just empty asset section.
	if !strings.Contains(prompt, "FINDINGS BY ASSET") {
		t.Error("prompt header should always be present")
	}
}

// ── parseCrossAssetResponse: attack chains in evidence ───────────────────────

func TestParseCrossAssetResponse_AttackChainInEvidence(t *testing.T) {
	raw := `{
		"summary": "s",
		"attack_chains": ["Step 1 (a.example.com): check.a → Step 2 (b.example.com): check.b → Compromise"],
		"cross_findings": [
			{
				"assets": ["a.example.com"],
				"check_id": "cross.test",
				"severity": "high",
				"title": "Test",
				"description": "desc"
			}
		]
	}`
	result, err := parseCrossAssetResponse(raw, "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.CrossFindings) == 0 {
		t.Fatal("expected cross findings")
	}
	chains, ok := result.CrossFindings[0].Evidence["attack_chains"].(string)
	if !ok || !strings.Contains(chains, "Step 1") {
		t.Errorf("attack_chains not in finding evidence: %v", result.CrossFindings[0].Evidence["attack_chains"])
	}
}

func TestParseCrossAssetResponse_DiscoveredAtSet(t *testing.T) {
	before := time.Now()
	raw := `{
		"summary": "s",
		"cross_findings": [
			{"assets": ["a.example.com"], "check_id": "cross.x", "severity": "low", "title": "X", "description": "d"}
		]
	}`
	result, _ := parseCrossAssetResponse(raw, "example.com")
	if len(result.CrossFindings) == 0 {
		t.Fatal("expected cross findings")
	}
	after := time.Now()
	at := result.CrossFindings[0].DiscoveredAt
	if at.Before(before) || at.After(after) {
		t.Errorf("DiscoveredAt not set correctly: %v", at)
	}
}

// ── parseCrossAssetResponse: graceful JSON fence stripping ───────────────────

func TestParseCrossAssetResponse_StripsMarkdownFences(t *testing.T) {
	raw := "```json\n{\"summary\": \"clean\", \"cross_findings\": [], \"attack_chains\": []}\n```"
	result, err := parseCrossAssetResponse(raw, "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Summary != "clean" {
		t.Errorf("expected Summary=clean, got %q", result.Summary)
	}
}

// ── Severity mapping via parseSeverity ───────────────────────────────────────

func TestAnalyze_SeverityMappedCorrectly(t *testing.T) {
	cases := []struct {
		sev  string
		want finding.Severity
	}{
		{"critical", finding.SeverityCritical},
		{"high", finding.SeverityHigh},
		{"medium", finding.SeverityMedium},
		{"low", finding.SeverityLow},
	}
	for _, tc := range cases {
		raw := `{"summary":"s","cross_findings":[{"assets":["a.example.com"],"check_id":"cross.x","severity":"` + tc.sev + `","title":"T","description":"d"}]}`
		result, _ := parseCrossAssetResponse(raw, "example.com")
		if len(result.CrossFindings) == 0 {
			t.Fatalf("expected cross findings for severity %q", tc.sev)
		}
		if result.CrossFindings[0].Severity != tc.want {
			t.Errorf("sev %q: got %v, want %v", tc.sev, result.CrossFindings[0].Severity, tc.want)
		}
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func makeFinding(checkID, asset string, sev finding.Severity, title string) finding.Finding {
	return finding.Finding{
		CheckID:      finding.CheckID(checkID),
		Asset:        asset,
		Severity:     sev,
		Title:        title,
		Module:       "test",
		Scanner:      "test",
		DiscoveredAt: time.Now(),
	}
}
