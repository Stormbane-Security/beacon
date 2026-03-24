package analyze

import (
	"testing"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/playbook"
)

func TestDetectChains_JWTAlgorithmConfusion(t *testing.T) {
	findings := []finding.Finding{
		{CheckID: "jwt.algorithm_confusion", Severity: finding.SeverityCritical},
		{CheckID: "oauth.token_long_expiry", Severity: finding.SeverityMedium},
	}
	chains := DetectChains(findings)
	if len(chains) == 0 {
		t.Error("expected JWT confusion chain, got none")
	}
	if chains[0].Severity != finding.SeverityCritical {
		t.Errorf("chain severity = %s, want Critical", chains[0].Severity)
	}
}

func TestDetectChains_NoChain(t *testing.T) {
	findings := []finding.Finding{
		{CheckID: "tls.cert_expiry_7d", Severity: finding.SeverityLow},
	}
	chains := DetectChains(findings)
	if len(chains) != 0 {
		t.Errorf("expected no chains, got %d", len(chains))
	}
}

func TestDetectChains_SCIMAndDynClient(t *testing.T) {
	findings := []finding.Finding{
		{CheckID: "iam.scim_unauthenticated", Severity: finding.SeverityCritical},
		{CheckID: "iam.dynamic_client_reg", Severity: finding.SeverityHigh},
	}
	chains := DetectChains(findings)
	if len(chains) == 0 {
		t.Error("expected SCIM+DynClient chain")
	}
}

func TestScoreFinding_HighSeverityNoAuth(t *testing.T) {
	f := finding.Finding{CheckID: "iam.scim_unauthenticated", Severity: finding.SeverityCritical}
	score := ScoreFinding(f, playbook.Evidence{IP: "1.2.3.4"}, nil)
	if score.Score < 8.0 {
		t.Errorf("expected score >= 8.0 for no-auth critical finding, got %.1f", score.Score)
	}
}

func TestScoreFinding_WAFReducesInjection(t *testing.T) {
	f := finding.Finding{CheckID: "web.ssti", Severity: finding.SeverityHigh}
	ev := playbook.Evidence{
		IP:        "1.2.3.4",
		ProxyType: "cloudflare",
	}
	score := ScoreFinding(f, ev, nil)
	// Base 5.0 + 1.5 (IP) - 0.5 (reverse proxy not set) - 1.0 (WAF+injection) + 2.0 (no auth) + 1.5 (well-known) = 9.0
	// But IsReverseProxy is false here, so: 5.0 + 1.5 - 1.0 + 2.0 + 1.5 = 9.0 (capped at 10)
	if score.Score <= 0 {
		t.Errorf("expected positive score, got %.1f", score.Score)
	}
	// Verify WAF factor is mentioned
	foundWAF := false
	for _, factor := range score.Factors {
		if len(factor) > 3 && factor[:3] == "WAF" {
			foundWAF = true
		}
	}
	if !foundWAF {
		t.Error("expected WAF factor in score factors")
	}
}

func TestScoreFinding_AuthBypassElevates(t *testing.T) {
	f := finding.Finding{CheckID: "jwt.algorithm_confusion", Severity: finding.SeverityHigh}
	score := ScoreFinding(f, playbook.Evidence{IP: "10.0.0.1"}, nil)
	// Base 5.0 + 1.5 (IP) + 3.0 (auth bypass) + 1.5 (well-known) = 11.0 → capped at 10.0
	if score.Score != 10.0 {
		t.Errorf("expected score capped at 10.0, got %.1f", score.Score)
	}
	if score.Label != "Trivially exploitable" {
		t.Errorf("expected 'Trivially exploitable', got %q", score.Label)
	}
}

func TestScoreFinding_ChainBoost(t *testing.T) {
	allFindings := []finding.Finding{
		{CheckID: "web.ssrf", Severity: finding.SeverityHigh},
		{CheckID: "iam.cloud_metadata_ssrf", Severity: finding.SeverityCritical},
	}
	f := allFindings[0]
	score := ScoreFinding(f, playbook.Evidence{}, allFindings)
	// Should detect a chain and boost score, and ChainsWith should include the partner
	if len(score.ChainsWith) == 0 {
		t.Error("expected ChainsWith to be non-empty for SSRF chain")
	}
}

func TestFormatChain(t *testing.T) {
	chain := AttackChain{
		Findings: []finding.Finding{
			{CheckID: "web.ssrf"},
			{CheckID: "iam.cloud_metadata_ssrf"},
		},
		Impact:    "Cloud credential theft via SSRF chain",
		Narrative: "Test narrative.",
		Severity:  finding.SeverityCritical,
	}
	out := FormatChain(chain)
	if out == "" {
		t.Error("expected non-empty FormatChain output")
	}
}

func TestScoreLabel(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{
		{9.0, "Trivially exploitable"},
		{7.5, "Likely exploitable"},
		{6.0, "Exploitable with some effort"},
		{3.5, "Requires chaining or specific conditions"},
		{1.0, "Low practical risk"},
	}
	for _, tc := range cases {
		got := scoreLabel(tc.score)
		if got != tc.want {
			t.Errorf("scoreLabel(%.1f) = %q, want %q", tc.score, got, tc.want)
		}
	}
}
