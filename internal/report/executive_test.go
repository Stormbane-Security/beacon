package report

import (
	"testing"

	"github.com/stormbane-security/beacon/internal/enrichment"
	"github.com/stormbane-security/beacon/internal/finding"
)

// ---------------------------------------------------------------------------
// Executive summary: 0 findings
// ---------------------------------------------------------------------------

func TestExecutiveSummary_ZeroFindings(t *testing.T) {
	summary := GenerateExecutiveSummary(nil)

	if summary.RiskScore != 0 {
		t.Errorf("expected risk score 0, got %d", summary.RiskScore)
	}
	if summary.RiskLevel != "Clean" {
		t.Errorf("expected risk level 'Clean', got %q", summary.RiskLevel)
	}
	if summary.TotalFindings != 0 {
		t.Errorf("expected total findings 0, got %d", summary.TotalFindings)
	}
	if summary.Narrative == "" {
		t.Error("expected non-empty narrative even with 0 findings")
	}
}

// ---------------------------------------------------------------------------
// Executive summary: 1 critical finding
// ---------------------------------------------------------------------------

func TestExecutiveSummary_OneCritical(t *testing.T) {
	findings := []enrichment.EnrichedFinding{
		{
			Finding: finding.Finding{
				CheckID:  "web.sqli",
				Severity: finding.SeverityCritical,
				Title:    "SQL Injection",
				Asset:    "app.example.com",
			},
			Explanation: "SQL injection found in search parameter.",
		},
	}

	summary := GenerateExecutiveSummary(findings)

	// Risk score: 1 critical * 25 = 25.
	if summary.RiskScore != 25 {
		t.Errorf("expected risk score 25, got %d", summary.RiskScore)
	}
	// Score 25 => "Medium" per riskLevelFromScore (25 >= 25).
	if summary.RiskLevel != "Medium" {
		t.Errorf("expected risk level 'Medium', got %q", summary.RiskLevel)
	}
	if summary.TotalFindings != 1 {
		t.Errorf("expected total findings 1, got %d", summary.TotalFindings)
	}
	if summary.BySeverity["critical"] != 1 {
		t.Errorf("expected 1 critical, got %d", summary.BySeverity["critical"])
	}
}

// ---------------------------------------------------------------------------
// Executive summary: mixed findings
// ---------------------------------------------------------------------------

func TestExecutiveSummary_MixedFindings(t *testing.T) {
	findings := []enrichment.EnrichedFinding{
		{Finding: finding.Finding{CheckID: "web.sqli", Severity: finding.SeverityCritical, Title: "SQL Injection", Asset: "a.example.com"}},
		{Finding: finding.Finding{CheckID: "web.xss", Severity: finding.SeverityHigh, Title: "XSS", Asset: "b.example.com"}},
		{Finding: finding.Finding{CheckID: "tls.protocol_tls10", Severity: finding.SeverityHigh, Title: "TLS 1.0", Asset: "c.example.com"}},
		{Finding: finding.Finding{CheckID: "email.spf_missing", Severity: finding.SeverityMedium, Title: "SPF Missing", Asset: "example.com"}},
		{Finding: finding.Finding{CheckID: "cookie.missing_secure", Severity: finding.SeverityLow, Title: "Cookie flag", Asset: "d.example.com"}},
		{Finding: finding.Finding{CheckID: "auth.login_form_detected", Severity: finding.SeverityInfo, Title: "Login form", Asset: "e.example.com"}},
	}

	summary := GenerateExecutiveSummary(findings)

	// Severity counts.
	if summary.BySeverity["critical"] != 1 {
		t.Errorf("expected 1 critical, got %d", summary.BySeverity["critical"])
	}
	if summary.BySeverity["high"] != 2 {
		t.Errorf("expected 2 high, got %d", summary.BySeverity["high"])
	}
	if summary.BySeverity["medium"] != 1 {
		t.Errorf("expected 1 medium, got %d", summary.BySeverity["medium"])
	}
	if summary.BySeverity["low"] != 1 {
		t.Errorf("expected 1 low, got %d", summary.BySeverity["low"])
	}
	if summary.BySeverity["info"] != 1 {
		t.Errorf("expected 1 info, got %d", summary.BySeverity["info"])
	}

	// Category counts.
	if summary.ByCategory["web"] != 2 {
		t.Errorf("expected 2 in 'web' category, got %d", summary.ByCategory["web"])
	}
	if summary.ByCategory["tls"] != 1 {
		t.Errorf("expected 1 in 'tls' category, got %d", summary.ByCategory["tls"])
	}
	if summary.ByCategory["email"] != 1 {
		t.Errorf("expected 1 in 'email' category, got %d", summary.ByCategory["email"])
	}

	// Risk score: 1*25 + 2*10 + 1*3 + 1*1 = 49.
	if summary.RiskScore != 49 {
		t.Errorf("expected risk score 49, got %d", summary.RiskScore)
	}

	// Total findings.
	if summary.TotalFindings != 6 {
		t.Errorf("expected 6 total findings, got %d", summary.TotalFindings)
	}
}

// ---------------------------------------------------------------------------
// Executive summary: top findings sorted by severity
// ---------------------------------------------------------------------------

func TestExecutiveSummary_TopFindingsSortedBySeverity(t *testing.T) {
	findings := []enrichment.EnrichedFinding{
		{Finding: finding.Finding{CheckID: "cookie.flag", Severity: finding.SeverityLow, Title: "Low", Asset: "a.example.com"}},
		{Finding: finding.Finding{CheckID: "web.sqli", Severity: finding.SeverityCritical, Title: "Critical", Asset: "b.example.com"}},
		{Finding: finding.Finding{CheckID: "tls.weak", Severity: finding.SeverityMedium, Title: "Medium", Asset: "c.example.com"}},
		{Finding: finding.Finding{CheckID: "web.xss", Severity: finding.SeverityHigh, Title: "High", Asset: "d.example.com"}},
	}

	summary := GenerateExecutiveSummary(findings)

	if len(summary.TopFindings) == 0 {
		t.Fatal("expected non-empty top findings")
	}

	// First top finding should be the critical one.
	if summary.TopFindings[0].Severity != "Critical" {
		t.Errorf("expected first top finding to be Critical, got %q", summary.TopFindings[0].Severity)
	}
	// Second should be high.
	if len(summary.TopFindings) >= 2 && summary.TopFindings[1].Severity != "High" {
		t.Errorf("expected second top finding to be High, got %q", summary.TopFindings[1].Severity)
	}
}

// ---------------------------------------------------------------------------
// Executive summary: max 5 top findings
// ---------------------------------------------------------------------------

func TestExecutiveSummary_TopFindingsMaxFive(t *testing.T) {
	var findings []enrichment.EnrichedFinding
	for i := 0; i < 10; i++ {
		findings = append(findings, enrichment.EnrichedFinding{
			Finding: finding.Finding{
				CheckID:  "web.xss",
				Severity: finding.SeverityHigh,
				Title:    "XSS variant",
				Asset:    "example.com",
			},
		})
	}

	summary := GenerateExecutiveSummary(findings)

	if len(summary.TopFindings) > 5 {
		t.Errorf("expected at most 5 top findings, got %d", len(summary.TopFindings))
	}
}

// ---------------------------------------------------------------------------
// Executive summary: recommendations generated
// ---------------------------------------------------------------------------

func TestExecutiveSummary_RecommendationsGenerated(t *testing.T) {
	findings := []enrichment.EnrichedFinding{
		{Finding: finding.Finding{CheckID: "web.sqli", Severity: finding.SeverityCritical, Title: "SQL Injection", Asset: "a.example.com"}},
		{Finding: finding.Finding{CheckID: "web.xss", Severity: finding.SeverityHigh, Title: "XSS", Asset: "b.example.com"}},
	}

	summary := GenerateExecutiveSummary(findings)

	if len(summary.Recommendations) == 0 {
		t.Error("expected non-empty recommendations for critical+high findings")
	}
}

// ---------------------------------------------------------------------------
// Executive summary: risk score capped at 100
// ---------------------------------------------------------------------------

func TestExecutiveSummary_RiskScoreCappedAt100(t *testing.T) {
	var findings []enrichment.EnrichedFinding
	// 5 critical findings: 5 * 25 = 125, should be capped at 100.
	for i := 0; i < 5; i++ {
		findings = append(findings, enrichment.EnrichedFinding{
			Finding: finding.Finding{
				CheckID:  "web.sqli",
				Severity: finding.SeverityCritical,
				Title:    "SQL Injection",
				Asset:    "example.com",
			},
		})
	}

	summary := GenerateExecutiveSummary(findings)

	if summary.RiskScore != 100 {
		t.Errorf("expected risk score capped at 100, got %d", summary.RiskScore)
	}
	if summary.RiskLevel != "Critical" {
		t.Errorf("expected risk level 'Critical', got %q", summary.RiskLevel)
	}
}

// ---------------------------------------------------------------------------
// Executive summary: omitted findings are excluded
// ---------------------------------------------------------------------------

func TestExecutiveSummary_OmittedExcluded(t *testing.T) {
	findings := []enrichment.EnrichedFinding{
		{Finding: finding.Finding{CheckID: "web.sqli", Severity: finding.SeverityCritical, Title: "SQL Injection", Asset: "a.example.com"}},
		{Finding: finding.Finding{CheckID: "tls.weak", Severity: finding.SeverityHigh, Title: "Weak TLS", Asset: "b.example.com"}, Omit: true},
	}

	summary := GenerateExecutiveSummary(findings)

	if summary.TotalFindings != 1 {
		t.Errorf("expected 1 total finding (omitted excluded), got %d", summary.TotalFindings)
	}
	if summary.BySeverity["high"] != 0 {
		t.Errorf("expected 0 high (omitted), got %d", summary.BySeverity["high"])
	}
}

// ---------------------------------------------------------------------------
// Executive summary: attack chain counting
// ---------------------------------------------------------------------------

func TestExecutiveSummary_AttackChainsCounted(t *testing.T) {
	findings := []enrichment.EnrichedFinding{
		{Finding: finding.Finding{CheckID: "web.sqli", Severity: finding.SeverityCritical, Title: "SQL Injection", Asset: "a.example.com"}},
		{Finding: finding.Finding{CheckID: "correlation.xss_csrf_chain", Severity: finding.SeverityCritical, Title: "XSS+CSRF Chain", Asset: "b.example.com"}},
		{Finding: finding.Finding{CheckID: "chain.ssrf_to_cloud", Severity: finding.SeverityCritical, Title: "SSRF Chain", Asset: "c.example.com"}},
	}

	summary := GenerateExecutiveSummary(findings)

	if summary.AttackChains != 2 {
		t.Errorf("expected 2 attack chains, got %d", summary.AttackChains)
	}
}
