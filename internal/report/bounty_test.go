package report

import (
	"strings"
	"testing"
	"time"

	"github.com/stormbane-security/beacon/internal/enrichment"
	"github.com/stormbane-security/beacon/internal/finding"
)

func TestRenderBounty_OnlyMediumAndAbove(t *testing.T) {
	findings := []enrichment.EnrichedFinding{
		enrichedWith(finding.SeverityCritical, "SQLi", "api.example.com"),
		enrichedWith(finding.SeverityHigh, "SSRF", "api.example.com"),
		enrichedWith(finding.SeverityMedium, "CORS", "api.example.com"),
		enrichedWith(finding.SeverityLow, "Info Leak", "api.example.com"),
		enrichedWith(finding.SeverityInfo, "Screenshot", "api.example.com"),
	}
	out := RenderBounty(testRun(), findings, "", nil)

	if !strings.Contains(out, "SQLi") {
		t.Error("expected critical finding in bounty report")
	}
	if !strings.Contains(out, "SSRF") {
		t.Error("expected high finding in bounty report")
	}
	if !strings.Contains(out, "CORS") {
		t.Error("expected medium finding in bounty report")
	}
	if strings.Contains(out, "Info Leak") {
		t.Error("low severity should NOT be in bounty report")
	}
	if strings.Contains(out, "Screenshot") {
		t.Error("info severity should NOT be in bounty report")
	}
}

func TestRenderBounty_ContainsCVSSEstimate(t *testing.T) {
	findings := []enrichment.EnrichedFinding{
		enrichedWith(finding.SeverityCritical, "RCE", "target.com"),
	}
	out := RenderBounty(testRun(), findings, "", nil)
	if !strings.Contains(out, "9.1") {
		t.Error("expected CVSS 9.1 for critical severity")
	}
}

func TestRenderBounty_ContainsStepsToReproduce(t *testing.T) {
	ef := enrichedWith(finding.SeverityHigh, "XSS", "target.com")
	ef.Finding.ProofCommand = "curl -s 'https://target.com/search?q=<script>alert(1)</script>'"
	out := RenderBounty(testRun(), []enrichment.EnrichedFinding{ef}, "", nil)
	if !strings.Contains(out, "Steps to Reproduce") {
		t.Error("expected steps to reproduce section")
	}
	if !strings.Contains(out, "curl") {
		t.Error("expected proof command in steps")
	}
}

func TestRenderBounty_ContainsImpactSection(t *testing.T) {
	findings := []enrichment.EnrichedFinding{
		enrichedWith(finding.SeverityCritical, "Cred Theft", "target.com"),
	}
	out := RenderBounty(testRun(), findings, "", nil)
	if !strings.Contains(out, "## Impact") {
		t.Error("expected impact section in bounty report")
	}
}

func TestRenderBounty_ContainsAffectedAsset(t *testing.T) {
	ef := enrichedWith(finding.SeverityHigh, "Open Redirect", "target.com")
	ef.Finding.Evidence = map[string]any{"url": "https://target.com/redirect?to=evil.com"}
	out := RenderBounty(testRun(), []enrichment.EnrichedFinding{ef}, "", nil)
	if !strings.Contains(out, "## Affected Asset") {
		t.Error("expected affected asset section")
	}
	if !strings.Contains(out, "target.com/redirect") {
		t.Error("expected endpoint URL in affected asset")
	}
}

func TestRenderBounty_EmptyForLowOnly(t *testing.T) {
	findings := []enrichment.EnrichedFinding{
		enrichedWith(finding.SeverityLow, "Minor", "target.com"),
	}
	out := RenderBounty(testRun(), findings, "", nil)
	if !strings.Contains(out, "No reportable findings") {
		t.Error("expected 'no reportable findings' for low-only results")
	}
}

func TestRenderBounty_FindingsOrderedBySeverity(t *testing.T) {
	findings := []enrichment.EnrichedFinding{
		enrichedWith(finding.SeverityMedium, "Medium Bug", "target.com"),
		enrichedWith(finding.SeverityCritical, "Critical Bug", "target.com"),
		enrichedWith(finding.SeverityHigh, "High Bug", "target.com"),
	}
	out := RenderBounty(testRun(), findings, "", nil)
	critIdx := strings.Index(out, "Critical Bug")
	highIdx := strings.Index(out, "High Bug")
	medIdx := strings.Index(out, "Medium Bug")
	if critIdx > highIdx || highIdx > medIdx {
		t.Error("findings should be ordered: critical -> high -> medium")
	}
}

func TestRenderBounty_ImpactForSQLi(t *testing.T) {
	ef := enrichedWith(finding.SeverityCritical, "SQL Injection", "target.com")
	ef.Finding.CheckID = "web.sqli"
	ef.Impact = "" // force default impact
	out := RenderBounty(testRun(), []enrichment.EnrichedFinding{ef}, "", nil)
	if !strings.Contains(out, "SQL injection") || !strings.Contains(out, "database") {
		t.Error("expected SQLi-specific impact statement")
	}
}

func TestRenderBounty_EvidenceExcludesBase64(t *testing.T) {
	ef := enrichedWith(finding.SeverityHigh, "Screenshot", "target.com")
	ef.Finding.Evidence = map[string]any{
		"url":       "https://target.com",
		"image_b64": "data:image/png;base64,AAAA...very_long_base64...",
	}
	ef.Finding.DiscoveredAt = time.Now()
	out := RenderBounty(testRun(), []enrichment.EnrichedFinding{ef}, "", nil)
	if strings.Contains(out, "very_long_base64") {
		t.Error("base64 screenshot data should NOT appear in bounty report")
	}
}

func TestRenderBounty_SeverityInTitle(t *testing.T) {
	ef := enrichedWith(finding.SeverityCritical, "RCE via Deserialization", "target.com")
	out := RenderBounty(testRun(), []enrichment.EnrichedFinding{ef}, "", nil)
	if !strings.Contains(out, "# [CRITICAL] RCE via Deserialization") {
		t.Error("expected [SEVERITY] prefix in finding title")
	}
}

func TestRenderBounty_SeverityJustification(t *testing.T) {
	ef := enrichedWith(finding.SeverityHigh, "SSRF", "target.com")
	out := RenderBounty(testRun(), []enrichment.EnrichedFinding{ef}, "", nil)
	if !strings.Contains(out, "## Severity Justification") {
		t.Error("expected severity justification section")
	}
	if !strings.Contains(out, "7.5") {
		t.Error("expected CVSS score in severity justification")
	}
}

func TestRenderBounty_ProofOfConceptSection(t *testing.T) {
	ef := enrichedWith(finding.SeverityHigh, "XSS", "target.com")
	ef.Finding.ProofCommand = "curl -s 'https://target.com/vuln'"
	out := RenderBounty(testRun(), []enrichment.EnrichedFinding{ef}, "", nil)
	if !strings.Contains(out, "## Proof of Concept") {
		t.Error("expected proof of concept section")
	}
}

func TestRenderBounty_ReferencesForSQLi(t *testing.T) {
	ef := enrichedWith(finding.SeverityCritical, "SQLi", "target.com")
	ef.Finding.CheckID = "web.sqli"
	out := RenderBounty(testRun(), []enrichment.EnrichedFinding{ef}, "", nil)
	if !strings.Contains(out, "## References") {
		t.Error("expected references section for SQLi finding")
	}
	if !strings.Contains(out, "owasp.org") {
		t.Error("expected OWASP reference for SQLi")
	}
}

func TestRenderBounty_RemediationSection(t *testing.T) {
	ef := enrichedWith(finding.SeverityCritical, "SQLi", "target.com")
	ef.Finding.CheckID = "web.sqli"
	ef.Remediation = ""
	ef.TechSpecificRemediation = ""
	out := RenderBounty(testRun(), []enrichment.EnrichedFinding{ef}, "", nil)
	if !strings.Contains(out, "## Remediation") {
		t.Error("expected remediation section")
	}
	if !strings.Contains(out, "parameterized") {
		t.Error("expected SQLi-specific remediation advice")
	}
}

func TestRenderBounty_SummarySection(t *testing.T) {
	ef := enrichedWith(finding.SeverityHigh, "Open Redirect", "target.com")
	ef.Explanation = "The target redirects to attacker-controlled URLs."
	out := RenderBounty(testRun(), []enrichment.EnrichedFinding{ef}, "", nil)
	if !strings.Contains(out, "## Summary") {
		t.Error("expected summary section")
	}
	if !strings.Contains(out, "attacker-controlled") {
		t.Error("expected explanation text in summary")
	}
}

func TestRenderBounty_ParameterExtraction(t *testing.T) {
	ef := enrichedWith(finding.SeverityHigh, "XSS", "target.com")
	ef.Finding.Evidence = map[string]any{
		"url":       "https://target.com/search",
		"parameter": "q",
	}
	out := RenderBounty(testRun(), []enrichment.EnrichedFinding{ef}, "", nil)
	if !strings.Contains(out, "**Parameter**: q") {
		t.Error("expected parameter in affected asset section")
	}
}
