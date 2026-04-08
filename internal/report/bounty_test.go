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

func TestRenderBounty_ContainsAffectedComponent(t *testing.T) {
	ef := enrichedWith(finding.SeverityHigh, "Open Redirect", "target.com")
	ef.Finding.Evidence = map[string]any{"url": "https://target.com/redirect?to=evil.com"}
	out := RenderBounty(testRun(), []enrichment.EnrichedFinding{ef}, "", nil)
	if !strings.Contains(out, "## Affected Component") {
		t.Error("expected affected component section")
	}
	if !strings.Contains(out, "target.com/redirect") {
		t.Error("expected endpoint URL in affected component")
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
		t.Error("findings should be ordered: critical → high → medium")
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
