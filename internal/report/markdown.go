package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/enrichment"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/store"
)

// markdownOpts holds optional configuration for enhanced markdown rendering.
type markdownOpts struct {
	narratives bool
}

// MarkdownOption configures enhanced markdown rendering.
type MarkdownOption func(*markdownOpts)

// WithNarratives enables attack narrative generation for chain/correlation findings.
func WithNarratives() MarkdownOption {
	return func(o *markdownOpts) { o.narratives = true }
}

// isChainFinding returns true if the finding is a chain or correlation finding
// that can produce an attack narrative.
func isChainFinding(f finding.Finding) bool {
	id := string(f.CheckID)
	return strings.HasPrefix(id, "chain.") || strings.HasPrefix(id, "correlation.")
}

// RenderMarkdown returns the scan results as a Markdown document.
func RenderMarkdown(run store.ScanRun, enriched []enrichment.EnrichedFinding, summary string, executions []store.AssetExecution) string {
	// Filter omitted findings before rendering.
	filtered := make([]enrichment.EnrichedFinding, 0, len(enriched))
	for _, ef := range enriched {
		if !ef.Omit {
			filtered = append(filtered, ef)
		}
	}
	enriched = filtered

	var b strings.Builder

	// Header
	_, _ = fmt.Fprintf(&b, "# Beacon Security Report — %s\n\n", run.Domain)
	_, _ = fmt.Fprintf(&b, "**Scan type:** %s  \n", run.ScanType)
	_, _ = fmt.Fprintf(&b, "**Started:** %s  \n", run.StartedAt.Format("2006-01-02 15:04"))
	if run.CompletedAt != nil {
		_, _ = fmt.Fprintf(&b, "**Completed:** %s  \n", run.CompletedAt.Format("2006-01-02 15:04"))
	}
	b.WriteString("\n")

	// Severity table
	counts := countSeverities(enriched)
	b.WriteString("## Summary\n\n")
	b.WriteString("| Severity | Count |\n")
	b.WriteString("|----------|-------|\n")
	_, _ = fmt.Fprintf(&b, "| Critical | %d |\n", counts[finding.SeverityCritical])
	_, _ = fmt.Fprintf(&b, "| High     | %d |\n", counts[finding.SeverityHigh])
	_, _ = fmt.Fprintf(&b, "| Medium   | %d |\n", counts[finding.SeverityMedium])
	_, _ = fmt.Fprintf(&b, "| Low      | %d |\n", counts[finding.SeverityLow])
	_, _ = fmt.Fprintf(&b, "| Info     | %d |\n", counts[finding.SeverityInfo])
	_, _ = fmt.Fprintf(&b, "| **Total**| **%d** |\n\n", len(enriched))

	// Executive summary
	if summary != "" {
		b.WriteString("## Executive Summary\n\n")
		b.WriteString(summary + "\n\n")
	}

	// Asset inventory table — all scanned assets including clean ones
	if inv := buildAssetInventory(enriched, executions); len(inv) > 0 {
		b.WriteString("## Asset Inventory\n\n")
		b.WriteString("| Asset | Tech | Findings | Critical | High | Medium | Low |\n")
		b.WriteString("|-------|------|----------|----------|------|--------|-----|\n")
		for _, e := range inv {
			findStr := "clean"
			if e.total > 0 {
				findStr = fmt.Sprintf("%d", e.total)
			}
			_, _ = fmt.Fprintf(&b, "| %s | %s | %s | %d | %d | %d | %d |\n",
				e.asset, e.tech, findStr, e.crit, e.high, e.med, e.low)
		}
		b.WriteString("\n")
	}

	// Network topology (Mermaid diagram) — unwrap findings for service sub-nodes.
	rawFindings := make([]finding.Finding, 0, len(enriched))
	for _, ef := range enriched {
		rawFindings = append(rawFindings, ef.Finding)
	}
	if topo := RenderTopologyMermaid(executions, rawFindings); topo != "" {
		b.WriteString(topo)
	}

	if len(enriched) == 0 {
		b.WriteString("## Findings\n\nNo findings.\n")
		return b.String()
	}

	b.WriteString("## Findings\n\n")

	order := []finding.Severity{
		finding.SeverityCritical,
		finding.SeverityHigh,
		finding.SeverityMedium,
		finding.SeverityLow,
		finding.SeverityInfo,
	}
	for _, sev := range order {
		for _, ef := range enriched {
			if ef.Finding.Severity != sev {
				continue
			}
			label := SeverityLabel(ef.Finding.Severity)
			_, _ = fmt.Fprintf(&b, "### [%s] %s\n\n", label, ef.Finding.Title)
			_, _ = fmt.Fprintf(&b, "**Asset:** %s  \n", ef.Finding.Asset)
			_, _ = fmt.Fprintf(&b, "**Check:** `%s`  \n", ef.Finding.CheckID)
			if ef.Finding.DiscoveredAt != (time.Time{}) {
				_, _ = fmt.Fprintf(&b, "**Found:** %s  \n", ef.Finding.DiscoveredAt.Format("2006-01-02 15:04"))
			}
			if ef.DeltaStatus != "" {
				_, _ = fmt.Fprintf(&b, "**Status:** %s  \n", ef.DeltaStatus)
			}
			if ef.Explanation != "" {
				b.WriteString("\n" + ef.Explanation + "\n")
			}
			if ef.Impact != "" {
				b.WriteString("\n**Impact:** " + ef.Impact + "\n")
			}
			if ef.Remediation != "" {
				b.WriteString("\n**Remediation:** " + ef.Remediation + "\n")
			}
			if ef.TechSpecificRemediation != "" {
				b.WriteString("\n**Tech-specific fix:** " + ef.TechSpecificRemediation + "\n")
			}
			if len(ef.ComplianceTags) > 0 {
				_, _ = fmt.Fprintf(&b, "\n**Compliance:** %s\n", strings.Join(ef.ComplianceTags, ", "))
			}
			proofCmd := ef.Finding.ProofCommand
			if proofCmd == "" {
				proofCmd = verifyCmd(ef.Finding.CheckID, ef.Finding.Asset)
			}
			if proofCmd != "" {
				_, _ = fmt.Fprintf(&b, "\n**Proof Command** (copy-paste to confirm):\n```sh\n%s\n```\n", proofCmd)
			}
			b.WriteString("\n---\n\n")
		}
	}

	return b.String()
}

// severityBadge returns an emoji severity badge for enhanced markdown reports.
func severityBadge(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical:
		return "\U0001f534 Critical"
	case finding.SeverityHigh:
		return "\U0001f7e0 High"
	case finding.SeverityMedium:
		return "\U0001f7e1 Medium"
	case finding.SeverityLow:
		return "\U0001f535 Low"
	default:
		return "\u26aa Info"
	}
}

// RenderEnhancedMarkdown returns a full-featured Markdown report with:
// - Executive summary with finding counts by severity
// - Table of contents
// - Severity badges (emoji)
// - Evidence tables per finding
// - Embedded screenshot references
// - Proof commands in code blocks
// - Remediation sections
// - Attack narratives for chain/correlation findings (when narratives=true)
// - Appendix with scan metadata
func RenderEnhancedMarkdown(run store.ScanRun, enriched []enrichment.EnrichedFinding, summary string, executions []store.AssetExecution, screenshotDir string, opts ...MarkdownOption) string {
	var mo markdownOpts
	for _, o := range opts {
		o(&mo)
	}
	// Filter omitted findings before rendering.
	filtered := make([]enrichment.EnrichedFinding, 0, len(enriched))
	for _, ef := range enriched {
		if !ef.Omit {
			filtered = append(filtered, ef)
		}
	}
	enriched = filtered

	var b strings.Builder

	// Title
	_, _ = fmt.Fprintf(&b, "# Beacon Security Report — %s\n\n", run.Domain)

	// Executive Summary
	counts := countSeverities(enriched)
	b.WriteString("## Executive Summary\n\n")

	if summary != "" {
		b.WriteString(summary + "\n\n")
	}

	b.WriteString("| Severity | Count |\n")
	b.WriteString("|----------|-------|\n")
	_, _ = fmt.Fprintf(&b, "| \U0001f534 Critical | %d |\n", counts[finding.SeverityCritical])
	_, _ = fmt.Fprintf(&b, "| \U0001f7e0 High | %d |\n", counts[finding.SeverityHigh])
	_, _ = fmt.Fprintf(&b, "| \U0001f7e1 Medium | %d |\n", counts[finding.SeverityMedium])
	_, _ = fmt.Fprintf(&b, "| \U0001f535 Low | %d |\n", counts[finding.SeverityLow])
	_, _ = fmt.Fprintf(&b, "| \u26aa Info | %d |\n", counts[finding.SeverityInfo])
	_, _ = fmt.Fprintf(&b, "| **Total** | **%d** |\n\n", len(enriched))

	// Table of Contents
	if len(enriched) > 0 {
		b.WriteString("## Table of Contents\n\n")
		order := []finding.Severity{
			finding.SeverityCritical,
			finding.SeverityHigh,
			finding.SeverityMedium,
			finding.SeverityLow,
			finding.SeverityInfo,
		}
		tocIdx := 0
		for _, sev := range order {
			for _, ef := range enriched {
				if ef.Finding.Severity != sev {
					continue
				}
				tocIdx++
				badge := severityBadge(ef.Finding.Severity)
				_, _ = fmt.Fprintf(&b, "%d. [%s — %s](#finding-%d)\n", tocIdx, badge, ef.Finding.Title, tocIdx)
			}
		}
		b.WriteString("\n")
	}

	// Asset inventory
	if inv := buildAssetInventory(enriched, executions); len(inv) > 0 {
		b.WriteString("## Asset Inventory\n\n")
		b.WriteString("| Asset | Tech | Findings | Critical | High | Medium | Low |\n")
		b.WriteString("|-------|------|----------|----------|------|--------|-----|\n")
		for _, e := range inv {
			findStr := "clean"
			if e.total > 0 {
				findStr = fmt.Sprintf("%d", e.total)
			}
			_, _ = fmt.Fprintf(&b, "| %s | %s | %s | %d | %d | %d | %d |\n",
				e.asset, e.tech, findStr, e.crit, e.high, e.med, e.low)
		}
		b.WriteString("\n")
	}

	// Collect all raw findings for narrative cross-referencing.
	allFindings := make([]finding.Finding, 0, len(enriched))
	for _, ef := range enriched {
		allFindings = append(allFindings, ef.Finding)
	}

	// Findings
	if len(enriched) == 0 {
		b.WriteString("## Findings\n\nNo findings.\n")
	} else {
		b.WriteString("## Findings\n\n")

		order := []finding.Severity{
			finding.SeverityCritical,
			finding.SeverityHigh,
			finding.SeverityMedium,
			finding.SeverityLow,
			finding.SeverityInfo,
		}
		findingIdx := 0
		for _, sev := range order {
			for _, ef := range enriched {
				if ef.Finding.Severity != sev {
					continue
				}
				findingIdx++
				renderEnhancedFinding(&b, ef, findingIdx, screenshotDir, mo.narratives, allFindings)
			}
		}
	}

	// Appendix: Scan Metadata
	b.WriteString("## Appendix: Scan Metadata\n\n")
	b.WriteString("| Field | Value |\n")
	b.WriteString("|-------|-------|\n")
	_, _ = fmt.Fprintf(&b, "| **Domain** | %s |\n", run.Domain)
	_, _ = fmt.Fprintf(&b, "| **Scan Type** | %s |\n", run.ScanType)
	_, _ = fmt.Fprintf(&b, "| **Started** | %s |\n", run.StartedAt.Format("2006-01-02 15:04:05 MST"))
	if run.CompletedAt != nil {
		_, _ = fmt.Fprintf(&b, "| **Completed** | %s |\n", run.CompletedAt.Format("2006-01-02 15:04:05 MST"))
		duration := run.CompletedAt.Sub(run.StartedAt)
		_, _ = fmt.Fprintf(&b, "| **Duration** | %s |\n", duration.Truncate(time.Second))
	}
	if len(run.Modules) > 0 {
		_, _ = fmt.Fprintf(&b, "| **Scanners Run** | %s |\n", strings.Join(run.Modules, ", "))
	}
	_, _ = fmt.Fprintf(&b, "| **Total Findings** | %d |\n", len(enriched))
	_, _ = fmt.Fprintf(&b, "| **Total Assets** | %d |\n", countUniqueAssets(enriched))
	b.WriteString("\n")

	return b.String()
}

// renderEnhancedFinding writes a single finding section for the enhanced markdown report.
// When narratives is true and the finding is a chain/correlation type, an attack narrative
// and inline PoC are appended after the description.
func renderEnhancedFinding(b *strings.Builder, ef enrichment.EnrichedFinding, idx int, screenshotDir string, narratives bool, allFindings []finding.Finding) {
	f := ef.Finding
	badge := severityBadge(f.Severity)

	_, _ = fmt.Fprintf(b, "### <a id=\"finding-%d\"></a>%s — %s\n\n", idx, badge, f.Title)

	_, _ = fmt.Fprintf(b, "**Asset:** `%s`  \n", f.Asset)
	_, _ = fmt.Fprintf(b, "**Check ID:** `%s`  \n", f.CheckID)
	if f.DiscoveredAt != (time.Time{}) {
		_, _ = fmt.Fprintf(b, "**Discovered:** %s  \n", f.DiscoveredAt.Format("2006-01-02 15:04"))
	}
	if ef.DeltaStatus != "" {
		_, _ = fmt.Fprintf(b, "**Status:** %s  \n", ef.DeltaStatus)
	}
	b.WriteString("\n")

	// Description
	if ef.Explanation != "" {
		b.WriteString(ef.Explanation + "\n\n")
	} else if f.Description != "" {
		b.WriteString(f.Description + "\n\n")
	}

	// Attack narrative and chain PoC for chain/correlation findings.
	if narratives && isChainFinding(f) {
		narrative := GenerateNarrative(f, allFindings)
		if narrative != "" {
			b.WriteString("#### Attack Narrative\n\n")
			b.WriteString(narrative + "\n\n")
		}
		pocContent, pocFilename, pocLang := GenerateChainPoC(f, allFindings)
		if pocContent != "" {
			_, _ = fmt.Fprintf(b, "#### Chain PoC (`%s`)\n\n", pocFilename)
			_, _ = fmt.Fprintf(b, "```%s\n%s\n```\n\n", pocLang, pocContent)
		}
	}

	// Impact
	if ef.Impact != "" {
		b.WriteString("**Impact:** " + ef.Impact + "\n\n")
	}

	// Evidence table
	if len(f.Evidence) > 0 {
		b.WriteString("#### Evidence\n\n")
		b.WriteString("| Key | Value |\n")
		b.WriteString("|-----|-------|\n")
		for k, v := range f.Evidence {
			if k == "image_b64" {
				continue
			}
			val := fmt.Sprintf("%v", v)
			if len(val) > 200 {
				val = val[:197] + "..."
			}
			// Escape pipe characters in values for table safety.
			val = strings.ReplaceAll(val, "|", "\\|")
			val = strings.ReplaceAll(val, "\n", " ")
			_, _ = fmt.Fprintf(b, "| `%s` | %s |\n", k, val)
		}
		b.WriteString("\n")
	}

	// Screenshot
	if screenshotDir != "" {
		filename := ScreenshotFilename(idx-1, f.CheckID)
		_, _ = fmt.Fprintf(b, "![Screenshot for %s](%s/%s)\n\n", f.Title, screenshotDir, filename)
	}

	// Proof command
	proofCmd := f.ProofCommand
	if proofCmd == "" {
		proofCmd = verifyCmd(f.CheckID, f.Asset)
	}
	if proofCmd != "" {
		b.WriteString("#### Proof Command\n\n")
		_, _ = fmt.Fprintf(b, "```sh\n%s\n```\n\n", proofCmd)
	}

	// Remediation
	if ef.Remediation != "" || ef.TechSpecificRemediation != "" {
		b.WriteString("#### Remediation\n\n")
		if ef.Remediation != "" {
			b.WriteString(ef.Remediation + "\n\n")
		}
		if ef.TechSpecificRemediation != "" {
			b.WriteString("**Tech-specific fix:** " + ef.TechSpecificRemediation + "\n\n")
		}
	}

	// Compliance tags
	if len(ef.ComplianceTags) > 0 {
		_, _ = fmt.Fprintf(b, "**Compliance:** %s\n\n", strings.Join(ef.ComplianceTags, ", "))
	}

	b.WriteString("---\n\n")
}

// countUniqueAssets returns the number of distinct assets across findings.
func countUniqueAssets(enriched []enrichment.EnrichedFinding) int {
	seen := make(map[string]bool)
	for _, ef := range enriched {
		seen[ef.Finding.Asset] = true
	}
	return len(seen)
}
