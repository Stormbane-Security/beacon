package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/enrichment"
	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/store"
)

// RenderMarkdown returns the scan results as a Markdown document.
func RenderMarkdown(run store.ScanRun, enriched []enrichment.EnrichedFinding, summary string, executions []store.AssetExecution) string {
	var b strings.Builder

	// Header
	fmt.Fprintf(&b, "# Beacon Security Report — %s\n\n", run.Domain)
	fmt.Fprintf(&b, "**Scan type:** %s  \n", run.ScanType)
	fmt.Fprintf(&b, "**Started:** %s  \n", run.StartedAt.Format("2006-01-02 15:04"))
	if run.CompletedAt != nil {
		fmt.Fprintf(&b, "**Completed:** %s  \n", run.CompletedAt.Format("2006-01-02 15:04"))
	}
	b.WriteString("\n")

	// Severity table
	counts := countSeverities(enriched)
	b.WriteString("## Summary\n\n")
	b.WriteString("| Severity | Count |\n")
	b.WriteString("|----------|-------|\n")
	fmt.Fprintf(&b, "| Critical | %d |\n", counts[finding.SeverityCritical])
	fmt.Fprintf(&b, "| High     | %d |\n", counts[finding.SeverityHigh])
	fmt.Fprintf(&b, "| Medium   | %d |\n", counts[finding.SeverityMedium])
	fmt.Fprintf(&b, "| Low      | %d |\n", counts[finding.SeverityLow])
	fmt.Fprintf(&b, "| Info     | %d |\n", counts[finding.SeverityInfo])
	fmt.Fprintf(&b, "| **Total**| **%d** |\n\n", len(enriched))

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
			fmt.Fprintf(&b, "| %s | %s | %s | %d | %d | %d | %d |\n",
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
			fmt.Fprintf(&b, "### [%s] %s\n\n", label, ef.Finding.Title)
			fmt.Fprintf(&b, "**Asset:** %s  \n", ef.Finding.Asset)
			fmt.Fprintf(&b, "**Check:** `%s`  \n", ef.Finding.CheckID)
			if ef.Finding.DiscoveredAt != (time.Time{}) {
				fmt.Fprintf(&b, "**Found:** %s  \n", ef.Finding.DiscoveredAt.Format("2006-01-02 15:04"))
			}
			if ef.DeltaStatus != "" {
				fmt.Fprintf(&b, "**Status:** %s  \n", ef.DeltaStatus)
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
				fmt.Fprintf(&b, "\n**Compliance:** %s\n", strings.Join(ef.ComplianceTags, ", "))
			}
			proofCmd := ef.Finding.ProofCommand
			if proofCmd == "" {
				proofCmd = verifyCmd(ef.Finding.CheckID, ef.Finding.Asset)
			}
			if proofCmd != "" {
				fmt.Fprintf(&b, "\n**Proof Command** (copy-paste to confirm):\n```sh\n%s\n```\n", proofCmd)
			}
			b.WriteString("\n---\n\n")
		}
	}

	return b.String()
}
