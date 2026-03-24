package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/enrichment"
	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/playbook"
	"github.com/stormbane/beacon/internal/store"
)

const textWidth = 72

// RenderText returns a plain-text (ASCII) security report suitable for
// terminal output or piping to other tools.
func RenderText(run store.ScanRun, enriched []enrichment.EnrichedFinding, summary string, executions []store.AssetExecution) string {
	var b strings.Builder
	sep := strings.Repeat("─", textWidth)
	thick := strings.Repeat("═", textWidth)

	// Header
	b.WriteString(thick + "\n")
	b.WriteString(center("BEACON SECURITY REPORT", textWidth) + "\n")
	b.WriteString(thick + "\n")
	fmt.Fprintf(&b, "  Domain:     %s\n", run.Domain)
	fmt.Fprintf(&b, "  Scan type:  %s\n", run.ScanType)
	fmt.Fprintf(&b, "  Started:    %s\n", run.StartedAt.Format("2006-01-02 15:04"))
	if run.CompletedAt != nil {
		fmt.Fprintf(&b, "  Completed:  %s\n", run.CompletedAt.Format("2006-01-02 15:04"))
	}
	b.WriteString(sep + "\n")

	// Severity counts
	counts := countSeverities(enriched)
	b.WriteString("\nSUMMARY\n")
	fmt.Fprintf(&b, "  Critical %-4d  High %-4d  Medium %-4d  Low %-4d  Info %-4d  Total %d\n\n",
		counts[finding.SeverityCritical],
		counts[finding.SeverityHigh],
		counts[finding.SeverityMedium],
		counts[finding.SeverityLow],
		counts[finding.SeverityInfo],
		len(enriched),
	)

	// Executive summary
	if summary != "" {
		b.WriteString(sep + "\n")
		b.WriteString("\nEXECUTIVE SUMMARY\n\n")
		b.WriteString(wordWrap(summary, textWidth-2, "  "))
		b.WriteString("\n")
	}

	// Asset inventory — all scanned assets, including those with zero findings
	inv := buildAssetInventory(enriched, executions)
	if len(inv) > 0 {
		clean := 0
		for _, e := range inv {
			if e.total == 0 {
				clean++
			}
		}
		b.WriteString("\n" + sep + "\n")
		fmt.Fprintf(&b, "\nASSET INVENTORY (%d assets, %d clean)\n", len(inv), clean)
		b.WriteString(sep + "\n\n")
		techW := 0
		for _, e := range inv {
			if len(e.tech) > techW {
				techW = len(e.tech)
			}
		}
		if techW < 4 {
			techW = 4
		}
		fmt.Fprintf(&b, "  %-45s  %-*s  findings\n", "Asset", techW, "Tech")
		b.WriteString("  " + strings.Repeat("─", 45) + "  " + strings.Repeat("─", techW) + "  ─────────\n")
		for _, e := range inv {
			var parts []string
			if e.crit > 0 {
				parts = append(parts, fmt.Sprintf("crit:%d", e.crit))
			}
			if e.high > 0 {
				parts = append(parts, fmt.Sprintf("high:%d", e.high))
			}
			if e.med > 0 {
				parts = append(parts, fmt.Sprintf("med:%d", e.med))
			}
			if e.low > 0 {
				parts = append(parts, fmt.Sprintf("low:%d", e.low))
			}
			findStr := "clean"
			if e.total > 0 {
				findStr = fmt.Sprintf("%d", e.total)
				if len(parts) > 0 {
					findStr += "  (" + strings.Join(parts, " ") + ")"
				}
			}
			fmt.Fprintf(&b, "  %-45s  %-*s  %s\n", e.asset, techW, e.tech, findStr)
		}
	}

	// Network topology — unwrap findings for service sub-nodes.
	rawFindings := make([]finding.Finding, 0, len(enriched))
	for _, ef := range enriched {
		rawFindings = append(rawFindings, ef.Finding)
	}
	if topo := RenderTopologyText(executions, rawFindings, textWidth); topo != "" {
		b.WriteString(topo)
	}

	if len(enriched) == 0 {
		b.WriteString("\n" + sep + "\n")
		b.WriteString("  No findings.\n")
		b.WriteString(thick + "\n")
		return b.String()
	}

	// Findings grouped by severity (descending)
	b.WriteString("\n" + sep + "\n")
	fmt.Fprintf(&b, "\nFINDINGS (%d)\n", len(enriched))
	b.WriteString(sep + "\n")

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
			label := strings.ToUpper(SeverityLabel(ef.Finding.Severity))
			fmt.Fprintf(&b, "\n[%s]  %s\n", label, ef.Finding.Title)
			fmt.Fprintf(&b, "  Asset:  %s\n", ef.Finding.Asset)
			fmt.Fprintf(&b, "  Check:  %s\n", ef.Finding.CheckID)
			if ef.Finding.DiscoveredAt != (time.Time{}) {
				fmt.Fprintf(&b, "  Found:  %s\n", ef.Finding.DiscoveredAt.Format("2006-01-02 15:04"))
			}
			if ef.DeltaStatus != "" {
				fmt.Fprintf(&b, "  Status: %s\n", ef.DeltaStatus)
			}
			if ef.Explanation != "" {
				b.WriteString("\n")
				b.WriteString(wordWrap(ef.Explanation, textWidth-4, "    "))
				b.WriteString("\n")
			}
			if ef.Impact != "" {
				b.WriteString("\n  Impact:\n")
				b.WriteString(wordWrap(ef.Impact, textWidth-4, "    "))
				b.WriteString("\n")
			}
			if ef.Remediation != "" {
				b.WriteString("\n  Remediation:\n")
				b.WriteString(wordWrap(ef.Remediation, textWidth-4, "    "))
				b.WriteString("\n")
			}
			if ef.TechSpecificRemediation != "" {
				b.WriteString("\n  Tech-specific fix:\n")
				b.WriteString(wordWrap(ef.TechSpecificRemediation, textWidth-4, "    "))
				b.WriteString("\n")
			}
			if len(ef.ComplianceTags) > 0 {
				fmt.Fprintf(&b, "\n  Compliance: %s\n", strings.Join(ef.ComplianceTags, ", "))
			}
			proofCmd := ef.Finding.ProofCommand
			if proofCmd == "" {
				proofCmd = verifyCmd(ef.Finding.CheckID, ef.Finding.Asset)
			}
			if proofCmd != "" {
				b.WriteString("\n  Proof Command (copy-paste to confirm):\n")
				b.WriteString("    " + proofCmd + "\n")
			}
			b.WriteString(sep + "\n")
		}
	}

	b.WriteString(thick + "\n")
	return b.String()
}

func countSeverities(enriched []enrichment.EnrichedFinding) map[finding.Severity]int {
	m := make(map[finding.Severity]int)
	for _, ef := range enriched {
		m[ef.Finding.Severity]++
	}
	return m
}

func center(s string, width int) string {
	if len(s) >= width {
		return s
	}
	pad := (width - len(s)) / 2
	return strings.Repeat(" ", pad) + s
}

// wordWrap wraps text at maxWidth columns, prefixing each line with indent.
func wordWrap(text string, maxWidth int, indent string) string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return ""
	}
	var b strings.Builder
	lineLen := 0
	b.WriteString(indent)
	for _, w := range words {
		if lineLen > 0 && lineLen+1+len(w) > maxWidth {
			b.WriteString("\n" + indent)
			lineLen = 0
		} else if lineLen > 0 {
			b.WriteByte(' ')
			lineLen++
		}
		b.WriteString(w)
		lineLen += len(w)
	}
	b.WriteString("\n")
	return b.String()
}

// assetInventoryEntry summarises one asset for the report inventory table.
type assetInventoryEntry struct {
	asset                string
	tech                 string // derived from evidence (e.g. "nginx", "Cloudflare", "host")
	total, crit, high, med, low int
}

// buildAssetInventory builds the full inventory from scanned asset executions
// (which includes clean assets with zero findings) merged with finding counts.
// Sorted by descending severity weight so the riskiest assets appear first.
func buildAssetInventory(enriched []enrichment.EnrichedFinding, executions []store.AssetExecution) []assetInventoryEntry {
	m := map[string]*assetInventoryEntry{}

	// Seed every scanned asset, even those with no findings.
	for _, ex := range executions {
		if _, ok := m[ex.Asset]; !ok {
			m[ex.Asset] = &assetInventoryEntry{
				asset: ex.Asset,
				tech:  deriveAssetType(ex.Evidence),
			}
		}
	}

	// Tally finding counts from enriched results.
	for _, ef := range enriched {
		a := ef.Finding.Asset
		if _, ok := m[a]; !ok {
			// Asset not in executions list (edge case); add it.
			m[a] = &assetInventoryEntry{asset: a}
		}
		e := m[a]
		e.total++
		switch ef.Finding.Severity {
		case finding.SeverityCritical:
			e.crit++
		case finding.SeverityHigh:
			e.high++
		case finding.SeverityMedium:
			e.med++
		case finding.SeverityLow:
			e.low++
		}
	}

	out := make([]assetInventoryEntry, 0, len(m))
	for _, e := range m {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool {
		wi := out[i].crit*1000 + out[i].high*100 + out[i].med*10 + out[i].low
		wj := out[j].crit*1000 + out[j].high*100 + out[j].med*10 + out[j].low
		if wi != wj {
			return wi > wj
		}
		if out[i].total != out[j].total {
			return out[i].total > out[j].total
		}
		return out[i].asset < out[j].asset
	})
	return out
}

// deriveAssetType returns a short human-readable technology label for an asset
// based on the evidence collected during fingerprinting.
func deriveAssetType(ev playbook.Evidence) string {
	// Prefer the web server banner — most specific signal.
	if ws := ev.ServiceVersions["web_server"]; ws != "" {
		// Strip version: "nginx/1.24.0" → "nginx", "Apache/2.4" → "Apache"
		if i := strings.IndexAny(ws, "/ "); i > 0 {
			ws = ws[:i]
		}
		return ws
	}
	// CDN detection via CNAME chain.
	for _, cname := range ev.CNAMEChain {
		lower := strings.ToLower(cname)
		switch {
		case strings.Contains(lower, "cloudfront"):
			return "CloudFront"
		case strings.Contains(lower, "cloudflare"):
			return "Cloudflare"
		case strings.Contains(lower, "akamai"):
			return "Akamai"
		case strings.Contains(lower, "fastly"):
			return "Fastly"
		}
	}
	// CDN detection via ASN.
	asnLower := strings.ToLower(ev.ASNOrg)
	switch {
	case strings.Contains(asnLower, "cloudflare"):
		return "Cloudflare"
	case strings.Contains(asnLower, "amazon"):
		return "AWS"
	case strings.Contains(asnLower, "google"):
		return "GCP"
	case strings.Contains(asnLower, "microsoft") || strings.Contains(asnLower, "azure"):
		return "Azure"
	}
	// Fallback: HTTP asset vs plain host.
	if ev.StatusCode > 0 {
		return "web"
	}
	return "host"
}
