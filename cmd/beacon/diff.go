package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/config"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/store"
	sqlitestore "github.com/stormbane-security/beacon/internal/store/sqlite"
)

// DiffCategory classifies a finding relative to a previous scan.
type DiffCategory string

const (
	DiffNew       DiffCategory = "NEW"
	DiffResolved  DiffCategory = "RESOLVED"
	DiffUnchanged DiffCategory = "UNCHANGED"
)

// DiffEntry holds a finding and its diff classification.
type DiffEntry struct {
	Finding  finding.Finding
	Category DiffCategory
}

// cmdDiff runs a diff between two scans: loads findings from a baseline scan
// (--baseline) and a comparison scan (--id), then categorises each finding as
// NEW, RESOLVED, or UNCHANGED.
func cmdDiff(cfg *config.Config, args []string) {
	var baselineID, compareID, outPath, severityFlag string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--baseline":
			i++
			if i < len(args) {
				baselineID = args[i]
			}
		case "--id":
			i++
			if i < len(args) {
				compareID = args[i]
			}
		case "--out":
			i++
			if i < len(args) {
				outPath = args[i]
			}
		case "--severity":
			i++
			if i < len(args) {
				severityFlag = args[i]
			}
		}
	}

	if baselineID == "" || compareID == "" {
		fatalf("both --baseline <scan-id> and --id <scan-id> are required\nUsage: beacon diff --baseline <old-scan-id> --id <new-scan-id>")
	}

	ctx := context.Background()

	st, err := sqlitestore.Open(cfg.Store.Path)
	if err != nil {
		fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	// Load both scan runs for metadata.
	baselineRun, err := st.GetScanRun(ctx, baselineID)
	if err != nil {
		fatalf("get baseline scan run %s: %v", baselineID, err)
	}
	compareRun, err := st.GetScanRun(ctx, compareID)
	if err != nil {
		fatalf("get comparison scan run %s: %v", compareID, err)
	}

	// Load findings from both scans.
	baselineFindings, err := st.GetFindings(ctx, baselineID)
	if err != nil {
		fatalf("get baseline findings: %v", err)
	}
	compareFindings, err := st.GetFindings(ctx, compareID)
	if err != nil {
		fatalf("get comparison findings: %v", err)
	}

	// Apply severity filter.
	minSev := finding.ParseSeverity(severityFlag)
	if minSev > finding.SeverityInfo {
		baselineFindings = filterFindingsBySeverity(baselineFindings, minSev)
		compareFindings = filterFindingsBySeverity(compareFindings, minSev)
	}

	// Build the diff.
	entries := diffFindings(baselineFindings, compareFindings)

	// Render.
	output := renderDiffReport(baselineRun, compareRun, entries)

	if outPath != "" {
		if err := os.WriteFile(outPath, []byte(output), 0o600); err != nil {
			fatalf("write diff report: %v", err)
		}
		_, _ = fmt.Fprintf(os.Stderr, "beacon: diff report written to %s\n", outPath)
	} else {
		fmt.Print(output)
	}
}

// findingKey produces a comparison key for a finding based on CheckID, Asset,
// and key evidence fields (path, port, parameter). Two findings with the same
// key are considered the "same" finding across scans.
func findingKey(f finding.Finding) string {
	parts := []string{string(f.CheckID), f.Asset}

	for _, k := range []string{"path", "port", "parameter"} {
		if v, ok := f.Evidence[k]; ok {
			parts = append(parts, fmt.Sprintf("%s=%v", k, v))
		}
	}

	return strings.Join(parts, "|")
}

// diffFindings compares baseline and comparison finding sets, producing
// categorised diff entries.
func diffFindings(baseline, compare []finding.Finding) []DiffEntry {
	// Index baseline findings by key.
	baselineIndex := make(map[string]finding.Finding, len(baseline))
	baselineUsed := make(map[string]bool, len(baseline))
	for _, f := range baseline {
		key := findingKey(f)
		baselineIndex[key] = f
	}

	var entries []DiffEntry

	// Walk comparison findings: if a match exists in baseline it's UNCHANGED,
	// otherwise it's NEW.
	for _, f := range compare {
		key := findingKey(f)
		if _, exists := baselineIndex[key]; exists {
			entries = append(entries, DiffEntry{Finding: f, Category: DiffUnchanged})
			baselineUsed[key] = true
		} else {
			entries = append(entries, DiffEntry{Finding: f, Category: DiffNew})
		}
	}

	// Any baseline finding not matched is RESOLVED.
	for _, f := range baseline {
		key := findingKey(f)
		if !baselineUsed[key] {
			entries = append(entries, DiffEntry{Finding: f, Category: DiffResolved})
		}
	}

	return entries
}

// filterFindingsBySeverity returns only findings at or above the given severity.
func filterFindingsBySeverity(findings []finding.Finding, min finding.Severity) []finding.Finding {
	var out []finding.Finding
	for _, f := range findings {
		if f.Severity >= min {
			out = append(out, f)
		}
	}
	return out
}

// renderDiffReport produces a colored text diff report.
func renderDiffReport(baseline, compare *store.ScanRun, entries []DiffEntry) string {
	var b strings.Builder

	_, _ = fmt.Fprintf(&b, "Scan Diff Report — %s\n", compare.Domain)
	_, _ = fmt.Fprintf(&b, "Baseline: %s (%s)\n", baseline.ID, baseline.StartedAt.Format(time.RFC3339))
	_, _ = fmt.Fprintf(&b, "Current:  %s (%s)\n", compare.ID, compare.StartedAt.Format(time.RFC3339))
	b.WriteString(strings.Repeat("─", 72) + "\n\n")

	// Count categories.
	var newCount, resolvedCount, unchangedCount int
	for _, e := range entries {
		switch e.Category {
		case DiffNew:
			newCount++
		case DiffResolved:
			resolvedCount++
		case DiffUnchanged:
			unchangedCount++
		}
	}

	_, _ = fmt.Fprintf(&b, "Summary: %d new, %d resolved, %d unchanged (of %d total)\n\n",
		newCount, resolvedCount, unchangedCount, len(entries))

	// Render by category.
	type categoryInfo struct {
		cat   DiffCategory
		color string
		label string
	}
	categories := []categoryInfo{
		{DiffNew, "\033[31m", "NEW"},
		{DiffResolved, "\033[32m", "RESOLVED"},
		{DiffUnchanged, "\033[90m", "UNCHANGED"},
	}

	for _, ci := range categories {
		var matching []DiffEntry
		for _, e := range entries {
			if e.Category == ci.cat {
				matching = append(matching, e)
			}
		}
		if len(matching) == 0 {
			continue
		}

		_, _ = fmt.Fprintf(&b, "── %s%s\033[0m (%d) ──\n", ci.color, ci.label, len(matching))
		for _, e := range matching {
			sev := severitySymbol(e.Finding.Severity)
			_, _ = fmt.Fprintf(&b, "  %s%s [%s] %s on %s\033[0m\n",
				ci.color, sev, e.Finding.CheckID, e.Finding.Title, e.Finding.Asset)
		}
		b.WriteString("\n")
	}

	return b.String()
}

// severitySymbol returns a short severity indicator.
func severitySymbol(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical:
		return "C"
	case finding.SeverityHigh:
		return "H"
	case finding.SeverityMedium:
		return "M"
	case finding.SeverityLow:
		return "L"
	default:
		return "I"
	}
}
