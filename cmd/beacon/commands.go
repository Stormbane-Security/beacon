package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/stormbane-security/beacon/internal/analyze"
	"github.com/stormbane-security/beacon/internal/config"
	"github.com/stormbane-security/beacon/internal/dedup"
	"github.com/stormbane-security/beacon/internal/enrichment"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	cloudmodule "github.com/stormbane-security/beacon/internal/modules/cloud"
	githubmodule "github.com/stormbane-security/beacon/internal/modules/github"
	"github.com/stormbane-security/beacon/internal/report"
	tfscan "github.com/stormbane-security/beacon/internal/scanner/terraform"
	"github.com/stormbane-security/beacon/internal/store"
	sqlitestore "github.com/stormbane-security/beacon/internal/store/sqlite"
	"github.com/stormbane-security/beacon/internal/verify"
)

// ---------- github scan ----------

func cmdScanGitHub(cfg *config.Config, orgOrRepo string, outPath string, format string, severityFlag string) {
	// Parse "github.com/org" or "github.com/org/repo" or just "org" or "org/repo".
	target := strings.TrimPrefix(orgOrRepo, "https://")
	target = strings.TrimPrefix(target, "github.com/")
	parts := strings.SplitN(target, "/", 2)

	input := module.Input{GitHubOrg: parts[0]}
	if len(parts) == 2 {
		input.GitHubRepo = parts[1]
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	mod := githubmodule.New(cfg.GitHubToken)
	_, _ = fmt.Fprintf(os.Stderr, "beacon: scanning GitHub org/repo %s for Actions vulnerabilities...\n", orgOrRepo)

	findings, err := mod.Run(ctx, input, module.ScanSurface)
	if err != nil {
		fatalf("github scan: %v", err)
	}

	minSev := finding.ParseSeverity(severityFlag)
	var filtered []finding.Finding
	for _, f := range findings {
		if f.Severity >= minSev {
			filtered = append(filtered, f)
		}
	}

	if len(filtered) == 0 {
		_, _ = fmt.Fprintf(os.Stderr, "beacon: no findings at or above severity %q\n", severityFlag)
		return
	}

	// Build output in the requested format.
	var out string
	switch strings.ToLower(format) {
	case "json":
		// Wrap raw findings in EnrichedFinding for the JSON renderer.
		enriched := make([]enrichment.EnrichedFinding, len(filtered))
		for i, f := range filtered {
			enriched[i] = enrichment.EnrichedFinding{Finding: f}
		}
		now := time.Now()
		syntheticRun := store.ScanRun{
			Domain:    orgOrRepo,
			ScanType:  module.ScanSurface,
			StartedAt: now,
			CompletedAt: &now,
			FindingCount: len(enriched),
		}
		var err error
		out, err = report.RenderJSON(syntheticRun, enriched, "", nil)
		if err != nil {
			fatalf("render json: %v", err)
		}
	case "markdown", "md":
		enriched := make([]enrichment.EnrichedFinding, len(filtered))
		for i, f := range filtered {
			enriched[i] = enrichment.EnrichedFinding{Finding: f}
		}
		now := time.Now()
		syntheticRun := store.ScanRun{
			Domain:    orgOrRepo,
			ScanType:  module.ScanSurface,
			StartedAt: now,
			CompletedAt: &now,
			FindingCount: len(enriched),
		}
		out = report.RenderMarkdown(syntheticRun, enriched, "", nil)
	default: // "text" or empty
		var sb strings.Builder
		_, _ = fmt.Fprintf(&sb, "GitHub Actions scan: %s\n%s\n\n", orgOrRepo, strings.Repeat("─", 60))
		for _, f := range filtered {
			_, _ = fmt.Fprintf(&sb, "[%s] %s\n  %s\n  Asset: %s\n\n", f.Severity, f.Title, f.Description, f.Asset)
		}
		out = sb.String()
	}

	if outPath != "" {
		if err := os.WriteFile(outPath, []byte(out), 0o600); err != nil {
			fatalf("write report: %v", err)
		}
		_, _ = fmt.Fprintf(os.Stderr, "beacon: report written to %s\n", outPath)
	} else {
		fmt.Print(out)
	}
}

// ---------- history ----------

func cmdHistory(cfg *config.Config, args []string) {
	var domain string
	for i := 0; i < len(args); i++ {
		if args[i] == "--domain" {
			i++
			if i < len(args) {
				domain = args[i]
			}
		}
	}
	if domain == "" {
		fatalf("--domain is required")
	}

	ctx := context.Background()
	st, err := sqlitestore.Open(cfg.Store.Path)
	if err != nil {
		fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	runs, err := st.ListScanRuns(ctx, domain)
	if err != nil {
		fatalf("list scans: %v", err)
	}

	if len(runs) == 0 {
		_, _ = fmt.Fprintf(os.Stderr, "no scans found for %s\n", domain)
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ID\tDOMAIN\tTYPE\tSTATUS\tFINDINGS\tSTARTED")
	for _, r := range runs {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\n",
			r.ID, r.Domain, r.ScanType, r.Status, r.FindingCount,
			r.StartedAt.Format("2006-01-02 15:04"))
	}
	_ = w.Flush()
}

// ---------- scans (list all) ----------

func cmdScans(cfg *config.Config, args []string) {
	limit := 50
	for i := 0; i < len(args); i++ {
		if args[i] == "--limit" {
			i++
			if i < len(args) {
				if n, err := strconv.Atoi(args[i]); err == nil && n > 0 {
					limit = n
				}
			}
		}
	}

	ctx := context.Background()
	st, err := sqlitestore.Open(cfg.Store.Path)
	if err != nil {
		fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	runs, err := st.ListAllScanRuns(ctx, limit)
	if err != nil {
		fatalf("list scans: %v", err)
	}

	if len(runs) == 0 {
		_, _ = fmt.Fprintln(os.Stderr, "no scans found")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ID\tDOMAIN\tTYPE\tSTATUS\tFINDINGS\tSTARTED\tDURATION")
	for _, r := range runs {
		dur := ""
		if r.CompletedAt != nil {
			dur = r.CompletedAt.Sub(r.StartedAt).Truncate(time.Second).String()
		} else if r.Status == store.StatusRunning {
			dur = time.Since(r.StartedAt).Truncate(time.Second).String() + " (running)"
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
			r.ID, r.Domain, r.ScanType, r.Status, r.FindingCount,
			r.StartedAt.Format("2006-01-02 15:04"), dur)
	}
	_ = w.Flush()
}

// ---------- stop ----------

func cmdStop(cfg *config.Config, args []string) {
	var id string
	for i := 0; i < len(args); i++ {
		if args[i] == "--id" {
			i++
			if i < len(args) {
				id = args[i]
			}
		}
	}
	if id == "" {
		fatalf("--id is required")
	}

	ctx := context.Background()
	st, err := sqlitestore.Open(cfg.Store.Path)
	if err != nil {
		fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	run, err := st.GetScanRun(ctx, id)
	if err != nil {
		fatalf("get scan: %v", err)
	}
	if run.Status != store.StatusRunning && run.Status != store.StatusPending {
		_, _ = fmt.Fprintf(os.Stderr, "scan %s is already %s\n", id, run.Status)
		return
	}

	// If this scan is running in the current process, cancel its context too.
	if j, ok := getLiveJob(id); ok {
		j.Stop()
	}

	run.Status = store.StatusStopped
	run.Error = "stopped via CLI"
	if err := st.UpdateScanRun(ctx, run); err != nil {
		fatalf("update scan: %v", err)
	}
	_, _ = fmt.Fprintf(os.Stderr, "beacon: scan %s marked as stopped\n", id)
}

// ---------- report ----------

func cmdReport(cfg *config.Config, args []string) {
	var id, format, severityFlag, outPath string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--id":
			i++
			if i < len(args) {
				id = args[i]
			}
		case "--format":
			i++
			if i < len(args) {
				format = args[i]
			}
		case "--severity":
			i++
			if i < len(args) {
				severityFlag = args[i]
			}
		case "--out":
			i++
			if i < len(args) {
				outPath = args[i]
			}
		}
	}
	if id == "" {
		fatalf("--id is required")
	}

	ctx := context.Background()
	st, err := sqlitestore.Open(cfg.Store.Path)
	if err != nil {
		fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	rep, err := st.GetReport(ctx, id)
	if err != nil {
		fatalf("get report: %v", err)
	}

	enriched, err := st.GetEnrichedFindings(ctx, id)
	if err != nil {
		// Fall back to HTML if enriched findings are unavailable.
		fmt.Print(rep.HTMLContent)
		return
	}

	enriched = filterBySeverity(enriched, severityFlag)

	run, err := st.GetScanRun(ctx, id)
	if err != nil {
		fatalf("get scan run: %v", err)
	}

	graphJSON, _ := st.GetAssetGraph(ctx, id)
	executions, _ := st.ListAssetExecutions(ctx, run.ID)
	output, err := renderFormat(format, *run, enriched, rep.Summary, rep, executions, graphJSON)
	if err != nil {
		fatalf("render report: %v", err)
	}

	if outPath != "" {
		if err := os.WriteFile(outPath, []byte(output), 0o600); err != nil {
			fatalf("write report file: %v", err)
		}
		_, _ = fmt.Fprintf(os.Stderr, "beacon: report written to %s\n", outPath)
	} else {
		fmt.Print(output)
	}
}

// ---------- analyze ----------

func cmdAnalyze(cfg *config.Config, args []string) {
	// Parse flags: --id <run-id> to verify a specific run, --out <file> to save report.
	var runID, outPath string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--id":
			if i+1 < len(args) {
				runID = args[i+1]
				i++
			}
		case "--out":
			if i+1 < len(args) {
				outPath = args[i+1]
				i++
			}
		}
	}

	if cfg.AnthropicAPIKey == "" {
		fatalf("ANTHROPIC_API_KEY is required for beacon analyze")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	st, err := sqlitestore.Open(cfg.Store.Path)
	if err != nil {
		fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	a, err := analyze.New(st, cfg.AnthropicAPIKey)
	if err != nil {
		fatalf("init analyzer: %v", err)
	}
	a.WithModel(cfg.ClaudeModel)
	a.WithProgress(func(msg string) {
		_, _ = fmt.Fprintf(os.Stderr, "beacon: %s\n", msg)
	})

	result, err := a.RunFull(ctx)
	if err != nil {
		fatalf("analyze: %v", err)
	}
	_, _ = fmt.Fprintf(os.Stderr, "beacon: analysis complete — %d suggestion(s), %d accuracy reviews\n",
		len(result.Suggestions), len(result.AccuracyReview))

	// Build the full markdown report from all analysis sections.
	var md strings.Builder
	md.WriteString("# Beacon Analysis Report\n\n")
	_, _ = fmt.Fprintf(&md, "Generated: %s\n\n", time.Now().Format(time.RFC3339))

	// Section: Finding Accuracy Review
	if len(result.AccuracyReview) > 0 {
		md.WriteString("## Finding Accuracy Review\n\n")
		fps := 0
		for _, r := range result.AccuracyReview {
			if r.Verdict == "likely_false_positive" {
				fps++
			}
		}
		_, _ = fmt.Fprintf(&md, "%d findings reviewed · %d likely false positives\n\n", len(result.AccuracyReview), fps)
		for _, r := range result.AccuracyReview {
			icon := "✓"
			switch r.Verdict {
			case "likely_false_positive":
				icon = "🚫"
			case "needs_verification":
				icon = "⚠️"
			}
			proofStatus := ""
			if !r.ProofCmdOK {
				proofStatus = fmt.Sprintf(" · proof broken: %s", r.ProofCmdIssue)
			}
			_, _ = fmt.Fprintf(&md, "- %s [%d%%] **%s** on `%s`%s\n", icon, r.Confidence, r.Title, r.Asset, proofStatus)
			if r.Reasoning != "" {
				_, _ = fmt.Fprintf(&md, "  > %s\n", r.Reasoning)
			}
		}
		md.WriteString("\n")
	}

	// Section: Credential Exposure Correlation (static, from verify package)
	v := verify.New(st, cfg.AnthropicAPIKey)
	if vreport, verr := v.RunLatest(ctx, runID); verr == nil && len(vreport.CredentialAlerts) > 0 {
		md.WriteString("## Credential Exposure + Exploit Path Correlation\n\n")
		for _, alert := range vreport.CredentialAlerts {
			fmt.Fprintf(&md, "- %s\n", alert)
		}
		md.WriteString("\n")
	}

	// Section: Scan Optimizations
	if len(result.ScanOptimizations) > 0 {
		md.WriteString("## Scan Optimizations\n\n")
		for _, o := range result.ScanOptimizations {
			fmt.Fprintf(&md, "- [%s] **%s**: %s\n", o.Type, o.Scanner, o.Description)
			if o.SuggestedChange != "" {
				fmt.Fprintf(&md, "  > Fix: %s\n", o.SuggestedChange)
			}
		}
		md.WriteString("\n")
	}

	// Section: Detection Gaps (CVEs we can't detect)
	if len(result.ScanGaps) > 0 {
		md.WriteString("## Detection Gaps\n\n")
		for _, g := range result.ScanGaps {
			fmt.Fprintf(&md, "- **%s** (%s): %s\n", g.CVEID, g.Product, g.ReasonUndetectable)
			if g.SuggestedNewScannerOrCheck != "" {
				fmt.Fprintf(&md, "  > Suggested: %s\n", g.SuggestedNewScannerOrCheck)
			}
		}
		md.WriteString("\n")
	}

	// Section: Fix Prompt for Claude Code
	if result.FixPrompt != "" && result.FixPrompt != "No scanner code fixes required." {
		md.WriteString("## Fix Prompt for Claude Code\n\n")
		md.WriteString("Paste this into Claude Code to fix identified scanner issues:\n\n")
		md.WriteString("```\n")
		md.WriteString(result.FixPrompt)
		md.WriteString("\n```\n\n")
	}

	// Section: Playbook Suggestions summary
	if len(result.Suggestions) > 0 {
		fmt.Fprintf(&md, "## Playbook Suggestions (%d saved)\n\n", len(result.Suggestions))
		md.WriteString("Run `beacon playbook suggestions` to review and apply.\n\n")
	}

	report := md.String()
	if outPath != "" {
		if err := os.WriteFile(outPath, []byte(report), 0o600); err != nil {
			fatalf("write output: %v", err)
		}
		_, _ = fmt.Fprintf(os.Stderr, "beacon: report written to %s\n", outPath)
	} else {
		fmt.Print(report)
	}

	_, _ = fmt.Fprintln(os.Stderr, "beacon: run 'beacon playbook suggestions' to review and apply suggestions")
}

// ---------- playbook ----------

func cmdPlaybookSuggestions(cfg *config.Config) {
	ctx := context.Background()

	st, err := sqlitestore.Open(cfg.Store.Path)
	if err != nil {
		fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	suggestions, err := st.ListPlaybookSuggestions(ctx, "pending")
	if err != nil {
		fatalf("list suggestions: %v", err)
	}

	if len(suggestions) == 0 {
		_, _ = fmt.Fprintln(os.Stdout, "No pending playbook suggestions. Run 'beacon analyze' to generate them.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ID\tTYPE\tPLAYBOOK\tSTATUS\tREASONING")
	for _, s := range suggestions {
		reasoning := s.Reasoning
		if len(reasoning) > 60 {
			reasoning = reasoning[:57] + "..."
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", s.ID, s.Type, s.TargetPlaybook, s.Status, reasoning)
	}
	_ = w.Flush()
}

func cmdPlaybookOpenPR(cfg *config.Config, args []string) {
	var id string
	for i := 0; i < len(args); i++ {
		if args[i] == "--id" {
			i++
			if i < len(args) {
				id = args[i]
			}
		}
	}
	if id == "" {
		fatalf("--id is required")
	}

	ctx := context.Background()
	st, err := sqlitestore.Open(cfg.Store.Path)
	if err != nil {
		fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	suggestions, err := st.ListPlaybookSuggestions(ctx, "")
	if err != nil {
		fatalf("list suggestions: %v", err)
	}

	var target *store.PlaybookSuggestion
	for i := range suggestions {
		if suggestions[i].ID == id {
			target = &suggestions[i]
			break
		}
	}
	if target == nil {
		fatalf("suggestion not found: %s", id)
	}

	// Sanitize the playbook name before using it in a file path.
	// Claude's response could contain path traversal sequences (e.g. "../etc/cron.d/evil").
	safeName := safePlaybookName(target.TargetPlaybook)
	if safeName == "" {
		fatalf("suggestion has invalid playbook name: %q", target.TargetPlaybook)
	}

	// Write YAML to a temp file and open a PR via gh CLI.
	yamlPath := filepath.Join(os.TempDir(), "beacon-playbook-"+safeName+".yaml")
	if err := os.WriteFile(yamlPath, []byte(target.SuggestedYAML), 0o600); err != nil {
		fatalf("write yaml: %v", err)
	}
	defer func() { _ = os.Remove(yamlPath) }()

	prTitle := fmt.Sprintf("playbook: add/update %s", target.TargetPlaybook)
	prBody := fmt.Sprintf("AI-suggested playbook change.\n\n**Reasoning:** %s\n\n**Type:** %s\n\n```yaml\n%s\n```",
		target.Reasoning, target.Type, target.SuggestedYAML)

	// Use gh CLI to create the PR.
	ghCmd := exec.Command("gh", "pr", "create",
		"--title", prTitle,
		"--body", prBody,
		"--base", "main",
	)
	ghCmd.Stdout = os.Stdout
	ghCmd.Stderr = os.Stderr

	_, _ = fmt.Fprintf(os.Stderr, "beacon: opening PR for suggestion %s...\n", id)
	if err := ghCmd.Run(); err != nil {
		fatalf("gh pr create: %v\n\nSuggested YAML written to %s", err, yamlPath)
	}

	target.Status = "pr_opened"
	if err := st.UpdatePlaybookSuggestion(ctx, target); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "beacon: warning: failed to update suggestion status: %v\n", err)
	}
}

// cmdPlaybookImport writes an approved suggestion's YAML to
// ~/.config/beacon/playbooks/<name>.yaml so LoadUserDir picks it up on
// the next scan. Usage: beacon playbook import --id <suggestion-id>
func cmdPlaybookImport(cfg *config.Config, args []string) {
	var id string
	for i := 0; i < len(args); i++ {
		if args[i] == "--id" {
			i++
			if i < len(args) {
				id = args[i]
			}
		}
	}
	if id == "" {
		fatalf("usage: beacon playbook import --id <suggestion-id>")
	}

	ctx := context.Background()
	st, err := sqlitestore.Open(cfg.Store.Path)
	if err != nil {
		fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	suggestions, err := st.ListPlaybookSuggestions(ctx, "")
	if err != nil {
		fatalf("list suggestions: %v", err)
	}
	var target *store.PlaybookSuggestion
	for i := range suggestions {
		if suggestions[i].ID == id {
			target = &suggestions[i]
			break
		}
	}
	if target == nil {
		fatalf("suggestion not found: %s", id)
	}

	if err := importPlaybookSuggestion(target); err != nil {
		fatalf("import playbook: %v", err)
	}
	target.Status = "imported"
	_ = st.UpdatePlaybookSuggestion(ctx, target)
	_, _ = fmt.Fprintf(os.Stdout, "Imported playbook %q — active on next scan.\n", target.TargetPlaybook)
}

// cmdPlaybookDismiss marks a pending suggestion as dismissed so it no longer
// appears in 'beacon playbook suggestions'. Usage: beacon playbook dismiss --id <id>
func cmdPlaybookDismiss(cfg *config.Config, args []string) {
	var id string
	for i := 0; i < len(args); i++ {
		if args[i] == "--id" {
			i++
			if i < len(args) {
				id = args[i]
			}
		}
	}
	if id == "" {
		fatalf("usage: beacon playbook dismiss --id <suggestion-id>")
	}

	ctx := context.Background()
	st, err := sqlitestore.Open(cfg.Store.Path)
	if err != nil {
		fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	suggestions, err := st.ListPlaybookSuggestions(ctx, "")
	if err != nil {
		fatalf("list suggestions: %v", err)
	}
	var target *store.PlaybookSuggestion
	for i := range suggestions {
		if suggestions[i].ID == id {
			target = &suggestions[i]
			break
		}
	}
	if target == nil {
		fatalf("suggestion not found: %s", id)
	}

	target.Status = "dismissed"
	if err := st.UpdatePlaybookSuggestion(ctx, target); err != nil {
		fatalf("dismiss: %v", err)
	}
	_, _ = fmt.Fprintf(os.Stdout, "Dismissed suggestion %s (%s).\n", id, target.TargetPlaybook)
}

// ---------- terraform ----------

// cmdTerraform scans one or more Terraform/OpenTofu HCL files (or directories)
// for infrastructure misconfigurations and prints findings to stdout.
//
// Usage:
//
//	beacon terraform <path> [<path>...]
//	beacon terraform --format json ./infra
//	beacon terraform --severity high ./infra
func cmdTerraform(cfg *config.Config, args []string) {
	var paths []string
	format := "text"
	severityFlag := ""

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--format", "-f":
			if i+1 < len(args) {
				i++
				format = args[i]
			}
		case "--severity", "-s":
			if i+1 < len(args) {
				i++
				severityFlag = args[i]
			}
		default:
			paths = append(paths, args[i])
		}
	}

	if len(paths) == 0 {
		fatalf("usage: beacon terraform [--format text|json|markdown] [--severity <level>] <path> [<path>...]")
	}

	findings, err := tfscan.ScanFiles(paths)
	if err != nil {
		fatalf("terraform scan: %v", err)
	}

	// Apply severity filter.
	minSev := finding.ParseSeverity(severityFlag)
	if minSev > finding.SeverityInfo {
		var filtered []finding.Finding
		for _, f := range findings {
			if f.Severity >= minSev {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}

	if len(findings) == 0 {
		fmt.Println("No issues found.")
		return
	}

	// Enrich with Claude if API key is set.
	enriched := make([]enrichment.EnrichedFinding, len(findings))
	for i, f := range findings {
		enriched[i] = enrichment.EnrichedFinding{Finding: f}
		// Populate TerraformFix from the finding Evidence if the scanner set it.
		if fix, ok := f.Evidence["terraform_fix"]; ok {
			if fixStr, ok := fix.(string); ok {
				enriched[i].TerraformFix = fixStr
			}
		}
	}

	if ai := cfg.ActiveAI(); ai != nil {
		enricher, err := enrichment.NewWithProvider(ai.Provider, ai.APIKey, ai.Model, ai.BaseURL)
		if err == nil {
			ctx := context.Background()
			if ef, err := enricher.Enrich(ctx, findings); err == nil {
				enriched = ef
				// Re-merge scanner-provided TerraformFix where Claude didn't produce one.
				for i, f := range findings {
					if enriched[i].TerraformFix == "" {
						if fix, ok := f.Evidence["terraform_fix"]; ok {
							if fixStr, ok := fix.(string); ok {
								enriched[i].TerraformFix = fixStr
							}
						}
					}
				}
			}
		}
	}

	// Render output.
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(enriched)
	case "markdown", "md":
		printTerraformMarkdown(enriched)
	default:
		printTerraformText(enriched)
	}
}

func printTerraformText(enriched []enrichment.EnrichedFinding) {
	counts := map[finding.Severity]int{}
	for _, ef := range enriched {
		counts[ef.Finding.Severity]++
	}
	fmt.Printf("Terraform scan: %d finding(s)\n", len(enriched))
	for _, sev := range []finding.Severity{finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium, finding.SeverityLow, finding.SeverityInfo} {
		if n := counts[sev]; n > 0 {
			fmt.Printf("  %s: %d\n", sev, n)
		}
	}
	fmt.Println()

	for _, ef := range enriched {
		f := ef.Finding
		fmt.Printf("[%s] %s\n", f.Severity, f.Title)
		fmt.Printf("  File: %s\n", f.Asset)
		if ef.Explanation != "" && ef.Explanation != f.Description {
			fmt.Printf("  %s\n", ef.Explanation)
		} else {
			fmt.Printf("  %s\n", f.Description)
		}
		if ef.Remediation != "" {
			fmt.Printf("  Fix: %s\n", ef.Remediation)
		}
		if ef.TerraformFix != "" {
			fmt.Println("  Terraform fix:")
			for _, line := range strings.Split(ef.TerraformFix, "\n") {
				fmt.Printf("    %s\n", line)
			}
		}
		fmt.Println()
	}
}

// ---------- enrich ----------

func cmdEnrich(cfg *config.Config, args []string) {
	var (
		inputPath    string
		outPath      string
		format       string
		severityFlag string
	)

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--input":
			i++
			if i < len(args) {
				inputPath = args[i]
			}
		case "--out":
			i++
			if i < len(args) {
				outPath = args[i]
			}
		case "--format":
			i++
			if i < len(args) {
				format = args[i]
			}
		case "--severity":
			i++
			if i < len(args) {
				severityFlag = args[i]
			}
		}
	}

	if inputPath == "" {
		fatalf("usage: beacon enrich --input <raw-findings.json> [--format text|json|markdown] [--out <path>] [--severity <level>]")
	}

	data, err := os.ReadFile(inputPath)
	if err != nil {
		fatalf("read input: %v", err)
	}
	raw, err := report.ParseRawJSON(data)
	if err != nil {
		fatalf("%v", err)
	}

	_, _ = fmt.Fprintf(os.Stderr, "beacon: loaded %d findings for %s from %s\n", len(raw.Findings), raw.Domain, inputPath)

	findings := raw.Findings

	// Apply severity filter before enrichment.
	minSev := finding.ParseSeverity(severityFlag)
	if minSev > finding.SeverityInfo {
		var filtered []finding.Finding
		for _, f := range findings {
			if f.Severity >= minSev {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}

	// Flag potential duplicates (idempotent — won't re-flag already-flagged findings).
	dedup.FlagDuplicates(findings)

	ctx := context.Background()

	// Initialize enricher.
	var enricher enrichment.Enricher
	if ai := cfg.ActiveAI(); ai != nil {
		ce, err := enrichment.NewWithProvider(ai.Provider, ai.APIKey, ai.Model, ai.BaseURL)
		if err != nil {
			fatalf("init enricher: %v", err)
		}
		// Open store for cache support.
		st, stErr := sqlitestore.Open(cfg.Store.Path)
		if stErr == nil {
			enricher = ce.WithCache(st)
			defer func() { _ = st.Close() }()
		} else {
			enricher = ce
		}
		_, _ = fmt.Fprintf(os.Stderr, "beacon: enriching %d findings with AI (%s)...\n", len(findings), ai.Provider)
	} else {
		enricher = enrichment.NewNoop()
		_, _ = fmt.Fprintf(os.Stderr, "beacon: no AI configured — building report with noop enrichment...\n")
	}

	enriched, err := enricher.Enrich(ctx, findings)
	if err != nil {
		fatalf("enrich: %v", err)
	}

	_, _ = fmt.Fprintf(os.Stderr, "beacon: generating executive summary...\n")
	enriched, summary, err := enricher.ContextualizeAndSummarize(ctx, enriched, raw.Domain)
	if err != nil {
		fatalf("contextualize: %v", err)
	}

	// Drop findings marked as having no actionable value.
	enriched = filterOmitted(enriched)
	enriched = filterBySeverity(enriched, severityFlag)

	// Build a synthetic ScanRun for rendering.
	now := time.Now()
	syntheticRun := store.ScanRun{
		ID:           raw.ScanID,
		Domain:       raw.Domain,
		ScanType:     module.ScanType(raw.ScanType),
		Status:       store.StatusCompleted,
		StartedAt:    raw.StartedAt,
		CompletedAt:  &now,
		FindingCount: len(enriched),
	}

	// Render output.
	var output string
	switch strings.ToLower(format) {
	case "json":
		output, err = report.RenderJSON(syntheticRun, enriched, summary, nil)
	case "markdown", "md":
		output = report.RenderMarkdown(syntheticRun, enriched, summary, nil)
	default:
		output = report.RenderText(syntheticRun, enriched, summary, nil)
	}
	if err != nil {
		fatalf("render: %v", err)
	}

	if outPath != "" {
		if err := os.WriteFile(outPath, []byte(output), 0o600); err != nil {
			fatalf("write report: %v", err)
		}
		_, _ = fmt.Fprintf(os.Stderr, "beacon: enriched report written to %s\n", outPath)
	} else {
		fmt.Print(output)
	}
}

func cmdScanCloud(cfg *config.Config, args []string) {
	var (
		awsProfile         string
		gcpCredentials     string
		azureSubscription  string
		doToken            string
		ociConfigFile      string
		domain             string
		format             = "text"
		outPath            string
		severityFlag       string
	)

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--aws-profile":
			if i+1 < len(args) {
				i++
				awsProfile = args[i]
			}
		case "--gcp-credentials":
			if i+1 < len(args) {
				i++
				gcpCredentials = args[i]
			}
		case "--azure-subscription":
			if i+1 < len(args) {
				i++
				azureSubscription = args[i]
			}
		case "--do-token":
			if i+1 < len(args) {
				i++
				doToken = args[i]
			}
		case "--oci-config":
			if i+1 < len(args) {
				i++
				ociConfigFile = args[i]
			}
		case "--domain":
			if i+1 < len(args) {
				i++
				domain = args[i]
			}
		case "--format", "-f":
			if i+1 < len(args) {
				i++
				format = args[i]
			}
		case "--out", "-o":
			if i+1 < len(args) {
				i++
				outPath = args[i]
			}
		case "--severity", "-s":
			if i+1 < len(args) {
				i++
				severityFlag = args[i]
			}
		}
	}

	inp := module.Input{
		CloudEnabled:        true,
		AWSProfile:          awsProfile,
		GCPCredentialsFile:  gcpCredentials,
		AzureSubscriptionID: azureSubscription,
		DOToken:             doToken,
		OCIConfigFile:       ociConfigFile,
		Domain:              domain,
	}

	providerList := cloudmodule.RegisteredProviders()
	if len(providerList) == 0 {
		fatalf("no cloud providers compiled in — rebuild without -tags no_cloud")
	}
	_, _ = fmt.Fprintf(os.Stderr, "beacon: cloud providers: %s\n", strings.Join(providerList, ", "))

	ctx := context.Background()
	m := cloudmodule.New()
	findings, err := m.Run(ctx, inp, module.ScanDeep)
	if err != nil {
		fatalf("cloud scan: %v", err)
	}

	// Apply severity filter.
	minSev := finding.ParseSeverity(severityFlag)
	if minSev > finding.SeverityInfo {
		var filtered []finding.Finding
		for _, f := range findings {
			if f.Severity >= minSev {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}

	if len(findings) == 0 {
		fmt.Println("No cloud posture issues found.")
		return
	}

	// Enrich with AI if configured.
	enriched := make([]enrichment.EnrichedFinding, len(findings))
	for i, f := range findings {
		enriched[i] = enrichment.EnrichedFinding{Finding: f}
	}
	if ai := cfg.ActiveAI(); ai != nil {
		if enricher, err := enrichment.NewWithProvider(ai.Provider, ai.APIKey, ai.Model, ai.BaseURL); err == nil {
			if ef, err := enricher.Enrich(ctx, findings); err == nil {
				enriched = ef
			}
		}
	}

	// Render output.
	var w io.Writer = os.Stdout
	if outPath != "" {
		f, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			fatalf("cloud: create output file: %v", err)
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(enriched)
	case "markdown", "md":
		printCloudMarkdown(w, enriched)
	default:
		printCloudText(w, enriched)
	}
}

func printCloudText(w io.Writer, enriched []enrichment.EnrichedFinding) {
	counts := map[finding.Severity]int{}
	for _, ef := range enriched {
		counts[ef.Finding.Severity]++
	}
	_, _ = fmt.Fprintf(w, "Cloud posture scan: %d finding(s)\n", len(enriched))
	for _, sev := range []finding.Severity{finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium, finding.SeverityLow, finding.SeverityInfo} {
		if n := counts[sev]; n > 0 {
			_, _ = fmt.Fprintf(w, "  %s: %d\n", sev, n)
		}
	}
	_, _ = fmt.Fprintln(w)
	for _, ef := range enriched {
		f := ef.Finding
		_, _ = fmt.Fprintf(w, "[%s] %s\n", f.Severity, f.Title)
		_, _ = fmt.Fprintf(w, "  Asset: %s\n", f.Asset)
		if ef.Explanation != "" && ef.Explanation != f.Description {
			_, _ = fmt.Fprintf(w, "  %s\n", ef.Explanation)
		} else {
			_, _ = fmt.Fprintf(w, "  %s\n", f.Description)
		}
		if f.ProofCommand != "" {
			_, _ = fmt.Fprintf(w, "  Proof: %s\n", f.ProofCommand)
		}
		if ef.Remediation != "" {
			_, _ = fmt.Fprintf(w, "  Fix: %s\n", ef.Remediation)
		}
		_, _ = fmt.Fprintln(w)
	}
}

func printCloudMarkdown(w io.Writer, enriched []enrichment.EnrichedFinding) {
	_, _ = fmt.Fprintf(w, "# Cloud Posture Scan Results\n\n%d finding(s)\n\n", len(enriched))
	for _, ef := range enriched {
		f := ef.Finding
		_, _ = fmt.Fprintf(w, "## [%s] %s\n\n", f.Severity, f.Title)
		_, _ = fmt.Fprintf(w, "**Asset:** `%s`\n\n", f.Asset)
		if ef.Explanation != "" {
			_, _ = fmt.Fprintf(w, "%s\n\n", ef.Explanation)
		} else if f.Description != "" {
			_, _ = fmt.Fprintf(w, "%s\n\n", f.Description)
		}
		if ef.Impact != "" {
			_, _ = fmt.Fprintf(w, "**Impact:** %s\n\n", ef.Impact)
		}
		if ef.Remediation != "" {
			_, _ = fmt.Fprintf(w, "**Remediation:** %s\n\n", ef.Remediation)
		}
		if f.ProofCommand != "" {
			_, _ = fmt.Fprintf(w, "**Proof:** `%s`\n\n", f.ProofCommand)
		}
		_, _ = fmt.Fprintf(w, "---\n\n")
	}
}

func printTerraformMarkdown(enriched []enrichment.EnrichedFinding) {
	fmt.Printf("# Terraform Scan Results\n\n")
	fmt.Printf("%d finding(s)\n\n", len(enriched))

	for _, ef := range enriched {
		f := ef.Finding
		fmt.Printf("## [%s] %s\n\n", f.Severity, f.Title)
		fmt.Printf("**File:** `%s`\n\n", f.Asset)
		if ef.Explanation != "" {
			fmt.Printf("%s\n\n", ef.Explanation)
		}
		if ef.Impact != "" {
			fmt.Printf("**Impact:** %s\n\n", ef.Impact)
		}
		if ef.Remediation != "" {
			fmt.Printf("**Remediation:** %s\n\n", ef.Remediation)
		}
		if ef.TerraformFix != "" {
			fmt.Printf("**Terraform Fix:**\n\n```hcl\n%s\n```\n\n", ef.TerraformFix)
		}
		fmt.Println("---")
		fmt.Println()
	}
}

// ---------- fingerprints ----------

func cmdFingerprints(cfg *config.Config, args []string) {
	db, err := sqlitestore.Open(cfg.Store.Path)
	if err != nil {
		fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()

	sub := "list"
	if len(args) > 0 {
		sub = args[0]
	}

	switch sub {
	case "list":
		rules, err := db.GetFingerprintRules(ctx, "active")
		if err != nil {
			fatalf("list rules: %v", err)
		}
		fmt.Printf("%-6s  %-8s  %-10s  %-22s  %-22s  %-14s  %-12s  %s\n",
			"ID", "SOURCE", "SIGNAL", "SIGNAL KEY/VALUE", "FIELD", "VALUE", "SEEN", "CONFIDENCE")
		fmt.Println(strings.Repeat("─", 110))
		for _, r := range rules {
			sig := r.SignalType
			kv := r.SignalValue
			if r.SignalKey != "" {
				kv = r.SignalKey + ": " + r.SignalValue
			}
			fmt.Printf("%-6d  %-8s  %-10s  %-22s  %-22s  %-14s  %-12d  %.0f%%\n",
				r.ID, r.Source, sig, truncateStr(kv, 22), r.Field, truncateStr(r.Value, 14), r.SeenCount, r.Confidence*100)
		}
		fmt.Printf("\n%d active rules\n", len(rules))

	case "pending":
		rules, err := db.GetFingerprintRules(ctx, "pending")
		if err != nil {
			fatalf("list pending: %v", err)
		}
		if len(rules) == 0 {
			fmt.Println("No pending fingerprint rules.")
			return
		}
		fmt.Printf("%-6s  %-8s  %-10s  %-25s  %-14s  %-14s  %s\n",
			"ID", "SOURCE", "SIGNAL", "SIGNAL KEY/VALUE", "FIELD", "VALUE", "CONFIDENCE")
		fmt.Println(strings.Repeat("─", 90))
		for _, r := range rules {
			kv := r.SignalValue
			if r.SignalKey != "" {
				kv = r.SignalKey + ": " + r.SignalValue
			}
			fmt.Printf("%-6d  %-8s  %-10s  %-25s  %-14s  %-14s  %.0f%%\n",
				r.ID, r.Source, r.SignalType, truncateStr(kv, 25), r.Field, truncateStr(r.Value, 14), r.Confidence*100)
		}
		fmt.Printf("\n%d pending rules awaiting review\n", len(rules))
		fmt.Println("Run 'beacon fingerprints approve <id>' to activate or 'beacon fingerprints reject <id>' to dismiss.")

	case "approve":
		if len(args) < 2 {
			fatalf("usage: beacon fingerprints approve <id>")
		}
		id, err := strconv.ParseInt(args[1], 10, 64)
		if err != nil {
			fatalf("invalid id: %v", err)
		}
		rules, err := db.GetFingerprintRules(ctx, "pending")
		if err != nil {
			fatalf("fetch rule: %v", err)
		}
		var found *store.FingerprintRule
		for i := range rules {
			if rules[i].ID == id {
				found = &rules[i]
				break
			}
		}
		if found == nil {
			fatalf("pending rule %d not found", id)
		}
		found.Status = "active"
		if err := db.UpsertFingerprintRule(ctx, found); err != nil {
			fatalf("approve: %v", err)
		}
		fmt.Printf("Rule %d approved: %s %s → %s: %s\n", id, found.SignalType, found.SignalValue, found.Field, found.Value)

	case "reject":
		if len(args) < 2 {
			fatalf("usage: beacon fingerprints reject <id>")
		}
		id, err := strconv.ParseInt(args[1], 10, 64)
		if err != nil {
			fatalf("invalid id: %v", err)
		}
		rules, _ := db.GetFingerprintRules(ctx, "pending")
		for i := range rules {
			if rules[i].ID == id {
				rules[i].Status = "rejected"
				_ = db.UpsertFingerprintRule(ctx, &rules[i])
				fmt.Printf("Rule %d rejected\n", id)
				return
			}
		}
		fatalf("pending rule %d not found", id)

	case "delete":
		if len(args) < 2 {
			fatalf("usage: beacon fingerprints delete <id>")
		}
		id, err := strconv.ParseInt(args[1], 10, 64)
		if err != nil {
			fatalf("invalid id: %v", err)
		}
		if err := db.DeleteFingerprintRule(ctx, id); err != nil {
			fatalf("delete: %v", err)
		}
		fmt.Printf("Deleted rule %d\n", id)

	case "add":
		// beacon fingerprints add <signal_type> <signal_key_or_--> <signal_value> <field> <value>
		if len(args) < 6 {
			fatalf("usage: beacon fingerprints add <signal_type> <signal_key|--> <signal_value> <field> <value>\n" +
				"  signal_type: header|body|path|cookie|cname|server|title|dns_suffix|asn_org\n" +
				"  signal_key:  header name for type=header, use '--' for others\n" +
				"  field:       framework|proxy_type|auth_system|cloud_provider|infra_layer|backend_services\n" +
				"  Example: beacon fingerprints add header x-my-cdn '' proxy_type mycdn")
		}
		key := args[2]
		if key == "--" {
			key = ""
		}
		r := &store.FingerprintRule{
			SignalType:  args[1],
			SignalKey:   key,
			SignalValue: args[3],
			Field:       args[4],
			Value:       args[5],
			Source:      "user",
			Status:      "active",
			Confidence:  1.0,
			SeenCount:   1,
		}
		if err := db.UpsertFingerprintRule(ctx, r); err != nil {
			fatalf("add rule: %v", err)
		}
		fmt.Printf("Added rule: %s %s → %s: %s\n", r.SignalType, r.SignalValue, r.Field, r.Value)

	default:
		fatalf("unknown subcommand: beacon fingerprints %s\n  subcommands: list, pending, approve, reject, delete, add", sub)
	}
}
