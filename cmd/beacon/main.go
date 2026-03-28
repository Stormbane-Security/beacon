// Beacon — security reconnaissance tool by Stormbane Security.
// Usage: beacon scan --domain <domain> [flags]
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"

	"github.com/stormbane/beacon/internal/analyze"
	"github.com/stormbane/beacon/internal/fingerprintdb"
	"github.com/stormbane/beacon/internal/verify"
	"github.com/stormbane/beacon/internal/api"
	"github.com/stormbane/beacon/internal/config"
	"github.com/stormbane/beacon/internal/enrichment"
	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/profiler"
	"github.com/stormbane/beacon/internal/module"
	githubmodule "github.com/stormbane/beacon/internal/modules/github"
	"github.com/stormbane/beacon/internal/modules/surface"
	"github.com/stormbane/beacon/internal/playbook"
	"github.com/stormbane/beacon/internal/report"
	tfscan "github.com/stormbane/beacon/internal/scanner/terraform"
	"github.com/stormbane/beacon/internal/store"
	sqlitestore "github.com/stormbane/beacon/internal/store/sqlite"
	"github.com/stormbane/beacon/internal/scanner/toolinstall"
	"golang.org/x/term"
)

const usageText = `Beacon — security reconnaissance tool

USAGE:
  beacon install                                 Install all required external tools
  beacon scan        --domain <domain> [flags]   Run a surface/deep scan
  beacon scan        --github <org> [flags]      Scan a GitHub org's Actions workflows
  beacon browse                                  Interactive TUI browser for past scans
  beacon history     --domain <domain>           List past scans
  beacon report      --id <scan-id> [flags]      Print a past report
  beacon analyze     [--id <run-id>] [--out <file>]  Playbook analysis + finding accuracy review
  beacon playbook    suggestions                 List AI playbook suggestions
  beacon playbook    import --id <id>            Import suggestion to ~/.config/beacon/playbooks/
  beacon playbook    dismiss --id <id>           Dismiss a suggestion (won't appear again)
  beacon playbook    open-pr --id <id>           Open a GitHub PR for a suggestion

SCAN FLAGS:
  --domain <domain>          Target domain (required)
  --deep                     Enable active probing (requires --permission-confirmed)
  --permission-confirmed     Acknowledge you have permission to run active probes
  --authorized               Enable exploitation-class probes (requires --deep, --permission-confirmed, and interactive acknowledgment)
  --format <fmt>             Output format: text (default), html, json, markdown
  --out <path>               Write report to file instead of stdout
  --severity <level>         Minimum severity to include: critical, high, medium, low, info (default)
  --verbose                  Show scanner-level progress (which scanner is running, fingerprint hits)
  --server <url>             Run against a remote beacond instance
  --api-key <key>            API key for the remote server

REPORT FLAGS:
  --id <scan-id>             Scan run ID (required)
  --format <fmt>             Output format: text (default), html, json, markdown
  --out <path>               Write report to file instead of stdout
  --severity <level>         Minimum severity to include: critical, high, medium, low, info (default)

REMOTE MODE:
  Set BEACON_SERVER_URL and BEACON_SERVER_API_KEY environment variables,
  or configure them in ~/.beacon/config.yaml, to route all commands to a
  remote beacond instance instead of running locally.

EXAMPLES:
  beacon scan --domain example.com
  beacon scan --domain example.com --format json
  beacon scan --domain example.com --severity high
  beacon scan --domain example.com --server https://beacon.example.com --api-key sk-...
  beacon scan --domain example.com --out report.html --format html
  beacon scan --domain example.com --deep --permission-confirmed
  beacon report --id <id> --format markdown
  beacon analyze
  beacon playbook suggestions
  beacon playbook import --id <suggestion-id>
  beacon playbook open-pr --id <suggestion-id>
  beacon terraform <path> [<path>...]
`

// version is set at build time via -ldflags "-X main.version=vX.Y.Z".
// It defaults to "dev" for local builds.
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		// No subcommand — open the interactive scan history browser.
		cfg, err := config.Load()
		if err != nil {
			fatalf("config: %v", err)
		}
		cmdBrowse(cfg)
		return
	}

	cfg, err := config.Load()
	if err != nil {
		fatalf("config: %v", err)
	}

	switch os.Args[1] {
	case "version", "--version", "-v":
		fmt.Printf("beacon %s\n", version)
		return
	case "install":
		cmdInstall()
	case "scan":
		cmdScan(cfg, os.Args[2:])
	case "browse":
		cmdBrowse(cfg)
	case "history":
		cmdHistory(cfg, os.Args[2:])
	case "report":
		cmdReport(cfg, os.Args[2:])
	case "analyze":
		cmdAnalyze(cfg, os.Args[2:])
	case "playbook":
		if len(os.Args) < 3 {
			fatalf("usage: beacon playbook <subcommand>")
		}
		switch os.Args[2] {
		case "suggestions":
			cmdPlaybookSuggestions(cfg)
		case "open-pr":
			cmdPlaybookOpenPR(cfg, os.Args[3:])
		case "import":
			cmdPlaybookImport(cfg, os.Args[3:])
		case "dismiss":
			cmdPlaybookDismiss(cfg, os.Args[3:])
		default:
			fatalf("unknown playbook subcommand: %s", os.Args[2])
		}
	case "fingerprints":
		cmdFingerprints(cfg, os.Args[2:])
	case "terraform":
		cmdTerraform(cfg, os.Args[2:])
	case "--help", "-h", "help":
		fmt.Print(usageText)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n%s", os.Args[1], usageText)
		os.Exit(1)
	}
}

// ---------- install ----------

func cmdInstall() {
	fmt.Fprintln(os.Stderr, "beacon: checking and installing required tools...")
	results := toolinstall.EnsureAll()
	ok := true
	for _, r := range results {
		switch {
		case r.Skipped:
			fmt.Fprintf(os.Stderr, "  %-16s  skipped (not supported on this platform)\n", r.Name)
		case r.Err != nil:
			fmt.Fprintf(os.Stderr, "  %-16s  FAILED: %v\n", r.Name, r.Err)
			ok = false
		default:
			fmt.Fprintf(os.Stderr, "  %-16s  ok  %s\n", r.Name, r.Path)
		}
	}
	if ok {
		fmt.Fprintln(os.Stderr, "beacon: all tools ready.")
	} else {
		fmt.Fprintln(os.Stderr, "beacon: some tools failed to install — see errors above.")
		os.Exit(1)
	}
}

// ---------- scan ----------

func cmdScan(cfg *config.Config, args []string) {
	var (
		domain              string
		githubOrg           string
		deep                bool
		permissionConfirmed bool
		authorized          bool
		outPath             string
		format              string
		severityFlag        string
		verbose             bool
		serverURL           string
		apiKey              string
		extraCIDRs          []string
	)

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--domain":
			i++
			if i < len(args) {
				domain = args[i]
			}
		case "--github":
			i++
			if i < len(args) {
				githubOrg = args[i]
			}
		case "--deep":
			deep = true
		case "--permission-confirmed":
			permissionConfirmed = true
		case "--authorized":
			authorized = true
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
		case "--verbose":
			verbose = true
		case "--server":
			i++
			if i < len(args) {
				serverURL = args[i]
			}
		case "--api-key":
			i++
			if i < len(args) {
				apiKey = args[i]
			}
		case "--cidr":
			i++
			if i < len(args) {
				extraCIDRs = append(extraCIDRs, args[i])
			}
		}
	}

	// GitHub Actions scan mode — mutually exclusive with domain scan.
	if githubOrg != "" {
		cmdScanGitHub(cfg, githubOrg, outPath, format, severityFlag)
		return
	}

	if domain == "" {
		fatalf("--domain or --github is required\n\n%s", usageText)
	}

	if deep && !permissionConfirmed {
		fatalf(`--deep requires --permission-confirmed

Deep scans send active probes to the target: vulnerability payloads (XSS,
SQLi, SSRF, path traversal), credential attempts, and aggressive TLS cipher
negotiation. These actions constitute unauthorized computer access in most
jurisdictions when performed without explicit written consent from the owner.

Applicable laws include (but are not limited to):
  US:  Computer Fraud and Abuse Act, 18 U.S.C. § 1030
  UK:  Computer Misuse Act 1990
  EU:  Directive 2013/40/EU on attacks against information systems
  DE:  StGB §202a (data espionage), §202c (hacking tools/methods)
  AU:  Criminal Code Act 1995, Part 10.7 (Computer offences)
  CA:  Criminal Code R.S.C. 1985, s342.1
  JP:  Unauthorized Computer Access Law (不正アクセス禁止法)
  BR:  Lei nº 12.737/2012 (Lei Carolina Dieckmann)
  SG:  Computer Misuse Act (Cap. 50A)
  IN:  Information Technology Act 2000, s43/66
  and equivalent laws in other jurisdictions.

By passing --permission-confirmed you confirm that:
  1. You have explicit written authorization from the owner of %s
     to perform active security testing against their systems.
  2. You understand that performing these scans without authorization
     may result in civil liability and/or criminal prosecution.
  3. You accept full legal responsibility for your use of --deep mode.`, domain)
	}

	if authorized && (!deep || !permissionConfirmed) {
		fatalf("--authorized requires --deep and --permission-confirmed")
	}
	if authorized {
		// Interactive legal acknowledgment — cannot be bypassed with a flag.
		fmt.Fprintf(os.Stderr, `
AUTHORIZED / EXPLOITATION SCAN MODE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
This mode enables active exploitation probes against %s, including:
  • Payload injection (SSTI, XXE, SSRF, Log4Shell, CRLF, prototype pollution)
  • Real authenticated sessions (SIWE/SIWS wallet login, OAuth flows)
  • File upload bypass attempts (may leave files on the target server)
  • Authorization flow mutation (token substitution, redirect_uri abuse)
  • SAML/JWT forgery attacks against protected endpoints

These actions constitute unauthorized computer access in most jurisdictions
unless you have EXPLICIT WRITTEN AUTHORIZATION from the system owner.

Applicable laws: US CFAA (18 U.S.C. §1030), UK CMA 1990, EU Dir. 2013/40/EU,
and equivalent laws in all other jurisdictions.

Type exactly: I have written authorization for %s
> `, domain, domain)
		reader := bufio.NewReader(os.Stdin)
		line, _ := reader.ReadString('\n')
		expected := fmt.Sprintf("I have written authorization for %s", domain)
		if strings.TrimSpace(line) != expected {
			fatalf("Acknowledgment not confirmed. Authorized mode cancelled.")
		}
		fmt.Fprintln(os.Stderr, "Acknowledgment confirmed. Proceeding with authorized scan.")
	}

	// Resolve server URL: flag > env/config
	if serverURL == "" {
		serverURL = cfg.Server.URL
	}
	if apiKey == "" {
		apiKey = cfg.Server.APIKey
	}

	// Remote mode: delegate to beacond
	if serverURL != "" {
		cmdScanRemote(serverURL, apiKey, domain, deep, permissionConfirmed, outPath)
		return
	}

	scanType := module.ScanSurface
	if deep {
		scanType = module.ScanDeep
	}
	if authorized {
		scanType = module.ScanAuthorized
	}


	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Open store
	st, err := sqlitestore.Open(cfg.Store.Path)
	if err != nil {
		fatalf("open store: %v", err)
	}
	defer st.Close()

	// Seed built-in fingerprint rules (idempotent — safe to call every scan).
	if seedErr := fingerprintdb.Seed(ctx, st); seedErr != nil {
		_ = seedErr // non-fatal
	}

	// Upsert target
	target, err := st.UpsertTarget(ctx, domain)
	if err != nil {
		fatalf("upsert target: %v", err)
	}

	// Create scan run
	run := &store.ScanRun{
		TargetID:  target.ID,
		Domain:    domain,
		ScanType:  scanType,
		Modules:   []string{"surface"},
		Status:    store.StatusPending,
		StartedAt: time.Now(),
	}
	if err := st.CreateScanRun(ctx, run); err != nil {
		fatalf("create scan run: %v", err)
	}

	fmt.Fprintf(os.Stderr, "beacon: scanning %s (%s)\n", domain, scanType)

	// Warn about missing API keys that meaningfully reduce scan coverage.
	warnMissingAPIKeys(cfg)

	run.Status = store.StatusRunning
	_ = st.UpdateScanRun(ctx, run)

	// Run surface module
	mod, err := surface.New(surface.Config{
		NucleiBin:       cfg.NucleiBin,
		SubfinderBin:    "subfinder",
		AmmassBin:       cfg.AmmassBin,
		TestsslBin:      cfg.TestsslBin,
		GauBin:          cfg.GauBin,
		KatanaBin:       cfg.KatanaBin,
		GowitnessBin:    cfg.GowitnessBin,
		AnthropicAPIKey:      cfg.AnthropicAPIKey,
		ShodanAPIKey:         cfg.ShodanAPIKey,
		HIBPAPIKey:           cfg.HIBPAPIKey,
		BingAPIKey:           cfg.BingAPIKey,
		OTXAPIKey:            cfg.OTXAPIKey,
		VirusTotalAPIKey:     cfg.VirusTotalAPIKey,
		SecurityTrailsAPIKey: cfg.SecurityTrailsAPIKey,
		CensysAPIID:          cfg.CensysAPIID,
		CensysAPISecret:      cfg.CensysAPISecret,
		GreyNoiseAPIKey:      cfg.GreyNoiseAPIKey,
		NmapBin:              cfg.NmapBin,
		Store:                st,
		HttpxBin:             cfg.HttpxBin,
		DnsxBin:              cfg.DnsxBin,
		FfufBin:              cfg.FfufBin,
		AdaptiveRecon:        cfg.AdaptiveRecon,
		ProxyPool:            cfg.ProxyPool,
		RequestJitterMs:      cfg.RequestJitterMs,
		ClaudeModel:          cfg.ClaudeModel,
		Auth:                 cfg.Auth,
		GitHubToken:          cfg.GitHubToken,
	})
	if err != nil {
		fatalf("init scanner: %v", err)
	}

	pr := newProgressRenderer(verbose, finding.ParseSeverity(severityFlag))
	pr.cancelFn = cancel // allow the live UI to stop the scan via 's' or Ctrl+C
	defer pr.Done()      // always restore terminal, even on panic
	input := module.Input{
		Domain:              domain,
		PermissionConfirmed: permissionConfirmed,
		ScanRunID:           run.ID,
		Progress:            pr.Handle,
		ExtraCIDRs:          extraCIDRs,
	}

	// Run the scan in a goroutine so we can respond to a detach signal.
	type scanResult struct {
		findings []finding.Finding
		err      error
	}
	resultCh := make(chan scanResult, 1)
	scanDone := make(chan struct{}) // closed when the scan goroutine exits
	go func() {
		f, e := mod.Run(ctx, input, scanType)
		resultCh <- scanResult{f, e}
		close(scanDone)
	}()

	// Wait for scan completion or user detach (b/Esc pressed in live UI).
	// waitScanResult drains resultCh and handles cancellation gracefully.
	// Returns (findings, stopped) where stopped=true means user cancelled via q.
	waitScanResult := func() ([]finding.Finding, bool) {
		res := <-resultCh
		if res.err != nil {
			if res.err == context.Canceled || strings.Contains(res.err.Error(), "context canceled") {
				// Graceful user stop — save partial findings, mark stopped.
				run.Status = store.StatusStopped
				run.Error = "stopped by user"
				_ = st.UpdateScanRun(ctx, run)
				if len(res.findings) > 0 {
					_ = st.SaveFindings(ctx, run.ID, res.findings)
				}
				return res.findings, true
			}
			run.Status = store.StatusFailed
			run.Error = res.err.Error()
			_ = st.UpdateScanRun(ctx, run)
			fatalf("scan failed: %v", res.err)
		}
		return res.findings, false
	}

	var findings []finding.Finding
	select {
	case res := <-resultCh:
		pr.Done() // restore terminal before any post-scan output
		if res.err != nil {
			if res.err == context.Canceled || strings.Contains(res.err.Error(), "context canceled") {
				run.Status = store.StatusStopped
				run.Error = "stopped by user"
				_ = st.UpdateScanRun(ctx, run)
				if len(res.findings) > 0 {
					_ = st.SaveFindings(ctx, run.ID, res.findings)
				}
				fmt.Fprintf(os.Stderr, "beacon: scan stopped — %d findings saved\n", len(res.findings))
				cmdBrowse(cfg)
				return
			}
			run.Status = store.StatusFailed
			run.Error = res.err.Error()
			_ = st.UpdateScanRun(ctx, run)
			fatalf("scan failed: %v", res.err)
		}
		findings = res.findings
	case <-pr.detached:
		// User pressed b — restore terminal and show browse TUI.
		// The scan goroutine continues; we wait for it after the browser exits.
		pr.Done()
		// Register this scan as a liveJob so browseInteractive can attach/stop it.
		pr.mu.Lock()
		pr.headless = true
		pr.detached = make(chan struct{}) // reset for potential re-attach
		pr.drawn = false
		pr.drawnLines = 0
		pr.mu.Unlock()
		lj := &liveJob{
			runID:    run.ID,
			domain:   domain,
			scanType: string(scanType),
			cancel:   cancel,
			renderer: pr,
			done:     scanDone,
		}
		registerJob(lj)
		cmdBrowse(cfg) // blocks until user quits the browser
		// User quit browse — exit beacon. The scan goroutine is cancelled via
		// the signal context (Ctrl+C) or will be cleaned up on process exit.
		// Mark the run as stopped so it doesn't stay "running" in history.
		unregisterJob(run.ID)
		select {
		case <-scanDone:
			// Scan already finished while we were in browse — fall through to save.
		default:
			// Still running — mark stopped and exit. Findings saved so far are lost.
			run.Status = store.StatusStopped
			run.Error = "detached by user"
			_ = st.UpdateScanRun(ctx, run)
			return
		}
		// Scan finished while in browse — save its results.
		var stopped bool
		findings, stopped = waitScanResult()
		if stopped {
			return
		}
	}

	// Save raw findings
	if err := st.SaveFindings(ctx, run.ID, findings); err != nil {
		fatalf("save findings: %v", err)
	}

	// Run deterministic compound-attack correlation rules synchronously.
	// These fire without AI and appear in the TUI even when AI is skipped.
	if corrFindings, err := analyze.RunDeterministicCorrelations(ctx, st, run.ID, domain); err != nil {
		fmt.Fprintf(os.Stderr, "beacon: deterministic correlations: %v\n", err)
	} else if len(corrFindings) > 0 {
		fmt.Fprintf(os.Stderr, "beacon: %d compound attack chain(s) detected\n", len(corrFindings))
	}

	// Apply severity filter before enrichment so below-threshold findings are
	// never sent to the Claude API — saves tokens and keeps prompts focused.
	minSev := finding.ParseSeverity(severityFlag)
	if minSev > finding.SeverityInfo {
		filtered := findings[:0]
		for _, f := range findings {
			if f.Severity >= minSev {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}

	// Enrich findings
	var enricher enrichment.Enricher
	if ai := cfg.ActiveAI(); ai != nil {
		ce, err := enrichment.NewWithProvider(ai.Provider, ai.APIKey, ai.Model, ai.BaseURL)
		if err != nil {
			fatalf("init enricher: %v", err)
		}
		enricher = ce.WithCache(st)
		fmt.Fprintf(os.Stderr, "beacon: %d findings — enriching with AI (%s)...\n", len(findings), ai.Provider)
	} else {
		enricher = enrichment.NewNoop()
		fmt.Fprintf(os.Stderr, "beacon: %d findings — building report...\n", len(findings))
	}

	enriched, err := enricher.Enrich(ctx, findings)
	if err != nil {
		fatalf("enrich: %v", err)
	}

	if cfg.ActiveAI() != nil {
		fmt.Fprintf(os.Stderr, "beacon: generating executive summary...\n")
	}
	enriched, summary, err := enricher.ContextualizeAndSummarize(ctx, enriched, domain)
	if err != nil {
		fatalf("contextualize: %v", err)
	}

	// Drop findings Claude marked as having no actionable value given other controls.
	enriched = filterOmitted(enriched)

	// Apply minimum-severity filter.
	enriched = filterBySeverity(enriched, severityFlag)

	if err := st.SaveEnrichedFindings(ctx, run.ID, enriched); err != nil {
		fatalf("save enriched findings: %v", err)
	}

	// Mark completed
	now := time.Now()
	run.Status = store.StatusCompleted
	run.CompletedAt = &now
	run.FindingCount = len(findings)
	if err := st.UpdateScanRun(ctx, run); err != nil {
		fatalf("update scan run: %v", err)
	}

	// Build HTML report (always saved to store for history/re-export).
	rep, err := report.Build(report.Input{
		ScanRun:          *run,
		EnrichedFindings: enriched,
		ExecutiveSummary: summary,
	})
	if err != nil {
		fatalf("build report: %v", err)
	}

	if err := st.SaveReport(ctx, rep); err != nil {
		fatalf("save report: %v", err)
	}

	// Deliver in the requested format.
	executions, _ := st.ListAssetExecutions(ctx, run.ID)
	output, err := renderFormat(format, *run, enriched, summary, rep, executions)
	if err != nil {
		fatalf("render report: %v", err)
	}

	if outPath != "" {
		if err := os.WriteFile(outPath, []byte(output), 0o644); err != nil {
			fatalf("write report file: %v", err)
		}
		fmt.Fprintf(os.Stderr, "beacon: report written to %s\n", outPath)
	} else {
		fmt.Print(output)
	}

	// Attack path analysis: uses Claude (Anthropic) specifically.
	// Requires anthropic_api_key in config regardless of the ai: provider block.
	if cfg.AttackPathAnalysis && cfg.AnthropicAPIKey != "" && len(findings) >= 2 {
		fmt.Fprintf(os.Stderr, "beacon: analysing attack paths...\n")
		chains := profiler.ReasonAttackPaths(ctx, cfg.AnthropicAPIKey, cfg.ClaudeModel, findings)
		if f := profiler.BuildAttackPathFinding(domain, chains); f != nil {
			fmt.Fprintf(os.Stderr, "beacon: %d attack path(s) identified\n", len(chains))
			_ = st.SaveFindings(ctx, run.ID, []finding.Finding{*f})
		}
	}

	// Webhook delivery: POST a structured JSON findings payload to the configured
	// endpoint so findings can be streamed to a SIEM or external platform.
	if cfg.WebhookURL != "" {
		if err := deliverWebhook(ctx, cfg.WebhookURL, cfg.WebhookAPIKey, *run, enriched, summary); err != nil {
			fmt.Fprintf(os.Stderr, "beacon: webhook delivery failed: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "beacon: findings posted to webhook\n")
		}
	}

	// Post-scan review summary: show pending fingerprint rules and playbook suggestions.
	{
		pendingRules, _ := st.GetFingerprintRules(ctx, "pending")
		pendingSuggs, _ := st.ListPlaybookSuggestions(ctx, "pending")
		if len(pendingRules) > 0 || len(pendingSuggs) > 0 {
			fmt.Fprintf(os.Stderr, "\nbeacon: review pending —")
			if len(pendingRules) > 0 {
				fmt.Fprintf(os.Stderr, " %d fingerprint rule%s", len(pendingRules), pluralS(len(pendingRules)))
			}
			if len(pendingSuggs) > 0 {
				if len(pendingRules) > 0 {
					fmt.Fprintf(os.Stderr, " ·")
				}
				fmt.Fprintf(os.Stderr, " %d playbook suggestion%s", len(pendingSuggs), pluralS(len(pendingSuggs)))
			}
			fmt.Fprintf(os.Stderr, "\n  run: beacon fingerprints pending  |  beacon playbook suggestions\n")
		}
	}
	fmt.Fprintf(os.Stderr, "beacon: done — scan ID: %s\n", run.ID)
}

// ---------- remote scan ----------

func cmdScanRemote(serverURL, apiKey, domain string, deep, permissionConfirmed bool, outPath string) {
	client := api.NewClient(serverURL, apiKey)

	fmt.Fprintf(os.Stderr, "beacon: submitting scan for %s to %s...\n", domain, serverURL)

	result, err := client.SubmitScan(domain, deep, permissionConfirmed)
	if err != nil {
		fatalf("submit scan: %v", err)
	}

	fmt.Fprintf(os.Stderr, "beacon: scan started — ID: %s\n", result.ScanRunID)
	fmt.Fprintf(os.Stderr, "beacon: streaming progress...\n")

	if err := client.StreamScan(result.ScanRunID, func(line string) {
		fmt.Fprintf(os.Stderr, "  %s\n", line)
	}); err != nil {
		fatalf("stream scan: %v", err)
	}

	fmt.Fprintf(os.Stderr, "beacon: scan complete — fetching report...\n")

	html, err := client.GetReport(result.ScanRunID)
	if err != nil {
		fatalf("get report: %v", err)
	}

	if outPath != "" {
		if err := os.WriteFile(outPath, []byte(html), 0o644); err != nil {
			fatalf("write report file: %v", err)
		}
		fmt.Fprintf(os.Stderr, "beacon: report written to %s\n", outPath)
	} else {
		fmt.Print(html)
	}
}

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
	fmt.Fprintf(os.Stderr, "beacon: scanning GitHub org/repo %s for Actions vulnerabilities...\n", orgOrRepo)

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
		fmt.Fprintf(os.Stderr, "beacon: no findings at or above severity %q\n", severityFlag)
		return
	}

	// Render findings as plain text summary.
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("GitHub Actions scan: %s\n%s\n\n", orgOrRepo, strings.Repeat("─", 60)))
	for _, f := range filtered {
		sb.WriteString(fmt.Sprintf("[%s] %s\n  %s\n  Asset: %s\n\n", f.Severity, f.Title, f.Description, f.Asset))
	}
	out := sb.String()

	if outPath != "" {
		if err := os.WriteFile(outPath, []byte(out), 0o644); err != nil {
			fatalf("write report: %v", err)
		}
		fmt.Fprintf(os.Stderr, "beacon: report written to %s\n", outPath)
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
	defer st.Close()

	runs, err := st.ListScanRuns(ctx, domain)
	if err != nil {
		fatalf("list scans: %v", err)
	}

	if len(runs) == 0 {
		fmt.Fprintf(os.Stderr, "no scans found for %s\n", domain)
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tDOMAIN\tTYPE\tSTATUS\tFINDINGS\tSTARTED")
	for _, r := range runs {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\n",
			r.ID, r.Domain, r.ScanType, r.Status, r.FindingCount,
			r.StartedAt.Format("2006-01-02 15:04"))
	}
	w.Flush()
}

// ---------- live job registry ----------

// liveJob represents a scan that is currently running inside this process.
// Created by launchScanJob; unregistered when the scan goroutine exits.
type liveJob struct {
	runID    string
	domain   string
	scanType string

	cancel   context.CancelFunc
	renderer *progressRenderer

	done chan struct{} // closed when the scan goroutine exits

	pauseMu sync.Mutex
	paused  bool
	pauseCh chan struct{} // non-nil when paused; close to resume

}

func (j *liveJob) Stop() { j.cancel() }

func (j *liveJob) Pause() {
	j.pauseMu.Lock()
	defer j.pauseMu.Unlock()
	if !j.paused {
		j.paused = true
		j.pauseCh = make(chan struct{})
	}
}

func (j *liveJob) Resume() {
	j.pauseMu.Lock()
	defer j.pauseMu.Unlock()
	if j.paused {
		j.paused = false
		ch := j.pauseCh
		j.pauseCh = nil
		close(ch)
	}
}

func (j *liveJob) PauseCheck(ctx context.Context) {
	j.pauseMu.Lock()
	ch := j.pauseCh
	j.pauseMu.Unlock()
	if ch == nil {
		return
	}
	select {
	case <-ch:
	case <-ctx.Done():
	}
}

var (
	liveJobsMu sync.RWMutex
	liveJobs   = make(map[string]*liveJob)
)

func registerJob(j *liveJob) {
	liveJobsMu.Lock()
	liveJobs[j.runID] = j
	liveJobsMu.Unlock()
}

func unregisterJob(runID string) {
	liveJobsMu.Lock()
	delete(liveJobs, runID)
	liveJobsMu.Unlock()
}

func getLiveJob(runID string) (*liveJob, bool) {
	liveJobsMu.RLock()
	j, ok := liveJobs[runID]
	liveJobsMu.RUnlock()
	return j, ok
}

// ---------- browse ----------

// browseMode tracks which screen the browser is showing.
type browseMode int

const (
	browseModeScans       browseMode = iota // list of past scan runs
	browseModeFinds                         // findings for a selected scan
	browseModeDetail                        // detail for a selected finding
	browseModeAssets                        // asset roster for a selected scan
	browseModeAssetDetail                   // per-asset info + findings
)

// browseState holds all TUI state for the scan history browser.
type browseState struct {
	mode browseMode

	// Scan list
	scans      []store.ScanRun
	scanCursor int
	scanOff    int

	// Loaded data for the selected scan (shared by finds + assets views)
	selectedRun *store.ScanRun
	findings    []enrichment.EnrichedFinding
	executions  []store.AssetExecution

	// Findings pager
	findCursor int
	findOff    int
	findMinSev finding.Severity // minimum severity filter (0 = show all)

	// Finding detail
	selectedFinding *enrichment.EnrichedFinding
	detailOff       int

	// Asset roster
	execCursor int
	execOff    int

	// Asset detail (per-asset findings pager)
	selectedExec    *store.AssetExecution
	execFindCursor  int
	execFindOff     int

	// Set when user presses 'r' to export a report after the TUI exits.
	exportRunID string

	// Animation frame for spinner (incremented by the ticker goroutine).
	spinFrame int

	// Delete / purge confirmation state.
	confirmingDelete bool   // waiting for y/n to delete selected scan
	confirmingPurge  bool   // waiting for y/n to purge all orphaned/failed/stopped scans
	deleteBlockedMsg string // non-empty: shown instead of confirming (e.g. "stop first")

	// Live scan attachment.
	attachedJob *liveJob // non-nil when user is viewing a running job's live UI

	// copyFlash is set to a short status message when 'y' is pressed.
	// Shown in the detail header for one render cycle, then cleared.
	copyFlash string

	// Asset detail scroll state.
	assetDetailOff      int  // scroll offset for the full evidence/findings lines view
	assetDetailFindLine int  // absolute line index where findings begin (set by render, used by Enter)
	assetDetailFromDetail bool // entered browseModeAssetDetail via [a] from browseModeDetail
}

var browseSpinChars = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// browseResult is what browseInteractive communicates back to cmdBrowse.
type browseResult struct {
	exportID      string // non-empty → export report for this scan run ID
	exportFormat  string // text, markdown, html, json (default: text)
	exportPath    string // non-empty → write to this file instead of stdout
	newScanDomain string // non-empty → launch a new scan for this domain
	newScanDeep   bool   // true → launch with --deep
}

// cmdBrowse opens the interactive scan history browser.
// Loops so the user can launch new scans and return to browse without restarting.
func cmdBrowse(cfg *config.Config) {
	for {
		res := browseInteractive(cfg)
		if res.exportID != "" {
			format := res.exportFormat
			if format == "" {
				format = "text"
			}
			args := []string{"--id", res.exportID, "--format", format}
			if res.exportPath != "" {
				args = append(args, "--out", res.exportPath)
			}
			cmdReport(cfg, args)
		}
		if res.newScanDomain == "" {
			break
		}
		// Launch a new scan then loop back to browse.
		args := []string{"--domain", res.newScanDomain}
		if res.newScanDeep {
			args = append(args, "--deep")
		}
		cmdScan(cfg, args)
	}
}

// launchScanJob starts a scan as a background liveJob. The job is registered
// in the global registry and unregistered automatically when it finishes.
// st must stay open for the lifetime of the job.
func launchScanJob(cfg *config.Config, st store.Store, domain string, scanType module.ScanType, permissionConfirmed bool, authorized bool) *liveJob {
	ctx, cancel := context.WithCancel(context.Background())

	bgCtx := context.Background()
	target, err := st.UpsertTarget(bgCtx, domain)
	if err != nil {
		cancel()
		return nil
	}
	run := &store.ScanRun{
		ID:        uuid.NewString(),
		TargetID:  target.ID,
		Domain:    domain,
		ScanType:  scanType,
		Status:    store.StatusRunning,
		StartedAt: time.Now(),
	}
	if err := st.CreateScanRun(bgCtx, run); err != nil {
		cancel()
		return nil
	}

	renderer := newHeadlessRenderer(finding.SeverityInfo)
	renderer.st = st

	job := &liveJob{
		runID:    run.ID,
		domain:   domain,
		scanType: string(scanType),
		cancel:   cancel,
		renderer: renderer,
		done:     make(chan struct{}),
	}
	renderer.cancelFn = job.Stop

	mod, err := surface.New(surface.Config{
		NucleiBin:            cfg.NucleiBin,
		SubfinderBin:         "subfinder",
		AmmassBin:            cfg.AmmassBin,
		TestsslBin:           cfg.TestsslBin,
		GauBin:               cfg.GauBin,
		KatanaBin:            cfg.KatanaBin,
		GowitnessBin:         cfg.GowitnessBin,
		AnthropicAPIKey:      cfg.AnthropicAPIKey,
		ShodanAPIKey:         cfg.ShodanAPIKey,
		HIBPAPIKey:           cfg.HIBPAPIKey,
		BingAPIKey:           cfg.BingAPIKey,
		OTXAPIKey:            cfg.OTXAPIKey,
		VirusTotalAPIKey:     cfg.VirusTotalAPIKey,
		SecurityTrailsAPIKey: cfg.SecurityTrailsAPIKey,
		CensysAPIID:          cfg.CensysAPIID,
		CensysAPISecret:      cfg.CensysAPISecret,
		GreyNoiseAPIKey:      cfg.GreyNoiseAPIKey,
		NmapBin:              cfg.NmapBin,
		Store:                st,
		HttpxBin:             cfg.HttpxBin,
		DnsxBin:              cfg.DnsxBin,
		FfufBin:              cfg.FfufBin,
		AdaptiveRecon:        cfg.AdaptiveRecon,
		ProxyPool:            cfg.ProxyPool,
		RequestJitterMs:      cfg.RequestJitterMs,
		ClaudeModel:          cfg.ClaudeModel,
		Auth:                 cfg.Auth,
		GitHubToken:          cfg.GitHubToken,
	})
	if err != nil {
		cancel()
		return nil
	}

	input := module.Input{
		Domain:              domain,
		PermissionConfirmed: permissionConfirmed,
		ScanRunID:           run.ID,
		Progress:            renderer.Handle,
		PauseCheck:          job.PauseCheck,
	}

	registerJob(job)

	go func() {
		defer close(job.done)
		defer unregisterJob(job.runID)
		defer renderer.Done()

		findings, err := mod.Run(ctx, input, scanType)

		now := time.Now()
		run.CompletedAt = &now
		run.FindingCount = len(findings)

		if err != nil {
			if err == context.Canceled || strings.Contains(err.Error(), "context canceled") {
				run.Status = store.StatusStopped
				run.Error = "stopped by user"
			} else {
				run.Status = store.StatusFailed
				run.Error = err.Error()
			}
		} else {
			run.Status = store.StatusCompleted
		}
		_ = st.UpdateScanRun(bgCtx, run)
		if len(findings) > 0 {
			_ = st.SaveFindings(bgCtx, run.ID, findings)
		}
	}()

	return job
}

// browseInteractive runs the raw-terminal TUI and returns a scan run ID if the
// user pressed 'r' to export a report, or "" to simply exit.
func browseInteractive(cfg *config.Config) browseResult {
	ctx := context.Background()
	st, err := sqlitestore.Open(cfg.Store.Path)
	if err != nil {
		fatalf("open store: %v", err)
	}
	defer st.Close()

	scans, err := st.ListRecentScanRuns(ctx, 200)
	if err != nil {
		fatalf("list scans: %v", err)
	}

	// Set terminal to raw mode.
	fd := int(os.Stdin.Fd())
	old, err := term.MakeRaw(fd)
	if err != nil {
		fatalf("set raw mode: %v", err)
	}
	defer term.Restore(fd, old)

	// Hide cursor, enter alternate screen.
	fmt.Fprint(os.Stderr, "\x1b[?1049h\x1b[?25l")
	defer fmt.Fprint(os.Stderr, "\x1b[?25h\x1b[?1049l")

	bs := &browseState{scans: scans}
	browseRender(bs)

	// Read stdin in a goroutine so the main loop can also respond to ticks.
	inputCh := make(chan []byte, 4)
	go func() {
		ibuf := make([]byte, 16)
		for {
			n, err := os.Stdin.Read(ibuf)
			if err != nil || n == 0 {
				close(inputCh)
				return
			}
			cp := make([]byte, n)
			copy(cp, ibuf[:n])
			inputCh <- cp
		}
	}()

	// Ticker drives spinner animation and periodic DB refresh for running scans.
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	tickCount := 0 // DB refresh every 4 ticks (2 s)

	for {
		var b []byte
		select {
		case raw, ok := <-inputCh:
			if !ok {
				return browseResult{}
			}
			b = raw
		case <-ticker.C:
			bs.spinFrame = (bs.spinFrame + 1) % len(browseSpinChars)
			tickCount++

			if bs.attachedJob != nil {
				job := bs.attachedJob
				// Detect detach: renderer closed its detached channel, or scan finished.
				detachNow := false
				select {
				case <-job.renderer.detached:
					detachNow = true
				default:
				}
				if !detachNow {
					select {
					case <-job.done:
						detachNow = true
					default:
					}
				}
				if detachNow {
					bs.attachedJob = nil
					fmt.Fprint(os.Stderr, "\x1b[?1049h\x1b[?25l")
					if updated, err := st.ListRecentScanRuns(ctx, 200); err == nil {
						bs.scans = updated
					}
					browseRender(bs)
				} else {
					job.renderer.mu.Lock()
					job.renderer.render()
					job.renderer.mu.Unlock()
				}
				continue
			}

			if tickCount%4 == 0 {
				// Reload statuses for any scan that is still "running" or "pending".
				for i, r := range bs.scans {
					if r.Status == store.StatusRunning || r.Status == store.StatusPending {
						if updated, err := st.GetScanRun(ctx, r.ID); err == nil {
							bs.scans[i] = *updated
						}
					}
				}
			}
			browseRender(bs)
			continue
		}

		// If attached to a live scan, route all keys to its renderer.
		if bs.attachedJob != nil {
			job := bs.attachedJob
			job.renderer.mu.Lock()
			job.renderer.processKey(b, len(b))
			// Check if renderer signalled detach ('b' key).
			detachNow := false
			select {
			case <-job.renderer.detached:
				detachNow = true
			default:
			}
			job.renderer.mu.Unlock()
			if detachNow {
				bs.attachedJob = nil
				fmt.Fprint(os.Stderr, "\x1b[?1049h\x1b[?25l")
				if updated, err := st.ListRecentScanRuns(ctx, 200); err == nil {
					bs.scans = updated
				}
				browseRender(bs)
			}
			continue
		}

		n := len(b)
		isQ     := b[0] == 'q'
		isEsc   := b[0] == 27 && n == 1
		isUp    := (b[0] == 'k') || (n >= 3 && b[0] == 27 && b[1] == '[' && b[2] == 'A')
		isDown  := (b[0] == 'j') || (n >= 3 && b[0] == 27 && b[1] == '[' && b[2] == 'B')
		isEnter := b[0] == '\r' || b[0] == '\n'

		switch bs.mode {
		case browseModeScans:
			// Dismiss the "stop first" error on any keypress, but let the key
			// fall through so 's' can stop the scan in the same press.
			if bs.deleteBlockedMsg != "" {
				bs.deleteBlockedMsg = ""
			}
			// Handle confirmation prompts first.
			if bs.confirmingDelete {
				if b[0] == 'y' || b[0] == 'Y' {
					if len(bs.scans) > 0 {
						id := bs.scans[bs.scanCursor].ID
						_ = st.DeleteScanRun(ctx, id)
						// Reload scan list.
						bs.scans, _ = st.ListRecentScanRuns(ctx, 200)
						if bs.scanCursor >= len(bs.scans) && bs.scanCursor > 0 {
							bs.scanCursor = len(bs.scans) - 1
						}
					}
				}
				bs.confirmingDelete = false
				browseRender(bs)
				continue
			}
			if bs.confirmingPurge {
				if b[0] == 'y' || b[0] == 'Y' {
					_, _ = st.PurgeOrphanedRuns(ctx, time.Now())
					bs.scans, _ = st.ListRecentScanRuns(ctx, 200)
					if bs.scanCursor >= len(bs.scans) && bs.scanCursor > 0 {
						bs.scanCursor = len(bs.scans) - 1
					}
				}
				bs.confirmingPurge = false
				browseRender(bs)
				continue
			}

			if isQ || isEsc {
				return browseResult{}
			}
			if isDown && bs.scanCursor < len(bs.scans)-1 {
				bs.scanCursor++
			}
			if isUp && bs.scanCursor > 0 {
				bs.scanCursor--
			}
			if (isEnter || b[0] == 'f') && len(bs.scans) > 0 {
				sel := bs.scans[bs.scanCursor]
				if job, ok := getLiveJob(sel.ID); ok {
					// 'f' jumps straight to findings list; Enter shows progress overview.
					if b[0] == 'f' {
						job.renderer.mu.Lock()
						job.renderer.mode = "findings"
						job.renderer.mu.Unlock()
					}
					attachJob(bs, job)
				} else {
					job := historicalJob(ctx, st, sel, "findings")
					attachJob(bs, job)
				}
				// Render immediately instead of waiting for the 500ms ticker.
				if bs.attachedJob != nil {
					bs.attachedJob.renderer.mu.Lock()
					bs.attachedJob.renderer.render()
					bs.attachedJob.renderer.mu.Unlock()
				}
				continue
			}
			if b[0] == 'a' && len(bs.scans) > 0 {
				sel := bs.scans[bs.scanCursor]
				if job, ok := getLiveJob(sel.ID); ok {
					job.renderer.mu.Lock()
					job.renderer.mode = "assets"
					job.renderer.mu.Unlock()
					attachJob(bs, job)
				} else {
					job := historicalJob(ctx, st, sel, "assets")
					attachJob(bs, job)
				}
				// Render immediately instead of waiting for the 500ms ticker.
				if bs.attachedJob != nil {
					bs.attachedJob.renderer.mu.Lock()
					bs.attachedJob.renderer.render()
					bs.attachedJob.renderer.mu.Unlock()
				}
				continue
			}
			// 'e'/'r' on a scan → prompt for export format, write to file.
			if (b[0] == 'e' || b[0] == 'r') && len(bs.scans) > 0 {
				sel := bs.scans[bs.scanCursor]
				res := browseExportPrompt(fd, old, sel.ID, sel.Domain)
				if res.exportID != "" {
					return res
				}
				old2, _ := term.MakeRaw(fd)
				old = old2
				fmt.Fprint(os.Stderr, "\x1b[?1049h\x1b[?25l")
				browseRender(bs)
				continue
			}
			// 's' → stop the selected live job, or mark an orphaned running scan as stopped.
			if b[0] == 's' && len(bs.scans) > 0 {
				sel := bs.scans[bs.scanCursor]
				if job, ok := getLiveJob(sel.ID); ok {
					job.Stop()
				} else if sel.Status == store.StatusRunning || sel.Status == store.StatusPending {
					// No live goroutine owns this scan — mark it stopped in the DB.
					sel.Status = store.StatusStopped
					sel.Error = "stopped by user"
					_ = st.UpdateScanRun(ctx, &sel)
					bs.scans[bs.scanCursor] = sel
				}
				// Reload scan list immediately so the updated status is visible.
				if updated, err := st.ListRecentScanRuns(ctx, 200); err == nil {
					bs.scans = updated
				}
				browseRender(bs)
			}
			// 'p' → pause or resume the selected live job.
			if b[0] == 'p' && len(bs.scans) > 0 {
				if job, ok := getLiveJob(bs.scans[bs.scanCursor].ID); ok {
					job.pauseMu.Lock()
					wasPaused := job.paused
					job.pauseMu.Unlock()
					if wasPaused {
						job.Resume()
					} else {
						job.Pause()
					}
				}
			}
			// 'd' → confirm then delete selected scan (blocked if it's a live job).
			if b[0] == 'd' && len(bs.scans) > 0 {
				if _, ok := getLiveJob(bs.scans[bs.scanCursor].ID); ok {
					bs.deleteBlockedMsg = "stop the scan first  [s] stop"
				} else {
					bs.confirmingDelete = true
					bs.deleteBlockedMsg = ""
				}
			}
			// 'X' (shift+x) → confirm then purge all orphaned/failed/stopped scans.
			if b[0] == 'X' {
				bs.confirmingPurge = true
			}
			// 'n' → scan type menu, then launch as a background job.
			if b[0] == 'n' {
				term.Restore(fd, old)
				fmt.Fprint(os.Stderr, "\x1b[?25h\x1b[?1049l\x1b[2J\x1b[H")
				fmt.Fprint(os.Stderr, "New scan\n\n")
				fmt.Fprint(os.Stderr, "  1) Surface scan       (passive recon, safe to run without permission)\n")
				fmt.Fprint(os.Stderr, "  2) Deep scan          (active probes — requires explicit permission)\n")
				fmt.Fprint(os.Stderr, "\nScan type [1, blank to cancel]: ")
				reader := bufio.NewReader(os.Stdin)
				typeLine, _ := reader.ReadString('\n')
				typeChoice := strings.TrimSpace(typeLine)

				// Blank input at any step cancels back to the TUI.
				if typeChoice == "" {
					old2, _ := term.MakeRaw(fd)
					old = old2
					fmt.Fprint(os.Stderr, "\x1b[?1049h\x1b[?25l")
					browseRender(bs)
					continue
				}

				scanType := module.ScanSurface
				permConfirmed := false
				authConfirmed := false
				switch typeChoice {
				case "2":
					scanType = module.ScanDeep
					fmt.Fprint(os.Stderr, "\nConfirm you have permission to actively probe the target [y/N]: ")
					permLine, _ := reader.ReadString('\n')
					if strings.ToLower(strings.TrimSpace(permLine)) != "y" {
						fmt.Fprint(os.Stderr, "Deep scan cancelled — permission not confirmed.\n")
						fmt.Fprint(os.Stderr, "Press Enter to return...")
						reader.ReadString('\n') //nolint:errcheck
						old2, _ := term.MakeRaw(fd)
						old = old2
						fmt.Fprint(os.Stderr, "\x1b[?1049h\x1b[?25l")
						browseRender(bs)
						continue
					}
					permConfirmed = true
				}

				fmt.Fprint(os.Stderr, "\nTarget domain (or blank to cancel): ")
				domainLine, _ := reader.ReadString('\n')
				domain := strings.TrimSpace(domainLine)

				old2, _ := term.MakeRaw(fd)
				old = old2
				fmt.Fprint(os.Stderr, "\x1b[?1049h\x1b[?25l")

				if domain == "" {
					browseRender(bs)
					continue
				}

				job := launchScanJob(cfg, st, domain, scanType, permConfirmed, authConfirmed)
				if job != nil {
					attachJob(bs, job)
				}
				if updated, err := st.ListRecentScanRuns(ctx, 200); err == nil {
					bs.scans = updated
				}
				browseRender(bs)
				continue
			}

		case browseModeFinds:
			if isQ {
				return browseResult{}
			}
			if isEsc {
				bs.mode = browseModeScans
				bs.findings = nil
				bs.executions = nil
				bs.selectedRun = nil
			}
			if b[0] == 'e' && bs.selectedRun != nil {
				res := browseExportPrompt(fd, old, bs.selectedRun.ID, bs.selectedRun.Domain)
				if res.exportID != "" {
					return res
				}
				old2, _ := term.MakeRaw(fd)
				old = old2
				fmt.Fprint(os.Stderr, "\x1b[?1049h\x1b[?25l")
				browseRender(bs)
				continue
			}
			if b[0] == 'a' {
				bs.mode = browseModeAssets
			}
			// Keys 1-5 set a minimum severity filter.
			if b[0] >= '1' && b[0] <= '5' {
				switch b[0] {
				case '1':
					bs.findMinSev = finding.SeverityInfo
				case '2':
					bs.findMinSev = finding.SeverityMedium
				case '3':
					bs.findMinSev = finding.SeverityHigh
				case '4':
					bs.findMinSev = finding.SeverityCritical
				case '5':
					bs.findMinSev = finding.SeverityInfo
				}
				bs.findCursor = 0
				bs.findOff = 0
			}
			if isDown && bs.findCursor < len(bs.findings)-1 {
				bs.findCursor++
			}
			if isUp && bs.findCursor > 0 {
				bs.findCursor--
			}
			if isEnter && len(bs.findings) > 0 {
				f := bs.findings[bs.findCursor]
				bs.selectedFinding = &f
				bs.detailOff = 0
				bs.mode = browseModeDetail
			}

		case browseModeDetail:
			if isQ {
				return browseResult{}
			}
			if isEsc || b[0] == 'b' {
				bs.mode = browseModeFinds
				bs.selectedFinding = nil
			}
			if isDown {
				bs.detailOff++
			}
			if isUp && bs.detailOff > 0 {
				bs.detailOff--
			}
			if b[0] == 'y' && bs.selectedFinding != nil {
				bf := &bs.selectedFinding.Finding
				ptext := bf.ProofCommand
				if ptext == "" {
					ptext = report.VerifyCmd(bf.CheckID, bf.Asset)
				}
				if ptext == "" {
					ptext = extractFindingURL(bf)
				}
				if ptext != "" {
					if copyToClipboard(ptext) {
						bs.copyFlash = "\x1b[1;32m✓ Copied!\x1b[0m"
					} else {
						bs.copyFlash = "\x1b[1;31m✗ Clipboard unavailable — copy manually\x1b[0m"
					}
				} else {
					bs.copyFlash = "\x1b[90mNo proof command to copy\x1b[0m"
				}
			}
			if b[0] == 'a' && bs.selectedFinding != nil {
				asset := bs.selectedFinding.Finding.Asset
				for i, ex := range bs.executions {
					if ex.Asset == asset {
						bs.selectedExec = &bs.executions[i]
						bs.assetDetailOff = 0
						bs.assetDetailFindLine = 0
						bs.execFindCursor = 0
						bs.execFindOff = 0
						bs.assetDetailFromDetail = true
						bs.mode = browseModeAssetDetail
						break
					}
				}
			}

		case browseModeAssets:
			if isQ {
				return browseResult{}
			}
			if isEsc || b[0] == 'b' {
				bs.mode = browseModeScans
				bs.findings = nil
				bs.executions = nil
				bs.selectedRun = nil
			}
			if b[0] == 'f' {
				bs.mode = browseModeFinds
			}
			if isDown && bs.execCursor < len(bs.executions)-1 {
				bs.execCursor++
			}
			if isUp && bs.execCursor > 0 {
				bs.execCursor--
			}
			if isEnter && len(bs.executions) > 0 {
				ex := bs.executions[bs.execCursor]
				bs.selectedExec = &ex
				bs.execFindCursor = 0
				bs.execFindOff = 0
				bs.mode = browseModeAssetDetail
			}

		case browseModeAssetDetail:
			if isQ {
				return browseResult{}
			}
			if isEsc || b[0] == 'b' {
				if bs.assetDetailFromDetail {
					bs.assetDetailFromDetail = false
					bs.mode = browseModeDetail
				} else {
					bs.mode = browseModeAssets
					bs.selectedExec = nil
				}
			}
			if isDown {
				bs.assetDetailOff++
				// Keep finding cursor in sync with scroll position in findings section.
				if bs.assetDetailFindLine > 0 {
					rel := bs.assetDetailOff - bs.assetDetailFindLine
					if rel > 0 {
						bs.execFindCursor = rel
					}
				}
			}
			if isUp && bs.assetDetailOff > 0 {
				bs.assetDetailOff--
				if bs.assetDetailFindLine > 0 {
					rel := bs.assetDetailOff - bs.assetDetailFindLine
					if rel > 0 {
						bs.execFindCursor = rel
					} else {
						bs.execFindCursor = 0
					}
				}
			}
			if isEnter && bs.selectedExec != nil {
				af := browseAssetFindings(bs)
				if bs.execFindCursor < len(af) {
					f := af[bs.execFindCursor]
					bs.selectedFinding = &f
					bs.detailOff = 0
					bs.assetDetailFromDetail = false
					bs.mode = browseModeDetail
				}
			}
		}

		browseRender(bs)
	}
}

func browseRender(bs *browseState) {
	_, termH, err := term.GetSize(int(os.Stderr.Fd()))
	if err != nil {
		termH = 24
	}
	termW, _, err := term.GetSize(int(os.Stderr.Fd()))
	if err != nil {
		termW = 80
	}

	var buf strings.Builder
	// Move to top-left, clear screen.
	buf.WriteString("\x1b[H\x1b[2J")

	switch bs.mode {
	case browseModeScans:
		browseRenderScans(&buf, bs, termW, termH)
	case browseModeFinds:
		browseRenderFinds(&buf, bs, termW, termH)
	case browseModeDetail:
		browseRenderDetail(&buf, bs, termW, termH)
	case browseModeAssets:
		browseRenderAssets(&buf, bs, termW, termH)
	case browseModeAssetDetail:
		browseRenderAssetDetail(&buf, bs, termW, termH)
	}

	fmt.Fprint(os.Stderr, buf.String())
}

// ── Browse helpers ────────────────────────────────────────────────────────────

// browseLoadScan loads findings and asset executions for a scan run into bs.
func browseLoadScan(ctx context.Context, st interface {
	GetEnrichedFindings(context.Context, string) ([]enrichment.EnrichedFinding, error)
	GetFindings(context.Context, string) ([]finding.Finding, error)
	ListAssetExecutions(context.Context, string) ([]store.AssetExecution, error)
}, bs *browseState, run store.ScanRun) {
	run2 := run
	bs.selectedRun = &run2

	ef, err := st.GetEnrichedFindings(ctx, run.ID)
	if err != nil || len(ef) == 0 {
		raw, _ := st.GetFindings(ctx, run.ID)
		ef = make([]enrichment.EnrichedFinding, len(raw))
		for i, f := range raw {
			ef[i] = enrichment.EnrichedFinding{Finding: f}
		}
	}
	sort.Slice(ef, func(i, j int) bool {
		return ef[i].Finding.Severity > ef[j].Finding.Severity
	})
	bs.findings = ef
	bs.findCursor = 0
	bs.findOff = 0
	bs.findMinSev = finding.SeverityInfo

	exec, _ := st.ListAssetExecutions(ctx, run.ID)
	// Sort assets by finding count descending, then name.
	sort.Slice(exec, func(i, j int) bool {
		if exec[i].FindingsCount != exec[j].FindingsCount {
			return exec[i].FindingsCount > exec[j].FindingsCount
		}
		return exec[i].Asset < exec[j].Asset
	})
	bs.executions = exec
	bs.execCursor = 0
	bs.execOff = 0
}

// browseAssetFindings returns the findings for bs.selectedExec, sorted by severity.
func browseAssetFindings(bs *browseState) []enrichment.EnrichedFinding {
	if bs.selectedExec == nil {
		return nil
	}
	var out []enrichment.EnrichedFinding
	for _, ef := range bs.findings {
		if ef.Finding.Asset == bs.selectedExec.Asset {
			out = append(out, ef)
		}
	}
	return out
}

// browseFindingCounts returns crit/high/med/low/info counts for a single asset.
func browseFindingCounts(bs *browseState, asset string) (crit, high, med, low, info int) {
	for _, ef := range bs.findings {
		f := ef.Finding
		if f.Asset != asset {
			continue
		}
		switch f.Severity {
		case finding.SeverityCritical:
			crit++
		case finding.SeverityHigh:
			high++
		case finding.SeverityMedium:
			med++
		case finding.SeverityLow:
			low++
		default:
			info++
		}
	}
	return
}

// ── Browse render functions ───────────────────────────────────────────────────

// attachJob sets bs.attachedJob and resets the renderer so it can be
// re-attached after a previous detach (the detached channel is re-created).
func attachJob(bs *browseState, job *liveJob) {
	job.renderer.mu.Lock()
	// If the renderer was previously detached, reset its signal channel so
	// re-attaching works correctly.
	select {
	case <-job.renderer.detached:
		// Channel was closed by a previous detach — create fresh channels so
		// the next 'b'/'q' keypress can close them without panicking.
		job.renderer.detached = make(chan struct{})
		job.renderer.stop = make(chan struct{})
		job.renderer.stopOnce = sync.Once{}
		// Reset to the top-level overview so the user doesn't land inside a
		// sub-view (e.g. assets) they left before detaching.
		job.renderer.mode = "progress"
		// Reset severity filter: a stale high-sev filter (e.g. "critical only")
		// would silently show 0 findings on re-attach, which is very confusing.
		job.renderer.minSeverity = finding.SeverityInfo
	default:
	}
	job.renderer.drawnLines = 0
	job.renderer.drawn = false
	job.renderer.mu.Unlock()
	bs.attachedJob = job
}

// loadHistoricalScan creates a headless renderer pre-populated with findings
// and assets from a completed (or stopped/failed) scan run. The renderer
// starts in findings view so the user sees findings immediately.
func loadHistoricalScan(ctx context.Context, st interface {
	GetFindings(context.Context, string) ([]finding.Finding, error)
	ListAssetExecutions(context.Context, string) ([]store.AssetExecution, error)
}, run store.ScanRun) *progressRenderer {
	r := newHeadlessRenderer(finding.SeverityInfo)
	r.phase = "done"
	r.mode = "findings"

	raw, _ := st.GetFindings(ctx, run.ID)
	sort.Slice(raw, func(i, j int) bool { return raw[i].Severity > raw[j].Severity })
	r.findings = raw
	r.findingCount = len(raw)

	execs, _ := st.ListAssetExecutions(ctx, run.ID)
	sort.Slice(execs, func(i, j int) bool {
		if execs[i].FindingsCount != execs[j].FindingsCount {
			return execs[i].FindingsCount > execs[j].FindingsCount
		}
		return execs[i].Asset < execs[j].Asset
	})
	for _, ex := range execs {
		r.assets = append(r.assets, liveAsset{
			Name:         ex.Asset,
			Status:       "done",
			FindingCount: ex.FindingsCount,
		})
		r.assetIdx[ex.Asset] = len(r.assets) - 1
		// Restore topology evidence so the topology view works for historical scans.
		r.topoEvidence[ex.Asset] = ex.Evidence
	}
	r.total = len(r.assets)
	r.done = len(r.assets)

	return r
}

// historicalJob wraps a DB scan run in a liveJob so it can be attached to the
// browse TUI. The done channel is intentionally never closed: the ticker's
// done-channel check is only meant to auto-detach when a live scan goroutine
// finishes. For historical scans (completed, stopped, failed, orphaned running)
// there is no goroutine, so we leave done open and let the user navigate back
// manually with 'b' or 'q'.
func historicalJob(ctx context.Context, st interface {
	GetFindings(context.Context, string) ([]finding.Finding, error)
	ListAssetExecutions(context.Context, string) ([]store.AssetExecution, error)
}, run store.ScanRun, initialMode string) *liveJob {
	r := loadHistoricalScan(ctx, st, run)
	r.mode = initialMode

	return &liveJob{
		runID:    run.ID,
		domain:   run.Domain,
		scanType: string(run.ScanType),
		cancel:   func() {},
		renderer: r,
		done:     make(chan struct{}), // never closed; user navigates back manually
	}
}

// browseExportPrompt pauses the TUI, asks the user for a report format and
// destination file, then returns a browseResult with the export details.
// Returns a zero-value browseResult if the user cancels.
// fd/old are the terminal fd and saved terminal state from the caller.
func browseExportPrompt(fd int, old *term.State, runID, domain string) browseResult {
	term.Restore(fd, old)
	fmt.Fprint(os.Stderr, "\x1b[?25h\x1b[?1049l")

	fmt.Fprint(os.Stderr, "\nExport report\n\n")
	fmt.Fprint(os.Stderr, "  1) Text      (plain text, terminal-friendly)\n")
	fmt.Fprint(os.Stderr, "  2) Markdown  (.md)\n")
	fmt.Fprint(os.Stderr, "  3) HTML      (.html)\n")
	fmt.Fprint(os.Stderr, "  4) JSON      (.json)\n")
	fmt.Fprint(os.Stderr, "\nFormat [1-4, blank to cancel]: ")

	reader := bufio.NewReader(os.Stdin)
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)
	if choice == "" {
		return browseResult{}
	}

	extMap := map[string]string{"1": "txt", "2": "md", "3": "html", "4": "json"}
	fmtMap := map[string]string{"1": "text", "2": "markdown", "3": "html", "4": "json"}
	ext, ok := extMap[choice]
	if !ok {
		fmt.Fprint(os.Stderr, "Invalid choice — cancelled.\n")
		return browseResult{}
	}
	format := fmtMap[choice]

	// Default output path.
	date := time.Now().Format("2006-01-02")
	defaultPath := fmt.Sprintf("%s-%s.%s", domain, date, ext)
	fmt.Fprintf(os.Stderr, "Output file [%s]: ", defaultPath)
	pathLine, _ := reader.ReadString('\n')
	outPath := strings.TrimSpace(pathLine)
	if outPath == "" {
		outPath = defaultPath
	}

	return browseResult{exportID: runID, exportFormat: format, exportPath: outPath}
}

func browseRenderScans(buf *strings.Builder, bs *browseState, termW, termH int) {
	bodyLines := termH - 3
	if bodyLines < 1 {
		bodyLines = 1
	}

	// Scroll window.
	if bs.scanCursor < bs.scanOff {
		bs.scanOff = bs.scanCursor
	}
	if bs.scanCursor >= bs.scanOff+bodyLines {
		bs.scanOff = bs.scanCursor - bodyLines + 1
	}

	if bs.deleteBlockedMsg != "" {
		fmt.Fprintf(buf, "\x1b[2K\r  \x1b[1;36mBeacon — Scan History\x1b[0m  \x1b[31m⚠ cannot delete a running scan — %s\x1b[0m\n", bs.deleteBlockedMsg)
	} else if bs.confirmingDelete {
		fmt.Fprintf(buf, "\x1b[2K\r  \x1b[1;36mBeacon — Scan History\x1b[0m  \x1b[31mDelete this scan? [y/N]\x1b[0m\n")
	} else if bs.confirmingPurge {
		fmt.Fprintf(buf, "\x1b[2K\r  \x1b[1;36mBeacon — Scan History\x1b[0m  \x1b[31mPurge all orphaned/failed/stopped scans? [y/N]\x1b[0m\n")
	} else {
		fmt.Fprintf(buf, "\x1b[2K\r  \x1b[1;36mBeacon — Scan History\x1b[0m  \x1b[90m[↵] attach/view  [a] assets  [e] export  [n] new  [s] stop  [p] pause  [d] delete  [X] purge  [q] quit  %d scans\x1b[0m\n", len(bs.scans))
	}
	// Domain column fills available width; minimum 20, cap at 50.
	// Layout: 2(indent) + domainW + 2 + 7(type) + 2 + 16(started) + 2 + status + trail
	domainW := termW - 65
	if domainW < 20 {
		domainW = 20
	}
	if domainW > 50 {
		domainW = 50
	}
	fmt.Fprintf(buf, "\x1b[2K\r  \x1b[90m%-*s  %-7s  %-14s  %s\x1b[0m\n", domainW, "DOMAIN", "TYPE", "STATUS", "STARTED")

	end := bs.scanOff + bodyLines
	if end > len(bs.scans) {
		end = len(bs.scans)
	}
	spin := browseSpinChars[bs.spinFrame%len(browseSpinChars)]
	for i := bs.scanOff; i < end; i++ {
		r := bs.scans[i]
		orphanThreshold := 2 * time.Hour
		isOrphaned := (r.Status == store.StatusRunning || r.Status == store.StatusPending) &&
			time.Since(r.StartedAt) > orphanThreshold
		var statusStr string
		switch {
		case isOrphaned:
			elapsed := time.Since(r.StartedAt).Round(time.Second)
			statusStr = fmt.Sprintf("\x1b[31m✗ orphaned %s\x1b[0m", elapsed)
		case r.Status == store.StatusRunning:
			elapsed := time.Since(r.StartedAt).Round(time.Second)
			if job, ok := getLiveJob(r.ID); ok {
				job.pauseMu.Lock()
				isPaused := job.paused
				job.pauseMu.Unlock()
				if isPaused {
					statusStr = fmt.Sprintf("\x1b[36m⏸ paused    %s\x1b[0m", elapsed)
				} else {
					statusStr = fmt.Sprintf("\x1b[33m%s ⚡ live   %s\x1b[0m", spin, elapsed)
				}
			} else {
				statusStr = fmt.Sprintf("\x1b[33m%s running %s\x1b[0m", spin, elapsed)
			}
		case r.Status == store.StatusPending:
			statusStr = fmt.Sprintf("\x1b[33m%s pending\x1b[0m", spin)
		case r.Status == store.StatusFailed:
			statusStr = "\x1b[31m✗ failed\x1b[0m"
		case r.Status == store.StatusStopped:
			if r.FindingCount > 0 {
				statusStr = fmt.Sprintf("\x1b[33m⏹ stopped  %d findings\x1b[0m", r.FindingCount)
			} else {
				statusStr = "\x1b[33m⏹ stopped\x1b[0m"
			}
		default: // completed
			statusStr = "\x1b[32m✓ done\x1b[0m"
		}
		// Build trailing info: finding count or duration for completed scans.
		var trailStr string
		if r.Status == store.StatusCompleted {
			if r.CompletedAt != nil {
				dur := r.CompletedAt.Sub(r.StartedAt).Round(time.Second)
				trailStr = fmt.Sprintf("\x1b[90m%d findings  %s\x1b[0m", r.FindingCount, dur)
			} else {
				trailStr = fmt.Sprintf("\x1b[90m%d findings\x1b[0m", r.FindingCount)
			}
		}
		line := fmt.Sprintf("  %-*s  %-7s  %-14s  %s  %s",
			domainW, truncate(r.Domain, domainW),
			r.ScanType,
			r.StartedAt.Format("2006-01-02 15:04"),
			statusStr,
			trailStr,
		)
		if i == bs.scanCursor {
			fmt.Fprintf(buf, "\x1b[7m\x1b[2K\r%s\x1b[0m\n", line)
		} else {
			fmt.Fprintf(buf, "\x1b[2K\r%s\n", line)
		}
	}
	fmt.Fprintf(buf, "\x1b[2K\r  \x1b[90m%d of %d\x1b[0m\n", bs.scanCursor+1, len(bs.scans))
}

func browseRenderFinds(buf *strings.Builder, bs *browseState, termW, termH int) {
	bodyLines := termH - 3
	if bodyLines < 1 {
		bodyLines = 1
	}

	// Apply severity filter.
	var filtered []enrichment.EnrichedFinding
	for _, ef := range bs.findings {
		if ef.Finding.Severity >= bs.findMinSev {
			filtered = append(filtered, ef)
		}
	}

	// Clamp cursor to filtered slice.
	if len(filtered) == 0 {
		bs.findCursor = 0
		bs.findOff = 0
	} else if bs.findCursor >= len(filtered) {
		bs.findCursor = len(filtered) - 1
	}

	// Scroll window.
	if bs.findCursor < bs.findOff {
		bs.findOff = bs.findCursor
	}
	if bs.findCursor >= bs.findOff+bodyLines {
		bs.findOff = bs.findCursor - bodyLines + 1
	}

	domain := ""
	started := ""
	if bs.selectedRun != nil {
		domain = bs.selectedRun.Domain
		started = bs.selectedRun.StartedAt.Format("2006-01-02 15:04")
	}

	// Build filter label for header.
	var filterLabel string
	switch bs.findMinSev {
	case finding.SeverityMedium:
		filterLabel = "  \x1b[33mMin: MED\x1b[0m"
	case finding.SeverityHigh:
		filterLabel = "  \x1b[31mMin: HIGH\x1b[0m"
	case finding.SeverityCritical:
		filterLabel = "  \x1b[1;31mMin: CRIT\x1b[0m"
	default:
		filterLabel = ""
	}

	fmt.Fprintf(buf, "\x1b[2K\r  \x1b[1;36m%s\x1b[0m  \x1b[90m%s  [↵] detail  [j/k] move  [1-5] filter  [e] export  [q/b] back  %d/%d\x1b[0m%s\n",
		domain, started, len(filtered), len(bs.findings), filterLabel)
	// Title column fills available terminal width; minimum 40.
	// Layout: 2(indent) + 10(sev) + 2(sep) + titleW + 2(sep) + ~32(checkid)
	titleW := termW - 48
	if titleW < 40 {
		titleW = 40
	}
	fmt.Fprintf(buf, "\x1b[2K\r  \x1b[90m%-8s  %-*s  %s\x1b[0m\n", "SEV", titleW, "TITLE", "CHECK ID")

	end := bs.findOff + bodyLines
	if end > len(filtered) {
		end = len(filtered)
	}
	for i := bs.findOff; i < end; i++ {
		ef := filtered[i]
		f := ef.Finding
		sev := severityTag(f.Severity)
		line := fmt.Sprintf("  %s  %-*s  \x1b[90m%s\x1b[0m",
			sev, titleW, truncate(f.Title, titleW), f.CheckID)
		if i == bs.findCursor {
			fmt.Fprintf(buf, "\x1b[7m\x1b[2K\r%s\x1b[0m\n", line)
		} else {
			fmt.Fprintf(buf, "\x1b[2K\r%s\n", line)
		}
	}
	count := len(filtered)
	if count == 0 {
		fmt.Fprintf(buf, "\x1b[2K\r  \x1b[90mNo findings match filter\x1b[0m\n")
	} else {
		fmt.Fprintf(buf, "\x1b[2K\r  \x1b[90m%d of %d\x1b[0m\n", bs.findCursor+1, count)
	}
}

func browseRenderDetail(buf *strings.Builder, bs *browseState, termW, termH int) {
	if bs.selectedFinding == nil {
		return
	}
	ef := bs.selectedFinding
	f := ef.Finding

	// Build content lines (same layout as the live finding_detail view).
	var lines []string
	lines = append(lines, fmt.Sprintf("\x1b[1m%s\x1b[0m", f.Title))
	lines = append(lines, fmt.Sprintf("%s  \x1b[90m%s\x1b[0m  \x1b[90m%s · %s\x1b[0m",
		severityTag(f.Severity), string(f.CheckID), f.Scanner, f.Asset))
	lines = append(lines, "")

	if f.Description != "" {
		for _, l := range wordWrapLines(f.Description, termW-4) {
			lines = append(lines, l)
		}
		lines = append(lines, "")
	}

	if ef.Explanation != "" {
		lines = append(lines, "\x1b[1;33mExplanation\x1b[0m")
		for _, l := range wordWrapLines(ef.Explanation, termW-4) {
			lines = append(lines, l)
		}
		lines = append(lines, "")
	}

	if ef.Impact != "" {
		lines = append(lines, "\x1b[1;31mImpact\x1b[0m")
		for _, l := range wordWrapLines(ef.Impact, termW-4) {
			lines = append(lines, l)
		}
		lines = append(lines, "")
	}

	if ef.Remediation != "" {
		lines = append(lines, "\x1b[1;32mRemediation\x1b[0m")
		for _, l := range wordWrapLines(ef.Remediation, termW-4) {
			lines = append(lines, l)
		}
		lines = append(lines, "")
	}

	if ef.TechSpecificRemediation != "" {
		lines = append(lines, "\x1b[1;32mTech-Specific Fix\x1b[0m")
		for _, l := range wordWrapLines(ef.TechSpecificRemediation, termW-4) {
			lines = append(lines, l)
		}
		lines = append(lines, "")
	}

	if ef.MitigatedBy != "" {
		lines = append(lines, "\x1b[90mNote: mitigated by "+ef.MitigatedBy+"\x1b[0m")
		lines = append(lines, "")
	}

	browseProofCmd := f.ProofCommand
	if browseProofCmd == "" {
		browseProofCmd = report.VerifyCmd(f.CheckID, f.Asset)
	}
	if browseProofCmd != "" {
		lines = append(lines, "\x1b[1;34mProof Command\x1b[0m  \x1b[90m([y] to copy)\x1b[0m")
		for _, cmdLine := range wordWrapAtShellBoundaries(browseProofCmd, termW-4) {
			lines = append(lines, "  \x1b[36m"+cmdLine+"\x1b[0m")
		}
		lines = append(lines, "")
	}

	if len(f.Evidence) > 0 {
		lines = append(lines, "\x1b[1mEvidence\x1b[0m")
		// Sort keys for stable output.
		keys := make([]string, 0, len(f.Evidence))
		for k := range f.Evidence {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			lines = append(lines, fmt.Sprintf("  \x1b[90m%-24s\x1b[0m  %s", k, formatEvidenceValue(k, f.Evidence[k])))
		}
		lines = append(lines, "")
	}

	// Clamp scroll offset.
	bodyLines := termH - 2
	if bodyLines < 1 {
		bodyLines = 1
	}
	maxOff := len(lines) - bodyLines
	if maxOff < 0 {
		maxOff = 0
	}
	if bs.detailOff > maxOff {
		bs.detailOff = maxOff
	}

	// Header — show copy flash feedback if present, otherwise normal hint bar.
	if bs.copyFlash != "" {
		fmt.Fprintf(buf, "\x1b[2K\r  %s  \x1b[90m[j/k] scroll  [b/q] back\x1b[0m\n", bs.copyFlash)
		bs.copyFlash = "" // clear after one render
	} else {
		fmt.Fprintf(buf, "\x1b[2K\r  \x1b[90m[j/k] scroll  [y] copy proof cmd  [a] asset  [b/q] back\x1b[0m\n")
	}

	end := bs.detailOff + bodyLines
	if end > len(lines) {
		end = len(lines)
	}
	for _, l := range lines[bs.detailOff:end] {
		fmt.Fprintf(buf, "\x1b[2K\r  %s\n", l)
	}
}

func browseRenderAssets(buf *strings.Builder, bs *browseState, termW, termH int) {
	bodyLines := termH - 3
	if bodyLines < 1 {
		bodyLines = 1
	}

	total := len(bs.executions)

	// Clamp cursor and scroll offset.
	if total == 0 {
		bs.execCursor = 0
	} else {
		if bs.execCursor >= total {
			bs.execCursor = total - 1
		}
		if bs.execCursor < 0 {
			bs.execCursor = 0
		}
	}
	if bs.execCursor < bs.execOff {
		bs.execOff = bs.execCursor
	}
	if bs.execCursor >= bs.execOff+bodyLines {
		bs.execOff = bs.execCursor - bodyLines + 1
	}

	domain := ""
	if bs.selectedRun != nil {
		domain = bs.selectedRun.Domain
	}
	fmt.Fprintf(buf, "\x1b[2K\r  \x1b[1;36m%s — Assets\x1b[0m  \x1b[90m[↵] detail  [f] findings  [j/k] move  [q/b] back  %d assets\x1b[0m\n",
		domain, total)
	// Asset name column fills available terminal width; minimum 42.
	// Layout: 2(cursor) + nameW + 2(sep) + 20(tech) + 2(sep) + ~20(badge)
	nameW := termW - 46
	if nameW < 42 {
		nameW = 42
	}
	fmt.Fprintf(buf, "\x1b[2K\r  \x1b[90m%-*s  %-20s  %s\x1b[0m\n", nameW, "Asset", "Tech/Cloud", "Findings")

	end := bs.execOff + bodyLines
	if end > total {
		end = total
	}
	for i := bs.execOff; i < end; i++ {
		ex := bs.executions[i]
		ev := ex.Evidence

		cursor := "  "
		if i == bs.execCursor {
			cursor = "\x1b[1;33m▶\x1b[0m "
		}

		name := ex.Asset
		if len(name) > nameW {
			name = "…" + name[len(name)-nameW+1:]
		}

		// Derive tech/cloud label.
		tech := ev.CloudProvider
		if ev.Framework != "" {
			if tech != "" {
				tech += "/" + ev.Framework
			} else {
				tech = ev.Framework
			}
		}
		if tech == "" {
			tech = ev.ProxyType
		}
		if tech == "" && ev.StatusCode > 0 {
			tech = "http"
		}
		if len(tech) > 20 {
			tech = tech[:19] + "…"
		}

		// Build severity badge string.
		crit, high, med, low, info := browseFindingCounts(bs, ex.Asset)
		var badgeParts []string
		if crit > 0 {
			badgeParts = append(badgeParts, fmt.Sprintf("\x1b[1;31m%dC\x1b[0m", crit))
		}
		if high > 0 {
			badgeParts = append(badgeParts, fmt.Sprintf("\x1b[31m%dH\x1b[0m", high))
		}
		if med > 0 {
			badgeParts = append(badgeParts, fmt.Sprintf("\x1b[33m%dM\x1b[0m", med))
		}
		if low > 0 {
			badgeParts = append(badgeParts, fmt.Sprintf("\x1b[90m%dL\x1b[0m", low))
		}
		if info > 0 {
			badgeParts = append(badgeParts, fmt.Sprintf("\x1b[90m%dI\x1b[0m", info))
		}
		badge := strings.Join(badgeParts, " ")
		if badge == "" && ex.FindingsCount == 0 {
			badge = "\x1b[32mclean\x1b[0m"
		}

		line := fmt.Sprintf(" %s%-*s  %-20s  %s", cursor, nameW, name, tech, badge)
		if i == bs.execCursor {
			fmt.Fprintf(buf, "\x1b[7m\x1b[2K\r%s\x1b[0m\n", line)
		} else {
			fmt.Fprintf(buf, "\x1b[2K\r%s\n", line)
		}
	}
	fmt.Fprintf(buf, "\x1b[2K\r  \x1b[90m%d of %d\x1b[0m\n", bs.execCursor+1, total)
}

func browseRenderAssetDetail(buf *strings.Builder, bs *browseState, termW, termH int) {
	if bs.selectedExec == nil {
		return
	}
	ex := bs.selectedExec
	ev := ex.Evidence

	// Build all content as scrollable lines (like browseRenderDetail).
	var lines []string
	kv := func(label string, value string) {
		lines = append(lines, fmt.Sprintf("  \x1b[90m%-26s\x1b[0m  %s", label, value))
	}

	// ── Discovery & Classification ────────────────────────────────────────
	lines = append(lines, "\x1b[1mDiscovery & Classification\x1b[0m")
	if ex.ExpandedFrom != "" {
		kv("expanded from", ex.ExpandedFrom)
	}
	src := ev.ClassificationSource
	if src == "" {
		src = "deterministic rules"
	}
	kv("classification", src)
	if ex.ClassifyDurationMs > 0 {
		kv("classify duration", fmt.Sprintf("%dms", ex.ClassifyDurationMs))
	}
	if len(ex.ScannersRun) > 0 {
		// Wrap long scanner lists.
		scanners := strings.Join(ex.ScannersRun, ", ")
		if len(scanners) > termW-32 {
			scanners = scanners[:termW-35] + "…"
		}
		kv("scanners run", scanners)
	}
	if len(ex.MatchedPlaybooks) > 0 {
		kv("matched playbooks", strings.Join(ex.MatchedPlaybooks, ", "))
	}
	lines = append(lines, "")

	// ── Network ───────────────────────────────────────────────────────────
	lines = append(lines, "\x1b[1mNetwork\x1b[0m")
	if ev.IP != "" {
		kv("ip", ev.IP)
	}
	if ev.ASNOrg != "" {
		asn := ev.ASNOrg
		if ev.ASNNum != "" {
			asn += " (" + ev.ASNNum + ")"
		}
		kv("asn", asn)
	}
	if len(ev.CNAMEChain) > 0 {
		kv("cname chain", strings.Join(ev.CNAMEChain, " → "))
	}
	if ev.StatusCode > 0 {
		kv("http status", fmt.Sprintf("%d", ev.StatusCode))
	}
	if ev.CloudProvider != "" {
		kv("cloud", ev.CloudProvider)
	}
	if ev.InfraLayer != "" {
		kv("infra layer", ev.InfraLayer)
	}
	if ev.ProxyType != "" {
		kv("proxy", ev.ProxyType)
	}
	if ev.Framework != "" {
		kv("framework", ev.Framework)
	}
	if ev.AuthSystem != "" {
		kv("auth system", ev.AuthSystem)
	}
	if ev.AuthScheme != "" {
		kv("auth scheme", ev.AuthScheme)
	}
	if ev.IsServerless {
		kv("serverless", "yes")
	}
	if ev.IsKubernetes {
		kv("kubernetes", "yes")
	}
	if ev.IsReverseProxy {
		kv("reverse proxy", "yes")
	}
	if ev.HTTP2Enabled {
		kv("http2", "yes")
	}
	if ev.MXProvider != "" {
		kv("mx provider", ev.MXProvider)
	}
	if len(ev.BackendServices) > 0 {
		kv("backend services", strings.Join(ev.BackendServices, ", "))
	}
	lines = append(lines, "")

	// ── TLS ───────────────────────────────────────────────────────────────
	if ev.CertIssuer != "" || len(ev.CertSANs) > 0 || ev.JARMFingerprint != "" {
		lines = append(lines, "\x1b[1mTLS\x1b[0m")
		if ev.CertIssuer != "" {
			kv("cert issuer", ev.CertIssuer)
		}
		if len(ev.CertSANs) > 0 {
			shown := ev.CertSANs
			if len(shown) > 6 {
				shown = shown[:6]
			}
			kv("cert SANs", strings.Join(shown, ", "))
			if len(ev.CertSANs) > 6 {
				kv("", fmt.Sprintf("(+%d more)", len(ev.CertSANs)-6))
			}
		}
		if ev.JARMFingerprint != "" {
			kv("jarm", ev.JARMFingerprint)
		}
		lines = append(lines, "")
	}

	// ── HTTP Headers & Fingerprints ───────────────────────────────────────
	interestingHeaders := []string{
		"server", "x-powered-by", "x-aspnet-version", "via",
		"x-cache", "x-amz-cf-id", "cf-ray", "x-vercel-id",
		"x-forwarded-server", "x-generator",
	}
	var headerLines []string
	for _, h := range interestingHeaders {
		if v, ok := ev.Headers[h]; ok && v != "" {
			headerLines = append(headerLines, fmt.Sprintf("  \x1b[90m%-26s\x1b[0m  %s", h, v))
		}
	}
	if len(headerLines) > 0 || len(ev.ServiceVersions) > 0 || ev.FaviconHash != "" || len(ev.CookieNames) > 0 {
		lines = append(lines, "\x1b[1mHTTP / Fingerprints\x1b[0m")
		lines = append(lines, headerLines...)
		// Service versions not already shown via headers.
		svOrder := []string{"web_server", "powered_by", "aspnet_version", "ssh_software", "ftp_software"}
		shownSV := map[string]bool{}
		for _, k := range svOrder {
			if v, ok := ev.ServiceVersions[k]; ok && v != "" {
				lines = append(lines, fmt.Sprintf("  \x1b[90m%-26s\x1b[0m  %s", k, v))
				shownSV[k] = true
			}
		}
		for k, v := range ev.ServiceVersions {
			if !shownSV[k] && v != "" {
				lines = append(lines, fmt.Sprintf("  \x1b[90m%-26s\x1b[0m  %s", k, v))
			}
		}
		if ev.FaviconHash != "" {
			kv("favicon hash", ev.FaviconHash)
		}
		if len(ev.CookieNames) > 0 {
			kv("cookies", strings.Join(ev.CookieNames, ", "))
		}
		if len(ev.VendorSignals) > 0 {
			kv("vendor signals", strings.Join(ev.VendorSignals, ", "))
		}
		lines = append(lines, "")
	}

	// ── Responding Paths ─────────────────────────────────────────────────
	if len(ev.RespondingPaths) > 0 || len(ev.RobotsTxtPaths) > 0 {
		lines = append(lines, "\x1b[1mPaths\x1b[0m")
		if len(ev.RespondingPaths) > 0 {
			shown := ev.RespondingPaths
			if len(shown) > 10 {
				shown = shown[:10]
			}
			kv("responding paths", strings.Join(shown, "  "))
			if len(ev.RespondingPaths) > 10 {
				kv("", fmt.Sprintf("(+%d more)", len(ev.RespondingPaths)-10))
			}
		}
		if len(ev.RobotsTxtPaths) > 0 {
			shown := ev.RobotsTxtPaths
			if len(shown) > 8 {
				shown = shown[:8]
			}
			kv("robots.txt disallow", strings.Join(shown, "  "))
		}
		if len(ex.DirbustPathsFound) > 0 {
			shown := ex.DirbustPathsFound
			if len(shown) > 10 {
				shown = shown[:10]
			}
			kv("dirbust hits", strings.Join(shown, "  "))
		}
		lines = append(lines, "")
	}

	// ── DNS ───────────────────────────────────────────────────────────────
	hasDNS := len(ev.TXTRecords) > 0 || len(ev.NSRecords) > 0 || ev.SOARecord != "" ||
		len(ev.MXRecords) > 0 || len(ev.AAAARecords) > 0 || ev.HasDMARC || len(ev.SPFIPs) > 0
	if hasDNS {
		lines = append(lines, "\x1b[1mDNS\x1b[0m")
		if ev.SOARecord != "" {
			kv("soa", ev.SOARecord)
		}
		if len(ev.NSRecords) > 0 {
			kv("ns", strings.Join(ev.NSRecords, ", "))
		}
		if len(ev.MXRecords) > 0 {
			kv("mx", strings.Join(ev.MXRecords, ", "))
		}
		if ev.HasDMARC {
			dmarc := "present"
			if ev.DMARCPolicy != "" {
				dmarc += " (p=" + ev.DMARCPolicy + ")"
			}
			kv("dmarc", dmarc)
		}
		if len(ev.SPFIPs) > 0 {
			kv("spf ips", strings.Join(ev.SPFIPs, ", "))
		}
		if len(ev.TXTRecords) > 0 {
			shown := ev.TXTRecords
			if len(shown) > 4 {
				shown = shown[:4]
			}
			for _, t := range shown {
				if len(t) > termW-32 {
					t = t[:termW-35] + "…"
				}
				lines = append(lines, fmt.Sprintf("  \x1b[90m%-26s\x1b[0m  %s", "txt", t))
			}
		}
		if len(ev.AAAARecords) > 0 {
			kv("ipv6", strings.Join(ev.AAAARecords, ", "))
		}
		lines = append(lines, "")
	}

	// ── Web3 ─────────────────────────────────────────────────────────────
	if len(ev.Web3Signals) > 0 || len(ev.ContractAddresses) > 0 {
		lines = append(lines, "\x1b[1mWeb3\x1b[0m")
		if len(ev.Web3Signals) > 0 {
			kv("signals", strings.Join(ev.Web3Signals, ", "))
		}
		if len(ev.ContractAddresses) > 0 {
			kv("contracts", strings.Join(ev.ContractAddresses, ", "))
		}
		lines = append(lines, "")
	}

	// ── AI / LLM ─────────────────────────────────────────────────────────
	if len(ev.AIEndpoints) > 0 || ev.LLMProvider != "" {
		lines = append(lines, "\x1b[1mAI / LLM\x1b[0m")
		if ev.LLMProvider != "" {
			kv("llm provider", ev.LLMProvider)
		}
		if len(ev.AIEndpoints) > 0 {
			kv("ai endpoints", strings.Join(ev.AIEndpoints, ", "))
		}
		if ev.HasAISSE {
			kv("sse streaming", "yes")
		}
		if ev.HasAgentTools {
			kv("agent tools", "yes")
		}
		lines = append(lines, "")
	}

	// ── Open Ports (from portscan findings) ──────────────────────────────
	var portParts []string
	for _, ef := range bs.findings {
		f := ef.Finding
		if f.Asset != ex.Asset || f.Scanner != "portscan" {
			continue
		}
		if p, ok := f.Evidence["port"]; ok {
			svc := ""
			if s, ok2 := f.Evidence["service"]; ok2 {
				svc = fmt.Sprintf("%v", s)
			}
			if svc != "" {
				portParts = append(portParts, fmt.Sprintf("%v/%s", p, svc))
			} else {
				portParts = append(portParts, fmt.Sprintf("%v", p))
			}
		}
	}
	if len(portParts) > 0 {
		lines = append(lines, "\x1b[1mOpen Ports\x1b[0m")
		kv("ports", strings.Join(portParts, "  "))
		lines = append(lines, "")
	}

	// ── Findings ─────────────────────────────────────────────────────────
	lines = append(lines, "\x1b[90m"+strings.Repeat("─", min(termW-4, 70))+"\x1b[0m")
	af := browseAssetFindings(bs)
	bs.assetDetailFindLine = len(lines) // record where findings start

	total := len(af)
	if total == 0 {
		lines = append(lines, "\x1b[32mNo findings — clean asset\x1b[0m")
	} else {
		// Clamp finding cursor.
		if bs.execFindCursor >= total {
			bs.execFindCursor = total - 1
		}
		for i, ef := range af {
			f := ef.Finding
			col := severityColor(f.Severity)
			sev := strings.ToUpper(f.Severity.String())
			if len(sev) > 4 {
				sev = sev[:4]
			}
			title := f.Title
			maxTitle := termW - 14
			if maxTitle < 20 {
				maxTitle = 20
			}
			if len(title) > maxTitle {
				title = title[:maxTitle-1] + "…"
			}
			cursor := "  "
			if i == bs.execFindCursor {
				cursor = "\x1b[1;33m▶\x1b[0m "
			}
			lines = append(lines, fmt.Sprintf("%s%s%-4s\x1b[0m  %s", cursor, col, sev, title))
		}
		lines = append(lines, fmt.Sprintf("\x1b[90m%d finding(s)\x1b[0m", total))
	}

	// ── Render ───────────────────────────────────────────────────────────
	name := ex.Asset
	if len(name) > 50 {
		name = "…" + name[len(name)-49:]
	}
	fmt.Fprintf(buf, "\x1b[2K\r  \x1b[90m◀\x1b[0m \x1b[1;36m%s\x1b[0m  \x1b[90m[j/k] scroll  [↵] open finding  [b/q] back\x1b[0m\n", name)

	bodyLines := termH - 2
	if bodyLines < 1 {
		bodyLines = 1
	}
	maxOff := len(lines) - bodyLines
	if maxOff < 0 {
		maxOff = 0
	}
	if bs.assetDetailOff > maxOff {
		bs.assetDetailOff = maxOff
	}

	end := bs.assetDetailOff + bodyLines
	if end > len(lines) {
		end = len(lines)
	}
	for _, l := range lines[bs.assetDetailOff:end] {
		fmt.Fprintf(buf, "\x1b[2K\r  %s\n", l)
	}
}


// severityTag returns a coloured severity badge matching the live TUI style.
func severityTag(sev finding.Severity) string {
	switch sev {
	case finding.SeverityCritical:
		return "\x1b[1;31mCRIT\x1b[0m"
	case finding.SeverityHigh:
		return "\x1b[31mHIGH\x1b[0m"
	case finding.SeverityMedium:
		return "\x1b[33mMED \x1b[0m"
	case finding.SeverityLow:
		return "\x1b[34mLOW \x1b[0m"
	default:
		return "\x1b[90mINFO\x1b[0m"
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
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
	defer st.Close()

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

	executions, _ := st.ListAssetExecutions(ctx, run.ID)
	output, err := renderFormat(format, *run, enriched, rep.Summary, rep, executions)
	if err != nil {
		fatalf("render report: %v", err)
	}

	if outPath != "" {
		if err := os.WriteFile(outPath, []byte(output), 0o644); err != nil {
			fatalf("write report file: %v", err)
		}
		fmt.Fprintf(os.Stderr, "beacon: report written to %s\n", outPath)
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
	defer st.Close()

	a, err := analyze.New(st, cfg.AnthropicAPIKey)
	if err != nil {
		fatalf("init analyzer: %v", err)
	}
	a.WithModel(cfg.ClaudeModel)
	a.WithProgress(func(msg string) {
		fmt.Fprintf(os.Stderr, "beacon: %s\n", msg)
	})

	result, err := a.RunFull(ctx)
	if err != nil {
		fatalf("analyze: %v", err)
	}
	fmt.Fprintf(os.Stderr, "beacon: analysis complete — %d suggestion(s), %d accuracy reviews\n",
		len(result.Suggestions), len(result.AccuracyReview))

	// Build the full markdown report from all analysis sections.
	var md strings.Builder
	md.WriteString("# Beacon Analysis Report\n\n")
	md.WriteString(fmt.Sprintf("Generated: %s\n\n", time.Now().Format(time.RFC3339)))

	// Section: Finding Accuracy Review
	if len(result.AccuracyReview) > 0 {
		md.WriteString("## Finding Accuracy Review\n\n")
		fps := 0
		for _, r := range result.AccuracyReview {
			if r.Verdict == "likely_false_positive" {
				fps++
			}
		}
		md.WriteString(fmt.Sprintf("%d findings reviewed · %d likely false positives\n\n", len(result.AccuracyReview), fps))
		for _, r := range result.AccuracyReview {
			icon := "✓"
			if r.Verdict == "likely_false_positive" {
				icon = "🚫"
			} else if r.Verdict == "needs_verification" {
				icon = "⚠️"
			}
			proofStatus := ""
			if !r.ProofCmdOK {
				proofStatus = fmt.Sprintf(" · proof broken: %s", r.ProofCmdIssue)
			}
			md.WriteString(fmt.Sprintf("- %s [%d%%] **%s** on `%s`%s\n", icon, r.Confidence, r.Title, r.Asset, proofStatus))
			if r.Reasoning != "" {
				md.WriteString(fmt.Sprintf("  > %s\n", r.Reasoning))
			}
		}
		md.WriteString("\n")
	}

	// Section: Credential Exposure Correlation (static, from verify package)
	v := verify.New(st, cfg.AnthropicAPIKey)
	if vreport, verr := v.RunLatest(ctx, runID); verr == nil && len(vreport.CredentialAlerts) > 0 {
		md.WriteString("## Credential Exposure + Exploit Path Correlation\n\n")
		for _, alert := range vreport.CredentialAlerts {
			md.WriteString(fmt.Sprintf("- %s\n", alert))
		}
		md.WriteString("\n")
	}

	// Section: Scan Optimizations
	if len(result.ScanOptimizations) > 0 {
		md.WriteString("## Scan Optimizations\n\n")
		for _, o := range result.ScanOptimizations {
			md.WriteString(fmt.Sprintf("- [%s] **%s**: %s\n", o.Type, o.Scanner, o.Description))
			if o.SuggestedChange != "" {
				md.WriteString(fmt.Sprintf("  > Fix: %s\n", o.SuggestedChange))
			}
		}
		md.WriteString("\n")
	}

	// Section: Detection Gaps (CVEs we can't detect)
	if len(result.ScanGaps) > 0 {
		md.WriteString("## Detection Gaps\n\n")
		for _, g := range result.ScanGaps {
			md.WriteString(fmt.Sprintf("- **%s** (%s): %s\n", g.CVEID, g.Product, g.ReasonUndetectable))
			if g.SuggestedNewScannerOrCheck != "" {
				md.WriteString(fmt.Sprintf("  > Suggested: %s\n", g.SuggestedNewScannerOrCheck))
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
		md.WriteString(fmt.Sprintf("## Playbook Suggestions (%d saved)\n\n", len(result.Suggestions)))
		md.WriteString("Run `beacon playbook suggestions` to review and apply.\n\n")
	}

	report := md.String()
	if outPath != "" {
		if err := os.WriteFile(outPath, []byte(report), 0o644); err != nil {
			fatalf("write output: %v", err)
		}
		fmt.Fprintf(os.Stderr, "beacon: report written to %s\n", outPath)
	} else {
		fmt.Print(report)
	}

	fmt.Fprintln(os.Stderr, "beacon: run 'beacon playbook suggestions' to review and apply suggestions")
}

// ---------- playbook ----------

func cmdPlaybookSuggestions(cfg *config.Config) {
	ctx := context.Background()

	st, err := sqlitestore.Open(cfg.Store.Path)
	if err != nil {
		fatalf("open store: %v", err)
	}
	defer st.Close()

	suggestions, err := st.ListPlaybookSuggestions(ctx, "pending")
	if err != nil {
		fatalf("list suggestions: %v", err)
	}

	if len(suggestions) == 0 {
		fmt.Fprintln(os.Stdout, "No pending playbook suggestions. Run 'beacon analyze' to generate them.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tTYPE\tPLAYBOOK\tSTATUS\tREASONING")
	for _, s := range suggestions {
		reasoning := s.Reasoning
		if len(reasoning) > 60 {
			reasoning = reasoning[:57] + "..."
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", s.ID, s.Type, s.TargetPlaybook, s.Status, reasoning)
	}
	w.Flush()
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
	defer st.Close()

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
	if err := os.WriteFile(yamlPath, []byte(target.SuggestedYAML), 0o644); err != nil {
		fatalf("write yaml: %v", err)
	}

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

	fmt.Fprintf(os.Stderr, "beacon: opening PR for suggestion %s...\n", id)
	if err := ghCmd.Run(); err != nil {
		fatalf("gh pr create: %v\n\nSuggested YAML written to %s", err, yamlPath)
	}

	target.Status = "pr_opened"
	_ = st.UpdatePlaybookSuggestion(ctx, target)
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
	defer st.Close()

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
	fmt.Fprintf(os.Stdout, "Imported playbook %q — active on next scan.\n", target.TargetPlaybook)
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
	defer st.Close()

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
	fmt.Fprintf(os.Stdout, "Dismissed suggestion %s (%s).\n", id, target.TargetPlaybook)
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

// ---------- helpers ----------

// filterBySeverity drops enriched findings below the specified minimum severity.
// severityFlag is a string like "high", "medium", etc. Empty string or "info"
// means no filtering (show all).
func filterBySeverity(enriched []enrichment.EnrichedFinding, severityFlag string) []enrichment.EnrichedFinding {
	min := finding.ParseSeverity(severityFlag)
	if min <= finding.SeverityInfo {
		return enriched
	}
	out := enriched[:0]
	for _, ef := range enriched {
		if ef.Finding.Severity >= min {
			out = append(out, ef)
		}
	}
	return out
}

// renderFormat produces the report string in the requested format.
// format is one of: "text" (default), "html", "json", "markdown".
func renderFormat(format string, run store.ScanRun, enriched []enrichment.EnrichedFinding, summary string, rep *store.Report, executions []store.AssetExecution) (string, error) {
	switch strings.ToLower(format) {
	case "html":
		return rep.HTMLContent, nil
	case "json":
		return report.RenderJSON(run, enriched, summary)
	case "markdown", "md":
		return report.RenderMarkdown(run, enriched, summary, executions), nil
	default: // "text" or empty
		return report.RenderText(run, enriched, summary, executions), nil
	}
}

// deliverWebhook POSTs a JSON findings payload to the configured webhook URL.
// The payload matches the structured JSON report format so SIEM consumers can
// ingest it with the same schema as `beacon scan --output json`.
// Errors are non-fatal — a failed webhook never blocks the scan report.
func deliverWebhook(ctx context.Context, webhookURL, apiKey string, run store.ScanRun, enriched []enrichment.EnrichedFinding, summary string) error {
	payload, err := report.RenderJSON(run, enriched, summary)
	if err != nil {
		return fmt.Errorf("render webhook payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL,
		strings.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "beacon-scanner/1.0")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// filterOmitted drops findings Claude marked as having no actionable value
// given other controls present in the scan.
func filterOmitted(enriched []enrichment.EnrichedFinding) []enrichment.EnrichedFinding {
	out := enriched[:0]
	for _, ef := range enriched {
		if !ef.Omit {
			out = append(out, ef)
		}
	}
	return out
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "beacon: "+format+"\n", args...)
	os.Exit(1)
}

// warnMissingAPIKeys prints a one-time pre-scan notice listing any optional
// API keys that are not configured. Each missing key reduces scan coverage in
// a specific way; the message explains what is skipped so the user can decide
// whether to obtain the key before proceeding.
//
// Also warns when nmap is configured but the process is not running as root,
// because nmap falls back to TCP connect scan (noisier) and some deep-mode
// NSE scripts with raw-socket requirements will have reduced coverage.
func warnMissingAPIKeys(cfg *config.Config) {
	type keyInfo struct {
		val  string
		name string
		desc string
	}
	keys := []keyInfo{
		{cfg.ShodanAPIKey, "BEACON_SHODAN_API_KEY", "Shodan passive host intel (open ports, CVEs, banners without active scanning)"},
		{cfg.OTXAPIKey, "BEACON_OTX_API_KEY", "AlienVault OTX passive DNS and subdomain discovery"},
		{cfg.HIBPAPIKey, "BEACON_HIBP_API_KEY", "Have I Been Pwned domain breach lookup"},
		{cfg.BingAPIKey, "BEACON_BING_API_KEY", "Bing Search API dorking for exposed files and subdomains"},
		{cfg.VirusTotalAPIKey, "BEACON_VIRUSTOTAL_API_KEY", "VirusTotal domain reputation and malware associations"},
		{cfg.SecurityTrailsAPIKey, "BEACON_SECURITYTRAILS_API_KEY", "SecurityTrails historical DNS and subdomain discovery"},
		{cfg.CensysAPIID, "BEACON_CENSYS_API_ID + BEACON_CENSYS_API_SECRET", "Censys internet-wide host and certificate data"},
		{cfg.GreyNoiseAPIKey, "BEACON_GREYNOISE_API_KEY", "GreyNoise IP noise context (reduces false positives on scanner IPs)"},
		{cfg.AnthropicAPIKey, "BEACON_ANTHROPIC_API_KEY / ai.api_key", "AI-powered finding enrichment, DLP vision analysis, and executive summary"},
	}

	var missing []keyInfo
	for _, k := range keys {
		if k.val == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		// Each key unlocks a distinct data source — not just a speed improvement.
		// Missing keys cause genuine detection gaps: passive DNS finds deleted subdomains
		// that active scanning never sees; HIBP breach data is not reproducible by probing;
		// Shodan captures ports that were open before the scan started but are now closed.
		fmt.Fprintf(os.Stderr, "beacon: missing optional keys — these are distinct data sources, not speed improvements:\n")
		for _, k := range missing {
			fmt.Fprintf(os.Stderr, "  %-55s  %s\n", k.name, k.desc)
		}
		if from := cfg.LoadedFrom(); from != "" {
			fmt.Fprintf(os.Stderr, "  Config loaded from: %s\n", from)
			fmt.Fprintf(os.Stderr, "  Add missing keys to that file using yaml key names (e.g. shodan_api_key: yourkey)\n\n")
		} else {
			fmt.Fprintf(os.Stderr, "  No config file found. Create ~/.beacon/config.yaml or set BEACON_* env vars.\n\n")
		}
	}

	// Warn when nmap is enabled but running without root privileges.
	// The core TCP connect scanner works fully without root. However, nmap
	// requires root (or CAP_NET_RAW on Linux) for SYN scanning and certain
	// NSE scripts (smb-vuln-*, ssl-heartbleed, ms17-010, snmp-info). Without
	// root, nmap silently falls back to TCP connect scan for those checks.
	if cfg.NmapBin != "" && os.Getuid() != 0 {
		fmt.Fprintf(os.Stderr, "beacon: nmap configured but running without root — nmap will use TCP connect scan\n")
		fmt.Fprintf(os.Stderr, "  Some deep-mode NSE scripts (ms17-010, smb-vuln-*, snmp-info) require raw sockets\n")
		fmt.Fprintf(os.Stderr, "  and will have reduced coverage without root or CAP_NET_RAW.\n")
		fmt.Fprintf(os.Stderr, "  Run with sudo or grant: sudo setcap cap_net_raw+ep %s\n\n", cfg.NmapBin)
	}
}

// ---------------------------------------------------------------------------
// Progress renderer
// ---------------------------------------------------------------------------
//
// Normal mode: 3-line live display redrawn every 100 ms via a background
// ticker.  ANSI cursor-up (\x1b[3A) moves back to the top of the block so
// each tick overwrites the previous frame in-place — the same technique used
// by docker build, cargo, and npm.
//
// Verbose mode: persistent scrolling log lines printed above the status block.
// When a verbose line is emitted the 3-line block is erased first so the log
// line lands cleanly, then the block is redrawn below it.
//
// Display layout (normal mode):
//
//   [==============================------]  85%   elapsed 4m12s   ETA ~44s
//   26 / 28 assets  ·  421 findings
//   ↳  scanning  pve2.mgmt.stormbane.net  [portscan → TCP connect scan]

// liveAsset tracks one discovered asset in the live asset roster.
type liveAsset struct {
	Name         string
	Status       string // "queued", "scanning", "done"
	FindingCount int
	sevCount     [5]int // index 0=Info, 1=Low, 2=Medium, 3=High, 4=Critical
}

// liveService is a discovered non-HTTP TCP service on a host.
type liveService struct {
	port    int
	service string
}

// recentOp records a scanner that just completed, shown in the progress view.
type recentOp struct {
	scanner  string
	asset    string
	cmd      string
	findings int
	elapsed  time.Duration
}

// findingsRow is one visual row in the findings pager: either a severity-group
// header or a reference to a finding in filteredFindings.
type findingsRow struct {
	isHeader bool
	severity finding.Severity // label/color for header rows
	idx      int              // index into filteredFindings (finding rows only)
}

// progressRenderer renders live scan progress to stderr.
//
// Modes: "progress" (default 3-line bar), "findings" (full-screen pager),
// "assets" (asset roster with cursor), "asset_detail" (per-asset findings).
// Press f=findings, a=assets, j/k=scroll, Enter=drill-in, q/b/Esc=back.
//
// Non-TTY (CI, pipe, redirect): ANSI suppressed; plain event lines only.
type progressRenderer struct {
	mu                sync.Mutex
	total             int
	done              int
	findingCount      int
	activeAsset       string
	activeScannerName string
	activeScannerCmd  string
	phase             string
	statusMsg         string
	verbose           bool
	ansi              bool // true when stderr is a TTY
	start             time.Time
	drawn             bool // true once the first frame has been written
	drawnLines        int  // actual number of lines in the current block

	// mode is one of: "progress", "findings", "assets", "asset_detail", "finding_detail", "topology", "topo_detail"
	mode string

	// Findings pager
	findings       []finding.Finding
	findingsOff    int // scroll offset (first visible row)
	findingsCursor   int               // highlighted row (index into findingsRows)
	filteredFindings    []finding.Finding // findings after severity+text filter, sorted by severity; rebuilt each frame
	filteredFindingsIdx []int             // parallel slice: r.findings index for each entry in filteredFindings
	findingsRows        []findingsRow     // visual rows (headers + finding refs); rebuilt each render frame

	// Asset roster
	assets       []liveAsset
	assetIdx     map[string]int // name → index in assets slice
	assetsCursor int            // highlighted row (absolute index)
	assetsOff    int            // scroll offset (first visible row)

	// Asset detail drill-down
	selectedAsset    string
	assetDetailOff   int
	assetDetailCursor int // highlighted finding row within asset detail

	// Finding detail drill-down
	selectedFinding      *finding.Finding
	findingDetailOff     int
	findingDetailOrigin  string // mode to return to when pressing b/q

	// Severity filter: findings below this level are excluded from the live pager
	minSeverity finding.Severity

	// severityOverrides maps finding index (in r.findings) to a user-adjusted
	// severity. Pressing [ / ] on a finding bumps its severity without
	// modifying the underlying scanner output.
	severityOverrides map[int]finding.Severity

	// findingFilter is the active text filter in the findings pager.
	findingFilter     string
	findingFilterMode bool // true when user is actively typing a filter

	// Topology map: asset → fingerprint evidence, built as fingerprint events arrive
	topoEvidence    map[string]playbook.Evidence
	topoServices    map[string][]liveService // asset → open TCP services (from port-scan findings)
	topoOff         int                      // scroll offset for topology view
	topoCursor      int                      // index into topoHostOrder (selectable entries)
	topoHostOrder   []string                 // ordered list of asset names as rendered (rebuilt each frame)
	topoDetailAsset string                   // asset selected for topo_detail view
	topoDetailOff   int                      // scroll offset for topo_detail view

	// Discovered Assets panel — IPs / deploy targets whose ownership has not
	// been automatically confirmed.  Populated by "unconfirmed_assets" and
	// "deploy_targets" progress events.  Surface scans always run; deep scans
	// require the operator to type "permission confirmed" in the detail view.
	discoveredAssets   []module.DiscoveredAsset
	discoveredOff      int    // scroll offset for list view
	discoveredCursor   int    // highlighted row
	discoveredDetailIdx int   // index of asset open in detail view
	discoveredConfirm  string // text typed into the permission gate
	discoveredConfirming bool // true while the operator is typing the gate phrase

	// store reference for post-scan review
	st store.Store

	// pendingReview is set by Done() when there are pending fingerprint rules or playbook suggestions.
	pendingReview string

	// Review mode state
	pendingReviewRules []store.FingerprintRule
	pendingReviewSuggs []store.PlaybookSuggestion
	reviewCursor       int

	stopOnce  sync.Once
	stop      chan struct{}
	detached  chan struct{} // closed when user presses b to detach (browse while scan runs)
	restoreFn func() // restores terminal from raw mode; nil when unused
	cancelFn      func() // cancels the scan context; set by cmdScan after construction
	confirmingExit bool // true when waiting for y/n confirmation to stop scan
	headless       bool // managed by browse TUI — no own stdin reader, no own ticker

	// ETA: rolling average of the last 10 completed asset durations.
	durations  []time.Duration
	assetStart map[string]time.Time

	// activeOps tracks all currently running scanner operations.
	// Key: "asset\x00scanner", Value: human-readable command string.
	// Populated on scanner_start, cleared on scanner_done and asset_done.
	activeOps   map[string]string
	scannerStart map[string]time.Time // Key: "asset\x00scanner" → start time

	// recentOps is a ring buffer of the last 20 completed scanner ops, shown
	// in the progress view when there are spare lines below the active ops.
	recentOps []recentOp
}

func newProgressRenderer(verbose bool, minSeverity finding.Severity) *progressRenderer {
	r := &progressRenderer{
		phase:       "discovering",
		mode:        "progress",
		verbose:     verbose,
		ansi:        term.IsTerminal(int(os.Stderr.Fd())),
		start:       time.Now(),
		stop:        make(chan struct{}),
		detached:    make(chan struct{}),
		assetStart:   make(map[string]time.Time),
		assetIdx:     make(map[string]int),
		minSeverity:  minSeverity,
		topoEvidence: make(map[string]playbook.Evidence),
		topoServices: make(map[string][]liveService),
		activeOps:    make(map[string]string),
		scannerStart: make(map[string]time.Time),
	}
	if !r.ansi {
		return r
	}

	// Put stdin in raw mode so single keypresses are read without Enter.
	// Keep ISIG so Ctrl+C still sends SIGINT.
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fd := int(os.Stdin.Fd())
		old, err := term.MakeRaw(fd)
		if err != nil {
			// MakeRaw failed on a live TTY — this happens when a previous beacon
			// process was killed (OOM, SIGKILL) while holding the terminal in raw
			// mode, leaving the tty settings corrupted. Attempt to restore sane
			// settings via "stty sane" and retry once.
			if execErr := exec.Command("stty", "sane").Run(); execErr == nil {
				old, err = term.MakeRaw(fd)
			}
		}
		if err == nil {
			r.restoreFn = func() { _ = term.Restore(fd, old) }
			r.startInputLoop()
		}
	}

	// Background ticker: redraws the status block every 100 ms.
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-r.stop:
				return
			case <-ticker.C:
				r.mu.Lock()
				r.render()
				r.mu.Unlock()
			}
		}
	}()
	return r
}

// newHeadlessRenderer creates a progressRenderer that is managed by the browse
// TUI. It does NOT start its own stdin reader or render ticker — the browse TUI
// drives rendering via render() and key handling via processKey().
func newHeadlessRenderer(minSeverity finding.Severity) *progressRenderer {
	return &progressRenderer{
		phase:        "discovering",
		mode:         "progress",
		ansi:         term.IsTerminal(int(os.Stderr.Fd())),
		start:        time.Now(),
		stop:         make(chan struct{}),
		detached:     make(chan struct{}),
		assetStart:   make(map[string]time.Time),
		assetIdx:     make(map[string]int),
		minSeverity:  minSeverity,
		topoEvidence: make(map[string]playbook.Evidence),
		topoServices: make(map[string][]liveService),
		activeOps:    make(map[string]string),
		scannerStart: make(map[string]time.Time),
		headless:     true,
	}
}

// processKey handles a single raw keypress forwarded from the browse TUI's
// input loop. Must be called with r.mu held.
func (r *progressRenderer) processKey(buf []byte, n int) {
	isDown  := buf[0] == 'j' || (n >= 3 && buf[0] == 0x1b && buf[1] == '[' && buf[2] == 'B')
	isUp    := buf[0] == 'k' || (n >= 3 && buf[0] == 0x1b && buf[1] == '[' && buf[2] == 'A')
	isEnter := buf[0] == '\r' || buf[0] == '\n'
	isEsc   := n == 1 && buf[0] == 0x1b

	// 'q' always detaches. 'b' navigates back one level; only detaches from "progress".
	// Esc only detaches when headless (non-headless Esc has mode-specific meanings).
	if !r.confirmingExit {
		isDetach := buf[0] == 'q' || (r.headless && isEsc && r.mode == "progress")
		isBack := buf[0] == 'b' || (r.headless && isEsc)
		if isDetach || (isBack && r.mode == "progress") {
			r.mu.Unlock()
			r.stopOnce.Do(func() { close(r.stop) })
			close(r.detached)
			r.mu.Lock()
			return
		}
		if isBack {
			r.navigateBack()
			r.render()
			return
		}
	}

	if r.confirmingExit {
		switch buf[0] {
		case 'y', 'Y':
			if r.cancelFn != nil {
				r.cancelFn()
			}
			r.confirmingExit = false
		default:
			r.confirmingExit = false
		}
		r.render()
		return
	}
	if buf[0] == 0x03 { // Ctrl+C
		if r.cancelFn != nil {
			r.cancelFn()
		}
		return
	}
	switch r.mode {
	case "progress":
		switch {
		case buf[0] == 'f' || buf[0] == ' ':
			r.mode = "findings"
			r.findingsOff = len(r.findings)
		case buf[0] == 'a':
			r.mode = "assets"
		case buf[0] == 't':
			r.mode = "topology"
			r.topoOff = 0
		case buf[0] == 'd' && len(r.discoveredAssets) > 0:
			r.discoveredOff = 0
			r.discoveredCursor = 0
			r.mode = "discovered"
		case buf[0] == 'b' || isEsc:
			// Signal detach back to the browse TUI.
			r.mu.Unlock()
			r.stopOnce.Do(func() { close(r.stop) })
			close(r.detached)
			r.mu.Lock() // re-acquire so caller's deferred unlock is safe
			return
		case buf[0] == 's':
			// 's' stops the scan (with confirmation). 'q'/'b' just detach.
			if r.phase != "done" {
				r.confirmingExit = true
			}
		case buf[0] == 'r':
			// Load pending items and enter review mode.
			if r.st != nil && r.phase == "done" {
				ctx := context.Background()
				r.pendingReviewRules, _ = r.st.GetFingerprintRules(ctx, "pending")
				r.pendingReviewSuggs, _ = r.st.ListPlaybookSuggestions(ctx, "pending")
				r.reviewCursor = 0
				r.mode = "review"
			}
		case buf[0] >= '1' && buf[0] <= '5':
			// 1-5 adjusts the minimum severity filter from any view.
			levels := []finding.Severity{
				finding.SeverityInfo,
				finding.SeverityLow,
				finding.SeverityMedium,
				finding.SeverityHigh,
				finding.SeverityCritical,
			}
			r.minSeverity = levels[buf[0]-'1']
			r.findingsOff = 0
			r.findingsCursor = 0
		}
	case "findings":
		if r.findingFilterMode {
			switch {
			case isEsc:
				// Escape: clear filter and exit filter mode.
				r.findingFilter = ""
				r.findingFilterMode = false
				r.findingsCursor = 0
				r.findingsOff = 0
			case isEnter:
				// Confirm filter, exit filter mode.
				r.findingFilterMode = false
				r.findingsCursor = 0
				r.findingsOff = 0
			case n == 1 && (buf[0] == 127 || buf[0] == 8):
				// Backspace: remove last rune.
				runes := []rune(r.findingFilter)
				if len(runes) > 0 {
					r.findingFilter = string(runes[:len(runes)-1])
				}
			default:
				// Append printable characters.
				if buf[0] >= 0x20 && buf[0] < 0x7f {
					r.findingFilter += string(buf[:n])
				}
			}
		} else {
			switch {
			case isEsc && r.findingFilter != "":
				// Escape when filter is set but not in filter mode: clear filter.
				r.findingFilter = ""
				r.findingsCursor = 0
				r.findingsOff = 0
			case buf[0] == 'f' || buf[0] == ' ':
				r.mode = "progress"
			case buf[0] == 'a':
				r.mode = "assets"
			case buf[0] == 't':
				r.mode = "topology"
				r.topoOff = 0
			case buf[0] == 'd' && len(r.discoveredAssets) > 0:
				r.discoveredOff = 0
				r.discoveredCursor = 0
				r.mode = "discovered"
			case buf[0] == '/':
				r.findingFilterMode = true
				r.findingFilter = ""
				r.findingsCursor = 0
				r.findingsOff = 0
			case isDown:
				// Advance cursor, skipping group-header rows.
				for r.findingsCursor+1 < len(r.findingsRows) {
					r.findingsCursor++
					if !r.findingsRows[r.findingsCursor].isHeader {
						break
					}
				}
			case isUp:
				// Move cursor back, skipping group-header rows.
				for r.findingsCursor > 0 {
					r.findingsCursor--
					if !r.findingsRows[r.findingsCursor].isHeader {
						break
					}
				}
			case isEnter:
				if len(r.findingsRows) > 0 && r.findingsCursor < len(r.findingsRows) && !r.findingsRows[r.findingsCursor].isHeader {
					f := r.filteredFindings[r.findingsRows[r.findingsCursor].idx]
					r.selectedFinding = &f
					r.findingDetailOff = 0
					r.findingDetailOrigin = "findings"
					r.mode = "finding_detail"
				}
			case buf[0] >= '1' && buf[0] <= '5':
				levels := []finding.Severity{
					finding.SeverityInfo,
					finding.SeverityLow,
					finding.SeverityMedium,
					finding.SeverityHigh,
					finding.SeverityCritical,
				}
				r.minSeverity = levels[buf[0]-'1']
				r.findingsOff = 0
				r.findingsCursor = 0
			case buf[0] == '[' || buf[0] == ']':
				// [ / ] bumps the highlighted finding's severity down or up.
				if len(r.findingsRows) > 0 && r.findingsCursor < len(r.findingsRows) && !r.findingsRows[r.findingsCursor].isHeader {
					rowIdx := r.findingsRows[r.findingsCursor].idx
					origIdx := r.filteredFindingsIdx[rowIdx]
					cur := r.filteredFindings[rowIdx].Severity
					allSevs := []finding.Severity{
						finding.SeverityInfo,
						finding.SeverityLow,
						finding.SeverityMedium,
						finding.SeverityHigh,
						finding.SeverityCritical,
					}
					pos := 0
					for i, s := range allSevs {
						if s == cur {
							pos = i
							break
						}
					}
					if buf[0] == ']' && pos < len(allSevs)-1 {
						pos++
					} else if buf[0] == '[' && pos > 0 {
						pos--
					}
					if r.severityOverrides == nil {
						r.severityOverrides = make(map[int]finding.Severity)
					}
					r.severityOverrides[origIdx] = allSevs[pos]
				}
			}
		}
	case "topology":
		switch {
		case isDown:
			if r.topoCursor < len(r.topoHostOrder)-1 {
				r.topoCursor++
			}
		case isUp:
			if r.topoCursor > 0 {
				r.topoCursor--
			}
		case isEnter:
			if len(r.topoHostOrder) > 0 && r.topoCursor < len(r.topoHostOrder) {
				r.topoDetailAsset = r.topoHostOrder[r.topoCursor]
				r.topoDetailOff = 0
				r.mode = "topo_detail"
			}
		case buf[0] == 'd' && len(r.discoveredAssets) > 0:
			r.discoveredOff = 0
			r.discoveredCursor = 0
			r.mode = "discovered"
		case buf[0] == 't':
			r.mode = "progress"
		}

	case "discovered":
		switch {
		case isDown:
			if r.discoveredCursor < len(r.discoveredAssets)-1 {
				r.discoveredCursor++
				// Scroll viewport down when cursor moves below visible area.
			}
		case isUp:
			if r.discoveredCursor > 0 {
				r.discoveredCursor--
			}
		case isEnter:
			if r.discoveredCursor < len(r.discoveredAssets) {
				r.discoveredDetailIdx = r.discoveredCursor
				r.discoveredConfirm = ""
				r.discoveredConfirming = false
				r.mode = "discovered_detail"
			}
		case buf[0] == 'b' || buf[0] == 'q' || isEsc:
			r.mode = "progress"
		}

	case "discovered_detail":
		if r.discoveredConfirming {
			// Operator is typing the permission gate phrase character by character.
			switch {
			case isEsc:
				r.discoveredConfirm = ""
				r.discoveredConfirming = false
			case isEnter:
				// Phrase accepted; the render function enables the deep scan action.
				r.discoveredConfirming = false
			case n == 1 && (buf[0] == 127 || buf[0] == 8): // backspace
				runes := []rune(r.discoveredConfirm)
				if len(runes) > 0 {
					r.discoveredConfirm = string(runes[:len(runes)-1])
				}
			default:
				if buf[0] >= 0x20 && buf[0] < 0x7f {
					r.discoveredConfirm += string(buf[:n])
				}
			}
		} else {
			switch {
			case isDown:
				r.discoveredDetailIdx++ // reused as scroll offset in detail view
				if r.discoveredDetailIdx >= len(r.discoveredAssets) {
					r.discoveredDetailIdx = len(r.discoveredAssets) - 1
				}
				r.discoveredConfirm = ""
				r.discoveredConfirming = false
			case isUp:
				if r.discoveredDetailIdx > 0 {
					r.discoveredDetailIdx--
					r.discoveredConfirm = ""
					r.discoveredConfirming = false
				}
			case buf[0] == 'p':
				// Start typing permission phrase.
				r.discoveredConfirm = ""
				r.discoveredConfirming = true
			case buf[0] == 'b' || buf[0] == 'q' || isEsc:
				r.mode = "discovered"
			}
		}
	case "topo_detail":
		switch {
		case isDown:
			r.topoDetailOff++
		case isUp:
			if r.topoDetailOff > 0 {
				r.topoDetailOff--
			}
		case buf[0] == 'n':
			// Advance to next host in topology order.
			if r.topoCursor < len(r.topoHostOrder)-1 {
				r.topoCursor++
				r.topoDetailAsset = r.topoHostOrder[r.topoCursor]
				r.topoDetailOff = 0
			}
		case buf[0] == 'p':
			// Go back to previous host in topology order.
			if r.topoCursor > 0 {
				r.topoCursor--
				r.topoDetailAsset = r.topoHostOrder[r.topoCursor]
				r.topoDetailOff = 0
			}
		case buf[0] == 'b':
			r.mode = "topology"
		}
	case "assets":
		switch {
		case isDown:
			if r.assetsCursor < len(r.assets)-1 {
				r.assetsCursor++
			}
		case isUp:
			if r.assetsCursor > 0 {
				r.assetsCursor--
			}
		case isEnter:
			if len(r.assets) > 0 && r.assetsCursor < len(r.assets) {
				r.selectedAsset = r.assets[r.assetsCursor].Name
				r.assetDetailOff = 0
				r.mode = "asset_detail"
			}
		case buf[0] == 'a':
			r.mode = "progress"
		}
	case "asset_detail":
		var af []finding.Finding
		for _, f := range r.findings {
			if f.Asset == r.selectedAsset {
				af = append(af, f)
			}
		}
		sort.Slice(af, func(i, j int) bool {
			if af[i].Severity != af[j].Severity {
				return af[i].Severity > af[j].Severity
			}
			return string(af[i].CheckID) < string(af[j].CheckID)
		})
		switch {
		case isDown:
			if r.assetDetailCursor < len(af)-1 {
				r.assetDetailCursor++
			}
		case isUp:
			if r.assetDetailCursor > 0 {
				r.assetDetailCursor--
			}
		case isEnter:
			if len(af) > 0 && r.assetDetailCursor < len(af) {
				f := af[r.assetDetailCursor]
				r.selectedFinding = &f
				r.findingDetailOff = 0
				r.findingDetailOrigin = "asset_detail"
				r.mode = "finding_detail"
			}
		case buf[0] == 'a':
			r.mode = "assets"
			r.assetDetailCursor = 0
		}
	case "finding_detail":
		switch {
		case isDown || buf[0] == ' ':
			r.findingDetailOff++
		case isUp:
			if r.findingDetailOff > 0 {
				r.findingDetailOff--
			}
		case isEsc || isEnter:
			r.mode = r.findingDetailOrigin
			r.selectedFinding = nil
		case buf[0] == '[' || buf[0] == ']':
			// [ / ] bumps the current finding's severity from the detail view too.
			if r.selectedFinding != nil {
				// Find the finding in r.findings to get its original index.
				for origIdx, f := range r.findings {
					if f.CheckID == r.selectedFinding.CheckID && f.Asset == r.selectedFinding.Asset {
						cur := r.selectedFinding.Severity
						allSevs := []finding.Severity{
							finding.SeverityInfo,
							finding.SeverityLow,
							finding.SeverityMedium,
							finding.SeverityHigh,
							finding.SeverityCritical,
						}
						pos := 0
						for i, s := range allSevs {
							if s == cur {
								pos = i
								break
							}
						}
						if buf[0] == ']' && pos < len(allSevs)-1 {
							pos++
						} else if buf[0] == '[' && pos > 0 {
							pos--
						}
						if r.severityOverrides == nil {
							r.severityOverrides = make(map[int]finding.Severity)
						}
						r.severityOverrides[origIdx] = allSevs[pos]
						r.selectedFinding.Severity = allSevs[pos]
						break
					}
				}
			}
		}
	case "review":
		type reviewItemP struct {
			kind   string
			id     int64
			suggID string
		}
		var ritems []reviewItemP
		for _, r2 := range r.pendingReviewRules {
			ritems = append(ritems, reviewItemP{kind: "fingerprint", id: r2.ID})
		}
		for _, s := range r.pendingReviewSuggs {
			ritems = append(ritems, reviewItemP{kind: "playbook", suggID: s.ID})
		}
		switch {
		case isDown:
			if r.reviewCursor < len(ritems)-1 {
				r.reviewCursor++
			}
		case isUp:
			if r.reviewCursor > 0 {
				r.reviewCursor--
			}
		case buf[0] == 'a':
			if r.reviewCursor < len(ritems) && r.st != nil {
				item := ritems[r.reviewCursor]
				ctx := context.Background()
				if item.kind == "fingerprint" {
					for i := range r.pendingReviewRules {
						if r.pendingReviewRules[i].ID == item.id {
							r.pendingReviewRules[i].Status = "active"
							_ = r.st.UpsertFingerprintRule(ctx, &r.pendingReviewRules[i])
							r.pendingReviewRules = append(r.pendingReviewRules[:i], r.pendingReviewRules[i+1:]...)
							break
						}
					}
				} else {
					for i := range r.pendingReviewSuggs {
						if r.pendingReviewSuggs[i].ID == item.suggID {
							r.pendingReviewSuggs[i].Status = "pr_opened"
							_ = r.st.UpdatePlaybookSuggestion(ctx, &r.pendingReviewSuggs[i])
							r.pendingReviewSuggs = append(r.pendingReviewSuggs[:i], r.pendingReviewSuggs[i+1:]...)
							break
						}
					}
				}
				if r.reviewCursor >= len(r.pendingReviewRules)+len(r.pendingReviewSuggs) {
					r.reviewCursor--
				}
				if r.reviewCursor < 0 {
					r.reviewCursor = 0
				}
				if len(r.pendingReviewRules)+len(r.pendingReviewSuggs) == 0 {
					r.pendingReview = ""
				}
			}
		case buf[0] == 'x':
			if r.reviewCursor < len(ritems) && r.st != nil {
				item := ritems[r.reviewCursor]
				ctx := context.Background()
				if item.kind == "fingerprint" {
					for i := range r.pendingReviewRules {
						if r.pendingReviewRules[i].ID == item.id {
							r.pendingReviewRules[i].Status = "rejected"
							_ = r.st.UpsertFingerprintRule(ctx, &r.pendingReviewRules[i])
							r.pendingReviewRules = append(r.pendingReviewRules[:i], r.pendingReviewRules[i+1:]...)
							break
						}
					}
				} else {
					for i := range r.pendingReviewSuggs {
						if r.pendingReviewSuggs[i].ID == item.suggID {
							r.pendingReviewSuggs[i].Status = "rejected"
							_ = r.st.UpdatePlaybookSuggestion(ctx, &r.pendingReviewSuggs[i])
							r.pendingReviewSuggs = append(r.pendingReviewSuggs[:i], r.pendingReviewSuggs[i+1:]...)
							break
						}
					}
				}
				if r.reviewCursor >= len(r.pendingReviewRules)+len(r.pendingReviewSuggs) {
					r.reviewCursor--
				}
				if r.reviewCursor < 0 {
					r.reviewCursor = 0
				}
				if len(r.pendingReviewRules)+len(r.pendingReviewSuggs) == 0 {
					r.pendingReview = ""
				}
			}
		case buf[0] == 'd':
			if r.reviewCursor < len(ritems) && r.st != nil {
				item := ritems[r.reviewCursor]
				ctx := context.Background()
				if item.kind == "fingerprint" {
					_ = r.st.DeleteFingerprintRule(ctx, item.id)
					for i := range r.pendingReviewRules {
						if r.pendingReviewRules[i].ID == item.id {
							r.pendingReviewRules = append(r.pendingReviewRules[:i], r.pendingReviewRules[i+1:]...)
							break
						}
					}
					if r.reviewCursor >= len(r.pendingReviewRules)+len(r.pendingReviewSuggs) {
						r.reviewCursor--
					}
					if r.reviewCursor < 0 {
						r.reviewCursor = 0
					}
				}
				if len(r.pendingReviewRules)+len(r.pendingReviewSuggs) == 0 {
					r.pendingReview = ""
				}
			}
		case buf[0] == 'i':
			// Import a playbook suggestion to ~/.config/beacon/playbooks/<name>.yaml
			// so that LoadUserDir picks it up on the next scan.
			if r.reviewCursor < len(ritems) && r.st != nil {
				item := ritems[r.reviewCursor]
				if item.kind == "playbook" {
					ctx := context.Background()
					for i := range r.pendingReviewSuggs {
						if r.pendingReviewSuggs[i].ID != item.suggID {
							continue
						}
						sugg := &r.pendingReviewSuggs[i]
						if err := importPlaybookSuggestion(sugg); err == nil {
							sugg.Status = "imported"
							_ = r.st.UpdatePlaybookSuggestion(ctx, sugg)
							r.pendingReviewSuggs = append(r.pendingReviewSuggs[:i], r.pendingReviewSuggs[i+1:]...)
						}
						break
					}
					if r.reviewCursor >= len(r.pendingReviewRules)+len(r.pendingReviewSuggs) {
						r.reviewCursor--
					}
					if r.reviewCursor < 0 {
						r.reviewCursor = 0
					}
					if len(r.pendingReviewRules)+len(r.pendingReviewSuggs) == 0 {
						r.pendingReview = ""
					}
				}
			}
		}
	}
	r.render()
}

// importPlaybookSuggestion writes a PlaybookSuggestion's YAML to
// ~/.config/beacon/playbooks/<name>.yaml so it is loaded on next scan.
func importPlaybookSuggestion(sugg *store.PlaybookSuggestion) error {
	safeName := safePlaybookName(sugg.TargetPlaybook)
	if safeName == "" {
		return fmt.Errorf("invalid playbook name: %q", sugg.TargetPlaybook)
	}
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(homeDir, ".config", "beacon", "playbooks")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, safeName+".yaml"), []byte(sugg.SuggestedYAML), 0o600)
}

// startInputLoop reads raw keypresses from stdin and handles view toggles /
// pager scrolling. Runs in its own goroutine.
//
// Lifecycle: the goroutine checks r.stop before each Read call and exits if
// the channel is closed. However, os.Stdin.Read blocks, so if the stop
// channel fires while a Read is in progress the goroutine will unblock only
// when the user types the next key (or the process exits). This is acceptable
// because Done() is deferred at the top of cmdScan and the process exits
// immediately after Done() returns, killing the goroutine at that point.
func (r *progressRenderer) startInputLoop() {
	go func() {
		buf := make([]byte, 4)
		for {
			select {
			case <-r.stop:
				return
			default:
			}
			n, err := os.Stdin.Read(buf)
			if err != nil || n == 0 {
				return
			}
			isDown  := buf[0] == 'j' || (n >= 3 && buf[0] == 0x1b && buf[1] == '[' && buf[2] == 'B')
			isUp    := buf[0] == 'k' || (n >= 3 && buf[0] == 0x1b && buf[1] == '[' && buf[2] == 'A')
			isEnter := buf[0] == '\r' || buf[0] == '\n'
			isEsc   := n == 1 && buf[0] == 0x1b

			r.mu.Lock()
			// While confirming exit, only y/n are meaningful.
			if r.confirmingExit {
				switch buf[0] {
				case 'y', 'Y':
					if r.cancelFn != nil {
						r.cancelFn()
					}
					r.confirmingExit = false
				default:
					r.confirmingExit = false
				}
				r.render()
				r.mu.Unlock()
				continue
			}
			// Ctrl+C (0x03) immediately stops the scan from any view.
			if buf[0] == 0x03 {
				if r.cancelFn != nil {
					r.cancelFn()
				}
				r.mu.Unlock()
				continue
			}
			// 'q' detaches. 'b' navigates back one level; only detaches from "progress".
			if buf[0] == 'q' || (buf[0] == 'b' && r.mode == "progress") || (isEsc && r.mode == "progress") {
				r.mu.Unlock()
				r.stopOnce.Do(func() { close(r.stop) })
				close(r.detached)
				return
			}
			if buf[0] == 'b' || isEsc {
				r.navigateBack()
				r.render()
				r.mu.Unlock()
				continue
			}

			switch r.mode {
			case "progress":
				switch {
				case buf[0] == 'f' || buf[0] == ' ':
					r.mode = "findings"
					r.findingsOff = len(r.findings)
				case buf[0] == 'a':
					r.mode = "assets"
				case buf[0] == 't':
					r.mode = "topology"
					r.topoOff = 0
				case buf[0] == 's':
					// 's' prompts to stop the scan; 'q'/'b' just detach (handled above).
					if r.phase != "done" {
						r.confirmingExit = true
					}
				case buf[0] == 'r':
					if r.st != nil && r.phase == "done" {
						ctx := context.Background()
						r.pendingReviewRules, _ = r.st.GetFingerprintRules(ctx, "pending")
						r.pendingReviewSuggs, _ = r.st.ListPlaybookSuggestions(ctx, "pending")
						r.reviewCursor = 0
						r.mode = "review"
					}
				case buf[0] >= '1' && buf[0] <= '5':
					// 1-5 adjusts minimum severity filter from any view.
					levels := []finding.Severity{
						finding.SeverityInfo,
						finding.SeverityLow,
						finding.SeverityMedium,
						finding.SeverityHigh,
						finding.SeverityCritical,
					}
					r.minSeverity = levels[buf[0]-'1']
					r.findingsOff = 0
					r.findingsCursor = 0
				}

			case "findings":
				switch {
				case buf[0] == 'f' || buf[0] == ' ':
					r.mode = "progress"
				case buf[0] == 'a':
					r.mode = "assets"
				case buf[0] == 't':
					r.mode = "topology"
					r.topoOff = 0
				case isDown:
					// Advance cursor, skipping group-header rows.
					for r.findingsCursor+1 < len(r.findingsRows) {
						r.findingsCursor++
						if !r.findingsRows[r.findingsCursor].isHeader {
							break
						}
					}
				case isUp:
					// Move cursor back, skipping group-header rows.
					for r.findingsCursor > 0 {
						r.findingsCursor--
						if !r.findingsRows[r.findingsCursor].isHeader {
							break
						}
					}
				case isEnter:
					if len(r.findingsRows) > 0 && r.findingsCursor < len(r.findingsRows) && !r.findingsRows[r.findingsCursor].isHeader {
						f := r.filteredFindings[r.findingsRows[r.findingsCursor].idx]
						r.selectedFinding = &f
						r.findingDetailOff = 0
						r.findingDetailOrigin = "findings"
						r.mode = "finding_detail"
					}
				}

			case "topology":
				switch {
				case isDown:
					r.topoOff++
				case isUp:
					if r.topoOff > 0 {
						r.topoOff--
					}
				case isEnter:
					if len(r.topoHostOrder) > 0 && r.topoCursor < len(r.topoHostOrder) {
						r.topoDetailAsset = r.topoHostOrder[r.topoCursor]
						r.topoDetailOff = 0
						r.mode = "topo_detail"
					}
				case buf[0] == 't':
					r.mode = "progress"
				}

			case "topo_detail":
				switch {
				case isDown:
					r.topoDetailOff++
				case isUp:
					if r.topoDetailOff > 0 {
						r.topoDetailOff--
					}
				case buf[0] == 'n':
					if r.topoCursor < len(r.topoHostOrder)-1 {
						r.topoCursor++
						r.topoDetailAsset = r.topoHostOrder[r.topoCursor]
						r.topoDetailOff = 0
					}
				case buf[0] == 'p':
					if r.topoCursor > 0 {
						r.topoCursor--
						r.topoDetailAsset = r.topoHostOrder[r.topoCursor]
						r.topoDetailOff = 0
					}
				case buf[0] == 'b' || isEsc:
					r.mode = "topology"
				}

			case "assets":
				switch {
				case isDown:
					if r.assetsCursor < len(r.assets)-1 {
						r.assetsCursor++
					}
				case isUp:
					if r.assetsCursor > 0 {
						r.assetsCursor--
					}
				case isEnter:
					if len(r.assets) > 0 && r.assetsCursor < len(r.assets) {
						r.selectedAsset = r.assets[r.assetsCursor].Name
						r.assetDetailOff = 0
						r.mode = "asset_detail"
					}
				case buf[0] == 'a':
					r.mode = "progress"
				}

			case "asset_detail":
				// Build per-asset findings to know total for cursor clamping.
				var af []finding.Finding
				for _, f := range r.findings {
					if f.Asset == r.selectedAsset {
						af = append(af, f)
					}
				}
				sort.Slice(af, func(i, j int) bool {
					if af[i].Severity != af[j].Severity {
						return af[i].Severity > af[j].Severity
					}
					return string(af[i].CheckID) < string(af[j].CheckID)
				})
				switch {
				case isDown:
					if r.assetDetailCursor < len(af)-1 {
						r.assetDetailCursor++
					}
				case isUp:
					if r.assetDetailCursor > 0 {
						r.assetDetailCursor--
					}
				case isEnter:
					if len(af) > 0 && r.assetDetailCursor < len(af) {
						f := af[r.assetDetailCursor]
						r.selectedFinding = &f
						r.findingDetailOff = 0
						r.findingDetailOrigin = "asset_detail"
						r.mode = "finding_detail"
					}
				case isEsc:
					r.mode = "assets"
				}

			case "finding_detail":
				switch {
				case isDown:
					r.findingDetailOff++
				case isUp:
					if r.findingDetailOff > 0 {
						r.findingDetailOff--
					}
				case buf[0] == 'y':
					// Copy proof command to clipboard; fall back to URL.
					if r.selectedFinding != nil {
						sf := r.selectedFinding
						text := sf.ProofCommand
						if text == "" {
							text = report.VerifyCmd(sf.CheckID, sf.Asset)
						}
						if text == "" {
							text = extractFindingURL(sf)
						}
						if text != "" {
							copyToClipboard(text)
						}
					}
				case isEsc || isEnter:
					if r.findingDetailOrigin != "" {
						r.mode = r.findingDetailOrigin
					} else {
						r.mode = "asset_detail"
					}
				}

			case "review":
				type reviewItemLocal struct {
					kind   string
					id     int64
					suggID string
				}
				var ritems []reviewItemLocal
				for _, r2 := range r.pendingReviewRules {
					ritems = append(ritems, reviewItemLocal{kind: "fingerprint", id: r2.ID})
				}
				for _, s := range r.pendingReviewSuggs {
					ritems = append(ritems, reviewItemLocal{kind: "playbook", suggID: s.ID})
				}
				switch {
				case isDown:
					if r.reviewCursor < len(ritems)-1 {
						r.reviewCursor++
					}
				case isUp:
					if r.reviewCursor > 0 {
						r.reviewCursor--
					}
				case buf[0] == 'a':
					if r.reviewCursor < len(ritems) && r.st != nil {
						item := ritems[r.reviewCursor]
						ctx := context.Background()
						if item.kind == "fingerprint" {
							for i := range r.pendingReviewRules {
								if r.pendingReviewRules[i].ID == item.id {
									r.pendingReviewRules[i].Status = "active"
									_ = r.st.UpsertFingerprintRule(ctx, &r.pendingReviewRules[i])
									r.pendingReviewRules = append(r.pendingReviewRules[:i], r.pendingReviewRules[i+1:]...)
									break
								}
							}
						} else {
							for i := range r.pendingReviewSuggs {
								if r.pendingReviewSuggs[i].ID == item.suggID {
									r.pendingReviewSuggs[i].Status = "pr_opened"
									_ = r.st.UpdatePlaybookSuggestion(ctx, &r.pendingReviewSuggs[i])
									r.pendingReviewSuggs = append(r.pendingReviewSuggs[:i], r.pendingReviewSuggs[i+1:]...)
									break
								}
							}
						}
						if r.reviewCursor >= len(r.pendingReviewRules)+len(r.pendingReviewSuggs) {
							r.reviewCursor--
						}
						if r.reviewCursor < 0 {
							r.reviewCursor = 0
						}
						total := len(r.pendingReviewRules) + len(r.pendingReviewSuggs)
						if total == 0 {
							r.pendingReview = ""
						}
					}
				case buf[0] == 'x':
					if r.reviewCursor < len(ritems) && r.st != nil {
						item := ritems[r.reviewCursor]
						ctx := context.Background()
						if item.kind == "fingerprint" {
							for i := range r.pendingReviewRules {
								if r.pendingReviewRules[i].ID == item.id {
									r.pendingReviewRules[i].Status = "rejected"
									_ = r.st.UpsertFingerprintRule(ctx, &r.pendingReviewRules[i])
									r.pendingReviewRules = append(r.pendingReviewRules[:i], r.pendingReviewRules[i+1:]...)
									break
								}
							}
						} else {
							for i := range r.pendingReviewSuggs {
								if r.pendingReviewSuggs[i].ID == item.suggID {
									r.pendingReviewSuggs[i].Status = "rejected"
									_ = r.st.UpdatePlaybookSuggestion(ctx, &r.pendingReviewSuggs[i])
									r.pendingReviewSuggs = append(r.pendingReviewSuggs[:i], r.pendingReviewSuggs[i+1:]...)
									break
								}
							}
						}
						if r.reviewCursor >= len(r.pendingReviewRules)+len(r.pendingReviewSuggs) {
							r.reviewCursor--
						}
						if r.reviewCursor < 0 {
							r.reviewCursor = 0
						}
						total := len(r.pendingReviewRules) + len(r.pendingReviewSuggs)
						if total == 0 {
							r.pendingReview = ""
						}
					}
				case buf[0] == 'd':
					if r.reviewCursor < len(ritems) && r.st != nil {
						item := ritems[r.reviewCursor]
						ctx := context.Background()
						if item.kind == "fingerprint" {
							_ = r.st.DeleteFingerprintRule(ctx, item.id)
							for i := range r.pendingReviewRules {
								if r.pendingReviewRules[i].ID == item.id {
									r.pendingReviewRules = append(r.pendingReviewRules[:i], r.pendingReviewRules[i+1:]...)
									break
								}
							}
							if r.reviewCursor >= len(r.pendingReviewRules)+len(r.pendingReviewSuggs) {
								r.reviewCursor--
							}
							if r.reviewCursor < 0 {
								r.reviewCursor = 0
							}
						}
						total := len(r.pendingReviewRules) + len(r.pendingReviewSuggs)
						if total == 0 {
							r.pendingReview = ""
						}
					}
				}
			}
			r.render()
			r.mu.Unlock()
		}
	}()
}

// Handle processes one ProgressEvent from the scan pipeline. Goroutine-safe.
func (r *progressRenderer) Handle(ev module.ProgressEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()

	switch ev.Phase {
	case "discovering":
		r.phase = "discovering"
		if ev.StatusMsg != "" {
			r.statusMsg = ev.StatusMsg
			if !r.ansi {
				fmt.Fprintf(os.Stderr, "beacon: %s\n", ev.StatusMsg)
			}
		}

	case "discovery_done":
		r.total = ev.AssetsTotal
		r.phase = "scanning"
		r.findingCount = ev.FindingCount
		// Populate asset roster from the full discovered list.
		for _, name := range ev.AssetNames {
			if _, exists := r.assetIdx[name]; !exists {
				r.assetIdx[name] = len(r.assets)
				r.assets = append(r.assets, liveAsset{Name: name, Status: "queued"})
			}
		}
		if !r.ansi {
			fmt.Fprintf(os.Stderr, "beacon: discovery done — %d assets\n", r.total)
		}

	case "unconfirmed_assets", "deploy_targets":
		// Assets whose domain ownership could not be confirmed automatically.
		// Surface scans always run against these; deep scans require the operator
		// to type the permission gate phrase in the Discovered Assets panel.
		r.discoveredAssets = append(r.discoveredAssets, ev.DiscoveredAssets...)

	case "scanning":
		r.phase = "scanning"
		if ev.AssetsTotal > r.total {
			r.total = ev.AssetsTotal
		}
		r.activeAsset = ev.ActiveAsset
		r.assetStart[ev.ActiveAsset] = time.Now()
		if idx, ok := r.assetIdx[ev.ActiveAsset]; ok {
			r.assets[idx].Status = "scanning"
		} else {
			// Dynamically discovered asset (recursive scan depth > 0).
			r.assetIdx[ev.ActiveAsset] = len(r.assets)
			r.assets = append(r.assets, liveAsset{Name: ev.ActiveAsset, Status: "scanning"})
		}

	case "asset_done":
		r.done = ev.AssetsDone
		r.findingCount = ev.FindingCount
		if ev.AssetsTotal > r.total {
			r.total = ev.AssetsTotal
		}
		if t, ok := r.assetStart[r.activeAsset]; ok {
			r.durations = append(r.durations, time.Since(t))
			delete(r.assetStart, r.activeAsset)
		}
		if idx, ok := r.assetIdx[r.activeAsset]; ok {
			r.assets[idx].Status = "done"
		}
		// Clear scanner info so Line 3 doesn't show stale data between assets.
		r.activeScannerName = ""
		r.activeScannerCmd = ""
		// Remove all ops for this asset from activeOps.
		doneAsset := r.activeAsset
		for key := range r.activeOps {
			if strings.HasPrefix(key, doneAsset+"\x00") {
				delete(r.activeOps, key)
			}
		}

	case "scanner_start":
		r.activeScannerName = ev.ScannerName
		r.activeScannerCmd = ev.ScannerCmd
		if ev.ScannerName != "" && ev.ActiveAsset != "" {
			key := ev.ActiveAsset + "\x00" + ev.ScannerName
			r.activeOps[key] = ev.ScannerCmd
			r.scannerStart[key] = time.Now()
		}
		if r.verbose {
			if r.ansi {
				r.logLine(fmt.Sprintf("  %-14s  %s", ev.ScannerName, ev.ScannerCmd))
			} else {
				fmt.Fprintf(os.Stderr, "  %-14s  %s\n", ev.ScannerName, ev.ScannerCmd)
			}
		}

	case "scanner_done":
		// Accumulate ALL findings into the live pager (unfiltered). Severity
		// filtering is applied at render time so the 1-5 key toggle works
		// retroactively without losing data.
		filteredDelta := 0
		for _, f := range ev.NewFindings {
			r.findings = append(r.findings, f)
			if f.Severity >= r.minSeverity {
				filteredDelta++
			}
			if idx, ok := r.assetIdx[ev.ActiveAsset]; ok {
				r.assets[idx].sevCount[int(f.Severity)]++
			}
			// Extract port scanner discoveries (unfiltered — topology shows all services).
			if port := liveEvidenceInt(f.Evidence, "port"); port > 0 {
				if svc, ok := f.Evidence["service"].(string); ok && svc != "" {
					existing := r.topoServices[f.Asset]
					dupe := false
					for _, e := range existing {
						if e.port == port {
							dupe = true
							break
						}
					}
					if !dupe {
						r.topoServices[f.Asset] = append(existing, liveService{port: port, service: svc})
					}
				}
			}
		}
		// Update per-asset finding count using the filtered delta so the count
		// matches what is actually visible when the user drills into that asset.
		if filteredDelta > 0 {
			if idx, ok := r.assetIdx[ev.ActiveAsset]; ok {
				r.assets[idx].FindingCount += filteredDelta
			}
			if r.mode == "findings" {
				// Auto-follow only when cursor was already at the bottom.
				atBottom := r.findingsCursor >= len(r.findings)-2
				if atBottom {
					r.findingsCursor = len(r.findings) - 1
					r.findingsOff = len(r.findings)
				}
			}
		}
		// Remove this specific op from activeOps (scanner finished) and
		// record it in recentOps so the progress view can show a done log.
		if ev.ScannerName != "" && ev.ActiveAsset != "" {
			key := ev.ActiveAsset + "\x00" + ev.ScannerName
			cmd := r.activeOps[key]
			elapsed := time.Since(r.scannerStart[key]).Truncate(time.Millisecond)
			delete(r.activeOps, key)
			delete(r.scannerStart, key)
			op := recentOp{
				scanner:  ev.ScannerName,
				asset:    ev.ActiveAsset,
				cmd:      cmd,
				findings: ev.FindingDelta,
				elapsed:  elapsed,
			}
			r.recentOps = append(r.recentOps, op)
			const maxRecent = 20
			if len(r.recentOps) > maxRecent {
				r.recentOps = r.recentOps[len(r.recentOps)-maxRecent:]
			}
		}
		if r.verbose && ev.FindingDelta > 0 {
			if r.ansi {
				r.logLine(fmt.Sprintf("  %-14s  \x1b[33m+%d finding(s)\x1b[0m on %s",
					ev.ScannerName, ev.FindingDelta, ev.ActiveAsset))
			} else {
				fmt.Fprintf(os.Stderr, "  %-14s  +%d finding(s) on %s\n",
					ev.ScannerName, ev.FindingDelta, ev.ActiveAsset)
			}
		}

	case "fingerprint":
		// Accumulate evidence for live topology view.
		r.topoEvidence[ev.ActiveAsset] = ev.Evidence
		if r.verbose {
			if r.ansi {
				r.logLine(fmt.Sprintf("  \x1b[36mfingerprint\x1b[0m    %s", ev.StatusMsg))
			} else {
				fmt.Fprintf(os.Stderr, "  fingerprint    %s\n", ev.StatusMsg)
			}
		}
	}

	if r.ansi {
		r.render()
	}
}

// logLine emits a persistent log line above the status block.
// Caller must hold r.mu.
func (r *progressRenderer) logLine(line string) {
	var buf strings.Builder
	if r.drawn && r.drawnLines > 0 {
		fmt.Fprintf(&buf, "\x1b[%dA", r.drawnLines)
		for i := 0; i < r.drawnLines; i++ {
			buf.WriteString("\x1b[2K\n")
		}
		fmt.Fprintf(&buf, "\x1b[%dA", r.drawnLines)
	}
	fmt.Fprintf(&buf, "\x1b[2K\r%s\n", line)
	os.Stderr.WriteString(buf.String())
	r.drawn = false
	r.drawnLines = 0
}

// eraseBlock moves the cursor to the top of the drawn status block and clears
// all lines. Caller must hold r.mu.
func (r *progressRenderer) eraseBlock() {
	if r.drawnLines == 0 {
		return
	}
	var buf strings.Builder
	fmt.Fprintf(&buf, "\x1b[%dA", r.drawnLines)
	for i := 0; i < r.drawnLines; i++ {
		buf.WriteString("\x1b[2K\n")
	}
	fmt.Fprintf(&buf, "\x1b[%dA", r.drawnLines)
	os.Stderr.WriteString(buf.String())
}

// render draws (or redraws) the status block in a single write to avoid
// partial-frame flicker. Caller must hold r.mu.
// navigateBack moves the renderer one level up in the view hierarchy.
// Caller must hold r.mu.
func (r *progressRenderer) navigateBack() {
	switch r.mode {
	case "finding_detail":
		if r.findingDetailOrigin != "" {
			r.mode = r.findingDetailOrigin
		} else {
			r.mode = "findings"
		}
		r.selectedFinding = nil
	case "asset_detail":
		r.mode = "assets"
		r.selectedAsset = ""
	case "topo_detail":
		r.mode = "topology"
	case "findings", "assets", "topology":
		r.mode = "progress"
	case "review":
		r.mode = "progress"
	default:
		r.mode = "progress"
	}
}

func (r *progressRenderer) render() {
	var buf strings.Builder

	if r.headless {
		// When managed by the browse TUI we own the full alternate screen, so
		// use the same home+clear approach as browseRender() instead of inline
		// cursor movement. This makes the attached view look identical to the
		// standalone scan view.
		buf.WriteString("\x1b[H\x1b[2J")
	} else if r.drawnLines > 0 {
		// Move cursor up to the start of the previous block and clear everything
		// below — handles mode switches where new content may be shorter than old.
		fmt.Fprintf(&buf, "\x1b[%dA\x1b[J", r.drawnLines)
	}

	var lines int
	switch r.mode {
	case "findings":
		lines = r.renderFindingsPager(&buf)
	case "assets":
		lines = r.renderAssets(&buf)
	case "asset_detail":
		lines = r.renderAssetDetail(&buf)
	case "finding_detail":
		lines = r.renderFindingDetail(&buf)
	case "topology":
		lines = r.renderTopology(&buf)
	case "topo_detail":
		lines = r.renderTopoDetail(&buf)
	case "discovered":
		lines = r.renderDiscovered(&buf)
	case "discovered_detail":
		lines = r.renderDiscoveredDetail(&buf)
	case "review":
		lines = r.renderReview(&buf)
	default:
		lines = r.renderProgress(&buf)
	}

	os.Stderr.WriteString(buf.String())
	r.drawn = true
	r.drawnLines = lines
}

// renderProgress writes the progress block into buf.
// Uses the full terminal height: 2 header lines, then active ops, then
// recently-completed ops to fill remaining space.
// Returns the total number of lines written.
// Caller must hold r.mu.
func (r *progressRenderer) renderProgress(buf *strings.Builder) int {
	termW, termH, err := term.GetSize(int(os.Stderr.Fd()))
	if err != nil || termW < 40 {
		termW = 120
	}
	if err != nil || termH < 6 {
		termH = 24
	}

	elapsed := time.Since(r.start).Truncate(time.Second)

	// Line 1: bar + % + elapsed + ETA  (or discovering status)
	if r.phase == "discovering" {
		elapsedStr := fmtElapsed(elapsed)
		// Reserve space for "  discovering  " prefix (15) + "  elapsed Xs" suffix (12+len)
		// Use as much of the terminal width as possible for the message.
		suffix := "  elapsed " + elapsedStr
		prefix := "  \x1b[34mdiscovering\x1b[0m  "
		// Visible prefix length (no ANSI codes): 2 + len("discovering") + 2 = 15
		msgMax := termW - 15 - len(suffix)
		if msgMax < 10 {
			msgMax = 10
		}
		msg := r.statusMsg
		if len(msg) > msgMax {
			msg = "…" + msg[len(msg)-msgMax+1:]
		}
		fmt.Fprintf(buf, "\x1b[2K\r%s%-*s%s\n", prefix, msgMax, msg, suffix)
	} else {
		const barWidth = 32
		pct := 0.0
		if r.total > 0 {
			pct = float64(r.done) / float64(r.total)
		}
		filled := int(pct * float64(barWidth))
		if filled > barWidth {
			filled = barWidth
		}
		bar := "\x1b[32m" + strings.Repeat("█", filled) + "\x1b[90m" +
			strings.Repeat("░", barWidth-filled) + "\x1b[0m"
		eta := r.eta()
		runningCount := len(r.activeOps)
		doneCount := len(r.recentOps)
		statusStr := fmt.Sprintf("\x1b[33m%d running\x1b[0m \x1b[90m·\x1b[0m \x1b[32m%d done\x1b[0m", runningCount, doneCount)
		fmt.Fprintf(buf, "\x1b[2K\r  %s  \x1b[1m%3.0f%%\x1b[0m   %s   ETA \x1b[33m%s\x1b[0m\n",
			bar, pct*100, statusStr, fmtETA(eta))
	}

	// Line 2: asset count + findings + nav hints (or exit confirm).
	// Count findings at or above the active severity filter for accurate display.
	visFindings := 0
	for _, f := range r.findings {
		if f.Severity >= r.minSeverity {
			visFindings++
		}
	}
	findingsLabel := fmt.Sprintf("\x1b[1m%d findings\x1b[0m", visFindings)
	if visFindings < len(r.findings) {
		findingsLabel = fmt.Sprintf("\x1b[1m%d\x1b[0m\x1b[90m/%d\x1b[0m \x1b[1mfindings\x1b[0m \x1b[33m[sev≥%s]\x1b[0m", visFindings, len(r.findings), r.minSeverity.String())
	}
	sevHint := "\x1b[90m[1-5] sev  \x1b[0m"
	if r.confirmingExit {
		fmt.Fprintf(buf, "\x1b[2K\r  %d / %d assets   %s   \x1b[1;31mStop scan? [y] yes  [n] no\x1b[0m\n",
			r.done, r.total, findingsLabel)
	} else if r.phase == "done" {
		reviewHint := ""
		if r.pendingReview != "" {
			reviewHint = "  \x1b[33m" + r.pendingReview + "\x1b[0m  \x1b[90m[r] review\x1b[0m"
		}
		discoveredHint := ""
		if len(r.discoveredAssets) > 0 {
			discoveredHint = fmt.Sprintf("  [d] discovered (%d)", len(r.discoveredAssets))
		}
		fmt.Fprintf(buf, "\x1b[2K\r  %d assets   %s   \x1b[90m%s[f] findings  [a] assets  [t] topology%s  [e] export  [q/b] back\x1b[0m%s\n",
			r.total, findingsLabel, sevHint, discoveredHint, reviewHint)
	} else if r.phase == "discovering" {
		// Asset list is not yet known — show findings count without misleading "0 / 0 assets".
		fmt.Fprintf(buf, "\x1b[2K\r  \x1b[34mdiscovering assets\x1b[0m   %s   \x1b[90m%s[f] findings  [q/b] detach  [s] stop\x1b[0m\n",
			findingsLabel, sevHint)
	} else {
		discoveredHint := ""
		if len(r.discoveredAssets) > 0 {
			discoveredHint = fmt.Sprintf("  [d] discovered (%d)", len(r.discoveredAssets))
		}
		fmt.Fprintf(buf, "\x1b[2K\r  %d / %d assets   %s   \x1b[90m%s[f] findings  [a] assets  [t] topology%s  [q/b] detach  [s] stop\x1b[0m\n",
			r.done, r.total, findingsLabel, sevHint, discoveredHint)
	}
	lineCount := 2

	// Spinner frame based on wall clock (updates each render tick).
	spinChars := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	spinFrame := int(time.Now().UnixMilli()/120) % len(spinChars)

	// Collect active ops and sort stably: by asset then scanner name.
	type activeOp struct {
		scanner string
		asset   string
		cmd     string
		elapsed time.Duration
	}
	var ops []activeOp
	for key, cmd := range r.activeOps {
		if idx := strings.IndexByte(key, '\x00'); idx >= 0 {
			elapsed := time.Duration(0)
			if start, ok := r.scannerStart[key]; ok {
				elapsed = time.Since(start).Truncate(time.Second)
			}
			ops = append(ops, activeOp{
				asset:   key[:idx],
				scanner: key[idx+1:],
				cmd:     cmd,
				elapsed: elapsed,
			})
		}
	}
	for i := 1; i < len(ops); i++ {
		for j := i; j > 0; j-- {
			a, b := ops[j-1], ops[j]
			if a.asset > b.asset || (a.asset == b.asset && a.scanner > b.scanner) {
				ops[j-1], ops[j] = ops[j], ops[j-1]
			}
		}
	}

	// How many lines are available below the 2 header lines?
	// Leave 1 blank line at bottom so the terminal doesn't scroll.
	available := termH - lineCount - 1
	if available < 1 {
		available = 1
	}

	// Column widths: scanner(12) + asset(dynamic) + cmd(rest), 2-char margins.
	// Layout: "  ↳  scanner     asset          cmd...\n"
	// Fixed visible chars: 2(indent) + 1(↳) + 2(spaces) + 12(scanner) + 2(spaces) = 19
	// Asset column scales with terminal: wider terminals show more of the asset name.
	const scannerW = 12
	assetW := termW/4
	if assetW < 30 {
		assetW = 30
	}
	if assetW > 55 {
		assetW = 55
	}
	cmdW := termW - 5 - scannerW - 2 - assetW - 2
	if cmdW < 20 {
		cmdW = 20
	}

	// Build a unified display: running ops first (sorted), then recently completed (newest first).
	// Each entry has a status tag so we can render them differently.
	type displayOp struct {
		scanner  string
		asset    string
		cmd      string
		elapsed  time.Duration
		running  bool
		findings int
	}
	var displayOps []displayOp
	for _, op := range ops {
		displayOps = append(displayOps, displayOp{
			scanner: op.scanner,
			asset:   op.asset,
			cmd:     op.cmd,
			elapsed: op.elapsed,
			running: true,
		})
	}
	// Append recently completed, newest first.
	recent := r.recentOps
	for i := len(recent) - 1; i >= 0; i-- {
		op := recent[i]
		displayOps = append(displayOps, displayOp{
			scanner:  op.scanner,
			asset:    op.asset,
			cmd:      op.cmd,
			elapsed:  op.elapsed,
			running:  false,
			findings: op.findings,
		})
	}

	shown := len(displayOps)
	if shown > available {
		shown = available
	}
	for _, op := range displayOps[:shown] {
		asset := op.asset
		if len(asset) > assetW {
			asset = "…" + asset[len(asset)-assetW+1:]
		}
		elapsedFmt := fmtElapsed(op.elapsed)
		if op.running {
			// Running: yellow spinner, live elapsed in brackets
			elapsedStr := fmt.Sprintf("  \x1b[33m[%s]\x1b[0m", elapsedFmt)
			elapsedVisible := 2 + 1 + len(elapsedFmt) + 1
			cmdAvail := cmdW - elapsedVisible
			if cmdAvail < 10 {
				cmdAvail = 10
			}
			cmd := op.cmd
			if len(cmd) > cmdAvail {
				cmd = cmd[:cmdAvail-1] + "…"
			}
			spin := spinChars[spinFrame]
			fmt.Fprintf(buf, "\x1b[2K\r  \x1b[33m%s\x1b[0m  \x1b[36m%-*s\x1b[0m  %-*s  \x1b[90m%s\x1b[0m%s\n",
				spin, scannerW, op.scanner, assetW, asset, cmd, elapsedStr)
		} else {
			// Done: green checkmark, fixed elapsed in gray, +N findings in yellow.
			findStr := ""
			if op.findings > 0 {
				findStr = fmt.Sprintf("  \x1b[33m+%d\x1b[0m", op.findings)
			}
			cmd := op.cmd
			if len(cmd) > cmdW {
				cmd = cmd[:cmdW-1] + "…"
			}
			fmt.Fprintf(buf, "\x1b[2K\r  \x1b[32m✓\x1b[0m  \x1b[90m%-*s  %-*s  %s\x1b[0m%s  \x1b[90m%s\x1b[0m\n",
				scannerW, op.scanner, assetW, asset, cmd, findStr, elapsedFmt)
		}
		lineCount++
	}

	if shown == 0 {
		// No active ops and no recent history yet — show a blank placeholder.
		buf.WriteString("\x1b[2K\r\n")
		lineCount++
	}

	return lineCount
}

// renderFindingsPager writes a scrollable findings list into buf and returns
// the number of lines written. Caller must hold r.mu.
func (r *progressRenderer) renderFindingsPager(buf *strings.Builder) int {
	termW, termH, err := term.GetSize(int(os.Stderr.Fd()))
	if err != nil || termW < 40 {
		termW = 120
	}
	if err != nil || termH < 5 {
		termH = 24
	}
	// Reserve 2 lines for header + footer.
	bodyLines := termH - 2
	if bodyLines < 1 {
		bodyLines = 1
	}

	// Apply filter: build a filtered view of findings (severity + text filter),
	// sorted by severity (Critical first). Store in r.filteredFindings so the
	// key handler can look up the correct finding on Enter.
	// Apply user severity overrides before filtering so bumped-down findings
	// disappear when they fall below minSeverity.
	type indexedFinding struct {
		f   finding.Finding
		idx int // original index in r.findings
	}
	var indexed []indexedFinding
	needle := strings.ToLower(r.findingFilter)
	for i, f := range r.findings {
		if ov, ok := r.severityOverrides[i]; ok {
			f.Severity = ov
		}
		if f.Severity < r.minSeverity {
			continue
		}
		if needle != "" {
			haystack := strings.ToLower(f.Title + f.Asset + string(f.CheckID))
			if !strings.Contains(haystack, needle) {
				continue
			}
		}
		indexed = append(indexed, indexedFinding{f: f, idx: i})
	}
	// Sort descending by severity so Critical appears first.
	sort.Slice(indexed, func(i, j int) bool {
		return indexed[i].f.Severity > indexed[j].f.Severity
	})
	filtered := make([]finding.Finding, len(indexed))
	filteredIdx := make([]int, len(indexed))
	for i, x := range indexed {
		filtered[i] = x.f
		filteredIdx[i] = x.idx
	}
	r.filteredFindings = filtered
	r.filteredFindingsIdx = filteredIdx

	// Build visual rows: inject a severity-group header at each boundary.
	var rows []findingsRow
	lastSev := finding.Severity(-1)
	for i, f := range filtered {
		if f.Severity != lastSev {
			rows = append(rows, findingsRow{isHeader: true, severity: f.Severity})
			lastSev = f.Severity
		}
		rows = append(rows, findingsRow{idx: i})
	}
	r.findingsRows = rows
	total := len(rows)

	// Clamp cursor and ensure it lands on a finding row, not a header.
	if total == 0 {
		r.findingsCursor = 0
	} else {
		if r.findingsCursor >= total {
			r.findingsCursor = total - 1
		} else if r.findingsCursor < 0 {
			r.findingsCursor = 0
		}
		// Advance past any header at current position.
		for r.findingsCursor < total && rows[r.findingsCursor].isHeader {
			r.findingsCursor++
		}
		if r.findingsCursor >= total {
			// Fell off end — step back to last finding row.
			r.findingsCursor = total - 1
			for r.findingsCursor > 0 && rows[r.findingsCursor].isHeader {
				r.findingsCursor--
			}
		}
	}

	// Keep scroll window centered on cursor.
	if r.findingsCursor < r.findingsOff {
		r.findingsOff = r.findingsCursor
	}
	if r.findingsCursor >= r.findingsOff+bodyLines {
		r.findingsOff = r.findingsCursor - bodyLines + 1
	}

	// Clamp scroll offset.
	maxOff := total - bodyLines
	if maxOff < 0 {
		maxOff = 0
	}
	if r.findingsOff > maxOff {
		r.findingsOff = maxOff
	}
	if r.findingsOff < 0 {
		r.findingsOff = 0
	}
	off := r.findingsOff
	end := off + bodyLines
	if end > total {
		end = total
	}

	lineCount := 0

	// Build severity selector shown in header — always visible so user knows
	// why findings might be hidden and how to change it.
	// Format: [1]all [2]low [3]med [4]high [5]crit  with current level highlighted.
	sevNames := []string{"all", "low+", "med+", "high+", "crit"}
	var sevParts []string
	for i, name := range sevNames {
		key := i + 1
		sev := finding.Severity(i) // SeverityInfo=0 → key 1, etc.
		if sev == r.minSeverity {
			sevParts = append(sevParts, fmt.Sprintf("\x1b[0m\x1b[1;33m[%d]%s\x1b[0m\x1b[90m", key, name))
		} else {
			sevParts = append(sevParts, fmt.Sprintf("[%d]%s", key, name))
		}
	}
	sevSelector := "\x1b[90m" + strings.Join(sevParts, " ") + "\x1b[0m"

	// Count real findings (non-header rows) for display.
	nFindings := len(filtered)
	totalFindings := len(r.findings)

	// Header — hints change depending on filter state.
	if r.findingFilterMode {
		fmt.Fprintf(buf, "\x1b[2K\r  \x1b[1;36mLive Findings\x1b[0m  %s  \x1b[90m[↵] open  [j/k] scroll  [f/q] back  %d/%d\x1b[0m\n", sevSelector, nFindings, totalFindings)
	} else if r.findingFilter != "" {
		fmt.Fprintf(buf, "\x1b[2K\r  \x1b[1;36mLive Findings\x1b[0m  %s  \x1b[90m[↵] open  [j/k] scroll  [[] sev  [/] filter: %s  [Esc] clear  [f/q] back  %d/%d\x1b[0m\n", sevSelector, r.findingFilter, nFindings, totalFindings)
	} else {
		fmt.Fprintf(buf, "\x1b[2K\r  \x1b[1;36mLive Findings\x1b[0m  %s  \x1b[90m[↵] open  [j/k] scroll  [[] sev  [/] filter  [f/q] back  %d/%d\x1b[0m\n", sevSelector, nFindings, totalFindings)
	}
	lineCount++

	// Visual rows: headers and finding rows interleaved.
	for i := off; i < end; i++ {
		row := rows[i]
		if row.isHeader {
			col := severityColor(row.severity)
			label := strings.ToUpper(row.severity.String())
			fmt.Fprintf(buf, "\x1b[2K\r  %s── %s ──\x1b[0m\n", col, label)
		} else {
			f := filtered[row.idx]
			col := severityColor(f.Severity)
			sev := strings.ToUpper(f.Severity.String())
			if len(sev) > 4 {
				sev = sev[:4]
			}
			asset := f.Asset
			if len(asset) > 30 {
				asset = "…" + asset[len(asset)-29:]
			}
			// Mark findings with a user-adjusted severity with a small indicator.
			overrideMarker := ""
			if _, ok := r.severityOverrides[filteredIdx[row.idx]]; ok {
				overrideMarker = "\x1b[90m*\x1b[0m"
			}
			// Fingerprint badge — compact tech label from asset evidence.
			// Appends ~AI when the classification was AI-inferred (not deterministic).
			badge := ""
			if ev, ok := r.topoEvidence[f.Asset]; ok {
				b := fingerprintBadge(ev)
				if strings.HasPrefix(ev.ClassificationSource, "ai:") {
					if b != "" {
						b += "~AI"
					} else {
						b = "AI"
					}
				}
				if b != "" {
					badge = " \x1b[90m[" + b + "]\x1b[0m"
				}
			}
			// Layout: 2(indent) + 4(sev) + 2(gap) + 30(asset) + 2(gap) = 40 fixed chars.
			// Badge is appended after title (no fixed width — it wraps to ANSI reset).
			titleMax := termW - 40
			if badge != "" {
				// Reserve space for badge (strip ANSI codes from length estimate).
				// fingerprintBadge max = 20 chars + " [" + "]" = 24 visible.
				titleMax -= 24
			}
			if titleMax < 20 {
				titleMax = 20
			}
			title := f.Title
			if len(title) > titleMax {
				title = title[:titleMax-1] + "…"
			}
			if i == r.findingsCursor {
				fmt.Fprintf(buf, "\x1b[2K\r\x1b[7m  %s%-4s\x1b[0m\x1b[7m  %-30s  %s\x1b[0m%s%s\n", col, sev, asset, title, badge, overrideMarker)
			} else {
				fmt.Fprintf(buf, "\x1b[2K\r  %s%-4s\x1b[0m  %-30s  %s%s%s\n", col, sev, asset, title, badge, overrideMarker)
			}
		}
		lineCount++
	}

	// Pad remaining rows so the block height is stable.
	for i := (end - off); i < bodyLines; i++ {
		buf.WriteString("\x1b[2K\r\n")
		lineCount++
	}

	// Footer — show filter input prompt when in filter mode.
	if r.findingFilterMode {
		fmt.Fprintf(buf, "\x1b[2K\r  /filter: \x1b[1m%s\x1b[0m_\n", r.findingFilter)
	} else if total == 0 {
		if r.phase == "done" {
			fmt.Fprintf(buf, "\x1b[2K\r  \x1b[90mNo findings\x1b[0m\n")
		} else {
			fmt.Fprintf(buf, "\x1b[2K\r  \x1b[90mNo findings yet — scan is still running\x1b[0m\n")
		}
	} else {
		fmt.Fprintf(buf, "\x1b[2K\r  \x1b[90m%d of %d\x1b[0m\n", r.findingsCursor+1, total)
	}
	lineCount++

	return lineCount
}

// renderAssets writes a scrollable asset roster into buf and returns the line count.
// Caller must hold r.mu.
func (r *progressRenderer) renderAssets(buf *strings.Builder) int {
	_, termH, err := term.GetSize(int(os.Stderr.Fd()))
	if err != nil || termH < 5 {
		termH = 24
	}
	bodyLines := termH - 2
	if bodyLines < 1 {
		bodyLines = 1
	}

	total := len(r.assets)

	// Clamp cursor.
	if total == 0 {
		r.assetsCursor = 0
	} else {
		if r.assetsCursor >= total {
			r.assetsCursor = total - 1
		}
		if r.assetsCursor < 0 {
			r.assetsCursor = 0
		}
	}

	// Scroll offset follows cursor.
	if r.assetsCursor < r.assetsOff {
		r.assetsOff = r.assetsCursor
	}
	if r.assetsCursor >= r.assetsOff+bodyLines {
		r.assetsOff = r.assetsCursor - bodyLines + 1
	}

	off := r.assetsOff
	end := off + bodyLines
	if end > total {
		end = total
	}

	lineCount := 0

	// Header
	fmt.Fprintf(buf, "\x1b[2K\r  \x1b[1;36mAssets\x1b[0m  \x1b[90m[a/q] progress  [j/k ↑↓] move  [↵] view findings  %d assets\x1b[0m\n", total)
	lineCount++

	for i := off; i < end; i++ {
		a := r.assets[i]

		cursor := "  "
		if i == r.assetsCursor {
			cursor = "\x1b[1;33m▶\x1b[0m "
		}

		var icon string
		switch a.Status {
		case "done":
			icon = "\x1b[32m✓\x1b[0m"
		case "scanning":
			icon = "\x1b[33m●\x1b[0m"
		default:
			icon = "\x1b[90m○\x1b[0m"
		}

		name := a.Name
		if len(name) > 42 {
			name = "…" + name[len(name)-41:]
		}

		var countStr string
		if a.FindingCount > 0 {
			// Build compact severity bar: e.g. "3C 2H 1M"
			sevColors := [5]string{"\x1b[90m", "\x1b[90m", "\x1b[37m", "\x1b[33m", "\x1b[31m"}
			sevLetters := [5]string{"I", "L", "M", "H", "C"}
			var parts []string
			for si := 4; si >= 0; si-- {
				if a.sevCount[si] > 0 {
					parts = append(parts, fmt.Sprintf("%s%d%s\x1b[0m", sevColors[si], a.sevCount[si], sevLetters[si]))
				}
			}
			countStr = strings.Join(parts, " ")
		} else if a.Status == "done" {
			countStr = "\x1b[32mclean\x1b[0m"
		}

		fmt.Fprintf(buf, "\x1b[2K\r %s%s  %-42s  %s\n", cursor, icon, name, countStr)
		lineCount++
	}

	// Pad remaining rows so block height is stable.
	for i := end - off; i < bodyLines; i++ {
		buf.WriteString("\x1b[2K\r\n")
		lineCount++
	}

	// Footer
	if total == 0 {
		fmt.Fprintf(buf, "\x1b[2K\r  \x1b[90mDiscovering assets…\x1b[0m\n")
	} else {
		fmt.Fprintf(buf, "\x1b[2K\r  \x1b[90m%d–%d of %d assets\x1b[0m\n", off+1, end, total)
	}
	lineCount++

	return lineCount
}

// renderAssetDetail writes a per-asset findings pager into buf and returns the line count.
// Shows an asset info panel (IP, tech, ports) at the top, then a cursor-navigable
// list of findings. Press Enter on a finding to open finding_detail mode.
// Caller must hold r.mu.
func (r *progressRenderer) renderAssetDetail(buf *strings.Builder) int {
	_, termH, err := term.GetSize(int(os.Stderr.Fd()))
	if err != nil || termH < 5 {
		termH = 24
	}

	// Collect findings for the selected asset.
	var af []finding.Finding
	for _, f := range r.findings {
		if f.Asset == r.selectedAsset {
			af = append(af, f)
		}
	}
	sort.Slice(af, func(i, j int) bool {
		if af[i].Severity != af[j].Severity {
			return af[i].Severity > af[j].Severity
		}
		return string(af[i].CheckID) < string(af[j].CheckID)
	})

	// Clamp cursor.
	if r.assetDetailCursor >= len(af) && len(af) > 0 {
		r.assetDetailCursor = len(af) - 1
	}
	if r.assetDetailCursor < 0 {
		r.assetDetailCursor = 0
	}

	// --- Asset info panel (always shown, 2-4 lines) ---
	lineCount := 0
	name := r.selectedAsset
	if len(name) > 50 {
		name = "\u2026" + name[len(name)-49:]
	}
	fmt.Fprintf(buf, "\x1b[2K\r  \x1b[90m\u25c0\x1b[0m \x1b[1;36m%s\x1b[0m  \x1b[90m[q/b] back  [j/k] move  [Enter] detail\x1b[0m\n", name)
	lineCount++

	// Network info line from fingerprint evidence.
	if ev, ok := r.topoEvidence[r.selectedAsset]; ok {
		var infoParts []string
		if ev.IP != "" {
			infoParts = append(infoParts, "IP: "+ev.IP)
		}
		if ev.ASNOrg != "" {
			org := ev.ASNOrg
			if len(org) > 20 {
				org = org[:19] + "\u2026"
			}
			infoParts = append(infoParts, "ASN: "+org)
		}
		if ev.StatusCode > 0 {
			infoParts = append(infoParts, fmt.Sprintf("HTTP %d", ev.StatusCode))
		}
		if ws := ev.ServiceVersions["web_server"]; ws != "" {
			if i := strings.IndexAny(ws, "/ "); i > 0 {
				ws = ws[:i]
			}
			infoParts = append(infoParts, ws)
		}
		if len(ev.CNAMEChain) > 0 {
			cn := ev.CNAMEChain[0]
			if len(cn) > 30 {
				cn = "\u2026" + cn[len(cn)-29:]
			}
			infoParts = append(infoParts, "\u2192 "+cn)
		}
		if len(infoParts) > 0 {
			fmt.Fprintf(buf, "\x1b[2K\r  \x1b[90m%s\x1b[0m\n", strings.Join(infoParts, "  "))
			lineCount++
		}
		// Open ports/services line.
		if svcs := r.topoServices[r.selectedAsset]; len(svcs) > 0 {
			var svcParts []string
			for _, sv := range svcs {
				svcParts = append(svcParts, fmt.Sprintf("%s:%d", sv.service, sv.port))
			}
			fmt.Fprintf(buf, "\x1b[2K\r  \x1b[90mports: %s\x1b[0m\n", strings.Join(svcParts, "  "))
			lineCount++
		}
		// Tech stack (framework, auth system, cloud, proxy).
		var techParts []string
		if ev.Framework != "" {
			techParts = append(techParts, ev.Framework)
		}
		if ev.CloudProvider != "" {
			techParts = append(techParts, ev.CloudProvider)
		}
		if ev.AuthSystem != "" {
			techParts = append(techParts, "\x1b[90mauth:\x1b[0m"+ev.AuthSystem)
		}
		if ev.ProxyType != "" {
			techParts = append(techParts, "\x1b[90mproxy:\x1b[0m"+ev.ProxyType)
		}
		if len(techParts) > 0 {
			fmt.Fprintf(buf, "\x1b[2K\r  \x1b[90mtech: \x1b[0m%s\n", strings.Join(techParts, "  "))
			lineCount++
		}
		// Responding paths — show all paths that returned a success response.
		if len(ev.RespondingPaths) > 0 {
			const pathCols = 2
			const maxPathRows = 5
			paths := ev.RespondingPaths
			overflow := 0
			maxShown := pathCols * maxPathRows
			if len(paths) > maxShown {
				overflow = len(paths) - maxShown
				paths = paths[:maxShown]
			}
			fmt.Fprintf(buf, "\x1b[2K\r  \x1b[90mpaths:\x1b[0m\n")
			lineCount++
			for i := 0; i < len(paths); i += pathCols {
				end := i + pathCols
				if end > len(paths) {
					end = len(paths)
				}
				var cols []string
				for _, p := range paths[i:end] {
					if len(p) > 34 {
						p = p[:33] + "\u2026"
					}
					cols = append(cols, fmt.Sprintf("\x1b[36m%-35s\x1b[0m", p))
				}
				fmt.Fprintf(buf, "\x1b[2K\r    %s\n", strings.Join(cols, "  "))
				lineCount++
			}
			if overflow > 0 {
				fmt.Fprintf(buf, "\x1b[2K\r    \x1b[90m... +%d more paths\x1b[0m\n", overflow)
				lineCount++
			}
		}
	}
	// Separator between asset info and findings list.
	fmt.Fprintf(buf, "\x1b[2K\r  \x1b[90m%s\x1b[0m\n", strings.Repeat("\u2500", 70))
	lineCount++

	// --- Findings list ---
	total := len(af)
	bodyLines := termH - lineCount - 1 // reserve 1 for footer
	if bodyLines < 1 {
		bodyLines = 1
	}

	// Keep cursor visible: adjust scroll so cursor row is always in view.
	if r.assetDetailCursor < r.assetDetailOff {
		r.assetDetailOff = r.assetDetailCursor
	}
	if r.assetDetailCursor >= r.assetDetailOff+bodyLines {
		r.assetDetailOff = r.assetDetailCursor - bodyLines + 1
	}
	maxOff := total - bodyLines
	if maxOff < 0 {
		maxOff = 0
	}
	if r.assetDetailOff > maxOff {
		r.assetDetailOff = maxOff
	}
	if r.assetDetailOff < 0 {
		r.assetDetailOff = 0
	}
	off := r.assetDetailOff
	end := off + bodyLines
	if end > total {
		end = total
	}

	for i := off; i < end; i++ {
		f := af[i]
		col := severityColor(f.Severity)
		sev := strings.ToUpper(f.Severity.String())
		if len(sev) > 4 {
			sev = sev[:4]
		}
		title := f.Title
		if len(title) > 44 {
			title = title[:43] + "\u2026"
		}
		checkID := string(f.CheckID)
		if len(checkID) > 26 {
			checkID = checkID[:25] + "\u2026"
		}
		cursor := "  "
		if i == r.assetDetailCursor {
			cursor = "\x1b[1;33m\u25b6\x1b[0m "
		}
		fmt.Fprintf(buf, "\x1b[2K\r%s%s%-4s\x1b[0m  %-44s  \x1b[90m%s\x1b[0m\n", cursor, col, sev, title, checkID)
		lineCount++
	}

	// Pad remaining body rows.
	for i := end - off; i < bodyLines; i++ {
		buf.WriteString("\x1b[2K\r\n")
		lineCount++
	}

	// Footer
	if total == 0 {
		fmt.Fprintf(buf, "\x1b[2K\r  \x1b[90mNo findings for this asset\x1b[0m\n")
	} else {
		fmt.Fprintf(buf, "\x1b[2K\r  \x1b[90m%d of %d findings\x1b[0m\n", r.assetDetailCursor+1, total)
	}
	lineCount++

	return lineCount
}

// renderFindingDetail writes a full finding detail view into buf and returns the line count.
// Shows asset info, finding metadata, description, and all evidence fields.
// Caller must hold r.mu.
func (r *progressRenderer) renderFindingDetail(buf *strings.Builder) int {
	termW, termH, err := term.GetSize(int(os.Stderr.Fd()))
	if err != nil || termH < 5 {
		termH = 24
	}
	if err != nil || termW < 40 {
		termW = 120
	}
	wrapWidth := termW - 4
	if wrapWidth < 20 {
		wrapWidth = 20
	}
	if wrapWidth > 100 {
		wrapWidth = 100
	}

	if r.selectedFinding == nil {
		r.mode = "asset_detail"
		return r.renderAssetDetail(buf)
	}
	f := r.selectedFinding

	// Build all content lines upfront so we can scroll them.
	var lines []string

	// Severity + title
	col := severityColor(f.Severity)
	sev := strings.ToUpper(f.Severity.String())
	title := f.Title
	lines = append(lines, fmt.Sprintf("  %s\x1b[1m[%s]\x1b[0m %s", col, sev, title))

	// Metadata
	lines = append(lines, fmt.Sprintf("  \x1b[90mAsset:    \x1b[0m%s", f.Asset))
	lines = append(lines, fmt.Sprintf("  \x1b[90mCheck:    \x1b[0m%s", string(f.CheckID)))
	lines = append(lines, fmt.Sprintf("  \x1b[90mScanner:  \x1b[0m%s", f.Scanner))
	if !f.DiscoveredAt.IsZero() {
		lines = append(lines, fmt.Sprintf("  \x1b[90mFound:    \x1b[0m%s", f.DiscoveredAt.Format("2006-01-02 15:04")))
	}

	// Service Fingerprint — technology stack classified for this asset.
	if ev, ok := r.topoEvidence[f.Asset]; ok {
		var fpLines []string
		if ev.ProxyType != "" {
			fpLines = append(fpLines, fmt.Sprintf("  \x1b[90m%-16s\x1b[0m%s", "Proxy/Server:", ev.ProxyType))
		}
		if ev.CloudProvider != "" {
			fpLines = append(fpLines, fmt.Sprintf("  \x1b[90m%-16s\x1b[0m%s", "Cloud:", ev.CloudProvider))
		}
		if ev.InfraLayer != "" {
			fpLines = append(fpLines, fmt.Sprintf("  \x1b[90m%-16s\x1b[0m%s", "Infra Layer:", ev.InfraLayer))
		}
		if ev.Framework != "" {
			fpLines = append(fpLines, fmt.Sprintf("  \x1b[90m%-16s\x1b[0m%s", "Framework:", ev.Framework))
		}
		if sv := ev.Headers["server"]; sv != "" {
			fpLines = append(fpLines, fmt.Sprintf("  \x1b[90m%-16s\x1b[0m%s", "Server Header:", sv))
		}
		if len(ev.BackendServices) > 0 {
			fpLines = append(fpLines, fmt.Sprintf("  \x1b[90m%-16s\x1b[0m%s", "Backends:", strings.Join(ev.BackendServices, ", ")))
		}
		if ev.IsReverseProxy {
			fpLines = append(fpLines, fmt.Sprintf("  \x1b[90m%-16s\x1b[0m%s", "Topology:", "reverse proxy detected"))
		}
		if ev.IsKubernetes {
			fpLines = append(fpLines, fmt.Sprintf("  \x1b[90m%-16s\x1b[0m%s", "Topology:", "kubernetes"))
		}
		if ev.ClassificationSource != "" && strings.HasPrefix(ev.ClassificationSource, "ai:") {
			confidence := strings.TrimPrefix(ev.ClassificationSource, "ai:")
			fpLines = append(fpLines, fmt.Sprintf("  \x1b[90m%-16s\x1b[0m\x1b[33m[AI]\x1b[0m classified (%s confidence) — verify via `beacon fingerprints`", "Source:", confidence))
		}
		if len(fpLines) > 0 {
			lines = append(lines, "  \x1b[1mService Fingerprint\x1b[0m")
			lines = append(lines, fpLines...)
		}
	}
	lines = append(lines, "")

	// Description
	if f.Description != "" {
		lines = append(lines, "  \x1b[1mDescription\x1b[0m")
		for _, ln := range wordWrapLines(f.Description, wrapWidth) {
			lines = append(lines, "  "+ln)
		}
		lines = append(lines, "")
	}

	// Proof command — copy-paste to reproduce in terminal.
	// Prefer the scanner-set command; fall back to the registry in verify.go.
	proofCmd := f.ProofCommand
	if proofCmd == "" {
		proofCmd = report.VerifyCmd(f.CheckID, f.Asset)
	}
	if proofCmd != "" {
		lines = append(lines, "  \x1b[1mProof Command\x1b[0m  \x1b[90m([y] to copy)\x1b[0m")
		lines = append(lines, "  \x1b[90mRun this in your terminal to confirm the finding:\x1b[0m")
		// Wrap long commands at natural word boundaries (flags, pipes, --flags).
		for _, cmdLine := range wordWrapAtShellBoundaries(proofCmd, wrapWidth) {
			lines = append(lines, fmt.Sprintf("  \x1b[36m%s\x1b[0m", cmdLine))
		}
		lines = append(lines, "")
	}

	// Evidence — separate "WHERE FOUND" keys from the rest.
	if len(f.Evidence) > 0 {
		// Primary location keys shown first.
		locationKeys := []string{"url", "path", "endpoint"}
		matchKeys    := []string{"matched_text", "match", "secret", "value", "key"}
		contextKeys  := []string{"port", "service", "method", "status_code", "header", "parameter", "cookie"}

		var locationLines, matchLines, contextLines, otherLines []string
		for _, k := range locationKeys {
			if v, ok := f.Evidence[k]; ok && fmt.Sprintf("%v", v) != "" {
				locationLines = append(locationLines, fmt.Sprintf("  \x1b[90m%-22s\x1b[0m%s", k+":", formatEvidenceValue(k, v)))
			}
		}
		for _, k := range matchKeys {
			if v, ok := f.Evidence[k]; ok && fmt.Sprintf("%v", v) != "" {
				matchLines = append(matchLines, fmt.Sprintf("  \x1b[90m%-22s\x1b[0m\x1b[33m%s\x1b[0m", k+":", formatEvidenceValue(k, v)))
			}
		}
		for _, k := range contextKeys {
			if v, ok := f.Evidence[k]; ok && fmt.Sprintf("%v", v) != "" {
				contextLines = append(contextLines, fmt.Sprintf("  \x1b[90m%-22s\x1b[0m%s", k+":", formatEvidenceValue(k, v)))
			}
		}
		known := map[string]bool{}
		for _, k := range append(append(locationKeys, matchKeys...), contextKeys...) {
			known[k] = true
		}
		for k, v := range f.Evidence {
			if !known[k] && fmt.Sprintf("%v", v) != "" {
				otherLines = append(otherLines, fmt.Sprintf("  \x1b[90m%-22s\x1b[0m%s", k+":", formatEvidenceValue(k, v)))
			}
		}
		sort.Strings(otherLines)

		if len(locationLines) > 0 {
			lines = append(lines, "  \x1b[1mWhere Found\x1b[0m")
			lines = append(lines, locationLines...)
			lines = append(lines, "")
		}
		if len(matchLines) > 0 {
			lines = append(lines, "  \x1b[1mWhat Was Found\x1b[0m")
			lines = append(lines, matchLines...)
			lines = append(lines, "")
		}
		if len(contextLines) > 0 || len(otherLines) > 0 {
			lines = append(lines, "  \x1b[1mContext\x1b[0m")
			lines = append(lines, contextLines...)
			lines = append(lines, otherLines...)
			lines = append(lines, "")
		}
	}

	// Scrolling
	total := len(lines)
	bodyH := termH - 2 // header + footer
	if bodyH < 1 {
		bodyH = 1
	}
	maxOff := total - bodyH
	if maxOff < 0 {
		maxOff = 0
	}
	if r.findingDetailOff > maxOff {
		r.findingDetailOff = maxOff
	}
	if r.findingDetailOff < 0 {
		r.findingDetailOff = 0
	}

	lineCount := 0

	// Header
	fmt.Fprintf(buf, "\x1b[2K\r  \x1b[90m\u25c0\x1b[0m \x1b[1mFinding Detail\x1b[0m  \x1b[90m[q/b] back  [j/k \u2191\u2193] scroll\x1b[0m\n")
	lineCount++

	// Body
	end := r.findingDetailOff + bodyH
	if end > total {
		end = total
	}
	for i := r.findingDetailOff; i < end; i++ {
		fmt.Fprintf(buf, "\x1b[2K\r%s\n", lines[i])
		lineCount++
	}
	for i := end - r.findingDetailOff; i < bodyH; i++ {
		buf.WriteString("\x1b[2K\r\n")
		lineCount++
	}

	// Footer
	scrollPct := 100
	if total > bodyH {
		scrollPct = (r.findingDetailOff * 100) / (total - bodyH)
	}
	fmt.Fprintf(buf, "\x1b[2K\r  \x1b[90mline %d/%d (%d%%)  [y] copy proof cmd  [b/q] back  [j/k] scroll\x1b[0m\n", r.findingDetailOff+1, total, scrollPct)
	lineCount++

	return lineCount
}
// renderTopology writes a live network topology tree into buf and returns the line count.
// Assets are grouped by cloud provider and IP. Built incrementally from fingerprint events.
// Caller must hold r.mu.
func (r *progressRenderer) renderTopology(buf *strings.Builder) int {
	_, termH, err := term.GetSize(int(os.Stderr.Fd()))
	if err != nil || termH < 5 {
		termH = 24
	}
	bodyLines := termH - 2 // header + footer
	if bodyLines < 1 {
		bodyLines = 1
	}

	// Build ordered content lines from accumulated evidence.
	type hostEntry struct {
		name   string
		tech   string
		status int
		cname  string
	}
	type ipSlot struct {
		ip    string
		hosts []hostEntry
	}
	type provSlot struct {
		name string
		ips  []ipSlot
	}

	provMap := map[string]map[string][]hostEntry{}
	var provOrder []string
	for asset, ev := range r.topoEvidence {
		prov := report.DeriveProvider(ev.CNAMEChain, ev.ASNOrg, ev.IP)
		ip := ev.IP
		if ip == "" {
			ip = "?"
		}
		tech := ""
		if ws := ev.ServiceVersions["web_server"]; ws != "" {
			if i := strings.IndexAny(ws, "/ "); i > 0 {
				tech = ws[:i]
			} else {
				tech = ws
			}
		}
		cname := ""
		if len(ev.CNAMEChain) > 0 {
			cname = ev.CNAMEChain[0]
		}
		if _, ok := provMap[prov]; !ok {
			provOrder = append(provOrder, prov)
			provMap[prov] = map[string][]hostEntry{}
		}
		provMap[prov][ip] = append(provMap[prov][ip], hostEntry{
			name: asset, tech: tech, status: ev.StatusCode, cname: cname,
		})
	}
	sort.Strings(provOrder)

	// Flatten into renderable lines, tracking which lines correspond to host entries.
	type lineEntry struct {
		text      string
		assetName string // non-empty for host lines (selectable)
	}
	var entries []lineEntry
	var hostOrder []string // ordered asset names for cursor navigation

	for pi, prov := range provOrder {
		_ = pi
		entries = append(entries, lineEntry{text: "\x1b[1m" + prov + "\x1b[0m"})
		var ipList []string
		for ip := range provMap[prov] {
			ipList = append(ipList, ip)
		}
		sort.Strings(ipList)
		for ii, ip := range ipList {
			hosts := provMap[prov][ip]
			sort.Slice(hosts, func(a, b int) bool { return hosts[a].name < hosts[b].name })
			lastIP := ii == len(ipList)-1
			ipBranch := "  ├─ "
			hostPad := "  │  "
			if lastIP {
				ipBranch = "  └─ "
				hostPad = "     "
			}
			shared := ""
			if len(hosts) > 1 {
				shared = fmt.Sprintf("  \x1b[90m(%d virtual hosts)\x1b[0m", len(hosts))
			}
			entries = append(entries, lineEntry{text: fmt.Sprintf("%s\x1b[33m%s\x1b[0m%s", ipBranch, ip, shared)})
			for hi, h := range hosts {
				lastH := hi == len(hosts)-1
				hBranch := hostPad + "├─ "
				svcPad := hostPad + "│  "
				if lastH {
					hBranch = hostPad + "└─ "
					svcPad = hostPad + "   "
				}
				svcs := r.topoServices[h.name]
				sort.Slice(svcs, func(a, b int) bool { return svcs[a].port < svcs[b].port })
				var parts []string
				if ev, ok := r.topoEvidence[h.name]; ok {
					// Build "proxy → framework → backend" chain.
					var chain []string
					if ev.ProxyType != "" {
						chain = append(chain, "\x1b[35m"+ev.ProxyType+"\x1b[0m")
					}
					if ev.Framework != "" {
						chain = append(chain, "\x1b[32m"+ev.Framework+"\x1b[0m")
					} else if h.tech != "" {
						chain = append(chain, "\x1b[32m"+h.tech+"\x1b[0m")
					}
					for _, bs := range ev.BackendServices {
						chain = append(chain, "\x1b[33m"+bs+"\x1b[0m")
					}
					if len(chain) > 0 {
						parts = append(parts, strings.Join(chain, " → "))
					}
					// Auth system.
					if ev.AuthSystem != "" {
						parts = append(parts, "\x1b[90mauth:\x1b[0m\x1b[36m"+ev.AuthSystem+"\x1b[0m")
					}
					// HTTP status if non-200.
					if h.status > 0 && h.status != 200 && h.status != 404 {
						parts = append(parts, fmt.Sprintf("\x1b[90mHTTP %d\x1b[0m", h.status))
					}
					// First 3 responding paths.
					for i, p := range ev.RespondingPaths {
						if i >= 3 {
							parts = append(parts, fmt.Sprintf("\x1b[90m+%d paths\x1b[0m", len(ev.RespondingPaths)-3))
							break
						}
						parts = append(parts, "\x1b[90m"+p+"\x1b[0m")
					}
					if ev.Title != "" && h.status == 404 {
						title := ev.Title
						if len(title) > 30 {
							title = title[:29] + "…"
						}
						parts = append(parts, "\x1b[90m\""+title+"\"\x1b[0m")
					}
				} else {
					// No evidence yet — show basic info.
					if h.status > 0 && h.status != 404 {
						parts = append(parts, fmt.Sprintf("HTTP %d", h.status))
					}
					if h.tech != "" {
						parts = append(parts, h.tech)
					}
				}
				if h.cname != "" {
					parts = append(parts, "\x1b[90m→ "+h.cname+"\x1b[0m")
				}
				detail := strings.Join(parts, " · ")
				if detail == "" && len(svcs) == 0 {
					if h.status == 404 {
						detail = "\x1b[90m404 (no paths found)\x1b[0m"
					} else {
						detail = "\x1b[90mno HTTP\x1b[0m"
					}
				}
				name := h.name
				if len(name) > 38 {
					name = "…" + name[len(name)-37:]
				}
				hostIdx := len(hostOrder)
				hostOrder = append(hostOrder, h.name)
				// Cursor highlight on selected host.
				cursor := "  "
				if hostIdx == r.topoCursor {
					cursor = "\x1b[7m▶\x1b[0m "
				}
				entries = append(entries, lineEntry{
					text:      fmt.Sprintf("%s%s\x1b[36m%-38s\x1b[0m  %s", cursor, hBranch, name, detail),
					assetName: h.name,
				})
				for si, svc := range svcs {
					sBranch := svcPad + "├─ "
					if si == len(svcs)-1 {
						sBranch = svcPad + "└─ "
					}
					entries = append(entries, lineEntry{text: fmt.Sprintf("%s\x1b[90m%s:%d\x1b[0m", sBranch, svc.service, svc.port)})
				}
			}
		}
		entries = append(entries, lineEntry{}) // blank line between providers
	}
	if len(entries) == 0 {
		entries = append(entries, lineEntry{text: "  \x1b[90mNo fingerprint data yet — waiting for assets to be scanned…\x1b[0m"})
	}

	// Update host order so key handler has current list.
	r.topoHostOrder = hostOrder
	if r.topoCursor >= len(hostOrder) && len(hostOrder) > 0 {
		r.topoCursor = len(hostOrder) - 1
	}

	// Find the line index of the cursor so we can auto-scroll to keep it visible.
	cursorLine := -1
	for i, e := range entries {
		if e.assetName != "" {
			idx := 0
			for j := 0; j < i; j++ {
				if entries[j].assetName != "" {
					idx++
				}
			}
			if idx == r.topoCursor {
				cursorLine = i
				break
			}
		}
	}
	// Auto-scroll: keep cursor line within visible window.
	if cursorLine >= 0 {
		if cursorLine < r.topoOff {
			r.topoOff = cursorLine
		} else if cursorLine >= r.topoOff+bodyLines {
			r.topoOff = cursorLine - bodyLines + 1
		}
	}

	lines := make([]string, len(entries))
	for i, e := range entries {
		lines[i] = e.text
	}

	maxOff := len(lines) - bodyLines
	if maxOff < 0 {
		maxOff = 0
	}
	if r.topoOff > maxOff {
		r.topoOff = maxOff
	}
	visible := lines[r.topoOff:]
	if len(visible) > bodyLines {
		visible = visible[:bodyLines]
	}

	drawn := 0
	fmt.Fprintf(buf, "\x1b[2K\r\x1b[1mNETWORK TOPOLOGY\x1b[0m  \x1b[90m%d assets  [↵] detail  [j/k] move  [t/q] back\x1b[0m\n",
		len(r.topoEvidence))
	drawn++
	for _, l := range visible {
		fmt.Fprintf(buf, "\x1b[2K\r%s\n", l)
		drawn++
	}
	for drawn-1 < bodyLines {
		buf.WriteString("\x1b[2K\r\n")
		drawn++
	}
	pct := 0
	if maxOff > 0 {
		pct = r.topoOff * 100 / maxOff
	}
	fmt.Fprintf(buf, "\x1b[2K\r\x1b[90m── %d%% ──\x1b[0m\n", pct)
	drawn++
	return drawn
}

// renderReview renders the pending fingerprint rules + playbook suggestions review pane.
// Keys: j/k move cursor, a approve, x reject, d delete, b/q back.
func (r *progressRenderer) renderReview(buf *strings.Builder) int {
	_, termH, err := term.GetSize(int(os.Stderr.Fd()))
	if err != nil || termH < 5 {
		termH = 24
	}
	bodyLines := termH - 2
	if bodyLines < 1 {
		bodyLines = 1
	}

	type reviewItem struct {
		kind   string // "fingerprint" or "playbook"
		label  string // one-line display string
		id     int64  // fingerprint rule ID (kind=fingerprint)
		suggID string // playbook suggestion ID (kind=playbook)
	}

	var items []reviewItem
	for _, r2 := range r.pendingReviewRules {
		sig := r2.SignalType
		if r2.SignalKey != "" {
			sig = r2.SignalType + ":" + r2.SignalKey
		}
		label := fmt.Sprintf("\x1b[35m[fingerprint]\x1b[0m  %-10s %-25s → %-14s = %-14s  \x1b[90mconf:%.0f%% seen:%d src:%s\x1b[0m",
			sig, truncateStr(r2.SignalValue, 25), r2.Field, truncateStr(r2.Value, 14), r2.Confidence*100, r2.SeenCount, r2.Source)
		items = append(items, reviewItem{kind: "fingerprint", label: label, id: r2.ID})
	}
	for _, s := range r.pendingReviewSuggs {
		target := s.TargetPlaybook
		if target == "" {
			target = "(new)"
		}
		label := fmt.Sprintf("\x1b[36m[playbook]   \x1b[0m  %-10s %-30s  \x1b[90m%s\x1b[0m",
			s.Type, truncateStr(target, 30), truncateStr(s.Reasoning, 40))
		items = append(items, reviewItem{kind: "playbook", label: label, suggID: s.ID})
	}

	fmt.Fprintf(buf, "\x1b[2K\r\x1b[1mREVIEW PENDING\x1b[0m  \x1b[90m[j/k] move  [a] approve  [x] reject  [d] delete  [i] import playbook  [b/q] back\x1b[0m\n")
	lineCount := 1

	if len(items) == 0 {
		fmt.Fprintf(buf, "\x1b[2K\r  \x1b[90mNo pending items.\x1b[0m\n")
		return 2
	}

	// Clamp cursor.
	if r.reviewCursor >= len(items) {
		r.reviewCursor = len(items) - 1
	}
	if r.reviewCursor < 0 {
		r.reviewCursor = 0
	}

	// Scroll offset to keep cursor visible.
	off := r.reviewCursor - bodyLines/2
	if off < 0 {
		off = 0
	}
	if off+bodyLines > len(items) {
		off = len(items) - bodyLines
		if off < 0 {
			off = 0
		}
	}

	for i := off; i < len(items) && lineCount < termH-1; i++ {
		item := items[i]
		cursor := "  "
		if i == r.reviewCursor {
			cursor = "\x1b[7m▶\x1b[0m "
		}
		fmt.Fprintf(buf, "\x1b[2K\r%s%s\n", cursor, item.label)
		lineCount++
	}
	return lineCount
}

// renderTopoDetail renders the full detail pane for a selected topology asset.
func (r *progressRenderer) renderTopoDetail(buf *strings.Builder) int {
	_, termH, err := term.GetSize(int(os.Stderr.Fd()))
	if err != nil || termH < 5 {
		termH = 24
	}
	termW, _, _ := func() (int, int, error) { w, h, e := term.GetSize(int(os.Stderr.Fd())); return w, h, e }()
	if termW < 40 {
		termW = 80
	}
	bodyLines := termH - 2

	asset := r.topoDetailAsset
	ev, hasEv := r.topoEvidence[asset]
	svcs := r.topoServices[asset]
	sort.Slice(svcs, func(a, b int) bool { return svcs[a].port < svcs[b].port })

	sep := strings.Repeat("─", termW-2)

	var lines []string
	add := func(format string, a ...any) {
		lines = append(lines, fmt.Sprintf(format, a...))
	}
	section := func(title string) {
		add("\x1b[90m%s\x1b[0m", sep)
		add("\x1b[1m  %s\x1b[0m", title)
	}

	add("\x1b[1;36m  %s\x1b[0m", asset)

	if hasEv {
		// ── Network ──
		section("NETWORK")
		if ev.IP != "" {
			add("  IP            %s", ev.IP)
		}
		if ev.ASNOrg != "" {
			add("  ASN           %s %s", ev.ASNNum, ev.ASNOrg)
		}
		if len(ev.CNAMEChain) > 0 {
			add("  CNAME chain   %s", strings.Join(ev.CNAMEChain, " → "))
		}
		if len(ev.AAAARecords) > 0 {
			add("  IPv6          %s", strings.Join(ev.AAAARecords, ", "))
		}

		// ── HTTP ──
		section("HTTP")
		if ev.StatusCode > 0 {
			add("  Status        %d", ev.StatusCode)
		}
		if ev.Title != "" {
			add("  Page title    %s", ev.Title)
		}
		if ev.HTTP2Enabled {
			add("  HTTP/2        enabled")
		}
		if ev.AuthScheme != "" {
			add("  Auth scheme   %s", ev.AuthScheme)
		}

		// ── Responding paths ──
		if len(ev.RespondingPaths) > 0 {
			section(fmt.Sprintf("RESPONDING PATHS  (%d)", len(ev.RespondingPaths)))
			for _, p := range ev.RespondingPaths {
				add("  %s", p)
			}
		}
		if len(ev.RobotsTxtPaths) > 0 {
			section(fmt.Sprintf("ROBOTS.TXT PATHS  (%d)", len(ev.RobotsTxtPaths)))
			for _, p := range ev.RobotsTxtPaths {
				add("  %s", p)
			}
		}

		// ── Technology stack ──
		section("TECHNOLOGY")
		if ev.Framework != "" {
			add("  Framework     %s", ev.Framework)
		}
		if ev.CloudProvider != "" {
			add("  Cloud         %s", ev.CloudProvider)
		}
		if ev.ProxyType != "" {
			add("  Proxy/CDN     %s", ev.ProxyType)
		}
		if ev.IsKubernetes {
			add("  Kubernetes    yes")
		}
		if ev.IsServerless {
			add("  Serverless    yes")
		}
		if ev.IsReverseProxy {
			add("  Reverse proxy yes")
		}
		for role, ver := range ev.ServiceVersions {
			add("  %-14s%s", role, ver)
		}
		if len(ev.BackendServices) > 0 {
			add("  Backends      %s", strings.Join(ev.BackendServices, ", "))
		}
		if len(ev.CookieNames) > 0 {
			add("  Session cookies %s", strings.Join(ev.CookieNames, ", "))
		}

		// ── Auth ──
		if ev.AuthSystem != "" || ev.AuthScheme != "" {
			section("AUTHENTICATION")
			if ev.AuthSystem != "" {
				add("  Auth system   %s", ev.AuthSystem)
			}
		}

		// ── TLS ──
		if len(ev.CertSANs) > 0 || ev.CertIssuer != "" || ev.JARMFingerprint != "" {
			section("TLS")
			if ev.CertIssuer != "" {
				add("  Issuer        %s", ev.CertIssuer)
			}
			if len(ev.CertSANs) > 0 {
				// Wrap SANs to avoid very long single line.
				const maxPerLine = 4
				for i := 0; i < len(ev.CertSANs); i += maxPerLine {
					end := i + maxPerLine
					if end > len(ev.CertSANs) {
						end = len(ev.CertSANs)
					}
					if i == 0 {
						add("  SANs          %s", strings.Join(ev.CertSANs[i:end], "  "))
					} else {
						add("                %s", strings.Join(ev.CertSANs[i:end], "  "))
					}
				}
			}
			if ev.JARMFingerprint != "" {
				add("  JARM          %s", ev.JARMFingerprint)
			}
		}

		// ── DNS ──
		section("DNS")
		if ev.MXProvider != "" {
			add("  Email         %s", ev.MXProvider)
		}
		if len(ev.MXRecords) > 0 {
			add("  MX records    %s", strings.Join(ev.MXRecords, ", "))
		}
		if ev.HasDMARC {
			add("  DMARC         p=%s", ev.DMARCPolicy)
		}
		if len(ev.NSRecords) > 0 {
			add("  Nameservers   %s", strings.Join(ev.NSRecords, ", "))
		}
		if len(ev.TXTRecords) > 0 {
			section(fmt.Sprintf("TXT RECORDS  (%d)", len(ev.TXTRecords)))
			for _, t := range ev.TXTRecords {
				if len(t) > termW-4 {
					t = t[:termW-7] + "…"
				}
				add("  %s", t)
			}
		}

		// ── AI / LLM ──
		if len(ev.AIEndpoints) > 0 || ev.LLMProvider != "" {
			section("AI / LLM")
			if ev.LLMProvider != "" {
				add("  Provider      %s", ev.LLMProvider)
			}
			for _, ep := range ev.AIEndpoints {
				add("  Endpoint      %s", ep)
			}
		}

		// ── Web3 ──
		if len(ev.Web3Signals) > 0 || len(ev.ContractAddresses) > 0 {
			section("WEB3")
			if len(ev.Web3Signals) > 0 {
				add("  Signals       %s", strings.Join(ev.Web3Signals, ", "))
			}
			for _, addr := range ev.ContractAddresses {
				add("  Contract      %s", addr)
			}
		}

		// ── Third-party vendors ──
		if len(ev.VendorSignals) > 0 {
			section("THIRD-PARTY VENDORS")
			add("  %s", strings.Join(ev.VendorSignals, ", "))
		}

		// ── Detection evidence: which response headers drove technology classification ──
		var reasonLines []string
		fingerHeaders := []string{
			"server", "x-powered-by", "via", "x-generator",
			"x-aspnet-version", "x-aspnetmvc-version",
			"x-envoy-upstream-service-time", "x-envoy-decorator-operation",
			"x-kong-request-id", "x-kong-upstream-latency",
			"x-traefik-request-id",
			"cf-ray", "cf-cache-status",
			"x-cache", "x-cache-hits",
			"x-amz-cf-id", "x-amz-request-id",
			"x-azure-ref",
			"fly-request-id", "x-vercel-id", "x-netlify-id",
			"x-fastly-request-id", "cdn-loop",
			"x-request-id", "x-correlation-id",
		}
		for _, hdr := range fingerHeaders {
			if val, ok := ev.Headers[hdr]; ok && val != "" {
				v := val
				if len(v) > termW-22 {
					v = v[:termW-25] + "…"
				}
				reasonLines = append(reasonLines, fmt.Sprintf("  %-20s %s", hdr+":", v))
			}
		}
		if len(reasonLines) > 0 {
			section("DETECTION EVIDENCE")
			for _, l := range reasonLines {
				add("%s", l)
			}
		}

		// ── Remaining response headers (sorted) ──
		if len(ev.Headers) > 0 {
			reasonSet := make(map[string]bool)
			for _, l := range reasonLines {
				trimmed := strings.TrimLeft(l, " ")
				if idx := strings.Index(trimmed, ":"); idx >= 0 {
					reasonSet[trimmed[:idx]] = true
				}
			}
			var extraHdrs []string
			for k := range ev.Headers {
				if !reasonSet[k] {
					extraHdrs = append(extraHdrs, k)
				}
			}
			sort.Strings(extraHdrs)
			if len(extraHdrs) > 0 {
				section(fmt.Sprintf("RESPONSE HEADERS  (%d)", len(ev.Headers)))
				for _, k := range extraHdrs {
					v := ev.Headers[k]
					if len(v) > termW-22 {
						v = v[:termW-25] + "…"
					}
					add("  %-20s %s", k+":", v)
				}
			}
		}
	}

	// ── Open ports ──
	if len(svcs) > 0 {
		section(fmt.Sprintf("OPEN PORTS  (%d)", len(svcs)))
		for _, svc := range svcs {
			add("  %-6d %s", svc.port, svc.service)
		}
	}

	if len(lines) == 0 {
		lines = append(lines, "  \x1b[90mNo detail available yet.\x1b[0m")
	}

	// Clamp scroll.
	maxOff := len(lines) - bodyLines
	if maxOff < 0 {
		maxOff = 0
	}
	if r.topoDetailOff > maxOff {
		r.topoDetailOff = maxOff
	}
	visible := lines[r.topoDetailOff:]
	if len(visible) > bodyLines {
		visible = visible[:bodyLines]
	}

	drawn := 0
	posHint := ""
	if len(r.topoHostOrder) > 1 {
		posHint = fmt.Sprintf("  \x1b[90m%d/%d", r.topoCursor+1, len(r.topoHostOrder))
	}
	fmt.Fprintf(buf, "\x1b[2K\r\x1b[1mASSET DETAIL\x1b[0m%s  \x1b[90m[j/k] scroll  [n/p] next/prev  [b] topology\x1b[0m\n", posHint)
	drawn++
	for _, l := range visible {
		fmt.Fprintf(buf, "\x1b[2K\r%s\n", l)
		drawn++
	}
	for drawn-1 < bodyLines {
		buf.WriteString("\x1b[2K\r\n")
		drawn++
	}
	pct := 0
	if maxOff > 0 {
		pct = r.topoDetailOff * 100 / maxOff
	}
	fmt.Fprintf(buf, "\x1b[2K\r\x1b[90m── %d%% ──\x1b[0m\n", pct)
	drawn++
	return drawn
}

// renderDiscovered renders the list of discovered (unconfirmed) assets.
// Keys: j/k move cursor, Enter for detail, b/q back.
func (r *progressRenderer) renderDiscovered(buf *strings.Builder) int {
	_, termH, err := term.GetSize(int(os.Stderr.Fd()))
	if err != nil || termH < 5 {
		termH = 24
	}
	bodyLines := termH - 2
	if bodyLines < 1 {
		bodyLines = 1
	}

	assets := r.discoveredAssets
	total := len(assets)

	// Build display lines.
	type row struct {
		text  string
		idx   int // index into assets
	}
	var rows []row
	for i, a := range assets {
		cursor := "  "
		if i == r.discoveredCursor {
			cursor = "\x1b[7m▶\x1b[0m "
		}

		// Confidence indicator.
		conf := "\x1b[33m⚠ unconfirmed\x1b[0m"
		if a.Confirmed {
			conf = "\x1b[32m✓ confirmed\x1b[0m"
		}

		// Via label.
		via := a.DiscoveredVia
		switch via {
		case "bgp":
			via = "BGP ASN"
		case "bgp_ptr":
			via = "BGP PTR"
		case "cdn_origin":
			via = "CDN origin"
		case "ghactions_deploy":
			via = "deploy target"
		}

		// First evidence item as a hint.
		hint := ""
		if len(a.Evidence) > 0 {
			hint = "\x1b[90m" + a.Evidence[0] + "\x1b[0m"
		}

		asset := a.Asset
		if len(asset) > 36 {
			asset = "…" + asset[len(asset)-35:]
		}
		rel := a.Relationship
		if len(rel) > 28 {
			rel = rel[:27] + "…"
		}

		line := fmt.Sprintf("%s\x1b[36m%-36s\x1b[0m  \x1b[90m%-14s\x1b[0m  %s", cursor, asset, via, conf)
		if rel != "" {
			line += fmt.Sprintf("  \x1b[90m%s\x1b[0m", rel)
		}
		_ = hint
		rows = append(rows, row{text: line, idx: i})
	}

	if len(rows) == 0 {
		rows = append(rows, row{text: "  \x1b[90mNo unconfirmed assets discovered yet.\x1b[0m"})
	}

	// Auto-scroll to keep cursor visible.
	maxOff := len(rows) - bodyLines
	if maxOff < 0 {
		maxOff = 0
	}
	if r.discoveredCursor < r.discoveredOff {
		r.discoveredOff = r.discoveredCursor
	} else if r.discoveredCursor >= r.discoveredOff+bodyLines {
		r.discoveredOff = r.discoveredCursor - bodyLines + 1
	}
	if r.discoveredOff > maxOff {
		r.discoveredOff = maxOff
	}

	visible := rows[r.discoveredOff:]
	if len(visible) > bodyLines {
		visible = visible[:bodyLines]
	}

	drawn := 0
	fmt.Fprintf(buf, "\x1b[2K\r\x1b[1mDISCOVERED ASSETS (%d)\x1b[0m  \x1b[90m[↵] detail  [j/k] move  [b/q] back\x1b[0m\n", total)
	drawn++
	for _, row := range visible {
		fmt.Fprintf(buf, "\x1b[2K\r%s\n", row.text)
		drawn++
	}
	for drawn-1 < bodyLines {
		buf.WriteString("\x1b[2K\r\n")
		drawn++
	}
	pct := 0
	if maxOff > 0 {
		pct = r.discoveredOff * 100 / maxOff
	}
	fmt.Fprintf(buf, "\x1b[2K\r\x1b[90m── %d%% ──\x1b[0m\n", pct)
	drawn++
	return drawn
}

// renderDiscoveredDetail renders full evidence and findings for one discovered
// asset, and presents the typed permission gate for authorizing a deep scan.
// j/k navigate between assets; [p] starts typing the gate phrase; b/q back.
func (r *progressRenderer) renderDiscoveredDetail(buf *strings.Builder) int {
	_, termH, err := term.GetSize(int(os.Stderr.Fd()))
	if err != nil || termH < 5 {
		termH = 24
	}
	termW, _, _ := func() (int, int, error) { w, h, e := term.GetSize(int(os.Stderr.Fd())); return w, h, e }()
	if termW < 40 {
		termW = 80
	}
	bodyLines := termH - 2

	if len(r.discoveredAssets) == 0 {
		fmt.Fprintf(buf, "\x1b[2K\r\x1b[1mDISCOVERED ASSET\x1b[0m\n\x1b[2K\r  \x1b[90mNo assets.\x1b[0m\n")
		return 2
	}

	idx := r.discoveredDetailIdx
	if idx < 0 {
		idx = 0
	}
	if idx >= len(r.discoveredAssets) {
		idx = len(r.discoveredAssets) - 1
	}
	a := r.discoveredAssets[idx]

	sep := strings.Repeat("─", termW-2)

	var lines []string
	add := func(format string, args ...any) {
		lines = append(lines, fmt.Sprintf(format, args...))
	}
	section := func(title string) {
		add("\x1b[90m%s\x1b[0m", sep)
		add("\x1b[1m  %s\x1b[0m", title)
	}

	// Title line.
	conf := "\x1b[33m⚠ UNCONFIRMED\x1b[0m"
	if a.Confirmed {
		conf = "\x1b[32m✓ CONFIRMED\x1b[0m"
	}
	via := a.DiscoveredVia
	add("\x1b[1;36m  %s\x1b[0m  \x1b[90m[%s]\x1b[0m  %s", a.Asset, via, conf)
	if a.Relationship != "" {
		add("  \x1b[90m%s\x1b[0m", a.Relationship)
	}
	if a.RootDomain != "" {
		add("  \x1b[90mroot domain: %s\x1b[0m", a.RootDomain)
	}
	if a.BoundHostname != "" {
		add("  \x1b[90mHost header: %s\x1b[0m", a.BoundHostname)
	}

	// Evidence section.
	if len(a.Evidence) > 0 {
		section("OWNERSHIP EVIDENCE")
		for _, ev := range a.Evidence {
			add("    %s", ev)
		}
	}

	// Surface-scan findings for this asset.
	var assetFindings []finding.Finding
	for _, f := range r.findings {
		if f.Asset == a.Asset {
			assetFindings = append(assetFindings, f)
		}
	}
	sort.Slice(assetFindings, func(i, j int) bool {
		return assetFindings[i].Severity > assetFindings[j].Severity
	})
	section(fmt.Sprintf("SURFACE SCAN FINDINGS (%d)", len(assetFindings)))
	if len(assetFindings) == 0 {
		add("    \x1b[90mno findings yet\x1b[0m")
	} else {
		for _, f := range assetFindings {
			col := severityColor(f.Severity)
			sev := strings.ToUpper(f.Severity.String())
			if len(sev) > 4 {
				sev = sev[:4]
			}
			title := f.Title
			maxT := termW - 16
			if maxT < 20 {
				maxT = 20
			}
			if len(title) > maxT {
				title = title[:maxT-1] + "…"
			}
			add("    %s[%s]\x1b[0m  %s", col, sev, title)
		}
	}

	// Permission gate section.
	section("DEEP SCAN PERMISSION")
	const gatePhrase = "permission confirmed"
	confirmed := r.discoveredConfirm == gatePhrase
	if confirmed {
		add("  \x1b[1;32m✓ Permission confirmed — deep scan authorized\x1b[0m")
		add("  \x1b[90mRe-run beacon with --permission-confirmed and target %s\x1b[0m", a.Asset)
	} else if a.Confirmed {
		add("  \x1b[90mAsset confirmed as belonging to %s — deep scan available.\x1b[0m", a.RootDomain)
		if r.discoveredConfirming {
			add("  Type phrase:  \x1b[1m%s\x1b[0m\x1b[7m \x1b[0m", r.discoveredConfirm)
		} else {
			add("  \x1b[90mPress [p] then type: \"%s\" to authorize deep scan.\x1b[0m", gatePhrase)
		}
	} else {
		add("  \x1b[33mThis asset has not been confirmed as belonging to %s.\x1b[0m", a.RootDomain)
		add("  \x1b[90mSurface (passive) scans are always authorized. Deep scans require\x1b[0m")
		add("  \x1b[90mexplicit confirmation that you own or have permission to test this asset.\x1b[0m")
		if r.discoveredConfirming {
			add("  Type phrase:  \x1b[1m%s\x1b[0m\x1b[7m \x1b[0m", r.discoveredConfirm)
		} else {
			add("  \x1b[90mPress [p] then type: \"%s\" to authorize deep scan.\x1b[0m", gatePhrase)
		}
	}

	// Render with scroll.
	add("\x1b[90m%s\x1b[0m", sep)

	maxOff := len(lines) - bodyLines
	if maxOff < 0 {
		maxOff = 0
	}
	// When navigating j/k in detail mode the idx changes but we need a stable
	// per-asset scroll — use discoveredDetailIdx changes as a reset signal.
	// (Scroll is not separately tracked; content is rendered from top.)
	off := 0
	if off > maxOff {
		off = maxOff
	}
	visible := lines[off:]
	if len(visible) > bodyLines {
		visible = visible[:bodyLines]
	}

	drawn := 0
	nav := fmt.Sprintf("%d/%d", idx+1, len(r.discoveredAssets))
	fmt.Fprintf(buf, "\x1b[2K\r\x1b[1mDISCOVERED ASSET\x1b[0m  \x1b[90m%s  [j/k] next/prev  [p] authorize  [b/q] back\x1b[0m\n", nav)
	drawn++
	for _, l := range visible {
		fmt.Fprintf(buf, "\x1b[2K\r%s\n", l)
		drawn++
	}
	for drawn-1 < bodyLines {
		buf.WriteString("\x1b[2K\r\n")
		drawn++
	}
	fmt.Fprintf(buf, "\x1b[2K\r\x1b[90m──────\x1b[0m\n")
	drawn++
	return drawn
}

// severityColor returns the ANSI color escape for a severity level.
// formatEvidenceValue returns a display-safe, truncated string for an evidence
// field value. Multi-line and HTML-heavy values are stripped and capped at 300
// chars so they don't overflow the terminal.
func formatEvidenceValue(key string, v any) string {
	// Render slices as comma-separated strings instead of Go's "[a b c]" format.
	switch val := v.(type) {
	case []string:
		v = strings.Join(val, ", ")
	case []any:
		parts := make([]string, len(val))
		for i, item := range val {
			parts[i] = fmt.Sprintf("%v", item)
		}
		v = strings.Join(parts, ", ")
	}
	raw := fmt.Sprintf("%v", v)

	// Strip HTML tags for known snippet keys or when the value looks like HTML.
	if strings.Contains(key, "snippet") || strings.Contains(key, "html") ||
		(strings.Contains(raw, "<") && strings.Contains(raw, ">")) {
		// Remove everything between < > (simple tag strip).
		var stripped strings.Builder
		inTag := false
		for _, ch := range raw {
			switch {
			case ch == '<':
				inTag = true
				stripped.WriteRune(' ')
			case ch == '>':
				inTag = false
			case !inTag:
				stripped.WriteRune(ch)
			}
		}
		raw = stripped.String()
	}

	// Collapse whitespace and newlines into a single line.
	raw = strings.Join(strings.Fields(raw), " ")

	// Truncate long values.
	const maxLen = 300
	if len(raw) > maxLen {
		raw = raw[:maxLen] + "…"
	}
	return raw
}

// wordWrapLines wraps text to maxWidth columns, returning one string per line.
func wordWrapLines(text string, maxWidth int) []string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return nil
	}
	var lines []string
	line := ""
	for _, w := range words {
		if line == "" {
			line = w
		} else if len(line)+1+len(w) > maxWidth {
			lines = append(lines, line)
			line = w
		} else {
			line += " " + w
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

// wordWrapAtShellBoundaries wraps a shell command at natural break points
// (pipes, &&, flag boundaries --) rather than arbitrary word boundaries.
// Continuation lines are indented with two spaces so the command is readable.
// Falls back to wordWrapLines if no shell boundaries are present.
func wordWrapAtShellBoundaries(cmd string, maxWidth int) []string {
	if maxWidth < 20 {
		maxWidth = 20
	}
	if len(cmd) <= maxWidth {
		return []string{cmd}
	}
	// Try to split at pipe/chain operators first.
	for _, sep := range []string{" | ", " && ", " || ", " ; "} {
		if idx := strings.Index(cmd, sep); idx != -1 && idx < maxWidth {
			rest := cmd[idx+len(sep):]
			first := cmd[:idx+len(sep)-1] // keep the operator on the first line
			var lines []string
			lines = append(lines, first)
			for _, sub := range wordWrapAtShellBoundaries(rest, maxWidth-2) {
				lines = append(lines, "  "+sub)
			}
			return lines
		}
	}
	// Try to split at a flag boundary (space followed by --) within maxWidth.
	if idx := strings.LastIndex(cmd[:maxWidth], " --"); idx > 0 {
		first := cmd[:idx]
		rest := cmd[idx+1:] // drop the leading space; keep "--..."
		var lines []string
		lines = append(lines, first)
		for _, sub := range wordWrapAtShellBoundaries(rest, maxWidth-2) {
			lines = append(lines, "  "+sub)
		}
		return lines
	}
	// No shell boundary found — fall back to word-wrap.
	return wordWrapLines(cmd, maxWidth)
}

// extractFindingURL returns the most useful URL from a finding's evidence map.
// It checks common evidence keys in priority order so the clipboard gets the
// most actionable link (e.g. the direct bucket URL rather than the base URL).
func extractFindingURL(f *finding.Finding) string {
	if f == nil {
		return ""
	}
	for _, key := range []string{
		"bucket_url", "write_url", "js_url", "probe_url", "url",
		"endpoint", "base_url", "redirect_url",
	} {
		if v, ok := f.Evidence[key]; ok {
			if s, ok := v.(string); ok && strings.HasPrefix(s, "http") {
				return s
			}
		}
	}
	// Fall back to the asset itself.
	if f.Asset != "" {
		return "https://" + f.Asset
	}
	return ""
}

// copyToClipboard writes text to the system clipboard using whatever tool is
// available (pbcopy on macOS, xclip/xsel on Linux, clip on Windows).
// Returns true if the copy succeeded.
func copyToClipboard(text string) bool {
	candidates := [][]string{
		{"pbcopy"},                           // macOS
		{"xclip", "-selection", "clipboard"}, // Linux/X11
		{"xsel", "--clipboard", "--input"},   // Linux/X11 alt
		{"clip"},                             // Windows
		{"wl-copy"},                          // Wayland
	}
	for _, args := range candidates {
		cmd := exec.Command(args[0], args[1:]...) //nolint:gosec
		// Use StdinPipe for reliable stdin delivery even when the parent
		// process has stdin in raw/non-blocking mode (TUI context).
		stdin, err := cmd.StdinPipe()
		if err != nil {
			continue
		}
		if err := cmd.Start(); err != nil {
			continue
		}
		_, _ = io.WriteString(stdin, text)
		stdin.Close()
		if err := cmd.Wait(); err == nil {
			return true
		}
	}
	return false
}

// fingerprintBadge returns a compact technology label for an asset built from
// its playbook Evidence, e.g. "cloudflare/nginx" or "haproxy" or "".
// Used in the findings list to show what kind of service has each finding.
func fingerprintBadge(ev playbook.Evidence) string {
	var parts []string
	if ev.CloudProvider != "" {
		parts = append(parts, ev.CloudProvider)
	}
	if ev.ProxyType != "" {
		// Avoid repeating cloud provider if proxy type is the same string
		if ev.ProxyType != ev.CloudProvider {
			parts = append(parts, ev.ProxyType)
		}
	}
	if len(parts) == 0 {
		// Fall back to raw server header
		if sv := ev.Headers["server"]; sv != "" {
			// Trim version numbers: "nginx/1.25.3" → "nginx"
			if idx := strings.Index(sv, "/"); idx > 0 {
				sv = sv[:idx]
			}
			parts = append(parts, strings.ToLower(sv))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	badge := strings.Join(parts, "/")
	if len(badge) > 20 {
		badge = badge[:19] + "…"
	}
	return badge
}

func severityColor(sev finding.Severity) string {
	switch sev {
	case finding.SeverityCritical:
		return "\x1b[1;31m" // bold red
	case finding.SeverityHigh:
		return "\x1b[31m" // red
	case finding.SeverityMedium:
		return "\x1b[33m" // yellow
	case finding.SeverityLow:
		return "\x1b[32m" // green
	default:
		return "\x1b[90m" // gray
	}
}

// fmtElapsed formats a duration as m:ss (e.g. "4:32") or s (e.g. "45s").
// liveEvidenceInt extracts an integer from a finding Evidence map.
// Handles both int (live findings) and float64 (JSON-decoded findings).
func liveEvidenceInt(ev map[string]any, key string) int {
	if ev == nil {
		return 0
	}
	switch v := ev[key].(type) {
	case int:
		return v
	case float64:
		return int(v)
	case int64:
		return int(v)
	}
	return 0
}

func fmtElapsed(d time.Duration) string {
	d = d.Truncate(time.Second)
	m := int(d.Minutes())
	s := int(d.Seconds()) % 60
	if m > 0 {
		return fmt.Sprintf("%dm%02ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

// fmtETA formats an ETA duration. Returns "…" when unknown.
func fmtETA(d time.Duration) string {
	if d <= 0 {
		return "…"
	}
	d = d.Truncate(time.Second)
	m := int(d.Minutes())
	s := int(d.Seconds()) % 60
	if m > 0 {
		return fmt.Sprintf("~%dm%02ds", m, s)
	}
	return fmt.Sprintf("~%ds", s)
}

// eta returns the estimated remaining time using a rolling average of the last
// 10 completed asset durations. Returns 0 when not enough data is available.
// Caller must hold r.mu.
func (r *progressRenderer) eta() time.Duration {
	if len(r.durations) == 0 || r.total <= r.done {
		return 0
	}
	window := r.durations
	if len(window) > 10 {
		window = window[len(window)-10:]
	}
	var sum time.Duration
	for _, d := range window {
		sum += d
	}
	avg := sum / time.Duration(len(window))
	return avg * time.Duration(r.total-r.done)
}

// Done stops the ticker, restores terminal state, and clears the status block.
// Safe to call multiple times.
func (r *progressRenderer) Done() {
	r.stopOnce.Do(func() { close(r.stop) })
	if r.headless {
		// Load pending review counts for the post-scan notice.
		if r.st != nil {
			ctx := context.Background()
			pendingRules, _ := r.st.GetFingerprintRules(ctx, "pending")
			pendingSuggs, _ := r.st.ListPlaybookSuggestions(ctx, "pending")
			if len(pendingRules)+len(pendingSuggs) > 0 {
				parts := []string{}
				if len(pendingRules) > 0 {
					parts = append(parts, fmt.Sprintf("%d fingerprint rule%s", len(pendingRules), pluralS(len(pendingRules))))
				}
				if len(pendingSuggs) > 0 {
					parts = append(parts, fmt.Sprintf("%d playbook suggestion%s", len(pendingSuggs), pluralS(len(pendingSuggs))))
				}
				r.mu.Lock()
				r.pendingReview = strings.Join(parts, " · ") + " pending"
				r.mu.Unlock()
			}
		}
		return // browse TUI owns the terminal; nothing to restore here
	}
	if r.restoreFn != nil {
		r.restoreFn()
		r.restoreFn = nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ansi {
		r.eraseBlock()
		r.drawn = false
		r.drawnLines = 0
	}
}

var validPlaybookName = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// safePlaybookName returns the base name of s if it matches the allowed
// character set, or "" if it contains path traversal or disallowed characters.
func safePlaybookName(s string) string {
	s = filepath.Base(s)
	if !validPlaybookName.MatchString(s) {
		return ""
	}
	return s
}

// ---------- fingerprints ----------

func cmdFingerprints(cfg *config.Config, args []string) {
	db, err := sqlitestore.Open(cfg.Store.Path)
	if err != nil {
		fatalf("open db: %v", err)
	}
	defer db.Close()
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

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func pluralS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
