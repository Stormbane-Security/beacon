package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/config"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/modules/surface"
	"github.com/stormbane-security/beacon/internal/store"
	sqlitestore "github.com/stormbane-security/beacon/internal/store/sqlite"
)

// RetestStatus indicates the outcome of retesting a single finding.
type RetestStatus string

const (
	RetestVulnerable RetestStatus = "STILL VULNERABLE"
	RetestRemediated RetestStatus = "REMEDIATED"
	RetestError      RetestStatus = "ERROR"
)

// RetestResult holds the outcome of retesting one finding.
type RetestResult struct {
	Finding finding.Finding
	Status  RetestStatus
	Detail  string
}

// cmdRetest loads findings from a previous scan and re-runs only the relevant
// scanners to check whether each finding is still present or has been remediated.
func cmdRetest(cfg *config.Config, args []string) {
	var scanID, outPath, severityFlag string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--id":
			i++
			if i < len(args) {
				scanID = args[i]
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

	if scanID == "" {
		fatalf("--id is required for retest mode\nUsage: beacon retest --id <scan-id>")
	}

	ctx := context.Background()

	st, err := sqlitestore.Open(cfg.Store.Path)
	if err != nil {
		fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	// Load the original scan run and its findings.
	run, err := st.GetScanRun(ctx, scanID)
	if err != nil {
		fatalf("get scan run: %v", err)
	}

	origFindings, err := st.GetFindings(ctx, scanID)
	if err != nil {
		fatalf("get findings for scan %s: %v", scanID, err)
	}

	if len(origFindings) == 0 {
		fmt.Println("No findings in the specified scan — nothing to retest.")
		return
	}

	// Apply severity filter.
	minSev := finding.ParseSeverity(severityFlag)
	if minSev > finding.SeverityInfo {
		var filtered []finding.Finding
		for _, f := range origFindings {
			if f.Severity >= minSev {
				filtered = append(filtered, f)
			}
		}
		origFindings = filtered
	}

	if len(origFindings) == 0 {
		fmt.Println("No findings match the severity filter — nothing to retest.")
		return
	}

	_, _ = fmt.Fprintf(os.Stderr, "beacon: retesting %d finding(s) from scan %s against %s\n",
		len(origFindings), scanID, run.Domain)

	// Group findings by scanner name so we run each scanner at most once per asset.
	type scannerAssetKey struct {
		scanner string
		asset   string
	}
	groups := make(map[scannerAssetKey][]finding.Finding)
	for _, f := range origFindings {
		key := scannerAssetKey{scanner: f.Scanner, asset: f.Asset}
		groups[key] = append(groups[key], f)
	}

	// Initialize the surface module for re-running scanners.
	mod, err := surface.New(surface.Config{
		NucleiBin:            cfg.NucleiBin,
		SubfinderBin:         "subfinder",
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
		OktaDomain:           cfg.OktaDomain,
		OktaToken:            cfg.OktaToken,
	})
	if err != nil {
		fatalf("init scanner module: %v", err)
	}

	// Run each unique (scanner, asset) combination and compare results.
	var results []RetestResult

	for key, keyFindings := range groups {
		_, _ = fmt.Fprintf(os.Stderr, "  retesting: scanner=%s asset=%s (%d findings)\n",
			key.scanner, key.asset, len(keyFindings))

		input := module.Input{
			Domain:              run.Domain,
			PermissionConfirmed: run.ScanType == module.ScanDeep || run.ScanType == module.ScanAuthorized,
			Scanners:            []string{key.scanner},
			Progress:            func(module.ProgressEvent) {}, // silent
		}

		newFindings, runErr := mod.Run(ctx, input, run.ScanType)
		if runErr != nil {
			// If the scanner errors, mark all its findings as ERROR.
			for _, f := range keyFindings {
				results = append(results, RetestResult{
					Finding: f,
					Status:  RetestError,
					Detail:  runErr.Error(),
				})
			}
			continue
		}

		// For each original finding, check if a matching finding exists in the new results.
		for _, orig := range keyFindings {
			if findMatchingFinding(orig, newFindings) {
				results = append(results, RetestResult{
					Finding: orig,
					Status:  RetestVulnerable,
				})
			} else {
				results = append(results, RetestResult{
					Finding: orig,
					Status:  RetestRemediated,
				})
			}
		}
	}

	// Render the retest report.
	output := renderRetestReport(run, results)

	if outPath != "" {
		if err := os.WriteFile(outPath, []byte(output), 0o600); err != nil {
			fatalf("write retest report: %v", err)
		}
		_, _ = fmt.Fprintf(os.Stderr, "beacon: retest report written to %s\n", outPath)
	} else {
		fmt.Print(output)
	}
}

// findMatchingFinding checks whether an original finding is still present in a
// new set of findings. Matching is by CheckID + Asset + key evidence fields
// (path, port, parameter) rather than exact content equality.
func findMatchingFinding(orig finding.Finding, newFindings []finding.Finding) bool {
	for _, nf := range newFindings {
		if nf.CheckID != orig.CheckID {
			continue
		}
		if nf.Asset != orig.Asset {
			continue
		}
		// Match on key evidence fields when present.
		if !evidenceFieldMatches(orig.Evidence, nf.Evidence, "path") {
			continue
		}
		if !evidenceFieldMatches(orig.Evidence, nf.Evidence, "port") {
			continue
		}
		if !evidenceFieldMatches(orig.Evidence, nf.Evidence, "parameter") {
			continue
		}
		return true
	}
	return false
}

// evidenceFieldMatches returns true if the given evidence key either doesn't
// exist in the original (nothing to compare) or has the same value in both.
func evidenceFieldMatches(orig, new map[string]any, key string) bool {
	origVal, origOK := orig[key]
	if !origOK {
		return true // field not present in original — don't require it in new
	}
	newVal, newOK := new[key]
	if !newOK {
		return true // field not in new results — don't fail the match on missing evidence
	}
	return fmt.Sprintf("%v", origVal) == fmt.Sprintf("%v", newVal)
}

// renderRetestReport produces a colored text report of retest results.
func renderRetestReport(run *store.ScanRun, results []RetestResult) string {
	var b strings.Builder

	_, _ = fmt.Fprintf(&b, "Retest Report — %s\n", run.Domain)
	_, _ = fmt.Fprintf(&b, "Original Scan: %s (%s)\n", run.ID, run.StartedAt.Format(time.RFC3339))
	_, _ = fmt.Fprintf(&b, "Retest Time:   %s\n", time.Now().Format(time.RFC3339))
	b.WriteString(strings.Repeat("─", 72) + "\n\n")

	// Count statuses.
	var vulnCount, remCount, errCount int
	for _, r := range results {
		switch r.Status {
		case RetestVulnerable:
			vulnCount++
		case RetestRemediated:
			remCount++
		case RetestError:
			errCount++
		}
	}

	_, _ = fmt.Fprintf(&b, "Summary: %d still vulnerable, %d remediated, %d errors (of %d total)\n\n",
		vulnCount, remCount, errCount, len(results))

	// Group by status for readability.
	statusOrder := []RetestStatus{RetestVulnerable, RetestRemediated, RetestError}
	statusLabels := map[RetestStatus]string{
		RetestVulnerable: "\033[31mSTILL VULNERABLE\033[0m",
		RetestRemediated: "\033[32mREMEDIATED\033[0m",
		RetestError:      "\033[33mERROR\033[0m",
	}

	for _, status := range statusOrder {
		var matching []RetestResult
		for _, r := range results {
			if r.Status == status {
				matching = append(matching, r)
			}
		}
		if len(matching) == 0 {
			continue
		}

		_, _ = fmt.Fprintf(&b, "── %s (%d) ──\n", statusLabels[status], len(matching))
		for _, r := range matching {
			_, _ = fmt.Fprintf(&b, "  [%s] %s on %s\n",
				r.Finding.CheckID, r.Finding.Title, r.Finding.Asset)
			if r.Detail != "" {
				_, _ = fmt.Fprintf(&b, "    detail: %s\n", r.Detail)
			}
		}
		b.WriteString("\n")
	}

	return b.String()
}
