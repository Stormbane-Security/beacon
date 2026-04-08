package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/stormbane-security/beacon/internal/asset"
	"github.com/stormbane-security/beacon/internal/config"
	"encoding/json"
	"github.com/stormbane-security/beacon/internal/enrichment"
	"github.com/stormbane-security/beacon/internal/exploit"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/modules/surface"
	"github.com/stormbane-security/beacon/internal/report"
	"github.com/stormbane-security/beacon/internal/store"
	sqlitestore "github.com/stormbane-security/beacon/internal/store/sqlite"
	"golang.org/x/term"
)

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
	if !j.paused || j.pauseCh == nil {
		j.pauseMu.Unlock()
		return
	}
	ch := j.pauseCh
	j.pauseMu.Unlock()
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
	detailMaxOff    int

	// Asset roster
	execCursor int
	execOff    int

	// Asset detail (per-asset findings pager)
	selectedExec    *store.AssetExecution
	execFindCursor  int
	execFindOff     int

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

	// Exploit action state.
	actionList   []exploit.Action  // actions available for selected finding
	actionCursor int               // selected action index
	actionResult *exploit.ActionResult // result of last action run
	actionRunning bool             // true while an action is executing

	// Asset detail scroll state.
	assetDetailOff      int  // scroll offset for the full evidence/findings lines view
	assetDetailMaxOff   int
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
	cmdBrowseWithAttach(cfg, "")
}

// cmdBrowseWithAttach opens the browser and, if attachRunID is non-empty,
// immediately attaches to that scan's live view instead of showing the list.
func cmdBrowseWithAttach(cfg *config.Config, attachRunID string) {
	for {
		res := browseInteractive(cfg, attachRunID)
		attachRunID = "" // only auto-attach on the first iteration
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
			if err := st.SaveFindings(bgCtx, run.ID, findings); err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "beacon: save findings %s: %v\n", run.ID, err)
			}
		}

		// Build and persist the asset graph so it is available for
		// `beacon report --format graph` and included in JSON reports.
		graphBuilder := asset.NewBuilder(run.ID, domain)
		graphBuilder.AddDomainAsset(domain, nil, "surface")
		graphBuilder.AddFindings(findings)
		g := graphBuilder.Build()
		if graphJSON, gErr := json.Marshal(g); gErr == nil {
			_ = st.SaveAssetGraph(bgCtx, run.ID, graphJSON)
		}
	}()

	return job
}

// browseInteractive runs the raw-terminal TUI and returns a scan run ID if the
// user pressed 'r' to export a report, or "" to simply exit.
// If attachRunID is non-empty, the browser immediately attaches to that scan's
// live view so the user lands inside the scan they just detached from.
func browseInteractive(cfg *config.Config, attachRunID string) browseResult {
	ctx := context.Background()
	st, err := sqlitestore.Open(cfg.Store.Path)
	if err != nil {
		fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

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
	defer func() { _ = term.Restore(fd, old) }()

	// Hide cursor, enter alternate screen.
	_, _ = fmt.Fprint(os.Stderr, "\x1b[?1049h\x1b[?25l")
	defer func() { _, _ = fmt.Fprint(os.Stderr, "\x1b[?25h\x1b[?1049l") }()

	bs := &browseState{scans: scans}

	// If we were launched from a detached scan, auto-attach to it so the user
	// lands back inside the scan they just left rather than the scan list.
	if attachRunID != "" {
		if job, ok := getLiveJob(attachRunID); ok {
			// Position cursor on the matching scan in the list.
			for i, r := range bs.scans {
				if r.ID == attachRunID {
					bs.scanCursor = i
					break
				}
			}
			attachJob(bs, job)
		}
	}

	browseRender(bs)

	// Read stdin in a goroutine so the main loop can also respond to ticks.
	// The done channel signals the goroutine to exit when browseInteractive
	// returns. Because os.Stdin.Read blocks, the goroutine may linger until the
	// next keypress or process exit; the done check prevents it from sending on
	// a closed inputCh after the function returns.
	inputCh := make(chan []byte, 4)
	browseDone := make(chan struct{})
	go func() {
		ibuf := make([]byte, 16)
		for {
			n, err := os.Stdin.Read(ibuf)
			if err != nil || n == 0 {
				close(inputCh)
				return
			}
			select {
			case <-browseDone:
				return
			default:
			}
			cp := make([]byte, n)
			copy(cp, ibuf[:n])
			select {
			case inputCh <- cp:
			case <-browseDone:
				return
			}
		}
	}()
	defer close(browseDone)

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
				// Detect detach: only when the user explicitly pressed 'b' to
				// close the detached channel. Do NOT auto-detach when the scan
				// finishes — keep showing the final state so the user can review
				// findings. They navigate back manually with 'b'.
				detachNow := false
				select {
				case <-job.renderer.detached:
					detachNow = true
				default:
				}
				if detachNow {
					bs.attachedJob = nil
					_, _ = fmt.Fprint(os.Stderr, "\x1b[?1049h\x1b[?25l")
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
				// Reload the full scan list so new scans started from
				// other terminals appear without restarting browse.
				if updated, err := st.ListRecentScanRuns(ctx, 200); err == nil {
					// Preserve cursor position by matching the currently
					// selected scan ID after the refresh.
					var selectedID string
					if bs.scanCursor < len(bs.scans) {
						selectedID = bs.scans[bs.scanCursor].ID
					}
					bs.scans = updated
					if selectedID != "" {
						for i, r := range bs.scans {
							if r.ID == selectedID {
								bs.scanCursor = i
								break
							}
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
				_, _ = fmt.Fprint(os.Stderr, "\x1b[?1049h\x1b[?25l")
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
				_, _ = fmt.Fprint(os.Stderr, "\x1b[?1049h\x1b[?25l")
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
				_ = term.Restore(fd, old)
				_, _ = fmt.Fprint(os.Stderr, "\x1b[?25h\x1b[?1049l\x1b[2J\x1b[H")
				_, _ = fmt.Fprint(os.Stderr, "New scan\n\n")
				_, _ = fmt.Fprint(os.Stderr, "  1) Surface scan       (passive recon, safe to run without permission)\n")
				_, _ = fmt.Fprint(os.Stderr, "  2) Deep scan          (active probes — requires explicit permission)\n")
				_, _ = fmt.Fprint(os.Stderr, "\nScan type [1, blank to cancel]: ")
				reader := bufio.NewReader(os.Stdin)
				typeLine, err := reader.ReadString('\n')
				if err != nil {
					typeLine = ""
				}
				typeChoice := strings.TrimSpace(typeLine)

				// Blank input at any step cancels back to the TUI.
				if typeChoice == "" {
					old2, _ := term.MakeRaw(fd)
					old = old2
					_, _ = fmt.Fprint(os.Stderr, "\x1b[?1049h\x1b[?25l")
					browseRender(bs)
					continue
				}

				scanType := module.ScanSurface
				permConfirmed := false
				authConfirmed := false
				switch typeChoice {
				case "2":
					scanType = module.ScanDeep
					_, _ = fmt.Fprint(os.Stderr, "\nConfirm you have permission to actively probe the target [y/N]: ")
					permLine, err := reader.ReadString('\n')
					if err != nil {
						permLine = ""
					}
					if strings.ToLower(strings.TrimSpace(permLine)) != "y" {
						_, _ = fmt.Fprint(os.Stderr, "Deep scan cancelled — permission not confirmed.\n")
						_, _ = fmt.Fprint(os.Stderr, "Press Enter to return...")
						reader.ReadString('\n') //nolint:errcheck
						old2, _ := term.MakeRaw(fd)
						old = old2
						_, _ = fmt.Fprint(os.Stderr, "\x1b[?1049h\x1b[?25l")
						browseRender(bs)
						continue
					}
					permConfirmed = true
				}

				_, _ = fmt.Fprint(os.Stderr, "\nTarget domain (or blank to cancel): ")
				domainLine, err := reader.ReadString('\n')
				if err != nil {
					domainLine = ""
				}
				domain := strings.TrimSpace(domainLine)

				old2, _ := term.MakeRaw(fd)
				old = old2
				_, _ = fmt.Fprint(os.Stderr, "\x1b[?1049h\x1b[?25l")

				if domain == "" || strings.ContainsAny(domain, " \t\r\n") {
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
				_, _ = fmt.Fprint(os.Stderr, "\x1b[?1049h\x1b[?25l")
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
					bs.findMinSev = finding.SeverityLow
				case '3':
					bs.findMinSev = finding.SeverityMedium
				case '4':
					bs.findMinSev = finding.SeverityHigh
				case '5':
					bs.findMinSev = finding.SeverityCritical
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
				bs.actionList = nil
				bs.actionResult = nil
				bs.actionCursor = 0
			}
			if isDown {
				if len(bs.actionList) > 0 && bs.actionCursor < len(bs.actionList)-1 {
					bs.actionCursor++
				}
				if bs.detailOff < bs.detailMaxOff {
					bs.detailOff++
				}
			}
			if isUp {
				if len(bs.actionList) > 0 && bs.actionCursor > 0 {
					bs.actionCursor--
				}
				if bs.detailOff > 0 {
					bs.detailOff--
				}
			}
			if b[0] == 'x' && len(bs.actionList) > 0 && !bs.actionRunning {
				bs.actionRunning = true
				bs.actionResult = nil
				actionIdx := bs.actionCursor
				actionFinding := bs.selectedFinding.Finding
				go func() {
					actionCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					defer cancel()
					result, err := bs.actionList[actionIdx].Run(actionCtx, actionFinding)
					if err != nil {
						result = &exploit.ActionResult{Success: false, Output: fmt.Sprintf("Error: %v", err)}
					}
					bs.actionResult = result
					bs.actionRunning = false
				}()
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
			if isDown && bs.assetDetailOff < bs.assetDetailMaxOff {
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

	_, _ = fmt.Fprint(os.Stderr, buf.String())
}

// ── Browse helpers ────────────────────────────────────────────────────────────

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
	sort.Slice(out, func(i, j int) bool {
		return out[i].Finding.Severity.Weight() > out[j].Finding.Severity.Weight()
	})
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
		job.renderer.detachOnce = sync.Once{}
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
	_ = term.Restore(fd, old)
	_, _ = fmt.Fprint(os.Stderr, "\x1b[?25h\x1b[?1049l")

	_, _ = fmt.Fprint(os.Stderr, "\nExport report\n\n")
	_, _ = fmt.Fprint(os.Stderr, "  1) Text      (plain text, terminal-friendly)\n")
	_, _ = fmt.Fprint(os.Stderr, "  2) Markdown  (.md)\n")
	_, _ = fmt.Fprint(os.Stderr, "  3) HTML      (.html)\n")
	_, _ = fmt.Fprint(os.Stderr, "  4) JSON      (.json)\n")
	_, _ = fmt.Fprint(os.Stderr, "\nFormat [1-4, blank to cancel]: ")

	reader := bufio.NewReader(os.Stdin)
	choice, err := reader.ReadString('\n')
	if err != nil {
		choice = ""
	}
	choice = strings.TrimSpace(choice)
	if choice == "" {
		return browseResult{}
	}

	extMap := map[string]string{"1": "txt", "2": "md", "3": "html", "4": "json"}
	fmtMap := map[string]string{"1": "text", "2": "markdown", "3": "html", "4": "json"}
	ext, ok := extMap[choice]
	if !ok {
		_, _ = fmt.Fprint(os.Stderr, "Invalid choice — cancelled.\n")
		return browseResult{}
	}
	format := fmtMap[choice]

	// Default output path.
	date := time.Now().Format("2006-01-02")
	defaultPath := fmt.Sprintf("%s-%s.%s", domain, date, ext)
	_, _ = fmt.Fprintf(os.Stderr, "Output file [%s]: ", defaultPath)
	pathLine, err := reader.ReadString('\n')
	if err != nil {
		pathLine = ""
	}
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
		_, _ = fmt.Fprintf(buf, "\x1b[2K\r  \x1b[1;36mBeacon — Scan History\x1b[0m  \x1b[31m⚠ cannot delete a running scan — %s\x1b[0m\n", bs.deleteBlockedMsg)
	} else if bs.confirmingDelete {
		_, _ = fmt.Fprintf(buf, "\x1b[2K\r  \x1b[1;36mBeacon — Scan History\x1b[0m  \x1b[31mDelete this scan? [y/N]\x1b[0m\n")
	} else if bs.confirmingPurge {
		_, _ = fmt.Fprintf(buf, "\x1b[2K\r  \x1b[1;36mBeacon — Scan History\x1b[0m  \x1b[31mPurge all orphaned/failed/stopped scans? [y/N]\x1b[0m\n")
	} else {
		_, _ = fmt.Fprintf(buf, "\x1b[2K\r  \x1b[1;36mBeacon — Scan History\x1b[0m  \x1b[90m[↵] attach/view  [a] assets  [e] export  [n] new  [s] stop  [p] pause  [d] delete  [X] purge  [q] quit  %d scans\x1b[0m\n", len(bs.scans))
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
	_, _ = fmt.Fprintf(buf, "\x1b[2K\r  \x1b[90m%-*s  %-7s  %-14s  %s\x1b[0m\n", domainW, "DOMAIN", "TYPE", "STATUS", "STARTED")

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
			_, _ = fmt.Fprintf(buf, "\x1b[7m\x1b[2K\r%s\x1b[0m\n", line)
		} else {
			_, _ = fmt.Fprintf(buf, "\x1b[2K\r%s\n", line)
		}
	}
	_, _ = fmt.Fprintf(buf, "\x1b[2K\r  \x1b[90m%d of %d\x1b[0m\n", bs.scanCursor+1, len(bs.scans))
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
	case finding.SeverityLow:
		filterLabel = "  \x1b[36mMin: LOW\x1b[0m"
	case finding.SeverityMedium:
		filterLabel = "  \x1b[33mMin: MED\x1b[0m"
	case finding.SeverityHigh:
		filterLabel = "  \x1b[31mMin: HIGH\x1b[0m"
	case finding.SeverityCritical:
		filterLabel = "  \x1b[1;31mMin: CRIT\x1b[0m"
	default:
		filterLabel = ""
	}

	_, _ = fmt.Fprintf(buf, "\x1b[2K\r  \x1b[1;36m%s\x1b[0m  \x1b[90m%s  [↵] detail  [j/k] move  [1-5] filter  [e] export  [q/b] back  %d/%d\x1b[0m%s\n",
		domain, started, len(filtered), len(bs.findings), filterLabel)
	// Title column fills available terminal width; minimum 40.
	// Layout: 2(indent) + 10(sev) + 2(sep) + titleW + 2(sep) + ~32(checkid)
	titleW := termW - 48
	if titleW < 40 {
		titleW = 40
	}
	_, _ = fmt.Fprintf(buf, "\x1b[2K\r  \x1b[90m%-8s  %-*s  %s\x1b[0m\n", "SEV", titleW, "TITLE", "CHECK ID")

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
			_, _ = fmt.Fprintf(buf, "\x1b[7m\x1b[2K\r%s\x1b[0m\n", line)
		} else {
			_, _ = fmt.Fprintf(buf, "\x1b[2K\r%s\n", line)
		}
	}
	count := len(filtered)
	if count == 0 {
		_, _ = fmt.Fprintf(buf, "\x1b[2K\r  \x1b[90mNo findings match filter\x1b[0m\n")
	} else {
		_, _ = fmt.Fprintf(buf, "\x1b[2K\r  \x1b[90m%d of %d\x1b[0m\n", bs.findCursor+1, count)
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
		lines = append(lines, wordWrapLines(f.Description, termW-4)...)
		lines = append(lines, "")
	}

	if ef.Explanation != "" {
		lines = append(lines, "\x1b[1;33mExplanation\x1b[0m")
		lines = append(lines, wordWrapLines(ef.Explanation, termW-4)...)
		lines = append(lines, "")
	}

	if ef.Impact != "" {
		lines = append(lines, "\x1b[1;31mImpact\x1b[0m")
		lines = append(lines, wordWrapLines(ef.Impact, termW-4)...)
		lines = append(lines, "")
	}

	if ef.Remediation != "" {
		lines = append(lines, "\x1b[1;32mRemediation\x1b[0m")
		lines = append(lines, wordWrapLines(ef.Remediation, termW-4)...)
		lines = append(lines, "")
	}

	if ef.TechSpecificRemediation != "" {
		lines = append(lines, "\x1b[1;32mTech-Specific Fix\x1b[0m")
		lines = append(lines, wordWrapLines(ef.TechSpecificRemediation, termW-4)...)
		lines = append(lines, "")
	}

	if ef.MitigatedBy != "" {
		lines = append(lines, "\x1b[90mNote: mitigated by "+ef.MitigatedBy+"\x1b[0m")
		lines = append(lines, "")
	}

	// Populate actions list for this finding (once, when entering detail view).
	if bs.actionList == nil {
		// Add verify command as fallback proof action.
		proofF := f
		if proofF.ProofCommand == "" {
			proofF.ProofCommand = report.VerifyCmd(f.CheckID, f.Asset)
		}
		bs.actionList = exploit.ActionsForFinding(proofF)
		bs.actionCursor = 0
		bs.actionResult = nil
	}

	if len(bs.actionList) > 0 {
		lines = append(lines, "\x1b[1;34mActions\x1b[0m  \x1b[90m([x] run · [↑↓] select · [y] copy proof)\x1b[0m")
		for i, a := range bs.actionList {
			cursor := "  "
			if i == bs.actionCursor {
				cursor = "\x1b[1;33m▸ \x1b[0m"
			}
			lines = append(lines, fmt.Sprintf("%s\x1b[36m%s\x1b[0m \x1b[90m— %s\x1b[0m", cursor, a.Name, a.Description))
		}
		lines = append(lines, "")
	} else {
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
	}

	// Show action result if present.
	if bs.actionResult != nil {
		status := "\x1b[1;32m✓ Success\x1b[0m"
		if !bs.actionResult.Success {
			status = "\x1b[1;31m✗ Failed\x1b[0m"
		}
		lines = append(lines, fmt.Sprintf("\x1b[1mResult\x1b[0m  %s", status))
		for _, line := range strings.Split(bs.actionResult.Output, "\n") {
			lines = append(lines, "  "+line)
		}
		lines = append(lines, "")
	}

	if bs.actionRunning {
		lines = append(lines, "\x1b[1;33m⠋ Running action...\x1b[0m")
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
	bs.detailMaxOff = maxOff
	if bs.detailOff > maxOff {
		bs.detailOff = maxOff
	}

	// Header — show copy flash feedback if present, otherwise normal hint bar.
	if bs.copyFlash != "" {
		_, _ = fmt.Fprintf(buf, "\x1b[2K\r  %s  \x1b[90m[j/k] scroll  [b/q] back\x1b[0m\n", bs.copyFlash)
		bs.copyFlash = "" // clear after one render
	} else {
		_, _ = fmt.Fprintf(buf, "\x1b[2K\r  \x1b[90m[j/k] scroll  [y] copy proof cmd  [a] asset  [b/q] back\x1b[0m\n")
	}

	end := bs.detailOff + bodyLines
	if end > len(lines) {
		end = len(lines)
	}
	for _, l := range lines[bs.detailOff:end] {
		_, _ = fmt.Fprintf(buf, "\x1b[2K\r  %s\n", l)
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
	_, _ = fmt.Fprintf(buf, "\x1b[2K\r  \x1b[1;36m%s — Assets\x1b[0m  \x1b[90m[↵] detail  [f] findings  [j/k] move  [q/b] back  %d assets\x1b[0m\n",
		domain, total)
	// Asset name column fills available terminal width; minimum 42.
	// Layout: 2(cursor) + nameW + 2(sep) + 20(tech) + 2(sep) + ~20(badge)
	nameW := termW - 46
	if nameW < 42 {
		nameW = 42
	}
	_, _ = fmt.Fprintf(buf, "\x1b[2K\r  \x1b[90m%-*s  %-20s  %s\x1b[0m\n", nameW, "Asset", "Tech/Cloud", "Findings")

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
			_, _ = fmt.Fprintf(buf, "\x1b[7m\x1b[2K\r%s\x1b[0m\n", line)
		} else {
			_, _ = fmt.Fprintf(buf, "\x1b[2K\r%s\n", line)
		}
	}
	_, _ = fmt.Fprintf(buf, "\x1b[2K\r  \x1b[90m%d of %d\x1b[0m\n", bs.execCursor+1, total)
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
	_, _ = fmt.Fprintf(buf, "\x1b[2K\r  \x1b[90m◀\x1b[0m \x1b[1;36m%s\x1b[0m  \x1b[90m[j/k] scroll  [↵] open finding  [b/q] back\x1b[0m\n", name)

	bodyLines := termH - 2
	if bodyLines < 1 {
		bodyLines = 1
	}
	maxOff := len(lines) - bodyLines
	if maxOff < 0 {
		maxOff = 0
	}
	bs.assetDetailMaxOff = maxOff
	if bs.assetDetailOff > maxOff {
		bs.assetDetailOff = maxOff
	}

	end := bs.assetDetailOff + bodyLines
	if end > len(lines) {
		end = len(lines)
	}
	for _, l := range lines[bs.assetDetailOff:end] {
		_, _ = fmt.Fprintf(buf, "\x1b[2K\r  %s\n", l)
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
	if n <= 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	if n == 1 {
		return "…"
	}
	return s[:n-1] + "…"
}
