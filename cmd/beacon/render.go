package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/playbook"
	"github.com/stormbane-security/beacon/internal/report"
	"github.com/stormbane-security/beacon/internal/store"
	"golang.org/x/term"
)

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

	stopOnce    sync.Once
	stop        chan struct{}
	detachOnce  sync.Once
	detached    chan struct{} // closed when user presses b to detach (browse while scan runs)
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

// newPlainRenderer creates a progressRenderer that outputs line-by-line text
// to stderr with no interactive TUI, no raw terminal mode, and no render ticker.
// Used with --no-tui for headless / CI / scripting scenarios.
func newPlainRenderer(verbose bool, minSeverity finding.Severity) *progressRenderer {
	return &progressRenderer{
		phase:        "discovering",
		mode:         "progress",
		verbose:      verbose,
		ansi:         false, // force line-by-line output, never TUI
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
			// Close channels under the lock so that a concurrent
			// attachJob reset cannot swap them between the decision
			// to close and the actual close call.
			r.stopOnce.Do(func() { close(r.stop) })
			r.detachOnce.Do(func() { close(r.detached) })
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
			// Signal detach back to the browse TUI. Close under the lock
			// to avoid a race with attachJob channel reset.
			r.stopOnce.Do(func() { close(r.stop) })
			r.detachOnce.Do(func() { close(r.detached) })
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
				r.stopOnce.Do(func() { close(r.stop) })
				r.detachOnce.Do(func() { close(r.detached) })
				r.mu.Unlock()
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
		// -- Network --
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

		// -- HTTP --
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

		// -- Responding paths --
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

		// -- Technology stack --
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

		// -- Auth --
		if ev.AuthSystem != "" || ev.AuthScheme != "" {
			section("AUTHENTICATION")
			if ev.AuthSystem != "" {
				add("  Auth system   %s", ev.AuthSystem)
			}
		}

		// -- TLS --
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

		// -- DNS --
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

		// -- AI / LLM --
		if len(ev.AIEndpoints) > 0 || ev.LLMProvider != "" {
			section("AI / LLM")
			if ev.LLMProvider != "" {
				add("  Provider      %s", ev.LLMProvider)
			}
			for _, ep := range ev.AIEndpoints {
				add("  Endpoint      %s", ep)
			}
		}

		// -- Web3 --
		if len(ev.Web3Signals) > 0 || len(ev.ContractAddresses) > 0 {
			section("WEB3")
			if len(ev.Web3Signals) > 0 {
				add("  Signals       %s", strings.Join(ev.Web3Signals, ", "))
			}
			for _, addr := range ev.ContractAddresses {
				add("  Contract      %s", addr)
			}
		}

		// -- Third-party vendors --
		if len(ev.VendorSignals) > 0 {
			section("THIRD-PARTY VENDORS")
			add("  %s", strings.Join(ev.VendorSignals, ", "))
		}

		// -- Detection evidence: which response headers drove technology classification --
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

		// -- Remaining response headers (sorted) --
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

	// -- Open ports --
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
	r.mu.Lock()
	headless := r.headless
	r.mu.Unlock()
	if headless {
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
