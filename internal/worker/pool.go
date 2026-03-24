package worker

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/stormbane/beacon/internal/config"
	"github.com/stormbane/beacon/internal/enrichment"
	"github.com/stormbane/beacon/internal/module"
	"github.com/stormbane/beacon/internal/modules/surface"
	"github.com/stormbane/beacon/internal/report"
	"github.com/stormbane/beacon/internal/store"
)

// Pool is an in-memory job queue with a fixed number of worker goroutines.
// Each worker processes one scan at a time. Concurrent scans = concurrency value.
type Pool struct {
	concurrency int
	queue       chan Job
	st          store.Store
	cfg         *config.Config

	// logMu guards logs map
	logMu sync.RWMutex
	logs  map[string][]string // scanRunID → log lines

	// subsMu guards subs map
	subsMu sync.RWMutex
	subs   map[string][]chan string // scanRunID → subscriber channels (for SSE)
}

// NewPool creates a Pool with the given concurrency and starts worker goroutines.
// Call Stop() to drain and shut down.
func NewPool(concurrency int, st store.Store, cfg *config.Config) *Pool {
	p := &Pool{
		concurrency: concurrency,
		queue:       make(chan Job, 256),
		st:          st,
		cfg:         cfg,
		logs:        make(map[string][]string),
		subs:        make(map[string][]chan string),
	}
	for range concurrency {
		go p.run()
	}
	return p
}

// Submit enqueues a job. Returns immediately; the job runs asynchronously.
func (p *Pool) Submit(job Job) {
	p.queue <- job
}

// Subscribe returns a channel that receives log lines for a scan in real time.
// The channel is closed when the scan completes or fails.
// If the scan is already done, Logs() returns the full history.
func (p *Pool) Subscribe(scanRunID string) <-chan string {
	ch := make(chan string, 64)
	p.subsMu.Lock()
	p.subs[scanRunID] = append(p.subs[scanRunID], ch)
	p.subsMu.Unlock()
	return ch
}

// Logs returns all log lines recorded so far for a scan.
func (p *Pool) Logs(scanRunID string) []string {
	p.logMu.RLock()
	defer p.logMu.RUnlock()
	lines := p.logs[scanRunID]
	cp := make([]string, len(lines))
	copy(cp, lines)
	return cp
}

// run is the worker goroutine loop.
func (p *Pool) run() {
	for job := range p.queue {
		p.process(job)
	}
}

func (p *Pool) process(job Job) {
	ctx := context.Background()

	p.emit(job.ScanRunID, fmt.Sprintf("scan started: %s (%s)", job.Domain, job.ScanType))

	// Mark running
	run, err := p.st.GetScanRun(ctx, job.ScanRunID)
	if err != nil {
		p.emitError(job.ScanRunID, fmt.Sprintf("get scan run: %v", err))
		return
	}
	run.Status = store.StatusRunning
	_ = p.st.UpdateScanRun(ctx, run)

	// Run surface module
	mod, err := surface.New(surface.Config{
		NucleiBin:       p.cfg.NucleiBin,
		SubfinderBin:    "subfinder",
		AmmassBin:       p.cfg.AmmassBin,
		TestsslBin:      p.cfg.TestsslBin,
		GauBin:          p.cfg.GauBin,
		KatanaBin:       p.cfg.KatanaBin,
		GowitnessBin:    p.cfg.GowitnessBin,
		AnthropicAPIKey: p.cfg.AnthropicAPIKey,
		Store:           p.st,
		HttpxBin:        p.cfg.HttpxBin,
		DnsxBin:         p.cfg.DnsxBin,
		FfufBin:         p.cfg.FfufBin,
		Auth:            p.cfg.Auth,
	})
	if err != nil {
		p.emitError(job.ScanRunID, fmt.Sprintf("init scanner: %v", err))
		return
	}

	input := module.Input{
		Domain:              job.Domain,
		PermissionConfirmed: job.PermissionConfirmed,
		ScanRunID:           job.ScanRunID,
	}

	p.emit(job.ScanRunID, "running scanners...")
	findings, err := mod.Run(ctx, input, job.ScanType)
	if err != nil {
		run.Status = store.StatusFailed
		run.Error = err.Error()
		_ = p.st.UpdateScanRun(ctx, run)
		p.emitError(job.ScanRunID, fmt.Sprintf("scan failed: %v", err))
		return
	}

	p.emit(job.ScanRunID, fmt.Sprintf("scan complete: %d findings", len(findings)))

	if err := p.st.SaveFindings(ctx, job.ScanRunID, findings); err != nil {
		p.emitError(job.ScanRunID, fmt.Sprintf("save findings: %v", err))
		return
	}

	// Enrich
	p.emit(job.ScanRunID, "enriching findings...")
	var enricher enrichment.Enricher
	if p.cfg.AnthropicAPIKey != "" {
		ce, err := enrichment.NewClaudeDefault(p.cfg.AnthropicAPIKey)
		if err == nil {
			enricher = ce.WithCache(p.st)
		}
	}
	if enricher == nil {
		enricher = enrichment.NewNoop()
	}

	enriched, err := enricher.Enrich(ctx, findings)
	if err != nil {
		p.emitError(job.ScanRunID, fmt.Sprintf("enrich: %v", err))
		return
	}

	enriched, summary, err := enricher.ContextualizeAndSummarize(ctx, enriched, job.Domain)
	if err != nil {
		p.emitError(job.ScanRunID, fmt.Sprintf("contextualize: %v", err))
		return
	}

	// Drop findings Claude determined have no actionable value given other controls.
	filtered := enriched[:0]
	for _, ef := range enriched {
		if !ef.Omit {
			filtered = append(filtered, ef)
		}
	}
	enriched = filtered

	// Regression comparison: tag each finding as "new" or "recurring" vs. the previous scan.
	p.emit(job.ScanRunID, "comparing with previous scan...")
	prev, _ := p.st.GetPreviousEnrichedFindings(ctx, job.Domain, job.ScanRunID)
	if len(prev) > 0 {
		prevKeys := make(map[string]bool, len(prev))
		for _, ef := range prev {
			prevKeys[ef.Finding.CheckID+"|"+ef.Finding.Asset] = true
		}
		for i := range enriched {
			key := enriched[i].Finding.CheckID + "|" + enriched[i].Finding.Asset
			if prevKeys[key] {
				enriched[i].DeltaStatus = "recurring"
			} else {
				enriched[i].DeltaStatus = "new"
			}
		}
	}

	if err := p.st.SaveEnrichedFindings(ctx, job.ScanRunID, enriched); err != nil {
		p.emitError(job.ScanRunID, fmt.Sprintf("save enriched: %v", err))
		return
	}

	// Build report
	now := time.Now()
	run.Status = store.StatusCompleted
	run.CompletedAt = &now
	run.FindingCount = len(findings)
	_ = p.st.UpdateScanRun(ctx, run)

	rep, err := report.Build(report.Input{
		ScanRun:          *run,
		EnrichedFindings: enriched,
		ExecutiveSummary: summary,
	})
	if err != nil {
		p.emitError(job.ScanRunID, fmt.Sprintf("build report: %v", err))
		return
	}
	if err := p.st.SaveReport(ctx, rep); err != nil {
		p.emitError(job.ScanRunID, fmt.Sprintf("save report: %v", err))
		return
	}

	p.emit(job.ScanRunID, "done")
	p.closeSubscribers(job.ScanRunID)
}

// emit records a log line and broadcasts it to all current subscribers.
func (p *Pool) emit(scanRunID, line string) {
	ts := time.Now().Format("15:04:05")
	msg := fmt.Sprintf("[%s] %s", ts, line)

	fmt.Fprintln(os.Stderr, "beacond:", msg)

	p.logMu.Lock()
	p.logs[scanRunID] = append(p.logs[scanRunID], msg)
	p.logMu.Unlock()

	p.subsMu.RLock()
	for _, ch := range p.subs[scanRunID] {
		select {
		case ch <- msg:
		default: // subscriber too slow — drop
		}
	}
	p.subsMu.RUnlock()
}

func (p *Pool) emitError(scanRunID, msg string) {
	p.emit(scanRunID, "ERROR: "+msg)
	p.closeSubscribers(scanRunID)
}

func (p *Pool) closeSubscribers(scanRunID string) {
	p.subsMu.Lock()
	for _, ch := range p.subs[scanRunID] {
		close(ch)
	}
	delete(p.subs, scanRunID)
	p.subsMu.Unlock()
}
