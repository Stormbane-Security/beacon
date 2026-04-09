// Package chainengine orchestrates active attack path chaining.
//
// Unlike passive correlation (which matches findings after the fact), the chain
// engine ACTIVELY exploits one finding to discover the next. For example, an
// SSRF finding triggers a follow-up request through the SSRF to reach cloud
// metadata, or default credentials are used to log in and crawl authenticated
// pages.
//
// SAFETY: The engine ONLY runs in ScanAuthorized mode. Every chain step checks
// exploit.CheckSafety before execution. The engine refuses to start in Surface
// or Deep mode — this is exploitation-class code that requires --authorized
// and interactive legal acknowledgment.
package chainengine

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/stormbane-security/beacon/internal/exploit"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scan"
)

// Engine orchestrates active attack path chaining.
// It monitors findings as they arrive and triggers follow-up probes
// when a finding enables deeper exploitation.
//
// SAFETY: Every chain step checks exploit.CheckSafety before execution.
// The engine ONLY runs in ScanAuthorized mode. It refuses to start
// in Surface or Deep mode.
type Engine struct {
	scanType  module.ScanType
	maxSafety exploit.Safety
	client    *http.Client
	findings  []finding.Finding
	mu        sync.Mutex
}

// New creates a chain engine. Returns an error if scanType is not ScanAuthorized.
func New(scanType module.ScanType) (*Engine, error) {
	if scanType != module.ScanAuthorized {
		return nil, fmt.Errorf("chainengine: requires ScanAuthorized mode, got %q — chain engine performs active exploitation", scanType)
	}
	return &Engine{
		scanType:  scanType,
		maxSafety: exploit.SafetyFromScanType(scanType),
		client: &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("stopped after 5 redirects")
				}
				return nil
			},
		},
	}, nil
}

// OnFinding is called when any scanner produces a finding. The engine
// checks if this finding enables a known attack chain and, if so,
// executes the next step. Returns new findings discovered through chaining.
func (e *Engine) OnFinding(ctx context.Context, f finding.Finding) []finding.Finding {
	if ctx.Err() != nil {
		return nil
	}

	// Skip exploitation entirely when the honeypot scanner has flagged this
	// asset — continuing would alert the honeypot operator and waste time on
	// intentionally-exposed vulnerabilities.
	if sctx, ok := scan.FromContext(ctx); ok && sctx.HoneypotDetected() {
		log.Printf("[chain] skipping chain evaluation on %s — honeypot detected", f.Asset)
		return nil
	}

	// Store every incoming finding so cross-finding chains (e.g. XSS +
	// missing HttpOnly) can look up related findings on the same asset.
	e.mu.Lock()
	e.findings = append(e.findings, f)
	e.mu.Unlock()

	var results []finding.Finding
	for _, chain := range DefaultChains {
		if !chain.Matches(f) {
			continue
		}

		log.Printf("[chain] triggered %q by %s on %s", chain.Name, f.CheckID, f.Asset)

		newFindings := chain.Execute(ctx, e, f)
		if len(newFindings) > 0 {
			results = append(results, newFindings...)
		}
	}

	if len(results) > 0 {
		e.mu.Lock()
		e.findings = append(e.findings, results...)
		e.mu.Unlock()
	}

	return results
}

// Results returns all findings discovered through active chaining.
func (e *Engine) Results() []finding.Finding {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]finding.Finding, len(e.findings))
	copy(out, e.findings)
	return out
}
