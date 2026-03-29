// Package memory provides an in-memory Store implementation for tests.
package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/stormbane/beacon/internal/enrichment"
	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
	"github.com/stormbane/beacon/internal/store"
)

// Store is a thread-safe in-memory store for tests.
type Store struct {
	mu           sync.RWMutex
	targets      map[string]*store.Target
	runs         map[string]*store.ScanRun
	findings     map[string][]finding.Finding
	enriched     map[string][]enrichment.EnrichedFinding
	reports      map[string]*store.Report
	suggestions  []*store.PlaybookSuggestion
	ecache       map[finding.CheckID][3]string // [explanation, impact, remediation]
	correlations []store.CorrelationFinding
	suppressions map[string]*store.FindingSuppression // id -> suppression
	assetGraphs  map[string][]byte                      // scanRunID -> graph JSON
}

func New() *Store {
	return &Store{
		targets:      make(map[string]*store.Target),
		runs:         make(map[string]*store.ScanRun),
		findings:     make(map[string][]finding.Finding),
		enriched:     make(map[string][]enrichment.EnrichedFinding),
		reports:      make(map[string]*store.Report),
		ecache:       make(map[finding.CheckID][3]string),
		suppressions: make(map[string]*store.FindingSuppression),
	}
}

func (s *Store) UpsertTarget(_ context.Context, domain string) (*store.Target, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.targets[domain]; ok {
		return t, nil
	}
	t := &store.Target{ID: uuid.NewString(), Domain: domain, CreatedAt: time.Now()}
	s.targets[domain] = t
	return t, nil
}

func (s *Store) GetTarget(_ context.Context, domain string) (*store.Target, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if t, ok := s.targets[domain]; ok {
		return t, nil
	}
	return nil, fmt.Errorf("target not found: %s", domain)
}

func (s *Store) ListTargets(_ context.Context) ([]store.Target, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]store.Target, 0, len(s.targets))
	for _, t := range s.targets {
		out = append(out, *t)
	}
	// Sort by CreatedAt descending for deterministic ordering.
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

func (s *Store) CreateScanRun(_ context.Context, run *store.ScanRun) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if run.ID == "" {
		run.ID = uuid.NewString()
	}
	cp := *run
	s.runs[run.ID] = &cp
	return nil
}

func (s *Store) UpdateScanRun(_ context.Context, run *store.ScanRun) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.runs[run.ID]; !ok {
		return fmt.Errorf("scan run not found: %s", run.ID)
	}
	cp := *run
	s.runs[run.ID] = &cp
	return nil
}

func (s *Store) GetScanRun(_ context.Context, id string) (*store.ScanRun, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if r, ok := s.runs[id]; ok {
		cp := *r
		return &cp, nil
	}
	return nil, fmt.Errorf("scan run not found: %s", id)
}

func (s *Store) ListScanRuns(_ context.Context, domain string) ([]store.ScanRun, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []store.ScanRun
	for _, r := range s.runs {
		if r.Domain == domain {
			out = append(out, *r)
		}
	}
	// Sort by StartedAt descending for deterministic ordering (map iteration is random).
	sort.Slice(out, func(i, j int) bool {
		return out[i].StartedAt.After(out[j].StartedAt)
	})
	return out, nil
}

func (s *Store) SaveFindings(_ context.Context, scanRunID string, findings []finding.Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.findings[scanRunID] = append(s.findings[scanRunID], findings...)
	return nil
}

func (s *Store) GetFindings(_ context.Context, scanRunID string) ([]finding.Finding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.findings[scanRunID], nil
}

func (s *Store) SaveEnrichedFindings(_ context.Context, scanRunID string, ef []enrichment.EnrichedFinding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enriched[scanRunID] = ef
	return nil
}

func (s *Store) GetEnrichedFindings(_ context.Context, scanRunID string) ([]enrichment.EnrichedFinding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.enriched[scanRunID], nil
}

func (s *Store) GetPreviousEnrichedFindings(_ context.Context, domain, currentScanRunID string) ([]enrichment.EnrichedFinding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Find the most recent completed scan run for domain excluding currentScanRunID.
	var prevRun *store.ScanRun
	for _, r := range s.runs {
		if r.Domain != domain || r.ID == currentScanRunID || r.Status != store.StatusCompleted {
			continue
		}
		if prevRun == nil {
			prevRun = r
			continue
		}
		// Keep the run with the later CompletedAt.
		if r.CompletedAt != nil && (prevRun.CompletedAt == nil || r.CompletedAt.After(*prevRun.CompletedAt)) {
			prevRun = r
		}
	}
	if prevRun == nil {
		return nil, nil
	}
	return s.enriched[prevRun.ID], nil
}

func (s *Store) SaveReport(_ context.Context, r *store.Report) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *r
	s.reports[r.ScanRunID] = &cp
	return nil
}

func (s *Store) GetReport(_ context.Context, scanRunID string) (*store.Report, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if r, ok := s.reports[scanRunID]; ok {
		cp := *r
		return &cp, nil
	}
	return nil, fmt.Errorf("report not found for scan run: %s", scanRunID)
}

func (s *Store) SaveAssetExecution(_ context.Context, exec *store.AssetExecution) error {
	return nil
}

func (s *Store) ListAssetExecutions(_ context.Context, scanRunID string) ([]store.AssetExecution, error) {
	return nil, nil
}

func (s *Store) SaveUnmatchedAsset(_ context.Context, u *store.UnmatchedAsset) error {
	return nil
}

func (s *Store) FingerprintExists(_ context.Context, fingerprint string) (bool, error) {
	return false, nil
}

func (s *Store) ListUnmatchedAssets(_ context.Context) ([]store.UnmatchedAsset, error) {
	return nil, nil
}

func (s *Store) SavePlaybookSuggestion(_ context.Context, sg *store.PlaybookSuggestion) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sg.ID == "" {
		sg.ID = fmt.Sprintf("ps-%d", len(s.suggestions)+1)
	}
	cp := *sg
	s.suggestions = append(s.suggestions, &cp)
	return nil
}

func (s *Store) ListPlaybookSuggestions(_ context.Context, status string) ([]store.PlaybookSuggestion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]store.PlaybookSuggestion, 0)
	for _, sg := range s.suggestions {
		if status == "" || sg.Status == status {
			out = append(out, *sg)
		}
	}
	return out, nil
}

func (s *Store) UpdatePlaybookSuggestion(_ context.Context, sg *store.PlaybookSuggestion) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, existing := range s.suggestions {
		if existing.ID == sg.ID {
			cp := *sg
			s.suggestions[i] = &cp
			return nil
		}
	}
	return fmt.Errorf("suggestion not found: %s", sg.ID)
}

func (s *Store) GetEnrichmentCache(_ context.Context, checkID finding.CheckID) (explanation, impact, remediation string, found bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if v, ok := s.ecache[checkID]; ok {
		return v[0], v[1], v[2], true
	}
	return "", "", "", false
}

func (s *Store) SaveEnrichmentCache(_ context.Context, checkID finding.CheckID, explanation, impact, remediation string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ecache[checkID] = [3]string{explanation, impact, remediation}
	return nil
}

func (s *Store) SaveCorrelationFindings(_ context.Context, findings []store.CorrelationFinding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range findings {
		f := findings[i]
		if f.ID == "" {
			f.ID = uuid.NewString()
		}
		if f.CreatedAt.IsZero() {
			f.CreatedAt = time.Now()
		}
		s.correlations = append(s.correlations, f)
	}
	return nil
}

func (s *Store) ListCorrelationFindings(_ context.Context, domain string) ([]store.CorrelationFinding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []store.CorrelationFinding
	for _, f := range s.correlations {
		if f.Domain == domain {
			out = append(out, f)
		}
	}
	return out, nil
}

func (s *Store) ListRecentScanRuns(_ context.Context, limit int) ([]store.ScanRun, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var completed []store.ScanRun
	for _, r := range s.runs {
		if r.Status == store.StatusCompleted {
			completed = append(completed, *r)
		}
	}

	// Sort by CompletedAt descending; nil CompletedAt goes last.
	sort.Slice(completed, func(i, j int) bool {
		ti := completed[i].CompletedAt
		tj := completed[j].CompletedAt
		if ti == nil && tj == nil {
			return false
		}
		if ti == nil {
			return false
		}
		if tj == nil {
			return true
		}
		return ti.After(*tj)
	})

	if limit > 0 && len(completed) > limit {
		completed = completed[:limit]
	}
	return completed, nil
}

// --- Finding suppressions ---

func (s *Store) UpsertSuppression(_ context.Context, sup *store.FindingSuppression) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sup.ID == "" {
		sup.ID = uuid.NewString()
	}
	// Replace any existing suppression with the same (domain, check_id, asset) key.
	for id, existing := range s.suppressions {
		if existing.Domain == sup.Domain && existing.CheckID == sup.CheckID && existing.Asset == sup.Asset {
			delete(s.suppressions, id)
			break
		}
	}
	copy := *sup
	copy.CreatedAt = time.Now()
	s.suppressions[copy.ID] = &copy
	return nil
}

func (s *Store) ListSuppressions(_ context.Context, domain string) ([]store.FindingSuppression, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []store.FindingSuppression
	for _, sup := range s.suppressions {
		if sup.Domain == domain {
			out = append(out, *sup)
		}
	}
	return out, nil
}

func (s *Store) DeleteSuppression(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.suppressions, id)
	return nil
}

func (s *Store) Close() error { return nil }

func (s *Store) SaveScannerMetric(_ context.Context, _ *store.ScannerMetric) error {
	return nil
}

func (s *Store) ListScannerMetrics(_ context.Context, _ string) ([]store.ScannerMetric, error) {
	return nil, nil
}

func (s *Store) GetScannerROI(_ context.Context, _ string) ([]store.ScannerROISummary, error) {
	return nil, nil
}

func (s *Store) SaveDiscoveryAudit(_ context.Context, _ []store.DiscoveryAudit) error {
	return nil
}

func (s *Store) GetDiscoverySourceSummary(_ context.Context, _ string) ([]store.DiscoverySourceSummary, error) {
	return nil, nil
}

func (s *Store) GetDiscoverySourcesByRun(_ context.Context, _ string) (map[string]string, error) {
	return nil, nil
}

func (s *Store) GetFalsePositivePatterns(_ context.Context, _ string) ([]string, error) {
	return nil, nil
}

func (s *Store) SaveSanitizedMetrics(_ context.Context, _ []store.SanitizedScannerMetric) error {
	return nil
}

func (s *Store) GetCrossDomainScannerSummary(_ context.Context) ([]store.CrossDomainScannerSummary, error) {
	return nil, nil
}

func (s *Store) DeleteScanRun(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.runs, id)
	delete(s.findings, id)
	delete(s.enriched, id)
	return nil
}

func (s *Store) GetFingerprintRules(_ context.Context, _ string) ([]store.FingerprintRule, error) {
	return nil, nil
}
func (s *Store) UpsertFingerprintRule(_ context.Context, _ *store.FingerprintRule) error {
	return nil
}
func (s *Store) DeleteFingerprintRule(_ context.Context, _ int64) error { return nil }
func (s *Store) IncrementFingerprintRuleSeen(_ context.Context, _ int64) error { return nil }

func (s *Store) PurgeOrphanedRuns(_ context.Context, olderThan time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	deleted := 0
	for id, r := range s.runs {
		if r.Status != store.StatusCompleted && r.Status != store.StatusRunning && r.Status != store.StatusPending && r.StartedAt.Before(olderThan) {
			delete(s.runs, id)
			delete(s.findings, id)
			delete(s.enriched, id)
			deleted++
		}
	}
	return deleted, nil
}

// SaveAssetGraph stores the asset graph JSON for a scan run.
func (s *Store) SaveAssetGraph(_ context.Context, scanRunID string, graphJSON []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.assetGraphs == nil {
		s.assetGraphs = make(map[string][]byte)
	}
	cp := make([]byte, len(graphJSON))
	copy(cp, graphJSON)
	s.assetGraphs[scanRunID] = cp
	return nil
}

// GetAssetGraph retrieves the asset graph JSON for a scan run.
func (s *Store) GetAssetGraph(_ context.Context, scanRunID string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.assetGraphs == nil {
		return nil, nil
	}
	data, ok := s.assetGraphs[scanRunID]
	if !ok {
		return nil, nil
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	return cp, nil
}

// Ensure Store satisfies the store.Store interface at compile time.
var _ store.Store = (*Store)(nil)

// helper to make a scan run with sensible defaults for tests
func NewScanRun(domain string, scanType module.ScanType) *store.ScanRun {
	return &store.ScanRun{
		ID:        uuid.NewString(),
		Domain:    domain,
		ScanType:  scanType,
		Status:    store.StatusPending,
		StartedAt: time.Now(),
	}
}
