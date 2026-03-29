package store_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stormbane/beacon/internal/enrichment"
	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
	"github.com/stormbane/beacon/internal/store"
	"github.com/stormbane/beacon/internal/store/memory"
	"github.com/stormbane/beacon/internal/store/sqlite"
)

// storeFactory creates a fresh Store for testing.
type storeFactory struct {
	name string
	new  func(t *testing.T) store.Store
}

func factories(t *testing.T) []storeFactory {
	t.Helper()
	return []storeFactory{
		{
			name: "memory",
			new: func(t *testing.T) store.Store {
				return memory.New()
			},
		},
		{
			name: "sqlite",
			new: func(t *testing.T) store.Store {
				s, err := sqlite.Open(t.TempDir() + "/test.db")
				if err != nil {
					t.Fatalf("open sqlite: %v", err)
				}
				t.Cleanup(func() { s.Close() })
				return s
			},
		},
	}
}

func seedRuns(t *testing.T, s store.Store, domain string, count int) []*store.ScanRun {
	t.Helper()
	ctx := context.Background()
	s.UpsertTarget(ctx, domain)

	var runs []*store.ScanRun
	now := time.Now()
	for i := 0; i < count; i++ {
		run := &store.ScanRun{
			Domain:    domain,
			ScanType:  module.ScanSurface,
			Status:    store.StatusCompleted,
			StartedAt: now.Add(time.Duration(i) * time.Second),
		}
		if err := s.CreateScanRun(ctx, run); err != nil {
			t.Fatalf("CreateScanRun: %v", err)
		}
		runs = append(runs, run)
	}
	return runs
}

// ---------------------------------------------------------------------------
// Cross-implementation: ListAllScanRuns behaves identically
// ---------------------------------------------------------------------------

func TestCrossImpl_ListAllScanRuns_EmptyStore(t *testing.T) {
	for _, f := range factories(t) {
		t.Run(f.name, func(t *testing.T) {
			s := f.new(t)
			runs, err := s.ListAllScanRuns(context.Background(), 10)
			if err != nil {
				t.Fatalf("ListAllScanRuns: %v", err)
			}
			if len(runs) != 0 {
				t.Errorf("expected 0 runs, got %d", len(runs))
			}
		})
	}
}

func TestCrossImpl_ListAllScanRuns_Limit(t *testing.T) {
	for _, f := range factories(t) {
		t.Run(f.name, func(t *testing.T) {
			s := f.new(t)
			seedRuns(t, s, "example.com", 10)

			runs, err := s.ListAllScanRuns(context.Background(), 5)
			if err != nil {
				t.Fatalf("ListAllScanRuns: %v", err)
			}
			if len(runs) != 5 {
				t.Errorf("expected 5 runs, got %d", len(runs))
			}
		})
	}
}

func TestCrossImpl_ListAllScanRuns_ZeroLimitDefaults(t *testing.T) {
	for _, f := range factories(t) {
		t.Run(f.name, func(t *testing.T) {
			s := f.new(t)
			seedRuns(t, s, "example.com", 55)

			runs, err := s.ListAllScanRuns(context.Background(), 0)
			if err != nil {
				t.Fatalf("ListAllScanRuns: %v", err)
			}
			if len(runs) != 50 {
				t.Errorf("expected 50 runs (default), got %d", len(runs))
			}
		})
	}
}

func TestCrossImpl_ListAllScanRuns_DescOrder(t *testing.T) {
	for _, f := range factories(t) {
		t.Run(f.name, func(t *testing.T) {
			s := f.new(t)
			seedRuns(t, s, "example.com", 5)

			runs, err := s.ListAllScanRuns(context.Background(), 50)
			if err != nil {
				t.Fatalf("ListAllScanRuns: %v", err)
			}
			for i := 1; i < len(runs); i++ {
				if runs[i].StartedAt.After(runs[i-1].StartedAt) {
					t.Errorf("runs not in descending order at index %d", i)
				}
			}
		})
	}
}

func TestCrossImpl_ListAllScanRuns_MultiDomain(t *testing.T) {
	for _, f := range factories(t) {
		t.Run(f.name, func(t *testing.T) {
			s := f.new(t)
			seedRuns(t, s, "a.com", 3)
			seedRuns(t, s, "b.com", 2)

			runs, err := s.ListAllScanRuns(context.Background(), 50)
			if err != nil {
				t.Fatalf("ListAllScanRuns: %v", err)
			}
			if len(runs) != 5 {
				t.Errorf("expected 5 runs across 2 domains, got %d", len(runs))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Cross-implementation: full scan lifecycle
// ---------------------------------------------------------------------------

func TestCrossImpl_ScanLifecycle(t *testing.T) {
	for _, f := range factories(t) {
		t.Run(f.name, func(t *testing.T) {
			ctx := context.Background()
			s := f.new(t)

			// 1. Upsert target
			tgt, err := s.UpsertTarget(ctx, "lifecycle.example.com")
			if err != nil {
				t.Fatalf("UpsertTarget: %v", err)
			}
			if tgt.ID == "" {
				t.Fatal("target ID is empty")
			}

			// 2. Create scan run
			run := &store.ScanRun{
				TargetID:  tgt.ID,
				Domain:    "lifecycle.example.com",
				ScanType:  module.ScanDeep,
				Status:    store.StatusPending,
				StartedAt: time.Now(),
			}
			if err := s.CreateScanRun(ctx, run); err != nil {
				t.Fatalf("CreateScanRun: %v", err)
			}
			if run.ID == "" {
				t.Fatal("run ID is empty after create")
			}

			// 3. Update to running
			run.Status = store.StatusRunning
			if err := s.UpdateScanRun(ctx, run); err != nil {
				t.Fatalf("UpdateScanRun: %v", err)
			}

			// 4. Save findings
			findings := []finding.Finding{
				{
					CheckID:  "test.check_1",
					Title:    "Test finding 1",
					Severity: finding.SeverityHigh,
					Asset:    "lifecycle.example.com",
				},
				{
					CheckID:  "test.check_2",
					Title:    "Test finding 2",
					Severity: finding.SeverityLow,
					Asset:    "lifecycle.example.com",
				},
			}
			if err := s.SaveFindings(ctx, run.ID, findings); err != nil {
				t.Fatalf("SaveFindings: %v", err)
			}

			// 5. Verify findings round-trip
			got, err := s.GetFindings(ctx, run.ID)
			if err != nil {
				t.Fatalf("GetFindings: %v", err)
			}
			if len(got) != 2 {
				t.Errorf("expected 2 findings, got %d", len(got))
			}

			// 6. Save enriched findings
			enriched := []enrichment.EnrichedFinding{
				{
					Finding:     findings[0],
					Explanation: "Test explanation",
					Impact:      "Test impact",
					Remediation: "Test remediation",
				},
			}
			if err := s.SaveEnrichedFindings(ctx, run.ID, enriched); err != nil {
				t.Fatalf("SaveEnrichedFindings: %v", err)
			}

			gotEnriched, err := s.GetEnrichedFindings(ctx, run.ID)
			if err != nil {
				t.Fatalf("GetEnrichedFindings: %v", err)
			}
			if len(gotEnriched) != 1 {
				t.Errorf("expected 1 enriched finding, got %d", len(gotEnriched))
			}

			// 7. Save asset graph
			graphJSON := []byte(`{"domain":"lifecycle.example.com"}`)
			if err := s.SaveAssetGraph(ctx, run.ID, graphJSON); err != nil {
				t.Fatalf("SaveAssetGraph: %v", err)
			}
			gotGraph, err := s.GetAssetGraph(ctx, run.ID)
			if err != nil {
				t.Fatalf("GetAssetGraph: %v", err)
			}
			if string(gotGraph) != string(graphJSON) {
				t.Errorf("graph JSON mismatch: got %q, want %q", gotGraph, graphJSON)
			}

			// 8. Complete the run
			now := time.Now()
			run.Status = store.StatusCompleted
			run.CompletedAt = &now
			run.FindingCount = len(findings)
			if err := s.UpdateScanRun(ctx, run); err != nil {
				t.Fatalf("UpdateScanRun (complete): %v", err)
			}

			// 9. Verify via ListScanRuns
			runs, err := s.ListScanRuns(ctx, "lifecycle.example.com")
			if err != nil {
				t.Fatalf("ListScanRuns: %v", err)
			}
			if len(runs) != 1 {
				t.Fatalf("expected 1 run, got %d", len(runs))
			}
			if runs[0].Status != store.StatusCompleted {
				t.Errorf("status = %s; want completed", runs[0].Status)
			}
			if runs[0].FindingCount != 2 {
				t.Errorf("finding count = %d; want 2", runs[0].FindingCount)
			}

			// 10. Verify via ListAllScanRuns
			allRuns, err := s.ListAllScanRuns(ctx, 50)
			if err != nil {
				t.Fatalf("ListAllScanRuns: %v", err)
			}
			if len(allRuns) != 1 {
				t.Errorf("ListAllScanRuns: expected 1, got %d", len(allRuns))
			}

			// 11. Delete and verify cleanup
			if err := s.DeleteScanRun(ctx, run.ID); err != nil {
				t.Fatalf("DeleteScanRun: %v", err)
			}

			gotFindings, _ := s.GetFindings(ctx, run.ID)
			if len(gotFindings) != 0 {
				t.Errorf("findings should be deleted, got %d", len(gotFindings))
			}
			gotGraphAfter, _ := s.GetAssetGraph(ctx, run.ID)
			if gotGraphAfter != nil {
				t.Error("asset graph should be deleted")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Cross-implementation: PurgeOrphanedRuns
// ---------------------------------------------------------------------------

func TestCrossImpl_PurgeOrphanedRuns(t *testing.T) {
	for _, f := range factories(t) {
		t.Run(f.name, func(t *testing.T) {
			ctx := context.Background()
			s := f.new(t)

			s.UpsertTarget(ctx, "purge.example.com")

			// Create runs with different statuses and ages.
			old := time.Now().Add(-48 * time.Hour)
			recent := time.Now().Add(-1 * time.Minute)

			runs := []struct {
				status    store.ScanStatus
				startedAt time.Time
			}{
				{store.StatusRunning, old},    // orphaned — should be purged
				{store.StatusCompleted, old},   // completed — never purged
				{store.StatusFailed, old},      // old failed — should be purged
				{store.StatusRunning, recent},  // recent running — should not be purged
			}

			for i, r := range runs {
				run := &store.ScanRun{
					Domain:    "purge.example.com",
					ScanType:  module.ScanSurface,
					Status:    r.status,
					StartedAt: r.startedAt,
				}
				s.CreateScanRun(ctx, run)
				runs[i].status = r.status // keep reference
			}

			threshold := time.Now().Add(-24 * time.Hour)
			deleted, err := s.PurgeOrphanedRuns(ctx, threshold)
			if err != nil {
				t.Fatalf("PurgeOrphanedRuns: %v", err)
			}
			if deleted != 2 {
				t.Errorf("deleted = %d; want 2 (old running + old failed)", deleted)
			}

			remaining, _ := s.ListAllScanRuns(ctx, 50)
			if len(remaining) != 2 {
				t.Errorf("remaining = %d; want 2 (completed + recent running)", len(remaining))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Cross-implementation: target idempotency
// ---------------------------------------------------------------------------

func TestCrossImpl_UpsertTarget_Idempotent(t *testing.T) {
	for _, f := range factories(t) {
		t.Run(f.name, func(t *testing.T) {
			ctx := context.Background()
			s := f.new(t)

			t1, err := s.UpsertTarget(ctx, "idem.example.com")
			if err != nil {
				t.Fatalf("first UpsertTarget: %v", err)
			}
			t2, err := s.UpsertTarget(ctx, "idem.example.com")
			if err != nil {
				t.Fatalf("second UpsertTarget: %v", err)
			}
			if t1.ID != t2.ID {
				t.Errorf("UpsertTarget returned different IDs: %s vs %s", t1.ID, t2.ID)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Cross-implementation: findings append (not overwrite)
// ---------------------------------------------------------------------------

func TestCrossImpl_SaveFindings_Appends(t *testing.T) {
	for _, f := range factories(t) {
		t.Run(f.name, func(t *testing.T) {
			ctx := context.Background()
			s := f.new(t)
			s.UpsertTarget(ctx, "append.example.com")

			run := &store.ScanRun{
				Domain:    "append.example.com",
				ScanType:  module.ScanSurface,
				Status:    store.StatusRunning,
				StartedAt: time.Now(),
			}
			s.CreateScanRun(ctx, run)

			batch1 := []finding.Finding{
				{CheckID: "a.1", Title: "First"},
			}
			batch2 := []finding.Finding{
				{CheckID: "a.2", Title: "Second"},
				{CheckID: "a.3", Title: "Third"},
			}

			s.SaveFindings(ctx, run.ID, batch1)
			s.SaveFindings(ctx, run.ID, batch2)

			got, err := s.GetFindings(ctx, run.ID)
			if err != nil {
				t.Fatalf("GetFindings: %v", err)
			}
			if len(got) != 3 {
				t.Errorf("expected 3 findings (append), got %d", len(got))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Cross-implementation: enrichment cache
// ---------------------------------------------------------------------------

func TestCrossImpl_EnrichmentCache(t *testing.T) {
	for _, f := range factories(t) {
		t.Run(f.name, func(t *testing.T) {
			ctx := context.Background()
			s := f.new(t)

			// Save to cache
			err := s.SaveEnrichmentCache(ctx, "test.check_id", "explanation", "impact", "remediation")
			if err != nil {
				t.Fatalf("SaveEnrichmentCache: %v", err)
			}

			// Retrieve from cache
			exp, imp, rem, found := s.GetEnrichmentCache(ctx, "test.check_id")
			if !found {
				t.Fatal("GetEnrichmentCache: expected found=true")
			}
			if exp != "explanation" || imp != "impact" || rem != "remediation" {
				t.Errorf("cache mismatch: got (%q, %q, %q)", exp, imp, rem)
			}

			// Miss returns empty strings
			exp2, imp2, rem2, found2 := s.GetEnrichmentCache(ctx, "nonexistent")
			if found2 {
				t.Error("expected found=false for cache miss")
			}
			if exp2 != "" || imp2 != "" || rem2 != "" {
				t.Errorf("expected empty for cache miss, got (%q, %q, %q)", exp2, imp2, rem2)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Cross-implementation: suppression
// ---------------------------------------------------------------------------

func TestCrossImpl_Suppression(t *testing.T) {
	for _, f := range factories(t) {
		t.Run(f.name, func(t *testing.T) {
			ctx := context.Background()
			s := f.new(t)

			supp := &store.FindingSuppression{
				CheckID: "test.suppressed",
				Domain:  "suppress.example.com",
				Status:  store.SuppressionAcceptedRisk,
				Note:    "Known and accepted",
			}

			if err := s.UpsertSuppression(ctx, supp); err != nil {
				t.Fatalf("UpsertSuppression: %v", err)
			}

			supps, err := s.ListSuppressions(ctx, "suppress.example.com")
			if err != nil {
				t.Fatalf("ListSuppressions: %v", err)
			}
			if len(supps) != 1 {
				t.Errorf("expected 1 suppression, got %d", len(supps))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Cross-implementation: correlation findings
// ---------------------------------------------------------------------------

func TestCrossImpl_CorrelationFindings(t *testing.T) {
	for _, f := range factories(t) {
		t.Run(f.name, func(t *testing.T) {
			ctx := context.Background()
			s := f.new(t)
			s.UpsertTarget(ctx, "corr.example.com")

			run := &store.ScanRun{
				Domain:    "corr.example.com",
				ScanType:  module.ScanSurface,
				Status:    store.StatusRunning,
				StartedAt: time.Now(),
			}
			s.CreateScanRun(ctx, run)

			corrs := []store.CorrelationFinding{
				{
					ScanRunID: run.ID,
					Title:     "Compound vuln",
					Domain:    "corr.example.com",
				},
			}
			if err := s.SaveCorrelationFindings(ctx, corrs); err != nil {
				t.Fatalf("SaveCorrelationFindings: %v", err)
			}

			got, err := s.ListCorrelationFindings(ctx, "corr.example.com")
			if err != nil {
				t.Fatalf("ListCorrelationFindings: %v", err)
			}
			if len(got) != 1 {
				t.Errorf("expected 1 correlation finding, got %d", len(got))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Cross-implementation: scan run status transitions
// ---------------------------------------------------------------------------

func TestCrossImpl_ScanRunStatusTransitions(t *testing.T) {
	for _, f := range factories(t) {
		t.Run(f.name, func(t *testing.T) {
			ctx := context.Background()
			s := f.new(t)
			s.UpsertTarget(ctx, "status.example.com")

			run := &store.ScanRun{
				Domain:    "status.example.com",
				ScanType:  module.ScanSurface,
				Status:    store.StatusPending,
				StartedAt: time.Now(),
			}
			s.CreateScanRun(ctx, run)

			// pending → running
			run.Status = store.StatusRunning
			s.UpdateScanRun(ctx, run)

			got, _ := s.GetScanRun(ctx, run.ID)
			if got.Status != store.StatusRunning {
				t.Errorf("status = %s; want running", got.Status)
			}

			// running → stopped
			run.Status = store.StatusStopped
			run.Error = "user stopped"
			s.UpdateScanRun(ctx, run)

			got, _ = s.GetScanRun(ctx, run.ID)
			if got.Status != store.StatusStopped {
				t.Errorf("status = %s; want stopped", got.Status)
			}
			if got.Error != "user stopped" {
				t.Errorf("error = %q; want %q", got.Error, "user stopped")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Edge: GetScanRun for non-existent ID
// ---------------------------------------------------------------------------

func TestCrossImpl_GetScanRun_NotFound(t *testing.T) {
	for _, f := range factories(t) {
		t.Run(f.name, func(t *testing.T) {
			ctx := context.Background()
			s := f.new(t)

			_, err := s.GetScanRun(ctx, "nonexistent-id")
			if err == nil {
				t.Error("expected error for non-existent scan run")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Edge: many domains with ListAllScanRuns
// ---------------------------------------------------------------------------

func TestCrossImpl_ListAllScanRuns_ManyDomains(t *testing.T) {
	for _, f := range factories(t) {
		t.Run(f.name, func(t *testing.T) {
			ctx := context.Background()
			s := f.new(t)

			for i := 0; i < 20; i++ {
				domain := fmt.Sprintf("domain-%d.example.com", i)
				s.UpsertTarget(ctx, domain)
				run := &store.ScanRun{
					Domain:    domain,
					ScanType:  module.ScanSurface,
					Status:    store.StatusCompleted,
					StartedAt: time.Now().Add(time.Duration(i) * time.Second),
				}
				s.CreateScanRun(ctx, run)
			}

			runs, err := s.ListAllScanRuns(ctx, 10)
			if err != nil {
				t.Fatalf("ListAllScanRuns: %v", err)
			}
			if len(runs) != 10 {
				t.Errorf("expected 10, got %d", len(runs))
			}

			// Verify they're the most recent 10 (domains 10-19).
			for _, r := range runs {
				if r.StartedAt.Before(time.Now().Add(-20 * time.Second)) {
					t.Error("returned an old run instead of the most recent ones")
				}
			}
		})
	}
}
