package sqlite_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/stormbane/beacon/internal/enrichment"
	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
	"github.com/stormbane/beacon/internal/playbook"
	"github.com/stormbane/beacon/internal/store"
	"github.com/stormbane/beacon/internal/store/sqlite"
)

// openTestStore opens an in-memory SQLite store for testing.
// The caller does not need to close it — the database is dropped when the
// connection closes, and garbage collection handles that.
func openTestStore(t *testing.T) *sqlite.Store {
	t.Helper()
	s, err := sqlite.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("failed to open test store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// ---------------------------------------------------------------------------
// Schema / Migration
// ---------------------------------------------------------------------------

func TestOpen_CreatesSchema(t *testing.T) {
	s := openTestStore(t)
	// Verify the store satisfies the interface (compile-time check is in store.go,
	// but we exercise it here to catch missing methods early).
	var _ store.Store = s
}

func TestOpen_IdempotentMigrations(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/migrate.db"

	// Open twice — second call must not fail due to duplicate column errors.
	s1, err := sqlite.Open(path)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	s1.Close()

	s2, err := sqlite.Open(path)
	if err != nil {
		t.Fatalf("second open (re-migration): %v", err)
	}
	s2.Close()
}

// ---------------------------------------------------------------------------
// Targets
// ---------------------------------------------------------------------------

func TestUpsertTarget_NewTarget(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	tgt, err := s.UpsertTarget(ctx, "example.com")
	if err != nil {
		t.Fatalf("UpsertTarget: %v", err)
	}
	if tgt.Domain != "example.com" {
		t.Errorf("domain = %q, want %q", tgt.Domain, "example.com")
	}
	if tgt.ID == "" {
		t.Error("expected non-empty ID")
	}
}

func TestUpsertTarget_Idempotent(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	t1, err := s.UpsertTarget(ctx, "example.com")
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	t2, err := s.UpsertTarget(ctx, "example.com")
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	if t1.ID != t2.ID {
		t.Errorf("IDs differ: %q != %q — upsert should be idempotent", t1.ID, t2.ID)
	}
}

func TestGetTarget_NotFound(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	_, err := s.GetTarget(ctx, "nonexistent.com")
	if err == nil {
		t.Fatal("expected error for nonexistent target")
	}
}

func TestListTargets_Empty(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	targets, err := s.ListTargets(ctx)
	if err != nil {
		t.Fatalf("ListTargets: %v", err)
	}
	if len(targets) != 0 {
		t.Errorf("expected 0 targets, got %d", len(targets))
	}
}

func TestListTargets_ReturnsAll(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	s.UpsertTarget(ctx, "a.com")
	s.UpsertTarget(ctx, "b.com")
	s.UpsertTarget(ctx, "c.com")

	targets, err := s.ListTargets(ctx)
	if err != nil {
		t.Fatalf("ListTargets: %v", err)
	}
	if len(targets) != 3 {
		t.Errorf("expected 3 targets, got %d", len(targets))
	}
}

// ---------------------------------------------------------------------------
// Scan Runs
// ---------------------------------------------------------------------------

func makeScanRun(domain string) *store.ScanRun {
	return &store.ScanRun{
		TargetID:     "target-1",
		Domain:       domain,
		ScanType:     module.ScanSurface,
		Modules:      []string{"surface"},
		Status:       store.StatusRunning,
		StartedAt:    time.Now().UTC(),
		FindingCount: 0,
	}
}

func TestCreateScanRun_AssignsID(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	run := makeScanRun("example.com")
	if err := s.CreateScanRun(ctx, run); err != nil {
		t.Fatalf("CreateScanRun: %v", err)
	}
	if run.ID == "" {
		t.Error("expected non-empty run ID after create")
	}
}

func TestCreateScanRun_PreservesExplicitID(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	run := makeScanRun("example.com")
	run.ID = "explicit-id-123"
	if err := s.CreateScanRun(ctx, run); err != nil {
		t.Fatalf("CreateScanRun: %v", err)
	}
	if run.ID != "explicit-id-123" {
		t.Errorf("ID = %q, want %q", run.ID, "explicit-id-123")
	}
}

func TestGetScanRun_Roundtrip(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	run := makeScanRun("example.com")
	run.Modules = []string{"surface", "github"}
	s.CreateScanRun(ctx, run)

	got, err := s.GetScanRun(ctx, run.ID)
	if err != nil {
		t.Fatalf("GetScanRun: %v", err)
	}
	if got.Domain != "example.com" {
		t.Errorf("domain = %q, want %q", got.Domain, "example.com")
	}
	if got.Status != store.StatusRunning {
		t.Errorf("status = %q, want %q", got.Status, store.StatusRunning)
	}
	if len(got.Modules) != 2 {
		t.Errorf("modules = %v, want 2 elements", got.Modules)
	}
}

func TestGetScanRun_NotFound(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	_, err := s.GetScanRun(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent scan run")
	}
}

func TestUpdateScanRun(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	run := makeScanRun("example.com")
	s.CreateScanRun(ctx, run)

	now := time.Now().UTC()
	run.Status = store.StatusCompleted
	run.CompletedAt = &now
	run.FindingCount = 5
	run.Error = "some warning"
	run.DiscoveryDurationMs = 1500
	run.ScanDurationMs = 3000
	run.AssetCount = 10
	run.DiscoverySources = map[string]int{"subdomain": 7, "passive": 3}

	if err := s.UpdateScanRun(ctx, run); err != nil {
		t.Fatalf("UpdateScanRun: %v", err)
	}

	got, _ := s.GetScanRun(ctx, run.ID)
	if got.Status != store.StatusCompleted {
		t.Errorf("status = %q, want %q", got.Status, store.StatusCompleted)
	}
	if got.FindingCount != 5 {
		t.Errorf("finding_count = %d, want 5", got.FindingCount)
	}
}

func TestListScanRuns_ByDomain(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	r1 := makeScanRun("a.com")
	r2 := makeScanRun("a.com")
	r3 := makeScanRun("b.com")
	s.CreateScanRun(ctx, r1)
	s.CreateScanRun(ctx, r2)
	s.CreateScanRun(ctx, r3)

	runs, err := s.ListScanRuns(ctx, "a.com")
	if err != nil {
		t.Fatalf("ListScanRuns: %v", err)
	}
	if len(runs) != 2 {
		t.Errorf("expected 2 runs for a.com, got %d", len(runs))
	}
}

func TestListScanRuns_EmptyResult(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	runs, err := s.ListScanRuns(ctx, "nonexistent.com")
	if err != nil {
		t.Fatalf("ListScanRuns: %v", err)
	}
	if len(runs) != 0 {
		t.Errorf("expected 0 runs, got %d", len(runs))
	}
}

func TestListRecentScanRuns(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		r := makeScanRun("example.com")
		r.StartedAt = time.Now().UTC().Add(time.Duration(i) * time.Second)
		s.CreateScanRun(ctx, r)
	}

	runs, err := s.ListRecentScanRuns(ctx, 3)
	if err != nil {
		t.Fatalf("ListRecentScanRuns: %v", err)
	}
	if len(runs) != 3 {
		t.Errorf("expected 3 runs, got %d", len(runs))
	}
	// Should be ordered by started_at DESC
	if runs[0].StartedAt.Before(runs[1].StartedAt) {
		t.Error("expected most recent run first")
	}
}

func TestDeleteScanRun(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	run := makeScanRun("example.com")
	s.CreateScanRun(ctx, run)

	// Add associated data
	s.SaveFindings(ctx, run.ID, []finding.Finding{
		{CheckID: "test.check", Module: "surface", Scanner: "test", Severity: finding.SeverityHigh,
			Title: "t", Description: "d", Asset: "a.com", DiscoveredAt: time.Now().UTC()},
	})
	s.SaveReport(ctx, &store.Report{ScanRunID: run.ID, Domain: "example.com", HTMLContent: "<h1>test</h1>"})

	if err := s.DeleteScanRun(ctx, run.ID); err != nil {
		t.Fatalf("DeleteScanRun: %v", err)
	}

	_, err := s.GetScanRun(ctx, run.ID)
	if err == nil {
		t.Error("expected error after deleting scan run")
	}

	findings, _ := s.GetFindings(ctx, run.ID)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings after delete, got %d", len(findings))
	}
}

func TestDeleteScanRun_Nonexistent(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	// Should succeed silently — DELETE WHERE id=? with no matching rows is fine.
	if err := s.DeleteScanRun(ctx, "nonexistent"); err != nil {
		t.Fatalf("DeleteScanRun nonexistent: %v", err)
	}
}

func TestPurgeOrphanedRuns_DeletesFailedOldRuns(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	old := makeScanRun("example.com")
	old.Status = store.StatusFailed
	old.StartedAt = time.Now().UTC().Add(-48 * time.Hour)
	s.CreateScanRun(ctx, old)

	recent := makeScanRun("example.com")
	recent.Status = store.StatusFailed
	recent.StartedAt = time.Now().UTC()
	s.CreateScanRun(ctx, recent)

	completed := makeScanRun("example.com")
	completed.Status = store.StatusCompleted
	completed.StartedAt = time.Now().UTC().Add(-48 * time.Hour)
	s.CreateScanRun(ctx, completed)

	purged, err := s.PurgeOrphanedRuns(ctx, time.Now().UTC().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("PurgeOrphanedRuns: %v", err)
	}
	if purged != 1 {
		t.Errorf("purged = %d, want 1 (only the old failed run)", purged)
	}

	// Completed run should still exist
	_, err = s.GetScanRun(ctx, completed.ID)
	if err != nil {
		t.Error("completed run should survive purge")
	}
}

func TestPurgeOrphanedRuns_DeletesOrphanedRunning(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	// A running scan from 5 hours ago is orphaned
	orphan := makeScanRun("example.com")
	orphan.Status = store.StatusRunning
	orphan.StartedAt = time.Now().UTC().Add(-5 * time.Hour)
	s.CreateScanRun(ctx, orphan)

	// olderThan = 1 hour ago, orphan threshold = 3 hours ago
	purged, err := s.PurgeOrphanedRuns(ctx, time.Now().UTC().Add(-1*time.Hour))
	if err != nil {
		t.Fatalf("PurgeOrphanedRuns: %v", err)
	}
	if purged != 1 {
		t.Errorf("purged = %d, want 1", purged)
	}
}

func TestPurgeOrphanedRuns_NoMatches(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	purged, err := s.PurgeOrphanedRuns(ctx, time.Now().UTC())
	if err != nil {
		t.Fatalf("PurgeOrphanedRuns: %v", err)
	}
	if purged != 0 {
		t.Errorf("purged = %d, want 0", purged)
	}
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

func makeFindings(n int) []finding.Finding {
	var out []finding.Finding
	for i := 0; i < n; i++ {
		out = append(out, finding.Finding{
			CheckID:      finding.CheckID("test.check_" + string(rune('a'+i))),
			Module:       "surface",
			Scanner:      "test",
			Severity:     finding.SeverityMedium,
			Title:        "Test Finding",
			Description:  "Description",
			Asset:        "asset.example.com",
			Evidence:     map[string]any{"key": "value"},
			DeepOnly:     i%2 == 0,
			DiscoveredAt: time.Now().UTC(),
		})
	}
	return out
}

func TestSaveFindings_Empty(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	// Empty slice should be a no-op, not an error.
	if err := s.SaveFindings(ctx, "run-1", nil); err != nil {
		t.Fatalf("SaveFindings empty: %v", err)
	}
}

func TestSaveFindings_Roundtrip(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	run := makeScanRun("example.com")
	s.CreateScanRun(ctx, run)

	input := makeFindings(3)
	if err := s.SaveFindings(ctx, run.ID, input); err != nil {
		t.Fatalf("SaveFindings: %v", err)
	}

	got, err := s.GetFindings(ctx, run.ID)
	if err != nil {
		t.Fatalf("GetFindings: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(got))
	}

	// Verify fields round-trip
	f := got[0]
	if f.Module != "surface" {
		t.Errorf("module = %q, want %q", f.Module, "surface")
	}
	if f.Severity != finding.SeverityMedium {
		t.Errorf("severity = %v, want %v", f.Severity, finding.SeverityMedium)
	}
	if f.Evidence["key"] != "value" {
		t.Errorf("evidence[key] = %v, want %q", f.Evidence["key"], "value")
	}
}

func TestSaveFindings_DedupByIndex(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	run := makeScanRun("example.com")
	s.CreateScanRun(ctx, run)

	f := finding.Finding{
		CheckID: "test.dup", Module: "surface", Scanner: "test",
		Severity: finding.SeverityLow, Title: "Dup",
		Description: "d", Asset: "a.com", DiscoveredAt: time.Now().UTC(),
	}

	// Save the same finding twice — should be deduplicated by the UNIQUE index.
	s.SaveFindings(ctx, run.ID, []finding.Finding{f})
	s.SaveFindings(ctx, run.ID, []finding.Finding{f})

	got, _ := s.GetFindings(ctx, run.ID)
	if len(got) != 1 {
		t.Errorf("expected 1 finding after dedup, got %d", len(got))
	}
}

func TestGetFindings_EmptyResult(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	got, err := s.GetFindings(ctx, "nonexistent-run")
	if err != nil {
		t.Fatalf("GetFindings: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 findings, got %d", len(got))
	}
}

func TestSaveFindings_DeepOnlyFlag(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	run := makeScanRun("example.com")
	s.CreateScanRun(ctx, run)

	f := finding.Finding{
		CheckID: "test.deep", Module: "surface", Scanner: "test",
		Severity: finding.SeverityHigh, Title: "Deep",
		Description: "d", Asset: "a.com", DeepOnly: true,
		DiscoveredAt: time.Now().UTC(),
	}
	s.SaveFindings(ctx, run.ID, []finding.Finding{f})

	got, _ := s.GetFindings(ctx, run.ID)
	if len(got) != 1 || !got[0].DeepOnly {
		t.Error("DeepOnly flag not preserved")
	}
}

// ---------------------------------------------------------------------------
// Enriched Findings
// ---------------------------------------------------------------------------

func TestSaveEnrichedFindings_Empty(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	if err := s.SaveEnrichedFindings(ctx, "run-1", nil); err != nil {
		t.Fatalf("SaveEnrichedFindings empty: %v", err)
	}
}

func TestSaveEnrichedFindings_Roundtrip(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	run := makeScanRun("example.com")
	s.CreateScanRun(ctx, run)

	efs := []enrichment.EnrichedFinding{
		{
			Finding: finding.Finding{
				CheckID: "test.check", Module: "surface", Scanner: "test",
				Severity: finding.SeverityHigh, Title: "XSS",
				Description: "d", Asset: "a.com",
				DiscoveredAt: time.Now().UTC(),
			},
			Explanation: "Cross-site scripting allows...",
			Impact:      "Session hijack",
			Remediation: "Encode output",
		},
	}

	if err := s.SaveEnrichedFindings(ctx, run.ID, efs); err != nil {
		t.Fatalf("SaveEnrichedFindings: %v", err)
	}

	got, err := s.GetEnrichedFindings(ctx, run.ID)
	if err != nil {
		t.Fatalf("GetEnrichedFindings: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 enriched finding, got %d", len(got))
	}
	if got[0].Explanation != "Cross-site scripting allows..." {
		t.Errorf("explanation = %q, want %q", got[0].Explanation, "Cross-site scripting allows...")
	}
	if got[0].Finding.CheckID != "test.check" {
		t.Errorf("finding.check_id = %q, want %q", got[0].Finding.CheckID, "test.check")
	}
	if got[0].Finding.Asset != "a.com" {
		t.Errorf("finding.asset = %q, want %q", got[0].Finding.Asset, "a.com")
	}
}

func TestSaveEnrichedFindings_IdempotentOverwrite(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	run := makeScanRun("example.com")
	s.CreateScanRun(ctx, run)

	ef := enrichment.EnrichedFinding{
		Finding: finding.Finding{
			CheckID: "test.check", Module: "surface", Scanner: "test",
			Severity: finding.SeverityHigh, Title: "XSS",
			Description: "d", Asset: "a.com",
			DiscoveredAt: time.Now().UTC(),
		},
		Explanation: "v1",
	}

	s.SaveEnrichedFindings(ctx, run.ID, []enrichment.EnrichedFinding{ef})
	ef.Explanation = "v2"
	s.SaveEnrichedFindings(ctx, run.ID, []enrichment.EnrichedFinding{ef})

	got, _ := s.GetEnrichedFindings(ctx, run.ID)
	if len(got) != 1 {
		t.Fatalf("expected 1 enriched finding after overwrite, got %d", len(got))
	}
	if got[0].Explanation != "v2" {
		t.Errorf("explanation = %q, want %q (latest overwrite)", got[0].Explanation, "v2")
	}
}

func TestGetPreviousEnrichedFindings_NoPrevious(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	got, err := s.GetPreviousEnrichedFindings(ctx, "example.com", "current-run")
	if err != nil {
		t.Fatalf("GetPreviousEnrichedFindings: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

func TestGetPreviousEnrichedFindings_ReturnsPrevious(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	// Create two completed runs
	prev := makeScanRun("example.com")
	prev.Status = store.StatusCompleted
	prev.StartedAt = time.Now().UTC().Add(-2 * time.Hour)
	completedTime := time.Now().UTC().Add(-1 * time.Hour)
	prev.CompletedAt = &completedTime
	s.CreateScanRun(ctx, prev)

	current := makeScanRun("example.com")
	current.Status = store.StatusCompleted
	currentComplete := time.Now().UTC()
	current.CompletedAt = &currentComplete
	s.CreateScanRun(ctx, current)

	// Enrich previous run
	s.SaveEnrichedFindings(ctx, prev.ID, []enrichment.EnrichedFinding{
		{
			Finding: finding.Finding{
				CheckID: "test.prev", Module: "surface", Scanner: "test",
				Severity: finding.SeverityLow, Title: "Old",
				Description: "d", Asset: "a.com", DiscoveredAt: time.Now().UTC(),
			},
			Explanation: "previous explanation",
		},
	})

	got, err := s.GetPreviousEnrichedFindings(ctx, "example.com", current.ID)
	if err != nil {
		t.Fatalf("GetPreviousEnrichedFindings: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 previous enriched finding, got %d", len(got))
	}
	if got[0].Explanation != "previous explanation" {
		t.Errorf("explanation = %q, want %q", got[0].Explanation, "previous explanation")
	}
}

// ---------------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------------

func TestSaveReport_Roundtrip(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	run := makeScanRun("example.com")
	s.CreateScanRun(ctx, run)

	rpt := &store.Report{
		ScanRunID:   run.ID,
		Domain:      "example.com",
		HTMLContent: "<h1>Report</h1>",
		Summary:     "3 findings",
	}
	if err := s.SaveReport(ctx, rpt); err != nil {
		t.Fatalf("SaveReport: %v", err)
	}
	if rpt.ID == "" {
		t.Error("expected non-empty report ID")
	}

	got, err := s.GetReport(ctx, run.ID)
	if err != nil {
		t.Fatalf("GetReport: %v", err)
	}
	if got.HTMLContent != "<h1>Report</h1>" {
		t.Errorf("html_content = %q, want %q", got.HTMLContent, "<h1>Report</h1>")
	}
	if got.Summary != "3 findings" {
		t.Errorf("summary = %q, want %q", got.Summary, "3 findings")
	}
}

func TestSaveReport_UpsertOnConflict(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	run := makeScanRun("example.com")
	s.CreateScanRun(ctx, run)

	rpt := &store.Report{ScanRunID: run.ID, Domain: "example.com", HTMLContent: "v1"}
	s.SaveReport(ctx, rpt)

	rpt2 := &store.Report{ScanRunID: run.ID, Domain: "example.com", HTMLContent: "v2", Summary: "updated"}
	s.SaveReport(ctx, rpt2)

	got, _ := s.GetReport(ctx, run.ID)
	if got.HTMLContent != "v2" {
		t.Errorf("html_content = %q, want %q after upsert", got.HTMLContent, "v2")
	}
}

func TestSaveReport_WithEmailFields(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	run := makeScanRun("example.com")
	s.CreateScanRun(ctx, run)

	emailedAt := time.Now().UTC()
	rpt := &store.Report{
		ScanRunID:   run.ID,
		Domain:      "example.com",
		HTMLContent: "<h1>Report</h1>",
		EmailedTo:   "user@example.com",
		EmailedAt:   &emailedAt,
	}
	s.SaveReport(ctx, rpt)

	got, _ := s.GetReport(ctx, run.ID)
	if got.EmailedTo != "user@example.com" {
		t.Errorf("emailed_to = %q, want %q", got.EmailedTo, "user@example.com")
	}
	if got.EmailedAt == nil {
		t.Error("expected non-nil emailed_at")
	}
}

func TestGetReport_NotFound(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	_, err := s.GetReport(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent report")
	}
}

// ---------------------------------------------------------------------------
// Asset Executions
// ---------------------------------------------------------------------------

func TestSaveAssetExecution_Roundtrip(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	run := makeScanRun("example.com")
	s.CreateScanRun(ctx, run)

	exec := &store.AssetExecution{
		ScanRunID:        run.ID,
		Asset:            "api.example.com",
		Evidence:         playbook.Evidence{IP: "1.2.3.4", Hostname: "api.example.com"},
		MatchedPlaybooks: []string{"generic_web"},
		ScannersRun:      []string{"cors", "jwt"},
		NucleiTagsRun:    []string{"cve2024"},
		DirbustPathsRun:  []string{"/admin", "/api"},
		DirbustPathsFound: []string{"/api"},
		FindingsCount:    2,
		ClassifyDurationMs: 50,
		ExpandedFrom:     "example.com",
	}
	if err := s.SaveAssetExecution(ctx, exec); err != nil {
		t.Fatalf("SaveAssetExecution: %v", err)
	}
	if exec.ID == "" {
		t.Error("expected non-empty execution ID")
	}

	got, err := s.ListAssetExecutions(ctx, run.ID)
	if err != nil {
		t.Fatalf("ListAssetExecutions: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 execution, got %d", len(got))
	}
	if got[0].Asset != "api.example.com" {
		t.Errorf("asset = %q, want %q", got[0].Asset, "api.example.com")
	}
	if got[0].Evidence.IP != "1.2.3.4" {
		t.Errorf("evidence.IP = %q, want %q", got[0].Evidence.IP, "1.2.3.4")
	}
	if len(got[0].MatchedPlaybooks) != 1 || got[0].MatchedPlaybooks[0] != "generic_web" {
		t.Errorf("matched_playbooks = %v, want [generic_web]", got[0].MatchedPlaybooks)
	}
	if len(got[0].DirbustPathsFound) != 1 {
		t.Errorf("dirbust_paths_found = %v, want 1 entry", got[0].DirbustPathsFound)
	}
	if got[0].FindingsCount != 2 {
		t.Errorf("findings_count = %d, want 2", got[0].FindingsCount)
	}
}

func TestListAssetExecutions_Empty(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	got, err := s.ListAssetExecutions(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("ListAssetExecutions: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 executions, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// Unmatched Assets
// ---------------------------------------------------------------------------

func TestSaveUnmatchedAsset_Roundtrip(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	u := &store.UnmatchedAsset{
		ScanRunID:   "run-1",
		Fingerprint: "fp-abc123",
		Asset:       "unknown.example.com",
		Evidence:    playbook.Evidence{IP: "10.0.0.1"},
	}
	if err := s.SaveUnmatchedAsset(ctx, u); err != nil {
		t.Fatalf("SaveUnmatchedAsset: %v", err)
	}

	got, err := s.ListUnmatchedAssets(ctx)
	if err != nil {
		t.Fatalf("ListUnmatchedAssets: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 unmatched, got %d", len(got))
	}
	if got[0].Asset != "unknown.example.com" {
		t.Errorf("asset = %q, want %q", got[0].Asset, "unknown.example.com")
	}
	if got[0].Evidence.IP != "10.0.0.1" {
		t.Errorf("evidence.IP = %q, want %q", got[0].Evidence.IP, "10.0.0.1")
	}
}

func TestSaveUnmatchedAsset_DuplicateFingerprint(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	u1 := &store.UnmatchedAsset{ScanRunID: "run-1", Fingerprint: "fp-dup", Asset: "a.com"}
	u2 := &store.UnmatchedAsset{ScanRunID: "run-2", Fingerprint: "fp-dup", Asset: "b.com"}
	s.SaveUnmatchedAsset(ctx, u1)
	s.SaveUnmatchedAsset(ctx, u2)

	got, _ := s.ListUnmatchedAssets(ctx)
	if len(got) != 1 {
		t.Errorf("expected 1 (deduped by fingerprint), got %d", len(got))
	}
}

func TestFingerprintExists(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	exists, err := s.FingerprintExists(ctx, "fp-nope")
	if err != nil {
		t.Fatalf("FingerprintExists: %v", err)
	}
	if exists {
		t.Error("expected false for nonexistent fingerprint")
	}

	s.SaveUnmatchedAsset(ctx, &store.UnmatchedAsset{
		ScanRunID: "run-1", Fingerprint: "fp-yes", Asset: "a.com",
	})
	exists, _ = s.FingerprintExists(ctx, "fp-yes")
	if !exists {
		t.Error("expected true after saving asset with this fingerprint")
	}
}

func TestListUnmatchedAssets_Empty(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	got, err := s.ListUnmatchedAssets(ctx)
	if err != nil {
		t.Fatalf("ListUnmatchedAssets: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// Playbook Suggestions
// ---------------------------------------------------------------------------

func TestSavePlaybookSuggestion_Roundtrip(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	sg := &store.PlaybookSuggestion{
		Type:            "new",
		TargetPlaybook:  "nginx_api",
		SuggestedYAML:   "match: ...",
		Reasoning:       "Seen nginx + API pattern",
		SuggestionKind:  "playbook",
		CodeSnippet:     "func ...",
		Priority:        "high",
		AffectedDomains: []string{"a.com", "b.com"},
	}
	if err := s.SavePlaybookSuggestion(ctx, sg); err != nil {
		t.Fatalf("SavePlaybookSuggestion: %v", err)
	}
	if sg.ID == "" {
		t.Error("expected non-empty suggestion ID")
	}
	if sg.Status != "pending" {
		t.Errorf("status = %q, want %q (default)", sg.Status, "pending")
	}

	got, err := s.ListPlaybookSuggestions(ctx, "")
	if err != nil {
		t.Fatalf("ListPlaybookSuggestions: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 suggestion, got %d", len(got))
	}
	if got[0].TargetPlaybook != "nginx_api" {
		t.Errorf("target_playbook = %q, want %q", got[0].TargetPlaybook, "nginx_api")
	}
	if got[0].SuggestionKind != "playbook" {
		t.Errorf("suggestion_kind = %q, want %q", got[0].SuggestionKind, "playbook")
	}
	if len(got[0].AffectedDomains) != 2 {
		t.Errorf("affected_domains = %v, want 2 entries", got[0].AffectedDomains)
	}
}

func TestListPlaybookSuggestions_FilterByStatus(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	sg1 := &store.PlaybookSuggestion{Type: "new", TargetPlaybook: "a", Status: "pending"}
	sg2 := &store.PlaybookSuggestion{Type: "new", TargetPlaybook: "b", Status: "merged"}
	s.SavePlaybookSuggestion(ctx, sg1)
	s.SavePlaybookSuggestion(ctx, sg2)

	pending, _ := s.ListPlaybookSuggestions(ctx, "pending")
	if len(pending) != 1 {
		t.Errorf("expected 1 pending, got %d", len(pending))
	}
	if pending[0].TargetPlaybook != "a" {
		t.Errorf("target_playbook = %q, want %q", pending[0].TargetPlaybook, "a")
	}

	all, _ := s.ListPlaybookSuggestions(ctx, "")
	if len(all) != 2 {
		t.Errorf("expected 2 total, got %d", len(all))
	}
}

func TestUpdatePlaybookSuggestion(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	sg := &store.PlaybookSuggestion{Type: "new", TargetPlaybook: "x"}
	s.SavePlaybookSuggestion(ctx, sg)

	sg.Status = "merged"
	sg.PRURL = "https://github.com/org/repo/pull/42"
	if err := s.UpdatePlaybookSuggestion(ctx, sg); err != nil {
		t.Fatalf("UpdatePlaybookSuggestion: %v", err)
	}

	got, _ := s.ListPlaybookSuggestions(ctx, "merged")
	if len(got) != 1 {
		t.Fatalf("expected 1 merged suggestion, got %d", len(got))
	}
	if got[0].PRURL != "https://github.com/org/repo/pull/42" {
		t.Errorf("pr_url = %q, want set value", got[0].PRURL)
	}
}

// ---------------------------------------------------------------------------
// Enrichment Cache
// ---------------------------------------------------------------------------

func TestEnrichmentCache_Roundtrip(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	checkID := finding.CheckID("tls.cert_expiry_7d")

	exp, imp, rem, found := s.GetEnrichmentCache(ctx, checkID)
	if found {
		t.Fatal("expected not found for empty cache")
	}

	if err := s.SaveEnrichmentCache(ctx, checkID, "cert expires soon", "outage risk", "renew cert"); err != nil {
		t.Fatalf("SaveEnrichmentCache: %v", err)
	}

	exp, imp, rem, found = s.GetEnrichmentCache(ctx, checkID)
	if !found {
		t.Fatal("expected found after save")
	}
	if exp != "cert expires soon" {
		t.Errorf("explanation = %q", exp)
	}
	if imp != "outage risk" {
		t.Errorf("impact = %q", imp)
	}
	if rem != "renew cert" {
		t.Errorf("remediation = %q", rem)
	}
}

func TestEnrichmentCache_Upsert(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	checkID := finding.CheckID("test.cache")
	s.SaveEnrichmentCache(ctx, checkID, "v1", "v1", "v1")
	s.SaveEnrichmentCache(ctx, checkID, "v2", "v2", "v2")

	exp, _, _, found := s.GetEnrichmentCache(ctx, checkID)
	if !found {
		t.Fatal("expected found after upsert")
	}
	if exp != "v2" {
		t.Errorf("explanation = %q, want %q (latest)", exp, "v2")
	}
}

// ---------------------------------------------------------------------------
// Correlation Findings
// ---------------------------------------------------------------------------

func TestSaveCorrelationFindings_Empty(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	if err := s.SaveCorrelationFindings(ctx, nil); err != nil {
		t.Fatalf("SaveCorrelationFindings empty: %v", err)
	}
}

func TestSaveCorrelationFindings_Roundtrip(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	run := makeScanRun("example.com")
	s.CreateScanRun(ctx, run)

	cfs := []store.CorrelationFinding{
		{
			ScanRunID:          run.ID,
			Domain:             "example.com",
			Title:              "SSRF to Internal Admin",
			Severity:           finding.SeverityCritical,
			Description:        "SSRF on api.example.com reaches admin.example.com",
			AffectedAssets:     []string{"api.example.com", "admin.example.com"},
			ContributingChecks: []string{"ssrf.open_redirect", "admin.exposed"},
			Remediation:        "Block SSRF",
		},
	}
	if err := s.SaveCorrelationFindings(ctx, cfs); err != nil {
		t.Fatalf("SaveCorrelationFindings: %v", err)
	}

	got, err := s.ListCorrelationFindings(ctx, "example.com")
	if err != nil {
		t.Fatalf("ListCorrelationFindings: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 correlation, got %d", len(got))
	}
	if got[0].Title != "SSRF to Internal Admin" {
		t.Errorf("title = %q", got[0].Title)
	}
	if got[0].Severity != finding.SeverityCritical {
		t.Errorf("severity = %v, want critical", got[0].Severity)
	}
	if len(got[0].AffectedAssets) != 2 {
		t.Errorf("affected_assets = %v, want 2", got[0].AffectedAssets)
	}
	if len(got[0].ContributingChecks) != 2 {
		t.Errorf("contributing_checks = %v, want 2", got[0].ContributingChecks)
	}
}

func TestListCorrelationFindings_Empty(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	got, err := s.ListCorrelationFindings(ctx, "nope.com")
	if err != nil {
		t.Fatalf("ListCorrelationFindings: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// Finding Suppressions
// ---------------------------------------------------------------------------

func TestUpsertSuppression_Roundtrip(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	sup := &store.FindingSuppression{
		Domain:  "example.com",
		CheckID: "email.spf_missing",
		Asset:   "mail.example.com",
		Status:  store.SuppressionFalsePositive,
		Note:    "SPF is handled by third party",
	}
	if err := s.UpsertSuppression(ctx, sup); err != nil {
		t.Fatalf("UpsertSuppression: %v", err)
	}

	got, err := s.ListSuppressions(ctx, "example.com")
	if err != nil {
		t.Fatalf("ListSuppressions: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(got))
	}
	if got[0].Status != store.SuppressionFalsePositive {
		t.Errorf("status = %q, want %q", got[0].Status, store.SuppressionFalsePositive)
	}
	if got[0].Note != "SPF is handled by third party" {
		t.Errorf("note = %q", got[0].Note)
	}
}

func TestUpsertSuppression_UpdateExisting(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	sup := &store.FindingSuppression{
		Domain: "example.com", CheckID: "tls.weak", Asset: "",
		Status: store.SuppressionAcceptedRisk, Note: "planned fix",
	}
	s.UpsertSuppression(ctx, sup)

	// Upsert with same (domain, check_id, asset) key but different status
	sup2 := &store.FindingSuppression{
		Domain: "example.com", CheckID: "tls.weak", Asset: "",
		Status: store.SuppressionWontFix, Note: "deprecated system",
	}
	s.UpsertSuppression(ctx, sup2)

	got, _ := s.ListSuppressions(ctx, "example.com")
	if len(got) != 1 {
		t.Fatalf("expected 1 suppression after upsert, got %d", len(got))
	}
	if got[0].Status != store.SuppressionWontFix {
		t.Errorf("status = %q, want %q after upsert", got[0].Status, store.SuppressionWontFix)
	}
	if got[0].Note != "deprecated system" {
		t.Errorf("note = %q, want updated value", got[0].Note)
	}
}

func TestDeleteSuppression(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	sup := &store.FindingSuppression{
		Domain: "example.com", CheckID: "test.check", Asset: "",
		Status: store.SuppressionFalsePositive,
	}
	s.UpsertSuppression(ctx, sup)

	got, _ := s.ListSuppressions(ctx, "example.com")
	if len(got) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(got))
	}

	if err := s.DeleteSuppression(ctx, got[0].ID); err != nil {
		t.Fatalf("DeleteSuppression: %v", err)
	}

	got, _ = s.ListSuppressions(ctx, "example.com")
	if len(got) != 0 {
		t.Errorf("expected 0 after delete, got %d", len(got))
	}
}

func TestListSuppressions_Empty(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	got, err := s.ListSuppressions(ctx, "nope.com")
	if err != nil {
		t.Fatalf("ListSuppressions: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// Scanner Metrics
// ---------------------------------------------------------------------------

func TestSaveScannerMetric_Roundtrip(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	run := makeScanRun("example.com")
	s.CreateScanRun(ctx, run)

	m := &store.ScannerMetric{
		ScanRunID:        run.ID,
		Asset:            "api.example.com",
		ScannerName:      "cors",
		DurationMs:       450,
		FindingsCritical: 0,
		FindingsHigh:     1,
		FindingsMedium:   2,
		FindingsLow:      0,
		FindingsInfo:     3,
		ErrorCount:       0,
		ErrorMessage:     "",
		Skipped:          false,
		SkipReason:       "",
		CreatedAt:        time.Now().UTC(),
	}
	if err := s.SaveScannerMetric(ctx, m); err != nil {
		t.Fatalf("SaveScannerMetric: %v", err)
	}

	got, err := s.ListScannerMetrics(ctx, run.ID)
	if err != nil {
		t.Fatalf("ListScannerMetrics: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 metric, got %d", len(got))
	}
	if got[0].ScannerName != "cors" {
		t.Errorf("scanner_name = %q, want %q", got[0].ScannerName, "cors")
	}
	if got[0].DurationMs != 450 {
		t.Errorf("duration_ms = %d, want 450", got[0].DurationMs)
	}
	if got[0].FindingsHigh != 1 {
		t.Errorf("findings_high = %d, want 1", got[0].FindingsHigh)
	}
	if got[0].FindingsInfo != 3 {
		t.Errorf("findings_info = %d, want 3", got[0].FindingsInfo)
	}
}

func TestSaveScannerMetric_SkippedFlag(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	run := makeScanRun("example.com")
	s.CreateScanRun(ctx, run)

	m := &store.ScannerMetric{
		ScanRunID:   run.ID,
		Asset:       "a.com",
		ScannerName: "jwt",
		Skipped:     true,
		SkipReason:  "no auth endpoints",
		CreatedAt:   time.Now().UTC(),
	}
	s.SaveScannerMetric(ctx, m)

	got, _ := s.ListScannerMetrics(ctx, run.ID)
	if len(got) != 1 {
		t.Fatalf("expected 1 metric, got %d", len(got))
	}
	if !got[0].Skipped {
		t.Error("expected Skipped=true")
	}
	if got[0].SkipReason != "no auth endpoints" {
		t.Errorf("skip_reason = %q", got[0].SkipReason)
	}
}

func TestSaveScannerMetric_ErrorMessage(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	run := makeScanRun("example.com")
	s.CreateScanRun(ctx, run)

	m := &store.ScannerMetric{
		ScanRunID:    run.ID,
		Asset:        "a.com",
		ScannerName:  "testssl",
		ErrorCount:   1,
		ErrorMessage: "TLS handshake timeout",
		CreatedAt:    time.Now().UTC(),
	}
	s.SaveScannerMetric(ctx, m)

	got, _ := s.ListScannerMetrics(ctx, run.ID)
	if got[0].ErrorMessage != "TLS handshake timeout" {
		t.Errorf("error_message = %q", got[0].ErrorMessage)
	}
}

func TestListScannerMetrics_Empty(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	got, err := s.ListScannerMetrics(ctx, "nope")
	if err != nil {
		t.Fatalf("ListScannerMetrics: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// Scanner ROI
// ---------------------------------------------------------------------------

func TestGetScannerROI(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	run := makeScanRun("example.com")
	run.Status = store.StatusCompleted
	s.CreateScanRun(ctx, run)

	for _, name := range []string{"cors", "cors", "jwt"} {
		m := &store.ScannerMetric{
			ScanRunID:   run.ID,
			Asset:       "a.com",
			ScannerName: name,
			DurationMs:  600,
			FindingsHigh: 1,
			CreatedAt:   time.Now().UTC(),
		}
		s.SaveScannerMetric(ctx, m)
	}

	got, err := s.GetScannerROI(ctx, "example.com")
	if err != nil {
		t.Fatalf("GetScannerROI: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 scanner summaries, got %d", len(got))
	}

	// cors should have 2 runs, jwt 1
	var corsROI *store.ScannerROISummary
	for i := range got {
		if got[i].ScannerName == "cors" {
			corsROI = &got[i]
		}
	}
	if corsROI == nil {
		t.Fatal("expected cors in ROI results")
	}
	if corsROI.RunCount != 2 {
		t.Errorf("cors run_count = %d, want 2", corsROI.RunCount)
	}
}

func TestGetScannerROI_Empty(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	got, err := s.GetScannerROI(ctx, "nope.com")
	if err != nil {
		t.Fatalf("GetScannerROI: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// Discovery Audit
// ---------------------------------------------------------------------------

func TestSaveDiscoveryAudit_Roundtrip(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	run := makeScanRun("example.com")
	s.CreateScanRun(ctx, run)

	audits := []store.DiscoveryAudit{
		{ID: "da-1", ScanRunID: run.ID, Asset: "api.example.com", Source: "subdomain", CreatedAt: time.Now().UTC()},
		{ID: "da-2", ScanRunID: run.ID, Asset: "cdn.example.com", Source: "passive", CreatedAt: time.Now().UTC()},
		{ID: "da-3", ScanRunID: run.ID, Asset: "mail.example.com", Source: "subdomain", CreatedAt: time.Now().UTC()},
	}
	if err := s.SaveDiscoveryAudit(ctx, audits); err != nil {
		t.Fatalf("SaveDiscoveryAudit: %v", err)
	}

	sources, err := s.GetDiscoverySourcesByRun(ctx, run.ID)
	if err != nil {
		t.Fatalf("GetDiscoverySourcesByRun: %v", err)
	}
	if len(sources) != 3 {
		t.Errorf("expected 3 sources, got %d", len(sources))
	}
	if sources["api.example.com"] != "subdomain" {
		t.Errorf("source for api = %q, want %q", sources["api.example.com"], "subdomain")
	}
}

func TestSaveDiscoveryAudit_EmptySlice(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	// Empty slice should succeed (transaction commits with no inserts).
	if err := s.SaveDiscoveryAudit(ctx, nil); err != nil {
		t.Fatalf("SaveDiscoveryAudit empty: %v", err)
	}
}

func TestGetDiscoverySourceSummary(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	run := makeScanRun("example.com")
	s.CreateScanRun(ctx, run)

	audits := []store.DiscoveryAudit{
		{ID: "da-1", ScanRunID: run.ID, Asset: "a.example.com", Source: "subdomain", CreatedAt: time.Now().UTC()},
		{ID: "da-2", ScanRunID: run.ID, Asset: "b.example.com", Source: "subdomain", CreatedAt: time.Now().UTC()},
		{ID: "da-3", ScanRunID: run.ID, Asset: "c.example.com", Source: "passive", CreatedAt: time.Now().UTC()},
	}
	s.SaveDiscoveryAudit(ctx, audits)

	got, err := s.GetDiscoverySourceSummary(ctx, "example.com")
	if err != nil {
		t.Fatalf("GetDiscoverySourceSummary: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 sources, got %d", len(got))
	}
	// Ordered by count DESC: subdomain (2) first, passive (1) second
	if got[0].Source != "subdomain" || got[0].AssetCount != 2 {
		t.Errorf("first source = %q count = %d, want subdomain/2", got[0].Source, got[0].AssetCount)
	}
}

func TestGetDiscoverySourcesByRun_Empty(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	got, err := s.GetDiscoverySourcesByRun(ctx, "nope")
	if err != nil {
		t.Fatalf("GetDiscoverySourcesByRun: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// False Positive Patterns
// ---------------------------------------------------------------------------

func TestGetFalsePositivePatterns_Empty(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	got, err := s.GetFalsePositivePatterns(ctx, "example.com")
	if err != nil {
		t.Fatalf("GetFalsePositivePatterns: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0, got %d", len(got))
	}
}

func TestGetFalsePositivePatterns_DetectsPattern(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	run := makeScanRun("example.com")
	run.Status = store.StatusCompleted
	completedAt := time.Now().UTC()
	run.CompletedAt = &completedAt
	s.CreateScanRun(ctx, run)

	// Save a finding
	f := finding.Finding{
		CheckID: "email.spf_missing", Module: "surface", Scanner: "email",
		Severity: finding.SeverityLow, Title: "SPF Missing",
		Description: "d", Asset: "example.com", DiscoveredAt: time.Now().UTC(),
	}
	s.SaveFindings(ctx, run.ID, []finding.Finding{f})

	// Save enriched finding with false positive language
	ef := enrichment.EnrichedFinding{
		Finding:     f,
		Explanation: "This is a false positive - the domain has a delegated SPF.",
	}
	s.SaveEnrichedFindings(ctx, run.ID, []enrichment.EnrichedFinding{ef})

	got, err := s.GetFalsePositivePatterns(ctx, "example.com")
	if err != nil {
		t.Fatalf("GetFalsePositivePatterns: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 false positive pattern, got %d", len(got))
	}
	if got[0] != "email.spf_missing" {
		t.Errorf("check_id = %q, want %q", got[0], "email.spf_missing")
	}
}

// ---------------------------------------------------------------------------
// Sanitized Cross-Domain Metrics
// ---------------------------------------------------------------------------

func TestSaveSanitizedMetrics_Empty(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	if err := s.SaveSanitizedMetrics(ctx, nil); err != nil {
		t.Fatalf("SaveSanitizedMetrics empty: %v", err)
	}
}

func TestSaveSanitizedMetrics_Roundtrip(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	metrics := []store.SanitizedScannerMetric{
		{
			ID: "sm-1", ScannerName: "cors", TechCategory: "nginx",
			PlaybookName: "nginx_web", DurationMs: 300,
			FindingsCritical: 0, FindingsHigh: 1, FindingsMedium: 0,
			FindingsLow: 2, FindingsInfo: 0,
			ErrorCount: 0, Skipped: false,
			CreatedAt: time.Now().UTC(),
		},
		{
			ID: "sm-2", ScannerName: "cors", TechCategory: "nginx",
			PlaybookName: "nginx_web", DurationMs: 500,
			FindingsCritical: 1, FindingsHigh: 0,
			CreatedAt: time.Now().UTC(),
		},
	}
	if err := s.SaveSanitizedMetrics(ctx, metrics); err != nil {
		t.Fatalf("SaveSanitizedMetrics: %v", err)
	}

	got, err := s.GetCrossDomainScannerSummary(ctx)
	if err != nil {
		t.Fatalf("GetCrossDomainScannerSummary: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 summary (grouped by scanner+tech), got %d", len(got))
	}
	if got[0].ScannerName != "cors" {
		t.Errorf("scanner_name = %q", got[0].ScannerName)
	}
	if got[0].RunCount != 2 {
		t.Errorf("run_count = %d, want 2", got[0].RunCount)
	}
	if got[0].TotalFindings != 4 {
		t.Errorf("total_findings = %d, want 4 (1+0+2+0+1+0)", got[0].TotalFindings)
	}
}

func TestGetCrossDomainScannerSummary_Empty(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	got, err := s.GetCrossDomainScannerSummary(ctx)
	if err != nil {
		t.Fatalf("GetCrossDomainScannerSummary: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// Fingerprint Rules
// ---------------------------------------------------------------------------

func TestUpsertFingerprintRule_Roundtrip(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	r := &store.FingerprintRule{
		SignalType:  "header",
		SignalKey:   "server",
		SignalValue: "nginx",
		Field:       "proxy_type",
		Value:       "nginx",
		Source:      "builtin",
		Status:      "active",
		Confidence:  1.0,
		SeenCount:   1,
	}
	if err := s.UpsertFingerprintRule(ctx, r); err != nil {
		t.Fatalf("UpsertFingerprintRule: %v", err)
	}

	got, err := s.GetFingerprintRules(ctx, "active")
	if err != nil {
		t.Fatalf("GetFingerprintRules: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(got))
	}
	if got[0].SignalType != "header" {
		t.Errorf("signal_type = %q", got[0].SignalType)
	}
	if got[0].Value != "nginx" {
		t.Errorf("value = %q", got[0].Value)
	}
	if got[0].ID == 0 {
		t.Error("expected non-zero ID from AUTOINCREMENT")
	}
}

func TestUpsertFingerprintRule_IncrementsSeen(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	r := &store.FingerprintRule{
		SignalType: "header", SignalKey: "server", SignalValue: "apache",
		Field: "proxy_type", Value: "apache",
		Source: "ai", Status: "active", Confidence: 0.9, SeenCount: 1,
	}
	s.UpsertFingerprintRule(ctx, r)
	s.UpsertFingerprintRule(ctx, r) // second upsert increments seen_count

	got, _ := s.GetFingerprintRules(ctx, "active")
	if len(got) != 1 {
		t.Fatalf("expected 1 rule after upsert, got %d", len(got))
	}
	if got[0].SeenCount != 2 {
		t.Errorf("seen_count = %d, want 2", got[0].SeenCount)
	}
}

func TestGetFingerprintRules_FilterByStatus(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	active := &store.FingerprintRule{
		SignalType: "header", SignalKey: "x-powered-by", SignalValue: "express",
		Field: "framework", Value: "express",
		Source: "ai", Status: "active", Confidence: 0.95, SeenCount: 5,
	}
	pending := &store.FingerprintRule{
		SignalType: "body", SignalKey: "", SignalValue: "wp-content",
		Field: "framework", Value: "wordpress",
		Source: "ai", Status: "pending", Confidence: 0.7, SeenCount: 1,
	}
	s.UpsertFingerprintRule(ctx, active)
	s.UpsertFingerprintRule(ctx, pending)

	// Empty status defaults to active
	activeRules, _ := s.GetFingerprintRules(ctx, "")
	if len(activeRules) != 1 {
		t.Errorf("expected 1 active rule (default filter), got %d", len(activeRules))
	}

	pendingRules, _ := s.GetFingerprintRules(ctx, "pending")
	if len(pendingRules) != 1 {
		t.Errorf("expected 1 pending rule, got %d", len(pendingRules))
	}
}

func TestDeleteFingerprintRule(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	r := &store.FingerprintRule{
		SignalType: "cname", SignalKey: "", SignalValue: "cloudfront",
		Field: "cloud_provider", Value: "aws",
		Source: "builtin", Status: "active", Confidence: 1.0, SeenCount: 1,
	}
	s.UpsertFingerprintRule(ctx, r)

	rules, _ := s.GetFingerprintRules(ctx, "active")
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	if err := s.DeleteFingerprintRule(ctx, rules[0].ID); err != nil {
		t.Fatalf("DeleteFingerprintRule: %v", err)
	}

	rules, _ = s.GetFingerprintRules(ctx, "active")
	if len(rules) != 0 {
		t.Errorf("expected 0 after delete, got %d", len(rules))
	}
}

func TestIncrementFingerprintRuleSeen(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	r := &store.FingerprintRule{
		SignalType: "title", SignalKey: "", SignalValue: "grafana",
		Field: "framework", Value: "grafana",
		Source: "builtin", Status: "active", Confidence: 1.0, SeenCount: 1,
	}
	s.UpsertFingerprintRule(ctx, r)

	rules, _ := s.GetFingerprintRules(ctx, "active")
	id := rules[0].ID

	s.IncrementFingerprintRuleSeen(ctx, id)
	s.IncrementFingerprintRuleSeen(ctx, id)

	rules, _ = s.GetFingerprintRules(ctx, "active")
	if rules[0].SeenCount != 3 {
		t.Errorf("seen_count = %d, want 3 (1 initial + 2 increments)", rules[0].SeenCount)
	}
}

// ---------------------------------------------------------------------------
// DeleteScanRun cascades to all child tables
// ---------------------------------------------------------------------------

func TestDeleteScanRun_CascadesAllTables(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	run := makeScanRun("example.com")
	s.CreateScanRun(ctx, run)

	// Populate all child tables
	s.SaveFindings(ctx, run.ID, makeFindings(2))
	s.SaveEnrichedFindings(ctx, run.ID, []enrichment.EnrichedFinding{
		{Finding: finding.Finding{CheckID: "test.a", Asset: "a.com", DiscoveredAt: time.Now().UTC()}, Explanation: "e"},
	})
	s.SaveReport(ctx, &store.Report{ScanRunID: run.ID, Domain: "example.com", HTMLContent: "<h1>x</h1>"})
	s.SaveAssetExecution(ctx, &store.AssetExecution{ScanRunID: run.ID, Asset: "a.com"})
	s.SaveUnmatchedAsset(ctx, &store.UnmatchedAsset{ScanRunID: run.ID, Fingerprint: "fp-cascade", Asset: "b.com"})
	s.SaveScannerMetric(ctx, &store.ScannerMetric{ScanRunID: run.ID, Asset: "a.com", ScannerName: "cors", CreatedAt: time.Now().UTC()})
	s.SaveDiscoveryAudit(ctx, []store.DiscoveryAudit{
		{ID: "da-c", ScanRunID: run.ID, Asset: "a.com", Source: "subdomain", CreatedAt: time.Now().UTC()},
	})
	s.SaveCorrelationFindings(ctx, []store.CorrelationFinding{
		{ScanRunID: run.ID, Domain: "example.com", Title: "chain", Severity: finding.SeverityHigh},
	})

	if err := s.DeleteScanRun(ctx, run.ID); err != nil {
		t.Fatalf("DeleteScanRun: %v", err)
	}

	// Verify all child data is gone
	findings, _ := s.GetFindings(ctx, run.ID)
	if len(findings) != 0 {
		t.Error("findings not cascaded")
	}
	enriched, _ := s.GetEnrichedFindings(ctx, run.ID)
	if len(enriched) != 0 {
		t.Error("enriched findings not cascaded")
	}
	_, err := s.GetReport(ctx, run.ID)
	if err == nil {
		t.Error("report not cascaded")
	}
	execs, _ := s.ListAssetExecutions(ctx, run.ID)
	if len(execs) != 0 {
		t.Error("asset executions not cascaded")
	}
	metrics, _ := s.ListScannerMetrics(ctx, run.ID)
	if len(metrics) != 0 {
		t.Error("scanner metrics not cascaded")
	}
	sources, _ := s.GetDiscoverySourcesByRun(ctx, run.ID)
	if len(sources) != 0 {
		t.Error("discovery audit not cascaded")
	}
	corrs, _ := s.ListCorrelationFindings(ctx, "example.com")
	if len(corrs) != 0 {
		t.Error("correlation findings not cascaded")
	}
}

// ---------------------------------------------------------------------------
// Close
// ---------------------------------------------------------------------------

func TestClose(t *testing.T) {
	dir := t.TempDir()
	s, err := sqlite.Open(dir + "/close.db")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Verify Store interface compliance at compile time
// ---------------------------------------------------------------------------

var _ store.Store = (*sqlite.Store)(nil)

// suppress unused import warning for sql package
var _ = sql.ErrNoRows
