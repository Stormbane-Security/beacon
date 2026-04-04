package memory_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stormbane-security/beacon/internal/enrichment"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/store"
	"github.com/stormbane-security/beacon/internal/store/memory"
)

// --- Helpers ---

func newStore() *memory.Store { return memory.New() }
func ctx() context.Context    { return context.Background() }

func mustUpsertTarget(t *testing.T, s *memory.Store, domain string) *store.Target {
	t.Helper()
	tgt, err := s.UpsertTarget(ctx(), domain)
	if err != nil {
		t.Fatalf("UpsertTarget(%q) error: %v", domain, err)
	}
	return tgt
}

func mustCreateRun(t *testing.T, s *memory.Store, domain string, scanType module.ScanType) *store.ScanRun {
	t.Helper()
	run := memory.NewScanRun(domain, scanType)
	if err := s.CreateScanRun(ctx(), run); err != nil {
		t.Fatalf("CreateScanRun error: %v", err)
	}
	return run
}

// --- Target tests ---

func TestUpsertTarget_CreatesNewTarget(t *testing.T) {
	s := newStore()
	tgt, err := s.UpsertTarget(ctx(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tgt.Domain != "example.com" {
		t.Errorf("Domain = %q; want %q", tgt.Domain, "example.com")
	}
	if tgt.ID == "" {
		t.Error("ID is empty; want non-empty UUID")
	}
	if tgt.CreatedAt.IsZero() {
		t.Error("CreatedAt is zero; want non-zero timestamp")
	}
}

func TestUpsertTarget_ReturnsSameTargetOnDuplicate(t *testing.T) {
	s := newStore()
	first, _ := s.UpsertTarget(ctx(), "example.com")
	second, _ := s.UpsertTarget(ctx(), "example.com")

	if first.ID != second.ID {
		t.Errorf("second upsert ID = %q; want same ID %q", second.ID, first.ID)
	}
}

func TestGetTarget_ReturnsErrorForMissingTarget(t *testing.T) {
	s := newStore()
	_, err := s.GetTarget(ctx(), "nonexistent.com")
	if err == nil {
		t.Fatal("GetTarget on missing domain: want error, got nil")
	}
}

func TestGetTarget_ReturnsExistingTarget(t *testing.T) {
	s := newStore()
	created := mustUpsertTarget(t, s, "example.com")
	got, err := s.GetTarget(ctx(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("ID = %q; want %q", got.ID, created.ID)
	}
}

func TestListTargets_EmptyStore(t *testing.T) {
	s := newStore()
	targets, err := s.ListTargets(ctx())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(targets) != 0 {
		t.Errorf("len = %d; want 0", len(targets))
	}
}

func TestListTargets_ReturnsAllTargetsSortedByCreatedAtDesc(t *testing.T) {
	s := newStore()
	// Insert with slight delay to ensure ordering.
	mustUpsertTarget(t, s, "alpha.com")
	time.Sleep(time.Millisecond)
	mustUpsertTarget(t, s, "beta.com")

	targets, err := s.ListTargets(ctx())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("len = %d; want 2", len(targets))
	}
	// Most recent first.
	if targets[0].Domain != "beta.com" {
		t.Errorf("targets[0].Domain = %q; want %q", targets[0].Domain, "beta.com")
	}
	if targets[1].Domain != "alpha.com" {
		t.Errorf("targets[1].Domain = %q; want %q", targets[1].Domain, "alpha.com")
	}
}

// --- ScanRun tests ---

func TestCreateScanRun_AssignsIDIfEmpty(t *testing.T) {
	s := newStore()
	run := &store.ScanRun{Domain: "example.com", ScanType: module.ScanSurface, Status: store.StatusPending, StartedAt: time.Now()}
	if err := s.CreateScanRun(ctx(), run); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if run.ID == "" {
		t.Error("ID is empty after CreateScanRun; want auto-generated UUID")
	}
}

func TestCreateScanRun_PreservesExplicitID(t *testing.T) {
	s := newStore()
	run := &store.ScanRun{ID: "custom-id-123", Domain: "example.com", ScanType: module.ScanSurface, Status: store.StatusPending, StartedAt: time.Now()}
	if err := s.CreateScanRun(ctx(), run); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got, err := s.GetScanRun(ctx(), "custom-id-123")
	if err != nil {
		t.Fatalf("GetScanRun error: %v", err)
	}
	if got.ID != "custom-id-123" {
		t.Errorf("ID = %q; want %q", got.ID, "custom-id-123")
	}
}

func TestCreateScanRun_StoresIndependentCopy(t *testing.T) {
	s := newStore()
	run := memory.NewScanRun("example.com", module.ScanSurface)
	_ = s.CreateScanRun(ctx(), run)

	// Mutate the original — stored copy must not change.
	origID := run.ID
	run.Domain = "mutated.com"

	got, _ := s.GetScanRun(ctx(), origID)
	if got.Domain != "example.com" {
		t.Errorf("stored Domain = %q; want %q (mutation leaked)", got.Domain, "example.com")
	}
}

func TestUpdateScanRun_UpdatesExistingRun(t *testing.T) {
	s := newStore()
	run := mustCreateRun(t, s, "example.com", module.ScanSurface)
	run.Status = store.StatusCompleted
	now := time.Now()
	run.CompletedAt = &now

	if err := s.UpdateScanRun(ctx(), run); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, _ := s.GetScanRun(ctx(), run.ID)
	if got.Status != store.StatusCompleted {
		t.Errorf("Status = %q; want %q", got.Status, store.StatusCompleted)
	}
	if got.CompletedAt == nil {
		t.Error("CompletedAt is nil; want non-nil")
	}
}

func TestUpdateScanRun_ErrorOnMissingRun(t *testing.T) {
	s := newStore()
	run := &store.ScanRun{ID: "does-not-exist"}
	if err := s.UpdateScanRun(ctx(), run); err == nil {
		t.Fatal("UpdateScanRun on missing run: want error, got nil")
	}
}

func TestGetScanRun_ReturnsCopy(t *testing.T) {
	s := newStore()
	run := mustCreateRun(t, s, "example.com", module.ScanSurface)

	got, _ := s.GetScanRun(ctx(), run.ID)
	got.Domain = "mutated.com"

	got2, _ := s.GetScanRun(ctx(), run.ID)
	if got2.Domain != "example.com" {
		t.Errorf("second GetScanRun Domain = %q; want %q (returned reference, not copy)", got2.Domain, "example.com")
	}
}

func TestGetScanRun_ErrorOnMissing(t *testing.T) {
	s := newStore()
	_, err := s.GetScanRun(ctx(), "no-such-id")
	if err == nil {
		t.Fatal("GetScanRun on missing ID: want error, got nil")
	}
}

func TestListScanRuns_FiltersByDomain(t *testing.T) {
	s := newStore()
	mustCreateRun(t, s, "a.com", module.ScanSurface)
	mustCreateRun(t, s, "b.com", module.ScanSurface)
	mustCreateRun(t, s, "a.com", module.ScanDeep)

	runs, err := s.ListScanRuns(ctx(), "a.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(runs) != 2 {
		t.Errorf("len = %d; want 2 (only a.com runs)", len(runs))
	}
	for _, r := range runs {
		if r.Domain != "a.com" {
			t.Errorf("run Domain = %q; want %q", r.Domain, "a.com")
		}
	}
}

func TestListScanRuns_SortedByStartedAtDesc(t *testing.T) {
	s := newStore()
	r1 := &store.ScanRun{ID: "r1", Domain: "x.com", StartedAt: time.Now().Add(-2 * time.Hour)}
	r2 := &store.ScanRun{ID: "r2", Domain: "x.com", StartedAt: time.Now().Add(-1 * time.Hour)}
	r3 := &store.ScanRun{ID: "r3", Domain: "x.com", StartedAt: time.Now()}
	_ = s.CreateScanRun(ctx(), r1)
	_ = s.CreateScanRun(ctx(), r2)
	_ = s.CreateScanRun(ctx(), r3)

	runs, _ := s.ListScanRuns(ctx(), "x.com")
	if len(runs) != 3 {
		t.Fatalf("len = %d; want 3", len(runs))
	}
	if runs[0].ID != "r3" || runs[1].ID != "r2" || runs[2].ID != "r1" {
		t.Errorf("order = [%s, %s, %s]; want [r3, r2, r1]", runs[0].ID, runs[1].ID, runs[2].ID)
	}
}

func TestListScanRuns_EmptyForUnknownDomain(t *testing.T) {
	s := newStore()
	mustCreateRun(t, s, "a.com", module.ScanSurface)
	runs, _ := s.ListScanRuns(ctx(), "unknown.com")
	if len(runs) != 0 {
		t.Errorf("len = %d; want 0", len(runs))
	}
}

// --- DeleteScanRun ---

func TestDeleteScanRun_RemovesRunAndAssociatedData(t *testing.T) {
	s := newStore()
	run := mustCreateRun(t, s, "example.com", module.ScanSurface)

	findings := []finding.Finding{{CheckID: "test.check", Asset: "example.com"}}
	_ = s.SaveFindings(ctx(), run.ID, findings)
	enriched := []enrichment.EnrichedFinding{{Finding: findings[0], Explanation: "test"}}
	_ = s.SaveEnrichedFindings(ctx(), run.ID, enriched)

	if err := s.DeleteScanRun(ctx(), run.ID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Run should be gone.
	if _, err := s.GetScanRun(ctx(), run.ID); err == nil {
		t.Error("GetScanRun after delete: want error, got nil")
	}
	// Findings should be gone.
	got, _ := s.GetFindings(ctx(), run.ID)
	if len(got) != 0 {
		t.Errorf("GetFindings after delete: len = %d; want 0", len(got))
	}
	// Enriched findings should be gone.
	ef, _ := s.GetEnrichedFindings(ctx(), run.ID)
	if len(ef) != 0 {
		t.Errorf("GetEnrichedFindings after delete: len = %d; want 0", len(ef))
	}
}

func TestDeleteScanRun_NoErrorForNonexistentID(t *testing.T) {
	s := newStore()
	if err := s.DeleteScanRun(ctx(), "does-not-exist"); err != nil {
		t.Fatalf("DeleteScanRun on missing ID: want nil, got %v", err)
	}
}

// --- Findings ---

func TestSaveFindings_DedupBySameCheckIDAssetTitle(t *testing.T) {
	s := newStore()
	run := mustCreateRun(t, s, "example.com", module.ScanSurface)

	f1 := finding.Finding{
		CheckID: "cors.wildcard_origin",
		Asset:   "api.example.com",
		Title:   "Wildcard CORS origin",
		Scanner: "cors",
		Module:  "surface",
	}
	f2 := f1 // exact same CheckID + Asset + Title

	// Save the same finding twice in separate batches.
	_ = s.SaveFindings(ctx(), run.ID, []finding.Finding{f1})
	_ = s.SaveFindings(ctx(), run.ID, []finding.Finding{f2})

	got, err := s.GetFindings(ctx(), run.ID)
	if err != nil {
		t.Fatalf("GetFindings: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("expected 1 finding after dedup, got %d", len(got))
	}
}

func TestSaveFindings_DifferentCheckIDsNotDeduped(t *testing.T) {
	s := newStore()
	run := mustCreateRun(t, s, "example.com", module.ScanSurface)

	f1 := finding.Finding{
		CheckID: "cors.wildcard_origin",
		Asset:   "api.example.com",
		Title:   "Wildcard CORS origin",
		Scanner: "cors",
		Module:  "surface",
	}
	f2 := finding.Finding{
		CheckID: "tls.expired_cert",
		Asset:   "api.example.com",
		Title:   "Expired TLS certificate",
		Scanner: "tls",
		Module:  "surface",
	}

	_ = s.SaveFindings(ctx(), run.ID, []finding.Finding{f1, f2})

	got, err := s.GetFindings(ctx(), run.ID)
	if err != nil {
		t.Fatalf("GetFindings: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 findings (different CheckIDs), got %d", len(got))
	}
}

func TestSaveFindings_SameCheckIDDifferentAssetNotDeduped(t *testing.T) {
	s := newStore()
	run := mustCreateRun(t, s, "example.com", module.ScanSurface)

	f1 := finding.Finding{
		CheckID: "cors.wildcard_origin",
		Asset:   "api.example.com",
		Title:   "Wildcard CORS origin",
		Scanner: "cors",
		Module:  "surface",
	}
	f2 := finding.Finding{
		CheckID: "cors.wildcard_origin",
		Asset:   "app.example.com",
		Title:   "Wildcard CORS origin",
		Scanner: "cors",
		Module:  "surface",
	}

	_ = s.SaveFindings(ctx(), run.ID, []finding.Finding{f1, f2})

	got, err := s.GetFindings(ctx(), run.ID)
	if err != nil {
		t.Fatalf("GetFindings: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 findings (same CheckID, different assets), got %d", len(got))
	}
}

func TestSaveFindings_AppendsBatches(t *testing.T) {
	s := newStore()
	run := mustCreateRun(t, s, "example.com", module.ScanSurface)

	batch1 := []finding.Finding{{CheckID: "a.check", Asset: "a.example.com"}}
	batch2 := []finding.Finding{{CheckID: "b.check", Asset: "b.example.com"}}
	_ = s.SaveFindings(ctx(), run.ID, batch1)
	_ = s.SaveFindings(ctx(), run.ID, batch2)

	got, err := s.GetFindings(ctx(), run.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("len = %d; want 2 (both batches appended)", len(got))
	}
}

func TestGetFindings_EmptyForUnknownRun(t *testing.T) {
	s := newStore()
	got, err := s.GetFindings(ctx(), "nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("len = %d; want 0", len(got))
	}
}

// --- Enriched Findings ---

func TestSaveAndGetEnrichedFindings(t *testing.T) {
	s := newStore()
	run := mustCreateRun(t, s, "example.com", module.ScanSurface)

	ef := []enrichment.EnrichedFinding{
		{Finding: finding.Finding{CheckID: "test.check", Asset: "a.com"}, Explanation: "explained"},
		{Finding: finding.Finding{CheckID: "test.other", Asset: "b.com"}, Impact: "high impact"},
	}
	if err := s.SaveEnrichedFindings(ctx(), run.ID, ef); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := s.GetEnrichedFindings(ctx(), run.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("len = %d; want 2", len(got))
	}
	if got[0].Explanation != "explained" {
		t.Errorf("Explanation = %q; want %q", got[0].Explanation, "explained")
	}
}

func TestSaveEnrichedFindings_OverwritesPreviousBatch(t *testing.T) {
	s := newStore()
	run := mustCreateRun(t, s, "example.com", module.ScanSurface)

	ef1 := []enrichment.EnrichedFinding{{Finding: finding.Finding{CheckID: "a"}, Explanation: "first"}}
	ef2 := []enrichment.EnrichedFinding{{Finding: finding.Finding{CheckID: "b"}, Explanation: "second"}}
	_ = s.SaveEnrichedFindings(ctx(), run.ID, ef1)
	_ = s.SaveEnrichedFindings(ctx(), run.ID, ef2)

	got, _ := s.GetEnrichedFindings(ctx(), run.ID)
	if len(got) != 1 {
		t.Fatalf("len = %d; want 1 (second save overwrites)", len(got))
	}
	if got[0].Explanation != "second" {
		t.Errorf("Explanation = %q; want %q", got[0].Explanation, "second")
	}
}

func TestGetEnrichedFindings_EmptyForUnknownRun(t *testing.T) {
	s := newStore()
	got, err := s.GetEnrichedFindings(ctx(), "nope")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("len = %d; want 0", len(got))
	}
}

// --- GetPreviousEnrichedFindings ---

func TestGetPreviousEnrichedFindings_ReturnsNilWhenNoPreviousRun(t *testing.T) {
	s := newStore()
	run := mustCreateRun(t, s, "example.com", module.ScanSurface)

	got, err := s.GetPreviousEnrichedFindings(ctx(), "example.com", run.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("got %v; want nil", got)
	}
}

func TestGetPreviousEnrichedFindings_FindsMostRecentCompletedRun(t *testing.T) {
	s := newStore()

	// Create two completed runs for the same domain.
	old := &store.ScanRun{ID: "old", Domain: "example.com", Status: store.StatusCompleted, StartedAt: time.Now().Add(-2 * time.Hour)}
	oldComplete := time.Now().Add(-90 * time.Minute)
	old.CompletedAt = &oldComplete
	_ = s.CreateScanRun(ctx(), old)
	_ = s.SaveEnrichedFindings(ctx(), "old", []enrichment.EnrichedFinding{{Explanation: "old-finding"}})

	recent := &store.ScanRun{ID: "recent", Domain: "example.com", Status: store.StatusCompleted, StartedAt: time.Now().Add(-1 * time.Hour)}
	recentComplete := time.Now().Add(-30 * time.Minute)
	recent.CompletedAt = &recentComplete
	_ = s.CreateScanRun(ctx(), recent)
	_ = s.SaveEnrichedFindings(ctx(), "recent", []enrichment.EnrichedFinding{{Explanation: "recent-finding"}})

	// Current run (not yet completed).
	current := mustCreateRun(t, s, "example.com", module.ScanSurface)

	got, err := s.GetPreviousEnrichedFindings(ctx(), "example.com", current.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d; want 1", len(got))
	}
	if got[0].Explanation != "recent-finding" {
		t.Errorf("Explanation = %q; want %q", got[0].Explanation, "recent-finding")
	}
}

func TestGetPreviousEnrichedFindings_IgnoresOtherDomains(t *testing.T) {
	s := newStore()

	other := &store.ScanRun{ID: "other", Domain: "other.com", Status: store.StatusCompleted, StartedAt: time.Now().Add(-1 * time.Hour)}
	otherComplete := time.Now().Add(-30 * time.Minute)
	other.CompletedAt = &otherComplete
	_ = s.CreateScanRun(ctx(), other)
	_ = s.SaveEnrichedFindings(ctx(), "other", []enrichment.EnrichedFinding{{Explanation: "other-domain"}})

	current := mustCreateRun(t, s, "example.com", module.ScanSurface)

	got, _ := s.GetPreviousEnrichedFindings(ctx(), "example.com", current.ID)
	if got != nil {
		t.Errorf("got %v; want nil (other domain should not match)", got)
	}
}

func TestGetPreviousEnrichedFindings_ExcludesCurrentRun(t *testing.T) {
	s := newStore()

	// Only completed run is the current one.
	run := &store.ScanRun{ID: "current", Domain: "example.com", Status: store.StatusCompleted, StartedAt: time.Now()}
	now := time.Now()
	run.CompletedAt = &now
	_ = s.CreateScanRun(ctx(), run)
	_ = s.SaveEnrichedFindings(ctx(), "current", []enrichment.EnrichedFinding{{Explanation: "self"}})

	got, _ := s.GetPreviousEnrichedFindings(ctx(), "example.com", "current")
	if got != nil {
		t.Errorf("got %v; want nil (current run must be excluded)", got)
	}
}

// --- Reports ---

func TestSaveAndGetReport(t *testing.T) {
	s := newStore()
	run := mustCreateRun(t, s, "example.com", module.ScanSurface)

	report := &store.Report{
		ID:          "rpt-1",
		ScanRunID:   run.ID,
		Domain:      "example.com",
		HTMLContent: "<h1>Report</h1>",
		Summary:     "All clear",
		CreatedAt:   time.Now(),
	}
	if err := s.SaveReport(ctx(), report); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := s.GetReport(ctx(), run.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.HTMLContent != "<h1>Report</h1>" {
		t.Errorf("HTMLContent = %q; want %q", got.HTMLContent, "<h1>Report</h1>")
	}
	if got.Summary != "All clear" {
		t.Errorf("Summary = %q; want %q", got.Summary, "All clear")
	}
}

func TestGetReport_ReturnsCopy(t *testing.T) {
	s := newStore()
	run := mustCreateRun(t, s, "example.com", module.ScanSurface)
	_ = s.SaveReport(ctx(), &store.Report{ScanRunID: run.ID, Summary: "original"})

	got, _ := s.GetReport(ctx(), run.ID)
	got.Summary = "mutated"

	got2, _ := s.GetReport(ctx(), run.ID)
	if got2.Summary != "original" {
		t.Errorf("Summary = %q; want %q (mutation leaked)", got2.Summary, "original")
	}
}

func TestGetReport_ErrorOnMissing(t *testing.T) {
	s := newStore()
	_, err := s.GetReport(ctx(), "no-such-run")
	if err == nil {
		t.Fatal("GetReport on missing run: want error, got nil")
	}
}

// --- Playbook Suggestions ---

func TestSavePlaybookSuggestion_AssignsIDIfEmpty(t *testing.T) {
	s := newStore()
	sg := &store.PlaybookSuggestion{Type: "new", Status: "pending"}
	if err := s.SavePlaybookSuggestion(ctx(), sg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sg.ID == "" {
		t.Error("ID is empty; want auto-generated ID")
	}
}

func TestListPlaybookSuggestions_FiltersByStatus(t *testing.T) {
	s := newStore()
	_ = s.SavePlaybookSuggestion(ctx(), &store.PlaybookSuggestion{Status: "pending"})
	_ = s.SavePlaybookSuggestion(ctx(), &store.PlaybookSuggestion{Status: "merged"})
	_ = s.SavePlaybookSuggestion(ctx(), &store.PlaybookSuggestion{Status: "pending"})

	tests := []struct {
		status string
		want   int
	}{
		{"pending", 2},
		{"merged", 1},
		{"dismissed", 0},
		{"", 3}, // empty = all
	}
	for _, tt := range tests {
		got, err := s.ListPlaybookSuggestions(ctx(), tt.status)
		if err != nil {
			t.Fatalf("ListPlaybookSuggestions(%q) error: %v", tt.status, err)
		}
		if len(got) != tt.want {
			t.Errorf("ListPlaybookSuggestions(%q) len = %d; want %d", tt.status, len(got), tt.want)
		}
	}
}

func TestUpdatePlaybookSuggestion_UpdatesInPlace(t *testing.T) {
	s := newStore()
	sg := &store.PlaybookSuggestion{Status: "pending"}
	_ = s.SavePlaybookSuggestion(ctx(), sg)

	sg.Status = "merged"
	if err := s.UpdatePlaybookSuggestion(ctx(), sg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	all, _ := s.ListPlaybookSuggestions(ctx(), "merged")
	if len(all) != 1 {
		t.Errorf("merged suggestions = %d; want 1", len(all))
	}
}

func TestUpdatePlaybookSuggestion_ErrorOnMissing(t *testing.T) {
	s := newStore()
	sg := &store.PlaybookSuggestion{ID: "nonexistent", Status: "pending"}
	if err := s.UpdatePlaybookSuggestion(ctx(), sg); err == nil {
		t.Fatal("UpdatePlaybookSuggestion on missing: want error, got nil")
	}
}

// --- Enrichment Cache ---

func TestEnrichmentCache_SaveAndGet(t *testing.T) {
	s := newStore()
	checkID := finding.CheckID("test.cache_check")
	if err := s.SaveEnrichmentCache(ctx(), checkID, "explanation", "impact", "remediation"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	exp, imp, rem, found := s.GetEnrichmentCache(ctx(), checkID)
	if !found {
		t.Fatal("found = false; want true")
	}
	if exp != "explanation" {
		t.Errorf("explanation = %q; want %q", exp, "explanation")
	}
	if imp != "impact" {
		t.Errorf("impact = %q; want %q", imp, "impact")
	}
	if rem != "remediation" {
		t.Errorf("remediation = %q; want %q", rem, "remediation")
	}
}

func TestEnrichmentCache_NotFoundForMissing(t *testing.T) {
	s := newStore()
	_, _, _, found := s.GetEnrichmentCache(ctx(), "nonexistent.check")
	if found {
		t.Error("found = true; want false for missing check")
	}
}

func TestEnrichmentCache_OverwritesOnSecondSave(t *testing.T) {
	s := newStore()
	checkID := finding.CheckID("overwrite.check")
	_ = s.SaveEnrichmentCache(ctx(), checkID, "v1", "v1", "v1")
	_ = s.SaveEnrichmentCache(ctx(), checkID, "v2", "v2", "v2")

	exp, _, _, found := s.GetEnrichmentCache(ctx(), checkID)
	if !found {
		t.Fatal("found = false; want true")
	}
	if exp != "v2" {
		t.Errorf("explanation = %q; want %q (should be overwritten)", exp, "v2")
	}
}

// --- Correlation Findings ---

func TestSaveCorrelationFindings_AssignsIDAndTimestamp(t *testing.T) {
	s := newStore()
	cf := []store.CorrelationFinding{
		{Domain: "example.com", Title: "Chain 1"},
	}
	if err := s.SaveCorrelationFindings(ctx(), cf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, _ := s.ListCorrelationFindings(ctx(), "example.com")
	if len(got) != 1 {
		t.Fatalf("len = %d; want 1", len(got))
	}
	if got[0].ID == "" {
		t.Error("ID is empty; want auto-generated UUID")
	}
	if got[0].CreatedAt.IsZero() {
		t.Error("CreatedAt is zero; want auto-set timestamp")
	}
}

func TestSaveCorrelationFindings_PreservesExplicitID(t *testing.T) {
	s := newStore()
	cf := []store.CorrelationFinding{
		{ID: "my-id", Domain: "example.com", Title: "Chain"},
	}
	_ = s.SaveCorrelationFindings(ctx(), cf)

	got, _ := s.ListCorrelationFindings(ctx(), "example.com")
	if got[0].ID != "my-id" {
		t.Errorf("ID = %q; want %q", got[0].ID, "my-id")
	}
}

func TestListCorrelationFindings_FiltersByDomain(t *testing.T) {
	s := newStore()
	_ = s.SaveCorrelationFindings(ctx(), []store.CorrelationFinding{
		{Domain: "a.com", Title: "Chain A"},
		{Domain: "b.com", Title: "Chain B"},
		{Domain: "a.com", Title: "Chain A2"},
	})

	got, _ := s.ListCorrelationFindings(ctx(), "a.com")
	if len(got) != 2 {
		t.Errorf("len = %d; want 2", len(got))
	}
}

func TestListCorrelationFindings_EmptyForUnknownDomain(t *testing.T) {
	s := newStore()
	got, _ := s.ListCorrelationFindings(ctx(), "unknown.com")
	if len(got) != 0 {
		t.Errorf("len = %d; want 0", len(got))
	}
}

// --- ListRecentScanRuns ---

func TestListRecentScanRuns_OnlyCompleted(t *testing.T) {
	s := newStore()
	now := time.Now()

	completed := &store.ScanRun{ID: "c1", Domain: "a.com", Status: store.StatusCompleted, StartedAt: now, CompletedAt: &now}
	pending := &store.ScanRun{ID: "p1", Domain: "a.com", Status: store.StatusPending, StartedAt: now}
	running := &store.ScanRun{ID: "r1", Domain: "a.com", Status: store.StatusRunning, StartedAt: now}
	_ = s.CreateScanRun(ctx(), completed)
	_ = s.CreateScanRun(ctx(), pending)
	_ = s.CreateScanRun(ctx(), running)

	got, err := s.ListRecentScanRuns(ctx(), 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("len = %d; want 1 (only completed runs)", len(got))
	}
}

func TestListRecentScanRuns_RespectsLimit(t *testing.T) {
	s := newStore()
	for i := 0; i < 5; i++ {
		t1 := time.Now().Add(time.Duration(i) * time.Minute)
		run := &store.ScanRun{
			ID:          fmt.Sprintf("r%d", i),
			Domain:      "example.com",
			Status:      store.StatusCompleted,
			StartedAt:   t1,
			CompletedAt: &t1,
		}
		_ = s.CreateScanRun(ctx(), run)
	}

	got, _ := s.ListRecentScanRuns(ctx(), 3)
	if len(got) != 3 {
		t.Errorf("len = %d; want 3", len(got))
	}
}

func TestListRecentScanRuns_SortedByCompletedAtDesc(t *testing.T) {
	s := newStore()
	t1 := time.Now().Add(-3 * time.Hour)
	t2 := time.Now().Add(-2 * time.Hour)
	t3 := time.Now().Add(-1 * time.Hour)

	_ = s.CreateScanRun(ctx(), &store.ScanRun{ID: "oldest", Domain: "a.com", Status: store.StatusCompleted, StartedAt: t1, CompletedAt: &t1})
	_ = s.CreateScanRun(ctx(), &store.ScanRun{ID: "newest", Domain: "a.com", Status: store.StatusCompleted, StartedAt: t3, CompletedAt: &t3})
	_ = s.CreateScanRun(ctx(), &store.ScanRun{ID: "middle", Domain: "a.com", Status: store.StatusCompleted, StartedAt: t2, CompletedAt: &t2})

	got, _ := s.ListRecentScanRuns(ctx(), 10)
	if len(got) != 3 {
		t.Fatalf("len = %d; want 3", len(got))
	}
	if got[0].ID != "newest" || got[1].ID != "middle" || got[2].ID != "oldest" {
		t.Errorf("order = [%s, %s, %s]; want [newest, middle, oldest]", got[0].ID, got[1].ID, got[2].ID)
	}
}

func TestListRecentScanRuns_ZeroLimitReturnsAll(t *testing.T) {
	s := newStore()
	for i := 0; i < 3; i++ {
		t1 := time.Now().Add(time.Duration(i) * time.Minute)
		_ = s.CreateScanRun(ctx(), &store.ScanRun{
			ID: fmt.Sprintf("r%d", i), Domain: "x.com",
			Status: store.StatusCompleted, StartedAt: t1, CompletedAt: &t1,
		})
	}

	got, _ := s.ListRecentScanRuns(ctx(), 0)
	if len(got) != 3 {
		t.Errorf("len = %d; want 3 (limit=0 should return all)", len(got))
	}
}

// --- Suppressions ---

func TestUpsertSuppression_CreatesNew(t *testing.T) {
	s := newStore()
	sup := &store.FindingSuppression{
		Domain:  "example.com",
		CheckID: "test.check",
		Asset:   "sub.example.com",
		Status:  store.SuppressionFalsePositive,
		Note:    "tested manually",
	}
	if err := s.UpsertSuppression(ctx(), sup); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sup.ID == "" {
		t.Error("ID is empty; want auto-generated UUID")
	}

	got, _ := s.ListSuppressions(ctx(), "example.com")
	if len(got) != 1 {
		t.Fatalf("len = %d; want 1", len(got))
	}
	if got[0].Note != "tested manually" {
		t.Errorf("Note = %q; want %q", got[0].Note, "tested manually")
	}
	if got[0].CreatedAt.IsZero() {
		t.Error("CreatedAt is zero; want auto-set timestamp")
	}
}

func TestUpsertSuppression_ReplacesExistingWithSameKey(t *testing.T) {
	s := newStore()
	sup1 := &store.FindingSuppression{
		Domain:  "example.com",
		CheckID: "test.check",
		Asset:   "sub.example.com",
		Status:  store.SuppressionFalsePositive,
		Note:    "first",
	}
	_ = s.UpsertSuppression(ctx(), sup1)

	sup2 := &store.FindingSuppression{
		Domain:  "example.com",
		CheckID: "test.check",
		Asset:   "sub.example.com",
		Status:  store.SuppressionAcceptedRisk,
		Note:    "updated",
	}
	_ = s.UpsertSuppression(ctx(), sup2)

	got, _ := s.ListSuppressions(ctx(), "example.com")
	if len(got) != 1 {
		t.Fatalf("len = %d; want 1 (upsert should replace)", len(got))
	}
	if got[0].Note != "updated" {
		t.Errorf("Note = %q; want %q", got[0].Note, "updated")
	}
	if got[0].Status != store.SuppressionAcceptedRisk {
		t.Errorf("Status = %q; want %q", got[0].Status, store.SuppressionAcceptedRisk)
	}
}

func TestUpsertSuppression_DifferentKeysCoexist(t *testing.T) {
	s := newStore()
	_ = s.UpsertSuppression(ctx(), &store.FindingSuppression{Domain: "example.com", CheckID: "a.check", Asset: "x.com"})
	_ = s.UpsertSuppression(ctx(), &store.FindingSuppression{Domain: "example.com", CheckID: "b.check", Asset: "x.com"})
	_ = s.UpsertSuppression(ctx(), &store.FindingSuppression{Domain: "example.com", CheckID: "a.check", Asset: "y.com"})

	got, _ := s.ListSuppressions(ctx(), "example.com")
	if len(got) != 3 {
		t.Errorf("len = %d; want 3 (different keys should all be kept)", len(got))
	}
}

func TestListSuppressions_FiltersByDomain(t *testing.T) {
	s := newStore()
	_ = s.UpsertSuppression(ctx(), &store.FindingSuppression{Domain: "a.com", CheckID: "x"})
	_ = s.UpsertSuppression(ctx(), &store.FindingSuppression{Domain: "b.com", CheckID: "y"})

	got, _ := s.ListSuppressions(ctx(), "a.com")
	if len(got) != 1 {
		t.Errorf("len = %d; want 1", len(got))
	}
}

func TestListSuppressions_EmptyForUnknownDomain(t *testing.T) {
	s := newStore()
	got, _ := s.ListSuppressions(ctx(), "unknown.com")
	if len(got) != 0 {
		t.Errorf("len = %d; want 0", len(got))
	}
}

func TestDeleteSuppression(t *testing.T) {
	s := newStore()
	sup := &store.FindingSuppression{Domain: "example.com", CheckID: "test.check"}
	_ = s.UpsertSuppression(ctx(), sup)

	if err := s.DeleteSuppression(ctx(), sup.ID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, _ := s.ListSuppressions(ctx(), "example.com")
	if len(got) != 0 {
		t.Errorf("len = %d; want 0 after delete", len(got))
	}
}

func TestDeleteSuppression_NoErrorForMissingID(t *testing.T) {
	s := newStore()
	if err := s.DeleteSuppression(ctx(), "does-not-exist"); err != nil {
		t.Fatalf("DeleteSuppression on missing ID: want nil, got %v", err)
	}
}

// --- PurgeOrphanedRuns ---

func TestPurgeOrphanedRuns_DeletesFailedAndStoppedOlderThanThreshold(t *testing.T) {
	s := newStore()
	threshold := time.Now().Add(-1 * time.Hour)
	// orphanThreshold = threshold - 2h = -3h from now

	// Old failed run, 2h ago (should be purged — failed + older than threshold).
	_ = s.CreateScanRun(ctx(), &store.ScanRun{ID: "old-failed", Domain: "a.com", Status: store.StatusFailed, StartedAt: time.Now().Add(-2 * time.Hour)})
	_ = s.SaveFindings(ctx(), "old-failed", []finding.Finding{{CheckID: "x"}})

	// Old stopped run, 3h ago (should be purged — stopped + older than threshold).
	_ = s.CreateScanRun(ctx(), &store.ScanRun{ID: "old-stopped", Domain: "a.com", Status: store.StatusStopped, StartedAt: time.Now().Add(-3 * time.Hour)})

	// Old completed run, 4h ago (should NOT be purged — completed runs are never purged).
	_ = s.CreateScanRun(ctx(), &store.ScanRun{ID: "old-completed", Domain: "a.com", Status: store.StatusCompleted, StartedAt: time.Now().Add(-4 * time.Hour)})

	// Old running run, 5h ago (SHOULD be purged — orphaned running, older than orphanThreshold -3h).
	_ = s.CreateScanRun(ctx(), &store.ScanRun{ID: "old-running", Domain: "a.com", Status: store.StatusRunning, StartedAt: time.Now().Add(-5 * time.Hour)})

	// Old pending run, 6h ago (SHOULD be purged — orphaned pending, older than orphanThreshold -3h).
	_ = s.CreateScanRun(ctx(), &store.ScanRun{ID: "old-pending", Domain: "a.com", Status: store.StatusPending, StartedAt: time.Now().Add(-6 * time.Hour)})

	// Recent running run, 2h ago (should NOT be purged — newer than orphanThreshold).
	_ = s.CreateScanRun(ctx(), &store.ScanRun{ID: "recent-running", Domain: "a.com", Status: store.StatusRunning, StartedAt: time.Now().Add(-2 * time.Hour)})

	// Recent failed run (should NOT be purged — newer than threshold).
	_ = s.CreateScanRun(ctx(), &store.ScanRun{ID: "new-failed", Domain: "a.com", Status: store.StatusFailed, StartedAt: time.Now()})

	deleted, err := s.PurgeOrphanedRuns(ctx(), threshold)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deleted != 4 {
		t.Errorf("deleted = %d; want 4 (old-failed, old-stopped, old-running, old-pending)", deleted)
	}

	// Verify old-failed is gone along with its findings.
	if _, err := s.GetScanRun(ctx(), "old-failed"); err == nil {
		t.Error("old-failed still exists after purge")
	}
	findings, _ := s.GetFindings(ctx(), "old-failed")
	if len(findings) != 0 {
		t.Error("findings for old-failed still exist after purge")
	}

	// Verify orphaned running/pending are gone.
	if _, err := s.GetScanRun(ctx(), "old-running"); err == nil {
		t.Error("old-running still exists after purge (should be orphaned)")
	}
	if _, err := s.GetScanRun(ctx(), "old-pending"); err == nil {
		t.Error("old-pending still exists after purge (should be orphaned)")
	}

	// Verify old-completed is preserved.
	if _, err := s.GetScanRun(ctx(), "old-completed"); err != nil {
		t.Errorf("old-completed was purged unexpectedly: %v", err)
	}

	// Verify recent-running is preserved.
	if _, err := s.GetScanRun(ctx(), "recent-running"); err != nil {
		t.Errorf("recent-running was purged unexpectedly: %v", err)
	}

	// Verify new-failed is preserved.
	if _, err := s.GetScanRun(ctx(), "new-failed"); err != nil {
		t.Errorf("new-failed was purged unexpectedly: %v", err)
	}
}

func TestPurgeOrphanedRuns_ReturnsZeroWhenNothingToPurge(t *testing.T) {
	s := newStore()
	deleted, err := s.PurgeOrphanedRuns(ctx(), time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deleted != 0 {
		t.Errorf("deleted = %d; want 0", deleted)
	}
}

// --- No-op / stub methods ---

func TestStubMethods_ReturnNilOrEmpty(t *testing.T) {
	s := newStore()

	// SaveAssetExecution
	if err := s.SaveAssetExecution(ctx(), &store.AssetExecution{}); err != nil {
		t.Errorf("SaveAssetExecution: %v", err)
	}

	// ListAssetExecutions
	ae, err := s.ListAssetExecutions(ctx(), "any")
	if err != nil {
		t.Errorf("ListAssetExecutions error: %v", err)
	}
	if ae != nil {
		t.Errorf("ListAssetExecutions = %v; want nil", ae)
	}

	// SaveUnmatchedAsset
	if err := s.SaveUnmatchedAsset(ctx(), &store.UnmatchedAsset{}); err != nil {
		t.Errorf("SaveUnmatchedAsset: %v", err)
	}

	// FingerprintExists
	exists, err := s.FingerprintExists(ctx(), "fp")
	if err != nil {
		t.Errorf("FingerprintExists error: %v", err)
	}
	if exists {
		t.Error("FingerprintExists = true; want false")
	}

	// ListUnmatchedAssets
	ua, err := s.ListUnmatchedAssets(ctx())
	if err != nil {
		t.Errorf("ListUnmatchedAssets error: %v", err)
	}
	if ua != nil {
		t.Errorf("ListUnmatchedAssets = %v; want nil", ua)
	}

	// SaveScannerMetric
	if err := s.SaveScannerMetric(ctx(), &store.ScannerMetric{}); err != nil {
		t.Errorf("SaveScannerMetric: %v", err)
	}

	// ListScannerMetrics
	sm, err := s.ListScannerMetrics(ctx(), "any")
	if err != nil {
		t.Errorf("ListScannerMetrics error: %v", err)
	}
	if sm != nil {
		t.Errorf("ListScannerMetrics = %v; want nil", sm)
	}

	// GetScannerROI
	roi, err := s.GetScannerROI(ctx(), "any")
	if err != nil {
		t.Errorf("GetScannerROI error: %v", err)
	}
	if roi != nil {
		t.Errorf("GetScannerROI = %v; want nil", roi)
	}

	// SaveDiscoveryAudit
	if err := s.SaveDiscoveryAudit(ctx(), []store.DiscoveryAudit{}); err != nil {
		t.Errorf("SaveDiscoveryAudit: %v", err)
	}

	// GetDiscoverySourceSummary
	dss, err := s.GetDiscoverySourceSummary(ctx(), "any")
	if err != nil {
		t.Errorf("GetDiscoverySourceSummary error: %v", err)
	}
	if dss != nil {
		t.Errorf("GetDiscoverySourceSummary = %v; want nil", dss)
	}

	// GetDiscoverySourcesByRun
	dsr, err := s.GetDiscoverySourcesByRun(ctx(), "any")
	if err != nil {
		t.Errorf("GetDiscoverySourcesByRun error: %v", err)
	}
	if dsr != nil {
		t.Errorf("GetDiscoverySourcesByRun = %v; want nil", dsr)
	}

	// GetFalsePositivePatterns
	fp, err := s.GetFalsePositivePatterns(ctx(), "any")
	if err != nil {
		t.Errorf("GetFalsePositivePatterns error: %v", err)
	}
	if fp != nil {
		t.Errorf("GetFalsePositivePatterns = %v; want nil", fp)
	}

	// SaveSanitizedMetrics
	if err := s.SaveSanitizedMetrics(ctx(), []store.SanitizedScannerMetric{}); err != nil {
		t.Errorf("SaveSanitizedMetrics: %v", err)
	}

	// GetCrossDomainScannerSummary
	cds, err := s.GetCrossDomainScannerSummary(ctx())
	if err != nil {
		t.Errorf("GetCrossDomainScannerSummary error: %v", err)
	}
	if cds != nil {
		t.Errorf("GetCrossDomainScannerSummary = %v; want nil", cds)
	}

	// GetFingerprintRules
	fr, err := s.GetFingerprintRules(ctx(), "active")
	if err != nil {
		t.Errorf("GetFingerprintRules error: %v", err)
	}
	if fr != nil {
		t.Errorf("GetFingerprintRules = %v; want nil", fr)
	}

	// UpsertFingerprintRule
	if err := s.UpsertFingerprintRule(ctx(), &store.FingerprintRule{}); err != nil {
		t.Errorf("UpsertFingerprintRule: %v", err)
	}

	// DeleteFingerprintRule
	if err := s.DeleteFingerprintRule(ctx(), 1); err != nil {
		t.Errorf("DeleteFingerprintRule: %v", err)
	}

	// IncrementFingerprintRuleSeen
	if err := s.IncrementFingerprintRuleSeen(ctx(), 1); err != nil {
		t.Errorf("IncrementFingerprintRuleSeen: %v", err)
	}

	// Close
	if err := s.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// --- NewScanRun helper ---

func TestNewScanRun_SetsDefaults(t *testing.T) {
	run := memory.NewScanRun("example.com", module.ScanDeep)
	if run.Domain != "example.com" {
		t.Errorf("Domain = %q; want %q", run.Domain, "example.com")
	}
	if run.ScanType != module.ScanDeep {
		t.Errorf("ScanType = %q; want %q", run.ScanType, module.ScanDeep)
	}
	if run.Status != store.StatusPending {
		t.Errorf("Status = %q; want %q", run.Status, store.StatusPending)
	}
	if run.ID == "" {
		t.Error("ID is empty; want non-empty UUID")
	}
	if run.StartedAt.IsZero() {
		t.Error("StartedAt is zero; want non-zero timestamp")
	}
}

// --- Interface compliance ---

func TestStore_ImplementsStoreInterface(t *testing.T) {
	var _ store.Store = (*memory.Store)(nil)
}

// --- Thread safety ---

func TestConcurrentReadWrites_Targets(t *testing.T) {
	s := newStore()
	const goroutines = 50
	var wg sync.WaitGroup

	// Concurrent UpsertTarget + GetTarget + ListTargets.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			domain := fmt.Sprintf("domain-%d.com", n)
			_, _ = s.UpsertTarget(ctx(), domain)
			_, _ = s.GetTarget(ctx(), domain)
			_, _ = s.ListTargets(ctx())
		}(i)
	}
	wg.Wait()

	targets, _ := s.ListTargets(ctx())
	if len(targets) != goroutines {
		t.Errorf("target count = %d; want %d", len(targets), goroutines)
	}
}

func TestConcurrentReadWrites_ScanRuns(t *testing.T) {
	s := newStore()
	const goroutines = 50
	var wg sync.WaitGroup
	ids := make([]string, goroutines)

	// Concurrent CreateScanRun.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			run := memory.NewScanRun("concurrent.com", module.ScanSurface)
			_ = s.CreateScanRun(ctx(), run)
			ids[n] = run.ID
		}(i)
	}
	wg.Wait()

	// Concurrent GetScanRun + ListScanRuns.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_, _ = s.GetScanRun(ctx(), ids[n])
			_, _ = s.ListScanRuns(ctx(), "concurrent.com")
		}(i)
	}
	wg.Wait()

	runs, _ := s.ListScanRuns(ctx(), "concurrent.com")
	if len(runs) != goroutines {
		t.Errorf("run count = %d; want %d", len(runs), goroutines)
	}
}

func TestConcurrentReadWrites_Findings(t *testing.T) {
	s := newStore()
	run := mustCreateRun(t, s, "example.com", module.ScanSurface)
	const goroutines = 50
	var wg sync.WaitGroup

	// Concurrent SaveFindings + GetFindings.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			f := []finding.Finding{{CheckID: finding.CheckID(fmt.Sprintf("check.%d", n)), Asset: "example.com"}}
			_ = s.SaveFindings(ctx(), run.ID, f)
			_, _ = s.GetFindings(ctx(), run.ID)
		}(i)
	}
	wg.Wait()

	got, _ := s.GetFindings(ctx(), run.ID)
	if len(got) != goroutines {
		t.Errorf("finding count = %d; want %d", len(got), goroutines)
	}
}

func TestConcurrentReadWrites_EnrichmentCache(t *testing.T) {
	s := newStore()
	const goroutines = 50
	var wg sync.WaitGroup

	// Concurrent SaveEnrichmentCache + GetEnrichmentCache.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			checkID := finding.CheckID(fmt.Sprintf("cache.%d", n))
			_ = s.SaveEnrichmentCache(ctx(), checkID, "exp", "imp", "rem")
			s.GetEnrichmentCache(ctx(), checkID)
		}(i)
	}
	wg.Wait()

	// Verify all entries were saved.
	for i := 0; i < goroutines; i++ {
		checkID := finding.CheckID(fmt.Sprintf("cache.%d", i))
		_, _, _, found := s.GetEnrichmentCache(ctx(), checkID)
		if !found {
			t.Errorf("cache entry %q not found after concurrent writes", checkID)
		}
	}
}

func TestConcurrentReadWrites_Suppressions(t *testing.T) {
	s := newStore()
	const goroutines = 50
	var wg sync.WaitGroup

	// Concurrent UpsertSuppression + ListSuppressions.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			sup := &store.FindingSuppression{
				Domain:  "concurrent.com",
				CheckID: finding.CheckID(fmt.Sprintf("check.%d", n)),
				Asset:   "asset.com",
				Status:  store.SuppressionFalsePositive,
			}
			_ = s.UpsertSuppression(ctx(), sup)
			_, _ = s.ListSuppressions(ctx(), "concurrent.com")
		}(i)
	}
	wg.Wait()

	got, _ := s.ListSuppressions(ctx(), "concurrent.com")
	if len(got) != goroutines {
		t.Errorf("suppression count = %d; want %d", len(got), goroutines)
	}
}

func TestConcurrentReadWrites_MixedOperations(t *testing.T) {
	s := newStore()
	const goroutines = 30
	var wg sync.WaitGroup

	// Exercise multiple store methods simultaneously to stress-test the mutex.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			domain := fmt.Sprintf("mixed-%d.com", n)
			_, _ = s.UpsertTarget(ctx(), domain)
			run := memory.NewScanRun(domain, module.ScanSurface)
			_ = s.CreateScanRun(ctx(), run)
			_ = s.SaveFindings(ctx(), run.ID, []finding.Finding{{CheckID: "m.check"}})
			_ = s.SaveEnrichedFindings(ctx(), run.ID, []enrichment.EnrichedFinding{{Explanation: "e"}})
			_ = s.SaveReport(ctx(), &store.Report{ScanRunID: run.ID, Summary: "s"})
			_ = s.SaveEnrichmentCache(ctx(), finding.CheckID(fmt.Sprintf("m.%d", n)), "a", "b", "c")
			_ = s.SaveCorrelationFindings(ctx(), []store.CorrelationFinding{{Domain: domain, Title: "chain"}})
			_ = s.SavePlaybookSuggestion(ctx(), &store.PlaybookSuggestion{Status: "pending"})
			_ = s.UpsertSuppression(ctx(), &store.FindingSuppression{Domain: domain, CheckID: "x"})
			_, _ = s.ListTargets(ctx())
			_, _ = s.ListScanRuns(ctx(), domain)
			_, _ = s.GetFindings(ctx(), run.ID)
			_, _ = s.GetEnrichedFindings(ctx(), run.ID)
			_, _ = s.ListCorrelationFindings(ctx(), domain)
			_, _ = s.ListSuppressions(ctx(), domain)
		}(i)
	}
	wg.Wait()
	// If we reach here without a race-detector failure, the test passes.
}

// --- Edge Case Tests ---

func TestSaveFindings_NilSlice(t *testing.T) {
	s := newStore()
	run := mustCreateRun(t, s, "example.com", module.ScanSurface)
	// Saving nil should be a no-op, not error.
	if err := s.SaveFindings(ctx(), run.ID, nil); err != nil {
		t.Fatalf("SaveFindings(nil): %v", err)
	}
	got, _ := s.GetFindings(ctx(), run.ID)
	if len(got) != 0 {
		t.Errorf("len = %d; want 0 after saving nil", len(got))
	}
}

func TestSaveFindings_EmptySlice(t *testing.T) {
	s := newStore()
	run := mustCreateRun(t, s, "example.com", module.ScanSurface)
	if err := s.SaveFindings(ctx(), run.ID, []finding.Finding{}); err != nil {
		t.Fatalf("SaveFindings(empty): %v", err)
	}
	got, _ := s.GetFindings(ctx(), run.ID)
	if len(got) != 0 {
		t.Errorf("len = %d; want 0 after saving empty slice", len(got))
	}
}

func TestSaveFindings_CallerMutationDoesNotCorrupt(t *testing.T) {
	s := newStore()
	run := mustCreateRun(t, s, "example.com", module.ScanSurface)

	findings := []finding.Finding{{CheckID: "orig.check", Asset: "example.com"}}
	_ = s.SaveFindings(ctx(), run.ID, findings)

	// Mutate the caller's slice after saving.
	findings[0].CheckID = "mutated.check"

	got, _ := s.GetFindings(ctx(), run.ID)
	if len(got) != 1 {
		t.Fatalf("len = %d; want 1", len(got))
	}
	if got[0].CheckID != "orig.check" {
		t.Errorf("CheckID = %q; want %q (caller mutation leaked into store)", got[0].CheckID, "orig.check")
	}
}

func TestGetFindings_ReturnedSliceMutationDoesNotCorrupt(t *testing.T) {
	s := newStore()
	run := mustCreateRun(t, s, "example.com", module.ScanSurface)

	_ = s.SaveFindings(ctx(), run.ID, []finding.Finding{{CheckID: "a.check", Asset: "a.com"}})

	got, _ := s.GetFindings(ctx(), run.ID)
	got[0].CheckID = "mutated"

	got2, _ := s.GetFindings(ctx(), run.ID)
	if got2[0].CheckID != "a.check" {
		t.Errorf("CheckID = %q; want %q (returned slice mutation leaked)", got2[0].CheckID, "a.check")
	}
}

// --- Additional edge case tests ---

func TestSaveFindingsNilSlice(t *testing.T) {
	s := newStore()
	run := mustCreateRun(t, s, "example.com", module.ScanSurface)

	// Save some initial findings so we can verify nil doesn't wipe them.
	initial := []finding.Finding{{CheckID: "existing.check", Asset: "example.com", Title: "Existing"}}
	if err := s.SaveFindings(ctx(), run.ID, initial); err != nil {
		t.Fatalf("SaveFindings(initial): %v", err)
	}

	// Calling SaveFindings with nil must not panic and must not corrupt state.
	if err := s.SaveFindings(ctx(), run.ID, nil); err != nil {
		t.Fatalf("SaveFindings(nil) returned error: %v", err)
	}

	// Existing findings must be preserved.
	got, err := s.GetFindings(ctx(), run.ID)
	if err != nil {
		t.Fatalf("GetFindings error: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("len = %d; want 1 (nil save should not change state)", len(got))
	}
	if got[0].CheckID != "existing.check" {
		t.Errorf("CheckID = %q; want %q", got[0].CheckID, "existing.check")
	}
}

func TestSaveFindingsEmptySlice(t *testing.T) {
	s := newStore()
	run := mustCreateRun(t, s, "example.com", module.ScanSurface)

	// Save some initial findings so we can verify empty slice doesn't wipe them.
	initial := []finding.Finding{{CheckID: "existing.check", Asset: "example.com", Title: "Existing"}}
	if err := s.SaveFindings(ctx(), run.ID, initial); err != nil {
		t.Fatalf("SaveFindings(initial): %v", err)
	}

	// Calling SaveFindings with empty slice must not panic and must not corrupt state.
	if err := s.SaveFindings(ctx(), run.ID, []finding.Finding{}); err != nil {
		t.Fatalf("SaveFindings(empty) returned error: %v", err)
	}

	// Existing findings must be preserved.
	got, err := s.GetFindings(ctx(), run.ID)
	if err != nil {
		t.Fatalf("GetFindings error: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("len = %d; want 1 (empty save should not change state)", len(got))
	}
	if got[0].CheckID != "existing.check" {
		t.Errorf("CheckID = %q; want %q", got[0].CheckID, "existing.check")
	}
}

func TestConcurrentWriteRead(t *testing.T) {
	s := newStore()
	run := mustCreateRun(t, s, "example.com", module.ScanSurface)
	const writers = 50
	const findingsPerWriter = 10
	const readers = 50
	var wg sync.WaitGroup

	// 50 goroutines each writing 10 unique findings.
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(writerN int) {
			defer wg.Done()
			for f := 0; f < findingsPerWriter; f++ {
				findings := []finding.Finding{{
					CheckID: finding.CheckID(fmt.Sprintf("writer%d.check%d", writerN, f)),
					Asset:   "example.com",
					Title:   fmt.Sprintf("Finding %d from writer %d", f, writerN),
				}}
				_ = s.SaveFindings(ctx(), run.ID, findings)
			}
		}(w)
	}

	// 50 goroutines reading concurrently with the writers.
	for r := 0; r < readers; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Read multiple times to increase overlap with writers.
			for i := 0; i < 5; i++ {
				got, err := s.GetFindings(ctx(), run.ID)
				if err != nil {
					t.Errorf("GetFindings during concurrent read: %v", err)
					return
				}
				// Each read should return a consistent snapshot (length may vary).
				_ = got
			}
		}()
	}

	wg.Wait()

	// After all writes complete, verify total count.
	got, err := s.GetFindings(ctx(), run.ID)
	if err != nil {
		t.Fatalf("GetFindings after concurrent writes: %v", err)
	}
	want := writers * findingsPerWriter
	if len(got) != want {
		t.Errorf("finding count = %d; want %d (50 writers * 10 findings each)", len(got), want)
	}
}

func TestDedupCaseSensitivity(t *testing.T) {
	s := newStore()
	run := mustCreateRun(t, s, "example.com", module.ScanSurface)

	lower := finding.Finding{
		CheckID: "cors.wildcard",
		Asset:   "api.example.com",
		Title:   "Wildcard CORS",
	}
	upper := finding.Finding{
		CheckID: "CORS.WILDCARD",
		Asset:   "api.example.com",
		Title:   "Wildcard CORS",
	}

	_ = s.SaveFindings(ctx(), run.ID, []finding.Finding{lower, upper})

	got, err := s.GetFindings(ctx(), run.ID)
	if err != nil {
		t.Fatalf("GetFindings: %v", err)
	}
	// The dedup key includes CheckID, so different cases must be treated as distinct findings.
	if len(got) != 2 {
		t.Errorf("expected 2 findings (case-sensitive dedup), got %d", len(got))
	}

	// Verify both CheckIDs are present.
	foundLower, foundUpper := false, false
	for _, f := range got {
		if f.CheckID == "cors.wildcard" {
			foundLower = true
		}
		if f.CheckID == "CORS.WILDCARD" {
			foundUpper = true
		}
	}
	if !foundLower {
		t.Error("missing finding with CheckID 'cors.wildcard'")
	}
	if !foundUpper {
		t.Error("missing finding with CheckID 'CORS.WILDCARD'")
	}
}

func TestSaveEnrichedFindings_CallerMutationDoesNotCorrupt(t *testing.T) {
	s := newStore()
	run := mustCreateRun(t, s, "example.com", module.ScanSurface)

	ef := []enrichment.EnrichedFinding{{Explanation: "original"}}
	_ = s.SaveEnrichedFindings(ctx(), run.ID, ef)

	ef[0].Explanation = "mutated"

	got, _ := s.GetEnrichedFindings(ctx(), run.ID)
	if got[0].Explanation != "original" {
		t.Errorf("Explanation = %q; want %q (caller mutation leaked)", got[0].Explanation, "original")
	}
}

func TestGetEnrichedFindings_ReturnedSliceMutationDoesNotCorrupt(t *testing.T) {
	s := newStore()
	run := mustCreateRun(t, s, "example.com", module.ScanSurface)

	_ = s.SaveEnrichedFindings(ctx(), run.ID, []enrichment.EnrichedFinding{{Explanation: "original"}})

	got, _ := s.GetEnrichedFindings(ctx(), run.ID)
	got[0].Explanation = "mutated"

	got2, _ := s.GetEnrichedFindings(ctx(), run.ID)
	if got2[0].Explanation != "original" {
		t.Errorf("Explanation = %q; want %q (returned slice mutation leaked)", got2[0].Explanation, "original")
	}
}

func TestDeleteScanRun_CleansReportsAndCorrelations(t *testing.T) {
	s := newStore()
	run := mustCreateRun(t, s, "example.com", module.ScanSurface)

	_ = s.SaveReport(ctx(), &store.Report{ScanRunID: run.ID, Summary: "test"})
	_ = s.SaveCorrelationFindings(ctx(), []store.CorrelationFinding{
		{ScanRunID: run.ID, Domain: "example.com", Title: "chain"},
	})
	_ = s.SaveAssetGraph(ctx(), run.ID, []byte(`{"nodes":[]}`))

	if err := s.DeleteScanRun(ctx(), run.ID); err != nil {
		t.Fatalf("DeleteScanRun: %v", err)
	}

	// Report should be gone.
	if _, err := s.GetReport(ctx(), run.ID); err == nil {
		t.Error("report still exists after DeleteScanRun")
	}

	// Correlation findings should be gone.
	corrs, _ := s.ListCorrelationFindings(ctx(), "example.com")
	if len(corrs) != 0 {
		t.Errorf("correlation findings len = %d; want 0 after delete", len(corrs))
	}

	// Asset graph should be gone.
	graph, _ := s.GetAssetGraph(ctx(), run.ID)
	if graph != nil {
		t.Error("asset graph still exists after DeleteScanRun")
	}
}

func TestPurgeOrphanedRuns_CleansReportsAndCorrelations(t *testing.T) {
	s := newStore()
	threshold := time.Now().Add(-1 * time.Hour)

	_ = s.CreateScanRun(ctx(), &store.ScanRun{
		ID: "purge-me", Domain: "a.com", Status: store.StatusFailed,
		StartedAt: time.Now().Add(-2 * time.Hour),
	})
	_ = s.SaveReport(ctx(), &store.Report{ScanRunID: "purge-me", Summary: "test"})
	_ = s.SaveCorrelationFindings(ctx(), []store.CorrelationFinding{
		{ScanRunID: "purge-me", Domain: "a.com", Title: "chain"},
	})

	deleted, err := s.PurgeOrphanedRuns(ctx(), threshold)
	if err != nil {
		t.Fatalf("PurgeOrphanedRuns: %v", err)
	}
	if deleted != 1 {
		t.Errorf("deleted = %d; want 1", deleted)
	}

	if _, err := s.GetReport(ctx(), "purge-me"); err == nil {
		t.Error("report still exists after purge")
	}

	corrs, _ := s.ListCorrelationFindings(ctx(), "a.com")
	if len(corrs) != 0 {
		t.Errorf("correlations len = %d; want 0 after purge", len(corrs))
	}
}

func TestPurgeOrphanedRuns_OrphanedRunningRuns(t *testing.T) {
	s := newStore()
	threshold := time.Now().Add(-1 * time.Hour)
	// orphanThreshold = threshold - 2h = -3h from now

	// Running run from 4 hours ago — orphaned.
	_ = s.CreateScanRun(ctx(), &store.ScanRun{
		ID: "orphan-run", Domain: "a.com", Status: store.StatusRunning,
		StartedAt: time.Now().Add(-4 * time.Hour),
	})

	// Running run from 2 hours ago — not yet orphaned.
	_ = s.CreateScanRun(ctx(), &store.ScanRun{
		ID: "active-run", Domain: "a.com", Status: store.StatusRunning,
		StartedAt: time.Now().Add(-2 * time.Hour),
	})

	deleted, err := s.PurgeOrphanedRuns(ctx(), threshold)
	if err != nil {
		t.Fatalf("PurgeOrphanedRuns: %v", err)
	}
	if deleted != 1 {
		t.Errorf("deleted = %d; want 1 (only the 4h-old orphan)", deleted)
	}

	if _, err := s.GetScanRun(ctx(), "orphan-run"); err == nil {
		t.Error("orphan-run still exists after purge")
	}
	if _, err := s.GetScanRun(ctx(), "active-run"); err != nil {
		t.Error("active-run was purged unexpectedly")
	}
}

func TestGetPreviousEnrichedFindings_SkipsCompletedRunsWithNilCompletedAt(t *testing.T) {
	s := newStore()

	// Completed run without CompletedAt (malformed) — should be skipped.
	_ = s.CreateScanRun(ctx(), &store.ScanRun{
		ID: "no-completed-at", Domain: "example.com", Status: store.StatusCompleted,
		StartedAt: time.Now().Add(-1 * time.Hour),
		// CompletedAt intentionally nil
	})
	_ = s.SaveEnrichedFindings(ctx(), "no-completed-at", []enrichment.EnrichedFinding{{Explanation: "malformed"}})

	current := mustCreateRun(t, s, "example.com", module.ScanSurface)

	got, err := s.GetPreviousEnrichedFindings(ctx(), "example.com", current.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("got %v; want nil (completed run without CompletedAt should be skipped)", got)
	}
}

func TestSaveFindings_EmptyScanRunID(t *testing.T) {
	s := newStore()
	// Saving with empty scan run ID should still work (store doesn't validate).
	err := s.SaveFindings(ctx(), "", []finding.Finding{{CheckID: "test.check"}})
	if err != nil {
		t.Fatalf("SaveFindings with empty scanRunID: %v", err)
	}
	got, _ := s.GetFindings(ctx(), "")
	if len(got) != 1 {
		t.Errorf("len = %d; want 1", len(got))
	}
}

// TestGetPreviousEnrichedFindings_AllRunsNilCompletedAt verifies that when every
// completed scan run has a nil CompletedAt, the function returns nil, nil without
// panicking (e.g., from a nil pointer dereference on prevRun.CompletedAt).
func TestGetPreviousEnrichedFindings_AllRunsNilCompletedAt(t *testing.T) {
	s := newStore()

	// Create two completed runs, both with nil CompletedAt (malformed).
	_ = s.CreateScanRun(ctx(), &store.ScanRun{
		ID:        "run-nil-1",
		Domain:    "example.com",
		Status:    store.StatusCompleted,
		StartedAt: time.Now().Add(-2 * time.Hour),
		// CompletedAt intentionally nil
	})
	_ = s.SaveEnrichedFindings(ctx(), "run-nil-1", []enrichment.EnrichedFinding{{Explanation: "first"}})

	_ = s.CreateScanRun(ctx(), &store.ScanRun{
		ID:        "run-nil-2",
		Domain:    "example.com",
		Status:    store.StatusCompleted,
		StartedAt: time.Now().Add(-1 * time.Hour),
		// CompletedAt intentionally nil
	})
	_ = s.SaveEnrichedFindings(ctx(), "run-nil-2", []enrichment.EnrichedFinding{{Explanation: "second"}})

	current := mustCreateRun(t, s, "example.com", module.ScanSurface)

	got, err := s.GetPreviousEnrichedFindings(ctx(), "example.com", current.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("got %v; want nil (all completed runs have nil CompletedAt)", got)
	}
}

func TestSaveCorrelationFindings_EmptySlice(t *testing.T) {
	s := newStore()
	// Empty slice should be a no-op.
	if err := s.SaveCorrelationFindings(ctx(), nil); err != nil {
		t.Fatalf("SaveCorrelationFindings(nil): %v", err)
	}
	if err := s.SaveCorrelationFindings(ctx(), []store.CorrelationFinding{}); err != nil {
		t.Fatalf("SaveCorrelationFindings(empty): %v", err)
	}
}

func TestAssetGraph_Roundtrip(t *testing.T) {
	s := newStore()
	run := mustCreateRun(t, s, "example.com", module.ScanSurface)

	data := []byte(`{"nodes":[{"id":"a.com"}],"edges":[]}`)
	if err := s.SaveAssetGraph(ctx(), run.ID, data); err != nil {
		t.Fatalf("SaveAssetGraph: %v", err)
	}

	got, err := s.GetAssetGraph(ctx(), run.ID)
	if err != nil {
		t.Fatalf("GetAssetGraph: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("graph = %q; want %q", string(got), string(data))
	}
}

func TestAssetGraph_CallerMutationDoesNotCorrupt(t *testing.T) {
	s := newStore()
	run := mustCreateRun(t, s, "example.com", module.ScanSurface)

	data := []byte(`{"nodes":[]}`)
	_ = s.SaveAssetGraph(ctx(), run.ID, data)

	// Mutate the original slice.
	data[0] = 'X'

	got, _ := s.GetAssetGraph(ctx(), run.ID)
	if got[0] == 'X' {
		t.Error("caller mutation of input corrupted stored data")
	}

	// Mutate the returned slice.
	got[0] = 'Y'

	got2, _ := s.GetAssetGraph(ctx(), run.ID)
	if got2[0] == 'Y' {
		t.Error("mutation of returned slice corrupted stored data")
	}
}

func TestAssetGraph_NotFound(t *testing.T) {
	s := newStore()
	got, err := s.GetAssetGraph(ctx(), "nonexistent")
	if err != nil {
		t.Fatalf("GetAssetGraph: %v", err)
	}
	if got != nil {
		t.Errorf("got %v; want nil for missing graph", got)
	}
}

func TestDeleteScanRun_DoesNotAffectOtherRuns(t *testing.T) {
	s := newStore()
	run1 := mustCreateRun(t, s, "a.com", module.ScanSurface)
	run2 := mustCreateRun(t, s, "b.com", module.ScanSurface)

	_ = s.SaveFindings(ctx(), run1.ID, []finding.Finding{{CheckID: "f1", Asset: "a.com"}})
	_ = s.SaveFindings(ctx(), run2.ID, []finding.Finding{{CheckID: "f2", Asset: "b.com"}})
	_ = s.SaveEnrichedFindings(ctx(), run1.ID, []enrichment.EnrichedFinding{{Explanation: "e1"}})
	_ = s.SaveEnrichedFindings(ctx(), run2.ID, []enrichment.EnrichedFinding{{Explanation: "e2"}})
	_ = s.SaveReport(ctx(), &store.Report{ScanRunID: run1.ID, Summary: "r1"})
	_ = s.SaveReport(ctx(), &store.Report{ScanRunID: run2.ID, Summary: "r2"})
	_ = s.SaveCorrelationFindings(ctx(), []store.CorrelationFinding{
		{ScanRunID: run1.ID, Domain: "a.com", Title: "c1"},
		{ScanRunID: run2.ID, Domain: "b.com", Title: "c2"},
	})

	_ = s.DeleteScanRun(ctx(), run1.ID)

	// run2 should be unaffected.
	if _, err := s.GetScanRun(ctx(), run2.ID); err != nil {
		t.Errorf("run2 was affected by deleting run1: %v", err)
	}
	f2, _ := s.GetFindings(ctx(), run2.ID)
	if len(f2) != 1 {
		t.Errorf("run2 findings len = %d; want 1", len(f2))
	}
	e2, _ := s.GetEnrichedFindings(ctx(), run2.ID)
	if len(e2) != 1 {
		t.Errorf("run2 enriched len = %d; want 1", len(e2))
	}
	r2, err := s.GetReport(ctx(), run2.ID)
	if err != nil {
		t.Errorf("run2 report error: %v", err)
	}
	if r2.Summary != "r2" {
		t.Errorf("run2 report summary = %q; want %q", r2.Summary, "r2")
	}
	c2, _ := s.ListCorrelationFindings(ctx(), "b.com")
	if len(c2) != 1 {
		t.Errorf("run2 correlations len = %d; want 1", len(c2))
	}
}

func TestConcurrentDeleteAndRead(t *testing.T) {
	s := newStore()
	const goroutines = 20
	var wg sync.WaitGroup

	// Create runs and populate data.
	for i := 0; i < goroutines; i++ {
		run := &store.ScanRun{
			ID:      fmt.Sprintf("run-%d", i),
			Domain:  "concurrent.com",
			Status:  store.StatusFailed,
			StartedAt: time.Now(),
		}
		_ = s.CreateScanRun(ctx(), run)
		_ = s.SaveFindings(ctx(), run.ID, []finding.Finding{{CheckID: finding.CheckID(fmt.Sprintf("c.%d", i))}})
	}

	// Concurrently delete and read.
	for i := 0; i < goroutines; i++ {
		wg.Add(2)
		go func(n int) {
			defer wg.Done()
			_ = s.DeleteScanRun(ctx(), fmt.Sprintf("run-%d", n))
		}(i)
		go func(n int) {
			defer wg.Done()
			_, _ = s.GetFindings(ctx(), fmt.Sprintf("run-%d", n))
			_, _ = s.ListScanRuns(ctx(), "concurrent.com")
		}(i)
	}
	wg.Wait()
	// If we reach here without a race-detector failure, the test passes.
}

// --- ListAllScanRuns tests ---

func TestListAllScanRuns_EmptyStore(t *testing.T) {
	s := newStore()
	runs, err := s.ListAllScanRuns(ctx(), 10)
	if err != nil {
		t.Fatalf("ListAllScanRuns: %v", err)
	}
	if len(runs) != 0 {
		t.Errorf("len = %d; want 0", len(runs))
	}
}

func TestListAllScanRuns_ReturnsAllDomains(t *testing.T) {
	s := newStore()
	mustUpsertTarget(t, s, "a.com")
	mustUpsertTarget(t, s, "b.com")
	mustCreateRun(t, s, "a.com", module.ScanSurface)
	mustCreateRun(t, s, "b.com", module.ScanSurface)
	mustCreateRun(t, s, "a.com", module.ScanDeep)

	runs, err := s.ListAllScanRuns(ctx(), 50)
	if err != nil {
		t.Fatalf("ListAllScanRuns: %v", err)
	}
	if len(runs) != 3 {
		t.Errorf("len = %d; want 3", len(runs))
	}
}

func TestListAllScanRuns_SortedByStartedAtDesc(t *testing.T) {
	s := newStore()
	mustUpsertTarget(t, s, "x.com")

	now := time.Now()
	for i := 0; i < 5; i++ {
		run := &store.ScanRun{
			ID:        fmt.Sprintf("run-%d", i),
			Domain:    "x.com",
			ScanType:  module.ScanSurface,
			Status:    store.StatusCompleted,
			StartedAt: now.Add(time.Duration(i) * time.Minute),
		}
		_ = s.CreateScanRun(ctx(), run)
	}

	runs, err := s.ListAllScanRuns(ctx(), 50)
	if err != nil {
		t.Fatalf("ListAllScanRuns: %v", err)
	}
	for i := 1; i < len(runs); i++ {
		if runs[i].StartedAt.After(runs[i-1].StartedAt) {
			t.Errorf("runs[%d].StartedAt (%v) > runs[%d].StartedAt (%v); want descending",
				i, runs[i].StartedAt, i-1, runs[i-1].StartedAt)
		}
	}
}

func TestListAllScanRuns_RespectsLimit(t *testing.T) {
	s := newStore()
	mustUpsertTarget(t, s, "x.com")
	for i := 0; i < 10; i++ {
		mustCreateRun(t, s, "x.com", module.ScanSurface)
	}

	runs, err := s.ListAllScanRuns(ctx(), 3)
	if err != nil {
		t.Fatalf("ListAllScanRuns: %v", err)
	}
	if len(runs) != 3 {
		t.Errorf("len = %d; want 3", len(runs))
	}
}

func TestListAllScanRuns_LimitZeroDefaultsTo50(t *testing.T) {
	s := newStore()
	mustUpsertTarget(t, s, "x.com")
	for i := 0; i < 60; i++ {
		run := &store.ScanRun{
			ID:        fmt.Sprintf("run-zero-%d", i),
			Domain:    "x.com",
			ScanType:  module.ScanSurface,
			Status:    store.StatusCompleted,
			StartedAt: time.Now().Add(time.Duration(i) * time.Second),
		}
		_ = s.CreateScanRun(ctx(), run)
	}

	runs, err := s.ListAllScanRuns(ctx(), 0)
	if err != nil {
		t.Fatalf("ListAllScanRuns: %v", err)
	}
	if len(runs) != 50 {
		t.Errorf("len = %d; want 50 (default limit)", len(runs))
	}
}

func TestListAllScanRuns_NegativeLimitDefaultsTo50(t *testing.T) {
	s := newStore()
	mustUpsertTarget(t, s, "x.com")
	for i := 0; i < 55; i++ {
		run := &store.ScanRun{
			ID:        fmt.Sprintf("neg-%d", i),
			Domain:    "x.com",
			ScanType:  module.ScanSurface,
			Status:    store.StatusCompleted,
			StartedAt: time.Now().Add(time.Duration(i) * time.Second),
		}
		_ = s.CreateScanRun(ctx(), run)
	}

	runs, err := s.ListAllScanRuns(ctx(), -1)
	if err != nil {
		t.Fatalf("ListAllScanRuns: %v", err)
	}
	if len(runs) != 50 {
		t.Errorf("len = %d; want 50 (default limit for negative)", len(runs))
	}
}

func TestListAllScanRuns_LimitExceedsCount(t *testing.T) {
	s := newStore()
	mustUpsertTarget(t, s, "x.com")
	mustCreateRun(t, s, "x.com", module.ScanSurface)
	mustCreateRun(t, s, "x.com", module.ScanDeep)

	runs, err := s.ListAllScanRuns(ctx(), 100)
	if err != nil {
		t.Fatalf("ListAllScanRuns: %v", err)
	}
	if len(runs) != 2 {
		t.Errorf("len = %d; want 2", len(runs))
	}
}

// --- AssetExecution tests ---

func TestSaveAssetExecution_RoundTrip(t *testing.T) {
	s := newStore()
	mustUpsertTarget(t, s, "example.com")
	run := mustCreateRun(t, s, "example.com", module.ScanSurface)

	exec := &store.AssetExecution{
		ID:          "exec-1",
		ScanRunID:   run.ID,
		Asset:       "sub.example.com",
		ScannersRun: []string{"cors", "tls"},
		FindingsCount: 2,
	}
	if err := s.SaveAssetExecution(ctx(), exec); err != nil {
		t.Fatalf("SaveAssetExecution: %v", err)
	}

	execs, err := s.ListAssetExecutions(ctx(), run.ID)
	if err != nil {
		t.Fatalf("ListAssetExecutions: %v", err)
	}
	if len(execs) != 1 {
		t.Fatalf("len = %d; want 1", len(execs))
	}
	if execs[0].Asset != "sub.example.com" {
		t.Errorf("Asset = %q; want %q", execs[0].Asset, "sub.example.com")
	}
	if len(execs[0].ScannersRun) != 2 {
		t.Errorf("ScannersRun len = %d; want 2", len(execs[0].ScannersRun))
	}
}

func TestListAssetExecutions_EmptyForUnknownRun(t *testing.T) {
	s := newStore()
	execs, err := s.ListAssetExecutions(ctx(), "nonexistent-run")
	if err != nil {
		t.Fatalf("ListAssetExecutions: %v", err)
	}
	if len(execs) != 0 {
		t.Errorf("len = %d; want 0", len(execs))
	}
}

func TestSaveAssetExecution_MultiplePerRun(t *testing.T) {
	s := newStore()
	mustUpsertTarget(t, s, "example.com")
	run := mustCreateRun(t, s, "example.com", module.ScanSurface)

	for i := 0; i < 5; i++ {
		exec := &store.AssetExecution{
			ID:        fmt.Sprintf("exec-%d", i),
			ScanRunID: run.ID,
			Asset:     fmt.Sprintf("sub%d.example.com", i),
		}
		_ = s.SaveAssetExecution(ctx(), exec)
	}

	execs, err := s.ListAssetExecutions(ctx(), run.ID)
	if err != nil {
		t.Fatalf("ListAssetExecutions: %v", err)
	}
	if len(execs) != 5 {
		t.Errorf("len = %d; want 5", len(execs))
	}
}

func TestSaveAssetExecution_IsolatedBetweenRuns(t *testing.T) {
	s := newStore()
	mustUpsertTarget(t, s, "a.com")
	mustUpsertTarget(t, s, "b.com")
	runA := mustCreateRun(t, s, "a.com", module.ScanSurface)
	runB := mustCreateRun(t, s, "b.com", module.ScanSurface)

	_ = s.SaveAssetExecution(ctx(), &store.AssetExecution{ID: "e1", ScanRunID: runA.ID, Asset: "x"})
	_ = s.SaveAssetExecution(ctx(), &store.AssetExecution{ID: "e2", ScanRunID: runB.ID, Asset: "y"})
	_ = s.SaveAssetExecution(ctx(), &store.AssetExecution{ID: "e3", ScanRunID: runB.ID, Asset: "z"})

	execsA, _ := s.ListAssetExecutions(ctx(), runA.ID)
	execsB, _ := s.ListAssetExecutions(ctx(), runB.ID)

	if len(execsA) != 1 {
		t.Errorf("runA execs: len = %d; want 1", len(execsA))
	}
	if len(execsB) != 2 {
		t.Errorf("runB execs: len = %d; want 2", len(execsB))
	}
}

func TestSaveAssetExecution_MutationIsolation(t *testing.T) {
	s := newStore()
	mustUpsertTarget(t, s, "example.com")
	run := mustCreateRun(t, s, "example.com", module.ScanSurface)

	exec := &store.AssetExecution{
		ID:        "exec-1",
		ScanRunID: run.ID,
		Asset:     "original",
	}
	_ = s.SaveAssetExecution(ctx(), exec)

	// Mutate the original after saving — should not affect stored copy.
	exec.Asset = "mutated"

	execs, _ := s.ListAssetExecutions(ctx(), run.ID)
	if execs[0].Asset != "original" {
		t.Errorf("Asset = %q; want %q (store should be independent of caller)", execs[0].Asset, "original")
	}
}

// --- AssetGraph tests ---

func TestSaveAssetGraph_RoundTrip(t *testing.T) {
	s := newStore()
	data := []byte(`{"domain":"example.com","assets":[]}`)
	if err := s.SaveAssetGraph(ctx(), "run-1", data); err != nil {
		t.Fatalf("SaveAssetGraph: %v", err)
	}
	got, err := s.GetAssetGraph(ctx(), "run-1")
	if err != nil {
		t.Fatalf("GetAssetGraph: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("got %q; want %q", got, data)
	}
}

func TestGetAssetGraph_ReturnsNilForMissing(t *testing.T) {
	s := newStore()
	got, err := s.GetAssetGraph(ctx(), "nonexistent")
	if err != nil {
		t.Fatalf("GetAssetGraph: %v", err)
	}
	if got != nil {
		t.Errorf("got %q; want nil", got)
	}
}

func TestSaveAssetGraph_MutationIsolation(t *testing.T) {
	s := newStore()
	data := []byte(`{"original":true}`)
	_ = s.SaveAssetGraph(ctx(), "run-1", data)

	// Mutate the input slice after saving.
	data[0] = '!'

	got, _ := s.GetAssetGraph(ctx(), "run-1")
	if got[0] == '!' {
		t.Error("mutation leaked into stored data")
	}
}

func TestDeleteScanRun_CleansUpAssetExecutionsAndGraphs(t *testing.T) {
	s := newStore()
	mustUpsertTarget(t, s, "example.com")
	run := mustCreateRun(t, s, "example.com", module.ScanSurface)

	_ = s.SaveAssetExecution(ctx(), &store.AssetExecution{ID: "e1", ScanRunID: run.ID, Asset: "x"})
	_ = s.SaveAssetGraph(ctx(), run.ID, []byte(`{}`))

	if err := s.DeleteScanRun(ctx(), run.ID); err != nil {
		t.Fatalf("DeleteScanRun: %v", err)
	}

	execs, _ := s.ListAssetExecutions(ctx(), run.ID)
	if len(execs) != 0 {
		t.Errorf("asset executions not cleaned up: len = %d", len(execs))
	}

	graph, _ := s.GetAssetGraph(ctx(), run.ID)
	if graph != nil {
		t.Error("asset graph not cleaned up")
	}
}

// --- Concurrent access for new methods ---

func TestListAllScanRuns_ConcurrentAccess(t *testing.T) {
	s := newStore()
	mustUpsertTarget(t, s, "concurrent.com")
	for i := 0; i < 20; i++ {
		mustCreateRun(t, s, "concurrent.com", module.ScanSurface)
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = s.ListAllScanRuns(ctx(), 10)
		}()
	}
	wg.Wait()
}

func TestAssetExecution_ConcurrentReadWrite(t *testing.T) {
	s := newStore()
	mustUpsertTarget(t, s, "concurrent.com")
	run := mustCreateRun(t, s, "concurrent.com", module.ScanSurface)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func(n int) {
			defer wg.Done()
			_ = s.SaveAssetExecution(ctx(), &store.AssetExecution{
				ID:        fmt.Sprintf("exec-%d", n),
				ScanRunID: run.ID,
				Asset:     fmt.Sprintf("asset-%d", n),
			})
		}(i)
		go func(n int) {
			defer wg.Done()
			_, _ = s.ListAssetExecutions(ctx(), run.ID)
		}(i)
	}
	wg.Wait()
}
