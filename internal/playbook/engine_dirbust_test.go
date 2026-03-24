package playbook_test

// Tests for DirbustPaths behaviour in BuildRunPlan.
// DirbustPaths lives in the Deep RunConfig.

import (
	"slices"
	"testing"

	"github.com/stormbane/beacon/internal/playbook"
)

// makePlaybookWithDirbust creates a Playbook whose Deep.DirbustPaths is set.
// surfScanners and dirbustPaths are the commonly varied fields; others are empty.
func makePlaybookWithDirbust(name string, dirbustPaths []string) *playbook.Playbook {
	return &playbook.Playbook{
		Name: name,
		Deep: playbook.RunConfig{
			DirbustPaths: dirbustPaths,
		},
	}
}

func TestDirbustPaths_DeduplicatedAcrossPlaybooks(t *testing.T) {
	// Both playbooks include "/admin" and "/api/v1/" — each must appear once.
	a := makePlaybookWithDirbust("a", []string{"/admin", "/api/v1/"})
	b := makePlaybookWithDirbust("b", []string{"/admin", "/api/v1/"})

	plan := playbook.BuildRunPlan([]*playbook.Playbook{a, b})

	counts := make(map[string]int)
	for _, p := range plan.DirbustPaths {
		counts[p]++
	}
	for path, n := range counts {
		if n > 1 {
			t.Errorf("dirbust path %q appears %d times in RunPlan.DirbustPaths — must appear exactly once", path, n)
		}
	}

	// Both paths must be present.
	for _, want := range []string{"/admin", "/api/v1/"} {
		if !slices.Contains(plan.DirbustPaths, want) {
			t.Errorf("path %q expected in DirbustPaths but not found; got %v", want, plan.DirbustPaths)
		}
	}
}

func TestDirbustPaths_UnionAcrossPlaybooks(t *testing.T) {
	// Playbook A: ["/admin", "/api/v1/"]
	// Playbook B: ["/metrics", "/admin"]
	// Expected result: ["/admin", "/api/v1/", "/metrics"]  (first-seen order, deduplicated)
	a := makePlaybookWithDirbust("a", []string{"/admin", "/api/v1/"})
	b := makePlaybookWithDirbust("b", []string{"/metrics", "/admin"})

	plan := playbook.BuildRunPlan([]*playbook.Playbook{a, b})

	want := []string{"/admin", "/api/v1/", "/metrics"}

	if len(plan.DirbustPaths) != len(want) {
		t.Fatalf("DirbustPaths length = %d; want %d (paths: %v)", len(plan.DirbustPaths), len(want), plan.DirbustPaths)
	}

	// Check all expected paths are present (exact order is first-seen).
	for _, path := range want {
		if !slices.Contains(plan.DirbustPaths, path) {
			t.Errorf("path %q expected in DirbustPaths but not found; got %v", path, plan.DirbustPaths)
		}
	}

	// Verify first-seen order: /admin must precede /api/v1/, /api/v1/ must precede /metrics.
	idxAdmin := slices.Index(plan.DirbustPaths, "/admin")
	idxAPI := slices.Index(plan.DirbustPaths, "/api/v1/")
	idxMetrics := slices.Index(plan.DirbustPaths, "/metrics")

	if idxAdmin >= idxAPI {
		t.Errorf("/admin (index %d) should precede /api/v1/ (index %d)", idxAdmin, idxAPI)
	}
	if idxAPI >= idxMetrics {
		t.Errorf("/api/v1/ (index %d) should precede /metrics (index %d)", idxAPI, idxMetrics)
	}
}

func TestDirbustPaths_EmptyWhenPlaybookHasNone(t *testing.T) {
	// Playbook with no dirbust_paths → plan.DirbustPaths is nil or empty.
	p := makePlaybook("no-dirbust", []string{"email"}, nil, nil)

	plan := playbook.BuildRunPlan([]*playbook.Playbook{p})

	if len(plan.DirbustPaths) != 0 {
		t.Errorf("expected DirbustPaths to be nil/empty, got %v", plan.DirbustPaths)
	}
}

func TestDirbustPaths_SinglePlaybookAllPathsPresent(t *testing.T) {
	paths := []string{"/admin", "/api/v1/", "/metrics", "/debug/pprof/", "/.git/"}
	p := makePlaybookWithDirbust("deep-playbook", paths)

	plan := playbook.BuildRunPlan([]*playbook.Playbook{p})

	if len(plan.DirbustPaths) != len(paths) {
		t.Fatalf("DirbustPaths length = %d; want %d; got %v", len(plan.DirbustPaths), len(paths), plan.DirbustPaths)
	}

	for _, want := range paths {
		if !slices.Contains(plan.DirbustPaths, want) {
			t.Errorf("path %q expected in DirbustPaths but not found; got %v", want, plan.DirbustPaths)
		}
	}
}
