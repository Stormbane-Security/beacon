package playbook_test

// Tests for BuildRunPlan — derived from the spec:
//   - Scanners must be deduplicated across matched playbooks
//   - NucleiTagsSurf must be deduplicated
//   - NucleiTagsDeep must be deduplicated
//   - DiscoverySteps are additive (not deduplicated)
//   - MatchedPlaybooks lists all matched playbook names in order

import (
	"slices"
	"testing"

	"github.com/stormbane/beacon/internal/playbook"
)

func makePlaybook(name string, surfScanners, surfTags, deepTags []string, discovery ...playbook.DiscoveryStep) *playbook.Playbook {
	return &playbook.Playbook{
		Name: name,
		Surface: playbook.RunConfig{
			Scanners:   surfScanners,
			NucleiTags: surfTags,
		},
		Deep: playbook.RunConfig{
			NucleiTags: deepTags,
		},
		Discovery: discovery,
	}
}

func TestRunPlanScannersAreDeduplicatedAcrossPlaybooks(t *testing.T) {
	// Both baseline and cloudflare request "webcontent" and "email".
	// The plan must contain each scanner exactly once.
	baseline := makePlaybook("baseline", []string{"email", "webcontent", "tls"}, nil, nil)
	cloudflare := makePlaybook("cloudflare", []string{"webcontent", "historicalurls"}, nil, nil)

	plan := playbook.BuildRunPlan([]*playbook.Playbook{baseline, cloudflare})

	counts := make(map[string]int)
	for _, s := range plan.Scanners {
		counts[s]++
	}
	for scanner, n := range counts {
		if n > 1 {
			t.Errorf("scanner %q appears %d times in RunPlan.Scanners — must appear exactly once", scanner, n)
		}
	}

	// All unique scanners must be present.
	want := []string{"email", "webcontent", "tls", "historicalurls"}
	for _, s := range want {
		if !slices.Contains(plan.Scanners, s) {
			t.Errorf("scanner %q expected in RunPlan.Scanners but not found; got %v", s, plan.Scanners)
		}
	}
}

func TestRunPlanNucleiSurfTagsAreDeduplicatedAcrossPlaybooks(t *testing.T) {
	a := makePlaybook("a", nil, []string{"ssl", "dns", "exposure"}, nil)
	b := makePlaybook("b", nil, []string{"dns", "cloudflare", "exposure"}, nil)

	plan := playbook.BuildRunPlan([]*playbook.Playbook{a, b})

	counts := make(map[string]int)
	for _, tag := range plan.NucleiTagsSurf {
		counts[tag]++
	}
	for tag, n := range counts {
		if n > 1 {
			t.Errorf("nuclei surface tag %q appears %d times — must appear exactly once", tag, n)
		}
	}

	want := []string{"ssl", "dns", "exposure", "cloudflare"}
	for _, tag := range want {
		if !slices.Contains(plan.NucleiTagsSurf, tag) {
			t.Errorf("surface tag %q expected but not found; got %v", tag, plan.NucleiTagsSurf)
		}
	}
}

func TestRunPlanNucleiDeepTagsAreDeduplicatedAcrossPlaybooks(t *testing.T) {
	a := makePlaybook("a", nil, nil, []string{"cves", "ssrf"})
	b := makePlaybook("b", nil, nil, []string{"cves", "aws"})

	plan := playbook.BuildRunPlan([]*playbook.Playbook{a, b})

	counts := make(map[string]int)
	for _, tag := range plan.NucleiTagsDeep {
		counts[tag]++
	}
	for tag, n := range counts {
		if n > 1 {
			t.Errorf("nuclei deep tag %q appears %d times — must appear exactly once", tag, n)
		}
	}
}

func TestRunPlanMatchedPlaybooksListsAllNamesInOrder(t *testing.T) {
	a := makePlaybook("baseline", nil, nil, nil)
	b := makePlaybook("cloudflare", nil, nil, nil)
	c := makePlaybook("aws_ec2", nil, nil, nil)

	plan := playbook.BuildRunPlan([]*playbook.Playbook{a, b, c})

	want := []string{"baseline", "cloudflare", "aws_ec2"}
	if !slices.Equal(plan.MatchedPlaybooks, want) {
		t.Errorf("MatchedPlaybooks = %v; want %v", plan.MatchedPlaybooks, want)
	}
}

func TestRunPlanDiscoveryStepsAreAdditive(t *testing.T) {
	stepA := playbook.DiscoveryStep{Type: "probe_subdomains", Patterns: []string{"origin.{domain}"}}
	stepB := playbook.DiscoveryStep{Type: "historical_dns"}

	a := makePlaybook("a", nil, nil, nil, stepA)
	b := makePlaybook("b", nil, nil, nil, stepB)

	plan := playbook.BuildRunPlan([]*playbook.Playbook{a, b})

	if len(plan.DiscoverySteps) != 2 {
		t.Errorf("DiscoverySteps length = %d; want 2 (steps are additive, not deduplicated)", len(plan.DiscoverySteps))
	}
}

func TestRunPlanEmptyInputProducesEmptyPlan(t *testing.T) {
	plan := playbook.BuildRunPlan(nil)

	if len(plan.Scanners) != 0 {
		t.Errorf("empty input: Scanners = %v; want empty", plan.Scanners)
	}
	if len(plan.NucleiTagsSurf) != 0 {
		t.Errorf("empty input: NucleiTagsSurf = %v; want empty", plan.NucleiTagsSurf)
	}
	if len(plan.MatchedPlaybooks) != 0 {
		t.Errorf("empty input: MatchedPlaybooks = %v; want empty", plan.MatchedPlaybooks)
	}
}
