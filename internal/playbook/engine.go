package playbook

import "strings"

// RunPlan is the union of all checks from matched playbooks for a single asset.
// The surface module executes this plan rather than calling scanners directly.
type RunPlan struct {
	Scanners         []string // deduplicated scanner names (e.g. "email", "tls")
	NucleiTagsSurf   []string // deduplicated Nuclei tags for surface scan
	NucleiTagsDeep   []string // deduplicated Nuclei tags for deep scan
	DirbustPaths     []string // deduplicated URL paths to probe in deep mode
	DiscoverySteps   []DiscoveryStep
	MatchedPlaybooks []string // names of playbooks that matched (for reporting)
}

// BuildRunPlan unions the surface/deep configs from all matched playbooks
// into a single deduplicated RunPlan.
func BuildRunPlan(matched []*Playbook) RunPlan {
	var plan RunPlan

	seenScanners   := map[string]bool{}
	seenTagsSurf   := map[string]bool{}
	seenTagsDeep   := map[string]bool{}
	seenDirbust    := map[string]bool{}
	seenDiscovery  := map[string]bool{}

	for _, p := range matched {
		plan.MatchedPlaybooks = append(plan.MatchedPlaybooks, p.Name)

		for _, s := range p.Surface.Scanners {
			if !seenScanners[s] {
				seenScanners[s] = true
				plan.Scanners = append(plan.Scanners, s)
			}
		}
		for _, t := range p.Surface.NucleiTags {
			if !seenTagsSurf[t] {
				seenTagsSurf[t] = true
				plan.NucleiTagsSurf = append(plan.NucleiTagsSurf, t)
			}
		}
		for _, t := range p.Deep.NucleiTags {
			if !seenTagsDeep[t] {
				seenTagsDeep[t] = true
				plan.NucleiTagsDeep = append(plan.NucleiTagsDeep, t)
			}
		}
		// Deep scanners also get added to the unified scanner list
		for _, s := range p.Deep.Scanners {
			if !seenScanners[s] {
				seenScanners[s] = true
				plan.Scanners = append(plan.Scanners, s)
			}
		}
		// Union dirbust paths across all matched playbooks (deep only)
		for _, path := range p.Deep.DirbustPaths {
			if !seenDirbust[path] {
				seenDirbust[path] = true
				plan.DirbustPaths = append(plan.DirbustPaths, path)
			}
		}
		for _, step := range p.Discovery {
			key := step.Type + "|" + strings.Join(step.Patterns, "|")
			if !seenDiscovery[key] {
				seenDiscovery[key] = true
				plan.DiscoverySteps = append(plan.DiscoverySteps, step)
			}
		}
	}

	return plan
}
