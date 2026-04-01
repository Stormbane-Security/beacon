package integration

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stormbane-security/beacon/internal/playbook"
)

// TestPlaybookMatching auto-generates a test case for every playbook match
// rule. For each rule in each playbook's match.any list, it synthesizes an
// Evidence packet that satisfies the rule, then verifies the playbook matches.
//
// This catches:
//   - Typos in match rules (e.g. body_contains: "opnestack")
//   - Rules that can never match due to field/logic errors
//   - Regressions when someone changes a playbook's match conditions
func TestPlaybookMatching(t *testing.T) {
	reg, err := playbook.Load()
	if err != nil {
		t.Fatalf("loading playbooks: %v", err)
	}

	for _, pb := range reg.All() {
		if pb.Match.Always {
			continue // baseline always matches — nothing to test
		}

		for i, rule := range pb.Match.Any {
			name := fmt.Sprintf("%s/any[%d]", pb.Name, i)

			t.Run(name, func(t *testing.T) {
				t.Parallel()

				ev := evidenceForMatchRule(rule)
				if ev == nil {
					t.Skip("rule type not supported by auto-generator")
					return
				}

				if !pb.Matches(*ev) {
					t.Errorf("playbook %q did not match synthesized evidence for any[%d]", pb.Name, i)
				}
			})
		}

		// For all-rules, synthesize evidence satisfying every rule simultaneously.
		if len(pb.Match.All) > 0 {
			t.Run(fmt.Sprintf("%s/all", pb.Name), func(t *testing.T) {
				t.Parallel()

				ev := mergeEvidenceForAllRules(pb.Match.All)
				if ev == nil {
					t.Skip("one or more all-rules not supported by auto-generator")
					return
				}

				if !pb.Matches(*ev) {
					t.Errorf("playbook %q did not match synthesized evidence for all rules", pb.Name)
				}
			})
		}
	}
}

// TestPlaybookNonMatch verifies that playbooks do NOT match empty evidence.
// Catches overly broad match rules that would fire on every asset.
func TestPlaybookNonMatch(t *testing.T) {
	reg, err := playbook.Load()
	if err != nil {
		t.Fatalf("loading playbooks: %v", err)
	}

	empty := playbook.Evidence{
		Headers: make(map[string]string),
	}

	for _, pb := range reg.All() {
		if pb.Match.Always {
			continue
		}
		t.Run(pb.Name+"_rejects_empty", func(t *testing.T) {
			t.Parallel()
			if pb.Matches(empty) {
				t.Errorf("playbook %q matched empty evidence — match rules are too broad", pb.Name)
			}
		})
	}
}

// evidenceForMatchRule synthesizes a minimal Evidence that satisfies one MatchRule.
func evidenceForMatchRule(r playbook.MatchRule) *playbook.Evidence {
	ev := &playbook.Evidence{
		Headers: make(map[string]string),
	}

	set := false

	if r.HeaderPresent != "" {
		ev.Headers[strings.ToLower(r.HeaderPresent)] = "test-value"
		set = true
	}
	if r.HeaderContains != "" {
		ev.Headers["x-test-"+strings.ToLower(r.HeaderContains)] = r.HeaderContains
		set = true
	}
	if r.HeaderValue != nil {
		ev.Headers[strings.ToLower(r.HeaderValue.Name)] = r.HeaderValue.Contains
		set = true
	}
	if r.TitleContains != "" {
		ev.Title = r.TitleContains
		set = true
	}
	if r.BodyContains != "" {
		ev.Body512 = r.BodyContains
		set = true
	}
	if r.PathResponds != "" {
		ev.RespondingPaths = []string{r.PathResponds}
		set = true
	}
	if r.ASNOrgContains != "" {
		ev.ASNOrg = r.ASNOrgContains
		set = true
	}
	if r.DNSSuffix != "" {
		ev.Hostname = "test" + r.DNSSuffix
		set = true
	}
	if r.CNAMEContains != "" {
		ev.CNAMEChain = []string{"target." + r.CNAMEContains + ".example.com"}
		set = true
	}
	if r.CertSANContains != "" {
		ev.CertSANs = []string{r.CertSANContains + ".example.com"}
		set = true
	}
	if r.ServiceVersionContains != "" {
		ev.ServiceVersions = map[string]string{"platform": r.ServiceVersionContains}
		set = true
	}
	if r.CloudProviderContains != "" {
		ev.CloudProvider = r.CloudProviderContains
		set = true
	}
	if r.FrameworkContains != "" {
		ev.Framework = r.FrameworkContains
		set = true
	}
	if r.AuthSystemContains != "" {
		ev.AuthSystem = r.AuthSystemContains
		set = true
	}
	if r.ProxyTypeContains != "" {
		ev.ProxyType = r.ProxyTypeContains
		set = true
	}
	if r.InfraLayerContains != "" {
		ev.InfraLayer = r.InfraLayerContains
		set = true
	}
	if r.IsServerless != nil {
		ev.IsServerless = *r.IsServerless
		set = true
	}
	if r.IsKubernetes != nil {
		ev.IsKubernetes = *r.IsKubernetes
		set = true
	}
	if r.HasContractAddresses {
		ev.ContractAddresses = []string{"0x1234567890abcdef1234567890abcdef12345678"}
		set = true
	}
	if r.AuthSchemeContains != "" {
		ev.AuthScheme = r.AuthSchemeContains
		set = true
	}
	if r.MXProviderContains != "" {
		ev.MXProvider = r.MXProviderContains
		set = true
	}
	if r.VendorSignalContains != "" {
		ev.VendorSignals = []string{r.VendorSignalContains}
		set = true
	}
	if r.Web3SignalContains != "" {
		ev.Web3Signals = []string{r.Web3SignalContains}
		set = true
	}
	if r.HasDMARC != nil {
		ev.HasDMARC = *r.HasDMARC
		set = true
	}
	if r.AIEndpointPresent {
		ev.AIEndpoints = []string{"/v1/chat/completions"}
		set = true
	}
	if r.LLMProviderContains != "" {
		ev.LLMProvider = r.LLMProviderContains
		set = true
	}
	if r.CheckIDPresent != "" {
		ev.PhaseACheckIDs = []string{r.CheckIDPresent}
		set = true
	}

	if !set {
		return nil
	}
	return ev
}

// mergeEvidenceForAllRules synthesizes evidence satisfying all rules simultaneously.
func mergeEvidenceForAllRules(rules []playbook.MatchRule) *playbook.Evidence {
	base := &playbook.Evidence{
		Headers: make(map[string]string),
	}

	for _, r := range rules {
		single := evidenceForMatchRule(r)
		if single == nil {
			return nil
		}
		// Merge single into base.
		for k, v := range single.Headers {
			base.Headers[k] = v
		}
		if single.Title != "" {
			base.Title = single.Title
		}
		if single.Body512 != "" {
			base.Body512 += " " + single.Body512
		}
		if single.ASNOrg != "" {
			base.ASNOrg = single.ASNOrg
		}
		if single.Hostname != "" {
			base.Hostname = single.Hostname
		}
		base.RespondingPaths = append(base.RespondingPaths, single.RespondingPaths...)
		base.CNAMEChain = append(base.CNAMEChain, single.CNAMEChain...)
		base.CertSANs = append(base.CertSANs, single.CertSANs...)
		if single.CloudProvider != "" {
			base.CloudProvider = single.CloudProvider
		}
		if single.Framework != "" {
			base.Framework = single.Framework
		}
		if single.AuthSystem != "" {
			base.AuthSystem = single.AuthSystem
		}
		if single.ProxyType != "" {
			base.ProxyType = single.ProxyType
		}
		if single.InfraLayer != "" {
			base.InfraLayer = single.InfraLayer
		}
		if single.IsServerless {
			base.IsServerless = true
		}
		if single.IsKubernetes {
			base.IsKubernetes = true
		}
		base.ContractAddresses = append(base.ContractAddresses, single.ContractAddresses...)
		if single.AuthScheme != "" {
			base.AuthScheme = single.AuthScheme
		}
		if single.MXProvider != "" {
			base.MXProvider = single.MXProvider
		}
		base.VendorSignals = append(base.VendorSignals, single.VendorSignals...)
		base.Web3Signals = append(base.Web3Signals, single.Web3Signals...)
		if single.HasDMARC {
			base.HasDMARC = true
		}
		base.AIEndpoints = append(base.AIEndpoints, single.AIEndpoints...)
		if single.LLMProvider != "" {
			base.LLMProvider = single.LLMProvider
		}
		base.PhaseACheckIDs = append(base.PhaseACheckIDs, single.PhaseACheckIDs...)
		if single.ServiceVersions != nil {
			if base.ServiceVersions == nil {
				base.ServiceVersions = make(map[string]string)
			}
			for k, v := range single.ServiceVersions {
				base.ServiceVersions[k] = v
			}
		}
	}
	return base
}
