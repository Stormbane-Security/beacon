// Package playbook defines the playbook system — YAML-driven scan configuration.
//
// Every aspect of scanning is driven by playbooks. The baseline playbook
// (match: always) runs on every asset. Targeted playbooks layer additional
// checks on top when specific evidence is detected.
//
// Playbook YAML lives in internal/playbook/playbooks/*.yaml and is embedded
// at compile time. No filesystem access required at runtime.
package playbook

import (
	"log"
	"strings"

	"gopkg.in/yaml.v3"
)

// Playbook defines what to scan for a given asset scenario.
type Playbook struct {
	Name        string          `yaml:"name"`
	Description string          `yaml:"description"`
	Match       MatchConfig     `yaml:"match"`
	Surface     RunConfig       `yaml:"surface"`
	Deep        RunConfig       `yaml:"deep"`
	Discovery   []DiscoveryStep `yaml:"discovery"`
}

// RunConfig lists scanners and Nuclei tags to run in a given scan mode.
type RunConfig struct {
	Scanners     []string `yaml:"scanners"`    // named Go scanner modules
	NucleiTags   []string `yaml:"nuclei_tags"` // Nuclei template tags
	DirbustPaths []string `yaml:"dictionary"`  // URL paths to probe in deep-mode dirbusting (asset-type-specific wordlist)
}

// DiscoveryStep describes additional asset discovery triggered by a playbook match.
type DiscoveryStep struct {
	Type     string   `yaml:"type"`     // probe_subdomains | historical_dns | s3_buckets
	Patterns []string `yaml:"patterns"` // e.g. ["direct.{domain}", "origin.{domain}"]
}

// MatchConfig describes when a playbook applies to an asset.
// If Always is true, the playbook applies to every asset (baseline).
// Otherwise Any/All are evaluated against Evidence.
type MatchConfig struct {
	Always bool        `yaml:"always"`
	Any    []MatchRule `yaml:"any"` // OR — any rule matches → playbook applies
	All    []MatchRule `yaml:"all"` // AND — all rules must match
}

// MatchRule is a single condition evaluated against Evidence.
type MatchRule struct {
	HeaderPresent          string            `yaml:"header_present"`
	HeaderContains         string            `yaml:"header_contains"` // substring match against any header name or value
	HeaderValue            *HeaderValueMatch `yaml:"header_value"`
	ASNOrgContains         string            `yaml:"asn_org_contains"`
	DNSSuffix              string            `yaml:"dns_suffix"`
	CNAMEContains          string            `yaml:"cname_contains"`
	TitleContains          string            `yaml:"title_contains"`
	BodyContains           string            `yaml:"body_contains"`
	CertSANContains        string            `yaml:"cert_san_contains"`
	PathResponds           string            `yaml:"path_responds"`
	ServiceVersionContains string            `yaml:"service_version_contains"` // substring match against any ServiceVersions value
	AIEndpointPresent      bool              `yaml:"ai_endpoint_present"`      // true when aidetect found ≥1 LLM endpoint
	LLMProviderContains    string            `yaml:"llm_provider_contains"`    // substring match against LLMProvider
	CloudProviderContains  string            `yaml:"cloud_provider_contains"`  // substring match on CloudProvider
	FrameworkContains      string            `yaml:"framework_contains"`       // substring match on Framework
	AuthSystemContains     string            `yaml:"auth_system_contains"`     // substring match on AuthSystem
	IsServerless           *bool             `yaml:"is_serverless"`            // match serverless signal
	IsKubernetes           *bool             `yaml:"is_kubernetes"`            // match k8s signal
	HasContractAddresses   bool              `yaml:"has_contract_addresses"`   // true = ContractAddresses not empty
	AuthSchemeContains     string            `yaml:"auth_scheme_contains"`     // substring match on AuthScheme ("negotiate","bearer","ntlm")
	MXProviderContains     string            `yaml:"mx_provider_contains"`     // substring match on MXProvider ("google","microsoft")
	VendorSignalContains   string            `yaml:"vendor_signal_contains"`   // substring match against any VendorSignals entry
	Web3SignalContains     string            `yaml:"web3_signal_contains"`     // substring match against any Web3Signals entry
	HasDMARC               *bool             `yaml:"has_dmarc"`                // true = DMARC record exists
	// ProxyTypeContains matches when e.ProxyType contains the substring.
	// Populated by classify from Server/Via/proxy-specific response headers.
	// Examples: "nginx", "traefik", "envoy", "kong", "haproxy", "caddy", "varnish", "f5", "akamai".
	ProxyTypeContains string `yaml:"proxy_type_contains"`
	// InfraLayerContains matches when e.InfraLayer contains the substring.
	// Populated by classify based on the role of the detected infrastructure.
	// Values: "cdn_edge", "api_gateway", "load_balancer", "service_mesh", "reverse_proxy".
	InfraLayerContains string `yaml:"infra_layer_contains"`
	// CheckIDPresent matches when the given check ID string appears in
	// Evidence.PhaseACheckIDs (populated from Phase A scanner findings before
	// the second playbook-matching pass). Used by network-device playbooks to
	// trigger on SSH-banner detections (e.g. "netdev.mikrotik_detected") that
	// the classify scanner cannot detect from HTTP headers alone.
	CheckIDPresent string `yaml:"check_id"`
}

// HeaderValueMatch checks that a named header contains a substring.
type HeaderValueMatch struct {
	Name     string `yaml:"name"`
	Contains string `yaml:"contains"`
}

// Matches returns true if the playbook applies to the given evidence.
func (p *Playbook) Matches(e Evidence) bool {
	if p.Match.Always {
		return true
	}
	if len(p.Match.All) > 0 {
		for _, rule := range p.Match.All {
			if !ruleMatches(rule, e) {
				return false
			}
		}
		return true
	}
	for _, rule := range p.Match.Any {
		if ruleMatches(rule, e) {
			return true
		}
	}
	return false
}

// ruleMatches returns true when ALL non-zero conditions within the rule are satisfied.
// Within a single MatchRule, multiple set fields are ANDed together.
// A rule with no fields set matches nothing (returns false).
func ruleMatches(r MatchRule, e Evidence) bool {
	checked := 0
	if r.HeaderPresent != "" {
		checked++
		if _, ok := e.Headers[strings.ToLower(r.HeaderPresent)]; !ok {
			return false
		}
	}
	if r.HeaderContains != "" {
		checked++
		needle := strings.ToLower(r.HeaderContains)
		found := false
		for k, v := range e.Headers {
			if strings.Contains(k, needle) || strings.Contains(strings.ToLower(v), needle) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if r.HeaderValue != nil {
		checked++
		v, ok := e.Headers[strings.ToLower(r.HeaderValue.Name)]
		if !ok || !strings.Contains(strings.ToLower(v), strings.ToLower(r.HeaderValue.Contains)) {
			return false
		}
	}
	if r.ASNOrgContains != "" {
		checked++
		if !strings.Contains(strings.ToUpper(e.ASNOrg), strings.ToUpper(r.ASNOrgContains)) {
			return false
		}
	}
	if r.DNSSuffix != "" {
		checked++
		if !strings.HasSuffix(strings.ToLower(e.Hostname), strings.ToLower(r.DNSSuffix)) {
			return false
		}
	}
	if r.CNAMEContains != "" {
		checked++
		found := false
		for _, c := range e.CNAMEChain {
			if strings.Contains(strings.ToLower(c), strings.ToLower(r.CNAMEContains)) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if r.TitleContains != "" {
		checked++
		if !strings.Contains(strings.ToLower(e.Title), strings.ToLower(r.TitleContains)) {
			return false
		}
	}
	if r.BodyContains != "" {
		checked++
		if !strings.Contains(strings.ToLower(e.Body512), strings.ToLower(r.BodyContains)) {
			return false
		}
	}
	if r.CertSANContains != "" {
		checked++
		found := false
		for _, san := range e.CertSANs {
			if strings.Contains(strings.ToLower(san), strings.ToLower(r.CertSANContains)) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if r.PathResponds != "" {
		checked++
		found := false
		for _, p := range e.RespondingPaths {
			if strings.EqualFold(p, r.PathResponds) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if r.ServiceVersionContains != "" {
		checked++
		needle := strings.ToLower(r.ServiceVersionContains)
		found := false
		for _, v := range e.ServiceVersions {
			if strings.Contains(strings.ToLower(v), needle) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if r.AIEndpointPresent {
		checked++
		if len(e.AIEndpoints) == 0 {
			return false
		}
	}
	if r.LLMProviderContains != "" {
		checked++
		if !strings.Contains(strings.ToLower(e.LLMProvider), strings.ToLower(r.LLMProviderContains)) {
			return false
		}
	}
	if r.CloudProviderContains != "" {
		checked++
		if !strings.Contains(strings.ToLower(e.CloudProvider), strings.ToLower(r.CloudProviderContains)) {
			return false
		}
	}
	if r.FrameworkContains != "" {
		checked++
		if !strings.Contains(strings.ToLower(e.Framework), strings.ToLower(r.FrameworkContains)) {
			return false
		}
	}
	if r.AuthSystemContains != "" {
		checked++
		if !strings.Contains(strings.ToLower(e.AuthSystem), strings.ToLower(r.AuthSystemContains)) {
			return false
		}
	}
	if r.IsServerless != nil {
		checked++
		if e.IsServerless != *r.IsServerless {
			return false
		}
	}
	if r.IsKubernetes != nil {
		checked++
		if e.IsKubernetes != *r.IsKubernetes {
			return false
		}
	}
	if r.HasContractAddresses {
		checked++
		if len(e.ContractAddresses) == 0 {
			return false
		}
	}
	if r.AuthSchemeContains != "" {
		checked++
		if !strings.Contains(strings.ToLower(e.AuthScheme), strings.ToLower(r.AuthSchemeContains)) {
			return false
		}
	}
	if r.MXProviderContains != "" {
		checked++
		if !strings.Contains(strings.ToLower(e.MXProvider), strings.ToLower(r.MXProviderContains)) {
			return false
		}
	}
	if r.VendorSignalContains != "" {
		checked++
		needle := strings.ToLower(r.VendorSignalContains)
		found := false
		for _, v := range e.VendorSignals {
			if strings.Contains(strings.ToLower(v), needle) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if r.Web3SignalContains != "" {
		checked++
		needle := strings.ToLower(r.Web3SignalContains)
		found := false
		for _, v := range e.Web3Signals {
			if strings.Contains(strings.ToLower(v), needle) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if r.HasDMARC != nil {
		checked++
		if e.HasDMARC != *r.HasDMARC {
			return false
		}
	}
	if r.ProxyTypeContains != "" {
		checked++
		if !strings.Contains(strings.ToLower(e.ProxyType), strings.ToLower(r.ProxyTypeContains)) {
			return false
		}
	}
	if r.InfraLayerContains != "" {
		checked++
		if !strings.Contains(strings.ToLower(e.InfraLayer), strings.ToLower(r.InfraLayerContains)) {
			return false
		}
	}
	if r.CheckIDPresent != "" {
		checked++
		found := false
		for _, id := range e.PhaseACheckIDs {
			if id == r.CheckIDPresent {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	// A rule with no conditions set matches nothing.
	return checked > 0
}

// ParsePlaybook parses a single YAML playbook definition.
// It logs a warning for any rule that has always: false and no conditions,
// because such a rule can never match.
func ParsePlaybook(data []byte) (*Playbook, error) {
	var p Playbook
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	if !p.Match.Always {
		for i, rule := range p.Match.Any {
			if isEmptyRule(rule) {
				log.Printf("playbook %q: match.any[%d] has always: false and no conditions — rule will never match", p.Name, i)
			}
		}
		for i, rule := range p.Match.All {
			if isEmptyRule(rule) {
				log.Printf("playbook %q: match.all[%d] has always: false and no conditions — rule will never match", p.Name, i)
			}
		}
	}
	return &p, nil
}

// isEmptyRule returns true when a MatchRule has no conditions set.
func isEmptyRule(r MatchRule) bool {
	return r.HeaderPresent == "" &&
		r.HeaderContains == "" &&
		r.HeaderValue == nil &&
		r.ASNOrgContains == "" &&
		r.DNSSuffix == "" &&
		r.CNAMEContains == "" &&
		r.TitleContains == "" &&
		r.BodyContains == "" &&
		r.CertSANContains == "" &&
		r.PathResponds == "" &&
		r.ServiceVersionContains == "" &&
		!r.AIEndpointPresent &&
		r.LLMProviderContains == "" &&
		r.CloudProviderContains == "" &&
		r.FrameworkContains == "" &&
		r.AuthSystemContains == "" &&
		r.IsServerless == nil &&
		r.IsKubernetes == nil &&
		!r.HasContractAddresses &&
		r.AuthSchemeContains == "" &&
		r.MXProviderContains == "" &&
		r.VendorSignalContains == "" &&
		r.Web3SignalContains == "" &&
		r.HasDMARC == nil &&
		r.ProxyTypeContains == "" &&
		r.InfraLayerContains == "" &&
		r.CheckIDPresent == ""
}
