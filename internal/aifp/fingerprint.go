// Package aifp (AI Fingerprinting) provides AI-driven technology identification
// and cross-asset vulnerability analysis for assets that resist deterministic
// fingerprinting.
//
// Design principles:
//   - AI is a classifier, not a scorer: it outputs a deterministic classification
//     (framework/proxy/cloud) that is immediately acted on, not a probability.
//   - Classification source is always recorded (ClassificationSource field) so
//     analysts know which findings were AI-guided vs deterministic.
//   - Every AI-inferred fingerprint also produces a ProposedRule that is saved
//     as "pending" in the store for human review and promotion to active.
//   - Errors are always non-fatal: callers should log and continue.
package aifp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/playbook"
	"github.com/stormbane/beacon/internal/store"
)

// ChatFn is the function signature for a single-shot AI prompt/response call.
// ClaudeEnricher.Chat satisfies this interface.
type ChatFn func(ctx context.Context, prompt string) (string, error)

// Classifier performs AI-driven technology fingerprinting when deterministic
// rules leave the Evidence struct partially or fully unclassified.
type Classifier struct {
	chat ChatFn
	st   store.Store // may be nil — skips rule persistence when absent
}

// NewClassifier creates a Classifier backed by the provided chat function.
func NewClassifier(chat ChatFn, st store.Store) *Classifier {
	return &Classifier{chat: chat, st: st}
}

// ClassifyResult is returned by Classify.
type ClassifyResult struct {
	// Technology classifications — merged into Evidence only for empty fields.
	Framework       string   `json:"framework"`
	ProxyType       string   `json:"proxy_type"`
	CloudProvider   string   `json:"cloud_provider"`
	AuthSystem      string   `json:"auth_system"`
	InfraLayer      string   `json:"infra_layer"`
	BackendServices []string `json:"backend_services"`
	IsKubernetes    bool     `json:"is_kubernetes"`
	IsServerless    bool     `json:"is_serverless"`
	IsReverseProxy  bool     `json:"is_reverse_proxy"`

	// Confidence tier — "high", "medium", or "low".
	// Displayed in the TUI with an [AI] badge; not used for scan logic.
	Confidence string `json:"confidence"`

	// Signals lists the evidence items that drove the classification.
	Signals []string `json:"signals"`

	// Explanation is a brief human-readable rationale.
	Explanation string `json:"explanation"`

	// SuggestedScanners is a list of scanner names warranted by this classification.
	// Fed into the convergence loop to run scanners the playbook system missed.
	SuggestedScanners []string `json:"suggested_scanners"`

	// ProposedRules are deterministic fingerprint rules derived from the signals.
	// Stored as "pending" in the DB — require human approval before use.
	ProposedRules []store.FingerprintRule
}

// NeedsClassification returns true when the Evidence lacks tech-stack
// classification that would drive meaningful playbook differences.
// Called before deciding whether to invoke the AI (avoids unnecessary API calls).
func NeedsClassification(ev *playbook.Evidence) bool {
	return ev.Framework == "" &&
		ev.ProxyType == "" &&
		ev.CloudProvider == "" &&
		ev.AuthSystem == "" &&
		len(ev.BackendServices) == 0
}

// MergeInto applies the ClassifyResult into ev, setting only fields that are
// currently empty (never overwrites deterministic classifications).
func (r *ClassifyResult) MergeInto(ev *playbook.Evidence) {
	if ev.Framework == "" {
		ev.Framework = r.Framework
	}
	if ev.ProxyType == "" {
		ev.ProxyType = r.ProxyType
	}
	if ev.CloudProvider == "" {
		ev.CloudProvider = r.CloudProvider
	}
	if ev.AuthSystem == "" {
		ev.AuthSystem = r.AuthSystem
	}
	if ev.InfraLayer == "" {
		ev.InfraLayer = r.InfraLayer
	}
	if !ev.IsKubernetes && r.IsKubernetes {
		ev.IsKubernetes = true
	}
	if !ev.IsServerless && r.IsServerless {
		ev.IsServerless = true
	}
	if !ev.IsReverseProxy && r.IsReverseProxy {
		ev.IsReverseProxy = true
	}
	seen := map[string]bool{}
	for _, s := range ev.BackendServices {
		seen[s] = true
	}
	for _, s := range r.BackendServices {
		if !seen[s] && s != "" {
			ev.BackendServices = append(ev.BackendServices, s)
			seen[s] = true
		}
	}
	if ev.ClassificationSource == "" && r.Confidence != "" {
		ev.ClassificationSource = "ai:" + r.Confidence
	}
}

// UnknownTechFinding returns an info-level finding noting that AI was used to
// classify the asset and a proposed fingerprint rule is pending review.
// Signals to analysts that they should validate the AI guess.
func (r *ClassifyResult) UnknownTechFinding(asset string) *finding.Finding {
	if r.Confidence == "high" && len(r.ProposedRules) > 0 {
		return nil // high confidence + rule saved — no noise needed
	}
	tech := strings.Join(nonEmpty(r.Framework, r.ProxyType, r.CloudProvider), "/")
	if tech == "" {
		tech = "unknown"
	}
	return &finding.Finding{
		CheckID:  finding.CheckAIFPUnknownTech,
		Module:   "aifp",
		Scanner:  "classifier",
		Severity: finding.SeverityInfo,
		Title:    fmt.Sprintf("AI-classified technology (%s confidence): %s", r.Confidence, tech),
		Description: fmt.Sprintf(
			"Deterministic fingerprinting did not identify the technology on %s. "+
				"AI classified it as %q (confidence: %s) based on: %s. "+
				"A proposed fingerprint rule has been saved for review. "+
				"Verify the classification and approve or reject the rule via `beacon fingerprints`.",
			asset, tech, r.Confidence, strings.Join(r.Signals, "; ")),
		Asset:        asset,
		Evidence:     map[string]any{"ai_classification": tech, "confidence": r.Confidence, "explanation": r.Explanation},
		ProofCommand: "beacon fingerprints pending",
		DiscoveredAt: time.Now(),
	}
}

// Classify calls the AI to identify the technology behind ev and returns a
// ClassifyResult. Also persists proposed fingerprint rules and a proposed
// playbook (when confidence is medium+) to the store for human review.
//
// Returns an error if the AI call fails — callers must treat this as non-fatal.
func (c *Classifier) Classify(ctx context.Context, ev *playbook.Evidence) (*ClassifyResult, error) {
	prompt := buildClassifyPrompt(ev)
	resp, err := c.chat(ctx, prompt)
	if err != nil {
		return nil, fmt.Errorf("aifp.Classify: %w", err)
	}
	result, err := parseClassifyResponse(resp)
	if err != nil {
		return nil, fmt.Errorf("aifp.Classify: parse: %w", err)
	}

	// Boost confidence for proposed rules whose predicted value agrees with what
	// deterministic rules already established in ev. Agreement = the AI is
	// confirming something the rule engine already knows, which is strong signal
	// that the rule is correct. Also escalate the overall confidence tier when
	// enough rules are confirmed.
	confirmed := 0
	for i := range result.ProposedRules {
		if deterministicConfirms(&result.ProposedRules[i], ev) {
			result.ProposedRules[i].Confidence = min(1.0, result.ProposedRules[i].Confidence*1.15)
			confirmed++
		}
	}
	if confirmed >= 2 && result.Confidence == "medium" {
		result.Confidence = "high"
	}

	if c.st != nil {
		// Persist proposed fingerprint rules.
		for i := range result.ProposedRules {
			_ = c.st.UpsertFingerprintRule(ctx, &result.ProposedRules[i])
		}
		// Persist a proposed playbook when the classifier has enough signal.
		if sugg := buildProposedPlaybook(result); sugg != nil {
			_ = c.st.SavePlaybookSuggestion(ctx, sugg)
		}
	}
	return result, nil
}

// ── Proposed playbook generation ─────────────────────────────────────────────

// deepOnlyScanners are active-probing scanners that should only run in deep mode.
var deepOnlyScanners = map[string]bool{
	"ratelimit": true, "smuggling": true, "hostheader": true,
}

// surfaceOnlyScanners are passive-only and appropriate for surface mode.
var surfaceOnlyScanners = map[string]bool{
	"webcontent": true, "dlp": true, "apiversions": true, "graphql": true,
}

// buildProposedPlaybook generates a PlaybookSuggestion from a ClassifyResult.
// Returns nil when there is insufficient signal or confidence to produce
// a useful playbook (avoids polluting the review queue with noise).
func buildProposedPlaybook(result *ClassifyResult) *store.PlaybookSuggestion {
	if result.Confidence == "low" {
		return nil
	}
	parts := nonEmpty(result.Framework, result.ProxyType, result.CloudProvider, result.AuthSystem)
	if len(parts) == 0 {
		return nil
	}
	tech := parts[0]
	if len(result.SuggestedScanners) == 0 {
		return nil
	}

	yaml := buildPlaybookYAML(tech, result)
	if yaml == "" {
		return nil // no match conditions — not useful
	}

	reasoning := fmt.Sprintf(
		"AI classified %q (confidence: %s). Signals: %s. %s",
		tech, result.Confidence, strings.Join(result.Signals, "; "), result.Explanation)

	return &store.PlaybookSuggestion{
		Type:           "new",
		TargetPlaybook: strings.ToLower(strings.NewReplacer(" ", "_", "-", "_", "/", "_").Replace(tech)),
		SuggestedYAML:  yaml,
		Reasoning:      reasoning,
		Priority:       result.Confidence, // "high" | "medium" | "low"
		Status:         "pending",
		SuggestionKind: "playbook",
		CreatedAt:      time.Now(),
	}
}

// buildPlaybookYAML produces a YAML playbook from a ClassifyResult.
// Match conditions are derived from ProposedRules and the resolved tech fields.
// Returns empty string when no usable match conditions can be constructed.
func buildPlaybookYAML(tech string, result *ClassifyResult) string {
	var b strings.Builder
	safeName := strings.ToLower(strings.NewReplacer(" ", "_", "-", "_", "/", "_").Replace(tech))

	fmt.Fprintf(&b, "name: %s\n", safeName)
	b.WriteString("description: >\n")
	fmt.Fprintf(&b, "  AI-detected: %s\n", result.Explanation)
	fmt.Fprintf(&b, "  Confidence: %s. Signals: %s.\n", result.Confidence, strings.Join(result.Signals, ", "))
	b.WriteString("  This playbook was proposed automatically — review match conditions and scanner list before approving.\n")
	b.WriteString("match:\n  any:\n")

	matchCount := 0

	// High-level evidence fields already resolved by the classifier.
	if result.Framework != "" {
		fmt.Fprintf(&b, "    - framework_contains: %q\n", result.Framework)
		matchCount++
	}
	if result.ProxyType != "" {
		fmt.Fprintf(&b, "    - proxy_type_contains: %q\n", result.ProxyType)
		matchCount++
	}
	if result.CloudProvider != "" {
		fmt.Fprintf(&b, "    - cloud_provider_contains: %q\n", result.CloudProvider)
		matchCount++
	}
	if result.AuthSystem != "" {
		fmt.Fprintf(&b, "    - auth_system_contains: %q\n", result.AuthSystem)
		matchCount++
	}

	// Signal-level rules (only include high-confidence signals).
	for _, r := range result.ProposedRules {
		if r.Confidence < 0.75 {
			continue
		}
		switch r.SignalType {
		case "header":
			if r.SignalKey != "" && r.SignalValue != "" {
				fmt.Fprintf(&b, "    - header_value:\n        name: %q\n        contains: %q\n", r.SignalKey, r.SignalValue)
				matchCount++
			} else if r.SignalKey != "" {
				fmt.Fprintf(&b, "    - header_present: %q\n", r.SignalKey)
				matchCount++
			}
		case "body":
			if r.SignalValue != "" {
				fmt.Fprintf(&b, "    - body_contains: %q\n", r.SignalValue)
				matchCount++
			}
		case "title":
			if r.SignalValue != "" {
				fmt.Fprintf(&b, "    - title_contains: %q\n", r.SignalValue)
				matchCount++
			}
		case "path":
			if r.SignalValue != "" {
				fmt.Fprintf(&b, "    - path_responds: %q\n", r.SignalValue)
				matchCount++
			}
		case "cname":
			if r.SignalValue != "" {
				fmt.Fprintf(&b, "    - cname_contains: %q\n", r.SignalValue)
				matchCount++
			}
		case "dns_suffix":
			if r.SignalValue != "" {
				fmt.Fprintf(&b, "    - dns_suffix: %q\n", r.SignalValue)
				matchCount++
			}
		case "asn_org":
			if r.SignalValue != "" {
				fmt.Fprintf(&b, "    - asn_org_contains: %q\n", r.SignalValue)
				matchCount++
			}
		case "cookie":
			if r.SignalValue != "" {
				// Cookies arrive as Set-Cookie header values.
				fmt.Fprintf(&b, "    - header_value:\n        name: \"set-cookie\"\n        contains: %q\n", r.SignalValue)
				matchCount++
			}
		}
	}

	if matchCount == 0 {
		return ""
	}

	// Partition suggested scanners into surface (passive) and deep (active).
	var surfaceScanners, deepScanners []string
	for _, s := range result.SuggestedScanners {
		if deepOnlyScanners[s] {
			deepScanners = append(deepScanners, s)
		} else if surfaceOnlyScanners[s] {
			surfaceScanners = append(surfaceScanners, s)
		} else {
			// Run in both modes.
			surfaceScanners = append(surfaceScanners, s)
			deepScanners = append(deepScanners, s)
		}
	}

	if len(surfaceScanners) > 0 {
		b.WriteString("surface:\n  scanners:\n")
		for _, s := range surfaceScanners {
			fmt.Fprintf(&b, "    - %s\n", s)
		}
	}
	if len(deepScanners) > 0 {
		b.WriteString("deep:\n  scanners:\n")
		for _, s := range deepScanners {
			fmt.Fprintf(&b, "    - %s\n", s)
		}
	}

	return b.String()
}

// ── Prompt construction ──────────────────────────────────────────────────────

func buildClassifyPrompt(ev *playbook.Evidence) string {
	var b strings.Builder
	b.WriteString("You are a security researcher performing technology fingerprinting of a web asset.\n")
	b.WriteString("Based ONLY on the raw signals below, identify the technology stack and propose deterministic rules.\n\n")
	b.WriteString("RAW SIGNALS:\n")

	if ev.StatusCode > 0 {
		fmt.Fprintf(&b, "- HTTP status: %d\n", ev.StatusCode)
	}
	// Headers — most informative signals.
	for k, v := range ev.Headers {
		fmt.Fprintf(&b, "- Header %s: %s\n", k, trunc(v, 140))
	}
	if ev.Title != "" {
		fmt.Fprintf(&b, "- Page title: %s\n", trunc(ev.Title, 100))
	}
	if ev.Body512 != "" {
		fmt.Fprintf(&b, "- Body (first 512 bytes): %s\n", trunc(ev.Body512, 300))
	}
	for _, san := range ev.CertSANs {
		fmt.Fprintf(&b, "- TLS SAN: %s\n", san)
	}
	if ev.CertIssuer != "" {
		fmt.Fprintf(&b, "- TLS issuer: %s\n", ev.CertIssuer)
	}
	for _, c := range ev.CNAMEChain {
		fmt.Fprintf(&b, "- CNAME: %s\n", c)
	}
	if ev.ASNOrg != "" {
		fmt.Fprintf(&b, "- ASN org: %s\n", ev.ASNOrg)
	}
	for _, p := range ev.RespondingPaths {
		fmt.Fprintf(&b, "- Responding path: %s\n", p)
	}
	for k, v := range ev.ServiceVersions {
		fmt.Fprintf(&b, "- Service version [%s]: %s\n", k, v)
	}
	for _, ck := range ev.CookieNames {
		fmt.Fprintf(&b, "- Cookie name: %s\n", ck)
	}
	if ev.JARMFingerprint != "" {
		fmt.Fprintf(&b, "- JARM: %s\n", ev.JARMFingerprint[:min(len(ev.JARMFingerprint), 32)])
	}
	if ev.FaviconHash != "" {
		fmt.Fprintf(&b, "- Favicon hash (FNV): %s\n", ev.FaviconHash)
	}
	if ev.DNSSuffix != "" {
		fmt.Fprintf(&b, "- DNS suffix: %s\n", ev.DNSSuffix)
	}
	// Tell the AI what deterministic rules already found to avoid duplication.
	if ev.Framework != "" {
		fmt.Fprintf(&b, "- Already identified framework: %s\n", ev.Framework)
	}
	if ev.ProxyType != "" {
		fmt.Fprintf(&b, "- Already identified proxy: %s\n", ev.ProxyType)
	}
	if ev.CloudProvider != "" {
		fmt.Fprintf(&b, "- Already identified cloud: %s\n", ev.CloudProvider)
	}

	b.WriteString(`
Only classify fields that deterministic rules left empty. Use short lowercase canonical names
(e.g. "nextjs", "traefik", "cloudflare", "auth0", "api_gateway").

Respond ONLY with valid JSON — no prose before or after:
{
  "framework": "",
  "proxy_type": "",
  "cloud_provider": "",
  "auth_system": "",
  "infra_layer": "",
  "backend_services": [],
  "is_kubernetes": false,
  "is_serverless": false,
  "is_reverse_proxy": false,
  "confidence": "high|medium|low",
  "signals": ["which signal drove each decision"],
  "explanation": "one sentence",
  "suggested_scanners": [],
  "proposed_rules": [
    {
      "signal_type": "header|body|path|cookie|cname|title|dns_suffix|asn_org",
      "signal_key": "",
      "signal_value": "",
      "field": "framework|proxy_type|auth_system|backend_services|cloud_provider|infra_layer",
      "value": "",
      "confidence": 0.9
    }
  ]
}

Rules for suggested_scanners — choose only from this list when the tech warrants it:
cors, jwt, webcontent, dlp, graphql, oauth, apiversions, hostheader, websocket,
nuclei, cms-plugins, aillm, jenkins, ratelimit, smuggling, cdnbypass, depconf.

Rules for proposed_rules:
- Only include rules where the signal is clearly visible in the evidence above.
- signal_type "header" requires signal_key (header name) and signal_value (substring).
- confidence 0.0–1.0; only emit rules you are ≥0.7 confident about.
- Leave framework/proxy_type/cloud_provider empty string if uncertain.`)

	return b.String()
}

// ── Response parsing ─────────────────────────────────────────────────────────

func parseClassifyResponse(text string) (*ClassifyResult, error) {
	text = stripFences(text)
	start := strings.Index(text, "{")
	end := strings.LastIndex(text, "}")
	if start < 0 || end <= start {
		return nil, fmt.Errorf("no JSON object in response")
	}
	text = text[start : end+1]

	var raw struct {
		Framework         string   `json:"framework"`
		ProxyType         string   `json:"proxy_type"`
		CloudProvider     string   `json:"cloud_provider"`
		AuthSystem        string   `json:"auth_system"`
		InfraLayer        string   `json:"infra_layer"`
		BackendServices   []string `json:"backend_services"`
		IsKubernetes      bool     `json:"is_kubernetes"`
		IsServerless      bool     `json:"is_serverless"`
		IsReverseProxy    bool     `json:"is_reverse_proxy"`
		Confidence        string   `json:"confidence"`
		Signals           []string `json:"signals"`
		Explanation       string   `json:"explanation"`
		SuggestedScanners []string `json:"suggested_scanners"`
		ProposedRules     []struct {
			SignalType  string  `json:"signal_type"`
			SignalKey   string  `json:"signal_key"`
			SignalValue string  `json:"signal_value"`
			Field       string  `json:"field"`
			Value       string  `json:"value"`
			Confidence  float64 `json:"confidence"`
		} `json:"proposed_rules"`
	}
	if err := json.Unmarshal([]byte(text), &raw); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	result := &ClassifyResult{
		Framework:         raw.Framework,
		ProxyType:         raw.ProxyType,
		CloudProvider:     raw.CloudProvider,
		AuthSystem:        raw.AuthSystem,
		InfraLayer:        raw.InfraLayer,
		BackendServices:   raw.BackendServices,
		IsKubernetes:      raw.IsKubernetes,
		IsServerless:      raw.IsServerless,
		IsReverseProxy:    raw.IsReverseProxy,
		Confidence:        raw.Confidence,
		Signals:           raw.Signals,
		Explanation:       raw.Explanation,
		SuggestedScanners: raw.SuggestedScanners,
	}

	for _, r := range raw.ProposedRules {
		if r.Field == "" || r.Value == "" || r.SignalType == "" {
			continue
		}
		result.ProposedRules = append(result.ProposedRules, store.FingerprintRule{
			SignalType:  r.SignalType,
			SignalKey:   r.SignalKey,
			SignalValue: r.SignalValue,
			Field:       r.Field,
			Value:       r.Value,
			Source:      "ai",
			Status:      "pending",
			Confidence:  r.Confidence,
			CreatedAt:   time.Now(),
		})
	}
	return result, nil
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func stripFences(text string) string {
	if i := strings.Index(text, "```json"); i >= 0 {
		text = text[i+7:]
		if j := strings.Index(text, "```"); j >= 0 {
			text = text[:j]
		}
	} else if i := strings.Index(text, "```"); i >= 0 {
		text = text[i+3:]
		if j := strings.Index(text, "```"); j >= 0 {
			text = text[:j]
		}
	}
	return strings.TrimSpace(text)
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func nonEmpty(ss ...string) []string {
	var out []string
	for _, s := range ss {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// deterministicConfirms returns true when the proposed rule's predicted value
// matches a field that deterministic fingerprinting already established in ev.
// This means the AI and deterministic rules agree — strong signal the rule is correct.
func deterministicConfirms(r *store.FingerprintRule, ev *playbook.Evidence) bool {
	if r.Value == "" {
		return false
	}
	switch r.Field {
	case "framework":
		return ev.Framework != "" && strings.EqualFold(ev.Framework, r.Value)
	case "proxy_type":
		return ev.ProxyType != "" && strings.EqualFold(ev.ProxyType, r.Value)
	case "cloud_provider":
		return ev.CloudProvider != "" && strings.EqualFold(ev.CloudProvider, r.Value)
	case "auth_system":
		return ev.AuthSystem != "" && strings.EqualFold(ev.AuthSystem, r.Value)
	case "infra_layer":
		return ev.InfraLayer != "" && strings.EqualFold(ev.InfraLayer, r.Value)
	case "backend_services":
		for _, s := range ev.BackendServices {
			if strings.EqualFold(s, r.Value) {
				return true
			}
		}
	}
	return false
}
