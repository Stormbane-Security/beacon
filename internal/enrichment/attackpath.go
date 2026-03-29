package enrichment

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/stormbane/beacon/internal/finding"
)

// AnalyzeAttackPaths performs a cross-module attack chain analysis across all
// enriched findings. It groups findings by module (surface, cloud, github),
// then asks the LLM to identify realistic multi-step attack chains that span
// modules and assets.
//
// Returns ("", nil) when there are fewer than 2 distinct modules or fewer than
// 3 total findings — not enough context for meaningful analysis.
func (c *ClaudeEnricher) AnalyzeAttackPaths(ctx context.Context, enriched []EnrichedFinding, domain string) (string, error) {
	if len(enriched) < 3 {
		return "", nil
	}

	// Group findings by module.
	byModule := make(map[string][]EnrichedFinding)
	for _, ef := range enriched {
		mod := ef.Finding.Module
		if mod == "" {
			mod = "surface"
		}
		byModule[mod] = append(byModule[mod], ef)
	}
	if len(byModule) < 2 {
		return "", nil
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "You are a senior penetration tester analyzing scan results for the domain: %s\n\n", domain)
	sb.WriteString("Below are all security findings grouped by scan module.\n\n")

	for mod, findings := range byModule {
		fmt.Fprintf(&sb, "=== Module: %s ===\n", strings.ToUpper(mod))
		for _, ef := range findings {
			f := ef.Finding
			fmt.Fprintf(&sb, "  - [%s] %s | severity: %s | asset: %s\n",
				string(f.CheckID), f.Title, f.Severity.String(), f.Asset)

			// Surface any cloud context embedded in evidence.
			if f.Evidence != nil {
				cloudFields := []string{"instance_id", "project_id", "external_ip", "public_ips"}
				for _, key := range cloudFields {
					if val, ok := f.Evidence[key]; ok && val != nil {
						fmt.Fprintf(&sb, "      %s: %v\n", key, val)
					}
				}
			}
		}
		sb.WriteString("\n")
	}

	sb.WriteString(`Based on the findings above, perform a realistic cross-module attack path analysis.

Please provide:

1. TOP 3 ATTACK CHAINS
   For each chain describe the exact steps an attacker would take, starting from the public internet.
   Format each step as: "attacker finds X on surface → pivots via Y cloud misconfiguration → achieves Z"
   Include which specific check IDs and assets are involved at each step.

2. HIGHEST-RISK CROSS-MODULE COMBINATION
   Identify the single most dangerous combination of findings that span two or more modules.
   Explain why this combination is particularly severe.

3. HIGHEST-LEVERAGE FIX
   Identify which single remediation would break the most attack chains. Explain your reasoning.

Be concise and specific. Focus on realistic, actionable attack paths — not theoretical ones.
`)

	prompt := sb.String()
	return c.callLLM(ctx, c.summaryModel, prompt)
}

// GenerateFollowUpProbes suggests targeted surface-safe follow-up checks based
// on the current set of enriched findings. It identifies cloud instance IPs
// that were not directly scanned and asks the LLM to suggest up to 5 probes.
//
// On any JSON parse error the function returns nil, nil (non-fatal).
func (c *ClaudeEnricher) GenerateFollowUpProbes(ctx context.Context, enriched []EnrichedFinding, domain string) ([]FollowUpProbe, error) {
	var sb strings.Builder
	fmt.Fprintf(&sb, "You are a security scanner assistant for the domain: %s\n\n", domain)
	sb.WriteString("Current findings (asset, check_id):\n")

	// Track assets that appear directly in findings.
	knownAssets := make(map[string]bool)
	for _, ef := range enriched {
		f := ef.Finding
		knownAssets[f.Asset] = true
		fmt.Fprintf(&sb, "  - asset: %s | check_id: %s | severity: %s\n",
			f.Asset, string(f.CheckID), f.Severity.String())
	}
	sb.WriteString("\n")

	// Collect cloud IPs from evidence that are not already a finding asset.
	var unseenIPs []string
	seen := make(map[string]bool)
	for _, ef := range enriched {
		if ef.Finding.Evidence == nil {
			continue
		}
		addIfUnseen := func(val any) {
			switch v := val.(type) {
			case string:
				if v != "" && !knownAssets[v] && !seen[v] {
					unseenIPs = append(unseenIPs, v)
					seen[v] = true
				}
			case []any:
				for _, item := range v {
					if s, ok := item.(string); ok && s != "" && !knownAssets[s] && !seen[s] {
						unseenIPs = append(unseenIPs, s)
						seen[s] = true
					}
				}
			}
		}
		if v, ok := ef.Finding.Evidence["external_ip"]; ok {
			addIfUnseen(v)
		}
		if v, ok := ef.Finding.Evidence["public_ips"]; ok {
			addIfUnseen(v)
		}
	}

	if len(unseenIPs) > 0 {
		sb.WriteString("Cloud instance IPs found in evidence but NOT yet directly scanned:\n")
		for _, ip := range unseenIPs {
			fmt.Fprintf(&sb, "  - %s\n", ip)
		}
		sb.WriteString("\n")
	}

	sb.WriteString(`Suggest up to 5 targeted follow-up probes that would provide the most security value.

CONSTRAINTS:
- Only suggest surface-safe probes (passive observation or standard service fingerprinting — no exploitation, no fuzzing, no auth bypass attempts)
- Prioritize unscanned IPs and assets implied by the current findings
- Valid scanner values: "portscan", "cve", "http", "k8s_api"

Respond with ONLY a JSON array in this exact format (no surrounding prose):
[
  {"asset": "<ip or hostname>", "reason": "<why this probe is valuable>", "check_id": "<suggested check id, or empty string>", "scanner": "<scanner name>"}
]

If there are no useful follow-up probes, return an empty array: []
`)

	prompt := sb.String()
	raw, err := c.callLLM(ctx, c.summaryModel, prompt)
	if err != nil {
		return nil, err
	}

	jsonText := extractJSONArray(raw)
	var probes []FollowUpProbe
	if err := json.Unmarshal([]byte(jsonText), &probes); err != nil {
		// Non-fatal: return nil so the caller can continue without follow-up probes.
		return nil, nil
	}

	// Enforce the 5-probe limit in case the LLM ignores the instruction.
	if len(probes) > 5 {
		probes = probes[:5]
	}

	// Validate that each probe has a non-empty Asset and Scanner.
	valid := probes[:0]
	for _, p := range probes {
		if strings.TrimSpace(p.Asset) != "" && strings.TrimSpace(p.Scanner) != "" {
			valid = append(valid, p)
		}
	}
	return valid, nil
}

// Ensure ClaudeEnricher satisfies Enricher at compile time.
var _ Enricher = (*ClaudeEnricher)(nil)

// Silence unused import lint if finding package is only used transitively.
var _ = finding.SeverityCritical
