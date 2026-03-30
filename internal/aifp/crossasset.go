package aifp

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
)

// CrossAnalyzer performs AI-driven cross-asset vulnerability analysis after
// all per-asset scans have completed.  It identifies attack chains, patterns
// that span multiple assets, and additional scans warranted by the full picture.
type CrossAnalyzer struct {
	chat ChatFn
}

// NewCrossAnalyzer creates a CrossAnalyzer backed by the provided chat function.
func NewCrossAnalyzer(chat ChatFn) *CrossAnalyzer {
	return &CrossAnalyzer{chat: chat}
}

// CrossAssetResult is returned by Analyze.
type CrossAssetResult struct {
	// CrossFindings are vulnerabilities or weaknesses that span multiple assets.
	CrossFindings []finding.Finding

	// AdditionalScans maps asset name → list of scanner names to run.
	// These are scanners the AI believes were missed given the full picture.
	AdditionalScans map[string][]string

	// AttackChains describes multi-step attack paths using discovered vulnerabilities.
	AttackChains []string

	// Summary is a brief executive summary of the cross-asset analysis.
	Summary string
}

// Analyze sends all findings to the AI for cross-asset analysis.
// Returns an error if the AI call fails — callers must treat this as non-fatal.
func (a *CrossAnalyzer) Analyze(ctx context.Context, allFindings []finding.Finding, rootDomain string) (*CrossAssetResult, error) {
	if len(allFindings) == 0 {
		return &CrossAssetResult{}, nil
	}
	prompt := buildCrossAssetPrompt(allFindings, rootDomain)
	resp, err := a.chat(ctx, prompt)
	if err != nil {
		return nil, fmt.Errorf("aifp.CrossAnalyzer: %w", err)
	}
	return parseCrossAssetResponse(resp, rootDomain)
}

// ── Prompt ───────────────────────────────────────────────────────────────────

func buildCrossAssetPrompt(allFindings []finding.Finding, rootDomain string) string {
	// Group findings by asset. Deduplicate by (asset, check_id).
	type key struct{ asset, checkID string }
	seen := map[key]bool{}
	grouped := map[string][]string{}
	var assetOrder []string
	assetSeen := map[string]bool{}

	for _, f := range allFindings {
		// Skip purely informational findings — noise in the cross-asset context.
		if f.Severity == finding.SeverityInfo {
			continue
		}
		k := key{f.Asset, string(f.CheckID)}
		if seen[k] {
			continue
		}
		seen[k] = true
		if !assetSeen[f.Asset] {
			assetOrder = append(assetOrder, f.Asset)
			assetSeen[f.Asset] = true
		}
		sev := strings.ToUpper(f.Severity.String())
		if len(sev) > 4 {
			sev = sev[:4]
		}
		entry := fmt.Sprintf("[%s] %s (%s)", sev, trunc(f.Title, 80), f.CheckID)
		grouped[f.Asset] = append(grouped[f.Asset], entry)
	}
	sort.Strings(assetOrder)

	var b strings.Builder
	fmt.Fprintf(&b, "You are a senior security researcher performing cross-asset analysis for domain %q.\n\n", rootDomain)
	b.WriteString("FINDINGS BY ASSET:\n")
	for _, asset := range assetOrder {
		fmt.Fprintf(&b, "\n%s:\n", asset)
		for _, line := range grouped[asset] {
			fmt.Fprintf(&b, "  %s\n", line)
		}
	}

	b.WriteString(`
Your tasks:
1. Identify vulnerabilities that span multiple assets (e.g. same JWT signing key, consistent auth bypass, shared credential, common misconfiguration pattern).
2. Build realistic multi-step attack chains linking specific findings to a high-impact outcome.
3. Recommend additional scanners to run on specific assets where the full picture suggests something was missed.

Respond ONLY with valid JSON:
{
  "summary": "2-3 sentence executive summary of the most critical cross-asset risks",
  "attack_chains": [
    "Step 1 (asset): finding → Step 2 (asset): finding → Impact"
  ],
  "cross_findings": [
    {
      "assets": ["asset1", "asset2"],
      "check_id": "cross.descriptive_id",
      "severity": "critical|high|medium|low",
      "title": "short title",
      "description": "what the cross-asset issue is and why it matters"
    }
  ],
  "additional_scans": {
    "asset.example.com": ["scanner1", "scanner2"]
  }
}

Constraints:
- cross_findings: only include findings with clear evidence across ≥2 assets. Do not invent vulnerabilities.
- additional_scans: choose only from: cors, jwt, webcontent, dlp, graphql, oauth, apiversions,
  hostheader, websocket, nuclei, cms-plugins, aillm, jenkins, ratelimit, smuggling.
- attack_chains: be specific — name the assets and check IDs involved.
- If nothing cross-asset is found, return empty arrays and a summary noting the scope was clean.`)

	return b.String()
}

// ── Response parsing ─────────────────────────────────────────────────────────

func parseCrossAssetResponse(text, rootDomain string) (*CrossAssetResult, error) {
	text = stripFences(text)
	start := strings.Index(text, "{")
	end := strings.LastIndex(text, "}")
	if start < 0 || end <= start {
		return &CrossAssetResult{Summary: "Cross-asset analysis returned unparseable response."}, nil
	}
	text = text[start : end+1]

	var raw struct {
		Summary      string   `json:"summary"`
		AttackChains []string `json:"attack_chains"`
		CrossFindings []struct {
			Assets      []string `json:"assets"`
			CheckID     string   `json:"check_id"`
			Severity    string   `json:"severity"`
			Title       string   `json:"title"`
			Description string   `json:"description"`
		} `json:"cross_findings"`
		AdditionalScans map[string][]string `json:"additional_scans"`
	}
	if err := json.Unmarshal([]byte(text), &raw); err != nil {
		// Graceful degradation — never expose raw LLM output as summary.
		return &CrossAssetResult{Summary: "Cross-asset analysis returned malformed JSON."}, nil
	}

	result := &CrossAssetResult{
		Summary:         raw.Summary,
		AttackChains:    raw.AttackChains,
		AdditionalScans: raw.AdditionalScans,
	}

	for _, cf := range raw.CrossFindings {
		if cf.Title == "" || len(cf.Assets) == 0 {
			continue
		}
		checkID := finding.CheckID(cf.CheckID)
		if checkID == "" {
			checkID = finding.CheckAIFPCrossAsset
		}
		sev := parseSeverity(cf.Severity)
		involvedStr := strings.Join(cf.Assets, ", ")
		for _, asset := range cf.Assets {
			result.CrossFindings = append(result.CrossFindings, finding.Finding{
				CheckID:  checkID,
				Module:   "aifp",
				Scanner:  "crossasset",
				Severity: sev,
				Title:    cf.Title,
				Description: cf.Description,
				Asset:    asset,
				Evidence: map[string]any{
					"involved_assets":   involvedStr,
					"analysis_source":   "ai_cross_asset",
					"attack_chains":     strings.Join(raw.AttackChains, " | "),
				},
				ProofCommand: fmt.Sprintf("beacon scan --domain %s", rootDomain),
				DiscoveredAt: time.Now(),
			})
		}
	}
	return result, nil
}

func parseSeverity(s string) finding.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return finding.SeverityCritical
	case "high":
		return finding.SeverityHigh
	case "medium":
		return finding.SeverityMedium
	case "low":
		return finding.SeverityLow
	default:
		return finding.SeverityInfo
	}
}
