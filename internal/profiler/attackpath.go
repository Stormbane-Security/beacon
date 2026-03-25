package profiler

// AttackPath reasoning: given all findings from a single scan run, ask Claude
// to identify multi-step attack chains that connect CI/CD misconfigurations to
// deployed infrastructure vulnerabilities.
//
// Only correlates findings from the SAME scan run — never reaches into the
// historical scan database. This keeps the reasoning grounded and avoids
// false connections from stale prior data.
//
// The result is emitted as a cicd.attack_path finding with:
//   - A concise attack chain narrative
//   - The specific findings that form each step
//   - Estimated impact and likelihood
//   - Recommended mitigations in priority order

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
)

// AttackChain describes one end-to-end attack path identified by Claude.
type AttackChain struct {
	Title       string   `json:"title"`
	Steps       []string `json:"steps"`       // ordered narrative steps
	FindingIDs  []string `json:"finding_ids"` // CheckIDs involved
	Impact      string   `json:"impact"`
	Likelihood  string   `json:"likelihood"` // "high" | "medium" | "low"
	Mitigations []string `json:"mitigations"`
}

// ReasonAttackPaths asks Claude to connect findings across assets in the same
// scan run into coherent attack chains. It returns at most 3 chains so the
// output stays actionable. Returns nil if no interesting chains are found or
// if the API call fails (errors are intentionally swallowed so attack path
// analysis never blocks the scan report).
func ReasonAttackPaths(ctx context.Context, apiKey, model string, findings []finding.Finding) []AttackChain {
	if apiKey == "" || len(findings) == 0 {
		return nil
	}

	// Build a compact summary of findings for the prompt.
	// We only pass CheckID, Severity, Asset, and Title — enough for reasoning
	// without sending potentially large evidence blobs to the API.
	type findingSummary struct {
		CheckID  string `json:"check_id"`
		Severity string `json:"severity"`
		Asset    string `json:"asset"`
		Title    string `json:"title"`
	}
	var summaries []findingSummary
	// Prioritise Critical/High findings — cap at 40 to keep prompt size bounded.
	for _, f := range findings {
		if f.Severity == finding.SeverityCritical || f.Severity == finding.SeverityHigh {
			summaries = append(summaries, findingSummary{
				CheckID:  string(f.CheckID),
				Severity: f.Severity.String(),
				Asset:    f.Asset,
				Title:    f.Title,
			})
		}
		if len(summaries) >= 40 {
			break
		}
	}
	if len(summaries) < 2 {
		return nil // need at least two findings to form a chain
	}

	summaryJSON, err := json.Marshal(summaries)
	if err != nil {
		return nil
	}

	prompt := fmt.Sprintf(`You are a senior penetration tester analysing findings from an automated security scan.

Below is a JSON array of security findings from a single scan run. The findings span multiple assets (domains, IPs, and CI/CD systems) that are all part of the same organisation's infrastructure.

Your task:
1. Identify up to 3 multi-step attack paths that chain two or more findings together.
2. Each path must be realistic — there must be a credible mechanism connecting each step (not just "both are vulnerabilities").
3. Focus on paths that cross trust boundaries: e.g. a CI/CD misconfiguration that leads to code execution on a deployed server, or a leaked credential that enables cloud access.
4. If no meaningful chains exist (findings are unrelated), return an empty array.

Findings:
%s

Respond ONLY with a JSON array of attack chains. Each chain must have:
{
  "title": "short title (one line)",
  "steps": ["step 1 description", "step 2 description", ...],
  "finding_ids": ["check_id_1", "check_id_2"],
  "impact": "brief impact statement",
  "likelihood": "high|medium|low",
  "mitigations": ["fix 1", "fix 2"]
}

Return [] if no credible chains exist. Do not include explanatory text outside the JSON array.`,
		string(summaryJSON))

	chains, err := callClaudeForChains(ctx, apiKey, model, prompt)
	if err != nil || len(chains) == 0 {
		return nil
	}
	return chains
}

// BuildAttackPathFinding converts ReasonAttackPaths output into a single
// cicd.attack_path finding that can be appended to scan results.
func BuildAttackPathFinding(asset string, chains []AttackChain) *finding.Finding {
	if len(chains) == 0 {
		return nil
	}

	// Format the chains into a readable description.
	var sb strings.Builder
	for i, chain := range chains {
		fmt.Fprintf(&sb, "## Attack Path %d: %s\n", i+1, chain.Title)
		fmt.Fprintf(&sb, "**Likelihood**: %s  **Impact**: %s\n\n", chain.Likelihood, chain.Impact)
		for j, step := range chain.Steps {
			fmt.Fprintf(&sb, "%d. %s\n", j+1, step)
		}
		if len(chain.Mitigations) > 0 {
			sb.WriteString("\n**Mitigations:**\n")
			for _, m := range chain.Mitigations {
				fmt.Fprintf(&sb, "- %s\n", m)
			}
		}
		sb.WriteString("\n")
	}

	// Severity is the highest likelihood chain's severity.
	sev := finding.SeverityHigh
	for _, chain := range chains {
		if chain.Likelihood == "high" {
			sev = finding.SeverityCritical
			break
		}
	}

	chainsJSON, _ := json.Marshal(chains)

	return &finding.Finding{
		CheckID:      finding.CheckCICDAttackPath,
		Module:       "surface",
		Scanner:      "profiler",
		Severity:     sev,
		Title:        fmt.Sprintf("AI-identified attack path: %s", chains[0].Title),
		Description:  sb.String(),
		Asset:        asset,
		Evidence:     map[string]any{"chains": string(chainsJSON), "chain_count": len(chains)},
		ProofCommand: "# See individual findings listed in each attack path step",
		DiscoveredAt: time.Now(),
	}
}

// callClaudeForChains calls the Anthropic Messages API and parses the response
// as a JSON array of AttackChain objects.
func callClaudeForChains(ctx context.Context, apiKey, model, prompt string) ([]AttackChain, error) {
	if model == "" {
		model = "claude-sonnet-4-6"
	}

	reqBody, _ := json.Marshal(map[string]any{
		"model":      model,
		"max_tokens": 2048,
		"messages": []map[string]any{
			{"role": "user", "content": prompt},
		},
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.anthropic.com/v1/messages", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}

	var apiResp struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, err
	}
	if len(apiResp.Content) == 0 {
		return nil, nil
	}

	text := strings.TrimSpace(apiResp.Content[0].Text)
	// Strip markdown code fences if Claude wrapped the JSON.
	text = strings.TrimPrefix(text, "```json")
	text = strings.TrimPrefix(text, "```")
	text = strings.TrimSuffix(text, "```")
	text = strings.TrimSpace(text)

	var chains []AttackChain
	if err := json.Unmarshal([]byte(text), &chains); err != nil {
		return nil, err
	}
	return chains, nil
}
