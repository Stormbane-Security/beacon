// Package analyze — PlaybookAdvisor uses Claude to suggest additional scanners
// to run on an asset beyond what the playbook matching system already selected.
//
// This runs during the per-asset scan pipeline, after playbook matching and
// before scanner execution. It gives the AI the collected evidence and the
// already-matched scanner set, then asks it to suggest complementary scanners
// from the available pool that are relevant to the detected tech stack.
//
// Design constraints:
//   - Uses claude-haiku for speed and cost (this runs during an active scan)
//   - 256 max output tokens — enough for a list of ~5 scanner names + rationale
//   - Hard cap: 5 suggestions per asset
//   - Only suggests scanners from the caller-supplied available list
//   - Skips silently if apiKey is empty (advisory is opt-in)
package analyze

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/playbook"
)

const (
	playbookAdvisorModel     = "claude-haiku-4-5-20251001"
	playbookAdvisorMaxTokens = 256
	playbookAdvisorMaxSugg   = 5
)

// PlaybookAdvisor uses Claude to suggest additional scanners based on evidence
// and already-matched playbooks.
type PlaybookAdvisor struct {
	apiKey     string
	apiURL     string
	model      string
	httpClient *http.Client
}

// NewPlaybookAdvisor creates a PlaybookAdvisor.
// Returns nil if apiKey is empty — callers must nil-check before use.
func NewPlaybookAdvisor(apiKey string) *PlaybookAdvisor {
	if apiKey == "" {
		return nil
	}
	return &PlaybookAdvisor{
		apiKey:     apiKey,
		apiURL:     apiURL,
		model:      playbookAdvisorModel,
		httpClient: &http.Client{Timeout: 90 * time.Second},
	}
}

// playbookAdvisorResponse is the JSON structure returned by Claude.
type playbookAdvisorResponse struct {
	Scanners  []string `json:"scanners"`
	Rationale string   `json:"rationale"`
}

// Suggest asks Claude to recommend additional scanners to run on the asset
// beyond what the playbook system already matched.
//
// ev is the collected evidence about the asset.
// matchedScanners is the set of scanner names already scheduled from playbooks.
// availableScanners is the full set of scanner names the caller may schedule.
// scanMode is either "surface" or "deep".
//
// Returns up to playbookAdvisorMaxSugg scanner names that exist in
// availableScanners and are not already in matchedScanners.
// Returns nil (never an error) if parsing fails — scan must never be blocked.
func (a *PlaybookAdvisor) Suggest(
	ctx context.Context,
	ev playbook.Evidence,
	matchedScanners []string,
	availableScanners []string,
	scanMode string,
) ([]string, error) {
	if len(availableScanners) == 0 {
		return nil, nil
	}

	prompt := buildPlaybookAdvisorPrompt(ev, matchedScanners, availableScanners, scanMode)

	text, err := a.callPlaybookAdvisor(ctx, prompt)
	if err != nil {
		return nil, err
	}

	return parsePlaybookAdvisorResponse(text, matchedScanners, availableScanners), nil
}

// buildPlaybookAdvisorPrompt constructs the prompt for the playbook advisor.
func buildPlaybookAdvisorPrompt(
	ev playbook.Evidence,
	matchedScanners []string,
	availableScanners []string,
	scanMode string,
) string {
	evidenceJSON, _ := json.Marshal(ev)

	var b strings.Builder

	b.WriteString("You are a security scan advisor. Given the evidence collected about a web asset, suggest additional scanners to run beyond what the playbook system already matched.\n\n")

	b.WriteString("Asset evidence:\n")
	b.Write(evidenceJSON)
	b.WriteString("\n\n")

	b.WriteString(fmt.Sprintf("Already running these scanners (from matched playbooks): %s\n\n",
		strings.Join(matchedScanners, ", ")))

	b.WriteString(fmt.Sprintf("Available additional scanners: %s\n",
		strings.Join(availableScanners, ", ")))

	b.WriteString(fmt.Sprintf("Scan mode: %s\n\n", scanMode))

	b.WriteString(fmt.Sprintf(`Respond with a JSON object:
{
  "scanners": ["scanner1", "scanner2"],
  "rationale": "one sentence explanation"
}

Rules:
- Only suggest scanners from the available list
- Maximum %d suggestions
- Do not suggest scanners already running
- Only suggest scanners relevant to the detected technology stack
- If nothing useful to add, return {"scanners": [], "rationale": "coverage complete"}
`, playbookAdvisorMaxSugg))

	return b.String()
}

// parsePlaybookAdvisorResponse extracts valid scanner names from Claude's JSON response.
// Returns only scanners that are in availableScanners and not in matchedScanners.
// Returns nil if parsing fails — callers must treat nil as an empty suggestion.
func parsePlaybookAdvisorResponse(text string, matchedScanners []string, availableScanners []string) []string {
	// Extract JSON object from response (Claude may wrap it in markdown fences).
	start := strings.Index(text, "{")
	end := strings.LastIndex(text, "}")
	if start == -1 || end <= start {
		return nil
	}

	var resp playbookAdvisorResponse
	if err := json.Unmarshal([]byte(text[start:end+1]), &resp); err != nil {
		return nil
	}

	// Build lookup sets for fast membership checks.
	alreadyRunning := make(map[string]bool, len(matchedScanners))
	for _, s := range matchedScanners {
		alreadyRunning[strings.TrimSpace(s)] = true
	}
	available := make(map[string]bool, len(availableScanners))
	for _, s := range availableScanners {
		available[strings.TrimSpace(s)] = true
	}

	seen := make(map[string]bool)
	var result []string

	for _, s := range resp.Scanners {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if alreadyRunning[s] {
			continue // already scheduled
		}
		if !available[s] {
			continue // not in the allowed list
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		result = append(result, s)

		if len(result) >= playbookAdvisorMaxSugg {
			break
		}
	}

	return result
}

// callPlaybookAdvisor sends the prompt to Claude and returns the raw text response.
func (a *PlaybookAdvisor) callPlaybookAdvisor(ctx context.Context, prompt string) (string, error) {
	body, err := json.Marshal(claudeRequest{
		Model:     a.model,
		MaxTokens: playbookAdvisorMaxTokens,
		Messages:  []claudeMessage{{Role: "user", Content: prompt}},
	})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.apiURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", a.apiKey)
	req.Header.Set("anthropic-version", apiVersion)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Claude API HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}

	var cr claudeResponse
	if err := json.Unmarshal(data, &cr); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}
	if cr.Error != nil {
		return "", fmt.Errorf("API error: %s", cr.Error.Message)
	}
	if len(cr.Content) == 0 {
		return "", fmt.Errorf("empty response")
	}
	return cr.Content[0].Text, nil
}
