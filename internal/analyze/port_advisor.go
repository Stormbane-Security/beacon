// Package analyze — PortAdvisor uses Claude to suggest additional ports to probe
// on specific assets after the initial scan round completes.
//
// When the initial scan finds signals (e.g. "Kubernetes API on 6443", "Java app
// with Spring headers", "banner says 'JBoss'"), the port advisor asks Claude which
// additional non-standard ports are likely to be open and worth probing on each
// specific asset. This supplements the static port lists with intelligence-driven
// targeting.
//
// Design constraints:
//   - Uses claude-haiku for speed and cost (runs during an active scan)
//   - 256 max output tokens — enough for a list of ~15 ports + brief reasoning
//   - Hard cap: 20 additional ports total per asset
//   - Only suggests ports not already in the initial scan list
//   - Skips silently if apiKey is empty or no compelling signals found
package analyze

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	portAdvisorModel     = "claude-haiku-4-5-20251001"
	portAdvisorMaxTokens = 256
	portAdvisorMaxPorts  = 20
)

// PortHint summarises what we know about an asset after the initial scan.
type PortHint struct {
	Hostname    string
	OpenPorts   []string // already-found ports, e.g. ["80/http","6443/k8s-api"]
	TechStack   []string // detected technologies, e.g. ["Spring Boot 3.1","Java 17"]
	KeyFindings []string // high/critical finding titles
	Banner      string   // any raw banner text (SSH version, HTTP Server header, etc.)
}

// PortAdvisor recommends additional ports to probe after initial findings are known.
type PortAdvisor struct {
	apiKey     string
	apiURL     string
	model      string
	httpClient *http.Client
}

// NewPortAdvisor creates a PortAdvisor.
// Returns nil if apiKey is empty — callers must nil-check before use.
func NewPortAdvisor(apiKey string) *PortAdvisor {
	if apiKey == "" {
		return nil
	}
	return &PortAdvisor{
		apiKey:     apiKey,
		apiURL:     apiURL,
		model:      portAdvisorModel,
		httpClient: &http.Client{Timeout: 90 * time.Second},
	}
}

// SuggestPorts asks Claude which additional port numbers to probe on the given asset
// based on what the initial scan found. Returns a deduplicated list of port numbers
// not already present in hint.OpenPorts (up to portAdvisorMaxPorts).
func (a *PortAdvisor) SuggestPorts(ctx context.Context, hint PortHint, alreadyScanned map[int]bool) ([]int, error) {
	if len(hint.TechStack) == 0 && len(hint.KeyFindings) == 0 && hint.Banner == "" {
		return nil, nil // no signal — don't waste an API call
	}

	prompt := buildPortPrompt(hint)
	suggested, err := a.callClaude(ctx, prompt)
	if err != nil {
		return nil, err
	}

	// Deduplicate against already-scanned ports.
	var out []int
	seen := make(map[int]bool)
	for _, p := range suggested {
		if alreadyScanned[p] || seen[p] || p < 1 || p > 65535 {
			continue
		}
		seen[p] = true
		out = append(out, p)
		if len(out) >= portAdvisorMaxPorts {
			break
		}
	}
	return out, nil
}

// buildPortPrompt constructs the prompt for port suggestion.
func buildPortPrompt(hint PortHint) string {
	var sb bytes.Buffer
	sb.WriteString("You are a penetration tester's port scanner. ")
	sb.WriteString("Given what we already know about a target, suggest additional TCP ports to probe.\n\n")
	sb.WriteString("Target: " + hint.Hostname + "\n")

	if len(hint.OpenPorts) > 0 {
		sb.WriteString("Already-open ports: ")
		for i, p := range hint.OpenPorts {
			if i > 0 {
				sb.WriteString(", ")
			}
			sb.WriteString(p)
		}
		sb.WriteString("\n")
	}

	if len(hint.TechStack) > 0 {
		sb.WriteString("Detected tech: ")
		for i, t := range hint.TechStack {
			if i > 0 {
				sb.WriteString(", ")
			}
			sb.WriteString(t)
		}
		sb.WriteString("\n")
	}

	if len(hint.KeyFindings) > 0 {
		sb.WriteString("Key findings:\n")
		for _, f := range hint.KeyFindings {
			sb.WriteString("  - " + f + "\n")
		}
	}

	if hint.Banner != "" {
		sb.WriteString("Banner: " + hint.Banner + "\n")
	}

	sb.WriteString(`
Based on the above intelligence, return ONLY a JSON array of integer port numbers to probe next.
Include ports likely to be open given the tech stack and findings.
Do not include ports already listed as open.
Limit to the 10 most valuable ports.
Example: [8080, 8443, 4848, 9990]

Return ONLY the JSON array, no other text.`)

	return sb.String()
}

// callClaude sends the prompt and returns a list of suggested port numbers.
func (a *PortAdvisor) callClaude(ctx context.Context, prompt string) ([]int, error) {
	body, _ := json.Marshal(map[string]any{
		"model":      a.model,
		"max_tokens": portAdvisorMaxTokens,
		"messages": []map[string]any{
			{"role": "user", "content": prompt},
		},
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.apiURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", a.apiKey)
	req.Header.Set("anthropic-version", apiVersion)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("Claude API HTTP %d: %s", resp.StatusCode, string(b))
	}

	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	if len(result.Content) == 0 {
		return nil, nil
	}

	text := result.Content[0].Text
	// Extract JSON array from response (may have surrounding whitespace/text).
	start := bytes.IndexByte([]byte(text), '[')
	end := bytes.LastIndexByte([]byte(text), ']')
	if start < 0 || end <= start {
		return nil, nil
	}

	var ports []int
	if err := json.Unmarshal([]byte(text[start:end+1]), &ports); err != nil {
		return nil, nil // unparseable response — skip silently
	}
	return ports, nil
}
