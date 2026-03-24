// Package profiler uses Claude to build a TargetProfile from fingerprint evidence
// collected during the surface scan phase.
//
// The profile:
//   - Summarises the likely tech stack and architecture
//   - Ranks scanner modules by probability of finding real vulnerabilities
//   - Suggests evasion strategies (timing, WAF behaviour, proxy use)
//   - Highlights the highest-risk attack surface areas with brief justification
//
// This is called after the classify/fingerprint phase and before the deep scan phase,
// so Claude has a complete evidence picture. It does NOT replace deterministic scanners —
// it supplements them by interpreting ambiguous or combined signals.
//
// Usage:
//
//	profile, err := profiler.Profile(ctx, apiKey, model, &evidence)
//	if err != nil { /* fall back to static playbook matching */ }
//	// merge profile.Modules into the run plan
package profiler

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
	"github.com/stormbane/beacon/internal/playbook"
)

const defaultModel = "claude-sonnet-4-6"

// TargetProfile is Claude's assessment of a scanned target.
type TargetProfile struct {
	// Summary is a 2-3 sentence description of the likely tech stack and architecture.
	Summary string `json:"summary"`

	// Modules is a ranked list of scanner names Claude recommends for this target,
	// most-likely-to-find-vulnerabilities first.
	Modules []string `json:"modules"`

	// EvasionTips are actionable suggestions for avoiding detection or rate limiting
	// (e.g. "slow down requests — Cloudflare rate limiting detected").
	EvasionTips []string `json:"evasion_tips"`

	// RiskAreas maps attack surface area names to a brief justification.
	// e.g. {"auth": "Auth0 misconfiguration likely given OIDC endpoints observed"}.
	RiskAreas map[string]string `json:"risk_areas"`
}

// Profile sends the fingerprint evidence to Claude and returns a TargetProfile.
// Returns an error if the API call fails or the response cannot be parsed.
// Callers should treat errors as non-fatal and fall back to static playbook matching.
func Profile(ctx context.Context, apiKey, model string, ev *playbook.Evidence) (*TargetProfile, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("profiler: no API key")
	}
	if model == "" {
		model = defaultModel
	}

	prompt := buildPrompt(ev)

	reqBody, err := json.Marshal(map[string]any{
		"model":      model,
		"max_tokens": 1024,
		"messages": []map[string]any{
			{"role": "user", "content": prompt},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("profiler: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.anthropic.com/v1/messages", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("profiler: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("profiler: API call: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	if err != nil {
		return nil, fmt.Errorf("profiler: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("profiler: API returned %d: %s", resp.StatusCode, body)
	}

	text, err := extractText(body)
	if err != nil {
		return nil, fmt.Errorf("profiler: extract text: %w", err)
	}

	profile, err := parseProfile(text)
	if err != nil {
		return nil, fmt.Errorf("profiler: parse profile: %w", err)
	}
	return profile, nil
}

// ProfileToFinding converts a TargetProfile into a Finding for storage.
func ProfileToFinding(asset string, profile *TargetProfile) finding.Finding {
	evidence := map[string]any{
		"summary":      profile.Summary,
		"modules":      strings.Join(profile.Modules, ", "),
		"evasion_tips": strings.Join(profile.EvasionTips, "; "),
	}
	for k, v := range profile.RiskAreas {
		evidence["risk_"+k] = v
	}
	return finding.Finding{
		CheckID:  finding.CheckAdaptiveReconProfile,
		Severity: finding.SeverityInfo,
		Asset:    asset,
		Title:       "AI Target Profile",
		Description: profile.Summary,
		Evidence: evidence,
	}
}

// buildPrompt constructs the Claude prompt from Evidence.
func buildPrompt(ev *playbook.Evidence) string {
	var sb strings.Builder
	sb.WriteString("You are a security scanner assistant. Given this fingerprint of a web target, identify:\n")
	sb.WriteString("1. The most likely tech stack and architecture (2-3 sentences)\n")
	sb.WriteString("2. The top 5 scanner modules most likely to find real vulnerabilities, ranked by probability\n")
	sb.WriteString("3. Any evasion considerations (rate limiting, WAF vendor, CDN behaviour)\n")
	sb.WriteString("4. The highest-risk attack surface areas with brief justification\n\n")
	sb.WriteString("Fingerprint:\n")

	writeField(&sb, "Cloud provider", ev.CloudProvider)
	writeField(&sb, "Framework", ev.Framework)
	writeField(&sb, "Auth system", ev.AuthSystem)
	writeField(&sb, "Auth scheme", ev.AuthScheme)
	writeField(&sb, "Proxy type", ev.ProxyType)
	if ev.ServiceVersions != nil {
		if ws, ok := ev.ServiceVersions["web_server"]; ok {
			writeField(&sb, "Web server", ws)
		}
	}
	if len(ev.CertSANs) > 0 {
		writeField(&sb, "TLS cert SANs", strings.Join(ev.CertSANs[:min(len(ev.CertSANs), 5)], ", "))
	}
	if len(ev.RespondingPaths) > 0 {
		writeField(&sb, "Responding paths", strings.Join(ev.RespondingPaths[:min(len(ev.RespondingPaths), 10)], ", "))
	}
	if len(ev.AIEndpoints) > 0 {
		writeField(&sb, "AI endpoints", strings.Join(ev.AIEndpoints, ", "))
	}
	writeField(&sb, "LLM provider", ev.LLMProvider)
	if len(ev.Web3Signals) > 0 {
		writeField(&sb, "Web3 signals", strings.Join(ev.Web3Signals, ", "))
	}
	if len(ev.VendorSignals) > 0 {
		writeField(&sb, "Third-party vendors", strings.Join(ev.VendorSignals, ", "))
	}
	writeField(&sb, "MX provider", ev.MXProvider)
	if len(ev.TXTRecords) > 0 {
		writeField(&sb, "TXT records", strings.Join(ev.TXTRecords[:min(len(ev.TXTRecords), 3)], "; "))
	}

	sb.WriteString("\nAvailable scanner modules: cors, hostheader, jwt, oauth, ssti, crlf, ssrf, hpp,\n")
	sb.WriteString("protopollution, aillm, saml, iam, authfuzz, xxe, deserial, fileupload, wafdetect,\n")
	sb.WriteString("vhost, websocket, ratelimit, tls, portscan, exposedfiles, graphql, webcontent,\n")
	sb.WriteString("dlp, nmap, log4shell, nginx, web3detect, aidetect.\n\n")
	sb.WriteString(`Respond ONLY with valid JSON, no markdown fences:
{"summary":"...","modules":["scanner1","scanner2",...],"evasion_tips":["..."],"risk_areas":{"area":"reason"}}`)

	return sb.String()
}

func writeField(sb *strings.Builder, label, value string) {
	if value == "" {
		return
	}
	sb.WriteString("- ")
	sb.WriteString(label)
	sb.WriteString(": ")
	sb.WriteString(value)
	sb.WriteString("\n")
}

// extractText pulls the text content from a Claude API response.
func extractText(body []byte) (string, error) {
	var resp struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", err
	}
	for _, c := range resp.Content {
		if c.Type == "text" && c.Text != "" {
			return c.Text, nil
		}
	}
	return "", fmt.Errorf("no text content in response")
}

// parseProfile parses a JSON TargetProfile from Claude's response text.
// It is tolerant of leading/trailing whitespace and extracts the JSON object
// even when surrounded by markdown fences.
func parseProfile(text string) (*TargetProfile, error) {
	text = strings.TrimSpace(text)
	// Strip markdown fences if present.
	if strings.HasPrefix(text, "```") {
		if i := strings.Index(text, "\n"); i >= 0 {
			text = text[i+1:]
		}
		text = strings.TrimSuffix(text, "```")
		text = strings.TrimSpace(text)
	}
	// Find the outermost JSON object.
	start := strings.Index(text, "{")
	end := strings.LastIndex(text, "}")
	if start < 0 || end <= start {
		return nil, fmt.Errorf("no JSON object found in response")
	}
	text = text[start : end+1]

	var profile TargetProfile
	if err := json.Unmarshal([]byte(text), &profile); err != nil {
		return nil, err
	}
	return &profile, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
