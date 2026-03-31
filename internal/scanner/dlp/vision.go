package dlp

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

const (
	visionModel   = "claude-haiku-4-5-20251001" // fast, cheap, multimodal
	visionAPIURL  = "https://api.anthropic.com/v1/messages"
	visionAPIVer  = "2023-06-01"
	visionMaxToks = 1024
)

// visionPrompt instructs Claude to look for sensitive data visible on screen.
const visionPrompt = `Analyze this screenshot of a web page for exposed sensitive data.

Look specifically for:
- Personal identifiable information: names with contact details, SSNs, passport/ID numbers, dates of birth
- Financial data: credit card numbers, bank account numbers, financial statements
- Credentials: usernames + passwords visible together, API keys, tokens, private keys
- Medical records or health information
- Large lists of user data (emails, phone numbers, addresses)
- Internal/confidential documents rendered in the browser
- Admin panels showing raw database content

Respond ONLY with a JSON object — no surrounding text:
{
  "sensitive_data_found": true | false,
  "findings": [
    {
      "type": "<category>",
      "description": "<one sentence describing what is visible and why it's a concern>",
      "severity": "critical" | "high" | "medium"
    }
  ]
}

If nothing sensitive is found, respond with: {"sensitive_data_found": false, "findings": []}`

// visionRequest is the Anthropic Messages API request with multimodal content.
type visionRequest struct {
	Model     string           `json:"model"`
	MaxTokens int              `json:"max_tokens"`
	Messages  []visionMessage  `json:"messages"`
}

type visionMessage struct {
	Role    string         `json:"role"`
	Content []contentBlock `json:"content"`
}

type contentBlock struct {
	Type   string        `json:"type"`
	Source *imageSource  `json:"source,omitempty"` // for type="image"
	Text   string        `json:"text,omitempty"`   // for type="text"
}

type imageSource struct {
	Type      string `json:"type"`       // "base64"
	MediaType string `json:"media_type"` // "image/png"
	Data      string `json:"data"`       // raw base64 (no data URI prefix)
}

type visionResponse struct {
	Content []struct {
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// AnalyzeScreenshots inspects any screenshot findings in the provided list using
// Claude Vision, returning additional DLP findings for anything sensitive detected.
// Returns nil if apiKey is empty or no screenshot findings are present.
func AnalyzeScreenshots(ctx context.Context, scanFindings []finding.Finding, apiKey string) []finding.Finding {
	if apiKey == "" {
		return nil
	}

	var dlpFindings []finding.Finding
	for _, f := range scanFindings {
		if f.CheckID != finding.CheckAssetScreenshot {
			continue
		}
		b64, ok := f.Evidence["image_b64"].(string)
		if !ok || b64 == "" {
			continue
		}
		vf, err := analyzeImage(ctx, f.Asset, b64, apiKey)
		if err != nil {
			continue // Vision failure is non-fatal
		}
		dlpFindings = append(dlpFindings, vf...)
	}
	return dlpFindings
}

func analyzeImage(ctx context.Context, asset, dataURI, apiKey string) ([]finding.Finding, error) {
	// Strip "data:image/png;base64," prefix if present.
	rawB64 := dataURI
	if idx := strings.Index(dataURI, ","); idx != -1 {
		rawB64 = dataURI[idx+1:]
	}

	reqBody, err := json.Marshal(visionRequest{
		Model:     visionModel,
		MaxTokens: visionMaxToks,
		Messages: []visionMessage{{
			Role: "user",
			Content: []contentBlock{
				{
					Type: "image",
					Source: &imageSource{
						Type:      "base64",
						MediaType: "image/png",
						Data:      rawB64,
					},
				},
				{Type: "text", Text: visionPrompt},
			},
		}},
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, visionAPIURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", visionAPIVer)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB cap
	if err != nil {
		return nil, err
	}

	var vr visionResponse
	if err := json.Unmarshal(data, &vr); err != nil {
		return nil, fmt.Errorf("parse vision response: %w", err)
	}
	if vr.Error != nil {
		return nil, fmt.Errorf("vision API error: %s", vr.Error.Message)
	}
	if len(vr.Content) == 0 {
		return nil, fmt.Errorf("empty vision response")
	}

	return parseVisionFindings(asset, vr.Content[0].Text), nil
}

func parseVisionFindings(asset, text string) []finding.Finding {
	// Extract JSON from the response (Claude sometimes adds a code fence).
	start := strings.Index(text, "{")
	end := strings.LastIndex(text, "}")
	if start == -1 || end <= start {
		return nil
	}

	var result struct {
		SensitiveDataFound bool `json:"sensitive_data_found"`
		Findings           []struct {
			Type        string `json:"type"`
			Description string `json:"description"`
			Severity    string `json:"severity"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(text[start:end+1]), &result); err != nil {
		return nil
	}
	if !result.SensitiveDataFound || len(result.Findings) == 0 {
		return nil
	}

	now := time.Now()
	var out []finding.Finding
	for _, vf := range result.Findings {
		sev := severityFromString(vf.Severity)
		out = append(out, finding.Finding{
			CheckID:  finding.CheckDLPVision,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: sev,
			Title:    fmt.Sprintf("Sensitive data visible on %s: %s", asset, vf.Type),
			Description: fmt.Sprintf(
				"Claude Vision analysis of the screenshot detected sensitive content: %s",
				vf.Description),
			Asset:        asset,
			Evidence:     map[string]any{"type": vf.Type, "detected_by": "claude-vision"},
			DiscoveredAt: now,
		})
	}
	return out
}

// identifyPrompt asks Claude to identify the software/service visible in a
// screenshot of an unmatched asset. Used when no playbook matched the asset.
const identifyPrompt = `You are analyzing a screenshot of a web application that our security scanner
could not automatically identify. Please identify what software or service is running.

Look for:
- Software name, version, and edition visible in titles, footers, or headers
- Login form branding (logo, text, color scheme)
- Admin panel type (Grafana, Jenkins, Kibana, phpMyAdmin, etc.)
- Framework indicators (error pages, routing URLs, page structure)
- Technology stack clues (language, framework, platform)
- Any error messages revealing software versions or paths
- Default pages (e.g. "Welcome to nginx!", "Apache2 Default Page")

Respond ONLY with a JSON object:
{
  "identified": true | false,
  "software": "<software name or empty string>",
  "version": "<version string or empty string>",
  "category": "<web-app|admin-panel|monitoring|database-ui|ci-cd|cms|api|framework-default|unknown>",
  "confidence": "high" | "medium" | "low",
  "reasoning": "<one sentence explaining what visual clues led to this identification>",
  "security_notes": "<any visible security concerns: default creds warning, exposed sensitive data, debug info, etc.>"
}

If the screenshot is blank, an error page, or completely unidentifiable, set "identified": false.`

// IdentifyServiceFromScreenshot uses Claude Vision to identify what software is
// running on an unmatched asset. Returns a finding describing the identified service,
// or nil if the service could not be identified or no screenshot is available.
//
// This runs after the normal scan pipeline for assets where no targeted playbook
// matched — giving the AI a chance to identify the service visually so the batch
// analyzer can suggest a new playbook.
func IdentifyServiceFromScreenshot(ctx context.Context, asset string, scanFindings []finding.Finding, apiKey string) *finding.Finding {
	if apiKey == "" {
		return nil
	}

	// Find the screenshot finding for this asset.
	var b64 string
	for _, f := range scanFindings {
		if f.CheckID == finding.CheckAssetScreenshot && f.Asset == asset {
			if v, ok := f.Evidence["image_b64"].(string); ok && v != "" {
				b64 = v
				break
			}
		}
	}
	if b64 == "" {
		return nil
	}

	rawB64 := b64
	if idx := strings.Index(b64, ","); idx != -1 {
		rawB64 = b64[idx+1:]
	}

	reqBody, err := json.Marshal(visionRequest{
		Model:     visionModel,
		MaxTokens: 512,
		Messages: []visionMessage{{
			Role: "user",
			Content: []contentBlock{
				{
					Type: "image",
					Source: &imageSource{
						Type:      "base64",
						MediaType: "image/png",
						Data:      rawB64,
					},
				},
				{Type: "text", Text: identifyPrompt},
			},
		}},
	})
	if err != nil {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, visionAPIURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", visionAPIVer)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var vr visionResponse
	if err := json.Unmarshal(data, &vr); err != nil || len(vr.Content) == 0 {
		return nil
	}

	text := vr.Content[0].Text
	start := strings.Index(text, "{")
	end := strings.LastIndex(text, "}")
	if start == -1 || end <= start {
		return nil
	}

	var id struct {
		Identified    bool   `json:"identified"`
		Software      string `json:"software"`
		Version       string `json:"version"`
		Category      string `json:"category"`
		Confidence    string `json:"confidence"`
		Reasoning     string `json:"reasoning"`
		SecurityNotes string `json:"security_notes"`
	}
	if err := json.Unmarshal([]byte(text[start:end+1]), &id); err != nil || !id.Identified {
		return nil
	}

	title := fmt.Sprintf("Vision identified: %s on %s", id.Software, asset)
	if id.Version != "" {
		title = fmt.Sprintf("Vision identified: %s %s on %s", id.Software, id.Version, asset)
	}

	desc := fmt.Sprintf(
		"Claude Vision analyzed the screenshot of %s and identified it as %s (category: %s, confidence: %s). "+
			"Reasoning: %s",
		asset, id.Software, id.Category, id.Confidence, id.Reasoning,
	)
	if id.SecurityNotes != "" {
		desc += " Security notes: " + id.SecurityNotes
	}

	f := finding.Finding{
		CheckID:  finding.CheckVisionServiceID,
		Module:   "surface",
		Scanner:  "dlp-vision",
		Severity: finding.SeverityInfo,
		Asset:    asset,
		Title:    title,
		Description: desc,
		Evidence: map[string]any{
			"software":       id.Software,
			"version":        id.Version,
			"category":       id.Category,
			"confidence":     id.Confidence,
			"security_notes": id.SecurityNotes,
		},
		DiscoveredAt: time.Now(),
	}
	return &f
}

func severityFromString(s string) finding.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return finding.SeverityCritical
	case "high":
		return finding.SeverityHigh
	case "medium":
		return finding.SeverityMedium
	default:
		return finding.SeverityHigh
	}
}
