// Package aimodelsec probes model-serving endpoints for model theft,
// system prompt extraction, and rate-limit bypass risks.
//
// It detects:
//   - Model weights downloadable without authentication (Ollama, HuggingFace TGI)
//   - System prompt extraction via /api/show (Ollama) or model introspection
//   - Missing rate limiting on inference endpoints
//
// This scanner is surface-mode safe — it sends only read-only GET/POST requests
// with no exploit payloads. POST bodies are minimal model metadata queries.
package aimodelsec

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scan"
)

func init() {
	scan.RegisterWithCheckDecls(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	},
		scan.Check(finding.CheckAIModelDownloadable, finding.SeverityHigh, finding.ModeSurface),
		scan.Check(finding.CheckAIPromptExtraction, finding.SeverityHigh, finding.ModeSurface),
		scan.Check(finding.CheckAINoRateLimit, finding.SeverityMedium, finding.ModeSurface),
	)
}

const scannerName = "aimodelsec"

// modelEndpoint describes a model-serving endpoint to probe.
type modelEndpoint struct {
	path     string
	method   string
	provider string
	body     string // optional POST body
}

// modelListEndpoints returns the list of model-listing endpoints to probe.
var modelListEndpoints = []modelEndpoint{
	{"/v1/models", "GET", "openai-compat", ""},
	{"/api/tags", "GET", "ollama", ""},
	{"/models", "GET", "huggingface-tgi", ""},
}

// Scanner probes model-serving endpoints for security issues.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, _ module.ScanType) ([]finding.Finding, error) {
	client := &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	scheme := detectScheme(ctx, client, asset)
	base := scheme + "://" + asset

	var findings []finding.Finding

	// Phase 1: Probe model listing endpoints for unauthenticated access.
	for _, ep := range modelListEndpoints {
		result := probeModelList(ctx, client, base+ep.path, ep.method, ep.provider)
		if result == nil {
			continue
		}

		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckAIModelDownloadable,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Title:    fmt.Sprintf("AI model list accessible without auth: %s (%s)", base+ep.path, ep.provider),
			Description: fmt.Sprintf(
				"The model-serving endpoint at %s returned a model listing without authentication. "+
					"Provider: %s. Models found: %s. "+
					"Unauthenticated model enumeration reveals deployed model names, sizes, and capabilities. "+
					"On Ollama instances this also enables model weight download via /api/pull, "+
					"allowing complete model theft.",
				base+ep.path, ep.provider, strings.Join(result.models, ", ")),
			Asset:        asset,
			ProofCommand: fmt.Sprintf("curl -s %s", base+ep.path),
			Evidence: map[string]any{
				"url":      base + ep.path,
				"provider": ep.provider,
				"models":   result.models,
				"no_auth":  true,
			},
			DiscoveredAt: time.Now(),
		})
	}

	// Phase 2: Ollama-specific system prompt extraction via /api/show.
	if f := probeOllamaShow(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	// Phase 3: Rate-limit check — send 5 rapid requests to /v1/models.
	if f := checkRateLimit(ctx, client, base, asset); f != nil {
		findings = append(findings, *f)
	}

	return findings, nil
}

type modelListResult struct {
	models []string
}

func probeModelList(ctx context.Context, client *http.Client, url, method, provider string) *modelListResult {
	var body io.Reader
	if method == "POST" {
		body = strings.NewReader("{}")
	}

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/json")
	if method == "POST" {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	bodyStr := string(respBody)

	// Reject HTML responses — a web app returning 200 on any path is not a model API.
	trimmed := strings.TrimSpace(bodyStr)
	if strings.HasPrefix(trimmed, "<") || strings.HasPrefix(trimmed, "<!") {
		return nil
	}

	var models []string

	switch provider {
	case "ollama":
		// Ollama /api/tags: {"models":[{"name":"llama2",...}]}
		var ollamaResp struct {
			Models []struct {
				Name string `json:"name"`
			} `json:"models"`
		}
		if json.Unmarshal(respBody, &ollamaResp) == nil && len(ollamaResp.Models) > 0 {
			for _, m := range ollamaResp.Models {
				models = append(models, m.Name)
			}
		}
	case "openai-compat":
		// OpenAI /v1/models: {"data":[{"id":"model-name","object":"model"}]}
		var oaiResp struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		if json.Unmarshal(respBody, &oaiResp) == nil && len(oaiResp.Data) > 0 {
			for _, m := range oaiResp.Data {
				models = append(models, m.ID)
			}
		}
	case "huggingface-tgi":
		// HuggingFace TGI /models: array of model objects or similar.
		// Also matches vLLM and other OpenAI-compatible servers.
		var tgiResp []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if json.Unmarshal(respBody, &tgiResp) == nil && len(tgiResp) > 0 {
			for _, m := range tgiResp {
				name := m.ID
				if name == "" {
					name = m.Name
				}
				if name != "" {
					models = append(models, name)
				}
			}
		}
		// Also try the OpenAI-compat format in case it's a wrapper.
		if len(models) == 0 {
			var oaiResp struct {
				Data []struct {
					ID string `json:"id"`
				} `json:"data"`
			}
			if json.Unmarshal(respBody, &oaiResp) == nil && len(oaiResp.Data) > 0 {
				for _, m := range oaiResp.Data {
					models = append(models, m.ID)
				}
			}
		}
	}

	if len(models) == 0 {
		return nil
	}

	return &modelListResult{models: models}
}

// probeOllamaShow attempts system prompt extraction via Ollama's /api/show endpoint.
func probeOllamaShow(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	// First check if this is an Ollama instance by probing /api/tags.
	tagsReq, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/tags", nil)
	if err != nil {
		return nil
	}
	tagsResp, err := client.Do(tagsReq)
	if err != nil {
		return nil
	}
	tagsBody, _ := io.ReadAll(io.LimitReader(tagsResp.Body, 4096))
	_ = tagsResp.Body.Close()

	if tagsResp.StatusCode != http.StatusOK {
		return nil
	}

	var ollamaResp struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if json.Unmarshal(tagsBody, &ollamaResp) != nil || len(ollamaResp.Models) == 0 {
		return nil
	}

	// Try /api/show with the first available model to extract system prompt.
	modelName := ollamaResp.Models[0].Name
	showBody := fmt.Sprintf(`{"name":"%s"}`, modelName)
	showReq, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/show", strings.NewReader(showBody))
	if err != nil {
		return nil
	}
	showReq.Header.Set("Content-Type", "application/json")

	showResp, err := client.Do(showReq)
	if err != nil {
		return nil
	}
	respBody, _ := io.ReadAll(io.LimitReader(showResp.Body, 16384))
	_ = showResp.Body.Close()

	if showResp.StatusCode != http.StatusOK {
		return nil
	}

	bodyStr := string(respBody)
	// Check for system prompt in the Modelfile or template field.
	hasSystemPrompt := strings.Contains(bodyStr, "SYSTEM") ||
		strings.Contains(bodyStr, "system") ||
		strings.Contains(bodyStr, "template")

	if !hasSystemPrompt {
		return nil
	}

	snippet := bodyStr
	if len(snippet) > 300 {
		snippet = snippet[:300] + "..."
	}

	return &finding.Finding{
		CheckID:  finding.CheckAIPromptExtraction,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Title:    fmt.Sprintf("System prompt extractable via /api/show for model %s", modelName),
		Description: fmt.Sprintf(
			"The Ollama /api/show endpoint at %s returned model configuration including the system "+
				"prompt/template for model %q without authentication. System prompts often contain "+
				"application logic, safety guardrails, and instructions that should not be disclosed. "+
				"An attacker can use extracted system prompts to craft more effective prompt injection attacks.",
			base+"/api/show", modelName),
		Asset:        asset,
		ProofCommand: fmt.Sprintf(`curl -s -X POST %s/api/show -d '{"name":"%s"}' | python3 -m json.tool | head -40`, base, modelName),
		Evidence: map[string]any{
			"url":      base + "/api/show",
			"model":    modelName,
			"snippet":  snippet,
			"provider": "ollama",
		},
		DiscoveredAt: time.Now(),
	}
}

// checkRateLimit sends 5 rapid requests to /v1/models and checks if any are
// rate-limited (429). If all succeed, the endpoint lacks rate limiting.
func checkRateLimit(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	url := base + "/v1/models"

	// First, verify the endpoint exists.
	testReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	testResp, err := client.Do(testReq)
	if err != nil {
		return nil
	}
	_ = testResp.Body.Close()
	if testResp.StatusCode == http.StatusNotFound || testResp.StatusCode == http.StatusMethodNotAllowed {
		return nil
	}

	// Send 5 rapid requests.
	rateLimited := false
	successCount := 0
	for i := 0; i < 5; i++ {
		if ctx.Err() != nil {
			return nil
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			rateLimited = true
			break
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			successCount++
		}
	}

	if rateLimited || successCount < 5 {
		return nil
	}

	return &finding.Finding{
		CheckID:  finding.CheckAINoRateLimit,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityMedium,
		Title:    fmt.Sprintf("AI model endpoint lacks rate limiting: %s", url),
		Description: fmt.Sprintf(
			"The AI model-serving endpoint at %s accepted 5 rapid consecutive requests without "+
				"returning HTTP 429 (Too Many Requests). Without rate limiting, an attacker can "+
				"abuse the model for unlimited inference, denial-of-wallet attacks (running up "+
				"compute costs), or high-volume data extraction.",
			url),
		Asset:        asset,
		ProofCommand: fmt.Sprintf("for i in $(seq 1 10); do curl -s -o /dev/null -w '%%{http_code}\\n' %s; done", url),
		Evidence: map[string]any{
			"url":             url,
			"requests_sent":   5,
			"all_succeeded":   true,
			"rate_limit_seen": false,
		},
		DiscoveredAt: time.Now(),
	}
}

func detectScheme(ctx context.Context, client *http.Client, asset string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+asset, nil)
	if err != nil {
		return "http"
	}
	resp, err := client.Do(req)
	if err != nil {
		return "http"
	}
	_ = resp.Body.Close()
	return "https"
}
