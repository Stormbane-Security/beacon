// Package aidetect passively discovers AI/LLM-powered endpoints.
// It probes common chat and inference API paths, inspects response headers
// and bodies for LLM provider signatures, and detects server-sent event
// streaming patterns characteristic of token-by-token LLM output.
//
// Findings are Info/Medium severity; the primary output is structured evidence
// (AIEndpoints, LLMProvider, HasAISSE) that triggers the ai_llm playbook for
// deeper active testing in deep mode.
//
// This scanner is surface-mode safe — no prompt payloads are sent.
// All probes are plain HTTP GETs or minimal POST requests with no injected content.
package aidetect

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
	"github.com/stormbane/beacon/internal/playbook"
)

const scannerName = "aidetect"

// candidatePaths are common LLM/AI endpoint patterns to probe.
var candidatePaths = []struct {
	path   string
	method string // GET or POST
}{
	// OpenAI-compatible API paths
	{"/v1/chat/completions", "POST"},
	{"/v1/completions", "POST"},
	{"/v1/models", "GET"},
	{"/v1/embeddings", "POST"},
	// Azure OpenAI path patterns (internal proxies / APIM backends)
	{"/openai/v1/chat/completions", "POST"},
	{"/openai/deployments/chat/completions", "POST"},
	{"/openai/deployments/gpt-4/chat/completions", "POST"},
	{"/openai/deployments/gpt-35-turbo/chat/completions", "POST"},
	{"/api/openai/v1/chat/completions", "POST"},
	{"/azure/openai/chat/completions", "POST"},
	// AWS Bedrock proxy patterns (LiteLLM, internal gateway)
	{"/bedrock/invoke", "POST"},
	{"/api/bedrock/chat", "POST"},
	{"/aws/bedrock/converse", "POST"},
	// Google Vertex AI / Gemini proxy patterns
	{"/gemini/generateContent", "POST"},
	{"/api/gemini/chat", "POST"},
	{"/vertex/chat/completions", "POST"},
	{"/api/vertex/generate", "POST"},
	// Generic chat routes
	{"/chat", "GET"},
	{"/chat/completions", "POST"},
	{"/api/chat", "POST"},
	{"/api/chat/completions", "POST"},
	{"/api/v1/chat", "POST"},
	// Inference / generation
	{"/generate", "POST"},
	{"/inference", "POST"},
	{"/infer", "POST"},
	{"/predict", "POST"},
	{"/api/generate", "POST"},
	{"/api/v1/generate", "POST"},
	{"/api/inference", "POST"},
	// Common assistant / chatbot routes
	{"/assistant", "GET"},
	{"/ai", "GET"},
	{"/llm", "GET"},
	{"/prompt", "POST"},
	// LangChain / agent frameworks
	{"/api/agent", "POST"},
	{"/api/agent/invoke", "POST"},
	{"/invoke", "POST"},
	{"/run", "POST"},
	// RAG / embeddings
	{"/embed", "POST"},
	{"/embeddings", "POST"},
	{"/api/embeddings", "POST"},
	// Ollama-specific paths
	{"/api/tags", "GET"},
	{"/api/ps", "GET"},
	// Hugging Face Inference API
	{"/models", "GET"},
}

// providerHeaders maps response header names to provider identifiers.
var providerHeaders = []struct {
	header   string
	provider string
}{
	{"openai-organization", "openai"},
	{"x-openai-organization", "openai"},
	{"x-ratelimit-requests-openai", "openai"},
	{"anthropic-request-id", "anthropic"},
	{"x-anthropic-request-id", "anthropic"},
	{"cf-aig-response", "workers_ai"},     // Cloudflare AI Gateway
	{"x-groq-request-id", "groq"},
	{"x-cohere-request-id", "cohere"},
	{"x-cohere-trace-id", "cohere"},
	{"x-huggingface-model", "huggingface"},
	{"x-hf-model", "huggingface"},
	{"x-lmstudio-id", "lmstudio"},
	{"x-lmstudio-version", "lmstudio"},
	{"x-vllm-model-name", "vllm"},
	{"x-vllm-request-id", "vllm"},
	{"x-ms-client-request-id", "azure_openai"},    // Azure OpenAI and Azure services
	{"x-ms-request-id", "azure_openai"},           // Azure APIM / OpenAI backend
	{"apim-request-id", "azure_openai"},           // Azure API Management gateway
	{"x-goog-request-id", "vertex_ai"},            // Google Vertex AI
	{"x-goog-api-key", "vertex_ai"},               // Gemini API key reflected (misconfigured proxy)
	{"x-amzn-requestid", "aws_bedrock"},           // AWS Bedrock (also general AWS)
	{"x-amzn-bedrock-invocation-latency", "aws_bedrock"}, // Bedrock-specific response header
	{"x-ollama-version", "ollama"},
	{"x-inference-time", "generic"},
}

// providerBodySignals are body substrings that strongly indicate LLM API responses.
var providerBodySignals = []struct {
	pattern  string
	provider string
}{
	// OpenAI
	{`"model":"gpt-`, "openai"},
	{`"object":"chat.completion"`, "openai"},
	{`"object":"text_completion"`, "openai"},
	// Anthropic
	{`"type":"content_block_delta"`, "anthropic"},
	{`"model":"claude-`, "anthropic"},
	// Ollama — specific response structure
	{`"done_reason"`, "ollama"},
	{`"total_duration"`, "ollama"},
	{`"load_duration"`, "ollama"},
	// Ollama /api/tags — model list response
	{`"models":[{"name"`, "ollama"},
	// Mistral
	{`"model":"mistral-`, "mistral"},
	{`"model":"mixtral-`, "mistral"},
	// Cohere
	{`"generations":[`, "cohere"},
	{`"generation_id"`, "cohere"},
	// Google Vertex AI / Gemini — Gemini response structure
	{`"candidates":[`, "vertex_ai"},
	{`"finishReason"`, "vertex_ai"},
	{`"safetyRatings"`, "vertex_ai"},
	{`"usageMetadata"`, "vertex_ai"},
	{`"promptTokenCount"`, "vertex_ai"},
	// Google Vertex AI model names in responses
	{`"model":"gemini-`, "vertex_ai"},
	{`"model":"text-bison`, "vertex_ai"},
	{`"model":"chat-bison`, "vertex_ai"},
	// AWS Bedrock — response body patterns
	{`"amazon-bedrock-`, "aws_bedrock"},
	{`"inputTextTokenCount"`, "aws_bedrock"},     // Titan model response
	{`"completionReason"`, "aws_bedrock"},         // Titan
	{`"outputText"`, "aws_bedrock"},               // Titan
	{`"x-amzn-bedrock-`, "aws_bedrock"},           // Bedrock metadata headers reflected
	// Hugging Face
	{`"generated_text"`, "huggingface"},
	// vLLM — model list format
	{`"owned_by":"vllm"`, "vllm"},
	// Generic OpenAI-compat signals (no specific provider identified yet)
	{`"finish_reason"`, "generic"},
	{`"choices":[`, "generic"},
	{`"usage":{"prompt_tokens"`, "generic"},
	{`"delta":{"content"`, "generic"},
	{`"done":false`, "generic"},
	{`"response":"`, "generic"},
}

// Scanner detects AI/LLM endpoints passively.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

// Run discovers LLM endpoints and returns findings. The Evidence pointer (if non-nil)
// is populated with AI signal data so the caller can trigger downstream playbooks.
// The standard scanner interface does not pass Evidence; call RunWithEvidence for that.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	return s.RunWithEvidence(ctx, asset, scanType, nil)
}

// RunWithEvidence is the extended entry point that populates ev with AI signals.
// Called by the surface module when it has an evidence pointer to fill.
func (s *Scanner) RunWithEvidence(ctx context.Context, asset string, _ module.ScanType, ev *playbook.Evidence) ([]finding.Finding, error) {
	client := &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	scheme := detectScheme(ctx, client, asset)
	base := scheme + "://" + asset

	var findings []finding.Finding

	for _, cand := range candidatePaths {
		result := probeEndpoint(ctx, client, base+cand.path, cand.method)
		if result == nil {
			continue
		}

		// Record in evidence for playbook matching.
		if ev != nil {
			ev.AIEndpoints = appendUniq(ev.AIEndpoints, cand.path)
			if ev.LLMProvider == "" && result.provider != "" {
				ev.LLMProvider = result.provider
			}
			if result.hasSSE {
				ev.HasAISSE = true
			}
			if result.hasTools {
				ev.HasAgentTools = true
			}
		}

		sev := finding.SeverityInfo
		title := fmt.Sprintf("AI/LLM endpoint accessible: %s", base+cand.path)
		desc := fmt.Sprintf(
			"An AI/LLM API endpoint was detected at %s. "+
				"Unauthenticated access to language model APIs may allow prompt injection, "+
				"data extraction, or unauthorized use of the model at the operator's expense.",
			base+cand.path)

		if result.noAuth {
			sev = finding.SeverityMedium
			title = fmt.Sprintf("Unauthenticated AI/LLM endpoint: %s", base+cand.path)
			desc = fmt.Sprintf(
				"The AI/LLM endpoint at %s returned a successful response without authentication. "+
					"Anyone can send prompts to this model, potentially leaking system context, "+
					"bypassing application intent, or incurring cost on the operator's API account.",
				base+cand.path)
		}

		checkID := finding.CheckAIEndpointExposed
		if result.hasSSE && result.noAuth {
			checkID = finding.CheckAIStreamingOpen
		}

		findings = append(findings, finding.Finding{
			CheckID:      checkID,
			Module:       "surface",
			Scanner:      scannerName,
			Severity:     sev,
			Title:        title,
			Description:  desc,
			Asset:        asset,
			ProofCommand: fmt.Sprintf("curl -si %s %s", base+cand.path, proofFlags(cand.method, cand.path)),
			Evidence: map[string]any{
				"url":      base + cand.path,
				"path":     cand.path,
				"method":   cand.method,
				"provider": result.provider,
				"no_auth":  result.noAuth,
				"has_sse":  result.hasSSE,
			},
			DiscoveredAt: time.Now(),
		})
	}

	// Check for API keys in response headers (e.g., misconfigured proxies echoing keys).
	if keyFinding := checkKeyLeak(ctx, client, base, asset); keyFinding != nil {
		findings = append(findings, *keyFinding)
	}

	// Scan page source + inline JS for provider endpoint references.
	if jsFindings := checkJSProviderLeak(ctx, client, base, asset, ev); len(jsFindings) > 0 {
		findings = append(findings, jsFindings...)
	}

	return findings, nil
}

type probeResult struct {
	provider string
	noAuth   bool // responded with 200 to a minimal LLM-style request
	hasSSE   bool // Content-Type: text/event-stream
	hasTools bool // tool_calls or function_call in body
}

func probeEndpoint(ctx context.Context, client *http.Client, url, method string) *probeResult {
	var body io.Reader
	if method == "POST" {
		// Minimal valid request body — does not inject prompts, just checks if endpoint exists.
		body = strings.NewReader(`{"model":"test","messages":[{"role":"user","content":"hi"}],"max_tokens":1}`)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil
	}
	if method == "POST" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json, text/event-stream")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	resp.Body.Close()

	// Skip 404, 405 — endpoint does not exist or method wrong.
	if resp.StatusCode == 404 || resp.StatusCode == 405 {
		return nil
	}

	result := &probeResult{}

	// Detect provider from request URL hostname (for cloud-hosted services).
	urlLower := strings.ToLower(url)
	switch {
	case strings.Contains(urlLower, "openai.azure.com"):
		result.provider = "azure_openai"
	case strings.Contains(urlLower, "api.openai.com"):
		result.provider = "openai"
	case strings.Contains(urlLower, "api.anthropic.com"):
		result.provider = "anthropic"
	case strings.Contains(urlLower, "inference.huggingface.co") ||
		strings.Contains(urlLower, "api-inference.huggingface.co"):
		result.provider = "huggingface"
	case strings.Contains(urlLower, "aiplatform.googleapis.com") ||
		strings.Contains(urlLower, "generativelanguage.googleapis.com"):
		result.provider = "vertex_ai"
	case strings.Contains(urlLower, "bedrock-runtime."):
		result.provider = "aws_bedrock"
	case strings.Contains(urlLower, "api.mistral.ai"):
		result.provider = "mistral"
	case strings.Contains(urlLower, "api.cohere.ai") ||
		strings.Contains(urlLower, "api.cohere.com"):
		result.provider = "cohere"
	case strings.Contains(urlLower, "api.groq.com"):
		result.provider = "groq"
	}

	// Detect provider from response headers (may override URL-based detection
	// when a proxy or gateway is in front).
	for _, ph := range providerHeaders {
		if resp.Header.Get(ph.header) != "" {
			if result.provider == "" {
				result.provider = ph.provider
			}
			break
		}
	}

	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	result.hasSSE = strings.Contains(ct, "text/event-stream")

	bodyStr := string(respBody)

	// Detect provider from body signals.
	if result.provider == "" {
		for _, sig := range providerBodySignals {
			if strings.Contains(bodyStr, sig.pattern) {
				result.provider = sig.provider
				break
			}
		}
	}

	// Detect tool/function-call patterns via JSON key-value structure.
	// Use the regex that requires the JSON key-value pattern to avoid matching
	// prose refusals like "I don't support \"tool_calls\"" which contain the
	// quoted string but not the JSON assignment operator followed by an array.
	result.hasTools = reToolCallsJSON.MatchString(bodyStr) ||
		strings.Contains(bodyStr, `"function_call":`) ||
		strings.Contains(bodyStr, `"tool_use":`)

	// 2xx = unauthenticated response to LLM-style request.
	result.noAuth = resp.StatusCode >= 200 && resp.StatusCode < 300

	// If no LLM signals at all (no provider header, no body signals, not 2xx),
	// this is likely a false positive — skip it.
	if result.provider == "" && !result.noAuth && !result.hasSSE {
		return nil
	}

	return result
}

// checkKeyLeak looks for LLM provider API keys accidentally echoed back in HTTP headers.
func checkKeyLeak(ctx context.Context, client *http.Client, base, asset string) *finding.Finding {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Look for key-like values in headers that should never be echoed.
	sensitiveHeaders := []string{
		"x-openai-api-key", "authorization", "x-api-key", "x-anthropic-api-key",
	}
	for _, h := range sensitiveHeaders {
		v := resp.Header.Get(h)
		if v == "" {
			continue
		}
		// Only flag if it looks like a real LLM key (sk-*, ant-*, etc.)
		lower := strings.ToLower(v)
		if strings.HasPrefix(lower, "sk-") || strings.HasPrefix(lower, "ant-") ||
			strings.HasPrefix(lower, "bearer sk-") {
			return &finding.Finding{
				CheckID:      finding.CheckAIKeyExposed,
				Module:       "surface",
				Scanner:      scannerName,
				Severity:     finding.SeverityCritical,
				Title:        "LLM provider API key exposed in HTTP response header",
				Description:  fmt.Sprintf("An LLM provider API key was found in the %q response header at %s. This key grants full API access on behalf of the account owner, enabling unauthorized model usage and potential data exposure.", h, base),
				Asset:        asset,
				ProofCommand: fmt.Sprintf("curl -sI %s | grep -i '%s'", base, h),
				Evidence: map[string]any{
					"url":    base,
					"header": h,
					// Truncate key: show prefix only to avoid logging real secrets.
					"key_prefix": truncate(v, 12),
				},
				DiscoveredAt: time.Now(),
			}
		}
	}
	return nil
}

// jsProviderPatterns are regex patterns that detect cloud LLM provider endpoint
// URLs hardcoded in page source or JavaScript bundles.
var jsProviderPatterns = []struct {
	re       *regexp.Regexp
	provider string
	label    string
}{
	// Azure OpenAI — deployment URL in JS
	{regexp.MustCompile(`https://[a-z0-9\-]+\.openai\.azure\.com/openai/deployments/`), "azure_openai", "Azure OpenAI deployment URL"},
	// AWS Bedrock — regional endpoint in JS
	{regexp.MustCompile(`https://bedrock(?:-runtime)?\.(?:us|eu|ap)-[a-z0-9\-]+\.amazonaws\.com`), "aws_bedrock", "AWS Bedrock endpoint URL"},
	// Google Vertex AI
	{regexp.MustCompile(`https://[a-z0-9\-]+-aiplatform\.googleapis\.com`), "vertex_ai", "Google Vertex AI endpoint URL"},
	// Google Gemini (generativelanguage API)
	{regexp.MustCompile(`https://generativelanguage\.googleapis\.com`), "vertex_ai", "Google Gemini API URL"},
	// Anthropic
	{regexp.MustCompile(`https://api\.anthropic\.com/v[0-9]/messages`), "anthropic", "Anthropic API URL"},
	// OpenAI
	{regexp.MustCompile(`https://api\.openai\.com/v[0-9]/`), "openai", "OpenAI API URL"},
}

// checkJSProviderLeak fetches the root page and looks for cloud LLM provider
// endpoint URLs hardcoded in inline or embedded JavaScript.
func checkJSProviderLeak(ctx context.Context, client *http.Client, base, asset string, ev *playbook.Evidence) []finding.Finding {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024)) // 256 KB cap
	resp.Body.Close()

	bodyStr := string(body)
	var findings []finding.Finding
	seen := map[string]bool{}

	for _, p := range jsProviderPatterns {
		match := p.re.FindString(bodyStr)
		if match == "" || seen[p.provider] {
			continue
		}
		seen[p.provider] = true

		if ev != nil && ev.LLMProvider == "" {
			ev.LLMProvider = p.provider
		}

		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckAIEndpointExposed,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityMedium,
			Title:    fmt.Sprintf("Cloud LLM provider endpoint hardcoded in page source: %s", p.label),
			Description: fmt.Sprintf(
				"A %s endpoint URL was found hardcoded in the page source at %s. "+
					"Hardcoded cloud AI provider URLs in client-side code expose your provider, model, "+
					"and possibly region/deployment configuration to any visitor, aiding targeted attacks.",
				p.label, base),
			Asset:        asset,
			ProofCommand: fmt.Sprintf(`curl -s %s | grep -oP '%s'`, base, p.re.String()),
			Evidence: map[string]any{
				"url":      base,
				"provider": p.provider,
				"pattern":  p.label,
				"match":    truncate(match, 80),
			},
			DiscoveredAt: time.Now(),
		})
	}
	return findings
}

func proofFlags(method, path string) string {
	if method == "POST" {
		return `-X POST -H 'Content-Type: application/json' -d '{"model":"test","messages":[{"role":"user","content":"hi"}],"max_tokens":1}'`
	}
	return ""
}

func appendUniq(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s + "…"
	}
	return s[:n] + "…"
}

// reToolCallsJSON matches the JSON key-value pattern "tool_calls": [ so that
// prose mentions of the string (e.g. refusal messages) are not flagged.
var reToolCallsJSON = regexp.MustCompile(`"tool_calls"\s*:\s*\[`)

func detectScheme(ctx context.Context, client *http.Client, asset string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+asset, nil)
	if err != nil {
		return "http"
	}
	resp, err := client.Do(req)
	if err != nil {
		return "http"
	}
	resp.Body.Close()
	return "https"
}
