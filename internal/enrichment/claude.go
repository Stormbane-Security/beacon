// Package enrichment provides AI-powered finding enrichment via Anthropic Claude.
package enrichment

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/stormbane/beacon/internal/finding"
)

//go:embed prompts/finding.tmpl
var defaultFindingTmpl string

//go:embed prompts/summary.tmpl
var defaultSummaryTmpl string

//go:embed prompts/contextual.tmpl
var defaultContextualTmpl string

const (
	findingModel        = "claude-haiku-4-5-20251001" // fast, cheap — per-finding batch
	defaultSummaryModel = "claude-sonnet-4-6"          // higher quality — once per scan
	claudeAPIURL        = "https://api.anthropic.com/v1/messages"
	claudeAPIVersion    = "2023-06-01"
	openAIAPIURL        = "https://api.openai.com/v1/chat/completions"
	geminiAPIURL        = "https://generativelanguage.googleapis.com/v1beta/models"
	ollamaAPIURL        = "http://localhost:11434/api/chat"
	mistralAPIURL       = "https://api.mistral.ai/v1/chat/completions"
	grokAPIURL          = "https://api.x.ai/v1/chat/completions"
	groqAPIURL          = "https://api.groq.com/openai/v1/chat/completions"
	maxTokens           = 4096
)

// defaultModelFor returns a sensible default model for a given provider.
func defaultModelFor(provider string) string {
	switch strings.ToLower(provider) {
	case "openai":
		return "gpt-4o"
	case "gemini":
		return "gemini-2.0-flash"
	case "ollama":
		return "llama3.1"
	case "mistral":
		return "mistral-large-latest"
	case "grok":
		return "grok-2"
	case "groq":
		return "llama-3.3-70b-versatile"
	default: // "claude" or unrecognised
		return defaultSummaryModel
	}
}

// defaultFindingModelFor returns the preferred fast/cheap model for per-finding enrichment.
func defaultFindingModelFor(provider string) string {
	switch strings.ToLower(provider) {
	case "openai":
		return "gpt-4o-mini"
	case "gemini":
		return "gemini-2.0-flash"
	case "ollama":
		return "llama3.1"
	case "mistral":
		return "mistral-small-latest"
	case "grok":
		return "grok-2"
	case "groq":
		return "llama-3.3-70b-versatile"
	default: // "claude"
		return findingModel
	}
}

// EnrichmentCache is a minimal interface for caching enrichment results by CheckID.
// store.Store satisfies this interface — defined here to avoid an import cycle.
type EnrichmentCache interface {
	GetEnrichmentCache(ctx context.Context, checkID finding.CheckID) (explanation, impact, remediation string, found bool)
	SaveEnrichmentCache(ctx context.Context, checkID finding.CheckID, explanation, impact, remediation string) error
}

// ClaudeEnricher calls an AI provider to enrich findings.
// Despite its name it supports Claude, OpenAI, Gemini, Ollama, Mistral, Grok, and Groq.
type ClaudeEnricher struct {
	provider        string // "claude" | "openai" | "gemini" | "ollama" | "mistral" | "grok" | "groq"
	apiKey          string
	baseURL         string // custom endpoint override (empty = use provider default)
	summaryModel    string
	findingModel    string // fast model for per-finding batch enrichment
	findingTmpl     *template.Template
	summaryTmpl     *template.Template
	contextualTmpl  *template.Template
	httpClient      *http.Client
	cache           EnrichmentCache // optional — nil = no caching
}

// NewClaudeDefault creates a ClaudeEnricher using the embedded default prompts.
func NewClaudeDefault(apiKey string) (*ClaudeEnricher, error) {
	return NewClaude(apiKey, defaultFindingTmpl, defaultSummaryTmpl)
}

// safeFuncs returns template functions that sanitize user-controlled data before
// it reaches Claude prompts, preventing prompt injection via crafted finding fields.
var safeFuncs = template.FuncMap{
	// safe truncates s to maxLen runes and removes newlines/control chars.
	// Use for any field that comes from external/user-controlled data
	// (finding titles, descriptions, asset names).
	"safe": func(s string) string {
		// Collapse newlines and CR to a single space — prevents injecting new
		// "instruction" lines into the prompt.
		s = strings.ReplaceAll(s, "\r\n", " ")
		s = strings.ReplaceAll(s, "\r", " ")
		s = strings.ReplaceAll(s, "\n", " ")
		// Remove other ASCII control characters.
		var b strings.Builder
		for _, r := range s {
			if r >= 0x20 || r == '\t' {
				b.WriteRune(r)
			}
		}
		result := b.String()
		// Truncate by rune count, not byte count, to avoid slicing
		// in the middle of a multi-byte UTF-8 character.
		runes := []rune(result)
		if len(runes) > 512 {
			result = string(runes[:512]) + "…"
		}
		return result
	},
}

// sanitize removes newlines/control characters and truncates to maxRunes.
// This is the non-template equivalent of the "safe" template function, for use
// in Go code that builds prompts via fmt.Sprintf rather than text/template.
func sanitize(s string, maxRunes int) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 || r == '\t' {
			b.WriteRune(r)
		}
	}
	result := b.String()
	runes := []rune(result)
	if len(runes) > maxRunes {
		result = string(runes[:maxRunes]) + "…"
	}
	return result
}

func NewClaude(apiKey string, findingTmplSrc, summaryTmplSrc string) (*ClaudeEnricher, error) {
	return newEnricher("claude", apiKey, "", findingTmplSrc, summaryTmplSrc)
}

// NewWithProvider creates an enricher for any supported AI provider.
// provider is one of: claude, openai, gemini, ollama, mistral, grok, groq.
// baseURL overrides the provider's default API endpoint (empty = use default).
// model overrides the provider's default model (empty = use default).
func NewWithProvider(provider, apiKey, model, baseURL string) (*ClaudeEnricher, error) {
	e, err := newEnricher(provider, apiKey, baseURL, defaultFindingTmpl, defaultSummaryTmpl)
	if err != nil {
		return nil, err
	}
	if model != "" {
		e.summaryModel = model
		e.findingModel = model
	}
	return e, nil
}

func newEnricher(provider, apiKey, baseURL, findingTmplSrc, summaryTmplSrc string) (*ClaudeEnricher, error) {
	if provider == "" {
		provider = "claude"
	}
	ft, err := template.New("finding").Funcs(safeFuncs).Parse(findingTmplSrc)
	if err != nil {
		return nil, fmt.Errorf("finding template: %w", err)
	}
	st, err := template.New("summary").Funcs(safeFuncs).Parse(summaryTmplSrc)
	if err != nil {
		return nil, fmt.Errorf("summary template: %w", err)
	}
	ct, err := template.New("contextual").Funcs(safeFuncs).Parse(defaultContextualTmpl)
	if err != nil {
		return nil, fmt.Errorf("contextual template: %w", err)
	}
	return &ClaudeEnricher{
		provider:       strings.ToLower(provider),
		apiKey:         apiKey,
		baseURL:        baseURL,
		summaryModel:   defaultModelFor(provider),
		findingModel:   defaultFindingModelFor(provider),
		findingTmpl:    ft,
		summaryTmpl:    st,
		contextualTmpl: ct,
		httpClient:     &http.Client{Timeout: 120 * time.Second},
	}, nil
}

// WithSummaryModel overrides the Claude model used for scan summaries.
// An empty string is ignored (keeps the default).
func (c *ClaudeEnricher) WithSummaryModel(model string) *ClaudeEnricher {
	if model != "" {
		c.summaryModel = model
	}
	return c
}

// Chat sends a single prompt to the AI and returns the response text.
// Uses the summary model (full reasoning). Safe for concurrent use.
// Errors from transient failures are retried automatically by callLLM.
func (c *ClaudeEnricher) Chat(ctx context.Context, prompt string) (string, error) {
	return c.callLLM(ctx, c.summaryModel, prompt)
}

// WithCache attaches a cache for enrichment results. When set, explanations
// already computed for a given CheckID are returned from cache without calling
// Claude, and new results are saved after each API call.
func (c *ClaudeEnricher) WithCache(cache EnrichmentCache) *ClaudeEnricher {
	c.cache = cache
	return c
}

// findingWithRef wraps a finding with its per-CheckID reference material so the
// template can render both the finding fields and the reference block.
type findingWithRef struct {
	finding.Finding
	Reference checkReference
}

func (c *ClaudeEnricher) Enrich(ctx context.Context, findings []finding.Finding) ([]EnrichedFinding, error) {
	if len(findings) == 0 {
		return nil, nil
	}

	// Pre-populate from cache and collect uncached findings (one per unique CheckID).
	type cached struct{ explanation, impact, remediation, terraformFix string }
	cacheHits := make(map[finding.CheckID]cached)
	seenUncached := make(map[finding.CheckID]bool)
	var uncached []finding.Finding

	if c.cache != nil {
		for _, f := range findings {
			if _, already := cacheHits[f.CheckID]; already {
				continue
			}
			if _, already := seenUncached[f.CheckID]; already {
				continue
			}
			explanation, impact, remediation, found := c.cache.GetEnrichmentCache(ctx, f.CheckID)
			if found && !looksLikeRawJSON(explanation) {
				cacheHits[f.CheckID] = cached{explanation: explanation, impact: impact, remediation: remediation}
			} else {
				// Cache miss or poisoned entry — treat as uncached and re-enrich.
				seenUncached[f.CheckID] = true
				uncached = append(uncached, f)
			}
		}
	} else {
		// No cache — enrich everything, but deduplicate by CheckID for the prompt.
		for _, f := range findings {
			if !seenUncached[f.CheckID] {
				seenUncached[f.CheckID] = true
				uncached = append(uncached, f)
			}
		}
	}

	// Call the LLM for uncached check types, in batches to avoid token limits.
	const enrichBatchSize = 20
	newEnrich := make(map[finding.CheckID]cached)
	for batchStart := 0; batchStart < len(uncached); batchStart += enrichBatchSize {
		batchEnd := batchStart + enrichBatchSize
		if batchEnd > len(uncached) {
			batchEnd = len(uncached)
		}
		batch := uncached[batchStart:batchEnd]

		// Wrap each finding with its per-CheckID reference material so the template
		// can inject documentation excerpts and Terraform examples into the prompt.
		withRefs := make([]findingWithRef, len(batch))
		for i, f := range batch {
			withRefs[i] = findingWithRef{Finding: f, Reference: referenceFor(string(f.CheckID))}
		}
		var promptBuf bytes.Buffer
		if err := c.findingTmpl.Execute(&promptBuf, withRefs); err != nil {
			return nil, fmt.Errorf("rendering finding prompt: %w", err)
		}
		responseText, err := c.callLLM(ctx, c.findingModel, promptBuf.String())
		if err != nil {
			return nil, fmt.Errorf("claude enrich batch %d: %w", batchStart/enrichBatchSize+1, err)
		}
		parsed, err := parseEnrichedResponse(batch, responseText)
		if err != nil {
			return nil, err
		}
		for _, ef := range parsed {
			newEnrich[ef.Finding.CheckID] = cached{explanation: ef.Explanation, impact: ef.Impact, remediation: ef.Remediation, terraformFix: ef.TerraformFix}
		}
	}

	// Save new results to cache — but only when the explanation looks like
	// human-readable prose, not a raw JSON blob from a failed parse.
	if c.cache != nil {
		for id, e := range newEnrich {
			if looksLikeRawJSON(e.explanation) {
				continue // skip — would pollute cache with bad data
			}
			if err := c.cache.SaveEnrichmentCache(ctx, id, e.explanation, e.impact, e.remediation); err != nil {
				// Log but don't fail — the enrichment itself succeeded; missing
				// cache only means the next scan re-computes this check type.
				fmt.Fprintf(os.Stderr, "enrichment: cache write failed for %s: %v\n", id, err)
			}
		}
	}

	// Assemble output — every finding gets enrichment from cache or new results.
	out := make([]EnrichedFinding, len(findings))
	for i, f := range findings {
		ef := EnrichedFinding{Finding: f}
		if e, ok := cacheHits[f.CheckID]; ok {
			ef.Explanation = e.explanation
			ef.Impact = e.impact
			ef.Remediation = e.remediation
			ef.TerraformFix = e.terraformFix
		} else if e, ok := newEnrich[f.CheckID]; ok {
			ef.Explanation = e.explanation
			ef.Impact = e.impact
			ef.Remediation = e.remediation
			ef.TerraformFix = e.terraformFix
		} else {
			ef.Explanation = f.Description
		}
		out[i] = ef
	}
	return out, nil
}

func (c *ClaudeEnricher) Summarize(ctx context.Context, enriched []EnrichedFinding, domain string) (string, error) {
	_, summary, err := c.ContextualizeAndSummarize(ctx, enriched, domain)
	return summary, err
}

// assetGroup is used to build the contextual prompt template data.
type assetGroup struct {
	Asset    string
	Findings []EnrichedFinding
}

// contextualFindingCap is the maximum number of findings to include in a single
// contextual analysis pass. Above this count we trim to critical/high only to
// stay within the 1M-token API limit.
const contextualFindingCap = 300

func (c *ClaudeEnricher) ContextualizeAndSummarize(ctx context.Context, enriched []EnrichedFinding, domain string) ([]EnrichedFinding, string, error) {
	if len(enriched) == 0 {
		return enriched, "", nil
	}

	// If there are too many findings, restrict the contextual pass to
	// critical and high severity only. The per-finding enrichment pass already
	// ran on all findings, so lower-severity findings lose only cross-asset
	// notes and compliance tags — an acceptable trade-off to avoid API errors.
	contextual := enriched
	if len(enriched) > contextualFindingCap {
		var filtered []EnrichedFinding
		for _, ef := range enriched {
			if ef.Finding.Severity == finding.SeverityCritical || ef.Finding.Severity == finding.SeverityHigh {
				filtered = append(filtered, ef)
			}
		}
		// If there are still too many high/critical findings, cap at the limit.
		if len(filtered) > contextualFindingCap {
			filtered = filtered[:contextualFindingCap]
		}
		contextual = filtered
	}

	// Group findings by asset (preserve order for deterministic output).
	orderSeen := []string{}
	groups := map[string][]EnrichedFinding{}
	for _, ef := range contextual {
		asset := ef.Finding.Asset
		if _, exists := groups[asset]; !exists {
			orderSeen = append(orderSeen, asset)
		}
		groups[asset] = append(groups[asset], ef)
	}
	assetGroups := make([]assetGroup, 0, len(orderSeen))
	for _, asset := range orderSeen {
		assetGroups = append(assetGroups, assetGroup{Asset: asset, Findings: groups[asset]})
	}

	var promptBuf bytes.Buffer
	data := struct {
		Domain      string
		AssetGroups []assetGroup
	}{Domain: domain, AssetGroups: assetGroups}
	if err := c.contextualTmpl.Execute(&promptBuf, data); err != nil {
		return enriched, "", fmt.Errorf("rendering contextual prompt: %w", err)
	}

	responseText, err := c.callLLM(ctx, c.summaryModel, promptBuf.String())
	if err != nil {
		return enriched, "", fmt.Errorf("contextual claude call: %w", err)
	}

	return applyContextualResponse(enriched, responseText)
}

// applyContextualResponse parses Claude's JSON response and merges the
// MitigatedBy, CrossAssetNote, and Omit fields back into the enriched findings.
func applyContextualResponse(enriched []EnrichedFinding, text string) ([]EnrichedFinding, string, error) {
	start := strings.Index(text, "{")
	end := strings.LastIndex(text, "}")
	if start == -1 || end <= start {
		// Can't parse — return findings unchanged with raw text as summary.
		return enriched, text, nil
	}

	var result struct {
		Summary             string `json:"summary"`
		AttackNarrative     string `json:"attack_narrative"`
		RemediationRoadmap  string `json:"remediation_roadmap"`
		Findings []struct {
			CheckID                 string   `json:"check_id"`
			Asset                   string   `json:"asset"`
			Omit                    bool     `json:"omit"`
			MitigatedBy             string   `json:"mitigated_by"`
			CrossAssetNote          string   `json:"cross_asset_note"`
			TechSpecificRemediation string   `json:"tech_specific_remediation"`
			ComplianceTags          []string `json:"compliance_tags"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(text[start:end+1]), &result); err != nil {
		// Graceful fallback — return unchanged findings, use full response as summary.
		return enriched, text, nil
	}

	// Build the full report summary: executive summary + narrative + roadmap.
	fullSummary := result.Summary
	if result.AttackNarrative != "" {
		fullSummary += "\n\n## Attack Narrative\n\n" + result.AttackNarrative
	}
	if result.RemediationRoadmap != "" {
		fullSummary += "\n\n## Remediation Roadmap\n\n" + result.RemediationRoadmap
	}

	// Index the contextual updates by (check_id, asset).
	type key struct{ checkID, asset string }
	type update struct {
		Omit                    bool
		MitigatedBy             string
		CrossAssetNote          string
		TechSpecificRemediation string
		ComplianceTags          []string
	}
	index := make(map[key]update, len(result.Findings))
	for _, f := range result.Findings {
		index[key{f.CheckID, f.Asset}] = update{
			f.Omit, f.MitigatedBy, f.CrossAssetNote,
			f.TechSpecificRemediation, f.ComplianceTags,
		}
	}

	out := make([]EnrichedFinding, len(enriched))
	for i, ef := range enriched {
		k := key{ef.Finding.CheckID, ef.Finding.Asset}
		if u, ok := index[k]; ok {
			ef.Omit = u.Omit
			ef.MitigatedBy = u.MitigatedBy
			ef.CrossAssetNote = u.CrossAssetNote
			ef.TechSpecificRemediation = u.TechSpecificRemediation
			ef.ComplianceTags = u.ComplianceTags
		}
		out[i] = ef
	}
	return out, fullSummary, nil
}

// claudeRequest is the Anthropic Messages API request body.
type claudeRequest struct {
	Model     string           `json:"model"`
	MaxTokens int              `json:"max_tokens"`
	Messages  []claudeMessage  `json:"messages"`
}

type claudeMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// claudeResponse is the Anthropic Messages API response body.
type claudeResponse struct {
	Content []struct {
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// callLLM dispatches a completion request to whichever provider is configured.
// callLLM dispatches to the configured provider with exponential backoff retry.
// Transient failures (network errors, 429 rate-limits, 5xx server errors) are
// retried up to 3 times with 1s → 2s → 4s delays before returning an error.
func (c *ClaudeEnricher) callLLM(ctx context.Context, model, prompt string) (string, error) {
	const maxAttempts = 3
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			delay := time.Duration(1<<uint(attempt-1)) * time.Second // 1s, 2s
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(delay):
			}
		}
		var result string
		var err error
		switch c.provider {
		case "openai", "mistral", "grok", "groq":
			result, err = c.callOpenAICompat(ctx, model, prompt)
		case "gemini":
			result, err = c.callGemini(ctx, model, prompt)
		case "ollama":
			result, err = c.callOllama(ctx, model, prompt)
		default: // "claude" or unrecognised
			result, err = c.callClaude(ctx, model, prompt)
		}
		if err == nil {
			return result, nil
		}
		lastErr = err
		// Don't retry on context cancellation.
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
	}
	return "", fmt.Errorf("after %d attempts: %w", maxAttempts, lastErr)
}

// callOpenAICompat calls any OpenAI-compatible chat completions endpoint
// (OpenAI, Mistral, Grok/xAI, Groq, Azure OpenAI, etc.).
func (c *ClaudeEnricher) callOpenAICompat(ctx context.Context, model, prompt string) (string, error) {
	endpoint := c.providerEndpoint()
	type msg struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	body, _ := json.Marshal(struct {
		Model     string `json:"model"`
		MaxTokens int    `json:"max_tokens"`
		Messages  []msg  `json:"messages"`
	}{model, maxTokens, []msg{{"user", prompt}}})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10)) // 256 KiB cap
	if resp.StatusCode != http.StatusOK {
		safeBody := strings.TrimSpace(string(data))
		if c.apiKey != "" {
			safeBody = strings.ReplaceAll(safeBody, c.apiKey, "[REDACTED]")
		}
		return "", fmt.Errorf("OpenAI-compat API HTTP %d: %s", resp.StatusCode, safeBody)
	}

	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Error *struct{ Message string `json:"message"` } `json:"error"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", fmt.Errorf("parsing OpenAI response: %w", err)
	}
	if out.Error != nil {
		return "", fmt.Errorf("OpenAI-compat API error: %s", out.Error.Message)
	}
	if len(out.Choices) == 0 {
		return "", fmt.Errorf("OpenAI-compat API returned no choices")
	}
	return out.Choices[0].Message.Content, nil
}

// callGemini calls the Google Generative Language API.
func (c *ClaudeEnricher) callGemini(ctx context.Context, model, prompt string) (string, error) {
	base := c.baseURL
	if base == "" {
		base = geminiAPIURL
	}
	url := fmt.Sprintf("%s/%s:generateContent?key=%s", strings.TrimRight(base, "/"), model, c.apiKey)

	body, _ := json.Marshal(struct {
		Contents []struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"contents"`
	}{Contents: []struct {
		Parts []struct {
			Text string `json:"text"`
		} `json:"parts"`
	}{{Parts: []struct {
		Text string `json:"text"`
	}{{Text: prompt}}}}})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		// Redact the response body to avoid leaking the API key, which
		// is passed as a URL query parameter for the Gemini API.
		safeBody := strings.TrimSpace(string(data))
		if c.apiKey != "" {
			safeBody = strings.ReplaceAll(safeBody, c.apiKey, "[REDACTED]")
		}
		return "", fmt.Errorf("Gemini API HTTP %d: %s", resp.StatusCode, safeBody)
	}

	var out struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
		Error *struct{ Message string `json:"message"` } `json:"error"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", fmt.Errorf("parsing Gemini response: %w", err)
	}
	if out.Error != nil {
		return "", fmt.Errorf("Gemini API error: %s", out.Error.Message)
	}
	if len(out.Candidates) == 0 || len(out.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("Gemini returned no content")
	}
	return out.Candidates[0].Content.Parts[0].Text, nil
}

// callOllama calls a local Ollama instance using its chat API.
func (c *ClaudeEnricher) callOllama(ctx context.Context, model, prompt string) (string, error) {
	endpoint := c.providerEndpoint()
	type msg struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	body, _ := json.Marshal(struct {
		Model    string `json:"model"`
		Messages []msg  `json:"messages"`
		Stream   bool   `json:"stream"`
	}{model, []msg{{"user", prompt}}, false})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("Ollama request failed (is Ollama running?): %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10)) // 256 KiB cap
	if resp.StatusCode != http.StatusOK {
		safeBody := strings.TrimSpace(string(data))
		if c.apiKey != "" {
			safeBody = strings.ReplaceAll(safeBody, c.apiKey, "[REDACTED]")
		}
		return "", fmt.Errorf("Ollama API HTTP %d: %s", resp.StatusCode, safeBody)
	}

	var out struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", fmt.Errorf("parsing Ollama response: %w", err)
	}
	if out.Error != "" {
		return "", fmt.Errorf("Ollama error: %s", out.Error)
	}
	return out.Message.Content, nil
}

// providerEndpoint returns the API endpoint URL for the current provider,
// using baseURL if set, otherwise the provider's canonical default.
func (c *ClaudeEnricher) providerEndpoint() string {
	if c.baseURL != "" {
		return c.baseURL
	}
	switch c.provider {
	case "openai":
		return openAIAPIURL
	case "mistral":
		return mistralAPIURL
	case "grok":
		return grokAPIURL
	case "groq":
		return groqAPIURL
	case "ollama":
		return ollamaAPIURL
	default:
		return claudeAPIURL
	}
}

func (c *ClaudeEnricher) callClaude(ctx context.Context, model, prompt string) (string, error) {
	body, err := json.Marshal(claudeRequest{
		Model:     model,
		MaxTokens: maxTokens,
		Messages: []claudeMessage{
			{Role: "user", Content: prompt},
		},
	})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, claudeAPIURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", claudeAPIVersion)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10)) // 256 KiB cap
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		safeBody := strings.TrimSpace(string(data))
		if c.apiKey != "" {
			safeBody = strings.ReplaceAll(safeBody, c.apiKey, "[REDACTED]")
		}
		return "", fmt.Errorf("Claude API HTTP %d: %s", resp.StatusCode, safeBody)
	}

	var cr claudeResponse
	if err := json.Unmarshal(data, &cr); err != nil {
		return "", fmt.Errorf("parsing Claude response: %w", err)
	}
	if cr.Error != nil {
		return "", fmt.Errorf("Claude API error: %s", cr.Error.Message)
	}
	if len(cr.Content) == 0 {
		return "", fmt.Errorf("Claude returned empty content")
	}
	return cr.Content[0].Text, nil
}

// extractJSONArray attempts to pull a JSON array out of text that may be
// wrapped in a markdown code fence (```json ... ```) or have leading prose.
func extractJSONArray(text string) string {
	// Strip markdown code fences — Claude sometimes wraps its JSON response.
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
	text = strings.TrimSpace(text)
	// Find outermost '[' ... ']' in case there is leading prose.
	start := strings.Index(text, "[")
	end := strings.LastIndex(text, "]")
	if start >= 0 && end > start {
		text = text[start : end+1]
	}
	return text
}

// looksLikeRawJSON returns true when s is a raw JSON blob rather than a
// human-readable explanation — used to prevent polluting the enrichment cache
// with unparsed Claude responses.
func looksLikeRawJSON(s string) bool {
	t := strings.TrimSpace(s)
	return strings.HasPrefix(t, "[{") || strings.HasPrefix(t, "```")
}

// parseEnrichedResponse parses the JSON array Claude returns for batch enrichment.
// Expected format: [{"check_id":"...","explanation":"...","impact":"...","remediation":"..."},...]
func parseEnrichedResponse(findings []finding.Finding, text string) ([]EnrichedFinding, error) {
	var parsed []struct {
		CheckID      string `json:"check_id"`
		Explanation  string `json:"explanation"`
		Impact       string `json:"impact"`
		Remediation  string `json:"remediation"`
		TerraformFix string `json:"terraform_fix"`
	}

	jsonText := extractJSONArray(text)
	if err := json.Unmarshal([]byte(jsonText), &parsed); err != nil {
		// Parse failed even after fence-stripping — fall back gracefully.
		// Use each finding's own Description; do NOT propagate raw text.
		out := make([]EnrichedFinding, len(findings))
		for i, f := range findings {
			out[i] = EnrichedFinding{Finding: f, Explanation: f.Description}
		}
		return out, nil
	}

	// Index parsed results by check_id
	type enrichEntry struct {
		Explanation  string
		Impact       string
		Remediation  string
		TerraformFix string
	}
	enrichMap := make(map[string]enrichEntry)
	for _, p := range parsed {
		enrichMap[p.CheckID] = enrichEntry{p.Explanation, p.Impact, p.Remediation, p.TerraformFix}
	}

	out := make([]EnrichedFinding, len(findings))
	for i, f := range findings {
		ef := EnrichedFinding{Finding: f}
		if e, ok := enrichMap[string(f.CheckID)]; ok {
			ef.Explanation = e.Explanation
			ef.Impact = e.Impact
			ef.Remediation = e.Remediation
			ef.TerraformFix = e.TerraformFix
		} else {
			ef.Explanation = f.Description
		}
		out[i] = ef
	}
	return out, nil
}

// AnalyzeAttackPaths — implemented in attackpath.go
// GenerateFollowUpProbes — implemented in attackpath.go
