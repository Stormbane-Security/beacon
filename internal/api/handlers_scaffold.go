package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/stormbane-security/bosun/pkg/catalog"
	"github.com/stormbane-security/bosun/pkg/scaffold"
)

// ── GET /v1/catalog ────────────────────────────────────────────────────────

func (s *Server) handleCatalog(w http.ResponseWriter, r *http.Request) {
	provider := r.URL.Query().Get("provider")
	category := r.URL.Query().Get("category")

	entries := catalog.All()
	if provider != "" {
		entries = catalog.ByProvider(provider)
	}
	if category != "" {
		var filtered []catalog.Entry
		for _, e := range entries {
			if e.Category == category {
				filtered = append(filtered, e)
			}
		}
		entries = filtered
	}

	if entries == nil {
		entries = []catalog.Entry{}
	}
	jsonOK(w, http.StatusOK, map[string]any{"entries": entries})
}

// ── GET /v1/catalog/{id} ──────────────────────────────────────────────────

func (s *Server) handleCatalogEntry(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	entry, ok := catalog.ByID(id)
	if !ok {
		jsonError(w, "catalog entry not found", http.StatusNotFound)
		return
	}
	jsonOK(w, http.StatusOK, entry)
}

// ── POST /v1/scaffold ─────────────────────────────────────────────────────

type scaffoldRequest struct {
	CatalogID string            `json:"catalog_id"`
	Params    map[string]string `json:"params"`
}

func (s *Server) handleScaffold(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req scaffoldRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.CatalogID == "" {
		jsonError(w, "catalog_id is required", http.StatusBadRequest)
		return
	}

	result, err := scaffold.Run(scaffold.Request{
		CatalogID: req.CatalogID,
		Params:    req.Params,
	})
	if err != nil {
		if result != nil && len(result.MissingParams) > 0 {
			jsonOK(w, http.StatusUnprocessableEntity, map[string]any{
				"error":          err.Error(),
				"missing_params": result.MissingParams,
				"entry":          result.Entry,
			})
			return
		}
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	jsonOK(w, http.StatusOK, map[string]any{
		"entry": result.Entry,
		"files": result.Files,
	})
}

// ── POST /v1/scaffold/match ───────────────────────────────────────────────

type matchRequest struct {
	Query string `json:"query"`
}

func (s *Server) handleScaffoldMatch(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req matchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Query == "" {
		jsonError(w, "query is required", http.StatusBadRequest)
		return
	}

	matches := scaffold.MatchIntent(req.Query)
	if matches == nil {
		matches = []catalog.Entry{}
	}
	// Limit to top 5.
	if len(matches) > 5 {
		matches = matches[:5]
	}

	jsonOK(w, http.StatusOK, map[string]any{"matches": matches})
}

// ── POST /v1/scaffold/chat ──────────────────────────────────────────────────

type chatMessage struct {
	Role    string `json:"role"`    // "user" or "assistant"
	Content string `json:"content"`
}

type chatRequest struct {
	Messages  []chatMessage `json:"messages"`
	ProjectID string        `json:"project_id,omitempty"`
}

// buildCatalogContext produces a compact text summary of the catalog for the system prompt.
func buildCatalogContext() string {
	var b strings.Builder
	b.WriteString("Available infrastructure templates (security-hardened, opinionated Terraform modules):\n\n")
	for _, e := range catalog.All() {
		fmt.Fprintf(&b, "- **%s** (id: `%s`, provider: %s, category: %s)\n", e.Name, e.ID, e.Provider, e.Category)
		fmt.Fprintf(&b, "  %s\n", e.Description)
		if len(e.Params) > 0 {
			b.WriteString("  Parameters: ")
			names := make([]string, 0, len(e.Params))
			for _, p := range e.Params {
				tag := p.Name
				if p.Required {
					tag += " (required)"
				}
				names = append(names, tag)
			}
			b.WriteString(strings.Join(names, ", "))
			b.WriteString("\n")
		}
		if len(e.SecurityNotes) > 0 {
			fmt.Fprintf(&b, "  Security: %s\n", strings.Join(e.SecurityNotes, "; "))
		}
		b.WriteString("\n")
	}
	return b.String()
}

const scaffoldSystemPrompt = `You are Beacon's infrastructure architect assistant. You help users decide what cloud infrastructure to build using security-hardened, opinionated Terraform modules.

Your job:
1. Understand what the user wants to build (application type, scale, provider preferences, compliance needs)
2. Ask clarifying questions — don't assume. Ask about: cloud provider, environment (dev/staging/prod), compliance requirements, team size, existing infrastructure
3. Recommend specific templates from the catalog below
4. Help fill in the required parameters
5. When you have enough information, respond with a JSON action block that the UI can use to auto-populate the scaffold form

When you're ready to recommend a specific template, include this JSON block in your response:
` + "```" + `json
{"action":"select","catalog_id":"<id>","params":{"key":"value",...}}
` + "```" + `

Only include the action block when you have gathered enough information to make a specific recommendation with parameter values. Keep asking questions until then.

Always prioritize security. Explain what security hardening each template provides. If the user asks for something insecure (public buckets, no encryption, overly permissive IAM), push back and explain why.

When generating a consolidated plan with multiple resources that share variables (e.g. a GKE cluster + a CI/CD pipeline that deploys to it), use a plan action block:
` + "```" + `json
{"action":"plan","name":"Plan name","items":[{"catalog_id":"...","params":{...}},...],"shared_vars":{"project_id":"...","region":"..."}}
` + "```" + `

%s`

// buildProjectContext formats the project's existing infrastructure for the system prompt.
func (s *Server) buildProjectContext(projectID string) string {
	if projectID == "" {
		return ""
	}
	ctx, err := s.projects.BuildContext(projectID)
	if err != nil {
		return ""
	}

	var b strings.Builder
	b.WriteString("\n\n## Current Project Context\n\n")
	fmt.Fprintf(&b, "Project: %s\n", ctx.ProjectName)
	if len(ctx.Domains) > 0 {
		fmt.Fprintf(&b, "Scanned domains: %s\n", strings.Join(ctx.Domains, ", "))
	}

	if len(ctx.ExistingResources) > 0 {
		b.WriteString("\n### Existing Infrastructure (discovered from scans, cloud APIs, and Terraform)\n")
		bySource := make(map[string][]string)
		for _, r := range ctx.ExistingResources {
			label := fmt.Sprintf("  - %s: %s (%s)", r.Type, r.Name, r.Provider)
			if len(r.Attrs) > 0 {
				var attrs []string
				for k, v := range r.Attrs {
					attrs = append(attrs, k+"="+v)
				}
				label += " [" + strings.Join(attrs, ", ") + "]"
			}
			bySource[r.Source] = append(bySource[r.Source], label)
		}
		for source, items := range bySource {
			fmt.Fprintf(&b, "\nSource: %s\n", source)
			for _, item := range items {
				b.WriteString(item + "\n")
			}
		}
	}

	if len(ctx.ManagedResources) > 0 {
		fmt.Fprintf(&b, "\n### Terraform-Managed Resources (%d total)\n", len(ctx.ManagedResources))
		for _, r := range ctx.ManagedResources {
			fmt.Fprintf(&b, "  - %s.%s", r.Type, r.Name)
			if r.FilePath != "" {
				fmt.Fprintf(&b, " (in %s)", r.FilePath)
			}
			b.WriteString("\n")
		}
	}

	if len(ctx.UnmanagedGaps) > 0 {
		fmt.Fprintf(&b, "\n### Unmanaged Gaps (in cloud but NOT in Terraform — consider importing or creating TF for these)\n")
		for _, r := range ctx.UnmanagedGaps {
			fmt.Fprintf(&b, "  - %s: %s (%s)\n", r.Type, r.Name, r.Provider)
		}
	}

	if len(ctx.Plans) > 0 {
		b.WriteString("\n### Existing Plans\n")
		for _, p := range ctx.Plans {
			fmt.Fprintf(&b, "  - %s: %s (%d items)\n", p.Name, p.Description, len(p.Items))
		}
	}

	b.WriteString("\nUse this context to make informed recommendations. When the user asks to build something, check if related infrastructure already exists and suggest connecting to it rather than duplicating. Identify shared variables (project_id, region, VPC, etc.) from existing resources.\n")

	return b.String()
}

func (s *Server) handleScaffoldChat(w http.ResponseWriter, r *http.Request) {
	if s.aiCfg.APIKey == "" && os.Getenv("ANTHROPIC_API_KEY") == "" {
		jsonError(w, "AI provider not configured — set ai.api_key in config or ANTHROPIC_API_KEY env var", http.StatusServiceUnavailable)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req chatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if len(req.Messages) == 0 {
		jsonError(w, "messages is required", http.StatusBadRequest)
		return
	}

	// Build the system prompt with catalog + optional project context.
	catalogCtx := buildCatalogContext()
	projectCtx := s.buildProjectContext(req.ProjectID)
	systemPrompt := fmt.Sprintf(scaffoldSystemPrompt, catalogCtx+projectCtx)

	// Resolve AI provider settings.
	apiKey := s.aiCfg.APIKey
	if apiKey == "" {
		apiKey = os.Getenv("ANTHROPIC_API_KEY")
	}
	model := s.aiCfg.Model
	if model == "" {
		model = "claude-sonnet-4-6"
	}
	endpoint := s.aiCfg.BaseURL
	provider := strings.ToLower(s.aiCfg.Provider)

	// Build and send the request based on provider.
	var reply string
	var err error
	switch provider {
	case "openai", "mistral", "grok", "groq":
		reply, err = s.chatOpenAICompat(r.Context(), apiKey, model, endpoint, provider, systemPrompt, req.Messages)
	default: // "claude" or unrecognised
		reply, err = s.chatClaude(r.Context(), apiKey, model, endpoint, systemPrompt, req.Messages)
	}
	if err != nil {
		jsonError(w, "AI error: "+err.Error(), http.StatusBadGateway)
		return
	}

	jsonOK(w, http.StatusOK, map[string]any{
		"reply": reply,
	})
}

// chatClaude calls the Anthropic Messages API with multi-turn conversation support.
func (s *Server) chatClaude(ctx context.Context, apiKey, model, endpoint, system string, msgs []chatMessage) (string, error) {
	if endpoint == "" {
		endpoint = "https://api.anthropic.com/v1/messages"
	}

	type msg struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	apiMsgs := make([]msg, len(msgs))
	for i, m := range msgs {
		apiMsgs[i] = msg{Role: m.Role, Content: m.Content}
	}

	body, err := json.Marshal(map[string]any{
		"model":      model,
		"max_tokens": 4096,
		"system":     system,
		"messages":   apiMsgs,
	})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		safe := strings.ReplaceAll(string(data), apiKey, "[REDACTED]")
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, safe)
	}

	var cr struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(data, &cr); err != nil {
		return "", fmt.Errorf("parsing response: %w", err)
	}
	if cr.Error != nil {
		return "", fmt.Errorf("API error: %s", cr.Error.Message)
	}
	if len(cr.Content) == 0 {
		return "", fmt.Errorf("empty response")
	}
	return cr.Content[0].Text, nil
}

// chatOpenAICompat calls any OpenAI-compatible chat completions endpoint with multi-turn support.
func (s *Server) chatOpenAICompat(ctx context.Context, apiKey, model, endpoint, provider, system string, msgs []chatMessage) (string, error) {
	if endpoint == "" {
		switch provider {
		case "openai":
			endpoint = "https://api.openai.com/v1/chat/completions"
		case "mistral":
			endpoint = "https://api.mistral.ai/v1/chat/completions"
		case "grok":
			endpoint = "https://api.x.ai/v1/chat/completions"
		case "groq":
			endpoint = "https://api.groq.com/openai/v1/chat/completions"
		default:
			endpoint = "https://api.openai.com/v1/chat/completions"
		}
	}

	type msg struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	apiMsgs := make([]msg, 0, len(msgs)+1)
	apiMsgs = append(apiMsgs, msg{Role: "system", Content: system})
	for _, m := range msgs {
		apiMsgs = append(apiMsgs, msg{Role: m.Role, Content: m.Content})
	}

	body, err := json.Marshal(map[string]any{
		"model":    model,
		"messages": apiMsgs,
	})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		safe := strings.ReplaceAll(string(data), apiKey, "[REDACTED]")
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, safe)
	}

	var cr struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(data, &cr); err != nil {
		return "", fmt.Errorf("parsing response: %w", err)
	}
	if len(cr.Choices) == 0 {
		return "", fmt.Errorf("empty response")
	}
	return cr.Choices[0].Message.Content, nil
}
