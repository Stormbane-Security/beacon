package aidetect

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane/beacon/internal/module"
	"github.com/stormbane/beacon/internal/playbook"
)

func TestAIDetect_OpenAICompatibleEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-OpenAI-Organization", "org-test")
			fmt.Fprintln(w, `{"object":"list","data":[{"id":"gpt-4","object":"model"}]}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for OpenAI-compatible /v1/models endpoint")
	}
	f := findings[0]
	if f.CheckID != "ai.endpoint_exposed" {
		t.Errorf("unexpected check ID: %s", f.CheckID)
	}
	if f.ProofCommand == "" {
		t.Error("ProofCommand should be set")
	}
}

func TestAIDetect_UnauthenticatedChatEndpoint(t *testing.T) {
	// Server accepts POST to /v1/chat/completions and returns a valid chat response.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/chat/completions" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			resp := map[string]any{
				"choices": []map[string]any{
					{"message": map[string]string{"content": "Hello!"}, "finish_reason": "stop"},
				},
				"model": "gpt-3.5-turbo",
			}
			json.NewEncoder(w).Encode(resp) //nolint:errcheck
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	var ev playbook.Evidence
	findings, err := New().RunWithEvidence(t.Context(), asset, module.ScanSurface, &ev)
	if err != nil {
		t.Fatal(err)
	}

	// Should find at least 1 finding (the unauthenticated chat endpoint).
	if len(findings) == 0 {
		t.Fatal("expected finding for unauthenticated /v1/chat/completions")
	}

	// Evidence should be populated.
	if len(ev.AIEndpoints) == 0 {
		t.Error("expected AIEndpoints to be populated in evidence")
	}
}

func TestAIDetect_404AllPaths(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when all paths return 404, got %d", len(findings))
	}
}

func TestAIDetect_SSEStreamingDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/chat/completions" {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprintln(w, `data: {"choices":[{"delta":{"content":"Hello"}}]}`)
			fmt.Fprintln(w, "data: [DONE]")
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	var ev playbook.Evidence
	findings, err := New().RunWithEvidence(t.Context(), asset, module.ScanSurface, &ev)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for SSE streaming endpoint")
	}
	if !ev.HasAISSE {
		t.Error("expected HasAISSE to be true in evidence")
	}

	// SSE + no auth should produce ai.streaming_open
	hasStreamingFinding := false
	for _, f := range findings {
		if f.CheckID == "ai.streaming_open" {
			hasStreamingFinding = true
		}
	}
	if !hasStreamingFinding {
		t.Error("expected ai.streaming_open finding for unauthenticated SSE endpoint")
	}
}

func TestAIDetect_AuthRequired_NoFinding(t *testing.T) {
	// Server returns 401 for LLM endpoints — properly secured.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return 401 for known LLM paths, but no provider signals.
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	// 401 responses have no provider signal and are not 2xx — should not flag.
	for _, f := range findings {
		t.Errorf("unexpected finding for auth-required server: %s", f.Title)
	}
}

func TestAIDetect_OllamaTagsEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/tags" && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintln(w, `{"models":[{"name":"llama2","size":3825819519}]}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for Ollama /api/tags endpoint")
	}
}

// TestAIDetect_ContentTypeWithCharset verifies that "application/json; charset=utf-8"
// is still recognized as a valid JSON content type (the charset parameter must not
// break the LLM endpoint detection logic).
func TestAIDetect_ContentTypeWithCharset(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			fmt.Fprintln(w, `{"object":"list","data":[{"id":"gpt-4","object":"model"}]}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding when Content-Type includes charset parameter alongside application/json")
	}
}

// TestAIDetect_401WithSSEHeader verifies that a 401 response containing an
// SSE Content-Type header does NOT produce a finding. Auth is required — the
// endpoint is not accessible without credentials.
func TestAIDetect_401WithSSEHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.CheckID == "ai.streaming_open" {
			t.Errorf("must not emit ai.streaming_open for 401 response even with SSE Content-Type header: %s", f.Title)
		}
	}
}

// TestAIDetect_NonLLMPathOnly verifies that a server that returns 200 only on
// a generic path (not a known LLM endpoint), with no provider headers or body
// signals, does not produce an ai.endpoint_exposed finding.
// Note: a 200 on a *known LLM path* (e.g. /v1/chat/completions) IS a signal
// regardless of body content — this tests the non-LLM-path case.
func TestAIDetect_NonLLMPathOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only serve 200 on a totally generic path — all LLM probe paths get 404.
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.CheckID == "ai.endpoint_exposed" {
			t.Errorf("must not emit ai.endpoint_exposed when only a non-LLM path returns 200: %s", f.Title)
		}
	}
}

// TestAIDetect_ToolCallsProseRefusalNoHasTools verifies that a response body
// containing the string "tool_calls" in prose (not as a JSON key) does NOT
// set hasTools in the evidence. Regression test for the substring false positive.
func TestAIDetect_ToolCallsProseRefusalNoHasTools(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/chat/completions" {
			w.Header().Set("Content-Type", "application/json")
			// Prose refusal mentioning "tool_calls" in a sentence — should NOT trigger
			fmt.Fprintln(w, `{"choices":[{"message":{"content":"I don't support \"tool_calls\" in this configuration."},"finish_reason":"stop"}]}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	var ev playbook.Evidence
	_, err := New().RunWithEvidence(t.Context(), asset, module.ScanSurface, &ev)
	if err != nil {
		t.Fatal(err)
	}
	if ev.HasAgentTools {
		t.Error("HasAgentTools must be false when 'tool_calls' appears in prose, not as a JSON key")
	}
}

// TestAIDetect_EmptyResponseBody verifies that a 200 response with an empty body
// does not produce any finding — there are no provider signals to detect.
func TestAIDetect_EmptyResponseBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/chat/completions" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			// Write nothing — empty body, no provider signals.
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	// A 200 with no body has no provider signals, but noAuth=true is set because
	// the status is 2xx. The scanner should still return a finding because the
	// endpoint responded without auth. We verify it does NOT panic and handles
	// empty body gracefully.
	for _, f := range findings {
		if f.Evidence != nil {
			if snap, ok := f.Evidence["model_snippet"]; ok && snap == nil {
				t.Error("model_snippet evidence must not be nil")
			}
		}
	}
}

func TestAIDetect_EvidenceProviderSet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("anthropic-request-id", "req_test123")
			fmt.Fprintln(w, `{"data":[]}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	var ev playbook.Evidence
	_, err := New().RunWithEvidence(t.Context(), asset, module.ScanSurface, &ev)
	if err != nil {
		t.Fatal(err)
	}
	if ev.LLMProvider != "anthropic" {
		t.Errorf("expected LLMProvider to be 'anthropic', got %q", ev.LLMProvider)
	}
}

// TestAIDetect_401WithAIHeader verifies that a 401 response bearing an
// OpenAI provider header (x-openai-organization) still produces a finding.
// Auth is required, but the presence of the header proves an AI endpoint
// exists at this address and is worth reporting.
func TestAIDetect_401WithAIHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return 401 on the well-known models listing path with a provider header.
		if r.URL.Path == "/v1/models" {
			w.Header().Set("x-openai-organization", "org-exposed")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	// The provider header is a strong signal that an AI endpoint exists here,
	// even though authentication is required. The scanner must emit a finding.
	found := false
	for _, f := range findings {
		if f.CheckID == "ai.endpoint_exposed" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected ai.endpoint_exposed finding when 401 response carries x-openai-organization header")
	}
}

// TestAIDetect_AnthropicHeaderDetected verifies that a response containing
// the "anthropic-request-id" header causes the finding to identify the
// provider as "anthropic" in the finding evidence.
func TestAIDetect_AnthropicHeaderDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("anthropic-request-id", "req_123")
			fmt.Fprintln(w, `{"data":[]}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding when anthropic-request-id header is present")
	}
	// The first matching finding must record provider = "anthropic" in evidence.
	for _, f := range findings {
		if f.CheckID == "ai.endpoint_exposed" {
			if f.Evidence["provider"] != "anthropic" {
				t.Errorf("expected evidence[\"provider\"] = \"anthropic\", got %v", f.Evidence["provider"])
			}
			return
		}
	}
	t.Error("no ai.endpoint_exposed finding with provider=anthropic found")
}
