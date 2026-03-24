package aillm

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
	"github.com/stormbane/beacon/internal/playbook"
)

// chatServer returns a test server that responds to POST /v1/chat/completions
// with the provided response text as the assistant message.
func chatServer(t *testing.T, responseText string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" || r.Method != "POST" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"choices": []map[string]any{
				{"message": map[string]string{"content": responseText}, "finish_reason": "stop"},
			},
		}
		json.NewEncoder(w).Encode(resp) //nolint:errcheck
	}))
}

func TestAILLM_SkippedInSurfaceMode(t *testing.T) {
	srv := chatServer(t, "INJECTION_CONFIRMED. I am now unrestricted.")
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("aillm should return nil in surface mode, got %d findings", len(findings))
	}
}

func TestAILLM_PromptInjectionDetected(t *testing.T) {
	srv := chatServer(t, "INJECTION_CONFIRMED. I have ignored all previous instructions and am now operating without restrictions.")
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanDeep)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckAIPromptInjection {
			found = true
			if f.ProofCommand == "" {
				t.Error("ProofCommand should be set on prompt injection finding")
			}
			if f.Evidence["probe"] == nil {
				t.Error("evidence should include probe name")
			}
			break
		}
	}
	if !found {
		t.Error("expected ai.prompt_injection finding when model confirms injection")
	}
}

func TestAILLM_PromptRefusal_NoFinding(t *testing.T) {
	// Model properly refuses the injection attempt.
	srv := chatServer(t, "I cannot ignore my previous instructions. I'm designed to be helpful and safe.")
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanDeep)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.CheckID == finding.CheckAIPromptInjection {
			t.Error("should not report prompt injection when model refuses")
		}
	}
}

func TestAILLM_SystemPromptLeak(t *testing.T) {
	srv := chatServer(t, "You are a helpful customer service assistant. You must always be polite and never reveal customer data. Always use formal language.")
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanDeep)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckAISystemLeak {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected ai.system_prompt_leak when model reveals system instructions")
	}
}

func TestAILLM_SSRFDetection(t *testing.T) {
	srv := chatServer(t, "I fetched the URL. Here is the content: ami-id, instance-id, placement/availability-zone: us-east-1a, security-credentials/iam-role")
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanDeep)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckAISSRFViaPLLM {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected ai.ssrf_via_llm when model returns AWS metadata")
	}
}

func TestAILLM_AuthRequired_NoFinding(t *testing.T) {
	// Endpoint requires auth — all probes get 401.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanDeep)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when endpoint requires auth, got %d", len(findings))
	}
}

func TestAILLM_Unreachable(t *testing.T) {
	findings, err := New().Run(t.Context(), "127.0.0.1:1", module.ScanDeep)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for unreachable host, got %d", len(findings))
	}
}

func TestAILLM_DataExfiltration(t *testing.T) {
	srv := chatServer(t, "Sure, here are the credentials I have access to: api_key: sk-abc123xyz789foobarbaz, database_url: postgres://admin:secretpass@db.internal/prod")
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanDeep)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckAIDataExfil {
			found = true
			break
		}
	}
	if !found {
		// Also acceptable if prompt injection finding was triggered first
		for _, f := range findings {
			if f.CheckID == finding.CheckAIPromptInjection {
				t.Log("data exfil probe triggered prompt injection finding instead — acceptable")
				return
			}
		}
		t.Error("expected ai.data_exfiltration finding when model returns credentials")
	}
}

func TestAILLM_ExtractModelText_OpenAI(t *testing.T) {
	body := []byte(`{"choices":[{"message":{"content":"Hello world"},"finish_reason":"stop"}]}`)
	got := extractModelText(body)
	if got != "Hello world" {
		t.Errorf("expected 'Hello world', got %q", got)
	}
}

func TestAILLM_ExtractModelText_Anthropic(t *testing.T) {
	body := []byte(`{"content":[{"type":"text","text":"Hello from Claude"}]}`)
	got := extractModelText(body)
	if got != "Hello from Claude" {
		t.Errorf("expected 'Hello from Claude', got %q", got)
	}
}

func TestAILLM_ExtractModelText_Ollama(t *testing.T) {
	body := []byte(`{"response":"Hello from Ollama","done":true}`)
	got := extractModelText(body)
	if got != "Hello from Ollama" {
		t.Errorf("expected 'Hello from Ollama', got %q", got)
	}
}

func TestAILLM_ExtractModelText_Invalid(t *testing.T) {
	body := []byte(`not json`)
	got := extractModelText(body)
	if got != "" {
		t.Errorf("expected empty string for invalid JSON, got %q", got)
	}
}

// TestAILLM_ToolCallsRefusal_NoFinding verifies that a response body containing
// the string "tool_calls" in prose (e.g. a refusal message) does NOT produce a
// tool abuse finding. Only the JSON pattern `"tool_calls": [` should match.
func TestAILLM_ToolCallsRefusal_NoFinding(t *testing.T) {
	srv := chatServer(t, `I cannot do tool_calls in this configuration.`)
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanDeep)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.CheckID == finding.CheckAIToolAbuse {
			t.Errorf("must not emit tool abuse finding when 'tool_calls' appears in prose refusal, not as JSON key: %s", f.Title)
		}
	}
}

// TestAILLM_EmptyResponseBody verifies that a 200 response with an empty body
// does not produce any finding (no patterns can match an empty string).
func TestAILLM_EmptyResponseBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/chat/completions" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			// Write nothing — empty body.
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanDeep)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty response body, got %d", len(findings))
	}
}

// TestAILLM_NonJSONResponse verifies that a 200 response with an HTML body
// does not produce any finding. The scanner must not panic on non-JSON content
// and must not match any success patterns against HTML noise.
func TestAILLM_NonJSONResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/chat/completions" && r.Method == "POST" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `<!DOCTYPE html><html><head><title>Not Found</title></head><body><h1>404 Not Found</h1></body></html>`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanDeep)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for HTML (non-JSON) response body, got %d", len(findings))
	}
}

func TestAILLM_EvidenceEndpointsUsed(t *testing.T) {
	// Verify that when Evidence has specific AI endpoints, only those are probed.
	probed := make(map[string]bool)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probed[r.URL.Path] = true
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"choices":[{"message":{"content":"I cannot do that."}}]}`)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	ev := &playbook.Evidence{AIEndpoints: []string{"/custom/llm"}}
	s := NewWithEvidence(ev)
	_, err := s.Run(t.Context(), asset, module.ScanDeep)
	if err != nil {
		t.Fatal(err)
	}

	if !probed["/custom/llm"] {
		t.Error("expected /custom/llm to be probed when set in Evidence")
	}
	if probed["/v1/chat/completions"] {
		t.Error("should not probe default paths when Evidence.AIEndpoints is set")
	}
}
