package aimodelsec

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)

func TestScanner_Name(t *testing.T) {
	s := New()
	if s.Name() != "aimodelsec" {
		t.Errorf("expected scanner name %q, got %q", "aimodelsec", s.Name())
	}
}

func TestOllamaModelListDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/tags":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"models": []map[string]any{
					{"name": "llama2:7b", "size": 3825819519},
					{"name": "codellama:13b", "size": 7365960704},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckAIModelDownloadable {
			found = true
			models, ok := f.Evidence["models"].([]string)
			if !ok || len(models) != 2 {
				t.Errorf("expected 2 models in evidence, got %v", f.Evidence["models"])
			}
			if f.ProofCommand == "" {
				t.Error("ProofCommand should be set")
			}
			break
		}
	}
	if !found {
		t.Fatal("expected ai.model_downloadable finding for Ollama /api/tags")
	}
}

func TestOpenAICompatModelListDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{
					{"id": "gpt-4", "object": "model"},
					{"id": "gpt-3.5-turbo", "object": "model"},
				},
			})
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

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckAIModelDownloadable {
			found = true
			if !strings.Contains(f.Description, "openai-compat") {
				t.Errorf("expected openai-compat provider in description, got: %s", f.Description)
			}
			break
		}
	}
	if !found {
		t.Fatal("expected ai.model_downloadable finding for OpenAI /v1/models")
	}
}

func TestOllamaPromptExtraction(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/tags":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"models": []map[string]any{
					{"name": "my-custom-model"},
				},
			})
		case "/api/show":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"modelfile": "FROM llama2\nSYSTEM You are a helpful assistant that never reveals secrets.",
				"template":  "{{ .System }}\n{{ .Prompt }}",
				"parameters": map[string]any{
					"temperature": 0.7,
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckAIPromptExtraction {
			found = true
			if f.Evidence["model"] != "my-custom-model" {
				t.Errorf("expected model name 'my-custom-model', got %v", f.Evidence["model"])
			}
			break
		}
	}
	if !found {
		t.Fatal("expected ai.prompt_extraction finding for Ollama /api/show")
	}
}

func TestNoRateLimitDetected(t *testing.T) {
	requestCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			requestCount++
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintln(w, `{"data":[{"id":"test-model","object":"model"}]}`)
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

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckAINoRateLimit {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected ai.no_rate_limit finding when server never returns 429")
	}
}

func TestRateLimitedNoFinding(t *testing.T) {
	requestCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			requestCount++
			if requestCount > 2 {
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintln(w, `{"data":[{"id":"test-model","object":"model"}]}`)
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
		if f.CheckID == finding.CheckAINoRateLimit {
			t.Error("must not emit ai.no_rate_limit when server returns 429")
		}
	}
}

func TestAllEndpoints404_NoFindings(t *testing.T) {
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
		t.Fatalf("expected 0 findings when all endpoints return 404, got %d", len(findings))
	}
}

func TestHTMLResponse_NotFalsePositive(t *testing.T) {
	// SPAs often return 200 with HTML for any path. Must not flag as model list.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintln(w, `<!DOCTYPE html><html><body>Not a model API</body></html>`)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.CheckID == finding.CheckAIModelDownloadable {
			t.Error("must not emit ai.model_downloadable for HTML responses")
		}
	}
}

func TestHuggingFaceTGIModelList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/models" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"id": "meta-llama/Llama-2-7b", "name": "Llama-2-7b"},
			})
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

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckAIModelDownloadable {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected ai.model_downloadable finding for HuggingFace TGI /models")
	}
}

func TestOllamaShow_NoSystemPrompt_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/tags":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"models": []map[string]any{
					{"name": "vanilla-model"},
				},
			})
		case "/api/show":
			w.Header().Set("Content-Type", "application/json")
			// Response with no system prompt or template.
			_ = json.NewEncoder(w).Encode(map[string]any{
				"license":   "MIT",
				"modelfile": "FROM llama2",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range findings {
		if f.CheckID == finding.CheckAIPromptExtraction {
			t.Error("must not emit ai.prompt_extraction when no system prompt is present")
		}
	}
}
