package analyze_test

// Tests for suggestion parsing — derived from the spec:
//   - Claude returns a JSON array of suggestion objects
//   - Objects missing required fields (type, target_playbook, suggested_yaml) are skipped
//   - Claude output with surrounding prose is handled (extract the JSON array)
//   - Empty response (no JSON array) returns zero suggestions, not an error
//   - Valid suggestions get status "pending"
//   - Both "new" and "improve" types are accepted

import (
	"testing"

	// Reach into the package's exported surface via the public Run method is
	// not feasible without a real store + API key, so we test parseSuggestions
	// by making it exported in a test-only way via a thin wrapper.
	// Instead we test the overall contract at the store level: any suggestions
	// returned from a run end up in the store with status "pending".
	//
	// For pure parsing logic we test via the public API: Run with a fake HTTP
	// server that returns known JSON, then verify the store contains the right
	// suggestions.  To avoid a live network call we expose a NewWithAPIURL
	// constructor that accepts a custom API endpoint — used only in tests.
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/stormbane/beacon/internal/analyze"
	memstore "github.com/stormbane/beacon/internal/store/memory"
)

// fakeEmptyIntelServer returns a server that responds with empty intel payloads.
func fakeEmptyIntelServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Minimal valid responses for both CISA KEV and NVD formats.
		fmt.Fprint(w, `{"vulnerabilities":[]}`)
	}))
}

// fakeClaudeServer returns a test server that responds with a fixed JSON body.
func fakeClaudeServer(t *testing.T, responseBody string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate Anthropic API response format.
		resp := map[string]any{
			"content": []map[string]any{
				{"type": "text", "text": responseBody},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp) //nolint:errcheck
	}))
}

func TestRunSavesValidSuggestionsWithStatusPending(t *testing.T) {
	claudeOutput := `[
		{
			"type": "new",
			"target_playbook": "hashicorp_vault",
			"suggested_yaml": "name: hashicorp_vault\nmatch:\n  any:\n    - title_contains: \"Vault\"\nsurface:\n  nuclei_tags: [vault]\n",
			"reasoning": "Several unmatched assets show Vault login pages"
		}
	]`

	srv := fakeClaudeServer(t, claudeOutput)
	defer srv.Close()

	// Point intel sources at empty servers so tests don't hit real network.
	emptySrv := fakeEmptyIntelServer(t)
	defer emptySrv.Close()

	st := memstore.New()
	a, err := analyze.NewWithAPIURL(st, "fake-key", srv.URL+"/v1/messages")
	if err != nil {
		t.Fatalf("create analyzer: %v", err)
	}
	a.WithIntelSources(analyze.IntelSources{CISAURL: emptySrv.URL, NVDURL: emptySrv.URL})

	n, err := a.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if n != 1 {
		t.Errorf("Run returned %d suggestions; want 1", n)
	}

	suggestions, err := st.ListPlaybookSuggestions(context.Background(), "pending")
	if err != nil {
		t.Fatalf("list suggestions: %v", err)
	}
	if len(suggestions) != 1 {
		t.Fatalf("store has %d pending suggestions; want 1", len(suggestions))
	}

	s := suggestions[0]
	if s.Status != "pending" {
		t.Errorf("suggestion status = %q; want %q", s.Status, "pending")
	}
	if s.Type != "new" {
		t.Errorf("suggestion type = %q; want %q", s.Type, "new")
	}
	if s.TargetPlaybook != "hashicorp_vault" {
		t.Errorf("target_playbook = %q; want %q", s.TargetPlaybook, "hashicorp_vault")
	}
}

// withFakeIntel points the analyzer at empty intel servers so no real network
// calls are made during tests that only care about suggestion parsing.
func withFakeIntel(t *testing.T, a *analyze.Analyzer) *analyze.Analyzer {
	t.Helper()
	empty := fakeEmptyIntelServer(t)
	t.Cleanup(empty.Close)
	return a.WithIntelSources(analyze.IntelSources{CISAURL: empty.URL, NVDURL: empty.URL})
}

func TestRunHandlesProseWrappingJSONArray(t *testing.T) {
	claudeOutput := `Here are my suggestions based on the scan data:

[
  {
    "type": "improve",
    "target_playbook": "wordpress",
    "suggested_yaml": "name: wordpress\nmatch:\n  any:\n    - body_contains: \"wp-content\"\n",
    "reasoning": "Add xmlrpc exposure tag"
  }
]

Let me know if you need any changes.`

	srv := fakeClaudeServer(t, claudeOutput)
	defer srv.Close()

	st := memstore.New()
	a, err := analyze.NewWithAPIURL(st, "fake-key", srv.URL+"/v1/messages")
	if err != nil {
		t.Fatalf("create analyzer: %v", err)
	}
	withFakeIntel(t, a)

	n, err := a.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if n != 1 {
		t.Errorf("Run returned %d suggestions; want 1 (must extract JSON from prose)", n)
	}
}

func TestRunReturnsZeroSuggestionsWhenClaudeOutputHasNoArray(t *testing.T) {
	claudeOutput := `I have analyzed the scan data but found no patterns warranting new playbooks at this time.`

	srv := fakeClaudeServer(t, claudeOutput)
	defer srv.Close()

	st := memstore.New()
	a, err := analyze.NewWithAPIURL(st, "fake-key", srv.URL+"/v1/messages")
	if err != nil {
		t.Fatalf("create analyzer: %v", err)
	}
	withFakeIntel(t, a)

	n, err := a.Run(context.Background())
	if err != nil {
		t.Fatalf("Run must not error when there are no suggestions: %v", err)
	}
	if n != 0 {
		t.Errorf("Run returned %d suggestions; want 0", n)
	}
}

func TestRunSkipsSuggestionsWithMissingRequiredFields(t *testing.T) {
	claudeOutput := `[
		{
			"type": "new",
			"target_playbook": "valid_playbook",
			"suggested_yaml": "name: valid_playbook\nmatch:\n  always: true\n",
			"reasoning": "valid"
		},
		{
			"type": "new",
			"target_playbook": "missing_yaml"
		},
		{
			"type": "improve",
			"suggested_yaml": "name: x\n"
		}
	]`

	srv := fakeClaudeServer(t, claudeOutput)
	defer srv.Close()

	st := memstore.New()
	a, err := analyze.NewWithAPIURL(st, "fake-key", srv.URL+"/v1/messages")
	if err != nil {
		t.Fatalf("create analyzer: %v", err)
	}
	withFakeIntel(t, a)

	n, err := a.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if n != 1 {
		t.Errorf("Run returned %d suggestions; want 1 (invalid entries must be skipped)", n)
	}
}

func TestRunAcceptsBothNewAndImproveTypes(t *testing.T) {
	claudeOutput := `[
		{
			"type": "new",
			"target_playbook": "new_thing",
			"suggested_yaml": "name: new_thing\nmatch:\n  always: true\n",
			"reasoning": "new playbook"
		},
		{
			"type": "improve",
			"target_playbook": "existing_playbook",
			"suggested_yaml": "name: existing_playbook\nmatch:\n  always: true\n",
			"reasoning": "improve existing"
		}
	]`

	srv := fakeClaudeServer(t, claudeOutput)
	defer srv.Close()

	st := memstore.New()
	a, err := analyze.NewWithAPIURL(st, "fake-key", srv.URL+"/v1/messages")
	if err != nil {
		t.Fatalf("create analyzer: %v", err)
	}
	withFakeIntel(t, a)

	n, err := a.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if n != 2 {
		t.Errorf("Run returned %d suggestions; want 2", n)
	}

	suggestions, _ := st.ListPlaybookSuggestions(context.Background(), "pending")
	types := make(map[string]bool)
	for _, s := range suggestions {
		types[s.Type] = true
	}
	if !types["new"] {
		t.Error("expected a suggestion of type 'new'")
	}
	if !types["improve"] {
		t.Error("expected a suggestion of type 'improve'")
	}
}
