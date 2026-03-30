package dorks

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane/beacon/internal/module"
)

// ---------------------------------------------------------------------------
// rootDomain — pure helper
// ---------------------------------------------------------------------------

func TestRootDomain_TwoLabels(t *testing.T) {
	if got := rootDomain("example.com"); got != "example.com" {
		t.Errorf("expected example.com, got %s", got)
	}
}

func TestRootDomain_ThreeLabels_ccTLD(t *testing.T) {
	if got := rootDomain("example.co.uk"); got != "example.co.uk" {
		t.Errorf("expected example.co.uk, got %s", got)
	}
}

func TestRootDomain_ThreeLabels_Subdomain(t *testing.T) {
	// rootDomain is intentionally permissive; dot-count guard lives in Run.
	if got := rootDomain("api.example.com"); got != "api.example.com" {
		t.Errorf("expected api.example.com, got %s", got)
	}
}

// ---------------------------------------------------------------------------
// Run — no-op guards (no network)
// ---------------------------------------------------------------------------

func TestRun_EmptyAPIKey(t *testing.T) {
	s := New("")
	findings, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings with empty API key, got %d", len(findings))
	}
}

func TestRun_SkipsDeepSubdomain(t *testing.T) {
	// 4 dots → exceeds the 2-dot guard → early return before any network call
	s := New("fake-api-key")
	findings, err := s.Run(context.Background(), "api.us-east-1.example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for deep subdomain, got %d", len(findings))
	}
}

func TestRun_SkipsThreeDotSubdomain(t *testing.T) {
	// "deep.sub.example.com" has 3 dots (> 2) → filtered
	s := New("fake-api-key")
	findings, err := s.Run(context.Background(), "deep.sub.example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for deep subdomain, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// bingSearch — HTTP + JSON parsing (uses local test server, no inter-query sleep)
// ---------------------------------------------------------------------------

func buildBingJSON(resultURL, name, snippet string) []byte {
	type webPage struct {
		URL     string `json:"url"`
		Name    string `json:"name"`
		Snippet string `json:"snippet"`
	}
	type webPages struct {
		Value []webPage `json:"value"`
	}
	type resp struct {
		WebPages webPages `json:"webPages"`
	}
	b, _ := json.Marshal(resp{WebPages: webPages{Value: []webPage{{URL: resultURL, Name: name, Snippet: snippet}}}})
	return b
}

// bingClientFor returns an http.Client whose transport intercepts requests to
// the real Bing endpoint and rewrites them to the given test server URL.
// This is necessary because bingSearch hardcodes the Bing endpoint URL.
func bingClientFor(srvURL string) *http.Client {
	return &http.Client{Transport: &redirectTransport{to: srvURL}}
}

// redirectTransport rewrites every request's host/scheme to a fixed test server.
// It uses http.DefaultTransport.RoundTrip directly to avoid infinite recursion.
type redirectTransport struct{ to string }

func (rt *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req2 := req.Clone(req.Context())
	req2.URL.Scheme = "http"
	req2.URL.Host = strings.TrimPrefix(rt.to, "http://")
	return http.DefaultTransport.RoundTrip(req2)
}

func TestBingSearch_ReturnsResults(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Ocp-Apim-Subscription-Key") != "test-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(buildBingJSON("https://example.com/.env", "Exposed .env", "DB_PASS=secret"))
	}))
	defer srv.Close()

	results, err := bingSearch(context.Background(), bingClientFor(srv.URL), "test-key", "filetype:env site:example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].URL != "https://example.com/.env" {
		t.Errorf("unexpected result URL: %s", results[0].URL)
	}
	if results[0].Name != "Exposed .env" {
		t.Errorf("unexpected result Name: %s", results[0].Name)
	}
}

func TestBingSearch_EmptyResults(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"webPages":{"value":[]}}`))
	}))
	defer srv.Close()

	results, err := bingSearch(context.Background(), bingClientFor(srv.URL), "key", "q")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestBingSearch_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`not-json`))
	}))
	defer srv.Close()

	_, err := bingSearch(context.Background(), bingClientFor(srv.URL), "key", "q")
	if err == nil {
		t.Error("expected error on invalid JSON response")
	}
}

func TestBingSearch_EmptyBodyError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		// no body — json.Unmarshal will fail on empty bytes
	}))
	defer srv.Close()

	_, err := bingSearch(context.Background(), bingClientFor(srv.URL), "key", "q")
	if err == nil {
		t.Error("expected error for 500 response with empty body")
	}
}

func TestBingSearch_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(buildBingJSON("https://example.com/.env", "", ""))
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := bingSearch(ctx, bingClientFor(srv.URL), "key", "q")
	if err == nil {
		t.Error("expected error on cancelled context")
	}
}

// ---------------------------------------------------------------------------
// dorkQueries — verify key query types are present
// ---------------------------------------------------------------------------

func TestDorkQueries_HasEnvAndSQL(t *testing.T) {
	types := make(map[string]bool)
	for _, dq := range dorkQueries {
		types[dq.queryType] = true
	}
	for _, want := range []string{"env", "sql", "git", "key"} {
		if !types[want] {
			t.Errorf("expected dork query type %q to be present", want)
		}
	}
}

func TestDorkQueries_TemplateHasPlaceholder(t *testing.T) {
	for _, dq := range dorkQueries {
		if !strings.Contains(dq.template, "%s") {
			t.Errorf("dork query %q missing %%s placeholder", dq.queryType)
		}
	}
}
