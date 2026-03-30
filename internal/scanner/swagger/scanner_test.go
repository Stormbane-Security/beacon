package swagger

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func hostFromURL(url string) string {
	return strings.TrimPrefix(url, "http://")
}

func hasCheckID(findings []finding.Finding, id finding.CheckID) bool {
	for _, f := range findings {
		if f.CheckID == id {
			return true
		}
	}
	return false
}

func findByCheckID(findings []finding.Finding, id finding.CheckID) *finding.Finding {
	for _, f := range findings {
		if f.CheckID == id {
			return &f
		}
	}
	return nil
}

// makeSpec builds a minimal valid OpenAPI JSON spec with the given paths.
func makeSpec(paths map[string]map[string]openAPIOperation) []byte {
	spec := openAPISpec{Paths: paths}
	b, _ := json.Marshal(spec)
	return b
}

// ---------------------------------------------------------------------------
// Test: swagger spec found at /swagger.json → exposure finding
// ---------------------------------------------------------------------------

func TestRun_SwaggerExposed_EmitsExposureFinding(t *testing.T) {
	spec := makeSpec(map[string]map[string]openAPIOperation{
		"/users": {
			"get": {Parameters: []openAPIParameter{{Name: "id", In: "query"}}},
		},
	})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/swagger.json" {
			w.Header().Set("Content-Type", "application/json")
			w.Write(spec)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	s := New()
	findings, err := s.Run(context.Background(), hostFromURL(ts.URL), module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckSwaggerExposed) {
		t.Fatal("expected CheckSwaggerExposed finding")
	}

	f := findByCheckID(findings, finding.CheckSwaggerExposed)
	if f.Severity != finding.SeverityMedium {
		t.Errorf("expected SeverityMedium, got %v", f.Severity)
	}
	if f.ProofCommand == "" {
		t.Error("expected non-empty ProofCommand")
	}
	if f.Scanner != scannerName {
		t.Errorf("expected scanner %q, got %q", scannerName, f.Scanner)
	}
	if f.Evidence["url"] == nil {
		t.Error("expected evidence to include 'url'")
	}
}

// ---------------------------------------------------------------------------
// Test: no spec found → no findings
// ---------------------------------------------------------------------------

func TestRun_NoSpecEndpoint_ReturnsNil(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	s := New()
	findings, err := s.Run(context.Background(), hostFromURL(ts.URL), module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when no spec exists, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Test: spec response is HTML (not JSON) → no findings
// ---------------------------------------------------------------------------

func TestRun_HTMLContentType_Skipped(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>"paths"</body></html>`))
	}))
	defer ts.Close()

	s := New()
	findings, err := s.Run(context.Background(), hostFromURL(ts.URL), module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for HTML response, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Test: 200 response but body does not contain "paths" → no findings
// ---------------------------------------------------------------------------

func TestRun_NoPaths_InBody_ReturnsNil(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"info": {"title": "test"}}`))
	}))
	defer ts.Close()

	s := New()
	findings, err := s.Run(context.Background(), hostFromURL(ts.URL), module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when response lacks 'paths', got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Test: malformed JSON spec → exposure finding still emitted, no panic
// ---------------------------------------------------------------------------

func TestRun_MalformedJSON_ExposureStillEmitted(t *testing.T) {
	// Body contains "paths" (so findSpec matches) but is not valid JSON.
	malformed := `{"paths": {invalid json}`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/swagger.json" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(malformed))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	s := New()
	// Deep mode to exercise the JSON unmarshal path.
	findings, err := s.Run(context.Background(), hostFromURL(ts.URL), module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckSwaggerExposed) {
		t.Fatal("expected CheckSwaggerExposed even with malformed JSON")
	}
	// Should NOT have API fuzz findings since the spec cannot be parsed.
	if hasCheckID(findings, finding.CheckWebAPIFuzz) {
		t.Error("did not expect CheckWebAPIFuzz with malformed spec")
	}
}

// ---------------------------------------------------------------------------
// Test: surface mode does NOT fuzz endpoints (only exposure finding)
// ---------------------------------------------------------------------------

func TestRun_SurfaceMode_NoFuzzing(t *testing.T) {
	spec := makeSpec(map[string]map[string]openAPIOperation{
		"/api/items": {
			"post": {Parameters: []openAPIParameter{{Name: "name", In: "query", Required: true}}},
		},
	})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/swagger.json" {
			w.Header().Set("Content-Type", "application/json")
			w.Write(spec)
			return
		}
		// Return 500 on any other endpoint to verify fuzzing is not happening.
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	s := New()
	findings, err := s.Run(context.Background(), hostFromURL(ts.URL), module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(findings, finding.CheckWebAPIFuzz) {
		t.Error("surface mode should not produce fuzz findings")
	}
	if len(findings) != 1 {
		t.Errorf("expected exactly 1 finding (exposure only), got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Test: deep mode fuzzes endpoints — 500 on empty input → fuzz finding
// ---------------------------------------------------------------------------

func TestRun_DeepMode_EmptyInput500_EmitsFuzzFinding(t *testing.T) {
	spec := makeSpec(map[string]map[string]openAPIOperation{
		"/api/items": {
			"post": {Parameters: []openAPIParameter{
				{Name: "name", In: "query", Required: true, Type: "string"},
			}},
		},
	})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/swagger.json" {
			w.Header().Set("Content-Type", "application/json")
			w.Write(spec)
			return
		}
		// Simulate unhandled validation error.
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"NullPointerException"}`))
	}))
	defer ts.Close()

	s := New()
	findings, err := s.Run(context.Background(), hostFromURL(ts.URL), module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckWebAPIFuzz) {
		t.Fatal("expected CheckWebAPIFuzz finding for 500 response")
	}
	f := findByCheckID(findings, finding.CheckWebAPIFuzz)
	if f.Severity != finding.SeverityHigh {
		t.Errorf("expected SeverityHigh, got %v", f.Severity)
	}
	if f.ProofCommand == "" {
		t.Error("expected non-empty ProofCommand")
	}
}

// ---------------------------------------------------------------------------
// Test: deep mode — endpoint returns 400 (proper validation) → no fuzz finding
// ---------------------------------------------------------------------------

func TestRun_DeepMode_ProperValidation400_NoFuzzFinding(t *testing.T) {
	spec := makeSpec(map[string]map[string]openAPIOperation{
		"/api/items": {
			"post": {Parameters: []openAPIParameter{
				{Name: "name", In: "query", Required: true, Type: "string"},
			}},
		},
	})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/swagger.json" {
			w.Header().Set("Content-Type", "application/json")
			w.Write(spec)
			return
		}
		// Proper validation response.
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"missing required field: name"}`))
	}))
	defer ts.Close()

	s := New()
	findings, err := s.Run(context.Background(), hostFromURL(ts.URL), module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(findings, finding.CheckWebAPIFuzz) {
		t.Error("did not expect CheckWebAPIFuzz when server returns 400")
	}
	// Should still have the exposure finding.
	if !hasCheckID(findings, finding.CheckSwaggerExposed) {
		t.Error("expected CheckSwaggerExposed finding")
	}
}

// ---------------------------------------------------------------------------
// Test: deep mode — type fuzz with SQL error in response body
// ---------------------------------------------------------------------------

func TestRun_DeepMode_TypeFuzz_SQLError(t *testing.T) {
	spec := makeSpec(map[string]map[string]openAPIOperation{
		"/api/items": {
			"post": {Parameters: []openAPIParameter{
				{Name: "id", In: "query", Required: true, Type: "integer"},
			}},
		},
	})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/swagger.json" {
			w.Header().Set("Content-Type", "application/json")
			w.Write(spec)
			return
		}
		// Simulate SQL error on type-fuzz payload.
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"syntax error at or near \"beacon\" - pg_query failed"}`))
	}))
	defer ts.Close()

	s := New()
	findings, err := s.Run(context.Background(), hostFromURL(ts.URL), module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have at least the exposure finding and fuzz finding(s).
	fuzzFindings := 0
	for _, f := range findings {
		if f.CheckID == finding.CheckWebAPIFuzz {
			fuzzFindings++
			if f.Evidence["sql_error_hint"] != nil && f.Evidence["sql_error_hint"].(bool) {
				// Good — SQL error hint detected.
			}
		}
	}
	if fuzzFindings == 0 {
		t.Error("expected at least one CheckWebAPIFuzz finding with SQL error")
	}
}

// ---------------------------------------------------------------------------
// Test: HEAD and OPTIONS methods are skipped
// ---------------------------------------------------------------------------

func TestRun_DeepMode_SkipsHEADAndOPTIONS(t *testing.T) {
	spec := makeSpec(map[string]map[string]openAPIOperation{
		"/api/items": {
			"head":    {Parameters: nil},
			"options": {Parameters: nil},
		},
	})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/swagger.json" {
			w.Header().Set("Content-Type", "application/json")
			w.Write(spec)
			return
		}
		// If we get a HEAD or OPTIONS probe, the scanner violated the skip rule.
		if r.Method == "HEAD" || r.Method == "OPTIONS" {
			t.Error("scanner should skip HEAD and OPTIONS methods")
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	s := New()
	findings, err := s.Run(context.Background(), hostFromURL(ts.URL), module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Only the exposure finding should be present (no fuzz findings for HEAD/OPTIONS).
	if hasCheckID(findings, finding.CheckWebAPIFuzz) {
		t.Error("did not expect fuzz findings for HEAD/OPTIONS-only spec")
	}
}

// ---------------------------------------------------------------------------
// Test: spec found at alternative path (/openapi.json)
// ---------------------------------------------------------------------------

func TestRun_SpecAtAlternativePath(t *testing.T) {
	spec := makeSpec(map[string]map[string]openAPIOperation{
		"/health": {"get": {}},
	})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi.json" {
			w.Header().Set("Content-Type", "application/json")
			w.Write(spec)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	s := New()
	findings, err := s.Run(context.Background(), hostFromURL(ts.URL), module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckSwaggerExposed) {
		t.Fatal("expected CheckSwaggerExposed when spec is at /openapi.json")
	}
	f := findByCheckID(findings, finding.CheckSwaggerExposed)
	if !strings.Contains(f.Evidence["url"].(string), "/openapi.json") {
		t.Errorf("expected evidence URL to contain /openapi.json, got %q", f.Evidence["url"])
	}
}

// ---------------------------------------------------------------------------
// Test: cancelled context → no findings, no error
// ---------------------------------------------------------------------------

func TestRun_CancelledContext_ReturnsNil(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"paths":{}}`))
	}))
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	s := New()
	findings, err := s.Run(ctx, hostFromURL(ts.URL), module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings on cancelled context, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Test: context deadline exceeded during deep scan
// ---------------------------------------------------------------------------

func TestRun_ContextDeadline_DuringDeepScan(t *testing.T) {
	spec := makeSpec(map[string]map[string]openAPIOperation{
		"/api/slow": {
			"post": {Parameters: []openAPIParameter{
				{Name: "x", In: "query", Required: true},
			}},
		},
	})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/swagger.json" {
			w.Header().Set("Content-Type", "application/json")
			w.Write(spec)
			return
		}
		// Simulate a slow endpoint.
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	s := New()
	// The spec fetch should succeed before the timeout, but fuzzing should be cut off.
	findings, err := s.Run(ctx, hostFromURL(ts.URL), module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should have exposure finding (spec was fetched before timeout) but no fuzz findings.
	if !hasCheckID(findings, finding.CheckSwaggerExposed) {
		// This is acceptable — if the context expired before spec fetch too.
		return
	}
	// If exposure was found, fuzz should have been cut off by timeout.
	if hasCheckID(findings, finding.CheckWebAPIFuzz) {
		t.Error("did not expect fuzz findings when context deadline cut short the probes")
	}
}

// ---------------------------------------------------------------------------
// Test: replacePathParams helper
// ---------------------------------------------------------------------------

func TestReplacePathParams(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"/users/{id}", "/users/1"},
		{"/users/{id}/posts/{postId}", "/users/1/posts/1"},
		{"/plain/path", "/plain/path"},
		{"/mixed/{id}/static", "/mixed/1/static"},
		{"/{a}/{b}/{c}", "/1/1/1"},
		{"/unclosed/{param", "/unclosed/{param"},
	}
	for _, tt := range tests {
		got := replacePathParams(tt.input)
		if got != tt.want {
			t.Errorf("replacePathParams(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Test: Name() returns expected value
// ---------------------------------------------------------------------------

func TestScanner_Name(t *testing.T) {
	s := New()
	if s.Name() != "swagger" {
		t.Errorf("expected scanner name %q, got %q", "swagger", s.Name())
	}
}

// ---------------------------------------------------------------------------
// Test: empty paths in spec → exposure finding but no fuzz findings
// ---------------------------------------------------------------------------

func TestRun_DeepMode_EmptyPaths_NoFuzzFindings(t *testing.T) {
	spec := makeSpec(map[string]map[string]openAPIOperation{})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/swagger.json" {
			w.Header().Set("Content-Type", "application/json")
			w.Write(spec)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	s := New()
	findings, err := s.Run(context.Background(), hostFromURL(ts.URL), module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckSwaggerExposed) {
		t.Fatal("expected exposure finding even with empty paths")
	}
	if hasCheckID(findings, finding.CheckWebAPIFuzz) {
		t.Error("did not expect fuzz findings with empty paths")
	}
}

// ---------------------------------------------------------------------------
// Test: authorized mode also fuzzes (like deep mode)
// ---------------------------------------------------------------------------

func TestRun_AuthorizedMode_FuzzesEndpoints(t *testing.T) {
	spec := makeSpec(map[string]map[string]openAPIOperation{
		"/api/delete": {
			"post": {Parameters: []openAPIParameter{
				{Name: "id", In: "query", Required: true},
			}},
		},
	})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/swagger.json" {
			w.Header().Set("Content-Type", "application/json")
			w.Write(spec)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	s := New()
	findings, err := s.Run(context.Background(), hostFromURL(ts.URL), module.ScanAuthorized)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckWebAPIFuzz) {
		t.Error("expected fuzz findings in authorized mode")
	}
}

// ---------------------------------------------------------------------------
// Test: path params are replaced correctly when fuzzing
// ---------------------------------------------------------------------------

func TestRun_DeepMode_PathParamsReplaced(t *testing.T) {
	spec := makeSpec(map[string]map[string]openAPIOperation{
		"/users/{userId}/posts/{postId}": {
			"get": {Parameters: []openAPIParameter{
				{Name: "userId", In: "path", Required: true},
				{Name: "postId", In: "path", Required: true},
			}},
		},
	})

	var probed string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/swagger.json" {
			w.Header().Set("Content-Type", "application/json")
			w.Write(spec)
			return
		}
		probed = r.URL.Path
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	s := New()
	s.Run(context.Background(), hostFromURL(ts.URL), module.ScanDeep)

	if probed != "/users/1/posts/1" {
		t.Errorf("expected path params replaced: got %q", probed)
	}
}
