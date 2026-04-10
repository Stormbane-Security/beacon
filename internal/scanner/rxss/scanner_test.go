package rxss

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanner/paramdiscovery"
)

// --- Surface mode is a no-op ---

func TestRun_SurfaceMode_ReturnsNil(t *testing.T) {
	s := New()
	findings, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings in surface mode, got %d", len(findings))
	}
}

// --- Canary reflected without encoding → finding emitted ---

func TestRun_DeepMode_CanaryReflected_FindingEmitted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if q == "" {
			q = r.FormValue("q")
		}
		w.WriteHeader(http.StatusOK)
		// Reflect the parameter value without encoding.
		_, _ = fmt.Fprintf(w, "<html><body>Results for: %s</body></html>", q)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	s := New()
	findings, err := s.Run(context.Background(), host, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() returned error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected at least one finding when canary is reflected unencoded")
	}

	for _, f := range findings {
		if f.CheckID != finding.CheckWebReflectedXSS {
			t.Errorf("unexpected check ID: %s", f.CheckID)
		}
	}
}

// --- Full HTML payload reflected → verified finding ---

func TestRun_DeepMode_HTMLPayloadReflected_Verified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if q == "" {
			q = r.FormValue("q")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "<html><body>Search: %s</body></html>", q)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	s := New()
	findings, err := s.Run(context.Background(), host, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() returned error: %v", err)
	}

	var foundVerified bool
	for _, f := range findings {
		if ev, ok := f.Evidence["confidence"]; ok && ev == "verified" {
			foundVerified = true
			break
		}
	}
	if !foundVerified {
		t.Error("expected at least one verified finding when full payload is reflected")
	}
}

// --- JavaScript context → Critical severity ---

func TestRun_DeepMode_JSContext_CriticalSeverity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if q == "" {
			q = r.FormValue("q")
		}
		w.WriteHeader(http.StatusOK)
		// Reflect in all contexts so the JS payload also reflects.
		_, _ = fmt.Fprintf(w, "<html><script>var x = '%s';</script></html>", q)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	s := New()
	findings, err := s.Run(context.Background(), host, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() returned error: %v", err)
	}

	var foundCritical bool
	for _, f := range findings {
		if f.Severity == finding.SeverityCritical {
			foundCritical = true
			break
		}
	}
	if !foundCritical {
		t.Error("expected Critical severity when JS context payload is reflected")
	}
}

// --- Server encodes output → no finding ---

func TestRun_DeepMode_EncodedOutput_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if q == "" {
			q = r.FormValue("q")
		}
		// HTML-encode < and > so the canary doesn't reflect raw.
		q = strings.ReplaceAll(q, "<", "&lt;")
		q = strings.ReplaceAll(q, ">", "&gt;")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "<html><body>Results for: %s</body></html>", q)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	s := New()
	findings, err := s.Run(context.Background(), host, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() returned error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected no findings when output is HTML-encoded, got %d", len(findings))
	}
}

// --- POST method reflection ---

func TestRun_DeepMode_POSTReflection_FindingEmitted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q string
		if r.Method == http.MethodPost {
			_ = r.ParseForm()
			q = r.PostFormValue("q")
		} else {
			// GET returns nothing interesting, forcing the scanner to find it via POST.
			q = ""
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "<html><body>%s</body></html>", q)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	s := New()
	findings, err := s.Run(context.Background(), host, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() returned error: %v", err)
	}

	var foundPost bool
	for _, f := range findings {
		if ev, ok := f.Evidence["method"]; ok && ev == "POST" {
			foundPost = true
			break
		}
	}
	if !foundPost {
		t.Error("expected a finding from POST method reflection")
	}
}

// --- ProofCommand contains actual host ---

func TestRun_DeepMode_ProofCommandHasHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if q == "" {
			q = r.FormValue("q")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "<html>%s</html>", q)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	s := New()
	findings, err := s.Run(context.Background(), host, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() returned error: %v", err)
	}

	for _, f := range findings {
		if f.ProofCommand == "" {
			t.Error("ProofCommand must not be empty")
		}
		if !strings.Contains(f.ProofCommand, host) {
			t.Errorf("ProofCommand must contain host %q, got: %s", host, f.ProofCommand)
		}
	}
}

// --- No reflection → no finding ---

func TestRun_DeepMode_NoReflection_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>Static content</body></html>"))
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	s := New()
	findings, err := s.Run(context.Background(), host, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings when server never reflects input, got %d", len(findings))
	}
}

// --- Discovered params from context ---

func TestRun_DeepMode_DiscoveredParams_Used(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only reflect the "custom_param" parameter.
		v := r.URL.Query().Get("custom_param")
		if v == "" {
			v = r.FormValue("custom_param")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "<html>%s</html>", v)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")

	// Inject discovered params via context.
	ctx := paramdiscovery.WithDiscoveredParams(context.Background(), map[string][]string{
		"/": {"custom_param"},
	})

	s := New()
	findings, err := s.Run(ctx, host, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() returned error: %v", err)
	}

	var foundCustom bool
	for _, f := range findings {
		if ev, ok := f.Evidence["parameter"]; ok && ev == "custom_param" {
			foundCustom = true
			break
		}
	}
	if !foundCustom {
		t.Error("expected finding for discovered parameter 'custom_param'")
	}
}

// --- Unreachable server → no panic ---

func TestRun_DeepMode_UnreachableServer_NoPanic(t *testing.T) {
	s := New()
	findings, err := s.Run(context.Background(), "127.0.0.1:1", module.ScanDeep)
	_ = err
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for unreachable server, got %d", len(findings))
	}
}

// --- Context cancellation → no panic ---

func TestRun_DeepMode_ContextCancelled_NoPanic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	host := strings.TrimPrefix(srv.URL, "http://")
	s := New()
	findings, _ := s.Run(ctx, host, module.ScanDeep)
	_ = findings // must not panic
}

// --- extractSnippet ---

func TestExtractSnippet_Found(t *testing.T) {
	body := "prefix_before_NEEDLE_after_suffix"
	got := extractSnippet(body, "NEEDLE", 5)
	if !strings.Contains(got, "NEEDLE") {
		t.Errorf("snippet should contain needle, got %q", got)
	}
}

func TestExtractSnippet_NotFound(t *testing.T) {
	got := extractSnippet("no match here", "NEEDLE", 5)
	if got != "" {
		t.Errorf("expected empty snippet when needle not found, got %q", got)
	}
}

// --- buildProofCommand ---

func TestBuildProofCommand_GET(t *testing.T) {
	cmd := buildProofCommand("GET", "http://example.com/search", "q", "test")
	if !strings.Contains(cmd, "curl") {
		t.Error("proof command should contain curl")
	}
	if !strings.Contains(cmd, "example.com") {
		t.Error("proof command should contain the host")
	}
}

func TestBuildProofCommand_POST(t *testing.T) {
	cmd := buildProofCommand("POST", "http://example.com/search", "q", "test")
	if !strings.Contains(cmd, "-X POST") {
		t.Error("POST proof command should contain -X POST")
	}
}
