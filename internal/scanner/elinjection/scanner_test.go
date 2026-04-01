package elinjection_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanner/elinjection"
)

// ---------------------------------------------------------------------------
// ScanSurface: scanner should skip (active payloads are deep-only)
// ---------------------------------------------------------------------------

func TestELInjection_SkippedInSurfaceMode(t *testing.T) {
	probed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probed = true
		w.Header().Set("Server", "Apache-Coyote/1.1")
		http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "abc123"})
		fmt.Fprintln(w, "hello")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := elinjection.New().Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings in surface mode, got %d", len(findings))
	}
	if probed {
		t.Error("scanner should not send any HTTP requests in surface mode")
	}
}

// ---------------------------------------------------------------------------
// Java detection gate: non-Java target should be skipped
// ---------------------------------------------------------------------------

func TestELInjection_NonJavaTarget_Skipped(t *testing.T) {
	injectionProbed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Root request for Java detection — return generic headers.
		if r.URL.Path == "/" && r.URL.RawQuery == "" {
			w.Header().Set("Server", "nginx/1.24.0")
			fmt.Fprintln(w, "Welcome")
			return
		}
		// Any other request means the scanner went past the Java gate.
		injectionProbed = true
		fmt.Fprintln(w, "should not reach here")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := elinjection.New().Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for non-Java target, got %d", len(findings))
	}
	if injectionProbed {
		t.Error("scanner should not probe injection paths on non-Java targets")
	}
}

// ---------------------------------------------------------------------------
// Java detection gate: JSESSIONID cookie triggers Java detection
// ---------------------------------------------------------------------------

func TestELInjection_JavaDetected_JSESSIONID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "abc123"})
		q := r.URL.Query().Get("q")
		if strings.Contains(q, "${7*7}") || strings.Contains(q, "#{7*7}") {
			fmt.Fprintln(w, "Result: 49")
			return
		}
		fmt.Fprintln(w, "OK")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := elinjection.New().Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least 1 finding when Java detected via JSESSIONID")
	}
}

// ---------------------------------------------------------------------------
// Java detection gate: Server header triggers Java detection
// ---------------------------------------------------------------------------

func TestELInjection_JavaDetected_ServerHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache-Coyote/1.1")
		q := r.URL.Query().Get("q")
		if strings.Contains(q, "${7*7}") || strings.Contains(q, "#{7*7}") {
			fmt.Fprintln(w, "Eval: 49")
			return
		}
		fmt.Fprintln(w, "OK")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := elinjection.New().Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least 1 finding when Java detected via Server header")
	}
}

// ---------------------------------------------------------------------------
// SpEL injection detected via query parameter
// ---------------------------------------------------------------------------

func TestELInjection_SpEL_QueryParam_Detected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache-Coyote/1.1")
		q := r.URL.Query().Get("q")
		if strings.Contains(q, "${7*7}") {
			fmt.Fprintln(w, "Result: 49")
			return
		}
		fmt.Fprintln(w, "Search results")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := elinjection.New().Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	var found bool
	for _, f := range findings {
		if f.CheckID == finding.CheckWebSpELInjection || f.CheckID == finding.CheckWebELInjection {
			found = true
			if f.Severity != finding.SeverityCritical {
				t.Errorf("expected Critical severity, got %s", f.Severity)
			}
			if f.ProofCommand == "" {
				t.Error("ProofCommand should be set")
			}
			if f.Asset != asset {
				t.Errorf("expected asset %q, got %q", asset, f.Asset)
			}
		}
	}
	if !found {
		t.Error("expected SpEL or EL injection finding for ${7*7} payload")
	}
}

// ---------------------------------------------------------------------------
// OGNL injection detected via query parameter
// ---------------------------------------------------------------------------

func TestELInjection_OGNL_QueryParam_Detected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "abc"})
		q := r.URL.Query().Get("q")
		if strings.Contains(q, "%{7*7}") {
			fmt.Fprintln(w, "Output: 49")
			return
		}
		fmt.Fprintln(w, "Welcome")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := elinjection.New().Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	var found bool
	for _, f := range findings {
		if f.CheckID == finding.CheckWebOGNLInjection {
			found = true
			if f.Severity != finding.SeverityCritical {
				t.Errorf("expected Critical severity, got %s", f.Severity)
			}
			if f.ProofCommand == "" {
				t.Error("ProofCommand should be set")
			}
		}
	}
	if !found {
		t.Error("expected OGNL injection finding for %%{7*7} payload")
	}
}

// ---------------------------------------------------------------------------
// Header injection: EL payload in User-Agent is evaluated
// ---------------------------------------------------------------------------

func TestELInjection_HeaderInjection_Detected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache-Coyote/1.1")
		ua := r.Header.Get("User-Agent")
		if strings.Contains(ua, "${7*7}") {
			fmt.Fprintln(w, "User agent eval: 49")
			return
		}
		fmt.Fprintln(w, "OK")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := elinjection.New().Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	var found bool
	for _, f := range findings {
		if f.CheckID == finding.CheckWebSpELInjection || f.CheckID == finding.CheckWebELInjection {
			if _, hasHeader := f.Evidence["header"]; hasHeader {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected EL injection finding via header injection")
	}
}

// ---------------------------------------------------------------------------
// POST body injection: EL payload in form parameter is evaluated
// ---------------------------------------------------------------------------

func TestELInjection_POSTInjection_Detected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache-Coyote/1.1")
		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err == nil {
				q := r.FormValue("q")
				if strings.Contains(q, "${7*7}") {
					fmt.Fprintln(w, "POST result: 49")
					return
				}
			}
		}
		fmt.Fprintln(w, "OK")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := elinjection.New().Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	var found bool
	for _, f := range findings {
		if f.CheckID == finding.CheckWebSpELInjection || f.CheckID == finding.CheckWebELInjection {
			if method, hasMethod := f.Evidence["method"]; hasMethod && method == "POST" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected EL injection finding via POST body injection")
	}
}

// ---------------------------------------------------------------------------
// Safe response: server does not evaluate expressions, no findings expected
// ---------------------------------------------------------------------------

func TestELInjection_SafeResponse_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache-Coyote/1.1")
		fmt.Fprintln(w, "Welcome to the application")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := elinjection.New().Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	for _, f := range findings {
		if f.CheckID == finding.CheckWebSpELInjection ||
			f.CheckID == finding.CheckWebOGNLInjection ||
			f.CheckID == finding.CheckWebELInjection {
			t.Errorf("unexpected EL injection finding on safe server: %+v", f)
		}
	}
}

// ---------------------------------------------------------------------------
// Baseline contains "49": delta check should suppress false positive
// ---------------------------------------------------------------------------

func TestELInjection_BaselineContains49_NoFalsePositive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache-Coyote/1.1")
		// Body always contains "49" regardless of input — for GET requests the
		// delta check should suppress findings. POST requests bypass delta checking
		// in the scanner, so restrict this test to GET-based vectors.
		if r.Method == http.MethodPost {
			fmt.Fprintln(w, "OK")
			return
		}
		fmt.Fprintln(w, "Showing 49 results for your query")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := elinjection.New().Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	for _, f := range findings {
		ev := f.Evidence
		// Only check GET-based vectors (query param and header injection).
		// POST injection in the scanner does not have a baseline delta check.
		if method, ok := ev["method"]; ok && method == "POST" {
			continue
		}
		if f.CheckID == finding.CheckWebSpELInjection ||
			f.CheckID == finding.CheckWebOGNLInjection ||
			f.CheckID == finding.CheckWebELInjection {
			t.Errorf("unexpected false positive on GET-based vector when baseline already contains '49': %+v", f)
		}
	}
}

// ---------------------------------------------------------------------------
// 404 paths: scanner should skip without emitting findings
// ---------------------------------------------------------------------------

func TestELInjection_404Skipped(t *testing.T) {
	rootHit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Root responds with Java headers for the Java gate to pass.
		if r.URL.Path == "/" && r.URL.RawQuery == "" && !rootHit {
			rootHit = true
			w.Header().Set("Server", "Apache-Coyote/1.1")
			fmt.Fprintln(w, "OK")
			return
		}
		// All other requests return 404.
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := elinjection.New().Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	for _, f := range findings {
		if f.CheckID == finding.CheckWebSpELInjection ||
			f.CheckID == finding.CheckWebOGNLInjection ||
			f.CheckID == finding.CheckWebELInjection {
			t.Errorf("unexpected finding on all-404 server: %+v", f)
		}
	}
}

// ---------------------------------------------------------------------------
// Empty response body: no crash, no findings
// ---------------------------------------------------------------------------

func TestELInjection_EmptyResponse_NoCrash(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache-Coyote/1.1")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := elinjection.New().Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	for _, f := range findings {
		if f.CheckID == finding.CheckWebSpELInjection ||
			f.CheckID == finding.CheckWebOGNLInjection ||
			f.CheckID == finding.CheckWebELInjection {
			t.Errorf("unexpected finding on empty response body: %+v", f)
		}
	}
}

// ---------------------------------------------------------------------------
// ScanDeep mode works (not just ScanAuthorized)
// ---------------------------------------------------------------------------

func TestELInjection_RunsInDeepMode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "test"})
		q := r.URL.Query().Get("q")
		if strings.Contains(q, "${7*7}") {
			fmt.Fprintln(w, "value: 49")
			return
		}
		fmt.Fprintln(w, "OK")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := elinjection.New().Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings in ScanDeep mode, got none")
	}
}

// ---------------------------------------------------------------------------
// ScanAuthorized mode also works
// ---------------------------------------------------------------------------

func TestELInjection_RunsInAuthorizedMode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "test"})
		q := r.URL.Query().Get("q")
		if strings.Contains(q, "${7*7}") {
			fmt.Fprintln(w, "value: 49")
			return
		}
		fmt.Fprintln(w, "OK")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := elinjection.New().Run(context.Background(), asset, module.ScanAuthorized)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings in ScanAuthorized mode, got none")
	}
}

// ---------------------------------------------------------------------------
// Echoes input literally: ${7*7} appears but not "49" — no finding
// ---------------------------------------------------------------------------

func TestELInjection_EchoesPayloadLiterally_NoFinding(t *testing.T) {
	// When the server echoes input literally, numeric payloads like ${7*7}
	// do NOT produce "49" in the response — only the literal string appears.
	// Non-numeric payloads (e.g. ${T(java.lang.Runtime)}) contain the expected
	// string as a substring of the payload itself, so those will match even
	// when echoed. This test validates the numeric case: literal echo of
	// ${7*7} should not produce a finding because "49" never appears.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache-Coyote/1.1")
		q := r.URL.Query().Get("q")
		if q != "" {
			// Echo the input back literally without evaluation.
			fmt.Fprintf(w, "You searched for: %s\n", q)
			return
		}
		fmt.Fprintln(w, "Welcome")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := elinjection.New().Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	for _, f := range findings {
		ev := f.Evidence
		// Only check numeric payloads (expect=49). Non-numeric payloads like
		// ${T(java.lang.Runtime)} embed their expected output in the payload
		// string, so echoing them literally is indistinguishable from evaluation.
		if expect, ok := ev["expect"]; ok && expect != "49" {
			continue
		}
		if f.CheckID == finding.CheckWebSpELInjection ||
			f.CheckID == finding.CheckWebOGNLInjection ||
			f.CheckID == finding.CheckWebELInjection {
			t.Errorf("unexpected EL injection finding for numeric payload when input is echoed literally: %+v", f)
		}
	}
}

// ---------------------------------------------------------------------------
// OGNL context reflection: ${#context} → "OgnlContext" in response
// ---------------------------------------------------------------------------

func TestELInjection_OGNLContext_Detected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache-Coyote/1.1")
		q := r.URL.Query().Get("q")
		if strings.Contains(q, "#context") {
			fmt.Fprintln(w, "Debug: OgnlContext{values=[]}")
			return
		}
		fmt.Fprintln(w, "OK")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := elinjection.New().Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	var found bool
	for _, f := range findings {
		if f.CheckID == finding.CheckWebOGNLInjection {
			found = true
		}
	}
	if !found {
		t.Error("expected OGNL injection finding for ${#context} → OgnlContext")
	}
}

// ---------------------------------------------------------------------------
// SpEL Runtime class reflection: ${T(java.lang.Runtime)} detected
// ---------------------------------------------------------------------------

func TestELInjection_SpEL_RuntimeReflection_Detected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache-Coyote/1.1")
		q := r.URL.Query().Get("q")
		if strings.Contains(q, "java.lang.Runtime") {
			fmt.Fprintln(w, "class java.lang.Runtime")
			return
		}
		fmt.Fprintln(w, "OK")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := elinjection.New().Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	var found bool
	for _, f := range findings {
		if f.CheckID == finding.CheckWebSpELInjection {
			found = true
		}
	}
	if !found {
		t.Error("expected SpEL injection finding for Runtime class reflection")
	}
}

// ---------------------------------------------------------------------------
// Finding fields: verify essential fields are populated correctly
// ---------------------------------------------------------------------------

func TestELInjection_FindingFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "sess"})
		q := r.URL.Query().Get("q")
		if strings.Contains(q, "${7*7}") || strings.Contains(q, "#{7*7}") {
			fmt.Fprintln(w, "Answer: 49")
			return
		}
		fmt.Fprintln(w, "OK")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := elinjection.New().Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least 1 finding")
	}

	f := findings[0]
	if f.Scanner != "elinjection" {
		t.Errorf("expected scanner name 'elinjection', got %q", f.Scanner)
	}
	if f.Module != "deep" {
		t.Errorf("expected module 'deep', got %q", f.Module)
	}
	if !f.DeepOnly {
		t.Error("expected DeepOnly to be true")
	}
	if f.Asset != asset {
		t.Errorf("expected asset %q, got %q", asset, f.Asset)
	}
	if f.Severity != finding.SeverityCritical {
		t.Errorf("expected Critical severity, got %s", f.Severity)
	}
	if f.ProofCommand == "" {
		t.Error("ProofCommand should be set")
	}
	if f.Title == "" {
		t.Error("Title should not be empty")
	}
	if f.Description == "" {
		t.Error("Description should not be empty")
	}
	if f.Evidence == nil {
		t.Error("Evidence should not be nil")
	}
	if f.DiscoveredAt.IsZero() {
		t.Error("DiscoveredAt should be set")
	}
}
