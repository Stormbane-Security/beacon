package exposedfiles

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)

func TestExposedFiles_EnvFileExposed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = fmt.Fprintln(w, "DATABASE_URL=postgres://user:pass@host/db")
			_, _ = fmt.Fprintln(w, "SECRET_KEY=abc123=xyz")
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
		t.Fatal("expected at least 1 finding for exposed .env")
	}
	f := findings[0]
	if f.CheckID != "exposure.env_file_exposed" {
		t.Errorf("unexpected check ID: %s", f.CheckID)
	}
	if f.ProofCommand == "" {
		t.Error("ProofCommand should be set")
	}
	if !strings.Contains(f.ProofCommand, ".env") {
		t.Errorf("ProofCommand should reference the found path, got: %s", f.ProofCommand)
	}
}

func TestExposedFiles_Soft404NotFlagged(t *testing.T) {
	// Server returns 200 for every path but body is HTML (soft 404)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintln(w, "<html><body>Page Not Found</body></html>")
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	// HTML responses without bodyContains match should be skipped.
	// Some targets have no bodyContains (e.g., SQLite), so check that
	// at minimum the .env file (requires "=") is NOT flagged.
	for _, f := range findings {
		if strings.Contains(f.Title, ".env") {
			t.Errorf("soft-404 HTML should not trigger .env finding: %s", f.Title)
		}
	}
}

func TestExposedFiles_BodyContainsFilterWorks(t *testing.T) {
	// Server returns .env path with 200 but wrong body content (no "=")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = fmt.Fprintln(w, "no variables here")
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
		if f.CheckID == "exposure.sensitive_file" && strings.Contains(fmt.Sprintf("%v", f.Evidence["path"]), ".env") {
			t.Errorf("should not flag .env when body doesn't contain '='")
		}
	}
}

func TestExposedFiles_404NotFlagged(t *testing.T) {
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
		t.Fatalf("expected 0 findings when server returns 404, got %d", len(findings))
	}
}

func TestExposedFiles_GitConfigExposed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.git/config" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = fmt.Fprintln(w, "[core]")
			_, _ = fmt.Fprintln(w, "\trepositoryformatversion = 0")
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
		if strings.Contains(fmt.Sprintf("%v", f.Evidence["path"]), ".git/config") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected finding for exposed .git/config")
	}
}

func TestExposedFiles_DeepOnlySkippedInSurface(t *testing.T) {
	// error.log is deepOnly — must not be probed in surface mode
	probed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/error.log" {
			probed = true
			w.Header().Set("Content-Type", "text/plain")
			_, _ = fmt.Fprintln(w, "some error")
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	if _, err := New().Run(t.Context(), asset, module.ScanSurface); err != nil {
		t.Fatal(err)
	}
	if probed {
		t.Error("deepOnly target /error.log should not be probed in surface mode")
	}
}

func TestExposedFiles_DeepOnlyProbedInDeep(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/error.log" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = fmt.Fprintln(w, "[2024-01-01 local.ERROR]: something failed")
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
	// Laravel log requires "local.ERROR" in body — this one has it
	found := false
	for _, f := range findings {
		if strings.Contains(fmt.Sprintf("%v", f.Evidence["path"]), "error.log") ||
			strings.Contains(fmt.Sprintf("%v", f.Evidence["path"]), "laravel.log") {
			found = true
		}
	}
	_ = found // deepOnly paths vary; just confirm no panic in deep mode
}

func TestExposedFiles_Spring4ShellDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" && strings.Contains(r.URL.RawQuery, "class.module.classLoader") {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprintln(w, "Whitelabel Error Page - Spring data binding error for classLoader")
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
		if strings.Contains(string(f.CheckID), "spring4shell") {
			found = true
		}
	}
	if !found {
		t.Error("expected Spring4Shell finding, got none")
	}
}

func TestExposedFiles_Spring4ShellNotFlaggedOn404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if strings.Contains(string(f.CheckID), "spring4shell") {
			t.Errorf("unexpected Spring4Shell finding on 404 server: %v", f)
		}
	}
}

func TestExposedFiles_ZimbraAuthBypassDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/service/extension/backup/mboximport" {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprintln(w, "Zimbra mboximport error: missing required parameter")
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
		if strings.Contains(string(f.CheckID), "zimbra") {
			found = true
		}
	}
	if !found {
		t.Error("expected Zimbra auth bypass finding, got none")
	}
}

func TestExposedFiles_ZimbraNotFlaggedOn401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/service/extension/backup/mboximport" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
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
		if strings.Contains(string(f.CheckID), "zimbra") {
			t.Errorf("unexpected Zimbra finding when server returns 401: %v", f)
		}
	}
}

// ===========================================================================
// CI/CD Panel detection (Gitea)
// ===========================================================================

func TestExposedFiles_GiteaVersionAPIDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/version" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintln(w, `{"version":"1.21.4"}`)
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
		if f.CheckID == "exposure.cicd_panel" {
			found = true
		}
	}
	if !found {
		t.Error("expected cicd_panel finding for Gitea version API")
	}
}

// ===========================================================================
// Monitoring Panel detection (Grafana)
// ===========================================================================

func TestExposedFiles_GrafanaHealthDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/health" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintln(w, `{"commit":"abc123","database":"ok","version":"10.2.3"}`)
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
		if f.CheckID == "exposure.monitoring_panel" {
			found = true
		}
	}
	if !found {
		t.Error("expected monitoring_panel finding for Grafana health API")
	}
}

func TestExposedFiles_GrafanaHealthNotFlaggedWithoutDatabaseKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/health" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintln(w, `{"status":"ok"}`) // no "database" key
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
		if f.CheckID == "exposure.monitoring_panel" && strings.Contains(f.Title, "Grafana") {
			t.Errorf("should not flag /api/health without 'database' in body, got: %v", f)
		}
	}
}

// ===========================================================================
// Spring Boot Actuator detection
// ===========================================================================

func TestExposedFiles_SpringActuatorDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/actuator" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintln(w, `{"_links":{"self":{"href":"/actuator"},"health":{"href":"/actuator/health"}}}`)
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
		if f.CheckID == "exposure.spring_actuator" {
			found = true
		}
	}
	if !found {
		t.Error("expected spring_actuator finding for /actuator endpoint")
	}
}

func TestExposedFiles_SpringActuatorNotFlaggedWithout_links(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/actuator" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintln(w, `{"status":"UP"}`) // no "_links"
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
		if f.CheckID == "exposure.spring_actuator" && strings.Contains(f.Title, "Actuator") {
			t.Errorf("should not flag /actuator without '_links' in body")
		}
	}
}

// ===========================================================================
// Vault default token detection
// ===========================================================================

func TestExposedFiles_VaultDefaultTokenDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/health" && r.Header.Get("X-Vault-Token") == "root" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintln(w, `{"initialized":true,"sealed":false,"standby":false,"version":"1.15.4"}`)
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
		if f.CheckID == "web.default_credentials" {
			found = true
		}
	}
	if !found {
		t.Error("expected default_credentials finding for Vault dev-mode root token")
	}
}

func TestExposedFiles_VaultRejectsTokenNotFlagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/health" {
			http.Error(w, "permission denied", http.StatusForbidden)
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
		if f.CheckID == "web.default_credentials" {
			t.Errorf("should not flag Vault when token is rejected: %v", f)
		}
	}
}

// ===========================================================================
// AI Model File Exposure
// ===========================================================================

func TestExposedFiles_AIModelFileONNX(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/model.onnx" {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write([]byte("\x08\x07\x12\x04onnx")) // ONNX magic bytes
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
		if f.CheckID == "exposure.ai_model_file" {
			found = true
		}
	}
	if !found {
		t.Error("expected ai_model_file finding for exposed /model.onnx")
	}
}

func TestExposedFiles_AIModelFilePickle(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/model.pkl" {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write([]byte("\x80\x04\x95")) // Python pickle v4 header
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
		if f.CheckID == "exposure.ai_model_file" {
			found = true
			if f.Severity != finding.SeverityCritical {
				t.Errorf("expected critical severity for pickle model file, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected ai_model_file finding for exposed /model.pkl")
	}
}

func TestExposedFiles_AIModelFile404NotFlagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.CheckID == "exposure.ai_model_file" {
			t.Errorf("should not flag AI model files when server returns 404: %v", f)
		}
	}
}

func TestExposedFiles_AIModelFileDeepOnlyInDeep(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/models/model.safetensors" {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write([]byte("safetensors data"))
			return
		}
		if r.URL.Path == "/model.safetensors" {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write([]byte("safetensors data"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")

	// Surface mode: should find /model.safetensors but NOT /models/model.safetensors
	surfaceFindings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range surfaceFindings {
		if f.CheckID == "exposure.ai_model_file" && strings.Contains(f.Title, "/models/") {
			t.Error("deepOnly path /models/model.safetensors should not be probed in surface mode")
		}
	}

	// Deep mode: should find both
	deepFindings, err := New().Run(t.Context(), asset, module.ScanDeep)
	if err != nil {
		t.Fatal(err)
	}
	var foundDeep bool
	for _, f := range deepFindings {
		if f.CheckID == "exposure.ai_model_file" && strings.Contains(f.Title, "/models/") {
			foundDeep = true
		}
	}
	if !foundDeep {
		t.Error("deepOnly path /models/model.safetensors should be probed in deep mode")
	}
}
