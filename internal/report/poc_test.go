package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
)

func TestGeneratePoC_XSS(t *testing.T) {
	f := finding.Finding{
		CheckID:     "web.xss",
		Asset:       "app.example.com",
		Title:       "Reflected XSS in search",
		Description: "The search parameter reflects user input without encoding.",
		Evidence:    map[string]any{"url": "https://app.example.com/search?q=<script>alert(1)</script>"},
	}
	content, filename, err := GeneratePoC(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasSuffix(filename, ".html") {
		t.Errorf("XSS poc should be .html, got %s", filename)
	}
	if !strings.Contains(content, "XSS") {
		t.Error("XSS poc should mention XSS")
	}
	if !strings.Contains(content, "app.example.com") {
		t.Error("XSS poc should contain the asset")
	}
	if !strings.Contains(content, "DISCLAIMER") {
		t.Error("XSS poc should contain disclaimer")
	}
}

func TestGeneratePoC_SSRF(t *testing.T) {
	f := finding.Finding{
		CheckID:     "web.ssrf",
		Asset:       "api.example.com",
		Title:       "SSRF via URL parameter",
		Description: "Server fetches attacker-supplied URLs.",
		Evidence:    map[string]any{"url": "https://api.example.com/proxy?url=", "parameter": "url"},
	}
	content, filename, err := GeneratePoC(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasSuffix(filename, ".py") {
		t.Errorf("SSRF poc should be .py, got %s", filename)
	}
	if !strings.Contains(content, "169.254.169.254") {
		t.Error("SSRF poc should probe cloud metadata")
	}
	if !strings.Contains(content, "DISCLAIMER") {
		t.Error("SSRF poc should contain disclaimer")
	}
}

func TestGeneratePoC_SQLi(t *testing.T) {
	f := finding.Finding{
		CheckID:     "web.sqli",
		Asset:       "db.example.com",
		Title:       "SQL Injection",
		Description: "SQL injection in id parameter.",
		Evidence:    map[string]any{"url": "https://db.example.com/users?id=1", "parameter": "id"},
	}
	content, filename, err := GeneratePoC(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasSuffix(filename, ".py") {
		t.Errorf("SQLi poc should be .py, got %s", filename)
	}
	if !strings.Contains(content, "sqlmap") {
		t.Error("SQLi poc should mention sqlmap")
	}
}

func TestGeneratePoC_CmdInjection(t *testing.T) {
	f := finding.Finding{
		CheckID:     "web.command_injection",
		Asset:       "cmd.example.com",
		Title:       "Command Injection",
		Description: "OS command injection via ping parameter.",
		Evidence:    map[string]any{"url": "https://cmd.example.com/ping", "parameter": "host"},
	}
	content, filename, err := GeneratePoC(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasSuffix(filename, ".py") {
		t.Errorf("cmdinj poc should be .py, got %s", filename)
	}
	if !strings.Contains(content, "sleep") {
		t.Error("cmdinj poc should use time-based detection")
	}
}

func TestGeneratePoC_HostHeader(t *testing.T) {
	f := finding.Finding{
		CheckID:     "web.host_header_injection",
		Asset:       "www.example.com",
		Title:       "Host Header Injection",
		Description: "Host header is reflected in password reset links.",
		Evidence:    map[string]any{"url": "https://www.example.com/reset"},
	}
	content, filename, err := GeneratePoC(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasSuffix(filename, ".sh") {
		t.Errorf("host header poc should be .sh, got %s", filename)
	}
	if !strings.Contains(content, "X-Forwarded-Host") {
		t.Error("host header poc should test X-Forwarded-Host")
	}
}

func TestGeneratePoC_CachePoison(t *testing.T) {
	f := finding.Finding{
		CheckID:     "cache.poison_unkeyed",
		Asset:       "cdn.example.com",
		Title:       "Cache Poisoning",
		Description: "Unkeyed header reflected into cached responses.",
		Evidence:    map[string]any{"url": "https://cdn.example.com/", "unkeyed_header": "X-Forwarded-Scheme"},
	}
	content, filename, err := GeneratePoC(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasSuffix(filename, ".sh") {
		t.Errorf("cache poison poc should be .sh, got %s", filename)
	}
	if !strings.Contains(content, "X-Forwarded-Scheme") {
		t.Error("cache poison poc should use the unkeyed header from evidence")
	}
}

func TestGeneratePoC_CORS(t *testing.T) {
	f := finding.Finding{
		CheckID:     "web.cors_misconfiguration",
		Asset:       "api.example.com",
		Title:       "CORS Misconfiguration",
		Description: "Origin is reflected with credentials allowed.",
		Evidence:    map[string]any{"url": "https://api.example.com/user"},
	}
	content, filename, err := GeneratePoC(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasSuffix(filename, ".html") {
		t.Errorf("CORS poc should be .html, got %s", filename)
	}
	if !strings.Contains(content, "fetch(") {
		t.Error("CORS poc should use fetch()")
	}
	if !strings.Contains(content, "credentials") {
		t.Error("CORS poc should send credentials")
	}
}

func TestGeneratePoC_JWT(t *testing.T) {
	f := finding.Finding{
		CheckID:     "jwt.weak_algorithm",
		Asset:       "auth.example.com",
		Title:       "JWT Weak Algorithm",
		Description: "Server accepts alg:none.",
		Evidence:    map[string]any{"url": "https://auth.example.com/api"},
	}
	content, filename, err := GeneratePoC(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasSuffix(filename, ".py") {
		t.Errorf("JWT poc should be .py, got %s", filename)
	}
	if !strings.Contains(content, "alg") {
		t.Error("JWT poc should reference algorithm manipulation")
	}
}

func TestGeneratePoC_Default(t *testing.T) {
	f := finding.Finding{
		CheckID:      "tls.heartbleed",
		Asset:        "ssl.example.com",
		Title:        "Heartbleed",
		Description:  "OpenSSL heartbleed vulnerability.",
		ProofCommand: "nmap --script ssl-heartbleed -p 443 ssl.example.com",
	}
	content, filename, err := GeneratePoC(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasSuffix(filename, ".sh") {
		t.Errorf("default poc should be .sh, got %s", filename)
	}
	if !strings.Contains(content, "nmap") {
		t.Error("default poc should include the proof command")
	}
}

func TestGeneratePoC_EmptyCheckID(t *testing.T) {
	f := finding.Finding{Asset: "example.com"}
	_, _, err := GeneratePoC(f)
	if err == nil {
		t.Error("expected error for empty check ID")
	}
}

func TestGeneratePoC_PDFSSRF(t *testing.T) {
	f := finding.Finding{
		CheckID: "web.pdf_ssrf",
		Asset:   "pdf.example.com",
		Title:   "PDF SSRF",
		Evidence: map[string]any{"url": "https://pdf.example.com/generate"},
	}
	_, filename, err := GeneratePoC(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasSuffix(filename, ".py") {
		t.Errorf("PDF SSRF poc should be .py, got %s", filename)
	}
}

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"example.com", "example-com"},
		{"sub.domain.example.com", "sub-domain-example-com"},
		{"192.168.1.1:8080", "192-168-1-1-8080"},
		{"safe-name_123", "safe-name_123"},
		{"///bad///", "bad"},
	}
	for _, tt := range tests {
		got := sanitizeFilename(tt.input)
		if got != tt.want {
			t.Errorf("sanitizeFilename(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestRenderPoCBundle(t *testing.T) {
	dir := t.TempDir()

	findings := []finding.Finding{
		{
			CheckID:      "web.xss",
			Severity:     finding.SeverityHigh,
			Asset:        "app.example.com",
			Title:        "XSS in search",
			Description:  "Reflected XSS.",
			ProofCommand: "curl https://app.example.com/search?q=<script>alert(1)</script>",
			Evidence:     map[string]any{"url": "https://app.example.com/search?q=test"},
		},
		{
			CheckID:      "tls.heartbleed",
			Severity:     finding.SeverityCritical,
			Asset:        "ssl.example.com",
			Title:        "Heartbleed",
			Description:  "OpenSSL heartbleed.",
			ProofCommand: "nmap --script ssl-heartbleed ssl.example.com",
			Evidence:     map[string]any{},
		},
	}

	err := RenderPoCBundle(findings, dir)
	if err != nil {
		t.Fatalf("RenderPoCBundle: %v", err)
	}

	// Check index.html exists.
	indexPath := filepath.Join(dir, "index.html")
	indexBytes, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	index := string(indexBytes)
	if !strings.Contains(index, "Beacon") {
		t.Error("index.html should mention Beacon")
	}
	if !strings.Contains(index, "app.example.com") {
		t.Error("index.html should list the XSS finding asset")
	}
	if !strings.Contains(index, "ssl.example.com") {
		t.Error("index.html should list the heartbleed finding asset")
	}

	// Check that at least 2 PoC files were created (plus index.html = 3 files minimum).
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(dirEntries) < 3 {
		t.Errorf("expected at least 3 files (2 pocs + index), got %d", len(dirEntries))
	}
}

func TestRenderPoCBundle_DuplicateFilenames(t *testing.T) {
	dir := t.TempDir()

	// Two identical findings should produce deduplicated filenames.
	f := finding.Finding{
		CheckID:  "web.xss",
		Asset:    "example.com",
		Title:    "XSS",
		Evidence: map[string]any{},
	}
	findings := []finding.Finding{f, f}

	err := RenderPoCBundle(findings, dir)
	if err != nil {
		t.Fatalf("RenderPoCBundle: %v", err)
	}

	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	// Should have: poc-xss-example-com.html, poc-xss-example-com-2.html, index.html
	if len(dirEntries) != 3 {
		names := make([]string, len(dirEntries))
		for i, e := range dirEntries {
			names[i] = e.Name()
		}
		t.Errorf("expected 3 files, got %d: %v", len(dirEntries), names)
	}
}

func TestRenderPoCBundle_EmptyFindings(t *testing.T) {
	dir := t.TempDir()
	err := RenderPoCBundle(nil, dir)
	if err != nil {
		t.Fatalf("RenderPoCBundle with nil findings: %v", err)
	}

	// Should still create index.html.
	indexPath := filepath.Join(dir, "index.html")
	if _, err := os.Stat(indexPath); os.IsNotExist(err) {
		t.Error("index.html should be created even with no findings")
	}
}
