package report

import (
	"strings"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
)

func TestGenerateChainPoC_SessionHijack(t *testing.T) {
	cf := finding.Finding{
		CheckID: "correlation.session_hijack_chain",
		Asset:   "api.example.com",
		Evidence: map[string]any{
			"url":       "https://api.example.com/data",
			"xss_url":   "https://api.example.com/search",
			"parameter": "q",
		},
	}
	content, filename, lang := GenerateChainPoC(cf, nil)

	if lang != "html" {
		t.Errorf("session hijack PoC lang = %q, want html", lang)
	}
	if !strings.HasSuffix(filename, ".html") {
		t.Errorf("filename %q should end in .html", filename)
	}
	if !strings.Contains(filename, "session-hijack") {
		t.Errorf("filename %q should contain 'session-hijack'", filename)
	}
	for _, want := range []string{"api.example.com", "document.cookie", "credentials"} {
		if !strings.Contains(content, want) {
			t.Errorf("session hijack PoC missing %q", want)
		}
	}
}

func TestGenerateChainPoC_SSRFToCloud(t *testing.T) {
	cf := finding.Finding{
		CheckID: "chain.ssrf_to_cloud_creds",
		Asset:   "app.target.io",
		Evidence: map[string]any{
			"url":            "https://app.target.io/proxy",
			"parameter":      "dest",
			"cloud_provider": "AWS",
			"iam_role":       "prod-role",
		},
	}
	content, filename, lang := GenerateChainPoC(cf, nil)

	if lang != "python" {
		t.Errorf("SSRF PoC lang = %q, want python", lang)
	}
	if !strings.HasSuffix(filename, ".py") {
		t.Errorf("filename %q should end in .py", filename)
	}
	for _, want := range []string{"app.target.io/proxy", "dest", "169.254.169.254", "prod-role"} {
		if !strings.Contains(content, want) {
			t.Errorf("SSRF PoC missing %q", want)
		}
	}
}

func TestGenerateChainPoC_SQLiDump(t *testing.T) {
	cf := finding.Finding{
		CheckID: "chain.sqli_to_credential_dump",
		Asset:   "shop.example.com",
		Evidence: map[string]any{
			"url":       "https://shop.example.com/product",
			"parameter": "pid",
			"payload":   "' UNION SELECT user,pass FROM accounts--",
		},
	}
	content, filename, lang := GenerateChainPoC(cf, nil)

	if lang != "python" {
		t.Errorf("SQLi PoC lang = %q, want python", lang)
	}
	if !strings.HasSuffix(filename, ".py") {
		t.Errorf("filename %q should end in .py", filename)
	}
	for _, want := range []string{"shop.example.com/product", "pid", "sqlmap"} {
		if !strings.Contains(content, want) {
			t.Errorf("SQLi PoC missing %q", want)
		}
	}
}

func TestGenerateChainPoC_EnvToDatabase(t *testing.T) {
	cf := finding.Finding{
		CheckID: "chain.env_to_database_access",
		Asset:   "web.example.com",
		Evidence: map[string]any{
			"path":         "/.env",
			"pivot_target": "db.prod",
			"pivot_port":   "5432",
		},
	}
	content, filename, lang := GenerateChainPoC(cf, nil)

	if lang != "bash" {
		t.Errorf("env-to-db PoC lang = %q, want bash", lang)
	}
	if !strings.HasSuffix(filename, ".sh") {
		t.Errorf("filename %q should end in .sh", filename)
	}
	for _, want := range []string{"web.example.com", "/.env", "db.prod", "5432"} {
		if !strings.Contains(content, want) {
			t.Errorf("env-to-db PoC missing %q", want)
		}
	}
}

func TestGenerateChainPoC_DefaultCreds(t *testing.T) {
	cf := finding.Finding{
		CheckID: "chain.default_creds_to_admin_access",
		Asset:   "panel.corp.com",
		Evidence: map[string]any{
			"url":      "https://panel.corp.com/admin",
			"username": "root",
			"password": "toor",
			"service":  "Grafana",
		},
	}
	content, filename, lang := GenerateChainPoC(cf, nil)

	if lang != "bash" {
		t.Errorf("default creds PoC lang = %q, want bash", lang)
	}
	for _, want := range []string{"panel.corp.com/admin", "root", "toor", "Grafana"} {
		if !strings.Contains(content, want) {
			t.Errorf("default creds PoC missing %q", want)
		}
	}
	if !strings.Contains(filename, "default-creds") {
		t.Errorf("filename %q should contain 'default-creds'", filename)
	}
}

func TestGenerateChainPoC_XSSSessionTheft(t *testing.T) {
	cf := finding.Finding{
		CheckID: "chain.xss_to_session_theft_poc",
		Asset:   "forum.example.com",
		Evidence: map[string]any{
			"url":       "https://forum.example.com/post",
			"parameter": "body",
		},
	}
	content, filename, lang := GenerateChainPoC(cf, nil)

	if lang != "html" {
		t.Errorf("XSS session theft PoC lang = %q, want html", lang)
	}
	for _, want := range []string{"forum.example.com", "body", "document.cookie"} {
		if !strings.Contains(content, want) {
			t.Errorf("XSS session theft PoC missing %q", want)
		}
	}
	if !strings.Contains(filename, "xss-session") {
		t.Errorf("filename %q should contain 'xss-session'", filename)
	}
}

func TestGenerateChainPoC_CachePoison(t *testing.T) {
	cf := finding.Finding{
		CheckID: "correlation.cache_poisoning_chain",
		Asset:   "cdn.example.com",
		Evidence: map[string]any{
			"url":            "https://cdn.example.com/main.js",
			"unkeyed_header": "X-Forwarded-Host",
		},
	}
	content, filename, lang := GenerateChainPoC(cf, nil)

	if lang != "bash" {
		t.Errorf("cache poison PoC lang = %q, want bash", lang)
	}
	for _, want := range []string{"cdn.example.com", "X-Forwarded-Host"} {
		if !strings.Contains(content, want) {
			t.Errorf("cache poison PoC missing %q", want)
		}
	}
	if !strings.Contains(filename, "cache-poison") {
		t.Errorf("filename %q should contain 'cache-poison'", filename)
	}
}

func TestGenerateChainPoC_DNSRebinding(t *testing.T) {
	cf := finding.Finding{
		CheckID: "correlation.dns_rebinding_chain",
		Asset:   "internal.example.com",
		Evidence: map[string]any{
			"pivot_target": "192.168.1.100",
			"pivot_port":   "8080",
		},
	}
	content, filename, lang := GenerateChainPoC(cf, nil)

	if lang != "html" {
		t.Errorf("DNS rebinding PoC lang = %q, want html", lang)
	}
	for _, want := range []string{"192.168.1.100", "8080"} {
		if !strings.Contains(content, want) {
			t.Errorf("DNS rebinding PoC missing %q", want)
		}
	}
	if !strings.Contains(filename, "dns-rebind") {
		t.Errorf("filename %q should contain 'dns-rebind'", filename)
	}
}

func TestGenerateChainPoC_AuthBypass(t *testing.T) {
	cf := finding.Finding{
		CheckID: "correlation.auth_bypass_chain",
		Asset:   "admin.example.com",
		Evidence: map[string]any{
			"url":              "https://admin.example.com/api",
			"injection_vector": "JWT alg:none",
		},
	}
	content, filename, lang := GenerateChainPoC(cf, nil)

	if lang != "python" {
		t.Errorf("auth bypass PoC lang = %q, want python", lang)
	}
	for _, want := range []string{"admin.example.com/api", "JWT alg:none", "alg"} {
		if !strings.Contains(content, want) {
			t.Errorf("auth bypass PoC missing %q", want)
		}
	}
	if !strings.Contains(filename, "auth-bypass") {
		t.Errorf("filename %q should contain 'auth-bypass'", filename)
	}
}

func TestGenerateChainPoC_Default(t *testing.T) {
	cf := finding.Finding{
		CheckID:      "correlation.custom_chain",
		Asset:        "host.example.com",
		Title:        "Custom Chain",
		ProofCommand: "curl https://host.example.com/vuln",
	}
	content, filename, lang := GenerateChainPoC(cf, nil)

	if lang != "bash" {
		t.Errorf("default PoC lang = %q, want bash", lang)
	}
	if !strings.Contains(content, "curl https://host.example.com/vuln") {
		t.Error("default PoC should include proof command from finding")
	}
	if !strings.Contains(filename, "host-example-com") {
		t.Errorf("filename %q should contain sanitized asset", filename)
	}
}

func TestGenerateChainPoC_UsesSpecificEvidence(t *testing.T) {
	// Verify PoC uses specific evidence, not defaults.
	cf := finding.Finding{
		CheckID: "chain.ssrf_to_cloud_creds",
		Asset:   "specific.host.io",
		Evidence: map[string]any{
			"url":            "https://specific.host.io/api/fetch-resource",
			"parameter":      "resource_url",
			"cloud_provider": "GCP",
			"iam_role":       "custom-sa@project.iam",
		},
	}
	content, _, _ := GenerateChainPoC(cf, nil)

	if !strings.Contains(content, "specific.host.io/api/fetch-resource") {
		t.Error("PoC should use specific URL from evidence")
	}
	if !strings.Contains(content, "resource_url") {
		t.Error("PoC should use specific parameter from evidence")
	}
	if !strings.Contains(content, "GCP") {
		t.Error("PoC should use GCP provider from evidence")
	}
	if !strings.Contains(content, "metadata.google.internal") {
		t.Error("PoC should use GCP metadata URL for GCP provider")
	}
}
