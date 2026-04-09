package report

import (
	"strings"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
)

func TestGenerateNarrative_SessionHijack(t *testing.T) {
	cf := finding.Finding{
		CheckID: "correlation.session_hijack_chain",
		Asset:   "api.example.com",
		Title:   "Session Hijack via CORS + XSS",
		Evidence: map[string]any{
			"url":       "https://api.example.com/data",
			"xss_url":   "https://api.example.com/search",
			"parameter": "q",
		},
	}
	all := []finding.Finding{cf}
	out := GenerateNarrative(cf, all)

	checks := []string{
		"## Attack Path: Session Hijack via CORS + XSS",
		"api.example.com",
		"CORS Misconfiguration",
		"Reflected XSS",
		"Cookie Theft",
		"Combined Attack",
		"/search",
		"`q`",
		"HttpOnly",
	}
	for _, want := range checks {
		if !strings.Contains(out, want) {
			t.Errorf("session hijack narrative missing %q", want)
		}
	}
}

func TestGenerateNarrative_CredentialTheft(t *testing.T) {
	cf := finding.Finding{
		CheckID: "correlation.credential_theft_chain",
		Asset:   "app.example.com",
		Title:   "Credential Theft via Exposed .env",
		Evidence: map[string]any{
			"path":             "/.env",
			"credential_source": "/.env",
			"snippet":          "DB_PASS=hunter2",
			"grants_access_to": "PostgreSQL database",
		},
	}
	out := GenerateNarrative(cf, nil)

	checks := []string{
		"Credential Theft",
		"app.example.com",
		"/.env",
		"DB_PASS=hunter2",
		"PostgreSQL database",
	}
	for _, want := range checks {
		if !strings.Contains(out, want) {
			t.Errorf("credential theft narrative missing %q", want)
		}
	}
}

func TestGenerateNarrative_SSRFToCloudCreds(t *testing.T) {
	cf := finding.Finding{
		CheckID: "chain.ssrf_to_cloud_creds",
		Asset:   "app.target.io",
		Evidence: map[string]any{
			"url":            "https://app.target.io/proxy",
			"parameter":      "dest",
			"cloud_provider": "AWS",
			"iam_role":       "prod-web-role",
		},
	}
	out := GenerateNarrative(cf, nil)

	checks := []string{
		"SSRF",
		"AWS",
		"app.target.io/proxy",
		"`dest`",
		"prod-web-role",
		"169.254.169.254",
	}
	for _, want := range checks {
		if !strings.Contains(out, want) {
			t.Errorf("SSRF-to-cloud narrative missing %q", want)
		}
	}
}

func TestGenerateNarrative_DefaultCredsToAdmin(t *testing.T) {
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
	out := GenerateNarrative(cf, nil)

	for _, want := range []string{"Default Credentials", "root", "toor", "Grafana", "panel.corp.com/admin"} {
		if !strings.Contains(out, want) {
			t.Errorf("default creds narrative missing %q", want)
		}
	}
}

func TestGenerateNarrative_EnvToDatabase(t *testing.T) {
	cf := finding.Finding{
		CheckID: "chain.env_to_database_access",
		Asset:   "web.example.com",
		Evidence: map[string]any{
			"path":         "/.env",
			"snippet":      "DATABASE_URL=mysql://root:secret@db.prod:3306/app",
			"pivot_target": "db.prod",
			"pivot_port":   "3306",
		},
	}
	out := GenerateNarrative(cf, nil)

	for _, want := range []string{"db.prod", "3306", "/.env", "DATABASE_URL"} {
		if !strings.Contains(out, want) {
			t.Errorf("env-to-db narrative missing %q", want)
		}
	}
}

func TestGenerateNarrative_SQLiToCredentialDump(t *testing.T) {
	cf := finding.Finding{
		CheckID: "chain.sqli_to_credential_dump",
		Asset:   "shop.example.com",
		Evidence: map[string]any{
			"url":          "https://shop.example.com/product",
			"parameter":    "pid",
			"payload":      "' UNION SELECT user,pass FROM accounts--",
			"record_count": "1500",
		},
	}
	out := GenerateNarrative(cf, nil)

	for _, want := range []string{"SQL Injection", "shop.example.com/product", "pid", "1500"} {
		if !strings.Contains(out, want) {
			t.Errorf("sqli-to-dump narrative missing %q", want)
		}
	}
}

func TestGenerateNarrative_XSSToSessionTheft(t *testing.T) {
	cf := finding.Finding{
		CheckID: "chain.xss_to_session_theft_poc",
		Asset:   "forum.example.com",
		Evidence: map[string]any{
			"url":       "https://forum.example.com/post",
			"parameter": "body",
		},
	}
	out := GenerateNarrative(cf, nil)

	for _, want := range []string{"XSS", "Session Theft", "forum.example.com/post", "body", "HttpOnly"} {
		if !strings.Contains(out, want) {
			t.Errorf("xss-session-theft narrative missing %q", want)
		}
	}
}

func TestGenerateNarrative_FullCompromise(t *testing.T) {
	cf := finding.Finding{
		CheckID: "correlation.full_compromise_chain",
		Asset:   "api.corp.com",
		Evidence: map[string]any{
			"url":              "https://api.corp.com/v1/query",
			"injection_vector": "SSRF",
			"pivot_target":     "redis.internal",
			"data_type":        "session tokens",
		},
	}
	out := GenerateNarrative(cf, nil)

	for _, want := range []string{"Full Compromise", "SSRF", "redis.internal", "session tokens"} {
		if !strings.Contains(out, want) {
			t.Errorf("full compromise narrative missing %q", want)
		}
	}
}

func TestGenerateNarrative_LateralMovement(t *testing.T) {
	cf := finding.Finding{
		CheckID: "correlation.lateral_movement_chain",
		Asset:   "edge.example.com",
		Evidence: map[string]any{
			"service":      "Redis",
			"pivot_target": "cache.internal",
			"pivot_port":   "6379",
			"url":          "https://edge.example.com/proxy",
		},
	}
	out := GenerateNarrative(cf, nil)

	for _, want := range []string{"Lateral Movement", "Redis", "cache.internal", "6379"} {
		if !strings.Contains(out, want) {
			t.Errorf("lateral movement narrative missing %q", want)
		}
	}
}

func TestGenerateNarrative_CachePoison(t *testing.T) {
	cf := finding.Finding{
		CheckID: "correlation.cache_poisoning_chain",
		Asset:   "cdn.example.com",
		Evidence: map[string]any{
			"url":             "https://cdn.example.com/assets/main.js",
			"unkeyed_header":  "X-Forwarded-Host",
			"payload":         "evil.attacker.com",
		},
	}
	out := GenerateNarrative(cf, nil)

	for _, want := range []string{"Cache Poisoning", "X-Forwarded-Host", "evil.attacker.com", "cdn.example.com"} {
		if !strings.Contains(out, want) {
			t.Errorf("cache poisoning narrative missing %q", want)
		}
	}
}

func TestGenerateNarrative_DNSRebinding(t *testing.T) {
	cf := finding.Finding{
		CheckID: "correlation.dns_rebinding_chain",
		Asset:   "internal.example.com",
		Evidence: map[string]any{
			"pivot_target": "192.168.1.100",
			"pivot_port":   "8080",
			"service":      "Jenkins",
		},
	}
	out := GenerateNarrative(cf, nil)

	for _, want := range []string{"DNS Rebinding", "192.168.1.100", "8080", "Jenkins"} {
		if !strings.Contains(out, want) {
			t.Errorf("DNS rebinding narrative missing %q", want)
		}
	}
}

func TestGenerateNarrative_AuthBypass(t *testing.T) {
	cf := finding.Finding{
		CheckID: "correlation.auth_bypass_chain",
		Asset:   "admin.example.com",
		Evidence: map[string]any{
			"url":              "https://admin.example.com/api",
			"service":          "admin API",
			"injection_vector": "JWT alg:none",
		},
	}
	out := GenerateNarrative(cf, nil)

	for _, want := range []string{"Authentication Bypass", "admin.example.com/api", "admin API", "JWT alg:none"} {
		if !strings.Contains(out, want) {
			t.Errorf("auth bypass narrative missing %q", want)
		}
	}
}

func TestGenerateNarrative_Generic(t *testing.T) {
	cf := finding.Finding{
		CheckID:     "correlation.attack_chain",
		Asset:       "target.example.com",
		Title:       "Custom Attack Chain",
		Description: "Multiple vulnerabilities combine into full compromise",
		Evidence: map[string]any{
			"url": "https://target.example.com/vuln",
		},
	}
	out := GenerateNarrative(cf, nil)

	if !strings.Contains(out, "Custom Attack Chain") {
		t.Error("generic narrative missing title")
	}
	if !strings.Contains(out, "target.example.com") {
		t.Error("generic narrative missing asset")
	}
}

func TestGenerateNarrative_UsesEvidenceNotGeneric(t *testing.T) {
	// Verify the narrative uses specific evidence values, not defaults.
	cf := finding.Finding{
		CheckID: "chain.ssrf_to_cloud_creds",
		Asset:   "specific-host.io",
		Evidence: map[string]any{
			"url":            "https://specific-host.io/fetch-url",
			"parameter":      "target_url",
			"cloud_provider": "GCP",
			"iam_role":       "my-custom-sa",
		},
	}
	out := GenerateNarrative(cf, nil)

	// Must contain specific values from evidence, not defaults.
	if !strings.Contains(out, "specific-host.io/fetch-url") {
		t.Error("narrative should use specific URL from evidence, not a default")
	}
	if !strings.Contains(out, "target_url") {
		t.Error("narrative should use specific parameter from evidence")
	}
	if !strings.Contains(out, "GCP") {
		t.Error("narrative should use GCP from evidence, not default AWS")
	}
	if !strings.Contains(out, "my-custom-sa") {
		t.Error("narrative should use specific IAM role from evidence")
	}
	// GCP should use google metadata endpoint
	if !strings.Contains(out, "metadata.google.internal") {
		t.Error("narrative should use GCP metadata endpoint for GCP provider")
	}
}

func TestIsChainFinding(t *testing.T) {
	tests := []struct {
		checkID string
		want    bool
	}{
		{"correlation.session_hijack_chain", true},
		{"chain.ssrf_to_cloud_creds", true},
		{"web.xss", false},
		{"port.redis_unauth", false},
		{"correlation.attack_chain", true},
		{"chain.env_to_database_access", true},
	}
	for _, tt := range tests {
		f := finding.Finding{CheckID: finding.CheckID(tt.checkID)}
		if got := isChainFinding(f); got != tt.want {
			t.Errorf("isChainFinding(%q) = %v, want %v", tt.checkID, got, tt.want)
		}
	}
}
