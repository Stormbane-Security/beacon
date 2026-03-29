package config

import (
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// Load — valid config file
// ---------------------------------------------------------------------------

func TestLoad_ValidFile(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.yaml")
	content := `
anthropic_api_key: sk-ant-test-key
shodan_api_key: shodan-key-123
claude_model: claude-opus-4-6
request_jitter_ms: 50
adaptive_recon: true
proxy_pool:
  - socks5://1.2.3.4:1080
  - http://5.6.7.8:8080
auth:
  - asset: "example.com"
    method: bearer
    token: tok-abc
`
	if err := os.WriteFile(cfgFile, []byte(content), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	t.Setenv("BEACON_CONFIG", cfgFile)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.AnthropicAPIKey != "sk-ant-test-key" {
		t.Errorf("AnthropicAPIKey = %q, want %q", cfg.AnthropicAPIKey, "sk-ant-test-key")
	}
	if cfg.ShodanAPIKey != "shodan-key-123" {
		t.Errorf("ShodanAPIKey = %q, want %q", cfg.ShodanAPIKey, "shodan-key-123")
	}
	if cfg.ClaudeModel != "claude-opus-4-6" {
		t.Errorf("ClaudeModel = %q, want %q", cfg.ClaudeModel, "claude-opus-4-6")
	}
	if cfg.RequestJitterMs != 50 {
		t.Errorf("RequestJitterMs = %d, want 50", cfg.RequestJitterMs)
	}
	if !cfg.AdaptiveRecon {
		t.Error("AdaptiveRecon = false, want true")
	}
	if len(cfg.ProxyPool) != 2 {
		t.Fatalf("ProxyPool length = %d, want 2", len(cfg.ProxyPool))
	}
	if cfg.ProxyPool[0] != "socks5://1.2.3.4:1080" {
		t.Errorf("ProxyPool[0] = %q, want %q", cfg.ProxyPool[0], "socks5://1.2.3.4:1080")
	}
	if len(cfg.Auth) != 1 {
		t.Fatalf("Auth length = %d, want 1", len(cfg.Auth))
	}
	if cfg.Auth[0].Asset != "example.com" {
		t.Errorf("Auth[0].Asset = %q, want %q", cfg.Auth[0].Asset, "example.com")
	}
	if cfg.Auth[0].Method != "bearer" {
		t.Errorf("Auth[0].Method = %q, want %q", cfg.Auth[0].Method, "bearer")
	}
	if cfg.LoadedFrom() != cfgFile {
		t.Errorf("LoadedFrom() = %q, want %q", cfg.LoadedFrom(), cfgFile)
	}
}

// ---------------------------------------------------------------------------
// Load — missing file falls back to defaults + env vars
// ---------------------------------------------------------------------------

func TestLoad_MissingFile_UsesDefaults(t *testing.T) {
	dir := t.TempDir()
	// Point at a file that does not exist.
	t.Setenv("BEACON_CONFIG", filepath.Join(dir, "nonexistent.yaml"))

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.ClaudeModel != "claude-sonnet-4-6" {
		t.Errorf("ClaudeModel = %q, want default %q", cfg.ClaudeModel, "claude-sonnet-4-6")
	}
	if cfg.NmapBin != "nmap" {
		t.Errorf("NmapBin = %q, want default %q", cfg.NmapBin, "nmap")
	}
	if cfg.SMTP.Port != 587 {
		t.Errorf("SMTP.Port = %d, want default 587", cfg.SMTP.Port)
	}
	if cfg.LoadedFrom() != "" {
		t.Errorf("LoadedFrom() = %q, want empty string for missing file", cfg.LoadedFrom())
	}
}

// ---------------------------------------------------------------------------
// Load — invalid YAML returns error
// ---------------------------------------------------------------------------

func TestLoad_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.yaml")
	// Write YAML with a tab character that confuses the parser.
	if err := os.WriteFile(cfgFile, []byte(":\t\ninvalid:\n  [broken"), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	t.Setenv("BEACON_CONFIG", cfgFile)

	_, err := Load()
	if err == nil {
		t.Fatal("Load() with invalid YAML should return error, got nil")
	}
}

// ---------------------------------------------------------------------------
// Load — env vars override file values
// ---------------------------------------------------------------------------

func TestLoad_EnvOverridesFile(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.yaml")
	content := `
anthropic_api_key: file-key
shodan_api_key: file-shodan
claude_model: file-model
`
	if err := os.WriteFile(cfgFile, []byte(content), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	t.Setenv("BEACON_CONFIG", cfgFile)
	t.Setenv("BEACON_ANTHROPIC_API_KEY", "env-key")
	t.Setenv("BEACON_SHODAN_API_KEY", "env-shodan")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.AnthropicAPIKey != "env-key" {
		t.Errorf("AnthropicAPIKey = %q, want env override %q", cfg.AnthropicAPIKey, "env-key")
	}
	if cfg.ShodanAPIKey != "env-shodan" {
		t.Errorf("ShodanAPIKey = %q, want env override %q", cfg.ShodanAPIKey, "env-shodan")
	}
	// claude_model should remain from file since we did not set BEACON_CLAUDE_MODEL.
	if cfg.ClaudeModel != "file-model" {
		t.Errorf("ClaudeModel = %q, want file value %q", cfg.ClaudeModel, "file-model")
	}
}

// ---------------------------------------------------------------------------
// Validate — valid config
// ---------------------------------------------------------------------------

func TestValidate_ValidConfig(t *testing.T) {
	cfg := defaults()
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() on defaults should pass, got: %v", err)
	}
}

func TestValidate_ValidAuth(t *testing.T) {
	methods := []string{"bearer", "api_key", "cookie", "basic", "oidc", "web3_evm", "web3_sol"}
	for _, m := range methods {
		t.Run(m, func(t *testing.T) {
			cfg := defaults()
			cfg.Auth = []AuthConfig{{Asset: "example.com", Method: m}}
			if err := cfg.Validate(); err != nil {
				t.Errorf("Validate() with method %q should pass, got: %v", m, err)
			}
		})
	}
}

func TestValidate_ValidAIProviders(t *testing.T) {
	providers := []string{"", "claude", "openai", "gemini", "ollama", "mistral", "grok", "groq"}
	for _, p := range providers {
		t.Run("provider="+p, func(t *testing.T) {
			cfg := defaults()
			cfg.AI.Provider = p
			if err := cfg.Validate(); err != nil {
				t.Errorf("Validate() with provider %q should pass, got: %v", p, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Validate — missing required fields / invalid values
// ---------------------------------------------------------------------------

func TestValidate_AuthMissingMethod(t *testing.T) {
	cfg := defaults()
	cfg.Auth = []AuthConfig{{Asset: "example.com", Method: ""}}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should fail when auth method is empty")
	}
	if got := err.Error(); got != "auth[0]: method is required" {
		t.Errorf("error = %q, want auth method required message", got)
	}
}

func TestValidate_AuthUnknownMethod(t *testing.T) {
	cfg := defaults()
	cfg.Auth = []AuthConfig{{Asset: "example.com", Method: "magic"}}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should fail for unknown auth method")
	}
}

func TestValidate_AuthMissingAsset(t *testing.T) {
	cfg := defaults()
	cfg.Auth = []AuthConfig{{Asset: "", Method: "bearer"}}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should fail when auth asset is empty")
	}
	if got := err.Error(); got != `auth[0]: asset is required (use "*" for all assets)` {
		t.Errorf("error = %q, want auth asset required message", got)
	}
}

func TestValidate_NegativeJitter(t *testing.T) {
	cfg := defaults()
	cfg.RequestJitterMs = -5
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should fail for negative jitter")
	}
}

func TestValidate_InvalidAIProvider(t *testing.T) {
	cfg := defaults()
	cfg.AI.Provider = "deepseek"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should fail for unsupported AI provider")
	}
}

func TestValidate_MultipleAuthErrors_ReportsFirst(t *testing.T) {
	cfg := defaults()
	cfg.Auth = []AuthConfig{
		{Asset: "good.com", Method: "bearer"},
		{Asset: "", Method: "cookie"},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should fail when second auth entry has empty asset")
	}
}

// ---------------------------------------------------------------------------
// applyEnv — environment variable overrides
// ---------------------------------------------------------------------------

func TestApplyEnv_APIKeys(t *testing.T) {
	tests := []struct {
		envVar string
		getter func(*Config) string
	}{
		{"BEACON_ANTHROPIC_API_KEY", func(c *Config) string { return c.AnthropicAPIKey }},
		{"BEACON_SHODAN_API_KEY", func(c *Config) string { return c.ShodanAPIKey }},
		{"BEACON_OTX_API_KEY", func(c *Config) string { return c.OTXAPIKey }},
		{"BEACON_HIBP_API_KEY", func(c *Config) string { return c.HIBPAPIKey }},
		{"BEACON_BING_API_KEY", func(c *Config) string { return c.BingAPIKey }},
		{"BEACON_VIRUSTOTAL_API_KEY", func(c *Config) string { return c.VirusTotalAPIKey }},
		{"BEACON_SECURITYTRAILS_API_KEY", func(c *Config) string { return c.SecurityTrailsAPIKey }},
		{"BEACON_CENSYS_API_ID", func(c *Config) string { return c.CensysAPIID }},
		{"BEACON_CENSYS_API_SECRET", func(c *Config) string { return c.CensysAPISecret }},
		{"BEACON_GREYNOISE_API_KEY", func(c *Config) string { return c.GreyNoiseAPIKey }},
		{"BEACON_GITHUB_TOKEN", func(c *Config) string { return c.GitHubToken }},
		{"BEACON_WEBHOOK_URL", func(c *Config) string { return c.WebhookURL }},
		{"BEACON_WEBHOOK_API_KEY", func(c *Config) string { return c.WebhookAPIKey }},
		{"BEACON_SERVER_URL", func(c *Config) string { return c.Server.URL }},
		{"BEACON_SERVER_API_KEY", func(c *Config) string { return c.Server.APIKey }},
	}
	for _, tt := range tests {
		t.Run(tt.envVar, func(t *testing.T) {
			cfg := defaults()
			t.Setenv(tt.envVar, "test-value-"+tt.envVar)
			applyEnv(cfg)
			got := tt.getter(cfg)
			want := "test-value-" + tt.envVar
			if got != want {
				t.Errorf("%s: got %q, want %q", tt.envVar, got, want)
			}
		})
	}
}

func TestApplyEnv_AIConfig(t *testing.T) {
	cfg := defaults()
	t.Setenv("BEACON_AI_PROVIDER", "openai")
	t.Setenv("BEACON_AI_API_KEY", "sk-openai-abc")
	t.Setenv("BEACON_AI_MODEL", "gpt-4-turbo")
	t.Setenv("BEACON_AI_BASE_URL", "https://custom.openai.com")
	applyEnv(cfg)

	if cfg.AI.Provider != "openai" {
		t.Errorf("AI.Provider = %q, want %q", cfg.AI.Provider, "openai")
	}
	if cfg.AI.APIKey != "sk-openai-abc" {
		t.Errorf("AI.APIKey = %q, want %q", cfg.AI.APIKey, "sk-openai-abc")
	}
	if cfg.AI.Model != "gpt-4-turbo" {
		t.Errorf("AI.Model = %q, want %q", cfg.AI.Model, "gpt-4-turbo")
	}
	if cfg.AI.BaseURL != "https://custom.openai.com" {
		t.Errorf("AI.BaseURL = %q, want %q", cfg.AI.BaseURL, "https://custom.openai.com")
	}
}

func TestApplyEnv_BinaryPaths(t *testing.T) {
	tests := []struct {
		envVar string
		getter func(*Config) string
	}{
		{"BEACON_NMAP_BIN", func(c *Config) string { return c.NmapBin }},
		{"BEACON_NUCLEI_BIN", func(c *Config) string { return c.NucleiBin }},
		{"BEACON_GITLEAKS_BIN", func(c *Config) string { return c.GitleaksBin }},
		{"BEACON_TESTSSL_BIN", func(c *Config) string { return c.TestsslBin }},
		{"BEACON_AMASS_BIN", func(c *Config) string { return c.AmmassBin }},
		{"BEACON_GAU_BIN", func(c *Config) string { return c.GauBin }},
		{"BEACON_KATANA_BIN", func(c *Config) string { return c.KatanaBin }},
		{"BEACON_GOWITNESS_BIN", func(c *Config) string { return c.GowitnessBin }},
		{"BEACON_HTTPX_BIN", func(c *Config) string { return c.HttpxBin }},
		{"BEACON_DNSX_BIN", func(c *Config) string { return c.DnsxBin }},
		{"BEACON_FFUF_BIN", func(c *Config) string { return c.FfufBin }},
	}
	for _, tt := range tests {
		t.Run(tt.envVar, func(t *testing.T) {
			cfg := defaults()
			t.Setenv(tt.envVar, "/custom/bin/"+tt.envVar)
			applyEnv(cfg)
			got := tt.getter(cfg)
			want := "/custom/bin/" + tt.envVar
			if got != want {
				t.Errorf("%s: got %q, want %q", tt.envVar, got, want)
			}
		})
	}
}

func TestApplyEnv_BoolFlags(t *testing.T) {
	tests := []struct {
		name   string
		envVar string
		value  string
		getter func(*Config) bool
		want   bool
	}{
		{"adaptive_recon true", "BEACON_ADAPTIVE_RECON", "true", func(c *Config) bool { return c.AdaptiveRecon }, true},
		{"adaptive_recon 1", "BEACON_ADAPTIVE_RECON", "1", func(c *Config) bool { return c.AdaptiveRecon }, true},
		{"adaptive_recon yes", "BEACON_ADAPTIVE_RECON", "yes", func(c *Config) bool { return c.AdaptiveRecon }, true},
		{"adaptive_recon false", "BEACON_ADAPTIVE_RECON", "false", func(c *Config) bool { return c.AdaptiveRecon }, false},
		{"attack_path true", "BEACON_ATTACK_PATH", "true", func(c *Config) bool { return c.AttackPathAnalysis }, true},
		{"attack_path 1", "BEACON_ATTACK_PATH", "1", func(c *Config) bool { return c.AttackPathAnalysis }, true},
		{"attack_path no", "BEACON_ATTACK_PATH", "no", func(c *Config) bool { return c.AttackPathAnalysis }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := defaults()
			t.Setenv(tt.envVar, tt.value)
			applyEnv(cfg)
			if got := tt.getter(cfg); got != tt.want {
				t.Errorf("%s=%s: got %v, want %v", tt.envVar, tt.value, got, tt.want)
			}
		})
	}
}

func TestApplyEnv_ProxyPool(t *testing.T) {
	cfg := defaults()
	t.Setenv("BEACON_PROXY_POOL", "socks5://a:1080, http://b:8080 , https://c:443")
	applyEnv(cfg)

	if len(cfg.ProxyPool) != 3 {
		t.Fatalf("ProxyPool length = %d, want 3", len(cfg.ProxyPool))
	}
	want := []string{"socks5://a:1080", "http://b:8080", "https://c:443"}
	for i, w := range want {
		if cfg.ProxyPool[i] != w {
			t.Errorf("ProxyPool[%d] = %q, want %q", i, cfg.ProxyPool[i], w)
		}
	}
}

func TestApplyEnv_ProxyPool_EmptySegments(t *testing.T) {
	cfg := defaults()
	t.Setenv("BEACON_PROXY_POOL", "socks5://a:1080,,  ,http://b:8080")
	applyEnv(cfg)

	if len(cfg.ProxyPool) != 2 {
		t.Fatalf("ProxyPool length = %d, want 2 (empty segments skipped)", len(cfg.ProxyPool))
	}
}

func TestApplyEnv_RequestJitterMs(t *testing.T) {
	cfg := defaults()
	t.Setenv("BEACON_REQUEST_JITTER_MS", "200")
	applyEnv(cfg)

	if cfg.RequestJitterMs != 200 {
		t.Errorf("RequestJitterMs = %d, want 200", cfg.RequestJitterMs)
	}
}

func TestApplyEnv_RequestJitterMs_InvalidIgnored(t *testing.T) {
	cfg := defaults()
	cfg.RequestJitterMs = 42
	t.Setenv("BEACON_REQUEST_JITTER_MS", "not-a-number")
	applyEnv(cfg)

	if cfg.RequestJitterMs != 42 {
		t.Errorf("RequestJitterMs = %d, want 42 (invalid env should be ignored)", cfg.RequestJitterMs)
	}
}

func TestApplyEnv_RequestJitterMs_NegativeIgnored(t *testing.T) {
	cfg := defaults()
	cfg.RequestJitterMs = 10
	t.Setenv("BEACON_REQUEST_JITTER_MS", "-5")
	applyEnv(cfg)

	// Negative values are silently ignored by applyEnv (ms >= 0 check).
	if cfg.RequestJitterMs != 10 {
		t.Errorf("RequestJitterMs = %d, want 10 (negative env should be ignored)", cfg.RequestJitterMs)
	}
}

func TestApplyEnv_SMTPConfig(t *testing.T) {
	cfg := defaults()
	t.Setenv("BEACON_SMTP_HOST", "smtp.example.com")
	t.Setenv("BEACON_SMTP_PORT", "465")
	t.Setenv("BEACON_SMTP_USER", "user@example.com")
	t.Setenv("BEACON_SMTP_PASS", "s3cret")
	t.Setenv("BEACON_SMTP_FROM", "noreply@example.com")
	applyEnv(cfg)

	if cfg.SMTP.Host != "smtp.example.com" {
		t.Errorf("SMTP.Host = %q, want %q", cfg.SMTP.Host, "smtp.example.com")
	}
	if cfg.SMTP.Port != 465 {
		t.Errorf("SMTP.Port = %d, want 465", cfg.SMTP.Port)
	}
	if cfg.SMTP.User != "user@example.com" {
		t.Errorf("SMTP.User = %q, want %q", cfg.SMTP.User, "user@example.com")
	}
	if cfg.SMTP.Password != "s3cret" {
		t.Errorf("SMTP.Password = %q, want %q", cfg.SMTP.Password, "s3cret")
	}
	if cfg.SMTP.From != "noreply@example.com" {
		t.Errorf("SMTP.From = %q, want %q", cfg.SMTP.From, "noreply@example.com")
	}
}

func TestApplyEnv_StorePath(t *testing.T) {
	cfg := defaults()
	t.Setenv("BEACON_STORE_PATH", "/tmp/custom.db")
	applyEnv(cfg)

	if cfg.Store.Path != "/tmp/custom.db" {
		t.Errorf("Store.Path = %q, want %q", cfg.Store.Path, "/tmp/custom.db")
	}
}

func TestApplyEnv_ClaudeModel(t *testing.T) {
	cfg := defaults()
	t.Setenv("BEACON_CLAUDE_MODEL", "claude-haiku-4-5-20251001")
	applyEnv(cfg)

	if cfg.ClaudeModel != "claude-haiku-4-5-20251001" {
		t.Errorf("ClaudeModel = %q, want %q", cfg.ClaudeModel, "claude-haiku-4-5-20251001")
	}
}

func TestApplyEnv_AuthToken(t *testing.T) {
	cfg := defaults()
	cfg.Auth = []AuthConfig{{Asset: "specific.com", Method: "bearer", Token: "per-asset"}}
	t.Setenv("BEACON_AUTH_TOKEN", "global-bearer-tok")
	applyEnv(cfg)

	if len(cfg.Auth) != 2 {
		t.Fatalf("Auth length = %d, want 2 (global prepended + existing)", len(cfg.Auth))
	}
	// Global token should be first.
	if cfg.Auth[0].Asset != "*" {
		t.Errorf("Auth[0].Asset = %q, want %q", cfg.Auth[0].Asset, "*")
	}
	if cfg.Auth[0].Token != "global-bearer-tok" {
		t.Errorf("Auth[0].Token = %q, want %q", cfg.Auth[0].Token, "global-bearer-tok")
	}
	if cfg.Auth[0].Method != "bearer" {
		t.Errorf("Auth[0].Method = %q, want %q", cfg.Auth[0].Method, "bearer")
	}
	// Existing per-asset entry preserved at index 1.
	if cfg.Auth[1].Asset != "specific.com" {
		t.Errorf("Auth[1].Asset = %q, want %q", cfg.Auth[1].Asset, "specific.com")
	}
}

// ---------------------------------------------------------------------------
// ActiveAI — returns correct provider config
// ---------------------------------------------------------------------------

func TestActiveAI_ExplicitProvider(t *testing.T) {
	cfg := defaults()
	cfg.AI = AIConfig{
		Provider: "OpenAI",
		APIKey:   "sk-test",
		Model:    "gpt-4o",
		BaseURL:  "https://api.openai.com",
	}
	ai := cfg.ActiveAI()
	if ai == nil {
		t.Fatal("ActiveAI() returned nil, want non-nil for explicit provider")
	}
	if ai.Provider != "openai" {
		t.Errorf("Provider = %q, want lowercased %q", ai.Provider, "openai")
	}
	if ai.APIKey != "sk-test" {
		t.Errorf("APIKey = %q, want %q", ai.APIKey, "sk-test")
	}
	if ai.Model != "gpt-4o" {
		t.Errorf("Model = %q, want %q", ai.Model, "gpt-4o")
	}
}

func TestActiveAI_OllamaNoAPIKey(t *testing.T) {
	cfg := defaults()
	cfg.AI = AIConfig{Provider: "ollama", Model: "llama3.1"}
	ai := cfg.ActiveAI()
	if ai == nil {
		t.Fatal("ActiveAI() returned nil, want non-nil for ollama (no api_key needed)")
	}
	if ai.Provider != "ollama" {
		t.Errorf("Provider = %q, want %q", ai.Provider, "ollama")
	}
	if ai.APIKey != "" {
		t.Errorf("APIKey = %q, want empty for ollama", ai.APIKey)
	}
}

func TestActiveAI_LegacyFallback(t *testing.T) {
	cfg := defaults()
	cfg.AnthropicAPIKey = "sk-ant-legacy"
	cfg.ClaudeModel = "claude-opus-4-6"
	ai := cfg.ActiveAI()
	if ai == nil {
		t.Fatal("ActiveAI() returned nil, want legacy claude fallback")
	}
	if ai.Provider != "claude" {
		t.Errorf("Provider = %q, want %q", ai.Provider, "claude")
	}
	if ai.APIKey != "sk-ant-legacy" {
		t.Errorf("APIKey = %q, want %q", ai.APIKey, "sk-ant-legacy")
	}
	if ai.Model != "claude-opus-4-6" {
		t.Errorf("Model = %q, want %q", ai.Model, "claude-opus-4-6")
	}
}

func TestActiveAI_ExplicitOverridesLegacy(t *testing.T) {
	cfg := defaults()
	cfg.AnthropicAPIKey = "sk-ant-legacy"
	cfg.AI = AIConfig{Provider: "gemini", APIKey: "gem-key"}
	ai := cfg.ActiveAI()
	if ai == nil {
		t.Fatal("ActiveAI() returned nil")
	}
	if ai.Provider != "gemini" {
		t.Errorf("Provider = %q, want %q (explicit should override legacy)", ai.Provider, "gemini")
	}
	if ai.APIKey != "gem-key" {
		t.Errorf("APIKey = %q, want %q", ai.APIKey, "gem-key")
	}
}

func TestActiveAI_NothingConfigured(t *testing.T) {
	cfg := defaults()
	ai := cfg.ActiveAI()
	if ai != nil {
		t.Errorf("ActiveAI() = %+v, want nil when no AI is configured", ai)
	}
}

func TestActiveAI_ProviderCaseInsensitive(t *testing.T) {
	cfg := defaults()
	cfg.AI = AIConfig{Provider: "  Claude  ", APIKey: "key"}
	ai := cfg.ActiveAI()
	if ai == nil {
		t.Fatal("ActiveAI() returned nil")
	}
	if ai.Provider != "claude" {
		t.Errorf("Provider = %q, want %q (should be trimmed and lowercased)", ai.Provider, "claude")
	}
}

// ---------------------------------------------------------------------------
// Redacted — masks sensitive fields
// ---------------------------------------------------------------------------

func TestRedacted_MasksCredentials(t *testing.T) {
	cfg := defaults()
	cfg.AnthropicAPIKey = "sk-ant-secret"
	cfg.AI.APIKey = "ai-secret"
	cfg.ShodanAPIKey = "shodan-secret"
	cfg.OTXAPIKey = "otx-secret"
	cfg.HIBPAPIKey = "hibp-secret"
	cfg.BingAPIKey = "bing-secret"
	cfg.VirusTotalAPIKey = "vt-secret"
	cfg.SecurityTrailsAPIKey = "st-secret"
	cfg.CensysAPIID = "censys-id-secret"
	cfg.CensysAPISecret = "censys-secret"
	cfg.GreyNoiseAPIKey = "gn-secret"
	cfg.GitHubToken = "gh-secret"
	cfg.Server.APIKey = "server-secret"
	cfg.WebhookAPIKey = "webhook-secret"
	cfg.SMTP.Password = "smtp-secret"

	r := cfg.Redacted()

	redactedFields := map[string]string{
		"AnthropicAPIKey":      r.AnthropicAPIKey,
		"AI.APIKey":            r.AI.APIKey,
		"ShodanAPIKey":         r.ShodanAPIKey,
		"OTXAPIKey":            r.OTXAPIKey,
		"HIBPAPIKey":           r.HIBPAPIKey,
		"BingAPIKey":           r.BingAPIKey,
		"VirusTotalAPIKey":     r.VirusTotalAPIKey,
		"SecurityTrailsAPIKey": r.SecurityTrailsAPIKey,
		"CensysAPIID":          r.CensysAPIID,
		"CensysAPISecret":      r.CensysAPISecret,
		"GreyNoiseAPIKey":      r.GreyNoiseAPIKey,
		"GitHubToken":          r.GitHubToken,
		"Server.APIKey":        r.Server.APIKey,
		"WebhookAPIKey":        r.WebhookAPIKey,
		"SMTP.Password":        r.SMTP.Password,
	}
	for field, val := range redactedFields {
		if val != "[REDACTED]" {
			t.Errorf("Redacted().%s = %q, want %q", field, val, "[REDACTED]")
		}
	}
}

func TestRedacted_EmptyFieldsStayEmpty(t *testing.T) {
	cfg := defaults()
	// All credential fields are empty by default.
	r := cfg.Redacted()

	if r.AnthropicAPIKey != "" {
		t.Errorf("Redacted().AnthropicAPIKey = %q, want empty (was not set)", r.AnthropicAPIKey)
	}
	if r.ShodanAPIKey != "" {
		t.Errorf("Redacted().ShodanAPIKey = %q, want empty (was not set)", r.ShodanAPIKey)
	}
	if r.SMTP.Password != "" {
		t.Errorf("Redacted().SMTP.Password = %q, want empty (was not set)", r.SMTP.Password)
	}
}

func TestRedacted_AuthCredentials(t *testing.T) {
	cfg := defaults()
	cfg.Auth = []AuthConfig{
		{
			Asset:           "example.com",
			Method:          "bearer",
			Token:           "secret-token",
			Password:        "secret-pass",
			Cookie:          "session=secret",
			ClientSecret:    "oidc-secret",
			EVMPrivateKey:   "0xdeadbeef",
			SolanaPrivateKey: "solana-secret-key",
		},
	}
	r := cfg.Redacted()

	if len(r.Auth) != 1 {
		t.Fatalf("Redacted().Auth length = %d, want 1", len(r.Auth))
	}
	a := r.Auth[0]
	// Asset and method should NOT be redacted.
	if a.Asset != "example.com" {
		t.Errorf("Auth[0].Asset = %q, should not be redacted", a.Asset)
	}
	if a.Method != "bearer" {
		t.Errorf("Auth[0].Method = %q, should not be redacted", a.Method)
	}
	// All credential fields should be redacted.
	authCreds := map[string]string{
		"Token":           a.Token,
		"Password":        a.Password,
		"Cookie":          a.Cookie,
		"ClientSecret":    a.ClientSecret,
		"EVMPrivateKey":   a.EVMPrivateKey,
		"SolanaPrivateKey": a.SolanaPrivateKey,
	}
	for field, val := range authCreds {
		if val != "[REDACTED]" {
			t.Errorf("Redacted().Auth[0].%s = %q, want %q", field, val, "[REDACTED]")
		}
	}
}

func TestRedacted_DoesNotMutateOriginal(t *testing.T) {
	cfg := defaults()
	cfg.AnthropicAPIKey = "original-key"
	cfg.Auth = []AuthConfig{{Asset: "*", Method: "bearer", Token: "original-token"}}

	_ = cfg.Redacted()

	// Original config should be untouched.
	if cfg.AnthropicAPIKey != "original-key" {
		t.Errorf("original AnthropicAPIKey = %q, was mutated by Redacted()", cfg.AnthropicAPIKey)
	}
	if cfg.Auth[0].Token != "original-token" {
		t.Errorf("original Auth[0].Token = %q, was mutated by Redacted()", cfg.Auth[0].Token)
	}
}

// ---------------------------------------------------------------------------
// defaults — verify sensible defaults
// ---------------------------------------------------------------------------

func TestDefaults_SensibleValues(t *testing.T) {
	cfg := defaults()

	if cfg.ClaudeModel != "claude-sonnet-4-6" {
		t.Errorf("default ClaudeModel = %q, want %q", cfg.ClaudeModel, "claude-sonnet-4-6")
	}
	if cfg.SMTP.Port != 587 {
		t.Errorf("default SMTP.Port = %d, want 587", cfg.SMTP.Port)
	}
	if cfg.NmapBin != "nmap" {
		t.Errorf("default NmapBin = %q, want %q", cfg.NmapBin, "nmap")
	}
	if cfg.FfufBin != "ffuf" {
		t.Errorf("default FfufBin = %q, want %q", cfg.FfufBin, "ffuf")
	}
	home, _ := os.UserHomeDir()
	wantStore := filepath.Join(home, ".beacon", "beacon.db")
	if cfg.Store.Path != wantStore {
		t.Errorf("default Store.Path = %q, want %q", cfg.Store.Path, wantStore)
	}
}

// ---------------------------------------------------------------------------
// Load — validation errors propagate
// ---------------------------------------------------------------------------

func TestLoad_ValidationError_Propagates(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.yaml")
	content := `
request_jitter_ms: -10
`
	if err := os.WriteFile(cfgFile, []byte(content), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	t.Setenv("BEACON_CONFIG", cfgFile)

	_, err := Load()
	if err == nil {
		t.Fatal("Load() should return error when validation fails")
	}
}

func TestLoad_InvalidAIProvider_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.yaml")
	content := `
ai:
  provider: unsupported-provider
  api_key: some-key
`
	if err := os.WriteFile(cfgFile, []byte(content), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	t.Setenv("BEACON_CONFIG", cfgFile)

	_, err := Load()
	if err == nil {
		t.Fatal("Load() should return error for unsupported AI provider")
	}
}

// ---------------------------------------------------------------------------
// Load — full integration with YAML + env + auth + AI
// ---------------------------------------------------------------------------

func TestLoad_FullIntegration(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.yaml")
	content := `
ai:
  provider: claude
  api_key: file-ai-key
  model: claude-sonnet-4-6
shodan_api_key: file-shodan
auth:
  - asset: "api.example.com"
    method: api_key
    token: file-api-key
    header: X-Custom-Key
smtp:
  host: smtp.example.com
  port: 587
  user: admin
  pass: password123
  from: beacon@example.com
store:
  path: /tmp/beacon-test.db
webhook_url: https://hooks.example.com/beacon
webhook_api_key: whk-secret
server:
  url: https://beacon.example.com
  api_key: srv-secret
`
	if err := os.WriteFile(cfgFile, []byte(content), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	t.Setenv("BEACON_CONFIG", cfgFile)
	// Env override for AI key.
	t.Setenv("BEACON_AI_API_KEY", "env-ai-key")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	// AI key should be overridden by env.
	if cfg.AI.APIKey != "env-ai-key" {
		t.Errorf("AI.APIKey = %q, want env override %q", cfg.AI.APIKey, "env-ai-key")
	}
	// Provider should be from file.
	if cfg.AI.Provider != "claude" {
		t.Errorf("AI.Provider = %q, want %q", cfg.AI.Provider, "claude")
	}
	// Shodan from file.
	if cfg.ShodanAPIKey != "file-shodan" {
		t.Errorf("ShodanAPIKey = %q, want %q", cfg.ShodanAPIKey, "file-shodan")
	}
	// Auth preserved from file.
	if len(cfg.Auth) != 1 {
		t.Fatalf("Auth length = %d, want 1", len(cfg.Auth))
	}
	if cfg.Auth[0].Header != "X-Custom-Key" {
		t.Errorf("Auth[0].Header = %q, want %q", cfg.Auth[0].Header, "X-Custom-Key")
	}
	// SMTP.
	if cfg.SMTP.Host != "smtp.example.com" {
		t.Errorf("SMTP.Host = %q, want %q", cfg.SMTP.Host, "smtp.example.com")
	}
	// Store.
	if cfg.Store.Path != "/tmp/beacon-test.db" {
		t.Errorf("Store.Path = %q, want %q", cfg.Store.Path, "/tmp/beacon-test.db")
	}
	// Webhook.
	if cfg.WebhookURL != "https://hooks.example.com/beacon" {
		t.Errorf("WebhookURL = %q, want %q", cfg.WebhookURL, "https://hooks.example.com/beacon")
	}
	// Server.
	if cfg.Server.URL != "https://beacon.example.com" {
		t.Errorf("Server.URL = %q, want %q", cfg.Server.URL, "https://beacon.example.com")
	}
}
