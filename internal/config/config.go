package config

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// AuthConfig holds optional credentials for authenticated scanning of a specific asset.
// When matched, beacon performs a pre-scan login and injects the resulting session
// into all HTTP requests made against that asset.
type AuthConfig struct {
	// Asset is the hostname this auth applies to. Use "*" to apply to all assets.
	Asset string `yaml:"asset"`

	// Method selects the auth mechanism:
	//   bearer   — static bearer token (Authorization: Bearer <token>)
	//   api_key  — API key header (default header: X-API-Key, override with Header field)
	//   cookie   — raw cookie string injected as Cookie header
	//   basic    — HTTP Basic Auth (Username + Password)
	//   oidc     — OAuth2 client_credentials flow (ClientID + ClientSecret + TokenURL)
	//   web3_evm — SIWE login (EVMPrivateKey hex, or ephemeral if empty)
	//   web3_sol — SIWS login (SolanaPrivateKey base58, or ephemeral if empty)
	Method string `yaml:"method"`

	// bearer / api_key
	Token  string `yaml:"token"`
	Header string `yaml:"header"` // default: "Authorization" for bearer, "X-API-Key" for api_key

	// basic
	Username string `yaml:"username"`
	Password string `yaml:"password"`

	// cookie — raw value of the Cookie header, e.g. "session=abc; csrf=xyz"
	Cookie string `yaml:"cookie"`

	// oidc / oauth2 client_credentials
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	TokenURL     string   `yaml:"token_url"`
	Scopes       []string `yaml:"scopes"`

	// web3_evm — hex-encoded secp256k1 private key (leave empty for ephemeral)
	EVMPrivateKey string `yaml:"evm_private_key"`

	// web3_sol — base58-encoded ed25519 private key (leave empty for ephemeral)
	SolanaPrivateKey string `yaml:"solana_private_key"`
}

// Config holds all Beacon configuration. Values are loaded from
// ~/.beacon/config.yaml with environment variable overrides (BEACON_ prefix).
type Config struct {
	AnthropicAPIKey string `yaml:"anthropic_api_key"`

	// ShodanAPIKey enables Shodan host lookups for each discovered IP.
	// Free tier: 1 result/IP, no scanning. Set via BEACON_SHODAN_API_KEY.
	ShodanAPIKey string `yaml:"shodan_api_key"`

	// OTXAPIKey enables AlienVault OTX passive DNS subdomain discovery.
	// Free registration at otx.alienvault.com. Set via BEACON_OTX_API_KEY.
	OTXAPIKey string `yaml:"otx_api_key"`

	// HIBPAPIKey enables Have I Been Pwned domain breach lookup.
	// Requires paid API key from haveibeenpwned.com. Set via BEACON_HIBP_API_KEY.
	HIBPAPIKey string `yaml:"hibp_api_key"`

	// BingAPIKey enables Bing Search API dorking for exposed files.
	// Free tier: 1,000 queries/month at azure.microsoft.com. Set via BEACON_BING_API_KEY.
	BingAPIKey string `yaml:"bing_api_key"`

	// VirusTotalAPIKey enables domain reputation and malware association lookups.
	// Free tier: 500 requests/day at virustotal.com. Set via BEACON_VIRUSTOTAL_API_KEY.
	VirusTotalAPIKey string `yaml:"virustotal_api_key"`

	// SecurityTrailsAPIKey enables historical DNS records and subdomain discovery.
	// Register at securitytrails.com. Set via BEACON_SECURITYTRAILS_API_KEY.
	SecurityTrailsAPIKey string `yaml:"securitytrails_api_key"`

	// CensysAPIID and CensysAPISecret enable internet-wide host data lookups.
	// Free tier: 250 queries/month at censys.io. Set via BEACON_CENSYS_API_ID and BEACON_CENSYS_API_SECRET.
	CensysAPIID     string `yaml:"censys_api_id"`
	CensysAPISecret string `yaml:"censys_api_secret"`

	// GreyNoiseAPIKey enables IP noise context (is this IP a known scanner?).
	// Free community key available at greynoise.io. Set via BEACON_GREYNOISE_API_KEY.
	GreyNoiseAPIKey string `yaml:"greynoise_api_key"`

	// AdaptiveRecon enables AI-driven target profiling after the classify phase.
	// When true and AnthropicAPIKey is set, Claude profiles each target and recommends
	// scanner modules and evasion strategies. Set via BEACON_ADAPTIVE_RECON=true.
	AdaptiveRecon bool `yaml:"adaptive_recon"`

	// ProxyPool is a comma-separated list of SOCKS5/HTTP proxy URLs for request evasion.
	// Proxies are rotated round-robin across assets. Set via BEACON_PROXY_POOL.
	// Example: "socks5://1.2.3.4:1080,http://5.6.7.8:8080"
	ProxyPool []string `yaml:"proxy_pool"`

	// RequestJitterMs is the maximum random delay in milliseconds injected between
	// scanner HTTP requests. 0 disables jitter (default). Set via BEACON_REQUEST_JITTER_MS.
	RequestJitterMs int `yaml:"request_jitter_ms"`

	// ClaudeModel overrides the Claude model used for AI analysis and scan summaries.
	// Defaults to claude-sonnet-4-6. Use claude-opus-4-6 for higher-quality suggestions
	// or claude-haiku-4-5-20251001 to reduce API cost.
	ClaudeModel string `yaml:"claude_model"`

	SMTP SMTPConfig `yaml:"smtp"`

	GitHubToken string `yaml:"github_token"`

	// External tool binary paths
	NmapBin      string `yaml:"nmap_bin"`
	NucleiBin    string `yaml:"nuclei_bin"`
	GitleaksBin  string `yaml:"gitleaks_bin"`
	TestsslBin   string `yaml:"testssl_bin"`
	AmmassBin    string `yaml:"amass_bin"`
	GauBin       string `yaml:"gau_bin"`
	KatanaBin    string `yaml:"katana_bin"`
	GowitnessBin string `yaml:"gowitness_bin"`
	// HttpxBin is the path to the httpx binary (optional, improves alive-checking speed).
	HttpxBin string `yaml:"httpx_bin"`
	// DnsxBin is the path to the dnsx binary (optional, improves DNS batch resolution speed).
	DnsxBin  string `yaml:"dnsx_bin"`
	// FfufBin is the path to the ffuf binary (optional, improves dirbust speed and evasion).
	FfufBin  string `yaml:"ffuf_bin"`

	Store StoreConfig `yaml:"store"`

	// Server connection — when set, beacon CLI acts as a remote client.
	Server ServerConfig `yaml:"server"`

	// Auth holds optional per-asset credentials for authenticated scanning.
	// BEACON_AUTH_TOKEN sets a global bearer token applied to all assets when
	// no specific AuthConfig entry is matched.
	Auth []AuthConfig `yaml:"auth"`

	// loadedFrom is the config file path that was successfully read.
	// Empty when no file was found (defaults + env vars only).
	loadedFrom string `yaml:"-"`
}

// ServerConfig holds connection details for a remote beacond instance.
type ServerConfig struct {
	URL    string `yaml:"url"`    // e.g. https://beacon.example.com
	APIKey string `yaml:"api_key"`
}

// SMTPConfig holds outbound email delivery settings.
type SMTPConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	User     string `yaml:"user"`
	Password string `yaml:"pass"`
	From     string `yaml:"from"`
}

// StoreConfig holds storage backend settings.
type StoreConfig struct {
	Path string `yaml:"path"` // SQLite file path
}

// Load reads config from the default location (~/.beacon/config.yaml)
// and applies BEACON_* environment variable overrides.
func Load() (*Config, error) {
	cfg := defaults()

	path := configPath()
	data, readErr := os.ReadFile(path)
	if readErr == nil {
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parsing config %s: %w", path, err)
		}
		cfg.loadedFrom = path
	}

	applyEnv(cfg)
	return cfg, nil
}

// LoadedFrom returns the config file path that was successfully read, or ""
// if no config file was found (defaults + env vars only).
func (c *Config) LoadedFrom() string { return c.loadedFrom }

// MustLoad calls Load and panics on error. Suitable for use in main().
func MustLoad() *Config {
	cfg, err := Load()
	if err != nil {
		panic(fmt.Sprintf("beacon: failed to load config: %v", err))
	}
	return cfg
}

func defaults() *Config {
	home, _ := os.UserHomeDir()
	return &Config{
		ClaudeModel:  "claude-sonnet-4-6",
		NmapBin:      "nmap",
		NucleiBin:    "nuclei",
		GitleaksBin:  "gitleaks",
		TestsslBin:   "testssl.sh",
		AmmassBin:    "amass",
		GauBin:       "gau",
		KatanaBin:    "katana",
		GowitnessBin: "gowitness",
		HttpxBin:     "httpx",
		DnsxBin:      "dnsx",
		FfufBin:      "ffuf",
		Store: StoreConfig{
			Path: filepath.Join(home, ".beacon", "beacon.db"),
		},
		SMTP: SMTPConfig{
			Port: 587,
		},
	}
}

func configPath() string {
	if p := os.Getenv("BEACON_CONFIG"); p != "" {
		return p
	}
	// When running under sudo, prefer the invoking user's home directory so
	// that ~/.beacon/config.yaml is found even when the effective user is root.
	// SUDO_USER is set by sudo to the original username.
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		if u, err := user.Lookup(sudoUser); err == nil {
			candidate := filepath.Join(u.HomeDir, ".beacon", "config.yaml")
			if _, err := os.Stat(candidate); err == nil {
				return candidate
			}
		}
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".beacon", "config.yaml")
}

func applyEnv(cfg *Config) {
	if v := os.Getenv("BEACON_ANTHROPIC_API_KEY"); v != "" {
		cfg.AnthropicAPIKey = v
	}
	if v := os.Getenv("BEACON_SHODAN_API_KEY"); v != "" {
		cfg.ShodanAPIKey = v
	}
	if v := os.Getenv("BEACON_OTX_API_KEY"); v != "" {
		cfg.OTXAPIKey = v
	}
	if v := os.Getenv("BEACON_HIBP_API_KEY"); v != "" {
		cfg.HIBPAPIKey = v
	}
	if v := os.Getenv("BEACON_BING_API_KEY"); v != "" {
		cfg.BingAPIKey = v
	}
	if v := os.Getenv("BEACON_VIRUSTOTAL_API_KEY"); v != "" {
		cfg.VirusTotalAPIKey = v
	}
	if v := os.Getenv("BEACON_SECURITYTRAILS_API_KEY"); v != "" {
		cfg.SecurityTrailsAPIKey = v
	}
	if v := os.Getenv("BEACON_CENSYS_API_ID"); v != "" {
		cfg.CensysAPIID = v
	}
	if v := os.Getenv("BEACON_CENSYS_API_SECRET"); v != "" {
		cfg.CensysAPISecret = v
	}
	if v := os.Getenv("BEACON_GREYNOISE_API_KEY"); v != "" {
		cfg.GreyNoiseAPIKey = v
	}
	if v := os.Getenv("BEACON_CLAUDE_MODEL"); v != "" {
		cfg.ClaudeModel = v
	}
	if v := os.Getenv("BEACON_GITHUB_TOKEN"); v != "" {
		cfg.GitHubToken = v
	}
	if v := os.Getenv("BEACON_NMAP_BIN"); v != "" {
		cfg.NmapBin = v
	}
	if v := os.Getenv("BEACON_NUCLEI_BIN"); v != "" {
		cfg.NucleiBin = v
	}
	if v := os.Getenv("BEACON_GITLEAKS_BIN"); v != "" {
		cfg.GitleaksBin = v
	}
	if v := os.Getenv("BEACON_TESTSSL_BIN"); v != "" {
		cfg.TestsslBin = v
	}
	if v := os.Getenv("BEACON_AMASS_BIN"); v != "" {
		cfg.AmmassBin = v
	}
	if v := os.Getenv("BEACON_GAU_BIN"); v != "" {
		cfg.GauBin = v
	}
	if v := os.Getenv("BEACON_KATANA_BIN"); v != "" {
		cfg.KatanaBin = v
	}
	if v := os.Getenv("BEACON_GOWITNESS_BIN"); v != "" {
		cfg.GowitnessBin = v
	}
	if v := os.Getenv("BEACON_HTTPX_BIN"); v != "" {
		cfg.HttpxBin = v
	}
	if v := os.Getenv("BEACON_DNSX_BIN"); v != "" {
		cfg.DnsxBin = v
	}
	if v := os.Getenv("BEACON_FFUF_BIN"); v != "" {
		cfg.FfufBin = v
	}
	if v := os.Getenv("BEACON_SERVER_URL"); v != "" {
		cfg.Server.URL = v
	}
	if v := os.Getenv("BEACON_SERVER_API_KEY"); v != "" {
		cfg.Server.APIKey = v
	}
	if v := os.Getenv("BEACON_ADAPTIVE_RECON"); v != "" {
		cfg.AdaptiveRecon = v == "true" || v == "1" || v == "yes"
	}
	if v := os.Getenv("BEACON_PROXY_POOL"); v != "" {
		var proxies []string
		for _, p := range strings.Split(v, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				proxies = append(proxies, p)
			}
		}
		cfg.ProxyPool = proxies
	}
	if v := os.Getenv("BEACON_REQUEST_JITTER_MS"); v != "" {
		if ms, err := strconv.Atoi(v); err == nil && ms >= 0 {
			cfg.RequestJitterMs = ms
		}
	}
	if v := os.Getenv("BEACON_STORE_PATH"); v != "" {
		cfg.Store.Path = v
	}
	if v := os.Getenv("BEACON_SMTP_HOST"); v != "" {
		cfg.SMTP.Host = v
	}
	if v := os.Getenv("BEACON_SMTP_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			cfg.SMTP.Port = p
		}
	}
	if v := os.Getenv("BEACON_SMTP_USER"); v != "" {
		cfg.SMTP.User = v
	}
	if v := os.Getenv("BEACON_SMTP_PASS"); v != "" {
		cfg.SMTP.Password = v
	}
	if v := os.Getenv("BEACON_SMTP_FROM"); v != "" {
		cfg.SMTP.From = v
	}
	// BEACON_AUTH_TOKEN injects a global bearer token for all assets when no
	// specific auth config entry exists. It is prepended so per-asset entries
	// in the YAML file take precedence (first matching entry wins).
	if v := os.Getenv("BEACON_AUTH_TOKEN"); v != "" {
		cfg.Auth = append([]AuthConfig{{Asset: "*", Method: "bearer", Token: v}}, cfg.Auth...)
	}
}
