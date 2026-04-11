// Package surface implements the Surface scan module.
// All scanning is now driven by playbooks loaded from internal/playbook/playbooks/*.yaml.
// The baseline playbook runs on every asset. Targeted playbooks are selected by
// classifying each asset's evidence and matching against the playbook registry.
//
// Pipeline:
//  1. Discover assets (subdomains via crt.sh + subfinder + amass + passive DNS)
//  2. Classify each asset → collect Evidence → match playbooks → build RunPlan
//  3. Execute RunPlan per asset concurrently
//  4. Write AssetExecution audit record per asset (for AI batch analysis)
package surface

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/stormbane-security/beacon/internal/aifp"
	"github.com/stormbane-security/beacon/internal/analyze"
	"github.com/stormbane-security/beacon/internal/auth"
	"github.com/stormbane-security/beacon/internal/config"
	"github.com/stormbane-security/beacon/internal/enrichment"
	"github.com/stormbane-security/beacon/internal/exploitcache"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/playbook"
	"github.com/stormbane-security/beacon/internal/scanner/classify"
	"github.com/stormbane-security/beacon/internal/scanner/paramdiscovery"
	"github.com/stormbane-security/beacon/internal/scan"
	"github.com/stormbane-security/beacon/internal/vulndb"
	sc "github.com/stormbane-security/beacon/internal/scanner"
	"github.com/stormbane-security/beacon/internal/scanner/assetintel"
	"github.com/stormbane-security/beacon/internal/scanner/bgp"
	_ "github.com/stormbane-security/beacon/internal/scanner/cdnbypass"
	_ "github.com/stormbane-security/beacon/internal/scanner/cmsplugins"
	_ "github.com/stormbane-security/beacon/internal/scanner/crlf"
	_ "github.com/stormbane-security/beacon/internal/scanner/iam"
	_ "github.com/stormbane-security/beacon/internal/scanner/log4shell"
	_ "github.com/stormbane-security/beacon/internal/scanner/saml"
	_ "github.com/stormbane-security/beacon/internal/scanner/protopollution"
	_ "github.com/stormbane-security/beacon/internal/scanner/ssti"
	_ "github.com/stormbane-security/beacon/internal/scanner/web3auth"
	_ "github.com/stormbane-security/beacon/internal/scanner/web3detect"
	_ "github.com/stormbane-security/beacon/internal/scanner/depconf"
	_ "github.com/stormbane-security/beacon/internal/scanner/ssrf"
	_ "github.com/stormbane-security/beacon/internal/scanner/nginx"
	_ "github.com/stormbane-security/beacon/internal/scanner/hpp"
	_ "github.com/stormbane-security/beacon/internal/scanner/harvester"
	_ "github.com/stormbane-security/beacon/internal/scanner/honeypot"
	_ "github.com/stormbane-security/beacon/internal/scanner/aidetect"
	"github.com/stormbane-security/beacon/internal/scanner/aillm"
	_ "github.com/stormbane-security/beacon/internal/scanner/apiversions"
	"github.com/stormbane-security/beacon/internal/scanner/autoprobe"
	_ "github.com/stormbane-security/beacon/internal/scanner/clickjacking"
	"github.com/stormbane-security/beacon/internal/scanner/dns"
	_ "github.com/stormbane-security/beacon/internal/scanner/exposedfiles"
	_ "github.com/stormbane-security/beacon/internal/scanner/httpmethods"
	_ "github.com/stormbane-security/beacon/internal/scanner/smuggling"
	_ "github.com/stormbane-security/beacon/internal/scanner/websocket"
	_ "github.com/stormbane-security/beacon/internal/scanner/apifuzz"
	_ "github.com/stormbane-security/beacon/internal/scanner/authsurface"
	_ "github.com/stormbane-security/beacon/internal/scanner/takeover"
	_ "github.com/stormbane-security/beacon/internal/scanner/wafbypass"
	_ "github.com/stormbane-security/beacon/internal/scanner/wafdetect"
	_ "github.com/stormbane-security/beacon/internal/scanner/oauth"
	_ "github.com/stormbane-security/beacon/internal/scanner/ratelimit"
	_ "github.com/stormbane-security/beacon/internal/scanner/cloudbuckets"
	_ "github.com/stormbane-security/beacon/internal/scanner/cors"
	_ "github.com/stormbane-security/beacon/internal/scanner/crawler"
	"github.com/stormbane-security/beacon/internal/scanner/dirbust"
	"github.com/stormbane-security/beacon/internal/scanner/dlp"
	_ "github.com/stormbane-security/beacon/internal/scanner/domxss"
	_ "github.com/stormbane-security/beacon/internal/scanner/dorks"
	_ "github.com/stormbane-security/beacon/internal/scanner/email"
	_ "github.com/stormbane-security/beacon/internal/scanner/graphql"
	_ "github.com/stormbane-security/beacon/internal/scanner/jenkins"
	_ "github.com/stormbane-security/beacon/internal/scanner/hibp"
	_ "github.com/stormbane-security/beacon/internal/scanner/historicalurls"
	_ "github.com/stormbane-security/beacon/internal/scanner/dnsrebind"
	_ "github.com/stormbane-security/beacon/internal/scanner/hostheader"
	_ "github.com/stormbane-security/beacon/internal/scanner/rxss"
	_ "github.com/stormbane-security/beacon/internal/scanner/secondorder"
	_ "github.com/stormbane-security/beacon/internal/scanner/jwt"
	"github.com/stormbane-security/beacon/internal/scanner/nuclei"
	"github.com/stormbane-security/beacon/internal/scanner/passivedns"
	"github.com/stormbane-security/beacon/internal/scanner/portscan"
	_ "github.com/stormbane-security/beacon/internal/scanner/screenshot"
	"github.com/stormbane-security/beacon/internal/scanner/subdomain"
	_ "github.com/stormbane-security/beacon/internal/scanner/testssl"
	_ "github.com/stormbane-security/beacon/internal/scanner/tls"
	_ "github.com/stormbane-security/beacon/internal/scanner/typosquat"
	_ "github.com/stormbane-security/beacon/internal/scanner/vhost"
	_ "github.com/stormbane-security/beacon/internal/scanner/webcontent"
	"github.com/stormbane-security/beacon/internal/scanner/whois"
	_ "github.com/stormbane-security/beacon/internal/scanner/authfuzz"
	_ "github.com/stormbane-security/beacon/internal/scanner/xxe"
	_ "github.com/stormbane-security/beacon/internal/scanner/deserial"
	_ "github.com/stormbane-security/beacon/internal/scanner/fileupload"
	_ "github.com/stormbane-security/beacon/internal/scanner/gateway"
	_ "github.com/stormbane-security/beacon/internal/scanner/swagger"
	_ "github.com/stormbane-security/beacon/internal/scanner/contractscan"
	_ "github.com/stormbane-security/beacon/internal/scanner/chainnode"
	_ "github.com/stormbane-security/beacon/internal/scanner/aimodelsec"
	_ "github.com/stormbane-security/beacon/internal/scanner/web3defi"
	_ "github.com/stormbane-security/beacon/internal/scanner/ghactions"
	_ "github.com/stormbane-security/beacon/internal/scanner/nextjs"
	_ "github.com/stormbane-security/beacon/internal/scanner/wifi"
	_ "github.com/stormbane-security/beacon/internal/scanner/idor"
	_ "github.com/stormbane-security/beacon/internal/scanner/correlation"
	_ "github.com/stormbane-security/beacon/internal/scanner/accesscontrol"
	_ "github.com/stormbane-security/beacon/internal/scanner/privesc"
	_ "github.com/stormbane-security/beacon/internal/scanner/statemachine"
	_ "github.com/stormbane-security/beacon/internal/scanner/elinjection"
	_ "github.com/stormbane-security/beacon/internal/scanner/containerimage"
	_ "github.com/stormbane-security/beacon/internal/scanner/redos"
	_ "github.com/stormbane-security/beacon/internal/scanner/artifactsign"
	_ "github.com/stormbane-security/beacon/internal/scanner/bitbucket"
	_ "github.com/stormbane-security/beacon/internal/scanner/circleci"
	_ "github.com/stormbane-security/beacon/internal/scanner/okta"
	"github.com/stormbane-security/beacon/internal/scanner/authctx"
	"github.com/stormbane-security/beacon/internal/scanner/schemedetect"
	_ "github.com/stormbane-security/beacon/internal/scanner/cmdinj"
	_ "github.com/stormbane-security/beacon/internal/scanner/verbtamper"
	_ "github.com/stormbane-security/beacon/internal/scanner/pathtraversal"
	_ "github.com/stormbane-security/beacon/internal/scanner/racecondition"
	_ "github.com/stormbane-security/beacon/internal/scanner/grpcreflect"
	_ "github.com/stormbane-security/beacon/internal/scanner/jsendpoints"
	_ "github.com/stormbane-security/beacon/internal/scanner/pdfssrf"
	_ "github.com/stormbane-security/beacon/internal/scanner/iisversion"
	_ "github.com/stormbane-security/beacon/internal/scanner/csrf"
	_ "github.com/stormbane-security/beacon/internal/scanner/openredir"
	_ "github.com/stormbane-security/beacon/internal/scanner/sqli"
	_ "github.com/stormbane-security/beacon/internal/scanner/nosqli"
	_ "github.com/stormbane-security/beacon/internal/scanner/errordisclosure"
	_ "github.com/stormbane-security/beacon/internal/scanner/hopbyhop"
	_ "github.com/stormbane-security/beacon/internal/scanner/bigip"
	_ "github.com/stormbane-security/beacon/internal/scanner/aiinfra"
	_ "github.com/stormbane-security/beacon/internal/scanner/mcpscan"
	_ "github.com/stormbane-security/beacon/internal/scanner/h2c"
	_ "github.com/stormbane-security/beacon/internal/scanner/secheaders"
	_ "github.com/stormbane-security/beacon/internal/scanner/proxychain"
	_ "github.com/stormbane-security/beacon/internal/scanner/cacheprobe"
	_ "github.com/stormbane-security/beacon/internal/scanner/cookie"
	_ "github.com/stormbane-security/beacon/internal/scanner/wellknown"
	_ "github.com/stormbane-security/beacon/internal/scanner/robotsmap"
	_ "github.com/stormbane-security/beacon/internal/scanner/http2"
	_ "github.com/stormbane-security/beacon/internal/scanner/ldapi"
	_ "github.com/stormbane-security/beacon/internal/scanner/cspaudit"
	_ "github.com/stormbane-security/beacon/internal/scanner/ntlm"
	_ "github.com/stormbane-security/beacon/internal/scanner/favicon"
	_ "github.com/stormbane-security/beacon/internal/scanner/ctlog"
	_ "github.com/stormbane-security/beacon/internal/scanner/asnmap"
	_ "github.com/stormbane-security/beacon/internal/scanner/ipv6"
	_ "github.com/stormbane-security/beacon/internal/scanner/apischema"
	_ "github.com/stormbane-security/beacon/internal/scanner/jsframework"
	_ "github.com/stormbane-security/beacon/internal/scanner/wsfuzz"
	"github.com/stormbane-security/beacon/internal/chainengine"
	"github.com/stormbane-security/beacon/internal/evasion"
	"github.com/stormbane-security/beacon/internal/fingerprintdb"
	"github.com/stormbane-security/beacon/internal/profiler"
	"github.com/stormbane-security/beacon/internal/store"
)

// Module is the Surface scan module.
type Module struct {
	vulndbURL string // URL of beacon-vulndb service (auto-upload findings)
	// Asset discovery
	subdomainScanner  *subdomain.PassiveScanner
	passiveDNSScanner *passivedns.Scanner

	// Root-domain-only scanners (run once, not per-subdomain)
	whoisScanner   *whois.Scanner
	bgpScanner     *bgp.Scanner

	// Named scanner registry — maps YAML scanner names to implementations
	scanners map[string]sc.Scanner

	// Nuclei scanner (handles both surface and deep tag lists)
	nucleiScanner *nuclei.Scanner

	// Playbook registry — lazy-loaded on first use so --scanners mode
	// (which never matches playbooks) skips the parsing cost entirely.
	registry     *playbook.Registry
	registryOnce sync.Once
	registryErr  error
	userPlaybookDir string // path to ~/.config/beacon/playbooks

	// Store for writing audit records (optional — nil = skip)
	st store.Store

	// Anthropic API key for DLP Vision analysis (optional — skipped if empty)
	anthropicKey string

	// discoveryAdvisor expands the asset list during deep scans using AI-guided
	// hostname suggestions. nil when no API key is configured.
	discoveryAdvisor  *analyze.DiscoveryAdvisor
	// portAdvisor suggests additional ports to probe after initial scan findings.
	portAdvisor       *analyze.PortAdvisor
	// playbookAdvisor suggests additional scanners to run beyond playbook matches.
	// nil when no API key is configured.
	playbookAdvisor   *analyze.PlaybookAdvisor
	maxDiscoveryDepth int
	maxAssets         int
	maxPlaybookDepth  int

	// Optional tool bins for faster scanning.
	httpxBin string
	dnsxBin  string
	ffufBin  string

	// harvesterEmails caches employee email addresses discovered by theHarvester
	// on the root domain. Protected by harvesterMu. Passed to autoprobe on every
	// asset so username enumeration tests use real discovered accounts.
	harvesterEmails   []string
	harvesterEmailsMu sync.Mutex

	// evasionStrategy applies proxy rotation and request jitter when configured.
	// nil when neither ProxyPool nor RequestJitterMs is set.
	evasionStrategy *evasion.Strategy

	// adaptiveRecon enables AI-powered target profiling after Phase A.
	// Profile findings are emitted and Claude's module suggestions merged into
	// the run plan for each asset.
	adaptiveRecon bool

	// claudeModel is the model used for profiling (defaults to claude-sonnet-4-6).
	claudeModel string

	// scannerFilter, when non-empty, restricts execution to only the named
	// scanners. Set from module.Input.Scanners at the start of Run. When
	// active, asset discovery, evidence classification, and playbook matching
	// are all skipped.
	scannerFilter []string

	// dryRun, when true, runs evidence collection and playbook matching but
	// stops before executing scanners. The planned scanner list is returned
	// as a single finding with the plan details in Evidence.
	dryRun bool

	// wordlistPath is a custom wordlist file path for brute-force scanners.
	wordlistPath string

	// screenshotsEnabled controls whether the screenshot scanner runs.
	screenshotsEnabled bool

	// authCfgs holds per-asset credentials for authenticated scanning.
	authCfgs []config.AuthConfig

	// fingerprintRules holds active DB-driven fingerprint rules loaded once at
	// scan start and applied per-asset after fingerprintTech().
	fingerprintRules []store.FingerprintRule

	// enricher is the AI client used for fingerprint gap-filling, scanner
	// suggestion, and cross-asset analysis. nil when no API key is configured.
	enricher *enrichment.ClaudeEnricher
}

// Config holds binary paths required to instantiate the module.
type Config struct {
	NucleiBin         string
	SubfinderBin      string
	TestsslBin        string
	GauBin            string
	KatanaBin         string
	GowitnessBin      string
	NucleiSurfaceList string
	NucleiDeepList    string
	// AnthropicAPIKey enables Claude Vision DLP analysis on screenshots (optional).
	AnthropicAPIKey string
	// ShodanAPIKey enables Shodan host lookups per discovered IP (optional).
	ShodanAPIKey string
	// HIBPAPIKey enables Have I Been Pwned domain breach lookup (optional).
	HIBPAPIKey string
	// BingAPIKey enables Bing Search API dork queries (optional).
	BingAPIKey string
	// OTXAPIKey enables AlienVault OTX subdomain discovery (optional).
	OTXAPIKey string
	// VirusTotalAPIKey enables domain reputation lookups (optional).
	VirusTotalAPIKey string
	// SecurityTrailsAPIKey enables historical DNS + subdomain discovery (optional).
	SecurityTrailsAPIKey string
	// CensysAPIID and CensysAPISecret enable Censys host lookups (optional).
	CensysAPIID     string
	CensysAPISecret string
	// GreyNoiseAPIKey enables IP noise context lookups (optional).
	GreyNoiseAPIKey string
	// NmapBin is the path to the nmap binary (optional).
	NmapBin string
	// HarvesterBin is the path to theHarvester binary. Optional.
	// When set, the harvester scanner runs on root domains to enumerate employee emails.
	HarvesterBin string
	// Store is optional. When set, AssetExecution records are written per scan.
	Store store.Store
	// MaxDiscoveryDepth controls how many AI-guided expansion rounds run after
	// the initial scan. 0 = disabled. Use DiscoveryDepth* constants.
	// Values above DiscoveryDepthHardCap are clamped automatically.
	MaxDiscoveryDepth int
	// MaxAssets is the total asset ceiling across all expansion rounds.
	// 0 means use MaxAssetsDefault. Values above MaxAssetsHardCap are clamped.
	MaxAssets int
	// MaxPlaybookDepth controls how many levels deep playbook-driven discovery
	// can recurse within a single asset scan. 0 = use PlaybookDepthDefault (1).
	// Values above PlaybookDepthHardCap are clamped automatically.
	MaxPlaybookDepth int
	// HttpxBin is the path to the httpx binary (optional, improves alive-checking speed).
	HttpxBin string
	// DnsxBin is the path to the dnsx binary (optional, improves DNS batch resolution speed).
	DnsxBin string
	// FfufBin is the path to the ffuf binary (optional, improves dirbust speed and evasion).
	FfufBin string

	// AdaptiveRecon enables AI-powered target profiling after the classify+Phase A
	// fingerprint step. When true and AnthropicAPIKey is set, Claude analyses the
	// collected evidence and recommends additional scanner modules and evasion strategy.
	// Set via BEACON_ADAPTIVE_RECON=true.
	AdaptiveRecon bool

	// ProxyPool is a list of SOCKS5/HTTP proxy URLs for request evasion.
	// Proxies are rotated round-robin across scanner invocations.
	// Set via BEACON_PROXY_POOL (comma-separated).
	ProxyPool []string

	// RequestJitterMs is the max random delay in ms injected between scanner
	// invocations. 0 disables jitter. Set via BEACON_REQUEST_JITTER_MS.
	RequestJitterMs int

	// ClaudeModel overrides the Claude model used for profiling.
	// Defaults to claude-sonnet-4-6 when empty.
	ClaudeModel string

	// WordlistPath is a custom wordlist file for brute-force scanners
	// (dirbust, subdomain brute, parameter discovery). When set, scanners
	// use this file instead of or in addition to their built-in wordlists.
	WordlistPath string

	// Auth holds per-asset credentials for authenticated scanning.
	// When a matching entry exists for the current asset (or asset == "*"),
	// scanners run against content that is gated behind a login.
	Auth []config.AuthConfig

	// GitHubToken is an optional GitHub personal access token used by the
	// ghactions scanner to fetch workflow files via the GitHub API.
	// Without it the scanner is limited to 60 unauthenticated requests/hour.
	GitHubToken string

	// OktaDomain is the Okta org domain (e.g., "yourorg.okta.com").
	OktaDomain string
	// OktaToken is the Okta API token for IAM configuration scanning.
	OktaToken string

	// ScreenshotsEnabled enables the screenshot scanner. When false (default),
	// the screenshot scanner is skipped entirely, saving ~2.7s per asset.
	// Set from --screenshots flag.
	ScreenshotsEnabled bool
}

const (
	defaultNucleiSurfaceList = "internal/scanner/nuclei/templates/surface.txt"
	defaultNucleiDeepList    = "internal/scanner/nuclei/templates/deep.txt"
)

// Discovery depth limits — how many AI-guided expansion rounds to run after
// the initial scan batch. Each round costs one Claude Haiku API call.
// These map to billing tiers; the hard cap is enforced regardless of config.
const (
	DiscoveryDepthDisabled   = 0 // no AI expansion (free tier)
	DiscoveryDepthStandard   = 1 // one expansion round (standard)
	DiscoveryDepthPro        = 3 // three rounds (pro)
	DiscoveryDepthHardCap    = 5 // absolute ceiling — never exceeded

	// MaxAssetsDefault is the total asset cap for standard tier.
	// Prevents runaway scans on unexpectedly large or hostile networks.
	MaxAssetsDefault = 200
	MaxAssetsPro     = 500
	MaxAssetsHardCap = 1000

	// PlaybookDepthDefault controls how many levels deep playbook-driven discovery
	// can recurse. At depth 1 (default): discovered assets are scanned but their
	// discoveries do not trigger further expansion — prevents infinite recursion
	// via looping CNAME chains. At depth 2: two levels of playbook expansion run.
	// Hard cap: 3. CDN playbooks (Cloudflare, Fastly) use depth 1 by default.
	PlaybookDepthDefault = 1
	PlaybookDepthHardCap = 3
)

// moduleScannerConfig adapts the module's Config into a scan.ScannerConfig
// for the global scanner registry. Keys map to scanner factory expectations.
func moduleScannerConfig(cfg Config) scan.MapConfig {
	return scan.MapConfig{
		"shodan.api_key":         cfg.ShodanAPIKey,
		"virustotal.api_key":     cfg.VirusTotalAPIKey,
		"securitytrails.api_key": cfg.SecurityTrailsAPIKey,
		"censys.api_id":          cfg.CensysAPIID,
		"censys.api_secret":      cfg.CensysAPISecret,
		"greynoise.api_key":      cfg.GreyNoiseAPIKey,
		"hibp.api_key":           cfg.HIBPAPIKey,
		"bing.api_key":           cfg.BingAPIKey,
		"github.token":           cfg.GitHubToken,
		"okta.domain":            cfg.OktaDomain,
		"okta.token":             cfg.OktaToken,
		"nmap.bin":               cfg.NmapBin,
		"gau.bin":                cfg.GauBin,
		"katana.bin":             cfg.KatanaBin,
		"gowitness.bin":          cfg.GowitnessBin,
		"testssl.bin":            cfg.TestsslBin,
		"harvester.bin":          cfg.HarvesterBin,
	}
}

// New creates a new Surface module.
// Returns an error if the embedded playbook registry fails to load.
func New(cfg Config) (*Module, error) {
	surfaceList := cfg.NucleiSurfaceList
	if surfaceList == "" {
		surfaceList = defaultNucleiSurfaceList
	}
	deepList := cfg.NucleiDeepList
	if deepList == "" {
		deepList = defaultNucleiDeepList
	}

	// Playbook registry is lazy-loaded on first use (via getRegistry()).
	// This avoids parsing YAML playbooks when --scanners mode is active,
	// since that path never matches playbooks.
	homeDir, _ := os.UserHomeDir()
	userPlaybookDir := filepath.Join(homeDir, ".config", "beacon", "playbooks")

	nucl := nuclei.New(cfg.NucleiBin, surfaceList, deepList)

	// Merge scanner-declared check IDs into the finding Registry.
	// Scanners that use RegisterWithCheckDecls() self-declare their checks;
	// this fills gaps in the hand-maintained Registry for gradual migration.
	scan.MergeChecksIntoRegistry()

	// Build scanner map from the global registry. All scanners register
	// themselves via init() in their packages — no manual wiring needed.
	scannerCfg := moduleScannerConfig(cfg)
	scannerMap := scan.Build(scannerCfg)

	// Special cases: nuclei shares a single instance and is not in the
	// scan.Build registry because it requires per-module configuration.
	// Register under both "nuclei" (for --scanners nuclei) and "tls"
	// (legacy alias for TLS-specific template runs).
	scannerMap["nuclei"] = nucl
	scannerMap["tls"] = nucl

	// Clamp depth and asset limits to their hard ceilings.
	maxDepth := cfg.MaxDiscoveryDepth
	if maxDepth > DiscoveryDepthHardCap {
		maxDepth = DiscoveryDepthHardCap
	}
	maxAssets := cfg.MaxAssets
	if maxAssets <= 0 {
		maxAssets = MaxAssetsDefault
	}
	if maxAssets > MaxAssetsHardCap {
		maxAssets = MaxAssetsHardCap
	}
	maxPlaybookDepth := cfg.MaxPlaybookDepth
	if maxPlaybookDepth <= 0 {
		maxPlaybookDepth = PlaybookDepthDefault
	}
	if maxPlaybookDepth > PlaybookDepthHardCap {
		maxPlaybookDepth = PlaybookDepthHardCap
	}

	// Build evasion strategy when proxy pool or jitter is configured.
	var evasionStrat *evasion.Strategy
	if len(cfg.ProxyPool) > 0 || cfg.RequestJitterMs > 0 {
		evasionStrat = &evasion.Strategy{
			ProxyPool:   cfg.ProxyPool,
			MaxJitterMs: cfg.RequestJitterMs,
		}
	}

	claudeModel := cfg.ClaudeModel
	if claudeModel == "" {
		claudeModel = "claude-sonnet-4-6"
	}

	var enricher *enrichment.ClaudeEnricher
	if cfg.AnthropicAPIKey != "" {
		if e, err := enrichment.NewWithProvider("claude", cfg.AnthropicAPIKey, claudeModel, ""); err == nil {
			enricher = e
		}
	}

	return &Module{
		subdomainScanner:  subdomain.NewPassiveWithKeys(cfg.SubfinderBin, cfg.OTXAPIKey),
		passiveDNSScanner: passivedns.New(),
		whoisScanner:      whois.New(),
		bgpScanner:        bgp.New(),
		scanners:          scannerMap,
		nucleiScanner:     nucl,
		userPlaybookDir:   userPlaybookDir,
		st:                cfg.Store,
		anthropicKey:      cfg.AnthropicAPIKey,
		discoveryAdvisor:  analyze.NewDiscoveryAdvisor(cfg.AnthropicAPIKey),
		portAdvisor:       analyze.NewPortAdvisor(cfg.AnthropicAPIKey),
		playbookAdvisor:   analyze.NewPlaybookAdvisor(cfg.AnthropicAPIKey),
		maxDiscoveryDepth: maxDepth,
		maxAssets:         maxAssets,
		maxPlaybookDepth:  maxPlaybookDepth,
		httpxBin:          cfg.HttpxBin,
		dnsxBin:           cfg.DnsxBin,
		ffufBin:           cfg.FfufBin,
		evasionStrategy:   evasionStrat,
		adaptiveRecon:     cfg.AdaptiveRecon,
		claudeModel:       claudeModel,
		wordlistPath:       cfg.WordlistPath,
		authCfgs:           cfg.Auth,
		enricher:           enricher,
		screenshotsEnabled: cfg.ScreenshotsEnabled,
	}, nil
}

func (m *Module) Name() string                       { return "surface" }
func (m *Module) RequiredInputs() []module.InputType { return []module.InputType{module.InputDomain} }

// getRegistry returns the playbook registry, loading it on first call.
// This defers the cost of parsing embedded + user YAML playbooks until
// they are actually needed, which means --scanners mode never pays it.
func (m *Module) getRegistry() (*playbook.Registry, error) {
	m.registryOnce.Do(func() {
		reg, err := playbook.Load()
		if err != nil {
			m.registryErr = fmt.Errorf("surface: load playbooks: %w", err)
			return
		}
		if m.userPlaybookDir != "" {
			if err := reg.LoadUserDir(m.userPlaybookDir); err != nil {
				m.registryErr = fmt.Errorf("surface: load user playbooks: %w", err)
				return
			}
		}
		m.registry = reg
	})
	return m.registry, m.registryErr
}

// isDeepOrAuthorized returns true for ScanDeep and ScanAuthorized.
// Use this to gate checks that need active probing but are not exploitation-class.
func isDeepOrAuthorized(t module.ScanType) bool {
	return t == module.ScanDeep || t == module.ScanAuthorized
}

// Run executes the full surface scan pipeline driven by playbooks.
func (m *Module) Run(ctx context.Context, input module.Input, scanType module.ScanType) ([]finding.Finding, error) {
	rootDomain := input.Domain

	// Store scanner filter and dry-run flag for use in runAsset.
	m.scannerFilter = input.Scanners
	m.dryRun = input.DryRun

	// Pass port restriction to the portscan scanner if set.
	if len(input.Ports) > 0 {
		if ps, ok := m.scanners["portscan"].(*portscan.Scanner); ok {
			ps.Ports = input.Ports
		}
	}

	// ── Scanner filter validation ───────────────────────────────────────────
	// When --scanners is set, validate that all requested scanners exist.
	// Discovery still runs normally — the filter only restricts which
	// scanners execute against each discovered asset (applied in runAsset).
	if len(m.scannerFilter) > 0 {
		for _, name := range m.scannerFilter {
			if _, ok := m.scanners[name]; !ok {
				return nil, fmt.Errorf("unknown scanner %q (available: use --help to list)", name)
			}
		}
	}

	// Load active fingerprint rules once per scan run and cache on the module.
	if m.st != nil {
		rules, _ := m.st.GetFingerprintRules(ctx, "active")
		m.fingerprintRules = rules
	}

	var allFindings []finding.Finding
	var mu sync.Mutex

	// unconfirmedAssets collects IPs and hostnames whose ownership by rootDomain
	// could not be automatically confirmed.  Surface scans still run against
	// them (passive observation is always safe); deep scans require the operator
	// to type an explicit confirmation in the TUI before they are allowed.
	var unconfirmedAssets []module.DiscoveredAsset
	var unconfirmedMu sync.Mutex
	addUnconfirmed := func(a module.DiscoveredAsset) {
		unconfirmedMu.Lock()
		unconfirmedAssets = append(unconfirmedAssets, a)
		unconfirmedMu.Unlock()
	}

	appendFindings := func(fs []finding.Finding) {
		if len(fs) == 0 {
			return
		}
		mu.Lock()
		allFindings = append(allFindings, fs...)
		mu.Unlock()
	}

	// ── Phase 1: Asset Discovery ─────────────────────────────────────────────
	var wgDiscover sync.WaitGroup

	// Amass active mode performs DNS zone-walking and brute-force queries —
	// gate it on PermissionConfirmed, not just ScanDeep, since aggressive
	// enumeration against a target requires explicit authorization.
	subdomainScanType := scanType
	if !input.PermissionConfirmed {
		subdomainScanType = module.ScanSurface
	}

	progress := func(msg string) {
		if input.Progress != nil {
			input.Progress(module.ProgressEvent{Phase: "discovering", StatusMsg: msg})
		}
	}
	discScanStart := func(scanner, cmd string) {
		if input.Progress != nil {
			input.Progress(module.ProgressEvent{
				Phase:       "scanner_start",
				ActiveAsset: rootDomain,
				ScannerName: scanner,
				ScannerCmd:  cmd,
			})
		}
	}
	discScanDone := func(scanner string, findings []finding.Finding) {
		if input.Progress != nil {
			input.Progress(module.ProgressEvent{
				Phase:        "scanner_done",
				ActiveAsset:  rootDomain,
				ScannerName:  scanner,
				FindingDelta: len(findings),
				NewFindings:  findings,
			})
		}
	}

	progress("enumerating subdomains...")

	// ── Improvement 3: Discovery cache ──────────────────────────────────────
	// Check the subdomain discovery cache before launching scanners. On a cache
	// hit (within 24h TTL), use cached results immediately and launch discovery
	// in the background to detect drift (new/removed subdomains).
	discoveryCache := scan.NewDiscoveryCache()
	var cachedAssets []string
	cacheHit := false
	if discoveryCache != nil {
		if cached, ok := discoveryCache.Get(rootDomain); ok {
			cachedAssets = cached
			cacheHit = true
			progress(fmt.Sprintf("cache hit: %d subdomains from previous scan — launching background refresh...", len(cached)))
		}
	}

	// ── Improvement 5: Wildcard DNS detection (pipeline-level) ──────────────
	// Detect wildcard DNS early. If detected, brute-force inside the subdomain
	// scanner is already skipped (it has its own detection), but we log the
	// warning here for pipeline-level visibility.
	wildcardDetected, wildcardIP := scan.DetectWildcard(ctx, rootDomain)
	if wildcardDetected {
		progress(fmt.Sprintf("wildcard DNS detected for *.%s (resolves to %s) — brute-force results will be filtered", rootDomain, wildcardIP))
	}

	type discoveryBatch struct {
		findings []finding.Finding
		source   string
	}
	// ── Improvement 4: Smart source prioritization ──────────────────────────
	// Launch discovery sources in priority order: cache (instant), passivedns
	// (fast), subdomain scanner (slower — queries crt.sh, subfinder, OTX,
	// urlscan, brute-force). Process results from each as they arrive so fast
	// sources feed the scan pipeline while slow sources are still running.
	batchResults := make(chan discoveryBatch, 4)

	// Source priority 2: Passive DNS (fast, single HTTP call)
	wgDiscover.Add(1)
	go func() {
		defer wgDiscover.Done()
		discScanStart("passivedns", fmt.Sprintf("hackertarget.com/hostsearch?q=%s", rootDomain))
		fs, _ := m.passiveDNSScanner.Run(ctx, rootDomain, scanType)
		discScanDone("passivedns", fs)
		batchResults <- discoveryBatch{findings: fs, source: "passivedns"}
	}()

	// Source priority 3: Subdomain scanner (crt.sh + subfinder + OTX + brute)
	// TODO: Add recursive subdomain discovery — after initial enumeration,
	// re-run discovery on each discovered subdomain to find sub-subdomains
	// (e.g. dev.api.example.com). Gate on ScanDeep to avoid noise in surface mode.
	wgDiscover.Add(1)
	go func() {
		defer wgDiscover.Done()
		subfinderFlags := "-silent -passive"
		if isDeepOrAuthorized(subdomainScanType) {
			subfinderFlags = "-silent" // active: DNS resolution + all sources
		}
		discScanStart("subdomain", fmt.Sprintf("crt.sh *.%s  +  subfinder -d %s %s", rootDomain, rootDomain, subfinderFlags))
		fs, _ := m.subdomainScanner.Run(ctx, rootDomain, subdomainScanType)
		discScanDone("subdomain", fs)
		batchResults <- discoveryBatch{findings: fs, source: "subdomain"}
	}()

	// Close the channel when all discovery goroutines finish — in a separate
	// goroutine so that processing of each batch can begin as soon as it
	// arrives (e.g. passivedns completes in seconds; subfinder may take minutes).
	go func() {
		wgDiscover.Wait()
		close(batchResults)
	}()

	assets := []string{rootDomain}
	seen := map[string]struct{}{rootDomain: {}}
	assetSource := map[string]string{rootDomain: "root"}

	// ── Improvement 1: Streaming results ────────────────────────────────────
	// Set up the scan semaphore and shared state BEFORE the discovery loop so
	// we can launch runAsset goroutines for new assets as each discovery batch
	// arrives, rather than waiting for all discovery to finish first.
	const maxConcurrentAssets = 10
	streamSem := make(chan struct{}, maxConcurrentAssets)
	expandSeen := map[string]bool{}
	var expandSeenMu sync.Mutex
	expandSeen[rootDomain] = true

	var assetsDone int64
	var wgStream sync.WaitGroup

	// launchAssetScan starts scanning a single asset via runAsset. Called from
	// the streaming discovery loop AND from the later BGP/AXFR/CIDR phases.
	// Thread-safe: uses streamSem for concurrency control.
	launchAssetScan := func(asset string) {
		select {
		case streamSem <- struct{}{}:
		case <-ctx.Done():
			return
		}
		if ctx.Err() != nil {
			<-streamSem
			return
		}
		if input.PauseCheck != nil {
			input.PauseCheck(ctx)
		}
		wgStream.Add(1)
		go func() {
			defer wgStream.Done()
			defer func() { <-streamSem }()
			if input.Progress != nil {
				input.Progress(module.ProgressEvent{
					Phase:       "scanning",
					AssetsTotal: len(assets), // approximate — still discovering
					AssetsDone:  int(atomic.LoadInt64(&assetsDone)),
					ActiveAsset: asset,
				})
			}
			fs := m.runAsset(ctx, asset, rootDomain, scanType, input.ScanRunID, 0, input.Progress, expandSeen, &expandSeenMu)
			done := int(atomic.AddInt64(&assetsDone, 1))
			if input.Progress != nil {
				mu.Lock()
				fc := len(allFindings)
				mu.Unlock()
				input.Progress(module.ProgressEvent{
					Phase:        "asset_done",
					AssetsTotal:  len(assets),
					AssetsDone:   done,
					FindingCount: fc + len(fs),
				})
			}
			appendFindings(fs)
		}()
	}

	// Source priority 1: Use cached subdomains immediately. Start scanning
	// them while live discovery sources are still running.
	if cacheHit && len(cachedAssets) > 0 {
		// Resolve cached assets to confirm they're still live.
		resolved := subdomain.ResolveBatch(ctx, cachedAssets, m.dnsxBin)
		for _, sub := range resolved {
			if sub == "" || !isValidHostname(sub) {
				continue
			}
			if _, ok := seen[sub]; !ok {
				seen[sub] = struct{}{}
				assets = append(assets, sub)
				assetSource[sub] = "cache"
				expandSeenMu.Lock()
				expandSeen[sub] = true
				expandSeenMu.Unlock()
				launchAssetScan(sub)
			}
		}
		progress(fmt.Sprintf("launched scans for %d cached assets — waiting for live discovery...", len(resolved)))
	}

	// Start scanning the root domain immediately while discovery runs.
	launchAssetScan(rootDomain)

	// Start WHOIS and BGP in parallel with discovery — no need to wait.
	var wgRoot sync.WaitGroup
	var bgpFindings []finding.Finding
	var bgpMu sync.Mutex

	wgRoot.Add(1)
	go func() {
		defer wgRoot.Done()
		discScanStart("whois", fmt.Sprintf("RDAP whois lookup for %s", rootDomain))
		fs, _ := m.whoisScanner.Run(ctx, rootDomain, scanType)
		discScanDone("whois", fs)
		appendFindings(fs)
	}()
	wgRoot.Add(1)
	go func() {
		defer wgRoot.Done()
		discScanStart("bgp", fmt.Sprintf("bgpview.io  ASN + prefix lookup for %s  →  ip-api.com reverse ASN", rootDomain))
		fs, _ := m.bgpScanner.Run(ctx, rootDomain, scanType)
		bgpMu.Lock()
		bgpFindings = fs
		bgpMu.Unlock()
		discScanDone("bgp", fs)
		appendFindings(fs)
	}()

	// Zone transfer runs concurrently with discovery too.
	var axfrAssets []string
	var wgAXFR sync.WaitGroup
	wgAXFR.Add(1)
	go func() {
		defer wgAXFR.Done()
		discScanStart("dns-axfr", fmt.Sprintf("dig axfr @<ns> %s", rootDomain))
		axfrFinding, axfrHosts := dns.ZoneTransferDiscovery(ctx, rootDomain, rootDomain)
		var axfrFindings []finding.Finding
		if axfrFinding != nil {
			axfrFindings = append(axfrFindings, *axfrFinding)
			appendFindings(axfrFindings)
			for _, h := range axfrHosts {
				if h == "" || !isValidHostname(h) {
					continue
				}
				mu.Lock()
				if _, ok := seen[h]; !ok {
					seen[h] = struct{}{}
					assets = append(assets, h)
					assetSource[h] = "axfr"
					axfrAssets = append(axfrAssets, h)
				}
				mu.Unlock()
			}
		}
		discScanDone("dns-axfr", axfrFindings)
		// Launch scans for AXFR-discovered assets immediately.
		for _, h := range axfrAssets {
			expandSeenMu.Lock()
			expandSeen[h] = true
			expandSeenMu.Unlock()
			launchAssetScan(h)
		}
	}()

	discStart := time.Now()
	// ── Improvement 1 (continued): Process batches as they arrive ───────────
	// Each batch of discovery results is processed immediately. New assets are
	// DNS-resolved and scanning starts right away — we don't wait for all
	// discovery sources to finish before the first subdomain scan begins.
	for batch := range batchResults {
		appendFindings(batch.findings)
		var batchNew []string
		for _, f := range batch.findings {
			subs := subdomain.Subdomains(f)
			subs = append(subs, passivedns.Subdomains(f)...)
			for _, sub := range subs {
				if sub == "" || !isValidHostname(sub) {
					continue // reject empty or malformed hostnames from discovery
				}
				if _, ok := seen[sub]; !ok {
					seen[sub] = struct{}{}
					assets = append(assets, sub)
					assetSource[sub] = batch.source
					batchNew = append(batchNew, sub)
				}
			}
			// CDN origin IPs: historical IPs that still respond directly for the
			// domain bypass CDN/WAF protections entirely. Add each as a scan asset
			// so the full scanner suite runs against the unprotected origin server.
			for _, ip := range passivedns.RespondingIPs(f) {
				if _, ok := seen[ip]; !ok {
					seen[ip] = struct{}{}
					assets = append(assets, ip)
					assetSource[ip] = "cdn_origin"
					batchNew = append(batchNew, ip)
				}
			}
		}
		// ── Improvement 2: DNS resolution for each batch ────────────────────
		// Resolve new hostnames from this batch immediately (concurrent, 50
		// goroutines). Only resolved hostnames get scanned.
		if len(batchNew) > 0 {
			resolved := subdomain.ResolveBatch(ctx, batchNew, m.dnsxBin)
			resolvedSet := make(map[string]struct{}, len(resolved))
			for _, r := range resolved {
				resolvedSet[r] = struct{}{}
			}
			for _, h := range batchNew {
				if _, ok := resolvedSet[h]; ok {
					expandSeenMu.Lock()
					expandSeen[h] = true
					expandSeenMu.Unlock()
					launchAssetScan(h)
				}
			}
			progress(fmt.Sprintf("%s: +%d assets (%d resolved) — scanning immediately", batch.source, len(batchNew), len(resolved)))
		}
	}
	discDuration := time.Since(discStart)

	// Update the discovery cache with all discovered subdomains.
	if discoveryCache != nil {
		var allSubs []string
		for sub := range seen {
			if sub != rootDomain {
				allSubs = append(allSubs, sub)
			}
		}
		discoveryCache.Put(rootDomain, allSubs)
	}

	// Wait for AXFR, WHOIS, and BGP to complete before processing BGP assets.
	wgAXFR.Wait()
	wgRoot.Wait()

	// Extract IPs and PTR hostnames discovered by BGP range scanning and add
	// them to the asset list so they receive the full classify + playbook +
	// portscan treatment. Without this step, BGP-discovered hosts would only
	// appear as findings but never be scanned.
	//
	// Ownership verification: BGP discovers every IP in the ASN, which may
	// include unrelated tenants on shared infrastructure.  We run passive
	// confirmation (PTR + TLS SAN) before treating an IP as in-scope.
	// Unconfirmed IPs still get a surface scan (unsolicited observation is
	// always safe) but are flagged for the operator to review before a deep
	// scan is allowed.
	// Cap BGP-discovered assets to prevent ASN enumeration from producing
	// thousands of targets that overwhelm the scan pipeline.
	const maxBGPAssets = 200
	bgpAdded := 0
	for _, f := range bgpFindings {
		if bgpAdded >= maxBGPAssets {
			break
		}
		switch f.CheckID {
		case finding.CheckASNIPService:
			if ip, ok := f.Evidence["ip"].(string); ok && ip != "" {
				if _, alreadySeen := seen[ip]; !alreadySeen {
					seen[ip] = struct{}{}
					assets = append(assets, ip) // surface scan always runs
					bgpAdded++
					ownership := checkAssetOwnership(ctx, ip, rootDomain)
					if ownership.Confidence >= AssetConfirmed {
						assetSource[ip] = "bgp"
					} else {
						assetSource[ip] = "bgp_unconfirmed"
						addUnconfirmed(module.DiscoveredAsset{
							Asset:         ip,
							DiscoveredVia: "bgp",
							Relationship:  fmt.Sprintf("IP in ASN for %s — %s", rootDomain, ownership.Confidence),
							Confirmed:     ownership.Confidence >= AssetConfirmed,
							Evidence:      ownership.Evidence,
							RootDomain:    rootDomain,
						})
					}
				}
			}
		case finding.CheckPTRRecord:
			if hostname, ok := f.Evidence["ptr_name"].(string); ok && hostname != "" {
				if _, alreadySeen := seen[hostname]; !alreadySeen {
					seen[hostname] = struct{}{}
					assets = append(assets, hostname) // surface scan always runs
					bgpAdded++
					if ipBelongsToDomain(hostname, rootDomain) {
						assetSource[hostname] = "bgp_ptr"
					} else {
						assetSource[hostname] = "bgp_ptr_unconfirmed"
						addUnconfirmed(module.DiscoveredAsset{
							Asset:         hostname,
							DiscoveredVia: "bgp_ptr",
							Relationship:  fmt.Sprintf("PTR record for BGP-discovered IP — not a subdomain of %s", rootDomain),
							Confirmed:     false,
							Evidence:      []string{fmt.Sprintf("PTR name: %s (does not end in .%s)", hostname, rootDomain)},
							RootDomain:    rootDomain,
						})
					}
				}
			}
		}
	}

	// Enumerate any manually specified CIDR ranges and probe for live HTTP/HTTPS
	// hosts. This covers IP space the org owns but hasn't announced via BGP,
	// or ranges on a shared ASN that BGP scanning correctly skipped.
	if len(input.ExtraCIDRs) > 0 {
		progress(fmt.Sprintf("probing %d manual CIDR ranges...", len(input.ExtraCIDRs)))
		extraIPs := enumerateAndProbeRanges(ctx, input.ExtraCIDRs)
		for _, ip := range extraIPs {
			if _, alreadySeen := seen[ip]; !alreadySeen {
				seen[ip] = struct{}{}
				assets = append(assets, ip) // surface scan always runs
				ownership := checkAssetOwnership(ctx, ip, rootDomain)
				if ownership.Confidence >= AssetConfirmed {
					assetSource[ip] = "cidr"
				} else {
					assetSource[ip] = "cidr_unconfirmed"
					addUnconfirmed(module.DiscoveredAsset{
						Asset:         ip,
						DiscoveredVia: "cidr",
						Relationship:  fmt.Sprintf("IP in operator-specified CIDR — %s", ownership.Confidence),
						Confirmed:     ownership.Confidence >= AssetConfirmed,
						Evidence:      ownership.Evidence,
						RootDomain:    rootDomain,
					})
				}
			}
		}
	}

	progress(fmt.Sprintf("discovery complete — %d assets queued for scanning", len(assets)))

	if input.Progress != nil {
		assetsCopy := make([]string, len(assets))
		copy(assetsCopy, assets)
		// Emit discovery_done with the full asset list.
		input.Progress(module.ProgressEvent{
			Phase:        "discovery_done",
			AssetsTotal:  len(assets),
			FindingCount: len(allFindings),
			AssetNames:   assetsCopy,
		})
		// Emit unconfirmed_assets so the TUI can show the Discovered Assets
		// panel immediately — surface scans for these assets will still arrive
		// via normal scanner_done events as the scan progresses.
		if len(unconfirmedAssets) > 0 {
			unconfirmedMu.Lock()
			unconfirmedCopy := make([]module.DiscoveredAsset, len(unconfirmedAssets))
			copy(unconfirmedCopy, unconfirmedAssets)
			unconfirmedMu.Unlock()
			input.Progress(module.ProgressEvent{
				Phase:            "unconfirmed_assets",
				DiscoveredAssets: unconfirmedCopy,
			})
		}
	}

	// ── Phase 2 & 3: Wait for streaming asset scans to complete ─────────────
	// Asset scanning was already launched incrementally in Phase 1 via
	// launchAssetScan as each discovery batch arrived. Now we also launch
	// scans for any assets added by BGP/CIDR that weren't launched yet,
	// then wait for everything to finish.
	scanStart := time.Now()

	// Launch scans for BGP/CIDR-discovered assets that were added after the
	// streaming discovery loop. These were added to `assets` and `seen` above
	// but haven't had launchAssetScan called yet.
	// Prioritize unlaunched assets so the most interesting ones scan first.
	var unlaunched []string
	for _, a := range assets {
		expandSeenMu.Lock()
		alreadyLaunched := expandSeen[a]
		expandSeenMu.Unlock()
		if !alreadyLaunched {
			unlaunched = append(unlaunched, a)
		}
	}
	if len(unlaunched) > 1 {
		unlaunched = scan.PrioritizeTargets(ctx, unlaunched)
	}
	for _, a := range unlaunched {
		expandSeenMu.Lock()
		expandSeen[a] = true
		expandSeenMu.Unlock()
		launchAssetScan(a)
	}

	wgStream.Wait()
	scanDuration := time.Since(scanStart)

	// ── Crawler-discovered hostname expansion ──────────────────────────────────
	// The katana crawler discovers URLs across the scanned assets. Any hostname
	// in those URLs that is a new subdomain of rootDomain is a potential asset
	// we missed during passive enumeration. Scan them now (surface pass only —
	// they were already crawled from their parent asset).
	// Cap at 20 new hosts to avoid runaway expansion from link-rich pages.
	const maxCrawlExpansion = 50
	if len(assets) < m.maxAssets {
		crawlCandidates := extractCrawlHostnames(rootDomain, allFindings, seen)
		if len(crawlCandidates) > maxCrawlExpansion {
			crawlCandidates = crawlCandidates[:maxCrawlExpansion]
		}
		// Alive-check candidates before scheduling full scans.
		var crawlAssets []string
		for _, h := range analyze.ProbeAliveBatch(ctx, crawlCandidates, m.httpxBin) {
			if _, ok := seen[h]; !ok {
				seen[h] = struct{}{}
				crawlAssets = append(crawlAssets, h)
				assets = append(assets, h)
			}
		}
		var wgCrawl sync.WaitGroup
	crawlLoop:
		for _, asset := range crawlAssets {
			asset := asset
			select {
			case streamSem <- struct{}{}:
			case <-ctx.Done():
				break crawlLoop
			}
			if ctx.Err() != nil {
				break crawlLoop
			}
			wgCrawl.Add(1)
			go func() {
				defer wgCrawl.Done()
				defer func() { <-streamSem }()
				fs := m.runAsset(ctx, asset, rootDomain, scanType, input.ScanRunID, 0, input.Progress, expandSeen, &expandSeenMu)
				appendFindings(fs)
			}()
		}
		wgCrawl.Wait()
	}

	// ── Harvester-discovered subdomain expansion ────────────────────────────
	// theHarvester emits subdomains discovered via OSINT (Google, Bing, GitHub,
	// crtsh, etc.) as CheckHarvesterSubdomains findings. These are not fed into
	// the initial asset list (harvester runs per-asset, not before the scan loop)
	// so we scan them now — same pattern as crawler-discovered hostnames.
	// Cap at 30 new hosts to prevent unbounded expansion on large domains.
	const maxHarvesterExpansion = 30
	if len(assets) < m.maxAssets {
		harvesterCandidates := extractHarvesterSubdomains(rootDomain, allFindings, seen)
		if len(harvesterCandidates) > maxHarvesterExpansion {
			harvesterCandidates = harvesterCandidates[:maxHarvesterExpansion]
		}
		var harvesterAssets []string
		for _, h := range analyze.ProbeAliveBatch(ctx, harvesterCandidates, m.httpxBin) {
			if _, ok := seen[h]; !ok {
				seen[h] = struct{}{}
				harvesterAssets = append(harvesterAssets, h)
				assets = append(assets, h)
				assetSource[h] = "harvester"
			}
		}
		var wgHarvester sync.WaitGroup
	harvesterLoop:
		for _, asset := range harvesterAssets {
			asset := asset
			select {
			case streamSem <- struct{}{}:
			case <-ctx.Done():
				break harvesterLoop
			}
			if ctx.Err() != nil {
				break harvesterLoop
			}
			wgHarvester.Add(1)
			go func() {
				defer wgHarvester.Done()
				defer func() { <-streamSem }()
				fs := m.runAsset(ctx, asset, rootDomain, scanType, input.ScanRunID, 0, input.Progress, expandSeen, &expandSeenMu)
				appendFindings(fs)
			}()
		}
		wgHarvester.Wait()
	}

	// Save discovery audit and timing after initial asset scan batch completes.
	if m.st != nil && input.ScanRunID != "" {
		audits := make([]store.DiscoveryAudit, 0, len(assetSource))
		for asset, source := range assetSource {
			audits = append(audits, store.DiscoveryAudit{
				ID: uuid.NewString(), ScanRunID: input.ScanRunID,
				Asset: asset, Source: source, CreatedAt: time.Now(),
			})
		}
		_ = m.st.SaveDiscoveryAudit(ctx, audits)
		_ = discDuration  // used to populate scan run timing below
		_ = scanDuration  // used to populate scan run timing below
	}

	// ── AI-driven additional port scan (surface + deep) ──────────────────────
	// After all assets are scanned, ask Claude which additional ports each asset
	// should have probed based on its findings. This supplements static port lists
	// with intelligence-driven targeting for detected tech stacks.
	// Only runs when an API key is configured (portAdvisor is non-nil).
	// Port advisor probing is active (TCP connect scans) — require PermissionConfirmed,
	// not just an API key, since probing AI-suggested ports without authorization
	// is equivalent to unsolicited port scanning.
	if m.portAdvisor != nil && input.PermissionConfirmed {
		// Build set of already-scanned ports for deduplication.
		alreadyScanned := buildScannedPorts()

		hints := buildHintsFromFindings(assets, allFindings)
		for _, hint := range hints {
			if len(hint.TechStack) == 0 && len(hint.KeyFindings) == 0 {
				continue // no signal — skip
			}
			portHint := analyze.PortHint{
				Hostname:    hint.Hostname,
				OpenPorts:   hint.OpenPorts,
				TechStack:   hint.TechStack,
				KeyFindings: hint.KeyFindings,
			}
			extraPorts, err := m.portAdvisor.SuggestPorts(ctx, portHint, alreadyScanned)
			if err != nil || len(extraPorts) == 0 {
				continue
			}
			// Probe suggested ports and emit findings.
			fs := probeExtraPorts(ctx, hint.Hostname, extraPorts)
			appendFindings(fs)
		}
	}

	// ── AI-guided expansion rounds (deep mode only) ───────────────────────────
	// After the initial scan batch finishes, send everything we know to Claude
	// and ask it to suggest hostnames we may have missed. Only runs when:
	//   • deep mode (requires authorization)
	//   • an API key is configured (advisor is non-nil)
	//   • MaxDiscoveryDepth > 0 (disabled by default for free tier)
	//   • total asset count is below MaxAssets
	if isDeepOrAuthorized(scanType) && m.discoveryAdvisor != nil && m.maxDiscoveryDepth > 0 {
		for round := 0; round < m.maxDiscoveryDepth; round++ {
			if len(assets) >= m.maxAssets {
				break // hard asset ceiling reached
			}

			// Build enriched hints from everything accumulated so far —
			// scan findings, tech stack, open ports — giving the AI the
			// richest signal before it suggests anything.
			hints := buildHintsFromFindings(assets, allFindings)

			suggestions, err := m.discoveryAdvisor.Suggest(ctx, rootDomain, hints)
			if err != nil || len(suggestions) == 0 {
				break
			}

			// Filter out already-seen and check asset ceiling.
			var candidates []string
			for _, h := range suggestions {
				if _, ok := seen[h]; ok {
					continue
				}
				if len(assets)+len(candidates) >= m.maxAssets {
					break
				}
				candidates = append(candidates, h)
			}
			// Batch probe all candidates at once — httpx is much faster than sequential HEAD.
			var roundAssets []string
			for _, h := range analyze.ProbeAliveBatch(ctx, candidates, m.httpxBin) {
				seen[h] = struct{}{}
				roundAssets = append(roundAssets, h)
			}

			if len(roundAssets) == 0 {
				break // no new live assets — stop expanding
			}

			// Full scan on new assets (same pipeline as the initial batch).
			assets = append(assets, roundAssets...)
			var wgRound sync.WaitGroup
		roundLoop:
			for _, asset := range roundAssets {
				asset := asset
				select {
				case streamSem <- struct{}{}:
				case <-ctx.Done():
					break roundLoop
				}
				if ctx.Err() != nil {
					break roundLoop
				}
				wgRound.Add(1)
				go func() {
					defer wgRound.Done()
					defer func() { <-streamSem }()
					if input.Progress != nil {
						input.Progress(module.ProgressEvent{
							Phase:       "scanning",
							AssetsTotal: len(assets),
							AssetsDone:  int(atomic.LoadInt64(&assetsDone)),
							ActiveAsset: asset,
						})
					}
					fs := m.runAsset(ctx, asset, rootDomain, scanType, input.ScanRunID, 0, input.Progress, expandSeen, &expandSeenMu)
					done := int(atomic.AddInt64(&assetsDone, 1))
					if input.Progress != nil {
						mu.Lock()
						fc := len(allFindings)
						mu.Unlock()
						input.Progress(module.ProgressEvent{
							Phase:        "asset_done",
							AssetsTotal:  len(assets),
							AssetsDone:   done,
							FindingCount: fc + len(fs),
						})
					}
					appendFindings(fs)
				}()
			}
			wgRound.Wait()
		}
	}

	// Safety gate: drop ModeDeep findings that leaked into a surface scan
	if scanType == module.ScanSurface {
		filtered := allFindings[:0]
		for _, f := range allFindings {
			if finding.Meta(f.CheckID).Mode == finding.ModeDeep {
				continue // BUG: deep check emitted during surface scan — drop it
			}
			filtered = append(filtered, f)
		}
		allFindings = filtered
	}

	// ── Cross-asset AI analysis ───────────────────────────────────────────────
	// After all assets are scanned, ask AI to identify attack chains, cross-asset
	// vulnerabilities, and additional scanners warranted by the full picture.
	// Only runs when attack path analysis is enabled and an enricher is available.
	// Additional scanners recommended here are run immediately per-asset.
	if m.enricher != nil && len(allFindings) > 0 {
		analyzer := aifp.NewCrossAnalyzer(m.enricher.Chat)
		if result, err := analyzer.Analyze(ctx, allFindings, rootDomain); err == nil {
			// Emit cross-asset findings.
			mu.Lock()
			allFindings = append(allFindings, result.CrossFindings...)
			mu.Unlock()

			// Emit summary as a progress event so the TUI can surface it.
			if input.Progress != nil && result.Summary != "" {
				input.Progress(module.ProgressEvent{
					Phase:     "cross_asset_analysis",
					StatusMsg: result.Summary,
				})
			}

			// Run any AI-recommended additional scans per asset.
			// Uses a small concurrency cap so we don't fan out unboundedly.
			if len(result.AdditionalScans) > 0 {
				const maxAdditionalConcurrent = 5
				addSem := make(chan struct{}, maxAdditionalConcurrent)
				var addWg sync.WaitGroup
				for targetAsset, scannerNames := range result.AdditionalScans {
					targetAsset, scannerNames := targetAsset, scannerNames
					select {
					case addSem <- struct{}{}:
					case <-ctx.Done():
						continue
					}
					addWg.Add(1)
					go func() {
						defer addWg.Done()
						defer func() { <-addSem }()
						// Snapshot per-asset findings for evidence extraction.
						mu.Lock()
						assetFindings := make([]finding.Finding, 0, len(allFindings))
						for _, f := range allFindings {
							if f.Asset == targetAsset {
								assetFindings = append(assetFindings, f)
							}
						}
						mu.Unlock()

						for _, name := range scannerNames {
							var fs []finding.Finding
							var scanErr error
							switch name {
							case "aillm":
								// Pass per-asset AI endpoints so the scanner targets
								// confirmed paths rather than the generic default list.
								ev := &playbook.Evidence{
									AIEndpoints: extractAIEndpoints(assetFindings),
								}
								result := scan.Execute(aillm.NewWithEvidence(ev), ctx, targetAsset, scanType)
								fs, scanErr = result.Findings, result.Error
							default:
								sc, ok := m.scanners[name]
								if !ok {
									continue
								}
								result := scan.Execute(sc, ctx, targetAsset, scanType)
								fs, scanErr = result.Findings, result.Error
							}
							_ = scanErr
							if len(fs) > 0 {
								mu.Lock()
								allFindings = append(allFindings, fs...)
								mu.Unlock()
							}
						}
					}()
				}
				addWg.Wait()
			}
		}
	}

	// Second safety gate: cross-asset AI analysis and its additional scanners
	// may have injected ModeDeep findings after the first gate.
	if scanType == module.ScanSurface {
		filtered := allFindings[:0]
		for _, f := range allFindings {
			if finding.Meta(f.CheckID).Mode == finding.ModeDeep {
				continue
			}
			filtered = append(filtered, f)
		}
		allFindings = filtered
	}

	// ── Active attack path chaining (ScanAuthorized only) ───────────────────
	// The chain engine takes completed findings and actively exploits one to
	// discover the next. Only runs in ScanAuthorized mode — New() enforces this.
	if chainEng, err := chainengine.New(scanType); err == nil {
		for _, f := range allFindings {
			if ctx.Err() != nil {
				break
			}
			chainResults := chainEng.OnFinding(ctx, f)
			if len(chainResults) > 0 {
				allFindings = append(allFindings, chainResults...)
			}
		}
	}

	// Deduplicate findings by CheckID+Asset, preferring native scanners over
	// nuclei. When both a native scanner and nuclei detect the same issue on
	// the same asset, the native finding has richer evidence and proof commands.
	allFindings = deduplicateFindings(allFindings)

	// Persist verified findings to the exploit cache for reuse in future scans.
	if cache := exploitcache.CacheFromContext(ctx); cache != nil {
		for _, f := range allFindings {
			if f.Confidence != finding.ConfidenceVerified {
				continue
			}
			service, _ := f.Evidence[finding.EvidenceService].(string)
			if service == "" {
				service, _ = f.Evidence[finding.EvidencePivotTarget].(string)
			}
			version, _ := f.Evidence[finding.EvidenceVersion].(string)
			if service != "" {
				_ = cache.SaveFromFinding(f, service, version)
			}
		}
	}

	return allFindings, nil
}

// deduplicateFindings removes duplicate findings sharing the same CheckID+Asset.
// When a native scanner and nuclei both produce a finding for the same check,
// the native scanner's finding is kept because it has richer evidence, better
// proof commands, and more specific descriptions.
func deduplicateFindings(findings []finding.Finding) []finding.Finding {
	type dedupKey struct {
		checkID string
		asset   string
		port    int
	}
	seen := make(map[dedupKey]int, len(findings)) // key → index in result
	result := make([]finding.Finding, 0, len(findings))

	for _, f := range findings {
		port, _ := f.Evidence["port"].(int)
		key := dedupKey{f.CheckID, f.Asset, port}
		if idx, exists := seen[key]; exists {
			// Prefer native scanner over nuclei.
			if result[idx].Scanner == "nuclei" && f.Scanner != "nuclei" {
				result[idx] = f // replace nuclei finding with native
			}
			// Otherwise keep the first (native) finding, skip the dupe.
			continue
		}
		seen[key] = len(result)
		result = append(result, f)
	}
	return result
}

// runFilteredScanners executes only the scanners named in m.scannerFilter
// against a single asset. No evidence collection, playbook matching, or
// convergence loops — just the bare scanner runs. Used by --scanners mode
// for targeted testing (e.g. Drydock).
func (m *Module) runFilteredScanners(ctx context.Context, asset string, scanType module.ScanType, scanRunID string, progressFn module.ProgressFunc) []finding.Finding {
	// Inject auth context for filtered scanner runs (--scanners mode).
	// The normal runAsset path does this after evidence collection, but the
	// filtered path skips evidence — auth must be injected here.
	httpClient := &http.Client{Timeout: 30 * time.Second}
	if len(m.authCfgs) > 0 {
		if authedClient, _, err := auth.Authenticate(ctx, m.authCfgs, asset, httpClient); err != nil {
			_ = err
		} else if authedClient != nil {
			httpClient = authedClient
		}
	}
	ctx = authctx.WithHTTPClient(ctx, httpClient)

	// If any injection scanner is in the filter, run native param discovery first
	// so discovered parameters are available in context.
	if isDeepOrAuthorized(scanType) {
		needsParamDiscovery := false
		for _, name := range m.scannerFilter {
			if injectionScannerNames[name] {
				needsParamDiscovery = true
				break
			}
		}
		if needsParamDiscovery {
			base := schemedetect.Base(ctx, httpClient, asset)
			nativeFound := paramdiscovery.DiscoverParams(ctx, httpClient, base+"/", "GET")
			if len(nativeFound) > 0 {
				params := make(map[string][]string)
				var names []string
				for _, p := range nativeFound {
					names = append(names, p.Name)
				}
				params["/"] = names
				ctx = paramdiscovery.WithDiscoveredParams(ctx, params)
			}
		}
	}

	// Always run portscan first as a prerequisite when it's not in the filter
	// but other scanners need HTTP service discovery to function.
	hasPortscan := false
	for _, name := range m.scannerFilter {
		if name == "portscan" {
			hasPortscan = true
			break
		}
	}
	var findings []finding.Finding
	var mu sync.Mutex
	if !hasPortscan {
		if ps, ok := m.scanners["portscan"]; ok {
			result := scan.Execute(ps, ctx, asset, scanType)
			findings = append(findings, result.Findings...)
		}
	}

	var wg sync.WaitGroup

	for _, name := range m.scannerFilter {
		scanner, ok := m.scanners[name]
		if !ok {
			continue
		}
		name, scanner := name, scanner
		if progressFn != nil {
			progressFn(module.ProgressEvent{
				Phase:       "scanner_start",
				ActiveAsset: asset,
				ScannerName: name,
				ScannerCmd:  name + " → " + asset,
			})
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			result := scan.Execute(scanner, ctx, asset, scanType)
			mu.Lock()
			findings = append(findings, result.Findings...)
			mu.Unlock()
			m.saveScanMetricElapsed(ctx, scanRunID, asset, name, result.Metrics.Duration, result.Findings, result.Error)
			if progressFn != nil {
				fsCopy := make([]finding.Finding, len(result.Findings))
				copy(fsCopy, result.Findings)
				progressFn(module.ProgressEvent{
					Phase:        "scanner_done",
					ActiveAsset:  asset,
					ScannerName:  name,
					FindingDelta: len(result.Findings),
					NewFindings:  fsCopy,
				})
			}
		}()
	}
	wg.Wait()
	return findings
}

// runAsset classifies a single asset, matches playbooks, executes the RunPlan,
// and writes an AssetExecution audit record.
// depth tracks playbook-driven discovery recursion depth; expanded assets are
// scanned at depth+1 and do not trigger further discovery (max depth = 1).
// expandSeen is a shared set (protected by expandSeenMu) that prevents two
// concurrent runAsset goroutines from independently discovering and scanning
// the same cert-SAN / port-service / body-subdomain child asset.
func (m *Module) runAsset(ctx context.Context, asset, rootDomain string, scanType module.ScanType, scanRunID string, depth int, progressFn module.ProgressFunc, expandSeen map[string]bool, expandSeenMu *sync.Mutex) []finding.Finding {
	// ── Fast path: --scanners filter ────────────────────────────────────────
	// When a scanner filter is active, skip evidence collection, playbook
	// matching, Phase A intelligence, and convergence loops. Just run the
	// requested scanners and return their findings.
	if len(m.scannerFilter) > 0 {
		return m.runFilteredScanners(ctx, asset, scanType, scanRunID, progressFn)
	}

	// Collect evidence — emit fingerprint event when interesting signals are found
	if progressFn != nil {
		progressFn(module.ProgressEvent{
			Phase:       "scanner_start",
			ActiveAsset: asset,
			ScannerName: "classify",
			ScannerCmd:  "HTTP probe + DNS + TLS fingerprint → " + asset,
		})
	}
	ev := classify.Collect(ctx, asset)

	// AI fingerprint gap-filling + scanner suggestion.
	// When deterministic rules leave key fields empty, the classifier fills them,
	// proposes a pending fingerprint rule for human review, and returns scanners
	// that are warranted by the identified technology but not in the current plan.
	// Falls back to legacy FillGaps when the enricher isn't available.
	var aifpSuggestedScanners []string
	var aifpUnknownFinding *finding.Finding
	if m.enricher != nil && aifp.NeedsClassification(&ev) {
		if result, err := aifp.NewClassifier(m.enricher.Chat, m.st).Classify(ctx, &ev); err == nil {
			result.MergeInto(&ev)
			aifpSuggestedScanners = result.SuggestedScanners
			aifpUnknownFinding = result.UnknownTechFinding(asset)
		}
	} else if m.anthropicKey != "" {
		_ = profiler.FillGaps(ctx, m.anthropicKey, m.claudeModel, &ev, m.st)
	}

	// Apply database-driven fingerprint rules to fill any remaining gaps.
	// Track which rules fired so SeenCount stays accurate across scans.
	if len(m.fingerprintRules) > 0 {
		if matched := fingerprintdb.Apply(m.fingerprintRules, &ev); m.st != nil {
			for _, id := range matched {
				_ = m.st.IncrementFingerprintRuleSeen(ctx, id)
			}
		}
	}

	// Pre-scan authentication: if an AuthConfig matches this asset, wrap the
	// base http.Client to inject credentials into all scanner requests.
	httpClient := &http.Client{Timeout: 30 * time.Second}
	var authHeaders map[string]string
	if len(m.authCfgs) > 0 {
		if authedClient, session, err := auth.Authenticate(ctx, m.authCfgs, asset, httpClient); err != nil {
			// Log but don't abort — fall back to unauthenticated scan.
			_ = err
		} else if authedClient != nil {
			httpClient = authedClient
			if session != nil && len(session.Headers) > 0 {
				authHeaders = session.Headers
			}
		}
	}

	// Wrap the HTTP transport with the evasion MonitoredTransport so every
	// scanner request is checked for WAF/IDS/rate-limit signals automatically.
	// The monitor is stored in context so scanners can call monitor.Blocked()
	// before sending additional probes.
	evasionMonitor := evasion.NewMonitor(m.evasionStrategy)
	adaptiveRate := evasion.NewAdaptiveRate(0, 30*time.Second) // start unlimited, max 30s between requests
	baseTransport := httpClient.Transport
	if baseTransport == nil {
		baseTransport = http.DefaultTransport
	}
	httpClient.Transport = &evasion.MonitoredTransport{
		Base:    baseTransport,
		Monitor: evasionMonitor,
		Rate:    adaptiveRate,
	}
	ctx = evasion.WithMonitor(ctx, evasionMonitor)

	ctx = authctx.WithHTTPClient(ctx, httpClient)

	// Post-auth re-classify: if we authenticated, re-fingerprint the asset with
	// the authenticated client. Many apps show a login page to unauthenticated
	// users but redirect to a dashboard after auth — the second classify captures
	// the real application surface (different title, headers, frameworks, status code).
	if len(m.authCfgs) > 0 && httpClient != nil {
		authEv := classify.Collect(ctx, asset)
		// Merge authenticated evidence into the original — keep DNS/TLS from
		// the first pass (those don't change with auth) but update HTTP-derived
		// fields that may differ.
		if authEv.StatusCode > 0 && authEv.StatusCode != ev.StatusCode {
			ev.StatusCode = authEv.StatusCode
		}
		if authEv.Title != "" && authEv.Title != ev.Title {
			ev.Title = authEv.Title
		}
		if authEv.AuthSystem == "" && ev.AuthSystem != "" {
			// Keep the original auth system detection
		} else if authEv.AuthSystem != "" {
			ev.AuthSystem = authEv.AuthSystem
		}
		// Merge headers — authenticated response may expose new headers.
		for k, v := range authEv.Headers {
			ev.Headers[k] = v
		}
		// Merge service versions discovered behind auth.
		for k, v := range authEv.ServiceVersions {
			ev.ServiceVersions[k] = v
		}
	}

	// Inject ScanContext — provides typed accessors (asset, scanType, HTTP client,
	// evidence) to scanners via scan.FromContext(ctx). Coexists with authctx
	// for backward compatibility.
	sctx := scan.NewContext(asset, scanType).WithHTTPClient(httpClient).WithEvidence(&ev)
	if authHeaders != nil {
		sctx.WithAuthHeaders(authHeaders)
	}
	if m.wordlistPath != "" {
		sctx.WithWordlist(m.wordlistPath)
	}
	sctx.WithScreenshots(m.screenshotsEnabled)
	ctx = sctx.Inject(ctx)

	if progressFn != nil && (ev.Title != "" || len(ev.ServiceVersions) > 0 || ev.CertIssuer != "") {
		parts := []string{}
		if ev.StatusCode > 0 {
			parts = append(parts, fmt.Sprintf("HTTP %d", ev.StatusCode))
		}
		for k, v := range ev.ServiceVersions {
			_ = k
			parts = append(parts, v)
			break // just show first hit
		}
		if ev.Title != "" {
			parts = append(parts, fmt.Sprintf("title=%q", ev.Title))
		}
		if ev.JARMFingerprint != "" {
			jarmPreview := ev.JARMFingerprint
			if len(jarmPreview) > 8 {
				jarmPreview = jarmPreview[:8] + "…"
			}
			parts = append(parts, "JARM="+jarmPreview)
		}
		msg := asset
		if len(parts) > 0 {
			msg += " → " + strings.Join(parts, " · ")
		}
		progressFn(module.ProgressEvent{
			Phase:       "fingerprint",
			ActiveAsset: asset,
			StatusMsg:   msg,
			Evidence:    ev,
		})
	}

	// Match playbooks (lazy-loaded on first use)
	reg, err := m.getRegistry()
	if err != nil {
		return nil // playbook load failure — degrade gracefully
	}
	matched := reg.Match(ev)

	// Playbook-driven discovery (e.g. Cloudflare origin probing) runs up to
	// maxPlaybookDepth levels deep. Stops at the configured ceiling to prevent
	// infinite recursion from looping CNAME chains or CDN origin patterns.
	var expandedAssets []string
	if depth < m.maxPlaybookDepth {
		expandedAssets = m.runDiscovery(ctx, asset, rootDomain, matched, scanType)
	}

	// Build unified RunPlan
	plan := playbook.BuildRunPlan(matched)

	// Merge deep-only scanners into the plan when the scan mode permits active probing.
	if scanType != module.ScanSurface && len(plan.DeepOnlyScanners) > 0 {
		plan.Scanners = append(plan.Scanners, plan.DeepOnlyScanners...)
	}

	// AI-powered scanner suggestions — augment the plan with scanners the
	// playbook system did not match but the AI considers relevant to the
	// detected tech stack. Runs only when an API key is configured.
	// Errors are silently ignored so advisor failures never block the scan.
	if m.playbookAdvisor != nil {
		// Compute the set of scanner names not yet in the plan so we can pass
		// them as candidates to the advisor (avoids re-suggesting duplicates).
		planScannerSet := make(map[string]bool, len(plan.Scanners))
		for _, s := range plan.Scanners {
			planScannerSet[s] = true
		}
		var available []string
		for name := range m.scanners {
			if !planScannerSet[name] {
				available = append(available, name)
			}
		}
		mode := "surface"
		if isDeepOrAuthorized(scanType) {
			mode = "deep"
		}
		suggestions, err := m.playbookAdvisor.Suggest(ctx, ev, plan.Scanners, available, mode)
		if err == nil {
			for _, s := range suggestions {
				if _, ok := m.scanners[s]; ok {
					plan.Scanners = append(plan.Scanners, s)
				}
			}
		}
	}

	// Merge AIFP-suggested scanners into the plan.
	for _, s := range aifpSuggestedScanners {
		if !planContains(plan.Scanners, s) {
			plan.Scanners = append(plan.Scanners, s)
		}
	}

	// ── Dry-run: output the planned scanner list and stop ────────────────────
	if m.dryRun {
		matchedNames := make([]string, len(matched))
		for i, pb := range matched {
			matchedNames[i] = pb.Name
		}
		return []finding.Finding{{
			CheckID:     finding.CheckMetaDryRunPlan,
			Module:      "surface",
			Scanner:     "planner",
			Severity:    finding.SeverityInfo,
			Title:       "Dry-run scan plan for " + asset,
			Description: "Planned scanners and matched playbooks (no scanners were executed)",
			Asset:       asset,
			Evidence: map[string]any{
				"scanners":  plan.Scanners,
				"playbooks": matchedNames,
				"evidence": map[string]any{
					"status_code":      ev.StatusCode,
					"title":            ev.Title,
					"service_versions": ev.ServiceVersions,
					"framework":        ev.Framework,
					"waf_vendor":       ev.WAFVendor,
				},
			},
		}}
	}

	noHTTP := ev.StatusCode == 0

	// ── Phase A: Intelligence scanners (parallel) ────────────────────────────
	// Run wafdetect, portscan, aidetect, and authsurface concurrently and wait
	// for all before starting Phase B. Their findings feed into Phase B:
	//   • wafdetect:    WAF vendor → skip vhost scanning on CDN-fronted assets
	//   • portscan:     open-port set → service-specific Nuclei tag injection
	//   • aidetect:     AI endpoint list → aillm uses discovered endpoints instead of
	//                  guessing defaults, reducing false negatives on non-standard paths
	//   • authsurface:  login form detection → auth pipeline acquires session before
	//                  Phase B so all subsequent scanners run authenticated
	phaseANames := []string{"wafdetect", "portscan", "aidetect", "authsurface"}
	phaseADone := make(map[string]bool, len(phaseANames))
	var phaseAMu sync.Mutex
	var phaseAFindings []finding.Finding
	var phaseAWg sync.WaitGroup

	// Per-scanner done channels allow streaming: portscan results are available
	// immediately (for service classification and HTTP alt-port recovery) while
	// slower Phase A scanners (wafdetect, authsurface) continue in parallel.
	phaseADoneCh := make(map[string]chan struct{}, len(phaseANames))

	for _, name := range phaseANames {
		if !planContains(plan.Scanners, name) {
			continue
		}
		sc, ok := m.scanners[name]
		if !ok {
			continue
		}
		phaseADone[name] = true
		doneCh := make(chan struct{})
		phaseADoneCh[name] = doneCh
		name, sc := name, sc
		phaseAWg.Add(1)
		go func() {
			defer phaseAWg.Done()
			result := scan.Execute(sc, ctx, asset, scanType)
			phaseAMu.Lock()
			phaseAFindings = append(phaseAFindings, result.Findings...)
			phaseAMu.Unlock()
			close(doneCh)
			m.saveScanMetricElapsed(ctx, scanRunID, asset, name, result.Metrics.Duration, result.Findings, result.Error)
		}()
	}

	// Stream portscan results: extract open ports as soon as portscan finishes,
	// overlapping with wafdetect/aidetect/authsurface still running.
	if ch, ok := phaseADoneCh["portscan"]; ok {
		<-ch
	}

	// Extract port intelligence immediately — don't wait for wafdetect/authsurface.
	phaseAMu.Lock()
	openPorts := extractOpenPorts(phaseAFindings)
	phaseAMu.Unlock()

	// Now wait for the remaining Phase A scanners to finish.
	phaseAWg.Wait()

	// Extract WAF, origin IP, and AI endpoint intelligence from all Phase A results.
	behindWAF, wafVendor := extractWAFInfo(phaseAFindings)
	originIP := extractOriginIP(phaseAFindings)
	// Feed WAF/IDS vendor back into evidence for playbook matching and AI enrichment.
	if wafVendor != "" {
		ev.WAFVendor = wafVendor
	}
	if idsVendor := extractIDSVendor(phaseAFindings); idsVendor != "" {
		ev.IDSVendor = idsVendor
	}
	// Populate ev.AIEndpoints from aidetect findings so aillm targets confirmed
	// endpoints instead of falling back to a generic default path list.
	if eps := extractAIEndpoints(phaseAFindings); len(eps) > 0 {
		ev.AIEndpoints = eps
	}
	// Classify the service type from portscan results — used to skip irrelevant
	// scanners (e.g., skip all HTTP scanners for a CouchDB/Redis target).
	svcClass := classifyService(openPorts)
	if svcClass != ServiceClassUnknown && svcClass != ServiceClassWebApp && progressFn != nil {
		classNames := map[ServiceClass]string{
			ServiceClassDatabase:     "database",
			ServiceClassMessageQueue: "message_queue",
			ServiceClassMonitoring:   "monitoring",
			ServiceClassCICD:         "cicd",
			ServiceClassInfra:        "infrastructure",
			ServiceClassAPI:          "api",
		}
		progressFn(module.ProgressEvent{
			Phase:       "service_class",
			ActiveAsset: asset,
			StatusMsg:   fmt.Sprintf("%s → service class: %s (irrelevant scanners will be skipped)", asset, classNames[svcClass]),
		})
	}

	// Propagate portscan-identified service versions into Evidence so Phase B
	// scanners and nuclei template selection can use them. Portscan probes
	// identify services via banner fingerprinting (e.g., "redis", "ssh", "mysql").
	if len(openPorts) > 0 {
		if ev.ServiceVersions == nil {
			ev.ServiceVersions = make(map[string]string)
		}
		for port, svc := range openPorts {
			if svc != "" {
				key := fmt.Sprintf("port_%d", port)
				ev.ServiceVersions[key] = svc
			}
		}
	}

	// Non-standard HTTP port recovery: if classify found no HTTP on 80/443 but
	// portscan found a known HTTP-capable port (8080, 8443, 3000, etc.), try
	// classify again on that port so HTTP-dependent scanners (crawler, JWT, OAuth,
	// CORS, etc.) aren't all skipped for a live web service on a non-standard port.
	if noHTTP {
		if altPort := httpAltPort(openPorts); altPort > 0 {
			altAsset := fmt.Sprintf("%s:%d", asset, altPort)
			altEv := classify.Collect(ctx, altAsset)
			if altEv.StatusCode > 0 {
				// Merge: keep DNS/ASN from original, take HTTP evidence from alt port.
				altEv.IP = ev.IP
				altEv.ASNOrg = ev.ASNOrg
				altEv.ASNNum = ev.ASNNum
				altEv.CNAMEChain = ev.CNAMEChain
				ev = altEv
				ev.Hostname = asset // keep original asset name for playbook matching
				noHTTP = false
				if progressFn != nil {
					progressFn(module.ProgressEvent{
						Phase:       "fingerprint",
						ActiveAsset: asset,
						StatusMsg:   fmt.Sprintf("%s → HTTP %d on port %d (non-standard)", asset, ev.StatusCode, altPort),
						Evidence:    ev,
					})
				}
			}
		}
	}

	// Second-pass playbook matching: populate PhaseACheckIDs from Phase A findings
	// so check_id: conditions in playbooks (e.g. "netdev.mikrotik_detected",
	// "port.checkpoint_topology") can match. Then re-run registry.Match and merge
	// any newly matched playbooks into the existing plan.
	if len(phaseAFindings) > 0 {
		checkIDSet := map[string]bool{}
		for _, f := range phaseAFindings {
			if string(f.CheckID) != "" {
				checkIDSet[string(f.CheckID)] = true
			}
		}
		for id := range checkIDSet {
			ev.PhaseACheckIDs = append(ev.PhaseACheckIDs, id)
		}
		// Re-match with updated evidence; merge scanners/tags not already in plan.
		existingPlaybooks := map[string]bool{}
		for _, pb := range matched {
			existingPlaybooks[pb.Name] = true
		}
		newMatches := reg.Match(ev)
		for _, pb := range newMatches {
			if !existingPlaybooks[pb.Name] {
				matched = append(matched, pb)
				// Merge new playbook's scanners and tags into the existing plan.
				extra := playbook.BuildRunPlan([]*playbook.Playbook{pb})
				existingSet := map[string]bool{}
				for _, s := range plan.Scanners {
					existingSet[s] = true
				}
				for _, s := range extra.Scanners {
					if !existingSet[s] {
						plan.Scanners = append(plan.Scanners, s)
					}
				}
				existingSurfTagSet := map[string]bool{}
				for _, t := range plan.NucleiTagsSurf {
					existingSurfTagSet[t] = true
				}
				for _, t := range extra.NucleiTagsSurf {
					if !existingSurfTagSet[t] {
						plan.NucleiTagsSurf = append(plan.NucleiTagsSurf, t)
					}
				}
				existingDeepTagSet := map[string]bool{}
				for _, t := range plan.NucleiTagsDeep {
					existingDeepTagSet[t] = true
				}
				for _, t := range extra.NucleiTagsDeep {
					if !existingDeepTagSet[t] {
						plan.NucleiTagsDeep = append(plan.NucleiTagsDeep, t)
					}
				}
				plan.DirbustPaths = append(plan.DirbustPaths, extra.DirbustPaths...)
			}
		}
	}

	// ── Adaptive recon profiling ─────────────────────────────────────────────
	// After Phase A we have the richest fingerprint: AI endpoints, WAF vendor,
	// open ports, and classify evidence. Feed all of this to the profiler so
	// Claude can recommend additional scanner modules and evasion strategy.
	// Runs only when AdaptiveRecon is enabled and an API key is present.
	// Errors are silently ignored — profiler failures must never block the scan.
	if m.adaptiveRecon && m.anthropicKey != "" {
		if prof, err := profiler.Profile(ctx, m.anthropicKey, m.claudeModel, &ev); err == nil {
			// Emit a finding summarising the profile so it appears in reports.
			// Phase B findings slice isn't allocated yet — append to phaseAFindings
			// so it flows into the unified findings slice below.
			pf := profiler.ProfileToFinding(asset, prof)
			pf.Module = "surface"
			pf.Scanner = "profiler"
			phaseAFindings = append(phaseAFindings, pf)

			// Merge profile-recommended scanner modules into the run plan.
			existingSet := make(map[string]bool, len(plan.Scanners))
			for _, s := range plan.Scanners {
				existingSet[s] = true
			}
			for _, s := range prof.Modules {
				if !existingSet[s] {
					if _, known := m.scanners[s]; known {
						plan.Scanners = append(plan.Scanners, s)
						existingSet[s] = true
					}
				}
			}

			// Log evasion tips to the progress stream so operators can act on them.
			if progressFn != nil && len(prof.EvasionTips) > 0 {
				progressFn(module.ProgressEvent{
					Phase:       "profiler",
					ActiveAsset: asset,
					StatusMsg:   "AI profile: " + strings.Join(prof.EvasionTips[:min(len(prof.EvasionTips), 2)], "; "),
				})
			}
		}
	}

	// ── Auth pipeline: acquire session from Phase A authsurface findings ────
	// If authsurface detected a login form and no user-provided auth config
	// matched this asset, try to acquire a session via auto-registration or
	// default credentials. On success, rebuild the HTTP client and ScanContext
	// so all Phase B scanners run authenticated.
	if len(m.authCfgs) == 0 || !authConfigMatchesAsset(m.authCfgs, asset) {
		loginForms := auth.ExtractLoginForms(phaseAFindings, ev.Scheme, asset)
		regAvailable := auth.HasRegistration(phaseAFindings)
		if len(loginForms) > 0 {
			pipeline := auth.NewPipeline(httpClient)
			authedClient, sessionInfo, pipelineErr := pipeline.AcquireSession(
				ctx, asset, ev.Scheme, &loginForms[0], m.authCfgs, regAvailable,
			)
			if pipelineErr == nil && authedClient != nil {
				httpClient = authedClient
				// Re-wrap with evasion monitoring.
				baseTransport = httpClient.Transport
				if baseTransport == nil {
					baseTransport = http.DefaultTransport
				}
				httpClient.Transport = &evasion.MonitoredTransport{
					Base:    baseTransport,
					Monitor: evasionMonitor,
					Rate:    adaptiveRate,
				}
				// Rebuild scan context with the authenticated client.
				ctx = authctx.WithHTTPClient(ctx, httpClient)
				sctx = scan.NewContext(asset, scanType).WithHTTPClient(httpClient).WithEvidence(&ev)
				if sessionInfo != nil && len(sessionInfo.Headers) > 0 {
					sctx.WithAuthHeaders(sessionInfo.Headers)
				}
				if m.wordlistPath != "" {
					sctx.WithWordlist(m.wordlistPath)
				}
				sctx.WithScreenshots(m.screenshotsEnabled)
				ctx = sctx.Inject(ctx)

				if progressFn != nil {
					source := "unknown"
					if sessionInfo != nil {
						source = sessionInfo.Source
					}
					progressFn(module.ProgressEvent{
						Phase:       "auth_pipeline",
						ActiveAsset: asset,
						StatusMsg:   fmt.Sprintf("Session acquired via %s", source),
					})
				}
			}
		}
	}

	// Apply inter-scanner jitter when evasion is configured. This inserts a
	// random [0, MaxJitterMs] ms sleep before each Phase B scanner starts,
	// spreading requests over time to avoid rate-limit clustering.
	// The evasion strategy's proxy rotation applies to scanners that
	// accept an HTTP client override (future work — proxies are transport-layer).
	jitter := m.evasionStrategy

	// Compute dirbust paths before Phase B — depends only on classify evidence
	// and playbook data, both available before any Phase B scanner runs.
	dirbustPaths := plan.DirbustPaths
	if isDeepOrAuthorized(scanType) && len(ev.RobotsTxtPaths) > 0 {
		seenPaths := map[string]bool{}
		for _, p := range dirbustPaths {
			seenPaths[p] = true
		}
		for _, p := range ev.RobotsTxtPaths {
			if !seenPaths[p] {
				seenPaths[p] = true
				dirbustPaths = append(dirbustPaths, p)
			}
		}
	}

	// ── Crawl-feed channel ────────────────────────────────────────────────────
	// crawlFeed carries URLs discovered by katana to the DLP scanner in real
	// time. Buffer of 128 gives DLP burst tolerance before it must drain.
	// Non-blocking sends in the crawler ensure katana stdout is never stalled.
	// The channel is closed exactly once via crawlFeedOnce — by whichever of
	// (a) the crawler goroutine (normal path) or (b) the deferred safety net
	// (crawler skipped / early error) fires first.
	crawlFeed := make(chan string, 128)
	var crawlFeedOnce sync.Once
	closeCrawlFeed := func() { crawlFeedOnce.Do(func() { close(crawlFeed) }) }
	defer closeCrawlFeed()
	ctx = context.WithValue(ctx, module.CrawlFeedKey, crawlFeed)
	ctx = context.WithValue(ctx, module.CrawlFeedCloserKey, closeCrawlFeed)

	// ── Phase B: Remaining scanners (concurrent) ──────────────────────────────
	// httpDependentScanners produce zero useful findings on assets with no web
	// server. All active HTTP probers are listed here to avoid wasted connections.
	httpDependentScanners := map[string]bool{
		"crawler": true, "screenshot": true, "webcontent": true, "dlp": true,
		"cors": true, "hostheader": true, "jwt": true, "ratelimit": true,
		"smuggling": true, "oauth": true, "graphql": true, "cms-plugins": true,
		"depconf": true, "cdnbypass": true, "jenkins": true,
		"clickjacking": true, "autoprobe": true, "websocket": true,
		"exposedfiles": true, "apiversions": true,
		"proxychain": true, "cacheprobe": true,
	}

	var findings []finding.Finding
	findings = append(findings, phaseAFindings...)
	var mu sync.Mutex
	var wg sync.WaitGroup

	// screenshotDone is closed when the screenshot scanner finishes.
	// The DLP Vision goroutine waits on this channel so it can start as soon
	// as screenshots are available, without waiting for all other Phase B
	// scanners (crawler, jwt, cors, nuclei, etc.) to complete.
	screenshotDone := make(chan struct{})
	screenshotScheduled := false

	for _, name := range plan.Scanners {
		if phaseADone[name] {
			continue // already ran in Phase A
		}
		skipReason := scannerSkipReason(name, scanType, noHTTP, behindWAF, wafVendor, originIP, httpDependentScanners, m.scanners, svcClass)
		if skipReason != "" {
			m.saveSkipMetric(ctx, scanRunID, asset, name, skipReason)
			continue
		}
		name, scanner := name, m.scanners[name]
		isScreenshot := name == "screenshot"
		if isScreenshot {
			screenshotScheduled = true
		}
		if progressFn != nil {
			cmd := scannerCmd(name, asset, scanType)
			if name == "assetintel" {
				if ai, ok := scanner.(*assetintel.Scanner); ok {
					sources := ai.ActiveSources()
					cmd = strings.Join(sources, " + ") + " → " + asset
				}
			}
			progressFn(module.ProgressEvent{
				Phase:       "scanner_start",
				ActiveAsset: asset,
				ScannerName: name,
				ScannerCmd:  cmd,
			})
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Apply inter-scanner jitter when evasion is configured.
			// Each goroutine sleeps a random [0, MaxJitterMs] ms before
			// starting its HTTP requests, spreading load over time.
			if jitter != nil {
				jitter.Jitter(ctx)
			}
			// Resolve the effective scanner — some scanners need per-asset
			// state (aillm evidence, autoprobe emails, origin IP routing).
			var effectiveScanner = scanner
			if name == "aillm" && len(ev.AIEndpoints) > 0 {
				effectiveScanner = aillm.NewWithEvidence(&ev)
			} else if name == "autoprobe" {
				m.harvesterEmailsMu.Lock()
				emails := m.harvesterEmails
				m.harvesterEmailsMu.Unlock()
				effectiveScanner = autoprobe.NewWithEmails(emails)
			}
			// Execute with panic recovery, timing, and structured result.
			var result *scan.Result
			if originSc, ok := effectiveScanner.(sc.OriginScanner); ok && originIP != "" {
				// OriginScanner uses a different method — wrap manually.
				result = scan.Execute(scan.AdaptFunc(name, func(ctx2 context.Context, a string, st module.ScanType) ([]finding.Finding, error) {
					return originSc.RunWithOriginIP(ctx2, a, originIP, st)
				}), ctx, asset, scanType)
			} else {
				result = scan.Execute(effectiveScanner, ctx, asset, scanType)
			}
			fs := result.Findings
			// Cache harvester emails for use by autoprobe on this and future assets.
			if name == "harvester" && len(fs) > 0 {
				for _, f := range fs {
					if f.CheckID == finding.CheckHarvesterEmails {
						if raw, ok := f.Evidence["emails"]; ok {
							switch v := raw.(type) {
							case []string:
								m.harvesterEmailsMu.Lock()
								m.harvesterEmails = v
								m.harvesterEmailsMu.Unlock()
							case []interface{}:
								emails := make([]string, 0, len(v))
								for _, item := range v {
									if s, ok := item.(string); ok {
										emails = append(emails, s)
									}
								}
								m.harvesterEmailsMu.Lock()
								m.harvesterEmails = emails
								m.harvesterEmailsMu.Unlock()
							}
						}
					}
				}
			}
			mu.Lock()
			findings = append(findings, fs...)
			mu.Unlock()
			m.saveScanMetricElapsed(ctx, scanRunID, asset, name, result.Metrics.Duration, fs, result.Error)
			if progressFn != nil && len(fs) > 0 {
				// Deep-copy fs before passing to the progress callback so that
				// the renderer's accumulated slice cannot alias the scanner's
				// local slice (which may be reallocated later).
				fsCopy := make([]finding.Finding, len(fs))
				copy(fsCopy, fs)
				progressFn(module.ProgressEvent{
					Phase:        "scanner_done",
					ActiveAsset:  asset,
					ScannerName:  name,
					FindingDelta: len(fs),
					NewFindings:  fsCopy,
				})
			}
			if isScreenshot {
				close(screenshotDone)
			}
		}()
	}
	// If screenshot was not scheduled (skipped or not in plan), close the
	// channel immediately so the DLP goroutine is not blocked.
	if !screenshotScheduled {
		close(screenshotDone)
	}

	// Dirbust — concurrent with Phase B scanners.
	// Depends only on classify evidence + playbook data (computed pre-Phase-B).
	if isDeepOrAuthorized(scanType) && len(dirbustPaths) > 0 && !noHTTP {
		wg.Add(1)
		go func() {
			defer wg.Done()
			db := dirbust.NewWithFfuf(m.ffufBin)
			db.SetFramework(ev.Framework)
			db.SetRecurse(true)
			dbFindings := db.Run(ctx, asset, dirbustPaths)
			mu.Lock()
			findings = append(findings, dbFindings...)
			mu.Unlock()
		}()
	}

	// IPv6 portscan: if classify found an AAAA record, run a portscan against
	// the IPv6 address concurrently with Phase B scanners.
	if ev.IPv6 != "" {
		if ps, ok := m.scanners["portscan"]; ok {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ipv6Findings, _ := ps.Run(ctx, ev.IPv6, scanType)
				mu.Lock()
				findings = append(findings, ipv6Findings...)
				mu.Unlock()
			}()
		}
	}

	// DLP Vision — waits only for the screenshot scanner, then runs concurrently
	// with remaining Phase B scanners (nuclei, crawler, jwt, etc.).
	// Depends solely on screenshot findings; no need to block on the full wg.
	if m.anthropicKey != "" {
		matchedCount := len(matched)
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case <-screenshotDone:
			}
			mu.Lock()
			snap := make([]finding.Finding, len(findings))
			copy(snap, findings)
			mu.Unlock()

			visionFindings := dlp.AnalyzeScreenshots(ctx, snap, m.anthropicKey)
			if len(visionFindings) > 0 {
				mu.Lock()
				findings = append(findings, visionFindings...)
				mu.Unlock()
			}
			if matchedCount <= 1 {
				mu.Lock()
				snap2 := make([]finding.Finding, len(findings))
				copy(snap2, findings)
				mu.Unlock()
				if vf := dlp.IdentifyServiceFromScreenshot(ctx, asset, snap2, m.anthropicKey); vf != nil {
					mu.Lock()
					findings = append(findings, *vf)
					mu.Unlock()
				}
			}
		}()
	}

	// Nuclei — concurrent with Phase B scanners.
	// Tags: playbook base + deep + version-derived + port-service-derived.
	// Port-service tags (e.g. "redis","elasticsearch") fire service-specific CVE
	// and misconfiguration templates that the playbook may not know to include.
	tags := plan.NucleiTagsSurf
	if isDeepOrAuthorized(scanType) {
		tags = append(tags, plan.NucleiTagsDeep...)
	}
	tags = append(tags, classify.VersionNucleiTags(ev)...)
	tags = append(tags, portscan.ServiceNucleiTags(openPorts)...)
	tags = sanitizeNucleiTags(tags)
	if len(tags) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			nucleiStart := time.Now()
			fs, nucleiErr := m.nucleiScanner.RunWithTags(ctx, asset, tags)
			mu.Lock()
			findings = append(findings, fs...)
			mu.Unlock()
			m.saveScanMetricElapsed(ctx, scanRunID, asset, "nuclei", time.Since(nucleiStart), fs, nucleiErr)
		}()
	}

	wg.Wait()

	// ── AI-classified unknown technology finding ──────────────────────────────
	// Emitted when deterministic rules couldn't classify the asset and AI was
	// used. Alerts analysts to review the proposed fingerprint rule.
	if aifpUnknownFinding != nil {
		findings = append(findings, *aifpUnknownFinding)
	}

	// ── Parameter discovery from crawl results + native brute-force ─────────
	// Extract URLs from crawler findings and discover parameters from URL query
	// strings so web vuln scanners triggered in the convergence loop (sqli, ssrf,
	// cmdinj, ssti, xxe, pathtraversal) can probe discovered parameters alongside
	// their hardcoded lists. Runs after Phase B (crawler has finished) and before
	// the convergence loop (web vuln scanners may be triggered there).
	//
	// Also runs native Arjun-style brute-force param discovery on the asset root
	// so injection scanners have discovered params even when crawl results are
	// sparse.
	{
		allParams := make(map[string][]string)

		// 1. Extract params from crawl result URLs.
		var crawlURLs []string
		for _, f := range findings {
			if f.CheckID != finding.CheckAssetCrawlEndpoints {
				continue
			}
			switch v := f.Evidence["endpoints"].(type) {
			case []string:
				crawlURLs = append(crawlURLs, v...)
			case []interface{}:
				for _, item := range v {
					if s, ok := item.(string); ok {
						crawlURLs = append(crawlURLs, s)
					}
				}
			}
		}
		if len(crawlURLs) > 0 {
			for path, params := range paramdiscovery.ExtractFromURLs(crawlURLs) {
				allParams[path] = params
			}
		}

		// 2. Native brute-force param discovery on asset root (deep/authorized only).
		if isDeepOrAuthorized(scanType) && !noHTTP {
			nativeClient := &http.Client{Timeout: 10 * time.Second}
			if authctx.IsAuthenticated(ctx) {
				nativeClient = authctx.HTTPClient(ctx)
			}
			base := schemedetect.Base(ctx, nativeClient, asset)
			nativeFound := paramdiscovery.DiscoverParams(ctx, nativeClient, base+"/", "GET")
			if len(nativeFound) > 0 {
				var names []string
				for _, p := range nativeFound {
					names = append(names, p.Name)
				}
				existing := allParams["/"]
				merged := mergeParamNames(existing, names)
				allParams["/"] = merged
			}
		}

		if len(allParams) > 0 {
			ctx = paramdiscovery.WithDiscoveredParams(ctx, allParams)
		}
	}

	// ── Evidence convergence loop ─────────────────────────────────────────────
	// After Phase B completes, extract new check IDs from findings and re-match
	// playbooks. Run any newly matched scanners that haven't run yet. Also runs
	// AI-suggested scanners on the first round.
	//
	// This handles late-discovered tech signals, e.g.:
	//   crawler finds /graphql → graphql scanner triggered
	//   jwt scanner finds Cognito tokens → aillm scanner triggered
	//   webcontent finds Spring error page → depconf scanner triggered
	//
	// Converges in at most maxConvergenceRounds passes (usually 1).
	{
		const maxConvergenceRounds = 3
		ranScanners := make(map[string]bool, len(phaseADone)+len(plan.Scanners))
		for name := range phaseADone {
			ranScanners[name] = true
		}
		for _, name := range plan.Scanners {
			ranScanners[name] = true
		}

		for round := 0; round < maxConvergenceRounds; round++ {
			// Collect check IDs from findings that aren't in ev.PhaseACheckIDs yet.
			mu.Lock()
			existingIDSet := make(map[string]bool, len(ev.PhaseACheckIDs))
			for _, id := range ev.PhaseACheckIDs {
				existingIDSet[id] = true
			}
			var newCheckIDs []string
			for _, f := range findings {
				id := string(f.CheckID)
				if id != "" && !existingIDSet[id] {
					newCheckIDs = append(newCheckIDs, id)
					existingIDSet[id] = true
				}
			}
			mu.Unlock()

			var newScanners []string
			seen := map[string]bool{}

			// (a) Re-match playbooks with newly discovered check IDs.
			if len(newCheckIDs) > 0 {
				ev.PhaseACheckIDs = append(ev.PhaseACheckIDs, newCheckIDs...)
				for _, pb := range reg.Match(ev) {
					for _, s := range playbook.BuildRunPlan([]*playbook.Playbook{pb}).Scanners {
						if !ranScanners[s] && !seen[s] {
							newScanners = append(newScanners, s)
							seen[s] = true
						}
					}
				}
			}

			// (b) AI-suggested scanners — first round only.
			if round == 0 {
				for _, name := range aifpSuggestedScanners {
					if !ranScanners[name] && !seen[name] {
						if _, ok := m.scanners[name]; ok {
							newScanners = append(newScanners, name)
							seen[name] = true
						}
					}
				}
			}

			if len(newScanners) == 0 {
				break // stable — no new scanners to run
			}

			for _, name := range newScanners {
				ranScanners[name] = true
			}

			var convWg sync.WaitGroup
			for _, name := range newScanners {
				convScanner, ok := m.scanners[name]
				if !ok {
					continue
				}
				skipReason := scannerSkipReason(name, scanType, noHTTP, behindWAF, wafVendor, originIP, httpDependentScanners, m.scanners, svcClass)
				if skipReason != "" {
					m.saveSkipMetric(ctx, scanRunID, asset, name, skipReason)
					continue
				}
				name, convScanner := name, convScanner
				convWg.Add(1)
				go func() {
					defer convWg.Done()
					// Mirror the same special-cases as Phase B to ensure convergence
					// scanners get the same context (AI endpoints, harvester emails,
					// origin IP) that Phase B scanners receive.
					var effectiveScanner = convScanner
					switch {
					case name == "aillm" && len(ev.AIEndpoints) > 0:
						effectiveScanner = aillm.NewWithEvidence(&ev)
					case name == "autoprobe":
						m.harvesterEmailsMu.Lock()
						emails := m.harvesterEmails
						m.harvesterEmailsMu.Unlock()
						effectiveScanner = autoprobe.NewWithEmails(emails)
					}
					var result *scan.Result
					if originSc, ok := effectiveScanner.(sc.OriginScanner); ok && originIP != "" {
						result = scan.Execute(scan.AdaptFunc(name, func(ctx2 context.Context, a string, st module.ScanType) ([]finding.Finding, error) {
							return originSc.RunWithOriginIP(ctx2, a, originIP, st)
						}), ctx, asset, scanType)
					} else {
						result = scan.Execute(effectiveScanner, ctx, asset, scanType)
					}
					mu.Lock()
					findings = append(findings, result.Findings...)
					mu.Unlock()
					m.saveScanMetricElapsed(ctx, scanRunID, asset, name, result.Metrics.Duration, result.Findings, result.Error)
				}()
			}
			convWg.Wait()

			// After each convergence round: refresh dynamic evidence signals from
			// new findings so subsequent rounds use up-to-date context.
			mu.Lock()
			convFindings := make([]finding.Finding, len(findings))
			copy(convFindings, findings)
			mu.Unlock()
			// Refresh AI endpoints discovered by aidetect if it ran in convergence.
			if eps := extractAIEndpoints(convFindings); len(eps) > 0 {
				ev.AIEndpoints = eps
			}
			// Refresh origin IP if a new wafdetect finding arrived.
			if newOrigin := extractOriginIP(convFindings); newOrigin != "" {
				originIP = newOrigin
			}
			if newBehindWAF, newVendor := extractWAFInfo(convFindings); newBehindWAF {
				behindWAF = true
				if wafVendor == "" {
					wafVendor = newVendor
				}
			}
		}
	}

	// ── Evasion monitor findings ─────────────────────────────────────────────
	// Collect any IDS/WAF/rate-limit detections the monitor observed during all
	// scanner phases and append them to the findings list.
	if monitorFindings := evasionMonitor.Findings(); len(monitorFindings) > 0 {
		findings = append(findings, monitorFindings...)
	}

	// ── Post-scan classify helpers (after wg.Wait — no concurrent writes) ─────
	// Run after goroutines finish to avoid data races on the findings slice.
	findings = append(findings, classify.CheckVersions(ev, asset)...)
	findings = append(findings, classify.CheckOSVVersions(ctx, ev, asset)...)
	if tf := classify.EmitTechStackFinding(ev, asset); tf != nil {
		findings = append(findings, *tf)
	}
	if df := classify.EmitDNSIntelFinding(ev, asset); df != nil {
		findings = append(findings, *df)
	}
	if jf := classify.EmitJARMFinding(ev, asset); jf != nil {
		findings = append(findings, *jf)
	}

	// Extract dirbust-found paths for the audit record.
	// Dirbust ran concurrently in Phase B; its findings are already in the slice.
	var dirbustPathsFound []string
	for _, f := range findings {
		if f.CheckID == finding.CheckDirbustFound {
			title := f.Title
			const prefix = "Path found: "
			if len(title) > len(prefix) {
				rest := title[len(prefix):]
				if i := strings.LastIndexByte(rest, ' '); i > 0 {
					dirbustPathsFound = append(dirbustPathsFound, rest[:i])
				}
			}
		}
	}

	// ── Parallel expansion scanning ───────────────────────────────────────────
	// Collect all depth+1 candidates from four sources:
	//   1. Port-service discoveries (Grafana :3000, Kibana :5601, etc.)
	//   2. TLS cert SANs that are new subdomains of rootDomain
	//   3. Subdomains extracted from page body/redirects
	//   4. Playbook-driven discovery steps
	// All candidates are dispatched concurrently (bounded by expandSem) so a
	// cert with 20 SANs doesn't block behind a sequential 120-second scan chain.
	// Only runs at depth 0 to prevent infinite recursion.
	if depth == 0 {
		// Collect candidates, claiming each in the shared expandSeen map atomically
		// so concurrent parent goroutines don't double-scan the same child asset.
		claimExpand := func(candidate string) bool {
			expandSeenMu.Lock()
			defer expandSeenMu.Unlock()
			if expandSeen[candidate] {
				return false
			}
			expandSeen[candidate] = true
			return true
		}

		var expandCandidates []string

		// Source 1: port services
		for _, f := range findings {
			if f.CheckID != finding.CheckPortServiceDiscovered {
				continue
			}
			portAsset, _ := f.Evidence["port_asset"].(string)
			if portAsset == "" || !claimExpand(portAsset) {
				continue
			}
			expandCandidates = append(expandCandidates, portAsset)
		}

		// Source 2: CertSANs
		for _, san := range ev.CertSANs {
			san = strings.TrimPrefix(san, "*.")
			if san == rootDomain || !strings.HasSuffix(san, "."+rootDomain) || !isValidHostname(san) {
				continue
			}
			if claimExpand(san) {
				expandCandidates = append(expandCandidates, san)
			}
		}

		// Source 3: body-discovered subdomains (cap at 10)
		bodyCount := 0
		for _, sub := range ev.SubdomainsInBody {
			if bodyCount >= 10 {
				break
			}
			if !isValidHostname(sub) || !strings.HasSuffix(sub, "."+rootDomain) {
				continue
			}
			if claimExpand(sub) {
				expandCandidates = append(expandCandidates, sub)
				bodyCount++
			}
		}

		// Source 4: playbook discovery steps
		for _, expandedAsset := range expandedAssets {
			if claimExpand(expandedAsset) {
				expandCandidates = append(expandCandidates, expandedAsset)
			}
		}

		// Source 5: OpenAPI/Swagger endpoint list feeds dirbust
		// When an API docs finding carries an "endpoints" list (e.g. parsed from
		// the spec by the exposedfiles or autoprobe scanner), add those paths to
		// ev.RespondingPaths so the audit record and any subsequent tooling can
		// reference them without re-parsing the spec.
		for _, f := range findings {
			if f.CheckID == finding.CheckExposureAPIDocs {
				if paths, ok := f.Evidence["endpoints"].([]string); ok {
					ev.RespondingPaths = append(ev.RespondingPaths, paths...)
				}
			}
		}

		// Source 6: CDN/WAF bypass origin IP → scan origin directly
		// When wafdetect or cdnbypass confirms a reachable origin IP behind a CDN
		// or WAF, scanning the origin directly is far more productive than scanning
		// the edge node. Add the raw IP (with optional non-standard port) as an
		// expand candidate so it gets its own full runAsset pass.
		for _, f := range findings {
			if f.CheckID == finding.CheckWAFOriginExposed || f.CheckID == finding.CheckCDNOriginFound {
				if originIP, ok := f.Evidence["origin_ip"].(string); ok && originIP != "" {
					originAsset := originIP
					if portStr, ok := f.Evidence["origin_port"].(string); ok && portStr != "" && portStr != "443" && portStr != "80" {
						originAsset = originIP + ":" + portStr
					}
					if claimExpand(originAsset) {
						expandCandidates = append(expandCandidates, originAsset)
					}
				}
			}
		}

		// Source 7: GraphQL confirmed endpoints → ensure in RespondingPaths
		// GraphQL scanners confirm the exact endpoint path (e.g. "/graphql",
		// "/v1/graphql"). Appending to RespondingPaths ensures the audit record
		// reflects these paths and they participate in path-responds playbook
		// matching on any follow-up scan.
		for _, f := range findings {
			if strings.HasPrefix(string(f.CheckID), "graphql.") {
				if ep, ok := f.Evidence["endpoint"].(string); ok && ep != "" {
					ev.RespondingPaths = append(ev.RespondingPaths, ep)
				}
			}
		}

		// Source 8: Cross-origin JS hosts that are subdomains of rootDomain
		// The webcontent scanner records the hosting domain of external JS files
		// in the "hosted_on" evidence field. When that domain is a subdomain of
		// rootDomain it is in scope and warrants its own asset scan.
		for _, f := range findings {
			if f.CheckID != finding.CheckJSHardcodedSecret &&
				f.CheckID != finding.CheckJSInternalEndpoint &&
				f.CheckID != finding.CheckJSSourceMapExposed {
				continue
			}
			if hostedOn, ok := f.Evidence["hosted_on"].(string); ok && hostedOn != "" {
				if strings.HasSuffix(hostedOn, "."+rootDomain) && isValidHostname(hostedOn) {
					if claimExpand(hostedOn) {
						expandCandidates = append(expandCandidates, hostedOn)
					}
				}
			}
		}

		// Source 9: API version paths discovered by apiversions scanner
		// apiversions confirms that /v1/, /v2/, /api/beta/, etc. respond with
		// non-404 API content. Adding them to RespondingPaths ensures the audit
		// record reflects these paths and they participate in path_responds
		// playbook matching on subsequent scans.
		for _, f := range findings {
			if f.CheckID != finding.CheckExposureAPIVersion {
				continue
			}
			if path, ok := f.Evidence["path"].(string); ok && path != "" {
				ev.RespondingPaths = append(ev.RespondingPaths, path)
			}
		}

		// Dispatch all candidates concurrently, bounded at 5 parallel depth+1 scans.
		const maxExpandConcurrent = 5
		expandSemCh := make(chan struct{}, maxExpandConcurrent)
		var expandWg sync.WaitGroup
		var expandMu sync.Mutex
		for _, candidate := range expandCandidates {
			candidate := candidate
			expandSemCh <- struct{}{}
			expandWg.Add(1)
			go func() {
				defer expandWg.Done()
				defer func() { <-expandSemCh }()
				fs := m.runAsset(ctx, candidate, rootDomain, scanType, scanRunID, depth+1, progressFn, expandSeen, expandSeenMu)
				expandMu.Lock()
				findings = append(findings, fs...)
				expandMu.Unlock()
			}()
		}
		expandWg.Wait()
	}

	// Write audit record
	if m.st != nil && scanRunID != "" {
		// Persist this asset's findings immediately so they survive if the process
		// is killed before the scan completes. main.go also calls SaveFindings at
		// the end — the store must be idempotent on duplicate check_id+asset pairs.
		if len(findings) > 0 {
			_ = m.st.SaveFindings(ctx, scanRunID, findings)
		}
		playbooks := make([]string, 0, len(matched))
		for _, p := range matched {
			playbooks = append(playbooks, p.Name)
		}

		// Log unmatched assets (only baseline matched = no targeted playbook)
		if len(matched) <= 1 { // only baseline
			fp := assetFingerprint(ev)
			exists, _ := m.st.FingerprintExists(ctx, fp)
			if !exists {
				_ = m.st.SaveUnmatchedAsset(ctx, &store.UnmatchedAsset{
					ScanRunID:   scanRunID,
					Fingerprint: fp,
					Asset:       asset,
					Evidence:    ev,
				})
			}
		}

		// Enrich evidence from Phase B findings so downstream consumers
		// (reports, AI enrichment, TUI asset detail) see the full picture.
		enrichEvidenceFromFindings(&ev, findings)

		_ = m.st.SaveAssetExecution(ctx, &store.AssetExecution{
			ScanRunID:         scanRunID,
			Asset:             asset,
			Evidence:          ev,
			MatchedPlaybooks:  playbooks,
			ScannersRun:       plan.Scanners,
			NucleiTagsRun:     tags,
			DirbustPathsRun:   dirbustPaths,
			DirbustPathsFound: dirbustPathsFound,
			FindingsCount:     len(findings),
			CreatedAt:         time.Now(),
		})
	}

	// Auto-upload findings to vulndb if configured.
	// This populates the database with every scan's results automatically:
	// fingerprints, findings, verified payloads, credentials, topology.
	if m.vulndbURL != "" {
		go func() {
			vc := vulndb.NewClient(m.vulndbURL)
			if err := func() error { b, err := json.Marshal(findings); if err != nil { return err }; return vc.UploadFindings(rootDomain, b) }(); err != nil {
				// Non-fatal — vulndb may not be running
				_ = err
			}
			// Save fingerprints from classify/detection findings
			for _, f := range findings {
				if svc, ok := f.Evidence[finding.EvidenceService].(string); ok && svc != "" {
					ver, _ := f.Evidence[finding.EvidenceVersion].(string)
					_ = vc.SaveFingerprint(vulndb.ServiceFingerprint{
						Domain:  rootDomain,
						Service: svc,
						Version: ver,
						LastSeen: time.Now(),
					})
				}
			}
			// Save verified payloads
			for _, f := range findings {
				if f.Confidence == finding.ConfidenceVerified {
					svc, _ := f.Evidence[finding.EvidenceService].(string)
					ver, _ := f.Evidence[finding.EvidenceVersion].(string)
					if svc != "" {
						_ = vc.SavePayload(vulndb.VerifiedPayload{
							Service:    svc,
							Version:    ver,
							VulnClass:  string(f.CheckID),
							CVEID:      fmt.Sprintf("%v", f.Evidence["cve_id"]),
							Payload:    fmt.Sprintf("%v", f.Evidence[finding.EvidencePayload]),
							ProofCommand:   f.ProofCommand,
							Confidence: f.Confidence,
						})
					}
				}
			}
		}()
	}

	return findings
}

// runDiscovery executes discovery steps from matched playbooks, returning
// any additional assets to scan.
func (m *Module) runDiscovery(ctx context.Context, asset, rootDomain string, matched []*playbook.Playbook, scanType module.ScanType) []string {
	var extra []string
	seen := map[string]bool{asset: true, rootDomain: true}

	for _, p := range matched {
		for _, step := range p.Discovery {
			switch step.Type {
			case "probe_subdomains":
				for _, pattern := range step.Patterns {
					host := expandPattern(pattern, rootDomain)
					if !seen[host] {
						seen[host] = true
						extra = append(extra, host)
					}
				}
			case "historical_dns":
				// Already handled by historicalurls scanner in baseline
			case "s3_buckets":
				// Already handled by cloudbuckets scanner in baseline
			}
		}
	}
	return extra
}

// expandPattern replaces {domain} in a pattern with the root domain.
func expandPattern(pattern, domain string) string {
	return strings.ReplaceAll(pattern, "{domain}", domain)
}

// isValidHostname returns true if s is a valid RFC 1123 hostname safe to
// pass as a command-line argument to subprocesses (nuclei, subfinder, amass).
// Rejects strings containing shell metacharacters, argument-injection prefixes
// (e.g. "--config"), null bytes, or labels that violate DNS rules.
// enumerateAndProbeRanges takes a list of CIDR strings, enumerates up to
// maxIPsPerScan IPs, and HTTP-probes each one. Returns IPs that respond on
// port 80 or 443.
func enumerateAndProbeRanges(ctx context.Context, cidrs []string) []string {
	const maxIPs = 4096
	const concurrency = 20

	var mu sync.Mutex
	var liveIPs []string
	seen := map[string]bool{}

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	client := &http.Client{
		Timeout: 3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	probe := func(ip string) {
		for _, scheme := range []string{"https", "http"} {
			url := scheme + "://" + ip
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				continue
			}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode <= 599 {
				mu.Lock()
				if !seen[ip] {
					seen[ip] = true
					liveIPs = append(liveIPs, ip)
				}
				mu.Unlock()
				return
			}
		}
	}

	total := 0
outer:
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		ip := cloneIPv4(ipNet.IP.To4())
		if ip == nil {
			continue
		}
		for ipNet.Contains(ip) {
			if total >= maxIPs {
				break outer
			}
			total++
			ipStr := ip.String()
			// Acquire semaphore before spawning to bound goroutine count.
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				break outer
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				probe(ipStr)
			}()
			incrementNetIP(ip)
		}
	}
	wg.Wait()
	return liveIPs
}

// cloneIPv4 returns a copy of the IPv4 net.IP, or nil for IPv6.
func cloneIPv4(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	clone := make(net.IP, len(ip))
	copy(clone, ip)
	return clone
}

// incrementNetIP increments an IPv4 net.IP in-place.
func incrementNetIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func isValidHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for i, c := range label {
			switch {
			case c >= 'a' && c <= 'z':
			case c >= 'A' && c <= 'Z':
			case c >= '0' && c <= '9':
			case c == '-':
				if i == 0 || i == len(label)-1 {
					return false // hyphens not allowed at label boundaries
				}
			default:
				return false // reject anything that isn't alnum or hyphen
			}
		}
	}
	return true
}

// assetFingerprint produces a short hash of key evidence fields for dedup.
func assetFingerprint(e playbook.Evidence) string {
	key := e.ASNOrg + "|" + e.DNSSuffix + "|" + e.Title
	h := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%x", h[:8])
}

// buildScannedPorts returns the set of port numbers already covered by the
// static portscan port lists. Used to deduplicate AI-suggested ports.
func buildScannedPorts() map[int]bool {
	out := make(map[int]bool)
	for _, e := range portscan.AllKnownPorts() {
		out[e] = true
	}
	return out
}

// probeExtraPorts runs a targeted TCP connect probe against the given ports on
// the asset. For any port that's open and hosts an HTTP service, it schedules
// a classify pass and returns findings.
func probeExtraPorts(ctx context.Context, asset string, ports []int) []finding.Finding {
	var findings []finding.Finding
	for _, port := range ports {
		portAsset := fmt.Sprintf("%s:%d", asset, port)
		ev := classify.Collect(ctx, portAsset)
		if ev.StatusCode == 0 {
			continue // port closed or no HTTP service
		}
		// Emit a port-service-discovered finding so the result is visible.
		f := finding.Finding{
			CheckID:  finding.CheckPortServiceDiscovered,
			Module:   "surface",
			Scanner:  "portadvisor",
			Severity: finding.SeverityInfo,
			Asset:    asset,
			Title:    fmt.Sprintf("AI-suggested service found on %s port %d", asset, port),
			Description: fmt.Sprintf(
				"The AI port advisor suggested probing port %d based on detected tech stack. "+
					"An HTTP service responded (status %d), indicating a service not in the default port list.",
				port, ev.StatusCode,
			),
			Evidence: map[string]any{
				"port":       port,
				"port_asset": portAsset,
				"status":     ev.StatusCode,
				"title":      ev.Title,
			},
			DiscoveredAt: time.Now(),
		}
		findings = append(findings, f)
	}
	return findings
}

// buildHintsFromFindings constructs AssetHints from accumulated scan findings
// without making any additional network probes. Used to build the richest
// possible context for the AI discovery advisor after a full scan round.
func buildHintsFromFindings(assets []string, findings []finding.Finding) []analyze.AssetHint {
	// Group finding titles by asset for quick lookup.
	byAsset := make(map[string][]finding.Finding, len(assets))
	for _, f := range findings {
		byAsset[f.Asset] = append(byAsset[f.Asset], f)
	}

	hints := make([]analyze.AssetHint, 0, len(assets))
	for _, asset := range assets {
		hint := analyze.AssetHint{Hostname: asset}

		for _, f := range byAsset[asset] {
			switch {
			case f.CheckID == finding.CheckWebTechDetected:
				// Tech stack finding — extract version strings from title.
				hint.TechStack = append(hint.TechStack, f.Title)

			case f.Scanner == "portscan":
				// Compact port summary: "6379/redis", "9200/elasticsearch".
				if port, ok := f.Evidence["port"]; ok {
					if svc, ok2 := f.Evidence["service"]; ok2 {
						hint.OpenPorts = append(hint.OpenPorts,
							fmt.Sprintf("%v/%v", port, svc))
					}
				}

			case f.Severity >= finding.SeverityHigh:
				// High/Critical findings give the AI strong signals about what
				// services and misconfigurations exist on this host.
				if len(hint.KeyFindings) < 8 { // cap to keep prompt bounded
					hint.KeyFindings = append(hint.KeyFindings, f.Title)
				}
			}
		}

		hints = append(hints, hint)
	}
	return hints
}

// ── Phase A/B scan helpers ────────────────────────────────────────────────────

// sanitizeNucleiTags returns only tags that are safe to pass to the nuclei -tags
// flag: lowercase alphanumeric, hyphens, and dots. Invalid tags are silently
// dropped to prevent command injection via AI-suggested or port-derived tag values.
func sanitizeNucleiTags(tags []string) []string {
	out := make([]string, 0, len(tags))
	for _, tag := range tags {
		ok := true
		for _, ch := range tag {
			if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '-' && ch != '.' {
				ok = false
				break
			}
		}
		if ok && tag != "" {
			out = append(out, tag)
		}
	}
	return out
}

// planContains reports whether name appears in the scanner list.
// authConfigMatchesAsset returns true if any AuthConfig explicitly targets the
// given asset (exact match or wildcard). Used to skip the auto-auth pipeline
// when the user already provided credentials.
func authConfigMatchesAsset(cfgs []config.AuthConfig, asset string) bool {
	for _, c := range cfgs {
		if c.Asset == asset || c.Asset == "*" {
			return true
		}
	}
	return false
}

func planContains(scanners []string, name string) bool {
	for _, s := range scanners {
		if s == name {
			return true
		}
	}
	return false
}

// extractOriginIP returns the real backend IP discovered by wafdetect, or ""
// if origin exposure was not detected in Phase A findings.
func extractOriginIP(findings []finding.Finding) string {
	for _, f := range findings {
		if f.CheckID == finding.CheckWAFOriginExposed {
			ip, _ := f.Evidence["origin_ip"].(string)
			return ip
		}
	}
	return ""
}

// extractWAFInfo inspects Phase A findings for WAF/CDN detection.
// Returns (true, vendor) when a WAF was detected; ("", false) otherwise.
func extractWAFInfo(findings []finding.Finding) (bool, string) {
	for _, f := range findings {
		if f.CheckID == finding.CheckWAFDetected {
			vendor, _ := f.Evidence["vendor"].(string)
			return true, vendor
		}
	}
	return false, ""
}

// extractIDSVendor inspects Phase A findings for IDS/NGFW detection.
func extractIDSVendor(findings []finding.Finding) string {
	for _, f := range findings {
		if f.CheckID == finding.CheckIDSDetected {
			vendor, _ := f.Evidence["vendor"].(string)
			return vendor
		}
	}
	return ""
}

// extractOpenPorts inspects Phase A findings for open TCP ports.
// Returns a map of port number → service name (e.g. 6379 → "redis").
func extractOpenPorts(findings []finding.Finding) map[int]string {
	ports := make(map[int]string)
	for _, f := range findings {
		if f.Scanner != "portscan" {
			continue
		}
		var port int
		switch v := f.Evidence["port"].(type) {
		case int:
			port = v
		case float64:
			port = int(v) // JSON round-trip stores numbers as float64
		default:
			continue
		}
		service, _ := f.Evidence["service"].(string)
		ports[port] = service
	}
	return ports
}

// extractCrawlHostnames scans all crawler findings across allFindings and returns
// new subdomains of rootDomain that were linked from crawled pages but not yet in seen.
// Limited to valid hostnames that differ from already-known assets.
func extractCrawlHostnames(rootDomain string, allFindings []finding.Finding, seen map[string]struct{}) []string {
	var candidates []string
	visited := make(map[string]bool)
	suffix := "." + rootDomain

	for _, f := range allFindings {
		if f.CheckID != finding.CheckAssetCrawlEndpoints {
			continue
		}
		// Handle both in-memory []string and JSON-deserialized []interface{} forms.
		var endpoints []string
		switch v := f.Evidence["endpoints"].(type) {
		case []string:
			endpoints = v
		case []interface{}:
			for _, item := range v {
				if s, ok := item.(string); ok {
					endpoints = append(endpoints, s)
				}
			}
		}
		for _, u := range endpoints {
			// Extract host from URL — accept "https://host/path" and "http://host/path"
			rest := u
			if strings.HasPrefix(rest, "https://") {
				rest = rest[len("https://"):]
			} else if strings.HasPrefix(rest, "http://") {
				rest = rest[len("http://"):]
			} else {
				continue
			}
			// Strip path/query/fragment
			if i := strings.IndexByte(rest, '/'); i >= 0 {
				rest = rest[:i]
			}
			if i := strings.IndexByte(rest, '?'); i >= 0 {
				rest = rest[:i]
			}
			// Strip port suffix if present
			if h, _, found := strings.Cut(rest, ":"); found {
				rest = h
			}
			host := strings.ToLower(rest)
			if visited[host] {
				continue
			}
			visited[host] = true
			if _, ok := seen[host]; ok {
				continue
			}
			if host == rootDomain || !strings.HasSuffix(host, suffix) {
				continue
			}
			if !isValidHostname(host) {
				continue
			}
			candidates = append(candidates, host)
		}
	}
	return candidates
}

// extractHarvesterSubdomains collects subdomains discovered by theHarvester
// OSINT scanner that are not already in seen. Only returns hostnames that are
// valid subdomains of rootDomain to prevent scanning unrelated external hosts.
func extractHarvesterSubdomains(rootDomain string, allFindings []finding.Finding, seen map[string]struct{}) []string {
	var candidates []string
	visited := make(map[string]bool)
	suffix := "." + rootDomain

	for _, f := range allFindings {
		if f.CheckID != finding.CheckHarvesterSubdomains {
			continue
		}
		var subs []string
		switch v := f.Evidence["subdomains"].(type) {
		case []string:
			subs = v
		case []interface{}:
			for _, item := range v {
				if s, ok := item.(string); ok {
					subs = append(subs, s)
				}
			}
		}
		for _, sub := range subs {
			host := strings.ToLower(strings.TrimSpace(sub))
			if visited[host] {
				continue
			}
			visited[host] = true
			if _, ok := seen[host]; ok {
				continue
			}
			if host == rootDomain || !strings.HasSuffix(host, suffix) {
				continue
			}
			if !isValidHostname(host) {
				continue
			}
			candidates = append(candidates, host)
		}
	}
	return candidates
}

// extractAIEndpoints collects confirmed AI endpoint paths from aidetect findings.
// These are passed to aillm so it targets only known-good paths instead of
// guessing from a generic default list.
func extractAIEndpoints(findings []finding.Finding) []string {
	var eps []string
	seen := make(map[string]bool)
	for _, f := range findings {
		if f.Scanner != "aidetect" {
			continue
		}
		if path, ok := f.Evidence["path"].(string); ok && path != "" && !seen[path] {
			seen[path] = true
			eps = append(eps, path)
		}
	}
	return eps
}

// enrichEvidenceFromFindings scans all scanner findings and backfills Evidence
// fields that classify couldn't know at fingerprint time. This ensures the
// stored Evidence (used by reports, TUI asset detail, AI enrichment) reflects
// everything discovered during the scan, not just initial fingerprinting.
func enrichEvidenceFromFindings(ev *playbook.Evidence, findings []finding.Finding) {
	for _, f := range findings {
		switch {
		// OAuth / OIDC → auth system
		case strings.HasPrefix(string(f.CheckID), "oauth.") || strings.HasPrefix(string(f.CheckID), "iam."):
			if ev.AuthSystem == "" {
				provider, _ := f.Evidence["provider"].(string)
				if provider != "" {
					ev.AuthSystem = provider
				} else {
					ev.AuthSystem = "oauth"
				}
			}

		// SAML → auth system
		case strings.HasPrefix(string(f.CheckID), "saml."):
			if ev.AuthSystem == "" {
				ev.AuthSystem = "saml"
			}

		// gRPC reflection
		case f.CheckID == finding.CheckPortGRPCReflectionEnabled:
			ev.GRPCReflection = true

		// WebSocket endpoints
		case f.CheckID == finding.CheckWebSocketOpen || f.CheckID == finding.CheckWebSocketCSWSH ||
			f.CheckID == finding.CheckWebSocketNoAuth:
			if endpoint, ok := f.Evidence["endpoint"].(string); ok && endpoint != "" {
				found := false
				for _, ws := range ev.WebSocketEndpoints {
					if ws == endpoint {
						found = true
						break
					}
				}
				if !found {
					ev.WebSocketEndpoints = append(ev.WebSocketEndpoints, endpoint)
				}
			}

		// JS framework detection
		case f.CheckID == finding.CheckJSFrameworkDetected:
			if ev.Framework == "" {
				if fw, ok := f.Evidence["framework"].(string); ok && fw != "" {
					ev.Framework = fw
				}
			}

		// Web3 signals from web3detect (RPC providers, wallet libs, contracts)
		case f.CheckID == finding.CheckWeb3RPCProviderDetected:
			if providers, ok := f.Evidence["providers"].([]string); ok {
				for _, p := range providers {
					if !containsStr(ev.Web3Signals, p) {
						ev.Web3Signals = append(ev.Web3Signals, p)
					}
				}
			}
		case f.CheckID == finding.CheckWeb3WalletLibDetected:
			if libs, ok := f.Evidence["libraries"].([]string); ok {
				for _, lib := range libs {
					if !containsStr(ev.Web3Signals, lib) {
						ev.Web3Signals = append(ev.Web3Signals, lib)
					}
				}
			}
		case f.CheckID == finding.CheckWeb3ContractFound:
			if addrs, ok := f.Evidence["addresses"].([]string); ok {
				for _, addr := range addrs {
					if !containsStr(ev.ContractAddresses, addr) {
						ev.ContractAddresses = append(ev.ContractAddresses, addr)
					}
				}
			}

		// External service references from JS bundles → ExternalServices
		case f.CheckID == finding.CheckJSExternalServiceRef:
			if svc, ok := f.Evidence["service"].(string); ok && svc != "" {
				if !containsStr(ev.ExternalServices, svc) {
					ev.ExternalServices = append(ev.ExternalServices, svc)
				}
			}

		// ── Port service fingerprints → PortServices ──────────────────────
		case f.CheckID == finding.CheckPortServiceIdentified:
			port, _ := f.Evidence["port"].(int)
			if port == 0 {
				break
			}
			if ev.PortServices == nil {
				ev.PortServices = make(map[int]playbook.PortServiceInfo)
			}
			if _, exists := ev.PortServices[port]; !exists {
				svc, _ := f.Evidence["service"].(string)
				ver, _ := f.Evidence["version"].(string)
				product, _ := f.Evidence["product"].(string)
				osHint, _ := f.Evidence["os_hint"].(string)
				banner, _ := f.Evidence["banner"].(string)
				if len(banner) > 256 {
					banner = banner[:256]
				}
				ev.PortServices[port] = playbook.PortServiceInfo{
					Service:  svc,
					Product:  product,
					Version:  ver,
					OSHint:   osHint,
					Banner:   banner,
					Protocol: "tcp",
				}
			}

		// ── Auth weakness signals → CredentialExposures ───────────────────
		case f.CheckID == finding.CheckPortRedisUnauth ||
			f.CheckID == finding.CheckPortMemcachedUnauth ||
			f.CheckID == finding.CheckPortElasticsearchUnauth ||
			f.CheckID == finding.CheckPortCouchDBUnauth:
			svc, _ := f.Evidence["service"].(string)
			if svc == "" {
				svc = string(f.CheckID)
			}
			ev.CredentialExposures = append(ev.CredentialExposures, playbook.CredentialExposure{
				Type:    "no_auth",
				Service: svc,
			})

		case f.CheckID == finding.CheckPortMinIODefaultCreds ||
			f.CheckID == finding.CheckPortGrafanaDefaultCreds ||
			f.CheckID == finding.CheckPortSonarQubeDefaultCreds ||
			f.CheckID == finding.CheckPortAirflowDefaultCreds ||
			f.CheckID == finding.CheckPortTomcatDefaultCreds ||
			f.CheckID == finding.CheckPortPortainerDefaultCreds ||
			f.CheckID == finding.CheckPortRabbitMQDefaultCreds ||
			f.CheckID == finding.CheckPortMSSQLDefaultCreds ||
			f.CheckID == finding.CheckPortSupersetDefaultCreds ||
			f.CheckID == finding.CheckWebDefaultCredentials:
			svc, _ := f.Evidence["service"].(string)
			if svc == "" {
				// Derive service from check ID prefix
				svc = string(f.CheckID)
			}
			ev.CredentialExposures = append(ev.CredentialExposures, playbook.CredentialExposure{
				Type:    "default_creds",
				Service: svc,
			})

		// ── Credential harvest → CredentialExposures with access targets ──
		case f.CheckID == finding.CheckExploitCredentialHarvest:
			svc, _ := f.Evidence["credential_source"].(string)
			target, _ := f.Evidence["grants_access_to"].(string)
			ev.CredentialExposures = append(ev.CredentialExposures, playbook.CredentialExposure{
				Type:           "harvested",
				Service:        svc,
				GrantsAccessTo: target,
			})

		// ── Data extraction → DataStoreConnections ────────────────────────
		case f.CheckID == finding.CheckExploitDataExtracted:
			svc, _ := f.Evidence["service"].(string)
			host, _ := f.Evidence["target_host"].(string)
			ev.DataStoreConnections = append(ev.DataStoreConnections, playbook.DataStoreConnection{
				Type:   svc,
				Host:   host,
				Source: "exploit_chain",
			})

		// ── Internal network discovery → NetworkAdjacency ─────────────────
		case f.CheckID == finding.CheckExploitInternalNetDiscovered:
			if hosts, ok := f.Evidence["hosts_found"].([]string); ok {
				for _, h := range hosts {
					ev.NetworkAdjacency = append(ev.NetworkAdjacency, playbook.NetworkAdjacent{
						Host:       h,
						Discovered: "container_network",
					})
				}
			}

		// ── CI/CD signals ─────────────────────────────────────────────────
		case f.CheckID == finding.CheckPortJenkinsNoAuth:
			if !containsStr(ev.CICDSignals, "jenkins") {
				ev.CICDSignals = append(ev.CICDSignals, "jenkins")
			}
		case f.CheckID == finding.CheckPortGiteaNoAuth:
			if !containsStr(ev.CICDSignals, "gitea") {
				ev.CICDSignals = append(ev.CICDSignals, "gitea")
			}
		case f.CheckID == finding.CheckGitLabAPIUnauth ||
			f.CheckID == finding.CheckGitLabPublicProjects:
			if !containsStr(ev.CICDSignals, "gitlab") {
				ev.CICDSignals = append(ev.CICDSignals, "gitlab")
			}

		// ── API schema exposure → ExposedAPISchemas ───────────────────────
		case f.CheckID == finding.CheckSwaggerExposed:
			path, _ := f.Evidence["path"].(string)
			if path == "" {
				path = "/swagger"
			}
			ev.ExposedAPISchemas = append(ev.ExposedAPISchemas, playbook.APISchemaInfo{
				Type: "openapi",
				Path: path,
			})
		case f.CheckID == finding.CheckPortGRPCReflectionEnabled:
			ev.ExposedAPISchemas = append(ev.ExposedAPISchemas, playbook.APISchemaInfo{
				Type: "grpc_reflection",
				Path: "/",
			})

		// ── UDP service fingerprints → PortServices ───────────────────────
		case f.CheckID == finding.CheckPortServiceDiscovered:
			if proto, _ := f.Evidence["protocol"].(string); proto == "udp" {
				port, _ := f.Evidence["port"].(int)
				svc, _ := f.Evidence["service"].(string)
				if port > 0 && svc != "" {
					if ev.PortServices == nil {
						ev.PortServices = make(map[int]playbook.PortServiceInfo)
					}
					if _, exists := ev.PortServices[port]; !exists {
						ev.PortServices[port] = playbook.PortServiceInfo{
							Service:  svc,
							Protocol: "udp",
						}
					}
				}
			}
		}
	}
}

func containsStr(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

// scannerSkipReason returns a non-empty human-readable reason if the named
// scanner should be skipped for this asset, or "" if it should run.
// Skip decisions are recorded as metrics so the AI can compute skip rates.
func scannerSkipReason(
	name string,
	_ module.ScanType,
	noHTTP bool,
	behindWAF bool,
	_ string, // wafVendor reserved for future vendor-specific logic
	originIP string,
	httpDep map[string]bool,
	scanners map[string]sc.Scanner,
	svcClass ServiceClass,
) string {
	// Scanner not in the registry — nothing to run.
	if _, ok := scanners[name]; !ok {
		return "scanner_not_registered"
	}
	// HTTP-dependent scanners have nothing to probe when the asset has no web service.
	if noHTTP && httpDep[name] {
		return "no_http_service"
	}
	// vhost sends crafted Host headers to the resolved IP. When the asset is
	// behind a CDN that IP is a shared edge node — probing it would reach other
	// tenants' backends. Skip unless we know the real origin IP, in which case
	// RunWithOriginIP targets that directly instead.
	if name == "vhost" && behindWAF && originIP == "" {
		return "behind_cdn_vhost_probe_unsafe"
	}
	// cdnbypass only has value when there is a CDN or WAF to bypass.
	if name == "cdnbypass" && !behindWAF {
		return "no_cdn_detected"
	}
	// Service type mismatch — skip scanners irrelevant to the detected service class.
	if svcClass != ServiceClassUnknown && svcClass != ServiceClassWebApp {
		if !serviceScannerRelevant(svcClass, name) {
			return "service_type_mismatch"
		}
	}

	return ""
}

// ServiceClass categorizes what kind of service the target runs.
type ServiceClass int

const (
	ServiceClassUnknown      ServiceClass = iota
	ServiceClassWebApp                     // HTML-serving web application (nginx, Apache, Express)
	ServiceClassAPI                        // REST/GraphQL/gRPC API
	ServiceClassDatabase                   // MySQL, PostgreSQL, MongoDB, CouchDB, Redis, Elasticsearch
	ServiceClassMessageQueue               // RabbitMQ, Kafka, MQTT, NATS
	ServiceClassMonitoring                 // Prometheus, Grafana, Kibana, Jaeger
	ServiceClassCICD                       // Jenkins, GitLab, TeamCity
	ServiceClassInfra                      // Docker, Kubernetes, Consul, Vault, etcd
	ServiceClassCloudStorage               // S3, GCS, Azure Blob — skip injection scanners
)

// classifyService maps a service name (from portscan evidence) to a ServiceClass.
// Returns ServiceClassUnknown for unrecognized services.
func classifyService(openPorts map[int]string) ServiceClass {
	// Database services — strongest signal, skip all HTTP scanners.
	dbServices := map[string]bool{
		"mysql": true, "postgresql": true, "postgres": true,
		"mongodb": true, "couchdb": true, "redis": true,
		"Elasticsearch": true, "OpenSearch": true,
		"memcached": true, "influxdb": true, "cassandra": true,
		"neo4j": true, "splunk": true, "mssql": true,
		"oracle": true, "clickhouse": true, "cockroachdb": true,
	}
	mqServices := map[string]bool{
		"rabbitmq": true, "kafka": true, "mqtt": true,
		"nats": true, "activemq": true, "mosquitto": true,
	}
	monServices := map[string]bool{
		"prometheus": true, "grafana": true, "kibana": true,
		"jaeger": true, "zabbix": true, "nagios": true,
		"wazuh": true,
	}
	cicdServices := map[string]bool{
		"jenkins": true, "gitlab": true, "teamcity": true,
		"drone": true, "bamboo": true, "concourse": true,
	}
	infraServices := map[string]bool{
		"docker": true, "kubernetes": true, "kubelet": true,
		"kubelet-readonly": true, "consul": true, "vault": true,
		"etcd": true, "envoy": true, "istio": true,
		"proxmox": true, "nomad": true,
	}

	// Check all open ports — if ANY port runs a known service, classify.
	// Priority: database > mq > infra > monitoring > cicd.
	// If multiple classes are present, the most restrictive wins.
	for _, svc := range openPorts {
		if svc == "" {
			continue
		}
		if dbServices[svc] {
			return ServiceClassDatabase
		}
	}
	for _, svc := range openPorts {
		if mqServices[svc] {
			return ServiceClassMessageQueue
		}
	}
	for _, svc := range openPorts {
		if infraServices[svc] {
			return ServiceClassInfra
		}
	}
	for _, svc := range openPorts {
		if monServices[svc] {
			return ServiceClassMonitoring
		}
	}
	for _, svc := range openPorts {
		if cicdServices[svc] {
			return ServiceClassCICD
		}
	}
	// Cloud storage: detected from service name patterns in portscan evidence.
	// S3/GCS/Azure responses have distinctive Server headers that portscan may capture.
	cloudStorageServices := map[string]bool{
		"s3": true, "gcs": true, "azure-blob": true, "minio": true,
		"AmazonS3": true, "UploadServer": true, // Google Cloud Storage Server header
	}
	for _, svc := range openPorts {
		if cloudStorageServices[svc] {
			return ServiceClassCloudStorage
		}
	}

	return ServiceClassUnknown
}

// serviceScannerRelevant returns true if the named scanner is relevant for the
// given service class. WebApp allows ALL scanners. Unknown allows ALL.
func serviceScannerRelevant(svcClass ServiceClass, scannerName string) bool {
	switch svcClass {
	case ServiceClassDatabase, ServiceClassMessageQueue:
		// Only portscan-phase and asset-level scanners are useful.
		return databaseRelevantScanners[scannerName]
	case ServiceClassAPI:
		return apiRelevantScanners[scannerName]
	case ServiceClassMonitoring:
		return monitoringRelevantScanners[scannerName]
	case ServiceClassCICD:
		return cicdRelevantScanners[scannerName]
	case ServiceClassInfra:
		return infraRelevantScanners[scannerName]
	case ServiceClassCloudStorage:
		return cloudStorageRelevantScanners[scannerName]
	default:
		return true
	}
}

// Scanner relevance maps per service class.
// These define which Phase B scanners are worth running.
// Phase A scanners (portscan, wafdetect, aidetect, authsurface) are never
// subject to service-class filtering — they run unconditionally.
var databaseRelevantScanners = map[string]bool{
	// Phase A (always run, but listed for completeness)
	"portscan": true, "wafdetect": true, "aidetect": true, "authsurface": true,
	// Asset intel / DNS — always relevant
	"assetintel": true, "email": true, "dorks": true, "hibp": true,
	"tls": true, "testssl": true, "dns": true, "typosquat": true,
	"favicon": true, "ctlog": true, "asnmap": true,
	// Nuclei covers database-specific CVEs via tags
	"nuclei": true,
}

var apiRelevantScanners = map[string]bool{
	"portscan": true, "wafdetect": true, "aidetect": true, "authsurface": true,
	"assetintel": true, "email": true, "dorks": true, "hibp": true,
	"tls": true, "testssl": true, "dns": true, "typosquat": true,
	"favicon": true, "ctlog": true, "asnmap": true, "nuclei": true,
	// API-relevant HTTP scanners
	"cors": true, "jwt": true, "graphql": true, "swagger": true,
	"authfuzz": true, "rxss": true, "ratelimit": true, "oauth": true,
	"secheaders": true, "exposedfiles": true, "apiversions": true,
	"apifuzz": true, "apischema": true, "grpcreflect": true,
	"hostheader": true, "smuggling": true, "websocket": true,
	"wsfuzz": true, "httpmethods": true, "cookie": true,
	"wellknown": true, "h2c": true, "http2": true,
	"crawler": true, "screenshot": true, "webcontent": true,
	"autoprobe": true, "idor": true, "accesscontrol": true,
	"sqli": true, "nosqli": true, "ssrf": true, "ssti": true,
	"cmdinj": true, "xxe": true, "deserial": true,
	"errordisclosure": true, "verbtamper": true,
}

var monitoringRelevantScanners = map[string]bool{
	"portscan": true, "wafdetect": true, "aidetect": true, "authsurface": true,
	"assetintel": true, "email": true, "dorks": true, "hibp": true,
	"tls": true, "testssl": true, "dns": true, "typosquat": true,
	"favicon": true, "ctlog": true, "asnmap": true, "nuclei": true,
	// Monitoring dashboards often expose sensitive data
	"secheaders": true, "exposedfiles": true, "swagger": true,
	"webcontent": true, "screenshot": true, "crawler": true,
	"cors": true, "jwt": true, "cookie": true, "wellknown": true,
	"autoprobe": true, "clickjacking": true,
}

var cicdRelevantScanners = map[string]bool{
	"portscan": true, "wafdetect": true, "aidetect": true, "authsurface": true,
	"assetintel": true, "email": true, "dorks": true, "hibp": true,
	"tls": true, "testssl": true, "dns": true, "typosquat": true,
	"favicon": true, "ctlog": true, "asnmap": true, "nuclei": true,
	// CI/CD-relevant scanners
	"secheaders": true, "exposedfiles": true, "jenkins": true,
	"webcontent": true, "screenshot": true, "crawler": true,
	"cors": true, "jwt": true, "cookie": true, "wellknown": true,
	"autoprobe": true, "ghactions": true, "bitbucket": true,
	"circleci": true, "okta": true,
}

var infraRelevantScanners = map[string]bool{
	"portscan": true, "wafdetect": true, "aidetect": true, "authsurface": true,
	"assetintel": true, "email": true, "dorks": true, "hibp": true,
	"tls": true, "testssl": true, "dns": true, "typosquat": true,
	"favicon": true, "ctlog": true, "asnmap": true, "nuclei": true,
	// Infrastructure scanners
	"secheaders": true, "exposedfiles": true, "swagger": true,
	"webcontent": true, "screenshot": true, "crawler": true,
	"cors": true, "jwt": true, "cookie": true, "wellknown": true,
	"autoprobe": true, "gateway": true, "containerimage": true,
}

var cloudStorageRelevantScanners = map[string]bool{
	"portscan": true, "wafdetect": true, "aidetect": true, "authsurface": true,
	"assetintel": true, "email": true, "dorks": true, "hibp": true,
	"tls": true, "testssl": true, "dns": true, "typosquat": true,
	"favicon": true, "ctlog": true, "asnmap": true, "nuclei": true,
	// Cloud storage: check bucket permissions, headers, TLS — skip injection scanners
	"secheaders": true, "cloudbuckets": true, "wellknown": true,
	"exposedfiles": true, "screenshot": true,
}

// saveScanMetricElapsed records a scanner run's timing and finding counts to the store.
// Non-fatal — metric failures must never affect the scan result.
func (m *Module) saveScanMetricElapsed(
	ctx context.Context,
	scanRunID, asset, scannerName string,
	elapsed time.Duration,
	fs []finding.Finding,
	scanErr error,
) {
	if m.st == nil || scanRunID == "" {
		return
	}
	metric := &store.ScannerMetric{
		ScanRunID:   scanRunID,
		Asset:       asset,
		ScannerName: scannerName,
		DurationMs:  elapsed.Milliseconds(),
		CreatedAt:   time.Now(),
	}
	if scanErr != nil {
		metric.ErrorCount = 1
		metric.ErrorMessage = scanErr.Error()
	}
	for _, f := range fs {
		switch f.Severity {
		case finding.SeverityCritical:
			metric.FindingsCritical++
		case finding.SeverityHigh:
			metric.FindingsHigh++
		case finding.SeverityMedium:
			metric.FindingsMedium++
		case finding.SeverityLow:
			metric.FindingsLow++
		default:
			metric.FindingsInfo++
		}
	}
	_ = m.st.SaveScannerMetric(ctx, metric)
}

// saveSkipMetric records that a scanner was intentionally skipped.
func (m *Module) saveSkipMetric(
	ctx context.Context,
	scanRunID, asset, scannerName, reason string,
) {
	if m.st == nil || scanRunID == "" {
		return
	}
	_ = m.st.SaveScannerMetric(ctx, &store.ScannerMetric{
		ScanRunID:   scanRunID,
		Asset:       asset,
		ScannerName: scannerName,
		Skipped:     true,
		SkipReason:  reason,
		CreatedAt:   time.Now(),
	})
}

// scannerCmd returns a human-readable description of what a scanner does on a
// given asset, used for verbose progress output.
func scannerCmd(name, asset string, scanType module.ScanType) string {
	mode := "surface"
	if isDeepOrAuthorized(scanType) {
		mode = "deep"
	}
	switch name {
	case "nuclei":
		return fmt.Sprintf("nuclei -u %s -tags %s", asset, mode)
	case "subfinder":
		return fmt.Sprintf("subfinder -d %s -silent", asset)
	case "wafdetect":
		return fmt.Sprintf("WAF fingerprint → %s", asset)
	case "portscan":
		return fmt.Sprintf("TCP connect scan → %s", asset)
	case "testssl":
		return fmt.Sprintf("testssl.sh --quiet %s:443", asset)
	case "screenshot":
		return fmt.Sprintf("gowitness scan single --url https://%s", asset)
	case "crawler":
		return fmt.Sprintf("katana -u https://%s -depth 2", asset)
	case "dirbust":
		return fmt.Sprintf("dirbust https://%s [playbook paths]", asset)
	case "jwt":
		return fmt.Sprintf("JWT analysis → https://%s/", asset)
	case "cors":
		return fmt.Sprintf("curl -H 'Origin: https://evil.com' https://%s/", asset)
	case "ratelimit":
		return fmt.Sprintf("rate limit probe → https://%s/api/", asset)
	case "graphql":
		return fmt.Sprintf("GraphQL introspection → https://%s/graphql", asset)
	case "oauth":
		return fmt.Sprintf("OIDC discovery → https://%s/.well-known/openid-configuration", asset)
	case "hostheader":
		return fmt.Sprintf("Host header injection → %s", asset)
	case "smuggling":
		return fmt.Sprintf("HTTP request smuggling probe → %s", asset)
	case "email":
		return fmt.Sprintf("SPF/DKIM/DMARC → %s", asset)
	case "dns":
		return fmt.Sprintf("dig AXFR/TXT/CAA/DNSSEC → %s", asset)
	case "webcontent":
		return fmt.Sprintf("JS secret scan → https://%s/", asset)
	case "clickjacking":
		return fmt.Sprintf("curl -sI https://%s/ | grep -i 'x-frame-options\\|content-security-policy'", asset)
	case "autoprobe":
		return fmt.Sprintf("username enumeration + lockout probe → https://%s/login", asset)
	case "websocket":
		return fmt.Sprintf("curl -H 'Origin: https://evil.com' -H 'Upgrade: websocket' -H 'Connection: Upgrade' -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' https://%s/ws", asset)
	case "exposedfiles":
		return fmt.Sprintf("curl -si https://%s/.env https://%s/.git/config", asset, asset)
	case "apiversions":
		return fmt.Sprintf("curl -si https://%s/api/v1/ https://%s/api/v2/", asset, asset)
	case "takeover":
		return fmt.Sprintf("subdomain takeover check → %s", asset)
	case "cloudbuckets":
		return fmt.Sprintf("cloud bucket enumeration → %s", asset)
	case "cdnbypass":
		return fmt.Sprintf("CDN origin IP discovery → %s", asset)
	case "proxychain":
		return fmt.Sprintf("proxy chain detection → %s", asset)
	case "cacheprobe":
		return fmt.Sprintf("CDN cache intelligence → %s", asset)
	default:
		return fmt.Sprintf("%s → %s", name, asset)
	}
}

// httpAltPort returns the first open port from openPorts that is likely running
// an HTTP service on a non-standard port. Returns 0 if none found.
// Used to recover HTTP scanning for assets where 80/443 are closed but a web
// service is present on an alternate port (common for dev servers, admin UIs, etc.).
func httpAltPort(openPorts map[int]string) int {
	// Ordered by likelihood of being an HTTP service.
	candidates := []int{8080, 8443, 8888, 3000, 4000, 5000, 8000, 8008, 8181, 9000, 9090, 9443}
	for _, p := range candidates {
		if _, open := openPorts[p]; open {
			return p
		}
	}
	return 0
}

// mergeParamNames combines two parameter name slices, deduplicating by name.
func mergeParamNames(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	var merged []string
	for _, s := range a {
		if !seen[s] {
			seen[s] = true
			merged = append(merged, s)
		}
	}
	for _, s := range b {
		if !seen[s] {
			seen[s] = true
			merged = append(merged, s)
		}
	}
	return merged
}

// injectionScannerNames lists scanners that benefit from param discovery results.
var injectionScannerNames = map[string]bool{
	"sqli": true, "nosqli": true, "rxss": true, "ssrf": true,
	"cmdinj": true, "ssti": true, "xxe": true, "pathtraversal": true,
	"pdfssrf": true, "elinjection": true,
}
