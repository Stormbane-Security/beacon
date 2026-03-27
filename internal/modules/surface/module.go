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
	"github.com/stormbane/beacon/internal/aifp"
	"github.com/stormbane/beacon/internal/analyze"
	"github.com/stormbane/beacon/internal/auth"
	"github.com/stormbane/beacon/internal/config"
	"github.com/stormbane/beacon/internal/enrichment"
	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
	"github.com/stormbane/beacon/internal/playbook"
	"github.com/stormbane/beacon/internal/scanner/classify"
	sc "github.com/stormbane/beacon/internal/scanner"
	"github.com/stormbane/beacon/internal/scanner/assetintel"
	"github.com/stormbane/beacon/internal/scanner/bgp"
	"github.com/stormbane/beacon/internal/scanner/cdnbypass"
	"github.com/stormbane/beacon/internal/scanner/cmsplugins"
	"github.com/stormbane/beacon/internal/scanner/crlf"
	"github.com/stormbane/beacon/internal/scanner/iam"
	"github.com/stormbane/beacon/internal/scanner/log4shell"
	"github.com/stormbane/beacon/internal/scanner/saml"
	"github.com/stormbane/beacon/internal/scanner/protopollution"
	"github.com/stormbane/beacon/internal/scanner/ssti"
	"github.com/stormbane/beacon/internal/scanner/web3auth"
	"github.com/stormbane/beacon/internal/scanner/web3detect"
	"github.com/stormbane/beacon/internal/scanner/depconf"
	"github.com/stormbane/beacon/internal/scanner/ssrf"
	"github.com/stormbane/beacon/internal/scanner/nginx"
	"github.com/stormbane/beacon/internal/scanner/hpp"
	"github.com/stormbane/beacon/internal/scanner/harvester"
	"github.com/stormbane/beacon/internal/scanner/aidetect"
	"github.com/stormbane/beacon/internal/scanner/aillm"
	"github.com/stormbane/beacon/internal/scanner/apiversions"
	"github.com/stormbane/beacon/internal/scanner/autoprobe"
	"github.com/stormbane/beacon/internal/scanner/clickjacking"
	"github.com/stormbane/beacon/internal/scanner/dns"
	"github.com/stormbane/beacon/internal/scanner/exposedfiles"
	"github.com/stormbane/beacon/internal/scanner/httpmethods"
	"github.com/stormbane/beacon/internal/scanner/smuggling"
	"github.com/stormbane/beacon/internal/scanner/websocket"
	"github.com/stormbane/beacon/internal/scanner/takeover"
	"github.com/stormbane/beacon/internal/scanner/wafdetect"
	"github.com/stormbane/beacon/internal/scanner/oauth"
	"github.com/stormbane/beacon/internal/scanner/ratelimit"
	"github.com/stormbane/beacon/internal/scanner/cloudbuckets"
	"github.com/stormbane/beacon/internal/scanner/cors"
	"github.com/stormbane/beacon/internal/scanner/crawler"
	"github.com/stormbane/beacon/internal/scanner/dirbust"
	"github.com/stormbane/beacon/internal/scanner/dlp"
	"github.com/stormbane/beacon/internal/scanner/dorks"
	"github.com/stormbane/beacon/internal/scanner/email"
	"github.com/stormbane/beacon/internal/scanner/graphql"
	"github.com/stormbane/beacon/internal/scanner/jenkins"
	"github.com/stormbane/beacon/internal/scanner/hibp"
	"github.com/stormbane/beacon/internal/scanner/historicalurls"
	"github.com/stormbane/beacon/internal/scanner/hostheader"
	"github.com/stormbane/beacon/internal/scanner/jwt"
	"github.com/stormbane/beacon/internal/scanner/nuclei"
	"github.com/stormbane/beacon/internal/scanner/passivedns"
	"github.com/stormbane/beacon/internal/scanner/portscan"
	"github.com/stormbane/beacon/internal/scanner/screenshot"
	"github.com/stormbane/beacon/internal/scanner/subdomain"
	"github.com/stormbane/beacon/internal/scanner/testssl"
	tlsscanner "github.com/stormbane/beacon/internal/scanner/tls"
	"github.com/stormbane/beacon/internal/scanner/typosquat"
	"github.com/stormbane/beacon/internal/scanner/vhost"
	"github.com/stormbane/beacon/internal/scanner/webcontent"
	"github.com/stormbane/beacon/internal/scanner/whois"
	"github.com/stormbane/beacon/internal/scanner/authfuzz"
	"github.com/stormbane/beacon/internal/scanner/xxe"
	"github.com/stormbane/beacon/internal/scanner/deserial"
	"github.com/stormbane/beacon/internal/scanner/fileupload"
	"github.com/stormbane/beacon/internal/scanner/gateway"
	"github.com/stormbane/beacon/internal/scanner/swagger"
	"github.com/stormbane/beacon/internal/scanner/contractscan"
	"github.com/stormbane/beacon/internal/scanner/chainnode"
	"github.com/stormbane/beacon/internal/scanner/githubactions"
	"github.com/stormbane/beacon/internal/evasion"
	"github.com/stormbane/beacon/internal/fingerprintdb"
	"github.com/stormbane/beacon/internal/profiler"
	"github.com/stormbane/beacon/internal/store"
)

// Module is the Surface scan module.
type Module struct {
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

	// Playbook registry
	registry *playbook.Registry

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
	AmmassBin         string
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

	// Auth holds per-asset credentials for authenticated scanning.
	// When a matching entry exists for the current asset (or asset == "*"),
	// scanners run against content that is gated behind a login.
	Auth []config.AuthConfig

	// GitHubToken is an optional GitHub personal access token used by the
	// githubactions scanner to fetch workflow files via the GitHub API.
	// Without it the scanner is limited to 60 unauthenticated requests/hour.
	GitHubToken string
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

	reg, err := playbook.Load()
	if err != nil {
		return nil, fmt.Errorf("surface: load playbooks: %w", err)
	}
	homeDir, _ := os.UserHomeDir()
	userPlaybookDir := filepath.Join(homeDir, ".config", "beacon", "playbooks")
	if err := reg.LoadUserDir(userPlaybookDir); err != nil {
		return nil, fmt.Errorf("surface: load user playbooks: %w", err)
	}

	nucl := nuclei.New(cfg.NucleiBin, surfaceList, deepList)

	scannerMap := map[string]sc.Scanner{
		"email":          email.New(),
		"whois":          whois.New(),
		"tls":            nucl,        // TLS cert checks are in nuclei surface templates
		"tlscheck":       tlsscanner.New(), // native Go TLS: key strength, OCSP, CT, PFS, HSTS policy
		"assetintel":     assetintel.NewWithKeys(cfg.ShodanAPIKey, cfg.VirusTotalAPIKey, cfg.SecurityTrailsAPIKey, cfg.CensysAPIID, cfg.CensysAPISecret, cfg.GreyNoiseAPIKey),
		"vhost":          vhost.New(),
		"webcontent":     webcontent.New(),
		"cloudbuckets":   cloudbuckets.New(),
		"historicalurls": historicalurls.New(cfg.GauBin),
		"crawler":        crawler.New(cfg.KatanaBin),
		"screenshot":     screenshot.New(cfg.GowitnessBin),
		"testssl":        testssl.New(cfg.TestsslBin),
		"bgp":            bgp.New(),
		"passivedns":     passivedns.New(),
		"typosquat":      typosquat.New(),
		"dlp":            dlp.New(),
		"portscan":       portscan.NewWithNmap(cfg.NmapBin),
		"graphql":        graphql.New(),
		"cdnbypass":      cdnbypass.New(),
		"hostheader":     hostheader.New(),
		"jwt":            jwt.New(),
		"cors":           cors.New(),
		"hibp":           hibp.New(cfg.HIBPAPIKey),
		"dorks":       dorks.New(cfg.BingAPIKey),
		"cms-plugins": cmsplugins.New(),
		"oauth":        oauth.New(),
		"ratelimit":    ratelimit.New(),
		"depconf":      depconf.New(),
		"smuggling":    smuggling.New(),
		"dns":          dns.New(),
		"httpmethods":  httpmethods.New(),
		"takeover":     takeover.New(),
		"wafdetect":    wafdetect.New(),
		"harvester":    harvester.New(cfg.HarvesterBin),
		"jenkins":      jenkins.New(),
		"clickjacking": clickjacking.New(),
		"autoprobe":    autoprobe.New(),
		"websocket":    websocket.New(),
		"exposedfiles": exposedfiles.New(),
		"apiversions":  apiversions.New(),
		"aidetect":     aidetect.New(),
		"aillm":        aillm.New(),
		"saml":         saml.New(),
		"iam":          iam.New(),
		"ssti":             ssti.New(),
		"crlf":             crlf.New(),
		"log4shell":        log4shell.New(),
		"protopollution":   protopollution.New(),
		"web3detect":       web3detect.New(),
		"web3auth":         web3auth.New(),
		"ssrf":             ssrf.New(),
		"nginx":            nginx.New(),
		"hpp":              hpp.New(),
		"authfuzz":         authfuzz.New(),
		"xxe":              xxe.New(),
		"deserial":         deserial.New(),
		"fileupload":       fileupload.New(),
		"gateway":          gateway.New(),
		"swagger":          swagger.New(),
		"contractscan":     contractscan.New(),
		"chainnode":        chainnode.New(),
		"githubactions":   githubactions.New(cfg.GitHubToken),
	}

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
		subdomainScanner:  subdomain.NewPassiveWithKeys(cfg.SubfinderBin, cfg.AmmassBin, cfg.OTXAPIKey),
		passiveDNSScanner: passivedns.New(),
		whoisScanner:      whois.New(),
		bgpScanner:        bgp.New(),
		scanners:          scannerMap,
		nucleiScanner:     nucl,
		registry:          reg,
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
		authCfgs:          cfg.Auth,
		enricher:          enricher,
	}, nil
}

func (m *Module) Name() string                       { return "surface" }
func (m *Module) RequiredInputs() []module.InputType { return []module.InputType{module.InputDomain} }

// isDeepOrAuthorized returns true for ScanDeep and ScanAuthorized.
// Use this to gate checks that need active probing but are not exploitation-class.
func isDeepOrAuthorized(t module.ScanType) bool {
	return t == module.ScanDeep || t == module.ScanAuthorized
}

// isAuthorized returns true only for ScanAuthorized.
// Use this to gate exploitation-class checks.
func isAuthorized(t module.ScanType) bool {
	return t == module.ScanAuthorized
}

// Run executes the full surface scan pipeline driven by playbooks.
func (m *Module) Run(ctx context.Context, input module.Input, scanType module.ScanType) ([]finding.Finding, error) {
	rootDomain := input.Domain

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

	type discoveryBatch struct {
		findings []finding.Finding
		source   string
	}
	batchResults := make(chan discoveryBatch, 2)

	wgDiscover.Add(2)
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
	go func() {
		defer wgDiscover.Done()
		discScanStart("passivedns", fmt.Sprintf("hackertarget.com/hostsearch?q=%s", rootDomain))
		fs, _ := m.passiveDNSScanner.Run(ctx, rootDomain, scanType)
		discScanDone("passivedns", fs)
		batchResults <- discoveryBatch{findings: fs, source: "passivedns"}
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

	discStart := time.Now()
	for batch := range batchResults {
		appendFindings(batch.findings)
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
				}
			}
		}
	}
	discDuration := time.Since(discStart)

	// Filter out hostnames that don't resolve — saves scanning dead assets.
	// dnsx probes all at once; fallback uses parallel stdlib DNS.
	if len(assets) > 1 { // skip single-asset (root domain) — always scan root
		dnsxCmd := "dnsx -silent (batch DNS resolution)"
		if m.dnsxBin == "" {
			dnsxCmd = "stdlib net.LookupHost (parallel DNS resolution — install dnsx for faster results)"
		}
		discScanStart("resolve", fmt.Sprintf("%s — filtering %d candidates", dnsxCmd, len(assets)))
		preResolve := len(assets)
		assets = subdomain.ResolveBatch(ctx, assets, m.dnsxBin)
		discScanDone("resolve", nil)
		_ = preResolve
		// Ensure root domain is always included even if DNS is flaky.
		hasRoot := false
		for _, a := range assets {
			if a == rootDomain {
				hasRoot = true
				break
			}
		}
		if !hasRoot {
			assets = append([]string{rootDomain}, assets...)
		}
	}

	// Zone transfer (AXFR): run against root domain during Phase 1 so that
	// any hostnames revealed by the zone data are added to the asset queue
	// before scanning starts. The finding is also emitted immediately.
	{
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
				if _, ok := seen[h]; !ok {
					seen[h] = struct{}{}
					assets = append(assets, h)
					assetSource[h] = "axfr"
				}
			}
		}
		discScanDone("dns-axfr", axfrFindings)
	}

	progress(fmt.Sprintf("found %d assets — running root-domain scanners (whois, bgp)...", len(assets)))

	// Root-only scanners (WHOIS, BGP) — always run, not playbook-driven.
	// BGP findings are captured separately so we can extract discovered IPs
	// and PTR hostnames and add them to the asset list for full scanning.
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
	for _, f := range bgpFindings {
		switch f.CheckID {
		case finding.CheckASNIPService:
			if ip, ok := f.Evidence["ip"].(string); ok && ip != "" {
				if _, alreadySeen := seen[ip]; !alreadySeen {
					seen[ip] = struct{}{}
					assets = append(assets, ip) // surface scan always runs
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

	// ── Phase 2 & 3: Classify + Execute per asset ────────────────────────────
	// Semaphore limits parallel asset scans to avoid flooding the target.
	// Each asset scan spawns ~12 goroutines and the crawler uses concurrency-5,
	// so without a limit a large domain (50+ subdomains) could send thousands of
	// simultaneous connections and cause a service disruption.
	const maxConcurrentAssets = 10
	sem := make(chan struct{}, maxConcurrentAssets)

	// expandSeen is shared across ALL runAsset goroutines to prevent two
	// concurrent parent assets from independently discovering and scanning
	// the same cert-SAN / port-service / body-subdomain child asset.
	expandSeen := map[string]bool{}
	var expandSeenMu sync.Mutex
	// Pre-populate with all initial assets so depth+1 expansion never
	// re-scans something already in the initial asset list.
	for _, a := range assets {
		expandSeen[a] = true
	}

	var assetsDone int64 // incremented atomically when each asset goroutine completes

	scanStart := time.Now()
	var wgAssets sync.WaitGroup
assetLoop:
	for _, asset := range assets {
		asset := asset
		// Acquire a semaphore slot, but respect context cancellation so we
		// don't leak goroutines when the scan is cancelled mid-flight.
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			break assetLoop
		}
		if ctx.Err() != nil {
			break assetLoop
		}
		// Allow the user to pause between assets.
		if input.PauseCheck != nil {
			input.PauseCheck(ctx)
		}
		wgAssets.Add(1)
		go func() {
			defer wgAssets.Done()
			defer func() { <-sem }() // release slot
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
	wgAssets.Wait()
	scanDuration := time.Since(scanStart)

	// ── Crawler-discovered hostname expansion ──────────────────────────────────
	// The katana crawler discovers URLs across the scanned assets. Any hostname
	// in those URLs that is a new subdomain of rootDomain is a potential asset
	// we missed during passive enumeration. Scan them now (surface pass only —
	// they were already crawled from their parent asset).
	// Cap at 20 new hosts to avoid runaway expansion from link-rich pages.
	const maxCrawlExpansion = 20
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
			case sem <- struct{}{}:
			case <-ctx.Done():
				break crawlLoop
			}
			if ctx.Err() != nil {
				break crawlLoop
			}
			wgCrawl.Add(1)
			go func() {
				defer wgCrawl.Done()
				defer func() { <-sem }()
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
			case sem <- struct{}{}:
			case <-ctx.Done():
				break harvesterLoop
			}
			if ctx.Err() != nil {
				break harvesterLoop
			}
			wgHarvester.Add(1)
			go func() {
				defer wgHarvester.Done()
				defer func() { <-sem }()
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
				case sem <- struct{}{}:
				case <-ctx.Done():
					break roundLoop
				}
				if ctx.Err() != nil {
					break roundLoop
				}
				wgRound.Add(1)
				go func() {
					defer wgRound.Done()
					defer func() { <-sem }()
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
					addSem <- struct{}{}
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
							switch {
							case name == "aillm":
								// Pass per-asset AI endpoints so the scanner targets
								// confirmed paths rather than the generic default list.
								ev := &playbook.Evidence{
									AIEndpoints: extractAIEndpoints(assetFindings),
								}
								fs, scanErr = aillm.NewWithEvidence(ev).Run(ctx, targetAsset, scanType)
							default:
								sc, ok := m.scanners[name]
								if !ok {
									continue
								}
								fs, scanErr = sc.Run(ctx, targetAsset, scanType)
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

	return allFindings, nil
}

// runAsset classifies a single asset, matches playbooks, executes the RunPlan,
// and writes an AssetExecution audit record.
// depth tracks playbook-driven discovery recursion depth; expanded assets are
// scanned at depth+1 and do not trigger further discovery (max depth = 1).
// expandSeen is a shared set (protected by expandSeenMu) that prevents two
// concurrent runAsset goroutines from independently discovering and scanning
// the same cert-SAN / port-service / body-subdomain child asset.
func (m *Module) runAsset(ctx context.Context, asset, rootDomain string, scanType module.ScanType, scanRunID string, depth int, progressFn module.ProgressFunc, expandSeen map[string]bool, expandSeenMu *sync.Mutex) []finding.Finding {
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
	httpClient := &http.Client{}
	if len(m.authCfgs) > 0 {
		if authedClient, session, err := auth.Authenticate(ctx, m.authCfgs, asset, httpClient); err != nil {
			// Log but don't abort — fall back to unauthenticated scan.
			_ = err
		} else if authedClient != nil {
			httpClient = authedClient
			_ = session // session.Label available for logging if verbose
		}
	}
	_ = httpClient // available for scanners that accept an http.Client in future

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
			parts = append(parts, "JARM="+ev.JARMFingerprint[:8]+"…")
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

	// Match playbooks
	matched := m.registry.Match(ev)

	// Playbook-driven discovery (e.g. Cloudflare origin probing) runs up to
	// maxPlaybookDepth levels deep. Stops at the configured ceiling to prevent
	// infinite recursion from looping CNAME chains or CDN origin patterns.
	var expandedAssets []string
	if depth < m.maxPlaybookDepth {
		expandedAssets = m.runDiscovery(ctx, asset, rootDomain, matched, scanType)
	}

	// Build unified RunPlan
	plan := playbook.BuildRunPlan(matched)

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

	noHTTP := ev.StatusCode == 0

	// ── Phase A: Intelligence scanners (parallel) ────────────────────────────
	// Run wafdetect, portscan, and aidetect concurrently and wait for all before
	// starting Phase B. Their findings feed into Phase B:
	//   • wafdetect: WAF vendor → skip vhost scanning on CDN-fronted assets
	//   • portscan:  open-port set → service-specific Nuclei tag injection
	//   • aidetect:  AI endpoint list → aillm uses discovered endpoints instead of
	//               guessing defaults, reducing false negatives on non-standard paths
	phaseANames := []string{"wafdetect", "portscan", "aidetect"}
	phaseADone := make(map[string]bool, len(phaseANames))
	var phaseAMu sync.Mutex
	var phaseAFindings []finding.Finding
	var phaseAWg sync.WaitGroup

	for _, name := range phaseANames {
		if !planContains(plan.Scanners, name) {
			continue
		}
		sc, ok := m.scanners[name]
		if !ok {
			continue
		}
		phaseADone[name] = true
		name, sc := name, sc
		phaseAWg.Add(1)
		go func() {
			defer phaseAWg.Done()
			start := time.Now()
			fs, scanErr := sc.Run(ctx, asset, scanType)
			phaseAMu.Lock()
			phaseAFindings = append(phaseAFindings, fs...)
			phaseAMu.Unlock()
			m.saveScanMetric(ctx, scanRunID, asset, name, start, fs, scanErr)
		}()
	}
	phaseAWg.Wait()

	// Extract WAF, origin IP, port, and AI endpoint intelligence from Phase A results.
	behindWAF, wafVendor := extractWAFInfo(phaseAFindings)
	originIP := extractOriginIP(phaseAFindings)
	openPorts := extractOpenPorts(phaseAFindings)
	// Populate ev.AIEndpoints from aidetect findings so aillm targets confirmed
	// endpoints instead of falling back to a generic default path list.
	if eps := extractAIEndpoints(phaseAFindings); len(eps) > 0 {
		ev.AIEndpoints = eps
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
		newMatches := m.registry.Match(ev)
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
				for _, p := range extra.DirbustPaths {
					plan.DirbustPaths = append(plan.DirbustPaths, p)
				}
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
		skipReason := scannerSkipReason(name, scanType, noHTTP, behindWAF, wafVendor, originIP, httpDependentScanners, m.scanners)
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
			start := time.Now()
			var fs []finding.Finding
			var scanErr error
			// aillm uses per-asset Evidence so it targets confirmed AI endpoints
			// discovered by aidetect (Phase A) rather than a generic default list.
			// autoprobe uses discovered harvester emails for higher-confidence
			// username enumeration against real employee accounts.
			if name == "aillm" && len(ev.AIEndpoints) > 0 {
				fs, scanErr = aillm.NewWithEvidence(&ev).Run(ctx, asset, scanType)
			} else if name == "autoprobe" {
				m.harvesterEmailsMu.Lock()
				emails := m.harvesterEmails
				m.harvesterEmailsMu.Unlock()
				fs, scanErr = autoprobe.NewWithEmails(emails).Run(ctx, asset, scanType)
			} else if originSc, ok := scanner.(sc.OriginScanner); ok && originIP != "" {
				// If the scanner supports direct-IP probing and we have a known origin IP
				// (e.g. the real backend behind a CDN), use it to avoid hitting shared CDN
				// edge infrastructure with crafted Host headers.
				fs, scanErr = originSc.RunWithOriginIP(ctx, asset, originIP, scanType)
			} else {
				fs, scanErr = scanner.Run(ctx, asset, scanType)
			}
			elapsed := time.Since(start)
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
			m.saveScanMetricElapsed(ctx, scanRunID, asset, name, elapsed, fs, scanErr)
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
			dbFindings := db.Run(ctx, asset, dirbustPaths)
			mu.Lock()
			findings = append(findings, dbFindings...)
			mu.Unlock()
		}()
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
				for _, pb := range m.registry.Match(ev) {
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
				skipReason := scannerSkipReason(name, scanType, noHTTP, behindWAF, wafVendor, originIP, httpDependentScanners, m.scanners)
				if skipReason != "" {
					m.saveSkipMetric(ctx, scanRunID, asset, name, skipReason)
					continue
				}
				name, convScanner := name, convScanner
				convWg.Add(1)
				go func() {
					defer convWg.Done()
					start := time.Now()
					var fs []finding.Finding
					var scanErr error
					// Mirror the same special-cases as Phase B to ensure convergence
					// scanners get the same context (AI endpoints, harvester emails,
					// origin IP) that Phase B scanners receive.
					switch {
					case name == "aillm" && len(ev.AIEndpoints) > 0:
						fs, scanErr = aillm.NewWithEvidence(&ev).Run(ctx, asset, scanType)
					case name == "autoprobe":
						m.harvesterEmailsMu.Lock()
						emails := m.harvesterEmails
						m.harvesterEmailsMu.Unlock()
						fs, scanErr = autoprobe.NewWithEmails(emails).Run(ctx, asset, scanType)
					default:
						if originSc, ok := convScanner.(sc.OriginScanner); ok && originIP != "" {
							fs, scanErr = originSc.RunWithOriginIP(ctx, asset, originIP, scanType)
						} else {
							fs, scanErr = convScanner.Run(ctx, asset, scanType)
						}
					}
					mu.Lock()
					findings = append(findings, fs...)
					mu.Unlock()
					m.saveScanMetricElapsed(ctx, scanRunID, asset, name, time.Since(start), fs, scanErr)
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

	// ── Post-scan classify helpers (after wg.Wait — no concurrent writes) ─────
	// Run after goroutines finish to avoid data races on the findings slice.
	findings = append(findings, classify.CheckVersions(ev, asset)...)
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
			if f.CheckID != "exposure.api_version" {
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
		defer wg.Done()
		sem <- struct{}{}
		defer func() { <-sem }()

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
			resp.Body.Close()
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
			wg.Add(1)
			go probe(ipStr)
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
			if !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '.') {
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
	return ""
}

// saveScanMetric records a scanner run's timing and finding counts to the store.
// Non-fatal — metric failures must never affect the scan result.
func (m *Module) saveScanMetric(
	ctx context.Context,
	scanRunID, asset, scannerName string,
	start time.Time,
	fs []finding.Finding,
	scanErr error,
) {
	m.saveScanMetricElapsed(ctx, scanRunID, asset, scannerName, time.Since(start), fs, scanErr)
}

// saveScanMetricElapsed is like saveScanMetric but accepts a pre-measured duration.
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
