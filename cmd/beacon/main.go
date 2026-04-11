// Beacon — security reconnaissance tool by Stormbane Security.
// Usage: beacon scan --domain <domain> [flags]
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/stormbane-security/beacon/internal/analyze"
	"github.com/stormbane-security/beacon/internal/asset"
	"github.com/stormbane-security/beacon/internal/config"
	"github.com/stormbane-security/beacon/internal/dedup"
	"github.com/stormbane-security/beacon/internal/enrichment"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/fingerprintdb"
	"github.com/stormbane-security/beacon/internal/module"
	cloudmodule "github.com/stormbane-security/beacon/internal/modules/cloud"
	githubmodule "github.com/stormbane-security/beacon/internal/modules/github"
	"github.com/stormbane-security/beacon/internal/modules/surface"
	"github.com/stormbane-security/beacon/internal/postexploit"
	"github.com/stormbane-security/beacon/internal/profiler"
	"github.com/stormbane-security/beacon/internal/recon"
	"github.com/stormbane-security/beacon/internal/report"
	"github.com/stormbane-security/beacon/internal/scanlog"
	"github.com/stormbane-security/beacon/internal/scanner/toolinstall"
	"github.com/stormbane-security/beacon/internal/store"
	memstore "github.com/stormbane-security/beacon/internal/store/memory"
	sqlitestore "github.com/stormbane-security/beacon/internal/store/sqlite"
	"golang.org/x/term"
)

const usageText = `Beacon — security reconnaissance tool

USAGE:
  beacon install                                 Install all required external tools
  beacon scan        --domain <domain> [flags]   Run a surface/deep scan
  beacon scan        --github <org> [flags]      Scan a GitHub org's Actions workflows
  beacon enrich      --input <file> [flags]      Enrich raw findings from a previous scan
  beacon browse                                  Interactive TUI browser for past scans
  beacon scans       [--limit N]                 List all past scans (no TUI)
  beacon history     --domain <domain>           List past scans for a domain
  beacon stop        --id <scan-id>              Mark a running scan as stopped
  beacon report      --id <scan-id> [flags]      Print a past report
  beacon analyze     [--id <run-id>] [--out <file>]  Playbook analysis + finding accuracy review
  beacon playbook    suggestions                 List AI playbook suggestions
  beacon playbook    import --id <id>            Import suggestion to ~/.config/beacon/playbooks/
  beacon playbook    dismiss --id <id>           Dismiss a suggestion (won't appear again)
  beacon playbook    open-pr --id <id>           Open a GitHub PR for a suggestion
  beacon classify    <target> [--format json|text]  Fingerprint a target without running scanners
  beacon retest      --id <scan-id>               Retest findings from a previous scan
  beacon diff        --baseline <id> --id <id>     Diff findings between two scans
  beacon scope       --program <name>             Show in-scope domains for a bug bounty program

SCAN FLAGS:
  --domain <domain>          Target domain (required unless --host or --targets is used)
  --host <target>            Add a target host; repeatable for multi-host sessions
  --targets <file>           File with one domain per line (enables multi-asset mode)
  --stdin                    Read targets from stdin (pipe from subfinder, httpx, etc.)
  --chaos <program>          Fetch targets from ProjectDiscovery Chaos for a bug bounty program
  --scope <file>             Scope file (.scope.yaml) to filter targets in/out of scope
  --new-only                 Only show findings not seen in previous scans of the same domain
  --deep                     Enable active probing (sends payloads — confirms permission interactively)
  --exploit                  Enable exploitation-class probes (active exploitation + post-exploit chains)
  --yes                      Skip all confirmation prompts (for CI/automation)
  --format <fmt>             Output format: text (default), html, json, markdown, bounty, ocsf, har, graph, pdf
  --out <path>               Write report to file instead of stdout
  --output-raw <path>        Write raw findings JSON (no enrichment) and exit; enrich later with beacon enrich
  --poc-dir <path>           Generate standalone PoC files for each finding into <path>
  --narratives               Include attack narratives and chain PoCs in markdown reports
  --screenshots <dir>        Capture screenshots of finding URLs into <dir> (requires Chrome)
  --severity <level>         Minimum severity to include: critical, high, medium, low, info (default)
  --verbose                  Show scanner-level progress (which scanner is running, fingerprint hits)
  --quiet                    Suppress informational stderr (missing API keys, nmap warnings, progress)
  --no-tui                   Disable interactive TUI; print line-by-line progress to stderr
  --scanners <list>          Comma-separated scanner names to run (skips playbook matching; e.g. cors,jwt,tls)
  --ports <list>             Comma-separated port numbers for portscan (e.g. 8123,6379); default: scan all known ports
  --no-enrich                Skip AI enrichment (output raw findings only)
  --no-db                    Skip scan history persistence (no SQLite writes)
  --anonymize                Anonymize IPs/hostnames before sending findings to AI (privacy mode)
  --no-nmap                  Skip nmap integration (no service version detection, no NSE scripts)
  --no-nuclei                Skip nuclei integration (no template-based vulnerability scanning)
  --no-testssl               Skip testssl.sh integration (no deep TLS analysis)
  --no-sqlmap                Skip sqlmap integration (no deep SQLi exploitation)
  --no-wpscan                Skip wpscan integration (no WordPress vulnerability scanning)
  --no-masscan               Skip masscan integration (no fast CIDR port scanning)
  --no-arjun                 Skip arjun integration (no external parameter discovery)
  --strict                   Hard-fail if required tools (nmap, nuclei) are missing (exit 1)
  --dry-run                  Fingerprint target and output planned scanner list as JSON (no scanners execute)
  --dns-server <addr>        Use a custom DNS server (e.g. 127.0.0.1:53) for email/DNS lookups
  --wordlist <path>           Custom wordlist file for brute-force scanners (dirbust, subdomain, param discovery)
  --log-file <path>          Write structured JSON logs to file (one event per line)
  --log-level <level>        Log level: debug, info (default), warn, error

ENRICH FLAGS:
  --input <file>             Raw findings JSON from --output-raw (required)
  --format <fmt>             Output format: text (default), json, markdown
  --out <path>               Write report to file instead of stdout
  --severity <level>         Minimum severity: critical, high, medium, low, info (default)

REPORT FLAGS:
  --id <scan-id>             Scan run ID (required)
  --format <fmt>             Output format: text (default), html, json, markdown, bounty, ocsf, har, graph, pdf
  --out <path>               Write report to file instead of stdout
  --screenshots <dir>        Capture screenshots of finding URLs into <dir> (requires Chrome)
  --severity <level>         Minimum severity to include: critical, high, medium, low, info (default)

EXAMPLES:
  beacon scan --domain example.com
  beacon scan --domain example.com --format json
  beacon scan --domain example.com --severity high
  beacon scan --domain example.com --out report.html --format html
  beacon scan --domain example.com --deep
  beacon scan --host example.com --host api.example.com --host cdn.example.com
  beacon scan --targets hosts.txt --deep
  beacon scan --domain example.com --output-raw findings.json
  beacon scan --domain example.com --scanners cors,jwt,tls
  beacon scan --chaos uber                                                Scan Chaos program targets
  beacon scan --stdin                                                     Pipe targets from subfinder/httpx
  subfinder -d example.com | beacon scan --stdin
  beacon scan --targets hosts.txt --new-only                              Only show new findings
  beacon scope --program hackerone:uber                                   Show program scope
  beacon enrich --input findings.json --format json --out enriched.json
  beacon report --id <id> --format markdown
  beacon scan --domain example.com --format graph | dot -Tsvg -o topology.svg
  beacon analyze
  beacon playbook suggestions
  beacon playbook import --id <suggestion-id>
  beacon playbook open-pr --id <suggestion-id>
  beacon terraform <path> [<path>...]
  beacon cloud       [flags]               Run cloud posture scan (GCP/AWS/Azure)

CLOUD FLAGS:
  --aws-profile <profile>    AWS CLI profile (default: env/default)
  --gcp-credentials <file>   GCP service account key JSON path (default: ADC)
  --azure-subscription <id>  Azure subscription ID (default: all accessible)
  --do-token <token>         DigitalOcean API token
  --oci-config <file>        Oracle Cloud Infrastructure config file path (default: ~/.oci/config)
  --okta-domain <domain>     Okta organization domain (e.g., yourorg.okta.com)
  --okta-token <token>       Okta API token (read-only admin)
  --domain <domain>          Asset label to associate findings with
  --format <fmt>             Output format: text (default), json, markdown
  --out <path>               Write report to file instead of stdout
  --severity <level>         Minimum severity: critical, high, medium, low, info (default)
`

// version is set at build time via -ldflags "-X main.version=vX.Y.Z".
// It defaults to "dev" for local builds.
var version = "dev"

// quiet suppresses informational stderr output (missing API key warnings,
// nmap capability notices, progress lines). Errors are never suppressed.
// Set via --quiet flag or BEACON_QUIET=1 env var.
var quiet bool

// info prints to stderr unless --quiet is active.
func info(format string, args ...any) {
	if !quiet {
		_, _ = fmt.Fprintf(os.Stderr, format, args...)
	}
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("beacon: internal error (recovered panic): %v", r)
			debug.PrintStack()
			os.Exit(1)
		}
	}()

	if len(os.Args) < 2 {
		// No subcommand — open the interactive scan history browser.
		cfg, err := config.Load()
		if err != nil {
			fatalf("config: %v", err)
		}
		cmdBrowse(cfg)
		return
	}

	cfg, err := config.Load()
	if err != nil {
		fatalf("config: %v", err)
	}

	switch os.Args[1] {
	case "version", "--version", "-v":
		fmt.Printf("beacon %s\n", version)
		return
	case "install":
		cmdInstall()
	case "scan":
		cmdScan(cfg, os.Args[2:])
	case "browse":
		cmdBrowse(cfg)
	case "scans":
		cmdScans(cfg, os.Args[2:])
	case "stop":
		cmdStop(cfg, os.Args[2:])
	case "history":
		cmdHistory(cfg, os.Args[2:])
	case "report":
		cmdReport(cfg, os.Args[2:])
	case "analyze":
		cmdAnalyze(cfg, os.Args[2:])
	case "playbook":
		if len(os.Args) < 3 {
			fatalf("usage: beacon playbook <subcommand>")
		}
		switch os.Args[2] {
		case "suggestions":
			cmdPlaybookSuggestions(cfg)
		case "open-pr":
			cmdPlaybookOpenPR(cfg, os.Args[3:])
		case "import":
			cmdPlaybookImport(cfg, os.Args[3:])
		case "dismiss":
			cmdPlaybookDismiss(cfg, os.Args[3:])
		default:
			fatalf("unknown playbook subcommand: %s", os.Args[2])
		}
	case "fingerprints":
		cmdFingerprints(cfg, os.Args[2:])
	case "terraform":
		cmdTerraform(cfg, os.Args[2:])
	case "cloud":
		cmdScanCloud(cfg, os.Args[2:])
	case "enrich":
		cmdEnrich(cfg, os.Args[2:])
	case "classify":
		cmdClassify(cfg, os.Args[2:])
	case "retest":
		cmdRetest(cfg, os.Args[2:])
	case "diff":
		cmdDiff(cfg, os.Args[2:])
	case "exploit":
		cmdExploit(cfg, os.Args[2:])
	case "scope":
		cmdScope(os.Args[2:])
	case "--help", "-h", "help":
		fmt.Print(usageText)
	default:
		_, _ = fmt.Fprintf(os.Stderr, "unknown command: %s\n\n%s", os.Args[1], usageText)
		os.Exit(1)
	}
}

// ---------- install ----------

func cmdInstall() {
	_, _ = fmt.Fprintln(os.Stderr, "beacon: checking and installing required tools...")
	results := toolinstall.EnsureAll()
	ok := true
	for _, r := range results {
		switch {
		case r.Skipped:
			_, _ = fmt.Fprintf(os.Stderr, "  %-16s  skipped (not supported on this platform)\n", r.Name)
		case r.Err != nil:
			_, _ = fmt.Fprintf(os.Stderr, "  %-16s  FAILED: %v\n", r.Name, r.Err)
			ok = false
		default:
			_, _ = fmt.Fprintf(os.Stderr, "  %-16s  ok  %s\n", r.Name, r.Path)
		}
	}
	if ok {
		_, _ = fmt.Fprintln(os.Stderr, "beacon: all tools ready.")
	} else {
		_, _ = fmt.Fprintln(os.Stderr, "beacon: some tools failed to install — see errors above.")
		os.Exit(1)
	}
}

// ---------- scan ----------

func cmdScan(cfg *config.Config, args []string) {
	var (
		domain              string
		assets              []string
		targetsFile         string
		githubOrg           string
		deep                bool
		permissionConfirmed bool
		authorized          bool
		autoApprove         bool
		outPath             string
		outputRawPath       string
		pocDir              string
		screenshotDir       string
		format              string
		severityFlag        string
		verbose             bool
		noTUI               bool
		noEnrich            bool
		noDB                bool
		anonymize           bool
		dryRun              bool
		noNmap              bool
		noNuclei            bool
		noTestssl           bool
		// noSqlmap            bool // TODO: wire when sqlmap integration lands
		// noWpscan            bool // TODO: wire when wpscan integration lands
		noMasscan           bool
		noArjun             bool
		strict              bool
		extraCIDRs          []string
		cloudEnabled        bool
		awsProfile          string
		gcpCredentials      string
		azureSubscription   string
		doToken             string
		ociConfigFile       string
		oktaDomain          string
		oktaToken           string
		scannersFlag        string
		portsFlag           string
		dnsServer           string
		wordlistPath        string
		logFile             string
		logLevel            string
		narratives          bool
		chaosProgram        string
		stdinTargets        bool
		scopeFile           string
		newOnly             bool
	)

	// --quiet can also be set via env var for automation.
	if os.Getenv("BEACON_QUIET") == "1" {
		quiet = true
	}

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--domain":
			i++
			if i < len(args) {
				domain = args[i]
			}
		case "--github":
			i++
			if i < len(args) {
				githubOrg = args[i]
			}
		case "--deep":
			deep = true
		case "--exploit":
			authorized = true
			deep = true
			permissionConfirmed = true
		case "--permission-confirmed":
			permissionConfirmed = true // backward compat
		case "--authorized":
			authorized = true // backward compat
		case "--yes":
			autoApprove = true
			permissionConfirmed = true // --yes implies permission confirmed
		case "--quiet":
			quiet = true
		case "--out":
			i++
			if i < len(args) {
				outPath = args[i]
			}
		case "--output-raw":
			i++
			if i < len(args) {
				outputRawPath = args[i]
			}
		case "--poc-dir":
			i++
			if i < len(args) {
				pocDir = args[i]
			}
		case "--screenshots":
			i++
			if i < len(args) {
				screenshotDir = args[i]
			}
		case "--format":
			i++
			if i < len(args) {
				format = args[i]
			}
		case "--severity":
			i++
			if i < len(args) {
				severityFlag = args[i]
			}
		case "--verbose":
			verbose = true
		case "--no-tui":
			noTUI = true
		case "--no-enrich":
			noEnrich = true
		case "--no-db":
			noDB = true
		case "--anonymize":
			anonymize = true
		case "--dry-run":
			dryRun = true
		case "--narratives":
			narratives = true
		case "--no-nmap":
			noNmap = true
		case "--no-nuclei":
			noNuclei = true
		case "--no-testssl":
			noTestssl = true
		case "--no-sqlmap":
			// noSqlmap = true
		case "--no-wpscan":
			// noWpscan = true
		case "--no-masscan":
			noMasscan = true
		case "--no-arjun":
			noArjun = true
		case "--strict":
			strict = true
		case "--cidr":
			i++
			if i < len(args) {
				extraCIDRs = append(extraCIDRs, args[i])
			}
		case "--host", "--asset":
			i++
			if i < len(args) {
				assets = append(assets, args[i])
			}
		case "--targets":
			i++
			if i < len(args) {
				targetsFile = args[i]
			}
		case "--cloud":
			cloudEnabled = true
		case "--aws-profile":
			i++
			if i < len(args) {
				awsProfile = args[i]
			}
		case "--gcp-credentials":
			i++
			if i < len(args) {
				gcpCredentials = args[i]
			}
		case "--azure-subscription":
			i++
			if i < len(args) {
				azureSubscription = args[i]
			}
		case "--do-token":
			i++
			if i < len(args) {
				doToken = args[i]
			}
		case "--oci-config":
			i++
			if i < len(args) {
				ociConfigFile = args[i]
			}
		case "--okta-domain":
			i++
			if i < len(args) {
				oktaDomain = args[i]
			}
		case "--okta-token":
			i++
			if i < len(args) {
				oktaToken = args[i]
			}
		case "--dns-server":
			i++
			if i < len(args) {
				dnsServer = args[i]
			}
		case "--scanners":
			i++
			if i < len(args) {
				scannersFlag = args[i]
			}
		case "--ports":
			i++
			if i < len(args) {
				portsFlag = args[i]
			}
		case "--wordlist":
			i++
			if i < len(args) {
				wordlistPath = args[i]
			}
		case "--log-file":
			i++
			if i < len(args) {
				logFile = args[i]
			}
		case "--log-level":
			i++
			if i < len(args) {
				logLevel = args[i]
			}
		case "--chaos":
			i++
			if i < len(args) {
				chaosProgram = args[i]
			}
		case "--stdin":
			stdinTargets = true
		case "--scope":
			i++
			if i < len(args) {
				scopeFile = args[i]
			}
		case "--new-only":
			newOnly = true
		default:
			if strings.HasPrefix(args[i], "--") {
				_, _ = fmt.Fprintf(os.Stderr, "beacon: unknown flag %q\n", args[i])
				os.Exit(2)
			}
		}
	}

	// Parse --scanners into a slice of scanner names.
	var scannersList []string
	if scannersFlag != "" {
		for _, s := range strings.Split(scannersFlag, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				scannersList = append(scannersList, s)
			}
		}
	}

	// Parse --ports into a slice of port numbers.
	var portsList []int
	if portsFlag != "" {
		for _, p := range strings.Split(portsFlag, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			n, err := strconv.Atoi(p)
			if err != nil || n <= 0 || n > 65535 {
				fatalf("invalid port %q in --ports", p)
			}
			portsList = append(portsList, n)
		}
	}

	// Validate --wordlist file exists if provided.
	if wordlistPath != "" {
		if _, err := os.Stat(wordlistPath); err != nil {
			fatalf("--wordlist: %v", err)
		}
	}

	// Override the default DNS resolver if --dns-server is set.
	if dnsServer != "" {
		net.DefaultResolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 5 * time.Second}
				return d.DialContext(ctx, network, dnsServer)
			},
		}
	}

	// Check for external tool availability.
	// Critical tools (nmap) cause a hard error; important tools warn with opt-out;
	// optional tools warn only. All warnings are grouped together.
	// --strict tool requirement check: nmap and nuclei are required tools.
	// With --strict, beacon hard-fails (exit 1) if any required tool is missing.
	// Without --strict, beacon warns and continues with reduced coverage.
	if strict {
		type requiredTool struct {
			name    string
			bin     string
			optOut  bool
			install string
		}
		strictRequired := []requiredTool{
			{"nmap", cfg.NmapBin, noNmap, "https://nmap.org/download"},
			{"nuclei", cfg.NucleiBin, noNuclei, "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
		}
		var missingStrict []string
		for _, rt := range strictRequired {
			if rt.optOut {
				continue
			}
			if _, err := exec.LookPath(rt.bin); err != nil {
				missingStrict = append(missingStrict, fmt.Sprintf("  %-14s not found. Install: %s", rt.name, rt.install))
			}
		}
		if len(missingStrict) > 0 {
			fatalf("beacon: --strict mode: required tools missing:\n%s\n\nInstall the missing tools or use --no-nmap / --no-nuclei to opt out.", strings.Join(missingStrict, "\n"))
		}
	}

	if noNmap {
		cfg.NmapBin = ""
	} else {
		if _, err := exec.LookPath(cfg.NmapBin); err != nil {
			fatalf("beacon: nmap not found. Install nmap (https://nmap.org/download) or pass --no-nmap to skip nmap integration.")
		}
	}
	// Critical tools — HARD FAIL if missing (unless explicitly opted out).
	// Skip this check when --scanners is used (filtered mode only needs
	// the requested scanners, not the full toolchain).
	// Use --no-<tool> to opt out explicitly.
	if len(scannersList) == 0 {
	criticalTools := []struct {
		name    string
		bin     string
		optOut  bool
		install string
	}{
		{"nuclei", cfg.NucleiBin, noNuclei, "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
		{"subfinder", "subfinder", false, "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
		{"katana", cfg.KatanaBin, false, "go install github.com/projectdiscovery/katana/cmd/katana@latest"},
		{"ffuf", cfg.FfufBin, false, "go install github.com/ffuf/ffuf/v2@latest"},
		{"gau", "gau", false, "go install github.com/lc/gau/v2/cmd/gau@latest"},
		{"httpx", cfg.HttpxBin, false, "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"},
		{"dnsx", cfg.DnsxBin, false, "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"},
	}

	var missingCritical []string
	for _, tc := range criticalTools {
		if tc.optOut {
			continue
		}
		if _, err := exec.LookPath(tc.bin); err != nil {
			missingCritical = append(missingCritical, fmt.Sprintf("  %-14s not found. Install: %s", tc.name, tc.install))
		}
	}
	if len(missingCritical) > 0 {
		_, _ = fmt.Fprintf(os.Stderr, "beacon: WARNING — required tools not found (reduced coverage):\n%s\n\n", strings.Join(missingCritical, "\n"))
		_, _ = fmt.Fprintf(os.Stderr, "Run: scripts/install-tools.sh  (or install manually)\n")
	}
	} // end if len(scannersList) == 0

	// Optional tools — WARN if missing but continue.
	// These enhance scanning but aren't required for core functionality.
	type optionalTool struct {
		name    string
		bin     string
		optOut  bool
		purpose string
	}
	optionalTools := []optionalTool{
		{"testssl", cfg.TestsslBin, noTestssl, "deep TLS vulnerability scanning"},
		{"masscan", cfg.MasscanBin, noMasscan, "fast CIDR/subnet port scanning"},
		{"arjun", cfg.ArjunBin, noArjun, "parameter discovery"},
	}

	var missingOptional []string
	for _, ot := range optionalTools {
		if ot.optOut {
			continue
		}
		if _, err := exec.LookPath(ot.bin); err != nil {
			missingOptional = append(missingOptional, fmt.Sprintf("  %-14s %s", ot.name, ot.purpose))
		}
	}
	if len(missingOptional) > 0 {
		_, _ = fmt.Fprintf(os.Stderr, "beacon: optional tools not found (reduced coverage):\n%s\n\n", strings.Join(missingOptional, "\n"))
	}

	if noNuclei {
		cfg.NucleiBin = ""
	}
	if noTestssl {
		cfg.TestsslBin = ""
	}
	if noMasscan {
		cfg.MasscanBin = ""
	}
	if noArjun {
		cfg.ArjunBin = ""
	}

	// Build unified target list from --domain, --asset, --targets, --stdin, and --chaos.
	if domain != "" {
		assets = append([]string{domain}, assets...)
	}
	if targetsFile != "" {
		lines, err := readTargetsFile(targetsFile)
		if err != nil {
			fatalf("read --targets: %v", err)
		}
		assets = append(assets, lines...)
	}
	if stdinTargets {
		stdinHosts, err := recon.ReadTargetsFromStdin()
		if err != nil {
			fatalf("read stdin: %v", err)
		}
		assets = append(assets, stdinHosts...)
	}
	if chaosProgram != "" {
		chaosCtx, chaosCancel := context.WithTimeout(context.Background(), 30*time.Second)
		chaosDomains, err := recon.FetchChaosDomains(chaosCtx, chaosProgram)
		chaosCancel()
		if err != nil {
			fatalf("chaos: %v", err)
		}
		info("beacon: loaded %d targets from Chaos program %q\n", len(chaosDomains), chaosProgram)
		assets = append(assets, chaosDomains...)
	}
	// Apply scope filtering if a scope file is provided.
	if scopeFile != "" {
		sc, err := recon.LoadScopeFile(scopeFile)
		if err != nil {
			fatalf("load scope: %v", err)
		}
		before := len(assets)
		assets = sc.FilterInScope(assets)
		if filtered := before - len(assets); filtered > 0 {
			info("beacon: scope filter removed %d out-of-scope targets (%d remaining)\n", filtered, len(assets))
		}
	}
	assets = uniqueStrings(assets)

	// GitHub-only mode (no domain targets) — delegate to the dedicated function.
	if githubOrg != "" && len(assets) == 0 {
		cmdScanGitHub(cfg, githubOrg, outPath, format, severityFlag)
		return
	}

	if len(assets) == 0 && githubOrg == "" {
		fatalf("--domain, --host, --targets, --stdin, --chaos, or --github is required\n\n%s", usageText)
	}

	// Multi-asset mode: scan all targets in a single session.
	// Also entered when --github is combined with domain targets, or when
	// --cloud is requested alongside domain scanning.
	if len(assets) > 1 || githubOrg != "" || cloudEnabled {
		cmdScanMultiAsset(cfg, assets, deep, permissionConfirmed, authorized, autoApprove, outPath, outputRawPath, format, severityFlag, verbose, noTUI, noEnrich, noDB, extraCIDRs, cloudEnabled, awsProfile, gcpCredentials, azureSubscription, doToken, ociConfigFile, oktaDomain, oktaToken, githubOrg, scannersList, portsList, dryRun, logFile, logLevel, wordlistPath, screenshotDir)
		return
	}

	// Single-asset: fall through to the existing scan path.
	domain = assets[0]

	if deep && !permissionConfirmed {
		if autoApprove || os.Getenv("BEACON_AUTHORIZED_ACK") == "1" {
			permissionConfirmed = true
		} else {
			_, _ = fmt.Fprintf(os.Stderr, `
Deep scans send active probes to %s: vulnerability payloads (XSS, SQLi,
SSRF), credential attempts, and service exploitation. This constitutes
unauthorized access without explicit written permission from the owner.

Do you have written authorization to scan %s? [y/N] `, domain, domain)
			reader := bufio.NewReader(os.Stdin)
			line, err := reader.ReadString('\n')
			if err != nil || !strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "y") {
				fatalf("Permission not confirmed. Use --yes to skip prompts in CI.")
			}
			permissionConfirmed = true
		}
	}

	// --authorized implies --deep and --permission-confirmed.
	if authorized {
		deep = true
		permissionConfirmed = true
	}
	if authorized && !autoApprove && os.Getenv("BEACON_AUTHORIZED_ACK") != "1" {
		_, _ = fmt.Fprintf(os.Stderr, `
Exploitation mode enables active exploitation against %s: payload injection,
credential testing, file upload bypass, token forgery.

Do you have written authorization to exploit %s? [y/N] `, domain, domain)
		reader := bufio.NewReader(os.Stdin)
		line, err := reader.ReadString('\n')
		if err != nil || !strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "y") {
			fatalf("Exploitation mode cancelled.")
		}
	} else if authorized {
		info("beacon: exploitation mode (--exploit --yes)\n")
	}

	scanType := module.ScanSurface
	if deep {
		scanType = module.ScanDeep
	}
	if authorized {
		scanType = module.ScanAuthorized
	}


	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Inject exploit module approval gate for authorized mode.
	if authorized && !autoApprove {
		ctx = postexploit.WithApproveFunc(ctx, interactiveApproveExploit)
	} else if authorized && autoApprove {
		// --yes: auto-approve all exploit modules without prompting.
		ctx = postexploit.WithApproveFunc(ctx, func(string, string, int) bool { return true })
	}

	// Set up structured logging. When --log-file is specified, logs go to that
	// file. When --verbose is set or --log-level is "debug", logs go to stderr
	// so developers can see the full execution chain in the terminal.
	if logFile != "" {
		sl := scanlog.New(logFile, scanlog.ParseLevel(logLevel))
		defer func() { _ = sl.Close() }()
		ctx = scanlog.WithLogger(ctx, sl)
	} else if verbose || logLevel == "debug" {
		level := scanlog.ParseLevel(logLevel)
		if verbose && level > slog.LevelDebug {
			level = slog.LevelDebug
		}
		sl := scanlog.New("", level) // "" → stderr
		ctx = scanlog.WithLogger(ctx, sl)
	}

	// Open store — use in-memory store when --no-db is set to avoid
	// persisting scan history (useful for drydock tests, CI, quick checks).
	var st store.Store
	if noDB {
		st = memstore.New()
	} else {
		sqlst, err := sqlitestore.Open(cfg.Store.Path)
		if err != nil {
			fatalf("open store: %v", err)
		}
		defer func() { _ = sqlst.Close() }()
		st = sqlst

		// Seed built-in fingerprint rules (idempotent — safe to call every scan).
		if seedErr := fingerprintdb.Seed(ctx, st); seedErr != nil {
			info("beacon: warning: fingerprint seed failed: %v\n", seedErr)
		}
	}

	// Upsert target
	target, err := st.UpsertTarget(ctx, domain)
	if err != nil {
		fatalf("upsert target: %v", err)
	}

	// Create scan run
	run := &store.ScanRun{
		TargetID:  target.ID,
		Domain:    domain,
		ScanType:  scanType,
		Modules:   []string{"surface"},
		Status:    store.StatusPending,
		StartedAt: time.Now(),
	}
	if err := st.CreateScanRun(ctx, run); err != nil {
		fatalf("create scan run: %v", err)
	}

	info("beacon: scanning %s (%s)\n", domain, scanType)

	// Warn about missing API keys that meaningfully reduce scan coverage.
	warnMissingAPIKeys(cfg)

	run.Status = store.StatusRunning
	_ = st.UpdateScanRun(ctx, run)

	// Run surface module
	mod, err := surface.New(surface.Config{
		NucleiBin:       cfg.NucleiBin,
		SubfinderBin:    "subfinder",
		TestsslBin:      cfg.TestsslBin,
		GauBin:          cfg.GauBin,
		KatanaBin:       cfg.KatanaBin,
		GowitnessBin:    cfg.GowitnessBin,
		AnthropicAPIKey:      cfg.AnthropicAPIKey,
		ShodanAPIKey:         cfg.ShodanAPIKey,
		HIBPAPIKey:           cfg.HIBPAPIKey,
		BingAPIKey:           cfg.BingAPIKey,
		OTXAPIKey:            cfg.OTXAPIKey,
		VirusTotalAPIKey:     cfg.VirusTotalAPIKey,
		SecurityTrailsAPIKey: cfg.SecurityTrailsAPIKey,
		CensysAPIID:          cfg.CensysAPIID,
		CensysAPISecret:      cfg.CensysAPISecret,
		GreyNoiseAPIKey:      cfg.GreyNoiseAPIKey,
		NmapBin:              cfg.NmapBin,
		Store:                st,
		HttpxBin:             cfg.HttpxBin,
		DnsxBin:              cfg.DnsxBin,
		FfufBin:              cfg.FfufBin,
		AdaptiveRecon:        cfg.AdaptiveRecon,
		ProxyPool:            cfg.ProxyPool,
		RequestJitterMs:      cfg.RequestJitterMs,
		ClaudeModel:          cfg.ClaudeModel,
		Auth:                 cfg.Auth,
		GitHubToken:          cfg.GitHubToken,
		OktaDomain:           cfg.OktaDomain,
		OktaToken:            cfg.OktaToken,
		WordlistPath:         wordlistPath,
		ScreenshotsEnabled:   screenshotDir != "",
	})
	if err != nil {
		fatalf("init scanner: %v", err)
	}

	var pr *progressRenderer
	if noTUI {
		pr = newPlainRenderer(verbose, finding.ParseSeverity(severityFlag))
	} else {
		pr = newProgressRenderer(verbose, finding.ParseSeverity(severityFlag))
	}
	pr.cancelFn = cancel // allow the live UI to stop the scan via 's' or Ctrl+C
	defer pr.Done()      // always restore terminal, even on panic
	input := module.Input{
		Domain:              domain,
		PermissionConfirmed: permissionConfirmed,
		ScanRunID:           run.ID,
		Progress:            pr.Handle,
		ExtraCIDRs:          extraCIDRs,
		Scanners:            scannersList,
		Ports:               portsList,
		DryRun:              dryRun,
	}

	// Run the scan in a goroutine so we can respond to a detach signal.
	type scanResult struct {
		findings []finding.Finding
		err      error
	}
	resultCh := make(chan scanResult, 1)
	scanDone := make(chan struct{}) // closed when the scan goroutine exits
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("beacon: scan goroutine panic (recovered): %v", r)
				debug.PrintStack()
				resultCh <- scanResult{nil, fmt.Errorf("scan panicked: %v", r)}
				close(scanDone)
			}
		}()
		f, e := mod.Run(ctx, input, scanType)
		resultCh <- scanResult{f, e}
		close(scanDone)
	}()

	// Wait for scan completion or user detach (b/Esc pressed in live UI).
	// waitScanResult drains resultCh and handles cancellation gracefully.
	// Returns (findings, stopped) where stopped=true means user cancelled via q.
	waitScanResult := func() ([]finding.Finding, bool) {
		res := <-resultCh
		if res.err != nil {
			// Use a fresh context for post-cancellation DB cleanup so saves
			// don't fail with "context canceled".
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cleanupCancel()
			if errors.Is(res.err, context.Canceled) || strings.Contains(res.err.Error(), "context canceled") {
				// Graceful user stop — save partial findings, mark stopped.
				run.Status = store.StatusStopped
				run.Error = "stopped by user"
				_ = st.UpdateScanRun(cleanupCtx, run)
				if len(res.findings) > 0 {
					if err := st.SaveFindings(cleanupCtx, run.ID, res.findings); err != nil {
						_, _ = fmt.Fprintf(os.Stderr, "beacon: save partial findings: %v\n", err)
					}
				}
				return res.findings, true
			}
			run.Status = store.StatusFailed
			run.Error = res.err.Error()
			_ = st.UpdateScanRun(cleanupCtx, run)
			fatalf("scan failed: %v", res.err)
		}
		return res.findings, false
	}

	var findings []finding.Finding
	select {
	case res := <-resultCh:
		pr.Done() // restore terminal before any post-scan output
		if res.err != nil {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cleanupCancel()
			if errors.Is(res.err, context.Canceled) || strings.Contains(res.err.Error(), "context canceled") {
				run.Status = store.StatusStopped
				run.Error = "stopped by user"
				_ = st.UpdateScanRun(cleanupCtx, run)
				if len(res.findings) > 0 {
					if err := st.SaveFindings(cleanupCtx, run.ID, res.findings); err != nil {
						_, _ = fmt.Fprintf(os.Stderr, "beacon: save partial findings: %v\n", err)
					}
				}
				_, _ = fmt.Fprintf(os.Stderr, "beacon: scan stopped — %d findings saved\n", len(res.findings))
				if !noTUI {
					cmdBrowse(cfg)
				}
				return
			}
			run.Status = store.StatusFailed
			run.Error = res.err.Error()
			_ = st.UpdateScanRun(cleanupCtx, run)
			fatalf("scan failed: %v", res.err)
		}
		findings = res.findings
	case <-pr.detached:
		// User pressed b — restore terminal and show browse TUI.
		// The scan goroutine continues; we wait for it after the browser exits.
		pr.Done()
		// Register this scan as a liveJob so browseInteractive can attach/stop it.
		pr.mu.Lock()
		pr.headless = true
		pr.detached = make(chan struct{}) // reset for potential re-attach
		pr.stop = make(chan struct{})
		pr.stopOnce = sync.Once{}
		pr.detachOnce = sync.Once{}
		pr.drawn = false
		pr.drawnLines = 0
		pr.mu.Unlock()
		lj := &liveJob{
			runID:    run.ID,
			domain:   domain,
			scanType: string(scanType),
			cancel:   cancel,
			renderer: pr,
			done:     scanDone,
		}
		registerJob(lj)
		cmdBrowseWithAttach(cfg, run.ID) // blocks until user quits the browser
		// User quit browse — exit beacon. The scan goroutine is cancelled via
		// the signal context (Ctrl+C) or will be cleaned up on process exit.
		// Mark the run as stopped so it doesn't stay "running" in history.
		unregisterJob(run.ID)
		select {
		case <-scanDone:
			// Scan already finished while we were in browse — fall through to save.
		default:
			// Still running — mark stopped and exit. Findings saved so far are lost.
			// Use a fresh context because the scan context may already be cancelled.
			dbCtx, dbCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer dbCancel()
			run.Status = store.StatusStopped
			run.Error = "detached by user"
			_ = st.UpdateScanRun(dbCtx, run)
			return
		}
		// Scan finished while in browse — save its results.
		var stopped bool
		findings, stopped = waitScanResult()
		if stopped {
			return
		}
	}

	// Save raw findings
	if err := st.SaveFindings(ctx, run.ID, findings); err != nil {
		fatalf("save findings: %v", err)
	}

	// Log all findings to structured log file (if --log-file was specified).
	sl := scanlog.FromContext(ctx)
	sl.ScanStart(domain, string(scanType), []string{domain})
	for _, f := range findings {
		sl.Finding(f)
	}
	sl.ScanComplete(domain, len(findings), time.Since(run.StartedAt))

	// Run deterministic compound-attack correlation rules synchronously.
	// These fire without AI and appear in the TUI even when AI is skipped.
	if corrFindings, err := analyze.RunDeterministicCorrelations(ctx, st, run.ID, domain); err != nil {
		info("beacon: deterministic correlations: %v\n", err)
	} else if len(corrFindings) > 0 {
		info("beacon: %d compound attack chain(s) detected\n", len(corrFindings))
	}

	// Build asset graph for this single-domain scan.
	graphBuilder := asset.NewBuilder(run.ID, domain)
	graphBuilder.AddDomainAsset(domain, nil, "surface")
	graphBuilder.AddFindings(findings)
	scanGraph := graphBuilder.Build()

	// Persist the graph so `beacon report --format graph` can retrieve it later.
	if graphJSON, err := json.Marshal(scanGraph); err == nil {
		_ = st.SaveAssetGraph(ctx, run.ID, graphJSON)
	}

	// AI fingerprint enrichment: analyse collected evidence to find
	// version-specific vulnerabilities and configuration anomalies.
	if ai := cfg.ActiveAI(); ai != nil && !noEnrich {
		if execs, execErr := st.ListAssetExecutions(ctx, run.ID); execErr == nil && len(execs) > 0 {
			var fpInputs []enrichment.FingerprintInput
			for _, ex := range execs {
				fpInputs = append(fpInputs, enrichment.FingerprintInputFromEvidence(ex.Asset, ex.Evidence))
			}
			ce, ceErr := enrichment.NewWithProvider(ai.Provider, ai.APIKey, ai.Model, ai.BaseURL)
			if ceErr == nil {
				info("beacon: analysing fingerprints for %d asset(s)...\n", len(fpInputs))
				fpResult, fpErr := ce.EnrichFingerprints(ctx, fpInputs)
				if fpErr != nil {
					info("beacon: fingerprint enrichment: %v\n", fpErr)
				} else if len(fpResult.Findings) > 0 {
					info("beacon: fingerprint analysis found %d issue(s)\n", len(fpResult.Findings))
					findings = append(findings, fpResult.Findings...)
					if err := st.SaveFindings(ctx, run.ID, fpResult.Findings); err != nil {
						_, _ = fmt.Fprintf(os.Stderr, "beacon: save fingerprint findings: %v\n", err)
					}
				}

				// FillGaps — ask AI to identify technologies the heuristic engine missed.
				// Proposed rules are saved with status=pending for human approval.
				info("beacon: checking for fingerprint detection gaps...\n")
				gapResult, gapErr := ce.FillGaps(ctx, fpInputs)
				if gapErr != nil {
					info("beacon: fillgaps: %v\n", gapErr)
				} else {
					if len(gapResult.ProposedRules) > 0 {
						info("beacon: AI proposed %d new fingerprint rule(s) — run 'beacon fingerprints pending' to review\n", len(gapResult.ProposedRules))
						for _, pr := range gapResult.ProposedRules {
							rule := store.FingerprintRule{
								SignalType:  pr.SignalType,
								SignalKey:   pr.SignalKey,
								SignalValue: pr.SignalValue,
								Field:       pr.Field,
								Value:       pr.Value,
								Source:      "ai",
								Status:      "pending",
								Confidence:  pr.Confidence,
							}
							if err := st.UpsertFingerprintRule(ctx, &rule); err != nil {
								_, _ = fmt.Fprintf(os.Stderr, "beacon: save proposed rule: %v\n", err)
							}
						}
					}
					if len(gapResult.MissedTechnologies) > 0 {
						info("beacon: AI identified %d undetected technolog(ies)\n", len(gapResult.MissedTechnologies))
					}
				}
			}
		}
	}

	// Apply severity filter before enrichment so below-threshold findings are
	// never sent to the Claude API — saves tokens and keeps prompts focused.
	totalFindingCount := len(findings)
	minSev := finding.ParseSeverity(severityFlag)
	if minSev > finding.SeverityInfo {
		var filtered []finding.Finding
		for _, f := range findings {
			if f.Severity >= minSev {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}

	// Flag potential duplicates across scanners and overlapping assets.
	dedup.FlagDuplicates(findings)

	// Save scan history for cross-run dedup.
	if !noDB {
		if err := recon.SaveScanHistory(run.ID, domain, findings); err != nil {
			info("beacon: save history: %v\n", err)
		}
	}

	// --new-only: filter to findings not seen in the previous scan.
	if newOnly {
		prev, err := recon.LatestScanHistory(domain)
		if err != nil {
			info("beacon: load previous scan history: %v\n", err)
		} else if prev != nil && prev.ScanID != run.ID {
			beforeCount := len(findings)
			findings = recon.FilterNewFindings(findings, prev.Findings)
			info("beacon: --new-only filtered %d findings to %d new (baseline: %s)\n",
				beforeCount, len(findings), prev.ScanID)
		}
	}

	// --output-raw: write raw findings and exit before enrichment.
	if outputRawPath != "" {
		scanTypeStr := string(scanType)
		raw, err := report.RenderRawJSON(domain, scanTypeStr, run.ID, run.StartedAt, findings)
		if err != nil {
			fatalf("render raw findings: %v", err)
		}
		if err := os.WriteFile(outputRawPath, []byte(raw), 0o600); err != nil {
			fatalf("write raw findings: %v", err)
		}
		// Mark completed so the run shows in history.
		now := time.Now()
		run.Status = store.StatusCompleted
		run.CompletedAt = &now
		run.FindingCount = totalFindingCount
		_ = st.UpdateScanRun(ctx, run)
		info("beacon: %d raw findings written to %s\n", len(findings), outputRawPath)
		info("beacon: enrich later with: beacon enrich --input %s\n", outputRawPath)
		return
	}

	// Dry-run: output the plan as JSON and exit — no enrichment or report.
	if dryRun {
		out, _ := json.MarshalIndent(findings, "", "  ")
		fmt.Println(string(out))
		return
	}

	// Enrich findings — skip AI enrichment when --no-enrich is set.
	var enricher enrichment.Enricher
	if noEnrich {
		enricher = enrichment.NewNoop()
		info("beacon: %d findings — building report (enrichment disabled)...\n", len(findings))
	} else if ai := cfg.ActiveAI(); ai != nil {
		ce, err := enrichment.NewWithProvider(ai.Provider, ai.APIKey, ai.Model, ai.BaseURL)
		if err != nil {
			fatalf("init enricher: %v", err)
		}
		enricher = ce.WithCache(st)
		if anonymize || cfg.AnonymizeAI {
			enricher = enrichment.NewAnonymizingEnricher(enricher)
			info("beacon: anonymize mode — IPs and hostnames will be stripped before AI analysis\n")
		}
		info("beacon: %d findings — enriching with AI (%s)...\n", len(findings), ai.Provider)
	} else {
		enricher = enrichment.NewNoop()
		info("beacon: %d findings — building report...\n", len(findings))
	}

	enriched, err := enricher.Enrich(ctx, findings)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "beacon: enrich: %v\n", err)
		// Fall back to unenriched findings so scanning results are not lost.
		enriched = make([]enrichment.EnrichedFinding, len(findings))
		for i, f := range findings {
			enriched[i] = enrichment.EnrichedFinding{Finding: f}
		}
	}

	var summary string
	if !noEnrich && cfg.ActiveAI() != nil && err == nil {
		info("beacon: generating executive summary...\n")
		enriched, summary, err = enricher.ContextualizeAndSummarize(ctx, enriched, domain)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "beacon: contextualize: %v\n", err)
		}
	}

	// Drop findings Claude marked as having no actionable value given other controls.
	enriched = filterOmitted(enriched)

	// Apply minimum-severity filter.
	enriched = filterBySeverity(enriched, severityFlag)

	if err := st.SaveEnrichedFindings(ctx, run.ID, enriched); err != nil {
		fatalf("save enriched findings: %v", err)
	}

	// Mark completed
	now := time.Now()
	run.Status = store.StatusCompleted
	run.CompletedAt = &now
	run.FindingCount = totalFindingCount
	if err := st.UpdateScanRun(ctx, run); err != nil {
		fatalf("update scan run: %v", err)
	}

	// Build HTML report (always saved to store for history/re-export).
	rep, err := report.Build(report.Input{
		ScanRun:          *run,
		EnrichedFindings: enriched,
		ExecutiveSummary: summary,
	})
	if err != nil {
		fatalf("build report: %v", err)
	}

	if err := st.SaveReport(ctx, rep); err != nil {
		fatalf("save report: %v", err)
	}

	// Capture screenshots if requested.
	if screenshotDir != "" {
		info("beacon: capturing screenshots...\n")
		if err := report.CaptureScreenshots(findings, screenshotDir); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "beacon: screenshot capture: %v\n", err)
		} else {
			info("beacon: screenshots saved to %s\n", screenshotDir)
		}
	}

	// Deliver in the requested format.
	// Retrieve persisted graph JSON so renderFormat can include it in JSON
	// reports or render DOT output for --format graph.
	persistedGraphJSON, _ := st.GetAssetGraph(ctx, run.ID)
	executions, _ := st.ListAssetExecutions(ctx, run.ID)

	// PDF format is handled separately since it writes a binary file.
	if strings.EqualFold(format, "pdf") {
		pdfPath := outPath
		if pdfPath == "" {
			pdfPath = fmt.Sprintf("beacon-report-%s.pdf", run.Domain)
		}
		if err := report.RenderPDF(*run, enriched, summary, executions, screenshotDir, pdfPath); err != nil {
			fatalf("render PDF: %v", err)
		}
		info("beacon: PDF report written to %s\n", pdfPath)
	} else {
		renderOpts := []string{screenshotDir}
		if narratives {
			renderOpts = append(renderOpts, "narratives")
		}
		output, err := renderFormat(format, *run, enriched, summary, rep, executions, persistedGraphJSON, renderOpts...)
		if err != nil {
			fatalf("render report: %v", err)
		}

		if outPath != "" {
			if err := os.WriteFile(outPath, []byte(output), 0o600); err != nil {
				fatalf("write report file: %v", err)
			}
			info("beacon: report written to %s\n", outPath)
		} else {
			fmt.Print(output)
		}
	}

	// PoC bundle generation: write standalone exploit scripts for each finding.
	if pocDir != "" {
		if err := report.RenderPoCBundle(findings, pocDir); err != nil {
			fatalf("generate poc bundle: %v", err)
		}
		info("beacon: %d PoC files written to %s\n", len(findings), pocDir)
	}
	// Attack path analysis: uses Claude (Anthropic) specifically.
	// Requires anthropic_api_key in config regardless of the ai: provider block.
	if cfg.AttackPathAnalysis && cfg.AnthropicAPIKey != "" && len(findings) >= 2 {
		info("beacon: analysing attack paths...\n")
		chains := profiler.ReasonAttackPaths(ctx, cfg.AnthropicAPIKey, cfg.ClaudeModel, findings)
		if f := profiler.BuildAttackPathFinding(domain, chains); f != nil {
			info("beacon: %d attack path(s) identified\n", len(chains))
			if err := st.SaveFindings(ctx, run.ID, []finding.Finding{*f}); err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "beacon: save attack path findings: %v\n", err)
			}
		}
	}

	// Webhook delivery: POST a structured JSON findings payload to the configured
	// endpoint so findings can be streamed to a SIEM or external platform.
	if cfg.WebhookURL != "" {
		if err := deliverWebhook(ctx, cfg.WebhookURL, cfg.WebhookAPIKey, *run, enriched, summary); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "beacon: webhook delivery failed: %v\n", err)
		} else {
			info("beacon: findings posted to webhook\n")
		}
	}

	// Post-scan review summary: show pending fingerprint rules and playbook suggestions.
	{
		pendingRules, _ := st.GetFingerprintRules(ctx, "pending")
		pendingSuggs, _ := st.ListPlaybookSuggestions(ctx, "pending")
		if len(pendingRules) > 0 || len(pendingSuggs) > 0 {
			info("\nbeacon: review pending —")
			if len(pendingRules) > 0 {
				info(" %d fingerprint rule%s", len(pendingRules), pluralS(len(pendingRules)))
			}
			if len(pendingSuggs) > 0 {
				if len(pendingRules) > 0 {
					info(" ·")
				}
				info(" %d playbook suggestion%s", len(pendingSuggs), pluralS(len(pendingSuggs)))
			}
			info("\n  run: beacon fingerprints pending  |  beacon playbook suggestions\n")
		}
	}
	info("beacon: done — scan ID: %s\n", run.ID)
}

// ---------- multi-asset scan ----------

// assetScanResult holds the outcome of a single-domain scan within a
// multi-asset session.
type assetScanResult struct {
	domain   string
	run      *store.ScanRun
	findings []finding.Finding
}

// cmdScanMultiAsset runs one scan session against multiple root domains.
// Each domain gets its own ScanRun in the store. After all individual scans
// complete, cross-asset correlations are computed over the combined findings.
func cmdScanMultiAsset(
	cfg *config.Config,
	targets []string,
	deep, permissionConfirmed, authorized, autoApproveExploits bool,
	outPath, outputRawPath, format, severityFlag string,
	verbose, noTUI, noEnrich, noDB bool,
	extraCIDRs []string,
	cloudEnabled bool,
	awsProfile, gcpCredentials, azureSubscription string,
	doToken, ociConfigFile string,
	oktaDomain, oktaToken string,
	githubOrg string,
	scannersList []string,
	portsList []int,
	dryRun bool,
	logFile, logLevel string,
	wordlistPath string,
	screenshotDir string,
) {
	scanType := module.ScanSurface
	if deep {
		scanType = module.ScanDeep
	}
	if authorized {
		scanType = module.ScanAuthorized
	}

	// --authorized/--exploit implies --deep.
	if authorized {
		deep = true
		permissionConfirmed = true
	}

	if deep && !permissionConfirmed {
		if autoApproveExploits || os.Getenv("BEACON_AUTHORIZED_ACK") == "1" {
			permissionConfirmed = true
		} else {
			_, _ = fmt.Fprintf(os.Stderr, `
Deep scans send active probes to %d targets. This constitutes unauthorized
access without explicit written permission from the owner.

Do you have written authorization to scan all listed targets? [y/N] `, len(targets))
			reader := bufio.NewReader(os.Stdin)
			line, err := reader.ReadString('\n')
			if err != nil || !strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "y") {
				fatalf("Permission not confirmed. Use --yes to skip prompts in CI.")
			}
			permissionConfirmed = true
		}
	}

	if authorized {
		if os.Getenv("BEACON_AUTHORIZED_ACK") != "1" && !autoApproveExploits {
			targetList := "  • " + strings.Join(targets, "\n  • ")
			_, _ = fmt.Fprintf(os.Stderr, `
EXPLOITATION MODE — %d targets:
%s

This enables active exploitation: payload injection, credential testing,
file upload bypass, token forgery. Do you have written authorization? [y/N] `, len(targets), targetList)
			reader := bufio.NewReader(os.Stdin)
			line, err := reader.ReadString('\n')
			if err != nil || !strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "y") {
				fatalf("Exploitation mode cancelled.")
			}
		} else {
			info("beacon: BEACON_AUTHORIZED_ACK=1 — skipping interactive prompt (CI mode)\n")
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Inject exploit module approval gate for authorized mode.
	if authorized && !autoApproveExploits {
		ctx = postexploit.WithApproveFunc(ctx, interactiveApproveExploit)
	} else if authorized && autoApproveExploits {
		ctx = postexploit.WithApproveFunc(ctx, func(string, string, int) bool { return true })
	}

	// Set up structured logging. When --log-file is specified, logs go to that
	// file. When --verbose is set or --log-level is "debug", logs go to stderr.
	if logFile != "" {
		sl := scanlog.New(logFile, scanlog.ParseLevel(logLevel))
		defer func() { _ = sl.Close() }()
		ctx = scanlog.WithLogger(ctx, sl)
	} else if verbose || logLevel == "debug" {
		level := scanlog.ParseLevel(logLevel)
		if verbose && level > slog.LevelDebug {
			level = slog.LevelDebug
		}
		sl := scanlog.New("", level) // "" → stderr
		ctx = scanlog.WithLogger(ctx, sl)
	}

	var st store.Store
	if noDB {
		st = memstore.New()
	} else {
		sqlst, err := sqlitestore.Open(cfg.Store.Path)
		if err != nil {
			fatalf("open store: %v", err)
		}
		defer func() { _ = sqlst.Close() }()
		st = sqlst
		if seedErr := fingerprintdb.Seed(ctx, st); seedErr != nil {
			info("beacon: warning: fingerprint seed failed: %v\n", seedErr)
		}
	}

	warnMissingAPIKeys(cfg)

	mod, err := surface.New(surface.Config{
		NucleiBin:            cfg.NucleiBin,
		SubfinderBin:         "subfinder",
		TestsslBin:           cfg.TestsslBin,
		GauBin:               cfg.GauBin,
		KatanaBin:            cfg.KatanaBin,
		GowitnessBin:         cfg.GowitnessBin,
		AnthropicAPIKey:      cfg.AnthropicAPIKey,
		ShodanAPIKey:         cfg.ShodanAPIKey,
		HIBPAPIKey:           cfg.HIBPAPIKey,
		BingAPIKey:           cfg.BingAPIKey,
		OTXAPIKey:            cfg.OTXAPIKey,
		VirusTotalAPIKey:     cfg.VirusTotalAPIKey,
		SecurityTrailsAPIKey: cfg.SecurityTrailsAPIKey,
		CensysAPIID:          cfg.CensysAPIID,
		CensysAPISecret:      cfg.CensysAPISecret,
		GreyNoiseAPIKey:      cfg.GreyNoiseAPIKey,
		NmapBin:              cfg.NmapBin,
		Store:                st,
		HttpxBin:             cfg.HttpxBin,
		DnsxBin:              cfg.DnsxBin,
		FfufBin:              cfg.FfufBin,
		AdaptiveRecon:        cfg.AdaptiveRecon,
		ProxyPool:            cfg.ProxyPool,
		RequestJitterMs:      cfg.RequestJitterMs,
		ClaudeModel:          cfg.ClaudeModel,
		Auth:                 cfg.Auth,
		GitHubToken:          cfg.GitHubToken,
		OktaDomain:           strOr(oktaDomain, cfg.OktaDomain),
		OktaToken:            strOr(oktaToken, cfg.OktaToken),
		WordlistPath:         wordlistPath,
		ScreenshotsEnabled:   screenshotDir != "",
	})
	if err != nil {
		fatalf("init scanner: %v", err)
	}

	info("beacon: multi-asset scan — %d targets (%s)\n", len(targets), scanType)
	for _, t := range targets {
		info("  • %s\n", t)
	}

	var (
		allResults  []assetScanResult
		allFindings []finding.Finding
	)

	for idx, domain := range targets {
		if ctx.Err() != nil {
			break
		}

		// Build peers list (every other target in this session).
		peers := make([]string, 0, len(targets)-1)
		for j, t := range targets {
			if j != idx {
				peers = append(peers, t)
			}
		}

		target, err := st.UpsertTarget(ctx, domain)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "beacon: upsert target %s: %v\n", domain, err)
			continue
		}

		run := &store.ScanRun{
			TargetID:  target.ID,
			Domain:    domain,
			ScanType:  scanType,
			Modules:   []string{"surface"},
			Status:    store.StatusPending,
			StartedAt: time.Now(),
		}
		if err := st.CreateScanRun(ctx, run); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "beacon: create scan run %s: %v\n", domain, err)
			continue
		}

		info("\nbeacon: [%d/%d] scanning %s\n", idx+1, len(targets), domain)
		run.Status = store.StatusRunning
		_ = st.UpdateScanRun(ctx, run)

		var pr *progressRenderer
		if noTUI {
			pr = newPlainRenderer(verbose, finding.ParseSeverity(severityFlag))
		} else {
			pr = newProgressRenderer(verbose, finding.ParseSeverity(severityFlag))
		}
		pr.cancelFn = cancel

		input := module.Input{
			Domain:              domain,
			Peers:               peers,
			PermissionConfirmed: permissionConfirmed,
			ScanRunID:           run.ID,
			Progress:            pr.Handle,
			ExtraCIDRs:          extraCIDRs,
			Scanners:            scannersList,
			Ports:               portsList,
			DryRun:              dryRun,
		}

		findings, scanErr := mod.Run(ctx, input, scanType)
		pr.Done()

		if scanErr != nil {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
			if errors.Is(scanErr, context.Canceled) || strings.Contains(scanErr.Error(), "context canceled") {
				run.Status = store.StatusStopped
				run.Error = "stopped by user"
				_ = st.UpdateScanRun(cleanupCtx, run)
				if len(findings) > 0 {
					if err := st.SaveFindings(cleanupCtx, run.ID, findings); err != nil {
						_, _ = fmt.Fprintf(os.Stderr, "beacon: save partial findings %s: %v\n", domain, err)
					}
				}
				cleanupCancel()
				_, _ = fmt.Fprintf(os.Stderr, "beacon: scan stopped for %s — %d findings saved\n", domain, len(findings))
				break
			}
			_, _ = fmt.Fprintf(os.Stderr, "beacon: scan failed for %s: %v\n", domain, scanErr)
			run.Status = store.StatusFailed
			run.Error = scanErr.Error()
			_ = st.UpdateScanRun(cleanupCtx, run)
			cleanupCancel()
			continue
		}

		if err := st.SaveFindings(ctx, run.ID, findings); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "beacon: save findings %s: %v\n", domain, err)
		}

		// Log findings to structured log file.
		sl := scanlog.FromContext(ctx)
		sl.ScanStart(domain, string(scanType), []string{domain})
		for _, f := range findings {
			sl.Finding(f)
		}
		sl.ScanComplete(domain, len(findings), time.Since(run.StartedAt))

		if corrFindings, err := analyze.RunDeterministicCorrelations(ctx, st, run.ID, domain); err != nil {
			info("beacon: correlations %s: %v\n", domain, err)
		} else if len(corrFindings) > 0 {
			info("beacon: %d compound chain(s) on %s\n", len(corrFindings), domain)
		}

		now := time.Now()
		run.Status = store.StatusCompleted
		run.CompletedAt = &now
		run.FindingCount = len(findings)
		_ = st.UpdateScanRun(ctx, run)

		info("beacon: %s — %d finding(s) [run ID: %s]\n", domain, len(findings), run.ID)
		allResults = append(allResults, assetScanResult{domain, run, findings})
		allFindings = append(allFindings, findings...)
	}

	// Dry-run: output all plans as JSON and exit.
	if dryRun {
		out, _ := json.MarshalIndent(allFindings, "", "  ")
		fmt.Println(string(out))
		return
	}

	// ── Cloud module (once per session) ───────────────────────────────────────
	var cloudFindings []finding.Finding
	if cloudEnabled || awsProfile != "" || gcpCredentials != "" || azureSubscription != "" || doToken != "" || ociConfigFile != "" {
		providerList := cloudmodule.RegisteredProviders()
		info("\nbeacon: running cloud posture scan (providers: %s)...\n", strings.Join(providerList, ", "))
		cloudAsset := "cloud"
		if len(targets) > 0 {
			cloudAsset = targets[0]
		}
		cloudMod := cloudmodule.New()
		cloudInput := module.Input{
			CloudEnabled:        true,
			AWSProfile:          awsProfile,
			GCPCredentialsFile:  gcpCredentials,
			AzureSubscriptionID: azureSubscription,
			DOToken:             doToken,
			OCIConfigFile:       ociConfigFile,
			Domain:              cloudAsset,
		}
		if cf, err := cloudMod.Run(ctx, cloudInput, scanType); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "beacon: cloud scan error: %v\n", err)
		} else {
			cloudFindings = cf
			info("beacon: cloud scan — %d finding(s)\n", len(cloudFindings))
			for i := range cloudFindings {
				cloudFindings[i].Module = "cloud"
			}
			for _, res := range allResults {
				if res.run == nil {
					continue
				}
				if err := st.SaveFindings(ctx, res.run.ID, cloudFindings); err != nil {
					_, _ = fmt.Fprintf(os.Stderr, "beacon: save cloud findings %s: %v\n", res.run.ID, err)
				}
			}
			allFindings = append(allFindings, cloudFindings...)
		}
	}

	// ── GitHub module (once per session, combined with domain scan) ────────────
	if githubOrg != "" && len(allResults) > 0 {
		info("\nbeacon: running GitHub scan for %s...\n", githubOrg)
		ghMod := githubmodule.New(cfg.GitHubToken)
		ghInput := module.Input{
			GitHubOrg: githubOrg,
			Domain:    githubOrg,
		}
		if ghFindings, err := ghMod.Run(ctx, ghInput, scanType); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "beacon: github scan error: %v\n", err)
		} else {
			info("beacon: github scan — %d finding(s)\n", len(ghFindings))
			for i := range ghFindings {
				ghFindings[i].Module = "github"
			}
			for _, res := range allResults {
				if res.run == nil {
					continue
				}
				if err := st.SaveFindings(ctx, res.run.ID, ghFindings); err != nil {
					_, _ = fmt.Fprintf(os.Stderr, "beacon: save github findings %s: %v\n", res.run.ID, err)
				}
			}
			allFindings = append(allFindings, ghFindings...)
		}
	}

	// ── Tier-1 cross-reference: cloud IPs → surface assets ────────────────────
	ipToCloudCtx := buildCloudIPIndex(cloudFindings)
	if len(ipToCloudCtx) > 0 {
		info("beacon: cross-reference — %d cloud IP(s) indexed\n", len(ipToCloudCtx))
	}

	// ── Asset graph construction ───────────────────────────────────────────────
	graph := buildSessionAssetGraph(allResults, cloudFindings, ipToCloudCtx)

	// Persist the graph for every scan run in the session so
	// `beacon report --id <any-run> --format graph` works for any run.
	if graphJSON, gErr := json.Marshal(graph); gErr == nil {
		for _, res := range allResults {
			if res.run != nil {
				_ = st.SaveAssetGraph(ctx, res.run.ID, graphJSON)
			}
		}
	}

	// ── Cross-asset correlation ────────────────────────────────────────────────
	if len(allResults) >= 2 {
		crossFindings := crossAssetCorrelate(allResults)
		if len(crossFindings) > 0 {
			info("\nbeacon: cross-asset — %d systemic finding(s)\n", len(crossFindings))
			for _, cf := range crossFindings {
				info("  [%s] %s\n", cf.Severity, cf.Title)
			}
			_ = st.SaveCorrelationFindings(ctx, crossFindings)
		}
	}

	// ── Asset correlation (surface ↔ cloud) ──────────────────────────────
	// Deterministic correlation: match surface-scanned domains to cloud
	// resources by IP overlap, CNAME chains, and TLS SAN matching.
	// Produces advisory findings — never merges or deduplicates assets.
	if len(cloudFindings) > 0 {
		var surfaceFindings []finding.Finding
		for _, res := range allResults {
			surfaceFindings = append(surfaceFindings, res.findings...)
		}
		assetCorrFindings := analyze.CorrelateAssets(surfaceFindings, cloudFindings)
		if len(assetCorrFindings) > 0 {
			info("beacon: asset correlation — %d link(s) found\n", len(assetCorrFindings))
			allFindings = append(allFindings, assetCorrFindings...)
			if len(allResults) > 0 && allResults[0].run != nil {
				_ = st.SaveFindings(ctx, allResults[0].run.ID, assetCorrFindings)
			}
		}
	}

	// ── AI fingerprint enrichment (multi-asset) ─────────────────────────────
	// Analyse collected fingerprint evidence across all assets to find
	// version-specific vulnerabilities and configuration anomalies.
	if ai := cfg.ActiveAI(); ai != nil && !noEnrich {
		var fpInputs []enrichment.FingerprintInput
		for _, res := range allResults {
			if res.run == nil {
				continue
			}
			if execs, execErr := st.ListAssetExecutions(ctx, res.run.ID); execErr == nil {
				for _, ex := range execs {
					fpInputs = append(fpInputs, enrichment.FingerprintInputFromEvidence(ex.Asset, ex.Evidence))
				}
			}
		}
		if len(fpInputs) > 0 {
			ce, ceErr := enrichment.NewWithProvider(ai.Provider, ai.APIKey, ai.Model, ai.BaseURL)
			if ceErr == nil {
				info("beacon: analysing fingerprints for %d asset(s)...\n", len(fpInputs))
				fpResult, fpErr := ce.EnrichFingerprints(ctx, fpInputs)
				if fpErr != nil {
					info("beacon: fingerprint enrichment: %v\n", fpErr)
				} else if len(fpResult.Findings) > 0 {
					info("beacon: fingerprint analysis found %d issue(s)\n", len(fpResult.Findings))
					allFindings = append(allFindings, fpResult.Findings...)
					if len(allResults) > 0 && allResults[0].run != nil {
						if err := st.SaveFindings(ctx, allResults[0].run.ID, fpResult.Findings); err != nil {
							_, _ = fmt.Fprintf(os.Stderr, "beacon: save fingerprint findings: %v\n", err)
						}
					}
				}
			}
		}
	}

	// Flag potential duplicates across scanners and overlapping assets.
	dedup.FlagDuplicates(allFindings)

	// --output-raw: write raw findings and exit before enrichment.
	if outputRawPath != "" {
		domainLabel := strings.Join(targets, ",")
		firstRunID := ""
		if len(allResults) > 0 && allResults[0].run != nil {
			firstRunID = allResults[0].run.ID
		}
		raw, err := report.RenderRawJSON(domainLabel, string(scanType), firstRunID, time.Now(), allFindings)
		if err != nil {
			fatalf("render raw findings: %v", err)
		}
		if err := os.WriteFile(outputRawPath, []byte(raw), 0o600); err != nil {
			fatalf("write raw findings: %v", err)
		}
		info("beacon: %d raw findings written to %s\n", len(allFindings), outputRawPath)
		info("beacon: enrich later with: beacon enrich --input %s\n", outputRawPath)
		return
	}

	// ── Unified cross-module enrichment ─────────────────────────────────────
	// Enrich ALL findings (surface + cloud + GitHub) together so the AI sees
	// the full picture: an exposed port on a GKE node with cluster-admin, a
	// leaked secret in GitHub Actions, and a misconfigured CORS on the same
	// domain are all enriched with cross-module context in a single pass.
	if ai := cfg.ActiveAI(); ai != nil && len(allFindings) > 0 && !noEnrich {
		enricher, enrichErr := enrichment.NewWithProvider(ai.Provider, ai.APIKey, ai.Model, ai.BaseURL)
		if enrichErr == nil {
			enricher = enricher.WithCache(st)

			info("beacon: enriching %d findings across all modules...\n", len(allFindings))
			allEnriched, enrichErr := enricher.Enrich(ctx, allFindings)
			if enrichErr != nil {
				_, _ = fmt.Fprintf(os.Stderr, "beacon: enrichment failed: %v\n", enrichErr)
			} else {
				// Contextual analysis — cross-module compound risk identification.
				domainStr := strings.Join(targets, ", ")
				allEnriched, summary, ctxErr := enricher.ContextualizeAndSummarize(ctx, allEnriched, domainStr)
				if ctxErr != nil {
					_, _ = fmt.Fprintf(os.Stderr, "beacon: contextualize: %v\n", ctxErr)
				}
				if summary != "" {
					info("\n\x1b[1mExecutive Summary:\x1b[0m\n%s\n", summary)
				}

				// Partition enriched findings back to each scan run and save them.
				// Build an index: asset → scan run ID for fast lookup.
				assetToRunID := make(map[string]string)
				for _, res := range allResults {
					if res.run == nil {
						continue
					}
					for _, f := range res.findings {
						assetToRunID[f.Asset] = res.run.ID
					}
				}
				byRunID := make(map[string][]enrichment.EnrichedFinding)
				for _, ef := range allEnriched {
					runID := assetToRunID[ef.Finding.Asset]
					if runID == "" {
						// Cloud/GitHub findings — assign to first run as fallback.
						if len(allResults) > 0 && allResults[0].run != nil {
							runID = allResults[0].run.ID
						}
					}
					if runID != "" {
						byRunID[runID] = append(byRunID[runID], ef)
					}
				}
				for runID, enrichedSlice := range byRunID {
					if err := st.SaveEnrichedFindings(ctx, runID, enrichedSlice); err != nil {
						_, _ = fmt.Fprintf(os.Stderr, "beacon: save enriched findings %s: %v\n", runID, err)
					}
				}

				// Attack-path analysis — cross-module attack chain reasoning.
				if analysis, err := enricher.AnalyzeAttackPaths(ctx, allEnriched, domainStr); err == nil && analysis != "" {
					info("\n\x1b[1mAttack Path Analysis:\x1b[0m\n%s\n", analysis)
				}

				// Follow-up probes — suggested targeted checks.
				if permissionConfirmed {
					probes, _ := enricher.GenerateFollowUpProbes(ctx, allEnriched, domainStr)
					if len(probes) > 0 {
						info("\n\x1b[1mSuggested follow-up probes (%d):\x1b[0m\n", len(probes))
						for i, p := range probes {
							info("  %d. [%s] %s — %s\n", i+1, p.Scanner, p.Asset, p.Reason)
						}
						if term.IsTerminal(int(os.Stdin.Fd())) {
							_, _ = fmt.Fprintf(os.Stderr, "\nRun follow-up probes? [y/N]: ")
							reader := bufio.NewReader(os.Stdin)
							line, err := reader.ReadString('\n')
							if err != nil {
								line = ""
							}
							if strings.TrimSpace(strings.ToLower(line)) == "y" {
								_, _ = fmt.Fprintf(os.Stderr, "beacon: follow-up probes queued for next scan (use --cidr flags with the IPs above).\n")
							}
						}
					}
				}
			}
		}
	}

	// ── Summary ────────────────────────────────────────────────────────────────
	info("\nbeacon: multi-asset scan complete\n")
	for _, res := range allResults {
		runID := "<no run>"
		if res.run != nil {
			runID = res.run.ID
		}
		info("  %-40s  %3d finding(s)  run: %s\n", res.domain, len(res.findings), runID)
	}
	if len(cloudFindings) > 0 {
		info("  %-40s  %3d cloud finding(s)\n", "cloud", len(cloudFindings))
	}
	info("  %-40s  %3d total\n", "", len(allFindings))
	info("\nTo view results: beacon browse\n")
	info("To report on a run: beacon report --id <run-id>\n")

	// ── Graph output ───────────────────────────────────────────────────────────
	if format == "graph" {
		dot := report.RenderGraphDOT(graph)
		if outPath != "" {
			if err := os.WriteFile(outPath, []byte(dot), 0o600); err != nil {
				fatalf("write graph file: %v", err)
			}
			info("beacon: graph written to %s\n", outPath)
		} else {
			fmt.Print(dot)
		}
	}
}

// interactiveApproveExploit prompts the user on stderr for each exploit module.
// Returns true if the user approves (y/Y/enter), false otherwise.
func interactiveApproveExploit(moduleName string, host string, port int) bool {
	_, _ = fmt.Fprintf(os.Stderr, "\nExploit module %q targets %s:%d. Proceed? [Y/n] ", moduleName, host, port)

	// If not a terminal (piped input), auto-deny for safety.
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		_, _ = fmt.Fprintln(os.Stderr, "n (non-interactive)")
		return false
	}

	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "" || line == "y" || line == "yes"
}
