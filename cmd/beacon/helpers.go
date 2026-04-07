package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/asset"
	"github.com/stormbane-security/beacon/internal/config"
	"github.com/stormbane-security/beacon/internal/enrichment"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/playbook"
	"github.com/stormbane-security/beacon/internal/report"
	"github.com/stormbane-security/beacon/internal/store"
)

func fatalf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, "beacon: "+format+"\n", args...)
	os.Exit(1)
}

// checkExternalTools checks for important and optional external tools in PATH,
// collecting all warnings and printing them as a single grouped block.
// Critical tools (nmap) are checked earlier and cause hard errors.
// Important tools warn with an opt-out flag; optional tools warn only.
func checkExternalTools(cfg *config.Config, noNuclei, noTestssl bool) {
	if quiet {
		return
	}

	type toolWarning struct {
		name    string
		message string
	}
	var warnings []toolWarning

	// Important tools (warn if missing, --no-X to opt out).
	if !noNuclei && cfg.NucleiBin != "" {
		if _, err := exec.LookPath(cfg.NucleiBin); err != nil {
			warnings = append(warnings, toolWarning{
				name:    "nuclei",
				message: "nuclei not found. Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
			})
			cfg.NucleiBin = ""
		}
	}
	if !noTestssl && cfg.TestsslBin != "" {
		if _, err := exec.LookPath(cfg.TestsslBin); err != nil {
			warnings = append(warnings, toolWarning{
				name:    "testssl",
				message: "testssl.sh not found. Install: brew install testssl or https://testssl.sh/",
			})
			cfg.TestsslBin = ""
		}
	}

	// Deprecation warnings for tools replaced by native functionality.
	if cfg.HttpxBin != "" {
		if _, err := exec.LookPath(cfg.HttpxBin); err == nil {
			warnings = append(warnings, toolWarning{
				name:    "httpx",
				message: "httpx integration deprecated — classify scanner provides equivalent functionality",
			})
		}
	}
	if cfg.DnsxBin != "" {
		if _, err := exec.LookPath(cfg.DnsxBin); err == nil {
			warnings = append(warnings, toolWarning{
				name:    "dnsx",
				message: "dnsx integration deprecated — beacon performs bulk DNS resolution natively",
			})
		}
	}

	// Optional tools (warn only, no flag needed).
	type optionalTool struct {
		bin  string
		name string
	}
	optionals := []optionalTool{
		{cfg.KatanaBin, "katana"},
		{cfg.FfufBin, "ffuf"},
		{cfg.GowitnessBin, "gowitness"},
		{cfg.GitleaksBin, "gitleaks"},
		{cfg.SqlmapBin, "sqlmap"},
		{cfg.WpscanBin, "wpscan"},
		{cfg.MasscanBin, "masscan"},
		{cfg.ArjunBin, "arjun"},
	}
	// dig is not in the config — check PATH directly.
	optionals = append(optionals, optionalTool{"dig", "dig"})

	for _, t := range optionals {
		if t.bin == "" {
			continue
		}
		if _, err := exec.LookPath(t.bin); err != nil {
			warnings = append(warnings, toolWarning{
				name:    t.name,
				message: fmt.Sprintf("%s not found in PATH — some scan features will be reduced", t.name),
			})
		}
	}

	if len(warnings) > 0 {
		_, _ = fmt.Fprintf(os.Stderr, "beacon: missing external tools:\n")
		for _, w := range warnings {
			_, _ = fmt.Fprintf(os.Stderr, "  %-16s  %s\n", w.name, w.message)
		}
		_, _ = fmt.Fprintf(os.Stderr, "\n")
	}
}

// warnMissingAPIKeys prints a one-time pre-scan notice listing any optional
// API keys that are not configured. Each missing key reduces scan coverage in
// a specific way; the message explains what is skipped so the user can decide
// whether to obtain the key before proceeding.
//
// Also warns when nmap is configured but the process is not running as root,
// because nmap falls back to TCP connect scan (noisier) and some deep-mode
// NSE scripts with raw-socket requirements will have reduced coverage.
func warnMissingAPIKeys(cfg *config.Config) {
	if quiet {
		return
	}

	type keyInfo struct {
		val  string
		name string
		desc string
	}
	keys := []keyInfo{
		{cfg.ShodanAPIKey, "BEACON_SHODAN_API_KEY", "Shodan passive host intel (open ports, CVEs, banners without active scanning)"},
		{cfg.OTXAPIKey, "BEACON_OTX_API_KEY", "AlienVault OTX passive DNS and subdomain discovery"},
		{cfg.HIBPAPIKey, "BEACON_HIBP_API_KEY", "Have I Been Pwned domain breach lookup"},
		{cfg.BingAPIKey, "BEACON_BING_API_KEY", "Bing Search API dorking for exposed files and subdomains"},
		{cfg.VirusTotalAPIKey, "BEACON_VIRUSTOTAL_API_KEY", "VirusTotal domain reputation and malware associations"},
		{cfg.SecurityTrailsAPIKey, "BEACON_SECURITYTRAILS_API_KEY", "SecurityTrails historical DNS and subdomain discovery"},
		{cfg.CensysAPIID, "BEACON_CENSYS_API_ID + BEACON_CENSYS_API_SECRET", "Censys internet-wide host and certificate data"},
		{cfg.GreyNoiseAPIKey, "BEACON_GREYNOISE_API_KEY", "GreyNoise IP noise context (reduces false positives on scanner IPs)"},
		{cfg.AnthropicAPIKey, "BEACON_ANTHROPIC_API_KEY / ai.api_key", "AI-powered finding enrichment, DLP vision analysis, and executive summary"},
	}

	var missing []keyInfo
	for _, k := range keys {
		if k.val == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		// Each key unlocks a distinct data source — not just a speed improvement.
		// Missing keys cause genuine detection gaps: passive DNS finds deleted subdomains
		// that active scanning never sees; HIBP breach data is not reproducible by probing;
		// Shodan captures ports that were open before the scan started but are now closed.
		_, _ = fmt.Fprintf(os.Stderr, "beacon: missing optional keys — these are distinct data sources, not speed improvements:\n")
		for _, k := range missing {
			_, _ = fmt.Fprintf(os.Stderr, "  %-55s  %s\n", k.name, k.desc)
		}
		if from := cfg.LoadedFrom(); from != "" {
			_, _ = fmt.Fprintf(os.Stderr, "  Config loaded from: %s\n", from)
			_, _ = fmt.Fprintf(os.Stderr, "  Add missing keys to that file using yaml key names (e.g. shodan_api_key: yourkey)\n\n")
		} else {
			_, _ = fmt.Fprintf(os.Stderr, "  No config file found. Create ~/.beacon/config.yaml or set BEACON_* env vars.\n\n")
		}
	}

	// Warn when nmap is enabled but running without root privileges.
	if cfg.NmapBin != "" && os.Getuid() != 0 {
		_, _ = fmt.Fprintf(os.Stderr, "beacon: nmap configured but running without root — nmap will use TCP connect scan\n")
		_, _ = fmt.Fprintf(os.Stderr, "  Some deep-mode NSE scripts (ms17-010, smb-vuln-*, snmp-info) require raw sockets\n")
		_, _ = fmt.Fprintf(os.Stderr, "  and will have reduced coverage without root or CAP_NET_RAW.\n")
		_, _ = fmt.Fprintf(os.Stderr, "  Run with sudo or grant: sudo setcap cap_net_raw+ep %s\n\n", cfg.NmapBin)
	}
}

// deliverWebhook POSTs a JSON findings payload to the configured webhook URL.
// The payload matches the structured JSON report format so SIEM consumers can
// ingest it with the same schema as `beacon scan --output json`.
// Errors are non-fatal — a failed webhook never blocks the scan report.
func deliverWebhook(ctx context.Context, webhookURL, apiKey string, run store.ScanRun, enriched []enrichment.EnrichedFinding, summary string) error {
	u, err := url.Parse(webhookURL)
	if err != nil {
		return fmt.Errorf("invalid webhook URL: %w", err)
	}
	switch u.Scheme {
	case "https":
		// OK
	case "http":
		_, _ = fmt.Fprintf(os.Stderr, "beacon: warning: webhook URL uses plain HTTP — credentials and findings will be sent in cleartext\n")
	default:
		return fmt.Errorf("unsupported webhook URL scheme %q: only https:// and http:// are allowed", u.Scheme)
	}

	payload, err := report.RenderJSON(run, enriched, summary, nil)
	if err != nil {
		return fmt.Errorf("render webhook payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL,
		strings.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "beacon-scanner/1.0")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	// Drain the response body so the underlying TCP connection can be reused.
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// filterBySeverity drops enriched findings below the specified minimum severity.
// severityFlag is a string like "high", "medium", etc. Empty string or "info"
// means no filtering (show all).
func filterBySeverity(enriched []enrichment.EnrichedFinding, severityFlag string) []enrichment.EnrichedFinding {
	min := finding.ParseSeverity(severityFlag)
	if min <= finding.SeverityInfo {
		return enriched
	}
	var out []enrichment.EnrichedFinding
	for _, ef := range enriched {
		if ef.Finding.Severity >= min {
			out = append(out, ef)
		}
	}
	return out
}

// filterOmitted drops findings Claude marked as having no actionable value
// given other controls present in the scan.
func filterOmitted(enriched []enrichment.EnrichedFinding) []enrichment.EnrichedFinding {
	var out []enrichment.EnrichedFinding
	for _, ef := range enriched {
		if !ef.Omit {
			out = append(out, ef)
		}
	}
	return out
}

// renderFormat produces the report string in the requested format.
// format is one of: "text" (default), "html", "json", "markdown", "ocsf", "graph".
// graphJSON is the persisted asset graph blob; it is included in the JSON report
// when non-nil and used to render DOT output for the "graph" format.
func renderFormat(format string, run store.ScanRun, enriched []enrichment.EnrichedFinding, summary string, rep *store.Report, executions []store.AssetExecution, graphJSON []byte) (string, error) {
	switch strings.ToLower(format) {
	case "html":
		return rep.HTMLContent, nil
	case "json":
		return report.RenderJSON(run, enriched, summary, graphJSON)
	case "markdown", "md":
		return report.RenderMarkdown(run, enriched, summary, executions), nil
	case "ocsf":
		// OCSF 1.4.0 NDJSON — one Vulnerability Finding event per line.
		// Compatible with AWS Security Lake, Splunk, OpenSearch Security Analytics,
		// Panther, Chronicle, and any OCSF-consuming SIEM or data lake.
		return report.RenderOCSF(run, enriched)
	case "graph":
		if len(graphJSON) > 0 {
			var g asset.AssetGraph
			if err := json.Unmarshal(graphJSON, &g); err == nil {
				return report.RenderGraphDOT(g), nil
			}
		}
		return "", fmt.Errorf("no asset graph available for this scan run")
	default: // "text" or empty
		return report.RenderText(run, enriched, summary, executions), nil
	}
}

var validPlaybookName = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// safePlaybookName returns the base name of s if it matches the allowed
// character set, or "" if it contains path traversal or disallowed characters.
func safePlaybookName(s string) string {
	s = filepath.Base(s)
	if !validPlaybookName.MatchString(s) {
		return ""
	}
	return s
}

// importPlaybookSuggestion writes a PlaybookSuggestion's YAML to
// ~/.config/beacon/playbooks/<name>.yaml so it is loaded on next scan.
func importPlaybookSuggestion(sugg *store.PlaybookSuggestion) error {
	safeName := safePlaybookName(sugg.TargetPlaybook)
	if safeName == "" {
		return fmt.Errorf("invalid playbook name: %q", sugg.TargetPlaybook)
	}
	// Validate that the suggested YAML is a parseable playbook before writing.
	if _, err := playbook.ParsePlaybook([]byte(sugg.SuggestedYAML)); err != nil {
		return fmt.Errorf("invalid playbook YAML: %w", err)
	}
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(homeDir, ".config", "beacon", "playbooks")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, safeName+".yaml"), []byte(sugg.SuggestedYAML), 0o600)
}

// readTargetsFile reads a file with one domain per line, ignoring blank
// lines and lines beginning with '#'.
func readTargetsFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, nil
}

// uniqueStrings returns ss with duplicates removed, preserving order.
func uniqueStrings(ss []string) []string {
	seen := make(map[string]bool, len(ss))
	var out []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func pluralS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// strOr returns the first non-empty string (CLI flag overrides config file).
func strOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// buildCloudIPIndex extracts all public IPs from cloud findings and maps them
// to a CloudContext. Used for tier-1 cross-referencing with surface scan IPs.
func buildCloudIPIndex(cloudFindings []finding.Finding) map[string]playbook.CloudContext {
	index := map[string]playbook.CloudContext{}
	for _, f := range cloudFindings {
		if f.Evidence == nil {
			continue
		}
		provider := ""
		checkStr := string(f.CheckID)
		if strings.HasPrefix(checkStr, "cloud.gcp") {
			provider = "gcp"
		} else if strings.HasPrefix(checkStr, "cloud.aws") {
			provider = "aws"
		} else if strings.HasPrefix(checkStr, "cloud.azure") {
			provider = "azure"
		}
		if provider == "" {
			continue
		}
		cc := playbook.CloudContext{
			Provider:         provider,
			ResourceType:     cloudEvidenceString(f.Evidence, "resource_type"),
			InstanceID:       cloudEvidenceString(f.Evidence, "instance_id"),
			Project:          cloudEvidenceString(f.Evidence, "project_id"),
			Region:           cloudEvidenceString(f.Evidence, "region"),
			Zone:             cloudEvidenceString(f.Evidence, "zone"),
			ResourceSnapshot: cloudEvidenceString(f.Evidence, "resource_snapshot"),
		}
		// Single IP.
		for _, key := range []string{"external_ip", "public_ip"} {
			if ip := cloudEvidenceString(f.Evidence, key); ip != "" {
				index[ip] = cc
			}
		}
		// Slice of IPs.
		if ips, ok := f.Evidence["public_ips"].([]string); ok {
			for _, ip := range ips {
				if ip != "" {
					index[ip] = cc
				}
			}
		}
		if ips, ok := f.Evidence["public_ips"].([]any); ok {
			for _, v := range ips {
				if ip, ok := v.(string); ok && ip != "" {
					index[ip] = cc
				}
			}
		}
	}
	return index
}

func cloudEvidenceString(ev map[string]any, key string) string {
	if ev == nil {
		return ""
	}
	if v, ok := ev[key].(string); ok {
		return v
	}
	return ""
}

// buildSessionAssetGraph constructs an AssetGraph from all scan results in
// the session, wiring surface assets to cloud assets via tier-1 IP matching.
func buildSessionAssetGraph(results []assetScanResult, cloudFindings []finding.Finding, ipToCloud map[string]playbook.CloudContext) asset.AssetGraph {
	// Derive session-level identifiers from the first result when available.
	var scanRunID, rootDomain string
	if len(results) > 0 {
		if results[0].run != nil {
			scanRunID = results[0].run.ID
		}
		rootDomain = results[0].domain
	}
	b := asset.NewBuilder(scanRunID, rootDomain)

	for _, res := range results {
		b.AddDomainAsset(res.domain, nil, "surface")
		// Feed surface scan findings into the graph so every discovered asset
		// has its finding refs attached.
		b.AddFindings(res.findings)
	}

	for _, f := range cloudFindings {
		if f.Evidence == nil {
			continue
		}
		provider := ""
		checkStr := string(f.CheckID)
		if strings.HasPrefix(checkStr, "cloud.gcp") {
			provider = "gcp"
		} else if strings.HasPrefix(checkStr, "cloud.aws") {
			provider = "aws"
		} else if strings.HasPrefix(checkStr, "cloud.azure") {
			provider = "azure"
		}
		if provider == "" {
			continue
		}
		instanceID := cloudEvidenceString(f.Evidence, "instance_id")
		if instanceID == "" {
			instanceID = f.Asset
		}
		assetID := provider + ":" + instanceID
		resourceType := asset.AssetType(cloudEvidenceString(f.Evidence, "resource_type"))
		if resourceType == "" {
			resourceType = asset.AssetType(provider + "_resource")
		}
		b.AddAsset(asset.Asset{
			ID:       assetID,
			Type:     resourceType,
			Name:     instanceID,
			Provider: provider,
		})
		b.AddFindings([]finding.Finding{f})
	}

	// Wire IP cross-references: for each cloud IP that matches a domain asset,
	// add a likely_same_as or points_to relationship.
	_ = ipToCloud // used by CrossReferenceByIP inside Build()

	g := b.Build()
	return g
}

// crossAssetCorrelate identifies the same vulnerability appearing across
// multiple target domains in the same session — a signal of systemic
// misconfiguration in a shared deployment or common infrastructure.
func crossAssetCorrelate(results []assetScanResult) []store.CorrelationFinding {
	if len(results) < 2 {
		return nil
	}

	type checkInfo struct {
		title    string
		severity finding.Severity
		domains  []string
		runIDs   []string
	}
	checkMap := make(map[finding.CheckID]*checkInfo)

	for _, res := range results {
		if res.run == nil {
			continue
		}
		seen := make(map[finding.CheckID]bool)
		for _, f := range res.findings {
			if seen[f.CheckID] {
				continue
			}
			seen[f.CheckID] = true
			if _, ok := checkMap[f.CheckID]; !ok {
				checkMap[f.CheckID] = &checkInfo{
					title:    f.Title,
					severity: f.Severity,
				}
			}
			checkMap[f.CheckID].domains = append(checkMap[f.CheckID].domains, res.domain)
			checkMap[f.CheckID].runIDs = append(checkMap[f.CheckID].runIDs, res.run.ID)
		}
	}

	var out []store.CorrelationFinding
	for checkID, info := range checkMap {
		if len(info.domains) < 2 {
			continue
		}
		// Attach to the first matching run so it's visible in the store.
		out = append(out, store.CorrelationFinding{
			ScanRunID: info.runIDs[0],
			Domain:    info.domains[0],
			Title:     fmt.Sprintf("[Cross-asset] %s", info.title),
			Severity:  info.severity,
			Description: fmt.Sprintf(
				"The same vulnerability (%s) was detected across %d of %d targets in this session: %s. "+
					"This indicates a systemic misconfiguration — likely a shared deployment template, "+
					"common software version, or shared infrastructure.",
				checkID, len(info.domains), len(results), strings.Join(info.domains, ", "),
			),
			AffectedAssets:     info.domains,
			ContributingChecks: []string{string(checkID)},
			Remediation:        "Remediate across all affected targets simultaneously to avoid incomplete fixes.",
			CreatedAt:          time.Now(),
		})
	}
	return out
}

// formatEvidenceValue returns a display-safe, truncated string for an evidence
// field value. Multi-line and HTML-heavy values are stripped and capped at 300
// chars so they don't overflow the terminal.
func formatEvidenceValue(key string, v any) string {
	// Render slices as comma-separated strings instead of Go's "[a b c]" format.
	switch val := v.(type) {
	case []string:
		v = strings.Join(val, ", ")
	case []any:
		parts := make([]string, len(val))
		for i, item := range val {
			parts[i] = fmt.Sprintf("%v", item)
		}
		v = strings.Join(parts, ", ")
	}
	raw := fmt.Sprintf("%v", v)

	// Strip HTML tags for known snippet keys or when the value looks like HTML.
	if strings.Contains(key, "snippet") || strings.Contains(key, "html") ||
		(strings.Contains(raw, "<") && strings.Contains(raw, ">")) {
		// Remove everything between < > (simple tag strip).
		var stripped strings.Builder
		inTag := false
		for _, ch := range raw {
			switch {
			case ch == '<':
				inTag = true
				stripped.WriteRune(' ')
			case ch == '>':
				inTag = false
			case !inTag:
				stripped.WriteRune(ch)
			}
		}
		raw = stripped.String()
	}

	// Collapse whitespace and newlines into a single line.
	raw = strings.Join(strings.Fields(raw), " ")

	// Truncate long values.
	const maxLen = 300
	if len(raw) > maxLen {
		raw = raw[:maxLen] + "…"
	}
	return raw
}

// wordWrapLines wraps text to maxWidth columns, returning one string per line.
func wordWrapLines(text string, maxWidth int) []string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return nil
	}
	var lines []string
	line := ""
	for _, w := range words {
		if line == "" {
			line = w
		} else if len(line)+1+len(w) > maxWidth {
			lines = append(lines, line)
			line = w
		} else {
			line += " " + w
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

// wordWrapAtShellBoundaries wraps a shell command at natural break points
// (pipes, &&, flag boundaries --) rather than arbitrary word boundaries.
// Continuation lines are indented with two spaces so the command is readable.
// Falls back to wordWrapLines if no shell boundaries are present.
func wordWrapAtShellBoundaries(cmd string, maxWidth int) []string {
	if maxWidth < 20 {
		maxWidth = 20
	}
	if len(cmd) <= maxWidth {
		return []string{cmd}
	}
	// Try to split at pipe/chain operators first.
	for _, sep := range []string{" | ", " && ", " || ", " ; "} {
		if idx := strings.Index(cmd, sep); idx != -1 && idx < maxWidth {
			rest := cmd[idx+len(sep):]
			first := cmd[:idx+len(sep)-1] // keep the operator on the first line
			var lines []string
			lines = append(lines, first)
			for _, sub := range wordWrapAtShellBoundaries(rest, maxWidth-2) {
				lines = append(lines, "  "+sub)
			}
			return lines
		}
	}
	// Try to split at a flag boundary (space followed by --) within maxWidth.
	if idx := strings.LastIndex(cmd[:maxWidth], " --"); idx > 0 {
		first := cmd[:idx]
		rest := cmd[idx+1:] // drop the leading space; keep "--..."
		var lines []string
		lines = append(lines, first)
		for _, sub := range wordWrapAtShellBoundaries(rest, maxWidth-2) {
			lines = append(lines, "  "+sub)
		}
		return lines
	}
	// No shell boundary found — fall back to word-wrap.
	return wordWrapLines(cmd, maxWidth)
}

// extractFindingURL returns the most useful URL from a finding's evidence map.
// It checks common evidence keys in priority order so the clipboard gets the
// most actionable link (e.g. the direct bucket URL rather than the base URL).
func extractFindingURL(f *finding.Finding) string {
	if f == nil || f.Evidence == nil {
		if f != nil && f.Asset != "" {
			return "https://" + f.Asset
		}
		return ""
	}
	for _, key := range []string{
		"bucket_url", "write_url", "js_url", "probe_url", "url",
		"endpoint", "base_url", "redirect_url",
	} {
		if v, ok := f.Evidence[key]; ok {
			if s, ok := v.(string); ok && strings.HasPrefix(s, "http") {
				return s
			}
		}
	}
	// Fall back to the asset itself.
	if f.Asset != "" {
		return "https://" + f.Asset
	}
	return ""
}

// copyToClipboard writes text to the system clipboard using whatever tool is
// available (pbcopy on macOS, xclip/xsel on Linux, clip on Windows).
// Returns true if the copy succeeded.
func copyToClipboard(text string) bool {
	// Try native clipboard tools first.
	candidates := [][]string{
		{"pbcopy"},                           // macOS
		{"xclip", "-selection", "clipboard"}, // Linux/X11
		{"xsel", "--clipboard", "--input"},   // Linux/X11 alt
		{"clip"},                             // Windows
		{"wl-copy"},                          // Wayland
	}
	for _, args := range candidates {
		cmd := exec.Command(args[0], args[1:]...) //nolint:gosec
		// Use StdinPipe for reliable stdin delivery even when the parent
		// process has stdin in raw/non-blocking mode (TUI context).
		stdin, err := cmd.StdinPipe()
		if err != nil {
			continue
		}
		if err := cmd.Start(); err != nil {
			continue
		}
		_, _ = io.WriteString(stdin, text)
		_ = stdin.Close()
		if err := cmd.Wait(); err == nil {
			return true
		}
	}
	// Fallback: OSC 52 escape sequence sets the system clipboard in terminals
	// that support it (iTerm2, kitty, alacritty, Windows Terminal, etc.).
	// Works even inside alternate screen mode where mouse selection fails.
	encoded := base64.StdEncoding.EncodeToString([]byte(text))
	_, _ = fmt.Fprintf(os.Stderr, "\x1b]52;c;%s\x07", encoded)
	return true
}

// fingerprintBadge returns a compact technology label for an asset built from
// its playbook Evidence, e.g. "cloudflare/nginx" or "haproxy" or "".
// Used in the findings list to show what kind of service has each finding.
func fingerprintBadge(ev playbook.Evidence) string {
	var parts []string
	if ev.CloudProvider != "" {
		parts = append(parts, ev.CloudProvider)
	}
	if ev.ProxyType != "" {
		// Avoid repeating cloud provider if proxy type is the same string
		if ev.ProxyType != ev.CloudProvider {
			parts = append(parts, ev.ProxyType)
		}
	}
	if len(parts) == 0 {
		// Fall back to raw server header
		if sv := ev.Headers["server"]; sv != "" {
			// Trim version numbers: "nginx/1.25.3" → "nginx"
			if idx := strings.Index(sv, "/"); idx > 0 {
				sv = sv[:idx]
			}
			parts = append(parts, strings.ToLower(sv))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	badge := strings.Join(parts, "/")
	if len(badge) > 20 {
		badge = badge[:19] + "…"
	}
	return badge
}

func severityColor(sev finding.Severity) string {
	switch sev {
	case finding.SeverityCritical:
		return "\x1b[1;31m" // bold red
	case finding.SeverityHigh:
		return "\x1b[31m" // red
	case finding.SeverityMedium:
		return "\x1b[33m" // yellow
	case finding.SeverityLow:
		return "\x1b[32m" // green
	default:
		return "\x1b[90m" // gray
	}
}

// liveEvidenceInt extracts an integer from a finding Evidence map.
// Handles both int (live findings) and float64 (JSON-decoded findings).
func liveEvidenceInt(ev map[string]any, key string) int {
	if ev == nil {
		return 0
	}
	switch v := ev[key].(type) {
	case int:
		return v
	case float64:
		return int(v)
	case int64:
		return int(v)
	}
	return 0
}

// fmtElapsed formats a duration as m:ss (e.g. "4:32") or s (e.g. "45s").
func fmtElapsed(d time.Duration) string {
	d = d.Truncate(time.Second)
	m := int(d.Minutes())
	s := int(d.Seconds()) % 60
	if m > 0 {
		return fmt.Sprintf("%dm%02ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

// fmtETA formats an ETA duration. Returns "…" when unknown.
func fmtETA(d time.Duration) string {
	if d <= 0 {
		return "…"
	}
	d = d.Truncate(time.Second)
	m := int(d.Minutes())
	s := int(d.Seconds()) % 60
	if m > 0 {
		return fmt.Sprintf("~%dm%02ds", m, s)
	}
	return fmt.Sprintf("~%ds", s)
}
