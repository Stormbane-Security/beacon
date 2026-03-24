// Package analyze implements the batch AI playbook analysis job.
// It reads accumulated scan data from the store, sends it to Claude,
// and saves playbook suggestions back to the store.
//
// The job is designed to run infrequently (daily/weekly) to amortize
// Claude API cost across many scans.
package analyze

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/playbook"
	"github.com/stormbane/beacon/internal/store"
)

const (
	// defaultAnalyzeModel uses Opus for analysis — this task requires deep
	// security reasoning across many domains of knowledge and Opus produces
	// significantly more accurate playbook suggestions and attack-chain
	// correlations than Sonnet. The analyze job runs infrequently (daily/weekly)
	// so the higher cost is acceptable.
	defaultAnalyzeModel = "claude-opus-4-6"
	apiURL              = "https://api.anthropic.com/v1/messages"
	apiVersion          = "2023-06-01"
	maxTokens           = 16384
)

// Analyzer runs the batch playbook analysis job.
type Analyzer struct {
	st           store.Store
	apiKey       string
	apiURL       string
	model        string
	httpClient   *http.Client
	registry     *playbook.Registry
	intelSources IntelSources
	progress     func(string)
}

// WithProgress sets a callback that is called with a short status string at
// each major phase of the analysis. Safe to call with nil (no-op).
func (a *Analyzer) WithProgress(fn func(string)) *Analyzer {
	a.progress = fn
	return a
}

func (a *Analyzer) emit(msg string) {
	if a.progress != nil {
		a.progress(msg)
	}
}

// WithIntelSources overrides the threat intel feed URLs.
// Intended for testing — use the default production URLs otherwise.
func (a *Analyzer) WithIntelSources(sources IntelSources) *Analyzer {
	a.intelSources = sources
	return a
}

// New creates an Analyzer.
func New(st store.Store, apiKey string) (*Analyzer, error) {
	return NewWithAPIURL(st, apiKey, apiURL)
}

// NewWithAPIURL creates an Analyzer with a custom API endpoint.
// Intended for testing — use New in production.
func NewWithAPIURL(st store.Store, apiKey, url string) (*Analyzer, error) {
	reg, err := playbook.Load()
	if err != nil {
		return nil, fmt.Errorf("analyze: load playbooks: %w", err)
	}
	return &Analyzer{
		st:           st,
		apiKey:       apiKey,
		apiURL:       url,
		model:        defaultAnalyzeModel,
		httpClient:   &http.Client{Timeout: 120 * time.Second},
		registry:     reg,
		intelSources: DefaultIntelSources(),
	}, nil
}

// WithModel overrides the Claude model used for analysis.
// Call before Run. An empty string is ignored (keeps the default).
func (a *Analyzer) WithModel(model string) *Analyzer {
	if model != "" {
		a.model = model
	}
	return a
}

// Run executes the batch analysis and saves suggestions and correlation findings to the store.
// Returns the number of playbook suggestions generated.
func (a *Analyzer) Run(ctx context.Context) (int, error) {
	result, err := a.RunFull(ctx)
	if err != nil {
		return 0, err
	}
	return len(result.Suggestions), nil
}

// RunFull executes the full analysis and returns all result sections.
// Callers that want accuracy review, optimizations, gaps, and the fix prompt
// should call this instead of Run.
func (a *Analyzer) RunFull(ctx context.Context) (*AnalysisResult, error) {
	a.emit("loading scan history, findings, evidence, and scanner ROI data...")
	prompt, domainRunIDs, err := a.buildPrompt(ctx)
	if err != nil {
		return nil, fmt.Errorf("build prompt: %w", err)
	}

	a.emit(fmt.Sprintf("sending %d domains to Claude for comprehensive analysis (this may take a minute)...", len(domainRunIDs)))
	responseText, err := a.callClaude(ctx, prompt)
	if err != nil {
		return nil, fmt.Errorf("claude: %w", err)
	}

	a.emit("parsing analysis results...")
	result, err := parseFullAnalysisResponse(responseText, domainRunIDs)
	if err != nil {
		// Graceful fallback: try legacy format for suggestions only.
		suggestions, _ := parseSuggestions(responseText)
		result = &AnalysisResult{Suggestions: suggestions}
	}

	for _, s := range result.Suggestions {
		if err := a.st.SavePlaybookSuggestion(ctx, s); err != nil {
			return nil, fmt.Errorf("save suggestion: %w", err)
		}
	}

	totalCorrelations := 0
	for _, corrs := range result.CorrelationsByDomain {
		if len(corrs) == 0 {
			continue
		}
		if err := a.st.SaveCorrelationFindings(ctx, corrs); err != nil {
			return nil, fmt.Errorf("save correlation findings: %w", err)
		}
		totalCorrelations += len(corrs)
	}

	if totalCorrelations > 0 {
		a.emit(fmt.Sprintf("saved %d cross-asset correlation finding(s)", totalCorrelations))
	}
	if len(result.AccuracyReview) > 0 {
		a.emit(fmt.Sprintf("accuracy reviewed %d findings", len(result.AccuracyReview)))
	}

	return result, nil
}

// lastAnalyzeRun returns the timestamp of the most recent analyze run by
// examining when the newest PlaybookSuggestion was created. Returns the zero
// time if no previous run is recorded (first-ever run).
func (a *Analyzer) lastAnalyzeRun(ctx context.Context) time.Time {
	suggestions, err := a.st.ListPlaybookSuggestions(ctx, "")
	if err != nil || len(suggestions) == 0 {
		return time.Time{}
	}
	var latest time.Time
	for _, s := range suggestions {
		if s.CreatedAt.After(latest) {
			latest = s.CreatedAt
		}
	}
	return latest
}

// buildPrompt assembles the analysis context from scan data + live threat intel.
// Returns the prompt string, a map of domain->scanRunID, and any error.
func (a *Analyzer) buildPrompt(ctx context.Context) (string, map[string]string, error) {
	// Determine when analyze last ran so we can filter CVEs to "new since then".
	lastRun := a.lastAnalyzeRun(ctx)

	// Fetch threat intel concurrently while we query the store.
	intelCh := make(chan ThreatIntel, 1)
	go func() {
		// Use a separate client with a shorter timeout for intel — don't block the
		// analysis if a feed is slow.
		intelClient := &http.Client{Timeout: 15 * time.Second}
		sources := a.intelSources
		sources.Since = lastRun
		intelCh <- sources.Fetch(ctx, intelClient)
	}()

	a.emit("querying store for unmatched assets...")
	unmatched, err := a.st.ListUnmatchedAssets(ctx)
	if err != nil {
		return "", nil, err
	}

	// Build domain picture and collect domain->runID mappings.
	a.emit("building domain picture from scan findings...")
	domainRunIDs, domainPicture, err := a.buildDomainPicture(ctx)
	if err != nil {
		return "", nil, err
	}

	a.emit("waiting for threat intelligence feeds...")
	intel := <-intelCh

	var b strings.Builder

	lastRunStr := "never (first run)"
	if !lastRun.IsZero() {
		lastRunStr = lastRun.Format("2006-01-02 15:04 UTC")
	}
	b.WriteString(fmt.Sprintf(`You are a senior security tool architect for Beacon, a reconnaissance scanner.
Your job is to analyze ALL accumulated scan history AND current threat intelligence,
then produce high-quality playbook improvements AND identify cross-asset attack chains.

Analysis last ran: %s
Today: %s

Playbooks are YAML files that configure which Nuclei tags and named scanners run for
matching assets. The available named scanners are:

  Surface (safe, passive or low-noise):
    email, whois, tls, tlscheck, assetintel, webcontent, cloudbuckets, historicalurls,
    crawler, screenshot, bgp, passivedns, cdnbypass, vhost, graphql, portscan,
    typosquat, dlp, dns, httpmethods, takeover, wafdetect, harvester, clickjacking,
    exposedfiles, apiversions, aidetect, saml, iam, web3detect, log4shell, depconf,
    dorks, cms-plugins, hibp

  Deep (active probes — requires --deep flag):
    testssl, cors, ratelimit, hostheader, jwt, oauth, autoprobe, websocket,
    smuggling, aillm, ssti, crlf

Match rule types (for the match: section):
  always, header_present, header_value, asn_org_contains, dns_suffix,
  cname_contains, title_contains, body_contains, cert_san_contains,
  path_responds, service_version_contains, ai_endpoint_present,
  llm_provider_contains, cloud_provider_contains, framework_contains,
  auth_system_contains, is_serverless (bool), is_kubernetes (bool),
  has_contract_addresses (bool), auth_scheme_contains, mx_provider_contains,
  vendor_signal_contains, has_dmarc (bool)

Nuclei CVE template naming convention: cve-YYYY-NNNNN
  (e.g. CVE-2024-12345 → nuclei tag "cve-2024-12345")

---
`, lastRunStr, time.Now().UTC().Format("2006-01-02")))


	// Existing playbooks.
	b.WriteString("## Existing playbooks\n")
	for _, p := range a.registry.All() {
		b.WriteString("  - " + p.Name + "\n")
	}
	b.WriteString("\n")

	// Unmatched assets from scan history.
	if len(unmatched) > 0 {
		shown := unmatched
		if len(shown) > 50 {
			shown = shown[:50]
		}
		b.WriteString(fmt.Sprintf("## Unmatched assets from scan history (%d unique fingerprints)\n", len(unmatched)))
		b.WriteString("These assets had no targeted playbook match — potential gaps in coverage.\n\n")
		for _, u := range shown {
			ev := u.Evidence
			b.WriteString(fmt.Sprintf(
				"  asset=%s asn_org=%q dns_suffix=%q title=%q status=%d cname=%v cert_issuer=%q\n",
				u.Asset, ev.ASNOrg, ev.DNSSuffix, ev.Title, ev.StatusCode,
				ev.CNAMEChain, ev.CertIssuer,
			))
		}
		b.WriteString("\n")
	}

	// Scanner ROI data — per-scanner timing and findings for each domain.
	for domain := range domainRunIDs {
		roi, err := a.st.GetScannerROI(ctx, domain)
		if err == nil && len(roi) > 0 {
			b.WriteString(fmt.Sprintf("## Scanner ROI for %s\n", domain))
			b.WriteString("Format: scanner | runs | avg_duration_ms | total_findings (crit/high) | error_rate | skip_rate | findings_per_min\n\n")
			for _, r := range roi {
				b.WriteString(fmt.Sprintf(
					"  %-20s | %3d runs | %5dms avg | %3d findings (%d crit/%d high) | %.0f%% err | %.0f%% skip | %.2f/min\n",
					r.ScannerName, r.RunCount, r.AvgDurationMs,
					r.TotalFindings, r.CriticalFindings, r.HighFindings,
					r.ErrorRate*100, r.SkipRate*100, r.FindingsPerMin,
				))
			}
			b.WriteString("\n")
		}
	}

	// Domain-wide findings for attack chain analysis.
	if domainPicture != "" {
		b.WriteString(domainPicture)
	}

	// Live threat intelligence.
	intel.AppendToPrompt(&b)

	b.WriteString(`---
## Your task

You are performing a comprehensive security analysis of ALL scan data above. Work through
EVERY section below in order. Return a single JSON object — no surrounding text.

---
### SECTION A: FINDING ACCURACY REVIEW

For EVERY finding in the scan data above, evaluate it line by line:
1. Does the evidence actually support the finding title and severity?
2. Is this a true positive or likely false positive? Assign a confidence score 0-100.
3. Is the proof_cmd syntactically correct? Will running it reproduce the finding?
   - Check: does the curl target the right URL (the specific file/endpoint, not root)?
   - Check: does the grep pattern match the signal in evidence (not generic keywords)?
   - Check: for SAML proofs, does it use a static base64 blob with a past date? (stale = broken)
   - Check: for SSRF, does the signal appear in the payload URL itself? (false positive pattern)
4. Flag: redirect responses (3xx) claimed as SSRF — the server redirected, did not fetch.
5. Flag: "computeMetadata" or similar payload-URL substrings used as SSRF signals.
6. Flag: JS secret proof commands that curl the root page instead of the specific JS file.

"accuracy_review": [
  {
    "asset": "...",
    "check_id": "...",
    "title": "...",
    "confidence": 0-100,
    "verdict": "true_positive" | "likely_false_positive" | "needs_verification",
    "reasoning": "...",
    "proof_cmd_ok": true | false,
    "proof_cmd_issue": "..." // null if ok
  }
]

---
### SECTION B: ATTACK CHAIN CORRELATIONS

Look across ALL assets. Identify multi-step paths that combine findings from ≥2 assets.
Examples: exposed admin + weak SPF + HIBP breach = phishing-to-admin.
Only include chains with compound risk not visible from any single asset.

"correlations": [
  {
    "title": "...",
    "severity": "critical"|"high"|"medium"|"low",
    "affected_assets": [...],
    "contributing_checks": [...],
    "description": "...",
    "remediation": "..."
  }
]

---
### SECTION C: SCAN OPTIMIZATION

Based on scanner ROI data, evidence patterns, false positives found, and timing:
1. Which scanners have systematically poor signal-to-noise on this tech stack?
2. Which scanners are too slow relative to findings produced?
3. What match rule improvements would target the right assets more precisely?
4. What scan ordering changes would find critical issues faster?
5. Which check IDs consistently produce false positives with this tech stack?
NEVER suggest removing a scanner entirely — only suggest conditional targeting.

"scan_optimizations": [
  {
    "type": "false_positive_pattern" | "performance" | "coverage_gap" | "ordering",
    "scanner": "...",
    "check_id": "...", // null if scanner-level
    "description": "...",
    "suggested_change": "..."
  }
]

---
### SECTION D: CVE / THREAT INTELLIGENCE MAPPING

For EACH CVE/advisory in the threat intel section:
a. Identify affected product and version range.
b. Assess Beacon detection feasibility — which match rule fingerprints this product?
c. If product has a playbook: add cve-YYYY-NNNNN to deep.nuclei_tags (surface too if KEV/ransomware).
d. If no playbook: suggest a minimal new playbook with match rules and the CVE tag.
e. CISA KEV = HIGHEST PRIORITY — being actively exploited right now. Every KEV entry
   for a fingerprintable product MUST produce a suggestion.
f. Flag CVEs that NO existing scanner can detect — these go in scan_gaps.

"playbook_suggestions": [
  {
    "type": "new" | "improve",
    "target_playbook": "...",
    "suggested_yaml": "...",
    "reasoning": "..."
  }
]
"scan_gaps": [
  {
    "cve_id": "...",
    "product": "...",
    "reason_undetectable": "...",
    "suggested_new_scanner_or_check": "..."
  }
]

---
### SECTION E: PLAYBOOK COVERAGE GAPS

For unmatched assets and matched assets with missing scanners:
1. Group unmatched assets by fingerprint (title, ASN, CNAME, headers) → suggest new playbooks.
2. For matched assets: "Did the scanner set miss something obvious?"
   - Asset matches wordpress but no cors or jwt scanner ran
   - Asset matches api but no ratelimit or autoprobe ran
3. Scanner ROI: high skip_rate (>50%) → scanner misconfigured for this stack.

(Add to playbook_suggestions array above.)

---
### SECTION F: FIX PROMPT FOR CLAUDE CODE

Generate a "fix_prompt" string — a complete, actionable prompt the user can paste into
Claude Code to fix all scanner code issues identified in SECTION A above.
Include ONLY issues that require code changes (broken proof commands, false positive logic,
wrong signal patterns). Format as a bulleted list of specific fixes with file/scanner names.
If no code fixes are needed, set to "No scanner code fixes required."

"fix_prompt": "Fix the following scanner code issues in the Beacon codebase:\n\n..."

---
### OUTPUT FORMAT (return ONLY this JSON, no other text):

{
  "accuracy_review": [...],
  "correlations": [...],
  "scan_optimizations": [...],
  "playbook_suggestions": [...],
  "scan_gaps": [...],
  "fix_prompt": "..."
}

Rules:
- Only use the named scanners and match rule types listed in the system header.
- Nuclei tags: cve-YYYY-NNNNN (lowercase).
- Do not duplicate existing playbooks.
- Each suggested_yaml must be complete valid YAML.
- Empty arrays [] for sections with no entries.
- Every entry needs substantive reasoning grounded in evidence from the scan data.
`)


	return b.String(), domainRunIDs, nil
}

// AnalysisResult holds all outputs from a Claude analysis run.
type AnalysisResult struct {
	Suggestions          []*store.PlaybookSuggestion
	CorrelationsByDomain map[string][]store.CorrelationFinding
	AccuracyReview       []AccuracyReviewItem
	ScanOptimizations    []ScanOptimization
	ScanGaps             []ScanGap
	FixPrompt            string
}

// AccuracyReviewItem is Claude's verdict on a single finding's accuracy.
type AccuracyReviewItem struct {
	Asset         string `json:"asset"`
	CheckID       string `json:"check_id"`
	Title         string `json:"title"`
	Confidence    int    `json:"confidence"`
	Verdict       string `json:"verdict"`       // "true_positive", "likely_false_positive", "needs_verification"
	Reasoning     string `json:"reasoning"`
	ProofCmdOK    bool   `json:"proof_cmd_ok"`
	ProofCmdIssue string `json:"proof_cmd_issue"`
}

// ScanOptimization is a suggestion for improving scanner accuracy or performance.
type ScanOptimization struct {
	Type            string `json:"type"`   // "false_positive_pattern", "performance", "coverage_gap", "ordering"
	Scanner         string `json:"scanner"`
	CheckID         string `json:"check_id"`
	Description     string `json:"description"`
	SuggestedChange string `json:"suggested_change"`
}

// ScanGap is a CVE or attack surface that no current scanner can detect.
type ScanGap struct {
	CVEID                        string `json:"cve_id"`
	Product                      string `json:"product"`
	ReasonUndetectable           string `json:"reason_undetectable"`
	SuggestedNewScannerOrCheck   string `json:"suggested_new_scanner_or_check"`
}

// parseAnalysisResponse parses Claude's JSON response.
// Handles the new comprehensive format (with accuracy_review, scan_optimizations,
// scan_gaps, fix_prompt) and falls back to the legacy format for backward compat.
func parseAnalysisResponse(text string, domainRunIDs map[string]string) ([]*store.PlaybookSuggestion, map[string][]store.CorrelationFinding, error) {
	result, err := parseFullAnalysisResponse(text, domainRunIDs)
	if err != nil {
		// Fall back to bare array format (backward compat with existing tests).
		suggestions, err2 := parseSuggestions(text)
		if err2 != nil {
			return nil, nil, err2
		}
		return suggestions, nil, nil
	}
	return result.Suggestions, result.CorrelationsByDomain, nil
}

// parseFullAnalysisResponse parses the comprehensive analysis JSON and returns
// all sections including accuracy review, optimizations, gaps, and fix prompt.
func parseFullAnalysisResponse(text string, domainRunIDs map[string]string) (*AnalysisResult, error) {
	objStart := strings.Index(text, "{")
	arrStart := strings.Index(text, "[")
	if objStart == -1 || (arrStart != -1 && arrStart < objStart) {
		return nil, fmt.Errorf("no JSON object found")
	}
	objEnd := strings.LastIndex(text, "}")
	if objEnd <= objStart {
		return nil, fmt.Errorf("unclosed JSON object")
	}

	jsonText := text[objStart : objEnd+1]
	var obj struct {
		PlaybookSuggestions []struct {
			Type           string `json:"type"`
			TargetPlaybook string `json:"target_playbook"`
			SuggestedYAML  string `json:"suggested_yaml"`
			Reasoning      string `json:"reasoning"`
		} `json:"playbook_suggestions"`
		Correlations      []rawCorrelation     `json:"correlations"`
		AccuracyReview    []AccuracyReviewItem `json:"accuracy_review"`
		ScanOptimizations []ScanOptimization   `json:"scan_optimizations"`
		ScanGaps          []ScanGap            `json:"scan_gaps"`
		FixPrompt         string               `json:"fix_prompt"`
	}
	if err := json.Unmarshal([]byte(jsonText), &obj); err != nil {
		return nil, fmt.Errorf("JSON parse: %w", err)
	}

	return &AnalysisResult{
		Suggestions:          parseSuggestionsFromRaw(obj.PlaybookSuggestions),
		CorrelationsByDomain: groupCorrelationsByDomain(obj.Correlations, domainRunIDs),
		AccuracyReview:       obj.AccuracyReview,
		ScanOptimizations:    obj.ScanOptimizations,
		ScanGaps:             obj.ScanGaps,
		FixPrompt:            obj.FixPrompt,
	}, nil
}

// parseSuggestionsFromRaw converts raw suggestion structs to PlaybookSuggestion pointers.
func parseSuggestionsFromRaw(raw []struct {
	Type           string `json:"type"`
	TargetPlaybook string `json:"target_playbook"`
	SuggestedYAML  string `json:"suggested_yaml"`
	Reasoning      string `json:"reasoning"`
}) []*store.PlaybookSuggestion {
	out := make([]*store.PlaybookSuggestion, 0, len(raw))
	for _, r := range raw {
		if r.Type == "" || r.TargetPlaybook == "" || r.SuggestedYAML == "" {
			continue
		}
		out = append(out, &store.PlaybookSuggestion{
			Type:           r.Type,
			TargetPlaybook: r.TargetPlaybook,
			SuggestedYAML:  r.SuggestedYAML,
			Reasoning:      r.Reasoning,
			Status:         "pending",
			CreatedAt:      time.Now(),
		})
	}
	return out
}

// groupCorrelationsByDomain assigns domain and scan run IDs to correlations.
// Correlations without a known domain in affected_assets are assigned to a "_unknown" key.
func groupCorrelationsByDomain(raw []rawCorrelation, domainRunIDs map[string]string) map[string][]store.CorrelationFinding {
	out := make(map[string][]store.CorrelationFinding)
	for _, r := range raw {
		// Find which domain this correlation belongs to by checking affected assets.
		domain := ""
		scanRunID := ""
		for d, runID := range domainRunIDs {
			for _, asset := range r.AffectedAssets {
				if strings.HasSuffix(asset, d) || asset == d {
					domain = d
					scanRunID = runID
					break
				}
			}
			if domain != "" {
				break
			}
		}
		// If no domain matched, use the first domain we have (best effort).
		if domain == "" && len(domainRunIDs) > 0 {
			for d, runID := range domainRunIDs {
				domain = d
				scanRunID = runID
				break
			}
		}

		corrs := parseCorrelations(scanRunID, domain, []rawCorrelation{r})
		if len(corrs) > 0 {
			out[domain] = append(out[domain], corrs...)
		}
	}
	return out
}

// parseSuggestions parses the legacy bare JSON array format Claude may return.
// Kept for backward compatibility with existing tests.
func parseSuggestions(text string) ([]*store.PlaybookSuggestion, error) {
	// Find the JSON array in the response (Claude sometimes adds prose).
	start := strings.Index(text, "[")
	end := strings.LastIndex(text, "]")
	if start == -1 || end == -1 || end <= start {
		// No suggestions found — not an error, just nothing to suggest.
		return nil, nil
	}
	jsonText := text[start : end+1]

	var raw []struct {
		Type           string `json:"type"`
		TargetPlaybook string `json:"target_playbook"`
		SuggestedYAML  string `json:"suggested_yaml"`
		Reasoning      string `json:"reasoning"`
	}
	if err := json.Unmarshal([]byte(jsonText), &raw); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}

	out := make([]*store.PlaybookSuggestion, 0, len(raw))
	for _, r := range raw {
		if r.Type == "" || r.TargetPlaybook == "" || r.SuggestedYAML == "" {
			continue
		}
		out = append(out, &store.PlaybookSuggestion{
			Type:           r.Type,
			TargetPlaybook: r.TargetPlaybook,
			SuggestedYAML:  r.SuggestedYAML,
			Reasoning:      r.Reasoning,
			Status:         "pending",
			CreatedAt:      time.Now(),
		})
	}
	return out, nil
}

// claudeRequest / claudeResponse are minimal Anthropic API types.
type claudeRequest struct {
	Model     string           `json:"model"`
	MaxTokens int              `json:"max_tokens"`
	Messages  []claudeMessage  `json:"messages"`
}

type claudeMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type claudeResponse struct {
	Content []struct {
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func (a *Analyzer) callClaude(ctx context.Context, prompt string) (string, error) {
	body, err := json.Marshal(claudeRequest{
		Model:     a.model,
		MaxTokens: maxTokens,
		Messages:  []claudeMessage{{Role: "user", Content: prompt}},
	})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.apiURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", a.apiKey)
	req.Header.Set("anthropic-version", apiVersion)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Claude API HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}

	var cr claudeResponse
	if err := json.Unmarshal(data, &cr); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}
	if cr.Error != nil {
		return "", fmt.Errorf("API error: %s", cr.Error.Message)
	}
	if len(cr.Content) == 0 {
		return "", fmt.Errorf("empty response")
	}
	return cr.Content[0].Text, nil
}
