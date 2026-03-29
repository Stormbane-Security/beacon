// Package verify implements post-scan finding accuracy review.
//
// It examines all findings from a scan run using static heuristics and
// (optionally) Claude AI to identify:
//   - Likely false positives
//   - Broken or stale proof commands
//   - Evidence inconsistencies
//   - Severity mismatches
//
// No outbound connections are made to target hosts. Analysis is purely
// based on the stored evidence and proof commands.
package verify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/store"
)

const (
	apiURL     = "https://api.anthropic.com/v1/messages"
	apiVersion = "2023-06-01"
	verifyModel = "claude-sonnet-4-6"
	maxTokens  = 8192
)

// Issue describes a problem found during verification of a single finding.
type Issue struct {
	Kind        string // "false_positive", "stale_proof", "broken_proof", "evidence_mismatch", "severity_mismatch"
	Severity    string // "critical", "warning", "info"
	Description string
	Suggestion  string // Actionable fix
}

// FindingVerdict is the result of verifying a single finding.
type FindingVerdict struct {
	Finding finding.Finding
	Issues  []Issue
	// AIAnalysis is set when Claude reviewed this finding.
	AIAnalysis string
}

// HasIssues returns true if any issues were found.
func (v *FindingVerdict) HasIssues() bool { return len(v.Issues) > 0 }

// Report is the full result of a verify run.
type Report struct {
	RunID            string
	Domain           string
	TotalCount       int
	IssueCount       int
	Verdicts         []FindingVerdict
	CredentialAlerts []string // cross-correlated credential + exploit path alerts
	GeneratedAt      time.Time
}

// Verifier reviews scan findings for accuracy.
type Verifier struct {
	st         store.Store
	apiKey     string
	apiURL     string
	httpClient *http.Client
}

// New creates a Verifier. apiKey is optional — static checks run without it.
func New(st store.Store, apiKey string) *Verifier {
	return &Verifier{
		st:         st,
		apiKey:     apiKey,
		apiURL:     apiURL,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// RunLatest verifies the most recent scan run, or the run specified by runID.
// If runID is empty the most recent completed run is used.
func (v *Verifier) RunLatest(ctx context.Context, runID string) (*Report, error) {
	var run *store.ScanRun
	if runID != "" {
		runs, err := v.st.ListRecentScanRuns(ctx, 200)
		if err != nil {
			return nil, fmt.Errorf("list runs: %w", err)
		}
		for i := range runs {
			if runs[i].ID == runID {
				run = &runs[i]
				break
			}
		}
		if run == nil {
			return nil, fmt.Errorf("run %q not found", runID)
		}
	} else {
		runs, err := v.st.ListRecentScanRuns(ctx, 1)
		if err != nil {
			return nil, fmt.Errorf("list runs: %w", err)
		}
		if len(runs) == 0 {
			return nil, fmt.Errorf("no scan runs found")
		}
		run = &runs[0]
	}

	findings, err := v.st.GetFindings(ctx, run.ID)
	if err != nil {
		return nil, fmt.Errorf("get findings: %w", err)
	}

	report := &Report{
		RunID:       run.ID,
		Domain:      run.Domain,
		TotalCount:  len(findings),
		GeneratedAt: time.Now(),
	}

	for _, f := range findings {
		verdict := FindingVerdict{Finding: f}
		verdict.Issues = staticChecks(f)

		// Use Claude for deeper analysis if API key is present.
		if v.apiKey != "" && len(verdict.Issues) > 0 {
			analysis, err := v.claudeAnalyze(ctx, f, verdict.Issues)
			if err == nil && analysis != "" {
				verdict.AIAnalysis = analysis
			}
		}

		report.Verdicts = append(report.Verdicts, verdict)
		if verdict.HasIssues() {
			report.IssueCount++
		}
	}

	report.CredentialAlerts = CorrelateCredentials(report.Verdicts)
	return report, nil
}

// staticChecks applies heuristic rules to detect common false positives
// and proof command problems without making any network requests.
func staticChecks(f finding.Finding) []Issue {
	var issues []Issue

	// ── SSRF checks ──────────────────────────────────────────────────────────
	if f.CheckID == finding.CheckWebSSRF {
		// A redirect response is not SSRF — it's an open redirect at best.
		if sc, ok := f.Evidence["status_code"]; ok {
			switch v := sc.(type) {
			case int:
				if v >= 300 && v < 400 {
					issues = append(issues, Issue{
						Kind:     "false_positive",
						Severity: "critical",
						Description: fmt.Sprintf(
							"SSRF finding was triggered by a %d redirect response, not a 200. "+
								"The server redirected the request to the metadata URL rather than fetching it. "+
								"This is an open redirect, not SSRF.", v),
						Suggestion: "Confirm by running: curl -s --max-redirs 0 \"<proof_url>\" — if you see a Location header pointing to the metadata URL it's open redirect only.",
					})
				}
			case float64:
				if v >= 300 && v < 400 {
					issues = append(issues, Issue{
						Kind:     "false_positive",
						Severity: "critical",
						Description: fmt.Sprintf(
							"SSRF finding triggered by %d redirect — server redirected, not fetched. Open redirect, not SSRF.", int(v)),
						Suggestion: "Add --max-redirs 0 to the proof curl and check for Location header.",
					})
				}
			}
		}
		// Signal appearing in the payload URL is not evidence of SSRF.
		if sig, ok := f.Evidence["signal"].(string); ok {
			if payload, ok := f.Evidence["payload"].(string); ok {
				if sig != "" && strings.Contains(payload, sig) {
					issues = append(issues, Issue{
						Kind:     "false_positive",
						Severity: "critical",
						Description: fmt.Sprintf(
							"The signal %q used to detect SSRF is a substring of the payload URL %q. "+
								"Any server that reflects the URL in an error body would trigger this — "+
								"the server may not have actually fetched the metadata endpoint.", sig, payload),
						Suggestion: "Use a signal that only appears in actual metadata content (e.g., 'ami-id', 'AccessKeyId') not in the URL itself.",
					})
				}
			}
		}
		// Check proof command grep pattern
		if pc := f.ProofCommand; pc != "" && strings.Contains(pc, "computeMetadata") {
			issues = append(issues, Issue{
				Kind:        "broken_proof",
				Severity:    "warning",
				Description: "Proof command greps for 'computeMetadata' which is in the payload URL — any URL reflection will match this.",
				Suggestion:  "Change grep to: grep -E 'ami-id|AccessKeyId|instance-id|local-hostname'",
			})
		}
	}

	// ── SAML checks ──────────────────────────────────────────────────────────
	if strings.HasPrefix(string(f.CheckID), "saml.") {
		if pc := f.ProofCommand; pc != "" {
			// Detect old base64-encoded static SAML assertions
			if strings.Contains(pc, "PD94bWw") || strings.Contains(pc, "PHNhbWxw") {
				// Check for hardcoded dates
				if strings.Contains(pc, "2024-") || strings.Contains(pc, "2023-") {
					issues = append(issues, Issue{
						Kind:     "stale_proof",
						Severity: "critical",
						Description: "Proof command contains a base64-encoded SAMLResponse with a hardcoded past date. " +
							"Servers enforcing time windows (typically ±5 minutes) will reject this assertion.",
						Suggestion: "Replace with the python3 proof command that generates a fresh assertion at runtime with the current timestamp.",
					})
				}
				// Static IDs in replay caches
				if strings.Contains(pc, "_beacon_test_assertion") || strings.Contains(pc, "ID=\"_beacon\"") {
					issues = append(issues, Issue{
						Kind:     "stale_proof",
						Severity: "warning",
						Description: "Proof command uses a hardcoded assertion ID that may be cached by the server's replay protection.",
						Suggestion: "Use unique IDs generated at runtime (e.g., via python3 time.time_ns()).",
					})
				}
			}
		}
	}

	// ── Missing proof command ──────────────────────────────────────────────
	if f.ProofCommand == "" && f.Severity >= finding.SeverityHigh {
		issues = append(issues, Issue{
			Kind:        "broken_proof",
			Severity:    "warning",
			Description: fmt.Sprintf("High/Critical finding %q has no proof command.", f.Title),
			Suggestion:  "Add a ProofCommand field to this scanner's finding struct.",
		})
	}

	// ── Host header: probe value mismatch ─────────────────────────────────
	if f.CheckID == finding.CheckHostHeaderInjection {
		injected, hasInjected := f.Evidence["injected_value"].(string)
		if hasInjected && f.ProofCommand != "" {
			if !strings.Contains(f.ProofCommand, injected) {
				issues = append(issues, Issue{
					Kind:     "broken_proof",
					Severity: "warning",
					Description: fmt.Sprintf(
						"Proof command does not contain the injected probe value %q — it may use a different value that won't trigger the reflection.", injected),
					Suggestion: fmt.Sprintf("Update proof command to use: -H 'Host: %s' and grep for '%s'", injected, injected),
				})
			}
		}
	}

	// ── Webcontent JS secrets: proof must grep the JS file, not root ──────
	if f.CheckID == finding.CheckJSHardcodedSecret {
		if jsURL, ok := f.Evidence["js_url"].(string); ok && jsURL != "" {
			if f.ProofCommand != "" && !strings.Contains(f.ProofCommand, jsURL) {
				issues = append(issues, Issue{
					Kind:     "broken_proof",
					Severity: "warning",
					Description: fmt.Sprintf(
						"Proof command does not reference the specific JS file URL (%s) where the secret was found. "+
							"Curling the root URL will not contain the secret.", jsURL),
					Suggestion: fmt.Sprintf("Use: curl -s '%s' | grep -oE '<regex>'", jsURL),
				})
			}
		}
		// Check if grep pattern is generic keyword-based instead of specific
		if pc := f.ProofCommand; pc != "" {
			genericPatterns := []string{"api_key|apikey|secret|token|password", "(api_key|apikey|secret|token|password)"}
			for _, gp := range genericPatterns {
				if strings.Contains(pc, gp) {
					issues = append(issues, Issue{
						Kind:     "broken_proof",
						Severity: "warning",
						Description: "Proof command uses a generic keyword grep (api_key|apikey|secret|token|password) that won't match many real secrets (e.g., Firebase 'AIzaSy...', Stripe 'sk_live_...').",
						Suggestion:  "Use the specific regex from the pattern that matched (e.g., 'AIzaSy[A-Za-z0-9\\-_]{33}' for Firebase keys).",
					})
					break
				}
			}
		}
	}

	// ── DLP: evidence has value but proof doesn't grep for it ─────────────
	if strings.HasPrefix(string(f.CheckID), "dlp.") {
		if matchVal, ok := f.Evidence["match"].(string); ok && matchVal != "" {
			if pc := f.ProofCommand; pc != "" {
				// Check that the match value (or a pattern matching it) is in the proof
				if !strings.Contains(pc, matchVal[:min(len(matchVal), 10)]) {
					issues = append(issues, Issue{
						Kind:        "evidence_mismatch",
						Severity:    "info",
						Description: fmt.Sprintf("Proof command may not grep for the actual matched value %q.", matchVal),
						Suggestion:  "Ensure the grep pattern in the proof command would match the specific value found.",
					})
				}
			}
		}
	}

	return issues
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// sanitizeForPrompt removes newlines and control characters from a string to
// prevent prompt injection when interpolating user-controlled data into AI
// prompts. Truncates to maxLen runes.
func sanitizeForPrompt(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 || r == '\t' {
			b.WriteRune(r)
		}
	}
	result := b.String()
	runes := []rune(result)
	if len(runes) > maxLen {
		result = string(runes[:maxLen])
	}
	return result
}

// claudeAnalyze asks Claude to review a finding's evidence for accuracy.
// It does NOT make any connections to the target — analysis is purely based
// on the stored evidence data.
func (v *Verifier) claudeAnalyze(ctx context.Context, f finding.Finding, staticIssues []Issue) (string, error) {
	evidenceJSON, _ := json.MarshalIndent(f.Evidence, "", "  ")
	issueDescs := make([]string, 0, len(staticIssues))
	for _, iss := range staticIssues {
		issueDescs = append(issueDescs, fmt.Sprintf("- [%s] %s", iss.Kind, iss.Description))
	}

	// Sanitize all user-controlled fields to prevent prompt injection via
	// crafted finding titles, descriptions, or asset names.
	safeTitle := sanitizeForPrompt(f.Title, 256)
	safeAsset := sanitizeForPrompt(f.Asset, 256)
	safeDesc := sanitizeForPrompt(f.Description, 512)
	safeScanner := sanitizeForPrompt(f.Scanner, 64)
	safeProof := sanitizeForPrompt(f.ProofCommand, 1024)

	prompt := fmt.Sprintf(`You are reviewing a security scan finding for accuracy. Do NOT suggest connecting to the target — analyze only the stored evidence.

Finding:
- Title: %s
- Check ID: %s
- Severity: %s
- Scanner: %s
- Asset: %s
- Description: %s

Evidence (what the scanner observed):
%s

Proof Command:
%s

Static analysis already flagged these issues:
%s

Please answer:
1. Based ONLY on the evidence fields above, is this finding likely accurate or a false positive? Explain why.
2. Is the proof command correct — will running it reproduce/confirm the finding? If not, what is wrong?
3. What is the single most important fix (if any)?

Keep your response under 150 words.`,
		safeTitle, f.CheckID, f.Severity.String(), safeScanner, safeAsset,
		safeDesc,
		string(evidenceJSON),
		safeProof,
		strings.Join(issueDescs, "\n"),
	)

	return v.callClaude(ctx, prompt)
}

// callClaude sends a single-turn message to the Claude API.
func (v *Verifier) callClaude(ctx context.Context, prompt string) (string, error) {
	body := map[string]any{
		"model":      verifyModel,
		"max_tokens": maxTokens,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.apiURL, bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", v.apiKey)
	req.Header.Set("anthropic-version", apiVersion)

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		// Redact any occurrence of the API key in the error body to
		// prevent accidental key exposure in logs or user-facing output.
		safeBody := string(respBody)
		if v.apiKey != "" {
			safeBody = strings.ReplaceAll(safeBody, v.apiKey, "[REDACTED]")
		}
		return "", fmt.Errorf("claude API %d: %s", resp.StatusCode, safeBody)
	}

	var result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", err
	}
	for _, c := range result.Content {
		if c.Type == "text" {
			return strings.TrimSpace(c.Text), nil
		}
	}
	return "", nil
}

// CorrelateCredentials cross-references DLP/exposed-file findings with other
// findings from the same scan to assess exploitability without active testing.
// It returns a list of enriched issues added to affected verdicts.
func CorrelateCredentials(verdicts []FindingVerdict) []string {
	var alerts []string

	// Collect credential findings and other context findings by asset.
	type credInfo struct {
		checkID  finding.CheckID
		title    string
		asset    string
		credType string // "api_key", "db_url", "oauth_secret", "private_key", etc.
		value    string // partial value for context (not logged fully)
	}

	var creds []credInfo
	authEndpoints := map[string]bool{} // assets with auth endpoints
	ssrfAssets := map[string]bool{}    // assets confirmed SSRF-vulnerable
	openRedirects := map[string]bool{} // assets with open redirects

	for _, v := range verdicts {
		f := v.Finding
		switch f.CheckID {
		case finding.CheckDLPAPIKey, finding.CheckDLPPrivateKey,
			finding.CheckDLPDatabaseURL, finding.CheckJSHardcodedSecret,
			finding.CheckOAuthClientSecretLeak:
			ct := "secret"
			if strings.Contains(strings.ToLower(f.Title), "api key") || strings.Contains(strings.ToLower(f.Title), "api_key") {
				ct = "api_key"
			} else if strings.Contains(strings.ToLower(f.Title), "database") || strings.Contains(strings.ToLower(f.Title), "db_url") {
				ct = "db_url"
			} else if strings.Contains(strings.ToLower(f.Title), "private key") {
				ct = "private_key"
			} else if strings.Contains(strings.ToLower(f.Title), "oauth") || strings.Contains(strings.ToLower(f.Title), "client_secret") {
				ct = "oauth_secret"
			}
			val := ""
			if m, ok := f.Evidence["match"].(string); ok {
				if len(m) > 20 {
					val = m[:8] + "…" + m[len(m)-4:]
				} else {
					val = m
				}
			}
			creds = append(creds, credInfo{
				checkID:  f.CheckID,
				title:    f.Title,
				asset:    f.Asset,
				credType: ct,
				value:    val,
			})

		case finding.CheckSAMLEndpointExposed, finding.CheckAIEndpointExposed,
			finding.CheckOAuthMissingState, finding.CheckOAuthOpenRedirect:
			authEndpoints[f.Asset] = true

		case finding.CheckWebSSRF, finding.CheckCloudMetadataSSRF:
			ssrfAssets[f.Asset] = true

		case finding.CheckWebOpenRedirect, finding.CheckSAMLOpenRedirect:
			openRedirects[f.Asset] = true
		}
	}

	for _, cred := range creds {
		var factors []string

		if authEndpoints[cred.asset] {
			factors = append(factors, "auth endpoint confirmed on same asset")
		}
		if ssrfAssets[cred.asset] {
			factors = append(factors, "SSRF confirmed on same asset — credential may be reachable from server-side")
		}
		if openRedirects[cred.asset] {
			factors = append(factors, "open redirect on same asset — credential phishing vector exists")
		}
		if cred.credType == "private_key" {
			factors = append(factors, "private key exposure enables full identity impersonation")
		}
		if cred.credType == "db_url" {
			factors = append(factors, "database URL includes credentials for direct connection")
		}

		if len(factors) > 0 {
			alert := fmt.Sprintf(
				"CREDENTIAL EXPOSURE + EXPLOIT PATH: %s on %s [%s]\n  Exploitability factors: %s",
				cred.title, cred.asset, cred.value,
				strings.Join(factors, "; "))
			alerts = append(alerts, alert)
		} else {
			alerts = append(alerts, fmt.Sprintf(
				"CREDENTIAL EXPOSED (no additional exploit path confirmed): %s on %s [%s]",
				cred.title, cred.asset, cred.value))
		}
	}

	return alerts
}

// FormatMarkdown renders the report as a markdown string suitable for
// copying into a conversation or saving to a file.
func (r *Report) FormatMarkdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Beacon Verify Report\n\n")
	fmt.Fprintf(&b, "**Run ID:** %s  \n", r.RunID)
	fmt.Fprintf(&b, "**Domain:** %s  \n", r.Domain)
	fmt.Fprintf(&b, "**Generated:** %s  \n", r.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "**Findings reviewed:** %d  \n", r.TotalCount)
	fmt.Fprintf(&b, "**Findings with issues:** %d  \n\n", r.IssueCount)

	if len(r.CredentialAlerts) > 0 {
		fmt.Fprintf(&b, "## Credential Exposure + Exploit Path Correlation\n\n")
		for _, alert := range r.CredentialAlerts {
			fmt.Fprintf(&b, "- %s\n", alert)
		}
		fmt.Fprintf(&b, "\n")
	}

	if r.IssueCount == 0 && len(r.CredentialAlerts) == 0 {
		fmt.Fprintf(&b, "✓ No accuracy issues detected.\n")
		return b.String()
	}
	if r.IssueCount == 0 {
		return b.String()
	}

	fmt.Fprintf(&b, "---\n\n")

	for _, v := range r.Verdicts {
		if !v.HasIssues() {
			continue
		}
		f := v.Finding
		fmt.Fprintf(&b, "## [%s] %s\n\n", f.Severity.String(), f.Title)
		fmt.Fprintf(&b, "- **Asset:** %s\n", f.Asset)
		fmt.Fprintf(&b, "- **Check:** %s\n", f.CheckID)
		fmt.Fprintf(&b, "- **Scanner:** %s\n\n", f.Scanner)

		for _, iss := range v.Issues {
			icon := "⚠️"
			if iss.Kind == "false_positive" {
				icon = "🚫"
			} else if iss.Severity == "critical" {
				icon = "🔴"
			}
			fmt.Fprintf(&b, "%s **%s**: %s\n\n", icon, strings.ReplaceAll(iss.Kind, "_", " "), iss.Description)
			if iss.Suggestion != "" {
				fmt.Fprintf(&b, "  > Fix: %s\n\n", iss.Suggestion)
			}
		}

		if v.AIAnalysis != "" {
			fmt.Fprintf(&b, "**AI Analysis:**\n\n%s\n\n", v.AIAnalysis)
		}

		fmt.Fprintf(&b, "---\n\n")
	}

	// Append a fix prompt the user can paste to Claude Code
	fmt.Fprintf(&b, "## Fix Prompt\n\n")
	fmt.Fprintf(&b, "Paste this into Claude Code to fix all flagged issues:\n\n")
	fmt.Fprintf(&b, "```\n")
	fmt.Fprintf(&b, "Fix the following scanner accuracy issues in the Beacon codebase:\n\n")
	for _, v := range r.Verdicts {
		if !v.HasIssues() {
			continue
		}
		for _, iss := range v.Issues {
			fmt.Fprintf(&b, "- [%s] %s (scanner: %s, check: %s)\n  Fix: %s\n",
				iss.Kind, iss.Description[:min(len(iss.Description), 120)],
				v.Finding.Scanner, v.Finding.CheckID, iss.Suggestion)
		}
	}
	fmt.Fprintf(&b, "```\n")

	return b.String()
}
