package analyze

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/store"
)

var timeNow = time.Now

// sensitiveHeaders lists HTTP header names whose values must never be sent to
// the Claude API — they may contain credentials, session tokens, or API keys.
var sensitiveHeaders = map[string]bool{
	"authorization":       true,
	"cookie":              true,
	"set-cookie":          true,
	"x-api-key":           true,
	"proxy-authorization": true,
	"x-auth-token":        true,
	"x-access-token":      true,
}

// safeSummaryHeaders returns a sanitized subset of headers safe to include in
// the analysis prompt. Auth/credential headers are stripped.
func safeSummaryHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	out := make(map[string]string, len(headers))
	for k, v := range headers {
		if sensitiveHeaders[strings.ToLower(k)] {
			continue
		}
		out[k] = v
	}
	return out
}

// domainSummary is the compact per-domain prompt section produced by
// buildDomainSummaries. RunID is the most-recent scan run ID for the domain;
// Text is the ready-to-embed prompt fragment.
type domainSummary struct {
	RunID string
	Text  string
}

// severityLabel returns the 4-char uppercase severity label used in compact output.
func severityLabel(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical:
		return "CRIT"
	case finding.SeverityHigh:
		return "HIGH"
	case finding.SeverityMedium:
		return "MED "
	case finding.SeverityLow:
		return "LOW "
	default:
		return "INFO"
	}
}

// truncateStr truncates s to at most maxChars runes, appending "…" if cut.
func truncateStr(s string, maxChars int) string {
	if utf8.RuneCountInString(s) <= maxChars {
		return s
	}
	runes := []rune(s)
	return string(runes[:maxChars]) + "…"
}

// isHTMLOrBase64 returns true when the value looks like raw HTML or a base64 blob:
// starts with "<" or is a long string of base64 characters with no whitespace.
func isHTMLOrBase64(s string) bool {
	if len(s) == 0 {
		return false
	}
	if s[0] == '<' {
		return true
	}
	// Base64: no spaces and only base64-alphabet characters in a long run.
	if len(s) > 60 {
		spaces := strings.Count(s, " ")
		if spaces == 0 {
			nonB64 := 0
			for _, c := range s {
				if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
					(c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
					nonB64++
				}
			}
			if float64(nonB64)/float64(len(s)) < 0.05 {
				return true
			}
		}
	}
	return false
}

// extractDetailedEvidence is like extractKeyEvidence but allows more pairs and
// longer values — used for critical/high findings where accuracy review needs
// enough context to distinguish true from false positives.
func extractDetailedEvidence(evidence map[string]any, maxPairs, maxValChars int) string {
	if len(evidence) == 0 {
		return ""
	}
	keys := make([]string, 0, len(evidence))
	for k := range evidence {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var pairs []string
	for _, k := range keys {
		if len(pairs) >= maxPairs {
			break
		}
		lk := strings.ToLower(k)
		if lk == "url" || lk == "endpoint" || lk == "path" || lk == "uri" {
			continue
		}
		v := evidence[k]
		if v == nil {
			continue
		}
		rv := reflect.ValueOf(v)
		if (rv.Kind() == reflect.Slice || rv.Kind() == reflect.Array) && rv.Len() > 10 {
			continue
		}
		var strVal string
		switch tv := v.(type) {
		case string:
			strVal = tv
		case []byte:
			strVal = string(tv)
		default:
			b, err := json.Marshal(v)
			if err != nil {
				continue
			}
			strVal = string(b)
		}
		if len(strVal) > 2000 {
			continue
		}
		if isHTMLOrBase64(strVal) {
			continue
		}
		pairs = append(pairs, fmt.Sprintf("%s=%s", k, truncateStr(strVal, maxValChars)))
	}
	return strings.Join(pairs, ", ")
}

// extractKeyEvidence picks at most 2 compact key=value pairs from a finding's
// evidence map, skipping URL/path/endpoint keys (already in the endpoint column),
// large values, arrays with >5 items, and HTML/base64 blobs.
// Returns a string like "status=403, header=x-frame-options".
func extractKeyEvidence(evidence map[string]any) string {
	if len(evidence) == 0 {
		return ""
	}

	// Stable sort for deterministic output.
	keys := make([]string, 0, len(evidence))
	for k := range evidence {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var pairs []string
	for _, k := range keys {
		if len(pairs) >= 2 {
			break
		}

		// Skip URL/path/endpoint keys — already shown in the endpoint column.
		lk := strings.ToLower(k)
		if lk == "url" || lk == "endpoint" || lk == "path" || lk == "uri" {
			continue
		}

		v := evidence[k]

		// Skip nil.
		if v == nil {
			continue
		}

		// Check for arrays >5 items using reflection.
		rv := reflect.ValueOf(v)
		if rv.Kind() == reflect.Slice || rv.Kind() == reflect.Array {
			if rv.Len() > 5 {
				continue
			}
		}

		// Convert to string for size/content checks.
		var strVal string
		switch tv := v.(type) {
		case string:
			strVal = tv
		case []byte:
			strVal = string(tv)
		default:
			b, err := json.Marshal(v)
			if err != nil {
				continue
			}
			strVal = string(b)
		}

		// Skip strings >200 chars.
		if len(strVal) > 200 {
			continue
		}

		// Skip HTML/base64 blobs.
		if isHTMLOrBase64(strVal) {
			continue
		}

		// Truncate long-ish values to 60 chars.
		displayVal := truncateStr(strVal, 60)

		pairs = append(pairs, fmt.Sprintf("%s=%s", k, displayVal))
	}

	return strings.Join(pairs, ", ")
}

// buildDomainSummaries queries the store for recent scan runs and returns a
// per-domain compact prompt section. Each entry contains the most-recent run ID
// and a ready-to-embed text fragment for that domain.
func (a *Analyzer) buildDomainSummaries(ctx context.Context) (map[string]domainSummary, error) {
	runs, err := a.st.ListRecentScanRuns(ctx, 50)
	if err != nil || len(runs) == 0 {
		return nil, nil
	}

	// Track the most recent run ID per domain (runs are ordered by completed_at DESC).
	domainRunID := make(map[string]string)
	for _, run := range runs {
		if _, seen := domainRunID[run.Domain]; !seen {
			domainRunID[run.Domain] = run.ID
		}
	}

	// Deduplicate: keep only the most recent run per domain.
	seenDomain := make(map[string]bool)
	dedupRuns := runs[:0]
	for _, run := range runs {
		if !seenDomain[run.Domain] {
			seenDomain[run.Domain] = true
			dedupRuns = append(dedupRuns, run)
		}
	}

	result := make(map[string]domainSummary, len(dedupRuns))

	for _, run := range dedupRuns {
		text, err := a.buildSingleDomainSummary(ctx, run)
		if err != nil {
			continue
		}
		result[run.Domain] = domainSummary{
			RunID: domainRunID[run.Domain],
			Text:  text,
		}
	}

	return result, nil
}

// buildSingleDomainSummary builds the compact text section for one scan run.
func (a *Analyzer) buildSingleDomainSummary(ctx context.Context, run store.ScanRun) (string, error) {
	var b strings.Builder

	// Header line.
	scannedAt := run.StartedAt.UTC().Format("2006-01-02")
	if run.CompletedAt != nil {
		scannedAt = run.CompletedAt.UTC().Format("2006-01-02")
	}
	b.WriteString(fmt.Sprintf(
		"### Domain: %s | run: %s | assets: %d | findings: %d | scanned: %s\n\n",
		run.Domain, run.ID, run.AssetCount, run.FindingCount, scannedAt,
	))

	// Scanner ROI section.
	roi, err := a.st.GetScannerROI(ctx, run.Domain)
	if err == nil && len(roi) > 0 {
		b.WriteString("Scanner ROI:\n")
		for _, r := range roi {
			b.WriteString(fmt.Sprintf(
				"  %-20s | %3d runs | %5dms avg | %3d findings (%d/%d) | %.0f%% err\n",
				r.ScannerName, r.RunCount, r.AvgDurationMs,
				r.TotalFindings, r.CriticalFindings, r.HighFindings,
				r.ErrorRate*100,
			))
		}
		b.WriteString("\n")
	}

	// Per-asset discovery sources.
	discSources, _ := a.st.GetDiscoverySourcesByRun(ctx, run.ID)

	// Raw findings.
	findings, err := a.st.GetFindings(ctx, run.ID)
	if err != nil || len(findings) == 0 {
		b.WriteString("Assets:\n  (no findings recorded)\n\n")
		return b.String(), nil
	}

	byAsset := make(map[string][]finding.Finding)
	for _, f := range findings {
		byAsset[f.Asset] = append(byAsset[f.Asset], f)
	}

	// Asset execution context.
	executions, _ := a.st.ListAssetExecutions(ctx, run.ID)
	type assetCtx struct {
		cloud     string
		framework string
		auth      string
		playbooks []string
		scanners  []string
	}
	ctxByAsset := make(map[string]assetCtx)
	for _, ex := range executions {
		ev := ex.Evidence
		ctxByAsset[ex.Asset] = assetCtx{
			cloud:     ev.CloudProvider,
			framework: ev.Framework,
			auth:      ev.AuthSystem,
			playbooks: ex.MatchedPlaybooks,
			scanners:  ex.ScannersRun,
		}
	}

	// Sort assets for deterministic output.
	assets := make([]string, 0, len(byAsset))
	for asset := range byAsset {
		assets = append(assets, asset)
	}
	sort.Strings(assets)

	b.WriteString("Assets:\n")

	const maxAssets = 20
	assetCount := 0
	for _, asset := range assets {
		if assetCount >= maxAssets {
			b.WriteString(fmt.Sprintf("  ... and %d more assets (omitted for length)\n", len(assets)-maxAssets))
			break
		}
		assetCount++

		src := discSources[asset]
		if src == "" {
			src = "unknown"
		}

		// Asset header line with tech context inline.
		ac := ctxByAsset[asset]
		var techParts []string
		if ac.cloud != "" {
			techParts = append(techParts, "cloud="+ac.cloud)
		}
		if ac.framework != "" {
			techParts = append(techParts, "fw="+ac.framework)
		}
		if ac.auth != "" {
			techParts = append(techParts, "auth="+ac.auth)
		}
		techStr := ""
		if len(techParts) > 0 {
			techStr = "[" + strings.Join(techParts, ", ") + "] "
		}
		b.WriteString(fmt.Sprintf("  %s %sdiscovered_via=%s\n", asset, techStr, src))

		if len(ac.playbooks) > 0 {
			b.WriteString(fmt.Sprintf("    matched: %s\n", strings.Join(ac.playbooks, ", ")))
		}
		if len(ac.scanners) > 0 {
			b.WriteString(fmt.Sprintf("    scanners: %s\n", strings.Join(ac.scanners, ", ")))
		}

		// Findings for this asset — sorted by severity desc, capped at 25.
		assetFindings := byAsset[asset]
		sort.Slice(assetFindings, func(i, j int) bool {
			return assetFindings[i].Severity > assetFindings[j].Severity
		})
		shown := assetFindings
		const maxFindings = 25
		if len(shown) > maxFindings {
			shown = shown[:maxFindings]
		}

		for _, f := range shown {
			sevLabel := severityLabel(f.Severity)

			// Resolve best endpoint string from evidence.
			endpoint := f.Asset
			for _, key := range []string{"endpoint", "url", "path", "uri"} {
				if v, ok := f.Evidence[key]; ok {
					if s, ok := v.(string); ok && s != "" {
						endpoint = s
						break
					}
				}
			}

			switch f.Severity {
			case finding.SeverityCritical, finding.SeverityHigh:
				// Three-line block: header | evidence | proof
				// Gives Claude enough context for accurate false-positive detection.
				b.WriteString(fmt.Sprintf("    %s %-28s | %s\n",
					sevLabel, string(f.CheckID), truncateStr(endpoint, 60)))

				// Evidence line: up to 4 key=value pairs, values up to 80 chars each.
				ev := extractDetailedEvidence(f.Evidence, 4, 80)
				if ev != "" {
					b.WriteString(fmt.Sprintf("         evidence: %s\n", ev))
				}

				// Proof line: up to 200 chars (enough to spot wrong URL or broken grep).
				if f.ProofCommand != "" {
					pc := strings.ReplaceAll(f.ProofCommand, "\n", " ; ")
					pc = strings.ReplaceAll(pc, "\r", "")
					b.WriteString(fmt.Sprintf("         proof:    %s\n", truncateStr(pc, 200)))
				}

			case finding.SeverityMedium:
				// One-liner with a single key evidence fact.
				keyEv := extractKeyEvidence(f.Evidence)
				line := fmt.Sprintf("    %s %-28s | %s", sevLabel, string(f.CheckID), truncateStr(endpoint, 50))
				if keyEv != "" {
					line += " | " + keyEv
				}
				b.WriteString(line + "\n")

			default:
				// Low/Info: check_id + title only — no evidence needed.
				b.WriteString(fmt.Sprintf("    %s %-28s  %s\n",
					sevLabel, string(f.CheckID), truncateStr(f.Title, 60)))
			}
		}

		if len(assetFindings) > maxFindings {
			b.WriteString(fmt.Sprintf("    ... and %d more findings\n", len(assetFindings)-maxFindings))
		}
	}

	b.WriteString("\n")
	return b.String(), nil
}

// buildDomainPicture is the legacy function kept for backward compatibility with
// buildPrompt. It calls buildDomainSummaries and concatenates the results into a
// single string, also returning the domain→runID map.
func (a *Analyzer) buildDomainPicture(ctx context.Context) (map[string]string, string, error) {
	summaries, err := a.buildDomainSummaries(ctx)
	if err != nil {
		return nil, "", err
	}
	if len(summaries) == 0 {
		return nil, "", nil
	}

	domainRunIDs := make(map[string]string, len(summaries))
	var b strings.Builder
	b.WriteString("## Domain-wide scan results\n\n")

	// Sort domains for deterministic output.
	domains := make([]string, 0, len(summaries))
	for d := range summaries {
		domains = append(domains, d)
	}
	sort.Strings(domains)

	for _, d := range domains {
		ds := summaries[d]
		domainRunIDs[d] = ds.RunID
		b.WriteString(ds.Text)
	}

	return domainRunIDs, b.String(), nil
}

// rawCorrelation is the intermediate struct for JSON parsing from Claude's response.
type rawCorrelation struct {
	Title              string   `json:"title"`
	Severity           string   `json:"severity"`
	AffectedAssets     []string `json:"affected_assets"`
	ContributingChecks []string `json:"contributing_checks"`
	Description        string   `json:"description"`
	Remediation        string   `json:"remediation"`
}

// parseCorrelations extracts CorrelationFinding entries from a slice of raw correlation data.
func parseCorrelations(scanRunID, domain string, raw []rawCorrelation) []store.CorrelationFinding {
	out := make([]store.CorrelationFinding, 0, len(raw))
	for _, r := range raw {
		if r.Title == "" || r.Description == "" {
			continue
		}
		out = append(out, store.CorrelationFinding{
			ScanRunID:          scanRunID,
			Domain:             domain,
			Title:              r.Title,
			Severity:           finding.ParseSeverity(r.Severity),
			Description:        r.Description,
			AffectedAssets:     r.AffectedAssets,
			ContributingChecks: r.ContributingChecks,
			Remediation:        r.Remediation,
			CreatedAt:          timeNow(),
		})
	}
	return out
}
