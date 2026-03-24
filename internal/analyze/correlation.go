package analyze

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

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

// buildDomainPicture queries the store for ALL recent scan runs and builds a
// comprehensive prompt section covering per-domain, per-asset findings with
// full evidence, proof commands, scanner coverage, and discovery topology.
// Returns a map of domain -> most recent scan run ID and the prompt text.
func (a *Analyzer) buildDomainPicture(ctx context.Context) (map[string]string, string, error) {
	runs, err := a.st.ListRecentScanRuns(ctx, 50)
	if err != nil || len(runs) == 0 {
		return nil, "", nil
	}

	// Track the most recent run ID per domain (runs are ordered by completed_at DESC).
	domainRunID := make(map[string]string)
	for _, run := range runs {
		if _, seen := domainRunID[run.Domain]; !seen {
			domainRunID[run.Domain] = run.ID
		}
	}

	var b strings.Builder
	b.WriteString("## Domain-wide scan results\n\n")

	for _, run := range runs {
		dur := ""
		if run.CompletedAt != nil {
			dur = fmt.Sprintf(" duration=%s", run.CompletedAt.Sub(run.StartedAt).Round(time.Second))
		}
		b.WriteString(fmt.Sprintf("### Domain: %s  scan_run=%s  assets=%d  findings=%d%s\n\n",
			run.Domain, run.ID, run.AssetCount, run.FindingCount, dur))

		// Per-asset discovery sources (where each asset was found).
		discSources, _ := a.st.GetDiscoverySourcesByRun(ctx, run.ID)

		// Raw findings.
		findings, err := a.st.GetFindings(ctx, run.ID)
		if err != nil || len(findings) == 0 {
			b.WriteString("  (no findings recorded)\n\n")
			continue
		}

		byAsset := make(map[string][]finding.Finding)
		for _, f := range findings {
			byAsset[f.Asset] = append(byAsset[f.Asset], f)
		}

		// Asset execution context: tech stack, matched playbooks, scanner coverage, dirbust.
		executions, _ := a.st.ListAssetExecutions(ctx, run.ID)
		type assetContext struct {
			stack       string
			playbooks   []string
			scannersRun []string
			found       []string
			classifyMs  int64
		}
		ctxByAsset := make(map[string]assetContext)
		for _, ex := range executions {
			ev := ex.Evidence
			ctxByAsset[ex.Asset] = assetContext{
				stack: fmt.Sprintf(
					"title=%q asn=%q cname=%v status=%d versions=%v framework=%q auth=%q cloud=%q",
					ev.Title, ev.ASNOrg, ev.CNAMEChain, ev.StatusCode,
					ev.ServiceVersions, ev.Framework, ev.AuthSystem,
					ev.CloudProvider,
				),
				playbooks:   ex.MatchedPlaybooks,
				scannersRun: ex.ScannersRun,
				found:       ex.DirbustPathsFound,
				classifyMs:  ex.ClassifyDurationMs,
			}
		}

		// Sort assets for deterministic output.
		assets := make([]string, 0, len(byAsset))
		for asset := range byAsset {
			assets = append(assets, asset)
		}
		sort.Strings(assets)

		assetCount := 0
		for _, asset := range assets {
			if assetCount >= 30 {
				b.WriteString(fmt.Sprintf("  ... and %d more assets (omitted for length)\n", len(assets)-30))
				break
			}
			assetCount++

			src := discSources[asset]
			if src == "" {
				src = "unknown"
			}
			b.WriteString(fmt.Sprintf("  asset: %s  discovered_via: %s\n", asset, src))
			if ac, ok := ctxByAsset[asset]; ok {
				b.WriteString(fmt.Sprintf("    stack: %s\n", ac.stack))
				if len(ac.playbooks) > 0 {
					b.WriteString(fmt.Sprintf("    matched_playbooks: %v\n", ac.playbooks))
				}
				if len(ac.scannersRun) > 0 {
					b.WriteString(fmt.Sprintf("    scanners_run: %v\n", ac.scannersRun))
				}
				if len(ac.found) > 0 {
					b.WriteString(fmt.Sprintf("    dirbust_found: %v\n", ac.found))
				}
				if ac.classifyMs > 0 {
					b.WriteString(fmt.Sprintf("    classify_ms: %d\n", ac.classifyMs))
				}
			}
			b.WriteString("    findings:\n")

			assetFindings := byAsset[asset]
			sort.Slice(assetFindings, func(i, j int) bool {
				return assetFindings[i].Severity > assetFindings[j].Severity
			})
			shown := assetFindings
			if len(shown) > 30 {
				shown = shown[:30]
			}
			for _, f := range shown {
				b.WriteString(fmt.Sprintf("      - [%s] %s %q\n",
					f.Severity, f.CheckID, f.Title))

				// Full evidence for all findings (not just critical/high).
				// Truncated at 1500 chars to balance completeness vs. prompt size.
				if len(f.Evidence) > 0 {
					if ev, err := json.Marshal(f.Evidence); err == nil {
						evStr := string(ev)
						if len(evStr) > 1500 {
							evStr = evStr[:1500] + "…"
						}
						b.WriteString(fmt.Sprintf("        evidence: %s\n", evStr))
					}
				}

				// Proof command — critical for accuracy review and validation.
				if f.ProofCommand != "" {
					// Truncate very long proof commands (e.g. SAML base64 blobs).
					pc := f.ProofCommand
					if len(pc) > 300 {
						pc = pc[:300] + "…"
					}
					b.WriteString(fmt.Sprintf("        proof_cmd: %s\n", pc))
				}
			}
			if len(assetFindings) > 30 {
				b.WriteString(fmt.Sprintf("      ... and %d more findings\n", len(assetFindings)-30))
			}
		}
		b.WriteString("\n")
	}

	return domainRunID, b.String(), nil
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
