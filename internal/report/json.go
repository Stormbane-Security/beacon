package report

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/stormbane-security/beacon/internal/asset"
	"github.com/stormbane-security/beacon/internal/enrichment"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/store"
)

// ---- Structured JSON report schema ----

// JSONReport is the top-level JSON report envelope with consistent schema.
type JSONReport struct {
	Metadata         JSONMetadata                 `json:"metadata"`
	Summary          JSONSummary                  `json:"summary"`
	Findings         []enrichment.EnrichedFinding `json:"findings"`
	Chains           []enrichment.EnrichedFinding `json:"chains,omitempty"`
	Recommendations  []string                     `json:"recommendations"`
	ExecutiveSummary *ExecutiveSummary             `json:"executive_summary,omitempty"`
	AssetGraph       *asset.AssetGraph            `json:"asset_graph,omitempty"`
}

// JSONMetadata holds scan metadata.
type JSONMetadata struct {
	Version     string     `json:"version"`
	ScanDate    time.Time  `json:"scan_date"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Target      string     `json:"target"`
	Duration    string     `json:"duration,omitempty"`
	ScanType    string     `json:"scan_type"`
	Modules     []string   `json:"modules,omitempty"`
	ScanID      string     `json:"scan_id,omitempty"`
}

// JSONSummary holds aggregate counts.
type JSONSummary struct {
	TotalFindings int            `json:"total_findings"`
	BySeverity    map[string]int `json:"by_severity"`
	ByCategory    map[string]int `json:"by_category"`
	AttackChains  int            `json:"attack_chains"`
	UniqueAssets  int            `json:"unique_assets"`
}

// beaconVersion is embedded at build time; fallback to "dev".
var beaconVersion = "dev"

// SetVersion allows the CLI to inject the build version for JSON reports.
func SetVersion(v string) {
	if v != "" {
		beaconVersion = v
	}
}

// RenderJSON returns the scan results as a structured JSON string.
// Findings are sorted by severity (critical first) for consistent output.
// If graphJSON is non-nil it is decoded and included as the "asset_graph" field.
func RenderJSON(run store.ScanRun, enriched []enrichment.EnrichedFinding, summary string, graphJSON []byte) (string, error) {
	// Filter omitted findings, then sort by severity descending.
	filtered := make([]enrichment.EnrichedFinding, 0, len(enriched))
	for _, ef := range enriched {
		if !ef.Omit {
			filtered = append(filtered, ef)
		}
	}
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].Finding.Severity != filtered[j].Finding.Severity {
			return filtered[i].Finding.Severity > filtered[j].Finding.Severity
		}
		return filtered[i].Finding.Asset < filtered[j].Finding.Asset
	})

	// Compute duration.
	var duration string
	if run.CompletedAt != nil {
		d := run.CompletedAt.Sub(run.StartedAt)
		duration = d.Truncate(time.Second).String()
	}

	// Severity counts.
	bySev := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"info":     0,
	}
	byCat := make(map[string]int)
	assetSet := make(map[string]bool)
	chainCount := 0
	var chains []enrichment.EnrichedFinding

	for _, ef := range filtered {
		switch ef.Finding.Severity {
		case finding.SeverityCritical:
			bySev["critical"]++
		case finding.SeverityHigh:
			bySev["high"]++
		case finding.SeverityMedium:
			bySev["medium"]++
		case finding.SeverityLow:
			bySev["low"]++
		default:
			bySev["info"]++
		}
		cat := categoryFromCheckID(ef.Finding.CheckID)
		byCat[cat]++
		assetSet[ef.Finding.Asset] = true

		id := string(ef.Finding.CheckID)
		if isChainFinding(ef.Finding) {
			chainCount++
			chains = append(chains, ef)
		}
		_ = id
	}

	// Executive summary.
	execSummary := GenerateExecutiveSummary(filtered)

	// Recommendations.
	recs := generateRecommendations(filtered)

	rep := JSONReport{
		Metadata: JSONMetadata{
			Version:     beaconVersion,
			ScanDate:    run.StartedAt,
			CompletedAt: run.CompletedAt,
			Target:      run.Domain,
			Duration:    duration,
			ScanType:    string(run.ScanType),
			Modules:     run.Modules,
			ScanID:      run.ID,
		},
		Summary: JSONSummary{
			TotalFindings: len(filtered),
			BySeverity:    bySev,
			ByCategory:    byCat,
			AttackChains:  chainCount,
			UniqueAssets:  len(assetSet),
		},
		Findings:         filtered,
		Chains:           chains,
		Recommendations:  recs,
		ExecutiveSummary: &execSummary,
	}

	if len(graphJSON) > 0 {
		var g asset.AssetGraph
		if err := json.Unmarshal(graphJSON, &g); err == nil && len(g.Assets) > 0 {
			rep.AssetGraph = &g
		}
	}

	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
