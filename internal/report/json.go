package report

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/stormbane-security/beacon/internal/asset"
	"github.com/stormbane-security/beacon/internal/enrichment"
	"github.com/stormbane-security/beacon/internal/store"
)

// jsonReport is the JSON serialization envelope.
type jsonReport struct {
	Domain           string                       `json:"domain"`
	ScanType         string                       `json:"scan_type"`
	StartedAt        time.Time                    `json:"started_at"`
	CompletedAt      *time.Time                   `json:"completed_at,omitempty"`
	ExecutiveSummary string                       `json:"executive_summary,omitempty"`
	FindingCount     int                          `json:"finding_count"`
	Findings         []enrichment.EnrichedFinding `json:"findings"`
	AssetGraph       *asset.AssetGraph            `json:"asset_graph,omitempty"`
}

// RenderJSON returns the scan results as a JSON string (pretty-printed).
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
	rep := jsonReport{
		Domain:           run.Domain,
		ScanType:         string(run.ScanType),
		StartedAt:        run.StartedAt,
		CompletedAt:      run.CompletedAt,
		ExecutiveSummary: summary,
		FindingCount:     len(filtered),
		Findings:         filtered,
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
