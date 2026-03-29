package report

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/stormbane/beacon/internal/asset"
	"github.com/stormbane/beacon/internal/enrichment"
	"github.com/stormbane/beacon/internal/store"
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
	// Sort by severity descending, then by asset name for deterministic output.
	sorted := make([]enrichment.EnrichedFinding, len(enriched))
	copy(sorted, enriched)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Finding.Severity != sorted[j].Finding.Severity {
			return sorted[i].Finding.Severity > sorted[j].Finding.Severity
		}
		return sorted[i].Finding.Asset < sorted[j].Finding.Asset
	})
	rep := jsonReport{
		Domain:           run.Domain,
		ScanType:         string(run.ScanType),
		StartedAt:        run.StartedAt,
		CompletedAt:      run.CompletedAt,
		ExecutiveSummary: summary,
		FindingCount:     len(sorted),
		Findings:         sorted,
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
