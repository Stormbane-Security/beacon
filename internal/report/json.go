package report

import (
	"encoding/json"
	"sort"
	"time"

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
}

// RenderJSON returns the scan results as a JSON string (pretty-printed).
// Findings are sorted by severity (critical first) for consistent output.
func RenderJSON(run store.ScanRun, enriched []enrichment.EnrichedFinding, summary string) (string, error) {
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
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
