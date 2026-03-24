package report

import (
	"encoding/json"
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
func RenderJSON(run store.ScanRun, enriched []enrichment.EnrichedFinding, summary string) (string, error) {
	rep := jsonReport{
		Domain:           run.Domain,
		ScanType:         string(run.ScanType),
		StartedAt:        run.StartedAt,
		CompletedAt:      run.CompletedAt,
		ExecutiveSummary: summary,
		FindingCount:     len(enriched),
		Findings:         enriched,
	}
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
