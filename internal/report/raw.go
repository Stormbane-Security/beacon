package report

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
)

// RawScanOutput is the serialization envelope for unenriched scan findings.
// Written by `beacon scan --output-raw` and consumed by `beacon enrich --input`.
type RawScanOutput struct {
	Domain       string            `json:"domain"`
	ScanType     string            `json:"scan_type"`
	ScanID       string            `json:"scan_id"`
	StartedAt    time.Time         `json:"started_at"`
	FindingCount int               `json:"finding_count"`
	Findings     []finding.Finding `json:"findings"`
}

// RenderRawJSON serializes raw findings as pretty-printed JSON.
func RenderRawJSON(domain, scanType, scanID string, startedAt time.Time, findings []finding.Finding) (string, error) {
	out := RawScanOutput{
		Domain:       domain,
		ScanType:     scanType,
		ScanID:       scanID,
		StartedAt:    startedAt,
		FindingCount: len(findings),
		Findings:     findings,
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ParseRawJSON deserializes a RawScanOutput from JSON bytes.
func ParseRawJSON(data []byte) (*RawScanOutput, error) {
	var out RawScanOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("parse raw findings: %w", err)
	}
	if len(out.Findings) == 0 && out.FindingCount == 0 {
		return &out, nil
	}
	if out.Domain == "" {
		return nil, fmt.Errorf("parse raw findings: missing domain field")
	}
	return &out, nil
}
