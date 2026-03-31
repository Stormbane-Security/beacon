package enrichment

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"text/template"
)

//go:embed prompts/fillgaps.tmpl
var defaultFillGapsTmpl string

// ProposedRule is a fingerprint rule suggested by the AI. The caller is
// responsible for converting it to a store.FingerprintRule and persisting
// it with Source="ai" and Status="pending".
type ProposedRule struct {
	SignalType  string  `json:"signal_type"`
	SignalKey   string  `json:"signal_key"`
	SignalValue string  `json:"signal_value"`
	Field       string  `json:"field"`
	Value       string  `json:"value"`
	Confidence  float64 `json:"confidence"`
	Reasoning   string  `json:"reasoning"`
}

// FillGapsResult contains proposed fingerprint rules and missed technology
// observations from the AI gap analysis.
type FillGapsResult struct {
	// ProposedRules are new fingerprint rules the AI suggests. They should
	// be saved with Source="ai" and Status="pending" — a human must approve
	// them before they take effect on future scans.
	ProposedRules []ProposedRule

	// MissedTechnologies are observations about technologies the heuristic
	// engine failed to detect, with evidence and security relevance.
	MissedTechnologies []MissedTechnology
}

// MissedTechnology describes a technology the AI identified that the
// heuristic fingerprinting pipeline missed.
type MissedTechnology struct {
	Asset             string `json:"asset"`
	Technology        string `json:"technology"`
	Evidence          string `json:"evidence"`
	SecurityRelevance string `json:"security_relevance"`
}

// fillGapsResponse is the parsed JSON structure returned by the AI.
type fillGapsResponse struct {
	ProposedRules      []fillGapsProposedRule `json:"proposed_rules"`
	MissedTechnologies []MissedTechnology     `json:"missed_technologies"`
}

type fillGapsProposedRule struct {
	SignalType  string  `json:"signal_type"`
	SignalKey   string  `json:"signal_key"`
	SignalValue string  `json:"signal_value"`
	Field       string  `json:"field"`
	Value       string  `json:"value"`
	Confidence  float64 `json:"confidence"`
	Reasoning   string  `json:"reasoning"`
}

// FillGaps sends fingerprint evidence to the AI and asks it to identify
// technologies that the heuristic pipeline missed. Returns proposed
// fingerprint rules and missed technology observations.
//
// Call this after EnrichFingerprints to discover detection blind spots.
// The caller should persist proposed rules with Source="ai", Status="pending"
// via store.UpsertFingerprintRule.
func (c *ClaudeEnricher) FillGaps(ctx context.Context, inputs []FingerprintInput) (*FillGapsResult, error) {
	if len(inputs) == 0 {
		return &FillGapsResult{}, nil
	}

	// Filter out inputs with no useful data.
	var filtered []FingerprintInput
	for _, inp := range inputs {
		if hasFingerprintData(inp) {
			filtered = append(filtered, inp)
		}
	}
	if len(filtered) == 0 {
		return &FillGapsResult{}, nil
	}

	tmpl, err := template.New("fillgaps").Funcs(safeFuncs).Parse(defaultFillGapsTmpl)
	if err != nil {
		return nil, fmt.Errorf("parsing fillgaps template: %w", err)
	}

	var promptBuf bytes.Buffer
	if err := tmpl.Execute(&promptBuf, filtered); err != nil {
		return nil, fmt.Errorf("rendering fillgaps prompt: %w", err)
	}

	responseText, err := c.callLLM(ctx, c.summaryModel, promptBuf.String())
	if err != nil {
		return nil, fmt.Errorf("fillgaps enrichment: %w", err)
	}

	return parseFillGapsResponse(responseText)
}

// parseFillGapsResponse extracts proposed rules and missed technologies
// from the AI's JSON response.
func parseFillGapsResponse(text string) (*FillGapsResult, error) {
	cleaned := extractJSONObject(text)

	var resp fillGapsResponse
	if err := json.Unmarshal([]byte(cleaned), &resp); err != nil {
		return &FillGapsResult{}, nil
	}

	result := &FillGapsResult{
		MissedTechnologies: resp.MissedTechnologies,
	}

	// Validate signal types and fields.
	validSignalTypes := map[string]bool{
		"header": true, "body": true, "server": true,
		"cookie": true, "path": true, "cname": true,
	}
	validFields := map[string]bool{
		"framework": true, "proxy_type": true, "auth_system": true,
		"cloud_provider": true, "infra_layer": true, "backend_services": true,
	}

	for _, proposed := range resp.ProposedRules {
		if !validSignalTypes[strings.ToLower(proposed.SignalType)] {
			continue
		}
		if !validFields[strings.ToLower(proposed.Field)] {
			continue
		}
		if proposed.SignalValue == "" || proposed.Value == "" {
			continue
		}
		if proposed.Confidence <= 0 || proposed.Confidence > 1.0 {
			proposed.Confidence = 0.7
		}

		result.ProposedRules = append(result.ProposedRules, ProposedRule{
			SignalType:  strings.ToLower(proposed.SignalType),
			SignalKey:   strings.ToLower(proposed.SignalKey),
			SignalValue: strings.ToLower(proposed.SignalValue),
			Field:       proposed.Field,
			Value:       strings.ToLower(proposed.Value),
			Confidence:  proposed.Confidence,
			Reasoning:   proposed.Reasoning,
		})
	}

	return result, nil
}
