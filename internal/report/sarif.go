package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/stormbane-security/beacon/internal/enrichment"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/store"
)

// SARIF output format for GitHub Code Scanning and other SARIF consumers.
// Implements SARIF v2.1.0 schema: https://docs.oasis-open.org/sarif/sarif/v2.1.0/

const sarifSchema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
const sarifVersion = "2.1.0"

// sarifLog is the top-level SARIF object.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

// sarifRun represents a single analysis run.
type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

// sarifTool describes the analysis tool.
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

// sarifDriver is the tool's primary component.
type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

// sarifRule defines a finding rule.
type sarifRule struct {
	ID               string              `json:"id"`
	Name             string              `json:"name,omitempty"`
	ShortDescription sarifMessage        `json:"shortDescription"`
	FullDescription  *sarifMessage       `json:"fullDescription,omitempty"`
	DefaultConfig    *sarifDefaultConfig `json:"defaultConfiguration,omitempty"`
	HelpURI          string              `json:"helpUri,omitempty"`
	Properties       map[string]any      `json:"properties,omitempty"`
}

// sarifDefaultConfig holds the default severity/level for a rule.
type sarifDefaultConfig struct {
	Level string `json:"level"`
}

// sarifMessage is a SARIF message object.
type sarifMessage struct {
	Text string `json:"text"`
}

// sarifResult is a single finding result.
type sarifResult struct {
	RuleID    string           `json:"ruleId"`
	RuleIndex int              `json:"ruleIndex"`
	Level     string           `json:"level"`
	Message   sarifMessage     `json:"message"`
	Locations []sarifLocation  `json:"locations,omitempty"`
	Properties map[string]any  `json:"properties,omitempty"`
}

// sarifLocation describes where a finding was observed.
type sarifLocation struct {
	PhysicalLocation *sarifPhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations,omitempty"`
}

// sarifPhysicalLocation points to a file/URI.
type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

// sarifArtifactLocation is a URI reference.
type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

// sarifLogicalLocation describes a logical location (host, service).
type sarifLogicalLocation struct {
	Name               string `json:"name"`
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
	Kind               string `json:"kind,omitempty"`
}

// RenderSARIF produces a SARIF v2.1.0 JSON document from enriched findings.
// The output is suitable for upload to GitHub Code Scanning via the
// `github/codeql-action/upload-sarif` action.
func RenderSARIF(run store.ScanRun, enriched []enrichment.EnrichedFinding) (string, error) {
	// Filter omitted findings and sort by severity.
	var filtered []enrichment.EnrichedFinding
	for _, ef := range enriched {
		if !ef.Omit {
			filtered = append(filtered, ef)
		}
	}
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].Finding.Severity != filtered[j].Finding.Severity {
			return filtered[i].Finding.Severity > filtered[j].Finding.Severity
		}
		return filtered[i].Finding.CheckID < filtered[j].Finding.CheckID
	})

	// Build unique rules from check IDs.
	ruleIndex := make(map[string]int)
	var rules []sarifRule

	for _, ef := range filtered {
		id := ef.Finding.CheckID
		if _, exists := ruleIndex[id]; exists {
			continue
		}
		ruleIndex[id] = len(rules)

		desc := ef.Finding.Description
		if ef.Explanation != "" {
			desc = ef.Explanation
		}
		if desc == "" {
			desc = ef.Finding.Title
		}

		rule := sarifRule{
			ID:               id,
			Name:             ruleNameFromCheckID(id),
			ShortDescription: sarifMessage{Text: ef.Finding.Title},
			DefaultConfig:    &sarifDefaultConfig{Level: sarifLevel(ef.Finding.Severity)},
			Properties:       map[string]any{"security-severity": sarifSecuritySeverity(ef.Finding.Severity)},
		}
		if desc != ef.Finding.Title {
			rule.FullDescription = &sarifMessage{Text: desc}
		}
		rules = append(rules, rule)
	}

	// Build results.
	var results []sarifResult
	for _, ef := range filtered {
		idx := ruleIndex[ef.Finding.CheckID]

		msg := ef.Finding.Title
		if ef.Explanation != "" {
			msg = ef.Explanation
		}

		result := sarifResult{
			RuleID:    ef.Finding.CheckID,
			RuleIndex: idx,
			Level:     sarifLevel(ef.Finding.Severity),
			Message:   sarifMessage{Text: msg},
			Locations: []sarifLocation{
				{
					LogicalLocations: []sarifLogicalLocation{
						{
							Name:               ef.Finding.Asset,
							FullyQualifiedName: ef.Finding.Asset,
							Kind:               "host",
						},
					},
				},
			},
		}

		// Add properties with evidence and proof command.
		props := map[string]any{
			"severity": SeverityLabel(ef.Finding.Severity),
			"asset":    ef.Finding.Asset,
			"scanner":  ef.Finding.Scanner,
		}
		if ef.Finding.ProofCommand != "" {
			props["proof_command"] = ef.Finding.ProofCommand
		}
		if ef.Finding.Confidence != "" {
			props["confidence"] = ef.Finding.Confidence
		}
		if ef.Impact != "" {
			props["impact"] = ef.Impact
		}
		if ef.Remediation != "" {
			props["remediation"] = ef.Remediation
		}
		if len(ef.ComplianceTags) > 0 {
			props["compliance_tags"] = ef.ComplianceTags
		}
		// Include up to 10 evidence key-value pairs.
		if len(ef.Finding.Evidence) > 0 {
			ev := make(map[string]any)
			count := 0
			for k, v := range ef.Finding.Evidence {
				if k == "image_b64" {
					continue
				}
				s := fmt.Sprintf("%v", v)
				if len(s) > 500 {
					s = s[:497] + "..."
				}
				ev[k] = s
				count++
				if count >= 10 {
					break
				}
			}
			if len(ev) > 0 {
				props["evidence"] = ev
			}
		}
		result.Properties = props
		results = append(results, result)
	}

	log := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "Beacon",
						Version:        beaconVersion,
						InformationURI: "https://github.com/stormbane-security/beacon",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	b, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// sarifLevel maps beacon severity to SARIF level.
func sarifLevel(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical, finding.SeverityHigh:
		return "error"
	case finding.SeverityMedium:
		return "warning"
	case finding.SeverityLow:
		return "note"
	default:
		return "none"
	}
}

// sarifSecuritySeverity maps to the numeric security-severity property
// used by GitHub code scanning for sorting.
func sarifSecuritySeverity(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical:
		return "9.5"
	case finding.SeverityHigh:
		return "8.0"
	case finding.SeverityMedium:
		return "5.5"
	case finding.SeverityLow:
		return "3.0"
	default:
		return "1.0"
	}
}

// ruleNameFromCheckID converts "tls.cert_expiry_7d" to "TlsCertExpiry7d".
func ruleNameFromCheckID(id string) string {
	parts := strings.FieldsFunc(id, func(r rune) bool {
		return r == '.' || r == '_'
	})
	var b strings.Builder
	for _, p := range parts {
		if len(p) > 0 {
			b.WriteString(strings.ToUpper(p[:1]))
			if len(p) > 1 {
				b.WriteString(p[1:])
			}
		}
	}
	return b.String()
}
