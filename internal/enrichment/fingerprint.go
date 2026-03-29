package enrichment

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"text/template"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/playbook"
)

//go:embed prompts/fingerprint.tmpl
var defaultFingerprintTmpl string

// FingerprintInput is the per-asset data passed to the fingerprint enrichment
// template. It mirrors the fields the template expects and is built from
// playbook.Evidence.
type FingerprintInput struct {
	Asset          string            `json:"asset"`
	Headers        map[string]string `json:"headers,omitempty"`
	ServerVersions map[string]string `json:"server_versions,omitempty"`
	Framework      string            `json:"framework,omitempty"`
	ProxyType      string            `json:"proxy_type,omitempty"`
	CloudProvider  string            `json:"cloud_provider,omitempty"`
	AuthSystem     string            `json:"auth_system,omitempty"`
	InfraLayer     string            `json:"infra_layer,omitempty"`
	CertIssuer     string            `json:"cert_issuer,omitempty"`
	CertSANs       []string          `json:"cert_sans,omitempty"`
	BackendServices []string         `json:"backend_services,omitempty"`
	CookieNames    []string          `json:"cookie_names,omitempty"`
	JARMFingerprint string           `json:"jarm_fingerprint,omitempty"`
	OSVersion      string            `json:"os_version,omitempty"`
	RuntimeVersion string            `json:"runtime_version,omitempty"`
}

// FingerprintInputFromEvidence converts a playbook.Evidence into a
// FingerprintInput suitable for the fingerprint enrichment template.
func FingerprintInputFromEvidence(asset string, ev playbook.Evidence) FingerprintInput {
	return FingerprintInput{
		Asset:           asset,
		Headers:         ev.Headers,
		ServerVersions:  ev.ServiceVersions,
		Framework:       ev.Framework,
		ProxyType:       ev.ProxyType,
		CloudProvider:   ev.CloudProvider,
		AuthSystem:      ev.AuthSystem,
		InfraLayer:      ev.InfraLayer,
		CertIssuer:      ev.CertIssuer,
		CertSANs:        ev.CertSANs,
		BackendServices: ev.BackendServices,
		CookieNames:     ev.CookieNames,
		JARMFingerprint: ev.JARMFingerprint,
		OSVersion:       ev.OSVersion,
		RuntimeVersion:  ev.RuntimeVersion,
	}
}

// fingerprintResponse is the parsed JSON structure returned by the AI for
// fingerprint enrichment.
type fingerprintResponse struct {
	Assets []fingerprintAssetResult `json:"assets"`
	CrossAssetPatterns []string     `json:"cross_asset_patterns"`
}

type fingerprintAssetResult struct {
	Asset            string                    `json:"asset"`
	StackAnalysis    string                    `json:"stack_analysis"`
	VersionIssues    []fingerprintVersionIssue `json:"version_issues"`
	ConfigAnomalies  []fingerprintConfigAnomaly `json:"config_anomalies"`
	AttackSurface    string                    `json:"attack_surface"`
	SuggestedScanners []string                 `json:"suggested_scanners"`
}

type fingerprintVersionIssue struct {
	Component   string `json:"component"`
	Version     string `json:"version"`
	CVEID       string `json:"cve_id"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

type fingerprintConfigAnomaly struct {
	Signal   string `json:"signal"`
	Risk     string `json:"risk"`
	Severity string `json:"severity"`
}

// newFingerprintTemplate parses the embedded fingerprint prompt template with
// safe template functions for prompt-injection prevention.
func newFingerprintTemplate() (*template.Template, error) {
	return template.New("fingerprint").Funcs(safeFuncs).Parse(defaultFingerprintTmpl)
}

// FingerprintResult holds the findings produced by AI fingerprint enrichment.
type FingerprintResult struct {
	// Findings are the version vulnerability and config anomaly findings.
	Findings []finding.Finding

	// SuggestedScanners maps asset → list of scanner names the AI thinks
	// should be run based on the technology stack.
	SuggestedScanners map[string][]string

	// CrossAssetPatterns are observations spanning multiple assets.
	CrossAssetPatterns []string
}

// EnrichFingerprints sends collected fingerprint evidence to the AI and returns
// findings for version-specific vulnerabilities (aifp.vulnerable_version) and
// configuration anomalies (aifp.config_anomaly).
//
// This function is designed to be called after scanning completes, before the
// standard finding enrichment pass. The returned findings are merged into the
// main finding list for enrichment and reporting.
func (c *ClaudeEnricher) EnrichFingerprints(ctx context.Context, inputs []FingerprintInput) (*FingerprintResult, error) {
	if len(inputs) == 0 {
		return &FingerprintResult{}, nil
	}

	// Filter out inputs that have no useful fingerprint data.
	var filtered []FingerprintInput
	for _, inp := range inputs {
		if hasFingerprintData(inp) {
			filtered = append(filtered, inp)
		}
	}
	if len(filtered) == 0 {
		return &FingerprintResult{}, nil
	}

	tmpl, err := newFingerprintTemplate()
	if err != nil {
		return nil, err
	}

	// Render the prompt.
	var promptBuf bytes.Buffer
	if err := tmpl.Execute(&promptBuf, filtered); err != nil {
		return nil, fmt.Errorf("rendering fingerprint prompt: %w", err)
	}

	// Call the AI.
	responseText, err := c.callLLM(ctx, c.summaryModel, promptBuf.String())
	if err != nil {
		return nil, fmt.Errorf("fingerprint enrichment: %w", err)
	}

	// Parse the response.
	return parseFingerprintResponse(responseText)
}

// parseFingerprintResponse extracts findings from the AI's JSON response.
func parseFingerprintResponse(text string) (*FingerprintResult, error) {
	// Strip markdown code fences.
	cleaned := extractJSONObject(text)

	var resp fingerprintResponse
	if err := json.Unmarshal([]byte(cleaned), &resp); err != nil {
		// Graceful degradation — return empty result rather than failing.
		return &FingerprintResult{}, nil
	}

	result := &FingerprintResult{
		SuggestedScanners:  make(map[string][]string),
		CrossAssetPatterns: resp.CrossAssetPatterns,
	}

	now := time.Now()

	for _, assetResult := range resp.Assets {
		asset := assetResult.Asset
		if asset == "" {
			continue
		}

		// Version vulnerability findings.
		for _, vi := range assetResult.VersionIssues {
			if vi.Component == "" || vi.Description == "" {
				continue
			}

			sev := parseFingerprintSeverity(vi.Severity)
			title := fmt.Sprintf("Known vulnerability in %s %s", vi.Component, vi.Version)
			if vi.CVEID != "" {
				title = fmt.Sprintf("%s (%s)", title, vi.CVEID)
			}

			evidence := map[string]any{
				"component":       vi.Component,
				"version":         vi.Version,
				"analysis_source": "ai_fingerprint",
			}
			if vi.CVEID != "" {
				evidence["cve_id"] = vi.CVEID
			}
			if assetResult.StackAnalysis != "" {
				evidence["stack_analysis"] = assetResult.StackAnalysis
			}

			result.Findings = append(result.Findings, finding.Finding{
				CheckID:      finding.CheckAIFPVulnVersion,
				Module:       "aifp",
				Scanner:      "fingerprint",
				Severity:     sev,
				Title:        title,
				Description:  vi.Description,
				Asset:        asset,
				Evidence:     evidence,
				ProofCommand: fmt.Sprintf("beacon scan --domain %s --verbose", asset),
				DiscoveredAt: now,
			})
		}

		// Configuration anomaly findings.
		for _, ca := range assetResult.ConfigAnomalies {
			if ca.Signal == "" || ca.Risk == "" {
				continue
			}

			sev := parseFingerprintSeverity(ca.Severity)

			evidence := map[string]any{
				"signal":          ca.Signal,
				"analysis_source": "ai_fingerprint",
			}
			if assetResult.StackAnalysis != "" {
				evidence["stack_analysis"] = assetResult.StackAnalysis
			}

			result.Findings = append(result.Findings, finding.Finding{
				CheckID:      finding.CheckAIFPConfigAnomaly,
				Module:       "aifp",
				Scanner:      "fingerprint",
				Severity:     sev,
				Title:        fmt.Sprintf("Configuration anomaly: %s", truncate(ca.Signal, 80)),
				Description:  ca.Risk,
				Asset:        asset,
				Evidence:     evidence,
				ProofCommand: fmt.Sprintf("beacon scan --domain %s --verbose", asset),
				DiscoveredAt: now,
			})
		}

		// Suggested scanners.
		if len(assetResult.SuggestedScanners) > 0 {
			result.SuggestedScanners[asset] = assetResult.SuggestedScanners
		}
	}

	return result, nil
}

// extractJSONObject pulls out the outermost JSON object from text that may
// have markdown fences or leading prose.
func extractJSONObject(text string) string {
	// Strip markdown code fences.
	if i := strings.Index(text, "```json"); i >= 0 {
		text = text[i+7:]
		if j := strings.Index(text, "```"); j >= 0 {
			text = text[:j]
		}
	} else if i := strings.Index(text, "```"); i >= 0 {
		text = text[i+3:]
		if j := strings.Index(text, "```"); j >= 0 {
			text = text[:j]
		}
	}
	text = strings.TrimSpace(text)
	// Find outermost '{' ... '}' in case there is leading prose.
	start := strings.Index(text, "{")
	end := strings.LastIndex(text, "}")
	if start >= 0 && end > start {
		text = text[start : end+1]
	}
	return text
}

// hasFingerprintData returns true when the input has enough data to warrant
// sending to the AI for analysis.
func hasFingerprintData(inp FingerprintInput) bool {
	return len(inp.Headers) > 0 ||
		len(inp.ServerVersions) > 0 ||
		inp.Framework != "" ||
		inp.ProxyType != "" ||
		inp.CloudProvider != "" ||
		inp.AuthSystem != "" ||
		len(inp.BackendServices) > 0 ||
		inp.CertIssuer != "" ||
		inp.OSVersion != "" ||
		inp.RuntimeVersion != ""
}

// parseFingerprintSeverity converts a severity string from the AI response to
// a finding.Severity value.
func parseFingerprintSeverity(s string) finding.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return finding.SeverityCritical
	case "high":
		return finding.SeverityHigh
	case "medium":
		return finding.SeverityMedium
	case "low":
		return finding.SeverityLow
	default:
		return finding.SeverityInfo
	}
}

// truncate shortens s to n runes, appending an ellipsis if truncated.
// Uses rune count instead of byte count to avoid slicing in the middle
// of a multi-byte UTF-8 character.
func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "..."
}
