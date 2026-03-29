package enrichment

import (
	"context"

	"github.com/stormbane/beacon/internal/finding"
)

// FollowUpProbe is a targeted follow-up check suggested by attack-path analysis.
// The caller presents these to the user and runs approved ones.
type FollowUpProbe struct {
	Asset   string `json:"asset"`   // IP or hostname to probe
	Reason  string `json:"reason"`  // why this probe is suggested (shown to user)
	CheckID string `json:"check_id,omitempty"` // suggested check ID if known
	Scanner string `json:"scanner"` // "portscan", "cve", "http", "k8s_api", etc.
}

// EnrichedFinding wraps a raw finding with AI-generated explanations.
type EnrichedFinding struct {
	Finding     finding.Finding `json:"finding"`
	Explanation string          `json:"explanation"` // plain-language description
	Impact      string          `json:"impact"`      // real-world risk
	Remediation string          `json:"remediation"` // step-by-step fix

	// Set by ContextualizeAndSummarize — domain-wide analysis pass.
	MitigatedBy             string   `json:"mitigated_by,omitempty"`              // what control reduces this risk
	CrossAssetNote          string   `json:"cross_asset_note,omitempty"`          // compound risk spanning multiple assets
	Omit                    bool     `json:"omit,omitempty"`                      // drop from report — no actionable value
	TechSpecificRemediation string   `json:"tech_specific_remediation,omitempty"` // stack-aware fix (e.g. exact Django setting)
	ComplianceTags          []string `json:"compliance_tags,omitempty"`           // e.g. ["SOC2-CC6.1", "PCI-3.4"]

	// TerraformFix is an HCL code block that remediates the finding in Terraform/OpenTofu.
	// Populated by Enrich when the finding maps to a known IaC resource.
	// Empty string when no Terraform fix applies.
	TerraformFix string `json:"terraform_fix,omitempty"`

	// Set by regression comparison after enrichment — not from Claude.
	DeltaStatus string `json:"delta_status,omitempty"` // "new" | "recurring" | "resolved"
}

// Enricher produces AI-generated explanations for raw findings.
type Enricher interface {
	// Enrich takes a batch of findings and returns enriched versions with per-check
	// explanations, impact, and remediation. Results are cached by CheckID.
	Enrich(ctx context.Context, findings []finding.Finding) ([]EnrichedFinding, error)

	// ContextualizeAndSummarize performs a single domain-wide analysis pass:
	//   - Identifies findings mitigated by other controls on the same or other assets
	//   - Identifies cross-asset compound risks
	//   - Sets MitigatedBy, CrossAssetNote, and Omit on affected findings
	//   - Produces an executive summary for a non-technical founder
	//
	// Returns updated findings (with Omit/MitigatedBy/CrossAssetNote populated)
	// and the executive summary string.
	ContextualizeAndSummarize(ctx context.Context, enriched []EnrichedFinding, domain string) ([]EnrichedFinding, string, error)

	// AnalyzeAttackPaths performs a cross-module attack chain analysis.
	// It takes all enriched findings from a multi-module scan (surface + cloud +
	// github) and identifies realistic attack chains that span across modules and
	// assets. Returns a narrative attack path analysis string suitable for
	// inclusion in reports and for operator briefing.
	AnalyzeAttackPaths(ctx context.Context, enriched []EnrichedFinding, domain string) (string, error)

	// GenerateFollowUpProbes suggests targeted follow-up checks based on what
	// was discovered. Only probes within the original scan mode are suggested.
	// The caller presents them to the user for approval before running.
	GenerateFollowUpProbes(ctx context.Context, enriched []EnrichedFinding, domain string) ([]FollowUpProbe, error)

	// EnrichFingerprints analyzes collected fingerprint evidence (server headers,
	// technology signatures, version strings) using AI to identify:
	//   - Version-specific known vulnerabilities (→ aifp.vulnerable_version findings)
	//   - Configuration anomalies (→ aifp.config_anomaly findings)
	//   - Technology stack relationships and suggested follow-up scanners
	//
	// Called after scanning completes; returned findings are merged into the
	// main finding list before the standard enrichment pass.
	EnrichFingerprints(ctx context.Context, inputs []FingerprintInput) (*FingerprintResult, error)
}
