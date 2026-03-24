package analyze

import (
	"fmt"
	"strings"

	"github.com/stormbane/beacon/internal/finding"
)

// AttackChain represents a set of findings that combine into a higher-impact attack path.
type AttackChain struct {
	// Findings is the subset of findings involved in this chain.
	Findings []finding.Finding
	// Impact describes the combined outcome: "Account takeover", "RCE + data exfil", etc.
	Impact string
	// Narrative is a plain-English attack path description.
	Narrative string
	// Severity is the chain's combined severity (usually the highest component or elevated).
	Severity finding.Severity
}

// chainPattern is an internal rule: if ALL of these CheckIDs are present in a finding set,
// it constitutes an attack chain.
type chainPattern struct {
	ids       []string // all must be present
	impact    string
	narrative string
	severity  finding.Severity
}

var knownChainPatterns = []chainPattern{
	{
		ids:    []string{"jwt.algorithm_confusion", "oauth.token_long_expiry"},
		impact: "Persistent authentication bypass",
		narrative: "An attacker can forge JWT tokens using the RS256-to-HS256 confusion attack, " +
			"and the long token expiry means forged tokens remain valid for extended periods.",
		severity: finding.SeverityCritical,
	},
	{
		ids:    []string{"iam.scim_unauthenticated", "iam.dynamic_client_reg"},
		impact: "Full account takeover via identity provider",
		narrative: "Unauthenticated SCIM exposes the full user directory. Dynamic client registration " +
			"allows creating a malicious OAuth client to phish any user with a legitimate-looking auth flow.",
		severity: finding.SeverityCritical,
	},
	{
		ids:    []string{"web.crlf_injection", "web.open_redirect"},
		impact: "Session hijacking via response splitting",
		narrative: "CRLF injection allows injecting arbitrary headers into responses. Combined with an " +
			"open redirect, an attacker can craft a URL that sets a malicious cookie and redirects to a " +
			"controlled page, enabling session fixation.",
		severity: finding.SeverityHigh,
	},
	{
		ids:    []string{"saml.signature_not_validated", "iam.idp_admin_exposed"},
		impact: "Admin account takeover via SAML bypass",
		narrative: "The SAML SP accepts unsigned assertions, allowing an attacker to craft an assertion " +
			"claiming admin identity. The exposed IdP admin panel provides a target endpoint to attack.",
		severity: finding.SeverityCritical,
	},
	{
		ids:    []string{"web.ssrf", "iam.cloud_metadata_ssrf"},
		impact: "Cloud credential theft via SSRF chain",
		narrative: "An SSRF vulnerability allows making server-side requests. The cloud metadata endpoint " +
			"(169.254.169.254) is reachable, enabling theft of IAM credentials that could grant AWS/GCP/Azure access.",
		severity: finding.SeverityCritical,
	},
	{
		ids:    []string{"web.ssti", "tls.cert_expiry_30d"},
		impact: "RCE on degraded security posture",
		narrative: "Server-side template injection enables remote code execution. The expiring TLS certificate " +
			"indicates the service may be neglected, reducing the chance of prompt patching.",
		severity: finding.SeverityCritical,
	},
	{
		ids:    []string{"jwt.audience_missing", "iam.token_introspect_exposed"},
		impact: "Cross-service token reuse",
		narrative: "JWT audience validation is missing, so tokens issued for one service can be replayed " +
			"against another. The exposed token introspection endpoint lets an attacker verify which tokens are still active.",
		severity: finding.SeverityHigh,
	},
}

// DetectChains identifies attack chains in a set of findings for a single asset.
// Returns only chains where all component findings are present.
func DetectChains(findings []finding.Finding) []AttackChain {
	// Build a set of all CheckIDs present.
	present := make(map[string]bool)
	byID := make(map[string]finding.Finding)
	for _, f := range findings {
		present[f.CheckID] = true
		byID[f.CheckID] = f
	}

	var chains []AttackChain
	for _, pattern := range knownChainPatterns {
		allPresent := true
		for _, id := range pattern.ids {
			if !present[id] {
				allPresent = false
				break
			}
		}
		if !allPresent {
			continue
		}
		var chainFindings []finding.Finding
		for _, id := range pattern.ids {
			chainFindings = append(chainFindings, byID[id])
		}
		chains = append(chains, AttackChain{
			Findings:  chainFindings,
			Impact:    pattern.impact,
			Narrative: pattern.narrative,
			Severity:  pattern.severity,
		})
	}
	return chains
}

// FormatChain returns a concise text representation of an attack chain for report output.
func FormatChain(c AttackChain) string {
	ids := make([]string, len(c.Findings))
	for i, f := range c.Findings {
		ids[i] = f.CheckID
	}
	return fmt.Sprintf("[%s] %s\n  Chain: %s\n  %s",
		c.Severity, c.Impact, strings.Join(ids, " + "), c.Narrative)
}
