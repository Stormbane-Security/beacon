package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/enrichment"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/store"
)

// RenderBounty generates a bug-bounty-submission-ready markdown report.
// Each finding is formatted as a standalone submission with:
// - Title, severity, CVSS estimate
// - Affected component/endpoint
// - Steps to reproduce (numbered)
// - Impact statement in bounty language
// - Proof of concept (curl commands)
// - Remediation recommendation
func RenderBounty(run store.ScanRun, enriched []enrichment.EnrichedFinding, _ string, _ []store.AssetExecution) string {
	filtered := make([]enrichment.EnrichedFinding, 0, len(enriched))
	for _, ef := range enriched {
		if !ef.Omit && ef.Finding.Severity >= finding.SeverityMedium {
			filtered = append(filtered, ef)
		}
	}

	if len(filtered) == 0 {
		return "# No reportable findings\n\nNo medium+ severity findings detected.\n"
	}

	var b strings.Builder

	// One section per finding — each is a standalone submission
	order := []finding.Severity{
		finding.SeverityCritical,
		finding.SeverityHigh,
		finding.SeverityMedium,
	}

	idx := 0
	for _, sev := range order {
		for _, ef := range filtered {
			if ef.Finding.Severity != sev {
				continue
			}
			idx++
			renderBountyFinding(&b, ef, run, idx)
		}
	}

	return b.String()
}

func renderBountyFinding(b *strings.Builder, ef enrichment.EnrichedFinding, run store.ScanRun, idx int) {
	f := ef.Finding
	label := SeverityLabel(f.Severity)
	cvss := estimateCVSS(f)

	_, _ = fmt.Fprintf(b, "# Finding %d: %s\n\n", idx, f.Title)

	// Metadata table
	b.WriteString("| Field | Value |\n")
	b.WriteString("|-------|-------|\n")
	_, _ = fmt.Fprintf(b, "| **Severity** | %s |\n", label)
	_, _ = fmt.Fprintf(b, "| **CVSS (est.)** | %.1f |\n", cvss)
	_, _ = fmt.Fprintf(b, "| **Asset** | `%s` |\n", f.Asset)
	_, _ = fmt.Fprintf(b, "| **Check ID** | `%s` |\n", f.CheckID)
	if f.DiscoveredAt != (time.Time{}) {
		_, _ = fmt.Fprintf(b, "| **Discovered** | %s |\n", f.DiscoveredAt.Format("2006-01-02 15:04 MST"))
	}
	b.WriteString("\n")

	// Affected Component
	b.WriteString("## Affected Component\n\n")
	endpoint := extractEndpoint(f)
	if endpoint != "" {
		_, _ = fmt.Fprintf(b, "- **Endpoint:** `%s`\n", endpoint)
	}
	_, _ = fmt.Fprintf(b, "- **Target:** `%s`\n", f.Asset)
	if svc, ok := f.Evidence["service"].(string); ok {
		_, _ = fmt.Fprintf(b, "- **Service:** %s\n", svc)
	}
	if ver, ok := f.Evidence["version"].(string); ok {
		_, _ = fmt.Fprintf(b, "- **Version:** %s\n", ver)
	}
	b.WriteString("\n")

	// Description
	b.WriteString("## Description\n\n")
	if ef.Explanation != "" {
		b.WriteString(ef.Explanation + "\n\n")
	} else {
		b.WriteString(f.Description + "\n\n")
	}

	// Steps to Reproduce
	b.WriteString("## Steps to Reproduce\n\n")
	proofCmd := f.ProofCommand
	if proofCmd == "" {
		proofCmd = verifyCmd(f.CheckID, f.Asset)
	}
	if proofCmd != "" {
		b.WriteString("1. Open a terminal\n")
		b.WriteString("2. Run the following command:\n")
		_, _ = fmt.Fprintf(b, "```sh\n%s\n```\n", proofCmd)
		b.WriteString("3. Observe the vulnerability in the output\n\n")
	} else {
		_, _ = fmt.Fprintf(b, "1. Navigate to `%s`\n", f.Asset)
		b.WriteString("2. Observe the vulnerability condition described above\n\n")
	}

	// Impact
	b.WriteString("## Impact\n\n")
	if ef.Impact != "" {
		b.WriteString(ef.Impact + "\n\n")
	} else {
		b.WriteString(bountyImpact(f) + "\n\n")
	}

	// Remediation
	if ef.Remediation != "" || ef.TechSpecificRemediation != "" {
		b.WriteString("## Remediation\n\n")
		if ef.Remediation != "" {
			b.WriteString(ef.Remediation + "\n\n")
		}
		if ef.TechSpecificRemediation != "" {
			b.WriteString(ef.TechSpecificRemediation + "\n\n")
		}
	}

	// Evidence
	if len(f.Evidence) > 0 {
		b.WriteString("## Supporting Evidence\n\n")
		b.WriteString("```json\n")
		for k, v := range f.Evidence {
			if k == "image_b64" {
				continue // skip large base64 screenshots
			}
			_, _ = fmt.Fprintf(b, "%s: %v\n", k, v)
		}
		b.WriteString("```\n\n")
	}

	b.WriteString("---\n\n")
}

// estimateCVSS returns an estimated CVSS score based on finding severity.
func estimateCVSS(f finding.Finding) float64 {
	switch f.Severity {
	case finding.SeverityCritical:
		return 9.1
	case finding.SeverityHigh:
		return 7.5
	case finding.SeverityMedium:
		return 5.3
	case finding.SeverityLow:
		return 3.1
	default:
		return 0.0
	}
}

// extractEndpoint pulls a URL or path from evidence for the affected component.
func extractEndpoint(f finding.Finding) string {
	for _, key := range []string{"url", "path", "matched_at", "endpoint"} {
		if v, ok := f.Evidence[key].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// bountyImpact generates a default impact statement based on check ID patterns.
func bountyImpact(f finding.Finding) string {
	id := string(f.CheckID)
	switch {
	case strings.HasPrefix(id, "exploit.credential"):
		return "An attacker can extract valid credentials from this service, enabling unauthorized access to backend systems, lateral movement within the infrastructure, and potential data exfiltration."
	case strings.HasPrefix(id, "exploit.code_execution"):
		return "An attacker can achieve remote code execution on the target server, enabling full system compromise, data exfiltration, and use as a pivot point for further attacks."
	case strings.HasPrefix(id, "exploit.data_extracted"):
		return "An attacker can access sensitive data including potentially PII, financial records, or internal configuration. This constitutes a data breach risk."
	case strings.HasPrefix(id, "exploit.lateral"):
		return "An attacker can use this service as a pivot point to access internal systems that are not directly exposed to the internet."
	case strings.HasPrefix(id, "port.") && strings.Contains(id, "default"):
		return "Default credentials allow an attacker to gain full administrative access to this service without any prior knowledge. This is a critical configuration weakness."
	case strings.HasPrefix(id, "port.") && (strings.Contains(id, "unauth") || strings.Contains(id, "no_auth") || strings.Contains(id, "exposed")):
		return "This service is accessible without authentication, exposing its full functionality to any network-level attacker."
	case strings.HasPrefix(id, "web.sqli") || strings.HasPrefix(id, "web.sql"):
		return "SQL injection allows an attacker to read, modify, or delete database contents, bypass authentication, and potentially achieve remote code execution on the database server."
	case strings.HasPrefix(id, "web.ssrf"):
		return "Server-side request forgery allows an attacker to make requests from the server to internal services, potentially accessing cloud metadata endpoints (AWS IAM credentials), internal APIs, and other infrastructure."
	case strings.HasPrefix(id, "web.xss") || strings.HasPrefix(id, "web.dom_xss"):
		return "Cross-site scripting allows an attacker to execute JavaScript in the context of other users' sessions, enabling session hijacking, credential theft, and account takeover."
	case strings.HasPrefix(id, "web.cors"):
		return "CORS misconfiguration allows an attacker-controlled website to make authenticated cross-origin requests, potentially exfiltrating user data or performing actions on behalf of the victim."
	case strings.HasPrefix(id, "headers.missing_hsts"):
		return "Missing HSTS header allows an attacker to perform SSL stripping attacks on the first connection, intercepting credentials and session tokens."
	case strings.HasPrefix(id, "tls."):
		return "TLS misconfiguration weakens the transport security, potentially allowing an attacker to intercept or modify traffic between clients and the server."
	case strings.HasPrefix(id, "cve."):
		return "This is a known CVE with public exploit code. An attacker can leverage publicly available tools to exploit this vulnerability."
	default:
		return "This finding represents a security weakness that could be leveraged by an attacker to compromise the confidentiality, integrity, or availability of the affected system."
	}
}
