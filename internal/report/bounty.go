package report

import (
	"fmt"
	"strings"

	"github.com/stormbane-security/beacon/internal/enrichment"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/store"
)

// RenderBounty generates a bug-bounty-submission-ready markdown report
// optimized for HackerOne/Bugcrowd submissions. Each finding is formatted
// as a standalone submission with:
//   - [SEVERITY] Title heading
//   - Summary paragraph
//   - Affected Asset (URL/Host, Endpoint, Parameter)
//   - Steps to Reproduce (numbered)
//   - Proof of Concept (curl/command block)
//   - Impact statement
//   - Severity Justification with CVSS estimate
//   - Remediation recommendation
//   - References
//
// Only findings with severity >= Medium are included. Findings are sorted
// critical → high → medium.
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

	// One section per finding, ordered by severity (critical first).
	order := []finding.Severity{
		finding.SeverityCritical,
		finding.SeverityHigh,
		finding.SeverityMedium,
	}

	for _, sev := range order {
		for _, ef := range filtered {
			if ef.Finding.Severity != sev {
				continue
			}
			renderBountyFinding(&b, ef, run)
		}
	}

	return b.String()
}

func renderBountyFinding(b *strings.Builder, ef enrichment.EnrichedFinding, run store.ScanRun) {
	f := ef.Finding
	label := strings.ToUpper(SeverityLabel(f.Severity))
	cvss := estimateCVSS(f)

	// --- Title ---
	_, _ = fmt.Fprintf(b, "# [%s] %s\n\n", label, f.Title)

	// --- Summary ---
	b.WriteString("## Summary\n\n")
	if ef.Explanation != "" {
		b.WriteString(ef.Explanation + "\n\n")
	} else {
		b.WriteString(f.Description + "\n\n")
	}

	// --- Affected Asset ---
	b.WriteString("## Affected Asset\n\n")
	_, _ = fmt.Fprintf(b, "- **URL/Host**: %s\n", f.Asset)
	endpoint := extractEndpoint(f)
	if endpoint != "" {
		_, _ = fmt.Fprintf(b, "- **Endpoint**: %s\n", endpoint)
	}
	if param := extractParam(f); param != "" {
		_, _ = fmt.Fprintf(b, "- **Parameter**: %s\n", param)
	}
	if svc, ok := f.Evidence["service"].(string); ok {
		_, _ = fmt.Fprintf(b, "- **Service**: %s\n", svc)
	}
	if ver, ok := f.Evidence["version"].(string); ok {
		_, _ = fmt.Fprintf(b, "- **Version**: %s\n", ver)
	}
	b.WriteString("\n")

	// --- Steps to Reproduce ---
	b.WriteString("## Steps to Reproduce\n\n")
	proofCmd := f.ProofCommand
	if proofCmd == "" {
		proofCmd = verifyCmd(f.CheckID, f.Asset)
	}
	if proofCmd != "" {
		b.WriteString("1. Open a terminal on any machine with network access to the target\n")
		b.WriteString("2. Run the following command:\n")
		_, _ = fmt.Fprintf(b, "```bash\n%s\n```\n", proofCmd)
		b.WriteString("3. Observe the vulnerability in the response\n\n")
	} else {
		_, _ = fmt.Fprintf(b, "1. Navigate to `%s`\n", f.Asset)
		b.WriteString("2. Observe the vulnerability condition described in the summary\n\n")
	}

	// --- Proof of Concept ---
	if proofCmd != "" {
		b.WriteString("## Proof of Concept\n\n")
		_, _ = fmt.Fprintf(b, "```bash\n%s\n```\n\n", proofCmd)
	}

	// --- Impact ---
	b.WriteString("## Impact\n\n")
	if ef.Impact != "" {
		b.WriteString(ef.Impact + "\n\n")
	} else {
		b.WriteString(bountyImpact(f) + "\n\n")
	}

	// --- Severity Justification ---
	b.WriteString("## Severity Justification\n\n")
	_, _ = fmt.Fprintf(b, "This finding is rated **%s** with an estimated CVSS score of **%.1f**. ", SeverityLabel(f.Severity), cvss)
	b.WriteString(severityJustification(f) + "\n\n")

	// --- Remediation ---
	b.WriteString("## Remediation\n\n")
	if ef.Remediation != "" {
		b.WriteString(ef.Remediation + "\n")
	}
	if ef.TechSpecificRemediation != "" {
		if ef.Remediation != "" {
			b.WriteString("\n")
		}
		b.WriteString(ef.TechSpecificRemediation + "\n")
	}
	if ef.Remediation == "" && ef.TechSpecificRemediation == "" {
		b.WriteString(defaultRemediation(f) + "\n")
	}
	b.WriteString("\n")

	// --- References ---
	refs := bountyReferences(f)
	if len(refs) > 0 {
		b.WriteString("## References\n\n")
		for _, ref := range refs {
			_, _ = fmt.Fprintf(b, "- %s\n", ref)
		}
		b.WriteString("\n")
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

// extractParam pulls a parameter name from evidence if present.
func extractParam(f finding.Finding) string {
	for _, key := range []string{"parameter", "param", "param_name", "query_param"} {
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

// severityJustification explains why a finding warrants its severity rating.
func severityJustification(f finding.Finding) string {
	id := string(f.CheckID)
	switch f.Severity {
	case finding.SeverityCritical:
		switch {
		case strings.HasPrefix(id, "exploit.code_execution"):
			return "Remote code execution provides complete control over the affected system, warranting a critical rating per CVSS v3.1 guidelines."
		case strings.HasPrefix(id, "exploit.credential"):
			return "Credential extraction enables immediate unauthorized access without further exploitation, representing a critical confidentiality impact."
		case strings.HasPrefix(id, "web.sqli"):
			return "SQL injection with data access capability impacts confidentiality, integrity, and potentially availability of all database-backed functionality."
		default:
			return "The vulnerability allows high-impact exploitation with low attack complexity and no required privileges."
		}
	case finding.SeverityHigh:
		return "The vulnerability has significant security impact and can be exploited with moderate effort. Network-adjacent or authenticated attackers can leverage this to compromise sensitive data or functionality."
	case finding.SeverityMedium:
		return "The vulnerability presents a real but limited risk. Exploitation requires specific conditions or yields limited impact compared to higher-severity issues."
	default:
		return "The severity is based on the potential impact and exploitability of the finding."
	}
}

// defaultRemediation provides generic remediation advice when enrichment has none.
func defaultRemediation(f finding.Finding) string {
	id := string(f.CheckID)
	switch {
	case strings.HasPrefix(id, "web.sqli"):
		return "Use parameterized queries or prepared statements for all database interactions. Never concatenate user input into SQL queries."
	case strings.HasPrefix(id, "web.xss") || strings.HasPrefix(id, "web.dom_xss"):
		return "Sanitize and encode all user-supplied input before rendering it in HTML context. Implement a Content-Security-Policy header to mitigate exploitation."
	case strings.HasPrefix(id, "web.ssrf"):
		return "Validate and whitelist allowed URLs/hosts for any server-side request functionality. Block access to internal/private IP ranges and cloud metadata endpoints."
	case strings.HasPrefix(id, "web.cors"):
		return "Restrict the Access-Control-Allow-Origin header to trusted origins only. Never reflect arbitrary Origin values with Access-Control-Allow-Credentials: true."
	case strings.HasPrefix(id, "tls."):
		return "Update TLS configuration to use TLS 1.2+ with strong cipher suites. Disable deprecated protocols (SSLv3, TLS 1.0, TLS 1.1)."
	case strings.HasPrefix(id, "headers."):
		return "Add the missing security headers to all HTTP responses. Consider using a security headers middleware or reverse proxy configuration."
	case strings.HasPrefix(id, "cve."):
		return "Apply the vendor-supplied patch or upgrade to a version that addresses this CVE. If patching is not immediately possible, implement compensating controls."
	default:
		return "Address the identified vulnerability according to security best practices for the affected technology. Consult the references section for specific guidance."
	}
}

// bountyReferences returns relevant reference links based on finding type.
func bountyReferences(f finding.Finding) []string {
	id := string(f.CheckID)
	var refs []string

	switch {
	case strings.HasPrefix(id, "web.sqli"):
		refs = append(refs,
			"https://owasp.org/www-community/attacks/SQL_Injection",
			"https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
		)
	case strings.HasPrefix(id, "web.xss") || strings.HasPrefix(id, "web.dom_xss"):
		refs = append(refs,
			"https://owasp.org/www-community/attacks/xss/",
			"https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
		)
	case strings.HasPrefix(id, "web.ssrf"):
		refs = append(refs,
			"https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
			"https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
		)
	case strings.HasPrefix(id, "web.cors"):
		refs = append(refs,
			"https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
			"https://portswigger.net/web-security/cors",
		)
	case strings.HasPrefix(id, "tls."):
		refs = append(refs,
			"https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
		)
	case strings.HasPrefix(id, "headers."):
		refs = append(refs,
			"https://owasp.org/www-project-secure-headers/",
			"https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
		)
	case strings.HasPrefix(id, "cve."):
		// Extract CVE ID from check ID if possible (e.g., cve.CVE_2021_44228).
		cveID := strings.TrimPrefix(id, "cve.")
		cveID = strings.ReplaceAll(cveID, "_", "-")
		refs = append(refs,
			fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cveID),
			fmt.Sprintf("https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s", cveID),
		)
	}

	return refs
}
