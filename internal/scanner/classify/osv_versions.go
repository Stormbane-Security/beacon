package classify

// CheckOSVVersions queries the OSV.dev vulnerability database for every
// fingerprinted service version in the asset's evidence. This turns passive
// version detection (Server: nginx/1.18.0) into comprehensive CVE coverage
// without maintaining a hardcoded vulnerability list.
//
// The function is called after classify.Collect() — no extra HTTP requests are
// made to the target; only the OSV API is contacted.

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/osv"
	"github.com/stormbane-security/beacon/internal/playbook"
)

// osvClient is the package-level OSV client, lazily initialised.
var osvClient *osv.Client

// getOSVClient returns a shared OSV client (created once).
func getOSVClient() *osv.Client {
	if osvClient == nil {
		osvClient = osv.New()
	}
	return osvClient
}

// SetOSVClient overrides the shared OSV client (for testing).
func SetOSVClient(c *osv.Client) {
	osvClient = c
}

// versionRe extracts a version number from strings like "Apache/2.4.51 (Ubuntu)"
// or "nginx/1.18.0" or "PHP/8.1.12".
var versionRe = regexp.MustCompile(`(?:^|/)([0-9]+(?:\.[0-9]+){1,3})`)

// CheckOSVVersions queries OSV for every fingerprinted service version and
// returns findings for each known CVE. Returns nil on error (best-effort).
func CheckOSVVersions(ctx context.Context, ev playbook.Evidence, asset string) []finding.Finding {
	if len(ev.ServiceVersions) == 0 {
		return nil
	}

	// Build OSV queries from service versions.
	type queryMeta struct {
		serviceKey  string
		serviceName string
		version     string
	}

	var queries []osv.PackageQuery
	var metas []queryMeta

	for key, versionStr := range ev.ServiceVersions {
		svcName, ver := extractServiceAndVersion(key, versionStr)
		if svcName == "" || ver == "" {
			continue
		}

		osvQueries := osv.ServiceToOSVQueries(svcName, ver)
		for _, q := range osvQueries {
			queries = append(queries, q)
			metas = append(metas, queryMeta{
				serviceKey:  key,
				serviceName: svcName,
				version:     ver,
			})
		}
	}

	if len(queries) == 0 {
		return nil
	}

	client := getOSVClient()
	results, err := client.QueryBatch(ctx, queries)
	if err != nil {
		return nil // best-effort; don't fail the scan
	}

	var findings []finding.Finding
	seen := make(map[string]bool) // dedupe by CVE ID per asset

	for i, result := range results {
		if result.Error != "" || len(result.Vulnerabilities) == 0 {
			continue
		}
		meta := metas[i]

		for _, vuln := range result.Vulnerabilities {
			// Prefer CVE ID for dedup; fall back to OSV ID.
			dedup := vuln.ID
			if cves := vuln.CVEIDs(); len(cves) > 0 {
				dedup = cves[0]
			}
			if seen[dedup] {
				continue
			}
			seen[dedup] = true

			severity := mapOSVSeverity(vuln.Severity)
			cveIDs := vuln.CVEIDs()
			cveStr := vuln.ID
			if len(cveIDs) > 0 {
				cveStr = strings.Join(cveIDs, ", ")
			}
			// Downgrade advisories with no CVE IDs and no severity to info —
			// these are distro package advisories (ALEA, DSA, USN, etc.) that
			// are often bug fixes, not security vulnerabilities.
			if len(cveIDs) == 0 && vuln.Severity == "" {
				severity = finding.SeverityInfo
			}

			title := fmt.Sprintf("Known CVE: %s affects %s %s", cveStr, meta.serviceName, meta.version)
			if len(title) > 120 {
				title = title[:117] + "..."
			}

			fixNote := ""
			if vuln.FixedVersion != "" {
				fixNote = fmt.Sprintf(" Upgrade to %s or later to remediate.", vuln.FixedVersion)
			}

			evidence := map[string]any{
				"osv_id":      vuln.ID,
				"cve_ids":     cveIDs,
				"package":     meta.serviceName,
				"version":     meta.version,
				"severity":    vuln.Severity,
				"summary":     vuln.Summary,
				"service_key": meta.serviceKey,
			}
			if vuln.FixedVersion != "" {
				evidence["fixed_version"] = vuln.FixedVersion
			}

			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckOSVCVEMatch,
				Module:   "surface",
				Scanner:  "classify",
				Severity: severity,
				Confidence: finding.ConfidenceProbable,
				Asset:      asset,
				Title:      title,
				Description: fmt.Sprintf(
					"The OSV vulnerability database reports %s (%s) affecting %s version %s "+
						"detected on %s.%s %s",
					cveStr, vuln.ID, meta.serviceName, meta.version,
					asset, fixNote, vuln.Summary),
				Evidence:     evidence,
				ProofCommand: fmt.Sprintf("curl -s -I 'https://%s' | grep -i server", asset),
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings
}

// extractServiceAndVersion parses a ServiceVersions entry into a normalised
// service name and version string suitable for OSV lookup.
//
// Examples:
//
//	("web_server", "Apache/2.4.51 (Ubuntu)") → ("apache", "2.4.51")
//	("web_server", "nginx/1.18.0")           → ("nginx", "1.18.0")
//	("powered_by", "PHP/8.1.12")             → ("php", "8.1.12")
//	("platform",   "jenkins")                → ("jenkins", "")  — no version in tag
//	("web_server", "Microsoft-IIS/10.0")     → ("microsoft-iis", "10.0")
func extractServiceAndVersion(key, value string) (string, string) {
	lower := strings.ToLower(value)

	// Try "name/version" pattern first.
	if idx := strings.IndexByte(lower, '/'); idx > 0 {
		name := lower[:idx]
		rest := value[idx+1:]
		m := versionRe.FindStringSubmatch(rest)
		if m != nil {
			return name, m[1]
		}
		// Try extracting version from the original (might have spaces).
		m = versionRe.FindStringSubmatch(lower[idx:])
		if m != nil {
			return name, m[1]
		}
	}

	// For "platform" key, the value is just the service name (e.g., "jenkins").
	// Check if there's an embedded version anywhere.
	if key == "platform" {
		m := versionRe.FindStringSubmatch(value)
		if m != nil {
			// e.g., "Jenkins 2.401.1"
			name := strings.Fields(lower)[0]
			return name, m[1]
		}
		// Platform tag with no version — cannot query OSV.
		return lower, ""
	}

	// Generator meta tags: "WordPress 6.4.3" or "Drupal 10 (https://...)"
	if key == "generator_meta" || key == "generator" {
		parts := strings.Fields(lower)
		if len(parts) >= 2 {
			m := versionRe.FindStringSubmatch(parts[1])
			if m != nil {
				return parts[0], m[1]
			}
		}
	}

	return "", ""
}

// mapOSVSeverity converts an OSV severity string to a beacon finding severity.
func mapOSVSeverity(sev string) finding.Severity {
	switch strings.ToLower(sev) {
	case "critical":
		return finding.SeverityCritical
	case "high":
		return finding.SeverityHigh
	case "medium":
		return finding.SeverityMedium
	case "low":
		return finding.SeverityLow
	default:
		// Empty or unknown severity — likely a distro advisory (ALEA, DSA, etc.)
		// without a CVE or CVSS score. Don't inflate to high.
		return finding.SeverityInfo
	}
}
