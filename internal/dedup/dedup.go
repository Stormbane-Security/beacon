// Package dedup detects potential duplicate findings within a single scan run.
//
// Beacon flags duplicates but never merges them — downstream consumers
// (Forecast) resolve duplicates using full multi-scan context. The dedup
// pass runs after all scanners complete and before enrichment.
//
// Duplicate detection strategies:
//  1. Same CheckID prefix, same asset — different sub-checks for the same issue class
//  2. Same CheckID, overlapping assets — wildcard/parent domain overlap
//  3. Cross-scanner overlap — different scanners reporting the same vulnerability class
//  4. Evidence fingerprint — identical evidence payloads from different check IDs
package dedup

import (
	"strings"

	"github.com/stormbane-security/beacon/internal/finding"
)

// findingKey uniquely identifies a finding for dedup references.
func findingKey(f finding.Finding) string {
	return string(f.CheckID) + "|" + f.Asset + "|" + f.Title
}

// FlagDuplicates scans findings for potential duplicates and sets
// DuplicateOf and DuplicateConfidence on likely duplicates.
// The original (first-seen, highest-severity) finding is kept clean;
// the duplicate gets the flag. Modifies findings in place.
func FlagDuplicates(findings []finding.Finding) {
	if len(findings) < 2 {
		return
	}

	// Index findings by asset and by check prefix for fast lookup.
	byAsset := make(map[string][]int)          // asset -> finding indices
	byPrefix := make(map[string][]int)         // check prefix -> finding indices
	byCheckAsset := make(map[string]int)       // checkID+asset -> first index
	for i := range findings {
		f := &findings[i]
		byAsset[f.Asset] = append(byAsset[f.Asset], i)

		prefix := checkPrefix(f.CheckID)
		byPrefix[prefix] = append(byPrefix[prefix], i)

		key := string(f.CheckID) + "\x00" + f.Asset
		if _, exists := byCheckAsset[key]; !exists {
			byCheckAsset[key] = i
		}
	}

	// Strategy 1: Same check prefix, same asset.
	// e.g., tls.protocol_sslv2 and tls.protocol_sslv3 on the same host
	// are related but not duplicates — skip. But nuclei.xyz and nuclei.xyz
	// from different title variants ARE duplicates.
	// We focus on cross-scanner overlap and asset overlap instead.

	// Strategy 2: Same CheckID, overlapping assets (wildcard/parent).
	flagAssetOverlaps(findings, byAsset)

	// Strategy 3: Cross-scanner same-class findings on same asset.
	flagCrossScannerDuplicates(findings, byAsset)

	// Strategy 4: Evidence fingerprint duplicates.
	flagEvidenceDuplicates(findings, byAsset)
}

// checkPrefix returns the namespace prefix of a CheckID.
// e.g., "tls.protocol_sslv2" -> "tls", "web.cors_misconfiguration" -> "web"
func checkPrefix(id finding.CheckID) string {
	if dot := strings.IndexByte(id, '.'); dot > 0 {
		return id[:dot]
	}
	return id
}

// flagAssetOverlaps flags findings where the same CheckID fires on both
// a specific subdomain and a parent/wildcard domain.
func flagAssetOverlaps(findings []finding.Finding, byAsset map[string][]int) {
	// Group by CheckID.
	byCheck := make(map[string][]int)
	for i := range findings {
		byCheck[string(findings[i].CheckID)] = append(byCheck[string(findings[i].CheckID)], i)
	}

	for _, indices := range byCheck {
		if len(indices) < 2 {
			continue
		}
		// For each pair, check if one asset is a parent of another.
		for a := 0; a < len(indices); a++ {
			fa := &findings[indices[a]]
			if fa.DuplicateOf != "" {
				continue
			}
			for b := a + 1; b < len(indices); b++ {
				fb := &findings[indices[b]]
				if fb.DuplicateOf != "" {
					continue
				}
				if fa.Asset == fb.Asset {
					continue
				}
				conf := assetOverlapConfidence(fa.Asset, fb.Asset)
				if conf > 0 {
					// The more specific asset (subdomain) keeps the finding;
					// the less specific one is the duplicate.
					if isMoreSpecific(fa.Asset, fb.Asset) {
						fb.DuplicateOf = findingKey(*fa)
						fb.DuplicateConfidence = conf
					} else {
						fa.DuplicateOf = findingKey(*fb)
						fa.DuplicateConfidence = conf
					}
				}
			}
		}
	}
}

// assetOverlapConfidence returns a confidence score (0.0–1.0) indicating
// how likely two assets are the same underlying resource.
func assetOverlapConfidence(a, b string) float64 {
	// Wildcard match: *.example.com overlaps with sub.example.com
	if strings.HasPrefix(a, "*.") {
		parent := a[2:]
		if strings.HasSuffix(b, "."+parent) || b == parent {
			return 0.9
		}
	}
	if strings.HasPrefix(b, "*.") {
		parent := b[2:]
		if strings.HasSuffix(a, "."+parent) || a == parent {
			return 0.9
		}
	}

	// Parent domain match: example.com and sub.example.com
	if strings.HasSuffix(a, "."+b) || strings.HasSuffix(b, "."+a) {
		return 0.7
	}

	// Same base domain, different subdomains sharing the same IP
	// would need asset graph context — flag with lower confidence.
	if sameBaseDomain(a, b) && a != b {
		return 0.4
	}

	return 0
}

// isMoreSpecific returns true if a is a more specific hostname than b.
func isMoreSpecific(a, b string) bool {
	// Wildcard is less specific than any concrete subdomain.
	if strings.HasPrefix(b, "*.") && !strings.HasPrefix(a, "*.") {
		return true
	}
	if strings.HasPrefix(a, "*.") && !strings.HasPrefix(b, "*.") {
		return false
	}
	// More dots = more specific.
	return strings.Count(a, ".") > strings.Count(b, ".")
}

// sameBaseDomain checks if two hostnames share the same registrable domain.
// Simple heuristic: compare last two labels.
func sameBaseDomain(a, b string) bool {
	return baseDomain(a) == baseDomain(b)
}

// knownMultiPartTLDs lists well-known country-code TLD suffixes that require
// three labels for a registrable domain (e.g., example.co.uk).
var knownMultiPartTLDs = map[string]bool{
	"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true,
	"co.jp": true, "or.jp": true, "ne.jp": true, "ac.jp": true,
	"co.kr": true, "or.kr": true,
	"co.nz": true, "net.nz": true, "org.nz": true,
	"co.za": true, "org.za": true, "net.za": true,
	"com.au": true, "net.au": true, "org.au": true,
	"com.br": true, "net.br": true, "org.br": true,
	"co.in": true, "net.in": true, "org.in": true,
	"com.cn": true, "net.cn": true, "org.cn": true,
	"com.mx": true, "org.mx": true,
	"com.ar": true, "org.ar": true,
	"co.il": true, "org.il": true,
	"com.tw": true, "org.tw": true,
	"com.sg": true, "org.sg": true,
	"com.hk": true, "org.hk": true,
}

// baseDomain extracts the registrable domain from a hostname.
// Handles multi-part TLDs like .co.uk correctly.
func baseDomain(host string) string {
	host = strings.TrimPrefix(host, "*.")
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return host
	}
	// Check for known multi-part TLDs (last 2 labels).
	if len(parts) >= 3 {
		suffix := parts[len(parts)-2] + "." + parts[len(parts)-1]
		if knownMultiPartTLDs[suffix] {
			return strings.Join(parts[len(parts)-3:], ".")
		}
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// crossScannerOverlaps maps check ID pairs that represent the same
// vulnerability class detected by different scanners or check paths.
var crossScannerOverlaps = map[[2]string]float64{
	// CORS: nuclei vs beacon's CORS scanner
	{"nuclei.misconfigured_cors", "web.cors_misconfiguration"}:        0.95,
	{"nuclei.misconfigured_cors", "web.cors_null_origin"}:             0.85,
	{"nuclei.misconfigured_cors", "web.cors_credentialed_reflection"}: 0.80,

	// S3 bucket: nuclei vs cloud scanner
	{"nuclei.s3_bucket_exposed", "cloud.bucket_public"}: 0.90,

	// Admin panels: dirbust vs exposure
	{"dirbust.path_found", "exposure.admin_path"}:        0.85,
	{"dirbust.path_found", "exposure.monitoring_panel"}:  0.80,
	{"dirbust.path_found", "exposure.cicd_panel"}:        0.80,
	{"dirbust.path_found", "exposure.spring_actuator"}:   0.85,
	{"dirbust.path_found", "exposure.api_docs"}:          0.80,

	// Git exposed: dirbust vs exposure
	{"dirbust.path_found", "exposure.git_exposed"}: 0.90,
	{"dirbust.path_found", "exposure.env_file_exposed"}: 0.90,

	// Port-based vs HTTP-based detection
	{"port.elasticsearch_unauthenticated", "exposure.monitoring_panel"}: 0.70,
	{"port.prometheus_unauthenticated", "exposure.monitoring_panel"}:    0.70,
	{"port.jupyter_exposed", "exposure.monitoring_panel"}:               0.70,

	// Subdomain takeover vs dangling CNAME
	{"subdomain.takeover", "dns.dangling_cname"}: 0.85,

	// Server version: nuclei version disclosure vs native EOL check
	{"nuclei.server-version-disclosure", "classify.eol_software"}: 0.90,
}

// flagCrossScannerDuplicates flags findings where different scanners
// detected the same vulnerability class on the same asset.
func flagCrossScannerDuplicates(findings []finding.Finding, byAsset map[string][]int) {
	for _, indices := range byAsset {
		if len(indices) < 2 {
			continue
		}
		for a := 0; a < len(indices); a++ {
			fa := &findings[indices[a]]
			if fa.DuplicateOf != "" {
				continue
			}
			for b := a + 1; b < len(indices); b++ {
				fb := &findings[indices[b]]
				if fb.DuplicateOf != "" {
					continue
				}
				if fa.CheckID == fb.CheckID {
					continue // same check on same asset is already handled by store dedup
				}

				conf := crossScannerConfidence(fa.CheckID, fb.CheckID)
				if conf > 0 {
					// Keep the more specific/higher-severity finding as canonical.
					if severityRank(fa.Severity) >= severityRank(fb.Severity) {
						fb.DuplicateOf = findingKey(*fa)
						fb.DuplicateConfidence = conf
					} else {
						fa.DuplicateOf = findingKey(*fb)
						fa.DuplicateConfidence = conf
					}
				}
			}
		}
	}
}

// crossScannerConfidence returns the overlap confidence for two check IDs.
func crossScannerConfidence(a, b finding.CheckID) float64 {
	if conf, ok := crossScannerOverlaps[[2]string{a, b}]; ok {
		return conf
	}
	if conf, ok := crossScannerOverlaps[[2]string{b, a}]; ok {
		return conf
	}
	return 0
}

// flagEvidenceDuplicates flags findings with identical evidence payloads
// on the same asset but different check IDs.
func flagEvidenceDuplicates(findings []finding.Finding, byAsset map[string][]int) {
	for _, indices := range byAsset {
		if len(indices) < 2 {
			continue
		}
		// Build evidence fingerprints for findings on this asset.
		type evidenceKey struct {
			url    string
			status string
		}
		seen := make(map[evidenceKey]int) // evidence key -> first finding index

		for _, i := range indices {
			f := &findings[i]
			if f.DuplicateOf != "" {
				continue
			}
			if f.Evidence == nil {
				continue
			}

			// Extract URL and status code as a lightweight evidence fingerprint.
			url, _ := f.Evidence["url"].(string)
			status, _ := f.Evidence["status_code"].(string)
			if url == "" {
				continue
			}
			ek := evidenceKey{url: url, status: status}

			if prevIdx, exists := seen[ek]; exists {
				prev := &findings[prevIdx]
				if prev.CheckID == f.CheckID {
					continue // same check, same evidence — already deduped by store
				}
				// Same URL + status on same asset from different checks.
				f.DuplicateOf = findingKey(*prev)
				f.DuplicateConfidence = 0.75
			} else {
				seen[ek] = i
			}
		}
	}
}

// severityRank returns a numeric rank for severity comparison.
// Higher rank = more severe.
func severityRank(s finding.Severity) int {
	switch s {
	case finding.SeverityCritical:
		return 5
	case finding.SeverityHigh:
		return 4
	case finding.SeverityMedium:
		return 3
	case finding.SeverityLow:
		return 2
	case finding.SeverityInfo:
		return 1
	default:
		return 0
	}
}
