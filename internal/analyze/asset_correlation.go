package analyze

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
)

// CorrelateAssets examines surface findings and cloud findings to discover
// relationships between domain-based assets and cloud infrastructure.
// It emits correlation findings with explicit evidence and confidence levels.
// NEVER merges or deduplicates assets — only creates advisory link findings.
func CorrelateAssets(surfaceFindings, cloudFindings []finding.Finding) []finding.Finding {
	surfaceIPs := buildSurfaceIPMap(surfaceFindings)
	cloudIPs := buildCloudIPMap(cloudFindings)

	var results []finding.Finding

	// 1. IP overlap correlations.
	ipOverlaps := findIPOverlaps(surfaceIPs, cloudIPs)
	results = append(results, ipOverlaps...)

	// 2. CNAME-to-cloud correlations.
	cnameCorrelations := findCNAMEToCloudCorrelations(surfaceFindings)
	results = append(results, cnameCorrelations...)

	// 3. TLS SAN overlap correlations.
	sanOverlaps := findTLSSANOverlaps(surfaceFindings, cloudFindings)
	results = append(results, sanOverlaps...)

	// 4. Composite correlations (IP + TLS SAN).
	composites := findCompositeCorrelations(ipOverlaps, sanOverlaps)
	results = append(results, composites...)

	// 5. Shared infrastructure correlations.
	sharedInfra := findSharedInfrastructure(surfaceIPs)
	results = append(results, sharedInfra...)

	// 6. Apply counter-signals (CDN detection reduces confidence).
	results = applyCounterSignals(results, surfaceFindings)

	return results
}

// surfaceIPEntry records a surface asset and its resolved IPs.
type surfaceIPEntry struct {
	asset string
	ips   []string
}

// cloudIPEntry records a cloud asset, its IPs, and resource type context.
type cloudIPEntry struct {
	asset        string
	ips          []string
	resourceType string
}

// buildSurfaceIPMap extracts IP addresses from surface findings.
// Looks at Evidence keys: "ip", "ips", "resolved_ips", "address", "a_records".
// Also considers the Asset field itself if it parses as an IP.
func buildSurfaceIPMap(findings []finding.Finding) map[string]surfaceIPEntry {
	entries := make(map[string]surfaceIPEntry) // keyed by asset name
	for _, f := range findings {
		entry, exists := entries[f.Asset]
		if !exists {
			entry = surfaceIPEntry{asset: f.Asset}
		}

		// If the asset itself is an IP address, include it.
		if net.ParseIP(f.Asset) != nil {
			entry.ips = appendUniqueIP(entry.ips, f.Asset)
		}

		// Extract IPs from evidence.
		for _, key := range []string{"ip", "ips", "resolved_ips", "address", "a_records"} {
			if v, ok := f.Evidence[key]; ok {
				entry.ips = appendUniqueIP(entry.ips, extractIPStrings(v)...)
			}
		}

		entries[f.Asset] = entry
	}
	return entries
}

// buildCloudIPMap extracts IP addresses from cloud findings.
// Looks at Evidence keys: "external_ip", "public_ip", "endpoint", "ingress_ip".
func buildCloudIPMap(findings []finding.Finding) map[string]cloudIPEntry {
	entries := make(map[string]cloudIPEntry) // keyed by asset name
	for _, f := range findings {
		entry, exists := entries[f.Asset]
		if !exists {
			entry = cloudIPEntry{asset: f.Asset}
		}

		// Capture resource type from evidence or scanner name.
		if rt, ok := f.Evidence["resource_type"].(string); ok && rt != "" {
			entry.resourceType = rt
		} else if entry.resourceType == "" {
			entry.resourceType = f.Scanner
		}

		for _, key := range []string{"external_ip", "public_ip", "endpoint", "ingress_ip"} {
			if v, ok := f.Evidence[key]; ok {
				entry.ips = appendUniqueIP(entry.ips, extractIPStrings(v)...)
			}
		}

		// The Asset field on cloud findings may be an IP.
		if net.ParseIP(f.Asset) != nil {
			entry.ips = appendUniqueIP(entry.ips, f.Asset)
		}

		entries[f.Asset] = entry
	}
	return entries
}

// findIPOverlaps emits a finding for each IP that appears in both surface
// and cloud maps.
func findIPOverlaps(surfaceIPs map[string]surfaceIPEntry, cloudIPs map[string]cloudIPEntry) []finding.Finding {
	// Build a reverse index: IP → cloud entries.
	cloudByIP := make(map[string][]cloudIPEntry)
	for _, entry := range cloudIPs {
		for _, ip := range entry.ips {
			norm := normalizeIP(ip)
			cloudByIP[norm] = append(cloudByIP[norm], entry)
		}
	}

	var results []finding.Finding
	seen := make(map[string]bool) // "surfaceAsset|cloudAsset|ip" → dedup

	// Deterministic iteration order.
	sortedSurface := sortedMapKeys(surfaceIPs)
	for _, surfaceAsset := range sortedSurface {
		sEntry := surfaceIPs[surfaceAsset]
		for _, ip := range sEntry.ips {
			norm := normalizeIP(ip)
			for _, cEntry := range cloudByIP[norm] {
				dedup := fmt.Sprintf("%s|%s|%s", sEntry.asset, cEntry.asset, norm)
				if seen[dedup] {
					continue
				}
				seen[dedup] = true

				results = append(results, finding.Finding{
					CheckID:  finding.CheckCorrelationIPOverlap,
					Module:   "correlation",
					Scanner:  "asset_correlation",
					Severity: finding.SeverityInfo,
					Asset:    sEntry.asset,
					Title:    fmt.Sprintf("Infrastructure match: %s \u2194 %s (IP overlap)", sEntry.asset, cEntry.asset),
					Description: fmt.Sprintf(
						"The surface asset %s and cloud resource %s both resolve to IP %s. "+
							"This is an advisory correlation indicating the domain is likely hosted "+
							"on this cloud resource. No assets have been merged or modified.",
						sEntry.asset, cEntry.asset, norm,
					),
					Evidence: map[string]any{
						"surface_asset":       sEntry.asset,
						"surface_ip":          norm,
						"cloud_asset":         cEntry.asset,
						"cloud_resource_type": cEntry.resourceType,
						"cloud_ip":            norm,
						"match_type":          "ip_overlap",
						"confidence":          "high",
					},
					ProofCommand: fmt.Sprintf("dig +short %s", sEntry.asset),
					DiscoveredAt: time.Now(),
				})
			}
		}
	}
	return results
}

// cloudCNAMEPatterns maps hostname suffixes to cloud provider names.
var cloudCNAMEPatterns = []struct {
	suffix   string
	provider string
}{
	// GCP
	{".googleapis.com", "gcp"},
	{".run.app", "gcp"},
	{".appspot.com", "gcp"},
	{".cloudfunctions.net", "gcp"},
	{".cloud.goog", "gcp"},
	// AWS
	{".elb.amazonaws.com", "aws"},
	{".cloudfront.net", "aws"},
	{".s3.amazonaws.com", "aws"},
	{".s3-website-", "aws"},
	{".execute-api.", "aws"},
	// Azure
	{".azurewebsites.net", "azure"},
	{".blob.core.windows.net", "azure"},
	{".azurefd.net", "azure"},
	{".trafficmanager.net", "azure"},
	{".azureedge.net", "azure"},
}

// findCNAMEToCloudCorrelations looks for cloud provider hostnames in CNAME
// chains within surface findings. Emits a correlation for each match.
func findCNAMEToCloudCorrelations(surfaceFindings []finding.Finding) []finding.Finding {
	var results []finding.Finding
	seen := make(map[string]bool) // "asset|cname" → dedup

	for _, f := range surfaceFindings {
		chains := extractCNAMEChains(f.Evidence)
		if len(chains) == 0 {
			continue
		}

		for _, cname := range chains {
			provider := matchCloudCNAME(cname)
			if provider == "" {
				continue
			}
			dedup := fmt.Sprintf("%s|%s", f.Asset, cname)
			if seen[dedup] {
				continue
			}
			seen[dedup] = true

			results = append(results, finding.Finding{
				CheckID:  finding.CheckCorrelationCNAMEToCloud,
				Module:   "correlation",
				Scanner:  "asset_correlation",
				Severity: finding.SeverityInfo,
				Asset:    f.Asset,
				Title:    fmt.Sprintf("CNAME points to %s infrastructure: %s \u2192 %s", provider, f.Asset, cname),
				Description: fmt.Sprintf(
					"The domain %s has a CNAME record pointing to %s (%s provider). "+
						"This is an advisory correlation indicating the domain uses %s infrastructure. "+
						"No assets have been merged or modified.",
					f.Asset, cname, provider, provider,
				),
				Evidence: map[string]any{
					"surface_asset":  f.Asset,
					"cname_target":   cname,
					"cloud_provider": provider,
					"cname_chain":    chains,
					"match_type":     "cname_to_cloud",
					"confidence":     "high",
				},
				ProofCommand: fmt.Sprintf("dig +short CNAME %s", f.Asset),
				DiscoveredAt: time.Now(),
			})
		}
	}
	return results
}

// findTLSSANOverlaps looks for TLS Subject Alternative Name entries in surface
// findings that match cloud finding asset names or evidence hostnames.
func findTLSSANOverlaps(surfaceFindings, cloudFindings []finding.Finding) []finding.Finding {
	// Build a set of cloud hostnames from asset names and evidence.
	cloudHostnames := make(map[string]string) // hostname → cloud asset name
	for _, f := range cloudFindings {
		// Extract hostnames from the cloud asset name.
		if isHostname(f.Asset) {
			cloudHostnames[strings.ToLower(f.Asset)] = f.Asset
		}
		// Check evidence for hostname-like values.
		for _, key := range []string{"hostname", "domain", "dns_name", "fqdn", "endpoint"} {
			if v, ok := f.Evidence[key].(string); ok && isHostname(v) {
				cloudHostnames[strings.ToLower(v)] = f.Asset
			}
		}
	}

	if len(cloudHostnames) == 0 {
		return nil
	}

	var results []finding.Finding
	seen := make(map[string]bool)

	for _, f := range surfaceFindings {
		sans := extractSANs(f.Evidence)
		if len(sans) == 0 {
			continue
		}

		for _, san := range sans {
			cloudAsset, ok := cloudHostnames[strings.ToLower(san)]
			if !ok {
				continue
			}
			dedup := fmt.Sprintf("%s|%s|%s", f.Asset, cloudAsset, san)
			if seen[dedup] {
				continue
			}
			seen[dedup] = true

			results = append(results, finding.Finding{
				CheckID:  finding.CheckCorrelationTLSSANOverlap,
				Module:   "correlation",
				Scanner:  "asset_correlation",
				Severity: finding.SeverityInfo,
				Asset:    f.Asset,
				Title:    fmt.Sprintf("TLS SAN overlap: %s certificate includes %s (cloud: %s)", f.Asset, san, cloudAsset),
				Description: fmt.Sprintf(
					"The TLS certificate for %s includes Subject Alternative Name '%s', "+
						"which matches cloud resource %s. This indicates the same TLS certificate "+
						"serves both the surface asset and the cloud resource. Advisory only.",
					f.Asset, san, cloudAsset,
				),
				Evidence: map[string]any{
					"surface_asset":  f.Asset,
					"san_match":      san,
					"cloud_asset":    cloudAsset,
					"match_type":     "tls_san_overlap",
					"confidence":     "high",
				},
				ProofCommand: fmt.Sprintf("echo | openssl s_client -connect %s:443 -servername %s 2>/dev/null | openssl x509 -noout -ext subjectAltName", f.Asset, f.Asset),
				DiscoveredAt: time.Now(),
			})
		}
	}
	return results
}

// findCompositeCorrelations emits a higher-confidence finding when both IP
// overlap AND TLS SAN overlap exist for the same surface↔cloud pair.
func findCompositeCorrelations(ipOverlaps, sanOverlaps []finding.Finding) []finding.Finding {
	// Build a set of (surface_asset, cloud_asset) pairs from IP overlaps.
	type assetPair struct {
		surface string
		cloud   string
	}
	ipPairs := make(map[assetPair]finding.Finding)
	for _, f := range ipOverlaps {
		surface, _ := f.Evidence["surface_asset"].(string)
		cloud, _ := f.Evidence["cloud_asset"].(string)
		if surface != "" && cloud != "" {
			ipPairs[assetPair{surface, cloud}] = f
		}
	}

	var results []finding.Finding
	seen := make(map[assetPair]bool)

	for _, sanF := range sanOverlaps {
		surface, _ := sanF.Evidence["surface_asset"].(string)
		cloud, _ := sanF.Evidence["cloud_asset"].(string)
		pair := assetPair{surface, cloud}
		if _, ok := ipPairs[pair]; !ok {
			continue
		}
		if seen[pair] {
			continue
		}
		seen[pair] = true

		ipF := ipPairs[pair]
		sharedIP, _ := ipF.Evidence["surface_ip"].(string)
		sanMatch, _ := sanF.Evidence["san_match"].(string)
		cloudResourceType, _ := ipF.Evidence["cloud_resource_type"].(string)

		results = append(results, finding.Finding{
			CheckID:  finding.CheckCorrelationCloudToSurface,
			Module:   "correlation",
			Scanner:  "asset_correlation",
			Severity: finding.SeverityMedium,
			Asset:    surface,
			Title:    fmt.Sprintf("Confirmed infrastructure link: %s \u2194 %s (IP + TLS SAN)", surface, cloud),
			Description: fmt.Sprintf(
				"The surface asset %s is confirmed to be served by cloud resource %s. "+
					"Two independent signals support this: shared IP address %s and TLS certificate "+
					"SAN entry '%s'. This composite correlation has high confidence. Advisory only.",
				surface, cloud, sharedIP, sanMatch,
			),
			Evidence: map[string]any{
				"surface_asset":       surface,
				"cloud_asset":         cloud,
				"cloud_resource_type": cloudResourceType,
				"shared_ip":           sharedIP,
				"san_match":           sanMatch,
				"match_type":          "composite_ip_and_san",
				"confidence":          "very_high",
				"signals":             []string{"ip_overlap", "tls_san_overlap"},
			},
			ProofCommand: fmt.Sprintf("dig +short %s && echo | openssl s_client -connect %s:443 -servername %s 2>/dev/null | openssl x509 -noout -ext subjectAltName", surface, surface, surface),
			DiscoveredAt: time.Now(),
		})
	}
	return results
}

// findSharedInfrastructure emits a finding when 2+ surface assets resolve to
// the same cloud resource IP, indicating shared backend infrastructure.
func findSharedInfrastructure(surfaceIPs map[string]surfaceIPEntry) []finding.Finding {
	// Reverse index: IP → list of surface assets.
	ipToAssets := make(map[string][]string)
	for _, entry := range surfaceIPs {
		for _, ip := range entry.ips {
			norm := normalizeIP(ip)
			ipToAssets[norm] = appendUnique(ipToAssets[norm], entry.asset)
		}
	}

	var results []finding.Finding
	seen := make(map[string]bool)

	// Deterministic iteration.
	sortedIPs := make([]string, 0, len(ipToAssets))
	for ip := range ipToAssets {
		sortedIPs = append(sortedIPs, ip)
	}
	sort.Strings(sortedIPs)

	for _, ip := range sortedIPs {
		assets := ipToAssets[ip]
		if len(assets) < 2 {
			continue
		}
		sort.Strings(assets)

		dedup := fmt.Sprintf("shared|%s|%s", ip, strings.Join(assets, ","))
		if seen[dedup] {
			continue
		}
		seen[dedup] = true

		results = append(results, finding.Finding{
			CheckID:  finding.CheckCorrelationSharedInfra,
			Module:   "correlation",
			Scanner:  "asset_correlation",
			Severity: finding.SeverityInfo,
			Asset:    assets[0],
			Title:    fmt.Sprintf("Shared infrastructure: %d assets on IP %s", len(assets), ip),
			Description: fmt.Sprintf(
				"%d surface assets resolve to the same IP address %s, indicating shared "+
					"backend infrastructure. Assets: %s. A vulnerability in the shared backend "+
					"could affect all of these assets. Advisory only.",
				len(assets), ip, joinAssets(assets),
			),
			Evidence: map[string]any{
				"shared_ip":    ip,
				"asset_count":  len(assets),
				"assets":       assets,
				"match_type":   "shared_infrastructure",
				"confidence":   "high",
			},
			ProofCommand: fmt.Sprintf("for d in %s; do echo \"$d: $(dig +short $d)\"; done", strings.Join(assets, " ")),
			DiscoveredAt: time.Now(),
		})
	}
	return results
}

// cdnHeaders are HTTP header keys and values that indicate a CDN is in front
// of the origin. When detected, confidence in direct IP↔cloud correlation
// should be reduced because the IP may belong to the CDN, not the origin.
var cdnIndicators = []struct {
	evidenceKey string
	substring   string
}{
	{"via", "cloudflare"},
	{"cf-ray", ""},     // presence of cf-ray header means Cloudflare
	{"x-cdn", ""},      // presence of x-cdn header means some CDN
	{"server", "cloudflare"},
	{"server", "cloudfront"},
	{"x-cache", ""},    // presence of x-cache usually means CDN
	{"x-amz-cf-id", ""}, // CloudFront
	{"x-served-by", "cache-"}, // Fastly
}

// applyCounterSignals scans surface findings for CDN indicators and annotates
// any correlation results for the same asset with counter-signal evidence
// and reduced stated confidence.
func applyCounterSignals(results []finding.Finding, surfaceFindings []finding.Finding) []finding.Finding {
	// Build a set of assets with CDN indicators.
	cdnAssets := make(map[string][]string) // asset → CDN signals found
	for _, f := range surfaceFindings {
		for _, ind := range cdnIndicators {
			if v, ok := f.Evidence[ind.evidenceKey]; ok {
				vs, isStr := v.(string)
				if ind.substring == "" {
					// Presence alone is sufficient.
					cdnAssets[f.Asset] = appendUnique(cdnAssets[f.Asset], ind.evidenceKey)
				} else if isStr && strings.Contains(strings.ToLower(vs), ind.substring) {
					cdnAssets[f.Asset] = appendUnique(cdnAssets[f.Asset],
						fmt.Sprintf("%s:%s", ind.evidenceKey, ind.substring))
				}
			}
		}
		// Also check for explicit CDN evidence keys.
		if cdn, ok := f.Evidence["cdn"].(string); ok && cdn != "" {
			cdnAssets[f.Asset] = appendUnique(cdnAssets[f.Asset], fmt.Sprintf("cdn:%s", cdn))
		}
		if cdn, ok := f.Evidence["cdn_detected"].(bool); ok && cdn {
			cdnAssets[f.Asset] = appendUnique(cdnAssets[f.Asset], "cdn_detected")
		}
	}

	if len(cdnAssets) == 0 {
		return results
	}

	// Build a new slice — never modify the input.
	out := make([]finding.Finding, len(results))
	for i, r := range results {
		signals, hasCDN := cdnAssets[r.Asset]
		if !hasCDN {
			out[i] = r
			continue
		}

		// Copy the finding and annotate with counter-signals.
		annotated := r
		newEvidence := make(map[string]any, len(r.Evidence)+2)
		for k, v := range r.Evidence {
			newEvidence[k] = v
		}
		newEvidence["counter_signals"] = signals
		// Reduce stated confidence when CDN is present.
		if _, ok := newEvidence["confidence"]; ok {
			newEvidence["confidence"] = "reduced_cdn_detected"
		}
		annotated.Evidence = newEvidence
		out[i] = annotated
	}
	return out
}

// --- Helper functions ---

// extractIPStrings extracts IP address strings from a value that may be
// a string, []string, []any, or comma-separated string.
func extractIPStrings(v any) []string {
	switch val := v.(type) {
	case string:
		// Could be a single IP or comma-separated list.
		parts := strings.Split(val, ",")
		var ips []string
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if net.ParseIP(p) != nil {
				ips = append(ips, p)
			}
		}
		return ips
	case []string:
		var ips []string
		for _, s := range val {
			if net.ParseIP(strings.TrimSpace(s)) != nil {
				ips = append(ips, strings.TrimSpace(s))
			}
		}
		return ips
	case []any:
		var ips []string
		for _, item := range val {
			if s, ok := item.(string); ok {
				if net.ParseIP(strings.TrimSpace(s)) != nil {
					ips = append(ips, strings.TrimSpace(s))
				}
			}
		}
		return ips
	}
	return nil
}

// extractCNAMEChains pulls CNAME chain values from finding evidence.
// Looks for keys: "cname_chain", "cnames", "cname".
func extractCNAMEChains(evidence map[string]any) []string {
	var chains []string
	for _, key := range []string{"cname_chain", "cnames", "cname"} {
		v, ok := evidence[key]
		if !ok {
			continue
		}
		switch val := v.(type) {
		case string:
			if val != "" {
				chains = append(chains, val)
			}
		case []string:
			chains = append(chains, val...)
		case []any:
			for _, item := range val {
				if s, ok := item.(string); ok && s != "" {
					chains = append(chains, s)
				}
			}
		}
	}
	return chains
}

// extractSANs pulls TLS Subject Alternative Name entries from finding evidence.
// Looks for keys: "sans", "tls_sans", "subject_alt_names".
func extractSANs(evidence map[string]any) []string {
	var sans []string
	for _, key := range []string{"sans", "tls_sans", "subject_alt_names"} {
		v, ok := evidence[key]
		if !ok {
			continue
		}
		switch val := v.(type) {
		case string:
			// Comma-separated list.
			for _, s := range strings.Split(val, ",") {
				s = strings.TrimSpace(s)
				if s != "" {
					sans = append(sans, s)
				}
			}
		case []string:
			sans = append(sans, val...)
		case []any:
			for _, item := range val {
				if s, ok := item.(string); ok && s != "" {
					sans = append(sans, s)
				}
			}
		}
	}
	return sans
}

// matchCloudCNAME returns the cloud provider name if the hostname matches
// a known cloud CNAME pattern, or empty string if no match.
func matchCloudCNAME(hostname string) string {
	lower := strings.ToLower(hostname)
	for _, p := range cloudCNAMEPatterns {
		if strings.Contains(lower, p.suffix) {
			return p.provider
		}
	}
	return ""
}

// normalizeIP returns the canonical string representation of an IP address.
func normalizeIP(s string) string {
	ip := net.ParseIP(s)
	if ip == nil {
		return s
	}
	return ip.String()
}

// isHostname returns true if the string looks like a hostname (contains a dot,
// is not an IP address).
func isHostname(s string) bool {
	if s == "" {
		return false
	}
	if net.ParseIP(s) != nil {
		return false
	}
	return strings.Contains(s, ".")
}

// appendUniqueIP appends IP strings to a slice, skipping duplicates after normalization.
func appendUniqueIP(existing []string, ips ...string) []string {
	seen := make(map[string]bool, len(existing))
	for _, ip := range existing {
		seen[normalizeIP(ip)] = true
	}
	for _, ip := range ips {
		norm := normalizeIP(ip)
		if !seen[norm] {
			seen[norm] = true
			existing = append(existing, ip)
		}
	}
	return existing
}

// appendUnique appends strings to a slice, skipping duplicates.
func appendUnique(existing []string, vals ...string) []string {
	seen := make(map[string]bool, len(existing))
	for _, s := range existing {
		seen[s] = true
	}
	for _, s := range vals {
		if !seen[s] {
			seen[s] = true
			existing = append(existing, s)
		}
	}
	return existing
}

// sortedMapKeys returns the keys of a map[string]surfaceIPEntry in sorted order.
func sortedMapKeys(m map[string]surfaceIPEntry) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
