package analyze

import (
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/stormbane/beacon/internal/playbook"
	"github.com/stormbane/beacon/internal/store"
)

// BuildSanitizedMetrics converts raw ScannerMetrics and AssetExecutions for a
// completed scan into sanitized form with all PII removed.
//
// Removed: domain names, hostnames, IP addresses, error message text.
// Retained: scanner name, tech category (e.g. "nginx"), matched playbook name,
// timing, severity counts, error flag, skipped flag.
//
// The resulting records are safe to aggregate across all customers/domains
// and are used by beacon analyze to surface cross-domain scanner patterns.
func BuildSanitizedMetrics(metrics []store.ScannerMetric, executions []store.AssetExecution) []store.SanitizedScannerMetric {
	// Build an asset → tech category and asset → playbook map from executions.
	assetTech := make(map[string]string, len(executions))
	assetPlaybook := make(map[string]string, len(executions))
	for _, ex := range executions {
		assetTech[ex.Asset] = techCategoryFromEvidence(ex.Evidence)
		if len(ex.MatchedPlaybooks) > 0 {
			assetPlaybook[ex.Asset] = ex.MatchedPlaybooks[0]
		} else {
			assetPlaybook[ex.Asset] = "none"
		}
	}

	out := make([]store.SanitizedScannerMetric, 0, len(metrics))
	for _, m := range metrics {
		tech := assetTech[m.Asset]
		if tech == "" {
			tech = "host"
		}
		pb := assetPlaybook[m.Asset]
		if pb == "" {
			pb = "none"
		}
		out = append(out, store.SanitizedScannerMetric{
			ID:               uuid.NewString(),
			ScannerName:      m.ScannerName,
			TechCategory:     tech,
			PlaybookName:     pb,
			DurationMs:       m.DurationMs,
			FindingsCritical: m.FindingsCritical,
			FindingsHigh:     m.FindingsHigh,
			FindingsMedium:   m.FindingsMedium,
			FindingsLow:      m.FindingsLow,
			FindingsInfo:     m.FindingsInfo,
			// Preserve the error count (non-zero = had errors) but drop the message.
			ErrorCount: m.ErrorCount,
			Skipped:    m.Skipped,
			CreatedAt:  time.Now().UTC(),
		})
	}
	return out
}

// techCategoryFromEvidence returns a short technology label derived from
// fingerprinting evidence. No hostname, domain, or IP is included.
func techCategoryFromEvidence(ev playbook.Evidence) string {
	// Web server banner is the most specific signal.
	if ws := ev.ServiceVersions["web_server"]; ws != "" {
		if i := strings.IndexAny(ws, "/ "); i > 0 {
			return ws[:i]
		}
		return ws
	}
	// CDN via CNAME chain.
	for _, cname := range ev.CNAMEChain {
		lower := strings.ToLower(cname)
		switch {
		case strings.Contains(lower, "cloudfront"):
			return "CloudFront"
		case strings.Contains(lower, "cloudflare"):
			return "Cloudflare"
		case strings.Contains(lower, "akamai"):
			return "Akamai"
		case strings.Contains(lower, "fastly"):
			return "Fastly"
		case strings.Contains(lower, "azureedge"):
			return "Azure CDN"
		}
	}
	// CDN via ASN.
	asnLower := strings.ToLower(ev.ASNOrg)
	switch {
	case strings.Contains(asnLower, "cloudflare"):
		return "Cloudflare"
	case strings.Contains(asnLower, "amazon"):
		return "AWS"
	case strings.Contains(asnLower, "google"):
		return "GCP"
	case strings.Contains(asnLower, "microsoft") || strings.Contains(asnLower, "azure"):
		return "Azure"
	case strings.Contains(asnLower, "fastly"):
		return "Fastly"
	case strings.Contains(asnLower, "akamai"):
		return "Akamai"
	}
	if ev.StatusCode > 0 {
		return "web"
	}
	return "host"
}
