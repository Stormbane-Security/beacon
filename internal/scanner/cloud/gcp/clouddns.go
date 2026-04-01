package gcp

import (
	"context"
	"fmt"
	"strings"
	"time"

	dns "google.golang.org/api/dns/v1"
	"google.golang.org/api/option"

	"github.com/stormbane-security/beacon/internal/finding"
)

func scanCloudDNS(ctx context.Context, projectID, asset string, opts []option.ClientOption) ([]finding.Finding, error) {
	svc, err := dns.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("dns service: %w", err)
	}

	var findings []finding.Finding

	var pageToken string
	for {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		call := svc.ManagedZones.List(projectID).Context(ctx)
		if pageToken != "" {
			call = call.PageToken(pageToken)
		}
		resp, err := call.Do()
		if err != nil {
			break // Non-fatal: Cloud DNS API may not be enabled.
		}

		for _, zone := range resp.ManagedZones {
			findings = append(findings, checkDNSSEC(zone, projectID, asset)...)
		}

		if resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
	}

	return findings, nil
}

// checkDNSSEC checks if a public Cloud DNS managed zone has DNSSEC enabled.
func checkDNSSEC(zone *dns.ManagedZone, projectID, asset string) []finding.Finding {
	// Only check public zones — private zones are internal and don't benefit from DNSSEC.
	if strings.EqualFold(zone.Visibility, "private") {
		return nil
	}

	// DNSSEC is enabled when DnssecConfig.State is "on".
	if zone.DnssecConfig != nil && strings.EqualFold(zone.DnssecConfig.State, "on") {
		return nil
	}

	return []finding.Finding{{
		CheckID: finding.CheckCloudGCPDNSNoDNSSEC,
		Title:   fmt.Sprintf("Cloud DNS managed zone without DNSSEC: %s", zone.Name),
		Description: fmt.Sprintf(
			"Cloud DNS managed zone %s (%s) in project %s does not have DNSSEC enabled. "+
				"Without DNSSEC, DNS responses can be spoofed via cache poisoning attacks, "+
				"allowing attackers to redirect traffic to malicious servers. "+
				"Enable DNSSEC on the managed zone to cryptographically sign DNS records.",
			zone.Name, zone.DnsName, projectID,
		),
		Severity:     finding.SeverityMedium,
		Asset:        asset,
		Scanner:      "cloud/gcp",
		ProofCommand: fmt.Sprintf("gcloud dns managed-zones describe %s --project=%s --format='get(dnssecConfig.state)'", zone.Name, projectID),
		Evidence: map[string]any{
			"zone":          zone.Name,
			"dns_name":      zone.DnsName,
			"resource_type": "cloud_dns_zone",
			"project_id":    projectID,
			"visibility":    zone.Visibility,
		},
		DiscoveredAt: time.Now(),
	}}
}
