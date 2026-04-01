package aws

import (
	"context"
	"fmt"
	"time"

	awscfg "github.com/aws/aws-sdk-go-v2/aws"
	route53 "github.com/aws/aws-sdk-go-v2/service/route53"

	"github.com/stormbane-security/beacon/internal/finding"
)

func scanRoute53(ctx context.Context, cfg awscfg.Config, accountID, region, asset string) ([]finding.Finding, error) {
	svc := route53.NewFromConfig(cfg)
	var findings []finding.Finding

	// List all hosted zones (paginated via marker).
	var marker *string
	firstPage := true
	for {
		input := &route53.ListHostedZonesInput{}
		if marker != nil {
			input.Marker = marker
		}
		resp, err := svc.ListHostedZones(ctx, input)
		if err != nil {
			if firstPage {
				return nil, fmt.Errorf("list hosted zones: %w", err)
			}
			break
		}
		firstPage = false

		for _, zone := range resp.HostedZones {
			// Only check public hosted zones.
			if zone.Config != nil && zone.Config.PrivateZone {
				continue
			}

			zoneID := awscfg.ToString(zone.Id)
			zoneName := awscfg.ToString(zone.Name)

			// Check DNSSEC signing status.
			dnssec, dnssecErr := svc.GetDNSSEC(ctx, &route53.GetDNSSECInput{
				HostedZoneId: zone.Id,
			})
			if dnssecErr == nil && dnssec.Status != nil {
				status := awscfg.ToString(dnssec.Status.ServeSignature)
				if status != "SIGNING" {
					findings = append(findings, finding.Finding{
						CheckID: finding.CheckCloudAWSRoute53NoDNSSEC,
						Title:   fmt.Sprintf("Route 53 hosted zone without DNSSEC signing: %s", zoneName),
						Description: fmt.Sprintf(
							"Route 53 hosted zone %s (%s) does not have DNSSEC signing enabled. "+
								"Without DNSSEC, DNS responses can be spoofed by an attacker to redirect "+
								"traffic to malicious servers. Enable DNSSEC signing to cryptographically "+
								"protect DNS responses.",
							zoneName, zoneID,
						),
						Severity:     finding.SeverityMedium,
						Asset:        asset,
						Scanner:      "cloud/aws",
						ProofCommand: fmt.Sprintf("aws route53 get-dnssec --hosted-zone-id %s", zoneID),
						Evidence: map[string]any{
							"account_id":    accountID,
							"region":        region,
							"resource_type": "route53_hosted_zone",
							"zone_id":       zoneID,
							"zone_name":     zoneName,
							"dnssec_status": status,
						},
						DiscoveredAt: time.Now(),
					})
				}
			}

			// Check DNS query logging.
			qlResp, qlErr := svc.ListQueryLoggingConfigs(ctx, &route53.ListQueryLoggingConfigsInput{
				HostedZoneId: zone.Id,
			})
			if qlErr == nil && len(qlResp.QueryLoggingConfigs) == 0 {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSRoute53NoQueryLogging,
					Title:   fmt.Sprintf("Route 53 hosted zone without DNS query logging: %s", zoneName),
					Description: fmt.Sprintf(
						"Route 53 hosted zone %s (%s) does not have DNS query logging configured. "+
							"Without query logging, DNS resolution patterns and potential exfiltration "+
							"via DNS tunneling leave no audit trail. Enable query logging to a CloudWatch "+
							"Logs group for visibility into DNS queries.",
						zoneName, zoneID,
					),
					Severity:     finding.SeverityLow,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: fmt.Sprintf("aws route53 list-query-logging-configs --hosted-zone-id %s", zoneID),
					Evidence: map[string]any{
						"account_id":    accountID,
						"region":        region,
						"resource_type": "route53_hosted_zone",
						"zone_id":       zoneID,
						"zone_name":     zoneName,
					},
					DiscoveredAt: time.Now(),
				})
			}
		}

		if !resp.IsTruncated {
			break
		}
		marker = resp.NextMarker
	}

	return findings, nil
}
