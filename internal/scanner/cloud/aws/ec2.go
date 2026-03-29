package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	awscfg "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"

	"github.com/stormbane/beacon/internal/finding"
)

func scanEC2(ctx context.Context, cfg awscfg.Config, accountID, region, asset string) ([]finding.Finding, error) {
	svc := ec2.NewFromConfig(cfg)
	var findings []finding.Finding

	// Find security groups with 0.0.0.0/0 ingress on sensitive ports.
	paginator := ec2.NewDescribeSecurityGroupsPaginator(svc, &ec2.DescribeSecurityGroupsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, sg := range page.SecurityGroups {
			for _, perm := range sg.IpPermissions {
				for _, ipRange := range perm.IpRanges {
					if awscfg.ToString(ipRange.CidrIp) == "0.0.0.0/0" {
						fromPort := awscfg.ToInt32(perm.FromPort)
						toPort := awscfg.ToInt32(perm.ToPort)
						// Flag broadly open rules on sensitive ports.
						if isSensitivePort(fromPort, toPort) {
							var sgSnapshot string
							if b, merr := json.Marshal(sg); merr == nil {
								if len(b) > 32768 {
									b = b[:32768]
								}
								sgSnapshot = string(b)
							}
							findings = append(findings, finding.Finding{
								CheckID: finding.CheckCloudAWSEC2PublicSG,
								Title:   fmt.Sprintf("AWS security group allows 0.0.0.0/0 on sensitive port: %s (%d-%d)", awscfg.ToString(sg.GroupName), fromPort, toPort),
								Description: fmt.Sprintf(
									"Security group %s (%s) in %s allows inbound traffic from any IP "+
										"(0.0.0.0/0) on port %d-%d. Restrict this rule to specific trusted CIDRs.",
									awscfg.ToString(sg.GroupName), awscfg.ToString(sg.GroupId), region, fromPort, toPort,
								),
								Severity:     finding.SeverityHigh,
								Asset:        asset,
								Scanner:      "cloud/aws",
								ProofCommand: fmt.Sprintf("aws ec2 describe-security-groups --group-ids %s --region %s", awscfg.ToString(sg.GroupId), region),
								Evidence: map[string]any{
									"account_id":        accountID,
									"sg_id":             awscfg.ToString(sg.GroupId),
									"sg_name":           awscfg.ToString(sg.GroupName),
									"from_port":         fromPort,
									"to_port":           toPort,
									"region":            region,
									"resource_type":     "security_group",
									"resource_snapshot": sgSnapshot,
								},
								DiscoveredAt: time.Now(),
							})
						}
					}
				}
			}
		}
	}

	return findings, nil
}

func isSensitivePort(from, to int32) bool {
	sensitive := []int32{22, 3389, 5432, 3306, 27017, 6379, 9200, 8080, 8443, 2375, 2376}
	for _, p := range sensitive {
		if from <= p && p <= to {
			return true
		}
	}
	// Also flag entire port range open.
	return from == 0 && to == 65535
}
