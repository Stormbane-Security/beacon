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
	sgPaginator := ec2.NewDescribeSecurityGroupsPaginator(svc, &ec2.DescribeSecurityGroupsInput{})
	for sgPaginator.HasMorePages() {
		page, err := sgPaginator.NextPage(ctx)
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

	// Check EC2 instances for IMDSv1 (HttpTokens != "required").
	// IMDSv1 is vulnerable to SSRF-based credential theft because it does not
	// require a session token for metadata requests.
	instPaginator := ec2.NewDescribeInstancesPaginator(svc, &ec2.DescribeInstancesInput{})
	for instPaginator.HasMorePages() {
		page, err := instPaginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, reservation := range page.Reservations {
			for _, inst := range reservation.Instances {
				if inst.MetadataOptions == nil {
					continue
				}
				if string(inst.MetadataOptions.HttpTokens) != "required" {
					instanceID := awscfg.ToString(inst.InstanceId)
					var instSnapshot string
					if b, merr := json.Marshal(inst.MetadataOptions); merr == nil {
						instSnapshot = string(b)
					}
					findings = append(findings, finding.Finding{
						CheckID: finding.CheckCloudAWSEC2IMDSv1,
						Title:   fmt.Sprintf("EC2 instance accepts IMDSv1 (SSRF credential theft risk): %s", instanceID),
						Description: fmt.Sprintf(
							"EC2 instance %s in %s has HttpTokens set to '%s' instead of 'required'. "+
								"IMDSv1 allows any process to retrieve instance credentials via a simple GET "+
								"to http://169.254.169.254/. An SSRF vulnerability can steal IAM credentials. "+
								"Enforce IMDSv2 by setting HttpTokens=required.",
							instanceID, region, inst.MetadataOptions.HttpTokens,
						),
						Severity:     finding.SeverityHigh,
						Asset:        asset,
						Scanner:      "cloud/aws",
						ProofCommand: fmt.Sprintf("aws ec2 describe-instances --instance-ids %s --region %s --query 'Reservations[].Instances[].MetadataOptions'", instanceID, region),
						Evidence: map[string]any{
							"account_id":        accountID,
							"instance_id":       instanceID,
							"region":            region,
							"resource_type":     "ec2_instance",
							"http_tokens":       string(inst.MetadataOptions.HttpTokens),
							"resource_snapshot": instSnapshot,
						},
						DiscoveredAt: time.Now(),
					})
				}
			}
		}
	}

	// Check for unencrypted EBS volumes.
	// Unencrypted volumes expose data at rest if the underlying storage is
	// physically compromised or snapshots are shared.
	volPaginator := ec2.NewDescribeVolumesPaginator(svc, &ec2.DescribeVolumesInput{})
	for volPaginator.HasMorePages() {
		page, err := volPaginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, vol := range page.Volumes {
			if vol.Encrypted != nil && !*vol.Encrypted {
				volumeID := awscfg.ToString(vol.VolumeId)
				// Collect attached instance IDs.
				var attachedInstances []string
				for _, att := range vol.Attachments {
					attachedInstances = append(attachedInstances, awscfg.ToString(att.InstanceId))
				}
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSEBSUnencrypted,
					Title:   fmt.Sprintf("EBS volume is not encrypted: %s", volumeID),
					Description: fmt.Sprintf(
						"EBS volume %s in %s is not encrypted at rest. Unencrypted volumes expose "+
							"data if the underlying storage is compromised or snapshots are shared "+
							"across accounts. Enable encryption on all EBS volumes using AWS-managed "+
							"or customer-managed KMS keys.",
						volumeID, region,
					),
					Severity:     finding.SeverityMedium,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: fmt.Sprintf("aws ec2 describe-volumes --volume-ids %s --region %s --query 'Volumes[].{VolumeId:VolumeId,Encrypted:Encrypted}'", volumeID, region),
					Evidence: map[string]any{
						"account_id":         accountID,
						"volume_id":          volumeID,
						"region":             region,
						"resource_type":      "ebs_volume",
						"attached_instances": attachedInstances,
					},
					DiscoveredAt: time.Now(),
				})
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
