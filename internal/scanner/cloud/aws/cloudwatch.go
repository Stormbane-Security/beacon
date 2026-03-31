package aws

import (
	"context"
	"fmt"
	"time"

	awscfg "github.com/aws/aws-sdk-go-v2/aws"
	cloudwatchlogs "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"

	"github.com/stormbane/beacon/internal/finding"
)

func scanCloudWatch(ctx context.Context, cfg awscfg.Config, accountID, region, asset string) ([]finding.Finding, error) {
	svc := cloudwatchlogs.NewFromConfig(cfg)
	var findings []finding.Finding

	paginator := cloudwatchlogs.NewDescribeLogGroupsPaginator(svc, &cloudwatchlogs.DescribeLogGroupsInput{})
	firstPage := true
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if firstPage {
				return nil, fmt.Errorf("describe log groups: %w", err)
			}
			break
		}
		firstPage = false

		for _, lg := range page.LogGroups {
			logGroupName := awscfg.ToString(lg.LogGroupName)

			// Check KMS encryption.
			if lg.KmsKeyId == nil || awscfg.ToString(lg.KmsKeyId) == "" {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSCloudWatchLogNoEncryption,
					Title:   fmt.Sprintf("CloudWatch log group without KMS encryption: %s", logGroupName),
					Description: fmt.Sprintf(
						"CloudWatch log group %s in %s does not have KMS encryption configured. "+
							"Without KMS encryption, log data is encrypted with the default CloudWatch "+
							"encryption which does not provide customer-managed key control. Associate "+
							"a KMS key for stronger data protection and key management.",
						logGroupName, region,
					),
					Severity:     finding.SeverityMedium,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: fmt.Sprintf("aws logs describe-log-groups --log-group-name-prefix %s --region %s --query 'logGroups[].{name:logGroupName,kmsKeyId:kmsKeyId}'", logGroupName, region),
					Evidence: map[string]any{
						"account_id":     accountID,
						"region":         region,
						"resource_type":  "cloudwatch_log_group",
						"log_group_name": logGroupName,
					},
					DiscoveredAt: time.Now(),
				})
			}

			// Check retention period.
			// RetentionInDays == nil or 0 means logs never expire (which is acceptable).
			// Values > 0 and < 90 are a finding.
			retentionDays := int32(0)
			if lg.RetentionInDays != nil {
				retentionDays = *lg.RetentionInDays
			}
			if retentionDays > 0 && retentionDays < 90 {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSCloudWatchLogShortRetention,
					Title:   fmt.Sprintf("CloudWatch log group with short retention (%d days): %s", retentionDays, logGroupName),
					Description: fmt.Sprintf(
						"CloudWatch log group %s in %s has a retention period of %d days, "+
							"which is less than the recommended 90 days. Short retention periods "+
							"may result in loss of log data needed for security investigations, "+
							"compliance audits, or incident response. Set retention to at least 90 days.",
						logGroupName, region, retentionDays,
					),
					Severity:     finding.SeverityLow,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: fmt.Sprintf("aws logs describe-log-groups --log-group-name-prefix %s --region %s --query 'logGroups[].{name:logGroupName,retentionInDays:retentionInDays}'", logGroupName, region),
					Evidence: map[string]any{
						"account_id":      accountID,
						"region":          region,
						"resource_type":   "cloudwatch_log_group",
						"log_group_name":  logGroupName,
						"retention_days":  retentionDays,
					},
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return findings, nil
}
