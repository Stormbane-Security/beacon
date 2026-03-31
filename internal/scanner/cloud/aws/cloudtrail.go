package aws

import (
	"context"
	"fmt"
	"time"

	awscfg "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"

	"github.com/stormbane/beacon/internal/finding"
)

func scanCloudTrail(ctx context.Context, cfg awscfg.Config, accountID, region, asset string) ([]finding.Finding, error) {
	svc := cloudtrail.NewFromConfig(cfg)
	var findings []finding.Finding

	resp, err := svc.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{
		IncludeShadowTrails: awscfg.Bool(false),
	})
	if err != nil {
		return nil, fmt.Errorf("describe trails: %w", err)
	}

	// Track whether at least one multi-region trail is actively logging.
	hasActiveMultiRegionTrail := false

	for _, trail := range resp.TrailList {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		trailName := awscfg.ToString(trail.Name)
		trailARN := awscfg.ToString(trail.TrailARN)

		// Get trail status to determine if it is actively logging.
		status, err := svc.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{
			Name: trail.TrailARN,
		})
		isLogging := err == nil && awscfg.ToBool(status.IsLogging)

		if trail.IsMultiRegionTrail != nil && *trail.IsMultiRegionTrail && isLogging {
			hasActiveMultiRegionTrail = true
		}

		// Check if trail logs are not encrypted with KMS.
		if awscfg.ToString(trail.KmsKeyId) == "" {
			findings = append(findings, finding.Finding{
				CheckID: finding.CheckCloudAWSCloudTrailNoEncryption,
				Title:   fmt.Sprintf("CloudTrail trail is not encrypted with KMS: %s", trailName),
				Description: fmt.Sprintf(
					"CloudTrail trail %s does not have KMS encryption configured. Without KMS "+
						"encryption, trail logs are protected only by S3 default encryption (AES-256). "+
						"KMS encryption provides additional access controls via key policies and "+
						"enables audit of log access through CloudTrail KMS events. Configure a "+
						"KMS key for the trail.",
					trailName,
				),
				Severity:     finding.SeverityMedium,
				Asset:        asset,
				Scanner:      "cloud/aws",
				ProofCommand: fmt.Sprintf("aws cloudtrail describe-trails --trail-name-list %s --query 'trailList[].{Name:Name,KmsKeyId:KmsKeyId}'", trailARN),
				Evidence: map[string]any{
					"account_id":    accountID,
					"trail_name":    trailName,
					"trail_arn":     trailARN,
					"region":        region,
					"resource_type": "cloudtrail",
				},
				DiscoveredAt: time.Now(),
			})
		}

		// Check if log file validation is disabled.
		if trail.LogFileValidationEnabled == nil || !*trail.LogFileValidationEnabled {
			findings = append(findings, finding.Finding{
				CheckID: finding.CheckCloudAWSCloudTrailNoValidation,
				Title:   fmt.Sprintf("CloudTrail log file validation is disabled: %s", trailName),
				Description: fmt.Sprintf(
					"CloudTrail trail %s does not have log file integrity validation enabled. "+
						"Without validation, an attacker who gains access to the S3 bucket can modify "+
						"or delete log files without detection. Enable log file validation to generate "+
						"digest files that allow verification of log integrity.",
					trailName,
				),
				Severity:     finding.SeverityMedium,
				Asset:        asset,
				Scanner:      "cloud/aws",
				ProofCommand: fmt.Sprintf("aws cloudtrail describe-trails --trail-name-list %s --query 'trailList[].{Name:Name,LogFileValidationEnabled:LogFileValidationEnabled}'", trailARN),
				Evidence: map[string]any{
					"account_id":    accountID,
					"trail_name":    trailName,
					"trail_arn":     trailARN,
					"region":        region,
					"resource_type": "cloudtrail",
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	// If no multi-region trail is actively logging, emit a critical finding.
	if !hasActiveMultiRegionTrail {
		findings = append(findings, finding.Finding{
			CheckID: finding.CheckCloudAWSNoCloudTrail,
			Title:   "No active multi-region CloudTrail trail found",
			Description: "No CloudTrail trail with multi-region logging enabled and actively recording was found. " +
				"Without CloudTrail, API calls across the AWS account are not logged, making it impossible " +
				"to detect unauthorized access, privilege escalation, or data exfiltration. Create a " +
				"multi-region trail that logs all management events to an S3 bucket with restricted access.",
			Severity:     finding.SeverityCritical,
			Asset:        asset,
			Scanner:      "cloud/aws",
			ProofCommand: "aws cloudtrail describe-trails --query 'trailList[].{Name:Name,IsMultiRegionTrail:IsMultiRegionTrail}'",
			Evidence: map[string]any{
				"account_id":    accountID,
				"region":        region,
				"resource_type": "cloudtrail",
				"trail_count":   len(resp.TrailList),
			},
			DiscoveredAt: time.Now(),
		})
	}

	return findings, nil
}
