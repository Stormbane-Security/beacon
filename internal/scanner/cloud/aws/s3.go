package aws

import (
	"context"
	"fmt"
	"time"

	awscfg "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/stormbane/beacon/internal/finding"
)

func scanS3(ctx context.Context, cfg awscfg.Config, accountID, asset string) ([]finding.Finding, error) {
	svc := s3.NewFromConfig(cfg)

	var findings []finding.Finding
	paginator := s3.NewListBucketsPaginator(svc, &s3.ListBucketsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if len(findings) == 0 {
				return nil, fmt.Errorf("list buckets: %w", err)
			}
			break
		}
		for _, bucket := range page.Buckets {
			name := awscfg.ToString(bucket.Name)

			// Check public access block.
			pab, err := svc.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
				Bucket: bucket.Name,
			})
			if err != nil {
				// If NoSuchPublicAccessBlockConfiguration — public access block not configured.
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSS3BucketPublic,
					Title:   fmt.Sprintf("S3 bucket has no public access block configuration: %s", name),
					Description: fmt.Sprintf(
						"S3 bucket %s does not have a Public Access Block configuration. "+
							"Without this, bucket policies or ACLs can expose the bucket to public access. "+
							"Enable all four Public Access Block settings on the bucket and at the account level.",
						name,
					),
					Severity:     finding.SeverityHigh,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: fmt.Sprintf("aws s3api get-public-access-block --bucket %s", name),
					Evidence:     map[string]any{"bucket": name, "account_id": accountID},
					DiscoveredAt: time.Now(),
				})
				continue
			}

			// Check if any public access block setting is false.
			if pab.PublicAccessBlockConfiguration != nil {
				c := pab.PublicAccessBlockConfiguration
				if !awscfg.ToBool(c.BlockPublicAcls) || !awscfg.ToBool(c.BlockPublicPolicy) ||
					!awscfg.ToBool(c.IgnorePublicAcls) || !awscfg.ToBool(c.RestrictPublicBuckets) {
					findings = append(findings, finding.Finding{
						CheckID: finding.CheckCloudAWSS3BucketPublic,
						Title:   fmt.Sprintf("S3 bucket public access block is not fully enabled: %s", name),
						Description: fmt.Sprintf(
							"S3 bucket %s has partial Public Access Block settings. One or more of "+
								"BlockPublicAcls/BlockPublicPolicy/IgnorePublicAcls/RestrictPublicBuckets is false. "+
								"Enable all four settings to prevent public exposure.",
							name,
						),
						Severity:     finding.SeverityHigh,
						Asset:        asset,
						Scanner:      "cloud/aws",
						ProofCommand: fmt.Sprintf("aws s3api get-public-access-block --bucket %s", name),
						Evidence: map[string]any{
							"bucket":                  name,
							"account_id":              accountID,
							"block_public_acls":       awscfg.ToBool(c.BlockPublicAcls),
							"block_public_policy":     awscfg.ToBool(c.BlockPublicPolicy),
							"ignore_public_acls":      awscfg.ToBool(c.IgnorePublicAcls),
							"restrict_public_buckets": awscfg.ToBool(c.RestrictPublicBuckets),
						},
						DiscoveredAt: time.Now(),
					})
				}
			}

			// Check encryption.
			enc, err := svc.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: bucket.Name})
			if err != nil || enc.ServerSideEncryptionConfiguration == nil ||
				len(enc.ServerSideEncryptionConfiguration.Rules) == 0 {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSS3NoEncryption,
					Title:   fmt.Sprintf("S3 bucket does not enforce server-side encryption: %s", name),
					Description: fmt.Sprintf(
						"S3 bucket %s does not have a default encryption configuration. "+
							"Data written to the bucket is stored unencrypted unless the uploader specifies "+
							"encryption. Enable AES-256 or AWS KMS default encryption.",
						name,
					),
					Severity:     finding.SeverityMedium,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: fmt.Sprintf("aws s3api get-bucket-encryption --bucket %s", name),
					Evidence:     map[string]any{"bucket": name, "account_id": accountID},
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return findings, nil
}
