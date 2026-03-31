package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	awscfg "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

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
				// Only flag if the error indicates no block is configured.
				// Permission errors (AccessDenied, etc.) should not generate false positives.
				errMsg := err.Error()
				if !strings.Contains(errMsg, "NoSuchPublicAccessBlockConfiguration") &&
					!strings.Contains(errMsg, "NoSuchPublicAccessBlock") {
					continue // permission error or transient — skip this bucket
				}
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
			enc, encErr := svc.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: bucket.Name})
			noEncryption := false
			if encErr != nil {
				encMsg := encErr.Error()
				if strings.Contains(encMsg, "ServerSideEncryptionConfigurationNotFoundError") ||
					strings.Contains(encMsg, "NoSuchEncryption") {
					noEncryption = true
				}
				// Permission errors (AccessDenied) — skip, don't flag as missing.
			} else if enc.ServerSideEncryptionConfiguration == nil ||
				len(enc.ServerSideEncryptionConfiguration.Rules) == 0 {
				noEncryption = true
			}
			if noEncryption {
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

			// Check versioning.
			ver, verErr := svc.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: bucket.Name})
			if verErr == nil && ver.Status != s3types.BucketVersioningStatusEnabled {
				findings = append(findings, finding.Finding{
					CheckID:     finding.CheckCloudAWSS3NoVersioning,
					Title:       fmt.Sprintf("S3 bucket does not have versioning enabled: %s", name),
					Description: fmt.Sprintf("S3 bucket %s does not have versioning enabled. Without versioning, accidental or malicious deletions and overwrites are permanent. Enable versioning to maintain a complete history of object changes.", name),
					Severity:    finding.SeverityMedium,
					Asset:       asset, Scanner: "cloud/aws",
					ProofCommand: fmt.Sprintf("aws s3api get-bucket-versioning --bucket %s", name),
					Evidence:     map[string]any{"bucket": name, "account_id": accountID, "status": string(ver.Status)},
					DiscoveredAt: time.Now(),
				})
			}

			// Check server access logging.
			log, logErr := svc.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{Bucket: bucket.Name})
			if logErr == nil && log.LoggingEnabled == nil {
				findings = append(findings, finding.Finding{
					CheckID:     finding.CheckCloudAWSS3NoLogging,
					Title:       fmt.Sprintf("S3 bucket does not have server access logging: %s", name),
					Description: fmt.Sprintf("S3 bucket %s does not have server access logging enabled. Access logs record all requests made to the bucket, which are critical for security auditing, forensics, and compliance. Enable server access logging to a separate logging bucket.", name),
					Severity:    finding.SeverityMedium,
					Asset:       asset, Scanner: "cloud/aws",
					ProofCommand: fmt.Sprintf("aws s3api get-bucket-logging --bucket %s", name),
					Evidence:     map[string]any{"bucket": name, "account_id": accountID},
					DiscoveredAt: time.Now(),
				})
			}

			// Check bucket policy for SSL-only enforcement.
			pol, polErr := svc.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: bucket.Name})
			hasSSLOnly := false
			if polErr == nil && pol.Policy != nil {
				// Parse the policy JSON and look for a Deny statement with
				// Condition.Bool["aws:SecureTransport"] == "false", which is the
				// standard pattern for enforcing SSL-only access.
				type policyStatement struct {
					Effect    string                            `json:"Effect"`
					Condition map[string]map[string]interface{} `json:"Condition"`
				}
				type bucketPolicy struct {
					Statement []policyStatement `json:"Statement"`
				}
				var bp bucketPolicy
				if err := json.Unmarshal([]byte(*pol.Policy), &bp); err == nil {
					for _, stmt := range bp.Statement {
						if stmt.Effect == "Deny" {
							if boolCond, ok := stmt.Condition["Bool"]; ok {
								if val, ok := boolCond["aws:SecureTransport"]; ok {
									if valStr, ok := val.(string); ok && valStr == "false" {
										hasSSLOnly = true
									}
								}
							}
						}
					}
				}
			}
			if !hasSSLOnly {
				findings = append(findings, finding.Finding{
					CheckID:     finding.CheckCloudAWSS3NoSSLOnly,
					Title:       fmt.Sprintf("S3 bucket policy does not enforce SSL-only access: %s", name),
					Description: fmt.Sprintf("S3 bucket %s does not have a bucket policy denying non-SSL (HTTP) requests. Without this policy, data can be transmitted in plaintext. Add a bucket policy with Effect:Deny and Condition aws:SecureTransport=false.", name),
					Severity:    finding.SeverityHigh,
					Asset:       asset, Scanner: "cloud/aws",
					ProofCommand: fmt.Sprintf("aws s3api get-bucket-policy --bucket %s", name),
					Evidence:     map[string]any{"bucket": name, "account_id": accountID},
					DiscoveredAt: time.Now(),
				})
			}

			// Check lifecycle configuration.
			lc, lcErr := svc.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{Bucket: bucket.Name})
			if lcErr != nil || lc.Rules == nil || len(lc.Rules) == 0 {
				// Only flag if the error is "no lifecycle" (not permission denied).
				isNoLifecycle := lcErr != nil && (strings.Contains(lcErr.Error(), "NoSuchLifecycleConfiguration") || strings.Contains(lcErr.Error(), "NoSuchLifecycle"))
				if isNoLifecycle || (lcErr == nil && (lc.Rules == nil || len(lc.Rules) == 0)) {
					findings = append(findings, finding.Finding{
						CheckID:     finding.CheckCloudAWSS3NoLifecycle,
						Title:       fmt.Sprintf("S3 bucket has no lifecycle configuration: %s", name),
						Description: fmt.Sprintf("S3 bucket %s does not have a lifecycle policy configured. Lifecycle policies automate transitioning objects to cheaper storage tiers and expiring old data, reducing costs and limiting data exposure window.", name),
						Severity:    finding.SeverityLow,
						Asset:       asset, Scanner: "cloud/aws",
						ProofCommand: fmt.Sprintf("aws s3api get-bucket-lifecycle-configuration --bucket %s", name),
						Evidence:     map[string]any{"bucket": name, "account_id": accountID},
						DiscoveredAt: time.Now(),
					})
				}
			}
		}
	}

	return findings, nil
}
