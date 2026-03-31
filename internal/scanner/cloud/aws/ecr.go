package aws

import (
	"context"
	"fmt"
	"strings"
	"time"

	awscfg "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"

	"github.com/stormbane/beacon/internal/finding"
)

func scanECR(ctx context.Context, cfg awscfg.Config, accountID, region, asset string) ([]finding.Finding, error) {
	svc := ecr.NewFromConfig(cfg)
	var findings []finding.Finding

	paginator := ecr.NewDescribeRepositoriesPaginator(svc, &ecr.DescribeRepositoriesInput{})
	for paginator.HasMorePages() {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		page, err := paginator.NextPage(ctx)
		if err != nil {
			if len(findings) == 0 {
				return nil, fmt.Errorf("describe ecr repositories: %w", err)
			}
			break
		}
		for _, repo := range page.Repositories {
			repoName := awscfg.ToString(repo.RepositoryName)
			repoARN := awscfg.ToString(repo.RepositoryArn)

			// Check if image scanning on push is disabled.
			if repo.ImageScanningConfiguration == nil || !repo.ImageScanningConfiguration.ScanOnPush {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSECRNoScanning,
					Title:   fmt.Sprintf("ECR repository does not have image scanning enabled: %s", repoName),
					Description: fmt.Sprintf(
						"ECR repository %s in %s does not have scan-on-push enabled. Without image "+
							"scanning, container images with known CVEs can be deployed undetected. "+
							"Enable ScanOnPush in the repository image scanning configuration.",
						repoName, region,
					),
					Severity:     finding.SeverityMedium,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: fmt.Sprintf("aws ecr describe-repositories --repository-names %s --region %s --query 'repositories[].imageScanningConfiguration'", repoName, region),
					Evidence: map[string]any{
						"account_id":    accountID,
						"repository":    repoName,
						"repository_arn": repoARN,
						"region":        region,
						"resource_type": "ecr_repository",
					},
					DiscoveredAt: time.Now(),
				})
			}

			// Check if image tag mutability is set to MUTABLE (supply chain risk).
			if repo.ImageTagMutability == ecrtypes.ImageTagMutabilityMutable {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSECRMutableTags,
					Title:   fmt.Sprintf("ECR repository allows mutable image tags: %s", repoName),
					Description: fmt.Sprintf(
						"ECR repository %s in %s has image tag mutability set to MUTABLE. This allows "+
							"existing tagged images to be overwritten, enabling supply chain attacks where "+
							"an attacker pushes a malicious image under a trusted tag (e.g. 'latest' or 'v1.0'). "+
							"Set image tag mutability to IMMUTABLE to prevent tag overwrites.",
						repoName, region,
					),
					Severity:     finding.SeverityHigh,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: fmt.Sprintf("aws ecr describe-repositories --repository-names %s --region %s --query 'repositories[].imageTagMutability'", repoName, region),
					Evidence: map[string]any{
						"account_id":        accountID,
						"repository":        repoName,
						"repository_arn":    repoARN,
						"region":            region,
						"resource_type":     "ecr_repository",
						"tag_mutability":    string(repo.ImageTagMutability),
					},
					DiscoveredAt: time.Now(),
				})
			}

			// Check for public access via repository policy.
			policyResp, err := svc.GetRepositoryPolicy(ctx, &ecr.GetRepositoryPolicyInput{
				RepositoryName: repo.RepositoryName,
			})
			if err != nil {
				// RepositoryPolicyNotFoundException means no policy = not public.
				// Any other error (permissions, transient) — skip.
				continue
			}
			policyText := awscfg.ToString(policyResp.PolicyText)
			if strings.Contains(policyText, `"Principal":"*"`) ||
				strings.Contains(policyText, `"Principal": "*"`) ||
				strings.Contains(policyText, `"AWS":"*"`) ||
				strings.Contains(policyText, `"AWS": "*"`) {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSECRPublic,
					Title:   fmt.Sprintf("ECR repository has a public access policy: %s", repoName),
					Description: fmt.Sprintf(
						"ECR repository %s in %s has a resource policy that grants access to Principal \"*\". "+
							"This allows any AWS account (or unauthenticated users) to pull images from the "+
							"repository, potentially exposing proprietary code and secrets baked into container "+
							"images. Restrict the policy to specific trusted AWS accounts or IAM principals.",
						repoName, region,
					),
					Severity:     finding.SeverityHigh,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: fmt.Sprintf("aws ecr get-repository-policy --repository-name %s --region %s", repoName, region),
					Evidence: map[string]any{
						"account_id":    accountID,
						"repository":    repoName,
						"repository_arn": repoARN,
						"region":        region,
						"resource_type": "ecr_repository",
					},
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return findings, nil
}
