package aws

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	awscfg "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/stormbane-security/beacon/internal/finding"
)

// scanIAMMFA checks customer-managed IAM policies for missing MFA conditions.
// Policies that grant broad or administrative access without requiring
// aws:MultiFactorAuthPresent allow privilege escalation with stolen credentials alone.
func scanIAMMFA(ctx context.Context, cfg awscfg.Config, accountID, asset string) ([]finding.Finding, error) {
	svc := iam.NewFromConfig(cfg)
	var findings []finding.Finding

	// Administrative policy names/patterns that should require MFA.
	adminPatterns := []string{
		"Admin", "admin",
		"PowerUser", "poweruser",
		"FullAccess", "fullaccess",
	}

	policyPaginator := iam.NewListPoliciesPaginator(svc, &iam.ListPoliciesInput{
		Scope: iamtypes.PolicyScopeTypeLocal, // customer-managed only
	})
	for policyPaginator.HasMorePages() {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		page, err := policyPaginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, policy := range page.Policies {
			policyName := awscfg.ToString(policy.PolicyName)

			// Only check policies with admin/power-user-like names or
			// that we can confirm grant broad access.
			isAdminLike := false
			for _, pattern := range adminPatterns {
				if strings.Contains(policyName, pattern) {
					isAdminLike = true
					break
				}
			}

			// Get the default version to inspect the document.
			versionResp, err := svc.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
				PolicyArn: policy.Arn,
				VersionId: policy.DefaultVersionId,
			})
			if err != nil || versionResp.PolicyVersion == nil {
				continue
			}

			rawDoc := awscfg.ToString(versionResp.PolicyVersion.Document)
			doc, _ := url.QueryUnescape(rawDoc)
			if doc == "" {
				doc = rawDoc
			}

			// Check if the policy grants broad access (Action:* or broad actions).
			hasWildcardAction := strings.Contains(doc, `"Action":"*"`) ||
				strings.Contains(doc, `"Action": "*"`) ||
				strings.Contains(doc, `"Action":["*"]`) ||
				strings.Contains(doc, `"Action": ["*"]`)
			hasBroadAccess := hasWildcardAction || isAdminLike

			if !hasBroadAccess {
				continue
			}

			// Check if the policy requires MFA.
			hasMFACondition := strings.Contains(doc, "aws:MultiFactorAuthPresent") ||
				strings.Contains(doc, "aws:MultiFactorAuthAge")

			if hasMFACondition {
				continue
			}

			findings = append(findings, finding.Finding{
				CheckID: finding.CheckCloudAWSIAMMFANotEnforced,
				Title:   fmt.Sprintf("AWS IAM policy allows access without MFA: %s", policyName),
				Description: fmt.Sprintf(
					"Customer-managed IAM policy %s grants broad or administrative access "+
						"without requiring aws:MultiFactorAuthPresent as a condition. Without MFA "+
						"enforcement in the policy, compromised long-lived credentials (access keys) "+
						"alone are sufficient to exercise the policy's permissions. Add a Condition "+
						"block requiring aws:MultiFactorAuthPresent=true for all sensitive actions.",
					policyName,
				),
				Severity:     finding.SeverityHigh,
				Asset:        asset,
				Scanner:      "cloud/aws",
				ProofCommand: fmt.Sprintf("aws iam get-policy-version --policy-arn %s --version-id %s --query 'PolicyVersion.Document'", awscfg.ToString(policy.Arn), awscfg.ToString(policy.DefaultVersionId)),
				Evidence: map[string]any{
					"account_id":    accountID,
					"policy_name":   policyName,
					"policy_arn":    awscfg.ToString(policy.Arn),
					"resource_type": "iam_policy",
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings, nil
}
