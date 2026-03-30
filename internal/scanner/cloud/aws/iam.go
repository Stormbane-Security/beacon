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

	"github.com/stormbane/beacon/internal/finding"
)

func scanIAM(ctx context.Context, cfg awscfg.Config, accountID, asset string) ([]finding.Finding, error) {
	svc := iam.NewFromConfig(cfg)
	var findings []finding.Finding

	// Check for root account access keys.
	summary, err := svc.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err == nil {
		if v, ok := summary.SummaryMap["AccountAccessKeysPresent"]; ok && v > 0 {
			findings = append(findings, finding.Finding{
				CheckID: finding.CheckCloudAWSIAMRootAccessKey,
				Title:   "AWS root account has active access keys",
				Description: "The AWS root account has programmatic access keys. Root account keys have " +
					"unrestricted access to all AWS services and cannot be restricted with IAM policies. " +
					"Delete root access keys and use IAM users or roles for all programmatic access. " +
					"Enable MFA on the root account.",
				Severity:     finding.SeverityCritical,
				Asset:        asset,
				Scanner:      "cloud/aws",
				ProofCommand: fmt.Sprintf("aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent' --profile %s", accountID),
				Evidence:     map[string]any{"account_id": accountID, "resource_type": "iam_user"},
				DiscoveredAt: time.Now(),
			})
		}

		// Check MFA on root.
		if v, ok := summary.SummaryMap["AccountMFAEnabled"]; ok && v == 0 {
			findings = append(findings, finding.Finding{
				CheckID:      finding.CheckCloudAWSIAMRootNoMFA,
				Title:        "AWS root account does not have MFA enabled",
				Description:  "The AWS root account does not have multi-factor authentication enabled. Root account compromise without MFA provides unrestricted access to the entire AWS organization. Enable hardware MFA on the root account immediately.",
				Severity:     finding.SeverityCritical,
				Asset:        asset,
				Scanner:      "cloud/aws",
				ProofCommand: "aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled'",
				Evidence:     map[string]any{"account_id": accountID, "resource_type": "iam_user"},
				DiscoveredAt: time.Now(),
			})
		}
	}

	// Check IAM users: MFA and access key age.
	paginator := iam.NewListUsersPaginator(svc, &iam.ListUsersInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, user := range page.Users {
			userName := awscfg.ToString(user.UserName)

			// Check MFA.
			mfaResp, err := svc.ListMFADevices(ctx, &iam.ListMFADevicesInput{UserName: user.UserName})
			if err == nil && len(mfaResp.MFADevices) == 0 {
				// Only flag users with console access (have a login profile).
				_, loginErr := svc.GetLoginProfile(ctx, &iam.GetLoginProfileInput{UserName: user.UserName})
				if loginErr == nil {
					findings = append(findings, finding.Finding{
						CheckID: finding.CheckCloudAWSIAMUserNoMFA,
						Title:   fmt.Sprintf("AWS IAM user has console access but no MFA: %s", userName),
						Description: fmt.Sprintf(
							"IAM user %s has console access enabled but no MFA device configured. "+
								"Without MFA, a compromised password grants full console access. "+
								"Enable MFA for all IAM users with console access, or migrate to SSO/Identity Center.",
							userName,
						),
						Severity:     finding.SeverityHigh,
						Asset:        asset,
						Scanner:      "cloud/aws",
						ProofCommand: fmt.Sprintf("aws iam list-mfa-devices --user-name %s", userName),
						Evidence:     map[string]any{"account_id": accountID, "user_name": userName, "resource_type": "iam_user"},
						DiscoveredAt: time.Now(),
					})
				}
			}

			// Check access key age.
			keysResp, err := svc.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: user.UserName})
			if err == nil {
				for _, key := range keysResp.AccessKeyMetadata {
					if key.Status == iamtypes.StatusTypeActive && key.CreateDate != nil {
						age := time.Since(*key.CreateDate)
						if age > 90*24*time.Hour {
							keyID := awscfg.ToString(key.AccessKeyId)
							findings = append(findings, finding.Finding{
								CheckID: finding.CheckCloudAWSIAMAccessKeyOld,
								Title:   fmt.Sprintf("AWS IAM access key older than 90 days: %s (%s)", userName, keyID),
								Description: fmt.Sprintf(
									"IAM user %s has an active access key (ID: %s) created %d days ago. "+
										"Long-lived access keys increase the blast radius of a credential leak. "+
										"Rotate keys every 90 days or migrate to IAM roles / Identity Center.",
									userName, keyID, int(age.Hours()/24),
								),
								Severity:     finding.SeverityMedium,
								Asset:        asset,
								Scanner:      "cloud/aws",
								ProofCommand: fmt.Sprintf("aws iam list-access-keys --user-name %s", userName),
								Evidence: map[string]any{
									"account_id":    accountID,
									"user_name":     userName,
									"key_id":        keyID,
									"age_days":      int(age.Hours() / 24),
									"created":       key.CreateDate.Format(time.RFC3339),
									"resource_type": "iam_user",
								},
								DiscoveredAt: time.Now(),
							})
						}
					}
				}
			}
		}
	}

	// Check managed policies for wildcard actions/resources.
	policyPaginator := iam.NewListPoliciesPaginator(svc, &iam.ListPoliciesInput{
		Scope: iamtypes.PolicyScopeTypeLocal, // customer-managed only
	})
	for policyPaginator.HasMorePages() {
		page, err := policyPaginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, policy := range page.Policies {
			// Get the default version to inspect the document.
			versionResp, err := svc.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
				PolicyArn: policy.Arn,
				VersionId: policy.DefaultVersionId,
			})
			if err != nil || versionResp.PolicyVersion == nil {
				continue
			}
			// AWS returns the policy document URL-encoded (RFC 3986).
			rawDoc := awscfg.ToString(versionResp.PolicyVersion.Document)
			doc, _ := url.QueryUnescape(rawDoc)
			if doc == "" {
				doc = rawDoc // fallback to raw if unescape fails
			}
			if strings.Contains(doc, `"Action":"*"`) && strings.Contains(doc, `"Resource":"*"`) ||
				strings.Contains(doc, `"Action": "*"`) && strings.Contains(doc, `"Resource": "*"`) {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSIAMPolicyWildcard,
					Title:   fmt.Sprintf("AWS IAM policy grants * on *: %s", awscfg.ToString(policy.PolicyName)),
					Description: fmt.Sprintf(
						"Customer-managed IAM policy %s contains Action:* with Resource:*. "+
							"This effectively grants administrator access to any principal the policy is attached to. "+
							"Replace with specific actions and resources following least privilege.",
						awscfg.ToString(policy.PolicyName),
					),
					Severity:     finding.SeverityHigh,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: fmt.Sprintf("aws iam get-policy-version --policy-arn %s --version-id %s", awscfg.ToString(policy.Arn), awscfg.ToString(policy.DefaultVersionId)),
					Evidence: map[string]any{
						"account_id":    accountID,
						"policy_name":   awscfg.ToString(policy.PolicyName),
						"policy_arn":    awscfg.ToString(policy.Arn),
						"resource_type": "iam_policy",
					},
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return findings, nil
}
