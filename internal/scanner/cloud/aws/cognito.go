package aws

import (
	"context"
	"fmt"
	"time"

	awscfg "github.com/aws/aws-sdk-go-v2/aws"
	cognitoidp "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	cognitotypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"

	"github.com/stormbane-security/beacon/internal/finding"
)

func scanCognito(ctx context.Context, cfg awscfg.Config, accountID, region, asset string) ([]finding.Finding, error) {
	svc := cognitoidp.NewFromConfig(cfg)
	var findings []finding.Finding

	// List user pools (paginated via NextToken).
	var nextToken *string
	firstPage := true
	for {
		input := &cognitoidp.ListUserPoolsInput{
			MaxResults: awscfg.Int32(60),
		}
		if nextToken != nil {
			input.NextToken = nextToken
		}
		resp, err := svc.ListUserPools(ctx, input)
		if err != nil {
			if firstPage {
				return nil, fmt.Errorf("list user pools: %w", err)
			}
			break
		}
		firstPage = false

		for _, pool := range resp.UserPools {
			poolID := awscfg.ToString(pool.Id)
			poolName := awscfg.ToString(pool.Name)

			// Describe the user pool to get full configuration.
			desc, descErr := svc.DescribeUserPool(ctx, &cognitoidp.DescribeUserPoolInput{
				UserPoolId: pool.Id,
			})
			if descErr != nil || desc.UserPool == nil {
				continue
			}
			up := desc.UserPool

			// Check MFA configuration.
			if up.MfaConfiguration == cognitotypes.UserPoolMfaTypeOff {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSCognitoNoMFA,
					Title:   fmt.Sprintf("Cognito user pool without MFA enabled: %s", poolName),
					Description: fmt.Sprintf(
						"Cognito user pool %s (%s) in %s has MFA disabled. Without multi-factor "+
							"authentication, compromised credentials alone grant full account access. "+
							"Enable MFA (OPTIONAL or REQUIRED) to add a second authentication factor.",
						poolName, poolID, region,
					),
					Severity:     finding.SeverityHigh,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: fmt.Sprintf("aws cognito-idp describe-user-pool --user-pool-id %s --region %s --query 'UserPool.MfaConfiguration'", poolID, region),
					Evidence: map[string]any{
						"account_id":        accountID,
						"region":            region,
						"resource_type":     "cognito_user_pool",
						"pool_id":           poolID,
						"pool_name":         poolName,
						"mfa_configuration": string(up.MfaConfiguration),
					},
					DiscoveredAt: time.Now(),
				})
			}

			// Check password policy.
			if up.Policies != nil && up.Policies.PasswordPolicy != nil {
				pp := up.Policies.PasswordPolicy
				minLen := awscfg.ToInt32(pp.MinimumLength)
				missingChars := !pp.RequireUppercase || !pp.RequireLowercase ||
					!pp.RequireNumbers || !pp.RequireSymbols
				if minLen < 12 || missingChars {
					findings = append(findings, finding.Finding{
						CheckID: finding.CheckCloudAWSCognitoWeakPassword,
						Title:   fmt.Sprintf("Cognito user pool with weak password policy: %s", poolName),
						Description: fmt.Sprintf(
							"Cognito user pool %s (%s) in %s has a weak password policy "+
								"(minimum length %d, missing character requirements). A minimum length "+
								"of 12 characters with uppercase, lowercase, numbers, and symbols is "+
								"recommended to resist brute-force and credential-stuffing attacks.",
							poolName, poolID, region, minLen,
						),
						Severity:     finding.SeverityMedium,
						Asset:        asset,
						Scanner:      "cloud/aws",
						ProofCommand: fmt.Sprintf("aws cognito-idp describe-user-pool --user-pool-id %s --region %s --query 'UserPool.Policies.PasswordPolicy'", poolID, region),
						Evidence: map[string]any{
							"account_id":        accountID,
							"region":            region,
							"resource_type":     "cognito_user_pool",
							"pool_id":           poolID,
							"pool_name":         poolName,
							"min_length":        minLen,
							"require_uppercase": pp.RequireUppercase,
							"require_lowercase": pp.RequireLowercase,
							"require_numbers":   pp.RequireNumbers,
							"require_symbols":   pp.RequireSymbols,
						},
						DiscoveredAt: time.Now(),
					})
				}
			}

			// Check advanced security features.
			noAdvancedSecurity := up.UserPoolAddOns == nil ||
				up.UserPoolAddOns.AdvancedSecurityMode == cognitotypes.AdvancedSecurityModeTypeOff
			if noAdvancedSecurity {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSCognitoNoAdvancedSecurity,
					Title:   fmt.Sprintf("Cognito user pool without advanced security features: %s", poolName),
					Description: fmt.Sprintf(
						"Cognito user pool %s (%s) in %s does not have advanced security features "+
							"enabled. Advanced security provides adaptive authentication, compromised "+
							"credential detection, and risk-based adaptive responses. Enable advanced "+
							"security mode (AUDIT or ENFORCED) for stronger account protection.",
						poolName, poolID, region,
					),
					Severity:     finding.SeverityMedium,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: fmt.Sprintf("aws cognito-idp describe-user-pool --user-pool-id %s --region %s --query 'UserPool.UserPoolAddOns'", poolID, region),
					Evidence: map[string]any{
						"account_id":    accountID,
						"region":        region,
						"resource_type": "cognito_user_pool",
						"pool_id":       poolID,
						"pool_name":     poolName,
					},
					DiscoveredAt: time.Now(),
				})
			}
		}

		if resp.NextToken == nil {
			break
		}
		nextToken = resp.NextToken
	}

	return findings, nil
}
