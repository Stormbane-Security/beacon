package aws

import (
	"context"
	"fmt"
	"strings"
	"time"

	awscfg "github.com/aws/aws-sdk-go-v2/aws"
	ssm "github.com/aws/aws-sdk-go-v2/service/ssm"

	"github.com/stormbane/beacon/internal/finding"
)

func scanSSM(ctx context.Context, cfg awscfg.Config, accountID, region, asset string) ([]finding.Finding, error) {
	svc := ssm.NewFromConfig(cfg)
	var findings []finding.Finding

	paginator := ssm.NewDescribeParametersPaginator(svc, &ssm.DescribeParametersInput{})
	firstPage := true
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if firstPage {
				return nil, fmt.Errorf("describe parameters: %w", err)
			}
			break
		}
		firstPage = false

		for _, param := range page.Parameters {
			paramName := awscfg.ToString(param.Name)
			paramType := string(param.Type)

			// Only flag non-SecureString parameters whose names suggest secrets.
			if paramType == "SecureString" {
				continue
			}

			if looksLikeSecret(paramName) {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSSSMParamNoEncryption,
					Title:   fmt.Sprintf("SSM parameter with secret-like name is not encrypted: %s", paramName),
					Description: fmt.Sprintf(
						"SSM parameter %s in %s is stored as type '%s' instead of 'SecureString'. "+
							"The parameter name suggests it may contain sensitive data (password, secret, "+
							"key, token, or credential). Unencrypted parameters are stored in plaintext "+
							"and visible to anyone with ssm:GetParameter permission. Use SecureString type "+
							"to encrypt the value with KMS.",
						paramName, region, paramType,
					),
					Severity:     finding.SeverityHigh,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: fmt.Sprintf("aws ssm describe-parameters --filters Key=Name,Values=%s --region %s --query 'Parameters[].{Name:Name,Type:Type}'", paramName, region),
					Evidence: map[string]any{
						"account_id":    accountID,
						"region":        region,
						"resource_type": "ssm_parameter",
						"param_name":    paramName,
						"param_type":    paramType,
					},
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return findings, nil
}

// looksLikeSecret returns true if the parameter name contains a keyword
// suggesting it holds sensitive data.
func looksLikeSecret(name string) bool {
	lower := strings.ToLower(name)
	keywords := []string{"password", "secret", "key", "token", "credential"}
	for _, kw := range keywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}
