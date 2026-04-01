package aws

import (
	"context"
	"fmt"
	"strings"
	"time"

	awscfg "github.com/aws/aws-sdk-go-v2/aws"
	wafv2 "github.com/aws/aws-sdk-go-v2/service/wafv2"
	wafv2types "github.com/aws/aws-sdk-go-v2/service/wafv2/types"

	"github.com/stormbane-security/beacon/internal/finding"
)

func scanWAF(ctx context.Context, cfg awscfg.Config, accountID, region, asset string) ([]finding.Finding, error) {
	svc := wafv2.NewFromConfig(cfg)
	var findings []finding.Finding

	resp, err := svc.ListWebACLs(ctx, &wafv2.ListWebACLsInput{
		Scope: wafv2types.ScopeRegional,
	})
	if err != nil {
		return nil, fmt.Errorf("list web acls: %w", err)
	}

	if len(resp.WebACLs) == 0 {
		findings = append(findings, finding.Finding{
			CheckID: finding.CheckCloudAWSWAFNoWebACL,
			Title:   fmt.Sprintf("No WAF web ACLs configured in region %s", region),
			Description: fmt.Sprintf(
				"No AWS WAF web ACLs are configured in region %s. Without WAF, web applications "+
					"are directly exposed to common web attacks including SQL injection, XSS, and "+
					"request flooding. Deploy WAF web ACLs with managed rule groups to protect "+
					"internet-facing resources.",
				region,
			),
			Severity:     finding.SeverityMedium,
			Asset:        asset,
			Scanner:      "cloud/aws",
			ProofCommand: fmt.Sprintf("aws wafv2 list-web-acls --scope REGIONAL --region %s", region),
			Evidence: map[string]any{
				"account_id":    accountID,
				"region":        region,
				"resource_type": "waf_web_acl",
			},
			DiscoveredAt: time.Now(),
		})
		return findings, nil
	}

	// Check each ACL for logging configuration.
	for _, acl := range resp.WebACLs {
		aclName := awscfg.ToString(acl.Name)
		aclARN := awscfg.ToString(acl.ARN)

		_, logErr := svc.GetLoggingConfiguration(ctx, &wafv2.GetLoggingConfigurationInput{
			ResourceArn: acl.ARN,
		})
		if logErr != nil {
			// If the error indicates no logging config, emit finding.
			// WAFNonexistentItemException means no logging is configured.
			errMsg := logErr.Error()
			if strings.Contains(errMsg, "WAFNonexistentItemException") ||
				strings.Contains(errMsg, "not found") ||
				strings.Contains(errMsg, "does not exist") {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSWAFNoLogging,
					Title:   fmt.Sprintf("WAF web ACL without logging enabled: %s", aclName),
					Description: fmt.Sprintf(
						"WAF web ACL %s in %s does not have logging enabled. Without logging, "+
							"blocked and allowed requests are not recorded, making it impossible "+
							"to investigate attacks, tune rules, or meet compliance requirements. "+
							"Enable logging to S3, CloudWatch Logs, or Kinesis Data Firehose.",
						aclName, region,
					),
					Severity:     finding.SeverityMedium,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: fmt.Sprintf("aws wafv2 get-logging-configuration --resource-arn %s --region %s", aclARN, region),
					Evidence: map[string]any{
						"account_id":    accountID,
						"region":        region,
						"resource_type": "waf_web_acl",
						"acl_name":      aclName,
						"acl_arn":       aclARN,
					},
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return findings, nil
}
