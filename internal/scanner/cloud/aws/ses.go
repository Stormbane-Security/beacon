package aws

import (
	"context"
	"fmt"
	"time"

	awscfg "github.com/aws/aws-sdk-go-v2/aws"
	ses "github.com/aws/aws-sdk-go-v2/service/sesv2"

	"github.com/stormbane/beacon/internal/finding"
)

func scanSES(ctx context.Context, cfg awscfg.Config, accountID, region, asset string) ([]finding.Finding, error) {
	svc := ses.NewFromConfig(cfg)
	var findings []finding.Finding

	var nextToken *string
	for {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		input := &ses.ListEmailIdentitiesInput{}
		if nextToken != nil {
			input.NextToken = nextToken
		}

		resp, err := svc.ListEmailIdentities(ctx, input)
		if err != nil {
			if len(findings) == 0 {
				return nil, fmt.Errorf("list ses email identities: %w", err)
			}
			break
		}

		for _, identity := range resp.EmailIdentities {
			identityName := awscfg.ToString(identity.IdentityName)

			// Get the full identity details to check DKIM status.
			detail, err := svc.GetEmailIdentity(ctx, &ses.GetEmailIdentityInput{
				EmailIdentity: identity.IdentityName,
			})
			if err != nil {
				continue
			}

			// Check DKIM verification status.
			dkimVerified := false
			if detail.DkimAttributes != nil {
				if string(detail.DkimAttributes.Status) == "SUCCESS" {
					dkimVerified = true
				}
			}
			if !dkimVerified {
				var dkimStatus string
				if detail.DkimAttributes != nil {
					dkimStatus = string(detail.DkimAttributes.Status)
				}
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSSESNoDKIM,
					Title:   fmt.Sprintf("SES identity does not have verified DKIM: %s", identityName),
					Description: fmt.Sprintf(
						"SES identity %s in %s does not have DKIM verification in a SUCCESS state (current: %s). "+
							"Without DKIM, emails sent from this identity are more likely to be marked as spam or "+
							"spoofed. DKIM provides cryptographic authentication of the sending domain, improving "+
							"deliverability and preventing email spoofing. Enable and verify DKIM for this identity.",
						identityName, region, dkimStatus,
					),
					Severity:     finding.SeverityMedium,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: fmt.Sprintf("aws sesv2 get-email-identity --email-identity %s --region %s --query 'DkimAttributes.Status'", identityName, region),
					Evidence: map[string]any{
						"account_id":    accountID,
						"identity_name": identityName,
						"dkim_status":   dkimStatus,
						"region":        region,
						"resource_type": "ses_identity",
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
