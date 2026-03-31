package aws

import (
	"context"
	"fmt"
	"strings"
	"time"

	awscfg "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"

	"github.com/stormbane/beacon/internal/finding"
)

func scanCloudFront(ctx context.Context, cfg awscfg.Config, accountID, asset string) ([]finding.Finding, error) {
	svc := cloudfront.NewFromConfig(cfg)
	var findings []finding.Finding

	input := &cloudfront.ListDistributionsInput{}
	for {
		resp, err := svc.ListDistributions(ctx, input)
		if err != nil {
			if len(findings) == 0 {
				return nil, fmt.Errorf("list cloudfront distributions: %w", err)
			}
			break
		}
		if resp.DistributionList == nil {
			break
		}

		for _, dist := range resp.DistributionList.Items {
			distID := awscfg.ToString(dist.Id)
			domainName := awscfg.ToString(dist.DomainName)
			proofCmd := fmt.Sprintf("aws cloudfront get-distribution --id %s", distID)

			// Check 1: DefaultCacheBehavior allows HTTP (no HTTPS enforcement).
			if dist.DefaultCacheBehavior != nil {
				policy := string(dist.DefaultCacheBehavior.ViewerProtocolPolicy)
				if policy == "allow-all" {
					findings = append(findings, finding.Finding{
						CheckID: finding.CheckCloudAWSCloudFrontNoHTTPS,
						Title:   fmt.Sprintf("CloudFront distribution allows HTTP (no HTTPS enforcement): %s", distID),
						Description: fmt.Sprintf(
							"CloudFront distribution %s (%s) has ViewerProtocolPolicy set to 'allow-all', "+
								"which allows unencrypted HTTP connections. Clients can send sensitive data over "+
								"plaintext HTTP. Set ViewerProtocolPolicy to 'redirect-to-https' or 'https-only' "+
								"to enforce encrypted connections.",
							distID, domainName,
						),
						Severity:     finding.SeverityHigh,
						Asset:        asset,
						Scanner:      "cloud/aws",
						ProofCommand: proofCmd,
						Evidence: map[string]any{
							"account_id":              accountID,
							"resource_type":           "cloudfront_distribution",
							"distribution_id":         distID,
							"domain_name":             domainName,
							"viewer_protocol_policy":  policy,
						},
						DiscoveredAt: time.Now(),
					})
				}
			}

			// Check 2: No WAF associated.
			if awscfg.ToString(dist.WebACLId) == "" {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSCloudFrontNoWAF,
					Title:   fmt.Sprintf("CloudFront distribution has no WAF associated: %s", distID),
					Description: fmt.Sprintf(
						"CloudFront distribution %s (%s) does not have a WAF Web ACL associated. "+
							"Without WAF, the distribution is unprotected against common web exploits "+
							"(SQLi, XSS, bot traffic). Associate an AWS WAF Web ACL to filter malicious requests.",
						distID, domainName,
					),
					Severity:     finding.SeverityMedium,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: proofCmd,
					Evidence: map[string]any{
						"account_id":      accountID,
						"resource_type":   "cloudfront_distribution",
						"distribution_id": distID,
						"domain_name":     domainName,
					},
					DiscoveredAt: time.Now(),
				})
			}

			// Check 3: S3 origins without Origin Access Control or OAI.
			if dist.Origins != nil {
				for _, origin := range dist.Origins.Items {
					originDomain := awscfg.ToString(origin.DomainName)
					if !strings.Contains(originDomain, ".s3.") && !strings.HasSuffix(originDomain, ".s3.amazonaws.com") {
						continue
					}
					hasOAC := awscfg.ToString(origin.OriginAccessControlId) != ""
					hasOAI := origin.S3OriginConfig != nil &&
						awscfg.ToString(origin.S3OriginConfig.OriginAccessIdentity) != ""
					if !hasOAC && !hasOAI {
						findings = append(findings, finding.Finding{
							CheckID: finding.CheckCloudAWSCloudFrontNoOAC,
							Title:   fmt.Sprintf("CloudFront S3 origin without Origin Access Control: %s (%s)", distID, originDomain),
							Description: fmt.Sprintf(
								"CloudFront distribution %s has an S3 origin (%s) without Origin Access Control (OAC) "+
									"or Origin Access Identity (OAI) configured. Without OAC/OAI, the S3 bucket must "+
									"allow public access for CloudFront to serve content, exposing the bucket directly. "+
									"Configure an Origin Access Control to restrict S3 access to CloudFront only.",
								distID, originDomain,
							),
							Severity:     finding.SeverityMedium,
							Asset:        asset,
							Scanner:      "cloud/aws",
							ProofCommand: proofCmd,
							Evidence: map[string]any{
								"account_id":      accountID,
								"resource_type":   "cloudfront_distribution",
								"distribution_id": distID,
								"domain_name":     domainName,
								"origin_domain":   originDomain,
							},
							DiscoveredAt: time.Now(),
						})
					}
				}
			}

			// Check 4: Access logging not enabled.
			if dist.DefaultCacheBehavior != nil {
				// Logging is at the distribution config level, exposed as a Logging field.
				// In the ListDistributions summary, we don't get Logging details, so we
				// check via the distribution's top-level fields available in the summary.
				// The SDK DistributionSummary does not include Logging — we need to call
				// GetDistribution for a definitive check. However, to avoid N+1 API calls,
				// we check the summary-level indicator: if the distribution has no logging
				// bucket, logging is not configured.
				// Actually, the ListDistributions DistributionSummary does not include
				// Logging config. We need to describe each distribution for this check.
			}
			getResp, getErr := svc.GetDistribution(ctx, &cloudfront.GetDistributionInput{
				Id: dist.Id,
			})
			if getErr == nil && getResp.Distribution != nil && getResp.Distribution.DistributionConfig != nil {
				dc := getResp.Distribution.DistributionConfig

				// Check 4: Logging disabled.
				if dc.Logging == nil || !awscfg.ToBool(dc.Logging.Enabled) {
					findings = append(findings, finding.Finding{
						CheckID: finding.CheckCloudAWSCloudFrontNoLogging,
						Title:   fmt.Sprintf("CloudFront distribution does not have access logging enabled: %s", distID),
						Description: fmt.Sprintf(
							"CloudFront distribution %s (%s) does not have access logging enabled. "+
								"Without access logs, you cannot audit request patterns, detect abuse, "+
								"or perform forensic analysis. Enable standard or real-time logging to "+
								"an S3 bucket or Kinesis Data Stream.",
							distID, domainName,
						),
						Severity:     finding.SeverityMedium,
						Asset:        asset,
						Scanner:      "cloud/aws",
						ProofCommand: proofCmd,
						Evidence: map[string]any{
							"account_id":      accountID,
							"resource_type":   "cloudfront_distribution",
							"distribution_id": distID,
							"domain_name":     domainName,
						},
						DiscoveredAt: time.Now(),
					})
				}
			}

			// Check 5: Insecure TLS minimum protocol version.
			if dist.ViewerCertificate != nil {
				minProto := string(dist.ViewerCertificate.MinimumProtocolVersion)
				isSecure := strings.Contains(minProto, "TLSv1.2")
				if !isSecure && minProto != "" {
					findings = append(findings, finding.Finding{
						CheckID: finding.CheckCloudAWSCloudFrontInsecureTLS,
						Title:   fmt.Sprintf("CloudFront distribution uses insecure minimum TLS version: %s", distID),
						Description: fmt.Sprintf(
							"CloudFront distribution %s (%s) has MinimumProtocolVersion set to '%s', "+
								"which allows connections using deprecated or weak TLS versions. "+
								"Set MinimumProtocolVersion to TLSv1.2_2021 (or at minimum TLSv1.2_2018) "+
								"to ensure only modern, secure TLS connections are accepted.",
							distID, domainName, minProto,
						),
						Severity:     finding.SeverityHigh,
						Asset:        asset,
						Scanner:      "cloud/aws",
						ProofCommand: proofCmd,
						Evidence: map[string]any{
							"account_id":                accountID,
							"resource_type":             "cloudfront_distribution",
							"distribution_id":           distID,
							"domain_name":               domainName,
							"minimum_protocol_version":  minProto,
						},
						DiscoveredAt: time.Now(),
					})
				}
			}

			// Check 6: Using default CloudFront certificate instead of custom cert.
			if dist.ViewerCertificate != nil &&
				dist.ViewerCertificate.CloudFrontDefaultCertificate != nil &&
				*dist.ViewerCertificate.CloudFrontDefaultCertificate {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSCloudFrontDefaultCert,
					Title:   fmt.Sprintf("CloudFront distribution uses default *.cloudfront.net certificate: %s", distID),
					Description: fmt.Sprintf(
						"CloudFront distribution %s (%s) is using the default *.cloudfront.net SSL certificate "+
							"instead of a custom certificate. This means the distribution is served from a "+
							"*.cloudfront.net domain rather than a branded custom domain, which can reduce "+
							"user trust and prevent use of custom domain names with HTTPS.",
						distID, domainName,
					),
					Severity:     finding.SeverityLow,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: proofCmd,
					Evidence: map[string]any{
						"account_id":      accountID,
						"resource_type":   "cloudfront_distribution",
						"distribution_id": distID,
						"domain_name":     domainName,
					},
					DiscoveredAt: time.Now(),
				})
			}
		}

		if resp.DistributionList.NextMarker == nil || !awscfg.ToBool(resp.DistributionList.IsTruncated) {
			break
		}
		input.Marker = resp.DistributionList.NextMarker
	}

	return findings, nil
}
