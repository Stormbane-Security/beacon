package aws

import (
	"context"
	"fmt"
	"time"

	awscfg "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"

	"github.com/stormbane-security/beacon/internal/finding"
)

func scanOpenSearch(ctx context.Context, cfg awscfg.Config, accountID, region, asset string) ([]finding.Finding, error) {
	svc := opensearch.NewFromConfig(cfg)
	var findings []finding.Finding

	listResp, err := svc.ListDomainNames(ctx, &opensearch.ListDomainNamesInput{})
	if err != nil {
		return nil, fmt.Errorf("list opensearch domains: %w", err)
	}

	for _, domainInfo := range listResp.DomainNames {
		name := awscfg.ToString(domainInfo.DomainName)
		proofCmd := fmt.Sprintf("aws opensearch describe-domain --domain-name %s --region %s", name, region)

		desc, err := svc.DescribeDomain(ctx, &opensearch.DescribeDomainInput{
			DomainName: domainInfo.DomainName,
		})
		if err != nil || desc.DomainStatus == nil {
			continue
		}
		domain := desc.DomainStatus

		// Check 1: Publicly accessible domain (not in VPC and has an endpoint).
		if domain.VPCOptions == nil && awscfg.ToString(domain.Endpoint) != "" {
			findings = append(findings, finding.Finding{
				CheckID: finding.CheckCloudAWSOpenSearchPublic,
				Title:   fmt.Sprintf("OpenSearch domain is publicly accessible: %s", name),
				Description: fmt.Sprintf(
					"OpenSearch domain %s in %s has a public endpoint (%s) and is not deployed within a VPC. "+
						"A publicly accessible OpenSearch domain exposes data to the internet and is vulnerable "+
						"to unauthorized access, data exfiltration, and brute-force attacks. Deploy the domain "+
						"within a VPC and restrict access using security groups and IAM policies.",
					name, region, awscfg.ToString(domain.Endpoint),
				),
				Severity:     finding.SeverityCritical,
				Asset:        asset,
				Scanner:      "cloud/aws",
				ProofCommand: proofCmd,
				Evidence: map[string]any{
					"account_id":    accountID,
					"region":        region,
					"resource_type": "opensearch_domain",
					"domain_name":   name,
					"endpoint":      awscfg.ToString(domain.Endpoint),
				},
				DiscoveredAt: time.Now(),
			})
		}

		// Check 2: Encryption at rest not enabled.
		if domain.EncryptionAtRestOptions == nil ||
			domain.EncryptionAtRestOptions.Enabled == nil ||
			!*domain.EncryptionAtRestOptions.Enabled {
			findings = append(findings, finding.Finding{
				CheckID: finding.CheckCloudAWSOpenSearchNoEncRest,
				Title:   fmt.Sprintf("OpenSearch domain does not have encryption at rest enabled: %s", name),
				Description: fmt.Sprintf(
					"OpenSearch domain %s in %s does not have encryption at rest enabled. "+
						"Data stored in the domain (indices, automated snapshots, logs) is unencrypted, "+
						"exposing it to risk if the underlying storage is compromised. Enable encryption "+
						"at rest using an AWS KMS key.",
					name, region,
				),
				Severity:     finding.SeverityMedium,
				Asset:        asset,
				Scanner:      "cloud/aws",
				ProofCommand: proofCmd,
				Evidence: map[string]any{
					"account_id":    accountID,
					"region":        region,
					"resource_type": "opensearch_domain",
					"domain_name":   name,
				},
				DiscoveredAt: time.Now(),
			})
		}

		// Check 3: Node-to-node encryption not enabled.
		if domain.NodeToNodeEncryptionOptions == nil ||
			domain.NodeToNodeEncryptionOptions.Enabled == nil ||
			!*domain.NodeToNodeEncryptionOptions.Enabled {
			findings = append(findings, finding.Finding{
				CheckID: finding.CheckCloudAWSOpenSearchNoEncTransit,
				Title:   fmt.Sprintf("OpenSearch domain does not have node-to-node encryption enabled: %s", name),
				Description: fmt.Sprintf(
					"OpenSearch domain %s in %s does not have node-to-node encryption enabled. "+
						"Without this, inter-node communication within the cluster is unencrypted, "+
						"allowing potential eavesdropping on data replication and internal queries. "+
						"Enable node-to-node encryption to protect data in transit within the cluster.",
					name, region,
				),
				Severity:     finding.SeverityHigh,
				Asset:        asset,
				Scanner:      "cloud/aws",
				ProofCommand: proofCmd,
				Evidence: map[string]any{
					"account_id":    accountID,
					"region":        region,
					"resource_type": "opensearch_domain",
					"domain_name":   name,
				},
				DiscoveredAt: time.Now(),
			})
		}

		// Check 4: Domain not in a VPC.
		if domain.VPCOptions == nil {
			findings = append(findings, finding.Finding{
				CheckID: finding.CheckCloudAWSOpenSearchNoVPC,
				Title:   fmt.Sprintf("OpenSearch domain is not deployed in a VPC: %s", name),
				Description: fmt.Sprintf(
					"OpenSearch domain %s in %s is not deployed within a VPC. Domains outside a VPC "+
						"rely solely on IAM and IP-based access policies for access control, which are "+
						"more error-prone than VPC-based network isolation. Deploy the domain in a VPC "+
						"with appropriate security groups to enforce network-level access control.",
					name, region,
				),
				Severity:     finding.SeverityHigh,
				Asset:        asset,
				Scanner:      "cloud/aws",
				ProofCommand: proofCmd,
				Evidence: map[string]any{
					"account_id":    accountID,
					"region":        region,
					"resource_type": "opensearch_domain",
					"domain_name":   name,
				},
				DiscoveredAt: time.Now(),
			})
		}

		// Check 5: Audit logging not enabled.
		auditLogsEnabled := false
		if domain.LogPublishingOptions != nil {
			if auditLog, ok := domain.LogPublishingOptions["AUDIT_LOGS"]; ok {
				if auditLog.Enabled != nil && *auditLog.Enabled {
					auditLogsEnabled = true
				}
			}
		}
		if !auditLogsEnabled {
			findings = append(findings, finding.Finding{
				CheckID: finding.CheckCloudAWSOpenSearchNoLogs,
				Title:   fmt.Sprintf("OpenSearch domain does not have audit logging enabled: %s", name),
				Description: fmt.Sprintf(
					"OpenSearch domain %s in %s does not have audit logging enabled. Without audit logs, "+
						"you cannot track who accessed or modified data in the domain, making it impossible "+
						"to detect unauthorized access or comply with regulatory requirements. Enable audit "+
						"logging by publishing AUDIT_LOGS to a CloudWatch log group.",
					name, region,
				),
				Severity:     finding.SeverityMedium,
				Asset:        asset,
				Scanner:      "cloud/aws",
				ProofCommand: proofCmd,
				Evidence: map[string]any{
					"account_id":    accountID,
					"region":        region,
					"resource_type": "opensearch_domain",
					"domain_name":   name,
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings, nil
}
