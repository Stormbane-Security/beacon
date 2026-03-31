package aws

import (
	"context"
	"fmt"
	"time"

	awscfg "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"

	"github.com/stormbane/beacon/internal/finding"
)

func scanElastiCache(ctx context.Context, cfg awscfg.Config, accountID, region, asset string) ([]finding.Finding, error) {
	svc := elasticache.NewFromConfig(cfg)
	var findings []finding.Finding

	var marker *string
	for {
		input := &elasticache.DescribeReplicationGroupsInput{}
		if marker != nil {
			input.Marker = marker
		}
		resp, err := svc.DescribeReplicationGroups(ctx, input)
		if err != nil {
			if len(findings) == 0 {
				return nil, fmt.Errorf("describe elasticache replication groups: %w", err)
			}
			break
		}

		for _, rg := range resp.ReplicationGroups {
			rgID := awscfg.ToString(rg.ReplicationGroupId)

			// Check transit encryption.
			if rg.TransitEncryptionEnabled == nil || !*rg.TransitEncryptionEnabled {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSElastiCacheNoEncTransit,
					Title:   fmt.Sprintf("ElastiCache replication group does not have encryption in transit: %s", rgID),
					Description: fmt.Sprintf(
						"ElastiCache replication group %s in %s does not have encryption in transit enabled. "+
							"Without TLS, data between clients and Redis nodes travels in plaintext, exposing "+
							"cached data (sessions, credentials, PII) to network-level interception. "+
							"Enable transit encryption on the replication group.",
						rgID, region,
					),
					Severity:     finding.SeverityHigh,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: fmt.Sprintf("aws elasticache describe-replication-groups --replication-group-id %s --region %s", rgID, region),
					Evidence: map[string]any{
						"account_id":               accountID,
						"region":                   region,
						"resource_type":            "elasticache_replication_group",
						"replication_group_id":     rgID,
						"transit_encryption":       false,
					},
					DiscoveredAt: time.Now(),
				})
			}

			// Check at-rest encryption.
			if rg.AtRestEncryptionEnabled == nil || !*rg.AtRestEncryptionEnabled {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSElastiCacheNoEncRest,
					Title:   fmt.Sprintf("ElastiCache replication group does not have encryption at rest: %s", rgID),
					Description: fmt.Sprintf(
						"ElastiCache replication group %s in %s does not have encryption at rest enabled. "+
							"Without at-rest encryption, cached data stored on disk (snapshots, swap files, "+
							"replication backlog) is unencrypted. Enable at-rest encryption to protect "+
							"data persisted by ElastiCache.",
						rgID, region,
					),
					Severity:     finding.SeverityMedium,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: fmt.Sprintf("aws elasticache describe-replication-groups --replication-group-id %s --region %s", rgID, region),
					Evidence: map[string]any{
						"account_id":               accountID,
						"region":                   region,
						"resource_type":            "elasticache_replication_group",
						"replication_group_id":     rgID,
						"at_rest_encryption":       false,
					},
					DiscoveredAt: time.Now(),
				})
			}

			// Check AUTH token (authentication).
			if rg.AuthTokenEnabled == nil || !*rg.AuthTokenEnabled {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSElastiCacheNoAuth,
					Title:   fmt.Sprintf("ElastiCache replication group does not require AUTH token: %s", rgID),
					Description: fmt.Sprintf(
						"ElastiCache replication group %s in %s does not have AUTH token authentication enabled. "+
							"Without AUTH, any client with network access to the Redis endpoint can read and write "+
							"all cached data without credentials. Enable AUTH token to require clients to "+
							"authenticate before executing commands.",
						rgID, region,
					),
					Severity:     finding.SeverityHigh,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: fmt.Sprintf("aws elasticache describe-replication-groups --replication-group-id %s --region %s", rgID, region),
					Evidence: map[string]any{
						"account_id":               accountID,
						"region":                   region,
						"resource_type":            "elasticache_replication_group",
						"replication_group_id":     rgID,
						"auth_token_enabled":       false,
					},
					DiscoveredAt: time.Now(),
				})
			}
		}

		if resp.Marker == nil {
			break
		}
		marker = resp.Marker
	}

	return findings, nil
}
