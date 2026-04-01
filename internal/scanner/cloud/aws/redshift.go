package aws

import (
	"context"
	"fmt"
	"time"

	awscfg "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/redshift"

	"github.com/stormbane-security/beacon/internal/finding"
)

func scanRedshift(ctx context.Context, cfg awscfg.Config, accountID, region, asset string) ([]finding.Finding, error) {
	svc := redshift.NewFromConfig(cfg)
	var findings []finding.Finding

	var marker *string
	for {
		input := &redshift.DescribeClustersInput{}
		if marker != nil {
			input.Marker = marker
		}
		resp, err := svc.DescribeClusters(ctx, input)
		if err != nil {
			if len(findings) == 0 {
				return nil, fmt.Errorf("describe redshift clusters: %w", err)
			}
			break
		}

		for _, cluster := range resp.Clusters {
			clusterID := awscfg.ToString(cluster.ClusterIdentifier)

			// Check if publicly accessible.
			if awscfg.ToBool(cluster.PubliclyAccessible) {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSRedshiftPublic,
					Title:   fmt.Sprintf("Redshift cluster is publicly accessible: %s", clusterID),
					Description: fmt.Sprintf(
						"Redshift cluster %s in %s is publicly accessible. A public Redshift endpoint "+
							"exposes the data warehouse to brute-force attacks and credential stuffing from "+
							"the internet. Disable public accessibility and restrict access to private "+
							"subnets with security group controls.",
						clusterID, region,
					),
					Severity:     finding.SeverityCritical,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: fmt.Sprintf("aws redshift describe-clusters --cluster-identifier %s --region %s", clusterID, region),
					Evidence: map[string]any{
						"account_id":          accountID,
						"region":              region,
						"resource_type":       "redshift_cluster",
						"cluster_identifier":  clusterID,
						"publicly_accessible": true,
					},
					DiscoveredAt: time.Now(),
				})
			}

			// Check encryption.
			if !awscfg.ToBool(cluster.Encrypted) {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSRedshiftNoEncryption,
					Title:   fmt.Sprintf("Redshift cluster is not encrypted: %s", clusterID),
					Description: fmt.Sprintf(
						"Redshift cluster %s in %s does not have encryption at rest enabled. "+
							"Without encryption, data stored in the cluster is vulnerable to unauthorized "+
							"access if the underlying storage is compromised. Enable encryption using "+
							"AWS KMS or HSM.",
						clusterID, region,
					),
					Severity:     finding.SeverityHigh,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: fmt.Sprintf("aws redshift describe-clusters --cluster-identifier %s --region %s", clusterID, region),
					Evidence: map[string]any{
						"account_id":         accountID,
						"region":             region,
						"resource_type":      "redshift_cluster",
						"cluster_identifier": clusterID,
						"encrypted":          false,
					},
					DiscoveredAt: time.Now(),
				})
			}

			// Check audit logging.
			logResp, logErr := svc.DescribeLoggingStatus(ctx, &redshift.DescribeLoggingStatusInput{
				ClusterIdentifier: cluster.ClusterIdentifier,
			})
			if logErr == nil && !awscfg.ToBool(logResp.LoggingEnabled) {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSRedshiftNoAuditLog,
					Title:   fmt.Sprintf("Redshift cluster does not have audit logging enabled: %s", clusterID),
					Description: fmt.Sprintf(
						"Redshift cluster %s in %s does not have audit logging enabled. "+
							"Without audit logs, database queries, connection attempts, and user "+
							"activity are not recorded, making incident investigation and compliance "+
							"auditing impossible. Enable audit logging to capture connection, user, "+
							"and user activity logs.",
						clusterID, region,
					),
					Severity:     finding.SeverityMedium,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: fmt.Sprintf("aws redshift describe-clusters --cluster-identifier %s --region %s", clusterID, region),
					Evidence: map[string]any{
						"account_id":         accountID,
						"region":             region,
						"resource_type":      "redshift_cluster",
						"cluster_identifier": clusterID,
						"logging_enabled":    false,
					},
					DiscoveredAt: time.Now(),
				})
			}

			// Check parameter groups for require_ssl.
			for _, pg := range cluster.ClusterParameterGroups {
				pgName := awscfg.ToString(pg.ParameterGroupName)
				requireSSL := false

				var paramMarker *string
				for {
					paramInput := &redshift.DescribeClusterParametersInput{
						ParameterGroupName: awscfg.String(pgName),
					}
					if paramMarker != nil {
						paramInput.Marker = paramMarker
					}
					paramResp, paramErr := svc.DescribeClusterParameters(ctx, paramInput)
					if paramErr != nil {
						break
					}
					for _, param := range paramResp.Parameters {
						if awscfg.ToString(param.ParameterName) == "require_ssl" &&
							awscfg.ToString(param.ParameterValue) == "true" {
							requireSSL = true
							break
						}
					}
					if requireSSL || paramResp.Marker == nil {
						break
					}
					paramMarker = paramResp.Marker
				}

				if !requireSSL {
					findings = append(findings, finding.Finding{
						CheckID: finding.CheckCloudAWSRedshiftNoSSL,
						Title:   fmt.Sprintf("Redshift cluster does not require SSL connections: %s", clusterID),
						Description: fmt.Sprintf(
							"Redshift cluster %s in %s (parameter group %s) does not have require_ssl "+
								"set to true. Without mandatory SSL, client connections can transmit queries "+
								"and query results (including sensitive data) in plaintext. Set the require_ssl "+
								"parameter to true in the cluster's parameter group.",
							clusterID, region, pgName,
						),
						Severity:     finding.SeverityHigh,
						Asset:        asset,
						Scanner:      "cloud/aws",
						ProofCommand: fmt.Sprintf("aws redshift describe-clusters --cluster-identifier %s --region %s", clusterID, region),
						Evidence: map[string]any{
							"account_id":         accountID,
							"region":             region,
							"resource_type":      "redshift_cluster",
							"cluster_identifier": clusterID,
							"parameter_group":    pgName,
							"require_ssl":        false,
						},
						DiscoveredAt: time.Now(),
					})
					break // One finding per cluster is sufficient.
				}
			}
		}

		if resp.Marker == nil {
			break
		}
		marker = resp.Marker
	}

	return findings, nil
}
