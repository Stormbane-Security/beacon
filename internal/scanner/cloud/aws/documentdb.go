package aws

import (
	"context"
	"fmt"
	"time"

	awscfg "github.com/aws/aws-sdk-go-v2/aws"
	docdb "github.com/aws/aws-sdk-go-v2/service/docdb"

	"github.com/stormbane/beacon/internal/finding"
)

func scanDocumentDB(ctx context.Context, cfg awscfg.Config, accountID, region, asset string) ([]finding.Finding, error) {
	svc := docdb.NewFromConfig(cfg)
	var findings []finding.Finding

	var marker *string
	for {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		input := &docdb.DescribeDBClustersInput{}
		if marker != nil {
			input.Marker = marker
		}

		resp, err := svc.DescribeDBClusters(ctx, input)
		if err != nil {
			if len(findings) == 0 {
				return nil, fmt.Errorf("describe documentdb clusters: %w", err)
			}
			break
		}

		for _, cluster := range resp.DBClusters {
			clusterID := awscfg.ToString(cluster.DBClusterIdentifier)
			engine := awscfg.ToString(cluster.Engine)

			// Check if storage encryption is disabled.
			if cluster.StorageEncrypted != nil && !*cluster.StorageEncrypted {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSDocDBNoEncryption,
					Title:   fmt.Sprintf("DocumentDB cluster storage is not encrypted: %s", clusterID),
					Description: fmt.Sprintf(
						"DocumentDB cluster %s (engine: %s) in %s does not have storage encryption enabled. "+
							"Unencrypted database storage exposes data at rest if the underlying storage "+
							"is compromised or snapshots are shared. Enable encryption using AWS KMS when "+
							"creating the cluster (encryption cannot be enabled on an existing unencrypted cluster).",
						clusterID, engine, region,
					),
					Severity:     finding.SeverityHigh,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: fmt.Sprintf("aws docdb describe-db-clusters --db-cluster-identifier %s --region %s --query 'DBClusters[].{DBClusterIdentifier:DBClusterIdentifier,StorageEncrypted:StorageEncrypted}'", clusterID, region),
					Evidence: map[string]any{
						"account_id":    accountID,
						"db_cluster":    clusterID,
						"engine":        engine,
						"region":        region,
						"resource_type": "docdb_cluster",
					},
					DiscoveredAt: time.Now(),
				})
			}

			// Check if automated backups are insufficient (retention period <= 1 day).
			if cluster.BackupRetentionPeriod != nil && *cluster.BackupRetentionPeriod <= 1 {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSDocDBNoBackup,
					Title:   fmt.Sprintf("DocumentDB cluster has insufficient backup retention: %s", clusterID),
					Description: fmt.Sprintf(
						"DocumentDB cluster %s (engine: %s) in %s has a backup retention period of %d day(s). "+
							"With minimal or no backup retention, data loss from accidental deletion, corruption, "+
							"or ransomware may be unrecoverable. Set the backup retention period to at least 7 days.",
						clusterID, engine, region, awscfg.ToInt32(cluster.BackupRetentionPeriod),
					),
					Severity:     finding.SeverityMedium,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: fmt.Sprintf("aws docdb describe-db-clusters --db-cluster-identifier %s --region %s --query 'DBClusters[].{DBClusterIdentifier:DBClusterIdentifier,BackupRetentionPeriod:BackupRetentionPeriod}'", clusterID, region),
					Evidence: map[string]any{
						"account_id":            accountID,
						"db_cluster":            clusterID,
						"engine":                engine,
						"region":                region,
						"resource_type":         "docdb_cluster",
						"backup_retention_days": awscfg.ToInt32(cluster.BackupRetentionPeriod),
					},
					DiscoveredAt: time.Now(),
				})
			}

			// Check if audit logging is enabled.
			// DocumentDB supports exporting "audit" and "profiler" logs to CloudWatch.
			hasAuditLog := false
			for _, logExport := range cluster.EnabledCloudwatchLogsExports {
				if logExport == "audit" {
					hasAuditLog = true
					break
				}
			}
			if !hasAuditLog {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSDocDBNoAuditLog,
					Title:   fmt.Sprintf("DocumentDB cluster does not have audit logging enabled: %s", clusterID),
					Description: fmt.Sprintf(
						"DocumentDB cluster %s (engine: %s) in %s does not export audit logs to CloudWatch. "+
							"Without audit logging, database operations (DDL/DML activity, authentication attempts, "+
							"authorization failures) are not recorded, making forensics and compliance difficult. "+
							"Enable the 'audit' log export in the cluster configuration.",
						clusterID, engine, region,
					),
					Severity:     finding.SeverityMedium,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: fmt.Sprintf("aws docdb describe-db-clusters --db-cluster-identifier %s --region %s --query 'DBClusters[].{DBClusterIdentifier:DBClusterIdentifier,EnabledCloudwatchLogsExports:EnabledCloudwatchLogsExports}'", clusterID, region),
					Evidence: map[string]any{
						"account_id":    accountID,
						"db_cluster":    clusterID,
						"engine":        engine,
						"region":        region,
						"resource_type": "docdb_cluster",
						"log_exports":   cluster.EnabledCloudwatchLogsExports,
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
