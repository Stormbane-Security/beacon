package aws

import (
	"context"
	"fmt"
	"time"

	awscfg "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"

	"github.com/stormbane/beacon/internal/finding"
)

func scanRDS(ctx context.Context, cfg awscfg.Config, accountID, region, asset string) ([]finding.Finding, error) {
	svc := rds.NewFromConfig(cfg)
	var findings []finding.Finding

	paginator := rds.NewDescribeDBInstancesPaginator(svc, &rds.DescribeDBInstancesInput{})
	for paginator.HasMorePages() {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		page, err := paginator.NextPage(ctx)
		if err != nil {
			if len(findings) == 0 {
				return nil, fmt.Errorf("describe db instances: %w", err)
			}
			break
		}
		for _, db := range page.DBInstances {
			dbID := awscfg.ToString(db.DBInstanceIdentifier)
			engine := awscfg.ToString(db.Engine)

			// Check if the RDS instance is publicly accessible.
			if awscfg.ToBool(db.PubliclyAccessible) {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSRDSPublic,
					Title:   fmt.Sprintf("RDS instance is publicly accessible: %s", dbID),
					Description: fmt.Sprintf(
						"RDS instance %s (engine: %s) in %s is configured with PubliclyAccessible=true. "+
							"This makes the database endpoint resolvable to a public IP, allowing any internet "+
							"host to attempt connections. Set PubliclyAccessible to false and use VPC private "+
							"subnets or VPN for database access.",
						dbID, engine, region,
					),
					Severity:     finding.SeverityCritical,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: fmt.Sprintf("aws rds describe-db-instances --db-instance-identifier %s --region %s --query 'DBInstances[].{DBInstanceIdentifier:DBInstanceIdentifier,PubliclyAccessible:PubliclyAccessible}'", dbID, region),
					Evidence: map[string]any{
						"account_id":    accountID,
						"db_instance":   dbID,
						"engine":        engine,
						"region":        region,
						"resource_type": "rds_instance",
					},
					DiscoveredAt: time.Now(),
				})
			}

			// Check if storage encryption is disabled.
			if db.StorageEncrypted != nil && !*db.StorageEncrypted {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSRDSNoEncryption,
					Title:   fmt.Sprintf("RDS instance storage is not encrypted: %s", dbID),
					Description: fmt.Sprintf(
						"RDS instance %s (engine: %s) in %s does not have storage encryption enabled. "+
							"Unencrypted database storage exposes data at rest if the underlying storage "+
							"is compromised or snapshots are shared. Enable encryption using AWS KMS when "+
							"creating the instance (encryption cannot be enabled on an existing unencrypted instance; "+
							"create an encrypted snapshot and restore from it).",
						dbID, engine, region,
					),
					Severity:     finding.SeverityHigh,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: fmt.Sprintf("aws rds describe-db-instances --db-instance-identifier %s --region %s --query 'DBInstances[].{DBInstanceIdentifier:DBInstanceIdentifier,StorageEncrypted:StorageEncrypted}'", dbID, region),
					Evidence: map[string]any{
						"account_id":    accountID,
						"db_instance":   dbID,
						"engine":        engine,
						"region":        region,
						"resource_type": "rds_instance",
					},
					DiscoveredAt: time.Now(),
				})
			}

			// Check if automated backups are disabled (retention period == 0).
			if db.BackupRetentionPeriod != nil && *db.BackupRetentionPeriod == 0 {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSRDSNoBackup,
					Title:   fmt.Sprintf("RDS instance has no automated backups: %s", dbID),
					Description: fmt.Sprintf(
						"RDS instance %s (engine: %s) in %s has a backup retention period of 0 days, "+
							"meaning automated backups are disabled. Without backups, data loss from accidental "+
							"deletion, corruption, or ransomware is unrecoverable. Set the backup retention "+
							"period to at least 7 days.",
						dbID, engine, region,
					),
					Severity:     finding.SeverityMedium,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: fmt.Sprintf("aws rds describe-db-instances --db-instance-identifier %s --region %s --query 'DBInstances[].{DBInstanceIdentifier:DBInstanceIdentifier,BackupRetentionPeriod:BackupRetentionPeriod}'", dbID, region),
					Evidence: map[string]any{
						"account_id":           accountID,
						"db_instance":          dbID,
						"engine":               engine,
						"region":               region,
						"resource_type":        "rds_instance",
						"backup_retention_days": 0,
					},
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return findings, nil
}
