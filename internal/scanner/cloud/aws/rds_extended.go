package aws

import (
	"context"
	"fmt"
	"time"

	awscfg "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"

	"github.com/stormbane-security/beacon/internal/finding"
)

func scanRDSExtended(ctx context.Context, cfg awscfg.Config, accountID, region, asset string) ([]finding.Finding, error) {
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

			// Check if auto minor version upgrade is disabled.
			if !awscfg.ToBool(db.AutoMinorVersionUpgrade) {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSRDSNoAutoMinorUpgrade,
					Title:   fmt.Sprintf("RDS instance does not have auto minor version upgrade enabled: %s", dbID),
					Description: fmt.Sprintf(
						"RDS instance %s (engine: %s) in %s does not have automatic minor version upgrades enabled. "+
							"Without auto minor upgrades, the database engine misses security patches and bug fixes "+
							"that AWS backports to minor versions. Enable AutoMinorVersionUpgrade to ensure the "+
							"instance receives critical patches during the maintenance window.",
						dbID, engine, region,
					),
					Severity:     finding.SeverityLow,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: fmt.Sprintf("aws rds describe-db-instances --db-instance-identifier %s --region %s --query 'DBInstances[].{DBInstanceIdentifier:DBInstanceIdentifier,AutoMinorVersionUpgrade:AutoMinorVersionUpgrade}'", dbID, region),
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

			// Check if deletion protection is disabled.
			if !awscfg.ToBool(db.DeletionProtection) {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSRDSNoDeletionProtection,
					Title:   fmt.Sprintf("RDS instance does not have deletion protection enabled: %s", dbID),
					Description: fmt.Sprintf(
						"RDS instance %s (engine: %s) in %s does not have deletion protection enabled. "+
							"Without deletion protection, the instance can be deleted by any IAM principal with "+
							"rds:DeleteDBInstance permission, including through automation errors or compromised "+
							"credentials. Enable deletion protection to prevent accidental or malicious deletion.",
						dbID, engine, region,
					),
					Severity:     finding.SeverityMedium,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: fmt.Sprintf("aws rds describe-db-instances --db-instance-identifier %s --region %s --query 'DBInstances[].{DBInstanceIdentifier:DBInstanceIdentifier,DeletionProtection:DeletionProtection}'", dbID, region),
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

			// Check if IAM database authentication is disabled.
			if !awscfg.ToBool(db.IAMDatabaseAuthenticationEnabled) {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSRDSNoIAMAuth,
					Title:   fmt.Sprintf("RDS instance does not have IAM database authentication enabled: %s", dbID),
					Description: fmt.Sprintf(
						"RDS instance %s (engine: %s) in %s does not have IAM database authentication enabled. "+
							"Without IAM authentication, database access relies solely on static passwords, which "+
							"can be leaked, brute-forced, or harvested from configuration files. IAM authentication "+
							"uses short-lived tokens tied to IAM policies, enabling centralized access control, "+
							"credential rotation, and CloudTrail auditability.",
						dbID, engine, region,
					),
					Severity:     finding.SeverityMedium,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: fmt.Sprintf("aws rds describe-db-instances --db-instance-identifier %s --region %s --query 'DBInstances[].{DBInstanceIdentifier:DBInstanceIdentifier,IAMDatabaseAuthenticationEnabled:IAMDatabaseAuthenticationEnabled}'", dbID, region),
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
		}
	}

	return findings, nil
}
