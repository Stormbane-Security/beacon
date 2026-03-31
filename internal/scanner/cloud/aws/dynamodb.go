package aws

import (
	"context"
	"fmt"
	"time"

	awscfg "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/stormbane/beacon/internal/finding"
)

func scanDynamoDB(ctx context.Context, cfg awscfg.Config, accountID, region, asset string) ([]finding.Finding, error) {
	svc := dynamodb.NewFromConfig(cfg)
	var findings []finding.Finding

	var lastEvaluatedTable *string
	for {
		input := &dynamodb.ListTablesInput{}
		if lastEvaluatedTable != nil {
			input.ExclusiveStartTableName = lastEvaluatedTable
		}
		resp, err := svc.ListTables(ctx, input)
		if err != nil {
			if len(findings) == 0 {
				return nil, fmt.Errorf("list dynamodb tables: %w", err)
			}
			break
		}

		for _, tableName := range resp.TableNames {
			desc, err := svc.DescribeTable(ctx, &dynamodb.DescribeTableInput{
				TableName: awscfg.String(tableName),
			})
			if err != nil || desc.Table == nil {
				continue
			}
			table := desc.Table

			// Check encryption — SSEDescription nil or SSEType is not KMS.
			// Default AWS-owned encryption does not count as CMK encryption.
			noKMS := table.SSEDescription == nil ||
				table.SSEDescription.SSEType != dbtypes.SSETypeKms
			if noKMS {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSDynamoDBNoEncryption,
					Title:   fmt.Sprintf("DynamoDB table does not use CMK encryption: %s", tableName),
					Description: fmt.Sprintf(
						"DynamoDB table %s in %s does not use a customer-managed KMS key for encryption. "+
							"Default AWS-owned encryption does not provide key management controls, audit "+
							"trails via CloudTrail, or the ability to revoke access by disabling the key. "+
							"Enable encryption with a customer-managed KMS key.",
						tableName, region,
					),
					Severity:     finding.SeverityMedium,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: fmt.Sprintf("aws dynamodb describe-table --table-name %s --region %s", tableName, region),
					Evidence: map[string]any{
						"account_id":    accountID,
						"region":        region,
						"resource_type": "dynamodb_table",
						"table_name":    tableName,
					},
					DiscoveredAt: time.Now(),
				})
			}

			// Check point-in-time recovery.
			cbResp, cbErr := svc.DescribeContinuousBackups(ctx, &dynamodb.DescribeContinuousBackupsInput{
				TableName: awscfg.String(tableName),
			})
			pitrEnabled := false
			if cbErr == nil && cbResp.ContinuousBackupsDescription != nil &&
				cbResp.ContinuousBackupsDescription.PointInTimeRecoveryDescription != nil {
				pitrEnabled = cbResp.ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus == dbtypes.PointInTimeRecoveryStatusEnabled
			}
			if !pitrEnabled {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSDynamoDBNoPITR,
					Title:   fmt.Sprintf("DynamoDB table does not have point-in-time recovery enabled: %s", tableName),
					Description: fmt.Sprintf(
						"DynamoDB table %s in %s does not have point-in-time recovery (PITR) enabled. "+
							"Without PITR, accidental writes, deletes, or application bugs can cause "+
							"permanent data loss. Enable PITR to allow restoring the table to any "+
							"second within the last 35 days.",
						tableName, region,
					),
					Severity:     finding.SeverityMedium,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: fmt.Sprintf("aws dynamodb describe-table --table-name %s --region %s", tableName, region),
					Evidence: map[string]any{
						"account_id":    accountID,
						"region":        region,
						"resource_type": "dynamodb_table",
						"table_name":    tableName,
					},
					DiscoveredAt: time.Now(),
				})
			}
		}

		if resp.LastEvaluatedTableName == nil {
			break
		}
		lastEvaluatedTable = resp.LastEvaluatedTableName
	}

	return findings, nil
}
