package azure

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"

	"github.com/stormbane/beacon/internal/finding"
)

func scanSQL(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID, asset string) ([]finding.Finding, error) {
	client, err := armsql.NewServersClient(subID, cred, nil)
	if err != nil {
		return nil, err
	}

	var findings []finding.Finding
	pager := client.NewListPager(nil)
	for pager.More() {
		if ctx.Err() != nil {
			break
		}
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, server := range page.Value {
			if server.Name == nil || server.Properties == nil {
				continue
			}
			findings = append(findings, evaluateSQLServer(ctx, cred, subID, *server.Name, server.Properties, asset)...)
		}
	}
	return findings, nil
}

// evaluateSQLServer checks a single Azure SQL server and its databases for
// misconfigurations and returns any findings.
func evaluateSQLServer(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID, name string, props *armsql.ServerProperties, asset string) []finding.Finding {
	var findings []finding.Finding

	// Check for public network access.
	if props.PublicNetworkAccess != nil && *props.PublicNetworkAccess != armsql.ServerNetworkAccessFlagDisabled {
		findings = append(findings, finding.Finding{
			CheckID: finding.CheckCloudAzureSQLPublic,
			Title:   fmt.Sprintf("Azure SQL server allows public network access: %s", name),
			Description: fmt.Sprintf(
				"SQL server %s has public network access enabled. This allows connections "+
					"from any public IP address, including the internet. Disable public network "+
					"access and use private endpoints to restrict connectivity to approved "+
					"virtual networks only.",
				name,
			),
			Severity:     finding.SeverityCritical,
			Asset:        asset,
			Scanner:      "cloud/azure",
			ProofCommand: fmt.Sprintf("az sql server show --name %s --query 'publicNetworkAccess'", name),
			Evidence: map[string]any{
				"server_name":     name,
				"subscription_id": subID,
				"resource_type":   "Microsoft.Sql/servers",
			},
			DiscoveredAt: time.Now(),
		})
	}

	// Check auditing policy.
	findings = append(findings, checkSQLAuditing(ctx, cred, subID, name, asset)...)

	// Check TDE on each database.
	findings = append(findings, checkSQLTDE(ctx, cred, subID, name, asset)...)

	return findings
}

// checkSQLAuditing retrieves the server blob auditing policy and flags if
// auditing is disabled.
func checkSQLAuditing(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID, serverName, asset string) []finding.Finding {
	client, err := armsql.NewServerBlobAuditingPoliciesClient(subID, cred, nil)
	if err != nil {
		return nil
	}

	resp, err := client.Get(ctx, "", serverName, nil)
	if err != nil {
		// Try listing by resource group — if we don't know the RG, iterate.
		return checkSQLAuditingViaList(ctx, client, serverName, subID, asset)
	}

	if resp.Properties != nil && resp.Properties.State != nil && *resp.Properties.State == armsql.BlobAuditingPolicyStateDisabled {
		return []finding.Finding{{
			CheckID: finding.CheckCloudAzureSQLNoAuditing,
			Title:   fmt.Sprintf("Azure SQL server does not have auditing enabled: %s", serverName),
			Description: fmt.Sprintf(
				"SQL server %s does not have blob auditing enabled. Auditing tracks database "+
					"events and writes them to an audit log. Without auditing, security incidents "+
					"and suspicious activity may go undetected. Enable auditing to a storage "+
					"account or Log Analytics workspace.",
				serverName,
			),
			Severity:     finding.SeverityHigh,
			Asset:        asset,
			Scanner:      "cloud/azure",
			ProofCommand: fmt.Sprintf("az sql server audit-policy show --name %s --query 'blobAuditingState'", serverName),
			Evidence: map[string]any{
				"server_name":     serverName,
				"subscription_id": subID,
				"resource_type":   "Microsoft.Sql/servers",
			},
			DiscoveredAt: time.Now(),
		}}
	}
	return nil
}

// checkSQLAuditingViaList falls back to listing auditing policies when the
// resource group is unknown.
func checkSQLAuditingViaList(ctx context.Context, client *armsql.ServerBlobAuditingPoliciesClient, serverName, subID, asset string) []finding.Finding {
	pager := client.NewListByServerPager("", serverName, nil)
	for pager.More() {
		if ctx.Err() != nil {
			break
		}
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, policy := range page.Value {
			if policy.Properties != nil && policy.Properties.State != nil && *policy.Properties.State == armsql.BlobAuditingPolicyStateDisabled {
				return []finding.Finding{{
					CheckID: finding.CheckCloudAzureSQLNoAuditing,
					Title:   fmt.Sprintf("Azure SQL server does not have auditing enabled: %s", serverName),
					Description: fmt.Sprintf(
						"SQL server %s does not have blob auditing enabled. Auditing tracks database "+
							"events and writes them to an audit log. Without auditing, security incidents "+
							"and suspicious activity may go undetected. Enable auditing to a storage "+
							"account or Log Analytics workspace.",
						serverName,
					),
					Severity:     finding.SeverityHigh,
					Asset:        asset,
					Scanner:      "cloud/azure",
					ProofCommand: fmt.Sprintf("az sql server audit-policy show --name %s --query 'blobAuditingState'", serverName),
					Evidence: map[string]any{
						"server_name":     serverName,
						"subscription_id": subID,
						"resource_type":   "Microsoft.Sql/servers",
					},
					DiscoveredAt: time.Now(),
				}}
			}
		}
	}
	return nil
}

// checkSQLTDE lists databases under a server and flags any that do not have
// transparent data encryption enabled.
func checkSQLTDE(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID, serverName, asset string) []finding.Finding {
	dbClient, err := armsql.NewDatabasesClient(subID, cred, nil)
	if err != nil {
		return nil
	}

	tdeClient, err := armsql.NewTransparentDataEncryptionsClient(subID, cred, nil)
	if err != nil {
		return nil
	}

	var findings []finding.Finding
	pager := dbClient.NewListByServerPager("", serverName, nil)
	for pager.More() {
		if ctx.Err() != nil {
			break
		}
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, db := range page.Value {
			if db.Name == nil {
				continue
			}
			// Skip system databases.
			if *db.Name == "master" {
				continue
			}
			resp, err := tdeClient.Get(ctx, "", serverName, *db.Name, armsql.TransparentDataEncryptionNameCurrent, nil)
			if err != nil {
				continue
			}
			if resp.Properties != nil && resp.Properties.State != nil && *resp.Properties.State == armsql.TransparentDataEncryptionStateDisabled {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAzureSQLNoTDE,
					Title:   fmt.Sprintf("Azure SQL database does not have TDE enabled: %s/%s", serverName, *db.Name),
					Description: fmt.Sprintf(
						"Database %s on SQL server %s does not have Transparent Data Encryption (TDE) enabled. "+
							"TDE encrypts data at rest, protecting database files, backups, and transaction logs "+
							"from offline attacks. Enable TDE to ensure data-at-rest encryption.",
						*db.Name, serverName,
					),
					Severity:     finding.SeverityHigh,
					Asset:        asset,
					Scanner:      "cloud/azure",
					ProofCommand: fmt.Sprintf("az sql db tde show --server %s --database %s --query 'status'", serverName, *db.Name),
					Evidence: map[string]any{
						"server_name":     serverName,
						"database_name":   *db.Name,
						"subscription_id": subID,
						"resource_type":   "Microsoft.Sql/servers/databases",
					},
					DiscoveredAt: time.Now(),
				})
			}
		}
	}
	return findings
}
