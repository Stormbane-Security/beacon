package azure

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"

	"github.com/stormbane-security/beacon/internal/finding"
)

func scanSQL(ctx context.Context, cred azcore.TokenCredential, subID, asset string) ([]finding.Finding, error) {
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
			// Extract resource group from the server's Azure resource ID.
			var resourceGroup string
			if server.ID != nil {
				resourceGroup = extractResourceGroup(*server.ID)
			}
			findings = append(findings, evaluateSQLServer(ctx, cred, subID, resourceGroup, *server.Name, server.Properties, asset)...)
		}
	}
	return findings, nil
}

// evaluateSQLServer checks a single Azure SQL server and its databases for
// misconfigurations and returns any findings.
func evaluateSQLServer(ctx context.Context, cred azcore.TokenCredential, subID, resourceGroup, name string, props *armsql.ServerProperties, asset string) []finding.Finding {
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
	if resourceGroup != "" {
		findings = append(findings, checkSQLAuditing(ctx, cred, subID, resourceGroup, name, asset)...)
	} else {
		log.Printf("[cloud/azure] skipping auditing check for SQL server %s: could not extract resource group from server ID", name)
	}

	// Check TDE on each database.
	if resourceGroup != "" {
		findings = append(findings, checkSQLTDE(ctx, cred, subID, resourceGroup, name, asset)...)
	} else {
		log.Printf("[cloud/azure] skipping TDE check for SQL server %s: could not extract resource group from server ID", name)
	}

	return findings
}

// checkSQLAuditing retrieves the server blob auditing policy and flags if
// auditing is disabled.
func checkSQLAuditing(ctx context.Context, cred azcore.TokenCredential, subID, resourceGroup, serverName, asset string) []finding.Finding {
	client, err := armsql.NewServerBlobAuditingPoliciesClient(subID, cred, nil)
	if err != nil {
		return nil
	}

	resp, err := client.Get(ctx, resourceGroup, serverName, nil)
	if err != nil {
		return nil
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

// checkSQLTDE lists databases under a server and flags any that do not have
// transparent data encryption enabled.
func checkSQLTDE(ctx context.Context, cred azcore.TokenCredential, subID, resourceGroup, serverName, asset string) []finding.Finding {
	dbClient, err := armsql.NewDatabasesClient(subID, cred, nil)
	if err != nil {
		return nil
	}

	tdeClient, err := armsql.NewTransparentDataEncryptionsClient(subID, cred, nil)
	if err != nil {
		return nil
	}

	var findings []finding.Finding
	pager := dbClient.NewListByServerPager(resourceGroup, serverName, nil)
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
			resp, err := tdeClient.Get(ctx, resourceGroup, serverName, *db.Name, armsql.TransparentDataEncryptionNameCurrent, nil)
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
