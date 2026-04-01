package azure

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	armpostgresqlflexibleservers "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/postgresql/armpostgresqlflexibleservers"

	"github.com/stormbane-security/beacon/internal/finding"
)

func scanPostgres(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID, asset string) ([]finding.Finding, error) {
	serverClient, err := armpostgresqlflexibleservers.NewServersClient(subID, cred, nil)
	if err != nil {
		return nil, err
	}

	configClient, err := armpostgresqlflexibleservers.NewConfigurationsClient(subID, cred, nil)
	if err != nil {
		return nil, err
	}

	var findings []finding.Finding
	pager := serverClient.NewListPager(nil)
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
			var resourceGroup string
			if server.ID != nil {
				resourceGroup = extractResourceGroup(*server.ID)
			}
			findings = append(findings, evaluatePostgresServer(ctx, configClient, *server.Name, resourceGroup, server.Properties, subID, asset)...)
		}
	}
	return findings, nil
}

// evaluatePostgresServer checks a single Azure Database for PostgreSQL flexible
// server for public access and SSL enforcement.
func evaluatePostgresServer(ctx context.Context, configClient *armpostgresqlflexibleservers.ConfigurationsClient, name, resourceGroup string, props *armpostgresqlflexibleservers.ServerProperties, subID, asset string) []finding.Finding {
	var findings []finding.Finding

	// Check for public network access.
	if props.Network != nil && props.Network.PublicNetworkAccess != nil &&
		*props.Network.PublicNetworkAccess == armpostgresqlflexibleservers.ServerPublicNetworkAccessStateEnabled {
		findings = append(findings, finding.Finding{
			CheckID: finding.CheckCloudAzurePostgresPublic,
			Title:   fmt.Sprintf("PostgreSQL flexible server has public access enabled: %s", name),
			Description: fmt.Sprintf(
				"Azure Database for PostgreSQL flexible server %s has public network access "+
					"enabled. This allows connections from any public IP address, including the "+
					"internet. Disable public network access and use private endpoints or VNet "+
					"integration to restrict connectivity to approved networks only.",
				name,
			),
			Severity:     finding.SeverityHigh,
			Asset:        asset,
			Scanner:      "cloud/azure",
			ProofCommand: fmt.Sprintf("az postgres flexible-server show --name %s --query 'network.publicNetworkAccess'", name),
			Evidence: map[string]any{
				"server_name":     name,
				"subscription_id": subID,
				"resource_type":   "Microsoft.DBforPostgreSQL/flexibleServers",
			},
			DiscoveredAt: time.Now(),
		})
	}

	// Check require_secure_transport configuration.
	if resourceGroup != "" {
		resp, err := configClient.Get(ctx, resourceGroup, name, "require_secure_transport", nil)
		if err == nil && resp.Properties != nil && resp.Properties.Value != nil {
			if !strings.EqualFold(*resp.Properties.Value, "ON") {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAzurePostgresNoSSL,
					Title:   fmt.Sprintf("PostgreSQL flexible server does not require SSL: %s", name),
					Description: fmt.Sprintf(
						"Azure Database for PostgreSQL flexible server %s does not require SSL/TLS "+
							"connections (require_secure_transport = %s). Without enforced SSL, database "+
							"connections may transmit credentials and query data in cleartext, exposing "+
							"them to network interception. Set require_secure_transport to ON.",
						name, *resp.Properties.Value,
					),
					Severity:     finding.SeverityHigh,
					Asset:        asset,
					Scanner:      "cloud/azure",
					ProofCommand: fmt.Sprintf("az postgres flexible-server parameter show --server-name %s --name require_secure_transport --query 'value'", name),
					Evidence: map[string]any{
						"server_name":              name,
						"require_secure_transport": *resp.Properties.Value,
						"subscription_id":          subID,
						"resource_type":            "Microsoft.DBforPostgreSQL/flexibleServers",
					},
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return findings
}
