package azure

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	armcosmos "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cosmos/armcosmos"

	"github.com/stormbane-security/beacon/internal/finding"
)

func scanCosmosDB(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID, asset string) ([]finding.Finding, error) {
	client, err := armcosmos.NewDatabaseAccountsClient(subID, cred, nil)
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
		for _, account := range page.Value {
			if account.Name == nil || account.Properties == nil {
				continue
			}
			findings = append(findings, evaluateCosmosDBAccount(*account.Name, account.Properties, subID, asset)...)
		}
	}
	return findings, nil
}

// evaluateCosmosDBAccount checks a single Cosmos DB account for public access
// and firewall configuration.
func evaluateCosmosDBAccount(name string, props *armcosmos.DatabaseAccountGetProperties, subID, asset string) []finding.Finding {
	var findings []finding.Finding

	// Check for public network access enabled.
	if props.PublicNetworkAccess != nil && *props.PublicNetworkAccess == armcosmos.PublicNetworkAccessEnabled {
		findings = append(findings, finding.Finding{
			CheckID: finding.CheckCloudAzureCosmosDBPublic,
			Title:   fmt.Sprintf("Cosmos DB account has public network access enabled: %s", name),
			Description: fmt.Sprintf(
				"Cosmos DB account %s has public network access enabled. This allows connections "+
					"from any public IP address, including the internet. Disable public network "+
					"access and use private endpoints to restrict connectivity to approved "+
					"virtual networks only.",
				name,
			),
			Severity:     finding.SeverityHigh,
			Asset:        asset,
			Scanner:      "cloud/azure",
			ProofCommand: fmt.Sprintf("az cosmosdb show --name %s --query 'publicNetworkAccess'", name),
			Evidence: map[string]any{
				"account_name":    name,
				"subscription_id": subID,
				"resource_type":   "Microsoft.DocumentDB/databaseAccounts",
			},
			DiscoveredAt: time.Now(),
		})

		// TCP connectivity test: confirm whether the public Cosmos DB account
		// is actually reachable from the internet.
		if props.DocumentEndpoint != nil && *props.DocumentEndpoint != "" {
			endpoint := *props.DocumentEndpoint
			parsed, parseErr := url.Parse(endpoint)
			if parseErr == nil && parsed.Host != "" {
				host := parsed.Host
				// Cosmos DB uses HTTPS (port 443) by default.
				if parsed.Port() == "" {
					host = host + ":443"
				}
				conn, dialErr := net.DialTimeout("tcp", host, 5*time.Second)
				if dialErr == nil {
					conn.Close()
					findings = append(findings, finding.Finding{
						CheckID: finding.CheckCloudAzureCosmosDBReachable,
						Title:   fmt.Sprintf("Cosmos DB account is publicly reachable via TCP: %s", name),
						Description: fmt.Sprintf(
							"Cosmos DB account %s is not only configured with public network access "+
								"but actually accepts TCP connections from the internet on %s. "+
								"This confirms the endpoint is reachable. Disable public network "+
								"access and use private endpoints.",
							name, host,
						),
						Severity:     finding.SeverityCritical,
						Asset:        asset,
						Scanner:      "cloud/azure",
						ProofCommand: fmt.Sprintf("nc -zv %s", host),
						Evidence: map[string]any{
							"account_name":    name,
							"subscription_id": subID,
							"resource_type":   "Microsoft.DocumentDB/databaseAccounts",
							"endpoint":        endpoint,
						},
						DiscoveredAt: time.Now(),
					})
				}
			}
		}
	}

	// Check for missing IP firewall rules.
	if len(props.IPRules) == 0 {
		findings = append(findings, finding.Finding{
			CheckID: finding.CheckCloudAzureCosmosDBNoFirewall,
			Title:   fmt.Sprintf("Cosmos DB account has no IP firewall rules: %s", name),
			Description: fmt.Sprintf(
				"Cosmos DB account %s does not have any IP firewall rules configured. "+
					"Without IP restrictions, the account accepts connections from any IP address "+
					"(when public access is enabled). Configure IP firewall rules to restrict "+
					"access to known IP ranges, or disable public access entirely.",
				name,
			),
			Severity:     finding.SeverityMedium,
			Asset:        asset,
			Scanner:      "cloud/azure",
			ProofCommand: fmt.Sprintf("az cosmosdb show --name %s --query 'ipRules'", name),
			Evidence: map[string]any{
				"account_name":    name,
				"subscription_id": subID,
				"resource_type":   "Microsoft.DocumentDB/databaseAccounts",
			},
			DiscoveredAt: time.Now(),
		})
	}

	return findings
}
