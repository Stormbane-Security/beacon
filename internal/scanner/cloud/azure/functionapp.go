package azure

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice"

	"github.com/stormbane-security/beacon/internal/finding"
)

func scanFunctionApps(ctx context.Context, cred azcore.TokenCredential, subID, asset string) ([]finding.Finding, error) {
	client, err := armappservice.NewWebAppsClient(subID, cred, nil)
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
		for _, app := range page.Value {
			if app.Name == nil || app.Properties == nil {
				continue
			}
			// Filter for Function Apps only.
			if app.Kind == nil || !strings.Contains(strings.ToLower(*app.Kind), "functionapp") {
				continue
			}
			findings = append(findings, evaluateFunctionApp(*app.Name, app.Properties, app.Identity, subID, asset)...)
		}
	}
	return findings, nil
}

// evaluateFunctionApp checks a single Azure Function App for HTTPS-only
// enforcement and managed identity configuration.
func evaluateFunctionApp(name string, props *armappservice.SiteProperties, identity *armappservice.ManagedServiceIdentity, subID, asset string) []finding.Finding {
	var findings []finding.Finding

	// Check HTTPS-only enforcement.
	if props.HTTPSOnly == nil || !*props.HTTPSOnly {
		findings = append(findings, finding.Finding{
			CheckID: finding.CheckCloudAzureFunctionAppNoHTTPS,
			Title:   fmt.Sprintf("Function App does not enforce HTTPS: %s", name),
			Description: fmt.Sprintf(
				"Function App %s does not have HTTPS Only enabled. Without this setting, "+
					"the function app accepts both HTTP and HTTPS traffic, allowing unencrypted "+
					"connections that expose data in transit including authentication tokens "+
					"and request payloads. Enable HTTPS Only to redirect all HTTP traffic to HTTPS.",
				name,
			),
			Severity:     finding.SeverityHigh,
			Asset:        asset,
			Scanner:      "cloud/azure",
			ProofCommand: fmt.Sprintf("az functionapp show --name %s --query 'httpsOnly'", name),
			Evidence: map[string]any{
				"function_app_name": name,
				"subscription_id":   subID,
				"resource_type":     "Microsoft.Web/sites",
			},
			DiscoveredAt: time.Now(),
		})
	}

	// Check managed identity.
	hasManagedIdentity := identity != nil && identity.Type != nil &&
		*identity.Type != armappservice.ManagedServiceIdentityTypeNone
	if !hasManagedIdentity {
		findings = append(findings, finding.Finding{
			CheckID: finding.CheckCloudAzureFunctionAppNoManagedID,
			Title:   fmt.Sprintf("Function App does not use managed identity: %s", name),
			Description: fmt.Sprintf(
				"Function App %s does not have a managed identity configured. Without managed "+
					"identity, the function app must use stored credentials (connection strings, "+
					"keys) to authenticate to Azure services, which are harder to rotate and "+
					"more likely to leak. Enable a system-assigned or user-assigned managed identity.",
				name,
			),
			Severity:     finding.SeverityMedium,
			Asset:        asset,
			Scanner:      "cloud/azure",
			ProofCommand: fmt.Sprintf("az functionapp identity show --name %s", name),
			Evidence: map[string]any{
				"function_app_name": name,
				"subscription_id":   subID,
				"resource_type":     "Microsoft.Web/sites",
			},
			DiscoveredAt: time.Now(),
		})
	}

	return findings
}
