package azure

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/security/armsecurity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"

	"github.com/stormbane/beacon/internal/finding"
)

// scanSecurity runs subscription-level security checks that don't fit neatly
// into a single resource category (NSG flow logs, Defender, Key Vault, App Service, SQL ATP).
func scanSecurity(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID, asset string) ([]finding.Finding, error) {
	var findings []finding.Finding

	// NSG Flow Logs
	nsgFindings, err := checkNSGFlowLogs(ctx, cred, subID, asset)
	if err == nil {
		findings = append(findings, nsgFindings...)
	}

	// Microsoft Defender for Cloud
	defenderFindings, err := checkDefender(ctx, cred, subID, asset)
	if err == nil {
		findings = append(findings, defenderFindings...)
	}

	// Key Vault soft delete and purge protection
	kvFindings, err := checkKeyVaults(ctx, cred, subID, asset)
	if err == nil {
		findings = append(findings, kvFindings...)
	}

	// App Service HTTPS and managed identity
	appFindings, err := checkAppServices(ctx, cred, subID, asset)
	if err == nil {
		findings = append(findings, appFindings...)
	}

	// SQL Advanced Threat Protection
	atpFindings, err := checkSQLATP(ctx, cred, subID, asset)
	if err == nil {
		findings = append(findings, atpFindings...)
	}

	return findings, nil
}

// checkNSGFlowLogs lists all NSGs in the subscription and checks whether
// flow log configuration exists for each.
func checkNSGFlowLogs(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID, asset string) ([]finding.Finding, error) {
	nsgClient, err := armnetwork.NewSecurityGroupsClient(subID, cred, nil)
	if err != nil {
		return nil, err
	}

	watcherClient, err := armnetwork.NewFlowLogsClient(subID, cred, nil)
	if err != nil {
		return nil, err
	}

	// Build a set of NSG resource IDs that have flow logs configured.
	flowLogTargets := make(map[string]bool)

	// List all Network Watchers to find flow logs.
	nwClient, err := armnetwork.NewWatchersClient(subID, cred, nil)
	if err != nil {
		return nil, err
	}

	nwPager := nwClient.NewListAllPager(nil)
	for nwPager.More() {
		if ctx.Err() != nil {
			break
		}
		page, err := nwPager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, watcher := range page.Value {
			if watcher.ID == nil {
				continue
			}
			// Extract resource group from watcher ID.
			rg := extractResourceGroup(*watcher.ID)
			if rg == "" {
				continue
			}
			watcherName := ""
			if watcher.Name != nil {
				watcherName = *watcher.Name
			}
			flPager := watcherClient.NewListPager(rg, watcherName, nil)
			for flPager.More() {
				if ctx.Err() != nil {
					break
				}
				flPage, err := flPager.NextPage(ctx)
				if err != nil {
					break
				}
				for _, fl := range flPage.Value {
					if fl.Properties != nil && fl.Properties.TargetResourceID != nil {
						flowLogTargets[strings.ToLower(*fl.Properties.TargetResourceID)] = true
					}
				}
			}
		}
	}

	// List all NSGs and check if each has a flow log.
	var findings []finding.Finding
	pager := nsgClient.NewListAllPager(nil)
	for pager.More() {
		if ctx.Err() != nil {
			break
		}
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, nsg := range page.Value {
			if nsg.ID == nil || nsg.Name == nil {
				continue
			}
			if !flowLogTargets[strings.ToLower(*nsg.ID)] {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAzureNoNSGFlowLogs,
					Title:   fmt.Sprintf("NSG does not have flow logs enabled: %s", *nsg.Name),
					Description: fmt.Sprintf(
						"Network Security Group %s does not have NSG Flow Logs configured. "+
							"Flow logs capture information about IP traffic flowing through an NSG, "+
							"which is essential for network monitoring, troubleshooting, and forensics. "+
							"Enable NSG Flow Logs via Network Watcher.",
						*nsg.Name,
					),
					Severity:     finding.SeverityMedium,
					Asset:        asset,
					Scanner:      "cloud/azure",
					ProofCommand: fmt.Sprintf("az network watcher flow-log list --query \"[?targetResourceId=='%s']\"", *nsg.ID),
					Evidence: map[string]any{
						"nsg_name":        *nsg.Name,
						"nsg_id":          *nsg.ID,
						"subscription_id": subID,
						"resource_type":   "Microsoft.Network/networkSecurityGroups",
					},
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return findings, nil
}

// defenderResourceTypes lists the key resource types that should have
// Microsoft Defender for Cloud (standard tier) enabled.
var defenderResourceTypes = []string{
	"VirtualMachines",
	"SqlServers",
	"AppServices",
	"StorageAccounts",
	"KeyVaults",
	"KubernetesService",
}

// checkDefender verifies that Microsoft Defender for Cloud is enabled
// (standard pricing tier) for key resource types.
func checkDefender(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID, asset string) ([]finding.Finding, error) {
	client, err := armsecurity.NewPricingsClient(cred, nil)
	if err != nil {
		return nil, err
	}

	scopeID := "subscriptions/" + subID
	resp, err := client.List(ctx, scopeID, nil)
	if err != nil {
		return nil, err
	}

	// Build a map of resource type -> pricing tier.
	pricingTiers := make(map[string]string)
	for _, pricing := range resp.Value {
		if pricing.Name == nil || pricing.Properties == nil || pricing.Properties.PricingTier == nil {
			continue
		}
		pricingTiers[*pricing.Name] = string(*pricing.Properties.PricingTier)
	}

	var findings []finding.Finding
	for _, resourceType := range defenderResourceTypes {
		tier, exists := pricingTiers[resourceType]
		if !exists || !strings.EqualFold(tier, "Standard") {
			findings = append(findings, finding.Finding{
				CheckID: finding.CheckCloudAzureNoDefender,
				Title:   fmt.Sprintf("Microsoft Defender for Cloud not enabled for %s", resourceType),
				Description: fmt.Sprintf(
					"Microsoft Defender for Cloud is not enabled (standard tier) for %s in "+
						"subscription %s. Defender provides advanced threat detection, vulnerability "+
						"assessment, and security recommendations. Enable the standard pricing tier "+
						"for comprehensive protection.",
					resourceType, subID,
				),
				Severity:     finding.SeverityMedium,
				Asset:        asset,
				Scanner:      "cloud/azure",
				ProofCommand: fmt.Sprintf("az security pricing show --name %s --query 'pricingTier'", resourceType),
				Evidence: map[string]any{
					"resource_type":   resourceType,
					"subscription_id": subID,
					"current_tier":    tier,
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings, nil
}

// checkKeyVaults lists all Key Vaults and checks for soft delete and purge
// protection configuration.
func checkKeyVaults(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID, asset string) ([]finding.Finding, error) {
	client, err := armkeyvault.NewVaultsClient(subID, cred, nil)
	if err != nil {
		return nil, err
	}

	var findings []finding.Finding
	pager := client.NewListBySubscriptionPager(nil)
	for pager.More() {
		if ctx.Err() != nil {
			break
		}
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, vault := range page.Value {
			if vault.Name == nil || vault.Properties == nil {
				continue
			}
			findings = append(findings, evaluateKeyVault(*vault.Name, vault.Properties, subID, asset)...)
		}
	}

	return findings, nil
}

// evaluateKeyVault checks a single Key Vault for soft delete and purge protection.
func evaluateKeyVault(name string, props *armkeyvault.VaultProperties, subID, asset string) []finding.Finding {
	var findings []finding.Finding

	// Check soft delete.
	if props.EnableSoftDelete != nil && !*props.EnableSoftDelete {
		findings = append(findings, finding.Finding{
			CheckID: finding.CheckCloudAzureKeyVaultNoSoftDelete,
			Title:   fmt.Sprintf("Key Vault does not have soft delete enabled: %s", name),
			Description: fmt.Sprintf(
				"Key Vault %s does not have soft delete enabled. Without soft delete, "+
					"deleted keys, secrets, and certificates are immediately and permanently "+
					"removed, with no recovery option. Enable soft delete to allow recovery "+
					"of accidentally deleted vault objects for a configurable retention period.",
				name,
			),
			Severity:     finding.SeverityMedium,
			Asset:        asset,
			Scanner:      "cloud/azure",
			ProofCommand: fmt.Sprintf("az keyvault show --name %s --query 'properties.enableSoftDelete'", name),
			Evidence: map[string]any{
				"vault_name":      name,
				"subscription_id": subID,
				"resource_type":   "Microsoft.KeyVault/vaults",
			},
			DiscoveredAt: time.Now(),
		})
	}

	// Check purge protection.
	if props.EnablePurgeProtection == nil || !*props.EnablePurgeProtection {
		findings = append(findings, finding.Finding{
			CheckID: finding.CheckCloudAzureKeyVaultNoPurgeProtect,
			Title:   fmt.Sprintf("Key Vault does not have purge protection enabled: %s", name),
			Description: fmt.Sprintf(
				"Key Vault %s does not have purge protection enabled. Without purge protection, "+
					"soft-deleted vault objects can be permanently purged before the retention period "+
					"expires, even by privileged users. Enable purge protection to enforce mandatory "+
					"retention of deleted objects.",
				name,
			),
			Severity:     finding.SeverityMedium,
			Asset:        asset,
			Scanner:      "cloud/azure",
			ProofCommand: fmt.Sprintf("az keyvault show --name %s --query 'properties.enablePurgeProtection'", name),
			Evidence: map[string]any{
				"vault_name":      name,
				"subscription_id": subID,
				"resource_type":   "Microsoft.KeyVault/vaults",
			},
			DiscoveredAt: time.Now(),
		})
	}

	return findings
}

// checkAppServices lists all web apps and checks for HTTPS-only and managed identity.
func checkAppServices(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID, asset string) ([]finding.Finding, error) {
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
			findings = append(findings, evaluateAppService(*app.Name, app.Properties, app.Identity, subID, asset)...)
		}
	}

	return findings, nil
}

// evaluateAppService checks a single App Service for HTTPS-only and managed identity.
func evaluateAppService(name string, props *armappservice.SiteProperties, identity *armappservice.ManagedServiceIdentity, subID, asset string) []finding.Finding {
	var findings []finding.Finding

	// Check HTTPS-only.
	if props.HTTPSOnly != nil && !*props.HTTPSOnly {
		findings = append(findings, finding.Finding{
			CheckID: finding.CheckCloudAzureAppServiceNoHTTPS,
			Title:   fmt.Sprintf("App Service does not enforce HTTPS: %s", name),
			Description: fmt.Sprintf(
				"App Service %s does not have HTTPS Only enabled. Without this setting, "+
					"the app accepts both HTTP and HTTPS traffic, allowing unencrypted connections "+
					"that expose data in transit. Enable HTTPS Only to redirect all HTTP traffic "+
					"to HTTPS.",
				name,
			),
			Severity:     finding.SeverityHigh,
			Asset:        asset,
			Scanner:      "cloud/azure",
			ProofCommand: fmt.Sprintf("az webapp show --name %s --query 'httpsOnly'", name),
			Evidence: map[string]any{
				"app_name":        name,
				"subscription_id": subID,
				"resource_type":   "Microsoft.Web/sites",
			},
			DiscoveredAt: time.Now(),
		})
	}

	// Check managed identity.
	hasManagedIdentity := identity != nil && identity.Type != nil &&
		*identity.Type != armappservice.ManagedServiceIdentityTypeNone
	if !hasManagedIdentity {
		findings = append(findings, finding.Finding{
			CheckID: finding.CheckCloudAzureAppServiceNoManagedID,
			Title:   fmt.Sprintf("App Service does not use managed identity: %s", name),
			Description: fmt.Sprintf(
				"App Service %s does not have a managed identity configured. Without managed "+
					"identity, the app must use stored credentials (connection strings, keys) to "+
					"authenticate to Azure services, which are harder to rotate and more likely "+
					"to leak. Enable a system-assigned or user-assigned managed identity.",
				name,
			),
			Severity:     finding.SeverityMedium,
			Asset:        asset,
			Scanner:      "cloud/azure",
			ProofCommand: fmt.Sprintf("az webapp identity show --name %s", name),
			Evidence: map[string]any{
				"app_name":        name,
				"subscription_id": subID,
				"resource_type":   "Microsoft.Web/sites",
			},
			DiscoveredAt: time.Now(),
		})
	}

	return findings
}

// checkSQLATP lists all SQL servers and checks if Advanced Threat Protection
// is enabled on each.
func checkSQLATP(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID, asset string) ([]finding.Finding, error) {
	serverClient, err := armsql.NewServersClient(subID, cred, nil)
	if err != nil {
		return nil, err
	}

	atpClient, err := armsql.NewServerAdvancedThreatProtectionSettingsClient(subID, cred, nil)
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
			if server.Name == nil || server.ID == nil {
				continue
			}
			rg := extractResourceGroup(*server.ID)
			if rg == "" {
				continue
			}
			findings = append(findings, checkServerATP(ctx, atpClient, rg, *server.Name, subID, asset)...)
		}
	}

	return findings, nil
}

// checkServerATP checks ATP status for a single SQL server.
func checkServerATP(ctx context.Context, client *armsql.ServerAdvancedThreatProtectionSettingsClient, resourceGroup, serverName, subID, asset string) []finding.Finding {
	pager := client.NewListByServerPager(resourceGroup, serverName, nil)
	atpEnabled := false
	for pager.More() {
		if ctx.Err() != nil {
			break
		}
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, setting := range page.Value {
			if setting.Properties != nil && setting.Properties.State != nil &&
				*setting.Properties.State == armsql.AdvancedThreatProtectionStateEnabled {
				atpEnabled = true
				break
			}
		}
		if atpEnabled {
			break
		}
	}

	if !atpEnabled {
		return []finding.Finding{{
			CheckID: finding.CheckCloudAzureSQLNoATP,
			Title:   fmt.Sprintf("Azure SQL server does not have Advanced Threat Protection enabled: %s", serverName),
			Description: fmt.Sprintf(
				"SQL server %s does not have Advanced Threat Protection (ATP) enabled. "+
					"ATP detects anomalous activities indicating unusual and potentially harmful "+
					"attempts to access or exploit databases, including SQL injection attacks, "+
					"brute force login attempts, and anomalous access patterns. Enable ATP for "+
					"proactive threat detection.",
				serverName,
			),
			Severity:     finding.SeverityHigh,
			Asset:        asset,
			Scanner:      "cloud/azure",
			ProofCommand: fmt.Sprintf("az sql server advanced-threat-protection-setting show --resource-group %s --server %s --query 'state'", resourceGroup, serverName),
			Evidence: map[string]any{
				"server_name":     serverName,
				"resource_group":  resourceGroup,
				"subscription_id": subID,
				"resource_type":   "Microsoft.Sql/servers",
			},
			DiscoveredAt: time.Now(),
		}}
	}

	return nil
}

// extractResourceGroup extracts the resource group name from an Azure resource ID.
// Format: /subscriptions/{sub}/resourceGroups/{rg}/providers/...
func extractResourceGroup(resourceID string) string {
	parts := strings.Split(resourceID, "/")
	for i, part := range parts {
		if strings.EqualFold(part, "resourceGroups") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}
