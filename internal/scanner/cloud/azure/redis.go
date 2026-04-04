package azure

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	armredis "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/redis/armredis"

	"github.com/stormbane-security/beacon/internal/finding"
)

func scanRedis(ctx context.Context, cred azcore.TokenCredential, subID, asset string) ([]finding.Finding, error) {
	client, err := armredis.NewClient(subID, cred, nil)
	if err != nil {
		return nil, err
	}

	fwClient, err := armredis.NewFirewallRulesClient(subID, cred, nil)
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
		for _, cache := range page.Value {
			if cache.Name == nil || cache.Properties == nil {
				continue
			}
			var resourceGroup string
			if cache.ID != nil {
				resourceGroup = extractResourceGroup(*cache.ID)
			}
			findings = append(findings, evaluateRedis(ctx, fwClient, *cache.Name, resourceGroup, cache.Properties, subID, asset)...)
		}
	}
	return findings, nil
}

// evaluateRedis checks a single Azure Cache for Redis instance for TLS
// configuration and firewall rules.
func evaluateRedis(ctx context.Context, fwClient *armredis.FirewallRulesClient, name, resourceGroup string, props *armredis.Properties, subID, asset string) []finding.Finding {
	var findings []finding.Finding

	// Check minimum TLS version. Should be 1.2.
	tlsOK := props.MinimumTLSVersion != nil && *props.MinimumTLSVersion == armredis.TLSVersionOne2
	if !tlsOK {
		currentTLS := "not set"
		if props.MinimumTLSVersion != nil {
			currentTLS = string(*props.MinimumTLSVersion)
		}
		findings = append(findings, finding.Finding{
			CheckID: finding.CheckCloudAzureRedisNoTLS,
			Title:   fmt.Sprintf("Azure Cache for Redis does not require TLS 1.2: %s", name),
			Description: fmt.Sprintf(
				"Azure Cache for Redis %s does not enforce a minimum TLS version of 1.2 "+
					"(current: %s). Older TLS versions (1.0, 1.1) have known vulnerabilities "+
					"that allow traffic interception and decryption. Set the minimum TLS version "+
					"to 1.2 to ensure all connections use modern cryptography.",
				name, currentTLS,
			),
			Severity:     finding.SeverityHigh,
			Asset:        asset,
			Scanner:      "cloud/azure",
			ProofCommand: fmt.Sprintf("az redis show --name %s --query 'minimumTlsVersion'", name),
			Evidence: map[string]any{
				"cache_name":        name,
				"current_tls":       currentTLS,
				"subscription_id":   subID,
				"resource_type":     "Microsoft.Cache/Redis",
			},
			DiscoveredAt: time.Now(),
		})
	}

	// Check firewall rules when public network access is enabled.
	publicAccess := props.PublicNetworkAccess != nil &&
		*props.PublicNetworkAccess == armredis.PublicNetworkAccessEnabled
	if publicAccess && resourceGroup != "" {
		hasRules := false
		fwPager := fwClient.NewListPager(resourceGroup, name, nil)
		for fwPager.More() {
			if ctx.Err() != nil {
				break
			}
			fwPage, err := fwPager.NextPage(ctx)
			if err != nil {
				break
			}
			if len(fwPage.Value) > 0 {
				hasRules = true
				break
			}
		}
		if !hasRules {
			findings = append(findings, finding.Finding{
				CheckID: finding.CheckCloudAzureRedisNoFirewall,
				Title:   fmt.Sprintf("Azure Cache for Redis has no firewall rules: %s", name),
				Description: fmt.Sprintf(
					"Azure Cache for Redis %s has public network access enabled but no firewall "+
						"rules configured. Without firewall rules, the cache accepts connections "+
						"from any IP address on the internet. Configure firewall rules to restrict "+
						"access to known IP ranges, or disable public network access entirely.",
					name,
				),
				Severity:     finding.SeverityMedium,
				Asset:        asset,
				Scanner:      "cloud/azure",
				ProofCommand: fmt.Sprintf("az redis firewall-rules list --name %s --resource-group %s", name, resourceGroup),
				Evidence: map[string]any{
					"cache_name":       name,
					"resource_group":   resourceGroup,
					"subscription_id":  subID,
					"resource_type":    "Microsoft.Cache/Redis",
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings
}
