package azure

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice"

	"github.com/stormbane-security/beacon/internal/finding"
)

func scanAKS(ctx context.Context, cred azcore.TokenCredential, subID, asset string) ([]finding.Finding, error) {
	client, err := armcontainerservice.NewManagedClustersClient(subID, cred, nil)
	if err != nil {
		return nil, err
	}

	var findings []finding.Finding
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, cluster := range page.Value {
			if cluster.Name == nil || cluster.Properties == nil {
				continue
			}
			findings = append(findings, evaluateAKSCluster(*cluster.Name, cluster.Properties, cluster.Identity, subID, asset)...)
		}
	}
	return findings, nil
}

// evaluateAKSCluster checks a single AKS cluster's properties for
// misconfigurations and returns any findings.
func evaluateAKSCluster(name string, props *armcontainerservice.ManagedClusterProperties, identity *armcontainerservice.ManagedClusterIdentity, subID, asset string) []finding.Finding {
	var findings []finding.Finding

	if props.APIServerAccessProfile != nil {
		ap := props.APIServerAccessProfile
		isPublic := ap.EnablePrivateCluster == nil || !*ap.EnablePrivateCluster
		noRestriction := len(ap.AuthorizedIPRanges) == 0
		if isPublic && noRestriction {
			findings = append(findings, finding.Finding{
				CheckID: finding.CheckCloudAzureAKSPublicEndpoint,
				Title:   fmt.Sprintf("AKS cluster has public API server with no IP restrictions: %s", name),
				Description: fmt.Sprintf(
					"AKS cluster %s has a public API server endpoint with no authorized IP range restrictions. "+
						"Any IP address can attempt to reach the Kubernetes API. "+
						"Enable API server authorized IP ranges or use a private cluster.",
					name,
				),
				Severity:     finding.SeverityHigh,
				Asset:        asset,
				Scanner:      "cloud/azure",
				ProofCommand: fmt.Sprintf("az aks show --name %s --query 'apiServerAccessProfile'", name),
				Evidence:     map[string]any{"cluster_name": name, "subscription_id": subID},
				DiscoveredAt: time.Now(),
			})
		}
	}

	// RBAC disabled.
	// Without RBAC, any authenticated user has full cluster access,
	// making it impossible to enforce least privilege.
	if props.EnableRBAC == nil || !*props.EnableRBAC {
		findings = append(findings, finding.Finding{
			CheckID: finding.CheckCloudAzureAKSNoRBAC,
			Title:   fmt.Sprintf("AKS cluster does not have RBAC enabled: %s", name),
			Description: fmt.Sprintf(
				"AKS cluster %s does not have Kubernetes RBAC enabled. Without RBAC, "+
					"any authenticated user has full cluster access including the ability to "+
					"create, modify, and delete any resource. Enable RBAC to enforce "+
					"role-based access control and least privilege.",
				name,
			),
			Severity:     finding.SeverityHigh,
			Asset:        asset,
			Scanner:      "cloud/azure",
			ProofCommand: fmt.Sprintf("az aks show --name %s --query 'enableRbac'", name),
			Evidence:     map[string]any{"cluster_name": name, "subscription_id": subID},
			DiscoveredAt: time.Now(),
		})
	}

	// Network policy not configured.
	// Without a network policy plugin, all pods can communicate with
	// all other pods, enabling lateral movement after compromise.
	networkPolicyConfigured := false
	if props.NetworkProfile != nil && props.NetworkProfile.NetworkPolicy != nil {
		policy := string(*props.NetworkProfile.NetworkPolicy)
		if policy != "" && policy != "none" {
			networkPolicyConfigured = true
		}
	}
	if !networkPolicyConfigured {
		findings = append(findings, finding.Finding{
			CheckID: finding.CheckCloudAzureAKSNoNetPolicy,
			Title:   fmt.Sprintf("AKS cluster does not have network policy enabled: %s", name),
			Description: fmt.Sprintf(
				"AKS cluster %s does not have a network policy plugin configured. "+
					"Without network policy, all pods can communicate with all other pods "+
					"in the cluster, enabling unrestricted lateral movement after a pod "+
					"compromise. Enable Azure or Calico network policy.",
				name,
			),
			Severity:     finding.SeverityMedium,
			Asset:        asset,
			Scanner:      "cloud/azure",
			ProofCommand: fmt.Sprintf("az aks show --name %s --query 'networkProfile.networkPolicy'", name),
			Evidence:     map[string]any{"cluster_name": name, "subscription_id": subID},
			DiscoveredAt: time.Now(),
		})
	}

	// Managed identity not configured.
	// AKS clusters should use managed identity (SystemAssigned or UserAssigned)
	// instead of a service principal. Service principals require manual secret
	// rotation and are harder to audit.
	hasManagedIdentity := false
	if identity != nil && identity.Type != nil {
		idType := string(*identity.Type)
		if idType == "SystemAssigned" || idType == "UserAssigned" {
			hasManagedIdentity = true
		}
	}
	if !hasManagedIdentity {
		findings = append(findings, finding.Finding{
			CheckID: finding.CheckCloudAzureAKSNoManagedIdentity,
			Title:   fmt.Sprintf("AKS cluster does not use managed identity: %s", name),
			Description: fmt.Sprintf(
				"AKS cluster %s uses a service principal instead of a managed identity. "+
					"Service principals require manual credential rotation and are harder to audit. "+
					"Managed identities (SystemAssigned or UserAssigned) eliminate credential "+
					"management overhead and integrate with Azure AD for automatic rotation.",
				name,
			),
			Severity:     finding.SeverityMedium,
			Asset:        asset,
			Scanner:      "cloud/azure",
			ProofCommand: fmt.Sprintf("az aks show --name %s --query 'identity'", name),
			Evidence:     map[string]any{"cluster_name": name, "subscription_id": subID},
			DiscoveredAt: time.Now(),
		})
	}

	// Azure AD (Microsoft Entra ID) integration not configured.
	// Without AAD integration, cluster authentication relies on local
	// Kubernetes accounts, which lack MFA, conditional access, and
	// centralized identity governance.
	if props.AADProfile == nil {
		findings = append(findings, finding.Finding{
			CheckID: finding.CheckCloudAzureAKSNoAADIntegration,
			Title:   fmt.Sprintf("AKS cluster does not have Azure AD integration enabled: %s", name),
			Description: fmt.Sprintf(
				"AKS cluster %s does not have Azure AD (Microsoft Entra ID) integration configured. "+
					"Without AAD integration, cluster authentication relies on local Kubernetes accounts "+
					"or client certificates, which lack multi-factor authentication, conditional access "+
					"policies, and centralized identity governance. Enable AAD integration to leverage "+
					"Azure AD for cluster RBAC and authentication.",
				name,
			),
			Severity:     finding.SeverityHigh,
			Asset:        asset,
			Scanner:      "cloud/azure",
			ProofCommand: fmt.Sprintf("az aks show --name %s --query 'aadProfile'", name),
			Evidence:     map[string]any{"cluster_name": name, "subscription_id": subID},
			DiscoveredAt: time.Now(),
		})
	}

	// Auto-upgrade not configured.
	// Without an auto-upgrade channel, clusters remain on older Kubernetes
	// versions with known vulnerabilities until manually upgraded.
	autoUpgradeConfigured := false
	if props.AutoUpgradeProfile != nil && props.AutoUpgradeProfile.UpgradeChannel != nil {
		channel := string(*props.AutoUpgradeProfile.UpgradeChannel)
		if channel != "" && channel != "none" {
			autoUpgradeConfigured = true
		}
	}
	if !autoUpgradeConfigured {
		findings = append(findings, finding.Finding{
			CheckID: finding.CheckCloudAzureAKSNoAutoUpgrade,
			Title:   fmt.Sprintf("AKS cluster does not have auto-upgrade configured: %s", name),
			Description: fmt.Sprintf(
				"AKS cluster %s does not have an auto-upgrade channel configured. Without "+
					"auto-upgrade, the cluster remains on its current Kubernetes version until "+
					"manually upgraded, leaving it exposed to known vulnerabilities in older "+
					"versions. Configure an auto-upgrade channel (stable, rapid, or patch) to "+
					"receive automatic security updates.",
				name,
			),
			Severity:     finding.SeverityMedium,
			Asset:        asset,
			Scanner:      "cloud/azure",
			ProofCommand: fmt.Sprintf("az aks show --name %s --query 'autoUpgradeProfile'", name),
			Evidence:     map[string]any{"cluster_name": name, "subscription_id": subID},
			DiscoveredAt: time.Now(),
		})
	}

	return findings
}
