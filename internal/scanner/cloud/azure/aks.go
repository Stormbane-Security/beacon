package azure

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice"

	"github.com/stormbane/beacon/internal/finding"
)

func scanAKS(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID, asset string) ([]finding.Finding, error) {
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
			findings = append(findings, evaluateAKSCluster(*cluster.Name, cluster.Properties, subID, asset)...)
		}
	}
	return findings, nil
}

// evaluateAKSCluster checks a single AKS cluster's properties for
// misconfigurations and returns any findings.
func evaluateAKSCluster(name string, props *armcontainerservice.ManagedClusterProperties, subID, asset string) []finding.Finding {
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

	return findings
}
