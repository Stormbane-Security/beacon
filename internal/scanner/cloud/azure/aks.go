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
			name := *cluster.Name
			props := cluster.Properties

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
		}
	}
	return findings, nil
}
