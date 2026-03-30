package azure

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerregistry/armcontainerregistry"

	"github.com/stormbane/beacon/internal/finding"
)

func scanACR(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID, asset string) ([]finding.Finding, error) {
	client, err := armcontainerregistry.NewRegistriesClient(subID, cred, nil)
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
		for _, registry := range page.Value {
			if registry.Name == nil || registry.Properties == nil {
				continue
			}
			findings = append(findings, evaluateACR(*registry.Name, registry.Properties, subID, asset)...)
		}
	}
	return findings, nil
}

// evaluateACR checks a single Azure Container Registry for misconfigurations
// and returns any findings.
func evaluateACR(name string, props *armcontainerregistry.RegistryProperties, subID, asset string) []finding.Finding {
	var findings []finding.Finding

	// Check for public network access.
	publicAccess := true
	if props.PublicNetworkAccess != nil && *props.PublicNetworkAccess == armcontainerregistry.PublicNetworkAccessDisabled {
		publicAccess = false
	}
	if publicAccess {
		findings = append(findings, finding.Finding{
			CheckID: finding.CheckCloudAzureACRPublic,
			Title:   fmt.Sprintf("Azure Container Registry allows public access: %s", name),
			Description: fmt.Sprintf(
				"Container Registry %s has public network access enabled. This allows "+
					"any network to pull and potentially push images. Disable public network "+
					"access and use private endpoints to restrict registry access to approved "+
					"virtual networks only.",
				name,
			),
			Severity:     finding.SeverityHigh,
			Asset:        asset,
			Scanner:      "cloud/azure",
			ProofCommand: fmt.Sprintf("az acr show --name %s --query 'publicNetworkAccess'", name),
			Evidence: map[string]any{
				"registry_name":   name,
				"subscription_id": subID,
				"resource_type":   "Microsoft.ContainerRegistry/registries",
			},
			DiscoveredAt: time.Now(),
		})
	}

	// Check for content trust (image signing) policy.
	contentTrustEnabled := false
	if props.Policies != nil && props.Policies.TrustPolicy != nil && props.Policies.TrustPolicy.Status != nil {
		if *props.Policies.TrustPolicy.Status == armcontainerregistry.PolicyStatusEnabled {
			contentTrustEnabled = true
		}
	}
	if !contentTrustEnabled {
		findings = append(findings, finding.Finding{
			CheckID: finding.CheckCloudAzureACRNoContentTrust,
			Title:   fmt.Sprintf("Azure Container Registry does not have content trust enabled: %s", name),
			Description: fmt.Sprintf(
				"Container Registry %s does not have content trust (image signing) enabled. "+
					"Without content trust, images are not cryptographically signed, making it "+
					"possible to deploy tampered or unauthorized images. Enable the trust policy "+
					"to require image signing via Docker Content Trust / Notary.",
				name,
			),
			Severity:     finding.SeverityMedium,
			Asset:        asset,
			Scanner:      "cloud/azure",
			ProofCommand: fmt.Sprintf("az acr config content-trust show --registry %s --query 'status'", name),
			Evidence: map[string]any{
				"registry_name":   name,
				"subscription_id": subID,
				"resource_type":   "Microsoft.ContainerRegistry/registries",
			},
			DiscoveredAt: time.Now(),
		})
	}

	return findings
}
