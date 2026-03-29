package azure

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"

	"github.com/stormbane/beacon/internal/finding"
)

// evaluateStorageAccount checks a single storage account's properties for
// misconfigurations and returns any findings.
func evaluateStorageAccount(name string, props *armstorage.AccountProperties, subID, asset string) []finding.Finding {
	var findings []finding.Finding

	// Check for public blob access at the account level.
	if props.AllowBlobPublicAccess != nil && *props.AllowBlobPublicAccess {
		findings = append(findings, finding.Finding{
			CheckID: finding.CheckCloudAzureBlobPublic,
			Title:   fmt.Sprintf("Azure storage account allows public blob access: %s", name),
			Description: fmt.Sprintf(
				"Storage account %s has AllowBlobPublicAccess enabled. This allows individual "+
					"containers within the account to be made public (anonymous read). "+
					"Set AllowBlobPublicAccess=false at the account level to prevent any container "+
					"from being made public, regardless of container-level settings.",
				name,
			),
			Severity:     finding.SeverityHigh,
			Asset:        asset,
			Scanner:      "cloud/azure",
			ProofCommand: fmt.Sprintf("az storage account show --name %s --query 'allowBlobPublicAccess'", name),
			Evidence: map[string]any{
				"account_name":    name,
				"subscription_id": subID,
			},
			DiscoveredAt: time.Now(),
		})
	}

	// Check HTTPS-only enforcement.
	if props.EnableHTTPSTrafficOnly != nil && !*props.EnableHTTPSTrafficOnly {
		findings = append(findings, finding.Finding{
			CheckID:      finding.CheckCloudAzureStorageHTTP,
			Title:        fmt.Sprintf("Azure storage account allows HTTP traffic: %s", name),
			Description:  fmt.Sprintf("Storage account %s allows HTTP (non-TLS) connections. Enable 'Secure transfer required' to enforce HTTPS for all blob, file, queue, and table operations.", name),
			Severity:     finding.SeverityMedium,
			Asset:        asset,
			Scanner:      "cloud/azure",
			ProofCommand: fmt.Sprintf("az storage account show --name %s --query 'enableHttpsTrafficOnly'", name),
			Evidence:     map[string]any{"account_name": name, "subscription_id": subID},
			DiscoveredAt: time.Now(),
		})
	}

	// Check for shared key access enabled.
	// When AllowSharedKeyAccess is true (or nil, which defaults to true),
	// the storage account accepts shared key authentication in addition to
	// Azure AD. Shared keys are long-lived secrets that cannot be scoped
	// to specific operations or enforced with conditional access.
	if props.AllowSharedKeyAccess == nil || *props.AllowSharedKeyAccess {
		findings = append(findings, finding.Finding{
			CheckID: finding.CheckCloudAzureStorageSharedKey,
			Title:   fmt.Sprintf("Azure storage account allows shared key access: %s", name),
			Description: fmt.Sprintf(
				"Storage account %s allows shared key (account key) authentication. "+
					"Shared keys are long-lived secrets that grant full access to the storage "+
					"account and cannot be scoped to specific operations or enforced with "+
					"conditional access policies. Disable shared key access and use Azure AD "+
					"authentication exclusively.",
				name,
			),
			Severity:     finding.SeverityMedium,
			Asset:        asset,
			Scanner:      "cloud/azure",
			ProofCommand: fmt.Sprintf("az storage account show --name %s --query 'allowSharedKeyAccess'", name),
			Evidence:     map[string]any{"account_name": name, "subscription_id": subID},
			DiscoveredAt: time.Now(),
		})
	}

	return findings
}

func scanStorage(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID, asset string) ([]finding.Finding, error) {
	client, err := armstorage.NewAccountsClient(subID, cred, nil)
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
		for _, account := range page.Value {
			if account.Name == nil || account.Properties == nil {
				continue
			}
			findings = append(findings, evaluateStorageAccount(*account.Name, account.Properties, subID, asset)...)
		}
	}
	return findings, nil
}
