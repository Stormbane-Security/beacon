package azure

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	armcompute "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	armnetwork "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"

	"github.com/stormbane-security/beacon/internal/finding"
)

func scanVMs(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID, asset string) ([]finding.Finding, error) {
	computeClient, err := armcompute.NewVirtualMachinesClient(subID, cred, nil)
	if err != nil {
		return nil, err
	}

	nicClient, err := armnetwork.NewInterfacesClient(subID, cred, nil)
	if err != nil {
		return nil, err
	}

	var findings []finding.Finding
	pager := computeClient.NewListAllPager(nil)
	for pager.More() {
		if ctx.Err() != nil {
			break
		}
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, vm := range page.Value {
			if vm.Name == nil || vm.Properties == nil {
				continue
			}
			findings = append(findings, evaluateVM(ctx, nicClient, *vm.Name, vm.Properties, subID, asset)...)
		}
	}
	return findings, nil
}

// evaluateVM checks a single Azure VM for disk encryption and public IP exposure.
func evaluateVM(ctx context.Context, nicClient *armnetwork.InterfacesClient, name string, props *armcompute.VirtualMachineProperties, subID, asset string) []finding.Finding {
	var findings []finding.Finding

	// Check disk encryption: either encryption at host or a disk encryption set on the OS disk.
	encryptionAtHost := false
	if props.SecurityProfile != nil && props.SecurityProfile.EncryptionAtHost != nil {
		encryptionAtHost = *props.SecurityProfile.EncryptionAtHost
	}
	hasDiskEncryptionSet := false
	if props.StorageProfile != nil && props.StorageProfile.OSDisk != nil &&
		props.StorageProfile.OSDisk.ManagedDisk != nil &&
		props.StorageProfile.OSDisk.ManagedDisk.DiskEncryptionSet != nil {
		hasDiskEncryptionSet = true
	}
	if !encryptionAtHost && !hasDiskEncryptionSet {
		findings = append(findings, finding.Finding{
			CheckID: finding.CheckCloudAzureVMNoDiskEncryption,
			Title:   fmt.Sprintf("Azure VM OS disk without encryption: %s", name),
			Description: fmt.Sprintf(
				"Virtual machine %s does not have encryption at host enabled and its OS disk "+
					"does not have a disk encryption set configured. Without disk encryption, "+
					"data at rest on the VM's OS disk is not protected against offline attacks. "+
					"Enable encryption at host or configure a disk encryption set.",
				name,
			),
			Severity:     finding.SeverityHigh,
			Asset:        asset,
			Scanner:      "cloud/azure",
			ProofCommand: fmt.Sprintf("az vm show --name %s --query '{encryptionAtHost: securityProfile.encryptionAtHost, diskEncryptionSet: storageProfile.osDisk.managedDisk.diskEncryptionSet}'", name),
			Evidence: map[string]any{
				"vm_name":         name,
				"subscription_id": subID,
				"resource_type":   "Microsoft.Compute/virtualMachines",
			},
			DiscoveredAt: time.Now(),
		})
	}

	// Check for public IP addresses on attached NICs.
	if props.NetworkProfile != nil {
		for _, nicRef := range props.NetworkProfile.NetworkInterfaces {
			if nicRef.ID == nil {
				continue
			}
			rg := extractResourceGroup(*nicRef.ID)
			nicName := extractResourceName(*nicRef.ID)
			if rg == "" || nicName == "" {
				continue
			}
			resp, err := nicClient.Get(ctx, rg, nicName, nil)
			if err != nil {
				continue
			}
			if resp.Properties == nil {
				continue
			}
			for _, ipConfig := range resp.Properties.IPConfigurations {
				if ipConfig.Properties == nil || ipConfig.Properties.PublicIPAddress == nil {
					continue
				}
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAzureVMPublicIP,
					Title:   fmt.Sprintf("Azure VM has a public IP address: %s", name),
					Description: fmt.Sprintf(
						"Virtual machine %s has a public IP address directly attached via "+
							"network interface %s. Direct public IP exposure increases the attack "+
							"surface by making the VM reachable from the internet. Use a load "+
							"balancer, Azure Bastion, or a VPN gateway instead of direct public IPs.",
						name, nicName,
					),
					Severity:     finding.SeverityHigh,
					Asset:        asset,
					Scanner:      "cloud/azure",
					ProofCommand: fmt.Sprintf("az vm list-ip-addresses --name %s --query '[].virtualMachine.network.publicIpAddresses'", name),
					Evidence: map[string]any{
						"vm_name":         name,
						"nic_name":        nicName,
						"subscription_id": subID,
						"resource_type":   "Microsoft.Compute/virtualMachines",
					},
					DiscoveredAt: time.Now(),
				})
				// One finding per VM is sufficient; break after first public IP found.
				return findings
			}
		}
	}

	return findings
}

// extractResourceName extracts the resource name (last segment) from an Azure resource ID.
func extractResourceName(resourceID string) string {
	parts := splitResourceID(resourceID)
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

// splitResourceID splits an Azure resource ID by "/".
func splitResourceID(resourceID string) []string {
	var parts []string
	current := ""
	for _, c := range resourceID {
		if c == '/' {
			if current != "" {
				parts = append(parts, current)
			}
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}
