package azure

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"

	"github.com/stormbane/beacon/internal/finding"
)

// broadRoles are Azure built-in roles that grant subscription-wide control.
var broadRoles = map[string]bool{
	"8e3af657-a8ff-443c-a75c-2fe8c4bcb635": true, // Owner
	"b24988ac-6180-42a0-ab88-20f7382dd24c": true, // Contributor
}

func scanRBAC(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID, asset string) ([]finding.Finding, error) {
	client, err := armauthorization.NewRoleAssignmentsClient(subID, cred, nil)
	if err != nil {
		return nil, err
	}

	scope := "/subscriptions/" + subID
	var findings []finding.Finding

	pager := client.NewListForScopePager(scope, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, assignment := range page.Value {
			if assignment.Properties == nil {
				continue
			}
			props := assignment.Properties
			roleDefID := strings.ToLower(lastSegment(fmt.Sprintf("%v", props.RoleDefinitionID)))

			if broadRoles[roleDefID] {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAzureOwnerDirect,
					Title:   "Azure subscription has direct Owner/Contributor assignment",
					Description: fmt.Sprintf(
						"A principal has been directly assigned the Owner or Contributor role on subscription %s. "+
							"Broad role assignments at the subscription scope violate least privilege. "+
							"Use more specific roles scoped to resource groups, or use Azure PIM for "+
							"just-in-time privileged access.",
						subID,
					),
					Severity:     finding.SeverityHigh,
					Asset:        asset,
					Scanner:      "cloud/azure",
					ProofCommand: fmt.Sprintf("az role assignment list --subscription %s --query \"[?roleDefinitionName=='Owner' || roleDefinitionName=='Contributor']\"", subID),
					Evidence: map[string]any{
						"subscription_id":    subID,
						"principal_id":       fmt.Sprintf("%v", props.PrincipalID),
						"role_definition_id": fmt.Sprintf("%v", props.RoleDefinitionID),
					},
					DiscoveredAt: time.Now(),
				})
			}
		}
	}
	return findings, nil
}

func lastSegment(s string) string {
	parts := strings.Split(s, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return s
}
