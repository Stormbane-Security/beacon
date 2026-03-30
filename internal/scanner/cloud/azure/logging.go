package azure

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"

	"github.com/stormbane/beacon/internal/finding"
)

func scanActivityLog(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID, asset string) ([]finding.Finding, error) {
	client, err := armmonitor.NewDiagnosticSettingsClient(cred, nil)
	if err != nil {
		return nil, err
	}

	resourceURI := "/subscriptions/" + subID
	pager := client.NewListPager(resourceURI, nil)

	hasLogAnalytics := false
	for pager.More() {
		if ctx.Err() != nil {
			break
		}
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, setting := range page.Value {
			if setting.Properties == nil {
				continue
			}
			// A diagnostic setting that sends to a Log Analytics workspace
			// satisfies the activity log export requirement.
			if setting.Properties.WorkspaceID != nil && *setting.Properties.WorkspaceID != "" {
				hasLogAnalytics = true
				break
			}
		}
		if hasLogAnalytics {
			break
		}
	}

	if !hasLogAnalytics {
		return []finding.Finding{{
			CheckID: finding.CheckCloudAzureNoActivityLog,
			Title:   fmt.Sprintf("Azure subscription has no activity log export to Log Analytics: %s", subID),
			Description: fmt.Sprintf(
				"Subscription %s does not have a diagnostic setting that exports activity logs "+
					"to a Log Analytics workspace. Without centralized log export, security-relevant "+
					"events (role assignments, policy changes, resource deletions) are only retained "+
					"for 90 days in the Azure portal and cannot be queried or alerted on. Create a "+
					"diagnostic setting that sends activity logs to a Log Analytics workspace.",
				subID,
			),
			Severity:     finding.SeverityHigh,
			Asset:        asset,
			Scanner:      "cloud/azure",
			ProofCommand: fmt.Sprintf("az monitor diagnostic-settings subscription list --subscription-id %s", subID),
			Evidence: map[string]any{
				"subscription_id": subID,
				"resource_type":   "Microsoft.Insights/diagnosticSettings",
			},
			DiscoveredAt: time.Now(),
		}}, nil
	}

	return nil, nil
}
