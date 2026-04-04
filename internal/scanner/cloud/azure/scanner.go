// Package azure implements authenticated Azure security scanning.
// Supports Azure CLI credentials, service principals, and managed identity.
package azure

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/subscription/armsubscription"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)

// Config holds Azure authentication configuration.
type Config struct {
	// SubscriptionIDs is the list of subscriptions to scan.
	// If empty, all accessible subscriptions are enumerated.
	SubscriptionIDs []string

	// TenantID, ClientID, ClientSecret are for service principal auth.
	// If empty, the Azure CLI / DefaultAzureCredential is used.
	TenantID     string
	ClientID     string
	ClientSecret string
}

// Scanner runs authenticated Azure security checks.
type Scanner struct {
	cfg Config
}

// New creates a new Azure cloud scanner.
func New(cfg Config) *Scanner {
	return &Scanner{cfg: cfg}
}

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "cloud/azure" }

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	cred, err := s.credential()
	if err != nil {
		return nil, fmt.Errorf("azure: credential: %w", err)
	}

	subscriptions := s.cfg.SubscriptionIDs
	if len(subscriptions) == 0 {
		discovered, err := listSubscriptions(ctx, cred)
		if err != nil {
			return nil, fmt.Errorf("azure: list subscriptions: %w", err)
		}
		subscriptions = discovered
	}

	var all []finding.Finding
	for _, subID := range subscriptions {
		findings, err := s.scanSubscription(ctx, cred, subID, asset)
		if err != nil {
			all = append(all, finding.Finding{
				CheckID:      finding.CheckCloudAzureScanError,
				Title:        fmt.Sprintf("Azure subscription scan failed: %s", subID),
				Description:  err.Error(),
				Severity:     finding.SeverityInfo,
				Asset:        asset,
				Scanner:      "cloud/azure",
				DiscoveredAt: time.Now(),
			})
			continue
		}
		all = append(all, findings...)
	}
	return all, nil
}

func (s *Scanner) credential() (azcore.TokenCredential, error) {
	if s.cfg.TenantID != "" && s.cfg.ClientID != "" && s.cfg.ClientSecret != "" {
		return azidentity.NewClientSecretCredential(s.cfg.TenantID, s.cfg.ClientID, s.cfg.ClientSecret, nil)
	}
	return azidentity.NewDefaultAzureCredential(nil)
}

func (s *Scanner) scanSubscription(ctx context.Context, cred azcore.TokenCredential, subID, asset string) ([]finding.Finding, error) {
	var findings []finding.Finding

	azureScanError := func(name string, err error) finding.Finding {
		return finding.Finding{
			CheckID:      finding.CheckCloudAzureScanError,
			Title:        fmt.Sprintf("Azure scan partial failure: %s", name),
			Description:  fmt.Sprintf("Azure %s scan failed: %v", name, err),
			Severity:     finding.SeverityInfo,
			Asset:        asset,
			Scanner:      "cloud/azure",
			DiscoveredAt: time.Now(),
		}
	}

	storageFindings, err := scanStorage(ctx, cred, subID, asset)
	if err == nil {
		findings = append(findings, storageFindings...)
	} else {
		findings = append(findings, azureScanError("Storage", err))
	}

	aksFindings, err := scanAKS(ctx, cred, subID, asset)
	if err == nil {
		findings = append(findings, aksFindings...)
	} else {
		findings = append(findings, azureScanError("AKS", err))
	}

	rbacFindings, err := scanRBAC(ctx, cred, subID, asset)
	if err == nil {
		findings = append(findings, rbacFindings...)
	} else {
		findings = append(findings, azureScanError("RBAC", err))
	}

	sqlFindings, err := scanSQL(ctx, cred, subID, asset)
	if err == nil {
		findings = append(findings, sqlFindings...)
	} else {
		findings = append(findings, azureScanError("SQL", err))
	}

	acrFindings, err := scanACR(ctx, cred, subID, asset)
	if err == nil {
		findings = append(findings, acrFindings...)
	} else {
		findings = append(findings, azureScanError("ACR", err))
	}

	activityLogFindings, err := scanActivityLog(ctx, cred, subID, asset)
	if err == nil {
		findings = append(findings, activityLogFindings...)
	} else {
		findings = append(findings, azureScanError("ActivityLog", err))
	}

	// Security checks (NSG flow logs, Defender, Key Vault, App Service, SQL ATP)
	securityFindings, err := scanSecurity(ctx, cred, subID, asset)
	if err == nil {
		findings = append(findings, securityFindings...)
	} else {
		findings = append(findings, azureScanError("Security", err))
	}

	vmFindings, err := scanVMs(ctx, cred, subID, asset)
	if err == nil {
		findings = append(findings, vmFindings...)
	} else {
		findings = append(findings, azureScanError("VMs", err))
	}

	cosmosFindings, err := scanCosmosDB(ctx, cred, subID, asset)
	if err == nil {
		findings = append(findings, cosmosFindings...)
	} else {
		findings = append(findings, azureScanError("CosmosDB", err))
	}

	functionAppFindings, err := scanFunctionApps(ctx, cred, subID, asset)
	if err == nil {
		findings = append(findings, functionAppFindings...)
	} else {
		findings = append(findings, azureScanError("FunctionApps", err))
	}

	redisFindings, err := scanRedis(ctx, cred, subID, asset)
	if err == nil {
		findings = append(findings, redisFindings...)
	} else {
		findings = append(findings, azureScanError("Redis", err))
	}

	postgresFindings, err := scanPostgres(ctx, cred, subID, asset)
	if err == nil {
		findings = append(findings, postgresFindings...)
	} else {
		findings = append(findings, azureScanError("Postgres", err))
	}

	mfaFindings, err := scanConditionalAccessMFA(ctx, cred, subID, asset)
	if err == nil {
		findings = append(findings, mfaFindings...)
	} else {
		findings = append(findings, azureScanError("ConditionalAccessMFA", err))
	}

	return findings, nil
}

func listSubscriptions(ctx context.Context, cred azcore.TokenCredential) ([]string, error) {
	client, err := armsubscription.NewSubscriptionsClient(cred, nil)
	if err != nil {
		return nil, err
	}
	var ids []string
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, sub := range page.Value {
			if sub.SubscriptionID != nil {
				ids = append(ids, *sub.SubscriptionID)
			}
		}
	}
	return ids, nil
}
