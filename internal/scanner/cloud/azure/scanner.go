// Package azure implements authenticated Azure security scanning.
// Supports Azure CLI credentials, service principals, and managed identity.
package azure

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/subscription/armsubscription"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
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

func (s *Scanner) credential() (*azidentity.DefaultAzureCredential, error) {
	// For service principal, set env vars AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET
	// before calling; DefaultAzureCredential picks them up automatically.
	// This also works with az login (CLI) and managed identity.
	return azidentity.NewDefaultAzureCredential(nil)
}

func (s *Scanner) scanSubscription(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID, asset string) ([]finding.Finding, error) {
	var findings []finding.Finding

	storageFindings, err := scanStorage(ctx, cred, subID, asset)
	if err == nil {
		findings = append(findings, storageFindings...)
	}

	aksFindings, err := scanAKS(ctx, cred, subID, asset)
	if err == nil {
		findings = append(findings, aksFindings...)
	}

	rbacFindings, err := scanRBAC(ctx, cred, subID, asset)
	if err == nil {
		findings = append(findings, rbacFindings...)
	}

	return findings, nil
}

func listSubscriptions(ctx context.Context, cred *azidentity.DefaultAzureCredential) ([]string, error) {
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
