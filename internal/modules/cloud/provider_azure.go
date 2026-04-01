//go:build !no_cloud && !no_cloud_azure

package cloud

import (
	"context"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanner/cloud/azure"
)

func init() {
	registerProvider("azure", func(ctx context.Context, inp module.Input, scanType module.ScanType) ([]finding.Finding, error) {
		asset := inp.Domain
		if asset == "" {
			asset = "cloud"
		}
		cfg := azure.Config{}
		if inp.AzureSubscriptionID != "" {
			cfg.SubscriptionIDs = []string{inp.AzureSubscriptionID}
		}
		return azure.New(cfg).Run(ctx, asset, scanType)
	})
}
