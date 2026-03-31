//go:build !no_cloud && !no_cloud_gcp

package cloud

import (
	"context"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
	"github.com/stormbane/beacon/internal/scanner/cloud/gcp"
)

func init() {
	registerProvider("gcp", func(ctx context.Context, inp module.Input, scanType module.ScanType) ([]finding.Finding, error) {
		asset := inp.Domain
		if asset == "" {
			asset = "cloud"
		}
		cfg := gcp.Config{
			ServiceAccountKeyFile: inp.GCPCredentialsFile,
		}
		return gcp.New(cfg).Run(ctx, asset, scanType)
	})
}
