//go:build !no_cloud && !no_cloud_oci

package cloud

import (
	"context"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanner/cloud/oci"
)

func init() {
	registerProvider("oci", func(ctx context.Context, inp module.Input, scanType module.ScanType) ([]finding.Finding, error) {
		asset := inp.Domain
		if asset == "" {
			asset = "cloud"
		}
		cfg := oci.Config{
			ConfigFile: inp.OCIConfigFile,
		}
		return oci.New(cfg).Run(ctx, asset, scanType)
	})
}
