//go:build !no_cloud && !no_cloud_digitalocean

package cloud

import (
	"context"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanner/cloud/digitalocean"
)

func init() {
	registerProvider("digitalocean", func(ctx context.Context, inp module.Input, scanType module.ScanType) ([]finding.Finding, error) {
		if inp.DOToken == "" {
			return nil, nil // no credentials — skip silently
		}
		asset := inp.Domain
		if asset == "" {
			asset = "cloud"
		}
		cfg := digitalocean.Config{
			Token: inp.DOToken,
		}
		return digitalocean.New(cfg).Run(ctx, asset, scanType)
	})
}
