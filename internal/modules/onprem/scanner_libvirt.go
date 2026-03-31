//go:build !no_onprem && !no_onprem_libvirt

package onprem

import (
	"context"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
	"github.com/stormbane/beacon/internal/scanner/onprem/libvirt"
)

func init() {
	registerScanner("libvirt", func(ctx context.Context, inp module.Input, scanType module.ScanType) ([]finding.Finding, error) {
		asset := inp.Domain
		if asset == "" {
			asset = "onprem"
		}
		cfg := libvirt.Config{
			Endpoint:      inp.LibvirtEndpoint,
			SkipTLSVerify: true,
		}
		return libvirt.New(cfg).Run(ctx, asset, scanType)
	})
}
