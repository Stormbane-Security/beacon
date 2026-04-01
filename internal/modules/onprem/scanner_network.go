//go:build !no_onprem && !no_onprem_network

package onprem

import (
	"context"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanner/onprem/network"
)

func init() {
	registerScanner("network", func(ctx context.Context, inp module.Input, scanType module.ScanType) ([]finding.Finding, error) {
		asset := inp.Domain
		if asset == "" {
			asset = "onprem"
		}
		cfg := network.Config{
			Targets: inp.NetworkTargets,
		}
		return network.New(cfg).Run(ctx, asset, scanType)
	})
}
