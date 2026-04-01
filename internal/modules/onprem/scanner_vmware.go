//go:build !no_onprem && !no_onprem_vmware

package onprem

import (
	"context"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanner/onprem/vmware"
)

func init() {
	registerScanner("vmware", func(ctx context.Context, inp module.Input, scanType module.ScanType) ([]finding.Finding, error) {
		asset := inp.Domain
		if asset == "" {
			asset = "onprem"
		}
		cfg := vmware.Config{
			Endpoint:      inp.VMwareEndpoint,
			Username:      inp.VMwareUsername,
			Password:      inp.VMwarePassword,
			SkipTLSVerify: inp.VMwareSkipTLS,
		}
		return vmware.New(cfg, nil).Run(ctx, asset, scanType)
	})
}
