//go:build !no_onprem && !no_onprem_proxmox

package onprem

import (
	"context"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanner/onprem/proxmox"
)

func init() {
	registerScanner("proxmox", func(ctx context.Context, inp module.Input, scanType module.ScanType) ([]finding.Finding, error) {
		asset := inp.Domain
		if asset == "" {
			asset = "onprem"
		}
		cfg := proxmox.Config{
			APIEndpoint:   inp.ProxmoxEndpoint,
			TokenID:       inp.ProxmoxTokenID,
			TokenSecret:   inp.ProxmoxTokenSecret,
			SkipTLSVerify: inp.ProxmoxSkipTLS,
		}
		return proxmox.New(cfg).Run(ctx, asset, scanType)
	})
}
