//go:build !no_onprem && !no_onprem_nas

package onprem

import (
	"context"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
	"github.com/stormbane/beacon/internal/scanner/onprem/nas"
)

func init() {
	registerScanner("nas", func(ctx context.Context, inp module.Input, scanType module.ScanType) ([]finding.Finding, error) {
		asset := inp.Domain
		if asset == "" {
			asset = "onprem"
		}
		cfg := nas.Config{
			Endpoint:      inp.NASEndpoint,
			Username:      inp.NASUsername,
			Password:      inp.NASPassword,
			NASType:       inp.NASType,
			SkipTLSVerify: inp.NASSkipTLS,
		}
		return nas.New(cfg, nil).Run(ctx, asset, scanType)
	})
}
