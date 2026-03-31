//go:build !no_onprem && !no_onprem_kubernetes

package onprem

import (
	"context"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
	"github.com/stormbane/beacon/internal/scanner/onprem/kubernetes"
)

func init() {
	registerScanner("kubernetes", func(ctx context.Context, inp module.Input, scanType module.ScanType) ([]finding.Finding, error) {
		asset := inp.Domain
		if asset == "" {
			asset = "onprem"
		}
		cfg := kubernetes.Config{
			KubeconfigPath: inp.KubeconfigPath,
			SkipTLSVerify:  true, // on-prem K8s often has self-signed certs
		}
		return kubernetes.New(cfg).Run(ctx, asset, scanType)
	})
}
