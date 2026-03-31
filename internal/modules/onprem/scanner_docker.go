//go:build !no_onprem && !no_onprem_docker

package onprem

import (
	"context"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
	"github.com/stormbane/beacon/internal/scanner/onprem/docker"
)

func init() {
	registerScanner("docker", func(ctx context.Context, inp module.Input, scanType module.ScanType) ([]finding.Finding, error) {
		asset := inp.Domain
		if asset == "" {
			asset = "onprem"
		}
		cfg := docker.Config{
			Endpoint: inp.DockerEndpoint,
		}
		return docker.New(cfg, nil).Run(ctx, asset, scanType)
	})
}
