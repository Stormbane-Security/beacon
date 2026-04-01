//go:build !no_cloud && !no_cloud_aws

package cloud

import (
	"context"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanner/cloud/aws"
)

func init() {
	registerProvider("aws", func(ctx context.Context, inp module.Input, scanType module.ScanType) ([]finding.Finding, error) {
		asset := inp.Domain
		if asset == "" {
			asset = "cloud"
		}
		cfg := aws.Config{
			Profile: inp.AWSProfile,
		}
		return aws.New(cfg).Run(ctx, asset, scanType)
	})
}
