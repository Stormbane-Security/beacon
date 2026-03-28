// Package cloud implements the Beacon cloud posture scan module.
// It runs authenticated checks against GCP, AWS, and Azure using the
// credentials provided in the scan Input.
package cloud

import (
	"context"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
	"github.com/stormbane/beacon/internal/scanner/cloud/aws"
	"github.com/stormbane/beacon/internal/scanner/cloud/azure"
	"github.com/stormbane/beacon/internal/scanner/cloud/gcp"
)

// Module runs cloud posture checks across GCP, AWS, and Azure.
type Module struct{}

// New creates a cloud module.
func New() *Module { return &Module{} }

// Name implements module.Module.
func (m *Module) Name() string { return "cloud" }

// RequiredInputs implements module.Module.
func (m *Module) RequiredInputs() []module.InputType { return []module.InputType{module.InputCloud} }

// Run implements module.Module.
// It runs whichever cloud scanners have credentials available in the Input.
func (m *Module) Run(ctx context.Context, inp module.Input, _ module.ScanType) ([]finding.Finding, error) {
	asset := inp.Domain
	if asset == "" {
		asset = "cloud"
	}

	var all []finding.Finding

	// GCP — use ADC by default; key file if provided.
	gcpCfg := gcp.Config{
		ServiceAccountKeyFile: inp.GCPCredentialsFile,
	}
	gcpScanner := gcp.New(gcpCfg)
	if gcpFindings, err := gcpScanner.Run(ctx, asset, module.ScanDeep); err == nil {
		all = append(all, gcpFindings...)
	}

	// AWS — use default profile/env unless AWSProfile is set.
	awsCfg := aws.Config{
		Profile: inp.AWSProfile,
	}
	awsScanner := aws.New(awsCfg)
	if awsFindings, err := awsScanner.Run(ctx, asset, module.ScanDeep); err == nil {
		all = append(all, awsFindings...)
	}

	// Azure — DefaultAzureCredential handles CLI, env vars, and managed identity.
	azureCfg := azure.Config{
		SubscriptionIDs: []string{},
	}
	if inp.AzureSubscriptionID != "" {
		azureCfg.SubscriptionIDs = []string{inp.AzureSubscriptionID}
	}
	azureScanner := azure.New(azureCfg)
	if azureFindings, err := azureScanner.Run(ctx, asset, module.ScanDeep); err == nil {
		all = append(all, azureFindings...)
	}

	return all, nil
}
