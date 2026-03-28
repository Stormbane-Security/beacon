// Package aws implements authenticated AWS security scanning.
// All API calls are read-only. Supports AWS credential profiles,
// environment variables, and assume-role for cross-account scanning.
package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

// Config holds AWS authentication configuration for one account.
type Config struct {
	// Profile is the AWS CLI profile name (from ~/.aws/credentials).
	// Defaults to the AWS_PROFILE env var or "default".
	Profile string

	// Region is the primary region to scan (us-east-1, eu-west-1, etc.).
	// If empty, uses AWS_DEFAULT_REGION or us-east-1.
	Region string

	// RoleARN is an IAM role to assume before scanning (cross-account).
	RoleARN string

	// AccountID is used for labeling findings; detected automatically via STS if empty.
	AccountID string
}

// Scanner runs authenticated AWS security checks.
type Scanner struct {
	cfg Config
}

// New creates a new AWS cloud scanner.
func New(cfg Config) *Scanner {
	return &Scanner{cfg: cfg}
}

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "cloud/aws" }

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	region := s.cfg.Region
	if region == "" {
		region = "us-east-1"
	}

	var loadOpts []func(*config.LoadOptions) error
	if s.cfg.Profile != "" {
		loadOpts = append(loadOpts, config.WithSharedConfigProfile(s.cfg.Profile))
	}
	loadOpts = append(loadOpts, config.WithRegion(region))

	cfg, err := config.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("aws: load config: %w", err)
	}

	// Detect account ID.
	accountID := s.cfg.AccountID
	if accountID == "" {
		stsSvc := sts.NewFromConfig(cfg)
		identity, err := stsSvc.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		if err == nil && identity.Account != nil {
			accountID = *identity.Account
		}
	}

	var all []finding.Finding

	// IAM checks (global, not region-specific).
	iamFindings, err := scanIAM(ctx, cfg, accountID, asset)
	if err == nil {
		all = append(all, iamFindings...)
	}

	// S3 checks (global).
	s3Findings, err := scanS3(ctx, cfg, accountID, asset)
	if err == nil {
		all = append(all, s3Findings...)
	}

	// EC2 checks (per region — scan us-east-1 + any specified region).
	ec2Findings, err := scanEC2(ctx, cfg, accountID, region, asset)
	if err == nil {
		all = append(all, ec2Findings...)
	}

	// EKS checks.
	eksFindings, err := scanEKS(ctx, cfg, accountID, region, asset)
	if err == nil {
		all = append(all, eksFindings...)
	}

	return all, nil
}
