// Package aws implements authenticated AWS security scanning.
// All API calls are read-only. Supports AWS credential profiles,
// environment variables, and assume-role for cross-account scanning.
package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
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

	// RDS checks.
	rdsFindings, err := scanRDS(ctx, cfg, accountID, region, asset)
	if err == nil {
		all = append(all, rdsFindings...)
	}

	// ECR checks.
	ecrFindings, err := scanECR(ctx, cfg, accountID, region, asset)
	if err == nil {
		all = append(all, ecrFindings...)
	}

	// CloudTrail checks.
	ctFindings, err := scanCloudTrail(ctx, cfg, accountID, region, asset)
	if err == nil {
		all = append(all, ctFindings...)
	}

	// Security posture checks (GuardDuty, Security Hub, Config, KMS, Lambda, API Gateway, SNS, SQS, Secrets Manager).
	secFindings, err := scanSecurity(ctx, cfg, accountID, region, asset)
	if err == nil {
		all = append(all, secFindings...)
	}

	// Lambda extended checks.
	lambdaFindings, err := scanLambda(ctx, cfg, accountID, region, asset)
	if err == nil {
		all = append(all, lambdaFindings...)
	}

	// ELB/ALB checks.
	elbFindings, err := scanELB(ctx, cfg, accountID, region, asset)
	if err == nil {
		all = append(all, elbFindings...)
	}

	// ECS checks.
	ecsFindings, err := scanECS(ctx, cfg, accountID, region, asset)
	if err == nil {
		all = append(all, ecsFindings...)
	}

	// DynamoDB checks.
	dynamoFindings, err := scanDynamoDB(ctx, cfg, accountID, region, asset)
	if err == nil {
		all = append(all, dynamoFindings...)
	}

	// ElastiCache checks.
	ecacheFindings, err := scanElastiCache(ctx, cfg, accountID, region, asset)
	if err == nil {
		all = append(all, ecacheFindings...)
	}

	// CloudFront checks (global — no region).
	cfFindings, err := scanCloudFront(ctx, cfg, accountID, asset)
	if err == nil {
		all = append(all, cfFindings...)
	}

	// OpenSearch checks.
	osFindings, err := scanOpenSearch(ctx, cfg, accountID, region, asset)
	if err == nil {
		all = append(all, osFindings...)
	}

	// Redshift checks.
	rsFindings, err := scanRedshift(ctx, cfg, accountID, region, asset)
	if err == nil {
		all = append(all, rsFindings...)
	}

	// Route 53 checks.
	r53Findings, err := scanRoute53(ctx, cfg, accountID, region, asset)
	if err == nil {
		all = append(all, r53Findings...)
	}

	// Cognito checks.
	cognitoFindings, err := scanCognito(ctx, cfg, accountID, region, asset)
	if err == nil {
		all = append(all, cognitoFindings...)
	}

	// CloudWatch Logs checks.
	cwFindings, err := scanCloudWatch(ctx, cfg, accountID, region, asset)
	if err == nil {
		all = append(all, cwFindings...)
	}

	// SSM Parameter Store checks.
	ssmFindings, err := scanSSM(ctx, cfg, accountID, region, asset)
	if err == nil {
		all = append(all, ssmFindings...)
	}

	// WAF checks.
	wafFindings, err := scanWAF(ctx, cfg, accountID, region, asset)
	if err == nil {
		all = append(all, wafFindings...)
	}

	// Kinesis checks.
	kinesisFindings, err := scanKinesis(ctx, cfg, accountID, region, asset)
	if err == nil {
		all = append(all, kinesisFindings...)
	}

	// DocumentDB checks.
	docdbFindings, err := scanDocumentDB(ctx, cfg, accountID, region, asset)
	if err == nil {
		all = append(all, docdbFindings...)
	}

	// SES checks.
	sesFindings, err := scanSES(ctx, cfg, accountID, region, asset)
	if err == nil {
		all = append(all, sesFindings...)
	}

	// RDS extended checks (auto-upgrade, deletion protection, IAM auth).
	rdsExtFindings, err := scanRDSExtended(ctx, cfg, accountID, region, asset)
	if err == nil {
		all = append(all, rdsExtFindings...)
	}

	// IAM MFA enforcement checks.
	mfaFindings, err := scanIAMMFA(ctx, cfg, accountID, asset)
	if err == nil {
		all = append(all, mfaFindings...)
	}

	return all, nil
}
