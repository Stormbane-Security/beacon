// Package gcp implements authenticated Google Cloud Platform security scanning.
// It uses Application Default Credentials (gcloud auth application-default login)
// or a service account key file. All API calls are read-only.
package gcp

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/option"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

// Config holds GCP authentication configuration.
type Config struct {
	// ProjectIDs is the list of GCP project IDs to scan.
	// If empty, the scanner uses the project from ADC.
	ProjectIDs []string

	// ServiceAccountKeyFile is the path to a service account JSON key.
	// If empty, Application Default Credentials are used.
	ServiceAccountKeyFile string
}

// Scanner runs authenticated GCP security checks.
type Scanner struct {
	cfg Config
}

// New creates a new GCP cloud scanner.
func New(cfg Config) *Scanner {
	return &Scanner{cfg: cfg}
}

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "cloud/gcp" }

// Run implements scanner.Scanner.
// asset is the root domain being scanned — used only for finding attribution.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	opts := s.clientOptions()

	projects := s.cfg.ProjectIDs
	if len(projects) == 0 {
		// Discover projects the credentials have access to.
		discovered, err := listProjects(ctx, opts)
		if err != nil {
			return nil, fmt.Errorf("gcp: list projects: %w", err)
		}
		projects = discovered
	}

	var all []finding.Finding
	for _, projectID := range projects {
		findings, err := s.scanProject(ctx, projectID, asset, opts)
		if err != nil {
			// Log and continue — one failed project shouldn't abort the whole scan.
			all = append(all, finding.Finding{
				CheckID:      finding.CheckCloudGCPScanError,
				Title:        fmt.Sprintf("GCP project scan failed: %s", projectID),
				Description:  err.Error(),
				Severity:     finding.SeverityInfo,
				Asset:        asset,
				Scanner:      "cloud/gcp",
				DiscoveredAt: time.Now(),
			})
			continue
		}
		all = append(all, findings...)
	}
	return all, nil
}

func (s *Scanner) scanProject(ctx context.Context, projectID, asset string, opts []option.ClientOption) ([]finding.Finding, error) {
	var findings []finding.Finding

	// IAM checks
	iamFindings, err := scanIAM(ctx, projectID, asset, opts)
	if err == nil {
		findings = append(findings, iamFindings...)
	}

	// GCS bucket checks
	bucketFindings, err := scanBuckets(ctx, projectID, asset, opts)
	if err == nil {
		findings = append(findings, bucketFindings...)
	}

	// Compute Engine checks
	computeFindings, err := scanCompute(ctx, projectID, asset, opts)
	if err == nil {
		findings = append(findings, computeFindings...)
	}

	// GKE checks
	gkeFindings, err := scanGKE(ctx, projectID, asset, opts)
	if err == nil {
		findings = append(findings, gkeFindings...)
	}

	return findings, nil
}

func (s *Scanner) clientOptions() []option.ClientOption {
	if s.cfg.ServiceAccountKeyFile != "" {
		return []option.ClientOption{
			option.WithCredentialsFile(s.cfg.ServiceAccountKeyFile),
		}
	}
	// Use Application Default Credentials.
	return nil
}

func listProjects(ctx context.Context, opts []option.ClientOption) ([]string, error) {
	svc, err := cloudresourcemanager.NewService(ctx, opts...)
	if err != nil {
		return nil, err
	}
	var projects []string
	req := svc.Projects.List()
	if err := req.Pages(ctx, func(page *cloudresourcemanager.ListProjectsResponse) error {
		for _, p := range page.Projects {
			if p.LifecycleState == "ACTIVE" {
				projects = append(projects, p.ProjectId)
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return projects, nil
}
