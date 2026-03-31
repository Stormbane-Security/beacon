// Package cicd implements the CI/CD scan module for non-GitHub platforms.
// It probes self-hosted Jenkins, GitLab, and TeamCity instances for
// security misconfigurations using HTTP-based endpoint checks.
package cicd

import (
	"context"
	"fmt"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
	"github.com/stormbane/beacon/internal/scanner/gitlab"
	"github.com/stormbane/beacon/internal/scanner/jenkins"
	"github.com/stormbane/beacon/internal/scanner/teamcity"
)

// Module implements module.Module for CI/CD platform scanning.
type Module struct{}

// New creates a CICD module.
func New() *Module { return &Module{} }

func (m *Module) Name() string                       { return "cicd" }
func (m *Module) RequiredInputs() []module.InputType { return []module.InputType{module.InputDomain} }

// Run probes the target as a potential Jenkins, GitLab, or TeamCity instance.
// All three scanners run against the target — each scanner validates that the
// target is actually its platform before emitting findings.
func (m *Module) Run(ctx context.Context, input module.Input, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanDeep && scanType != module.ScanAuthorized {
		return nil, nil
	}

	target := input.Domain
	if target == "" {
		return nil, fmt.Errorf("cicd module: domain is required")
	}

	var all []finding.Finding

	// Jenkins
	jenkinsScanner := jenkins.New()
	jf, err := jenkinsScanner.Run(ctx, target, scanType)
	if err == nil {
		all = append(all, jf...)
	}

	// GitLab — probe both HTTPS and HTTP
	gitlabScanner := gitlab.New()
	for _, scheme := range []string{"https://", "http://"} {
		gf, err := gitlabScanner.Run(ctx, scheme+target, scanType)
		if err == nil && len(gf) > 0 {
			all = append(all, gf...)
			break // found findings on one scheme, don't double-count
		}
	}

	// TeamCity — probe both HTTPS and HTTP
	teamcityScanner := teamcity.New()
	for _, scheme := range []string{"https://", "http://"} {
		tf, err := teamcityScanner.Run(ctx, scheme+target, scanType)
		if err == nil && len(tf) > 0 {
			all = append(all, tf...)
			break
		}
	}

	return all, nil
}
