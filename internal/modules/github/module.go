// Package github implements the GitHub/CI scan module.
// It scans GitHub organisations and repositories for Actions workflow
// security misconfigurations using the ghactions scanner, and for
// repository/org configuration issues using the ghrepo scanner.
package github

import (
	"context"
	"fmt"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
	"github.com/stormbane/beacon/internal/scanner/ghactions"
	"github.com/stormbane/beacon/internal/scanner/ghrepo"
)

// Module implements module.Module for GitHub/CI scanning.
type Module struct {
	token string // GitHub personal access token (optional)
}

// New creates a Module. Pass a GitHub personal access token to increase API
// rate limits and allow scanning private repositories. Pass an empty string
// for unauthenticated access (60 req/hour limit).
func New(githubToken string) *Module {
	return &Module{token: githubToken}
}

func (m *Module) Name() string                       { return "github" }
func (m *Module) RequiredInputs() []module.InputType { return []module.InputType{module.InputGitHub} }

// Run scans the GitHub org/repo specified in input for Actions workflow issues
// and repository configuration misconfigurations.
func (m *Module) Run(ctx context.Context, input module.Input, scanType module.ScanType) ([]finding.Finding, error) {
	target, err := resolveTarget(input)
	if err != nil {
		return nil, err
	}

	var all []finding.Finding

	// GitHub Actions workflow analysis.
	actionsScanner := ghactions.New(m.token)
	actionsFindings, err := actionsScanner.Run(ctx, target, scanType)
	if err != nil {
		return nil, fmt.Errorf("github module (actions): %w", err)
	}
	all = append(all, actionsFindings...)

	// Repository and org configuration checks.
	repoScanner := ghrepo.New(m.token)
	repoFindings, err := repoScanner.Run(ctx, target, scanType)
	if err != nil {
		// Non-fatal: repo config checks may fail due to auth requirements.
		// Still return actions findings.
		return all, fmt.Errorf("github module (repo): %w", err)
	}
	all = append(all, repoFindings...)

	return all, nil
}

// resolveTarget builds an "owner/repo" string from the module input.
// GitHubOrg and GitHubRepo are both required.
func resolveTarget(input module.Input) (string, error) {
	org := input.GitHubOrg
	repo := input.GitHubRepo

	if org == "" {
		return "", fmt.Errorf("github module: GitHubOrg is required")
	}
	if repo == "" {
		return "", fmt.Errorf("github module: GitHubRepo is required")
	}
	return org + "/" + repo, nil
}
