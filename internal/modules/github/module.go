// Package github implements the GitHub/CI scan module.
// It scans GitHub organisations and repositories for Actions workflow
// security misconfigurations using the ghactions scanner, for
// repository/org configuration issues using the ghrepo scanner, and for
// organisation-level settings using the ghorg scanner.
package github

import (
	"context"
	"fmt"
	"strings"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanner/ghactions"
	"github.com/stormbane-security/beacon/internal/scanner/ghorg"
	"github.com/stormbane-security/beacon/internal/scanner/ghrepo"
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
	var all []finding.Finding

	// Per-repo scanners require an "owner/repo" target. Only run them when
	// both org and repo are available (or repo contains a full slug).
	if target, err := resolveTarget(input); err == nil {
		// GitHub Actions workflow analysis.
		actionsScanner := ghactions.New(m.token)
		actionsFindings, err := actionsScanner.Run(ctx, target, scanType)
		if err != nil {
			return nil, fmt.Errorf("github module (actions): %w", err)
		}
		all = append(all, actionsFindings...)

		// Repository configuration checks.
		repoScanner := ghrepo.New(m.token)
		repoFindings, err := repoScanner.Run(ctx, target, scanType)
		if err != nil {
			// Non-fatal: repo config checks may fail due to auth requirements.
			// Still return actions findings.
			return all, fmt.Errorf("github module (repo): %w", err)
		}
		all = append(all, repoFindings...)
	}

	// Organisation-level checks (MFA, actions policy, default token permissions).
	// These only require an org name and are skipped when no org is provided.
	if org := resolveOrg(input); org != "" {
		orgScanner := ghorg.New(m.token)
		orgFindings, _ := orgScanner.Run(ctx, org, scanType)
		all = append(all, orgFindings...)
	}

	return all, nil
}

// resolveTarget builds an "owner/repo" string from the module input.
// It requires both an org and a repo. If GitHubRepo already contains a
// full "owner/repo" slug, GitHubOrg may be empty (the owner is extracted
// from the slug).
func resolveTarget(input module.Input) (string, error) {
	org := input.GitHubOrg
	repo := input.GitHubRepo

	// If repo contains a slash, treat it as a full "owner/repo" slug.
	if repo != "" && strings.Contains(repo, "/") {
		return repo, nil
	}

	if org == "" {
		return "", fmt.Errorf("github module: GitHubOrg is required when GitHubRepo is not a full slug")
	}
	if repo == "" {
		return "", fmt.Errorf("github module: GitHubRepo is required for per-repo scanning")
	}
	return org + "/" + repo, nil
}

// resolveOrg returns the GitHub organisation name from the input. If
// GitHubOrg is empty but GitHubRepo contains a full "owner/repo" slug,
// the owner portion is extracted.
func resolveOrg(input module.Input) string {
	if input.GitHubOrg != "" {
		return input.GitHubOrg
	}
	if input.GitHubRepo != "" && strings.Contains(input.GitHubRepo, "/") {
		parts := strings.SplitN(input.GitHubRepo, "/", 2)
		return parts[0]
	}
	return ""
}
