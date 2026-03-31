// Package ghorg scans GitHub organisation-level security configuration.
//
// It uses the GitHub REST API v3 (orgs, actions endpoints). An authenticated
// token (BEACON_GITHUB_TOKEN) with read:org scope is required for most checks.
// Unauthenticated requests only see public org data and quickly hit rate limits.
package ghorg

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const scannerName = "github.org"

// Scanner checks org-level security configuration via the GitHub API.
type Scanner struct {
	token      string
	httpClient *http.Client
}

// New creates a Scanner. githubToken should have read:org scope for full coverage.
func New(githubToken string) *Scanner {
	return &Scanner{
		token:      githubToken,
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
}

func (s *Scanner) Name() string { return scannerName }

// Run scans the given org name for security misconfigurations.
func (s *Scanner) Run(ctx context.Context, target string, _ module.ScanType) ([]finding.Finding, error) {
	org := sanitizePathSegment(target)

	var all []finding.Finding

	meta, err := s.getOrgMeta(ctx, org)
	if err != nil {
		return nil, fmt.Errorf("ghorg: fetching org %q: %w", org, err)
	}

	// MFA requirement.
	if !meta.TwoFactorRequirementEnabled {
		all = append(all, finding.Finding{
			CheckID:  finding.CheckGitHubOrgMFANotRequired,
			Module:   "github",
			Scanner:  scannerName,
			Severity: finding.SeverityCritical,
			Asset:    org,
			Title:    "Organisation does not require two-factor authentication",
			Description: "The GitHub organisation does not enforce two-factor authentication (2FA/MFA) " +
				"for all members. Any member account without MFA is a single-password target: one " +
				"phished or reused credential grants an attacker push access to every repository the " +
				"member can access, including production infrastructure. Enable the MFA requirement " +
				"under Organisation Settings > Authentication security > Require two-factor " +
				"authentication for everyone in your organisation.",
			Evidence:     map[string]any{"two_factor_requirement_enabled": false},
			ProofCommand: fmt.Sprintf("gh api /orgs/%s --jq '.two_factor_requirement_enabled'", org),
			DiscoveredAt: time.Now(),
		})
	}

	// Public repository count — informational context.
	if meta.PublicRepos > 0 {
		all = append(all, finding.Finding{
			CheckID:  finding.CheckGitHubPublicRepos,
			Module:   "github",
			Scanner:  scannerName,
			Severity: finding.SeverityInfo,
			Asset:    org,
			Title:    fmt.Sprintf("Organisation has %d public repositories", meta.PublicRepos),
			Description: fmt.Sprintf(
				"The organisation %q has %d public repositories. Public repositories are readable by "+
					"anyone on the internet, including their full git history, Actions workflow files, "+
					"and any accidentally committed secrets. Audit public repositories periodically and "+
					"consider whether each should be public or private.",
				org, meta.PublicRepos),
			Evidence:     map[string]any{"public_repos": meta.PublicRepos},
			DiscoveredAt: time.Now(),
		})
	}

	// Actions permissions and fork PR policy (requires token).
	if s.token != "" {
		if ap, err := s.getOrgActionsPermissions(ctx, org); err == nil {
			if ap.AllowedActions == "all" {
				all = append(all, finding.Finding{
					CheckID:  finding.CheckGitHubActionsUnrestricted,
					Module:   "github",
					Scanner:  scannerName,
					Severity: finding.SeverityMedium,
					Asset:    org,
					Title:    "Organisation allows all GitHub Actions (no allow-list)",
					Description: "The organisation permits all GitHub Actions to run across member " +
						"repositories without restriction. Any action published to the Marketplace " +
						"(or any public repo) can be referenced in a workflow and executed with access " +
						"to repository secrets. Restrict allowed actions to GitHub-owned actions and " +
						"a curated list under Organisation Settings > Actions > General > " +
						"Allow actions and reusable workflows.",
					Evidence:     map[string]any{"allowed_actions": "all"},
					ProofCommand: fmt.Sprintf("gh api /orgs/%s/actions/permissions", org),
					DiscoveredAt: time.Now(),
				})
			}

			if ap.ForkPRWorkflowsPolicy == "run_workflows" || ap.ForkPRWorkflowsPolicy == "" {
				all = append(all, finding.Finding{
					CheckID:  finding.CheckGitHubForkWorkflowApproval,
					Module:   "github",
					Scanner:  scannerName,
					Severity: finding.SeverityHigh,
					Asset:    org,
					Title:    "Fork pull request workflows run without approval gate",
					Description: "The organisation does not require approval before running workflows " +
						"from fork pull requests. An external contributor can open a fork PR that " +
						"triggers workflows with access to repository secrets — even if the PR changes " +
						"only documentation. Set the fork PR approval policy to require approval for " +
						"all outside collaborators (or all contributors) under Organisation Settings > " +
						"Actions > General > Fork pull request workflows.",
					Evidence:     map[string]any{"fork_pr_workflows_policy": ap.ForkPRWorkflowsPolicy},
					ProofCommand: fmt.Sprintf("gh api /orgs/%s/actions/permissions", org),
					DiscoveredAt: time.Now(),
				})
			}
		}

		// Default workflow token permissions at org level.
		if wp, err := s.getOrgWorkflowPermissions(ctx, org); err == nil {
			if wp.DefaultWorkflowPermissions == "write" {
				all = append(all, finding.Finding{
					CheckID:  finding.CheckGitHubDefaultTokenWrite,
					Module:   "github",
					Scanner:  scannerName,
					Severity: finding.SeverityHigh,
					Asset:    org,
					Title:    "Organisation default GITHUB_TOKEN permission is read-write",
					Description: "The organisation default workflow token permission is 'write', meaning " +
						"every workflow in every repository inherits write access to contents, packages, " +
						"and other scopes unless explicitly restricted. A compromised workflow step can " +
						"push code, create releases, or modify repository settings. Set the default to " +
						"'read' under Organisation Settings > Actions > Workflow permissions.",
					Evidence:     map[string]any{"default_workflow_permissions": "write"},
					ProofCommand: fmt.Sprintf("gh api /orgs/%s/actions/permissions/workflow", org),
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return all, nil
}

// -------------------------------------------------------------------------
// API types
// -------------------------------------------------------------------------

type ghOrgMeta struct {
	TwoFactorRequirementEnabled bool `json:"two_factor_requirement_enabled"`
	PublicRepos                 int  `json:"public_repos"`
}

type ghOrgActionsPermissions struct {
	AllowedActions string `json:"allowed_actions"` // "all", "local_only", "selected"
	// The fork PR approval policy is returned under a different key by the
	// /orgs/{org}/actions/permissions endpoint depending on GHES vs GHEC.
	// GHEC uses "fork_pull_request_workflows_policy"; earlier API versions
	// used "default_workflow_permissions" (colliding with the workflow perms
	// endpoint).  We map the correct field name here.
	ForkPRWorkflowsPolicy string `json:"fork_pull_request_workflows_policy"`
}

type ghOrgWorkflowPermissions struct {
	DefaultWorkflowPermissions   string `json:"default_workflow_permissions"`
	CanApprovePullRequestReviews bool   `json:"can_approve_pull_request_reviews"`
}

// -------------------------------------------------------------------------
// API helpers
// -------------------------------------------------------------------------

func (s *Scanner) getOrgMeta(ctx context.Context, org string) (ghOrgMeta, error) {
	body, err := s.apiGet(ctx, fmt.Sprintf("https://api.github.com/orgs/%s", org))
	if err != nil {
		return ghOrgMeta{}, err
	}
	var meta ghOrgMeta
	return meta, json.Unmarshal(body, &meta)
}

func (s *Scanner) getOrgActionsPermissions(ctx context.Context, org string) (ghOrgActionsPermissions, error) {
	body, err := s.apiGet(ctx, fmt.Sprintf("https://api.github.com/orgs/%s/actions/permissions", org))
	if err != nil {
		return ghOrgActionsPermissions{}, err
	}
	var ap ghOrgActionsPermissions
	return ap, json.Unmarshal(body, &ap)
}

func (s *Scanner) getOrgWorkflowPermissions(ctx context.Context, org string) (ghOrgWorkflowPermissions, error) {
	body, err := s.apiGet(ctx, fmt.Sprintf("https://api.github.com/orgs/%s/actions/permissions/workflow", org))
	if err != nil {
		return ghOrgWorkflowPermissions{}, err
	}
	var wp ghOrgWorkflowPermissions
	return wp, json.Unmarshal(body, &wp)
}

func (s *Scanner) apiGet(ctx context.Context, urlStr string) ([]byte, error) {
	return s.apiGetRetry(ctx, urlStr, true)
}

func (s *Scanner) apiGetRetry(ctx context.Context, urlStr string, retryOnRateLimit bool) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if s.token != "" {
		req.Header.Set("Authorization", "token "+s.token)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Handle GitHub API rate limiting: 403 with X-RateLimit-Remaining: 0.
	if resp.StatusCode == http.StatusForbidden && retryOnRateLimit {
		remaining := resp.Header.Get("X-RateLimit-Remaining")
		resetHeader := resp.Header.Get("X-RateLimit-Reset")
		if remaining == "0" && resetHeader != "" {
			resetUnix, parseErr := strconv.ParseInt(resetHeader, 10, 64)
			if parseErr == nil {
				wait := time.Until(time.Unix(resetUnix, 0))
				if wait > 0 && wait <= 60*time.Second {
					select {
					case <-time.After(wait):
					case <-ctx.Done():
						return nil, ctx.Err()
					}
					return s.apiGetRetry(ctx, urlStr, false)
				}
			}
		}
		return nil, fmt.Errorf("GitHub API %s: HTTP %d (rate limited)", urlStr, resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API %s: HTTP %d", urlStr, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// sanitizePathSegment strips path-traversal sequences, slashes, and query
// parameters from a user-supplied value before embedding it in a URL path.
// This prevents SSRF via crafted org/repo names like "../../other" or
// "org?q=inject".
func sanitizePathSegment(s string) string {
	// Remove anything after a '?' or '#' (query/fragment injection).
	if idx := strings.IndexAny(s, "?#"); idx >= 0 {
		s = s[:idx]
	}
	// Percent-encode the segment so slashes and dots are escaped.
	return url.PathEscape(s)
}
