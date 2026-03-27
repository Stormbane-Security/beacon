// Package ghrepo scans GitHub repository and organisation configuration for
// security misconfigurations, absent security controls, and leaked secrets in
// committed source code.
//
// It uses the GitHub REST API v3 (repos, orgs, contents endpoints). An
// authenticated token (BEACON_GITHUB_TOKEN) is required for most checks;
// unauthenticated requests only see public repository data and quickly hit
// rate limits.
package ghrepo

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const scannerName = "github.repo"

// Scanner checks repo/org configuration and scans committed files for secrets.
type Scanner struct {
	token      string
	httpClient *http.Client
}

// New creates a Scanner. githubToken is required for private repos and org checks.
func New(githubToken string) *Scanner {
	return &Scanner{
		token:      githubToken,
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
}

func (s *Scanner) Name() string { return scannerName }

// Run scans repository configuration and source code for the given "owner/repo" target.
func (s *Scanner) Run(ctx context.Context, target string, _ module.ScanType) ([]finding.Finding, error) {
	owner, repo, ok := splitOwnerRepo(target)
	if !ok {
		return nil, fmt.Errorf("ghrepo: invalid target %q — expected owner/repo", target)
	}
	repoSlug := owner + "/" + repo

	var all []finding.Finding

	// Repo metadata (visibility, vulnerability alerts, secret scanning, etc.)
	repoMeta, err := s.getRepoMeta(ctx, owner, repo)
	if err == nil {
		all = append(all, checkRepoConfig(repoMeta, repoSlug)...)
	}

	// Vulnerability alerts.
	vulnAlertsEnabled, _ := s.vulnAlertsEnabled(ctx, owner, repo)
	if !vulnAlertsEnabled {
		all = append(all, finding.Finding{
			CheckID:  finding.CheckGitHubNoVulnAlerts,
			Module:   "github",
			Scanner:  scannerName,
			Severity: finding.SeverityMedium,
			Asset:    repoSlug,
			Title:    "Dependabot vulnerability alerts are disabled",
			Description: "Dependabot vulnerability alerts are not enabled for this repository. " +
				"Vulnerability alerts notify you when a dependency with a known CVE is detected " +
				"in your dependency graph, allowing you to update or remediate before the vulnerability " +
				"is exploited. Enable them under Settings > Code security and analysis > Dependabot alerts.",
			Evidence:     map[string]any{"vulnerability_alerts": "disabled"},
			DiscoveredAt: time.Now(),
		})
	}

	// Branch protection on the default branch.
	if repoMeta.DefaultBranch != "" {
		bp, err := s.getBranchProtection(ctx, owner, repo, repoMeta.DefaultBranch)
		if err != nil {
			// No protection at all — the API returns 404 when protection is absent.
			all = append(all, finding.Finding{
				CheckID:  finding.CheckGitHubNoBranchProtection,
				Module:   "github",
				Scanner:  scannerName,
				Severity: finding.SeverityHigh,
				Asset:    repoSlug,
				Title:    fmt.Sprintf("No branch protection on default branch %q", repoMeta.DefaultBranch),
				Description: fmt.Sprintf(
					"The default branch %q has no branch protection rules. Anyone with write access can "+
						"force-push commits, bypass required reviews, and merge unreviewed code directly "+
						"to the production branch. Enable branch protection with at minimum: required pull "+
						"request reviews (1+), dismiss stale reviews, and prevent force pushes.",
					repoMeta.DefaultBranch),
				Evidence:     map[string]any{"branch": repoMeta.DefaultBranch},
				DiscoveredAt: time.Now(),
			})
		} else {
			all = append(all, checkBranchProtection(bp, repoMeta.DefaultBranch, repoSlug)...)
		}
	}

	// Dependabot configuration (.github/dependabot.yml or dependabot.yaml).
	hasDependabot, _ := s.fileExists(ctx, owner, repo, ".github/dependabot.yml")
	if !hasDependabot {
		hasDependabot, _ = s.fileExists(ctx, owner, repo, ".github/dependabot.yaml")
	}
	if !hasDependabot {
		all = append(all, finding.Finding{
			CheckID:  finding.CheckGitHubNoDependabot,
			Module:   "github",
			Scanner:  scannerName,
			Severity: finding.SeverityMedium,
			Asset:    repoSlug,
			Title:    "Dependabot not configured",
			Description: "No .github/dependabot.yml file found. Dependabot automatically opens pull " +
				"requests to update outdated and vulnerable dependencies. Without it, dependency " +
				"vulnerabilities may go unpatched indefinitely. Add a dependabot.yml that covers all " +
				"package ecosystems used in this repository (npm, pip, go, docker, actions).",
			Evidence:     map[string]any{"config_file": ".github/dependabot.yml"},
			DiscoveredAt: time.Now(),
		})
	}

	// SAST: look for CodeQL, Semgrep, Snyk, Trivy, Grype, Checkov, or TruffleHog in workflows.
	// These are the most common SAST/SCA/secrets scanning tools used in GitHub Actions.
	sastTools := []string{"codeql", "semgrep", "snyk", "trivy", "grype", "checkov", "trufflehog", "gitleaks", "sonarqube", "sonarcloud"}
	hasSAST := false
	for _, tool := range sastTools {
		if found, _ := s.hasWorkflowWithPattern(ctx, owner, repo, tool); found {
			hasSAST = true
			break
		}
	}
	if !hasSAST {
		all = append(all, finding.Finding{
			CheckID:  finding.CheckGitHubNoSAST,
			Module:   "github",
			Scanner:  scannerName,
			Severity: finding.SeverityMedium,
			Asset:    repoSlug,
			Title:    "No SAST or security scanning workflow detected",
			Description: "No workflow file containing a SAST or security scanning tool was found " +
				"(checked for: CodeQL, Semgrep, Snyk, Trivy, Grype, Checkov, TruffleHog, Gitleaks, " +
				"SonarQube, SonarCloud). Static analysis automatically detects vulnerability classes " +
				"(SQL injection, XSS, path traversal, secrets in code) in pull requests before they " +
				"merge. Enable GitHub Code Scanning or add a security workflow for your stack.",
			Evidence:     map[string]any{"missing": "no sast/sca/secrets-scanning workflow found"},
			DiscoveredAt: time.Now(),
		})
	}

	// Dependency review: look for actions/dependency-review-action in PR workflows.
	hasDependencyReview, _ := s.hasWorkflowWithPattern(ctx, owner, repo, "dependency-review")
	if !hasDependencyReview {
		all = append(all, finding.Finding{
			CheckID:  finding.CheckGitHubNoDependencyReview,
			Module:   "github",
			Scanner:  scannerName,
			Severity: finding.SeverityMedium,
			Asset:    repoSlug,
			Title:    "No dependency review action in PR workflows",
			Description: "No workflow using actions/dependency-review-action was found. The dependency " +
				"review action blocks pull requests that introduce dependencies with known vulnerabilities " +
				"or license violations — before the dependency is merged. Without it, vulnerable " +
				"dependencies can be introduced silently. Add a pull_request workflow using " +
				"actions/dependency-review-action.",
			Evidence:     map[string]any{"missing": "actions/dependency-review-action"},
			DiscoveredAt: time.Now(),
		})
	}

	// Default workflow token permissions (requires token).
	if s.token != "" {
		if wp, err := s.getWorkflowPermissions(ctx, owner, repo); err == nil {
			if wp.DefaultWorkflowPermissions == "write" {
				all = append(all, finding.Finding{
					CheckID:  finding.CheckGitHubDefaultTokenWrite,
					Module:   "github",
					Scanner:  scannerName,
					Severity: finding.SeverityHigh,
					Asset:    repoSlug,
					Title:    "Default GITHUB_TOKEN permission is read-write",
					Description: "The repository default workflow token permission is set to 'write', " +
						"granting every workflow job write access to contents, packages, and other scopes " +
						"unless explicitly restricted. This violates the principle of least privilege: " +
						"a compromised workflow step or injected action can push code, create releases, " +
						"or modify repository settings. Set the default to 'read' under " +
						"Settings > Actions > Workflow permissions, then add explicit write permissions " +
						"per job with a `permissions:` block.",
					Evidence:     map[string]any{"default_workflow_permissions": "write"},
					DiscoveredAt: time.Now(),
				})
			}
		}

		// Actions allowed policy.
		if ap, err := s.getActionsPermissions(ctx, owner, repo); err == nil {
			if ap.AllowedActions == "all" {
				all = append(all, finding.Finding{
					CheckID:  finding.CheckGitHubActionsUnrestricted,
					Module:   "github",
					Scanner:  scannerName,
					Severity: finding.SeverityMedium,
					Asset:    repoSlug,
					Title:    "All GitHub Actions are permitted (no allow-list)",
					Description: "The repository allows all GitHub Actions to run without restriction. " +
						"An attacker who compromises or creates an action can be used in a workflow " +
						"without any gate. Restrict allowed actions to GitHub-owned actions and a " +
						"curated list of trusted third-party actions under " +
						"Settings > Actions > General > Allow actions and reusable workflows.",
					Evidence:     map[string]any{"allowed_actions": "all"},
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	// Scan top-level and common paths for .env files and secrets.
	all = append(all, s.scanForSecrets(ctx, owner, repo, repoSlug)...)

	// Webhooks (requires token with admin:repo_hook or admin:org_hook scope).
	if s.token != "" {
		hooks, err := s.getWebhooks(ctx, owner, repo)
		if err == nil {
			for _, hook := range hooks {
				if !hook.Active {
					continue
				}
				if hook.Config.InsecureSSL != "1" && hook.Config.Secret == "" {
					all = append(all, finding.Finding{
						CheckID:  finding.CheckGitHubWebhookNoSecret,
						Module:   "github",
						Scanner:  scannerName,
						Severity: finding.SeverityHigh,
						Asset:    repoSlug,
						Title:    fmt.Sprintf("Webhook to %s has no secret", hook.Config.URL),
						Description: fmt.Sprintf(
							"The repository webhook delivering to %s is not configured with a secret. "+
								"Without a secret, any party that discovers the webhook URL can send forged "+
								"events that your webhook receiver cannot distinguish from genuine GitHub "+
								"events. Set a strong random secret on the webhook and verify the "+
								"X-Hub-Signature-256 header in your receiver.", hook.Config.URL),
						Evidence:     map[string]any{"webhook_url": hook.Config.URL},
						DiscoveredAt: time.Now(),
					})
				}
			}
		}
	}

	return all, nil
}

// -------------------------------------------------------------------------
// Repository configuration checks
// -------------------------------------------------------------------------

type ghRepoMeta struct {
	DefaultBranch string `json:"default_branch"`
	Private       bool   `json:"private"`
	SecurityAndAnalysis struct {
		SecretScanning struct {
			Status string `json:"status"` // "enabled" or "disabled"
		} `json:"secret_scanning"`
		SecretScanningPushProtection struct {
			Status string `json:"status"`
		} `json:"secret_scanning_push_protection"`
	} `json:"security_and_analysis"`
	AllowForking        bool `json:"allow_forking"`
	DeleteBranchOnMerge bool `json:"delete_branch_on_merge"`
}

type ghActionsPermissions struct {
	AllowedActions string `json:"allowed_actions"` // "all", "local_only", "selected"
}

type ghWorkflowPermissions struct {
	DefaultWorkflowPermissions   string `json:"default_workflow_permissions"` // "read" or "write"
	CanApprovePullRequestReviews bool   `json:"can_approve_pull_request_reviews"`
}

func (s *Scanner) getRepoMeta(ctx context.Context, owner, repo string) (ghRepoMeta, error) {
	body, err := s.apiGet(ctx, fmt.Sprintf("https://api.github.com/repos/%s/%s", owner, repo))
	if err != nil {
		return ghRepoMeta{}, err
	}
	var meta ghRepoMeta
	err = json.Unmarshal(body, &meta)
	return meta, err
}

func checkRepoConfig(meta ghRepoMeta, repoSlug string) []finding.Finding {
	var findings []finding.Finding

	if meta.SecurityAndAnalysis.SecretScanning.Status == "disabled" {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckGitHubNoSecretScanning,
			Module:   "github",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Asset:    repoSlug,
			Title:    "GitHub secret scanning is disabled",
			Description: "GitHub secret scanning is not enabled for this repository. Secret scanning " +
				"automatically detects known credential patterns (API keys, tokens, certificates) " +
				"committed to the repository and alerts repository administrators before the secret " +
				"can be exploited. Enable it under Settings > Code security and analysis.",
			Evidence:     map[string]any{"secret_scanning": "disabled"},
			DiscoveredAt: time.Now(),
		})
	}

	if meta.SecurityAndAnalysis.SecretScanningPushProtection.Status == "disabled" {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckGitHubNoPushProtection,
			Module:   "github",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Asset:    repoSlug,
			Title:    "Secret scanning push protection is disabled",
			Description: "Push protection is not enabled for this repository. Without push protection, " +
				"secrets can be committed and pushed to the repository before GitHub's secret scanning " +
				"alerts fire — the secret is already in history by the time the alert is sent. " +
				"Push protection blocks the push at the point of git push, before any secret reaches " +
				"the remote. Enable it under Settings > Code security and analysis > Secret scanning > Push protection.",
			Evidence:     map[string]any{"push_protection": "disabled"},
			DiscoveredAt: time.Now(),
		})
	}

	return findings
}

type ghBranchProtection struct {
	RequiredPullRequestReviews *struct {
		RequiredApprovingReviewCount int  `json:"required_approving_review_count"`
		DismissStaleReviews          bool `json:"dismiss_stale_reviews"`
	} `json:"required_pull_request_reviews"`
	RequiredStatusChecks *struct {
		Strict   bool     `json:"strict"`
		Contexts []string `json:"contexts"`
		Checks   []struct {
			Context string `json:"context"`
		} `json:"checks"`
	} `json:"required_status_checks"`
	EnforceAdmins struct {
		Enabled bool `json:"enabled"`
	} `json:"enforce_admins"`
	AllowForcePushes struct {
		Enabled bool `json:"enabled"`
	} `json:"allow_force_pushes"`
	RequireSignedCommits *struct {
		Enabled bool `json:"enabled"`
	} `json:"required_signatures"`
}

func (s *Scanner) getBranchProtection(ctx context.Context, owner, repo, branch string) (ghBranchProtection, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/branches/%s/protection", owner, repo, branch)
	body, err := s.apiGet(ctx, url)
	if err != nil {
		return ghBranchProtection{}, err
	}
	var bp ghBranchProtection
	err = json.Unmarshal(body, &bp)
	return bp, err
}

func checkBranchProtection(bp ghBranchProtection, branch, repoSlug string) []finding.Finding {
	var findings []finding.Finding

	if bp.AllowForcePushes.Enabled {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckGitHubNoBranchProtection,
			Module:   "github",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Asset:    repoSlug,
			Title:    fmt.Sprintf("Force pushes allowed on protected branch %q", branch),
			Description: fmt.Sprintf(
				"Branch %q has protection enabled but still allows force pushes. A force push can "+
					"rewrite history, remove commits, and silently alter the audit trail. "+
					"Disable force pushes under branch protection settings.", branch),
			Evidence:     map[string]any{"branch": branch, "allow_force_pushes": true},
			DiscoveredAt: time.Now(),
		})
	}

	if bp.RequiredPullRequestReviews == nil {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckGitHubNoBranchProtection,
			Module:   "github",
			Scanner:  scannerName,
			Severity: finding.SeverityMedium,
			Asset:    repoSlug,
			Title:    fmt.Sprintf("No required reviewers on branch %q", branch),
			Description: fmt.Sprintf(
				"Branch %q does not require pull request reviews before merging. Without required "+
					"reviewers, a single developer can merge unreviewed code to the production branch. "+
					"Require at least 1 approving review and enable dismiss stale reviews.", branch),
			Evidence:     map[string]any{"branch": branch, "required_reviews": 0},
			DiscoveredAt: time.Now(),
		})
	} else if bp.RequiredPullRequestReviews != nil && !bp.RequiredPullRequestReviews.DismissStaleReviews {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckGitHubNoBranchProtection,
			Module:   "github",
			Scanner:  scannerName,
			Severity: finding.SeverityLow,
			Asset:    repoSlug,
			Title:    fmt.Sprintf("Stale reviews not dismissed on branch %q", branch),
			Description: fmt.Sprintf(
				"Branch %q requires PR reviews but does not dismiss stale approvals when new commits "+
					"are pushed. An approved PR can have malicious code added after approval, and the "+
					"approval remains valid. Enable 'Dismiss stale pull request approvals when new commits "+
					"are pushed' in branch protection settings.", branch),
			Evidence:     map[string]any{"branch": branch, "dismiss_stale_reviews": false},
			DiscoveredAt: time.Now(),
		})
	}

	// Required status checks gate CI on merge.
	if bp.RequiredStatusChecks == nil || (len(bp.RequiredStatusChecks.Contexts) == 0 && len(bp.RequiredStatusChecks.Checks) == 0) {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckGitHubNoRequiredStatusChecks,
			Module:   "github",
			Scanner:  scannerName,
			Severity: finding.SeverityMedium,
			Asset:    repoSlug,
			Title:    fmt.Sprintf("No required CI status checks on branch %q", branch),
			Description: fmt.Sprintf(
				"Branch %q does not require any CI status checks to pass before merging. Without "+
					"required status checks, broken code and failing tests can be merged to the default "+
					"branch. Add required status checks for your CI workflow jobs under branch protection settings.", branch),
			Evidence:     map[string]any{"branch": branch, "required_status_checks": "none"},
			DiscoveredAt: time.Now(),
		})
	}

	// Signed commits.
	if bp.RequireSignedCommits == nil || !bp.RequireSignedCommits.Enabled {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckGitHubNoSignedCommits,
			Module:   "github",
			Scanner:  scannerName,
			Severity: finding.SeverityLow,
			Asset:    repoSlug,
			Title:    fmt.Sprintf("Signed commits not required on branch %q", branch),
			Description: fmt.Sprintf(
				"Branch %q does not require signed commits. Without commit signing, anyone with write "+
					"access can commit as any author identity — there is no cryptographic link between "+
					"a commit and the developer who made it. Enable required signed commits to ensure "+
					"all commits are verified with GPG or SSH keys.", branch),
			Evidence:     map[string]any{"branch": branch, "require_signed_commits": false},
			DiscoveredAt: time.Now(),
		})
	}

	return findings
}

// fileExists returns true if the given path exists in the repository's default branch.
func (s *Scanner) fileExists(ctx context.Context, owner, repo, path string) (bool, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s", owner, repo, path)
	_, err := s.apiGet(ctx, url)
	return err == nil, err
}

// hasWorkflowWithPattern returns true if any workflow file in .github/workflows/ contains the given string.
func (s *Scanner) hasWorkflowWithPattern(ctx context.Context, owner, repo, pattern string) (bool, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/.github/workflows", owner, repo)
	body, err := s.apiGet(ctx, url)
	if err != nil {
		return false, err
	}
	type ghItem struct {
		Name        string `json:"name"`
		Type        string `json:"type"`
		DownloadURL string `json:"download_url"`
	}
	var items []ghItem
	if err := json.Unmarshal(body, &items); err != nil {
		return false, err
	}
	for _, item := range items {
		if item.Type != "file" {
			continue
		}
		if strings.Contains(strings.ToLower(item.Name), pattern) {
			return true, nil
		}
		// Also fetch content for broader pattern matching.
		content, err := s.fetchFileContent(ctx, owner, repo, item.Name, ".github/workflows/")
		if err == nil && strings.Contains(strings.ToLower(content), pattern) {
			return true, nil
		}
	}
	return false, nil
}

// -------------------------------------------------------------------------
// Secret scanning in source code
// -------------------------------------------------------------------------

// secretPattern describes a regex that detects a secret type in source code.
// oidcGuidance, when non-empty, is appended to the finding description to
// recommend an OIDC / keyless alternative to the leaked long-lived credential.
type secretPattern struct {
	name         string
	pattern      *regexp.Regexp
	checkID      finding.CheckID
	oidcGuidance string
}

var secretPatterns = []secretPattern{
	{
		name:    "AWS access key ID",
		pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		checkID: finding.CheckGitHubSecretInCode,
		oidcGuidance: "OIDC migration: replace this long-lived key with GitHub OIDC role assumption. " +
			"Add `id-token: write` to your workflow permissions and use aws-actions/configure-aws-credentials " +
			"with `role-to-assume` instead of storing AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY as secrets. " +
			"This eliminates the credential entirely — there is no key to rotate or leak.",
	},
	{
		name:    "GCP service account key (JSON)",
		pattern: regexp.MustCompile(`"type"\s*:\s*"service_account"`),
		checkID: finding.CheckGitHubSecretInCode,
		oidcGuidance: "OIDC migration: replace this service account JSON key with GCP Workload Identity Federation. " +
			"Configure a Workload Identity Pool that trusts GitHub Actions, then use google-github-actions/auth " +
			"with `workload_identity_provider` and `service_account` (no key file). " +
			"This removes the long-lived JSON key entirely.",
	},
	{
		name:    "GitHub classic personal access token (ghp_)",
		pattern: regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`),
		checkID: finding.CheckGitHubSecretInCode,
		oidcGuidance: "This is a classic PAT — the most dangerous PAT type. Classic PATs grant " +
			"account-level permissions across every repository the owner can access and have no " +
			"mandatory expiry. They cannot be scoped to a single repo. Revoke it immediately, then " +
			"choose one of these alternatives:\n" +
			"1. ${{ secrets.GITHUB_TOKEN }} for same-repo CI operations — no token needed at all.\n" +
			"2. A fine-grained PAT (Settings → Developer settings → Fine-grained tokens) scoped " +
			"to specific repositories with only the permissions required and a short expiry.\n" +
			"3. A GitHub App installation token for automation — short-lived, auditable, not " +
			"tied to any individual's account.",
	},
	{
		name:    "GitHub fine-grained personal access token (github_pat_)",
		pattern: regexp.MustCompile(`github_pat_[0-9a-zA-Z_]{82}`),
		checkID: finding.CheckGitHubSecretInCode,
		oidcGuidance: "This is a fine-grained PAT — better than a classic PAT (repo-scoped, " +
			"permission-limited, supports expiry) but still a long-lived credential tied to one " +
			"person's account. Revoke it and replace with:\n" +
			"1. ${{ secrets.GITHUB_TOKEN }} if the workflow only touches the current repo.\n" +
			"2. A GitHub App installation token for cross-repo or organisation access — " +
			"tokens are short-lived (1 hour), auditable, and survive employee departures.",
	},
	{
		name:    "npm publish token",
		pattern: regexp.MustCompile(`npm_[0-9a-zA-Z]{36}`),
		checkID: finding.CheckGitHubSecretInCode,
		oidcGuidance: "OIDC migration: switch to npm Provenance / OIDC Trusted Publishing. " +
			"Add `id-token: write` to your publish workflow and use `npm publish --provenance`. " +
			"npmjs.com accepts OIDC tokens directly — no npm_TOKEN secret needed.",
	},
	{
		name:    "Stripe secret key",
		pattern: regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`),
		checkID: finding.CheckGitHubSecretInCode,
	},
	{
		name:    "Stripe publishable key",
		pattern: regexp.MustCompile(`pk_live_[0-9a-zA-Z]{24}`),
		checkID: finding.CheckGitHubSecretInCode,
	},
	{
		name:    "Slack bot/user token",
		pattern: regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z-]{10,}`),
		checkID: finding.CheckGitHubSecretInCode,
	},
	{
		name:    "Slack webhook URL",
		pattern: regexp.MustCompile(`https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9a-zA-Z]+`),
		checkID: finding.CheckGitHubSecretInCode,
	},
	{
		name:    "Twilio auth token",
		pattern: regexp.MustCompile(`SK[0-9a-f]{32}`),
		checkID: finding.CheckGitHubSecretInCode,
	},
	{
		name:    "SendGrid API key",
		pattern: regexp.MustCompile(`SG\.[0-9a-zA-Z_-]{22}\.[0-9a-zA-Z_-]{43}`),
		checkID: finding.CheckGitHubSecretInCode,
	},
	{
		name:    "Anthropic API key",
		pattern: regexp.MustCompile(`sk-ant-[0-9a-zA-Z_-]{95}`),
		checkID: finding.CheckGitHubSecretInCode,
	},
	{
		name:    "OpenAI API key",
		pattern: regexp.MustCompile(`sk-[0-9a-zA-Z]{48}`),
		checkID: finding.CheckGitHubSecretInCode,
	},
	{
		name:    "PEM private key",
		pattern: regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`),
		checkID: finding.CheckGitHubPrivateKeyInRepo,
	},
	{
		name:    "JWT signing secret (HS256 pattern in config)",
		pattern: regexp.MustCompile(`(?i)(jwt[_-]?secret|jwt[_-]?key|signing[_-]?secret)\s*[:=]\s*["']?[0-9a-zA-Z+/=_-]{20,}`),
		checkID: finding.CheckGitHubSecretInCode,
	},
	{
		name:    "Database URL with credentials",
		pattern: regexp.MustCompile(`(postgres|mysql|mongodb)://[^:]+:[^@]+@`),
		checkID: finding.CheckGitHubSecretInCode,
	},
	{
		name:    "Docker Hub password or access token",
		pattern: regexp.MustCompile(`(?i)(docker[_-]?password|docker[_-]?token|dockerhub[_-]?token)\s*[:=]\s*["']?[0-9a-zA-Z_-]{10,}`),
		checkID: finding.CheckGitHubSecretInCode,
		oidcGuidance: "OIDC migration: for GitHub Container Registry (ghcr.io) use the built-in GITHUB_TOKEN " +
			"with `packages: write` — no Docker password needed. For Docker Hub, use a fine-grained " +
			"access token scoped to specific repositories rather than your account password.",
	},
	{
		name:    "Vercel deployment token",
		pattern: regexp.MustCompile(`(?i)(vercel[_-]?token|vercel[_-]?api[_-]?token)\s*[:=]\s*["']?[0-9a-zA-Z_-]{20,}`),
		checkID: finding.CheckGitHubSecretInCode,
		oidcGuidance: "OIDC migration: install the Vercel GitHub App and connect your repository directly. " +
			"The App handles deployments without a VERCEL_TOKEN secret — deployments are triggered " +
			"automatically on push/PR with no long-lived credential required.",
	},
	{
		name:    "Terraform Cloud / HCP Terraform token",
		pattern: regexp.MustCompile(`(?i)(tf[_-]?api[_-]?token|tfc[_-]?token|terraform[_-]?cloud[_-]?token)\s*[:=]\s*["']?[0-9a-zA-Z./-]{20,}`),
		checkID: finding.CheckGitHubSecretInCode,
		oidcGuidance: "OIDC migration: Terraform Cloud / HCP Terraform supports Dynamic Provider Credentials. " +
			"Configure a Workload Identity token in your TFC workspace so that AWS/GCP/Azure providers " +
			"authenticate via OIDC rather than static keys. For the TFC API token itself, use a " +
			"short-lived team token scoped to the workspace rather than a user token.",
	},
	{
		name:    "Fly.io API token",
		pattern: regexp.MustCompile(`(?i)(fly[_-]?api[_-]?token|FLY_API_TOKEN)\s*[:=]\s*["']?fo1[0-9a-zA-Z_-]{40,}`),
		checkID: finding.CheckGitHubSecretInCode,
		oidcGuidance: "Prefer Fly.io deploy tokens scoped to a single app (`flyctl tokens create deploy`) " +
			"over an account-wide API token. Fly.io OIDC support via GitHub Actions is available for " +
			"passwordless deploys — see fly.io/docs/reference/openid-connect/.",
	},
	{
		name:    "PyPI API token",
		pattern: regexp.MustCompile(`pypi-[0-9a-zA-Z_-]{40,}`),
		checkID: finding.CheckGitHubSecretInCode,
		oidcGuidance: "OIDC migration: switch to PyPI Trusted Publishing. Configure your PyPI project to " +
			"trust your GitHub Actions workflow, then use pypa/gh-action-pypi-publish with OIDC " +
			"(`id-token: write`). No PYPI_API_TOKEN secret is required — PyPI issues a short-lived " +
			"upload token automatically.",
	},
}

// scanPaths are file paths and directories to check for leaked secrets.
var scanPaths = []string{
	".env",
	".env.local",
	".env.production",
	".env.staging",
	"config.json",
	"config/database.yml",
	"config/secrets.yml",
	"credentials.json",
	"service-account.json",
	"secrets.json",
	"terraform.tfvars",
	".aws/credentials",
}

func (s *Scanner) scanForSecrets(ctx context.Context, owner, repo, repoSlug string) []finding.Finding {
	var findings []finding.Finding

	// Check well-known sensitive paths.
	for _, path := range scanPaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}
		content, err := s.fetchFileContent(ctx, owner, repo, path, "")
		if err != nil {
			continue
		}

		// Flag .env files simply being present.
		if strings.HasPrefix(path, ".env") {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckGitHubTrackedEnvFile,
				Module:   "github",
				Scanner:  scannerName,
				Severity: finding.SeverityCritical,
				Asset:    repoSlug,
				Title:    fmt.Sprintf("Environment file tracked in git: %s", path),
				Description: fmt.Sprintf(
					"The file %q is tracked in the git repository. Environment files typically contain "+
						"API keys, database passwords, and other secrets that should never be committed. "+
						"Remove the file from git history using git-filter-repo, add it to .gitignore, "+
						"and rotate any secrets it contains immediately.", path),
				Evidence:     map[string]any{"path": path},
				ProofCommand: fmt.Sprintf("curl -s https://raw.githubusercontent.com/%s/HEAD/%s | head -20", repoSlug, path),
				DiscoveredAt: time.Now(),
			})
		}

		// Scan content for secret patterns.
		for _, sp := range secretPatterns {
			if m := sp.pattern.FindString(content); m != "" {
				// Redact the match partially for the evidence.
				redacted := m
				if len(m) > 8 {
					redacted = m[:4] + strings.Repeat("*", len(m)-8) + m[len(m)-4:]
				}
				desc := fmt.Sprintf(
					"A %s pattern was detected in %q. This secret is accessible to anyone with "+
						"read access to the repository (and permanently in git history for public repos). "+
						"Revoke and rotate the credential immediately, then remove it from git history "+
						"using git-filter-repo. Use GitHub Secrets or a secrets manager for runtime access.",
					sp.name, path)
				if sp.oidcGuidance != "" {
					desc += "\n\n" + sp.oidcGuidance
				}
				findings = append(findings, finding.Finding{
					CheckID:      sp.checkID,
					Module:       "github",
					Scanner:      scannerName,
					Severity:     finding.SeverityCritical,
					Asset:        repoSlug,
					Title:        fmt.Sprintf("%s found in %s", sp.name, path),
					Description:  desc,
					Evidence:     map[string]any{"path": path, "pattern": sp.name, "match_redacted": redacted},
					ProofCommand: fmt.Sprintf("curl -s https://raw.githubusercontent.com/%s/HEAD/%s", repoSlug, path),
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return findings
}

// -------------------------------------------------------------------------
// Webhook checks
// -------------------------------------------------------------------------

type ghWebhook struct {
	Config struct {
		URL         string `json:"url"`
		ContentType string `json:"content_type"`
		Secret      string `json:"secret"`
		InsecureSSL string `json:"insecure_ssl"` // "0" = no, "1" = yes
	} `json:"config"`
	Active bool `json:"active"`
}

func (s *Scanner) getWebhooks(ctx context.Context, owner, repo string) ([]ghWebhook, error) {
	body, err := s.apiGet(ctx, fmt.Sprintf("https://api.github.com/repos/%s/%s/hooks", owner, repo))
	if err != nil {
		return nil, err
	}
	var hooks []ghWebhook
	err = json.Unmarshal(body, &hooks)
	return hooks, err
}

// -------------------------------------------------------------------------
// GitHub API helpers
// -------------------------------------------------------------------------

func (s *Scanner) fetchFileContent(ctx context.Context, owner, repo, path, prefix string) (string, error) {
	fullPath := prefix + path
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s", owner, repo, fullPath)
	body, err := s.apiGet(ctx, url)
	if err != nil {
		return "", err
	}
	type ghFile struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	var f ghFile
	if err := json.Unmarshal(body, &f); err != nil {
		return "", err
	}
	if f.Encoding != "base64" {
		return "", fmt.Errorf("unexpected encoding %q", f.Encoding)
	}
	cleaned := strings.ReplaceAll(f.Content, "\n", "")
	decoded, err := base64.StdEncoding.DecodeString(cleaned)
	return string(decoded), err
}

func (s *Scanner) apiGet(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
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
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API %s: HTTP %d", url, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return data, err
}

// vulnAlertsEnabled returns true if Dependabot vulnerability alerts are enabled.
// The API returns 204 when enabled, 404 when disabled.
func (s *Scanner) vulnAlertsEnabled(ctx context.Context, owner, repo string) (bool, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/vulnerability-alerts", owner, repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if s.token != "" {
		req.Header.Set("Authorization", "token "+s.token)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusNoContent, nil
}

// getWorkflowPermissions returns the default GITHUB_TOKEN permissions for workflows.
func (s *Scanner) getWorkflowPermissions(ctx context.Context, owner, repo string) (ghWorkflowPermissions, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/actions/permissions/workflow", owner, repo)
	body, err := s.apiGet(ctx, url)
	if err != nil {
		return ghWorkflowPermissions{}, err
	}
	var wp ghWorkflowPermissions
	err = json.Unmarshal(body, &wp)
	return wp, err
}

// getActionsPermissions returns the actions allowed policy for the repository.
func (s *Scanner) getActionsPermissions(ctx context.Context, owner, repo string) (ghActionsPermissions, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/actions/permissions", owner, repo)
	body, err := s.apiGet(ctx, url)
	if err != nil {
		return ghActionsPermissions{}, err
	}
	var ap ghActionsPermissions
	err = json.Unmarshal(body, &ap)
	return ap, err
}

func splitOwnerRepo(target string) (owner, repo string, ok bool) {
	target = strings.TrimPrefix(target, "https://github.com/")
	target = strings.TrimPrefix(target, "http://github.com/")
	target = strings.TrimPrefix(target, "github.com/")
	parts := strings.SplitN(target, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}
