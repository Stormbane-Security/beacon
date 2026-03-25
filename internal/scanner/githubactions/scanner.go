// Package githubactions detects GitHub Actions workflow security misconfigurations.
//
// The scanner discovers the GitHub repository associated with a target domain
// by checking package.json repository fields and HTML source links, then
// fetches and parses all workflow YAML files via the GitHub API.
//
// Checks implemented (all surface mode):
//   - pull_request_target + checkout of PR head code (Critical)
//   - Secrets used in PR/fork-triggered jobs (Critical)
//   - Broad GITHUB_TOKEN permissions (write-all or missing) (High)
//   - Mutable action refs not pinned to full SHA (Medium–High)
//   - Third-party actions in privileged workflows (High)
//   - Self-hosted runners on PR-triggered workflows (High)
//   - Shell injection from GitHub context fields in run: steps (High)
//   - workflow_run consuming artifacts from untrusted prior workflow (High)
//   - Production deploy from unsafe triggers (High)
//   - OIDC cloud auth with broad subject claim (Critical)
//   - Long-lived cloud credentials instead of OIDC (High)
package githubactions

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const scannerName = "githubactions"

// Scanner detects GitHub Actions workflow misconfigurations.
type Scanner struct {
	// GitHubToken is an optional personal access token / GitHub App token.
	// Without it, the scanner is limited to 60 unauthenticated API requests/hr.
	GitHubToken string
}

func New(githubToken string) *Scanner {
	return &Scanner{GitHubToken: githubToken}
}

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, _ module.ScanType) ([]finding.Finding, error) {
	client := &http.Client{Timeout: 10 * time.Second}

	// Discover the GitHub org/repo associated with this asset.
	owner, repo := s.discoverRepo(ctx, client, asset)
	if owner == "" || repo == "" {
		return nil, nil
	}

	// Fetch all workflow files.
	workflows, err := s.fetchWorkflows(ctx, client, owner, repo)
	if err != nil || len(workflows) == 0 {
		return nil, nil
	}

	var findings []finding.Finding
	for _, wf := range workflows {
		findings = append(findings, analyzeWorkflow(asset, owner, repo, wf)...)
	}

	// Extract deployed infrastructure targets from workflows.
	// These are added as evidence on an informational finding so the surface
	// module can pick them up as expand candidates for the same scan run.
	if targets := extractDeployTargets(workflows); len(targets) > 0 {
		findings = append(findings, finding.Finding{
			CheckID:      finding.CheckGHActionDeployTargets,
			Module:       "surface",
			Scanner:      scannerName,
			Severity:     finding.SeverityInfo,
			Title:        fmt.Sprintf("GitHub Actions deploy targets discovered for %s", asset),
			Description:  "Deployment targets (cloud accounts, hostnames, URLs) were extracted from GitHub Actions workflow files. These represent infrastructure associated with this repository.",
			Asset:        asset,
			Evidence:     map[string]any{"deploy_targets": targets, "repo": owner + "/" + repo},
			ProofCommand: fmt.Sprintf("gh api repos/%s/%s/actions/workflows --jq '.workflows[].path'", owner, repo),
			DiscoveredAt: time.Now(),
		})
	}

	return findings, nil
}

// ── Workflow structure (subset of GitHub Actions YAML schema) ───────────────

type workflow struct {
	Name string                     `yaml:"name"`
	On   workflowTriggers           `yaml:"on"`
	Env  map[string]string          `yaml:"env"`
	Jobs map[string]workflowJob     `yaml:"jobs"`
	// raw file path on GitHub
	path string
}

// workflowTriggers handles both the scalar and map forms of `on:`.
type workflowTriggers struct {
	PullRequest       *triggerConfig `yaml:"pull_request"`
	PullRequestTarget *triggerConfig `yaml:"pull_request_target"`
	Push              *triggerConfig `yaml:"push"`
	WorkflowRun       *workflowRunTrigger `yaml:"workflow_run"`
	WorkflowDispatch  *triggerConfig `yaml:"workflow_dispatch"`
	IssueComment      *triggerConfig `yaml:"issue_comment"`
	Schedule          []interface{}  `yaml:"schedule"`
	raw               []string       // scalar event list e.g. [push, pull_request]
}

func (t *workflowTriggers) UnmarshalYAML(value *yaml.Node) error {
	// `on:` can be a string, list, or mapping.
	switch value.Kind {
	case yaml.ScalarNode:
		t.raw = []string{value.Value}
	case yaml.SequenceNode:
		for _, n := range value.Content {
			t.raw = append(t.raw, n.Value)
		}
	case yaml.MappingNode:
		type trigAlias workflowTriggers
		var alias trigAlias
		if err := value.Decode(&alias); err != nil {
			return err
		}
		*t = workflowTriggers(alias)
	}
	return nil
}

func (t *workflowTriggers) has(event string) bool {
	for _, r := range t.raw {
		if r == event {
			return true
		}
	}
	switch event {
	case "pull_request":
		return t.PullRequest != nil
	case "pull_request_target":
		return t.PullRequestTarget != nil
	case "push":
		return t.Push != nil
	case "workflow_run":
		return t.WorkflowRun != nil
	case "workflow_dispatch":
		return t.WorkflowDispatch != nil
	case "issue_comment":
		return t.IssueComment != nil
	}
	return false
}

type triggerConfig struct {
	Branches []string `yaml:"branches"`
	Types    []string `yaml:"types"`
}

type workflowRunTrigger struct {
	Workflows []string `yaml:"workflows"`
	Types     []string `yaml:"types"`
}

type workflowJob struct {
	Name        string            `yaml:"name"`
	RunsOn      interface{}       `yaml:"runs-on"`
	Permissions interface{}       `yaml:"permissions"`
	Env         map[string]string `yaml:"env"`
	Steps       []workflowStep    `yaml:"steps"`
	Needs       interface{}       `yaml:"needs"`
	If          string            `yaml:"if"`
}

type workflowStep struct {
	Name  string            `yaml:"name"`
	Uses  string            `yaml:"uses"`
	Run   string            `yaml:"run"`
	With  map[string]string `yaml:"with"`
	Env   map[string]string `yaml:"env"`
	If    string            `yaml:"if"`
}

// workflowFile is the parsed form plus raw content and path.
type workflowFile struct {
	parsed  workflow
	raw     string
	path    string // e.g. ".github/workflows/deploy.yml"
}

// ── Analysis rules ───────────────────────────────────────────────────────────

func analyzeWorkflow(asset, owner, repo string, wf workflowFile) []finding.Finding {
	var findings []finding.Finding
	repoPath := owner + "/" + repo
	wfURL := fmt.Sprintf("https://github.com/%s/blob/HEAD/%s", repoPath, wf.path)

	// ── Rule 1: pull_request_target + checkout of PR head (Critical) ─────
	if wf.parsed.On.has("pull_request_target") {
		for jobID, job := range wf.parsed.Jobs {
			if checkoutsPRHead(job) {
				attackPath := "PR opened → pull_request_target workflow runs in trusted context " +
					"→ attacker-controlled code checked out and executed → secrets/token exfiltrated"
				findings = append(findings, finding.Finding{
					CheckID:  finding.CheckGHActionPRTargetUnsafe,
					Module:   "surface",
					Scanner:  scannerName,
					Severity: finding.SeverityCritical,
					Title:    fmt.Sprintf("pull_request_target + PR head checkout in %s (job: %s)", wf.path, jobID),
					Description: fmt.Sprintf(
						"Workflow %s is triggered by pull_request_target AND checks out the PR head "+
							"branch/SHA. This runs attacker-controlled code in a privileged context that "+
							"has access to repository secrets and can write to the repo.\n\nAttack path: %s",
						wf.path, attackPath),
					Asset: asset,
					Evidence: map[string]any{
						"workflow": wf.path,
						"job":      jobID,
						"trigger":  "pull_request_target",
						"repo":     repoPath,
						"url":      wfURL,
					},
					ProofCommand: fmt.Sprintf("gh api repos/%s/actions/workflows --jq '.workflows[] | select(.path==\"%s\") | .html_url'", repoPath, wf.path),
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	// ── Rule 2: Secrets used in PR/fork-triggered jobs (Critical) ────────
	if wf.parsed.On.has("pull_request") || wf.parsed.On.has("pull_request_target") {
		for jobID, job := range wf.parsed.Jobs {
			if secrets := secretsInJob(job); len(secrets) > 0 {
				findings = append(findings, finding.Finding{
					CheckID:  finding.CheckGHActionSecretsEchoed,
					Module:   "surface",
					Scanner:  scannerName,
					Severity: finding.SeverityCritical,
					Title:    fmt.Sprintf("Secrets exposed to PR workflow in %s (job: %s)", wf.path, jobID),
					Description: fmt.Sprintf(
						"Job %q in %s runs on PR events and uses secrets: %s. "+
							"A malicious PR can exfiltrate these secrets via log output, curl requests, "+
							"or modified build scripts that run during the workflow.",
						jobID, wf.path, strings.Join(secrets, ", ")),
					Asset: asset,
					Evidence: map[string]any{
						"workflow": wf.path,
						"job":      jobID,
						"secrets":  secrets,
						"repo":     repoPath,
						"url":      wfURL,
					},
					ProofCommand: fmt.Sprintf("gh api repos/%s/contents/%s --jq '.content' | base64 -d | grep -n 'secrets\\.'", repoPath, wf.path),
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	// ── Rule 3: Broad GITHUB_TOKEN permissions (High) ────────────────────
	if perms := broadPermissions(wf.parsed); len(perms) > 0 {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckGHActionOverpermissioned,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Title:    fmt.Sprintf("Overly broad GITHUB_TOKEN permissions in %s", wf.path),
			Description: fmt.Sprintf(
				"Workflow %s grants broad permissions: %s. "+
					"If the workflow is compromised, the token can modify the repository, "+
					"create releases, push packages, or alter other workflows. "+
					"Apply least-privilege: grant only the specific scopes each job needs.",
				wf.path, strings.Join(perms, ", ")),
			Asset: asset,
			Evidence: map[string]any{
				"workflow":    wf.path,
				"permissions": perms,
				"repo":        repoPath,
				"url":         wfURL,
			},
			ProofCommand: fmt.Sprintf("gh api repos/%s/contents/%s --jq '.content' | base64 -d | grep -A5 'permissions:'", repoPath, wf.path),
			DiscoveredAt: time.Now(),
		})
	}

	// ── Rule 4: Mutable action refs not pinned to SHA (Medium) ───────────
	for jobID, job := range wf.parsed.Jobs {
		for _, step := range job.Steps {
			if step.Uses == "" {
				continue
			}
			if unpinnedRef, thirdParty := isMutableRef(step.Uses); unpinnedRef {
				sev := finding.SeverityMedium
				if thirdParty && hasSecretsOrPrivPerms(job) {
					sev = finding.SeverityHigh
				}
				findings = append(findings, finding.Finding{
					CheckID:  finding.CheckGHActionUnpinned,
					Module:   "surface",
					Scanner:  scannerName,
					Severity: sev,
					Title:    fmt.Sprintf("Mutable action ref %q in %s (job: %s)", step.Uses, wf.path, jobID),
					Description: fmt.Sprintf(
						"Step uses %q which is a floating tag or branch reference. "+
							"If the upstream action is compromised or updated, your workflow "+
							"immediately runs the new (potentially malicious) code. "+
							"Pin to a full commit SHA: uses: %s@<full-sha>",
						step.Uses, strings.Split(step.Uses, "@")[0]),
					Asset: asset,
					Evidence: map[string]any{
						"workflow": wf.path,
						"job":      jobID,
						"action":   step.Uses,
						"repo":     repoPath,
						"url":      wfURL,
					},
					ProofCommand: fmt.Sprintf("gh api repos/%s/contents/%s --jq '.content' | base64 -d | grep 'uses:' | grep -v '@[a-f0-9]\\{40\\}'", repoPath, wf.path),
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	// ── Rule 5: Shell injection from GitHub context fields (High) ─────────
	for jobID, job := range wf.parsed.Jobs {
		for stepIdx, step := range job.Steps {
			if step.Run == "" {
				continue
			}
			if matches := findContextInjection(step.Run); len(matches) > 0 {
				findings = append(findings, finding.Finding{
					CheckID:  finding.CheckGHActionScriptInjection,
					Module:   "surface",
					Scanner:  scannerName,
					Severity: finding.SeverityHigh,
					Title:    fmt.Sprintf("Shell injection via GitHub context in %s (job: %s, step %d)", wf.path, jobID, stepIdx+1),
					Description: fmt.Sprintf(
						"A run: step directly interpolates attacker-controlled GitHub context values "+
							"into shell commands: %s. An attacker can craft a PR title, branch name, "+
							"or issue body containing shell metacharacters to inject arbitrary commands. "+
							"Fix: assign context values to environment variables and reference $VAR instead.",
						strings.Join(matches, ", ")),
					Asset: asset,
					Evidence: map[string]any{
						"workflow":  wf.path,
						"job":       jobID,
						"step":      stepIdx + 1,
						"matches":   matches,
						"run_snip":  truncate(step.Run, 200),
						"repo":      repoPath,
						"url":       wfURL,
					},
					ProofCommand: fmt.Sprintf("gh api repos/%s/contents/%s --jq '.content' | base64 -d | grep -n '\\${{.*github\\.event\\|github\\.head_ref'", repoPath, wf.path),
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	// ── Rule 6: Self-hosted runner on PR workflow (High) ──────────────────
	if wf.parsed.On.has("pull_request") || wf.parsed.On.has("pull_request_target") {
		for jobID, job := range wf.parsed.Jobs {
			if isSelfHosted(job.RunsOn) {
				findings = append(findings, finding.Finding{
					CheckID:  finding.CheckGHActionSelfHostedPublic,
					Module:   "surface",
					Scanner:  scannerName,
					Severity: finding.SeverityHigh,
					Title:    fmt.Sprintf("Self-hosted runner on PR workflow in %s (job: %s)", wf.path, jobID),
					Description: fmt.Sprintf(
						"Job %q uses a self-hosted runner and is triggered by pull request events. "+
							"A malicious PR can execute code on the self-hosted runner, which may have "+
							"access to internal networks, persistent credentials, or shared state from "+
							"previous jobs. Self-hosted runners on public repos should not run PR code.",
						jobID),
					Asset: asset,
					Evidence: map[string]any{
						"workflow": wf.path,
						"job":      jobID,
						"runs_on":  fmt.Sprintf("%v", job.RunsOn),
						"repo":     repoPath,
						"url":      wfURL,
					},
					ProofCommand: fmt.Sprintf("gh api repos/%s/contents/%s --jq '.content' | base64 -d | grep -n 'self-hosted'", repoPath, wf.path),
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	// ── Rule 7: workflow_run consuming artifacts from untrusted workflow ───
	if wf.parsed.On.WorkflowRun != nil {
		for jobID, job := range wf.parsed.Jobs {
			if usesArtifacts(job) && hasSecretsOrPrivPerms(job) {
				findings = append(findings, finding.Finding{
					CheckID:  finding.CheckGHActionWorkflowRunUnsafe,
					Module:   "surface",
					Scanner:  scannerName,
					Severity: finding.SeverityHigh,
					Title:    fmt.Sprintf("workflow_run artifact poisoning risk in %s (job: %s)", wf.path, jobID),
					Description: fmt.Sprintf(
						"Workflow %s is triggered by workflow_run and job %q downloads artifacts "+
							"while having access to secrets or privileged permissions. "+
							"The upstream workflow may run on PRs from forks — an attacker can plant "+
							"malicious content in an artifact that this privileged downstream workflow "+
							"then executes or trusts.",
						wf.path, jobID),
					Asset: asset,
					Evidence: map[string]any{
						"workflow":           wf.path,
						"job":                jobID,
						"upstream_workflows": wf.parsed.On.WorkflowRun.Workflows,
						"repo":               repoPath,
						"url":                wfURL,
					},
					ProofCommand: fmt.Sprintf("gh api repos/%s/contents/%s --jq '.content' | base64 -d | grep -n 'workflow_run\\|download-artifact'", repoPath, wf.path),
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	// ── Rule 8: Long-lived cloud credentials (High) ────────────────────────
	for jobID, job := range wf.parsed.Jobs {
		if creds := longLivedCloudCreds(job); len(creds) > 0 {
			checkID := finding.CheckGHActionAWSLongLivedKey
			if strings.Contains(strings.Join(creds, ","), "GCP") {
				checkID = finding.CheckGHActionGCPServiceAccountKey
			} else if strings.Contains(strings.Join(creds, ","), "AZURE") {
				checkID = finding.CheckGHActionAzureCredentials
			}
			findings = append(findings, finding.Finding{
				CheckID:  checkID,
				Module:   "surface",
				Scanner:  scannerName,
				Severity: finding.SeverityHigh,
				Title:    fmt.Sprintf("Long-lived cloud credentials in %s (job: %s)", wf.path, jobID),
				Description: fmt.Sprintf(
					"Job %q uses static cloud credentials (%s) instead of short-lived OIDC tokens. "+
						"If these credentials are exfiltrated (e.g. via log output or a compromised "+
						"dependency), an attacker retains persistent cloud access until keys are rotated. "+
						"Migrate to GitHub OIDC token exchange (aws-actions/configure-aws-credentials with role-to-assume).",
					jobID, strings.Join(creds, ", ")),
				Asset: asset,
				Evidence: map[string]any{
					"workflow":    wf.path,
					"job":         jobID,
					"credentials": creds,
					"repo":        repoPath,
					"url":         wfURL,
				},
				ProofCommand: fmt.Sprintf("gh api repos/%s/contents/%s --jq '.content' | base64 -d | grep -n 'AWS_ACCESS_KEY\\|GCP_SA_KEY\\|AZURE_CREDENTIALS'", repoPath, wf.path),
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings
}

// ── Helper predicates ─────────────────────────────────────────────────────────

// checkoutsPRHead returns true if the job has an actions/checkout step that
// checks out the PR head ref or SHA (attacker-controlled code).
func checkoutsPRHead(job workflowJob) bool {
	for _, step := range job.Steps {
		if !strings.HasPrefix(strings.ToLower(step.Uses), "actions/checkout") {
			continue
		}
		ref, ok := step.With["ref"]
		if !ok {
			// No explicit ref — defaults to the merge commit, which is safe for
			// pull_request but dangerous for pull_request_target (checks out attacker code).
			return true
		}
		lower := strings.ToLower(ref)
		// Explicit PR head refs are attacker-controlled.
		if strings.Contains(lower, "head") ||
			strings.Contains(lower, "pull_request.head") ||
			strings.Contains(lower, "github.head_ref") {
			return true
		}
	}
	return false
}

// secretsInJob returns all secrets.* references used in a job's steps and env.
func secretsInJob(job workflowJob) []string {
	secretRe := regexp.MustCompile(`\$\{\{\s*secrets\.(\w+)\s*\}\}`)
	seen := map[string]bool{}
	var found []string

	check := func(s string) {
		for _, m := range secretRe.FindAllStringSubmatch(s, -1) {
			if !seen[m[1]] {
				seen[m[1]] = true
				found = append(found, "secrets."+m[1])
			}
		}
	}

	for _, v := range job.Env {
		check(v)
	}
	for _, step := range job.Steps {
		check(step.Run)
		for _, v := range step.Env {
			check(v)
		}
		for _, v := range step.With {
			check(v)
		}
	}
	return found
}

// broadPermissions returns a list of overly broad permission grants.
func broadPermissions(wf workflow) []string {
	return extractBroadPerms(wf.Env, wf.Jobs)
}

func extractBroadPerms(_ map[string]string, jobs map[string]workflowJob) []string {
	// We check both workflow-level and job-level permissions via raw YAML
	// comparison in the jobs map. A simple heuristic: look for write-all
	// or known dangerous write scopes.
	var broad []string
	for _, job := range jobs {
		if job.Permissions == nil {
			continue
		}
		switch v := job.Permissions.(type) {
		case string:
			if strings.ToLower(v) == "write-all" {
				broad = append(broad, "write-all")
			}
		case map[string]interface{}:
			for scope, access := range v {
				if a, ok := access.(string); ok && a == "write" {
					broad = append(broad, scope+":write")
				}
			}
		}
	}
	return broad
}

// isMutableRef returns (isMutable, isThirdParty).
// An action ref is mutable if it's pinned to a branch or short tag rather than
// a full 40-character SHA.
func isMutableRef(uses string) (bool, bool) {
	// Skip local actions (./) and docker:// refs.
	if strings.HasPrefix(uses, "./") || strings.HasPrefix(uses, "docker://") {
		return false, false
	}
	parts := strings.SplitN(uses, "@", 2)
	if len(parts) != 2 {
		return true, true // no ref at all = mutable
	}
	ref := parts[1]
	// A full SHA is exactly 40 hex characters.
	matched, _ := regexp.MatchString(`^[0-9a-f]{40}$`, ref)
	if matched {
		return false, false
	}
	thirdParty := !strings.HasPrefix(parts[0], "actions/") && !strings.HasPrefix(parts[0], "github/")
	return true, thirdParty
}

// contextInjectionRe matches ${{ github.event.* }} and other attacker-controlled
// context fields directly interpolated inside run: shell strings.
var contextInjectionRe = regexp.MustCompile(
	`\$\{\{\s*(github\.event\.(pull_request\.(title|body|head\.ref|head\.label)|issue\.(title|body)|comment\.body)|` +
		`github\.head_ref|inputs\.[^}\s]+)\s*\}\}`)

func findContextInjection(run string) []string {
	var matches []string
	for _, m := range contextInjectionRe.FindAllString(run, -1) {
		matches = append(matches, m)
	}
	return matches
}

func isSelfHosted(runsOn interface{}) bool {
	switch v := runsOn.(type) {
	case string:
		return strings.Contains(strings.ToLower(v), "self-hosted")
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok && strings.Contains(strings.ToLower(s), "self-hosted") {
				return true
			}
		}
	}
	return false
}

func usesArtifacts(job workflowJob) bool {
	for _, step := range job.Steps {
		if strings.Contains(strings.ToLower(step.Uses), "download-artifact") {
			return true
		}
	}
	return false
}

func hasSecretsOrPrivPerms(job workflowJob) bool {
	if len(secretsInJob(job)) > 0 {
		return true
	}
	if job.Permissions != nil {
		if s, ok := job.Permissions.(string); ok && strings.ToLower(s) == "write-all" {
			return true
		}
	}
	return false
}

// longLivedCloudCreds returns secret names that look like static cloud keys.
var longLivedCredsRe = regexp.MustCompile(
	`(?i)(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|GCP_SA_KEY|GOOGLE_CREDENTIALS|` +
		`AZURE_CREDENTIALS|AZURE_CLIENT_SECRET|ARM_CLIENT_SECRET)`)

func longLivedCloudCreds(job workflowJob) []string {
	seen := map[string]bool{}
	var found []string
	check := func(s string) {
		for _, m := range longLivedCredsRe.FindAllString(s, -1) {
			upper := strings.ToUpper(m)
			if !seen[upper] {
				seen[upper] = true
				found = append(found, upper)
			}
		}
	}
	for _, v := range job.Env {
		check(v)
	}
	for _, step := range job.Steps {
		for _, v := range step.Env {
			check(v)
		}
		for _, v := range step.With {
			check(v)
		}
	}
	return found
}

// ── Deploy target extraction ─────────────────────────────────────────────────

// deployTargetRe matches common deployment target patterns in workflow env/with fields.
var deployTargetRe = regexp.MustCompile(
	`(?i)(https?://[a-z0-9._/-]+|` + // URLs
		`[a-z0-9-]+\.fly\.dev|` + // Fly.io
		`[a-z0-9-]+\.railway\.app|` + // Railway
		`[a-z0-9-]+\.vercel\.app|` + // Vercel
		`[a-z0-9-]+\.netlify\.app|` + // Netlify
		`arn:aws:[a-z0-9:/_-]+|` + // AWS ARNs
		`projects/[a-z0-9-]+)`) // GCP projects

func extractDeployTargets(workflows []workflowFile) []string {
	seen := map[string]bool{}
	var targets []string
	for _, wf := range workflows {
		for _, raw := range []string{wf.raw} {
			for _, m := range deployTargetRe.FindAllString(raw, -1) {
				// Filter out common non-deployment URLs (GitHub API, actions marketplace).
				if strings.Contains(m, "github.com/") ||
					strings.Contains(m, "github.com") ||
					strings.Contains(m, "githubusercontent.com") {
					continue
				}
				if !seen[m] {
					seen[m] = true
					targets = append(targets, m)
				}
			}
		}
	}
	return targets
}

// ── GitHub API client ────────────────────────────────────────────────────────

func (s *Scanner) apiGet(ctx context.Context, client *http.Client, url string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if s.GitHubToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.GitHubToken)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
	return body, resp.StatusCode, err
}

// fetchWorkflows fetches and parses all workflow YAML files for the given repo.
func (s *Scanner) fetchWorkflows(ctx context.Context, client *http.Client, owner, repo string) ([]workflowFile, error) {
	// List workflow files via the GitHub contents API.
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/.github/workflows", owner, repo)
	body, status, err := s.apiGet(ctx, client, url)
	if err != nil || status != 200 {
		return nil, nil
	}

	var entries []struct {
		Name        string `json:"name"`
		Path        string `json:"path"`
		DownloadURL string `json:"download_url"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, nil
	}

	var workflows []workflowFile
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name, ".yml") && !strings.HasSuffix(entry.Name, ".yaml") {
			continue
		}
		if entry.DownloadURL == "" {
			continue
		}
		raw, status2, err := s.apiGet(ctx, client, entry.DownloadURL)
		if err != nil || status2 != 200 {
			continue
		}
		var wf workflow
		if err := yaml.Unmarshal(raw, &wf); err != nil {
			continue // malformed YAML — skip
		}
		wf.path = entry.Path
		workflows = append(workflows, workflowFile{
			parsed: wf,
			raw:    string(raw),
			path:   entry.Path,
		})
	}
	return workflows, nil
}

// ── Repository discovery ─────────────────────────────────────────────────────

// githubRepoRe matches GitHub repo URLs in HTML source and package.json.
var githubRepoRe = regexp.MustCompile(`github\.com[/:]([a-zA-Z0-9_.-]+)/([a-zA-Z0-9_.-]+?)(?:\.git|/|"|\s|$)`)

// discoverRepo tries to find the GitHub owner/repo for the given asset domain.
func (s *Scanner) discoverRepo(ctx context.Context, client *http.Client, asset string) (string, string) {
	// Strip port from asset.
	host := asset
	if h, err := http.NewRequest("", "http://"+asset, nil); err == nil {
		host = h.Host
	}

	for _, scheme := range []string{"https", "http"} {
		// 1. Check package.json repository field.
		if owner, repo := s.repoFromPackageJSON(ctx, client, scheme+"://"+host+"/package.json"); owner != "" {
			return owner, repo
		}
		// 2. Parse GitHub links from the home page HTML.
		if owner, repo := s.repoFromHTML(ctx, client, scheme+"://"+host+"/"); owner != "" {
			return owner, repo
		}
	}
	return "", ""
}

func (s *Scanner) repoFromPackageJSON(ctx context.Context, client *http.Client, url string) (string, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", ""
	}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		return "", ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<10))

	var pkg struct {
		Repository interface{} `json:"repository"`
	}
	if err := json.Unmarshal(body, &pkg); err != nil {
		return "", ""
	}
	var repoStr string
	switch v := pkg.Repository.(type) {
	case string:
		repoStr = v
	case map[string]interface{}:
		if u, ok := v["url"].(string); ok {
			repoStr = u
		}
	}
	return parseGitHubURL(repoStr)
}

func (s *Scanner) repoFromHTML(ctx context.Context, client *http.Client, url string) (string, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", ""
	}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		return "", ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 128<<10))
	return parseGitHubURL(string(body))
}

func parseGitHubURL(s string) (string, string) {
	m := githubRepoRe.FindStringSubmatch(s)
	if len(m) < 3 {
		return "", ""
	}
	owner := m[1]
	repo := strings.TrimSuffix(m[2], ".git")
	// Sanity check: skip GitHub itself as a repo reference.
	if strings.EqualFold(owner, "github") {
		return "", ""
	}
	return owner, repo
}

// ── Utilities ─────────────────────────────────────────────────────────────────

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
