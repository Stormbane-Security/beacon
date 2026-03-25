// Package ghactions scans GitHub Actions workflow files for common security misconfigurations.
//
// It uses the GitHub Contents API to fetch .github/workflows/*.yml files for a given
// org/repo target, then applies a set of static analysis rules to each workflow file.
// All rules are implemented as string-pattern and regex checks — no full YAML AST traversal.
package ghactions

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

const scannerName = "github.actions"

// Scanner fetches and analyses GitHub Actions workflow files for a repo.
type Scanner struct {
	token      string // GitHub personal access token (optional, raises rate limit)
	httpClient *http.Client
}

// New creates a Scanner. Pass an empty string for githubToken to use unauthenticated requests.
func New(githubToken string) *Scanner {
	return &Scanner{
		token:      githubToken,
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
}

// Name returns the stable scanner identifier.
func (s *Scanner) Name() string { return scannerName }

// Run analyses GitHub Actions workflows for the given target.
// target must be "owner/repo" (e.g. "myorg/myrepo").
func (s *Scanner) Run(ctx context.Context, target string, _ module.ScanType) ([]finding.Finding, error) {
	owner, repo, ok := splitOwnerRepo(target)
	if !ok {
		return nil, fmt.Errorf("ghactions: invalid target %q — expected owner/repo", target)
	}

	// Determine whether the repo is public for the self-hosted runner check.
	isPublic, err := s.isRepoPublic(ctx, owner, repo)
	if err != nil {
		// Non-fatal: treat as unknown (skip self-hosted check rather than abort).
		isPublic = false
	}

	paths, err := s.listWorkflows(ctx, owner, repo)
	if err != nil {
		return nil, fmt.Errorf("ghactions: listing workflows for %s/%s: %w", owner, repo, err)
	}

	repoSlug := owner + "/" + repo
	var all []finding.Finding

	for _, path := range paths {
		select {
		case <-ctx.Done():
			return all, ctx.Err()
		default:
		}

		content, err := s.fetchWorkflowContent(ctx, owner, repo, path)
		if err != nil {
			// Skip unreadable files rather than abort the whole scan.
			continue
		}

		all = append(all, checkUnpinnedActions(content, repoSlug)...)
		all = append(all, checkPRTargetUnsafe(content, repoSlug)...)
		all = append(all, checkScriptInjection(content, repoSlug)...)
		all = append(all, checkOverpermissioned(content, repoSlug)...)
		all = append(all, checkSecretsEchoed(content, repoSlug)...)
		if isPublic {
			all = append(all, checkSelfHostedOnPublic(content, repoSlug)...)
		}
		all = append(all, checkWorkflowRunUnsafe(content, repoSlug)...)
		all = append(all, checkGitHubEnvInjection(content, repoSlug)...)
		all = append(all, checkSecretsInherit(content, repoSlug)...)
		all = append(all, checkInsecureCommands(content, repoSlug)...)
		all = append(all, checkBotConditionSpoofable(content, repoSlug)...)
		all = append(all, checkArtiPacked(content, repoSlug)...)
		all = append(all, checkCachePoisoning(content, repoSlug)...)
		all = append(all, checkLongLivedCloudCreds(content, repoSlug)...)
		all = append(all, checkPATUsedInWorkflow(content, repoSlug)...)
	}

	return all, nil
}

// -------------------------------------------------------------------------
// Analysis rules
// -------------------------------------------------------------------------

// reFullSHA matches a 40-character lowercase hex string (a full git SHA).
var reFullSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

// reUsesStep matches "uses: owner/action@ref" in a workflow YAML line.
// Group 1 = full "owner/action@ref", group 2 = action path, group 3 = ref.
var reUsesStep = regexp.MustCompile(`uses:\s+([^\s#]+@([^\s#@]+))`)

// checkUnpinnedActions flags any `uses:` step whose ref is not a 40-char SHA.
func checkUnpinnedActions(workflowYAML, repo string) []finding.Finding {
	var findings []finding.Finding
	seen := make(map[string]struct{})

	for _, line := range strings.Split(workflowYAML, "\n") {
		m := reUsesStep.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		fullRef := strings.TrimSpace(m[1]) // e.g. "actions/checkout@v3"
		ref := strings.TrimSpace(m[2])     // e.g. "v3"

		// Skip local actions (./.github/actions/…) — they are always pinned by
		// the repo itself and can't be hijacked via a supply-chain attack.
		if strings.HasPrefix(fullRef, "./") {
			continue
		}

		// A ref that is exactly a 40-hex-char SHA is safely pinned.
		if reFullSHA.MatchString(ref) {
			continue
		}

		if _, ok := seen[fullRef]; ok {
			continue
		}
		seen[fullRef] = struct{}{}

		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckGHActionUnpinned,
			Module:   "github",
			Scanner:  scannerName,
			Severity: finding.SeverityMedium,
			Asset:    repo,
			Title:    fmt.Sprintf("Unpinned action: %s", fullRef),
			Description: fmt.Sprintf(
				"The workflow references %q using a mutable tag or branch ref rather than an immutable "+
					"40-character commit SHA. If the upstream action is compromised or the tag is moved, "+
					"the workflow will silently execute attacker-controlled code. Pin to a full SHA instead: "+
					`uses: %s@<40-char-sha>  # %s`, fullRef, actionBase(fullRef), ref,
			),
			Evidence:     map[string]any{"action": fullRef, "ref": ref},
			DiscoveredAt: time.Now(),
		})
	}
	return findings
}

// actionBase returns the "owner/action" part of "owner/action@ref".
func actionBase(fullRef string) string {
	if idx := strings.LastIndex(fullRef, "@"); idx >= 0 {
		return fullRef[:idx]
	}
	return fullRef
}

// rePRTarget detects a pull_request_target trigger.
var rePRTarget = regexp.MustCompile(`pull_request_target`)

// reCheckoutUnsafeRef detects checkout steps that use an untrusted head ref.
var reCheckoutUnsafeRef = regexp.MustCompile(
	`ref:\s*\$\{\{.*github\.(event\.pull_request\.head\.(sha|ref)|head_ref).*\}\}`,
)

// checkPRTargetUnsafe flags workflows that trigger on pull_request_target AND
// check out the PR contributor's code — a known RCE vector.
func checkPRTargetUnsafe(workflowYAML, repo string) []finding.Finding {
	if !rePRTarget.MatchString(workflowYAML) {
		return nil
	}
	if !reCheckoutUnsafeRef.MatchString(workflowYAML) {
		return nil
	}
	return []finding.Finding{{
		CheckID:  finding.CheckGHActionPRTargetUnsafe,
		Module:   "github",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Asset:    repo,
		Title:    "pull_request_target with unsafe checkout of PR head",
		Description: "A workflow is triggered by pull_request_target (which runs with write permissions " +
			"and access to repository secrets) and checks out the PR contributor's code using " +
			"github.event.pull_request.head.sha or github.head_ref. An attacker can open a PR with " +
			"malicious workflow changes that execute in a privileged context, leaking secrets or " +
			"modifying the repository.",
		Evidence:     map[string]any{"trigger": "pull_request_target", "unsafe_checkout": true},
		DiscoveredAt: time.Now(),
	}}
}

// reInjectionSinks matches user-controlled GitHub context values embedded in
// run: steps. Any of these can be used to inject shell commands.
var reInjectionSinks = regexp.MustCompile(
	`\$\{\{\s*github\.event\.(pull_request\.(title|body|head\.ref|head\.label)|` +
		`issue\.(title|body)|` +
		`comment\.body|` +
		`review\.body|` +
		`review_comment\.body|` +
		`discussion\.(title|body))\s*\}\}`,
)

// isRunKey returns true when a trimmed YAML line is the start of a run: step.
// It accepts bare "run: ..." / "run: |" forms as well as inline list-item
// forms like "- run: ..." that appear in step lists. It explicitly rejects
// "runs-on:" and similar prefixes.
func isRunKey(trimmed string) bool {
	// Strip an optional leading "- " list marker (YAML sequence item).
	candidate := trimmed
	if strings.HasPrefix(candidate, "- ") {
		candidate = strings.TrimPrefix(candidate, "- ")
		candidate = strings.TrimSpace(candidate)
	}
	if candidate == "run:" {
		return true
	}
	return strings.HasPrefix(candidate, "run:") &&
		len(candidate) > 4 &&
		(candidate[4] == ' ' || candidate[4] == '|' || candidate[4] == '>')
}

// checkScriptInjection flags run: steps that embed user-controlled context values directly.
func checkScriptInjection(workflowYAML, repo string) []finding.Finding {
	var findings []finding.Finding

	// We scan every line of the YAML looking for injection sinks.
	// Rather than full YAML parsing, we use a two-pass approach:
	// 1. Collect the indent level of the first `run:` key we see.
	// 2. Mark all lines as part of a run block until we see a key at the same
	//    or lesser indent that is not a continuation of the block scalar.
	//
	// This handles both single-line  (run: echo ...) and block-scalar (run: |) forms.
	inRun := false
	runIndent := 0 // column index of the 'r' in "run:"
	for _, line := range strings.Split(workflowYAML, "\n") {
		trimmed := strings.TrimSpace(line)

		// Detect start of a run: step (single-line or block scalar).
		if isRunKey(trimmed) {
			inRun = true
			// Compute indent of this run: key.
			runIndent = len(line) - len(strings.TrimLeft(line, " \t"))
		} else if inRun {
			// Compute indent of the current line.
			currentIndent := len(line) - len(strings.TrimLeft(line, " \t"))

			// A new YAML key at the same or lesser indent than the run: key
			// ends the block. We detect a YAML key as a non-empty, non-comment
			// line that contains ": " or ends with ":" and has no ${{ (so it
			// isn't a shell command or expression continuation).
			isNewKey := len(trimmed) > 0 &&
				!strings.HasPrefix(trimmed, "#") &&
				currentIndent <= runIndent &&
				(strings.Contains(trimmed, ": ") || strings.HasSuffix(trimmed, ":")) &&
				!strings.Contains(trimmed, "${{")
			if isNewKey {
				inRun = false
			}
		}

		if !inRun {
			continue
		}

		m := reInjectionSinks.FindString(line)
		if m == "" {
			continue
		}

		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckGHActionScriptInjection,
			Module:   "github",
			Scanner:  scannerName,
			Severity: finding.SeverityCritical,
			Asset:    repo,
			Title:    fmt.Sprintf("Script injection via user-controlled context: %s", m),
			Description: fmt.Sprintf(
				"A run: step embeds the GitHub context expression %q directly in a shell command. "+
					"An attacker can craft a pull request title, issue body, or comment that contains "+
					"shell metacharacters to execute arbitrary commands in the workflow runner. "+
					"Use an intermediate environment variable instead: "+
					"env:\\n  VALUE: ${{ %s }}\\nrun: echo \"$VALUE\"",
				m, strings.Trim(strings.TrimSpace(m), "${{ }}")),
			Evidence:     map[string]any{"injection_sink": m},
			DiscoveredAt: time.Now(),
		})
	}
	return findings
}

// reWriteAll matches a permissions block set to write-all.
var reWriteAll = regexp.MustCompile(`permissions:\s*write-all`)

// reWritePermission matches individual permission values set to write.
var reWritePermission = regexp.MustCompile(`permissions:\s*write\b`)

// rePermissionsBlock detects any permissions: declaration.
var rePermissionsBlock = regexp.MustCompile(`(?m)^\s*permissions:`)

// checkOverpermissioned flags workflows with overly broad permissions.
func checkOverpermissioned(workflowYAML, repo string) []finding.Finding {
	var findings []finding.Finding

	if reWriteAll.MatchString(workflowYAML) {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckGHActionOverpermissioned,
			Module:   "github",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Asset:    repo,
			Title:    "Workflow uses permissions: write-all",
			Description: "The workflow grants write access to all GitHub API scopes via `permissions: write-all`. " +
				"This follows the principle of least privilege and should be narrowed to only the scopes " +
				"the workflow actually needs (e.g. `contents: read`).",
			Evidence:     map[string]any{"permissions": "write-all"},
			DiscoveredAt: time.Now(),
		})
		return findings // write-all subsumes the per-key write check
	}

	if reWritePermission.MatchString(workflowYAML) {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckGHActionOverpermissioned,
			Module:   "github",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Asset:    repo,
			Title:    "Workflow grants broad write permission",
			Description: "A `permissions: write` entry grants write access. " +
				"Restrict permissions to the minimal set needed for each job.",
			Evidence:     map[string]any{"permissions": "write"},
			DiscoveredAt: time.Now(),
		})
		return findings
	}

	// Absence of any permissions block means GitHub defaults apply.
	// On repos where the default token has write access (the historical default),
	// omitting permissions is equivalent to write-all.
	if !rePermissionsBlock.MatchString(workflowYAML) {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckGHActionOverpermissioned,
			Module:   "github",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Asset:    repo,
			Title:    "Workflow has no permissions block (defaults may include write access)",
			Description: "The workflow does not declare a `permissions:` block. " +
				"Unless the repository has been configured to restrict the default token to read-only, " +
				"the GITHUB_TOKEN may have write access to contents, packages, and other scopes. " +
				"Explicitly declare `permissions: {}` or only the required scopes.",
			Evidence:     map[string]any{"permissions": "absent"},
			DiscoveredAt: time.Now(),
		})
	}

	return findings
}

// reEchoSecret matches echo/printf/cat commands that directly embed a secret context expression.
var reEchoSecret = regexp.MustCompile(
	`(?i)(echo|printf|print|cat)\s[^#\n]*\$\{\{\s*secrets\.[^\s\}]+\s*\}\}`,
)

// reSecretEnvAssign detects env vars assigned from secrets (to catch indirect echoes).
// e.g.  TOKEN: ${{ secrets.MY_TOKEN }}
var reSecretEnvAssign = regexp.MustCompile(`(\w+):\s*\$\{\{\s*secrets\.(\S+?)\s*\}\}`)

// reEchoEnvVar matches commands that print an environment variable (by name).
var reEchoEnvVar = regexp.MustCompile(`(?i)(echo|printf|print)\s[^#\n]*\$(\w+)`)

// checkSecretsEchoed flags run: steps that may print secret values.
func checkSecretsEchoed(workflowYAML, repo string) []finding.Finding {
	var findings []finding.Finding

	// Direct: echo ${{ secrets.FOO }}
	for _, m := range reEchoSecret.FindAllString(workflowYAML, -1) {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckGHActionSecretsEchoed,
			Module:   "github",
			Scanner:  scannerName,
			Severity: finding.SeverityCritical,
			Asset:    repo,
			Title:    "Secret value may be printed in workflow logs",
			Description: fmt.Sprintf(
				"A run: step appears to echo a secret expression directly: %q. "+
					"This will print the secret value to the workflow log, which is visible to anyone with "+
					"read access to the repository. GitHub masks known secrets in logs, but this masking "+
					"can be circumvented. Never echo secrets directly.", m),
			Evidence:     map[string]any{"pattern": m},
			DiscoveredAt: time.Now(),
		})
	}

	// Indirect: look for env vars populated from secrets, then echoed.
	secretEnvVars := make(map[string]string) // envVarName -> secret name
	for _, m := range reSecretEnvAssign.FindAllStringSubmatch(workflowYAML, -1) {
		if len(m) == 3 {
			secretEnvVars[strings.ToUpper(m[1])] = m[2]
		}
	}

	if len(secretEnvVars) > 0 {
		for _, m := range reEchoEnvVar.FindAllStringSubmatch(workflowYAML, -1) {
			if len(m) < 3 {
				continue
			}
			varName := strings.ToUpper(m[2])
			secretName, ok := secretEnvVars[varName]
			if !ok {
				continue
			}
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckGHActionSecretsEchoed,
				Module:   "github",
				Scanner:  scannerName,
				Severity: finding.SeverityCritical,
				Asset:    repo,
				Title:    fmt.Sprintf("Secret %q may be printed via env var $%s", secretName, varName),
				Description: fmt.Sprintf(
					"The environment variable $%s is populated from secrets.%s and then appears in a "+
						"print/echo command. This may expose the secret in workflow logs.", varName, secretName),
				Evidence:     map[string]any{"env_var": varName, "secret": secretName},
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings
}

// reSelfHosted detects self-hosted runner labels.
var reSelfHosted = regexp.MustCompile(`runs-on:.*self-hosted`)

// checkSelfHostedOnPublic flags self-hosted runners used in public repositories.
// The caller is responsible for only calling this when the repo is confirmed public.
func checkSelfHostedOnPublic(workflowYAML, repo string) []finding.Finding {
	if !reSelfHosted.MatchString(workflowYAML) {
		return nil
	}
	return []finding.Finding{{
		CheckID:  finding.CheckGHActionSelfHostedPublic,
		Module:   "github",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Asset:    repo,
		Title:    "Self-hosted runner used in public repository",
		Description: "A workflow in this public repository uses a self-hosted runner. " +
			"Any GitHub user can fork the repository and open a pull request that triggers " +
			"the workflow on your private infrastructure. This can allow untrusted users to " +
			"execute arbitrary code on your self-hosted runner. Use GitHub-hosted runners for " +
			"public repositories, or add an approval gate for fork PRs.",
		Evidence:     map[string]any{"runner": "self-hosted", "repo_visibility": "public"},
		DiscoveredAt: time.Now(),
	}}
}

// -------------------------------------------------------------------------
// New checks: workflow_run, GITHUB_ENV injection, secrets:inherit,
// insecure commands, bot conditions, ArtiPACKED, cache poisoning
// -------------------------------------------------------------------------

// reWorkflowRunTrigger detects a workflow_run trigger.
var reWorkflowRunTrigger = regexp.MustCompile(`workflow_run:`)

// checkWorkflowRunUnsafe flags workflows triggered by workflow_run that check out
// the triggering workflow's head ref — a privilege escalation vector similar to
// pull_request_target but less obvious.
func checkWorkflowRunUnsafe(workflowYAML, repo string) []finding.Finding {
	if !reWorkflowRunTrigger.MatchString(workflowYAML) {
		return nil
	}
	if !reCheckoutUnsafeRef.MatchString(workflowYAML) {
		return nil
	}
	return []finding.Finding{{
		CheckID:  finding.CheckGHActionWorkflowRunUnsafe,
		Module:   "github",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Asset:    repo,
		Title:    "workflow_run trigger with unsafe checkout of triggering workflow's ref",
		Description: "A workflow triggered by workflow_run runs in the privileged context of the target " +
			"repository (with access to secrets) but checks out code from the triggering workflow's branch. " +
			"An attacker can trigger this from a fork, executing code in a privileged environment. " +
			"Remove the unsafe checkout or add an explicit approval gate before processing untrusted code.",
		Evidence:     map[string]any{"trigger": "workflow_run", "unsafe_checkout": true},
		DiscoveredAt: time.Now(),
	}}
}

// reGitHubEnvWrite detects writes to the GITHUB_ENV or GITHUB_PATH files.
var reGitHubEnvWrite = regexp.MustCompile(`(?i)(echo\s.*>>\s*\$GITHUB_ENV|echo\s.*>>\s*\$GITHUB_PATH|tee\s+-a\s+\$GITHUB_ENV)`)

// checkGitHubEnvInjection flags run: steps that write untrusted input to GITHUB_ENV or GITHUB_PATH.
func checkGitHubEnvInjection(workflowYAML, repo string) []finding.Finding {
	if !reGitHubEnvWrite.MatchString(workflowYAML) {
		return nil
	}
	// Only flag if there's also a user-controlled context value nearby (within the workflow).
	if !reInjectionSinks.MatchString(workflowYAML) {
		return nil
	}
	return []finding.Finding{{
		CheckID:  finding.CheckGHActionGitHubEnvInjection,
		Module:   "github",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Asset:    repo,
		Title:    "Untrusted input may be written to GITHUB_ENV or GITHUB_PATH",
		Description: "The workflow writes to $GITHUB_ENV or $GITHUB_PATH (which inject environment " +
			"variables and PATH entries into subsequent steps) and also uses user-controlled GitHub " +
			"context values. If the untrusted value reaches the env file write, an attacker can inject " +
			"arbitrary environment variables — including LD_PRELOAD — or hijack PATH to run malicious " +
			"binaries in later steps. Use an intermediate sanitised env var and validate input.",
		Evidence:     map[string]any{"vector": "GITHUB_ENV/GITHUB_PATH injection"},
		DiscoveredAt: time.Now(),
	}}
}

// reSecretsInherit detects blanket secrets: inherit in workflow_call.
var reSecretsInherit = regexp.MustCompile(`secrets:\s*inherit`)

// checkSecretsInherit flags reusable workflow calls that use secrets: inherit.
func checkSecretsInherit(workflowYAML, repo string) []finding.Finding {
	if !reSecretsInherit.MatchString(workflowYAML) {
		return nil
	}
	return []finding.Finding{{
		CheckID:  finding.CheckGHActionSecretsInherit,
		Module:   "github",
		Scanner:  scannerName,
		Severity: finding.SeverityMedium,
		Asset:    repo,
		Title:    "Reusable workflow called with secrets: inherit",
		Description: "A workflow_call invocation uses `secrets: inherit`, which passes ALL secrets " +
			"from the calling workflow to the called workflow. This violates the principle of least " +
			"privilege. Explicitly list only the secrets the called workflow actually needs: " +
			"secrets:\\n  MY_SECRET: ${{ secrets.MY_SECRET }}",
		Evidence:     map[string]any{"pattern": "secrets: inherit"},
		DiscoveredAt: time.Now(),
	}}
}

// reInsecureCommands detects the legacy insecure workflow commands re-enablement env var.
var reInsecureCommands = regexp.MustCompile(`ACTIONS_ALLOW_UNSECURE_COMMANDS:\s*true`)

// checkInsecureCommands flags workflows that re-enable deprecated set-env/add-path commands.
func checkInsecureCommands(workflowYAML, repo string) []finding.Finding {
	if !reInsecureCommands.MatchString(workflowYAML) {
		return nil
	}
	return []finding.Finding{{
		CheckID:  finding.CheckGHActionInsecureCommands,
		Module:   "github",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Asset:    repo,
		Title:    "Deprecated insecure workflow commands re-enabled",
		Description: "The workflow sets `ACTIONS_ALLOW_UNSECURE_COMMANDS: true`, re-enabling the " +
			"deprecated ::set-env:: and ::add-path:: workflow commands. These commands were disabled " +
			"because they allow any step (including actions from third parties) to inject arbitrary " +
			"environment variables and PATH entries. Remove this env var and use $GITHUB_ENV / " +
			"$GITHUB_PATH file writes instead.",
		Evidence:     map[string]any{"env_var": "ACTIONS_ALLOW_UNSECURE_COMMANDS"},
		DiscoveredAt: time.Now(),
	}}
}

// reBotCondition detects actor comparisons used as security gates.
var reBotCondition = regexp.MustCompile(`github\.actor\s*==\s*'(dependabot\[bot\]|renovate\[bot\]|github-actions\[bot\])'`)

// checkBotConditionSpoofable flags security conditions based on github.actor which can be spoofed.
func checkBotConditionSpoofable(workflowYAML, repo string) []finding.Finding {
	m := reBotCondition.FindString(workflowYAML)
	if m == "" {
		return nil
	}
	return []finding.Finding{{
		CheckID:  finding.CheckGHActionBotConditionSpoofable,
		Module:   "github",
		Scanner:  scannerName,
		Severity: finding.SeverityMedium,
		Asset:    repo,
		Title:    fmt.Sprintf("Spoofable bot condition: %s", m),
		Description: fmt.Sprintf(
			"The workflow uses `%s` as a security gate. The github.actor value can be spoofed by "+
				"a contributor whose GitHub username happens to match or by creating an account with "+
				"that exact name before the bot account is created. Use github.event_name and "+
				"verified event payload fields, or the `github.event.sender.type == 'Bot'` check "+
				"combined with repository permission checks instead.", m),
		Evidence:     map[string]any{"condition": m},
		DiscoveredAt: time.Now(),
	}}
}

// reCheckoutStep detects actions/checkout usage.
var reCheckoutStep = regexp.MustCompile(`uses:\s*actions/checkout`)

// rePersistCredentialsFalse detects explicit opt-out of credential persistence.
var rePersistCredentialsFalse = regexp.MustCompile(`persist-credentials:\s*false`)

// reUploadArtifact detects artifact upload steps.
var reUploadArtifact = regexp.MustCompile(`uses:\s*actions/upload-artifact`)

// checkArtiPacked flags workflows where git credentials may be included in uploaded artifacts.
func checkArtiPacked(workflowYAML, repo string) []finding.Finding {
	if !reCheckoutStep.MatchString(workflowYAML) {
		return nil
	}
	if !reUploadArtifact.MatchString(workflowYAML) {
		return nil
	}
	// Only flag if persist-credentials is NOT explicitly set to false.
	if rePersistCredentialsFalse.MatchString(workflowYAML) {
		return nil
	}
	return []finding.Finding{{
		CheckID:  finding.CheckGHActionArtiPacked,
		Module:   "github",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Asset:    repo,
		Title:    "Git credentials may be included in uploaded artifact (ArtiPACKED)",
		Description: "The workflow checks out the repository (which by default persists git credentials " +
			"to .git/config) and also uploads an artifact. If the artifact upload path includes the " +
			"repository checkout directory, the .git/config file containing the GITHUB_TOKEN will be " +
			"included in the artifact and accessible to anyone who can download it. Set " +
			"`persist-credentials: false` on the checkout step, or ensure the artifact path " +
			"excludes the .git directory.",
		Evidence:     map[string]any{"vector": "ArtiPACKED — credentials in artifact"},
		DiscoveredAt: time.Now(),
	}}
}

// reReleaseTrigger detects release-related workflow triggers.
var reReleaseTrigger = regexp.MustCompile(`(?m)^\s*release:|on:\s*release`)

// reRestoreCache detects cache restore steps.
var reRestoreCache = regexp.MustCompile(`uses:\s*actions/cache`)

// checkCachePoisoning flags release workflows that restore build caches.
func checkCachePoisoning(workflowYAML, repo string) []finding.Finding {
	if !reReleaseTrigger.MatchString(workflowYAML) {
		return nil
	}
	if !reRestoreCache.MatchString(workflowYAML) {
		return nil
	}
	return []finding.Finding{{
		CheckID:  finding.CheckGHActionCachePoisoning,
		Module:   "github",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Asset:    repo,
		Title:    "Release workflow restores build cache — cache poisoning risk",
		Description: "A release workflow restores a build cache via actions/cache. Build caches " +
			"are populated by PR workflows (which run in the context of the PR branch). An attacker " +
			"with write access to a PR can poison the cache with malicious artifacts that are then " +
			"consumed by the privileged release workflow. Use a separate, isolated build environment " +
			"for releases or disable cache restore in release workflows.",
		Evidence:     map[string]any{"vector": "cache poisoning on release trigger"},
		DiscoveredAt: time.Now(),
	}}
}

// -------------------------------------------------------------------------
// OIDC vs long-lived credential checks
// -------------------------------------------------------------------------

// cloudCredCheck describes a pattern that detects a long-lived secret being used
// instead of OIDC/Workload Identity.
type cloudCredCheck struct {
	checkID     finding.CheckID
	secretNames []string // secret context names that indicate a long-lived key
	oidcAction  string   // action name that indicates OIDC is being used (skip if present)
	service     string   // human-readable service name
	mitigation  string   // recommended OIDC approach
}

var cloudCredChecks = []cloudCredCheck{
	{
		checkID:     finding.CheckGHActionAWSLongLivedKey,
		secretNames: []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"},
		oidcAction:  "aws-actions/configure-aws-credentials",
		service:     "AWS",
		mitigation:  "Use aws-actions/configure-aws-credentials with `role-to-assume` and `id-token: write` permission (OIDC) instead of long-lived access keys.",
	},
	{
		checkID:     finding.CheckGHActionGCPServiceAccountKey,
		secretNames: []string{"GOOGLE_CREDENTIALS", "GCP_SA_KEY", "GOOGLE_APPLICATION_CREDENTIALS", "GCP_CREDENTIALS"},
		oidcAction:  "google-github-actions/auth",
		service:     "GCP",
		mitigation:  "Use google-github-actions/auth with `workload_identity_provider` and `service_account` (Workload Identity Federation) instead of a service account JSON key.",
	},
	{
		checkID:     finding.CheckGHActionAzureCredentials,
		secretNames: []string{"AZURE_CREDENTIALS", "AZURE_CLIENT_SECRET", "ARM_CLIENT_SECRET"},
		oidcAction:  "azure/login",
		service:     "Azure",
		mitigation:  "Use azure/login with `client-id`, `tenant-id`, and `subscription-id` with `id-token: write` (OIDC federated credentials) instead of a service principal JSON secret.",
	},
	{
		checkID:     finding.CheckGHActionNPMTokenNotOIDC,
		secretNames: []string{"NODE_AUTH_TOKEN", "NPM_TOKEN", "NPM_AUTH_TOKEN"},
		oidcAction:  "npm/provenance",
		service:     "npm",
		mitigation:  "Use npm OIDC Trusted Publishing: set `id-token: write`, configure `NPM_CONFIG_PROVENANCE=true`, and use a granular access token scoped to the package instead of a long-lived automation token.",
	},
	{
		checkID:     finding.CheckGHActionPyPITokenNotTrusted,
		secretNames: []string{"PYPI_API_TOKEN", "PYPI_TOKEN", "TWINE_PASSWORD", "POETRY_PYPI_TOKEN_PYPI"},
		oidcAction:  "pypa/gh-action-pypi-publish",
		service:     "PyPI",
		mitigation:  "Use PyPI Trusted Publishing: configure the package on PyPI to trust this GitHub repository and workflow, then use pypa/gh-action-pypi-publish with `id-token: write` — no API token needed.",
	},
	{
		checkID:     finding.CheckGHActionDockerPasswordSecret,
		secretNames: []string{"DOCKER_PASSWORD", "DOCKERHUB_TOKEN", "DOCKER_TOKEN", "REGISTRY_PASSWORD"},
		oidcAction:  "docker/login-action",
		service:     "Docker registry",
		mitigation:  "For GitHub Container Registry (ghcr.io) use `GITHUB_TOKEN` with `packages: write`. For Docker Hub, consider OIDC with a fine-grained access token scoped to specific repositories.",
	},
	{
		checkID:     finding.CheckGHActionVercelToken,
		secretNames: []string{"VERCEL_TOKEN"},
		oidcAction:  "",
		service:     "Vercel",
		mitigation:  "Rotate VERCEL_TOKEN regularly and scope it to the minimum required projects. Consider using Vercel's GitHub App integration which does not require a token secret.",
	},
	{
		checkID:     finding.CheckGHActionTerraformCloudToken,
		secretNames: []string{"TF_API_TOKEN", "TFC_TOKEN", "TERRAFORM_CLOUD_TOKEN", "TF_TOKEN_app_terraform_io"},
		oidcAction:  "hashicorp/setup-terraform",
		service:     "Terraform Cloud/HCP Terraform",
		mitigation:  "Use HCP Terraform's OIDC integration: configure a dynamic provider credentials policy in HCP Terraform and use `id-token: write` instead of a long-lived API token.",
	},
	{
		checkID:     finding.CheckGHActionFlyToken,
		secretNames: []string{"FLY_API_TOKEN", "FLY_TOKEN"},
		oidcAction:  "superfly/flyctl-actions",
		service:     "Fly.io",
		mitigation:  "Use Fly.io OIDC: create a deploy token scoped to the specific app with the minimum TTL, or use flyctl's --access-token flag with a short-lived token generated via OIDC.",
	},
}

// reSecretRef matches ${{ secrets.NAME }} and captures NAME.
var reSecretRef = regexp.MustCompile(`\$\{\{\s*secrets\.(\w+)\s*\}\}`)

// checkLongLivedCloudCreds checks whether the workflow uses long-lived cloud credentials
// instead of OIDC / Workload Identity.
func checkLongLivedCloudCreds(workflowYAML, repo string) []finding.Finding {
	// Collect all secret names referenced in this workflow.
	secretsUsed := make(map[string]struct{})
	for _, m := range reSecretRef.FindAllStringSubmatch(workflowYAML, -1) {
		if len(m) == 2 {
			secretsUsed[strings.ToUpper(m[1])] = struct{}{}
		}
	}
	if len(secretsUsed) == 0 {
		return nil
	}

	var findings []finding.Finding
	for _, check := range cloudCredChecks {
		// If the OIDC action is already present, skip — they're using OIDC.
		if check.oidcAction != "" && strings.Contains(workflowYAML, check.oidcAction) {
			// Only skip if the oidc action appears with role-to-assume / workload_identity_provider
			// (simple heuristic: the action slug just being present is enough to skip).
			continue
		}
		for _, secretName := range check.secretNames {
			if _, ok := secretsUsed[secretName]; ok {
				findings = append(findings, finding.Finding{
					CheckID:  check.checkID,
					Module:   "github",
					Scanner:  scannerName,
					Severity: finding.SeverityHigh,
					Asset:    repo,
					Title:    fmt.Sprintf("%s: long-lived credential secret instead of OIDC", check.service),
					Description: fmt.Sprintf(
						"The workflow uses secrets.%s — a long-lived %s credential. Long-lived keys "+
							"increase the blast radius if the secret is leaked: they remain valid until "+
							"manually rotated, often have broad permissions, and are an attractive target "+
							"for supply chain attacks. %s",
						secretName, check.service, check.mitigation),
					Evidence:     map[string]any{"secret": secretName, "service": check.service},
					DiscoveredAt: time.Now(),
				})
				break // one finding per service
			}
		}
	}
	return findings
}

// patSecretNames are common secret names that indicate a GitHub Personal Access Token
// is being used in a workflow. These are checked case-insensitively.
var patSecretNames = []string{
	"GH_PAT", "GITHUB_PAT", "GH_TOKEN", "GITHUB_TOKEN_PAT",
	"PERSONAL_ACCESS_TOKEN", "GITHUB_ACCESS_TOKEN", "ACCESS_TOKEN",
	"REPO_TOKEN", "CI_TOKEN", "BOT_TOKEN", "GITHUB_API_TOKEN",
	"GIT_TOKEN", "GH_API_TOKEN", "GITHUB_PERSONAL_TOKEN",
}

// checkPATUsedInWorkflow detects common PAT-named secrets used in workflows and
// recommends GITHUB_TOKEN or a fine-grained PAT / GitHub App token as appropriate.
func checkPATUsedInWorkflow(workflowYAML, repo string) []finding.Finding {
	// Collect all secret names referenced in this workflow.
	secretsUsed := make(map[string]string) // upper-case name -> original name
	for _, m := range reSecretRef.FindAllStringSubmatch(workflowYAML, -1) {
		if len(m) == 2 {
			secretsUsed[strings.ToUpper(m[1])] = m[1]
		}
	}

	var findings []finding.Finding
	seen := make(map[string]struct{})
	for _, name := range patSecretNames {
		orig, ok := secretsUsed[name]
		if !ok {
			continue
		}
		if _, already := seen[name]; already {
			continue
		}
		seen[name] = struct{}{}

		// Distinguish classic PAT guidance from general PAT guidance based on name signals.
		// We can't see the actual token value here (only the secret name), so we key on
		// whether the name is very generic (could be a GitHub App token) vs clearly a PAT.
		desc := fmt.Sprintf(
			"The workflow uses secrets.%s, which appears to be a GitHub Personal Access Token (PAT). "+
				"PATs carry risks that the built-in GITHUB_TOKEN does not:\n\n"+
				"• Classic PATs (ghp_...) grant broad account-level permissions across all repos "+
				"the owner can access — they cannot be scoped to a single repository.\n"+
				"• Fine-grained PATs (github_pat_...) are better: repo-scoped, permission-limited, "+
				"and support expiry — but they are still long-lived credentials tied to one person's account.\n\n"+
				"Recommended alternatives in order of preference:\n"+
				"1. Use ${{ secrets.GITHUB_TOKEN }} for operations on the current repository "+
				"(contents, packages, pull requests) — it is automatically provisioned per-run with minimal scope.\n"+
				"2. For cross-repository or organisation-wide access, create a GitHub App and use "+
				"its installation token (short-lived, auditable, not tied to a personal account).\n"+
				"3. If a PAT is unavoidable, use a fine-grained PAT with the narrowest permissions, "+
				"shortest acceptable expiry, and store it as an organisation secret scoped to only "+
				"the repositories that need it — never a classic PAT.",
			orig)

		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckGHActionPATUsedInWorkflow,
			Module:   "github",
			Scanner:  scannerName,
			Severity: finding.SeverityMedium,
			Asset:    repo,
			Title:    fmt.Sprintf("PAT secret %q used in workflow — prefer GITHUB_TOKEN or GitHub App token", orig),
			Description: desc,
			Evidence:    map[string]any{"secret": orig},
			DiscoveredAt: time.Now(),
		})
	}
	return findings
}

// -------------------------------------------------------------------------
// GitHub API helpers
// -------------------------------------------------------------------------

// ghContentItem represents one item from the GitHub Contents API list response.
type ghContentItem struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	Type        string `json:"type"` // "file" or "dir"
	DownloadURL string `json:"download_url"`
}

// ghFileContent represents a single file returned by the GitHub Contents API.
type ghFileContent struct {
	Content  string `json:"content"`  // base64-encoded
	Encoding string `json:"encoding"` // "base64"
}

// ghRepo is the minimal fields we need from the repo API response.
type ghRepo struct {
	Private bool `json:"private"`
}

// listWorkflows returns the paths of all .yml/.yaml files in .github/workflows/.
func (s *Scanner) listWorkflows(ctx context.Context, owner, repo string) ([]string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/.github/workflows", owner, repo)
	body, err := s.apiGet(ctx, url)
	if err != nil {
		return nil, err
	}

	var items []ghContentItem
	if err := json.Unmarshal(body, &items); err != nil {
		return nil, fmt.Errorf("parsing workflows list: %w", err)
	}

	var paths []string
	for _, item := range items {
		if item.Type != "file" {
			continue
		}
		lower := strings.ToLower(item.Name)
		if strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml") {
			paths = append(paths, item.Path)
		}
	}
	return paths, nil
}

// fetchWorkflowContent returns the decoded text content of a workflow file.
func (s *Scanner) fetchWorkflowContent(ctx context.Context, owner, repo, path string) (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s", owner, repo, path)
	body, err := s.apiGet(ctx, url)
	if err != nil {
		return "", err
	}

	var file ghFileContent
	if err := json.Unmarshal(body, &file); err != nil {
		return "", fmt.Errorf("parsing file content for %s: %w", path, err)
	}

	if file.Encoding != "base64" {
		return "", fmt.Errorf("unexpected encoding %q for %s", file.Encoding, path)
	}

	// GitHub returns base64 with embedded newlines; strip them before decoding.
	cleaned := strings.ReplaceAll(file.Content, "\n", "")
	decoded, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		return "", fmt.Errorf("base64 decode failed for %s: %w", path, err)
	}
	return string(decoded), nil
}

// isRepoPublic returns true when the repository is publicly visible.
func (s *Scanner) isRepoPublic(ctx context.Context, owner, repo string) (bool, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s", owner, repo)
	body, err := s.apiGet(ctx, url)
	if err != nil {
		return false, err
	}

	var r ghRepo
	if err := json.Unmarshal(body, &r); err != nil {
		return false, fmt.Errorf("parsing repo metadata: %w", err)
	}
	return !r.Private, nil
}

// apiGet performs an authenticated (if token is set) GET against the GitHub API.
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

	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20)) // 4 MiB max
	if err != nil {
		return nil, err
	}
	return data, nil
}

// -------------------------------------------------------------------------
// Utility
// -------------------------------------------------------------------------

// splitOwnerRepo splits "owner/repo" into its two components.
// Returns ok=false if the string is not in that form.
func splitOwnerRepo(target string) (owner, repo string, ok bool) {
	// Strip a leading "github.com/" prefix if present.
	target = strings.TrimPrefix(target, "https://github.com/")
	target = strings.TrimPrefix(target, "http://github.com/")
	target = strings.TrimPrefix(target, "github.com/")

	parts := strings.SplitN(target, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}
