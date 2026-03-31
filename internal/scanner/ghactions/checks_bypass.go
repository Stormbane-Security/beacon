package ghactions

// checks_bypass.go — detects workflows that deliberately circumvent the
// safety mechanisms GitHub provides: PR reviews, branch protection rules,
// and deployment approval gates.

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
)

// ── Regex table ────────────────────────────────────────────────────────────

// Issue-comment trigger: matches all YAML forms:
//   on: issue_comment
//   on: [issue_comment, ...]
//   on:\n  issue_comment:
var reIssueCommentTrigger = regexp.MustCompile(`(?m)(on:\s*\[?[^\]]*\bissue_comment\b|^\s*issue_comment\s*[:\[])`)

// Unsafe checkout of PR head in an issue_comment context.
// Matches github.event.issue.pull_request.head.sha or .head.ref
var reIssueCommentCheckout = regexp.MustCompile(
	`github\.event\.issue\.pull_request\.head\.(sha|ref)`)

// Auto-merge patterns: gh pr merge, github.rest.pulls.merge, hub merge, ...
var reAutoMerge = regexp.MustCompile(
	`(?i)\bgh\s+pr\s+merge\b|` +
		`github\.rest\.pulls\.merge\s*\(|` +
		`octokit\.pulls\.merge\s*\(|` +
		`hub\s+merge\b`)

// Auto-approve patterns: gh pr review --approve, github.rest.pulls.createReview
var reAutoApprove = regexp.MustCompile(
	`(?i)\bgh\s+pr\s+review\b.*--approve|` +
		`github\.rest\.pulls\.createReview\s*\(|` +
		`octokit\.pulls\.createReview\s*\(`)

// schedule trigger line
var reScheduleTrigger = regexp.MustCompile(`(?m)^\s*schedule\s*:`)

// permissions write indicators in a workflow
var reWritePermissions = regexp.MustCompile(
	`(?m)permissions:\s*(write-all|write)|` +
		`(?m)(contents|pull-requests|packages|deployments)\s*:\s*write`)

// job block start: "  job-name:" or "  job-name: " at 2-space indent
var reJobStart = regexp.MustCompile(`(?m)^  [a-zA-Z0-9_-]+:\s*$`)

// timeout-minutes: N
var reTimeout = regexp.MustCompile(`(?m)^\s+timeout-minutes\s*:\s*\d`)

// continue-on-error: true
var reContinueOnError = regexp.MustCompile(`(?m)continue-on-error\s*:\s*true`)

// security-relevant tool names in a step name or run block
var securityToolPattern = regexp.MustCompile(
	`(?i)\b(trivy|semgrep|snyk|grype|checkov|trufflehog|gitleaks|codeql|` +
		`sonar|bandit|gosec|eslint.*security|npm\s+audit|yarn\s+audit|` +
		`dependency.?review|secret.?scan)\b`)

// ── checkIssueCommentUnsafe ────────────────────────────────────────────────

// checkIssueCommentUnsafe flags workflows triggered by issue_comment that
// check out the PR's head SHA or ref.  Because issue_comment runs with the
// target branch's secrets and write permissions (unlike pull_request which
// sandboxes forks), checking out untrusted PR code gives external contributors
// RCE with full repository write access.
//
// This is distinct from the pull_request_target vector (covered by
// checkPRTargetUnsafe) — the trigger and permissions model differ.
func checkIssueCommentUnsafe(workflowYAML, repo string) []finding.Finding {
	if !reIssueCommentTrigger.MatchString(workflowYAML) {
		return nil
	}
	if !reIssueCommentCheckout.MatchString(workflowYAML) {
		return nil
	}
	return []finding.Finding{{
		CheckID:  finding.CheckGHActionIssueCommentUnsafe,
		Module:   "github",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("issue_comment workflow checks out untrusted PR code in %s", repo),
		Description: "The workflow is triggered by issue_comment and checks out " +
			"github.event.issue.pull_request.head.sha or .head.ref. " +
			"Unlike pull_request, issue_comment runs with the target branch's write " +
			"permissions and secrets. An attacker can open a PR, comment to trigger " +
			"the workflow, and execute arbitrary code with repository write access. " +
			"Fix: never check out PR head code in issue_comment workflows. " +
			"Use pull_request (sandboxed) instead, or explicitly limit permissions.",
		Asset:        repo,
		Evidence:     map[string]any{"trigger": "issue_comment", "unsafe_ref": "github.event.issue.pull_request.head"},
		ProofCommand: fmt.Sprintf("gh api repos/%s/actions/workflows --jq '[.workflows[].path]'", repo),
		DiscoveredAt: time.Now(),
	}}
}

// ── checkWorkflowAutoMerge ─────────────────────────────────────────────────

// checkWorkflowAutoMerge flags workflows that programmatically merge pull
// requests.  When a workflow can merge its own PRs it bypasses branch
// protection rules entirely — required reviews and status checks can be
// circumvented by creating a PR that auto-merges the moment it passes CI.
func checkWorkflowAutoMerge(workflowYAML, repo string) []finding.Finding {
	m := reAutoMerge.FindString(workflowYAML)
	if m == "" {
		return nil
	}
	return []finding.Finding{{
		CheckID:  finding.CheckGHActionAutoMerge,
		Module:   "github",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("workflow auto-merges pull requests in %s — bypasses branch protection", repo),
		Description: fmt.Sprintf(
			"A workflow step calls '%s', which merges pull requests programmatically. "+
				"This bypasses any required-reviewer or required-status-check branch "+
				"protection rules: an attacker with write access (or a compromised bot) "+
				"can merge malicious code without human review. "+
				"Fix: remove auto-merge logic from workflows; use GitHub's built-in "+
				"auto-merge feature only with protected branches and required checks "+
				"that cannot be self-satisfied by the same workflow.", m),
		Asset:        repo,
		Evidence:     map[string]any{"pattern": m},
		ProofCommand: fmt.Sprintf("gh api repos/%s/actions/workflows --jq '[.workflows[].path]'", repo),
		DiscoveredAt: time.Now(),
	}}
}

// ── checkWorkflowAutoApprove ───────────────────────────────────────────────

// checkWorkflowAutoApprove flags workflows that programmatically approve pull
// requests.  Required-reviewer branch protection is defeated when the same
// automated process that creates or modifies a PR can also approve it,
// satisfying the reviewer count without human oversight.
func checkWorkflowAutoApprove(workflowYAML, repo string) []finding.Finding {
	m := reAutoApprove.FindString(workflowYAML)
	if m == "" {
		return nil
	}
	return []finding.Finding{{
		CheckID:  finding.CheckGHActionAutoApprove,
		Module:   "github",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Title:    fmt.Sprintf("workflow auto-approves pull requests in %s — bypasses required reviewer", repo),
		Description: fmt.Sprintf(
			"A workflow step calls '%s', which approves pull requests programmatically. "+
				"If the same bot account that submits code can also approve it, "+
				"required-reviewer branch protection is effectively disabled. "+
				"Fix: ensure the approving identity is a separate human-controlled account; "+
				"use CODEOWNERS to require specific human reviewers for sensitive paths.", m),
		Asset:        repo,
		Evidence:     map[string]any{"pattern": m},
		ProofCommand: fmt.Sprintf("gh api repos/%s/actions/workflows --jq '[.workflows[].path]'", repo),
		DiscoveredAt: time.Now(),
	}}
}

// ── checkScheduledWritePermissions ────────────────────────────────────────

// checkScheduledWritePermissions flags scheduled workflows that have write
// permissions.  Scheduled workflows run on a cron timer without any human
// trigger or review.  Combined with write access they can push commits,
// create releases, or modify repository settings autonomously.
func checkScheduledWritePermissions(workflowYAML, repo string) []finding.Finding {
	if !reScheduleTrigger.MatchString(workflowYAML) {
		return nil
	}
	m := reWritePermissions.FindString(workflowYAML)
	if m == "" {
		return nil
	}
	return []finding.Finding{{
		CheckID:  finding.CheckGHActionScheduledWrite,
		Module:   "github",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Title:    fmt.Sprintf("scheduled workflow has write permissions in %s", repo),
		Description: fmt.Sprintf(
			"The workflow uses a schedule trigger and declares write permissions (%s). "+
				"Scheduled workflows run automatically on a timer without human approval. "+
				"Write access allows pushing commits, creating/deleting branches, "+
				"publishing packages, or triggering deployments — all without anyone "+
				"clicking 'run'. "+
				"Fix: scope permissions to the minimum needed (e.g. contents: read); "+
				"if writes are required, add a manual approval step or use "+
				"environment protection rules.", m),
		Asset:        repo,
		Evidence:     map[string]any{"trigger": "schedule", "permissions": m},
		ProofCommand: fmt.Sprintf("gh api repos/%s/actions/workflows --jq '[.workflows[].path]'", repo),
		DiscoveredAt: time.Now(),
	}}
}

// ── checkMissingJobTimeout ─────────────────────────────────────────────────

// checkMissingJobTimeout flags workflow jobs that do not set timeout-minutes.
// Without a timeout, a hung job (network stall, infinite loop, waiting for
// input) runs until GitHub's default 6-hour cap, holding a runner slot and
// accumulating billable minutes.  On self-hosted runners the default is
// effectively infinite and the runner is blocked until manual cancellation.
//
// Only flagged when there are at least two job blocks but no timeout anywhere
// in the file — a single-job workflow that already sets a global timeout at
// the workflow level is not penalised.
func checkMissingJobTimeout(workflowYAML, repo string) []finding.Finding {
	// If any timeout-minutes is set (anywhere in the file) treat it as covered.
	if reTimeout.MatchString(workflowYAML) {
		return nil
	}
	// Only report for workflows with at least one job block.
	if !reJobStart.MatchString(workflowYAML) {
		return nil
	}
	return []finding.Finding{{
		CheckID:  finding.CheckGHActionMissingJobTimeout,
		Module:   "github",
		Scanner:  scannerName,
		Severity: finding.SeverityMedium,
		Title:    fmt.Sprintf("workflow jobs have no timeout-minutes in %s", repo),
		Description: "No job in this workflow sets timeout-minutes. " +
			"A hung or looping job will consume runner time until GitHub's " +
			"6-hour default cap (or indefinitely on self-hosted runners), " +
			"wasting CI minutes and blocking other work. " +
			"Fix: add timeout-minutes to every job, sized to the expected " +
			"maximum legitimate run time (e.g. 30 minutes for a typical build).",
		Asset:        repo,
		Evidence:     map[string]any{"timeout_set": false},
		ProofCommand: fmt.Sprintf("gh api repos/%s/actions/workflows --jq '[.workflows[].path]'", repo),
		DiscoveredAt: time.Now(),
	}}
}

// ── checkContinueOnErrorSecurity ──────────────────────────────────────────

// checkContinueOnErrorSecurity flags security-relevant steps that use
// continue-on-error: true.  When a SAST scanner, secret scanner, or
// dependency-audit step is configured to continue on error, a failure in that
// tool is silently swallowed — the PR or merge can proceed as if the scan
// passed, completely nullifying the security gate.
func checkContinueOnErrorSecurity(workflowYAML, repo string) []finding.Finding {
	lines := strings.Split(workflowYAML, "\n")

	// Walk the file looking for step blocks that contain both a security tool
	// reference AND continue-on-error: true.
	type stepBlock struct {
		start int
		lines []string
	}

	var steps []stepBlock
	var current *stepBlock
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Heuristic: a new step begins with "- " at any indentation level.
		if strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "-\t") {
			if current != nil {
				steps = append(steps, *current)
			}
			current = &stepBlock{start: i}
		}
		if current != nil {
			current.lines = append(current.lines, line)
		}
	}
	if current != nil {
		steps = append(steps, *current)
	}

	var flagged []string
	for _, step := range steps {
		block := strings.Join(step.lines, "\n")
		if !reContinueOnError.MatchString(block) {
			continue
		}
		if !securityToolPattern.MatchString(block) {
			continue
		}
		// Extract the step name for the evidence.
		for _, l := range step.lines {
			if strings.Contains(l, "name:") {
				flagged = append(flagged, strings.TrimSpace(strings.SplitN(l, "name:", 2)[1]))
				break
			}
		}
		if len(flagged) == 0 {
			flagged = append(flagged, fmt.Sprintf("step at line %d", step.start+1))
		}
	}

	if len(flagged) == 0 {
		return nil
	}

	return []finding.Finding{{
		CheckID:  finding.CheckGHActionContinueOnErrorSecurity,
		Module:   "github",
		Scanner:  scannerName,
		Severity: finding.SeverityMedium,
		Title:    fmt.Sprintf("security step(s) with continue-on-error: true in %s (%s)", repo, flagged[0]),
		Description: fmt.Sprintf(
			"The following security-relevant step(s) use continue-on-error: true: %s. "+
				"When a SAST, secret-scanning, or dependency-audit step is allowed to fail "+
				"silently, a tool crash or detected vulnerability no longer blocks the PR "+
				"from merging. The security gate is effectively disabled. "+
				"Fix: remove continue-on-error from security steps; if the tool is flaky, "+
				"fix the flakiness rather than masking it.",
			strings.Join(flagged, ", ")),
		Asset:        repo,
		Evidence:     map[string]any{"affected_steps": flagged},
		ProofCommand: fmt.Sprintf("gh api repos/%s/actions/workflows --jq '[.workflows[].path]'", repo),
		DiscoveredAt: time.Now(),
	}}
}
