package ghactions

// checks_supply_chain.go — detects supply-chain risks in GitHub Actions workflows:
// OIDC trust scope, typosquatting, repo-jacking, draft PR triggers,
// trojan source chars, runner label spoofing, and lockfile injection.

import (
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/stormbane-security/beacon/internal/finding"
)

// ── checkOIDCTrustTooWide ──────────────────────────────────────────────────

// reOIDCActions matches OIDC federation actions.
var reOIDCActions = regexp.MustCompile(
	`uses:\s*(aws-actions/configure-aws-credentials|google-github-actions/auth|azure/login)`)

// reIDTokenWrite detects id-token: write permission.
var reIDTokenWrite = regexp.MustCompile(`(?m)id-token\s*:\s*write`)

// reEnvironmentKey detects the presence of an environment: constraint on a job.
var reEnvironmentKey = regexp.MustCompile(`(?m)^\s+environment\s*:`)

// checkOIDCTrustTooWide detects workflows using OIDC federation actions
// (aws-actions/configure-aws-credentials, google-github-actions/auth, azure/login)
// with id-token: write permission but without scoping the trust policy via an
// environment: constraint on the job. Without scoping, any branch or triggering
// event can obtain cloud credentials via the OIDC token.
func checkOIDCTrustTooWide(workflowYAML, repo string) []finding.Finding {
	m := reOIDCActions.FindStringSubmatch(workflowYAML)
	if m == nil {
		return nil
	}
	action := m[1]

	// Only relevant if the workflow requests id-token: write.
	if !reIDTokenWrite.MatchString(workflowYAML) {
		return nil
	}

	// If the workflow uses an environment: constraint, the trust is scoped.
	if reEnvironmentKey.MatchString(workflowYAML) {
		return nil
	}

	return []finding.Finding{{
		CheckID:  finding.CheckGHActionOIDCTrustTooWide,
		Module:   "github",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Asset:    repo,
		Title:    fmt.Sprintf("OIDC federation trust not scoped (%s)", action),
		Description: fmt.Sprintf(
			"The workflow uses %s for OIDC federation with `id-token: write` but does not "+
				"scope the trust policy using an `environment:` constraint on the job. Without scoping, "+
				"any branch or triggering event can obtain cloud credentials via the OIDC token. "+
				"An attacker who can push a branch or trigger the workflow gains cloud access. "+
				"Fix: add an `environment:` to the job and configure the cloud provider's trust "+
				"policy to require that environment.", action),
		Evidence:     map[string]any{"action": action, "id_token_write": true, "environment_constraint": false},
		DiscoveredAt: time.Now(),
	}}
}

// ── checkTyposquatAction ───────────────────────────────────────────────────

// popularActions is the list of commonly used GitHub Actions that typosquatters
// target. Each entry is "owner/name" in lowercase.
var popularActions = []string{
	"actions/checkout",
	"actions/setup-node",
	"actions/setup-python",
	"actions/cache",
	"actions/upload-artifact",
	"actions/download-artifact",
	"actions/setup-java",
	"actions/setup-go",
	"github/codeql-action",
	"docker/build-push-action",
	"docker/login-action",
}

// levenshtein computes the Levenshtein edit distance between two strings.
func levenshtein(a, b string) int {
	la := utf8.RuneCountInString(a)
	lb := utf8.RuneCountInString(b)

	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}

	ra := []rune(a)
	rb := []rune(b)

	// Use a single-row DP approach.
	prev := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}

	for i := 1; i <= la; i++ {
		curr := make([]int, lb+1)
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			del := prev[j] + 1
			ins := curr[j-1] + 1
			sub := prev[j-1] + cost
			min := del
			if ins < min {
				min = ins
			}
			if sub < min {
				min = sub
			}
			curr[j] = min
		}
		prev = curr
	}
	return prev[lb]
}

// reUsesAction extracts the "owner/name" part (before @) from a uses: line.
// Group 1 = "owner/name"
var reUsesAction = regexp.MustCompile(`uses:\s+([^@\s#]+)@`)

// checkTyposquatAction flags uses: references where the owner/name is within
// edit distance 2 of a popular action but is not an exact match — a likely
// typosquatting attempt.
func checkTyposquatAction(workflowYAML, repo string) []finding.Finding {
	var findings []finding.Finding
	seen := make(map[string]struct{})

	for _, m := range reUsesAction.FindAllStringSubmatch(workflowYAML, -1) {
		if len(m) < 2 {
			continue
		}
		actionSlug := strings.TrimSpace(m[1])

		// Skip local actions.
		if strings.HasPrefix(actionSlug, "./") {
			continue
		}

		// Skip reusable workflow refs (contain /.github/workflows/).
		if strings.Contains(actionSlug, "/.github/workflows/") {
			continue
		}

		lower := strings.ToLower(actionSlug)
		if _, ok := seen[lower]; ok {
			continue
		}
		seen[lower] = struct{}{}

		for _, popular := range popularActions {
			if lower == popular {
				break // exact match — not a typosquat
			}
			dist := levenshtein(lower, popular)
			if dist > 0 && dist <= 2 {
				findings = append(findings, finding.Finding{
					CheckID:  finding.CheckGHActionTyposquatAction,
					Module:   "github",
					Scanner:  scannerName,
					Severity: finding.SeverityHigh,
					Asset:    repo,
					Title:    fmt.Sprintf("Possible typosquat action: %s (similar to %s)", actionSlug, popular),
					Description: fmt.Sprintf(
						"The workflow uses %q which is within edit distance %d of the popular action %q. "+
							"Typosquatting is a common supply-chain attack: an attacker registers a similarly-named "+
							"action that appears legitimate but executes malicious code. "+
							"Verify that %q is the intended action, or correct it to %s.",
						actionSlug, dist, popular, actionSlug, popular),
					Evidence:     map[string]any{"action": actionSlug, "similar_to": popular, "edit_distance": dist},
					DiscoveredAt: time.Now(),
				})
				break // one finding per action slug
			}
		}
	}
	return findings
}

// ── checkRepoJackingRisk ──────────────────────────────────────────────────

// trustedActionOwners is the set of well-known GitHub action owners that are
// not at risk of repo-jacking (first-party or large verified orgs).
var trustedActionOwners = map[string]struct{}{
	"actions":                {},
	"github":                 {},
	"docker":                 {},
	"aws-actions":            {},
	"google-github-actions":  {},
	"azure":                  {},
	"hashicorp":              {},
	"cloudflare":             {},
}

// reUsesActionWithRef extracts "owner/name" and "ref" from a uses: line.
// Group 1 = "owner/name", Group 2 = ref (after @).
var reUsesActionWithRef = regexp.MustCompile(`uses:\s+([^@\s#]+)@([^\s#]+)`)

// checkRepoJackingRisk flags actions from non-trusted owners that are referenced
// by tag rather than SHA. When an org/owner renames their GitHub account, the old
// name becomes claimable. An attacker can register the old name and serve a
// malicious action. Actions pinned to a full SHA are safe because GitHub validates
// the commit hash regardless of namespace changes.
func checkRepoJackingRisk(workflowYAML, repo string) []finding.Finding {
	var findings []finding.Finding
	seen := make(map[string]struct{})

	for _, m := range reUsesActionWithRef.FindAllStringSubmatch(workflowYAML, -1) {
		if len(m) < 3 {
			continue
		}
		actionSlug := strings.TrimSpace(m[1])
		ref := strings.TrimSpace(m[2])

		if strings.HasPrefix(actionSlug, "./") {
			continue
		}

		// Skip reusable workflow refs.
		if strings.Contains(actionSlug, "/.github/workflows/") {
			continue
		}

		// Extract the org/owner portion.
		parts := strings.SplitN(actionSlug, "/", 2)
		if len(parts) < 2 {
			continue
		}
		org := strings.ToLower(parts[0])

		// Skip trusted owners.
		if _, trusted := trustedActionOwners[org]; trusted {
			continue
		}

		// SHA-pinned refs are safe — the hash is verified regardless of namespace.
		if reFullSHA.MatchString(ref) {
			continue
		}

		key := actionSlug + "@" + ref
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckGHActionRepoJackingRisk,
			Module:   "github",
			Scanner:  scannerName,
			Severity: finding.SeverityCritical,
			Asset:    repo,
			Title:    fmt.Sprintf("Repo-jacking risk: %s@%s from non-trusted owner %q", actionSlug, ref, org),
			Description: fmt.Sprintf(
				"The workflow references %s@%s from owner %q, which is not in the set of trusted "+
					"action owners. When a GitHub user or org renames their account, the old name "+
					"becomes available for anyone to claim. An attacker can register the old name "+
					"and serve a malicious action under the same owner/repo path. Tag-based refs "+
					"are especially dangerous because the attacker controls which commit the tag "+
					"points to. "+
					"Fix: pin to a full 40-character commit SHA, or fork the action into your own org.",
				actionSlug, ref, org),
			Evidence:     map[string]any{"action": actionSlug, "ref": ref, "org": org},
			DiscoveredAt: time.Now(),
		})
	}
	return findings
}

// ── checkDraftPRTrigger ────────────────────────────────────────────────────

// rePRTargetTrigger detects pull_request_target: in the on: block.
var rePRTargetTrigger = regexp.MustCompile(`(?m)^\s*pull_request_target\s*:`)

// reDraftPRGuard detects if: conditions that filter out draft PRs.
var reDraftPRGuard = regexp.MustCompile(`(?i)if\s*:.*!.*github\.event\.pull_request\.draft`)

// checkDraftPRTrigger flags pull_request_target workflows that don't filter out
// draft PRs. Without a draft check, there is a TOCTOU risk: an attacker opens a
// draft PR to get CI running, then converts to ready which triggers additional
// workflows with stale security checks.
func checkDraftPRTrigger(workflowYAML, repo string) []finding.Finding {
	if !rePRTargetTrigger.MatchString(workflowYAML) {
		return nil
	}
	// If the workflow checks for draft status, it's guarded.
	if reDraftPRGuard.MatchString(workflowYAML) {
		return nil
	}
	return []finding.Finding{{
		CheckID:  finding.CheckGHActionDraftPRTrigger,
		Module:   "github",
		Scanner:  scannerName,
		Severity: finding.SeverityMedium,
		Asset:    repo,
		Title:    "pull_request_target without draft PR filter (TOCTOU risk)",
		Description: "The workflow triggers on pull_request_target without checking " +
			"`if: !github.event.pull_request.draft`. An attacker can open a draft PR " +
			"to get CI running, then convert it to ready which triggers additional " +
			"workflows with stale security checks (TOCTOU). " +
			"Fix: add `if: !github.event.pull_request.draft` to the job or step level.",
		Evidence:     map[string]any{"trigger": "pull_request_target", "draft_guard": false},
		DiscoveredAt: time.Now(),
	}}
}

// ── checkTrojanSource ──────────────────────────────────────────────────────

// bidiChars are Unicode bidirectional control characters that can make
// displayed code appear different from what actually executes.
var bidiChars = []rune{
	'\u202A', // LEFT-TO-RIGHT EMBEDDING
	'\u202B', // RIGHT-TO-LEFT EMBEDDING
	'\u202C', // POP DIRECTIONAL FORMATTING
	'\u202D', // LEFT-TO-RIGHT OVERRIDE
	'\u202E', // RIGHT-TO-LEFT OVERRIDE
	'\u2066', // LEFT-TO-RIGHT ISOLATE
	'\u2067', // RIGHT-TO-LEFT ISOLATE
	'\u2068', // FIRST STRONG ISOLATE
	'\u2069', // POP DIRECTIONAL ISOLATE
	'\u200F', // RIGHT-TO-LEFT MARK
	'\u200E', // LEFT-TO-RIGHT MARK
}

// checkTrojanSource scans workflow YAML for Unicode bidirectional control
// characters. These invisible characters can make code appear different in
// an editor than what the shell actually executes, hiding malicious commands
// in plain sight.
func checkTrojanSource(workflowYAML, repo string) []finding.Finding {
	found := make(map[rune]struct{})
	for _, r := range workflowYAML {
		for _, bidi := range bidiChars {
			if r == bidi {
				found[r] = struct{}{}
			}
		}
	}
	if len(found) == 0 {
		return nil
	}

	var chars []string
	for r := range found {
		chars = append(chars, fmt.Sprintf("U+%04X", r))
	}

	return []finding.Finding{{
		CheckID:  finding.CheckGHActionTrojanSource,
		Module:   "github",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Asset:    repo,
		Title:    fmt.Sprintf("Trojan Source: bidirectional control characters in workflow (%s)", strings.Join(chars, ", ")),
		Description: fmt.Sprintf(
			"The workflow file contains Unicode bidirectional control characters (%s). "+
				"These invisible characters can make code appear different in an editor than what "+
				"the shell actually executes — an attacker can hide malicious commands that look "+
				"like comments or benign code. This technique is known as Trojan Source (CVE-2021-42574). "+
				"Fix: remove all bidirectional control characters from the workflow file. "+
				"Use `cat -v` or a hex editor to inspect invisible characters.",
			strings.Join(chars, ", ")),
		Evidence:     map[string]any{"bidi_chars": chars},
		DiscoveredAt: time.Now(),
	}}
}

// ── checkRunnerLabelSpoof ──────────────────────────────────────────────────

// reRunsOnSelfHosted matches runs-on lines that include self-hosted.
var reRunsOnSelfHosted = regexp.MustCompile(`(?m)runs-on\s*:.*self-hosted`)

// githubHostedLabels are the default GitHub-hosted runner labels. If a
// self-hosted runner uses one of these, the label is spoofable: anyone
// registering a self-hosted runner with the same label can intercept jobs.
var githubHostedLabels = []string{
	"ubuntu-latest",
	"ubuntu-22.04",
	"ubuntu-24.04",
	"ubuntu-20.04",
	"windows-latest",
	"windows-2022",
	"windows-2019",
	"macos-latest",
	"macos-14",
	"macos-13",
	"macos-12",
}

// checkRunnerLabelSpoof flags self-hosted runners that also use a default
// GitHub-hosted label. When runs-on includes both "self-hosted" and a standard
// label like "ubuntu-latest", the label is ambiguous: a rogue self-hosted
// runner registered with the same label can intercept jobs intended for
// GitHub-hosted infrastructure.
func checkRunnerLabelSpoof(workflowYAML, repo string) []finding.Finding {
	var findings []finding.Finding
	for _, line := range strings.Split(workflowYAML, "\n") {
		if !reRunsOnSelfHosted.MatchString(line) {
			continue
		}
		lower := strings.ToLower(line)
		for _, label := range githubHostedLabels {
			if strings.Contains(lower, label) {
				findings = append(findings, finding.Finding{
					CheckID:  finding.CheckGHActionRunnerLabelSpoof,
					Module:   "github",
					Scanner:  scannerName,
					Severity: finding.SeverityHigh,
					Asset:    repo,
					Title:    fmt.Sprintf("Self-hosted runner uses spoofable label %q", label),
					Description: fmt.Sprintf(
						"The workflow uses `runs-on: [self-hosted, %s]`. The label %q is also a "+
							"default GitHub-hosted runner label. Any self-hosted runner registered with "+
							"this label can intercept jobs, potentially executing on an attacker-controlled "+
							"machine. This is especially dangerous in organization-shared runner groups. "+
							"Fix: use unique custom labels for self-hosted runners (e.g. `my-org-linux-x64`) "+
							"that cannot collide with GitHub-hosted labels.", label, label),
					Evidence:     map[string]any{"label": label, "self_hosted": true},
					DiscoveredAt: time.Now(),
				})
				return findings // one finding per workflow is enough
			}
		}
	}
	return findings
}

// ── checkLockfileInjection ────────────────────────────────────────────────

// rePREvent detects pull_request or pull_request_target triggers.
var rePREvent = regexp.MustCompile(`(?m)(pull_request|pull_request_target)`)

// reInstallCommands detects common package install commands in run: steps.
var reInstallCommands = regexp.MustCompile(
	`(?m)(npm\s+install|npm\s+ci|yarn\s+install|pip\s+install\s+-r|` +
		`bundle\s+install|go\s+mod\s+download|cargo\s+build|composer\s+install)`)

// reLockfileCheck detects a prior lockfile diff check (git diff on lockfile names).
var reLockfileCheck = regexp.MustCompile(
	`(?i)git\s+diff.*\b(package-lock|yarn\.lock|Pipfile\.lock|go\.sum|pnpm-lock|Gemfile\.lock|Cargo\.lock|composer\.lock)\b`)

// checkLockfileInjection flags PR-triggered workflows that run package install
// commands without first checking if the lockfile was modified. A malicious PR
// can modify the lockfile to point to attacker-controlled registries or packages
// with altered integrity hashes, and the install command will fetch the
// tampered dependencies.
func checkLockfileInjection(workflowYAML, repo string) []finding.Finding {
	if !rePREvent.MatchString(workflowYAML) {
		return nil
	}
	if !reInstallCommands.MatchString(workflowYAML) {
		return nil
	}
	// If the workflow checks lockfile diffs, it's aware of the risk.
	if reLockfileCheck.MatchString(workflowYAML) {
		return nil
	}
	return []finding.Finding{{
		CheckID:  finding.CheckGHActionLockfileInjection,
		Module:   "github",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Asset:    repo,
		Title:    "PR workflow runs package install without lockfile verification",
		Description: "The workflow is triggered by pull_request or pull_request_target and runs a package " +
			"install command (npm install, yarn install, pip install -r, bundle install, go mod download, " +
			"cargo build, or composer install) without first verifying lockfile integrity. A malicious PR " +
			"can modify the lockfile to point to attacker-controlled registries or packages with altered " +
			"integrity hashes. The install step will fetch tampered dependencies and execute arbitrary " +
			"install scripts. " +
			"Fix: check if lockfiles were modified before installing (e.g. `git diff --name-only` " +
			"on lockfile paths), use `npm ci` (which errors on lockfile mismatch with package.json), " +
			"or run installs in a sandboxed environment.",
		Evidence:     map[string]any{"trigger": "pull_request", "lockfile_check": false},
		DiscoveredAt: time.Now(),
	}}
}
