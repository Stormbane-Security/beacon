// Package circleci scans CircleCI configuration files for common security
// misconfigurations.
//
// It uses the GitHub Contents API to fetch .circleci/config.yml for a given
// owner/repo target, then applies a set of static analysis rules to the pipeline
// definition. All rules are implemented as string-pattern and regex checks — no full
// YAML AST traversal.
package circleci

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/scan"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)

func init() {
	scan.Register(scannerName, func(cfg scan.ScannerConfig) scan.Scanner {
		return New(cfg.Get("github.token"))
	})
}

const scannerName = "circleci"

// Scanner fetches and analyses CircleCI configuration for a GitHub repo.
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

// Run analyses the CircleCI configuration for the given target.
// target must be "owner/repo" (e.g. "myorg/myrepo").
func (s *Scanner) Run(ctx context.Context, target string, scanType module.ScanType) ([]finding.Finding, error) {
	owner, repo, ok := splitOwnerRepo(target)
	if !ok {
		return nil, fmt.Errorf("circleci: invalid target %q — expected owner/repo", target)
	}

	content, isPublic, err := s.fetchConfig(ctx, owner, repo)
	if err != nil {
		return nil, fmt.Errorf("circleci: fetching config for %s/%s: %w", owner, repo, err)
	}

	repoSlug := owner + "/" + repo
	var all []finding.Finding

	if isPublic {
		all = append(all, checkPublicConfig(content, repoSlug)...)
	}

	all = append(all, checkUnpinnedImages(content, repoSlug)...)
	all = append(all, checkSecretEchoed(content, repoSlug)...)
	all = append(all, checkInsecureSteps(content, repoSlug)...)
	all = append(all, checkUnconstrainedContext(content, repoSlug)...)
	all = append(all, checkMachineExecutor(content, repoSlug)...)

	return all, nil
}

// -------------------------------------------------------------------------
// Analysis rules
// -------------------------------------------------------------------------

// reImageLine matches "image:" and "- image:" directives in CircleCI config YAML.
var reImageLine = regexp.MustCompile(`(?m)^\s*-?\s*image:\s*(.+)$`)

// reSHA256Digest matches an @sha256: digest suffix on a Docker image reference.
var reSHA256Digest = regexp.MustCompile(`@sha256:[0-9a-f]{64}`)

// checkUnpinnedImages flags Docker images in CircleCI jobs that are not pinned
// by SHA256 digest. Mutable tags (e.g. "latest", "node:18") can be overwritten
// in a supply-chain attack.
func checkUnpinnedImages(configYAML, repo string) []finding.Finding {
	var findings []finding.Finding
	seen := make(map[string]struct{})

	for _, m := range reImageLine.FindAllStringSubmatch(configYAML, -1) {
		imageRef := strings.TrimSpace(m[1])

		// Skip multi-line image blocks.
		if imageRef == "" || imageRef == "|" || imageRef == ">" {
			continue
		}

		// Strip inline YAML comments.
		if idx := strings.Index(imageRef, " #"); idx >= 0 {
			imageRef = strings.TrimSpace(imageRef[:idx])
		}

		// Remove surrounding quotes.
		imageRef = strings.Trim(imageRef, `"'`)

		if imageRef == "" {
			continue
		}

		// Skip if already pinned by sha256 digest.
		if reSHA256Digest.MatchString(imageRef) {
			continue
		}

		if _, ok := seen[imageRef]; ok {
			continue
		}
		seen[imageRef] = struct{}{}

		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckCircleCIUnpinnedImage,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityMedium,
			Asset:    repo,
			Title:    fmt.Sprintf("Unpinned Docker image in CircleCI config: %s", imageRef),
			Description: fmt.Sprintf(
				"The CircleCI config references Docker image %q using a mutable tag rather than an immutable "+
					"sha256 digest. If the upstream image is compromised or the tag is moved, "+
					"the pipeline will silently execute attacker-controlled code. Pin to a digest instead: "+
					`image: %s@sha256:<digest>`, imageRef, imageBase(imageRef),
			),
			Evidence:     map[string]any{"image": imageRef},
			ProofCommand: fmt.Sprintf("curl -s 'https://api.github.com/repos/%s/contents/.circleci/config.yml' | jq -r .content | base64 -d | grep 'image:'", repo),
			DiscoveredAt: time.Now(),
		})
	}

	return findings
}

// imageBase returns the image name without the tag (everything before ":tag").
func imageBase(ref string) string {
	if idx := strings.Index(ref, "@"); idx >= 0 {
		return ref[:idx]
	}
	// Strip :tag suffix, but be careful not to strip port numbers (e.g. registry:5000/image).
	if idx := strings.LastIndex(ref, ":"); idx >= 0 {
		after := ref[idx+1:]
		if !strings.Contains(after, "/") {
			return ref[:idx]
		}
	}
	return ref
}

// reEchoSecret matches commands that echo or print environment variables that are
// likely secrets. CircleCI uses $VARIABLE syntax for environment variables.
// This catches patterns like:
//   - echo $CIRCLE_TOKEN
//   - echo "$MY_SECRET"
//   - printf '%s' $API_KEY
//   - curl -H "Authorization: $SECRET_TOKEN" ...
var reEchoSecret = regexp.MustCompile(
	`(?im)(echo|printf|cat|curl)\s+[^#\n]*\$\{?\s*(` +
		`CIRCLE_TOKEN|DOCKERHUB_PASSWORD|` +
		`[A-Z_]*(?:SECRET|TOKEN|PASSWORD|KEY|CREDENTIAL|AUTH|PRIVATE|API_KEY)[A-Z_]*` +
		`)\s*\}?`,
)

// checkSecretEchoed flags pipeline scripts that appear to echo or print
// secret/sensitive variable values. CircleCI masks environment variables set in
// project settings and contexts, but masking can be circumvented via encoding,
// character splitting, or writing to artifacts.
func checkSecretEchoed(configYAML, repo string) []finding.Finding {
	var findings []finding.Finding
	seen := make(map[string]struct{})

	for _, m := range reEchoSecret.FindAllStringSubmatch(configYAML, -1) {
		if len(m) < 3 {
			continue
		}
		cmd := strings.TrimSpace(m[1])
		varName := strings.TrimSpace(m[2])

		key := cmd + ":" + varName
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckCircleCISecretEchoed,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Asset:    repo,
			Title:    fmt.Sprintf("Secret variable may be printed in CI logs: $%s", varName),
			Description: fmt.Sprintf(
				"A CircleCI step appears to %s the variable $%s which looks like a secret or credential. "+
					"Even though CircleCI masks environment variables from contexts and project settings, "+
					"masking can be circumvented by encoding, splitting, or writing to artifacts. "+
					"Never echo secrets directly in CI scripts.",
				cmd, varName,
			),
			Evidence:     map[string]any{"command": cmd, "variable": varName},
			ProofCommand: fmt.Sprintf("curl -s 'https://api.github.com/repos/%s/contents/.circleci/config.yml' | jq -r .content | base64 -d | grep -i '%s'", repo, varName),
			DiscoveredAt: time.Now(),
		})
	}

	return findings
}

// reSetupRemoteDocker matches setup_remote_docker steps without a version pin.
// The version key is optional but when missing, CircleCI uses an old default
// Docker Engine version with known CVEs.
var reSetupRemoteDocker = regexp.MustCompile(`(?m)^\s*-\s*setup_remote_docker\s*$`)

// reNoOutputTimeoutZero matches no_output_timeout: 0 (disabling output timeout).
var reNoOutputTimeoutZero = regexp.MustCompile(`(?m)^\s*no_output_timeout:\s*0\s*$`)

// reSensitiveArtifact matches store_artifacts with paths to sensitive files.
var reSensitiveArtifact = regexp.MustCompile(`(?m)^\s*-\s*store_artifacts:.*(?:/etc/shadow|~/\.ssh|~/\.aws|~/.gnupg)`)

// reSensitiveArtifactPath matches path: directives referencing sensitive locations
// inside a store_artifacts block.
var reSensitiveArtifactPath = regexp.MustCompile(`(?m)^\s*path:\s*(?:/etc/shadow|~/\.ssh|~/\.aws|~/.gnupg)`)

// checkInsecureSteps flags CircleCI steps with dangerous configurations:
// - setup_remote_docker without version pin
// - no_output_timeout: 0 disabling timeout
// - store_artifacts with sensitive file paths
func checkInsecureSteps(configYAML, repo string) []finding.Finding {
	var findings []finding.Finding

	if reSetupRemoteDocker.MatchString(configYAML) {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckCircleCIInsecureStep,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Asset:    repo,
			Title:    "setup_remote_docker without version pin",
			Description: "The CircleCI config uses setup_remote_docker without specifying a Docker Engine " +
				"version. Without an explicit version, CircleCI may use an old default with known " +
				"vulnerabilities. Pin to a specific version: setup_remote_docker: { version: 20.10.24 }",
			Evidence:     map[string]any{"pattern": "setup_remote_docker"},
			ProofCommand: fmt.Sprintf("curl -s 'https://api.github.com/repos/%s/contents/.circleci/config.yml' | jq -r .content | base64 -d | grep 'setup_remote_docker'", repo),
			DiscoveredAt: time.Now(),
		})
	}

	if reNoOutputTimeoutZero.MatchString(configYAML) {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckCircleCIInsecureStep,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Asset:    repo,
			Title:    "Step disables output timeout (no_output_timeout: 0)",
			Description: "A CircleCI step sets no_output_timeout: 0, which removes the output timeout " +
				"entirely. A compromised or malfunctioning step could run indefinitely without producing " +
				"output, consuming build credits and potentially maintaining persistent access to the " +
				"build environment.",
			Evidence:     map[string]any{"pattern": "no_output_timeout: 0"},
			ProofCommand: fmt.Sprintf("curl -s 'https://api.github.com/repos/%s/contents/.circleci/config.yml' | jq -r .content | base64 -d | grep 'no_output_timeout'", repo),
			DiscoveredAt: time.Now(),
		})
	}

	if reSensitiveArtifact.MatchString(configYAML) || reSensitiveArtifactPath.MatchString(configYAML) {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckCircleCIInsecureStep,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Asset:    repo,
			Title:    "store_artifacts exposes sensitive file paths",
			Description: "The CircleCI config uses store_artifacts with a path that references sensitive " +
				"files such as /etc/shadow, ~/.ssh, or ~/.aws. Artifacts are downloadable by anyone " +
				"with access to the CircleCI project and may persist long after the build completes.",
			Evidence:     map[string]any{"pattern": "store_artifacts with sensitive path"},
			ProofCommand: fmt.Sprintf("curl -s 'https://api.github.com/repos/%s/contents/.circleci/config.yml' | jq -r .content | base64 -d | grep -A2 'store_artifacts'", repo),
			DiscoveredAt: time.Now(),
		})
	}

	return findings
}

// checkPublicConfig flags repos where the CircleCI config is accessible without
// authentication — meaning the repo is public. CI configs often reveal internal
// service names, deployment targets, and environment variable names.
func checkPublicConfig(configYAML, repo string) []finding.Finding {
	return []finding.Finding{{
		CheckID:  finding.CheckCircleCIPublicConfig,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityInfo,
		Asset:    repo,
		Title:    "CircleCI configuration is publicly accessible",
		Description: "The .circleci/config.yml file is readable without authentication, confirming " +
			"the repository is public. CI configurations reveal build infrastructure details " +
			"including Docker image names, deployment targets, service dependencies, and " +
			"environment variable names (though not values). Attackers use this information " +
			"to map internal infrastructure and identify supply-chain attack vectors.",
		Evidence: map[string]any{
			"file":        ".circleci/config.yml",
			"config_size": len(configYAML),
		},
		ProofCommand: fmt.Sprintf("curl -sI 'https://api.github.com/repos/%s/contents/.circleci/config.yml'", repo),
		DiscoveredAt: time.Now(),
	}}
}

// reContextLine matches "context:" directives in CircleCI config YAML.
// This captures both single-value (context: my-context) and list-item (- my-context)
// forms within a job's context block.
var reContextLine = regexp.MustCompile(`(?m)^\s*context:\s*(.+)$`)

// reFiltersLine matches "filters:" directives in CircleCI workflow job references.
var reFiltersLine = regexp.MustCompile(`(?m)^\s*filters:`)

// checkUnconstrainedContext flags shared org contexts that are used without
// corresponding branch filters in the same workflow job reference. Without branch
// filters, any branch pushed to the repo — including branches from forks in some
// configurations — can access the context's secrets.
func checkUnconstrainedContext(configYAML, repo string) []finding.Finding {
	var findings []finding.Finding

	// Simple heuristic: if the config has context: references but no filters:
	// blocks, the contexts are unconstrained.
	contextMatches := reContextLine.FindAllStringSubmatch(configYAML, -1)
	if len(contextMatches) == 0 {
		return nil
	}

	hasFilters := reFiltersLine.MatchString(configYAML)
	if hasFilters {
		return nil
	}

	seen := make(map[string]struct{})
	for _, m := range contextMatches {
		ctxName := strings.TrimSpace(m[1])
		ctxName = strings.Trim(ctxName, `"'`)

		// Skip empty or list-start values.
		if ctxName == "" || ctxName == "|" || ctxName == ">" {
			continue
		}

		if _, ok := seen[ctxName]; ok {
			continue
		}
		seen[ctxName] = struct{}{}

		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckCircleCIUnconstrained,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityMedium,
			Asset:    repo,
			Title:    fmt.Sprintf("Shared context %q used without branch filters", ctxName),
			Description: fmt.Sprintf(
				"The CircleCI config references context %q without any branch filters. "+
					"Without filters, any branch pushed to the repo can access the context's secrets. "+
					"Add a filters block to restrict which branches can use this context: "+
					"filters: { branches: { only: [main] } }",
				ctxName,
			),
			Evidence:     map[string]any{"context": ctxName},
			ProofCommand: fmt.Sprintf("curl -s 'https://api.github.com/repos/%s/contents/.circleci/config.yml' | jq -r .content | base64 -d | grep -A5 'context:'", repo),
			DiscoveredAt: time.Now(),
		})
	}

	return findings
}

// reMachineTrue matches "machine: true" in CircleCI config YAML.
var reMachineTrue = regexp.MustCompile(`(?m)^\s*machine:\s*true\s*$`)

// reMachineImage matches "machine:" with an image specification (e.g. machine: { image: ubuntu-2204:current }).
var reMachineImage = regexp.MustCompile(`(?m)^\s*machine:\s*$`)

// reExecutorMachine matches "executor: machine" or executor references to machine type.
var reExecutorMachine = regexp.MustCompile(`(?m)^\s*executor:\s*machine\s*$`)

// checkMachineExecutor flags jobs that use the machine executor, which runs
// the job in a full VM with root access and persistent disk. This is more
// privileged than Docker executors and provides a larger attack surface.
func checkMachineExecutor(configYAML, repo string) []finding.Finding {
	var findings []finding.Finding

	if reMachineTrue.MatchString(configYAML) || reMachineImage.MatchString(configYAML) || reExecutorMachine.MatchString(configYAML) {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckCircleCIMachineExecutor,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityMedium,
			Asset:    repo,
			Title:    "Job uses machine executor (privileged VM)",
			Description: "The CircleCI config uses the machine executor, which runs the job in a full " +
				"virtual machine with root access, persistent disk, and full network access. " +
				"Machine executors have a larger attack surface than Docker executors — a compromised " +
				"job can access the host kernel, install persistent backdoors, and potentially " +
				"pivot to other infrastructure. Use Docker executors when possible.",
			Evidence:     map[string]any{"pattern": "machine executor"},
			ProofCommand: fmt.Sprintf("curl -s 'https://api.github.com/repos/%s/contents/.circleci/config.yml' | jq -r .content | base64 -d | grep -i 'machine'", repo),
			DiscoveredAt: time.Now(),
		})
	}

	return findings
}

// -------------------------------------------------------------------------
// API helpers
// -------------------------------------------------------------------------

// ghFileContent represents a file returned by the GitHub Contents API.
type ghFileContent struct {
	Content  string `json:"content"`  // base64-encoded
	Encoding string `json:"encoding"` // "base64"
}

// fetchConfig retrieves the .circleci/config.yml from the GitHub Contents API.
// Returns the YAML content, whether the repo appears to be public (fetchable
// without auth token), and any error.
func (s *Scanner) fetchConfig(ctx context.Context, owner, repo string) (string, bool, error) {
	apiURL := fmt.Sprintf(
		"https://api.github.com/repos/%s/%s/contents/.circleci/config.yml",
		url.PathEscape(owner), url.PathEscape(repo),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return "", false, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if s.token != "" {
		req.Header.Set("Authorization", "token "+s.token)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB limit
	if err != nil {
		return "", false, fmt.Errorf("reading response body: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return "", false, fmt.Errorf(".circleci/config.yml not found for %s/%s (HTTP 404)", owner, repo)
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		return "", false, fmt.Errorf("access denied for %s/%s (HTTP %d) — repo may be private", owner, repo, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("unexpected status %d for %s/%s", resp.StatusCode, owner, repo)
	}

	var file ghFileContent
	if err := json.Unmarshal(body, &file); err != nil {
		return "", false, fmt.Errorf("parsing GitHub API response for %s/%s: %w", owner, repo, err)
	}

	if file.Encoding != "base64" {
		return "", false, fmt.Errorf("unexpected encoding %q for %s/%s", file.Encoding, owner, repo)
	}

	// GitHub returns base64 with embedded newlines; strip them before decoding.
	cleaned := strings.ReplaceAll(file.Content, "\n", "")
	decoded, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		return "", false, fmt.Errorf("base64 decode failed for %s/%s: %w", owner, repo, err)
	}

	// Successfully fetched without auth = public repo.
	isPublic := s.token == ""

	return string(decoded), isPublic, nil
}

// splitOwnerRepo extracts owner and repo from a target string.
// Accepts formats:
//   - "owner/repo"
//   - "https://github.com/owner/repo"
//   - "github.com/owner/repo"
func splitOwnerRepo(target string) (owner, repo string, ok bool) {
	target = strings.TrimPrefix(target, "https://github.com/")
	target = strings.TrimPrefix(target, "http://github.com/")
	target = strings.TrimPrefix(target, "github.com/")

	parts := strings.SplitN(target, "/", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	repo = strings.TrimSuffix(parts[1], "/")
	repo = strings.TrimSuffix(repo, ".git")
	return url.PathEscape(parts[0]), url.PathEscape(repo), true
}
