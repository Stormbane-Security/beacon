// Package bitbucket scans Bitbucket Pipelines configuration files for common security
// misconfigurations.
//
// It uses the Bitbucket REST API to fetch bitbucket-pipelines.yml for a given
// workspace/repo target, then applies a set of static analysis rules to the pipeline
// definition. All rules are implemented as string-pattern and regex checks — no full
// YAML AST traversal.
package bitbucket

import (
	"context"
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
	scan.RegisterWithCheckDecls(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	},
		scan.Check(finding.CheckBitbucketPipelineInsecureStep, finding.SeverityHigh, finding.ModeSurface),
		scan.Check(finding.CheckBitbucketPipelineSecretEchoed, finding.SeverityHigh, finding.ModeSurface),
		scan.Check(finding.CheckBitbucketPipelineUnpinned, finding.SeverityMedium, finding.ModeSurface),
		scan.Check(finding.CheckBitbucketPublicPipeline, finding.SeverityMedium, finding.ModeSurface),
	)
}
const scannerName = "bitbucket"

// Scanner fetches and analyses Bitbucket Pipelines configuration for a repo.
type Scanner struct {
	httpClient *http.Client
}

// New creates a Scanner.
func New() *Scanner {
	return &Scanner{
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
}

// Name returns the stable scanner identifier.
func (s *Scanner) Name() string { return scannerName }

// Run analyses the Bitbucket Pipelines configuration for the given target.
// target must be "workspace/repo" (e.g. "myteam/myrepo") or a full Bitbucket URL.
func (s *Scanner) Run(ctx context.Context, target string, scanType module.ScanType) ([]finding.Finding, error) {
	workspace, repo, ok := splitWorkspaceRepo(target)
	if !ok {
		return nil, fmt.Errorf("bitbucket: invalid target %q — expected workspace/repo or bitbucket.org URL", target)
	}

	// Fetch the pipeline configuration file.
	content, isPublic, err := s.fetchPipelineConfig(ctx, workspace, repo)
	if err != nil {
		return nil, fmt.Errorf("bitbucket: fetching pipeline config for %s/%s: %w", workspace, repo, err)
	}

	repoSlug := workspace + "/" + repo
	var all []finding.Finding

	// If the pipeline config is fetchable without auth, the repo is public.
	if isPublic {
		all = append(all, checkPublicPipeline(content, repoSlug)...)
	}

	all = append(all, checkUnpinnedImages(content, repoSlug)...)
	all = append(all, checkSecretEchoed(content, repoSlug)...)
	all = append(all, checkInsecureSteps(content, repoSlug)...)

	return all, nil
}

// -------------------------------------------------------------------------
// Analysis rules
// -------------------------------------------------------------------------

// reImageLine matches "image:" directives in the pipeline YAML, including
// nested image definitions like "image: name: ...". It captures everything
// after "image:" on the same line.
var reImageLine = regexp.MustCompile(`(?m)^\s*image:\s*(.+)$`)

// reImageNameLine matches "name:" inside an image block for multi-line image definitions.
var reImageNameLine = regexp.MustCompile(`(?m)^\s*name:\s*(.+)$`)

// reSHA256Digest matches an @sha256: digest suffix on a Docker image reference.
var reSHA256Digest = regexp.MustCompile(`@sha256:[0-9a-f]{64}`)

// checkUnpinnedImages flags Docker images in pipeline steps that are not pinned
// by SHA256 digest. Mutable tags (e.g. "latest", "node:18") can be overwritten
// in a supply-chain attack.
func checkUnpinnedImages(pipelineYAML, repo string) []finding.Finding {
	var findings []finding.Finding
	seen := make(map[string]struct{})

	// Check direct "image: <ref>" lines.
	for _, m := range reImageLine.FindAllStringSubmatch(pipelineYAML, -1) {
		imageRef := strings.TrimSpace(m[1])

		// Skip multi-line image blocks (image:\n  name: ...) — we handle
		// those separately via reImageNameLine.
		if imageRef == "" || imageRef == "|" || imageRef == ">" {
			continue
		}

		// If the value starts with "name:" it's an inline map, extract the image name.
		if strings.HasPrefix(imageRef, "name:") {
			imageRef = strings.TrimSpace(strings.TrimPrefix(imageRef, "name:"))
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
			CheckID:  finding.CheckBitbucketPipelineUnpinned,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityMedium,
			Asset:    repo,
			Title:    fmt.Sprintf("Unpinned Docker image in pipeline: %s", imageRef),
			Description: fmt.Sprintf(
				"The pipeline references Docker image %q using a mutable tag rather than an immutable "+
					"sha256 digest. If the upstream image is compromised or the tag is moved, "+
					"the pipeline will silently execute attacker-controlled code. Pin to a digest instead: "+
					`image: %s@sha256:<digest>`, imageRef, imageBase(imageRef),
			),
			Evidence:     map[string]any{"image": imageRef},
			ProofCommand: fmt.Sprintf("curl -s 'https://api.bitbucket.org/2.0/repositories/%s/src/HEAD/bitbucket-pipelines.yml'", repo),
			DiscoveredAt: time.Now(),
		})
	}

	// Also check "name:" lines inside image blocks.
	for _, m := range reImageNameLine.FindAllStringSubmatch(pipelineYAML, -1) {
		imageRef := strings.TrimSpace(m[1])
		imageRef = strings.Trim(imageRef, `"'`)

		if imageRef == "" {
			continue
		}

		if reSHA256Digest.MatchString(imageRef) {
			continue
		}

		if _, ok := seen[imageRef]; ok {
			continue
		}
		seen[imageRef] = struct{}{}

		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckBitbucketPipelineUnpinned,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityMedium,
			Asset:    repo,
			Title:    fmt.Sprintf("Unpinned Docker image in pipeline: %s", imageRef),
			Description: fmt.Sprintf(
				"The pipeline references Docker image %q using a mutable tag rather than an immutable "+
					"sha256 digest. If the upstream image is compromised or the tag is moved, "+
					"the pipeline will silently execute attacker-controlled code. Pin to a digest instead: "+
					`image: %s@sha256:<digest>`, imageRef, imageBase(imageRef),
			),
			Evidence:     map[string]any{"image": imageRef},
			ProofCommand: fmt.Sprintf("curl -s 'https://api.bitbucket.org/2.0/repositories/%s/src/HEAD/bitbucket-pipelines.yml'", repo),
			DiscoveredAt: time.Now(),
		})
	}

	return findings
}

// imageBase returns the image name without the tag (everything before ":tag").
func imageBase(ref string) string {
	// If it contains @sha256:, strip that.
	if idx := strings.Index(ref, "@"); idx >= 0 {
		return ref[:idx]
	}
	// Strip :tag suffix, but be careful not to strip port numbers (e.g. registry:5000/image).
	// Only strip if the part after the last colon looks like a tag (no slashes).
	if idx := strings.LastIndex(ref, ":"); idx >= 0 {
		after := ref[idx+1:]
		if !strings.Contains(after, "/") {
			return ref[:idx]
		}
	}
	return ref
}

// reEchoSecret matches commands that echo or print environment variables that are
// likely secrets. Bitbucket Pipelines uses $VARIABLE syntax for secured variables.
// This catches patterns like:
//   - echo $SECRET_VAR
//   - echo "$MY_TOKEN"
//   - printf '%s' $API_KEY
//   - echo ${BITBUCKET_SECURE_VAR}
var reEchoSecret = regexp.MustCompile(
	`(?im)(echo|printf|print|cat)\s+[^#\n]*\$\{?\s*(` +
		`[A-Z_]*(?:SECRET|TOKEN|PASSWORD|KEY|CREDENTIAL|AUTH|PRIVATE|API_KEY|AWS_SECRET|DOCKER_PASSWORD)[A-Z_]*` +
		`)\s*\}?`,
)

// checkSecretEchoed flags pipeline scripts that appear to echo or print
// secret/secured variable values. Bitbucket masks secured variables in logs,
// but this masking can be circumvented (e.g., base64 encoding, character splitting).
func checkSecretEchoed(pipelineYAML, repo string) []finding.Finding {
	var findings []finding.Finding
	seen := make(map[string]struct{})

	for _, m := range reEchoSecret.FindAllStringSubmatch(pipelineYAML, -1) {
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
			CheckID:  finding.CheckBitbucketPipelineSecretEchoed,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityCritical,
			Asset:    repo,
			Title:    fmt.Sprintf("Secret variable may be printed in pipeline logs: $%s", varName),
			Description: fmt.Sprintf(
				"A pipeline script appears to %s the variable $%s which looks like a secret or credential. "+
					"Even though Bitbucket masks secured variables in logs, masking can be circumvented "+
					"by encoding, splitting, or writing to artifacts. Never echo secrets directly in "+
					"pipeline scripts.",
				cmd, varName,
			),
			Evidence:     map[string]any{"command": cmd, "variable": varName},
			ProofCommand: fmt.Sprintf("curl -s 'https://api.bitbucket.org/2.0/repositories/%s/src/HEAD/bitbucket-pipelines.yml' | grep -i 'echo.*%s'", repo, varName),
			DiscoveredAt: time.Now(),
		})
	}

	return findings
}

// reAfterScript matches "after-script:" blocks in Bitbucket Pipelines.
// After-scripts always run (even on failure) and have access to all
// environment variables including secrets — a common exfiltration vector.
var reAfterScript = regexp.MustCompile(`(?m)^\s*after-script:`)

// reMaxTimeZero matches "max-time: 0" in step definitions, which removes the
// execution timeout — a step could run indefinitely.
var reMaxTimeZero = regexp.MustCompile(`(?m)^\s*max-time:\s*0\s*$`)

// reDockerService matches Docker-in-Docker service definitions in Bitbucket Pipelines.
// Running Docker daemon inside a pipeline step with no restrictions is dangerous.
var reDockerService = regexp.MustCompile(`(?m)^\s*-\s*docker`)

// reServicesBlock detects the presence of a services: block.
var reServicesBlock = regexp.MustCompile(`(?m)^\s*services:`)

// reRunAsUser detects "run-as-user: 0" (running as root).
var reRunAsUser = regexp.MustCompile(`(?m)^\s*run-as-user:\s*0\s*$`)

// checkInsecureSteps flags pipeline steps with dangerous configurations:
// - after-script blocks that could leak secrets on failure
// - max-time: 0 removing execution timeout
// - Docker-in-Docker services (privileged container access)
// - run-as-user: 0 (running as root)
func checkInsecureSteps(pipelineYAML, repo string) []finding.Finding {
	var findings []finding.Finding

	if reAfterScript.MatchString(pipelineYAML) {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckBitbucketPipelineInsecureStep,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityMedium,
			Asset:    repo,
			Title:    "Pipeline uses after-script block (runs even on failure)",
			Description: "The pipeline defines an after-script block which executes regardless of whether " +
				"the main script succeeds or fails. After-scripts have access to all environment variables " +
				"including secrets. If the after-script sends data to external services (e.g., Slack webhooks, " +
				"HTTP endpoints), it could exfiltrate secrets on a compromised build. Review after-script " +
				"blocks to ensure they do not reference or transmit secret variables.",
			Evidence:     map[string]any{"pattern": "after-script"},
			ProofCommand: fmt.Sprintf("curl -s 'https://api.bitbucket.org/2.0/repositories/%s/src/HEAD/bitbucket-pipelines.yml' | grep -A5 'after-script'", repo),
			DiscoveredAt: time.Now(),
		})
	}

	if reMaxTimeZero.MatchString(pipelineYAML) {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckBitbucketPipelineInsecureStep,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityLow,
			Asset:    repo,
			Title:    "Pipeline step has no execution timeout (max-time: 0)",
			Description: "A pipeline step sets max-time: 0, which removes the execution timeout entirely. " +
				"A compromised or malfunctioning step could run indefinitely, consuming pipeline minutes " +
				"and potentially maintaining persistent access to the build environment. Set an appropriate " +
				"max-time value (default is 120 minutes).",
			Evidence:     map[string]any{"pattern": "max-time: 0"},
			ProofCommand: fmt.Sprintf("curl -s 'https://api.bitbucket.org/2.0/repositories/%s/src/HEAD/bitbucket-pipelines.yml' | grep 'max-time'", repo),
			DiscoveredAt: time.Now(),
		})
	}

	if reServicesBlock.MatchString(pipelineYAML) && reDockerService.MatchString(pipelineYAML) {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckBitbucketPipelineInsecureStep,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Asset:    repo,
			Title:    "Pipeline uses Docker-in-Docker service (privileged mode)",
			Description: "The pipeline defines a Docker service for Docker-in-Docker builds. This grants " +
				"the pipeline step privileged container access, which can be used to escape the container " +
				"sandbox, access the host filesystem, or interfere with other containers. Consider using " +
				"Kaniko or buildx for unprivileged image builds instead.",
			Evidence:     map[string]any{"pattern": "services: docker"},
			ProofCommand: fmt.Sprintf("curl -s 'https://api.bitbucket.org/2.0/repositories/%s/src/HEAD/bitbucket-pipelines.yml' | grep -B2 -A2 'docker'", repo),
			DiscoveredAt: time.Now(),
		})
	}

	if reRunAsUser.MatchString(pipelineYAML) {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckBitbucketPipelineInsecureStep,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityMedium,
			Asset:    repo,
			Title:    "Pipeline step runs as root (run-as-user: 0)",
			Description: "A pipeline step is configured with run-as-user: 0, executing commands as the root " +
				"user inside the container. While this does not directly break out of the container, it " +
				"increases the blast radius of any vulnerability — a compromised root process can modify " +
				"all files in the build environment and potentially exploit kernel vulnerabilities for " +
				"container escape.",
			Evidence:     map[string]any{"pattern": "run-as-user: 0"},
			ProofCommand: fmt.Sprintf("curl -s 'https://api.bitbucket.org/2.0/repositories/%s/src/HEAD/bitbucket-pipelines.yml' | grep 'run-as-user'", repo),
			DiscoveredAt: time.Now(),
		})
	}

	return findings
}

// checkPublicPipeline flags repos where the pipeline configuration is accessible
// to unauthenticated users — meaning the repo is public. Pipeline configs often
// reveal internal service names, deployment targets, and environment variable names.
func checkPublicPipeline(pipelineYAML, repo string) []finding.Finding {
	return []finding.Finding{{
		CheckID:  finding.CheckBitbucketPublicPipeline,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityInfo,
		Asset:    repo,
		Title:    "Bitbucket Pipeline configuration is publicly accessible",
		Description: "The bitbucket-pipelines.yml file is readable without authentication, confirming " +
			"the repository is public. Pipeline configurations reveal build infrastructure details " +
			"including Docker image names, deployment targets, service dependencies, and " +
			"environment variable names (though not values). Attackers use this information " +
			"to map internal infrastructure and identify supply-chain attack vectors.",
		Evidence: map[string]any{
			"file":        "bitbucket-pipelines.yml",
			"config_size": len(pipelineYAML),
		},
		ProofCommand: fmt.Sprintf("curl -sI 'https://api.bitbucket.org/2.0/repositories/%s/src/HEAD/bitbucket-pipelines.yml'", repo),
		DiscoveredAt: time.Now(),
	}}
}

// -------------------------------------------------------------------------
// API helpers
// -------------------------------------------------------------------------

// bbFileResponse represents the Bitbucket API response when fetching raw file
// fetchPipelineConfig retrieves the bitbucket-pipelines.yml from the Bitbucket
// REST API. Returns the YAML content, whether the repo appears to be public
// (fetchable without auth), and any error.
func (s *Scanner) fetchPipelineConfig(ctx context.Context, workspace, repo string) (string, bool, error) {
	apiURL := fmt.Sprintf(
		"https://api.bitbucket.org/2.0/repositories/%s/%s/src/HEAD/bitbucket-pipelines.yml",
		url.PathEscape(workspace), url.PathEscape(repo),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return "", false, err
	}
	req.Header.Set("Accept", "application/json")

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
		return "", false, fmt.Errorf("bitbucket-pipelines.yml not found for %s/%s (HTTP 404)", workspace, repo)
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		return "", false, fmt.Errorf("access denied for %s/%s (HTTP %d) — repo may be private", workspace, repo, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		// Try to extract an error message from the response.
		var errResp struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(body, &errResp) == nil && errResp.Error.Message != "" {
			return "", false, fmt.Errorf("API error for %s/%s: %s (HTTP %d)", workspace, repo, errResp.Error.Message, resp.StatusCode)
		}
		return "", false, fmt.Errorf("unexpected status %d for %s/%s", resp.StatusCode, workspace, repo)
	}

	// The Bitbucket src endpoint returns raw file content directly for text files.
	// If the response is JSON with a "type" field, it's a directory listing or error.
	content := string(body)
	if len(content) > 0 && content[0] == '{' {
		var check struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(body, &check) == nil && check.Type == "error" {
			return "", false, fmt.Errorf("API returned error object for %s/%s", workspace, repo)
		}
	}

	// Successfully fetched without auth = public repo.
	isPublic := true

	return content, isPublic, nil
}

// splitWorkspaceRepo extracts workspace and repo from a target string.
// Accepts formats:
//   - "workspace/repo"
//   - "https://bitbucket.org/workspace/repo"
//   - "bitbucket.org/workspace/repo"
func splitWorkspaceRepo(target string) (workspace, repo string, ok bool) {
	// Strip Bitbucket URL prefixes.
	target = strings.TrimPrefix(target, "https://bitbucket.org/")
	target = strings.TrimPrefix(target, "http://bitbucket.org/")
	target = strings.TrimPrefix(target, "bitbucket.org/")

	// Also handle API URLs.
	target = strings.TrimPrefix(target, "https://api.bitbucket.org/2.0/repositories/")

	parts := strings.SplitN(target, "/", 3) // split into at most 3 parts
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	// Strip trailing slashes or extra path segments from the repo name.
	repo = strings.TrimSuffix(parts[1], "/")
	// Strip .git suffix if present.
	repo = strings.TrimSuffix(repo, ".git")
	// Percent-encode both segments to prevent path traversal.
	return url.PathEscape(parts[0]), url.PathEscape(repo), true
}
