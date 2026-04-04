// Package gitlab probes self-hosted GitLab instances for security misconfigurations.
//
// All checks use HTTP probing against well-known GitLab endpoints. Deep mode
// only — every probe is an active request logged by the target.
package gitlab

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)

// Regex patterns for .gitlab-ci.yml analysis.
var (
	// Matches image directives without a digest pin (no @sha256:).
	reUnpinnedImage = regexp.MustCompile(`(?m)^\s*image:\s*["']?([^@\s"']+)["']?\s*$`)
	// Matches secret-like CI variables referenced in script blocks.
	reSecretInScript = regexp.MustCompile(`(?m)\$\{?(CI_JOB_TOKEN|SECRET_\w+|PRIVATE_TOKEN|DEPLOY_TOKEN|API_KEY\w*|AWS_SECRET_ACCESS_KEY|PASSWORD\w*)\}?`)
	// Matches privileged Docker-in-Docker configuration.
	rePrivilegedDind = regexp.MustCompile(`(?m)^\s*-?\s*["']?docker:.*dind["']?\s*$`)
	rePrivilegedFlag = regexp.MustCompile(`(?mi)privileged\s*:\s*["']?true["']?`)
)

const scannerName = "gitlab"

// Scanner probes a GitLab instance for misconfigurations.
type Scanner struct {
	httpClient *http.Client
}

// New creates a GitLab scanner with sensible defaults.
func New() *Scanner {
	return &Scanner{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (s *Scanner) Name() string { return scannerName }

// Run probes the target GitLab instance for security misconfigurations.
// target is a URL (e.g., "https://gitlab.example.com").
func (s *Scanner) Run(ctx context.Context, target string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanDeep && scanType != module.ScanAuthorized {
		return nil, nil
	}

	target = strings.TrimRight(target, "/")
	var all []finding.Finding

	checks := []struct {
		fn func(ctx context.Context, target string) []finding.Finding
	}{
		{s.checkPublicRegistration},
		{s.checkPublicSnippets},
		{s.checkPublicProjects},
		{s.checkCILintExposed},
		{s.checkGraphQLIntrospection},
		{s.checkOutdatedVersion},
		{s.checkHealthExposed},
		{s.checkPrometheusExposed},
		{s.checkAPIUnauth},
		{s.checkCIConfig},
	}

	for _, c := range checks {
		if ctx.Err() != nil {
			return all, ctx.Err()
		}
		all = append(all, c.fn(ctx, target)...)
	}
	return all, nil
}

func (s *Scanner) get(ctx context.Context, url string) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner/1.0)")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
	_ = resp.Body.Close()
	return resp, body, nil
}

func (s *Scanner) postJSON(ctx context.Context, url string, payload string) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(payload))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner/1.0)")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
	_ = resp.Body.Close()
	return resp, body, nil
}

func (s *Scanner) checkPublicRegistration(ctx context.Context, target string) []finding.Finding {
	url := target + "/users/sign_up"
	resp, body, err := s.get(ctx, url)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	lower := strings.ToLower(string(body))
	if !strings.Contains(lower, "sign up") && !strings.Contains(lower, "register") {
		return nil
	}
	return []finding.Finding{{
		CheckID:  finding.CheckGitLabPublicRegistration,
		Module:   "cicd",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Asset:    target,
		Title:    "GitLab public user registration enabled",
		Description: "Self-registration is enabled on this GitLab instance. Any internet user can " +
			"create an account, potentially gaining access to internal projects, CI/CD pipelines, " +
			"and runners. Disable public registration in Admin → Settings → General → Sign-up restrictions.",
		Evidence:     map[string]any{"url": url, "status": resp.StatusCode},
		ProofCommand: fmt.Sprintf("curl -s -o /dev/null -w '%%{http_code}' '%s'", url),
		DiscoveredAt: time.Now(),
	}}
}

func (s *Scanner) checkPublicSnippets(ctx context.Context, target string) []finding.Finding {
	url := target + "/explore/snippets"
	resp, body, err := s.get(ctx, url)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	if !strings.Contains(strings.ToLower(string(body)), "snippet") {
		return nil
	}
	return []finding.Finding{{
		CheckID:  finding.CheckGitLabPublicSnippets,
		Module:   "cicd",
		Scanner:  scannerName,
		Severity: finding.SeverityMedium,
		Asset:    target,
		Title:    "GitLab public snippets accessible without authentication",
		Description: "Public snippet listing is accessible without authentication. Snippets may " +
			"contain secrets, internal documentation, or code samples. Restrict snippet visibility " +
			"in Admin → Settings → General → Visibility and access controls.",
		Evidence:     map[string]any{"url": url},
		ProofCommand: fmt.Sprintf("curl -s -o /dev/null -w '%%{http_code}' '%s'", url),
		DiscoveredAt: time.Now(),
	}}
}

func (s *Scanner) checkPublicProjects(ctx context.Context, target string) []finding.Finding {
	url := target + "/explore/projects"
	resp, body, err := s.get(ctx, url)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	if !strings.Contains(strings.ToLower(string(body)), "project") {
		return nil
	}
	return []finding.Finding{{
		CheckID:  finding.CheckGitLabPublicProjects,
		Module:   "cicd",
		Scanner:  scannerName,
		Severity: finding.SeverityMedium,
		Asset:    target,
		Title:    "GitLab public project listing accessible without authentication",
		Description: "The project explorer is accessible without authentication, exposing project names, " +
			"descriptions, and potentially source code. Restrict project visibility in Admin → Settings " +
			"→ General → Visibility and access controls.",
		Evidence:     map[string]any{"url": url},
		ProofCommand: fmt.Sprintf("curl -s -o /dev/null -w '%%{http_code}' '%s'", url),
		DiscoveredAt: time.Now(),
	}}
}

func (s *Scanner) checkCILintExposed(ctx context.Context, target string) []finding.Finding {
	url := target + "/api/v4/ci/lint"
	resp, _, err := s.get(ctx, url)
	if err != nil {
		return nil
	}
	// 401/403 means auth is required (good). 200 or 422 means accessible.
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return nil
	}
	if resp.StatusCode != 200 && resp.StatusCode != 422 {
		return nil
	}
	return []finding.Finding{{
		CheckID:  finding.CheckGitLabCILintExposed,
		Module:   "cicd",
		Scanner:  scannerName,
		Severity: finding.SeverityMedium,
		Asset:    target,
		Title:    "GitLab CI lint API accessible without authentication",
		Description: "The CI/CD lint API endpoint is accessible without authentication. Attackers can " +
			"validate CI/CD configurations to understand the pipeline structure, discover available " +
			"runners, and identify secrets referenced in variables. Require authentication for API access.",
		Evidence:     map[string]any{"url": url, "status": resp.StatusCode},
		ProofCommand: fmt.Sprintf("curl -s -o /dev/null -w '%%{http_code}' '%s'", url),
		DiscoveredAt: time.Now(),
	}}
}

func (s *Scanner) checkGraphQLIntrospection(ctx context.Context, target string) []finding.Finding {
	url := target + "/api/graphql"
	resp, body, err := s.postJSON(ctx, url, `{"query":"{ __schema { types { name } } }"}`)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	if !strings.Contains(string(body), "__schema") {
		return nil
	}
	return []finding.Finding{{
		CheckID:  finding.CheckGitLabGraphQLIntrospection,
		Module:   "cicd",
		Scanner:  scannerName,
		Severity: finding.SeverityMedium,
		Asset:    target,
		Title:    "GitLab GraphQL introspection enabled without authentication",
		Description: "GraphQL introspection is enabled and accessible without authentication. " +
			"Attackers can enumerate the entire API schema, discovering internal queries, mutations, " +
			"and data types. Disable introspection in production or require authentication.",
		Evidence:     map[string]any{"url": url},
		ProofCommand: fmt.Sprintf("curl -s -X POST '%s' -H 'Content-Type: application/json' -d '{\"query\":\"{ __schema { types { name } } }\"}' | head -c 200", url),
		DiscoveredAt: time.Now(),
	}}
}

func (s *Scanner) checkOutdatedVersion(ctx context.Context, target string) []finding.Finding {
	// Try API endpoint first.
	url := target + "/api/v4/version"
	resp, body, err := s.get(ctx, url)
	if err != nil {
		return nil
	}
	var verInfo struct {
		Version string `json:"version"`
	}
	if resp.StatusCode == 200 {
		_ = json.Unmarshal(body, &verInfo)
	}
	if verInfo.Version == "" {
		return nil
	}
	// Check for critically outdated versions (major version < 16 is EOL).
	parts := strings.SplitN(verInfo.Version, ".", 2)
	if len(parts) < 1 {
		return nil
	}
	var major int
	_, _ = fmt.Sscanf(parts[0], "%d", &major)
	if major >= 17 {
		return nil // reasonably current
	}
	return []finding.Finding{{
		CheckID:  finding.CheckGitLabOutdatedVersion,
		Module:   "cicd",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Asset:    target,
		Title:    fmt.Sprintf("GitLab %s is outdated and likely contains known vulnerabilities", verInfo.Version),
		Description: fmt.Sprintf(
			"GitLab %s is running on this instance. Versions below the current stable release "+
				"are likely missing critical security patches. Check GitLab's release blog for "+
				"applicable CVEs and upgrade to the latest stable release.", verInfo.Version),
		Evidence:     map[string]any{"version": verInfo.Version, "url": url},
		ProofCommand: fmt.Sprintf("curl -s '%s' | jq .version", url),
		DiscoveredAt: time.Now(),
	}}
}

func (s *Scanner) checkHealthExposed(ctx context.Context, target string) []finding.Finding {
	for _, path := range []string{"/-/health", "/-/readiness", "/-/liveness"} {
		url := target + path
		resp, _, err := s.get(ctx, url)
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		return []finding.Finding{{
			CheckID:  finding.CheckGitLabHealthExposed,
			Module:   "cicd",
			Scanner:  scannerName,
			Severity: finding.SeverityLow,
			Asset:    target,
			Title:    "GitLab health check endpoints exposed",
			Description: "Health/readiness/liveness endpoints are accessible without authentication. " +
				"While typically low risk, these can reveal operational state and may assist " +
				"in timing attacks or confirming the application stack.",
			Evidence:     map[string]any{"url": url, "status": resp.StatusCode},
			ProofCommand: fmt.Sprintf("curl -s '%s'", url),
			DiscoveredAt: time.Now(),
		}}
	}
	return nil
}

func (s *Scanner) checkPrometheusExposed(ctx context.Context, target string) []finding.Finding {
	url := target + "/-/metrics"
	resp, body, err := s.get(ctx, url)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	if !strings.Contains(string(body), "# HELP") && !strings.Contains(string(body), "# TYPE") {
		return nil
	}
	return []finding.Finding{{
		CheckID:  finding.CheckGitLabPrometheusExposed,
		Module:   "cicd",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Asset:    target,
		Title:    "GitLab Prometheus metrics endpoint exposed without authentication",
		Description: "The /-/metrics endpoint exposes Prometheus metrics without authentication. " +
			"Metrics can reveal user counts, request rates, job queue depth, database latency, " +
			"and other operational details useful for reconnaissance. Restrict access in " +
			"Admin → Settings → Metrics and profiling → Metrics - Prometheus.",
		Evidence:     map[string]any{"url": url},
		ProofCommand: fmt.Sprintf("curl -s '%s' | head -20", url),
		DiscoveredAt: time.Now(),
	}}
}

func (s *Scanner) checkAPIUnauth(ctx context.Context, target string) []finding.Finding {
	url := target + "/api/v4/projects?per_page=1"
	resp, body, err := s.get(ctx, url)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	// Verify it's actually returning project data.
	var projects []json.RawMessage
	if err := json.Unmarshal(body, &projects); err != nil || len(projects) == 0 {
		return nil
	}
	return []finding.Finding{{
		CheckID:  finding.CheckGitLabAPIUnauth,
		Module:   "cicd",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Asset:    target,
		Title:    "GitLab API v4 accessible without authentication",
		Description: "The GitLab REST API returns project data without authentication. Attackers can " +
			"enumerate projects, users, groups, and CI/CD configurations. Require authentication " +
			"for all API access in Admin → Settings → General → Visibility and access controls.",
		Evidence:     map[string]any{"url": url, "project_count_sample": len(projects)},
		ProofCommand: fmt.Sprintf("curl -s '%s' | jq '.[].path_with_namespace'", url),
		DiscoveredAt: time.Now(),
	}}
}

// checkCIConfig fetches .gitlab-ci.yml from accessible public projects and
// analyzes them for common CI/CD security issues: unpinned images, secrets in
// scripts, and privileged Docker-in-Docker runners.
func (s *Scanner) checkCIConfig(ctx context.Context, target string) []finding.Finding {
	// First, enumerate public projects to find .gitlab-ci.yml files.
	projectsURL := target + "/api/v4/projects?visibility=public&per_page=20&simple=true"
	resp, body, err := s.get(ctx, projectsURL)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}

	var projects []struct {
		ID                int    `json:"id"`
		PathWithNamespace string `json:"path_with_namespace"`
		DefaultBranch     string `json:"default_branch"`
	}
	if err := json.Unmarshal(body, &projects); err != nil || len(projects) == 0 {
		return nil
	}

	var findings []finding.Finding
	for _, proj := range projects {
		if ctx.Err() != nil {
			break
		}
		if proj.DefaultBranch == "" {
			proj.DefaultBranch = "main"
		}

		// Fetch .gitlab-ci.yml from the repository files API.
		ciURL := fmt.Sprintf("%s/api/v4/projects/%d/repository/files/.gitlab-ci.yml/raw?ref=%s",
			target, proj.ID, proj.DefaultBranch)
		ciResp, ciBody, ciErr := s.get(ctx, ciURL)
		if ciErr != nil || ciResp.StatusCode != 200 {
			continue
		}

		ciContent := string(ciBody)
		findings = append(findings, s.analyzeCIYAML(target, proj.PathWithNamespace, ciContent)...)
	}

	return findings
}

// analyzeCIYAML checks a .gitlab-ci.yml content string for security issues.
func (s *Scanner) analyzeCIYAML(target, projectPath, content string) []finding.Finding {
	var findings []finding.Finding

	// Check for unpinned Docker images.
	// Images without a @sha256: digest can be silently replaced upstream.
	matches := reUnpinnedImage.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		image := match[1]
		// Skip if it contains a digest pin.
		if strings.Contains(image, "@sha256:") {
			continue
		}
		// Skip variable references — can't evaluate those statically.
		if strings.Contains(image, "$") {
			continue
		}
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckGitLabCIUnpinnedImage,
			Module:   "cicd",
			Scanner:  scannerName,
			Severity: finding.SeverityMedium,
			Asset:    target,
			Title:    fmt.Sprintf("GitLab CI uses unpinned Docker image in %s: %s", projectPath, image),
			Description: fmt.Sprintf(
				"Project %s uses Docker image '%s' in .gitlab-ci.yml without a digest pin (@sha256:). "+
					"An attacker who compromises the image registry or gains push access to the tag "+
					"can inject malicious code into every CI pipeline run. Pin images by digest.",
				projectPath, image,
			),
			Evidence: map[string]any{
				"project": projectPath,
				"image":   image,
			},
			ProofCommand: fmt.Sprintf("curl -s '%s/api/v4/projects/%s/repository/files/.gitlab-ci.yml/raw?ref=main' | grep -i 'image:'",
				target, strings.ReplaceAll(projectPath, "/", "%%2F")),
			DiscoveredAt: time.Now(),
		})
	}

	// Check for secret variables referenced directly in script blocks.
	secretMatches := reSecretInScript.FindAllStringSubmatch(content, -1)
	seen := make(map[string]bool)
	for _, match := range secretMatches {
		if len(match) < 2 {
			continue
		}
		varName := match[1]
		if seen[varName] {
			continue
		}
		seen[varName] = true
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckGitLabCISecretInScript,
			Module:   "cicd",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Asset:    target,
			Title:    fmt.Sprintf("GitLab CI references secret variable in script: %s ($%s)", projectPath, varName),
			Description: fmt.Sprintf(
				"Project %s references secret variable $%s directly in a .gitlab-ci.yml script block. "+
					"CI job logs may capture expanded variable values. If the project is public or logs "+
					"are accessible, secrets can be leaked. Use CI/CD file variables or masked variables "+
					"and avoid echoing them in script blocks.",
				projectPath, varName,
			),
			Evidence: map[string]any{
				"project":  projectPath,
				"variable": varName,
			},
			ProofCommand: fmt.Sprintf("curl -s '%s/api/v4/projects/%s/repository/files/.gitlab-ci.yml/raw?ref=main' | grep -i '%s'",
				target, strings.ReplaceAll(projectPath, "/", "%%2F"), varName),
			DiscoveredAt: time.Now(),
		})
	}

	// Check for privileged Docker-in-Docker.
	// DinD services with privileged: true give the CI job full host access.
	hasDind := rePrivilegedDind.MatchString(content)
	hasPrivileged := rePrivilegedFlag.MatchString(content)
	if hasDind && hasPrivileged {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckGitLabCIPrivilegedRunner,
			Module:   "cicd",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Asset:    target,
			Title:    fmt.Sprintf("GitLab CI uses privileged Docker-in-Docker in %s", projectPath),
			Description: fmt.Sprintf(
				"Project %s uses Docker-in-Docker (docker:dind) with privileged: true in "+
					".gitlab-ci.yml. Privileged containers have full access to the host kernel, "+
					"allowing container escape and host compromise. Use Kaniko, Buildah, or "+
					"unprivileged build tools instead of privileged DinD.",
				projectPath,
			),
			Evidence: map[string]any{
				"project": projectPath,
			},
			ProofCommand: fmt.Sprintf("curl -s '%s/api/v4/projects/%s/repository/files/.gitlab-ci.yml/raw?ref=main' | grep -E '(dind|privileged)'",
				target, strings.ReplaceAll(projectPath, "/", "%%2F")),
			DiscoveredAt: time.Now(),
		})
	}

	return findings
}
