// Package teamcity probes self-hosted TeamCity instances for security misconfigurations.
//
// All checks probe the TeamCity REST API via the /guestAuth/ prefix (guest access)
// and /app/rest/ (authenticated endpoints exposed without auth). Deep mode only.
package teamcity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const scannerName = "teamcity"

// Scanner probes a TeamCity instance for misconfigurations.
type Scanner struct {
	httpClient *http.Client
}

// New creates a TeamCity scanner.
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

// Run probes the target TeamCity instance for security misconfigurations.
// target is a URL (e.g., "https://teamcity.example.com").
func (s *Scanner) Run(ctx context.Context, target string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanDeep && scanType != module.ScanAuthorized {
		return nil, nil
	}

	target = strings.TrimRight(target, "/")
	var all []finding.Finding

	checks := []struct {
		fn func(ctx context.Context, target string) []finding.Finding
	}{
		{s.checkGuestAccess},
		{s.checkAgentDetailsExposed},
		{s.checkBuildConfigsExposed},
		{s.checkUserListExposed},
		{s.checkProjectListExposed},
		{s.checkOutdatedVersion},
		{s.checkDebugEndpoint},
	}

	for _, c := range checks {
		if ctx.Err() != nil {
			return all, ctx.Err()
		}
		all = append(all, c.fn(ctx, target)...)
	}
	return all, nil
}

func (s *Scanner) getJSON(ctx context.Context, url string) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner/1.0)")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
	resp.Body.Close()
	return resp, body, nil
}

func (s *Scanner) checkGuestAccess(ctx context.Context, target string) []finding.Finding {
	url := target + "/guestAuth/app/rest/server"
	resp, body, err := s.getJSON(ctx, url)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	var serverInfo map[string]any
	if err := json.Unmarshal(body, &serverInfo); err != nil {
		return nil
	}
	if _, ok := serverInfo["version"]; !ok {
		return nil
	}
	version, _ := serverInfo["version"].(string)
	return []finding.Finding{{
		CheckID:  finding.CheckTeamCityGuestAccess,
		Module:   "cicd",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Asset:    target,
		Title:    "TeamCity guest user access enabled — full REST API accessible",
		Description: "TeamCity guest login is enabled, allowing unauthenticated access to the REST API " +
			"including server info, build configurations, agents, and potentially build artifacts. " +
			"Disable guest access in Administration → Authentication → Allow login as guest user.",
		Evidence:     map[string]any{"url": url, "version": version},
		ProofCommand: fmt.Sprintf("curl -s -H 'Accept: application/json' '%s' | head -c 200", url),
		DiscoveredAt: time.Now(),
	}}
}

func (s *Scanner) checkAgentDetailsExposed(ctx context.Context, target string) []finding.Finding {
	url := target + "/guestAuth/app/rest/agents"
	resp, body, err := s.getJSON(ctx, url)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	if !strings.Contains(string(body), "agent") {
		return nil
	}
	return []finding.Finding{{
		CheckID:  finding.CheckTeamCityAgentDetailsExposed,
		Module:   "cicd",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Asset:    target,
		Title:    "TeamCity build agent details accessible via guest access",
		Description: "Build agent information is accessible without authentication via the guest " +
			"REST API. Agent details reveal hostnames, OS versions, IP addresses, and installed " +
			"build tools — valuable for lateral movement planning.",
		Evidence:     map[string]any{"url": url},
		ProofCommand: fmt.Sprintf("curl -s -H 'Accept: application/json' '%s' | head -c 300", url),
		DiscoveredAt: time.Now(),
	}}
}

func (s *Scanner) checkBuildConfigsExposed(ctx context.Context, target string) []finding.Finding {
	url := target + "/guestAuth/app/rest/buildTypes"
	resp, body, err := s.getJSON(ctx, url)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	if !strings.Contains(string(body), "buildType") {
		return nil
	}
	return []finding.Finding{{
		CheckID:  finding.CheckTeamCityBuildConfigsExposed,
		Module:   "cicd",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Asset:    target,
		Title:    "TeamCity build configurations accessible via guest access",
		Description: "Build configurations are accessible without authentication. These reveal " +
			"repository URLs, build steps, deployment targets, and environment variable names. " +
			"An attacker can map the entire CI/CD pipeline from this data.",
		Evidence:     map[string]any{"url": url},
		ProofCommand: fmt.Sprintf("curl -s -H 'Accept: application/json' '%s' | head -c 300", url),
		DiscoveredAt: time.Now(),
	}}
}

func (s *Scanner) checkUserListExposed(ctx context.Context, target string) []finding.Finding {
	url := target + "/guestAuth/app/rest/users"
	resp, body, err := s.getJSON(ctx, url)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	if !strings.Contains(string(body), "user") {
		return nil
	}
	return []finding.Finding{{
		CheckID:  finding.CheckTeamCityUserListExposed,
		Module:   "cicd",
		Scanner:  scannerName,
		Severity: finding.SeverityMedium,
		Asset:    target,
		Title:    "TeamCity user list accessible via guest access",
		Description: "The user list is accessible without authentication. User names and IDs can " +
			"be used for credential stuffing, phishing, or social engineering attacks.",
		Evidence:     map[string]any{"url": url},
		ProofCommand: fmt.Sprintf("curl -s -H 'Accept: application/json' '%s' | head -c 300", url),
		DiscoveredAt: time.Now(),
	}}
}

func (s *Scanner) checkProjectListExposed(ctx context.Context, target string) []finding.Finding {
	url := target + "/guestAuth/app/rest/projects"
	resp, body, err := s.getJSON(ctx, url)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	if !strings.Contains(string(body), "project") {
		return nil
	}
	return []finding.Finding{{
		CheckID:  finding.CheckTeamCityProjectListExposed,
		Module:   "cicd",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Asset:    target,
		Title:    "TeamCity project list accessible via guest access",
		Description: "Projects and their configurations are accessible without authentication. " +
			"Project names, VCS roots, and build chains reveal internal infrastructure, " +
			"repository locations, and deployment topology.",
		Evidence:     map[string]any{"url": url},
		ProofCommand: fmt.Sprintf("curl -s -H 'Accept: application/json' '%s' | head -c 300", url),
		DiscoveredAt: time.Now(),
	}}
}

func (s *Scanner) checkOutdatedVersion(ctx context.Context, target string) []finding.Finding {
	// Try guest API first, then login page.
	var version string
	url := target + "/guestAuth/app/rest/server"
	resp, body, err := s.getJSON(ctx, url)
	if err == nil && resp.StatusCode == 200 {
		var info map[string]any
		if json.Unmarshal(body, &info) == nil {
			version, _ = info["version"].(string)
		}
	}
	if version == "" {
		return nil
	}
	// TeamCity 2024.x is current. Flag anything < 2023.
	parts := strings.SplitN(version, ".", 2)
	if len(parts) < 1 {
		return nil
	}
	var year int
	fmt.Sscanf(parts[0], "%d", &year)
	if year >= 2024 {
		return nil
	}
	return []finding.Finding{{
		CheckID:  finding.CheckTeamCityOutdatedVersion,
		Module:   "cicd",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Asset:    target,
		Title:    fmt.Sprintf("TeamCity %s is outdated and likely contains known vulnerabilities", version),
		Description: fmt.Sprintf(
			"TeamCity %s is running on this instance. Check JetBrains security advisories "+
				"for applicable CVEs (including CVE-2024-27198/CVE-2024-27199 auth bypass). "+
				"Upgrade to the latest stable release.", version),
		Evidence:     map[string]any{"version": version},
		ProofCommand: fmt.Sprintf("curl -s -H 'Accept: application/json' '%s' | jq .version", url),
		DiscoveredAt: time.Now(),
	}}
}

func (s *Scanner) checkDebugEndpoint(ctx context.Context, target string) []finding.Finding {
	url := target + "/app/rest/debug/jvm/systemProperties"
	resp, body, err := s.getJSON(ctx, url)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	if len(body) < 50 {
		return nil
	}
	return []finding.Finding{{
		CheckID:  finding.CheckTeamCityDebugEndpoint,
		Module:   "cicd",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Asset:    target,
		Title:    "TeamCity JVM debug endpoint exposed — system properties accessible",
		Description: "The JVM system properties debug endpoint is accessible without proper " +
			"authentication. System properties may contain database credentials, API keys, " +
			"LDAP passwords, and other secrets passed via -D flags or environment variables.",
		Evidence:     map[string]any{"url": url, "body_length": len(body)},
		ProofCommand: fmt.Sprintf("curl -s -H 'Accept: application/json' '%s' | head -c 500", url),
		DiscoveredAt: time.Now(),
	}}
}
