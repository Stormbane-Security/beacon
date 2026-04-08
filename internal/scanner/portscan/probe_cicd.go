package portscan

import (
	"context"
	"fmt"
	"strings"

	"github.com/stormbane-security/beacon/internal/finding"
)

func init() {
	registerProbe(ServiceProbe{
		Name:         "gitlab",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{80, 443, 8929},
		Detect:       detectGitLab,
	})
	registerProbe(ServiceProbe{
		Name:         "teamcity",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{8111},
		Detect:       detectTeamCity,
	})
	registerProbe(ServiceProbe{
		Name:         "bamboo",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{8085},
		Detect:       detectBamboo,
	})
	registerProbe(ServiceProbe{
		Name:         "nfs",
		Category:     ProbeCatProtocol,
		DefaultPorts: []int{2049},
		Detect:       detectNFS,
	})
	registerProbe(ServiceProbe{
		Name:         "hazelcast",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{5701},
		Detect:       detectHazelcast,
	})
}

// detectGitLab identifies GitLab instances via page title, body content, and API version endpoint.
func detectGitLab(ctx context.Context, host string, port int, _ string, makeF findingMaker) []finding.Finding {
	useTLS := port == 443
	body, ok := probeHTTPAnyBody(ctx, host, port, useTLS, "/")
	if !ok {
		return nil
	}
	lower := strings.ToLower(body)
	if !strings.Contains(lower, "gitlab") {
		return nil
	}

	ev := map[string]any{"port": port, "service": "gitlab"}

	// Try to extract version from the API endpoint.
	if apiBody, apiOK := probeHTTPBody(ctx, host, port, useTLS, "/api/v4/version"); apiOK {
		if ver := parseJSONStringField(apiBody, "version"); ver != "" {
			ev["gitlab_version"] = ver
		}
	}

	ev["proof"] = fmt.Sprintf("curl -sk https://%s:%d/ | grep -i gitlab", host, port)
	return []finding.Finding{makeF(
		finding.CheckPortGitLabExposed,
		finding.SeverityHigh,
		fmt.Sprintf("GitLab instance exposed on port %d", port),
		"A GitLab instance is publicly accessible. GitLab exposes source code repositories, CI/CD pipelines, "+
			"container registries, and secret variables. Public or misconfigured instances allow user "+
			"self-registration, repository enumeration, and CI token theft. Unauthenticated access to "+
			"/api/v4/projects may expose private repositories. Restrict access to trusted networks "+
			"and disable self-registration if not required.",
		ev,
	)}
}

// detectTeamCity identifies JetBrains TeamCity build servers.
func detectTeamCity(ctx context.Context, host string, port int, _ string, makeF findingMaker) []finding.Finding {
	body, ok := probeHTTPAnyBody(ctx, host, port, false, "/")
	if !ok {
		return nil
	}
	lower := strings.ToLower(body)
	if !strings.Contains(lower, "teamcity") {
		return nil
	}

	ev := map[string]any{"port": port, "service": "teamcity"}

	// Check REST API for server info (version, build number).
	if apiBody, apiOK := probeHTTPBody(ctx, host, port, false, "/app/rest/server"); apiOK {
		if ver := parseJSONStringField(apiBody, "version"); ver != "" {
			ev["teamcity_version"] = ver
		}
		if build := parseJSONStringField(apiBody, "buildNumber"); build != "" {
			ev["teamcity_build"] = build
		}
	}

	ev["proof"] = fmt.Sprintf("curl -s http://%s:%d/app/rest/server", host, port)
	return []finding.Finding{makeF(
		finding.CheckPortTeamCityExposed,
		finding.SeverityHigh,
		fmt.Sprintf("JetBrains TeamCity build server exposed on port %d", port),
		"A JetBrains TeamCity build server is publicly accessible. TeamCity stores build "+
			"configurations, deployment credentials, VCS roots with repository passwords, and "+
			"SSH keys. CVE-2024-27198 (CVSS 9.8, KEV) allows unauthenticated admin creation via "+
			"path-confusion in the REST API on versions before 2023.11.4. CVE-2023-42793 (CVSS 9.8, KEV) "+
			"allows unauthenticated admin token generation via /RPC2. "+
			"Restrict to trusted networks and apply all security patches.",
		ev,
	)}
}

// detectBamboo identifies Atlassian Bamboo CI/CD servers.
func detectBamboo(ctx context.Context, host string, port int, _ string, makeF findingMaker) []finding.Finding {
	body, ok := probeHTTPAnyBody(ctx, host, port, false, "/")
	if !ok {
		return nil
	}
	lower := strings.ToLower(body)
	if !strings.Contains(lower, "bamboo") && !strings.Contains(lower, "atlassian") {
		return nil
	}
	// Verify it's actually Bamboo, not just any Atlassian product.
	if !strings.Contains(lower, "bamboo") {
		return nil
	}

	ev := map[string]any{
		"port":    port,
		"service": "bamboo",
		"proof":   fmt.Sprintf("curl -s http://%s:%d/ | grep -i bamboo", host, port),
	}
	return []finding.Finding{makeF(
		finding.CheckPortBambooExposed,
		finding.SeverityHigh,
		fmt.Sprintf("Atlassian Bamboo CI/CD server exposed on port %d", port),
		"An Atlassian Bamboo build server is publicly accessible. Bamboo stores build plans, "+
			"deployment projects, shared credentials, and repository access tokens. Exposed Bamboo "+
			"instances allow enumeration of build plans and may permit unauthenticated access to "+
			"build logs containing secrets. Restrict access to trusted networks.",
		ev,
	)}
}

// detectNFS sends a NULL RPC call to port 2049 to confirm an NFS service is listening.
// The NULL procedure (proc 0) is defined for every RPC program and requires no arguments.
func detectNFS(ctx context.Context, host string, port int, _ string, makeF findingMaker) []finding.Finding {
	if !probeNFSNull(ctx, host, port) {
		return nil
	}
	ev := map[string]any{
		"port":    port,
		"service": "nfs",
		"proof":   fmt.Sprintf("showmount -e %s", host),
	}
	findings := []finding.Finding{makeF(
		finding.CheckPortServiceIdentified,
		finding.SeverityInfo,
		fmt.Sprintf("NFS service identified on port %d", port),
		"An NFS (Network File System) service is listening. NFS is commonly used for shared "+
			"file storage across Unix/Linux systems. Internet-exposed NFS allows unauthenticated "+
			"mounting of exported filesystems if exports are not restricted by IP.",
		ev,
	)}

	// Check if exports are enumerable via a MOUNT EXPORT call on the same port.
	if probeNFSExport(ctx, host, port) {
		findings = append(findings, makeF(
			finding.CheckPortNFSExportsExposed,
			finding.SeverityHigh,
			fmt.Sprintf("NFS exports enumerable on port %d", port),
			"NFS exports can be listed without authentication. An attacker can enumerate all shared "+
				"directories and may be able to mount them if the export list permits wildcard or "+
				"broad subnet access. Use 'showmount -e' to list exports and restrict to specific IPs.",
			map[string]any{
				"port":    port,
				"service": "nfs",
				"proof":   fmt.Sprintf("showmount -e %s", host),
			},
		))
	}
	return findings
}

// detectHazelcast identifies Hazelcast in-memory data grid instances via the REST API.
func detectHazelcast(ctx context.Context, host string, port int, _ string, makeF findingMaker) []finding.Finding {
	body, ok := probeHTTPBody(ctx, host, port, false, "/hazelcast/rest/cluster")
	if !ok {
		// Hazelcast may not have REST API enabled; try a raw TCP connection check.
		body, ok = probeHTTPAnyBody(ctx, host, port, false, "/")
		if !ok || !strings.Contains(strings.ToLower(body), "hazelcast") {
			return nil
		}
	}
	lower := strings.ToLower(body)
	if !strings.Contains(lower, "hazelcast") && !strings.Contains(lower, "member") &&
		!strings.Contains(lower, "cluster") {
		return nil
	}

	ev := map[string]any{
		"port":    port,
		"service": "hazelcast",
		"proof":   fmt.Sprintf("curl -s http://%s:%d/hazelcast/rest/cluster", host, port),
	}
	return []finding.Finding{makeF(
		finding.CheckPortHazelcastExposed,
		finding.SeverityHigh,
		fmt.Sprintf("Hazelcast in-memory data grid exposed on port %d", port),
		"A Hazelcast cluster node is publicly accessible. Hazelcast stores application data, "+
			"session state, and cached objects in memory. The REST API and client protocol allow "+
			"reading and writing arbitrary map entries, executing code on cluster members via "+
			"EntryProcessors, and joining the cluster as a rogue member. Restrict to trusted "+
			"networks and enable client authentication.",
		ev,
	)}
}
