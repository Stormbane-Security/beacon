package portscan

import (
	"context"
	"fmt"
	"strings"

	"github.com/stormbane-security/beacon/internal/finding"
)

func init() {
	registerProbe(ServiceProbe{
		Name:         "superset",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{8088},
		Detect:       detectSuperset,
	})
	registerProbe(ServiceProbe{
		Name:         "nacos",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{8848},
		Detect:       detectNacos,
	})
	registerProbe(ServiceProbe{
		Name:         "wazuh-api",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{55000},
		Detect:       detectWazuhAPI,
	})
	registerProbe(ServiceProbe{
		Name:         "veeam",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{9401, 9419},
		Detect:       detectVeeam,
	})
	registerProbe(ServiceProbe{
		Name:         "wingftp",
		Category:     ProbeCatBanner,
		DefaultPorts: []int{},
		Detect:       detectWingFTPPlaceholder,
	})
	registerProbe(ServiceProbe{
		Name:         "cloud-metadata",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{},
		Detect:       detectCloudMetadata,
	})
	registerProbe(ServiceProbe{
		Name:         "metabase",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{3000},
		Detect:       detectMetabase,
	})
}

func detectSuperset(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	body, ok := probeHTTPBody(ctx, host, port, false, "/api/v1/")
	if !ok {
		return nil
	}
	lower := strings.ToLower(body)
	if !strings.Contains(lower, "superset") && !strings.Contains(lower, "apache") {
		return nil
	}
	ev := map[string]any{"port": port, "service": "superset"}
	// Extract version from {"version":"X.Y.Z",...} JSON field.
	if ver := parseJSONStringField(body, "version"); ver != "" {
		ev["superset_version"] = ver
	}
	return []finding.Finding{makeF(
		finding.CheckPortSupersetExposed,
		finding.SeverityCritical,
		fmt.Sprintf("Apache Superset BI platform exposed on port %d", port),
		"Apache Superset is publicly accessible. CVE-2023-27524 (CVSS 8.9, EPSS 84%) allows "+
			"session cookie forgery when the default SECRET_KEY is not changed, granting admin "+
			"access to all dashboards and database credentials. Superset stores production database "+
			"connection strings. Restrict to trusted networks and rotate the SECRET_KEY.",
		ev,
	)}
}

func detectNacos(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	body, ok := probeHTTPBody(ctx, host, port, false, "/nacos/v1/cs/configs?dataId=&group=&tenant=")
	if !ok {
		return nil
	}
	bodyLow := strings.ToLower(body)
	if !strings.Contains(bodyLow, "pageitems") && !strings.Contains(bodyLow, "nacos") &&
		!strings.Contains(bodyLow, "totalcount") {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortNacosExposed,
		finding.SeverityHigh,
		fmt.Sprintf("Nacos service discovery/config center exposed unauthenticated on port %d", port),
		"A Nacos service discovery and configuration management platform is publicly accessible. "+
			"Nacos installations often ship with default credentials (nacos:nacos) and no network restriction. "+
			"Unauthenticated or default-credential access exposes all service registrations, "+
			"configuration data (including secrets and database passwords), and allows "+
			"arbitrary configuration injection to all connected microservices. "+
			"Enable Nacos authentication mode (nacos.core.auth.enabled=true) and rotate default credentials.",
		map[string]any{"port": port, "service": "nacos",
			"url": fmt.Sprintf("http://%s:%d/nacos/v1/cs/configs", host, port)},
	)}
}

func detectWazuhAPI(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	body, ok := probeHTTPBody(ctx, host, port, true, "/")
	if !ok || !strings.Contains(body, "wazuh") {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortWazuhAPIExposed,
		finding.SeverityHigh,
		fmt.Sprintf("Wazuh security platform API exposed on port %d", port),
		"The Wazuh SIEM/XDR REST API is publicly accessible. The Wazuh manager API controls "+
			"all security agents and has access to security alerts, compliance data, and agent commands. "+
			"Unauthorized access allows reading security alerts, disabling agents, and pivoting to managed endpoints.",
		map[string]any{"port": port, "service": "wazuh", "banner": banner},
	)}
}

func detectVeeam(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	body, ok := probeHTTPBody(ctx, host, port, true, "/api/v1/serverInfo")
	if !ok && !probeHTTP(ctx, host, port, true, "/api/v1/serverInfo") {
		return nil
	}
	label := "Veeam Backup & Replication"
	switch port {
	case 9401:
		label = "Veeam Backup & Replication Enterprise Manager"
	case 9419:
		label = "Veeam Catalog Service"
	}
	ev := map[string]any{"port": port, "service": "veeam", "banner": banner}

	// Try to extract version from the serverInfo JSON response.
	confidence := finding.ConfidenceProbable
	if ok && body != "" {
		// Veeam API returns JSON like {"version":"12.0.0.1420",...}
		if ver := extractJSONField(body, "version"); ver != "" {
			ev["veeam_version"] = ver
			// CVE-2025-23120 affects Veeam < 12.3.0.310 (patch P20250119).
			if versionBefore(ver, "12.3.0.310") {
				confidence = finding.ConfidenceVerified
			} else {
				// Patched version — still exposed, but CVE not applicable.
				// Emit only the exposure finding, not the CVE finding.
				return nil
			}
		}
	}

	f := makeF(
		finding.CheckCVEVeeamBackupExposed,
		finding.SeverityCritical,
		fmt.Sprintf("%s exposed on port %d", label, port),
		"A Veeam Backup & Replication service is publicly accessible. "+
			"CVE-2025-23120 (CVSS 9.9, KEV-listed) allows unauthenticated remote code execution on "+
			"Veeam Backup & Replication servers via deserialization. Veeam stores backup credentials "+
			"for all protected infrastructure — compromise allows full domain credential extraction. "+
			"Restrict to trusted backup networks immediately.",
		ev,
	)
	f.Confidence = confidence
	return []finding.Finding{f}
}

// detectWingFTPPlaceholder is a no-op. Wing FTP detection is handled in the FTP probe
// (probe_network.go) via banner parsing. This entry exists only to document the grouping.
func detectWingFTPPlaceholder(_ context.Context, _ string, _ int, _ string, _ findingMaker) []finding.Finding {
	return nil
}

// detectCloudMetadata attempts to reach cloud instance metadata services.
// These probes only succeed when beacon is running INSIDE a cloud instance (e.g. during
// authorized SSRF testing). AWS, GCP, and Azure metadata endpoints are checked.
func detectCloudMetadata(ctx context.Context, host string, port int, _ string, makeF findingMaker) []finding.Finding {
	// Only probe the well-known metadata IP — ignore other hosts.
	if host != "169.254.169.254" {
		return nil
	}

	var findings []finding.Finding

	// AWS IMDSv1: GET http://169.254.169.254/latest/meta-data/
	if body, ok := probeHTTPBody(ctx, host, 80, false, "/latest/meta-data/"); ok {
		bodyLow := strings.ToLower(body)
		if strings.Contains(bodyLow, "ami-id") || strings.Contains(bodyLow, "instance-id") ||
			strings.Contains(bodyLow, "hostname") || strings.Contains(bodyLow, "security-credentials") {
			findings = append(findings, makeF(
				finding.CheckPortCloudMetadataAccessible,
				finding.SeverityCritical,
				"AWS EC2 instance metadata service (IMDSv1) accessible",
				"The AWS EC2 instance metadata service at 169.254.169.254 is reachable and returns "+
					"instance metadata. IMDSv1 does not require a session token, making it exploitable via "+
					"SSRF attacks to steal IAM role credentials at /latest/meta-data/iam/security-credentials/. "+
					"Enforce IMDSv2 (HttpTokens=required) on all EC2 instances to require PUT-based token exchange.",
				map[string]any{
					"port":     80,
					"service":  "aws-metadata",
					"provider": "aws",
					"proof":    "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/",
				},
			))
		}
	}

	// Azure: GET with Metadata:true header — probeHTTPBody doesn't set it,
	// so we check the basic path which returns 400 without the header (still fingerprint).
	if body, ok := probeHTTPAnyBody(ctx, host, 80, false, "/metadata/instance?api-version=2021-02-01"); ok {
		bodyLow := strings.ToLower(body)
		if strings.Contains(bodyLow, "compute") || strings.Contains(bodyLow, "azure") ||
			strings.Contains(bodyLow, "metadata") {
			findings = append(findings, makeF(
				finding.CheckPortCloudMetadataAccessible,
				finding.SeverityCritical,
				"Azure Instance Metadata Service (IMDS) accessible",
				"The Azure Instance Metadata Service at 169.254.169.254 is reachable. "+
					"SSRF attacks can extract managed identity tokens via /metadata/identity/oauth2/token "+
					"to access Azure resources. Apply network-level restrictions and use managed identity "+
					"scoping to limit blast radius.",
				map[string]any{
					"port":     80,
					"service":  "azure-metadata",
					"provider": "azure",
					"proof":    "curl -s -H 'Metadata:true' 'http://169.254.169.254/metadata/instance?api-version=2021-02-01'",
				},
			))
		}
	}

	return findings
}

// detectMetabase identifies Metabase BI dashboards via page title or /api/session/properties.
func detectMetabase(ctx context.Context, host string, port int, _ string, makeF findingMaker) []finding.Finding {
	useTLS := port == 443
	// Check homepage for Metabase branding.
	body, ok := probeHTTPAnyBody(ctx, host, port, useTLS, "/")
	if ok {
		bodyLow := strings.ToLower(body)
		if strings.Contains(bodyLow, "metabase") {
			return metabaseFinding(host, port, useTLS, makeF)
		}
	}
	// Check the session properties API — always returns JSON on Metabase instances.
	if apiBody, apiOK := probeHTTPBody(ctx, host, port, useTLS, "/api/session/properties"); apiOK {
		apiLow := strings.ToLower(apiBody)
		if strings.Contains(apiLow, "metabase") || strings.Contains(apiLow, "\"engines\"") {
			return metabaseFinding(host, port, useTLS, makeF)
		}
	}
	return nil
}

func metabaseFinding(host string, port int, useTLS bool, makeF findingMaker) []finding.Finding {
	s := "http"
	if useTLS {
		s = "https"
	}
	return []finding.Finding{makeF(
		finding.CheckPortMetabaseExposed,
		finding.SeverityHigh,
		fmt.Sprintf("Metabase BI dashboard exposed on port %d", port),
		"A Metabase business intelligence dashboard is publicly accessible. Metabase stores database "+
			"connection credentials and provides direct SQL query access to connected data sources. "+
			"CVE-2023-38646 (CVSS 9.8) allows unauthenticated RCE on Metabase < 0.46.6.1 via the "+
			"/api/setup/validate endpoint. Restrict access to trusted networks and update to the latest version.",
		map[string]any{
			"port":    port,
			"service": "metabase",
			"proof":   fmt.Sprintf("curl -sk %s://%s:%d/api/session/properties", s, host, port),
		},
	)}
}
