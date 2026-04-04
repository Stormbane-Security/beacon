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
	if !probeHTTP(ctx, host, port, true, "/api/v1/serverInfo") {
		return nil
	}
	label := "Veeam Backup & Replication"
	switch port {
	case 9401:
		label = "Veeam Backup & Replication Enterprise Manager"
	case 9419:
		label = "Veeam Catalog Service"
	}
	return []finding.Finding{makeF(
		finding.CheckCVEVeeamBackupExposed,
		finding.SeverityCritical,
		fmt.Sprintf("%s exposed on port %d", label, port),
		"A Veeam Backup & Replication service is publicly accessible. "+
			"CVE-2025-23120 (CVSS 9.9, KEV-listed) allows unauthenticated remote code execution on "+
			"Veeam Backup & Replication servers via deserialization. Veeam stores backup credentials "+
			"for all protected infrastructure — compromise allows full domain credential extraction. "+
			"Restrict to trusted backup networks immediately.",
		map[string]any{"port": port, "service": "veeam", "banner": banner},
	)}
}

// detectWingFTPPlaceholder is a no-op. Wing FTP detection is handled in the FTP probe
// (probe_network.go) via banner parsing. This entry exists only to document the grouping.
func detectWingFTPPlaceholder(_ context.Context, _ string, _ int, _ string, _ findingMaker) []finding.Finding {
	return nil
}
