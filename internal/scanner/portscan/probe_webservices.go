package portscan

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
)

func init() {
	registerProbe(ServiceProbe{
		Name:         "jupyter",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{8888},
		Detect:       detectJupyter,
	})
	registerProbe(ServiceProbe{
		Name:         "prometheus",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{9090},
		Detect:       detectPrometheus,
	})
	registerProbe(ServiceProbe{
		Name:         "kibana",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{5601},
		Detect:       detectKibana,
	})
	registerProbe(ServiceProbe{
		Name:         "minio-console",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{9001},
		Detect:       detectMinIOConsole,
	})
	registerProbe(ServiceProbe{
		Name:         "consul",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{8500},
		Detect:       detectConsul,
	})
	registerProbe(ServiceProbe{
		Name:         "etcd",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{2379, 2380},
		Detect:       detectEtcd,
	})
	registerProbe(ServiceProbe{
		Name:         "webmin",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{10000},
		Detect:       detectWebmin,
	})
	registerProbe(ServiceProbe{
		Name:         "netdata",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{19999},
		Detect:       detectNetdata,
	})
	registerProbe(ServiceProbe{
		Name:         "nexus-artifactory",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{8081, 8082},
		Detect:       detectNexusArtifactory,
	})
	registerProbe(ServiceProbe{
		Name:         "phpmyadmin-adminer",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{},
		Detect:       detectPHPMyAdminAdminer,
	})
	registerProbe(ServiceProbe{
		Name:         "weblogic",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{7001},
		Detect:       detectWebLogic,
	})
	registerProbe(ServiceProbe{
		Name:         "jetdirect",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{9100},
		Detect:       detectJetDirect,
	})
	registerProbe(ServiceProbe{
		Name:         "ipp-cups",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{631},
		Detect:       detectIPPCUPS,
	})
	registerProbe(ServiceProbe{
		Name:         "salt-api",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{8000},
		Detect:       detectSaltAPI,
	})
	registerProbe(ServiceProbe{
		Name:         "vllm",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{8000},
		Detect:       detectVLLM,
	})
	registerProbe(ServiceProbe{
		Name:         "localai",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{8080},
		Detect:       detectLocalAI,
	})
	registerProbe(ServiceProbe{
		Name:         "adguard-home",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{3000},
		Detect:       detectAdGuardHome,
	})
	registerProbe(ServiceProbe{
		Name:         "huggingface-tgi",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{3000},
		Detect:       detectHuggingFaceTGI,
	})
	registerProbe(ServiceProbe{
		Name:         "mlflow",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{5000},
		Detect:       detectMLflow,
	})
	registerProbe(ServiceProbe{
		Name:         "intel-amt",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{16992},
		Detect:       detectIntelAMT,
	})
	registerProbe(ServiceProbe{
		Name:         "vite-dev",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{5173},
		Detect:       detectViteDev,
	})
	registerProbe(ServiceProbe{
		Name:         "ingress-nginx-admission",
		Category:     ProbeCatTLS,
		DefaultPorts: []int{8443},
		Detect:       detectIngressNginxAdmission,
	})
	registerProbe(ServiceProbe{
		Name:         "kubernetes-dashboard-8443",
		Category:     ProbeCatTLS,
		DefaultPorts: []int{8443},
		Detect:       detectKubeDashboard8443,
	})
	registerProbe(ServiceProbe{
		Name:         "kubernetes-dashboard-nodeport",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{},
		Detect:       detectKubeDashboardNodePort,
	})
	registerProbe(ServiceProbe{
		Name:         "tika",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{9998},
		Detect:       detectApacheTika,
	})
	registerProbe(ServiceProbe{
		Name:         "vault",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{8200},
		Detect:       detectVault,
	})
	registerProbe(ServiceProbe{
		Name:         "jboss",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{8080, 9990},
		Detect:       detectJBoss,
	})
	registerProbe(ServiceProbe{
		Name:         "coldfusion",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{8500, 8888},
		Detect:       detectColdFusion,
	})
	registerProbe(ServiceProbe{
		Name:         "jaeger",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{16686},
		Detect:       detectJaeger,
	})
	registerProbe(ServiceProbe{
		Name:         "adminer",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{8080},
		Detect:       detectAdminer,
	})
	registerProbe(ServiceProbe{
		Name:         "goanywhere",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{8000, 8001},
		Detect:       detectGoAnywhere,
	})
	registerProbe(ServiceProbe{
		Name:         "tomcat",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{8080, 8443},
		Detect:       detectTomcat,
	})
	registerProbe(ServiceProbe{
		Name:         "jenkins",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{8080},
		Detect:       detectJenkins,
	})
	registerProbe(ServiceProbe{
		Name:         "wordpress",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{80, 443},
		Detect:       detectWordPress,
	})
	registerProbe(ServiceProbe{
		Name:         "drupal",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{80, 443},
		Detect:       detectDrupal,
	})
	registerProbe(ServiceProbe{
		Name:         "joomla",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{80, 443},
		Detect:       detectJoomla,
	})
	registerProbe(ServiceProbe{
		Name:         "ghost",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{2368},
		Detect:       detectGhost,
	})
	registerProbe(ServiceProbe{
		Name:         "nextcloud",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{80, 443},
		Detect:       detectNextcloud,
	})
	registerProbe(ServiceProbe{
		Name:         "spring-actuator",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{8080, 8443},
		Detect:       detectSpringBoot,
	})
	registerProbe(ServiceProbe{
		Name:         "django",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{8000, 80, 443},
		Detect:       detectDjango,
	})
	registerProbe(ServiceProbe{
		Name:         "laravel",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{80, 443, 8000},
		Detect:       detectLaravel,
	})
	registerProbe(ServiceProbe{
		Name:         "express",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{3000, 8080},
		Detect:       detectExpressJS,
	})
	registerProbe(ServiceProbe{
		Name:         "aspnet",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{80, 443},
		Detect:       detectASPNET,
	})
	registerProbe(ServiceProbe{
		Name:         "rails",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{3000, 80, 443},
		Detect:       detectRails,
	})
	registerProbe(ServiceProbe{
		Name:         "fastapi",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{8000, 80},
		Detect:       detectFastAPI,
	})
	registerProbe(ServiceProbe{
		Name:         "magento",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{80, 443},
		Detect:       detectMagento,
	})
	registerProbe(ServiceProbe{
		Name:         "confluence",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{8090, 443, 80},
		Detect:       detectConfluence,
	})
	registerProbe(ServiceProbe{
		Name:         "jira",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{8080, 443, 80},
		Detect:       detectJira,
	})
}

func detectJupyter(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	exposed := probeJupyter(ctx, host, port)
	if !exposed {
		return nil
	}
	ev := map[string]any{"port": port, "service": "jupyter", "authenticated": false, "banner": banner}
	// Extract Jupyter version from /api endpoint (returns {"version":"7.0.6",...}).
	if apiBody, apiOK := probeHTTPBody(ctx, host, port, false, "/api"); apiOK {
		if ver := parseJSONStringField(apiBody, "version"); ver != "" {
			ev["version"] = ver
			ev["product"] = "Jupyter " + ver
		}
	}
	return []finding.Finding{makeF(
		finding.CheckPortJupyterExposed,
		finding.SeverityCritical,
		fmt.Sprintf("Jupyter Notebook exposed on port %d", port),
		"A Jupyter Notebook server is publicly accessible. "+
			"Jupyter provides arbitrary code execution and full filesystem access to the server.",
		ev,
	)}
}

func detectPrometheus(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	// Prometheus /api/v1/targets returns JSON with "status":"success" and "activeTargets".
	// Reject HTML responses (SPAs return 200 with HTML for any path).
	body, ok := probeHTTPBody(ctx, host, port, false, "/api/v1/targets")
	if !ok || !strings.Contains(body, "activeTargets") {
		return nil
	}
	ev := map[string]any{"port": port, "service": "prometheus", "authenticated": false, "banner": banner}
	// Extract Prometheus version from /api/v1/status/buildinfo (already unauthenticated).
	if buildBody, buildOK := probeHTTPBody(ctx, host, port, false, "/api/v1/status/buildinfo"); buildOK {
		if ver := parseJSONStringField(buildBody, "version"); ver != "" {
			ev["version"] = ver
			ev["product"] = "Prometheus " + ver
		}
	}
	return []finding.Finding{makeF(
		finding.CheckPortPrometheusUnauth,
		finding.SeverityCritical,
		fmt.Sprintf("Unauthenticated Prometheus exposed on port %d", port),
		"A Prometheus metrics server is accessible without authentication. "+
			"Internal infrastructure topology, host names, and service metadata are exposed.",
		ev,
	)}
}

func detectKibana(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	body, ok := probeHTTPBody(ctx, host, port, false, "/api/status")
	if !ok {
		return nil
	}
	ev := map[string]any{"port": port, "service": "kibana", "banner": banner}
	// Extract version from {"version":{"number":"8.16.1",...},...}
	kibanaVer := parseJSONStringField(body, "number")
	if kibanaVer == "" {
		return nil
	}
	ev["kibana_version"] = kibanaVer
	ev["version"] = kibanaVer
	ev["product"] = "Kibana " + kibanaVer
	var findings []finding.Finding
	// Always emit exposed dashboard finding — Kibana should never be public.
	findings = append(findings, makeF(
		finding.CheckPortKibanaExposed,
		finding.SeverityHigh,
		fmt.Sprintf("Kibana %s dashboard exposed on port %d", kibanaVer, port),
		fmt.Sprintf("A Kibana %s dashboard is publicly accessible without authentication. "+
			"Kibana provides full access to Elasticsearch data, saved searches, dashboards, and Dev Tools console. "+
			"Restrict access with authentication (X-Pack Security or a reverse proxy) and network-level controls.",
			kibanaVer),
		ev,
	))
	if isVulnerableKibana(kibanaVer) {
		findings = append(findings, makeF(
			finding.CheckPortKibanaVulnerable,
			finding.SeverityCritical,
			fmt.Sprintf("Kibana %s is vulnerable to CVE-2025-25015 (prototype pollution RCE)", kibanaVer),
			"CVE-2025-25015 (CVSS 9.9) is a prototype pollution vulnerability in Kibana 8.15.0–8.17.2 "+
				"that allows an unauthenticated attacker to achieve remote code execution. "+
				"Upgrade to Kibana 8.17.3 or later immediately. "+
				"Kibana should also not be directly internet-accessible.",
			ev,
		))
	}
	return findings
}

func detectMinIOConsole(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	if !probeMinIODefaultCreds(ctx, host, port) {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortMinIODefaultCreds,
		finding.SeverityCritical,
		fmt.Sprintf("MinIO console accepts default credentials (minioadmin:minioadmin) on port %d", port),
		"The MinIO object storage web console is accessible with the factory-default credentials "+
			"minioadmin/minioadmin. An attacker can read, write, or delete all stored objects and "+
			"reconfigure the MinIO cluster. Change the root credentials immediately via environment "+
			"variables MINIO_ROOT_USER and MINIO_ROOT_PASSWORD.",
		map[string]any{"port": port, "service": "minio", "authenticated": true, "default_creds": true},
	)}
}

func detectConsul(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	body, ok := probeHTTPBody(ctx, host, port, false, "/v1/catalog/nodes")
	if !ok {
		return nil
	}
	bodyLow := strings.ToLower(body)
	if !strings.HasPrefix(strings.TrimSpace(body), "[") ||
		(!strings.Contains(bodyLow, "node") && !strings.Contains(bodyLow, "address") &&
			!strings.Contains(bodyLow, "datacenter")) {
		return nil
	}
	ev := map[string]any{"port": port, "service": "consul",
		"url": fmt.Sprintf("http://%s:%d/v1/catalog/nodes", host, port)}
	// Extract Consul version from /v1/agent/self (already unauthenticated if ACLs are off).
	if selfBody, selfOK := probeHTTPBody(ctx, host, port, false, "/v1/agent/self"); selfOK {
		if ver := parseJSONStringField(selfBody, "Version"); ver != "" {
			ev["version"] = ver
		} else if ver := parseJSONStringField(selfBody, "version"); ver != "" {
			ev["version"] = ver
		}
	}
	return []finding.Finding{makeF(
		finding.CheckPortConsulNoACL,
		finding.SeverityHigh,
		fmt.Sprintf("HashiCorp Consul responds without ACL authentication on port %d", port),
		"A HashiCorp Consul service mesh instance returns cluster node information without authentication. "+
			"With ACLs disabled, the Consul API exposes full cluster topology, all registered services "+
			"and their network endpoints, and the key-value store (which often contains secrets, "+
			"TLS certificates, and database credentials). An attacker can also register malicious "+
			"services to redirect internal traffic. Enable Consul ACLs "+
			"(acl { enabled = true }) and restrict the HTTP port to trusted networks.",
		ev,
	)}
}

func detectEtcd(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	// Detect etcd by HTTP response content — /version returns etcd version info.
	if body, ok := probeHTTPBody(ctx, host, port, false, "/version"); ok && strings.Contains(strings.ToLower(body), "etcd") {
		ev := map[string]any{"port": port, "service": "etcd"}
		if ver := parseJSONStringField(body, "etcdserver"); ver != "" {
			ev["version"] = ver
			ev["product"] = "etcd " + ver
		}
		return []finding.Finding{makeF(
			finding.CheckPortEtcdExposed,
			finding.SeverityCritical,
			fmt.Sprintf("etcd client API exposed on port %d", port),
			"An etcd cluster member is publicly accessible. etcd stores all Kubernetes cluster "+
				"state including secrets, service account tokens, and cluster configuration. "+
				"Unauthenticated etcd access gives full read/write to the key-value store "+
				"and their network endpoints, and the key-value store (which often contains secrets, "+
				"TLS certificates, and database credentials).",
			ev,
		)}
	}
	// Also try HTTPS — etcd may be configured with TLS.
	if body, ok := probeHTTPBody(ctx, host, port, true, "/version"); ok && strings.Contains(strings.ToLower(body), "etcd") {
		ev := map[string]any{"port": port, "service": "etcd"}
		if ver := parseJSONStringField(body, "etcdserver"); ver != "" {
			ev["version"] = ver
			ev["product"] = "etcd " + ver
		}
		return []finding.Finding{makeF(
			finding.CheckPortEtcdExposed,
			finding.SeverityCritical,
			fmt.Sprintf("etcd client API exposed on port %d", port),
			"An etcd cluster member is publicly accessible via TLS. etcd stores all Kubernetes cluster "+
				"state including secrets, service account tokens, and cluster configuration.",
			ev,
		)}
	}
	// Fall back to port-based for well-known etcd ports when HTTP probes fail.
	if port != 2379 && port != 2380 {
		return nil
	}
	label := "etcd client"
	if port == 2380 {
		label = "etcd peer"
	}
	return []finding.Finding{makeF(
		finding.CheckPortEtcdExposed,
		finding.SeverityCritical,
		fmt.Sprintf("etcd %s port exposed on port %d", label, port),
		fmt.Sprintf("The etcd %s port (%d) is publicly accessible. etcd is the primary datastore for "+
			"Kubernetes clusters and contains all cluster state: pod specs, secrets, service account "+
			"tokens, RBAC policies, and ConfigMaps. Direct access to etcd allows an attacker to read "+
			"all secrets, modify RBAC to grant cluster-admin, or delete the entire cluster state. "+
			"etcd must never be exposed to the internet — restrict access to the control plane network "+
			"and require mutual TLS (mTLS) for all client connections.", label, port),
		map[string]any{"port": port, "service": "etcd", "banner": banner},
	)}
}

func detectWebmin(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	// Webmin login page contains form with action="/session_login.cgi" and "Webmin" branding.
	body, ok := probeHTTPBody(ctx, host, port, true, "/session_login.cgi")
	if !ok {
		return nil
	}
	bodyLow := strings.ToLower(body)
	if !strings.Contains(bodyLow, "webmin") && !strings.Contains(bodyLow, "session_login") {
		return nil
	}
	ev := map[string]any{"port": port, "service": "webmin", "banner": banner}
	// Extract Webmin version from page title (e.g. "Login to Webmin" page may contain version)
	// or from body text like "Webmin 2.105".
	for _, prefix := range []string{"webmin ", "webmin/"} {
		if idx := strings.Index(bodyLow, prefix); idx >= 0 {
			after := body[idx+len(prefix):]
			ver := ""
			for _, c := range after {
				if (c >= '0' && c <= '9') || c == '.' {
					ver += string(c)
				} else if ver != "" {
					break
				}
			}
			if ver != "" && strings.Contains(ver, ".") {
				ev["version"] = strings.TrimRight(ver, ".")
				ev["product"] = "Webmin " + strings.TrimRight(ver, ".")
				break
			}
		}
	}
	return []finding.Finding{makeF(
		finding.CheckPortWebminExposed,
		finding.SeverityHigh,
		fmt.Sprintf("Webmin server management panel exposed on port %d", port),
		"Webmin is publicly accessible. Webmin provides web-based Unix/Linux system administration "+
			"and has a history of critical vulnerabilities. CVE-2019-15107 allowed unauthenticated RCE "+
			"and CVE-2022-0824 allowed unauthenticated file read. Restrict to trusted networks.",
		ev,
	)}
}

func detectNetdata(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	body, ok := probeHTTPBody(ctx, host, port, false, "/api/v1/info")
	if !ok {
		return nil
	}
	bodyLow := strings.ToLower(body)
	if !strings.Contains(bodyLow, "netdata") && (!strings.Contains(bodyLow, "hostname") ||
		!strings.Contains(bodyLow, "os_name")) {
		return nil
	}
	ev := map[string]any{"port": port, "service": "netdata",
		"url": fmt.Sprintf("http://%s:%d", host, port)}
	if ver := parseJSONStringField(body, "version"); ver != "" {
		ev["version"] = ver
		ev["product"] = "Netdata " + ver
	}
	return []finding.Finding{makeF(
		finding.CheckPortNetdataExposed,
		finding.SeverityMedium,
		fmt.Sprintf("Netdata monitoring dashboard exposed unauthenticated on port %d", port),
		"A Netdata real-time monitoring dashboard is publicly accessible without authentication. "+
			"Netdata exposes detailed system metrics: CPU, memory, disk, network, running processes, "+
			"Docker containers, and application internals. This information significantly aids "+
			"reconnaissance for targeted attacks. Older Netdata versions allow unauthenticated "+
			"dashboard access by default. Enable Netdata Cloud authentication or place Netdata "+
			"behind an authenticated reverse proxy restricted to monitoring networks.",
		ev,
	)}
}

func detectNexusArtifactory(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	// Probe for JFrog Artifactory.
	if body, ok := probeHTTPBody(ctx, host, port, false, "/artifactory/api/system/ping"); ok {
		if strings.TrimSpace(body) == "OK" || strings.Contains(strings.ToLower(body), "artifactory") {
			// Attempt default admin:password credentials on the REST API.
			if _, authed := probeHTTPBodyWithAuth(ctx, host, port, false, "/artifactory/api/system/configuration", "admin", "password"); authed {
				return []finding.Finding{makeF(
					finding.CheckPortArtifactoryExposed,
					finding.SeverityCritical,
					fmt.Sprintf("JFrog Artifactory accepts default admin:password credentials on port %d", port),
					"JFrog Artifactory repository manager accepts the default admin:password credentials. "+
						"An attacker gains full administrative control: read/write all artifact repositories "+
						"(including private packages), inject malicious artifacts into the supply chain, "+
						"export credentials to external registries, and access pipeline secrets. "+
						"Change admin password immediately and enable access tokens with least privilege.",
					map[string]any{"port": port, "service": "artifactory", "creds": "admin:password", "authenticated": true},
				)}
			}
			artEv := map[string]any{"port": port, "service": "artifactory",
				"url": fmt.Sprintf("http://%s:%d/artifactory/", host, port)}
			// Extract Artifactory version from /artifactory/api/system/version (already public).
			if verBody, verOK := probeHTTPBody(ctx, host, port, false, "/artifactory/api/system/version"); verOK {
				if ver := parseJSONStringField(verBody, "version"); ver != "" {
					artEv["version"] = ver
					artEv["product"] = "JFrog Artifactory " + ver
				}
			}
			return []finding.Finding{makeF(
				finding.CheckPortArtifactoryExposed,
				finding.SeverityHigh,
				fmt.Sprintf("JFrog Artifactory repository manager exposed on port %d", port),
				"A JFrog Artifactory repository manager is publicly accessible. "+
					"Artifactory hosts build artifacts, Docker images, npm/Maven/PyPI packages, and pipeline credentials. "+
					"Unauthenticated access or default credentials allow supply chain compromise by "+
					"injecting malicious artifacts into repositories used by development pipelines. "+
					"Restrict access to trusted networks and rotate all repository credentials.",
				artEv,
			)}
		}
	}
	// Probe for Sonatype Nexus Repository Manager.
	if body, ok := probeHTTPBody(ctx, host, port, false, "/service/rest/v1/status"); ok {
		bodyLow := strings.ToLower(body)
		if strings.Contains(bodyLow, "nexus") || strings.Contains(bodyLow, "sonatype") {
			nexusEv := map[string]any{"port": port, "service": "nexus",
				"url": fmt.Sprintf("http://%s:%d/", host, port)}
			if ver := parseJSONStringField(body, "version"); ver != "" {
				nexusEv["version"] = ver
				nexusEv["product"] = "Sonatype Nexus " + ver
			}
			return []finding.Finding{makeF(
				finding.CheckPortNexusExposed,
				finding.SeverityHigh,
				fmt.Sprintf("Sonatype Nexus Repository Manager exposed on port %d", port),
				"A Sonatype Nexus Repository Manager is publicly accessible. "+
					"Nexus hosts Maven, npm, Docker, PyPI, and raw binary artifacts. "+
					"Older Nexus versions use default credentials (admin:admin123) and may be vulnerable to "+
					"CVE-2019-7238 (Nexus 3 < 3.15.0 pre-auth RCE via EL injection, CVSS 9.8, KEV). "+
					"Restrict to trusted networks and update to the latest version.",
				nexusEv,
			)}
		}
	}
	// Also check Nexus UI root.
	if body, ok := probeHTTPBody(ctx, host, port, false, "/"); ok {
		bodyLow := strings.ToLower(body)
		if strings.Contains(bodyLow, "nexus repository") || strings.Contains(bodyLow, "sonatype nexus") {
			return []finding.Finding{makeF(
				finding.CheckPortNexusExposed,
				finding.SeverityHigh,
				fmt.Sprintf("Sonatype Nexus Repository Manager detected on port %d", port),
				"A Sonatype Nexus Repository Manager is publicly accessible. "+
					"Check for default admin:admin123 credentials and CVE-2019-7238 (pre-auth RCE, CVSS 9.8, KEV).",
				map[string]any{"port": port, "service": "nexus"},
			)}
		}
	}
	return nil
}

func detectPHPMyAdminAdminer(_ context.Context, _ string, _ int, _ string, _ findingMaker) []finding.Finding {
	// Placeholder — phpMyAdmin/Adminer detection is done via HTTP fingerprinting
	// in the web scanner, not via port probe. No-op here.
	return nil
}

func detectWebLogic(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	body, ok := probeHTTPBody(ctx, host, port, false, "/console/login/LoginForm.jsp")
	if !ok {
		return nil
	}
	lb := strings.ToLower(body)
	// Require "weblogic" specifically — "oracle" alone matches database admin tools like Adminer.
	if !strings.Contains(lb, "weblogic") {
		return nil
	}
	ev := map[string]any{"port": port, "service": "weblogic"}
	confidence := finding.ConfidenceProbable

	// Try to extract version from the console login page.
	if ver := parseWebLogicVersion(body); ver != "" {
		ev["weblogic_version"] = ver
		ev["version"] = ver
		ev["product"] = "Oracle WebLogic " + ver
		// CVE-2020-14882/14883 affects WebLogic < 14.1.1.0.0 and < 12.2.1.4.0
		// (with Oct 2020 CPU patch). Conservatively: anything < 14.1.1.1 or < 12.2.1.5.
		vulnerable := versionBefore(ver, "14.1.1.1") // covers 12.x, 10.x, etc.
		if vulnerable {
			confidence = finding.ConfidenceVerified
		} else {
			// Patched — still exposed but CVE not exploitable.
			return nil
		}
	}

	f := makeF(
		finding.CheckCVEWebLogicConsole,
		finding.SeverityCritical,
		fmt.Sprintf("Oracle WebLogic admin console exposed on port %d (CVE-2020-14882 KEV)", port),
		"Oracle WebLogic admin console at /console/login/LoginForm.jsp is internet-accessible. "+
			"CVE-2020-14882/14883 (CVSS 9.8, KEV) allows unauthenticated RCE via double URL-encoded "+
			"paths. The WebLogic admin console must never be internet-facing regardless of patch level.",
		ev,
	)
	f.Confidence = confidence
	return []finding.Finding{f}
}

func detectJetDirect(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	// Send a PJL status query. Printers respond with model info; node-exporter does not.
	if body, ok := probeHTTPBody(ctx, host, port, false, "/metrics"); ok && strings.Contains(body, "node_") {
		// Prometheus node-exporter — not a printer
		return nil
	}
	if !probeJetDirect(ctx, host, port) {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortJetDirectExposed,
		finding.SeverityMedium,
		fmt.Sprintf("JetDirect/PJL printer raw print port exposed on port %d", port),
		"TCP port 9100 (HP JetDirect/PJL raw print port) is internet-accessible. "+
			"Attackers can submit rogue print jobs, execute PJL commands to read stored print jobs, "+
			"change device configuration, or exploit printer-specific vulnerabilities. "+
			"PJL `INFO ID` commands reveal printer model and firmware version without authentication. "+
			"Printers and MFPs should never have port 9100 internet-accessible.",
		map[string]any{"port": port, "service": "jetdirect", "banner": banner},
	)}
}

func detectIPPCUPS(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	body, ok := probeHTTPBody(ctx, host, port, false, "/")
	if !ok {
		return nil
	}
	lb := strings.ToLower(body)
	if !strings.Contains(lb, "cups") && !strings.Contains(lb, "ipp") {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortIPPExposed,
		finding.SeverityMedium,
		fmt.Sprintf("IPP/CUPS printer exposed on port %d", port),
		"An IPP (Internet Printing Protocol) server is publicly accessible. "+
			"Internet-exposed printers can be exploited for arbitrary file reads via print job manipulation, "+
			"used as proxies for internal network access (CUPS SSRF), and may expose document queues. "+
			"CVE-2024-47176 (CUPS RCE via crafted UDP packet) affects CUPS < 2.4.11.",
		map[string]any{"port": port, "service": "ipp", "banner": banner},
	)}
}

func detectSaltAPI(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	body, ok := probeHTTPBody(ctx, host, port, false, "/")
	if !ok || !strings.Contains(body, "wheel_async") {
		return nil
	}
	ev := map[string]any{"port": port, "service": "salt-api", "authenticated": false}
	confidence := finding.ConfidenceProbable

	// Try to extract Salt version from the API response.
	if ver := parseSaltVersion(body); ver != "" {
		ev["salt_version"] = ver
		ev["version"] = ver
		ev["product"] = "SaltStack " + ver
		// CVE-2021-25281/25282 affects Salt < 3002.5, < 3001.6, < 3000.8.
		// Simplified: anything < 3002.5 is vulnerable.
		if versionBefore(ver, "3002.5") {
			confidence = finding.ConfidenceVerified
		} else {
			return nil // patched
		}
	}

	f := makeF(
		finding.CheckCVESaltStackAPI,
		finding.SeverityCritical,
		fmt.Sprintf("CVE-2021-25281/25282: SaltStack Salt API exposed on port %d", port),
		"A SaltStack Salt API (salt-api) is internet-accessible without authentication. "+
			"CVE-2021-25281 (CVSS 9.8, KEV) allows unauthenticated access to the wheel client, "+
			"and CVE-2021-25282 is an arbitrary file write via wheel.pillar_roots.write — "+
			"an attacker can write to /etc/crontab or any system file to achieve root RCE. "+
			"Salt API must never be exposed to the internet. Restrict to internal management networks.",
		ev,
	)
	f.Confidence = confidence
	return []finding.Finding{f}
}

func detectVLLM(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	vbody, vok := probeHTTPBody(ctx, host, port, false, "/v1/models")
	if !vok {
		return nil
	}
	bodyLow := strings.ToLower(vbody)
	if !strings.Contains(bodyLow, "vllm") && (!strings.Contains(bodyLow, `"owned_by"`) ||
		!strings.Contains(bodyLow, "data") || !strings.Contains(bodyLow, "model")) {
		return nil
	}
	ev := map[string]any{"port": port, "service": "vllm",
		"url": fmt.Sprintf("http://%s:%d/v1/models", host, port)}
	// Try /version endpoint for vLLM version (returns {"version":"0.4.2"}).
	if verBody, verOK := probeHTTPBody(ctx, host, port, false, "/version"); verOK {
		if ver := parseJSONStringField(verBody, "version"); ver != "" {
			ev["version"] = ver
			ev["product"] = "vLLM " + ver
		}
	}
	return []finding.Finding{makeF(
		finding.CheckPortvLLMExposed,
		finding.SeverityHigh,
		fmt.Sprintf("vLLM inference server exposed unauthenticated on port %d", port),
		"A vLLM OpenAI-compatible LLM inference server is publicly accessible without authentication. "+
			"vLLM is a high-throughput serving framework for large language models. "+
			"Unauthenticated access allows unlimited inference at the operator's GPU cost, "+
			"exposure of fine-tuned model capabilities, and potential prompt injection attacks. "+
			"Add --api-key to require authentication and restrict to trusted networks.",
		ev,
	)}
}

func detectLocalAI(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	lbody, lok := probeHTTPBody(ctx, host, port, false, "/v1/models")
	if !lok {
		return nil
	}
	bodyLow := strings.ToLower(lbody)
	if !strings.Contains(bodyLow, "localai") && !strings.Contains(bodyLow, "local ai") &&
		!strings.Contains(bodyLow, "go-skynet") {
		return nil
	}
	ev := map[string]any{"port": port, "service": "localai",
		"url": fmt.Sprintf("http://%s:%d/v1/models", host, port)}
	if ver := parseJSONStringField(lbody, "version"); ver != "" {
		ev["version"] = ver
		ev["product"] = "LocalAI " + ver
	}
	return []finding.Finding{makeF(
		finding.CheckPortLocalAIExposed,
		finding.SeverityHigh,
		fmt.Sprintf("LocalAI inference server exposed unauthenticated on port %d", port),
		"A LocalAI OpenAI-compatible LLM inference server is publicly accessible without authentication. "+
			"LocalAI serves language models, image generation, and audio transcription locally. "+
			"Unauthenticated access allows unlimited inference at the operator's cost, "+
			"exposure of locally loaded models, and potential arbitrary model file access. "+
			"Configure authentication and restrict access to trusted networks.",
		ev,
	)}
}

func detectAdGuardHome(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	body, ok := probeHTTPBody(ctx, host, port, false, "/control/status")
	if !ok {
		return nil
	}
	bodyLow := strings.ToLower(body)
	if !strings.Contains(bodyLow, "dns_addresses") && (!strings.Contains(bodyLow, "running") ||
		!strings.Contains(bodyLow, "version")) {
		return nil
	}
	ev := map[string]any{"port": port, "service": "adguard",
		"url": fmt.Sprintf("http://%s:%d/control/status", host, port)}
	if ver := parseJSONStringField(body, "version"); ver != "" {
		ev["version"] = ver
		ev["product"] = "AdGuard Home " + ver
	}
	return []finding.Finding{makeF(
		finding.CheckPortAdGuardExposed,
		finding.SeverityHigh,
		fmt.Sprintf("AdGuard Home admin UI exposed unauthenticated on port %d", port),
		"The AdGuard Home admin API at /control/status is accessible without authentication. "+
			"AdGuard Home controls DNS resolution for all devices on the network. "+
			"Unauthenticated access allows an attacker to reconfigure upstream DNS servers "+
			"(enabling DNS hijacking of the entire network), disable ad/malware filtering, "+
			"read DNS query logs, and modify access control lists. "+
			"Enable authentication in AdGuard Home settings and restrict access to the "+
			"admin interface to trusted internal addresses only.",
		ev,
	)}
}

func detectHuggingFaceTGI(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	body, ok := probeHTTPBody(ctx, host, port, false, "/info")
	if !ok {
		return nil
	}
	bodyLow := strings.ToLower(body)
	if !strings.Contains(bodyLow, "model_id") || !strings.Contains(bodyLow, "max_input_length") {
		return nil
	}
	ev := map[string]any{"port": port, "service": "huggingface-tgi",
		"url": fmt.Sprintf("http://%s:%d/info", host, port)}
	if ver := parseJSONStringField(body, "version"); ver != "" {
		ev["version"] = ver
		ev["product"] = "HuggingFace TGI " + ver
	}
	if modelID := parseJSONStringField(body, "model_id"); modelID != "" {
		ev["model_id"] = modelID
	}
	return []finding.Finding{makeF(
		finding.CheckPortHuggingFaceTGIExposed,
		finding.SeverityHigh,
		fmt.Sprintf("HuggingFace Text Generation Inference server exposed unauthenticated on port %d", port),
		"A HuggingFace Text Generation Inference (TGI) server is publicly accessible without authentication. "+
			"The /info endpoint discloses the loaded model ID, maximum input/output lengths, and server configuration. "+
			"Unauthenticated access allows unlimited LLM inference at the operator's compute cost, "+
			"model identification for targeted attacks, and potential prompt injection against downstream applications. "+
			"Add authentication via a reverse proxy and restrict the port to trusted networks.",
		ev,
	)}
}

func detectMLflow(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	body, ok := probeHTTPBody(ctx, host, port, false, "/ping")
	if !ok || !strings.Contains(strings.ToLower(body), "ready") {
		return nil
	}
	ev := map[string]any{"port": port, "service": "mlflow"}
	// Version from GET /version returns plain-text version string.
	if verBody, ok2 := probeHTTPBody(ctx, host, port, false, "/version"); ok2 {
		ver := strings.TrimSpace(verBody)
		if ver != "" && !strings.ContainsAny(ver, "<>{") {
			ev["mlflow_version"] = ver
			ev["version"] = ver
			ev["product"] = "MLflow " + ver
		}
	}
	findings := []finding.Finding{makeF(
		finding.CheckPortMLflowExposed,
		finding.SeverityCritical,
		fmt.Sprintf("MLflow experiment tracking server exposed on port %d", port),
		"An MLflow server is publicly accessible without authentication. MLflow stores "+
			"model artifacts, experiment parameters, training metrics, and run data. "+
			"CVE-2023-6014 (CVSS 9.1) allows unauthenticated account creation via POST "+
			"/api/2.0/users/create on MLflow < 2.8.0. Restrict to trusted networks.",
		ev,
	)}
	// CVE-2023-6014: check if account creation API is open.
	if probeHTTP(ctx, host, port, false, "/api/2.0/mlflow/experiments/list") {
		emitMLflowCVE := true
		mlflowConfidence := finding.ConfidenceProbable
		// Version was already extracted above into ev["mlflow_version"].
		if ver, ok := ev["mlflow_version"].(string); ok && ver != "" {
			if versionBefore(ver, "2.8.0") {
				mlflowConfidence = finding.ConfidenceVerified
			} else {
				emitMLflowCVE = false // patched MLflow
			}
		}
		if emitMLflowCVE {
			mlF := makeF(
				finding.CheckCVEMLflowAuthBypass,
				finding.SeverityCritical,
				fmt.Sprintf("CVE-2023-6014: MLflow unauthenticated REST API confirmed on port %d", port),
				"The MLflow experiments list API (/api/2.0/mlflow/experiments/list) returns data "+
					"without authentication. CVE-2023-6014 (CVSS 9.1) allows unauthenticated account "+
					"creation on MLflow < 2.8.0. Upgrade MLflow and restrict network access.",
				ev,
			)
			mlF.Confidence = mlflowConfidence
			findings = append(findings, mlF)
		}
	}
	return findings
}

func detectIntelAMT(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	body, ok := probeHTTPBody(ctx, host, port, false, "/index.htm")
	if !ok || !strings.Contains(strings.ToLower(body), "intel") {
		return nil
	}
	ev := map[string]any{"port": port, "service": "intel-amt"}
	// Try to extract AMT version from the HTML body (e.g. "Intel(R) Active Management Technology X.Y.Z").
	bodyLow := strings.ToLower(body)
	for _, prefix := range []string{"active management technology ", "amt "} {
		if idx := strings.Index(bodyLow, prefix); idx >= 0 {
			after := body[idx+len(prefix):]
			ver := ""
			for _, c := range after {
				if (c >= '0' && c <= '9') || c == '.' {
					ver += string(c)
				} else if ver != "" {
					break
				}
			}
			if ver != "" && strings.Contains(ver, ".") {
				ev["version"] = strings.TrimRight(ver, ".")
				ev["product"] = "Intel AMT " + strings.TrimRight(ver, ".")
				break
			}
		}
	}
	f := makeF(
		finding.CheckCVEIntelAMTAuthBypass,
		finding.SeverityCritical,
		fmt.Sprintf("CVE-2017-5689: Intel AMT management interface exposed on port %d", port),
		"The Intel Active Management Technology (AMT) web interface is internet-accessible. "+
			"CVE-2017-5689 (CVSS 9.8, KEV) allows unauthenticated access by sending an empty "+
			"Digest authentication response (Authorization: Digest response=\"\"). "+
			"AMT runs on the Intel Management Engine (ME) — a dedicated microcontroller separate "+
			"from the main CPU and OS — providing full KVM, remote console, and power control. "+
			"A compromised AMT instance survives OS reinstalls and disk wipes. "+
			"Disable AMT if not needed, update firmware, and block port 16992/16993 at the firewall.",
		ev,
	)
	// Intel AMT firmware version is rarely extractable from HTTP — confidence is probable.
	f.Confidence = finding.ConfidenceProbable
	return []finding.Finding{f}
}

func detectViteDev(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	// Vite's /__vite_ping returns a tiny non-HTML response. SPAs and generic
	// web servers return HTML or their default response for any path.
	// Require a short, specific response — Vite returns empty body or
	// a very short text response, and also sets specific headers.
	body, hdrs, ok := probeHTTPBodyAndHeaders(ctx, host, port, false, "/__vite_ping")
	if !ok {
		return nil
	}
	trimmed := strings.TrimSpace(body)
	// Reject HTML, shell scripts, and long responses (Vite returns < 20 bytes).
	if strings.HasPrefix(trimmed, "<") || strings.HasPrefix(trimmed, "#!") || len(trimmed) > 50 {
		return nil
	}
	// Require a Vite-specific signal: the response should NOT have a Server
	// header from known non-Vite servers.
	server := strings.ToLower(hdrs.Get("Server"))
	if server != "" && !strings.Contains(server, "vite") {
		return nil
	}
	now := time.Now()
	var findings []finding.Finding

	// CVE-2025-30208: /@fs/ path traversal with double-? query confusion.
	if body, ok := probeHTTPBody(ctx, host, port, false, "/@fs/etc/passwd?import&raw??"); ok &&
		strings.Contains(body, "export default") && strings.Contains(body, "root:") {
		// The file read itself confirms the CVE is exploitable — verified confidence.
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckCVEViteFileRead,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityCritical,
			Title:    fmt.Sprintf("CVE-2025-30208: Vite dev server arbitrary file read on port %d", port),
			Description: fmt.Sprintf(
				"The Vite development server on %s:%d is vulnerable to CVE-2025-30208 — "+
					"a path traversal that bypasses the /@fs/ allowlist by exploiting a regex "+
					"confusion via a double-question-mark in the query string. "+
					"The probe retrieved /etc/passwd as a JS module. "+
					"Affects Vite < 6.2.4 / < 6.1.3 / < 6.0.12 / < 5.4.15 / < 4.5.10. "+
					"Upgrade Vite and never expose dev servers publicly.",
				host, port,
			),
			Asset: host,
			Evidence: map[string]any{
				"url":          fmt.Sprintf("http://%s:%d/@fs/etc/passwd?import&raw??", host, port),
				"body_excerpt": body[:min(len(body), 256)],
			},
			ProofCommand: fmt.Sprintf(
				"curl -s 'http://%s:%d/@fs/etc/passwd?import&raw??'",
				host, port,
			),
			Confidence:   finding.ConfidenceVerified,
			DiscoveredAt: now,
		})
	}

	viteEv := map[string]any{"port": port, "service": "vite", "banner": banner}
	// Try to extract Vite version from the homepage HTML (e.g. "/@vite/client" script src with version).
	if homeBody, homeOK := probeHTTPBody(ctx, host, port, false, "/"); homeOK {
		homeLow := strings.ToLower(homeBody)
		// Vite injects a script like <script type="module" src="/@vite/client"></script>
		// and the HTML may contain "vite v5.4.1" or similar in comments/meta.
		for _, prefix := range []string{"vite/", "vite v", "vite@"} {
			if idx := strings.Index(homeLow, prefix); idx >= 0 {
				after := homeBody[idx+len(prefix):]
				ver := ""
				for _, c := range after {
					if (c >= '0' && c <= '9') || c == '.' {
						ver += string(c)
					} else if ver != "" {
						break
					}
				}
				if ver != "" && strings.Contains(ver, ".") {
					viteEv["version"] = strings.TrimRight(ver, ".")
					viteEv["product"] = "Vite " + strings.TrimRight(ver, ".")
					break
				}
			}
		}
	}
	findings = append(findings, makeF(
		finding.CheckPortDevServerExposed,
		finding.SeverityHigh,
		fmt.Sprintf("Vite development server exposed on port %d", port),
		"A Vite JavaScript development server is publicly accessible. Development servers "+
			"expose unminified source code, internal file paths, environment variables embedded in code, "+
			"and the /__vite_ping health endpoint. Production deployments should never expose dev servers.",
		viteEv,
	))
	return findings
}

func detectIngressNginxAdmission(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	body := probeIngressAdmissionWebhook(ctx, host, port)
	if body == "" {
		return nil
	}
	now := time.Now()
	// Version is rarely extractable from the admission webhook response — probable confidence.
	return []finding.Finding{{
		CheckID:  finding.CheckCVEIngressNightmare,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Title:    fmt.Sprintf("CVE-2025-1974 (IngressNightmare): ingress-nginx admission webhook exposed on port %d", port),
		Description: fmt.Sprintf(
			"%s has the ingress-nginx admission controller webhook accessible on port %d. "+
				"CVE-2025-1974 allows an unauthenticated attacker to send a crafted AdmissionReview "+
				"request containing a malicious nginx configuration directive, achieving remote code "+
				"execution in the ingress-nginx pod. The webhook should never be internet-accessible — "+
				"restrict port 8443 to the Kubernetes API server CIDR only via NetworkPolicy.",
			host, port,
		),
		Asset: host,
		Evidence: map[string]any{
			"port":          port,
			"service":       "ingress-nginx-admission-webhook",
			"response_body": body[:min(len(body), 256)],
		},
		ProofCommand: fmt.Sprintf(
			`curl -sk -X POST https://%s:%d/admission -H 'Content-Type: application/json' `+
				`-d '{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview"}'`,
			host, port,
		),
		Confidence:   finding.ConfidenceProbable,
		DiscoveredAt: now,
	}}
}

func detectKubeDashboard8443(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	body, ok := probeHTTPBody(ctx, host, port, true, "/")
	if !ok {
		return nil
	}
	lb := strings.ToLower(body)
	if !strings.Contains(lb, "dashboard") || (!strings.Contains(lb, "kubernetes") && !strings.Contains(lb, "k8s")) {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortKubeDashboardExposed,
		finding.SeverityCritical,
		fmt.Sprintf("Kubernetes Dashboard exposed on port %d", port),
		"The Kubernetes Dashboard is publicly accessible. The dashboard provides full "+
			"cluster management capabilities including viewing secrets, creating workloads, "+
			"and executing commands in containers. An exposed dashboard — especially with "+
			"default or permissive RBAC — enables complete cluster takeover. "+
			"Remove public access and restrict the dashboard to kubectl proxy or a VPN.",
		map[string]any{"port": port, "service": "kubernetes-dashboard"},
	)}
}

func detectKubeDashboardNodePort(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	if port < 30000 || port > 32767 {
		return nil
	}
	// Try HTTPS first, then HTTP.
	for _, useTLS := range []bool{true, false} {
		body, ok := probeHTTPBody(ctx, host, port, useTLS, "/")
		if !ok {
			continue
		}
		lb := strings.ToLower(body)
		if strings.Contains(lb, "kubernetes-dashboard") || strings.Contains(lb, "kubernetes dashboard") ||
			(strings.Contains(lb, "dashboard") && strings.Contains(lb, "kubernetes")) {
			return []finding.Finding{makeF(
				finding.CheckPortKubeDashboardExposed,
				finding.SeverityCritical,
				fmt.Sprintf("Kubernetes Dashboard exposed on NodePort %d", port),
				"The Kubernetes Dashboard is publicly accessible via a NodePort service. "+
					"The dashboard provides full cluster management capabilities including viewing "+
					"secrets, creating workloads, and executing commands in containers. An exposed "+
					"dashboard — especially with default or permissive RBAC — enables complete "+
					"cluster takeover. Remove the NodePort service and restrict dashboard access "+
					"to kubectl proxy or a VPN.",
				map[string]any{"port": port, "service": "kubernetes-dashboard"},
			)}
		}
	}
	return nil
}

// detectVault checks for HashiCorp Vault API exposure and unauthenticated secret access.
func detectVault(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	// Step 1: Check seal status — this confirms it's Vault and reveals operational state.
	body, ok := probeHTTPBody(ctx, host, port, false, "/v1/sys/seal-status")
	if !ok {
		body, ok = probeHTTPBody(ctx, host, port, true, "/v1/sys/seal-status")
	}
	if !ok {
		return nil
	}

	lb := strings.ToLower(body)
	if !strings.Contains(lb, "sealed") || !strings.Contains(lb, "cluster_name") {
		return nil
	}

	ev := map[string]any{"port": port, "service": "vault", "banner": banner}

	// Extract version and seal status.
	isSealed := strings.Contains(body, `"sealed":true`)
	isUnsealed := strings.Contains(body, `"sealed":false`)
	if idx := strings.Index(body, `"version":"`); idx > 0 {
		end := strings.Index(body[idx+11:], `"`)
		if end > 0 {
			ev["version"] = body[idx+11 : idx+11+end]
		}
	}
	ev["sealed"] = isSealed

	var findings []finding.Finding

	// Always report Vault exposure as a fingerprint finding.
	findings = append(findings, makeF(
		finding.CheckPortVaultExposed,
		finding.SeverityHigh,
		fmt.Sprintf("HashiCorp Vault API exposed on port %d", port),
		"A HashiCorp Vault server is publicly accessible. Vault stores secrets, encryption "+
			"keys, and database credentials. Even if authentication is required, exposing Vault "+
			"to the internet increases the attack surface for brute-force, CVE exploitation, and "+
			"seal/unseal manipulation. Restrict to internal networks via firewall rules.",
		ev,
	))

	// Step 2: If unsealed, try to read secrets without authentication.
	if isUnsealed {
		ev["sealed"] = false
		// Try listing secret engines.
		mountsBody, mountsOk := probeHTTPBody(ctx, host, port, false, "/v1/sys/mounts")
		if !mountsOk {
			mountsBody, mountsOk = probeHTTPBody(ctx, host, port, true, "/v1/sys/mounts")
		}
		if mountsOk && strings.Contains(mountsBody, "secret/") {
			ev["unauthenticated_mounts"] = true
			findings = append(findings, makeF(
				finding.CheckPortVaultUnsealedNoAuth,
				finding.SeverityCritical,
				fmt.Sprintf("HashiCorp Vault on port %d is unsealed and secrets are readable without authentication", port),
				"The Vault server is unsealed and its secret engine mount listing is accessible "+
					"without any authentication token. This means secrets can be read, written, "+
					"and deleted by any network-reachable attacker. This is a critical finding "+
					"that requires immediate remediation: enable authentication, seal the vault, "+
					"and rotate all stored secrets.",
				ev,
			))
		}
	}

	return findings
}

// detectJBoss checks for JBoss/WildFly management console and REST API exposure.
func detectJBoss(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	ev := map[string]any{"port": port, "service": "jboss", "banner": banner}

	// Check the management REST API (port 9990 by default).
	body, ok := probeHTTPBody(ctx, host, port, false, "/management")
	if !ok {
		body, ok = probeHTTPBody(ctx, host, port, true, "/management")
	}
	if ok && (strings.Contains(body, "product-name") || strings.Contains(body, "release-version")) {
		// Extract product name and version.
		if idx := strings.Index(body, `"product-name"`); idx >= 0 {
			sub := body[idx:]
			if qi := strings.Index(sub, `": "`); qi > 0 {
				end := strings.Index(sub[qi+4:], `"`)
				if end > 0 {
					ev["product"] = sub[qi+4 : qi+4+end]
				}
			}
		}
		if idx := strings.Index(body, `"release-version"`); idx >= 0 {
			sub := body[idx:]
			if qi := strings.Index(sub, `": "`); qi > 0 {
				end := strings.Index(sub[qi+4:], `"`)
				if end > 0 {
					ev["version"] = sub[qi+4 : qi+4+end]
				}
			}
		}

		return []finding.Finding{makeF(
			finding.CheckPortJBossManagementExposed,
			finding.SeverityHigh,
			fmt.Sprintf("JBoss/WildFly management API exposed on port %d", port),
			"The JBoss/WildFly application server management REST API is publicly accessible "+
				"without authentication. The management API allows deploying applications, reading "+
				"server configuration, and executing operations. Historically, unauthenticated JBoss "+
				"management access has been exploited for remote code execution (CVE-2010-0738, "+
				"CVE-2015-7501). Restrict management access to localhost or a management network.",
			ev,
		)}
	}

	// Check the web console at /console.
	body, ok = probeHTTPBody(ctx, host, port, false, "/console/App.html")
	if !ok {
		body, ok = probeHTTPBody(ctx, host, port, true, "/console/App.html")
	}
	if ok {
		lb := strings.ToLower(body)
		if strings.Contains(lb, "wildfly") || strings.Contains(lb, "jboss") ||
			strings.Contains(lb, "hal management console") || strings.Contains(lb, "management console") {
			return []finding.Finding{makeF(
				finding.CheckPortJBossManagementExposed,
				finding.SeverityHigh,
				fmt.Sprintf("JBoss/WildFly management console exposed on port %d", port),
				"The JBoss/WildFly HAL Management Console web interface is publicly accessible. "+
					"The console provides full application server management capabilities including "+
					"deploying WAR files, configuring datasources, and managing security domains. "+
					"Restrict to localhost or a management network.",
				ev,
			)}
		}
	}

	return nil
}

// detectColdFusion checks for Adobe ColdFusion administrator panel exposure.
func detectColdFusion(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	ev := map[string]any{"port": port, "service": "coldfusion", "banner": banner}

	// Adobe ColdFusion admin paths.
	paths := []string{"/CFIDE/administrator/", "/CFIDE/administrator/index.cfm", "/CFIDE/main/ide.cfm"}

	for _, path := range paths {
		body, ok := probeHTTPBody(ctx, host, port, false, path)
		if !ok {
			body, ok = probeHTTPBody(ctx, host, port, true, path)
		}
		if !ok {
			continue
		}
		lb := strings.ToLower(body)
		if strings.Contains(lb, "coldfusion") || strings.Contains(lb, "cfide") ||
			strings.Contains(lb, "adobe") && strings.Contains(lb, "administrator") {
			if idx := strings.Index(lb, "version"); idx >= 0 {
				snippet := body[idx:min(idx+40, len(body))]
				ev["version_hint"] = snippet
			}

			return []finding.Finding{makeF(
				finding.CheckPortColdFusionAdminExposed,
				finding.SeverityHigh,
				fmt.Sprintf("Adobe ColdFusion administrator panel exposed on port %d", port),
				"The Adobe ColdFusion administrator panel (/CFIDE/administrator/) is publicly "+
					"accessible. ColdFusion has a history of critical pre-authentication RCE "+
					"vulnerabilities (CVE-2023-26360 KEV, CVE-2023-29298). Exposing the admin "+
					"panel increases the attack surface for brute-force, credential stuffing, and "+
					"CVE exploitation. Restrict /CFIDE/ to internal networks.",
				ev,
			)}
		}
	}

	// Lucee (open-source CFML engine) admin paths.
	luceePaths := []string{"/lucee/admin/server.cfm", "/lucee/admin/web.cfm"}
	for _, path := range luceePaths {
		body, ok := probeHTTPBody(ctx, host, port, false, path)
		if !ok {
			body, ok = probeHTTPBody(ctx, host, port, true, path)
		}
		if !ok {
			continue
		}
		lb := strings.ToLower(body)
		// Require "lucee" specifically — "password" + "login" matches any login page.
		if strings.Contains(lb, "lucee") {
			ev["service"] = "lucee"
			return []finding.Finding{makeF(
				finding.CheckPortColdFusionAdminExposed,
				finding.SeverityHigh,
				fmt.Sprintf("Lucee CFML administrator panel exposed on port %d", port),
				"The Lucee Server administrator panel (/lucee/admin/) is publicly accessible. "+
					"Lucee is an open-source CFML engine with similar attack surface to Adobe "+
					"ColdFusion. The admin panel allows server configuration, datasource management, "+
					"and extension installation. Restrict /lucee/admin/ to internal networks.",
				ev,
			)}
		}
	}

	return nil
}

func detectApacheTika(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	body, ok := probeHTTPBody(ctx, host, port, false, "/version")
	if !ok {
		return nil
	}
	// Tika /version returns plain-text like "Apache Tika 1.17" or just "1.17".
	// Many other services expose /version as JSON or HTML — reject those.
	trimmed := strings.TrimSpace(body)
	if strings.HasPrefix(trimmed, "<") || strings.HasPrefix(trimmed, "{") ||
		strings.HasPrefix(trimmed, "[") || len(trimmed) > 100 {
		return nil
	}
	// Positive match: must contain "tika" or look like a bare semver (digits and dots only).
	lowerTrimmed := strings.ToLower(trimmed)
	isTika := strings.Contains(lowerTrimmed, "tika")
	if !isTika {
		// Check for bare semver like "1.17" or "2.9.1" — no spaces, no letters except dots.
		clean := strings.ReplaceAll(trimmed, ".", "")
		for _, c := range clean {
			if c < '0' || c > '9' {
				return nil // Contains non-digit/dot characters — not a Tika version
			}
		}
	}
	ev := map[string]any{"port": port, "service": "tika", "banner": banner}
	tikaVer := trimmed
	if strings.HasPrefix(strings.ToLower(tikaVer), "apache tika ") {
		tikaVer = tikaVer[len("apache tika "):]
	}
	ev["tika_version"] = tikaVer
	ev["version"] = tikaVer
	ev["product"] = "Apache Tika " + tikaVer
	if isApacheTikaRCEVulnerable(tikaVer) {
		return []finding.Finding{makeF(
			finding.CheckCVEApacheTikaRCE,
			finding.SeverityCritical,
			fmt.Sprintf("CVE-2018-1335: Apache Tika Server %s vulnerable to command injection RCE", tikaVer),
			fmt.Sprintf("Apache Tika Server %s is internet-accessible and vulnerable to CVE-2018-1335 (CVSS 9.8). "+
				"The X-Tika-OCRTesseractPath and X-Tika-OCRLanguage HTTP headers are passed unsanitized to "+
				"external process invocations (Tesseract OCR), enabling OS command injection via a PUT request "+
				"to /tika with Content-Type: image/jp2. Upgrade to Apache Tika Server ≥ 1.18 immediately and "+
				"restrict the Tika Server REST API to trusted internal networks.", tikaVer),
			ev,
		)}
	}
	// Tika found but version is safe or unknown — still flag exposure.
	return []finding.Finding{makeF(
		finding.CheckCVEApacheTikaRCE,
		finding.SeverityHigh,
		fmt.Sprintf("Apache Tika Server REST API exposed on port %d", port),
		"An Apache Tika Server REST API is internet-accessible without authentication. "+
			"Tika Server is a document parsing service not designed for direct internet exposure. "+
			"Verify the version is ≥ 1.18 (CVE-2018-1335 command injection) and restrict to internal networks.",
		ev,
	)}
}

func detectJaeger(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	// Jaeger /api/services returns JSON with service list.
	body, ok := probeHTTPBody(ctx, host, port, false, "/api/services")
	if !ok {
		return nil
	}
	trimmed := strings.TrimSpace(body)
	if !strings.HasPrefix(trimmed, "{") || !strings.Contains(body, "data") {
		return nil
	}
	ev := map[string]any{"port": port, "service": "jaeger", "banner": banner}
	// Try to extract Jaeger version from the homepage HTML (Jaeger UI embeds version in body).
	if homeBody, homeOK := probeHTTPBody(ctx, host, port, false, "/"); homeOK {
		if ver := parseJSONStringField(homeBody, "gitVersion"); ver != "" {
			ev["version"] = ver
			ev["product"] = "Jaeger " + ver
		} else if ver := parseJSONStringField(homeBody, "jaegerVersion"); ver != "" {
			ev["version"] = ver
			ev["product"] = "Jaeger " + ver
		}
	}
	return []finding.Finding{makeF(
		finding.CheckPortJaegerExposed,
		finding.SeverityHigh,
		fmt.Sprintf("Jaeger distributed tracing UI exposed without authentication on port %d", port),
		"Jaeger distributed tracing is publicly accessible without authentication. "+
			"Trace data reveals internal service architecture, request/response payloads, "+
			"error messages with stack traces, and HTTP headers which may contain auth tokens. "+
			"Restrict to internal networks and enable authentication.",
		ev,
	)}
}

func detectAdminer(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	body, ok := probeHTTPBody(ctx, host, port, false, "/")
	if !ok {
		return nil
	}
	if !strings.Contains(strings.ToLower(body), "adminer") {
		return nil
	}
	ev := map[string]any{"port": port, "service": "adminer", "banner": banner}
	// Extract Adminer version from <h1> tag like "Adminer 4.8.1" or title.
	if idx := strings.Index(strings.ToLower(body), "adminer"); idx >= 0 {
		rest := body[idx:]
		after := strings.TrimSpace(rest[len("adminer"):])
		ver := ""
		for _, c := range after {
			if (c >= '0' && c <= '9') || c == '.' {
				ver += string(c)
			} else if ver != "" {
				break
			}
		}
		if ver != "" && strings.Contains(ver, ".") {
			ev["version"] = strings.TrimRight(ver, ".")
			ev["product"] = "Adminer " + strings.TrimRight(ver, ".")
		}
	}
	return []finding.Finding{makeF(
		finding.CheckPortAdminerExposed,
		finding.SeverityCritical,
		fmt.Sprintf("Adminer database admin panel exposed on port %d", port),
		"Adminer is a full-featured PHP database management tool accessible without authentication. "+
			"It supports MySQL, PostgreSQL, SQLite, MSSQL, Oracle, and other databases. "+
			"CVE-2021-21311 (Adminer < 4.7.9) allows SSRF to exfiltrate MySQL credentials. "+
			"Adminer should never be publicly accessible.",
		ev,
	)}
}

func detectTomcat(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	// Tomcat may return 200 (default webapp) or 404 (no default webapp) on root.
	// Both responses contain "Apache Tomcat" in the body. Use probeHTTPAny to
	// get the body regardless of status code.
	body, ok := probeHTTPBody(ctx, host, port, false, "/")
	if !ok {
		// Try non-existent path — Tomcat's 404 page has "Apache Tomcat/VERSION".
		body, ok = probeHTTPAnyBody(ctx, host, port, false, "/nonexistent-beacon-probe")
		if !ok {
			return nil
		}
	}
	lb := strings.ToLower(body)
	if !strings.Contains(lb, "tomcat") && !strings.Contains(lb, "apache-coyote") {
		return nil
	}
	ev := map[string]any{"port": port, "service": "tomcat", "banner": banner}
	// Extract version from "Apache Tomcat/9.0.117" pattern.
	if idx := strings.Index(body, "Apache Tomcat/"); idx >= 0 {
		snippet := body[idx+len("Apache Tomcat/"):]
		if end := strings.IndexAny(snippet, "<\" \n\r"); end > 0 {
			ver := snippet[:end]
			ev["tomcat_version"] = ver
			ev["version"] = ver
			ev["product"] = "Apache Tomcat " + ver
		}
	}
	return []finding.Finding{makeF(
		finding.CheckPortTomcatExposed,
		finding.SeverityMedium,
		fmt.Sprintf("Apache Tomcat exposed on port %d", port),
		"An Apache Tomcat server is publicly accessible. If the Manager application "+
			"is enabled with default credentials (tomcat:tomcat), attackers can deploy "+
			"malicious WAR files for remote code execution.",
		ev,
	)}
}

func detectGoAnywhere(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	body, ok := probeHTTPBody(ctx, host, port, false, "/")
	if !ok {
		// GoAnywhere often redirects to /goanywhere/; try that too.
		body, ok = probeHTTPBody(ctx, host, port, false, "/goanywhere/")
		if !ok {
			return nil
		}
	}
	lb := strings.ToLower(body)
	if !strings.Contains(lb, "goanywhere") {
		return nil
	}

	ev := map[string]any{"port": port, "service": "goanywhere", "banner": banner}
	var findings []finding.Finding

	// Extract version from response if present (e.g., "GoAnywhere MFT v7.1.1").
	ver := ""
	for _, prefix := range []string{"GoAnywhere MFT v", "GoAnywhere MFT V", "goanywhere/", "version\":\""} {
		if idx := strings.Index(body, prefix); idx >= 0 {
			snippet := body[idx+len(prefix):]
			if end := strings.IndexAny(snippet, "\"<& \n\r,)"); end > 0 && end < 20 {
				ver = strings.TrimSpace(snippet[:end])
				break
			}
		}
	}
	if ver != "" {
		ev["version"] = ver
	}

	findings = append(findings, makeF(
		finding.CheckPortGoAnywhereExposed,
		finding.SeverityHigh,
		fmt.Sprintf("GoAnywhere MFT admin portal exposed on port %d", port),
		"Fortra GoAnywhere MFT file transfer platform is publicly accessible. "+
			"GoAnywhere has been targeted by CL0P ransomware via CVE-2023-0669 "+
			"(pre-auth deserialization RCE). The admin portal should be restricted "+
			"to internal networks with VPN access only.",
		ev,
	))

	// CVE-2023-0669: pre-auth RCE via License Response Servlet deserialization.
	// Affected: GoAnywhere MFT < 7.1.2.
	if ver != "" && isGoAnywhereVulnerable(ver) {
		findings = append(findings, makeF(
			finding.CheckCVEGoAnywhereRCE,
			finding.SeverityCritical,
			fmt.Sprintf("CVE-2023-0669: GoAnywhere MFT %s pre-auth RCE", ver),
			fmt.Sprintf("GoAnywhere MFT %s is vulnerable to CVE-2023-0669 (CVSS 7.2, KEV). "+
				"The License Response Servlet deserializes untrusted data, enabling "+
				"unauthenticated remote code execution. This CVE was actively exploited "+
				"by CL0P ransomware to exfiltrate data from 130+ organizations. "+
				"Upgrade to GoAnywhere MFT 7.1.2 or later immediately.", ver),
			ev,
		))
	}

	return findings
}

// ── Web framework / CMS / server fingerprinting probes ──────────────────

// detectJenkins identifies Jenkins CI servers via X-Jenkins header, dashboard title, or /api/json.
func detectJenkins(ctx context.Context, host string, port int, _ string, makeF findingMaker) []finding.Finding {
	useTLS := port == 443 || port == 8443
	body, hdrs, ok := probeHTTPBodyAndHeaders(ctx, host, port, useTLS, "/")
	if !ok {
		return nil
	}

	jenkinsHeader := hdrs.Get("X-Jenkins")
	bodyLow := strings.ToLower(body)
	isJenkins := jenkinsHeader != "" ||
		strings.Contains(bodyLow, "dashboard [jenkins]") ||
		strings.Contains(bodyLow, "jenkins-crumb")

	if !isJenkins {
		return nil
	}

	ev := map[string]any{"port": port, "service": "jenkins"}
	if jenkinsHeader != "" {
		ev["jenkins_version"] = jenkinsHeader
		ev["version"] = jenkinsHeader
		ev["product"] = "Jenkins " + jenkinsHeader
	}

	// Check if unauthenticated access works — try /api/json which exposes job listing.
	if apiBody, apiOK := probeHTTPBody(ctx, host, port, useTLS, "/api/json"); apiOK {
		apiLow := strings.ToLower(apiBody)
		if strings.Contains(apiLow, "\"jobs\"") || strings.Contains(apiLow, "\"primaryview\"") {
			ev["unauthenticated_api"] = true
			ev["proof"] = fmt.Sprintf("curl -sk %s://%s:%d/api/json", scheme(useTLS), host, port)
			return []finding.Finding{makeF(
				finding.CheckPortJenkinsNoAuth,
				finding.SeverityCritical,
				fmt.Sprintf("Jenkins CI server allows unauthenticated access on port %d", port),
				"Jenkins is publicly accessible without authentication. The JSON API exposes all jobs, "+
					"build configurations, and credentials. Jenkins with anonymous read access often also "+
					"exposes the Groovy script console (/script) for unauthenticated RCE. "+
					"Enable Jenkins security realm and restrict anonymous access immediately.",
				ev,
			)}
		}
	}

	ev["proof"] = fmt.Sprintf("curl -sI %s://%s:%d/ | grep -i x-jenkins", scheme(useTLS), host, port)
	return []finding.Finding{makeF(
		finding.CheckPortServiceIdentified,
		finding.SeverityInfo,
		fmt.Sprintf("Jenkins CI server detected on port %d", port),
		"A Jenkins continuous integration server is running. Verify that authentication is "+
			"enforced and that the script console is not accessible to unauthenticated users.",
		ev,
	)}
}

// detectWordPress identifies WordPress installations via wp-login.php, wp-content, or wp-includes.
func detectWordPress(ctx context.Context, host string, port int, _ string, makeF findingMaker) []finding.Finding {
	useTLS := port == 443
	// First check the homepage for WordPress fingerprints.
	body, ok := probeHTTPAnyBody(ctx, host, port, useTLS, "/")
	if ok {
		bodyLow := strings.ToLower(body)
		if strings.Contains(bodyLow, "wp-content") || strings.Contains(bodyLow, "wp-includes") ||
			strings.Contains(bodyLow, "wordpress") {
			return wpFinding(host, port, useTLS, makeF)
		}
	}
	// Fall back to probing wp-login.php directly.
	if loginBody, loginOK := probeHTTPAnyBody(ctx, host, port, useTLS, "/wp-login.php"); loginOK {
		if strings.Contains(strings.ToLower(loginBody), "wordpress") ||
			strings.Contains(strings.ToLower(loginBody), "wp-login") {
			return wpFinding(host, port, useTLS, makeF)
		}
	}
	return nil
}

func wpFinding(host string, port int, useTLS bool, makeF findingMaker) []finding.Finding {
	ev := map[string]any{
		"port":    port,
		"service": "wordpress",
		"proof":   fmt.Sprintf("curl -sk %s://%s:%d/ | grep -i wp-content", scheme(useTLS), host, port),
	}

	// Extract WordPress version from generator meta tag on homepage.
	wpVersion := ""
	if body, ok := probeHTTPAnyBody(context.Background(), host, port, useTLS, "/"); ok {
		wpVersion = parseWPVersionFromBody(body)
	}
	if wpVersion != "" {
		ev["version"] = wpVersion
		ev["product"] = "WordPress " + wpVersion
	}

	var findings []finding.Finding

	// Check /wp-json/ REST API accessibility.
	if apiBody, apiOK := probeHTTPAnyBody(context.Background(), host, port, useTLS, "/wp-json/"); apiOK {
		apiLow := strings.ToLower(apiBody)
		if strings.Contains(apiLow, "wp/v2") || strings.Contains(apiLow, "\"namespaces\"") {
			ev["rest_api_accessible"] = true
		}
	}

	// Check /xmlrpc.php accessibility.
	// WordPress XML-RPC returns "XML-RPC server accepts POST requests only" or
	// contains "xmlrpc" in a WordPress-specific context. Exclude S3-style XML
	// error responses that contain the path name in <BucketName>.
	if xmlBody, xmlOK := probeHTTPAnyBody(context.Background(), host, port, useTLS, "/xmlrpc.php"); xmlOK {
		xmlLow := strings.ToLower(xmlBody)
		isWPXMLRPC := (strings.Contains(xmlLow, "xml-rpc server accepts post requests only") ||
			strings.Contains(xmlLow, "xml-rpc") && strings.Contains(xmlLow, "wordpress")) &&
			!strings.Contains(xmlLow, "<bucketname>") // exclude S3 XML errors
		if isWPXMLRPC {
			ev["xmlrpc_accessible"] = true
			findings = append(findings, makeF(
				finding.CheckPortWordPressXMLRPCExposed,
				finding.SeverityHigh,
				fmt.Sprintf("WordPress XML-RPC enabled on port %d — brute force and SSRF risk", port),
				"The WordPress XML-RPC endpoint (/xmlrpc.php) is accessible. XML-RPC enables "+
					"amplified brute-force attacks (system.multicall), pingback SSRF for internal "+
					"network scanning, and DDoS amplification. Disable XML-RPC or restrict access.",
				map[string]any{
					"port":    port,
					"service": "wordpress",
					"proof":   fmt.Sprintf("curl -sk %s://%s:%d/xmlrpc.php", scheme(useTLS), host, port),
				},
			))
		}
	}

	// Check /wp-login.php accessibility.
	if loginBody, loginOK := probeHTTPAnyBody(context.Background(), host, port, useTLS, "/wp-login.php"); loginOK {
		loginLow := strings.ToLower(loginBody)
		if strings.Contains(loginLow, "wp-login") || strings.Contains(loginLow, "wordpress") {
			ev["login_page_accessible"] = true
		}
	}

	desc := "A WordPress installation is running. "
	if wpVersion != "" {
		desc += fmt.Sprintf("Detected version: %s. ", wpVersion)
	}
	desc += "WordPress is the most targeted CMS on the internet. " +
		"Check for outdated core/plugins/themes, exposed wp-login.php (brute-force target), " +
		"XML-RPC (/xmlrpc.php), REST API user enumeration (/wp-json/wp/v2/users), and " +
		"debug.log exposure (/wp-content/debug.log)."

	findings = append(findings, makeF(
		finding.CheckPortWordPressDetected,
		finding.SeverityInfo,
		fmt.Sprintf("WordPress CMS detected on port %d", port),
		desc,
		ev,
	))
	return findings
}

// parseWPVersionFromBody extracts the WordPress version from the generator meta tag
// or from wp-includes version references in the HTML body.
func parseWPVersionFromBody(body string) string {
	// Look for <meta name="generator" content="WordPress X.Y.Z" />
	bodyLow := strings.ToLower(body)
	if idx := strings.Index(bodyLow, "wordpress"); idx >= 0 {
		// Find the version number after "WordPress "
		rest := body[idx:]
		if wpIdx := strings.Index(strings.ToLower(rest), "wordpress"); wpIdx >= 0 {
			after := strings.TrimSpace(rest[wpIdx+9:])
			ver := ""
			for _, c := range after {
				if (c >= '0' && c <= '9') || c == '.' {
					ver += string(c)
				} else if ver != "" {
					break
				}
			}
			if ver != "" && strings.Contains(ver, ".") {
				return strings.TrimRight(ver, ".")
			}
		}
	}
	// Look for ?ver=X.Y.Z in wp-includes or wp-content references.
	for _, marker := range []string{"wp-includes", "wp-content"} {
		if idx := strings.Index(bodyLow, marker); idx >= 0 {
			rest := body[idx:]
			if verIdx := strings.Index(rest, "?ver="); verIdx >= 0 && verIdx < 200 {
				after := rest[verIdx+5:]
				ver := ""
				for _, c := range after {
					if (c >= '0' && c <= '9') || c == '.' {
						ver += string(c)
					} else if ver != "" {
						break
					}
				}
				if ver != "" && strings.Contains(ver, ".") {
					return strings.TrimRight(ver, ".")
				}
			}
		}
	}
	return ""
}

// parseGeneratorVersion extracts a version number from a <meta name="generator"> tag
// whose content starts with the given product name (case-insensitive).
// Example: <meta name="generator" content="Joomla! 4.3.2" /> → "4.3.2"
func parseGeneratorVersion(body, product string) string {
	bodyLow := strings.ToLower(body)
	productLow := strings.ToLower(product)
	// Look for generator meta tag containing the product name.
	genIdx := strings.Index(bodyLow, "generator")
	if genIdx < 0 {
		return ""
	}
	// Find the product name after the generator tag.
	rest := bodyLow[genIdx:]
	pIdx := strings.Index(rest, productLow)
	if pIdx < 0 {
		return ""
	}
	after := body[genIdx+pIdx+len(product):]
	// Skip non-digit prefix (e.g. "! " in "Joomla! 4.3.2").
	ver := ""
	started := false
	for _, c := range after {
		if (c >= '0' && c <= '9') || c == '.' {
			ver += string(c)
			started = true
		} else if started {
			break
		}
		// Stop scanning if we hit tag boundary.
		if c == '"' || c == '<' || c == '>' {
			break
		}
	}
	if ver != "" && strings.Contains(ver, ".") {
		return strings.TrimRight(ver, ".")
	}
	return ""
}

// parseXMLVersion extracts version from a <version>X.Y.Z</version> XML tag.
func parseXMLVersion(body string) string {
	bodyLow := strings.ToLower(body)
	const tag = "<version>"
	const endTag = "</version>"
	idx := strings.Index(bodyLow, tag)
	if idx < 0 {
		return ""
	}
	rest := body[idx+len(tag):]
	end := strings.Index(strings.ToLower(rest), endTag)
	if end < 0 || end > 30 {
		return ""
	}
	ver := strings.TrimSpace(rest[:end])
	if strings.Contains(ver, ".") {
		return ver
	}
	return ""
}

// detectDrupal identifies Drupal via X-Drupal-Cache header, Drupal.settings in body, or drupal.js.
// Enhanced: extracts version from CHANGELOG.txt, X-Generator header, and checks /core/install.php.
func detectDrupal(ctx context.Context, host string, port int, _ string, makeF findingMaker) []finding.Finding {
	useTLS := port == 443
	body, hdrs, ok := probeHTTPBodyAndHeaders(ctx, host, port, useTLS, "/")
	if !ok {
		return nil
	}

	drupalCache := hdrs.Get("X-Drupal-Cache")
	xGen := hdrs.Get("X-Generator")
	bodyLow := strings.ToLower(body)
	isDrupal := drupalCache != "" ||
		strings.Contains(strings.ToLower(xGen), "drupal") ||
		strings.Contains(bodyLow, "drupal.settings") ||
		strings.Contains(bodyLow, "/core/misc/drupal.js") ||
		strings.Contains(bodyLow, "/misc/drupal.js")

	if !isDrupal {
		return nil
	}
	ev := map[string]any{
		"port":    port,
		"service": "drupal",
		"proof":   fmt.Sprintf("curl -sI %s://%s:%d/ | grep -i x-drupal", scheme(useTLS), host, port),
	}
	if xGen != "" {
		ev["x_generator"] = xGen
	}

	// Extract Drupal version from X-Generator header (e.g. "Drupal 10 (https://www.drupal.org)").
	drupalVersion := ""
	if xGen != "" {
		xgl := strings.ToLower(xGen)
		if idx := strings.Index(xgl, "drupal"); idx >= 0 {
			rest := strings.TrimSpace(xGen[idx+6:])
			if spIdx := strings.IndexAny(rest, " ("); spIdx > 0 {
				drupalVersion = strings.TrimSpace(rest[:spIdx])
			} else if rest != "" {
				drupalVersion = rest
			}
		}
	}

	// Try CHANGELOG.txt for exact version (Drupal 7 and older).
	if drupalVersion == "" {
		if clBody, clOK := probeHTTPAnyBody(ctx, host, port, useTLS, "/CHANGELOG.txt"); clOK {
			drupalVersion = parseDrupalChangelog(clBody)
		}
	}

	// Try /core/install.php accessibility (Drupal 8+).
	installAccessible := false
	if instBody, instOK := probeHTTPAnyBody(ctx, host, port, useTLS, "/core/install.php"); instOK {
		if strings.Contains(strings.ToLower(instBody), "drupal") {
			installAccessible = true
			ev["install_php_accessible"] = true
		}
	}

	if drupalVersion != "" {
		ev["version"] = drupalVersion
		ev["product"] = "Drupal " + drupalVersion
	}

	desc := "A Drupal installation is running. "
	if drupalVersion != "" {
		desc += fmt.Sprintf("Detected version: %s. ", drupalVersion)
	}
	if installAccessible {
		desc += "The installer at /core/install.php is publicly accessible, which may allow reinstallation. "
	}
	desc += "Drupal has a history of critical RCE vulnerabilities " +
		"(Drupalgeddon SA-CORE-2014-005, Drupalgeddon2 CVE-2018-7600/7602). " +
		"Verify Drupal core and contributed modules are fully patched."

	return []finding.Finding{makeF(
		finding.CheckPortDrupalDetected,
		finding.SeverityInfo,
		fmt.Sprintf("Drupal CMS detected on port %d", port),
		desc,
		ev,
	)}
}

// parseDrupalChangelog extracts the version from a Drupal CHANGELOG.txt file.
// Looks for patterns like "Drupal 7.95" or "Drupal 10.2.5" in the first few lines.
func parseDrupalChangelog(body string) string {
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		if len(lines) > 20 {
			break
		}
		ll := strings.ToLower(line)
		if idx := strings.Index(ll, "drupal"); idx >= 0 {
			rest := strings.TrimSpace(line[idx+6:])
			// Extract version number (digits and dots).
			ver := ""
			for _, c := range rest {
				if (c >= '0' && c <= '9') || c == '.' {
					ver += string(c)
				} else if ver != "" {
					break
				}
			}
			if ver != "" && strings.Contains(ver, ".") {
				return strings.TrimRight(ver, ".")
			}
		}
	}
	return ""
}

// detectJoomla identifies Joomla via /administrator/ or /media/jui/ references in the homepage.
func detectJoomla(ctx context.Context, host string, port int, _ string, makeF findingMaker) []finding.Finding {
	useTLS := port == 443
	body, ok := probeHTTPAnyBody(ctx, host, port, useTLS, "/")
	if !ok {
		return nil
	}
	bodyLow := strings.ToLower(body)
	isJoomla := strings.Contains(bodyLow, "/media/jui/") ||
		strings.Contains(bodyLow, "joomla") ||
		strings.Contains(bodyLow, "/administrator/")

	if !isJoomla {
		// Try /administrator/ directly.
		if adminBody, adminOK := probeHTTPAnyBody(ctx, host, port, useTLS, "/administrator/"); adminOK {
			adminLow := strings.ToLower(adminBody)
			if strings.Contains(adminLow, "joomla") {
				isJoomla = true
			}
		}
	}
	if !isJoomla {
		return nil
	}
	ev := map[string]any{
		"port":    port,
		"service": "joomla",
		"proof":   fmt.Sprintf("curl -sk %s://%s:%d/administrator/", scheme(useTLS), host, port),
	}
	// Extract Joomla version from <meta name="generator" content="Joomla! X.Y.Z" />
	// in the already-fetched homepage body.
	if ver := parseGeneratorVersion(body, "joomla"); ver != "" {
		ev["version"] = ver
	} else {
		// Try /administrator/manifests/files/joomla.xml which contains <version>X.Y.Z</version>.
		if xmlBody, xmlOK := probeHTTPAnyBody(ctx, host, port, useTLS, "/administrator/manifests/files/joomla.xml"); xmlOK {
			if v := parseXMLVersion(xmlBody); v != "" {
				ev["version"] = v
			}
		}
	}
	return []finding.Finding{makeF(
		finding.CheckPortJoomlaDetected,
		finding.SeverityInfo,
		fmt.Sprintf("Joomla CMS detected on port %d", port),
		"A Joomla installation is running. Check for outdated core/extensions and exposed "+
			"/administrator/ login. CVE-2015-8562 (PHP object injection via User-Agent) and "+
			"CVE-2023-23752 (unauthenticated info disclosure) are common Joomla attack vectors.",
		ev,
	)}
}

// detectGhost identifies Ghost CMS via /ghost/api/ or ghost- meta tags in HTML.
func detectGhost(ctx context.Context, host string, port int, _ string, makeF findingMaker) []finding.Finding {
	useTLS := port == 443
	body, ok := probeHTTPAnyBody(ctx, host, port, useTLS, "/")
	if !ok {
		return nil
	}
	bodyLow := strings.ToLower(body)
	// Require stronger Ghost CMS fingerprints to avoid false positives on
	// pages that happen to contain "ghost-" in CSS class names.
	isGhost := strings.Contains(bodyLow, "content=\"ghost") ||
		strings.Contains(bodyLow, "ghost.org") ||
		strings.Contains(bodyLow, "ghost-signup") ||
		strings.Contains(bodyLow, "ghost-portal")

	if !isGhost {
		// Try the Ghost API endpoint.
		if apiBody, apiOK := probeHTTPAnyBody(ctx, host, port, useTLS, "/ghost/api/v4/admin/site/"); apiOK {
			if strings.Contains(strings.ToLower(apiBody), "ghost") ||
				strings.Contains(apiBody, "\"title\"") {
				isGhost = true
			}
		}
	}
	if !isGhost {
		return nil
	}
	ev := map[string]any{
		"port":    port,
		"service": "ghost",
		"proof":   fmt.Sprintf("curl -sk %s://%s:%d/ | grep -i ghost", scheme(useTLS), host, port),
	}
	// Extract Ghost version from meta generator tag or API response body.
	if ver := parseGhostVersion(body); ver != "" {
		ev["version"] = ver
		ev["product"] = "Ghost " + ver
	}
	return []finding.Finding{makeF(
		finding.CheckPortGhostDetected,
		finding.SeverityInfo,
		fmt.Sprintf("Ghost CMS detected on port %d", port),
		"A Ghost publishing platform is running. Verify the Ghost admin panel (/ghost/) is "+
			"not publicly accessible without authentication and that the Ghost version is current.",
		ev,
	)}
}

// detectNextcloud identifies Nextcloud via /status.php JSON response.
func detectNextcloud(ctx context.Context, host string, port int, _ string, makeF findingMaker) []finding.Finding {
	useTLS := port == 443
	body, ok := probeHTTPBody(ctx, host, port, useTLS, "/status.php")
	if !ok {
		return nil
	}
	bodyLow := strings.ToLower(body)
	if !strings.Contains(bodyLow, "\"installed\"") || !strings.Contains(bodyLow, "\"version\"") {
		return nil
	}
	ev := map[string]any{
		"port":    port,
		"service": "nextcloud",
		"proof":   fmt.Sprintf("curl -sk %s://%s:%d/status.php", scheme(useTLS), host, port),
	}
	if ver := parseJSONStringField(body, "versionstring"); ver != "" {
		ev["nextcloud_version"] = ver
		ev["version"] = ver
	}
	return []finding.Finding{makeF(
		finding.CheckPortNextcloudDetected,
		finding.SeverityInfo,
		fmt.Sprintf("Nextcloud detected on port %d", port),
		"A Nextcloud file sync and collaboration platform is running. Nextcloud exposes "+
			"user data, files, calendars, and contacts. Verify the instance is fully patched "+
			"and that /status.php does not leak version information to unauthenticated users.",
		ev,
	)}
}

// detectSpringBoot identifies Spring Boot Actuator endpoints (/actuator, /actuator/health).
func detectSpringBoot(ctx context.Context, host string, port int, _ string, makeF findingMaker) []finding.Finding {
	useTLS := port == 443 || port == 8443
	body, ok := probeHTTPBody(ctx, host, port, useTLS, "/actuator")
	if !ok {
		// Some deployments serve actuator on management port only.
		return nil
	}
	bodyLow := strings.ToLower(body)
	if !strings.Contains(bodyLow, "_links") && !strings.Contains(bodyLow, "\"self\"") {
		return nil
	}

	ev := map[string]any{
		"port":    port,
		"service": "spring-boot-actuator",
		"proof":   fmt.Sprintf("curl -sk %s://%s:%d/actuator", scheme(useTLS), host, port),
	}

	// Extract Spring Boot version from /actuator/info if available.
	if infoBody, infoOK := probeHTTPBody(ctx, host, port, useTLS, "/actuator/info"); infoOK {
		if ver := parseJSONStringField(infoBody, "version"); ver != "" {
			ev["version"] = ver
		}
	}

	// Check which sensitive endpoints are exposed.
	exposed := []string{}
	for _, ep := range []string{"env", "configprops", "beans", "mappings", "heapdump", "threaddump"} {
		if strings.Contains(bodyLow, ep) {
			exposed = append(exposed, ep)
		}
	}
	if len(exposed) > 0 {
		ev["exposed_endpoints"] = exposed
	}

	sev := finding.SeverityHigh
	detail := "Spring Boot Actuator endpoints are publicly accessible. "
	if len(exposed) > 0 {
		detail += fmt.Sprintf("Exposed endpoints include: %s. ", strings.Join(exposed, ", "))
	}
	detail += "The /actuator/env endpoint leaks environment variables and secrets. " +
		"/actuator/heapdump contains JVM memory with credentials and session tokens. " +
		"Restrict actuator endpoints to management networks using management.server.port " +
		"and Spring Security endpoint protection."

	return []finding.Finding{makeF(
		finding.CheckPortSpringActuatorExposed,
		sev,
		fmt.Sprintf("Spring Boot Actuator exposed on port %d", port),
		detail,
		ev,
	)}
}

// detectDjango identifies Django via debug page signatures or /admin/ login page.
func detectDjango(ctx context.Context, host string, port int, _ string, makeF findingMaker) []finding.Finding {
	useTLS := port == 443
	body, ok := probeHTTPAnyBody(ctx, host, port, useTLS, "/")
	if ok {
		bodyLow := strings.ToLower(body)
		// Django debug mode shows a distinctive page.
		if strings.Contains(bodyLow, "you're seeing this message because") &&
			strings.Contains(bodyLow, "django") {
			ev := map[string]any{
				"port":       port,
				"service":    "django",
				"debug_mode": true,
				"proof":      fmt.Sprintf("curl -sk %s://%s:%d/", scheme(useTLS), host, port),
			}
			// Extract Django version from debug page text like "Django Version: 4.2.1"
			if idx := strings.Index(bodyLow, "django version"); idx >= 0 {
				after := body[idx:]
				ver := ""
				inVer := false
				for _, c := range after {
					if (c >= '0' && c <= '9') || c == '.' {
						ver += string(c)
						inVer = true
					} else if inVer {
						break
					}
				}
				if ver != "" && strings.Contains(ver, ".") {
					ev["version"] = strings.TrimRight(ver, ".")
				}
			}
			return []finding.Finding{makeF(
				finding.CheckPortDjangoDetected,
				finding.SeverityMedium,
				fmt.Sprintf("Django debug mode detected on port %d", port),
				"Django is running with DEBUG=True, exposing detailed error pages with settings, "+
					"installed apps, middleware, URL patterns, and database configuration to any visitor. "+
					"Set DEBUG=False in production immediately.",
				ev,
			)}
		}
	}

	// Check /admin/ for Django admin login.
	if adminBody, adminOK := probeHTTPAnyBody(ctx, host, port, useTLS, "/admin/"); adminOK {
		adminLow := strings.ToLower(adminBody)
		if strings.Contains(adminLow, "django administration") ||
			strings.Contains(adminLow, "django") && strings.Contains(adminLow, "csrfmiddlewaretoken") {
			return []finding.Finding{makeF(
				finding.CheckPortDjangoDetected,
				finding.SeverityInfo,
				fmt.Sprintf("Django web framework detected on port %d", port),
				"A Django application with the admin interface is running. The Django admin login "+
					"page is accessible. Ensure strong credentials, enforce 2FA, and consider restricting "+
					"/admin/ to internal networks.",
				map[string]any{
					"port":    port,
					"service": "django",
					"proof":   fmt.Sprintf("curl -sk %s://%s:%d/admin/", scheme(useTLS), host, port),
				},
			)}
		}
	}
	return nil
}

// detectLaravel identifies Laravel via laravel_session cookie or X-Powered-By header.
func detectLaravel(ctx context.Context, host string, port int, _ string, makeF findingMaker) []finding.Finding {
	useTLS := port == 443
	_, hdrs, ok := probeHTTPBodyAndHeaders(ctx, host, port, useTLS, "/")
	if !ok {
		return nil
	}

	isLaravel := false
	// Check X-Powered-By header.
	if pw := hdrs.Get("X-Powered-By"); strings.Contains(strings.ToLower(pw), "laravel") {
		isLaravel = true
	}
	// Check Set-Cookie for laravel_session.
	if !isLaravel {
		for _, c := range hdrs.Values("Set-Cookie") {
			if strings.Contains(strings.ToLower(c), "laravel_session") {
				isLaravel = true
				break
			}
		}
	}
	if !isLaravel {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortLaravelDetected,
		finding.SeverityInfo,
		fmt.Sprintf("Laravel PHP framework detected on port %d", port),
		"A Laravel application is running. Check that APP_DEBUG is false, APP_KEY is rotated, "+
			"and that /.env is not accessible. Laravel debug mode (Ignition) has been exploited via "+
			"CVE-2021-3129 for unauthenticated RCE.",
		map[string]any{
			"port":    port,
			"service": "laravel",
			"proof":   fmt.Sprintf("curl -sI %s://%s:%d/ | grep -i laravel", scheme(useTLS), host, port),
		},
	)}
}

// detectExpressJS identifies Express.js via X-Powered-By: Express header.
func detectExpressJS(ctx context.Context, host string, port int, _ string, makeF findingMaker) []finding.Finding {
	useTLS := port == 443
	_, hdrs, ok := probeHTTPBodyAndHeaders(ctx, host, port, useTLS, "/")
	if !ok {
		return nil
	}
	pw := hdrs.Get("X-Powered-By")
	if !strings.EqualFold(strings.TrimSpace(pw), "Express") {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortExpressDetected,
		finding.SeverityInfo,
		fmt.Sprintf("Express.js framework detected on port %d", port),
		"An Express.js (Node.js) application is running and leaking its framework identity "+
			"via the X-Powered-By header. Disable this header with app.disable('x-powered-by') "+
			"or use helmet.js to reduce fingerprinting surface.",
		map[string]any{
			"port":    port,
			"service": "express",
			"proof":   fmt.Sprintf("curl -sI %s://%s:%d/ | grep -i x-powered-by", scheme(useTLS), host, port),
		},
	)}
}

// detectASPNET identifies ASP.NET via X-AspNet-Version, X-Powered-By: ASP.NET, or .aspx in redirects.
func detectASPNET(ctx context.Context, host string, port int, _ string, makeF findingMaker) []finding.Finding {
	useTLS := port == 443
	body, hdrs, ok := probeHTTPBodyAndHeaders(ctx, host, port, useTLS, "/")
	if !ok {
		return nil
	}

	isASPNET := false
	ev := map[string]any{"port": port, "service": "aspnet"}

	if ver := hdrs.Get("X-AspNet-Version"); ver != "" {
		isASPNET = true
		ev["aspnet_version"] = ver
		ev["version"] = ver
		ev["product"] = "ASP.NET " + ver
	}
	if pw := hdrs.Get("X-Powered-By"); strings.Contains(strings.ToLower(pw), "asp.net") {
		isASPNET = true
	}
	if loc := hdrs.Get("Location"); strings.Contains(strings.ToLower(loc), ".aspx") {
		isASPNET = true
	}
	if strings.Contains(strings.ToLower(body), "__viewstate") {
		isASPNET = true
	}
	if !isASPNET {
		return nil
	}

	ev["proof"] = fmt.Sprintf("curl -sI %s://%s:%d/ | grep -i asp", scheme(useTLS), host, port)
	return []finding.Finding{makeF(
		finding.CheckPortASPNETDetected,
		finding.SeverityInfo,
		fmt.Sprintf("ASP.NET framework detected on port %d", port),
		"An ASP.NET application is running. The server leaks framework identity via response headers. "+
			"Remove X-AspNet-Version and X-Powered-By headers in production. Check for ViewState "+
			"deserialization vulnerabilities and exposed Trace.axd/Elmah.axd error endpoints.",
		ev,
	)}
}

// detectRails identifies Ruby on Rails via X-Runtime header, _rails_ cookies, or Rails error page.
func detectRails(ctx context.Context, host string, port int, _ string, makeF findingMaker) []finding.Finding {
	useTLS := port == 443
	body, hdrs, ok := probeHTTPBodyAndHeaders(ctx, host, port, useTLS, "/")
	if !ok {
		return nil
	}

	isRails := false
	ev := map[string]any{"port": port, "service": "rails"}

	// X-Runtime header is a strong Rails fingerprint.
	if rt := hdrs.Get("X-Runtime"); rt != "" {
		isRails = true
		ev["x_runtime"] = rt
	}
	// Check cookies for _rails_ session.
	if !isRails {
		for _, c := range hdrs.Values("Set-Cookie") {
			if strings.Contains(c, "_session") && strings.Contains(strings.ToLower(body), "rails") {
				isRails = true
				break
			}
		}
	}
	// Check for Rails error page.
	if !isRails {
		bodyLow := strings.ToLower(body)
		if strings.Contains(bodyLow, "rails") && strings.Contains(bodyLow, "routing error") {
			isRails = true
		}
	}
	if !isRails {
		return nil
	}

	ev["proof"] = fmt.Sprintf("curl -sI %s://%s:%d/ | grep -i x-runtime", scheme(useTLS), host, port)
	return []finding.Finding{makeF(
		finding.CheckPortRailsDetected,
		finding.SeverityInfo,
		fmt.Sprintf("Ruby on Rails detected on port %d", port),
		"A Ruby on Rails application is running. The X-Runtime header leaks framework identity "+
			"and can be used for timing attacks. Remove it in production via config.middleware.delete "+
			"Rack::Runtime. Check for CVE-2013-0156 (XML parsing RCE) on older versions.",
		ev,
	)}
}

// detectFastAPI identifies FastAPI via auto-generated /docs (Swagger UI) or /openapi.json.
func detectFastAPI(ctx context.Context, host string, port int, _ string, makeF findingMaker) []finding.Finding {
	useTLS := port == 443
	// FastAPI auto-generates /openapi.json — most reliable fingerprint.
	body, ok := probeHTTPBody(ctx, host, port, useTLS, "/openapi.json")
	if ok {
		bodyLow := strings.ToLower(body)
		if strings.Contains(bodyLow, "\"openapi\"") && strings.Contains(bodyLow, "\"paths\"") {
			ev := map[string]any{
				"port":    port,
				"service": "fastapi",
				"proof":   fmt.Sprintf("curl -sk %s://%s:%d/openapi.json", scheme(useTLS), host, port),
			}
			if title := parseJSONStringField(body, "title"); title != "" {
				ev["api_title"] = title
			}
			if ver := parseJSONStringField(body, "version"); ver != "" {
				ev["version"] = ver
				ev["product"] = "FastAPI " + ver
			}
			return []finding.Finding{makeF(
				finding.CheckPortFastAPIDetected,
				finding.SeverityInfo,
				fmt.Sprintf("FastAPI detected on port %d (OpenAPI spec exposed)", port),
				"A FastAPI application exposes its OpenAPI specification at /openapi.json and Swagger UI "+
					"at /docs. This reveals all API endpoints, parameters, and schemas. If this API handles "+
					"sensitive data, disable docs in production: app = FastAPI(docs_url=None, redoc_url=None, "+
					"openapi_url=None).",
				ev,
			)}
		}
	}

	// Fall back to /docs — FastAPI's default Swagger UI.
	if docsBody, docsOK := probeHTTPAnyBody(ctx, host, port, useTLS, "/docs"); docsOK {
		docsLow := strings.ToLower(docsBody)
		if strings.Contains(docsLow, "swagger") && strings.Contains(docsLow, "fastapi") {
			return []finding.Finding{makeF(
				finding.CheckPortFastAPIDetected,
				finding.SeverityInfo,
				fmt.Sprintf("FastAPI detected on port %d (Swagger UI at /docs)", port),
				"A FastAPI application with Swagger UI at /docs is running. The interactive API docs "+
					"expose all endpoints. Disable in production if not intended for public use.",
				map[string]any{
					"port":    port,
					"service": "fastapi",
					"proof":   fmt.Sprintf("curl -sk %s://%s:%d/docs", scheme(useTLS), host, port),
				},
			)}
		}
	}
	return nil
}

// scheme returns "https" if useTLS is true, "http" otherwise.
func scheme(useTLS bool) string {
	if useTLS {
		return "https"
	}
	return "http"
}

// detectMagento identifies Magento ecommerce platform via body content, headers, and known endpoints.
func detectMagento(ctx context.Context, host string, port int, _ string, makeF findingMaker) []finding.Finding {
	useTLS := port == 443
	body, hdrs, ok := probeHTTPBodyAndHeaders(ctx, host, port, useTLS, "/")
	if !ok {
		return nil
	}

	bodyLow := strings.ToLower(body)
	xMagentoVary := hdrs.Get("X-Magento-Vary")
	xMagentoCache := hdrs.Get("X-Magento-Cache-Control")
	isMagento := xMagentoVary != "" || xMagentoCache != "" ||
		strings.Contains(bodyLow, "mage.cookies") ||
		strings.Contains(bodyLow, "x-magento-") ||
		strings.Contains(bodyLow, "/static/version")

	if !isMagento {
		return nil
	}

	ev := map[string]any{
		"port":    port,
		"service": "magento",
		"proof":   fmt.Sprintf("curl -sk %s://%s:%d/ | grep -i magento", scheme(useTLS), host, port),
	}

	// Try /magento_version endpoint for exact version.
	if verBody, verOK := probeHTTPAnyBody(ctx, host, port, useTLS, "/magento_version"); verOK {
		ver := strings.TrimSpace(verBody)
		if len(ver) > 0 && len(ver) < 50 && !strings.Contains(strings.ToLower(ver), "<") {
			ev["version"] = ver
			ev["product"] = "Magento " + ver
		}
	}

	// Check for admin panel at common paths.
	for _, adminPath := range []string{"/admin", "/backend"} {
		if adminBody, adminOK := probeHTTPAnyBody(ctx, host, port, useTLS, adminPath); adminOK {
			adminLow := strings.ToLower(adminBody)
			if strings.Contains(adminLow, "magento") || strings.Contains(adminLow, "login") {
				ev["admin_panel_path"] = adminPath
				ev["admin_panel_accessible"] = true
				break
			}
		}
	}

	return []finding.Finding{makeF(
		finding.CheckPortMagentoDetected,
		finding.SeverityInfo,
		fmt.Sprintf("Magento ecommerce platform detected on port %d", port),
		"A Magento installation is running. Magento handles payment card data and has had "+
			"critical vulnerabilities including Magecart skimming attacks, Shoplift bug "+
			"(CVE-2015-1397), and various RCE flaws. Verify the installation is fully patched "+
			"and the admin panel is not publicly accessible.",
		ev,
	)}
}

// detectConfluence identifies Atlassian Confluence via /status endpoint, login page, and headers.
func detectConfluence(ctx context.Context, host string, port int, _ string, makeF findingMaker) []finding.Finding {
	useTLS := port == 443

	ev := map[string]any{
		"port":    port,
		"service": "confluence",
	}
	confluenceVersion := ""
	isConfluence := false

	// Check /status endpoint — returns JSON with {"state":"RUNNING","buildInfo":{"version":"..."}}.
	if statusBody, statusOK := probeHTTPAnyBody(ctx, host, port, useTLS, "/status"); statusOK {
		statusLow := strings.ToLower(statusBody)
		if strings.Contains(statusLow, "confluence") || strings.Contains(statusLow, "\"state\"") {
			isConfluence = true
			if ver := parseJSONStringField(statusBody, "version"); ver != "" {
				confluenceVersion = ver
			}
		}
	}

	// Check login page for Confluence branding.
	if !isConfluence {
		if loginBody, loginOK := probeHTTPAnyBody(ctx, host, port, useTLS, "/login.action"); loginOK {
			loginLow := strings.ToLower(loginBody)
			if strings.Contains(loginLow, "confluence") || strings.Contains(loginLow, "atlassian") {
				isConfluence = true
				// Try to extract version from login page footer.
				if ver := parseConfluenceVersionFromPage(loginBody); ver != "" && confluenceVersion == "" {
					confluenceVersion = ver
				}
			}
		}
	}

	// Check root page for Confluence indicators.
	if !isConfluence {
		if rootBody, _, rootOK := probeHTTPBodyAndHeaders(ctx, host, port, useTLS, "/"); rootOK {
			rootLow := strings.ToLower(rootBody)
			if strings.Contains(rootLow, "confluence") || strings.Contains(rootLow, "atlassian-token") {
				isConfluence = true
			}
		}
	}

	if !isConfluence {
		return nil
	}

	if confluenceVersion != "" {
		ev["version"] = confluenceVersion
		ev["product"] = "Confluence " + confluenceVersion
	}

	// Check /rest/api/space for unauthenticated access.
	if spaceBody, spaceOK := probeHTTPAnyBody(ctx, host, port, useTLS, "/rest/api/space"); spaceOK {
		spaceLow := strings.ToLower(spaceBody)
		if strings.Contains(spaceLow, "\"results\"") || strings.Contains(spaceLow, "\"key\"") {
			ev["unauth_api_access"] = true
			ev["spaces_accessible"] = true
		}
	}

	ev["proof"] = fmt.Sprintf("curl -sk %s://%s:%d/status", scheme(useTLS), host, port)

	desc := "An Atlassian Confluence instance is running. "
	if confluenceVersion != "" {
		desc += fmt.Sprintf("Detected version: %s. ", confluenceVersion)
	}
	desc += "Confluence has had critical RCE vulnerabilities including CVE-2022-26134 (OGNL injection), " +
		"CVE-2023-22515 (broken access control), and CVE-2023-22527 (template injection). " +
		"Verify the instance is fully patched and restrict access."

	return []finding.Finding{makeF(
		finding.CheckPortConfluenceDetected,
		finding.SeverityInfo,
		fmt.Sprintf("Atlassian Confluence detected on port %d", port),
		desc,
		ev,
	)}
}

// parseConfluenceVersionFromPage extracts version from Confluence login/page HTML.
func parseConfluenceVersionFromPage(body string) string {
	bodyLow := strings.ToLower(body)
	idx := strings.Index(bodyLow, "confluence")
	for idx >= 0 && idx < len(body)-20 {
		after := strings.TrimSpace(body[idx+10:])
		ver := ""
		for _, c := range after {
			if (c >= '0' && c <= '9') || c == '.' {
				ver += string(c)
			} else if ver != "" {
				break
			}
		}
		if ver != "" && strings.Contains(ver, ".") {
			return strings.TrimRight(ver, ".")
		}
		next := strings.Index(bodyLow[idx+10:], "confluence")
		if next < 0 {
			break
		}
		idx = idx + 10 + next
	}
	return ""
}

// detectJira identifies Atlassian Jira via /status, /rest/api/2/serverInfo, or dashboard.
func detectJira(ctx context.Context, host string, port int, _ string, makeF findingMaker) []finding.Finding {
	useTLS := port == 443

	ev := map[string]any{
		"port":    port,
		"service": "jira",
	}
	jiraVersion := ""
	isJira := false

	// Check /status endpoint.
	if statusBody, statusOK := probeHTTPAnyBody(ctx, host, port, useTLS, "/status"); statusOK {
		statusLow := strings.ToLower(statusBody)
		if strings.Contains(statusLow, "jira") || strings.Contains(statusLow, "\"state\"") {
			isJira = true
		}
	}

	// Check /rest/api/2/serverInfo — exposes version and metadata.
	if infoBody, infoOK := probeHTTPAnyBody(ctx, host, port, useTLS, "/rest/api/2/serverInfo"); infoOK {
		infoLow := strings.ToLower(infoBody)
		if strings.Contains(infoLow, "\"version\"") || strings.Contains(infoLow, "jira") {
			isJira = true
			if ver := parseJSONStringField(infoBody, "version"); ver != "" {
				jiraVersion = ver
			}
			ev["unauth_api_access"] = true
		}
	}

	// Check dashboard.
	if !isJira {
		if dashBody, dashOK := probeHTTPAnyBody(ctx, host, port, useTLS, "/secure/Dashboard.jspa"); dashOK {
			dashLow := strings.ToLower(dashBody)
			if strings.Contains(dashLow, "jira") || strings.Contains(dashLow, "atlassian") {
				isJira = true
			}
		}
	}

	// Check root page.
	if !isJira {
		if rootBody, _, rootOK := probeHTTPBodyAndHeaders(ctx, host, port, useTLS, "/"); rootOK {
			rootLow := strings.ToLower(rootBody)
			if strings.Contains(rootLow, "jira") && strings.Contains(rootLow, "atlassian") {
				isJira = true
			}
		}
	}

	if !isJira {
		return nil
	}

	if jiraVersion != "" {
		ev["version"] = jiraVersion
		ev["product"] = "Jira " + jiraVersion
	}

	ev["proof"] = fmt.Sprintf("curl -sk %s://%s:%d/rest/api/2/serverInfo", scheme(useTLS), host, port)

	var findings []finding.Finding

	if unauthAPI, _ := ev["unauth_api_access"].(bool); unauthAPI {
		findings = append(findings, makeF(
			finding.CheckPortJiraUnauthAPI,
			finding.SeverityHigh,
			fmt.Sprintf("Jira REST API accessible without authentication on port %d", port),
			"The Jira REST API (/rest/api/2/serverInfo) is accessible without authentication. "+
				"This may expose project data, issue details, user information, and internal metadata. "+
				"Configure Jira to require authentication for all API endpoints and restrict "+
				"anonymous access in Global Permissions.",
			ev,
		))
	}

	desc := "An Atlassian Jira instance is running. "
	if jiraVersion != "" {
		desc += fmt.Sprintf("Detected version: %s. ", jiraVersion)
	}
	desc += "Jira has had critical vulnerabilities including CVE-2019-11581 (SSTI RCE), " +
		"CVE-2021-26086 (path traversal), and CVE-2022-0540 (auth bypass). " +
		"Verify the instance is fully patched and restrict public access."

	findings = append(findings, makeF(
		finding.CheckPortJiraDetected,
		finding.SeverityInfo,
		fmt.Sprintf("Atlassian Jira detected on port %d", port),
		desc,
		ev,
	))
	return findings
}

// isGoAnywhereVulnerable returns true for GoAnywhere MFT versions < 7.1.2.
func isGoAnywhereVulnerable(ver string) bool {
	parts := strings.Split(ver, ".")
	if len(parts) < 3 {
		return false
	}
	maj, min, patch := 0, 0, 0
	_, _ = fmt.Sscanf(parts[0], "%d", &maj)
	_, _ = fmt.Sscanf(parts[1], "%d", &min)
	_, _ = fmt.Sscanf(parts[2], "%d", &patch)
	if maj < 7 {
		return true
	}
	if maj == 7 && min < 1 {
		return true
	}
	if maj == 7 && min == 1 && patch < 2 {
		return true
	}
	return false
}
