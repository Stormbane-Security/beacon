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
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{8443},
		Detect:       detectIngressNginxAdmission,
	})
	registerProbe(ServiceProbe{
		Name:         "kubernetes-dashboard-8443",
		Category:     ProbeCatHTTP,
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
}

func detectJupyter(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	exposed := probeJupyter(ctx, host, port)
	if !exposed {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortJupyterExposed,
		finding.SeverityCritical,
		fmt.Sprintf("Jupyter Notebook exposed on port %d", port),
		"A Jupyter Notebook server is publicly accessible. "+
			"Jupyter provides arbitrary code execution and full filesystem access to the server.",
		map[string]any{"port": port, "service": "jupyter", "authenticated": false, "banner": banner},
	)}
}

func detectPrometheus(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	unauth := probeHTTP(ctx, host, port, false, "/api/v1/targets")
	if !unauth {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortPrometheusUnauth,
		finding.SeverityCritical,
		fmt.Sprintf("Unauthenticated Prometheus exposed on port %d", port),
		"A Prometheus metrics server is accessible without authentication. "+
			"Internal infrastructure topology, host names, and service metadata are exposed.",
		map[string]any{"port": port, "service": "prometheus", "authenticated": false, "banner": banner},
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
		map[string]any{"port": port, "service": "consul",
			"url": fmt.Sprintf("http://%s:%d/v1/catalog/nodes", host, port)},
	)}
}

func detectEtcd(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	// Detect etcd by HTTP response content — /version returns etcd version info.
	if body, ok := probeHTTPBody(ctx, host, port, false, "/version"); ok && strings.Contains(strings.ToLower(body), "etcd") {
		return []finding.Finding{makeF(
			finding.CheckPortEtcdExposed,
			finding.SeverityCritical,
			fmt.Sprintf("etcd client API exposed on port %d", port),
			"An etcd cluster member is publicly accessible. etcd stores all Kubernetes cluster "+
				"state including secrets, service account tokens, and cluster configuration. "+
				"Unauthenticated etcd access gives full read/write to the key-value store "+
				"and their network endpoints, and the key-value store (which often contains secrets, "+
				"TLS certificates, and database credentials).",
			map[string]any{"port": port, "service": "etcd"},
		)}
	}
	// Also try HTTPS — etcd may be configured with TLS.
	if body, ok := probeHTTPBody(ctx, host, port, true, "/version"); ok && strings.Contains(strings.ToLower(body), "etcd") {
		return []finding.Finding{makeF(
			finding.CheckPortEtcdExposed,
			finding.SeverityCritical,
			fmt.Sprintf("etcd client API exposed on port %d", port),
			"An etcd cluster member is publicly accessible via TLS. etcd stores all Kubernetes cluster "+
				"state including secrets, service account tokens, and cluster configuration.",
			map[string]any{"port": port, "service": "etcd"},
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
	if !probeHTTP(ctx, host, port, true, "/session_login.cgi") {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortWebminExposed,
		finding.SeverityHigh,
		fmt.Sprintf("Webmin server management panel exposed on port %d", port),
		"Webmin is publicly accessible. Webmin provides web-based Unix/Linux system administration "+
			"and has a history of critical vulnerabilities. CVE-2019-15107 allowed unauthenticated RCE "+
			"and CVE-2022-0824 allowed unauthenticated file read. Restrict to trusted networks.",
		map[string]any{"port": port, "service": "webmin", "banner": banner},
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
		map[string]any{"port": port, "service": "netdata",
			"url": fmt.Sprintf("http://%s:%d", host, port)},
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
			return []finding.Finding{makeF(
				finding.CheckPortArtifactoryExposed,
				finding.SeverityHigh,
				fmt.Sprintf("JFrog Artifactory repository manager exposed on port %d", port),
				"A JFrog Artifactory repository manager is publicly accessible. "+
					"Artifactory hosts build artifacts, Docker images, npm/Maven/PyPI packages, and pipeline credentials. "+
					"Unauthenticated access or default credentials allow supply chain compromise by "+
					"injecting malicious artifacts into repositories used by development pipelines. "+
					"Restrict access to trusted networks and rotate all repository credentials.",
				map[string]any{"port": port, "service": "artifactory",
					"url": fmt.Sprintf("http://%s:%d/artifactory/", host, port)},
			)}
		}
	}
	// Probe for Sonatype Nexus Repository Manager.
	if body, ok := probeHTTPBody(ctx, host, port, false, "/service/rest/v1/status"); ok {
		bodyLow := strings.ToLower(body)
		if strings.Contains(bodyLow, "nexus") || strings.Contains(bodyLow, "sonatype") {
			return []finding.Finding{makeF(
				finding.CheckPortNexusExposed,
				finding.SeverityHigh,
				fmt.Sprintf("Sonatype Nexus Repository Manager exposed on port %d", port),
				"A Sonatype Nexus Repository Manager is publicly accessible. "+
					"Nexus hosts Maven, npm, Docker, PyPI, and raw binary artifacts. "+
					"Older Nexus versions use default credentials (admin:admin123) and may be vulnerable to "+
					"CVE-2019-7238 (Nexus 3 < 3.15.0 pre-auth RCE via EL injection, CVSS 9.8, KEV). "+
					"Restrict to trusted networks and update to the latest version.",
				map[string]any{"port": port, "service": "nexus",
					"url": fmt.Sprintf("http://%s:%d/", host, port)},
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
	if !strings.Contains(lb, "weblogic") && !strings.Contains(lb, "oracle") {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckCVEWebLogicConsole,
		finding.SeverityCritical,
		fmt.Sprintf("Oracle WebLogic admin console exposed on port %d (CVE-2020-14882 KEV)", port),
		"Oracle WebLogic admin console at /console/login/LoginForm.jsp is internet-accessible. "+
			"CVE-2020-14882/14883 (CVSS 9.8, KEV) allows unauthenticated RCE via double URL-encoded "+
			"paths. The WebLogic admin console must never be internet-facing regardless of patch level.",
		map[string]any{"port": port, "service": "weblogic"},
	)}
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
	return []finding.Finding{makeF(
		finding.CheckCVESaltStackAPI,
		finding.SeverityCritical,
		fmt.Sprintf("CVE-2021-25281/25282: SaltStack Salt API exposed on port %d", port),
		"A SaltStack Salt API (salt-api) is internet-accessible without authentication. "+
			"CVE-2021-25281 (CVSS 9.8, KEV) allows unauthenticated access to the wheel client, "+
			"and CVE-2021-25282 is an arbitrary file write via wheel.pillar_roots.write — "+
			"an attacker can write to /etc/crontab or any system file to achieve root RCE. "+
			"Salt API must never be exposed to the internet. Restrict to internal management networks.",
		map[string]any{"port": port, "service": "salt-api", "authenticated": false},
	)}
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
	return []finding.Finding{makeF(
		finding.CheckPortvLLMExposed,
		finding.SeverityHigh,
		fmt.Sprintf("vLLM inference server exposed unauthenticated on port %d", port),
		"A vLLM OpenAI-compatible LLM inference server is publicly accessible without authentication. "+
			"vLLM is a high-throughput serving framework for large language models. "+
			"Unauthenticated access allows unlimited inference at the operator's GPU cost, "+
			"exposure of fine-tuned model capabilities, and potential prompt injection attacks. "+
			"Add --api-key to require authentication and restrict to trusted networks.",
		map[string]any{"port": port, "service": "vllm",
			"url": fmt.Sprintf("http://%s:%d/v1/models", host, port)},
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
	return []finding.Finding{makeF(
		finding.CheckPortLocalAIExposed,
		finding.SeverityHigh,
		fmt.Sprintf("LocalAI inference server exposed unauthenticated on port %d", port),
		"A LocalAI OpenAI-compatible LLM inference server is publicly accessible without authentication. "+
			"LocalAI serves language models, image generation, and audio transcription locally. "+
			"Unauthenticated access allows unlimited inference at the operator's cost, "+
			"exposure of locally loaded models, and potential arbitrary model file access. "+
			"Configure authentication and restrict access to trusted networks.",
		map[string]any{"port": port, "service": "localai",
			"url": fmt.Sprintf("http://%s:%d/v1/models", host, port)},
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
		map[string]any{"port": port, "service": "adguard",
			"url": fmt.Sprintf("http://%s:%d/control/status", host, port)},
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
	return []finding.Finding{makeF(
		finding.CheckPortHuggingFaceTGIExposed,
		finding.SeverityHigh,
		fmt.Sprintf("HuggingFace Text Generation Inference server exposed unauthenticated on port %d", port),
		"A HuggingFace Text Generation Inference (TGI) server is publicly accessible without authentication. "+
			"The /info endpoint discloses the loaded model ID, maximum input/output lengths, and server configuration. "+
			"Unauthenticated access allows unlimited LLM inference at the operator's compute cost, "+
			"model identification for targeted attacks, and potential prompt injection against downstream applications. "+
			"Add authentication via a reverse proxy and restrict the port to trusted networks.",
		map[string]any{"port": port, "service": "huggingface-tgi",
			"url": fmt.Sprintf("http://%s:%d/info", host, port)},
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
		findings = append(findings, makeF(
			finding.CheckCVEMLflowAuthBypass,
			finding.SeverityCritical,
			fmt.Sprintf("CVE-2023-6014: MLflow unauthenticated REST API confirmed on port %d", port),
			"The MLflow experiments list API (/api/2.0/mlflow/experiments/list) returns data "+
				"without authentication. CVE-2023-6014 (CVSS 9.1) allows unauthenticated account "+
				"creation on MLflow < 2.8.0. Upgrade MLflow and restrict network access.",
			ev,
		))
	}
	return findings
}

func detectIntelAMT(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	body, ok := probeHTTPBody(ctx, host, port, false, "/index.htm")
	if !ok || !strings.Contains(strings.ToLower(body), "intel") {
		return nil
	}
	return []finding.Finding{makeF(
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
		map[string]any{"port": port, "service": "intel-amt"},
	)}
}

func detectViteDev(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	if !probeHTTP(ctx, host, port, false, "/__vite_ping") {
		return nil
	}
	now := time.Now()
	var findings []finding.Finding

	// CVE-2025-30208: /@fs/ path traversal with double-? query confusion.
	if body, ok := probeHTTPBody(ctx, host, port, false, "/@fs/etc/passwd?import&raw??"); ok &&
		strings.Contains(body, "export default") && strings.Contains(body, "root:") {
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
			DiscoveredAt: now,
		})
	}

	findings = append(findings, makeF(
		finding.CheckPortDevServerExposed,
		finding.SeverityHigh,
		fmt.Sprintf("Vite development server exposed on port %d", port),
		"A Vite JavaScript development server is publicly accessible. Development servers "+
			"expose unminified source code, internal file paths, environment variables embedded in code, "+
			"and the /__vite_ping health endpoint. Production deployments should never expose dev servers.",
		map[string]any{"port": port, "service": "vite", "banner": banner},
	))
	return findings
}

func detectIngressNginxAdmission(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	body := probeIngressAdmissionWebhook(ctx, host, port)
	if body == "" {
		return nil
	}
	now := time.Now()
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
		if strings.Contains(lb, "lucee") || strings.Contains(lb, "password") && strings.Contains(lb, "login") {
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
	ev := map[string]any{"port": port, "service": "tika", "banner": banner}
	tikaVer := strings.TrimSpace(body)
	if strings.HasPrefix(strings.ToLower(tikaVer), "apache tika ") {
		tikaVer = tikaVer[len("apache tika "):]
	}
	ev["tika_version"] = tikaVer
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
