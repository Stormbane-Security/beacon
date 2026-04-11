package portscan

import (
	"context"
	"fmt"
	"strings"

	"github.com/stormbane-security/beacon/internal/finding"
)

func init() {
	registerProbe(ServiceProbe{
		Name:         "kubernetes-api",
		Category:     ProbeCatTLS,
		DefaultPorts: []int{6443, 8001},
		Detect:       detectKubernetesAPI,
	})
	registerProbe(ServiceProbe{
		Name:         "docker-daemon",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{2375},
		Detect:       detectDockerDaemon,
	})
	registerProbe(ServiceProbe{
		Name:         "kubelet",
		Category:     ProbeCatTLS,
		DefaultPorts: []int{10250},
		Detect:       detectKubelet,
	})
	registerProbe(ServiceProbe{
		Name:         "kubelet-readonly",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{10255},
		Detect:       detectKubeletReadOnly,
	})
	registerProbe(ServiceProbe{
		Name:         "cisco-smart-install",
		Category:     ProbeCatProtocol,
		DefaultPorts: []int{4786},
		Detect:       detectCiscoSmartInstall,
	})
	registerProbe(ServiceProbe{
		Name:         "checkpoint",
		Category:     ProbeCatProtocol,
		DefaultPorts: []int{264},
		Detect:       detectCheckPoint,
	})
	registerProbe(ServiceProbe{
		Name:         "mikrotik-api",
		Category:     ProbeCatProtocol,
		DefaultPorts: []int{8728},
		Detect:       detectMikroTikAPI,
	})
	registerProbe(ServiceProbe{
		Name:         "mikrotik-winbox",
		Category:     ProbeCatProtocol,
		DefaultPorts: []int{8291},
		Detect:       detectMikroTikWinbox,
	})
	registerProbe(ServiceProbe{
		Name:         "proxmox",
		Category:     ProbeCatTLS,
		DefaultPorts: []int{8006},
		Detect:       detectProxmox,
	})
	registerProbe(ServiceProbe{
		Name:         "istio-envoy",
		Category:     ProbeCatHTTP, // Envoy admin is plain HTTP
		DefaultPorts: []int{15000, 15001, 15006},
		Detect:       detectIstioEnvoy,
	})
	registerProbe(ServiceProbe{
		Name:         "juniper-anomaly",
		Category:     ProbeCatProtocol,
		DefaultPorts: []int{8160},
		Detect:       detectJuniperAnomaly,
	})
}

func detectKubernetesAPI(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	// Detect K8s API by probing for version info. probeK8sVersion makes an HTTP request
	// and parses the Kubernetes version response, so it works on any port.
	k8sVer := probeK8sVersion(ctx, host, port)
	if k8sVer == "" && port != 6443 && port != 8001 {
		return nil
	}
	k8sName := "Kubernetes API server"
	if port == 8001 {
		k8sName = "kubectl proxy"
	}

	// Fingerprint the cloud provider from version string and API response.
	// GKE: "v1.28.3-gke.1286000", EKS: "v1.28.2-eks-a59e1f0", AKS: "-1+aks"
	cloudProvider := identifyK8sCloudProvider(k8sVer, host, port)

	ev := map[string]any{
		"port":    port,
		"service": "kubernetes",
		"banner":  banner,
	}
	if k8sVer != "" {
		ev["k8s_version"] = k8sVer
	}
	if cloudProvider != "" {
		ev["cloud_provider"] = cloudProvider
	}

	var k8sFindings []finding.Finding
	title := fmt.Sprintf("%s exposed on port %d", k8sName, port)
	if cloudProvider != "" {
		title = fmt.Sprintf("%s (%s) exposed on port %d", k8sName, cloudProvider, port)
	}
	k8sFindings = append(k8sFindings, makeF(
		finding.CheckPortK8sAPIExposed,
		finding.SeverityHigh,
		title,
		fmt.Sprintf("The %s is publicly reachable (version: %s, provider: %s). "+
			"Misconfigured RBAC or anonymous access on the Kubernetes API allows full cluster compromise.",
			k8sName, k8sVer, orDefault(cloudProvider, "unknown")),
		ev,
	))

	// Check anonymous RBAC — can unauthenticated users list namespaces?
	if body, ok := probeHTTPBody(ctx, host, port, true, "/api/v1/namespaces"); ok {
		if strings.Contains(body, "NamespaceList") || strings.Contains(body, `"kind"`) {
			k8sFindings = append(k8sFindings, makeF(
				finding.CheckK8sAnonymousRBAC,
				finding.SeverityCritical,
				fmt.Sprintf("Kubernetes API allows anonymous namespace listing on port %d", port),
				"The Kubernetes API server returns namespace data without authentication. "+
					"Anonymous RBAC grants allow unauthenticated users to enumerate cluster resources. "+
					"This typically means the cluster has --anonymous-auth=true (default) with overly "+
					"permissive ClusterRoleBindings granting access to system:anonymous or system:unauthenticated. "+
					"Restrict anonymous access: kubectl delete clusterrolebinding system:anonymous",
				map[string]any{"port": port, "service": "kubernetes", "anonymous_access": true,
					"k8s_version": k8sVer, "cloud_provider": cloudProvider},
			))
		}
	}

	// Check if secrets are enumerable without auth
	if body, ok := probeHTTPBody(ctx, host, port, true, "/api/v1/secrets?limit=1"); ok {
		if strings.Contains(body, "SecretList") || strings.Contains(body, `"kind":"Secret"`) {
			k8sFindings = append(k8sFindings, makeF(
				finding.CheckK8sSecretsExposed,
				finding.SeverityCritical,
				fmt.Sprintf("Kubernetes secrets enumerable without authentication on port %d", port),
				"The Kubernetes API server returns secret objects to unauthenticated requests. "+
					"This exposes all cluster secrets including TLS certificates, service account tokens, "+
					"database passwords, and cloud provider credentials. Full cluster compromise is trivial. "+
					"This is the most critical Kubernetes misconfiguration possible.",
				map[string]any{"port": port, "service": "kubernetes", "secrets_exposed": true,
					"k8s_version": k8sVer},
			))
		}
	}

	// CVE-2018-1002105: Kubernetes ≤ 1.12.2 API server WebSocket upgrade privilege escalation.
	if k8sVer != "" && isKubernetesPrivEscVulnerable(k8sVer) {
		k8sFindings = append(k8sFindings, makeF(
			finding.CheckCVEKubernetesPrivEsc,
			finding.SeverityCritical,
			fmt.Sprintf("CVE-2018-1002105: Kubernetes %s vulnerable to unauthenticated cluster-admin privilege escalation", k8sVer),
			fmt.Sprintf("Kubernetes %s is internet-accessible and vulnerable to CVE-2018-1002105 (CVSS 9.8, KEV). "+
				"An unauthenticated attacker can send a WebSocket upgrade request to an aggregated API endpoint "+
				"and establish a raw TCP bridge through the API server. The bridge runs with the API server's "+
				"cluster-admin credentials, granting full cluster access without any authentication. "+
				"This affects Kubernetes < 1.10.11, < 1.11.5, and < 1.12.3. "+
				"Upgrade Kubernetes immediately.", k8sVer),
			map[string]any{"port": port, "service": "kubernetes", "k8s_version": k8sVer, "cve": "CVE-2018-1002105"},
		))
	}
	return k8sFindings
}

// identifyK8sCloudProvider detects the managed K8s provider from version strings
// and API response characteristics.
// GKE versions contain "-gke.", EKS contains "-eks-", AKS contains "+aks".
func identifyK8sCloudProvider(version, host string, port int) string {
	v := strings.ToLower(version)
	switch {
	case strings.Contains(v, "-gke"):
		return "GKE"
	case strings.Contains(v, "-eks"):
		return "EKS"
	case strings.Contains(v, "+aks"), strings.Contains(v, "-aks"):
		return "AKS"
	case strings.Contains(v, "+rke"), strings.Contains(v, "-rancher"):
		return "Rancher"
	case strings.Contains(v, "+k3s"):
		return "K3s"
	case strings.Contains(v, "-doks"):
		return "DOKS" // DigitalOcean
	}
	return ""
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func detectDockerDaemon(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	// Validate response contains Docker version JSON (e.g. "ApiVersion").
	// Prevents false positives from SPAs that return HTML for any path.
	// Try unversioned path first (works on all Docker versions), then
	// fall back to versioned path for older daemons.
	body, ok := probeHTTPBody(ctx, host, port, false, "/version")
	if !ok || !strings.Contains(body, "ApiVersion") {
		body, ok = probeHTTPBody(ctx, host, port, false, "/v1.24/version")
		if !ok || !strings.Contains(body, "ApiVersion") {
			return nil
		}
	}
	return []finding.Finding{makeF(
		finding.CheckPortDockerUnauth,
		finding.SeverityCritical,
		fmt.Sprintf("Unauthenticated Docker daemon exposed on port %d", port),
		"The Docker daemon API is reachable over plain TCP without TLS or authentication. "+
			"A remote attacker can spawn privileged containers and gain full host control.",
		map[string]any{"port": port, "service": "docker", "authenticated": false, "banner": banner},
	)}
}

func detectKubelet(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	// Kubelet /pods returns JSON with "kind":"PodList". Validate body to avoid SPA FPs.
	body, ok := probeHTTPBody(ctx, host, port, true, "/pods")
	if !ok || !strings.Contains(body, "PodList") {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortKubeletUnauth,
		finding.SeverityCritical,
		fmt.Sprintf("Unauthenticated Kubelet API exposed on port %d", port),
		"The Kubernetes Kubelet API is reachable without authentication. "+
			"An attacker can enumerate running pods and execute commands inside containers.",
		map[string]any{"port": port, "service": "kubelet", "authenticated": false, "banner": banner},
	)}
}

func detectKubeletReadOnly(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	// Validate response contains Kubernetes pod list JSON (e.g. "PodList" kind).
	// Prevents false positives from SPAs that return HTML for any path.
	body, ok := probeHTTPBody(ctx, host, port, false, "/pods")
	if !ok || !strings.Contains(body, "PodList") {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortKubeletReadOnly,
		finding.SeverityHigh,
		fmt.Sprintf("Kubelet read-only API exposed on port %d", port),
		"The Kubernetes Kubelet read-only API is publicly accessible on port 10255. "+
			"This endpoint provides unauthenticated access to pod listings, container specs, "+
			"resource usage metrics, and container logs. An attacker can enumerate all workloads "+
			"running on the node, discover internal service names, environment variables (which "+
			"often contain secrets), and mounted volumes. Disable the read-only port by setting "+
			"--read-only-port=0 in the kubelet configuration.",
		map[string]any{"port": port, "service": "kubelet-readonly", "authenticated": false, "banner": banner},
	)}
}

func detectCiscoSmartInstall(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	if !probeCiscoSmartInstall(ctx, host, port) {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortCiscoSmartInstall,
		finding.SeverityCritical,
		fmt.Sprintf("CVE-2018-0171: Cisco Smart Install protocol exposed on port %d", port),
		"The Cisco IOS Smart Install protocol is accessible on port 4786. "+
			"CVE-2018-0171 (CVSS 9.8, KEV) allows unauthenticated attackers to read and write "+
			"the device configuration, change the TFTP server, and reload the device. "+
			"Smart Install is actively exploited by state-sponsored threat actors for network infrastructure "+
			"takeover. Disable Smart Install with 'no vstack' in IOS configuration and block port 4786 "+
			"at the network perimeter.",
		map[string]any{"port": port, "service": "cisco-smart-install", "protocol": "smart-install", "banner": banner},
	)}
}

func detectCheckPoint(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	if !probeCheckPoint(ctx, host, port) {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortCheckPointExposed,
		finding.SeverityHigh,
		fmt.Sprintf("Check Point FW-1 topology port exposed on port %d", port),
		"TCP port 264 (Check Point FW-1 topology/cpstat protocol) is internet-accessible. "+
			"This port is used by Check Point SmartConsole and management tools to discover firewall "+
			"topology. Exposure can leak firewall cluster object names, IP addresses, and version "+
			"information. CVE-2024-24919 (Check Point CloudGuard arbitrary file read) affects devices "+
			"with this and related management ports exposed. Restrict to management network only.",
		map[string]any{"port": port, "service": "checkpoint", "banner": banner},
	)}
}

func detectMikroTikAPI(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	if !probeMikroTikAPI(ctx, host, port) {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortMikroTikAPIExposed,
		finding.SeverityHigh,
		fmt.Sprintf("MikroTik RouterOS API exposed on port %d", port),
		"The MikroTik RouterOS API service is internet-accessible. The RouterOS API on port 8728 "+
			"provides programmatic access to all router configuration including firewall rules, routing, "+
			"user accounts, and VPN settings. Default credentials (admin/<empty>) are common. "+
			"CVE-2023-30799 allows privilege escalation from admin to superadmin via this interface. "+
			"Restrict to trusted management IPs immediately.",
		map[string]any{"port": port, "service": "mikrotik-api", "banner": banner},
	)}
}

func detectMikroTikWinbox(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	if !probeMikroTikWinbox(ctx, host, port) {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortWinboxExposed,
		finding.SeverityHigh,
		fmt.Sprintf("MikroTik Winbox management port exposed on port %d", port),
		"MikroTik RouterOS Winbox management protocol is publicly accessible. "+
			"CVE-2018-14847 (Winbox credential disclosure without authentication — CVSS 9.1) "+
			"allowed unauthenticated attackers to read the RouterOS password database via port 8291. "+
			"This was widely exploited and over 2 million devices were affected. "+
			"Even on patched devices, Winbox exposure enables brute-force attacks on admin credentials. "+
			"Restrict Winbox to trusted management IPs via IP firewall filter rules.",
		map[string]any{"port": port, "service": "mikrotik-winbox", "banner": banner},
	)}
}

func detectProxmox(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	body, ok := probeHTTPBody(ctx, host, port, true, "/api2/json/version")
	if !ok {
		return nil
	}
	bodyLow := strings.ToLower(body)
	if !strings.Contains(bodyLow, "version") || !strings.Contains(bodyLow, "release") {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortProxmoxExposed,
		finding.SeverityHigh,
		fmt.Sprintf("Proxmox VE hypervisor management UI exposed on port %d", port),
		"The Proxmox VE hypervisor management interface is publicly accessible. "+
			"Proxmox VE controls virtual machines, containers, storage, and networking "+
			"for the entire hypervisor. Default credentials (root:proxmox) or weak "+
			"passwords combined with internet exposure create critical infrastructure risk. "+
			"Proxmox management should be restricted to dedicated management VLANs "+
			"accessible only via VPN. Enable 2FA and change default credentials immediately.",
		map[string]any{"port": port, "service": "proxmox",
			"url": fmt.Sprintf("https://%s:%d", host, port)},
	)}
}

func detectIstioEnvoy(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	// Envoy admin interface on port 15000 exposes /server_info, /clusters, /config_dump.
	// Istio pilot debug on 15014 exposes mesh configuration.
	// These are protocol-level fingerprints, not just port assumptions.
	body, ok := probeHTTPBody(ctx, host, port, false, "/server_info")
	if !ok {
		// Try /clusters as fallback — Envoy admin endpoint
		body, ok = probeHTTPBody(ctx, host, port, false, "/clusters")
		if !ok {
			return nil
		}
	}

	isEnvoy := strings.Contains(body, "envoy") || strings.Contains(body, "ENVOY") ||
		strings.Contains(body, "hot_restart_version") || strings.Contains(body, "concurrency")
	isIstio := strings.Contains(body, "istio") || strings.Contains(body, "pilot")

	if !isEnvoy && !isIstio {
		return nil
	}

	service := "envoy"
	if isIstio {
		service = "istio"
	}

	ev := map[string]any{
		"port":    port,
		"service": service,
	}

	// Extract version from server_info if available
	if idx := strings.Index(body, "version"); idx >= 0 {
		snippet := body[idx:]
		if end := strings.IndexAny(snippet, "\n\r}"); end > 0 && end < 200 {
			ev["version_info"] = strings.TrimSpace(snippet[:end])
		}
	}

	// Check what's exposed on the admin interface
	var exposed []string
	for _, path := range []string{"/config_dump", "/clusters", "/listeners", "/certs"} {
		if _, pathOK := probeHTTPBody(ctx, host, port, false, path); pathOK {
			exposed = append(exposed, path)
		}
	}
	if len(exposed) > 0 {
		ev["exposed_endpoints"] = exposed
	}

	return []finding.Finding{makeF(
		finding.CheckK8sIstioAdminExposed,
		finding.SeverityHigh,
		fmt.Sprintf("Istio/Envoy admin interface exposed on port %d", port),
		fmt.Sprintf("The %s admin interface is publicly accessible on port %d. "+
			"This exposes service mesh configuration, TLS certificates, upstream cluster "+
			"details, and listener configurations. An attacker can map the entire internal "+
			"service topology, extract TLS private keys from /certs, and identify internal "+
			"service addresses from /clusters. The admin interface should never be exposed "+
			"externally — bind it to localhost only (--admin-address-path or "+
			"meshConfig.defaultConfig.proxyAdminPort in Istio).", service, port),
		ev,
	)}
}

func detectJuniperAnomaly(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	if !probeJuniperAnomaly(ctx, host, port) {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortJuniperAnomalyExposed,
		finding.SeverityCritical,
		"Juniper PTX anomaly detection port exposed (CVE-2026-21902)",
		"TCP port 8160 (Juniper On-Box Anomaly Detection Framework) is internet-accessible. "+
			"CVE-2026-21902 (CVSS 9.8) allows an unauthenticated attacker to execute arbitrary code as root "+
			"by sending crafted requests to this port. "+
			"This port should only be reachable from internal processes. "+
			"Apply the Junos OS Evolved patch or restrict access with firewall filters immediately.",
		map[string]any{"port": port, "service": "juniper-anomaly", "banner": banner},
	)}
}
