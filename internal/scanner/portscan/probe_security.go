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
		Category:     ProbeCatHTTP,
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
		Category:     ProbeCatHTTP,
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
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{8006},
		Detect:       detectProxmox,
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
		// No K8s version response and not a standard K8s port — skip.
		return nil
	}
	k8sName := "Kubernetes API server"
	if port == 8001 {
		k8sName = "kubectl proxy"
	}
	var k8sFindings []finding.Finding
	k8sFindings = append(k8sFindings, makeF(
		finding.CheckPortK8sAPIExposed,
		finding.SeverityHigh,
		fmt.Sprintf("%s exposed on port %d", k8sName, port),
		fmt.Sprintf("The %s is publicly reachable. "+
			"Misconfigured RBAC or anonymous access on the Kubernetes API allows full cluster compromise.", k8sName),
		map[string]any{"port": port, "service": "kubernetes", "banner": banner},
	))
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

func detectDockerDaemon(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	unauth := probeHTTP(ctx, host, port, false, "/v1.24/version")
	if !unauth {
		return nil
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
	unauth := probeHTTP(ctx, host, port, true, "/pods")
	if !unauth {
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
	unauth := probeHTTP(ctx, host, port, false, "/pods")
	if !unauth {
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
