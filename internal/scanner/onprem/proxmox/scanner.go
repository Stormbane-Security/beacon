// Package proxmox implements authenticated Proxmox VE security scanning.
// It uses the Proxmox PVE REST API v2 directly. All API calls are read-only
// (GET requests only). Supports API token authentication and optional TLS
// verification bypass for self-signed certificates common on Proxmox hosts.
package proxmox

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)

const (
	maxBody    = 10 << 20 // 10 MiB limit on response bodies
	scannerTag = "onprem/proxmox"

	// minSafeVersion is the minimum Proxmox VE major.minor that does not have
	// publicly disclosed CVEs with available exploits. Anything below this
	// triggers an outdated-version finding.
	minSafeMajor = 8
	minSafeMinor = 1
)

// Config holds Proxmox VE authentication configuration.
type Config struct {
	// APIEndpoint is the Proxmox VE API URL (e.g., "https://192.168.1.100:8006").
	APIEndpoint string

	// TokenID is the API token ID (e.g., "user@pam!tokenid").
	TokenID string

	// TokenSecret is the API token secret UUID.
	TokenSecret string

	// SkipTLSVerify disables TLS certificate verification. Common on Proxmox
	// hosts that use self-signed certificates.
	SkipTLSVerify bool
}

// Scanner runs authenticated Proxmox VE security checks.
type Scanner struct {
	cfg    Config
	client *http.Client

	// baseURL overrides cfg.APIEndpoint for testing. When empty, the
	// production endpoint from Config is used.
	baseURL string
}

// New creates a new Proxmox VE scanner.
func New(cfg Config) *Scanner {
	transport := &http.Transport{}
	if cfg.SkipTLSVerify {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // user explicitly opted in
		}
	}
	return &Scanner{
		cfg: cfg,
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
	}
}

// SetBaseURL overrides the API base URL. Used in tests to point the scanner
// at an httptest server.
func (s *Scanner) SetBaseURL(u string) { s.baseURL = u }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return scannerTag }

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, asset string, _ module.ScanType) ([]finding.Finding, error) {
	endpoint := s.endpoint()
	if endpoint == "" {
		return nil, fmt.Errorf("proxmox: API endpoint not configured")
	}

	var all []finding.Finding

	// Check 1: TLS — is the endpoint using plain HTTP?
	all = append(all, s.checkTLS(asset)...)

	// Check 2: Version — is PVE outdated?
	version, err := s.fetchVersion(ctx)
	if err != nil {
		all = append(all, s.scanError(asset, fmt.Sprintf("version check failed: %v", err)))
		return all, nil
	}
	all = append(all, s.checkVersion(asset, version)...)

	// Check 3: Root API token.
	all = append(all, s.checkRootToken(asset)...)

	// Check 4: Default credentials — try unauthenticated API access.
	defaultCredsFindings, err := s.checkDefaultCreds(ctx, asset)
	if err == nil {
		all = append(all, defaultCredsFindings...)
	}

	// Check 5: Cluster firewall.
	firewallFindings, err := s.checkFirewall(ctx, asset)
	if err != nil {
		all = append(all, s.scanError(asset, fmt.Sprintf("firewall check failed: %v", err)))
	} else {
		all = append(all, firewallFindings...)
	}

	// Check 6: HA status.
	haFindings, err := s.checkHA(ctx, asset)
	if err != nil {
		all = append(all, s.scanError(asset, fmt.Sprintf("HA check failed: %v", err)))
	} else {
		all = append(all, haFindings...)
	}

	// Fetch nodes for per-node checks.
	nodes, err := s.fetchNodes(ctx)
	if err != nil {
		all = append(all, s.scanError(asset, fmt.Sprintf("node enumeration failed: %v", err)))
		return all, nil
	}

	// Fetch backup schedules for VM/CT backup checks.
	backedUpVMIDs := s.fetchBackedUpVMIDs(ctx)

	for _, node := range nodes {
		nodeName, _ := node["node"].(string)
		if nodeName == "" {
			continue
		}

		// Check 7: VMs — guest agent, backup, console.
		vmFindings, err := s.checkVMs(ctx, asset, nodeName, backedUpVMIDs)
		if err != nil {
			all = append(all, s.scanError(asset, fmt.Sprintf("VM check on node %s failed: %v", nodeName, err)))
		} else {
			all = append(all, vmFindings...)
		}

		// Check 8: LXC containers — privileged, backup.
		ctFindings, err := s.checkContainers(ctx, asset, nodeName, backedUpVMIDs)
		if err != nil {
			all = append(all, s.scanError(asset, fmt.Sprintf("LXC check on node %s failed: %v", nodeName, err)))
		} else {
			all = append(all, ctFindings...)
		}

		// Check 9: Storage — encryption.
		storageFindings, err := s.checkStorage(ctx, asset, nodeName)
		if err != nil {
			all = append(all, s.scanError(asset, fmt.Sprintf("storage check on node %s failed: %v", nodeName, err)))
		} else {
			all = append(all, storageFindings...)
		}
	}

	return all, nil
}

// ---------------------------------------------------------------------------
// API helpers
// ---------------------------------------------------------------------------

// endpoint returns the effective API base URL.
func (s *Scanner) endpoint() string {
	if s.baseURL != "" {
		return s.baseURL
	}
	return strings.TrimRight(s.cfg.APIEndpoint, "/")
}

// authHeader returns the PVE API token authorization header value.
func (s *Scanner) authHeader() string {
	return fmt.Sprintf("PVEAPIToken=%s=%s", s.cfg.TokenID, s.cfg.TokenSecret)
}

// curlProof returns a curl command that reproduces the API call.
func (s *Scanner) curlProof(path string) string {
	ep := s.endpoint()
	tlsFlag := ""
	if s.cfg.SkipTLSVerify || strings.HasPrefix(ep, "https") {
		tlsFlag = "-k "
	}
	redactedAuth := fmt.Sprintf("PVEAPIToken=%s=$PROXMOX_TOKEN", s.cfg.TokenID)
	return fmt.Sprintf("curl %s%s%s -H 'Authorization: %s'", tlsFlag, ep, path, redactedAuth)
}

// doRequest performs an authenticated GET against the Proxmox API and decodes
// the JSON response into dst.
func (s *Scanner) doRequest(ctx context.Context, path string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.endpoint()+path, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", s.authHeader())

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("http request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API %s returned %d: %s", path, resp.StatusCode, truncate(string(body), 200))
	}

	if err := json.Unmarshal(body, dst); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// doUnauthRequest performs an unauthenticated GET to detect default/open access.
func (s *Scanner) doUnauthRequest(ctx context.Context, path string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.endpoint()+path, nil)
	if err != nil {
		return 0, fmt.Errorf("build request: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("http request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body) //nolint:errcheck
	return resp.StatusCode, nil
}

// ---------------------------------------------------------------------------
// Data fetchers
// ---------------------------------------------------------------------------

type pveResponse struct {
	Data json.RawMessage `json:"data"`
}

func (s *Scanner) fetchVersion(ctx context.Context) (map[string]any, error) {
	var resp pveResponse
	if err := s.doRequest(ctx, "/api2/json/version", &resp); err != nil {
		return nil, err
	}
	var data map[string]any
	if err := json.Unmarshal(resp.Data, &data); err != nil {
		return nil, fmt.Errorf("decode version data: %w", err)
	}
	return data, nil
}

func (s *Scanner) fetchNodes(ctx context.Context) ([]map[string]any, error) {
	var resp pveResponse
	if err := s.doRequest(ctx, "/api2/json/nodes", &resp); err != nil {
		return nil, err
	}
	var nodes []map[string]any
	if err := json.Unmarshal(resp.Data, &nodes); err != nil {
		return nil, fmt.Errorf("decode nodes data: %w", err)
	}
	return nodes, nil
}

func (s *Scanner) fetchVMs(ctx context.Context, node string) ([]map[string]any, error) {
	var resp pveResponse
	if err := s.doRequest(ctx, fmt.Sprintf("/api2/json/nodes/%s/qemu", node), &resp); err != nil {
		return nil, err
	}
	var vms []map[string]any
	if err := json.Unmarshal(resp.Data, &vms); err != nil {
		return nil, fmt.Errorf("decode qemu data: %w", err)
	}
	return vms, nil
}

func (s *Scanner) fetchVMConfig(ctx context.Context, node string, vmid int) (map[string]any, error) {
	var resp pveResponse
	path := fmt.Sprintf("/api2/json/nodes/%s/qemu/%d/config", node, vmid)
	if err := s.doRequest(ctx, path, &resp); err != nil {
		return nil, err
	}
	var cfg map[string]any
	if err := json.Unmarshal(resp.Data, &cfg); err != nil {
		return nil, fmt.Errorf("decode vm config: %w", err)
	}
	return cfg, nil
}

func (s *Scanner) fetchContainers(ctx context.Context, node string) ([]map[string]any, error) {
	var resp pveResponse
	if err := s.doRequest(ctx, fmt.Sprintf("/api2/json/nodes/%s/lxc", node), &resp); err != nil {
		return nil, err
	}
	var cts []map[string]any
	if err := json.Unmarshal(resp.Data, &cts); err != nil {
		return nil, fmt.Errorf("decode lxc data: %w", err)
	}
	return cts, nil
}

func (s *Scanner) fetchContainerConfig(ctx context.Context, node string, vmid int) (map[string]any, error) {
	var resp pveResponse
	path := fmt.Sprintf("/api2/json/nodes/%s/lxc/%d/config", node, vmid)
	if err := s.doRequest(ctx, path, &resp); err != nil {
		return nil, err
	}
	var cfg map[string]any
	if err := json.Unmarshal(resp.Data, &cfg); err != nil {
		return nil, fmt.Errorf("decode ct config: %w", err)
	}
	return cfg, nil
}

func (s *Scanner) fetchStorage(ctx context.Context, node string) ([]map[string]any, error) {
	var resp pveResponse
	if err := s.doRequest(ctx, fmt.Sprintf("/api2/json/nodes/%s/storage", node), &resp); err != nil {
		return nil, err
	}
	var storages []map[string]any
	if err := json.Unmarshal(resp.Data, &storages); err != nil {
		return nil, fmt.Errorf("decode storage data: %w", err)
	}
	return storages, nil
}

func (s *Scanner) fetchFirewallOptions(ctx context.Context) (map[string]any, error) {
	var resp pveResponse
	if err := s.doRequest(ctx, "/api2/json/cluster/firewall/options", &resp); err != nil {
		return nil, err
	}
	var opts map[string]any
	if err := json.Unmarshal(resp.Data, &opts); err != nil {
		return nil, fmt.Errorf("decode firewall options: %w", err)
	}
	return opts, nil
}

// fetchBackedUpVMIDs returns a set of VMID strings that have at least one
// backup schedule configured.
func (s *Scanner) fetchBackedUpVMIDs(ctx context.Context) map[string]bool {
	result := make(map[string]bool)

	var resp pveResponse
	if err := s.doRequest(ctx, "/api2/json/cluster/backup", &resp); err != nil {
		return result
	}

	var jobs []map[string]any
	if err := json.Unmarshal(resp.Data, &jobs); err != nil {
		return result
	}

	for _, job := range jobs {
		// "all" field means all VMs are backed up.
		if allVal, ok := job["all"]; ok {
			if allNum, _ := allVal.(float64); allNum == 1 {
				result["__all__"] = true
				return result
			}
		}
		// "vmid" is a comma-separated list of VMIDs.
		vmidStr, _ := job["vmid"].(string)
		for _, id := range strings.Split(vmidStr, ",") {
			id = strings.TrimSpace(id)
			if id != "" {
				result[id] = true
			}
		}
	}

	return result
}

// ---------------------------------------------------------------------------
// Security checks
// ---------------------------------------------------------------------------

// configEndpoint returns the user-configured API endpoint (ignoring any
// test override). This is used for the TLS check which inspects the
// user's real configuration, not the httptest override.
func (s *Scanner) configEndpoint() string {
	return strings.TrimRight(s.cfg.APIEndpoint, "/")
}

// checkTLS emits a finding if the API endpoint uses plain HTTP.
func (s *Scanner) checkTLS(asset string) []finding.Finding {
	ep := s.configEndpoint()
	if strings.HasPrefix(ep, "http://") {
		return []finding.Finding{{
			CheckID: finding.CheckOnpremProxmoxNoTLS,
			Title:   "Proxmox VE API accessible over HTTP without TLS",
			Description: fmt.Sprintf(
				"The Proxmox VE API at %s is served over plain HTTP. API tokens, session "+
					"cookies, and VM configuration data are transmitted in cleartext. Configure "+
					"the pveproxy service to require TLS with a valid certificate.",
				ep,
			),
			Severity:     finding.SeverityHigh,
			Asset:        asset,
			Scanner:      scannerTag,
			ProofCommand: fmt.Sprintf("curl %s/api2/json/version", ep),
			Evidence: map[string]any{
				"endpoint":      ep,
				"resource_type": "proxmox_api",
				"protocol":      "http",
			},
			DiscoveredAt: time.Now(),
		}}
	}
	return nil
}

// checkVersion emits a finding if the PVE version is below the minimum safe version.
func (s *Scanner) checkVersion(asset string, version map[string]any) []finding.Finding {
	versionStr, _ := version["version"].(string)
	if versionStr == "" {
		return nil
	}

	major, minor := parseVersion(versionStr)
	if major < minSafeMajor || (major == minSafeMajor && minor < minSafeMinor) {
		return []finding.Finding{{
			CheckID: finding.CheckOnpremProxmoxOutdatedVersion,
			Title:   fmt.Sprintf("Proxmox VE is running outdated version %s", versionStr),
			Description: fmt.Sprintf(
				"Proxmox VE version %s is below the minimum recommended version %d.%d. "+
					"Older versions have known CVEs including privilege escalation and "+
					"authentication bypass. Upgrade to the latest stable release.",
				versionStr, minSafeMajor, minSafeMinor,
			),
			Severity:     finding.SeverityHigh,
			Asset:        asset,
			Scanner:      scannerTag,
			ProofCommand: s.curlProof("/api2/json/version"),
			Evidence: map[string]any{
				"version":          versionStr,
				"release":          version["release"],
				"min_safe_version": fmt.Sprintf("%d.%d", minSafeMajor, minSafeMinor),
				"resource_type":    "proxmox_version",
			},
			DiscoveredAt: time.Now(),
		}}
	}
	return nil
}

// checkRootToken emits a finding if the configured API token belongs to root@pam.
func (s *Scanner) checkRootToken(asset string) []finding.Finding {
	if strings.HasPrefix(s.cfg.TokenID, "root@pam!") {
		return []finding.Finding{{
			CheckID: finding.CheckOnpremProxmoxRootAPIToken,
			Title:   "Proxmox API token belongs to root@pam",
			Description: fmt.Sprintf(
				"The API token %q belongs to the root@pam superuser. If this token is "+
					"compromised, an attacker gains full control of the Proxmox cluster. "+
					"Create a dedicated unprivileged user with only the permissions required "+
					"for scanning.",
				s.cfg.TokenID,
			),
			Severity:     finding.SeverityHigh,
			Asset:        asset,
			Scanner:      scannerTag,
			ProofCommand: s.curlProof("/api2/json/access/users"),
			Evidence: map[string]any{
				"token_id":      s.cfg.TokenID,
				"resource_type": "proxmox_api_token",
			},
			DiscoveredAt: time.Now(),
		}}
	}
	return nil
}

// checkDefaultCreds detects if the Proxmox API is accessible without authentication.
func (s *Scanner) checkDefaultCreds(ctx context.Context, asset string) ([]finding.Finding, error) {
	status, err := s.doUnauthRequest(ctx, "/api2/json/version")
	if err != nil {
		return nil, err
	}

	// If the API returns 200 without auth, the default configuration is dangerously open.
	if status == http.StatusOK {
		return []finding.Finding{{
			CheckID: finding.CheckOnpremProxmoxDefaultCreds,
			Title:   "Proxmox VE API accessible without authentication",
			Description: fmt.Sprintf(
				"The Proxmox VE API at %s returned HTTP 200 for an unauthenticated request. "+
					"This may indicate disabled authentication, a misconfigured reverse proxy, "+
					"or default credentials. Any network-adjacent attacker can manage the entire "+
					"hypervisor cluster.",
				s.endpoint(),
			),
			Severity:     finding.SeverityCritical,
			Asset:        asset,
			Scanner:      scannerTag,
			ProofCommand: fmt.Sprintf("curl -k %s/api2/json/version", s.endpoint()),
			Evidence: map[string]any{
				"endpoint":      s.endpoint(),
				"status_code":   status,
				"resource_type": "proxmox_api",
			},
			DiscoveredAt: time.Now(),
		}}, nil
	}

	return nil, nil
}

// checkFirewall emits a finding if the datacenter firewall is disabled.
func (s *Scanner) checkFirewall(ctx context.Context, asset string) ([]finding.Finding, error) {
	opts, err := s.fetchFirewallOptions(ctx)
	if err != nil {
		return nil, err
	}

	// The "enable" field is 0 (disabled) or 1 (enabled).
	enableVal, _ := opts["enable"].(float64)
	if enableVal == 0 {
		return []finding.Finding{{
			CheckID: finding.CheckOnpremProxmoxNoFirewall,
			Title:   "Proxmox datacenter firewall is disabled",
			Description: "The Proxmox VE datacenter-level firewall is not enabled. Without the " +
				"built-in firewall, all VMs and containers rely entirely on host-level " +
				"iptables or external network firewalls. Enable the datacenter firewall " +
				"and define appropriate rules for management, VM, and storage traffic.",
			Severity:     finding.SeverityMedium,
			Asset:        asset,
			Scanner:      scannerTag,
			ProofCommand: s.curlProof("/api2/json/cluster/firewall/options"),
			Evidence: map[string]any{
				"firewall_enabled": false,
				"resource_type":    "proxmox_firewall",
			},
			DiscoveredAt: time.Now(),
		}}, nil
	}

	return nil, nil
}

// checkHA emits a finding if the cluster has only one node (no HA).
func (s *Scanner) checkHA(ctx context.Context, asset string) ([]finding.Finding, error) {
	nodes, err := s.fetchNodes(ctx)
	if err != nil {
		return nil, err
	}

	if len(nodes) <= 1 {
		nodeName := "unknown"
		if len(nodes) == 1 {
			nodeName, _ = nodes[0]["node"].(string)
		}
		return []finding.Finding{{
			CheckID: finding.CheckOnpremProxmoxNoHA,
			Title:   fmt.Sprintf("Proxmox cluster has no HA — single node: %s", nodeName),
			Description: fmt.Sprintf(
				"The Proxmox cluster contains only one node (%s). If this node fails, all "+
					"VMs and containers become unavailable with no automatic failover. Add at "+
					"least two additional nodes and configure HA groups for critical workloads.",
				nodeName,
			),
			Severity:     finding.SeverityLow,
			Asset:        asset,
			Scanner:      scannerTag,
			ProofCommand: s.curlProof("/api2/json/nodes"),
			Evidence: map[string]any{
				"node_count":    len(nodes),
				"node_name":     nodeName,
				"resource_type": "proxmox_cluster",
			},
			DiscoveredAt: time.Now(),
		}}, nil
	}

	return nil, nil
}

// checkVMs inspects QEMU VMs on a node for missing guest agent, backups, and console exposure.
func (s *Scanner) checkVMs(ctx context.Context, asset, node string, backedUp map[string]bool) ([]finding.Finding, error) {
	vms, err := s.fetchVMs(ctx, node)
	if err != nil {
		return nil, err
	}

	var findings []finding.Finding

	for _, vm := range vms {
		vmid := jsonInt(vm["vmid"])
		vmName, _ := vm["name"].(string)
		if vmName == "" {
			vmName = fmt.Sprintf("vm-%d", vmid)
		}
		vmidStr := fmt.Sprintf("%d", vmid)

		// Fetch VM config for guest agent and console checks.
		cfg, cfgErr := s.fetchVMConfig(ctx, node, vmid)

		// Check: QEMU guest agent not enabled.
		if cfgErr == nil {
			agentVal, _ := cfg["agent"].(string)
			// agent value is "0" or absent when disabled, "1" or "1,..." when enabled.
			if !strings.HasPrefix(agentVal, "1") {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckOnpremProxmoxVMNoAgent,
					Title:   fmt.Sprintf("VM %q on node %s has no QEMU guest agent", vmName, node),
					Description: fmt.Sprintf(
						"VM %s (VMID %d) on node %s does not have the QEMU guest agent enabled. "+
							"Without the agent, Proxmox cannot perform consistent snapshots, "+
							"graceful shutdowns, or collect guest IP information. Enable the agent "+
							"in VM options and install qemu-guest-agent inside the guest OS.",
						vmName, vmid, node,
					),
					Severity:     finding.SeverityLow,
					Asset:        asset,
					Scanner:      scannerTag,
					ProofCommand: s.curlProof(fmt.Sprintf("/api2/json/nodes/%s/qemu/%d/config", node, vmid)),
					Evidence: map[string]any{
						"vm_name":       vmName,
						"vmid":          vmid,
						"node":          node,
						"agent":         agentVal,
						"resource_type": "proxmox_vm",
					},
					DiscoveredAt: time.Now(),
				})
			}

			// Check: noVNC/SPICE console accessible.
			// If a VNC or SPICE display is configured (vga field present and not "none"),
			// the console is accessible through the Proxmox web UI.
			vgaVal, _ := cfg["vga"].(string)
			if vgaVal != "" && vgaVal != "none" {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckOnpremProxmoxOpenConsole,
					Title:   fmt.Sprintf("VM %q on node %s has console access via %s", vmName, node, vgaVal),
					Description: fmt.Sprintf(
						"VM %s (VMID %d) on node %s has a graphical console configured (vga=%s). "+
							"Any user with Proxmox web UI access can open a noVNC or SPICE session "+
							"to this VM. Restrict console access via Proxmox permissions or set "+
							"vga=none for headless workloads.",
						vmName, vmid, node, vgaVal,
					),
					Severity:     finding.SeverityMedium,
					Asset:        asset,
					Scanner:      scannerTag,
					ProofCommand: s.curlProof(fmt.Sprintf("/api2/json/nodes/%s/qemu/%d/config", node, vmid)),
					Evidence: map[string]any{
						"vm_name":       vmName,
						"vmid":          vmid,
						"node":          node,
						"vga":           vgaVal,
						"resource_type": "proxmox_vm",
					},
					DiscoveredAt: time.Now(),
				})
			}
		}

		// Check: VM has no backup schedule.
		if !backedUp["__all__"] && !backedUp[vmidStr] {
			findings = append(findings, finding.Finding{
				CheckID: finding.CheckOnpremProxmoxVMNoBackup,
				Title:   fmt.Sprintf("VM %q on node %s has no backup schedule", vmName, node),
				Description: fmt.Sprintf(
					"VM %s (VMID %d) on node %s is not included in any Proxmox backup schedule. "+
						"Without regular backups, a disk failure or misconfiguration could cause "+
						"permanent data loss. Add this VM to a backup job in Datacenter > Backup.",
					vmName, vmid, node,
				),
				Severity:     finding.SeverityMedium,
				Asset:        asset,
				Scanner:      scannerTag,
				ProofCommand: s.curlProof("/api2/json/cluster/backup"),
				Evidence: map[string]any{
					"vm_name":       vmName,
					"vmid":          vmid,
					"node":          node,
					"resource_type": "proxmox_vm",
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings, nil
}

// checkContainers inspects LXC containers on a node for privileged mode and missing backups.
func (s *Scanner) checkContainers(ctx context.Context, asset, node string, backedUp map[string]bool) ([]finding.Finding, error) {
	cts, err := s.fetchContainers(ctx, node)
	if err != nil {
		return nil, err
	}

	var findings []finding.Finding

	for _, ct := range cts {
		vmid := jsonInt(ct["vmid"])
		ctName, _ := ct["name"].(string)
		if ctName == "" {
			ctName = fmt.Sprintf("ct-%d", vmid)
		}
		vmidStr := fmt.Sprintf("%d", vmid)

		// Fetch container config for unprivileged check.
		cfg, cfgErr := s.fetchContainerConfig(ctx, node, vmid)

		// Check: privileged container.
		if cfgErr == nil {
			unprivilegedVal, _ := cfg["unprivileged"].(float64)
			if unprivilegedVal == 0 {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckOnpremProxmoxPrivilegedCT,
					Title:   fmt.Sprintf("LXC container %q on node %s runs in privileged mode", ctName, node),
					Description: fmt.Sprintf(
						"LXC container %s (VMID %d) on node %s is running in privileged mode. "+
							"Privileged containers share the host's UID namespace and a container "+
							"escape gives immediate root access to the hypervisor. Convert to an "+
							"unprivileged container unless the workload specifically requires "+
							"host-level device access.",
						ctName, vmid, node,
					),
					Severity:     finding.SeverityHigh,
					Asset:        asset,
					Scanner:      scannerTag,
					ProofCommand: s.curlProof(fmt.Sprintf("/api2/json/nodes/%s/lxc/%d/config", node, vmid)),
					Evidence: map[string]any{
						"ct_name":       ctName,
						"vmid":          vmid,
						"node":          node,
						"unprivileged":  0,
						"resource_type": "proxmox_lxc",
					},
					DiscoveredAt: time.Now(),
				})
			}
		}

		// Check: container has no backup schedule.
		if !backedUp["__all__"] && !backedUp[vmidStr] {
			findings = append(findings, finding.Finding{
				CheckID: finding.CheckOnpremProxmoxVMNoBackup,
				Title:   fmt.Sprintf("Container %q on node %s has no backup schedule", ctName, node),
				Description: fmt.Sprintf(
					"LXC container %s (VMID %d) on node %s is not included in any Proxmox backup "+
						"schedule. Without regular backups, a disk failure or misconfiguration could "+
						"cause permanent data loss. Add this container to a backup job.",
					ctName, vmid, node,
				),
				Severity:     finding.SeverityMedium,
				Asset:        asset,
				Scanner:      scannerTag,
				ProofCommand: s.curlProof("/api2/json/cluster/backup"),
				Evidence: map[string]any{
					"ct_name":       ctName,
					"vmid":          vmid,
					"node":          node,
					"resource_type": "proxmox_lxc",
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings, nil
}

// checkStorage inspects storage backends on a node for missing encryption.
func (s *Scanner) checkStorage(ctx context.Context, asset, node string) ([]finding.Finding, error) {
	storages, err := s.fetchStorage(ctx, node)
	if err != nil {
		return nil, err
	}

	var findings []finding.Finding

	// Storage types that support encryption at rest natively.
	encryptableTypes := map[string]bool{
		"zfspool": true, "zfs": true, "rbd": true, "cephfs": true, "lvm": true, "lvmthin": true,
	}

	for _, st := range storages {
		storageName, _ := st["storage"].(string)
		storageType, _ := st["type"].(string)

		// Only flag storage types where encryption is feasible.
		if !encryptableTypes[storageType] {
			continue
		}

		// Proxmox does not expose an "encrypted" field in the storage API.
		// The presence of a storage type that supports but does not indicate
		// encryption warrants a check.
		findings = append(findings, finding.Finding{
			CheckID: finding.CheckOnpremProxmoxStorageNoEncrypt,
			Title:   fmt.Sprintf("Storage %q on node %s has no encryption at rest", storageName, node),
			Description: fmt.Sprintf(
				"Storage backend %q (type: %s) on node %s does not have encryption at rest "+
					"configured. If the physical storage is stolen or decommissioned, data is "+
					"accessible in plaintext. Enable LUKS, ZFS native encryption, or Ceph "+
					"encryption depending on the backend type.",
				storageName, storageType, node,
			),
			Severity:     finding.SeverityMedium,
			Asset:        asset,
			Scanner:      scannerTag,
			ProofCommand: s.curlProof(fmt.Sprintf("/api2/json/nodes/%s/storage", node)),
			Evidence: map[string]any{
				"storage_name": storageName,
				"storage_type": storageType,
				"node":         node,
				"resource_type": "proxmox_storage",
			},
			DiscoveredAt: time.Now(),
		})
	}

	return findings, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// scanError creates a scan-error finding.
func (s *Scanner) scanError(asset, description string) finding.Finding {
	return finding.Finding{
		CheckID:      finding.CheckOnpremProxmoxScanError,
		Title:        "Proxmox VE scan error",
		Description:  description,
		Severity:     finding.SeverityInfo,
		Asset:        asset,
		Scanner:      scannerTag,
		DiscoveredAt: time.Now(),
	}
}

// parseVersion extracts major.minor from a version string like "8.1.4".
func parseVersion(v string) (major, minor int) {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) >= 1 {
		_, _ = fmt.Sscanf(parts[0], "%d", &major)
	}
	if len(parts) >= 2 {
		_, _ = fmt.Sscanf(parts[1], "%d", &minor)
	}
	return
}

// jsonInt extracts an integer from a JSON number (float64) or string.
func jsonInt(v any) int {
	switch val := v.(type) {
	case float64:
		return int(val)
	case string:
		var n int
		_, _ = fmt.Sscanf(val, "%d", &n)
		return n
	default:
		return 0
	}
}

// truncate shortens s to at most maxLen characters.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
