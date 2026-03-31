// Package vmware implements a deep-mode scanner for VMware vCenter/ESXi hosts.
// It queries the vSphere REST API to detect host and VM security misconfigurations
// including SSH/shell services, lockdown mode, VMware Tools status, copy/paste
// isolation, disk shrink, drag-drop, default certificates, and datastore encryption.
package vmware

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const scannerName = "onprem/vmware"

// Config holds VMware vSphere connection parameters.
type Config struct {
	Endpoint      string // vCenter/ESXi REST API URL (e.g., "https://vcenter.local")
	Username      string
	Password      string
	SkipTLSVerify bool
}

// Scanner probes VMware vCenter/ESXi hosts for security misconfigurations.
type Scanner struct {
	cfg    Config
	client *http.Client
}

// New returns a new Scanner with the given configuration.
// If client is nil, a default HTTP client is created based on config.
func New(cfg Config, client *http.Client) *Scanner {
	if client == nil {
		tr := &http.Transport{}
		if cfg.SkipTLSVerify {
			tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}
		client = &http.Client{Timeout: 30 * time.Second, Transport: tr}
	}
	return &Scanner{cfg: cfg, client: client}
}

// Name returns the stable scanner identifier.
func (s *Scanner) Name() string { return scannerName }

// --------------------------------------------------------------------------
// vSphere REST API response types
// --------------------------------------------------------------------------

type sessionResponse struct {
	Value string `json:"value"`
}

type esxiHost struct {
	Host           string `json:"host"`
	Name           string `json:"name"`
	ConnectionState string `json:"connection_state"`
	PowerState     string `json:"power_state"`
}

type hostListResponse struct {
	Value []esxiHost `json:"value"`
}

type vmSummary struct {
	VM        string `json:"vm"`
	Name      string `json:"name"`
	PowerState string `json:"power_state"`
}

type vmListResponse struct {
	Value []vmSummary `json:"value"`
}

type vmExtraConfig struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type vmDetail struct {
	Name  string `json:"name"`
	Guest struct {
		ToolsStatus      string `json:"tools_status"`
		ToolsVersionStatus string `json:"tools_version_status"`
	} `json:"guest"`
	ExtraConfig []vmExtraConfig `json:"-"` // populated from extraConfigs field if present
}

type vmDetailResponse struct {
	Value vmDetail `json:"value"`
}

type datastore struct {
	Datastore string `json:"datastore"`
	Name      string `json:"name"`
	Type      string `json:"type"`
}

type datastoreListResponse struct {
	Value []datastore `json:"value"`
}

// --------------------------------------------------------------------------
// Run
// --------------------------------------------------------------------------

// Run executes the VMware vSphere scanner. This scanner requires Deep mode
// because it authenticates to the vSphere REST API and queries host/VM state.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanDeep && scanType != module.ScanAuthorized {
		return nil, nil
	}

	endpoint := s.cfg.Endpoint
	if endpoint == "" {
		endpoint = "https://" + asset
	}
	endpoint = strings.TrimRight(endpoint, "/")

	var findings []finding.Finding

	// Authenticate to vSphere REST API.
	token, err := s.authenticate(ctx, endpoint)
	if err != nil {
		findings = append(findings, finding.Finding{
			CheckID:      finding.CheckOnpremVMwareScanError,
			Scanner:      scannerName,
			Severity:     finding.SeverityInfo,
			Title:        fmt.Sprintf("VMware API scan failed on %s", endpoint),
			Description:  fmt.Sprintf("Could not authenticate to vSphere REST API at %s: %v", endpoint, err),
			Asset:        asset,
			ProofCommand: fmt.Sprintf("curl -sk -X POST '%s/api/session' -u '%s:***'", endpoint, s.cfg.Username),
			Evidence: map[string]any{
				"endpoint": endpoint,
				"error":    err.Error(),
			},
			DiscoveredAt: time.Now(),
		})
		return findings, nil
	}

	// Check for default/self-signed certificates by examining TLS.
	if s.cfg.SkipTLSVerify {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckOnpremVMwareDefaultCerts,
			Scanner:  scannerName,
			Severity: finding.SeverityMedium,
			Title:    fmt.Sprintf("VMware vCenter/ESXi at %s uses untrusted TLS certificate", asset),
			Description: fmt.Sprintf(
				"vSphere API at %s required TLS verification to be skipped, indicating "+
					"a self-signed or default certificate. This enables man-in-the-middle attacks.",
				endpoint,
			),
			Asset:        asset,
			ProofCommand: fmt.Sprintf("openssl s_client -connect %s:443 </dev/null 2>&1 | openssl x509 -noout -issuer -subject", asset),
			Evidence: map[string]any{
				"endpoint":        endpoint,
				"skip_tls_verify": true,
			},
			DiscoveredAt: time.Now(),
		})
	}

	// Enumerate ESXi hosts.
	findings = append(findings, s.scanHosts(ctx, endpoint, token, asset)...)

	// Enumerate VMs.
	findings = append(findings, s.scanVMs(ctx, endpoint, token, asset)...)

	// Enumerate datastores.
	findings = append(findings, s.scanDatastores(ctx, endpoint, token, asset)...)

	return findings, nil
}

// --------------------------------------------------------------------------
// Authentication
// --------------------------------------------------------------------------

func (s *Scanner) authenticate(ctx context.Context, endpoint string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/api/session", nil)
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(s.cfg.Username, s.cfg.Password)

	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("authentication failed: HTTP %d: %s", resp.StatusCode, string(body))
	}

	// The session endpoint may return the token as a plain JSON string or
	// wrapped in a {"value":"..."} envelope.
	token := strings.Trim(string(body), "\" \n\r\t")
	if token == "" {
		var sr sessionResponse
		if err := json.Unmarshal(body, &sr); err == nil && sr.Value != "" {
			token = sr.Value
		}
	}
	if token == "" {
		return "", fmt.Errorf("empty session token")
	}
	return token, nil
}

// --------------------------------------------------------------------------
// Host scanning
// --------------------------------------------------------------------------

func (s *Scanner) scanHosts(ctx context.Context, endpoint, token, asset string) []finding.Finding {
	var findings []finding.Finding

	hosts, err := s.listHosts(ctx, endpoint, token)
	if err != nil {
		return findings
	}

	for _, h := range hosts {
		// Check SSH service.
		if s.isServiceRunning(ctx, endpoint, token, h.Host, "SSH") {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckOnpremVMwareESXiSSH,
				Scanner:  scannerName,
				Severity: finding.SeverityMedium,
				Title:    fmt.Sprintf("ESXi host %s has SSH service enabled", h.Name),
				Description: fmt.Sprintf(
					"ESXi host %s (%s) has SSH enabled. SSH should be disabled in production "+
						"to reduce the attack surface. Use the DCUI or vSphere Client for management.",
					h.Name, h.Host,
				),
				Asset:        asset,
				ProofCommand: fmt.Sprintf("curl -sk -H 'vmware-api-session-id: SESSION' '%s/api/vcenter/host'", endpoint),
				Evidence: map[string]any{
					"host_id":   h.Host,
					"host_name": h.Name,
					"service":   "SSH",
				},
				DiscoveredAt: time.Now(),
			})
		}

		// Check ESXi Shell service.
		if s.isServiceRunning(ctx, endpoint, token, h.Host, "shell") {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckOnpremVMwareESXiShell,
				Scanner:  scannerName,
				Severity: finding.SeverityMedium,
				Title:    fmt.Sprintf("ESXi host %s has ESXi Shell enabled", h.Name),
				Description: fmt.Sprintf(
					"ESXi host %s (%s) has ESXi Shell enabled. The shell provides direct "+
						"access to the hypervisor and should be disabled when not in use.",
					h.Name, h.Host,
				),
				Asset:        asset,
				ProofCommand: fmt.Sprintf("curl -sk -H 'vmware-api-session-id: SESSION' '%s/api/vcenter/host'", endpoint),
				Evidence: map[string]any{
					"host_id":   h.Host,
					"host_name": h.Name,
					"service":   "ESXi Shell",
				},
				DiscoveredAt: time.Now(),
			})
		}

		// Check lockdown mode.
		if !s.isLockdownEnabled(ctx, endpoint, token, h.Host) {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckOnpremVMwareNoLockdown,
				Scanner:  scannerName,
				Severity: finding.SeverityHigh,
				Title:    fmt.Sprintf("ESXi host %s not in lockdown mode", h.Name),
				Description: fmt.Sprintf(
					"ESXi host %s (%s) is not in lockdown mode. Lockdown mode restricts "+
						"direct API access to the host, forcing all management through vCenter. "+
						"Without lockdown, compromised credentials allow direct host manipulation.",
					h.Name, h.Host,
				),
				Asset:        asset,
				ProofCommand: fmt.Sprintf("curl -sk -H 'vmware-api-session-id: SESSION' '%s/api/vcenter/host'", endpoint),
				Evidence: map[string]any{
					"host_id":       h.Host,
					"host_name":     h.Name,
					"lockdown_mode": "disabled",
				},
				DiscoveredAt: time.Now(),
			})
		}

		// Check ESXi version for outdated/vulnerable releases.
		version := s.getHostVersion(ctx, endpoint, token, h.Host)
		if version != "" && isOutdatedESXi(version) {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckOnpremVMwareOutdatedVersion,
				Scanner:  scannerName,
				Severity: finding.SeverityHigh,
				Title:    fmt.Sprintf("ESXi host %s runs outdated version %s", h.Name, version),
				Description: fmt.Sprintf(
					"ESXi host %s (%s) is running version %s which has known CVEs. "+
						"Update to the latest ESXi release to mitigate known vulnerabilities.",
					h.Name, h.Host, version,
				),
				Asset:        asset,
				ProofCommand: fmt.Sprintf("curl -sk -H 'vmware-api-session-id: SESSION' '%s/api/vcenter/host'", endpoint),
				Evidence: map[string]any{
					"host_id":   h.Host,
					"host_name": h.Name,
					"version":   version,
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings
}

// --------------------------------------------------------------------------
// VM scanning
// --------------------------------------------------------------------------

func (s *Scanner) scanVMs(ctx context.Context, endpoint, token, asset string) []finding.Finding {
	var findings []finding.Finding

	vms, err := s.listVMs(ctx, endpoint, token)
	if err != nil {
		return findings
	}

	for _, vm := range vms {
		detail, err := s.getVMDetail(ctx, endpoint, token, vm.VM)
		if err != nil {
			continue
		}

		vmName := vm.Name
		if vmName == "" {
			vmName = vm.VM
		}

		proofCmd := fmt.Sprintf("curl -sk -H 'vmware-api-session-id: SESSION' '%s/api/vcenter/vm/%s'", endpoint, vm.VM)

		// Check VMware Tools.
		if detail.Guest.ToolsStatus == "" || detail.Guest.ToolsStatus == "toolsNotInstalled" || detail.Guest.ToolsStatus == "toolsNotRunning" {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckOnpremVMwareVMNoTools,
				Scanner:  scannerName,
				Severity: finding.SeverityLow,
				Title:    fmt.Sprintf("VM %s has no VMware Tools installed or running", vmName),
				Description: fmt.Sprintf(
					"VM %s (%s) does not have VMware Tools installed or running. VMware Tools "+
						"provides guest OS heartbeat, graceful shutdown, and security patching "+
						"integration. Without it, the VM cannot be managed effectively.",
					vmName, vm.VM,
				),
				Asset:        asset,
				ProofCommand: proofCmd,
				Evidence: map[string]any{
					"vm_id":        vm.VM,
					"vm_name":      vmName,
					"tools_status": detail.Guest.ToolsStatus,
				},
				DiscoveredAt: time.Now(),
			})
		}

		// Check copy/paste isolation.
		if extraConfigEnabled(detail.ExtraConfig, "isolation.tools.copy.disable", "FALSE") ||
			extraConfigEnabled(detail.ExtraConfig, "isolation.tools.paste.disable", "FALSE") {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckOnpremVMwareVMCopyPaste,
				Scanner:  scannerName,
				Severity: finding.SeverityLow,
				Title:    fmt.Sprintf("VM %s allows copy/paste between guest and host", vmName),
				Description: fmt.Sprintf(
					"VM %s (%s) has copy/paste enabled between guest and host. This "+
						"allows data exfiltration from the guest OS through the clipboard. "+
						"Disable isolation.tools.copy.disable and isolation.tools.paste.disable.",
					vmName, vm.VM,
				),
				Asset:        asset,
				ProofCommand: proofCmd,
				Evidence: map[string]any{
					"vm_id":   vm.VM,
					"vm_name": vmName,
					"setting": "copy_paste_enabled",
				},
				DiscoveredAt: time.Now(),
			})
		}

		// Check disk shrink.
		if extraConfigEnabled(detail.ExtraConfig, "isolation.tools.diskShrink.disable", "FALSE") {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckOnpremVMwareVMDiskShrink,
				Scanner:  scannerName,
				Severity: finding.SeverityMedium,
				Title:    fmt.Sprintf("VM %s allows disk shrinking", vmName),
				Description: fmt.Sprintf(
					"VM %s (%s) has disk shrinking enabled. A guest OS user can issue "+
						"disk shrink operations which can cause denial of service on the "+
						"datastore. Disable isolation.tools.diskShrink.disable.",
					vmName, vm.VM,
				),
				Asset:        asset,
				ProofCommand: proofCmd,
				Evidence: map[string]any{
					"vm_id":   vm.VM,
					"vm_name": vmName,
					"setting": "disk_shrink_enabled",
				},
				DiscoveredAt: time.Now(),
			})
		}

		// Check drag-drop.
		if extraConfigEnabled(detail.ExtraConfig, "isolation.tools.dnd.disable", "FALSE") {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckOnpremVMwareVMDragDrop,
				Scanner:  scannerName,
				Severity: finding.SeverityLow,
				Title:    fmt.Sprintf("VM %s allows drag-drop file transfer", vmName),
				Description: fmt.Sprintf(
					"VM %s (%s) has drag-drop enabled between guest and host. This "+
						"provides another file transfer vector for data exfiltration. "+
						"Disable isolation.tools.dnd.disable.",
					vmName, vm.VM,
				),
				Asset:        asset,
				ProofCommand: proofCmd,
				Evidence: map[string]any{
					"vm_id":   vm.VM,
					"vm_name": vmName,
					"setting": "drag_drop_enabled",
				},
				DiscoveredAt: time.Now(),
			})
		}

		// Check snapshots.
		if !s.vmHasSnapshots(ctx, endpoint, token, vm.VM) {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckOnpremVMwareVMNoSnapshot,
				Scanner:  scannerName,
				Severity: finding.SeverityLow,
				Title:    fmt.Sprintf("VM %s has no snapshots", vmName),
				Description: fmt.Sprintf(
					"VM %s (%s) has no snapshots. Without snapshots, there is no quick "+
						"rollback capability in case of ransomware or configuration errors.",
					vmName, vm.VM,
				),
				Asset:        asset,
				ProofCommand: proofCmd,
				Evidence: map[string]any{
					"vm_id":     vm.VM,
					"vm_name":   vmName,
					"snapshots": 0,
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings
}

// --------------------------------------------------------------------------
// Datastore scanning
// --------------------------------------------------------------------------

func (s *Scanner) scanDatastores(ctx context.Context, endpoint, token, asset string) []finding.Finding {
	var findings []finding.Finding

	datastores, err := s.listDatastores(ctx, endpoint, token)
	if err != nil {
		return findings
	}

	for _, ds := range datastores {
		// VMFS and NFS datastores typically lack native encryption.
		// vSAN datastores support encryption natively.
		if ds.Type != "vsan" {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckOnpremVMwareDatastoreNoEncrypt,
				Scanner:  scannerName,
				Severity: finding.SeverityMedium,
				Title:    fmt.Sprintf("Datastore %s (%s) has no native encryption", ds.Name, ds.Type),
				Description: fmt.Sprintf(
					"Datastore %s (%s type, ID %s) does not use vSAN encryption or VM-level "+
						"encryption. Data at rest on this datastore may be accessible if "+
						"physical disks are stolen or improperly decommissioned.",
					ds.Name, ds.Type, ds.Datastore,
				),
				Asset:        asset,
				ProofCommand: fmt.Sprintf("curl -sk -H 'vmware-api-session-id: SESSION' '%s/api/vcenter/datastore'", endpoint),
				Evidence: map[string]any{
					"datastore_id":   ds.Datastore,
					"datastore_name": ds.Name,
					"datastore_type": ds.Type,
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings
}

// --------------------------------------------------------------------------
// API helpers
// --------------------------------------------------------------------------

func (s *Scanner) apiGet(ctx context.Context, endpoint, token, path string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+path, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("vmware-api-session-id", token)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

func (s *Scanner) listHosts(ctx context.Context, endpoint, token string) ([]esxiHost, error) {
	body, status, err := s.apiGet(ctx, endpoint, token, "/api/vcenter/host")
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("list hosts returned HTTP %d", status)
	}
	// Try direct array first, then wrapped response.
	var hosts []esxiHost
	if err := json.Unmarshal(body, &hosts); err == nil {
		return hosts, nil
	}
	var wrapped hostListResponse
	if err := json.Unmarshal(body, &wrapped); err != nil {
		return nil, fmt.Errorf("decode hosts: %w", err)
	}
	return wrapped.Value, nil
}

func (s *Scanner) listVMs(ctx context.Context, endpoint, token string) ([]vmSummary, error) {
	body, status, err := s.apiGet(ctx, endpoint, token, "/api/vcenter/vm")
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("list VMs returned HTTP %d", status)
	}
	var vms []vmSummary
	if err := json.Unmarshal(body, &vms); err == nil {
		return vms, nil
	}
	var wrapped vmListResponse
	if err := json.Unmarshal(body, &wrapped); err != nil {
		return nil, fmt.Errorf("decode VMs: %w", err)
	}
	return wrapped.Value, nil
}

func (s *Scanner) getVMDetail(ctx context.Context, endpoint, token, vmID string) (*vmDetail, error) {
	body, status, err := s.apiGet(ctx, endpoint, token, "/api/vcenter/vm/"+vmID)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("VM detail %s returned HTTP %d", vmID, status)
	}
	// Try direct parse first, then wrapped.
	var detail vmDetail
	if err := json.Unmarshal(body, &detail); err == nil && detail.Name != "" {
		// Parse extra_configs from raw JSON.
		detail.ExtraConfig = parseExtraConfigs(body)
		return &detail, nil
	}
	var wrapped vmDetailResponse
	if err := json.Unmarshal(body, &wrapped); err != nil {
		return nil, fmt.Errorf("decode VM detail %s: %w", vmID, err)
	}
	wrapped.Value.ExtraConfig = parseExtraConfigs(body)
	return &wrapped.Value, nil
}

func (s *Scanner) listDatastores(ctx context.Context, endpoint, token string) ([]datastore, error) {
	body, status, err := s.apiGet(ctx, endpoint, token, "/api/vcenter/datastore")
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("list datastores returned HTTP %d", status)
	}
	var datastores []datastore
	if err := json.Unmarshal(body, &datastores); err == nil {
		return datastores, nil
	}
	var wrapped datastoreListResponse
	if err := json.Unmarshal(body, &wrapped); err != nil {
		return nil, fmt.Errorf("decode datastores: %w", err)
	}
	return wrapped.Value, nil
}

// isServiceRunning checks if an ESXi service (e.g., SSH, shell) is reported
// as running. Since the REST API does not directly expose per-host service
// status, the scanner checks via the host summary response.
func (s *Scanner) isServiceRunning(ctx context.Context, endpoint, token, hostID, service string) bool {
	body, status, err := s.apiGet(ctx, endpoint, token, "/api/vcenter/host/"+hostID)
	if err != nil || status != http.StatusOK {
		return false
	}
	// Parse the host detail for services field.
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return false
	}
	// Check services array or service-specific field.
	if services, ok := raw["services"].([]any); ok {
		for _, svc := range services {
			if m, ok := svc.(map[string]any); ok {
				svcKey, _ := m["key"].(string)
				running, _ := m["running"].(bool)
				if strings.EqualFold(svcKey, service) && running {
					return true
				}
			}
		}
	}
	// Also check direct fields like "ssh_enabled" or "shell_enabled".
	lowerService := strings.ToLower(service)
	if v, ok := raw[lowerService+"_enabled"]; ok {
		if enabled, ok := v.(bool); ok && enabled {
			return true
		}
	}
	if v, ok := raw[lowerService+"_running"]; ok {
		if running, ok := v.(bool); ok && running {
			return true
		}
	}
	return false
}

// isLockdownEnabled checks if a host has lockdown mode enabled.
func (s *Scanner) isLockdownEnabled(ctx context.Context, endpoint, token, hostID string) bool {
	body, status, err := s.apiGet(ctx, endpoint, token, "/api/vcenter/host/"+hostID)
	if err != nil || status != http.StatusOK {
		return true // assume secure on error
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return true
	}
	// lockdown_mode or lockdown field.
	if mode, ok := raw["lockdown_mode"].(string); ok {
		return mode != "DISABLED" && mode != "disabled" && mode != ""
	}
	if lockdown, ok := raw["lockdown"].(bool); ok {
		return lockdown
	}
	return false
}

// getHostVersion attempts to extract the ESXi version string from host detail.
func (s *Scanner) getHostVersion(ctx context.Context, endpoint, token, hostID string) string {
	body, status, err := s.apiGet(ctx, endpoint, token, "/api/vcenter/host/"+hostID)
	if err != nil || status != http.StatusOK {
		return ""
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return ""
	}
	if version, ok := raw["version"].(string); ok {
		return version
	}
	if product, ok := raw["product"].(map[string]any); ok {
		if v, ok := product["version"].(string); ok {
			return v
		}
	}
	return ""
}

// vmHasSnapshots checks if a VM has any snapshots.
func (s *Scanner) vmHasSnapshots(ctx context.Context, endpoint, token, vmID string) bool {
	body, status, err := s.apiGet(ctx, endpoint, token, "/api/vcenter/vm/"+vmID+"/snapshots")
	if err != nil || status != http.StatusOK {
		// If the snapshots endpoint fails, also check the VM detail.
		body2, status2, err2 := s.apiGet(ctx, endpoint, token, "/api/vcenter/vm/"+vmID)
		if err2 != nil || status2 != http.StatusOK {
			return true // assume has snapshots on error
		}
		var raw map[string]any
		if err := json.Unmarshal(body2, &raw); err != nil {
			return true
		}
		if snapshots, ok := raw["snapshots"].([]any); ok {
			return len(snapshots) > 0
		}
		return false
	}
	// Parse snapshots list.
	var snapshots []any
	if err := json.Unmarshal(body, &snapshots); err == nil {
		return len(snapshots) > 0
	}
	return false
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

// parseExtraConfigs extracts extra_config / extraConfig entries from raw JSON.
func parseExtraConfigs(data []byte) []vmExtraConfig {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}
	for _, key := range []string{"extra_config", "extraConfig", "extra_configs"} {
		if v, ok := raw[key]; ok {
			var configs []vmExtraConfig
			if err := json.Unmarshal(v, &configs); err == nil {
				return configs
			}
		}
	}
	// Also check nested value.
	if v, ok := raw["value"]; ok {
		var inner map[string]json.RawMessage
		if err := json.Unmarshal(v, &inner); err == nil {
			for _, key := range []string{"extra_config", "extraConfig", "extra_configs"} {
				if ec, ok := inner[key]; ok {
					var configs []vmExtraConfig
					if err := json.Unmarshal(ec, &configs); err == nil {
						return configs
					}
				}
			}
		}
	}
	return nil
}

// extraConfigEnabled checks if a specific key in the VM's extra config is set
// to a given value (case-insensitive). Returns true if the key exists and matches.
func extraConfigEnabled(configs []vmExtraConfig, key, value string) bool {
	for _, c := range configs {
		if strings.EqualFold(c.Key, key) && strings.EqualFold(c.Value, value) {
			return true
		}
	}
	return false
}

// isOutdatedESXi checks if the given version is known to have CVEs.
// This is a simplified check against known-vulnerable major versions.
var outdatedESXiVersions = []string{
	"5.", "6.0", "6.5", "6.7",
}

func isOutdatedESXi(version string) bool {
	for _, prefix := range outdatedESXiVersions {
		if strings.HasPrefix(version, prefix) {
			return true
		}
	}
	return false
}
