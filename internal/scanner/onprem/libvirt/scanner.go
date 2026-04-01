// Package libvirt implements security scanning for libvirt/KVM hypervisors.
// It checks for unauthenticated TCP listeners, missing TLS, and VM/network
// configuration issues. For VM and network inventory, it connects to a
// lightweight REST proxy (e.g., cockpit-machines or a custom HTTP wrapper)
// that exposes libvirt domain and network data as JSON.
package libvirt

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)

const (
	maxBody    = 10 << 20 // 10 MiB limit on response bodies
	scannerTag = "onprem/libvirt"

	// Default libvirt listener ports.
	portTCP = "16509" // libvirtd plain TCP (no auth)
	portTLS = "16514" // libvirtd TLS

	dialTimeout = 5 * time.Second
)

// Config holds libvirt scanner configuration.
type Config struct {
	// Endpoint is the REST proxy URL for VM/network inventory
	// (e.g., "http://192.168.1.50:8080").
	Endpoint string

	// Host is the libvirt hypervisor hostname or IP used for TCP/TLS
	// port checks. If empty, it is derived from Endpoint.
	Host string

	// SkipTLSVerify disables TLS certificate verification for the REST proxy.
	SkipTLSVerify bool
}

// domain represents a libvirt domain (VM) returned by the REST proxy.
type domain struct {
	Name       string       `json:"name"`
	UUID       string       `json:"uuid"`
	State      string       `json:"state"`
	VCPUs      int          `json:"vcpus"`
	MemoryMB   int          `json:"memory_mb"`
	OS         domainOS     `json:"os"`
	Features   domainFeat   `json:"features"`
	DiskFormat string       `json:"disk_format"`
	MemBalloon string       `json:"memballoon"`
	NetMode    string       `json:"network_mode"`
}

type domainOS struct {
	Type string `json:"type"`
	Arch string `json:"arch"`
	Boot string `json:"boot"`
}

type domainFeat struct {
	SecureBoot bool `json:"secure_boot"`
}

// network represents a libvirt virtual network returned by the REST proxy.
type network struct {
	Name   string `json:"name"`
	Mode   string `json:"mode"`
	Bridge string `json:"bridge"`
	DHCP   bool   `json:"dhcp"`
}

// Scanner runs libvirt/KVM security checks.
type Scanner struct {
	cfg    Config
	client *http.Client

	// baseURL overrides cfg.Endpoint for testing.
	baseURL string

	// dialFunc overrides net.DialTimeout for testing TCP/TLS port checks.
	dialFunc func(network, address string, timeout time.Duration) (net.Conn, error)
}

// New creates a new libvirt scanner.
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

// SetBaseURL overrides the REST proxy base URL. Used in tests.
func (s *Scanner) SetBaseURL(u string) { s.baseURL = u }

// SetDialFunc overrides the TCP dial function. Used in tests to point at
// local listeners instead of real hosts.
func (s *Scanner) SetDialFunc(fn func(string, string, time.Duration) (net.Conn, error)) {
	s.dialFunc = fn
}

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return scannerTag }

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanDeep && scanType != module.ScanAuthorized {
		return nil, nil
	}

	host := s.host()

	var all []finding.Finding

	// Check 1: TCP listener without auth on port 16509.
	tcpOpen := false
	if host != "" {
		open, findings := s.checkTCPNoAuth(asset, host)
		all = append(all, findings...)
		tcpOpen = open
	}

	// Check 2: TLS listener on port 16514 (only relevant when TCP is open).
	if host != "" && tcpOpen {
		all = append(all, s.checkTLSDisabled(asset, host)...)
	}

	// REST proxy checks — require a configured endpoint.
	ep := s.endpoint()
	if ep == "" {
		// No REST proxy configured; return just port-check findings.
		return all, nil
	}

	// Check 3: VM inventory.
	domains, err := s.fetchDomains(ctx)
	if err != nil {
		all = append(all, s.scanError(asset, fmt.Sprintf("domain listing failed: %v", err)))
	} else {
		all = append(all, s.checkDomains(asset, host, domains)...)
	}

	// Check 4: Network inventory.
	networks, err := s.fetchNetworks(ctx)
	if err != nil {
		all = append(all, s.scanError(asset, fmt.Sprintf("network listing failed: %v", err)))
	} else {
		all = append(all, s.checkNetworks(asset, host, networks)...)
	}

	return all, nil
}

// ---------------------------------------------------------------------------
// Host / endpoint helpers
// ---------------------------------------------------------------------------

// host returns the hypervisor host for TCP/TLS port checks.
func (s *Scanner) host() string {
	if s.cfg.Host != "" {
		return s.cfg.Host
	}
	// Derive from endpoint URL.
	ep := s.cfg.Endpoint
	if ep == "" {
		return ""
	}
	ep = strings.TrimPrefix(ep, "http://")
	ep = strings.TrimPrefix(ep, "https://")
	// Strip path.
	if idx := strings.Index(ep, "/"); idx >= 0 {
		ep = ep[:idx]
	}
	// Strip port.
	h, _, err := net.SplitHostPort(ep)
	if err != nil {
		return ep // no port in the string
	}
	return h
}

// endpoint returns the effective REST proxy base URL.
func (s *Scanner) endpoint() string {
	if s.baseURL != "" {
		return s.baseURL
	}
	return strings.TrimRight(s.cfg.Endpoint, "/")
}

// dial wraps net.DialTimeout, allowing tests to inject a custom dialer.
func (s *Scanner) dial(network, address string, timeout time.Duration) (net.Conn, error) {
	if s.dialFunc != nil {
		return s.dialFunc(network, address, timeout)
	}
	return net.DialTimeout(network, address, timeout)
}

// ---------------------------------------------------------------------------
// Port checks
// ---------------------------------------------------------------------------

// checkTCPNoAuth probes port 16509 (libvirt plain TCP). If the port is open,
// it means libvirtd is accepting unauthenticated remote connections.
// Returns whether the port was open plus any findings.
func (s *Scanner) checkTCPNoAuth(asset, host string) (bool, []finding.Finding) {
	addr := net.JoinHostPort(host, portTCP)
	conn, err := s.dial("tcp", addr, dialTimeout)
	if err != nil {
		return false, nil
	}
	_ = conn.Close()

	return true, []finding.Finding{{
		CheckID: finding.CheckOnpremLibvirtTCPNoAuth,
		Title:   fmt.Sprintf("libvirt TCP listener open without authentication on %s", addr),
		Description: fmt.Sprintf(
			"The libvirt daemon on %s is listening on TCP port %s without authentication. "+
				"Any host that can reach this port has full read/write access to all VMs, "+
				"storage pools, and virtual networks. Disable the TCP listener in "+
				"/etc/libvirt/libvirtd.conf (listen_tcp = 0) and use TLS or SSH transport instead.",
			host, portTCP,
		),
		Severity:     finding.SeverityCritical,
		Asset:        asset,
		Scanner:      scannerTag,
		ProofCommand: fmt.Sprintf("virsh -c qemu+tcp://%s/system list --all", host),
		Evidence: map[string]any{
			"host":          host,
			"port":          portTCP,
			"protocol":      "tcp",
			"resource_type": "libvirt_listener",
		},
		DiscoveredAt: time.Now(),
	}}
}

// checkTLSDisabled probes port 16514 (libvirt TLS). If TCP 16509 is open
// but TLS 16514 is not, TLS has not been configured as a replacement.
func (s *Scanner) checkTLSDisabled(asset, host string) []finding.Finding {
	addr := net.JoinHostPort(host, portTLS)
	conn, err := s.dial("tcp", addr, dialTimeout)
	if err == nil {
		_ = conn.Close()
		return nil // TLS port is open, good
	}

	return []finding.Finding{{
		CheckID: finding.CheckOnpremLibvirtTLSDisabled,
		Title:   fmt.Sprintf("libvirt TLS listener not available on %s", host),
		Description: fmt.Sprintf(
			"The libvirt daemon on %s has TCP port %s open (unauthenticated) but TLS port %s "+
				"is not listening. Without TLS, all libvirt management traffic is transmitted in "+
				"cleartext with no client certificate authentication. Configure TLS in "+
				"/etc/libvirt/libvirtd.conf with proper CA, server, and client certificates.",
			host, portTCP, portTLS,
		),
		Severity:     finding.SeverityHigh,
		Asset:        asset,
		Scanner:      scannerTag,
		ProofCommand: fmt.Sprintf("virsh -c qemu+tls://%s/system list --all", host),
		Evidence: map[string]any{
			"host":          host,
			"tcp_port":      portTCP,
			"tcp_open":      true,
			"tls_port":      portTLS,
			"tls_open":      false,
			"resource_type": "libvirt_listener",
		},
		DiscoveredAt: time.Now(),
	}}
}

// ---------------------------------------------------------------------------
// REST proxy API
// ---------------------------------------------------------------------------

// doRequest performs a GET against the REST proxy and decodes JSON into dst.
func (s *Scanner) doRequest(ctx context.Context, path string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.endpoint()+path, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

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

// fetchDomains retrieves the VM inventory from the REST proxy.
func (s *Scanner) fetchDomains(ctx context.Context) ([]domain, error) {
	var domains []domain
	if err := s.doRequest(ctx, "/domains", &domains); err != nil {
		return nil, err
	}
	return domains, nil
}

// fetchNetworks retrieves virtual network inventory from the REST proxy.
func (s *Scanner) fetchNetworks(ctx context.Context) ([]network, error) {
	var networks []network
	if err := s.doRequest(ctx, "/networks", &networks); err != nil {
		return nil, err
	}
	return networks, nil
}

// ---------------------------------------------------------------------------
// Domain (VM) checks
// ---------------------------------------------------------------------------

// checkDomains inspects each VM for security issues.
func (s *Scanner) checkDomains(asset, host string, domains []domain) []finding.Finding {
	var findings []finding.Finding

	for _, d := range domains {
		name := d.Name
		if name == "" {
			name = d.UUID
		}

		connURI := host
		if connURI == "" {
			connURI = "localhost"
		}

		// Check: VM without UEFI Secure Boot.
		if !d.Features.SecureBoot {
			findings = append(findings, finding.Finding{
				CheckID: finding.CheckOnpremLibvirtVMNoSecureBoot,
				Title:   fmt.Sprintf("VM %q does not have UEFI Secure Boot enabled", name),
				Description: fmt.Sprintf(
					"VM %s (UUID %s) does not have UEFI Secure Boot enabled. Without Secure Boot, "+
						"the VM boot chain is not cryptographically verified, allowing boot-level "+
						"rootkits or unauthorized kernel modifications. Enable UEFI firmware with "+
						"Secure Boot in the VM's XML configuration (<os firmware='efi'> with "+
						"<loader secure='yes'/>).",
					name, d.UUID,
				),
				Severity:     finding.SeverityMedium,
				Asset:        asset,
				Scanner:      scannerTag,
				ProofCommand: fmt.Sprintf("virsh -c qemu+ssh://%s/system dumpxml %s | grep -A5 '<os'", connURI, name),
				Evidence: map[string]any{
					"vm_name":       name,
					"vm_uuid":       d.UUID,
					"state":         d.State,
					"os_type":       d.OS.Type,
					"os_arch":       d.OS.Arch,
					"secure_boot":   false,
					"resource_type": "libvirt_domain",
				},
				DiscoveredAt: time.Now(),
			})
		}

		// Check: VM using raw disk format.
		if strings.EqualFold(d.DiskFormat, "raw") {
			findings = append(findings, finding.Finding{
				CheckID: finding.CheckOnpremLibvirtVMRawDisk,
				Title:   fmt.Sprintf("VM %q uses raw disk format", name),
				Description: fmt.Sprintf(
					"VM %s (UUID %s) uses raw disk format instead of qcow2 or another "+
						"copy-on-write format. Raw disks do not support snapshots, thin "+
						"provisioning, or built-in encryption. Convert to qcow2 format with "+
						"'qemu-img convert -f raw -O qcow2' for better operational flexibility.",
					name, d.UUID,
				),
				Severity:     finding.SeverityLow,
				Asset:        asset,
				Scanner:      scannerTag,
				ProofCommand: fmt.Sprintf("virsh -c qemu+ssh://%s/system domblkinfo %s --all", connURI, name),
				Evidence: map[string]any{
					"vm_name":       name,
					"vm_uuid":       d.UUID,
					"disk_format":   d.DiskFormat,
					"resource_type": "libvirt_domain",
				},
				DiscoveredAt: time.Now(),
			})
		}

		// Check: VM without memory balloon driver.
		if d.MemBalloon == "" || strings.EqualFold(d.MemBalloon, "none") {
			findings = append(findings, finding.Finding{
				CheckID: finding.CheckOnpremLibvirtVMNoMemBalloon,
				Title:   fmt.Sprintf("VM %q has no memory balloon driver", name),
				Description: fmt.Sprintf(
					"VM %s (UUID %s) does not have a memory balloon driver configured. Without "+
						"the balloon driver, the hypervisor cannot dynamically reclaim unused memory "+
						"from the guest, leading to memory overcommit failures and potential OOM "+
						"conditions on the host. Add <memballoon model='virtio'/> to the VM XML.",
					name, d.UUID,
				),
				Severity:     finding.SeverityLow,
				Asset:        asset,
				Scanner:      scannerTag,
				ProofCommand: fmt.Sprintf("virsh -c qemu+ssh://%s/system dumpxml %s | grep memballoon", connURI, name),
				Evidence: map[string]any{
					"vm_name":       name,
					"vm_uuid":       d.UUID,
					"memballoon":    d.MemBalloon,
					"resource_type": "libvirt_domain",
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// Network checks
// ---------------------------------------------------------------------------

// checkNetworks inspects virtual networks for isolation issues.
func (s *Scanner) checkNetworks(asset, host string, networks []network) []finding.Finding {
	var findings []finding.Finding

	for _, n := range networks {
		connURI := host
		if connURI == "" {
			connURI = "localhost"
		}

		// Check: virtual network in NAT mode (default, no isolation).
		if strings.EqualFold(n.Mode, "nat") {
			findings = append(findings, finding.Finding{
				CheckID: finding.CheckOnpremLibvirtNetNoIsolation,
				Title:   fmt.Sprintf("Virtual network %q uses NAT mode without isolation", n.Name),
				Description: fmt.Sprintf(
					"Virtual network %q (bridge %s) is configured in NAT mode. NAT is the "+
						"libvirt default and provides no isolation between VMs on the same network. "+
						"All VMs can communicate freely with each other and reach the host. Use "+
						"isolated or routed mode with nwfilter rules for workload isolation, or "+
						"configure Open vSwitch with port-level ACLs.",
					n.Name, n.Bridge,
				),
				Severity:     finding.SeverityMedium,
				Asset:        asset,
				Scanner:      scannerTag,
				ProofCommand: fmt.Sprintf("virsh -c qemu+ssh://%s/system net-dumpxml %s", connURI, n.Name),
				Evidence: map[string]any{
					"network_name":  n.Name,
					"mode":          n.Mode,
					"bridge":        n.Bridge,
					"dhcp":          n.DHCP,
					"resource_type": "libvirt_network",
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// scanError creates a scan-error finding.
func (s *Scanner) scanError(asset, description string) finding.Finding {
	return finding.Finding{
		CheckID:      finding.CheckOnpremLibvirtScanError,
		Title:        "libvirt scan error",
		Description:  description,
		Severity:     finding.SeverityInfo,
		Asset:        asset,
		Scanner:      scannerTag,
		DiscoveredAt: time.Now(),
	}
}

// truncate shortens s to at most maxLen characters.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
