// Package docker implements a deep-mode scanner for Docker Engine hosts.
// It queries the Docker Engine API to detect container security misconfigurations
// including privileged containers, host namespace sharing, sensitive host mounts,
// missing resource limits, and exposed unauthenticated APIs.
package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)

const scannerName = "onprem/docker"

// Config holds Docker Engine connection parameters.
type Config struct {
	Endpoint    string // Docker API URL (e.g., "http://192.168.1.100:2375" or "unix:///var/run/docker.sock")
	TLSCertPath string // optional TLS client cert
	TLSKeyPath  string // optional TLS client key
	TLSCAPath   string // optional TLS CA cert
}

// Scanner probes Docker Engine hosts for container security misconfigurations.
type Scanner struct {
	cfg    Config
	client *http.Client
}

// New returns a new Scanner with the given configuration.
// If client is nil, a default HTTP client with a 15-second timeout is used.
func New(cfg Config, client *http.Client) *Scanner {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &Scanner{cfg: cfg, client: client}
}

// Name returns the stable scanner identifier.
func (s *Scanner) Name() string { return scannerName }

// sensitiveHostPaths are mount source paths that indicate dangerous host access.
var sensitiveHostPaths = []string{
	"/",
	"/etc",
	"/proc",
	"/sys",
	"/var/run/docker.sock",
	"/root",
	"/home",
}

// dangerousCaps are Linux capabilities that grant near-root power inside a container.
var dangerousCaps = map[string]bool{
	"SYS_ADMIN":  true,
	"SYS_PTRACE": true,
	"NET_ADMIN":  true,
	"ALL":        true,
}

// --------------------------------------------------------------------------
// Docker API response types
// --------------------------------------------------------------------------

// containerSummary represents a single entry from GET /containers/json.
type containerSummary struct {
	ID    string   `json:"Id"`
	Names []string `json:"Names"`
	Image string   `json:"Image"`
	State string   `json:"State"`
}

// containerInspect represents the response from GET /containers/{id}/json.
type containerInspect struct {
	ID         string `json:"Id"`
	Name       string `json:"Name"`
	Image      string `json:"Image"`
	Created    string `json:"Created"`
	HostConfig struct {
		Privileged     bool     `json:"Privileged"`
		NetworkMode    string   `json:"NetworkMode"`
		PidMode        string   `json:"PidMode"`
		IpcMode        string   `json:"IpcMode"`
		CapAdd         []string `json:"CapAdd"`
		ReadonlyRootfs bool     `json:"ReadonlyRootfs"`
		Binds          []string `json:"Binds"`
		Memory         int64    `json:"Memory"`
		NanoCpus       int64    `json:"NanoCpus"`
	} `json:"HostConfig"`
	Config struct {
		User        string      `json:"User"`
		Healthcheck interface{} `json:"Healthcheck"`
	} `json:"Config"`
}

// --------------------------------------------------------------------------
// Run
// --------------------------------------------------------------------------

// Run executes the Docker Engine scanner.
//
// In Surface mode only the exposed-API check fires (passive TCP probe).
// In Deep/Authorized mode the scanner queries the Docker API for container
// details and inspects each one for security misconfigurations.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	endpoint := s.cfg.Endpoint
	if endpoint == "" {
		endpoint = "http://" + asset + ":2375"
	}

	var findings []finding.Finding

	// --- Surface check: unauthenticated TCP API ---
	if isExposedAPI(ctx, s.client, endpoint) {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckOnpremDockerExposedAPI,
			Scanner:  scannerName,
			Severity: finding.SeverityCritical,
			Title:    fmt.Sprintf("Docker API exposed without TLS on %s", endpoint),
			Description: fmt.Sprintf(
				"The Docker Engine API at %s is accessible over unauthenticated HTTP. "+
					"Anyone with network access can manage containers, pull images, and "+
					"escalate to full host root access.",
				endpoint,
			),
			Asset:        asset,
			ProofCommand: fmt.Sprintf("curl -s %s/version", endpoint),
			Evidence: map[string]any{
				"endpoint": endpoint,
			},
			DiscoveredAt: time.Now(),
		})
	}

	// Surface mode stops here.
	if scanType == module.ScanSurface {
		return findings, nil
	}

	// --- Deep mode: enumerate and inspect containers ---
	containers, err := listContainers(ctx, s.client, endpoint)
	if err != nil {
		findings = append(findings, finding.Finding{
			CheckID:      finding.CheckOnpremDockerScanError,
			Scanner:      scannerName,
			Severity:     finding.SeverityInfo,
			Title:        fmt.Sprintf("Docker API scan failed on %s", endpoint),
			Description:  fmt.Sprintf("Could not list containers from %s: %v", endpoint, err),
			Asset:        asset,
			ProofCommand: fmt.Sprintf("curl -s %s/containers/json?all=true", endpoint),
			Evidence: map[string]any{
				"endpoint": endpoint,
				"error":    err.Error(),
			},
			DiscoveredAt: time.Now(),
		})
		return findings, nil
	}

	for _, cs := range containers {
		ci, err := inspectContainer(ctx, s.client, endpoint, cs.ID)
		if err != nil {
			continue
		}

		name := containerName(ci)

		findings = append(findings, inspectFindings(ci, name, asset, endpoint)...)
	}

	return findings, nil
}

// --------------------------------------------------------------------------
// API helpers
// --------------------------------------------------------------------------

// isExposedAPI performs a lightweight probe to check if the Docker API is
// reachable over plain HTTP (no TLS).
func isExposedAPI(ctx context.Context, client *http.Client, endpoint string) bool {
	if !strings.HasPrefix(endpoint, "http://") {
		return false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/version", nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode == http.StatusOK
}

// listContainers calls GET /containers/json?all=true and returns a summary list.
func listContainers(ctx context.Context, client *http.Client, endpoint string) ([]containerSummary, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/containers/json?all=true", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10 MB cap
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("docker API returned %d: %s", resp.StatusCode, string(body))
	}

	var containers []containerSummary
	if err := json.Unmarshal(body, &containers); err != nil {
		return nil, fmt.Errorf("decode containers: %w", err)
	}
	return containers, nil
}

// inspectContainer calls GET /containers/{id}/json and returns full details.
func inspectContainer(ctx context.Context, client *http.Client, endpoint, id string) (*containerInspect, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/containers/"+id+"/json", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20)) // 5 MB cap
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("inspect %s returned %d", id, resp.StatusCode)
	}

	var ci containerInspect
	if err := json.Unmarshal(body, &ci); err != nil {
		return nil, fmt.Errorf("decode inspect %s: %w", id, err)
	}
	return &ci, nil
}

// containerName returns a human-readable container name from the inspect response.
func containerName(ci *containerInspect) string {
	n := ci.Name
	if n == "" {
		n = ci.ID
	}
	return strings.TrimPrefix(n, "/")
}

// --------------------------------------------------------------------------
// Per-container security checks
// --------------------------------------------------------------------------

// inspectFindings runs all security checks against a single inspected container
// and returns any findings.
func inspectFindings(ci *containerInspect, name, asset, endpoint string) []finding.Finding {
	var findings []finding.Finding
	proofCmd := fmt.Sprintf("curl -s %s/containers/%s/json | jq .HostConfig", endpoint, ci.ID)

	// Privileged container
	if ci.HostConfig.Privileged {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckOnpremDockerPrivilegedContainer,
			Scanner:  scannerName,
			Severity: finding.SeverityCritical,
			Title:    fmt.Sprintf("Container %q running in privileged mode", name),
			Description: fmt.Sprintf(
				"Container %s (%s) is running with --privileged, which disables all "+
					"security mechanisms (cgroups, seccomp, AppArmor, namespaces) and "+
					"grants full device access. This is equivalent to root on the host.",
				name, ci.ID,
			),
			Asset:        asset,
			ProofCommand: proofCmd,
			Evidence: map[string]any{
				"container_id":   ci.ID,
				"container_name": name,
				"privileged":     true,
			},
			DiscoveredAt: time.Now(),
		})
	}

	// Host network namespace
	if ci.HostConfig.NetworkMode == "host" {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckOnpremDockerHostNetwork,
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Title:    fmt.Sprintf("Container %q shares host network namespace", name),
			Description: fmt.Sprintf(
				"Container %s (%s) uses --network host, sharing the host's network stack. "+
					"The container can bind to any port, sniff traffic, and access services "+
					"listening on localhost.",
				name, ci.ID,
			),
			Asset:        asset,
			ProofCommand: proofCmd,
			Evidence: map[string]any{
				"container_id":   ci.ID,
				"container_name": name,
				"network_mode":   "host",
			},
			DiscoveredAt: time.Now(),
		})
	}

	// Running as root
	if isRootUser(ci.Config.User) {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckOnpremDockerRootUser,
			Scanner:  scannerName,
			Severity: finding.SeverityMedium,
			Title:    fmt.Sprintf("Container %q running as root", name),
			Description: fmt.Sprintf(
				"Container %s (%s) runs as UID 0. If an attacker escapes the container, "+
					"they inherit root privileges on the host. Use a non-root USER in the "+
					"Dockerfile.",
				name, ci.ID,
			),
			Asset:        asset,
			ProofCommand: proofCmd,
			Evidence: map[string]any{
				"container_id":   ci.ID,
				"container_name": name,
				"user":           ci.Config.User,
			},
			DiscoveredAt: time.Now(),
		})
	}

	// No resource limits
	if ci.HostConfig.Memory == 0 && ci.HostConfig.NanoCpus == 0 {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckOnpremDockerNoResourceLimits,
			Scanner:  scannerName,
			Severity: finding.SeverityLow,
			Title:    fmt.Sprintf("Container %q has no CPU/memory limits", name),
			Description: fmt.Sprintf(
				"Container %s (%s) runs without memory or CPU constraints. A resource "+
					"exhaustion attack or runaway process can starve the host and other containers.",
				name, ci.ID,
			),
			Asset:        asset,
			ProofCommand: proofCmd,
			Evidence: map[string]any{
				"container_id":   ci.ID,
				"container_name": name,
				"memory":         ci.HostConfig.Memory,
				"nano_cpus":      ci.HostConfig.NanoCpus,
			},
			DiscoveredAt: time.Now(),
		})
	}

	// Sensitive host mounts
	for _, bind := range ci.HostConfig.Binds {
		hostPath := bindHostPath(bind)
		if isSensitiveMount(hostPath) {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckOnpremDockerHostMount,
				Scanner:  scannerName,
				Severity: finding.SeverityCritical,
				Title:    fmt.Sprintf("Container %q mounts sensitive host path %s", name, hostPath),
				Description: fmt.Sprintf(
					"Container %s (%s) binds host path %q. Mounting sensitive host "+
						"directories gives the container read/write access to host files, "+
						"enabling privilege escalation and data theft.",
					name, ci.ID, hostPath,
				),
				Asset:        asset,
				ProofCommand: proofCmd,
				Evidence: map[string]any{
					"container_id":   ci.ID,
					"container_name": name,
					"bind":           bind,
					"host_path":      hostPath,
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	// No healthcheck
	if ci.Config.Healthcheck == nil {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckOnpremDockerNoHealthcheck,
			Scanner:  scannerName,
			Severity: finding.SeverityLow,
			Title:    fmt.Sprintf("Container %q has no healthcheck configured", name),
			Description: fmt.Sprintf(
				"Container %s (%s) has no HEALTHCHECK. Without health probes, the "+
					"orchestrator cannot detect and restart unhealthy containers, leading "+
					"to silent failures.",
				name, ci.ID,
			),
			Asset:        asset,
			ProofCommand: proofCmd,
			Evidence: map[string]any{
				"container_id":   ci.ID,
				"container_name": name,
				"healthcheck":    nil,
			},
			DiscoveredAt: time.Now(),
		})
	}

	// Dangerous capabilities
	for _, cap := range ci.HostConfig.CapAdd {
		capUpper := strings.ToUpper(cap)
		if dangerousCaps[capUpper] {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckOnpremDockerCapSysAdmin,
				Scanner:  scannerName,
				Severity: finding.SeverityCritical,
				Title:    fmt.Sprintf("Container %q has dangerous capability %s", name, capUpper),
				Description: fmt.Sprintf(
					"Container %s (%s) has CAP_%s added. This capability grants near-root "+
						"power and can be used to escape container isolation.",
					name, ci.ID, capUpper,
				),
				Asset:        asset,
				ProofCommand: proofCmd,
				Evidence: map[string]any{
					"container_id":   ci.ID,
					"container_name": name,
					"capability":     capUpper,
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	// Host PID namespace
	if ci.HostConfig.PidMode == "host" {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckOnpremDockerHostPID,
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Title:    fmt.Sprintf("Container %q shares host PID namespace", name),
			Description: fmt.Sprintf(
				"Container %s (%s) uses --pid=host, sharing the host's PID namespace. "+
					"The container can see and signal all host processes, enabling process "+
					"injection and privilege escalation.",
				name, ci.ID,
			),
			Asset:        asset,
			ProofCommand: proofCmd,
			Evidence: map[string]any{
				"container_id":   ci.ID,
				"container_name": name,
				"pid_mode":       "host",
			},
			DiscoveredAt: time.Now(),
		})
	}

	// Host IPC namespace
	if ci.HostConfig.IpcMode == "host" {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckOnpremDockerHostIPC,
			Scanner:  scannerName,
			Severity: finding.SeverityMedium,
			Title:    fmt.Sprintf("Container %q shares host IPC namespace", name),
			Description: fmt.Sprintf(
				"Container %s (%s) uses --ipc=host, sharing the host's IPC namespace. "+
					"The container can read and write shared memory segments used by host "+
					"processes.",
				name, ci.ID,
			),
			Asset:        asset,
			ProofCommand: proofCmd,
			Evidence: map[string]any{
				"container_id":   ci.ID,
				"container_name": name,
				"ipc_mode":       "host",
			},
			DiscoveredAt: time.Now(),
		})
	}

	// Outdated image (Created > 90 days ago)
	if ci.Created != "" {
		created, err := time.Parse(time.RFC3339Nano, ci.Created)
		if err == nil && time.Since(created) > 90*24*time.Hour {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckOnpremDockerOutdatedImage,
				Scanner:  scannerName,
				Severity: finding.SeverityMedium,
				Title:    fmt.Sprintf("Container %q uses image created over 90 days ago", name),
				Description: fmt.Sprintf(
					"Container %s (%s) was created on %s, more than 90 days ago. "+
						"Outdated images are more likely to contain unpatched vulnerabilities.",
					name, ci.ID, created.Format("2006-01-02"),
				),
				Asset:        asset,
				ProofCommand: proofCmd,
				Evidence: map[string]any{
					"container_id":   ci.ID,
					"container_name": name,
					"created":        ci.Created,
					"age_days":       int(time.Since(created).Hours() / 24),
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	// Writable root filesystem
	if !ci.HostConfig.ReadonlyRootfs {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckOnpremDockerWritableRootFS,
			Scanner:  scannerName,
			Severity: finding.SeverityLow,
			Title:    fmt.Sprintf("Container %q has writable root filesystem", name),
			Description: fmt.Sprintf(
				"Container %s (%s) does not use --read-only. An attacker who gains code "+
					"execution can modify the container filesystem to persist backdoors "+
					"or tamper with application binaries.",
				name, ci.ID,
			),
			Asset:        asset,
			ProofCommand: proofCmd,
			Evidence: map[string]any{
				"container_id":     ci.ID,
				"container_name":   name,
				"readonly_rootfs":  false,
			},
			DiscoveredAt: time.Now(),
		})
	}

	return findings
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

// isRootUser returns true if the User field indicates UID 0 (root).
// Docker defaults to root when User is empty.
func isRootUser(user string) bool {
	u := strings.TrimSpace(user)
	return u == "" || u == "0" || u == "root"
}

// bindHostPath extracts the host path from a Docker bind mount string.
// Bind format: /host/path:/container/path[:opts]
func bindHostPath(bind string) string {
	parts := strings.SplitN(bind, ":", 2)
	if len(parts) == 0 {
		return bind
	}
	return parts[0]
}

// isSensitiveMount returns true if the host path is a known sensitive location.
func isSensitiveMount(hostPath string) bool {
	for _, sp := range sensitiveHostPaths {
		// Exact match or the host path starts with the sensitive path followed
		// by a separator. Special case: "/" matches only the exact root mount.
		if sp == "/" {
			if hostPath == "/" {
				return true
			}
			continue
		}
		if hostPath == sp || strings.HasPrefix(hostPath, sp+"/") {
			return true
		}
	}
	return false
}
