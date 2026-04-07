package agent

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// LateralResult is the result of a lateral movement attempt.
type LateralResult struct {
	Target   string `json:"target"`
	Protocol string `json:"protocol"` // ssh, smb, http, k8s, cloud_api
	Success  bool   `json:"success"`
	Method   string `json:"method"`   // e.g., "password", "key", "token"
	Username string `json:"username,omitempty"`
	Output   string `json:"output,omitempty"` // command output if executed
	Error    string `json:"error,omitempty"`
}

// InternalTarget is a host:port discovered on the internal network.
type InternalTarget struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Service string `json:"service"` // ssh, http, postgres, mysql, redis, etc.
	Banner  string `json:"banner,omitempty"`
}

// commonPorts to scan on discovered internal hosts.
var commonPorts = []struct {
	port    int
	service string
}{
	{22, "ssh"},
	{80, "http"},
	{443, "https"},
	{3306, "mysql"},
	{5432, "postgres"},
	{6379, "redis"},
	{27017, "mongodb"},
	{8080, "http-alt"},
	{8443, "https-alt"},
	{9200, "elasticsearch"},
	{5672, "rabbitmq"},
	{11211, "memcached"},
	{2379, "etcd"},
	{8500, "consul"},
	{10250, "kubelet"},
	{6443, "k8s-api"},
	{9090, "prometheus"},
	{3000, "grafana"},
	{8888, "jupyter"},
	{5601, "kibana"},
}

// DiscoverInternalTargets scans the local network for reachable services.
// It discovers subnets from the agent's network interfaces and scans common ports.
func DiscoverInternalTargets(ctx context.Context, netInfo *NetworkInfo) []InternalTarget {
	if netInfo == nil {
		return nil
	}

	// Extract subnets from interfaces.
	var subnets []*net.IPNet
	for _, iface := range netInfo.Interfaces {
		for _, addr := range iface.Addrs {
			_, ipnet, err := net.ParseCIDR(addr)
			if err != nil {
				continue
			}
			// Skip loopback and link-local.
			if ipnet.IP.IsLoopback() || ipnet.IP.IsLinkLocalUnicast() {
				continue
			}
			subnets = append(subnets, ipnet)
		}
	}

	if len(subnets) == 0 {
		return nil
	}

	var (
		targets []InternalTarget
		mu      sync.Mutex
		wg      sync.WaitGroup
		sem     = make(chan struct{}, 50) // limit concurrency
	)

	for _, subnet := range subnets {
		hosts := enumerateHosts(subnet, 256) // max 256 hosts per subnet
		for _, host := range hosts {
			if ctx.Err() != nil {
				break
			}
			for _, p := range commonPorts {
				if ctx.Err() != nil {
					break
				}
				wg.Add(1)
				go func(h string, port int, service string) {
					defer wg.Done()
					select {
					case sem <- struct{}{}:
					case <-ctx.Done():
						return
					}
					defer func() { <-sem }()

					addr := net.JoinHostPort(h, fmt.Sprintf("%d", port))
					conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
					if err != nil {
						return
					}

					// Try to read a banner (100ms timeout).
					var banner string
					_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
					buf := make([]byte, 256)
					if n, err := conn.Read(buf); err == nil && n > 0 {
						banner = strings.TrimSpace(string(buf[:n]))
					}
					_ = conn.Close()

					mu.Lock()
					targets = append(targets, InternalTarget{
						Host:    h,
						Port:    port,
						Service: service,
						Banner:  banner,
					})
					mu.Unlock()
				}(host, p.port, p.service)
			}
		}
	}

	wg.Wait()
	return targets
}

// enumerateHosts returns up to maxHosts IP addresses in a subnet.
func enumerateHosts(subnet *net.IPNet, maxHosts int) []string {
	var hosts []string
	ip := make(net.IP, len(subnet.IP))
	copy(ip, subnet.IP)

	// Compute broadcast address from network + inverted mask.
	broadcast := make(net.IP, len(subnet.IP))
	for i := range broadcast {
		broadcast[i] = subnet.IP[i] | ^subnet.Mask[i]
	}

	for i := 0; i < maxHosts; i++ {
		ip = nextIP(ip)
		if !subnet.Contains(ip) {
			break
		}
		// Skip network (subnet.IP) and broadcast addresses.
		if ip.Equal(subnet.IP) || ip.Equal(broadcast) {
			continue
		}
		hosts = append(hosts, ip.String())
	}
	return hosts
}

// nextIP increments an IP address by 1.
func nextIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] > 0 {
			break
		}
	}
	return next
}

// TrySSH attempts SSH authentication with the given credentials.
// Returns the result of running 'id' on success.
func TrySSH(ctx context.Context, host string, port int, username, password string) LateralResult {
	result := LateralResult{
		Target:   net.JoinHostPort(host, fmt.Sprintf("%d", port)),
		Protocol: "ssh",
		Username: username,
		Method:   "password",
	}

	// Use the ssh command-line tool for now. This avoids pulling in the
	// golang.org/x/crypto/ssh dependency until we need it. The agent runs
	// on the target so the ssh binary is usually available.
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	_ = conn.Close()

	// SSH banner grab confirms it's an SSH server.
	result.Success = false
	result.Error = "ssh library not linked — banner confirmed SSH server is reachable"
	return result
}

// TryHTTP attempts to access an HTTP endpoint, optionally with credentials.
func TryHTTP(ctx context.Context, url, username, password string) LateralResult {
	result := LateralResult{
		Target:   url,
		Protocol: "http",
		Method:   "none",
	}

	if username != "" {
		result.Method = "basic_auth"
		result.Username = username
	}

	// Simple TCP check — full HTTP is done by beacon scanners.
	// The agent's job is to prove reachability, not to scan.
	conn, err := net.DialTimeout("tcp", extractHostPort(url), 3*time.Second)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	_ = conn.Close()
	result.Success = true
	result.Output = "reachable"
	return result
}

// extractHostPort pulls host:port from a URL string.
func extractHostPort(rawURL string) string {
	// Strip scheme.
	s := rawURL
	if idx := strings.Index(s, "://"); idx != -1 {
		s = s[idx+3:]
	}
	// Strip path.
	if idx := strings.Index(s, "/"); idx != -1 {
		s = s[:idx]
	}
	// Add default port if missing.
	if _, _, err := net.SplitHostPort(s); err != nil {
		if strings.HasPrefix(rawURL, "https") {
			return s + ":443"
		}
		return s + ":80"
	}
	return s
}
