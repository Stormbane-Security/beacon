package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
)

// checkRebinding checks if the target's DNS resolves to a private/internal IP
// address. Hosts that resolve to RFC 1918 / RFC 6598 addresses from public DNS
// are potential DNS rebinding targets — an attacker can register a domain that
// alternates between an external IP (their server) and the target's internal IP,
// bypassing same-origin policy in browsers.
func checkRebinding(ctx context.Context, domain, asset string) *finding.Finding {
	resolver := &net.Resolver{}
	addrs, err := resolver.LookupHost(ctx, asset)
	if err != nil || len(addrs) == 0 {
		return nil
	}

	var privateAddrs []string
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if isPrivateIP(ip) {
			privateAddrs = append(privateAddrs, addr)
		}
	}

	if len(privateAddrs) == 0 {
		return nil
	}

	return &finding.Finding{
		CheckID:  finding.CheckDNSRebindingVulnerable,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityMedium,
		Asset:    asset,
		Title:    fmt.Sprintf("DNS rebinding risk: %s resolves to private IP", asset),
		Description: fmt.Sprintf(
			"The hostname %s resolves to private/internal IP address(es): %s. "+
				"An attacker can exploit DNS rebinding by registering a domain that "+
				"alternates between their external IP and this internal IP. When a "+
				"victim's browser caches the attacker's IP first then switches to "+
				"the internal IP, same-origin policy is bypassed, allowing the "+
				"attacker to read responses from internal services. Ensure internal "+
				"services validate the Host header and use DNS pinning.",
			asset, strings.Join(privateAddrs, ", "),
		),
		Evidence: map[string]any{
			"domain":       asset,
			"all_ips":      addrs,
			"private_ips":  privateAddrs,
		},
		ProofCommand: fmt.Sprintf("dig +short %s", asset),
		DiscoveredAt: time.Now(),
	}
}

// isPrivateIP returns true if the IP is in a private/internal range:
// - 10.0.0.0/8
// - 172.16.0.0/12
// - 192.168.0.0/16
// - 100.64.0.0/10 (CGNAT / RFC 6598)
// - 127.0.0.0/8 (loopback)
// - 169.254.0.0/16 (link-local)
// - fc00::/7 (IPv6 ULA)
// - ::1 (IPv6 loopback)
// - fe80::/10 (IPv6 link-local)
func isPrivateIP(ip net.IP) bool {
	privateRanges := []struct {
		network string
	}{
		{"10.0.0.0/8"},
		{"172.16.0.0/12"},
		{"192.168.0.0/16"},
		{"100.64.0.0/10"},
		{"127.0.0.0/8"},
		{"169.254.0.0/16"},
		{"fc00::/7"},
		{"fe80::/10"},
	}

	if ip.Equal(net.IPv6loopback) {
		return true
	}

	for _, r := range privateRanges {
		_, cidr, err := net.ParseCIDR(r.network)
		if err != nil {
			continue
		}
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}
