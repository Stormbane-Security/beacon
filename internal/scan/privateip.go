package scan

import "net"

// privateRanges are CIDR blocks for private/reserved IP addresses.
var privateRanges = []net.IPNet{
	parseCIDR("127.0.0.0/8"),
	parseCIDR("10.0.0.0/8"),
	parseCIDR("172.16.0.0/12"),
	parseCIDR("192.168.0.0/16"),
	parseCIDR("::1/128"),
	parseCIDR("fc00::/7"),
	parseCIDR("fe80::/10"),
}

func parseCIDR(s string) net.IPNet {
	_, n, _ := net.ParseCIDR(s)
	return *n
}

// IsPrivateTarget returns true if the asset resolves to a private/loopback IP
// or is "localhost". External-data scanners (whois, historicalurls, assetintel,
// cloudbuckets, etc.) should skip these targets since external APIs have no
// data for private addresses.
func IsPrivateTarget(asset string) bool {
	// Strip port if present.
	host := asset
	if h, _, err := net.SplitHostPort(asset); err == nil {
		host = h
	}

	if host == "localhost" {
		return true
	}

	ip := net.ParseIP(host)
	if ip == nil {
		// Resolve hostname.
		addrs, err := net.LookupHost(host)
		if err != nil || len(addrs) == 0 {
			return false
		}
		ip = net.ParseIP(addrs[0])
		if ip == nil {
			return false
		}
	}

	for _, r := range privateRanges {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}
