package dns

import (
	"net"
	"testing"
)

// ---------------------------------------------------------------------------
// isPrivateIP — private range detection
// ---------------------------------------------------------------------------

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		private bool
	}{
		// RFC 1918 ranges.
		{"10.x", "10.0.0.1", true},
		{"10.x high", "10.255.255.255", true},
		{"172.16.x", "172.16.0.1", true},
		{"172.31.x", "172.31.255.255", true},
		{"192.168.x", "192.168.1.1", true},
		{"192.168.0.0", "192.168.0.0", true},

		// RFC 6598 (CGNAT).
		{"100.64.x", "100.64.0.1", true},
		{"100.127.x", "100.127.255.255", true},

		// Loopback.
		{"127.0.0.1", "127.0.0.1", true},
		{"127.1.2.3", "127.1.2.3", true},

		// Link-local.
		{"169.254.x", "169.254.1.1", true},

		// Public IPs — NOT private.
		{"8.8.8.8", "8.8.8.8", false},
		{"1.1.1.1", "1.1.1.1", false},
		{"93.184.216.34", "93.184.216.34", false},
		{"172.15.255.255", "172.15.255.255", false}, // just below 172.16
		{"172.32.0.0", "172.32.0.0", false},         // just above 172.31

		// IPv6 private.
		{"::1", "::1", true},
		{"fc00::1", "fc00::1", true},
		{"fd12::1", "fd12::1", true},
		{"fe80::1", "fe80::1", true},

		// IPv6 public.
		{"2001:db8::1", "2001:db8::1", false},
		{"2606:4700::1", "2606:4700::1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP %q", tt.ip)
			}
			got := isPrivateIP(ip)
			if got != tt.private {
				t.Errorf("isPrivateIP(%s) = %v, want %v", tt.ip, got, tt.private)
			}
		})
	}
}
