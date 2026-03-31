package bgp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stormbane/beacon/internal/module"
)

// ---------------------------------------------------------------------------
// Pure helper functions
// ---------------------------------------------------------------------------

func TestParseCIDR_Valid(t *testing.T) {
	_, _, ok := parseCIDR("10.0.0.0/8")
	if !ok {
		t.Error("expected valid parse for 10.0.0.0/8")
	}
}

func TestParseCIDR_Invalid(t *testing.T) {
	_, _, ok := parseCIDR("not-a-cidr")
	if ok {
		t.Error("expected parse failure for invalid CIDR")
	}
}

func TestParseCIDR_IPv6(t *testing.T) {
	_, _, ok := parseCIDR("2001:db8::/32")
	if !ok {
		t.Error("expected valid parse for IPv6 CIDR")
	}
}

func TestEnumerateIPs_SlashThirty(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("192.168.1.0/30")
	ips := enumerateIPs(ipNet)
	// /30 = 4 addresses: .0, .1, .2, .3
	if len(ips) != 4 {
		t.Errorf("expected 4 IPs for /30, got %d: %v", len(ips), ips)
	}
	if ips[0] != "192.168.1.0" {
		t.Errorf("expected first IP 192.168.1.0, got %s", ips[0])
	}
	if ips[3] != "192.168.1.3" {
		t.Errorf("expected last IP 192.168.1.3, got %s", ips[3])
	}
}

func TestEnumerateIPs_SlashThirtyTwo(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("10.0.0.1/32")
	ips := enumerateIPs(ipNet)
	if len(ips) != 1 {
		t.Errorf("expected 1 IP for /32, got %d", len(ips))
	}
}

func TestIncrementIP(t *testing.T) {
	ip := net.IP{192, 168, 1, 255}
	incrementIP(ip)
	if ip[2] != 2 || ip[3] != 0 {
		t.Errorf("incrementIP: expected 192.168.2.0, got %v", ip)
	}
}

func TestCloneIP_NotNil(t *testing.T) {
	orig := net.IP{1, 2, 3, 4}
	clone := cloneIP(orig)
	orig[0] = 99
	if clone[0] != 1 {
		t.Error("cloneIP should produce an independent copy")
	}
}

func TestCloneIP_Nil(t *testing.T) {
	if cloneIP(nil) != nil {
		t.Error("cloneIP(nil) should return nil")
	}
}

// ---------------------------------------------------------------------------
// sharedInfraASNs — verify key cloud providers are guarded
// ---------------------------------------------------------------------------

func TestSharedInfraASNs(t *testing.T) {
	for asn, name := range map[int]string{
		13335: "Cloudflare",
		16509: "AWS",
		8075:  "Azure",
		15169: "Google Cloud",
		54113: "Fastly",
	} {
		if !sharedInfraASNs[asn] {
			t.Errorf("ASN %d (%s) should be in sharedInfraASNs", asn, name)
		}
	}
}

// ---------------------------------------------------------------------------
// Run — subdomain guard (no network required)
// ---------------------------------------------------------------------------

func TestRun_SkipsSubdomainWithThreeDots(t *testing.T) {
	s := New()
	findings, err := s.Run(context.Background(), "sub.example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for subdomain, got %d", len(findings))
	}
}

func TestRun_SkipsDeepSubdomain(t *testing.T) {
	s := New()
	findings, _ := s.Run(context.Background(), "api.us-east-1.example.com", module.ScanSurface)
	if len(findings) != 0 {
		t.Errorf("expected no findings for deep subdomain, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Run — context cancellation must not panic
// ---------------------------------------------------------------------------

func TestRun_ContextCancelledNoPanic(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	s := New()
	_, _ = s.Run(ctx, "example.com", module.ScanSurface)
}
