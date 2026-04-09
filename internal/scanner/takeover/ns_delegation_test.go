package takeover

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
)

// ── mock resolver ────────────────────────────────────────────────────────────

// mockResolver implements Resolver with configurable responses per nameserver.
type mockResolver struct {
	nsRecords []*net.NS
	nsErr     error
	// directResults maps "nameserver|host" to a status.
	directResults map[string]nsQueryStatus
}

func (m *mockResolver) LookupNS(_ context.Context, _ string) ([]*net.NS, error) {
	return m.nsRecords, m.nsErr
}

func (m *mockResolver) LookupHostDirect(_ context.Context, nameserver, host string) (nsQueryStatus, error) {
	key := nameserver + "|" + host
	if status, ok := m.directResults[key]; ok {
		return status, nil
	}
	return nsFailed, fmt.Errorf("mock: no result configured for %s", key)
}

// ── provider matching ────────────────────────────────────────────────────────

func TestMatchProvider_Route53(t *testing.T) {
	got := matchProvider("ns-1234.awsdns-01.co.uk.")
	if got != "AWS Route53" {
		t.Errorf("matchProvider(awsdns): got %q, want %q", got, "AWS Route53")
	}
}

func TestMatchProvider_Cloudflare(t *testing.T) {
	got := matchProvider("anna.ns.cloudflare.com.")
	if got != "Cloudflare" {
		t.Errorf("matchProvider(cloudflare): got %q, want %q", got, "Cloudflare")
	}
}

func TestMatchProvider_DigitalOcean(t *testing.T) {
	got := matchProvider("ns1.digitalocean.com.")
	if got != "DigitalOcean" {
		t.Errorf("matchProvider(digitalocean): got %q, want %q", got, "DigitalOcean")
	}
}

func TestMatchProvider_Unknown(t *testing.T) {
	got := matchProvider("ns1.internal-corp.example.com.")
	if got != "" {
		t.Errorf("matchProvider(unknown): got %q, want empty", got)
	}
}

func TestMatchProvider_AzureDNS(t *testing.T) {
	got := matchProvider("ns1-01.azure-dns.com.")
	if got != "Azure DNS" {
		t.Errorf("matchProvider(azure-dns): got %q, want %q", got, "Azure DNS")
	}
}

func TestMatchProvider_NS1(t *testing.T) {
	got := matchProvider("dns1.p01.nsone.net.")
	if got != "NS1" {
		t.Errorf("matchProvider(nsone): got %q, want %q", got, "NS1")
	}
}

// ── CheckNSDelegation — NXDOMAIN → Critical takeover ────────────────────────

func TestCheckNSDelegation_NXDOMAIN_CriticalTakeover(t *testing.T) {
	mock := &mockResolver{
		nsRecords: []*net.NS{
			{Host: "ns-1234.awsdns-01.co.uk."},
			{Host: "ns-5678.awsdns-02.net."},
		},
		directResults: map[string]nsQueryStatus{
			"ns-1234.awsdns-01.co.uk|sub.example.com": nsNXDomain,
			"ns-5678.awsdns-02.net|sub.example.com":   nsNXDomain,
		},
	}

	findings := checkNSDelegationWith(context.Background(), "sub.example.com", mock)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	for _, f := range findings {
		if f.CheckID != finding.CheckSubdomainNSDelegationTakeover {
			t.Errorf("expected check ID %q, got %q", finding.CheckSubdomainNSDelegationTakeover, f.CheckID)
		}
		if f.Severity != finding.SeverityCritical {
			t.Errorf("expected severity Critical, got %s", f.Severity)
		}
		if f.ProofCommand == "" {
			t.Error("expected ProofCommand to be set")
		}
		ns := f.Evidence["ns_status"]
		if ns != "NXDOMAIN" {
			t.Errorf("expected ns_status NXDOMAIN, got %v", ns)
		}
	}
}

// ── CheckNSDelegation — SERVFAIL → High stale ───────────────────────────────

func TestCheckNSDelegation_Failed_StaleDelegation(t *testing.T) {
	mock := &mockResolver{
		nsRecords: []*net.NS{
			{Host: "ns1.digitalocean.com."},
		},
		directResults: map[string]nsQueryStatus{
			"ns1.digitalocean.com|stale.example.com": nsFailed,
		},
	}

	findings := checkNSDelegationWith(context.Background(), "stale.example.com", mock)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.CheckID != finding.CheckSubdomainNSDelegationStale {
		t.Errorf("expected check ID %q, got %q", finding.CheckSubdomainNSDelegationStale, f.CheckID)
	}
	if f.Severity != finding.SeverityHigh {
		t.Errorf("expected severity High, got %s", f.Severity)
	}
	if f.Evidence["provider"] != "DigitalOcean" {
		t.Errorf("expected provider DigitalOcean, got %v", f.Evidence["provider"])
	}
}

// ── CheckNSDelegation — Active NS → no finding ──────────────────────────────

func TestCheckNSDelegation_Active_NoFinding(t *testing.T) {
	mock := &mockResolver{
		nsRecords: []*net.NS{
			{Host: "anna.ns.cloudflare.com."},
			{Host: "bob.ns.cloudflare.com."},
		},
		directResults: map[string]nsQueryStatus{
			"anna.ns.cloudflare.com|active.example.com": nsActive,
			"bob.ns.cloudflare.com|active.example.com":  nsActive,
		},
	}

	findings := checkNSDelegationWith(context.Background(), "active.example.com", mock)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for active NS, got %d", len(findings))
	}
}

// ── CheckNSDelegation — No NS records → no finding ──────────────────────────

func TestCheckNSDelegation_NoNS_NoFinding(t *testing.T) {
	mock := &mockResolver{
		nsRecords: nil,
		nsErr:     fmt.Errorf("no such host"),
	}

	findings := checkNSDelegationWith(context.Background(), "norecord.example.com", mock)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for no NS records, got %d", len(findings))
	}
}

// ── CheckNSDelegation — Empty zone (NOERROR, no answers) → High ─────────────

func TestCheckNSDelegation_EmptyZone_HighFinding(t *testing.T) {
	mock := &mockResolver{
		nsRecords: []*net.NS{
			{Host: "ns-1.awsdns-01.com."},
		},
		directResults: map[string]nsQueryStatus{
			"ns-1.awsdns-01.com|empty.example.com": nsEmpty,
		},
	}

	findings := checkNSDelegationWith(context.Background(), "empty.example.com", mock)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.CheckID != finding.CheckSubdomainNSDelegationTakeover {
		t.Errorf("expected check ID %q, got %q", finding.CheckSubdomainNSDelegationTakeover, f.CheckID)
	}
	if f.Severity != finding.SeverityHigh {
		t.Errorf("expected severity High for empty zone, got %s", f.Severity)
	}
	if f.Evidence["ns_status"] != "NOERROR_EMPTY" {
		t.Errorf("expected ns_status NOERROR_EMPTY, got %v", f.Evidence["ns_status"])
	}
}

// ── CheckNSDelegation — Mixed: one active, one NXDOMAIN ─────────────────────

func TestCheckNSDelegation_MixedStatus(t *testing.T) {
	mock := &mockResolver{
		nsRecords: []*net.NS{
			{Host: "anna.ns.cloudflare.com."},
			{Host: "ns-dead.awsdns-01.co.uk."},
		},
		directResults: map[string]nsQueryStatus{
			"anna.ns.cloudflare.com|mixed.example.com":  nsActive,
			"ns-dead.awsdns-01.co.uk|mixed.example.com": nsNXDomain,
		},
	}

	findings := checkNSDelegationWith(context.Background(), "mixed.example.com", mock)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (NXDOMAIN NS only), got %d", len(findings))
	}
	if findings[0].Evidence["nameserver"] != "ns-dead.awsdns-01.co.uk" {
		t.Errorf("expected finding for ns-dead, got nameserver=%v", findings[0].Evidence["nameserver"])
	}
}

// ── CheckNSDelegation — Unknown provider still reported ──────────────────────

func TestCheckNSDelegation_UnknownProvider_StillReported(t *testing.T) {
	mock := &mockResolver{
		nsRecords: []*net.NS{
			{Host: "ns1.obscure-dns-provider.io."},
		},
		directResults: map[string]nsQueryStatus{
			"ns1.obscure-dns-provider.io|vuln.example.com": nsNXDomain,
		},
	}

	findings := checkNSDelegationWith(context.Background(), "vuln.example.com", mock)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for unknown provider, got %d", len(findings))
	}
	// Provider label falls back to the NS hostname itself.
	if findings[0].Evidence["provider"] != "ns1.obscure-dns-provider.io" {
		t.Errorf("expected provider to be NS hostname, got %v", findings[0].Evidence["provider"])
	}
}

// ── nsHostnames helper ───────────────────────────────────────────────────────

func TestNsHostnames(t *testing.T) {
	records := []*net.NS{
		{Host: "ns1.example.com."},
		{Host: "ns2.example.com."},
	}
	got := nsHostnames(records)
	if len(got) != 2 {
		t.Fatalf("expected 2 hostnames, got %d", len(got))
	}
	// Trailing dots should be stripped.
	for _, h := range got {
		if h[len(h)-1] == '.' {
			t.Errorf("hostname %q still has trailing dot", h)
		}
	}
}
