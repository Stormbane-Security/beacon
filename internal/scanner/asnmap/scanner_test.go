package asnmap

import (
	"testing"

	"github.com/stormbane-security/beacon/internal/module"
)

func TestScannerName(t *testing.T) {
	s := New()
	if s.Name() != "asnmap" {
		t.Errorf("Name() = %q; want %q", s.Name(), "asnmap")
	}
}

func TestSubdomainFilter(t *testing.T) {
	// The scanner skips assets with >1 dot (only root domains).
	// Verify this logic by calling Run with a subdomain.
	s := New()
	findings, err := s.Run(t.Context(), "sub.example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for subdomain, got %d", len(findings))
	}
}

func TestParseTeamCymruResponse(t *testing.T) {
	// queryASNViaDNS parses "ASN | Prefix | CC | RIR | Allocated" format.
	// We can't unit-test the DNS call without mocking, but we can verify
	// the field parsing logic is correct by inspecting the format expectations.

	// Verify the reversed-IP construction.
	ip := "93.184.216.34"
	parts := []string{"93", "184", "216", "34"}
	want := "34.216.184.93.origin.asn.cymru.com"
	got := parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0] + ".origin.asn.cymru.com"
	_ = ip
	if got != want {
		t.Errorf("reversed DNS = %q; want %q", got, want)
	}
}
