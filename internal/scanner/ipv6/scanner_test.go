package ipv6

import (
	"context"
	"testing"

	"github.com/stormbane-security/beacon/internal/module"
)

func TestIPv6NoAAAA(t *testing.T) {
	// Use a domain that likely has no AAAA record.
	s := New()
	findings, err := s.Run(context.Background(), "this-domain-does-not-exist-beacon-test.invalid", module.ScanSurface)
	if err != nil {
		// DNS failure is expected for non-existent domain.
		return
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-existent domain, got %d", len(findings))
	}
}

func TestScannerName(t *testing.T) {
	s := New()
	if s.Name() != "ipv6" {
		t.Errorf("Name() = %q, want ipv6", s.Name())
	}
}
