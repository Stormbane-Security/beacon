package testssl

import (
	"testing"

	"github.com/stormbane/beacon/internal/finding"
)

// TestBEASTMappedToOwnCheckID verifies that the BEAST testssl ID produces
// finding.CheckTLSBEAST, not the generic CheckTLSWeakCipher. BEAST is a
// distinct vulnerability (CBC ciphers in TLS 1.0) and deserves its own
// check ID so it can be independently tracked and suppressed.
func TestBEASTMappedToOwnCheckID(t *testing.T) {
	r := testsslResult{
		ID:       "BEAST",
		Severity: "medium",
		Finding:  "TLS1: AES128-SHA AES256-SHA",
	}
	f := resultToFinding("example.com", r)
	if f == nil {
		t.Fatal("expected a finding for BEAST result, got nil")
	}
	if f.CheckID != finding.CheckTLSBEAST {
		t.Errorf("BEAST result: expected CheckID=%s, got %s", finding.CheckTLSBEAST, f.CheckID)
	}
}

// TestWeakCipherStillMapped verifies that non-BEAST weak cipher IDs (RC4, EXPORT,
// LOW, 3DES_IDEA) still map to CheckTLSWeakCipher after the BEAST split.
func TestWeakCipherStillMapped(t *testing.T) {
	for _, id := range []string{"RC4", "EXPORT", "LOW", "3DES_IDEA"} {
		r := testsslResult{
			ID:       id,
			Severity: "high",
			Finding:  "vulnerable",
		}
		f := resultToFinding("example.com", r)
		if f == nil {
			t.Fatalf("%s: expected a finding, got nil", id)
		}
		if f.CheckID != finding.CheckTLSWeakCipher {
			t.Errorf("%s: expected CheckTLSWeakCipher, got %s", id, f.CheckID)
		}
	}
}

// TestOKSeverity_NoFinding verifies that testssl "OK" results (not vulnerable)
// are not converted to findings.
func TestOKSeverity_NoFinding(t *testing.T) {
	r := testsslResult{
		ID:       "BEAST",
		Severity: "ok",
		Finding:  "not vulnerable",
	}
	f := resultToFinding("example.com", r)
	if f != nil {
		t.Errorf("expected nil for OK severity, got finding with CheckID=%s", f.CheckID)
	}
}

// TestNotVulnerableFinding_NoFinding verifies that results whose Finding field
// says "not vulnerable" are skipped regardless of severity label.
func TestNotVulnerableFinding_NoFinding(t *testing.T) {
	r := testsslResult{
		ID:       "HEARTBLEED",
		Severity: "critical",
		Finding:  "not vulnerable",
	}
	f := resultToFinding("example.com", r)
	if f != nil {
		t.Errorf("expected nil for 'not vulnerable' finding text, got %+v", f)
	}
}

// TestUnknownID_FallbackCheckID verifies that an unrecognised testssl ID
// falls back to a "tls.issue.<id>" pattern rather than panicking or returning nil.
func TestUnknownID_FallbackCheckID(t *testing.T) {
	r := testsslResult{
		ID:       "SOME_NEW_CHECK",
		Severity: "medium",
		Finding:  "some issue found",
	}
	f := resultToFinding("example.com", r)
	if f == nil {
		t.Fatal("expected fallback finding for unknown testssl ID, got nil")
	}
	expected := "tls.issue.some_new_check"
	if f.CheckID != expected {
		t.Errorf("expected fallback CheckID %q, got %q", expected, f.CheckID)
	}
}
