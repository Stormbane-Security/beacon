package finding_test

import (
	"testing"

	"github.com/stormbane/beacon/internal/finding"
)

// containsTag returns true when the slice contains target.
func containsTag(tags []string, target string) bool {
	for _, t := range tags {
		if t == target {
			return true
		}
	}
	return false
}

func TestComplianceTags_EmailSPFMissing(t *testing.T) {
	tags := finding.ComplianceTags(finding.CheckEmailSPFMissing)
	if len(tags) == 0 {
		t.Fatal("ComplianceTags(CheckEmailSPFMissing) returned empty slice; want non-empty")
	}
	if !containsTag(tags, "SOC2-CC6.1") {
		t.Errorf("ComplianceTags(CheckEmailSPFMissing) = %v; want slice containing 'SOC2-CC6.1'", tags)
	}
}

func TestComplianceTags_EmailDMARCMissing(t *testing.T) {
	tags := finding.ComplianceTags(finding.CheckEmailDMARCMissing)
	if len(tags) == 0 {
		t.Fatal("ComplianceTags(CheckEmailDMARCMissing) returned empty slice; want non-empty")
	}
	if !containsTag(tags, "SOC2-CC6.1") {
		t.Errorf("ComplianceTags(CheckEmailDMARCMissing) = %v; want slice containing 'SOC2-CC6.1'", tags)
	}
}

func TestComplianceTags_DLPCreditCard(t *testing.T) {
	tags := finding.ComplianceTags(finding.CheckDLPCreditCard)
	if len(tags) == 0 {
		t.Fatal("ComplianceTags(CheckDLPCreditCard) returned empty slice; want non-empty")
	}
	if !containsTag(tags, "PCI-3.4") {
		t.Errorf("ComplianceTags(CheckDLPCreditCard) = %v; want slice containing 'PCI-3.4'", tags)
	}
}

func TestComplianceTags_DLPSSN(t *testing.T) {
	tags := finding.ComplianceTags(finding.CheckDLPSSN)
	if len(tags) == 0 {
		t.Fatal("ComplianceTags(CheckDLPSSN) returned empty slice; want non-empty")
	}
	if !containsTag(tags, "HIPAA-164.312") {
		t.Errorf("ComplianceTags(CheckDLPSSN) = %v; want slice containing 'HIPAA-164.312'", tags)
	}
}

func TestComplianceTags_PortRDPExposed(t *testing.T) {
	tags := finding.ComplianceTags(finding.CheckPortRDPExposed)
	if len(tags) == 0 {
		t.Fatal("ComplianceTags(CheckPortRDPExposed) returned empty slice; want non-empty")
	}
}

func TestComplianceTags_NonexistentCheck(t *testing.T) {
	tags := finding.ComplianceTags("nonexistent.check")
	if tags != nil {
		t.Errorf("ComplianceTags(\"nonexistent.check\") = %v; want nil", tags)
	}
}

func TestComplianceTags_HeadersMissingReferrerPolicy(t *testing.T) {
	// This low-value check is expected to have no compliance mapping.
	// The test documents and locks the actual behavior.
	tags := finding.ComplianceTags(finding.CheckHeadersMissingReferrerPolicy)
	if tags != nil {
		t.Errorf("ComplianceTags(CheckHeadersMissingReferrerPolicy) = %v; want nil (no compliance mapping for low-value header check)", tags)
	}
}
