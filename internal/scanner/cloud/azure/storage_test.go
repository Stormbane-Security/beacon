package azure

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"

	"github.com/stormbane/beacon/internal/finding"
)

func boolPtr(b bool) *bool { return &b }

// -------------------------------------------------------------------------
// helpers
// -------------------------------------------------------------------------

func hasCheckID(findings []finding.Finding, id finding.CheckID) bool {
	for _, f := range findings {
		if f.CheckID == id {
			return true
		}
	}
	return false
}

func countCheckID(findings []finding.Finding, id finding.CheckID) int {
	n := 0
	for _, f := range findings {
		if f.CheckID == id {
			n++
		}
	}
	return n
}

func assertHasCheckID(t *testing.T, findings []finding.Finding, id finding.CheckID) {
	t.Helper()
	if !hasCheckID(findings, id) {
		t.Errorf("expected finding with CheckID %q, got none (total findings: %d)", id, len(findings))
	}
}

func assertNotHasCheckID(t *testing.T, findings []finding.Finding, id finding.CheckID) {
	t.Helper()
	if hasCheckID(findings, id) {
		t.Errorf("unexpected finding with CheckID %q", id)
	}
}

// -------------------------------------------------------------------------
// evaluateStorageAccount — public blob access
// -------------------------------------------------------------------------

func TestStorageAccount_BlobPublicAccessEnabled(t *testing.T) {
	props := &armstorage.AccountProperties{
		AllowBlobPublicAccess:  boolPtr(true),
		EnableHTTPSTrafficOnly: boolPtr(true),
		AllowSharedKeyAccess:   boolPtr(false),
	}
	findings := evaluateStorageAccount("teststorage", props, "sub-123", "example.com")
	assertHasCheckID(t, findings, finding.CheckCloudAzureBlobPublic)
}

func TestStorageAccount_BlobPublicAccessDisabled(t *testing.T) {
	props := &armstorage.AccountProperties{
		AllowBlobPublicAccess:  boolPtr(false),
		EnableHTTPSTrafficOnly: boolPtr(true),
		AllowSharedKeyAccess:   boolPtr(false),
	}
	findings := evaluateStorageAccount("teststorage", props, "sub-123", "example.com")
	assertNotHasCheckID(t, findings, finding.CheckCloudAzureBlobPublic)
}

func TestStorageAccount_BlobPublicAccessNil(t *testing.T) {
	props := &armstorage.AccountProperties{
		AllowBlobPublicAccess:  nil,
		EnableHTTPSTrafficOnly: boolPtr(true),
		AllowSharedKeyAccess:   boolPtr(false),
	}
	findings := evaluateStorageAccount("teststorage", props, "sub-123", "example.com")
	// nil means not explicitly enabled, so no finding
	assertNotHasCheckID(t, findings, finding.CheckCloudAzureBlobPublic)
}

// -------------------------------------------------------------------------
// evaluateStorageAccount — HTTPS traffic only
// -------------------------------------------------------------------------

func TestStorageAccount_HTTPTrafficAllowed(t *testing.T) {
	props := &armstorage.AccountProperties{
		AllowBlobPublicAccess:  boolPtr(false),
		EnableHTTPSTrafficOnly: boolPtr(false),
		AllowSharedKeyAccess:   boolPtr(false),
	}
	findings := evaluateStorageAccount("teststorage", props, "sub-123", "example.com")
	assertHasCheckID(t, findings, finding.CheckCloudAzureStorageHTTP)
}

func TestStorageAccount_HTTPSOnly(t *testing.T) {
	props := &armstorage.AccountProperties{
		AllowBlobPublicAccess:  boolPtr(false),
		EnableHTTPSTrafficOnly: boolPtr(true),
		AllowSharedKeyAccess:   boolPtr(false),
	}
	findings := evaluateStorageAccount("teststorage", props, "sub-123", "example.com")
	assertNotHasCheckID(t, findings, finding.CheckCloudAzureStorageHTTP)
}

func TestStorageAccount_HTTPSNil(t *testing.T) {
	props := &armstorage.AccountProperties{
		AllowBlobPublicAccess:  boolPtr(false),
		EnableHTTPSTrafficOnly: nil,
		AllowSharedKeyAccess:   boolPtr(false),
	}
	findings := evaluateStorageAccount("teststorage", props, "sub-123", "example.com")
	// nil means not explicitly disabled, so no finding
	assertNotHasCheckID(t, findings, finding.CheckCloudAzureStorageHTTP)
}

// -------------------------------------------------------------------------
// evaluateStorageAccount — shared key access
// -------------------------------------------------------------------------

func TestStorageAccount_SharedKeyAccessEnabled(t *testing.T) {
	props := &armstorage.AccountProperties{
		AllowBlobPublicAccess:  boolPtr(false),
		EnableHTTPSTrafficOnly: boolPtr(true),
		AllowSharedKeyAccess:   boolPtr(true),
	}
	findings := evaluateStorageAccount("teststorage", props, "sub-123", "example.com")
	assertHasCheckID(t, findings, finding.CheckCloudAzureStorageSharedKey)
}

func TestStorageAccount_SharedKeyAccessNil_DefaultsToFinding(t *testing.T) {
	// When AllowSharedKeyAccess is nil, Azure defaults to allowing shared key.
	// The scanner should emit a finding.
	props := &armstorage.AccountProperties{
		AllowBlobPublicAccess:  boolPtr(false),
		EnableHTTPSTrafficOnly: boolPtr(true),
		AllowSharedKeyAccess:   nil,
	}
	findings := evaluateStorageAccount("teststorage", props, "sub-123", "example.com")
	assertHasCheckID(t, findings, finding.CheckCloudAzureStorageSharedKey)
}

func TestStorageAccount_SharedKeyAccessDisabled(t *testing.T) {
	props := &armstorage.AccountProperties{
		AllowBlobPublicAccess:  boolPtr(false),
		EnableHTTPSTrafficOnly: boolPtr(true),
		AllowSharedKeyAccess:   boolPtr(false),
	}
	findings := evaluateStorageAccount("teststorage", props, "sub-123", "example.com")
	assertNotHasCheckID(t, findings, finding.CheckCloudAzureStorageSharedKey)
}

// -------------------------------------------------------------------------
// evaluateStorageAccount — fully secure account produces no findings
// -------------------------------------------------------------------------

func TestStorageAccount_FullySecure_NoFindings(t *testing.T) {
	props := &armstorage.AccountProperties{
		AllowBlobPublicAccess:  boolPtr(false),
		EnableHTTPSTrafficOnly: boolPtr(true),
		AllowSharedKeyAccess:   boolPtr(false),
	}
	findings := evaluateStorageAccount("securesa", props, "sub-123", "example.com")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for fully secure storage account, got %d", len(findings))
		for _, f := range findings {
			t.Logf("  CheckID=%s Title=%s", f.CheckID, f.Title)
		}
	}
}

// -------------------------------------------------------------------------
// evaluateStorageAccount — all misconfigurations at once
// -------------------------------------------------------------------------

func TestStorageAccount_AllMisconfigured(t *testing.T) {
	props := &armstorage.AccountProperties{
		AllowBlobPublicAccess:  boolPtr(true),
		EnableHTTPSTrafficOnly: boolPtr(false),
		AllowSharedKeyAccess:   boolPtr(true),
	}
	findings := evaluateStorageAccount("badstorage", props, "sub-123", "example.com")
	assertHasCheckID(t, findings, finding.CheckCloudAzureBlobPublic)
	assertHasCheckID(t, findings, finding.CheckCloudAzureStorageHTTP)
	assertHasCheckID(t, findings, finding.CheckCloudAzureStorageSharedKey)
	if len(findings) != 3 {
		t.Errorf("expected exactly 3 findings for fully misconfigured account, got %d", len(findings))
	}
}

// -------------------------------------------------------------------------
// evaluateStorageAccount — finding metadata correctness
// -------------------------------------------------------------------------

func TestStorageAccount_FindingMetadata(t *testing.T) {
	props := &armstorage.AccountProperties{
		AllowBlobPublicAccess:  boolPtr(true),
		EnableHTTPSTrafficOnly: boolPtr(true),
		AllowSharedKeyAccess:   boolPtr(false),
	}
	findings := evaluateStorageAccount("myaccount", props, "sub-abc", "target.com")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Scanner != "cloud/azure" {
		t.Errorf("Scanner = %q; want %q", f.Scanner, "cloud/azure")
	}
	if f.Asset != "target.com" {
		t.Errorf("Asset = %q; want %q", f.Asset, "target.com")
	}
	if f.Severity != finding.SeverityHigh {
		t.Errorf("Severity = %v; want SeverityHigh", f.Severity)
	}
	if f.ProofCommand == "" {
		t.Error("ProofCommand should not be empty")
	}
	if f.Evidence["account_name"] != "myaccount" {
		t.Errorf("Evidence[account_name] = %v; want %q", f.Evidence["account_name"], "myaccount")
	}
	if f.Evidence["subscription_id"] != "sub-abc" {
		t.Errorf("Evidence[subscription_id] = %v; want %q", f.Evidence["subscription_id"], "sub-abc")
	}
	if f.DiscoveredAt.IsZero() {
		t.Error("DiscoveredAt should not be zero")
	}
}

// -------------------------------------------------------------------------
// evaluateStorageAccount — table-driven severity check
// -------------------------------------------------------------------------

func TestStorageAccount_Severities(t *testing.T) {
	tests := []struct {
		name     string
		checkID  finding.CheckID
		wantSev  finding.Severity
		props    *armstorage.AccountProperties
	}{
		{
			name:    "blob public access is high severity",
			checkID: finding.CheckCloudAzureBlobPublic,
			wantSev: finding.SeverityHigh,
			props: &armstorage.AccountProperties{
				AllowBlobPublicAccess:  boolPtr(true),
				EnableHTTPSTrafficOnly: boolPtr(true),
				AllowSharedKeyAccess:   boolPtr(false),
			},
		},
		{
			name:    "HTTP traffic is medium severity",
			checkID: finding.CheckCloudAzureStorageHTTP,
			wantSev: finding.SeverityMedium,
			props: &armstorage.AccountProperties{
				AllowBlobPublicAccess:  boolPtr(false),
				EnableHTTPSTrafficOnly: boolPtr(false),
				AllowSharedKeyAccess:   boolPtr(false),
			},
		},
		{
			name:    "shared key access is medium severity",
			checkID: finding.CheckCloudAzureStorageSharedKey,
			wantSev: finding.SeverityMedium,
			props: &armstorage.AccountProperties{
				AllowBlobPublicAccess:  boolPtr(false),
				EnableHTTPSTrafficOnly: boolPtr(true),
				AllowSharedKeyAccess:   boolPtr(true),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := evaluateStorageAccount("sa", tt.props, "sub-1", "asset")
			for _, f := range findings {
				if f.CheckID == tt.checkID {
					if f.Severity != tt.wantSev {
						t.Errorf("CheckID %q: Severity = %v; want %v", tt.checkID, f.Severity, tt.wantSev)
					}
					return
				}
			}
			t.Errorf("expected finding with CheckID %q, got none", tt.checkID)
		})
	}
}
