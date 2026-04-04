package oci

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
)

// ── helpers ─────────────────────────────────────────────────────────────────

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

func findByCheckID(findings []finding.Finding, id finding.CheckID) *finding.Finding {
	for i := range findings {
		if findings[i].CheckID == id {
			return &findings[i]
		}
	}
	return nil
}

// testScanner creates a Scanner pointed at the given httptest.Server with
// a pre-built ociConfig. No real OCI credentials or signing required.
func testScanner(ts *httptest.Server) (*Scanner, *ociConfig) {
	s := &Scanner{
		cfg:     Config{},
		client:  ts.Client(),
		baseURL: ts.URL,
	}
	cfg := &ociConfig{
		Tenancy:     "ocid1.tenancy.oc1..test",
		User:        "ocid1.user.oc1..test",
		Region:      "us-ashburn-1",
		Fingerprint: "aa:bb:cc:dd:ee",
	}
	return s, cfg
}

// ── Scanner constructor and Name ────────────────────────────────────────────

func TestNew(t *testing.T) {
	cfg := Config{ConfigFile: "/path/to/config"}
	s := New(cfg)
	if s == nil {
		t.Fatal("New returned nil")
	}
	if s.cfg.ConfigFile != "/path/to/config" {
		t.Errorf("ConfigFile = %q; want /path/to/config", s.cfg.ConfigFile)
	}
	if s.client == nil {
		t.Error("client should not be nil")
	}
}

func TestName(t *testing.T) {
	s := New(Config{})
	if got := s.Name(); got != "cloud/oci" {
		t.Errorf("Name() = %q; want %q", got, "cloud/oci")
	}
}

// ── checkBucket — public access detection ───────────────────────────────────

func TestCheckBucket_PublicObjectRead(t *testing.T) {
	bucket := bucketDetail{
		Name:             "public-data",
		Namespace:        "testns",
		CompartmentID:    "ocid1.compartment.oc1..test",
		PublicAccessType: "ObjectRead",
		KmsKeyID:         "ocid1.key.oc1..test",
	}
	findings := checkBucket(bucket, "testns", "us-ashburn-1", "example.com")
	assertHasCheckID(t, findings, finding.CheckCloudOCIBucketPublic)

	f := findByCheckID(findings, finding.CheckCloudOCIBucketPublic)
	if f.Severity != finding.SeverityCritical {
		t.Errorf("Severity = %v; want SeverityCritical", f.Severity)
	}
	if !strings.Contains(f.Description, "list and read objects from") {
		t.Errorf("Description should describe ObjectRead access, got: %s", f.Description)
	}
}

func TestCheckBucket_PublicObjectReadWithoutList(t *testing.T) {
	bucket := bucketDetail{
		Name:             "semi-public",
		Namespace:        "testns",
		CompartmentID:    "ocid1.compartment.oc1..test",
		PublicAccessType: "ObjectReadWithoutList",
		KmsKeyID:         "ocid1.key.oc1..test",
	}
	findings := checkBucket(bucket, "testns", "us-ashburn-1", "example.com")
	assertHasCheckID(t, findings, finding.CheckCloudOCIBucketPublic)

	f := findByCheckID(findings, finding.CheckCloudOCIBucketPublic)
	if !strings.Contains(f.Description, "read objects from (without listing)") {
		t.Errorf("Description should describe ObjectReadWithoutList access, got: %s", f.Description)
	}
}

func TestCheckBucket_NoPublicAccess(t *testing.T) {
	bucket := bucketDetail{
		Name:             "private-data",
		Namespace:        "testns",
		CompartmentID:    "ocid1.compartment.oc1..test",
		PublicAccessType: "NoPublicAccess",
		KmsKeyID:         "ocid1.key.oc1..test",
	}
	findings := checkBucket(bucket, "testns", "us-ashburn-1", "example.com")
	assertNotHasCheckID(t, findings, finding.CheckCloudOCIBucketPublic)
}

func TestCheckBucket_EmptyPublicAccessType(t *testing.T) {
	bucket := bucketDetail{
		Name:             "private-data",
		Namespace:        "testns",
		CompartmentID:    "ocid1.compartment.oc1..test",
		PublicAccessType: "",
		KmsKeyID:         "ocid1.key.oc1..test",
	}
	findings := checkBucket(bucket, "testns", "us-ashburn-1", "example.com")
	assertNotHasCheckID(t, findings, finding.CheckCloudOCIBucketPublic)
}

// ── checkBucket — missing CMEK ──────────────────────────────────────────────

func TestCheckBucket_NoCMEK(t *testing.T) {
	bucket := bucketDetail{
		Name:             "no-cmek",
		Namespace:        "testns",
		CompartmentID:    "ocid1.compartment.oc1..test",
		PublicAccessType: "NoPublicAccess",
		KmsKeyID:         "",
	}
	findings := checkBucket(bucket, "testns", "us-ashburn-1", "example.com")
	assertHasCheckID(t, findings, finding.CheckCloudOCIBucketNoEncryption)

	f := findByCheckID(findings, finding.CheckCloudOCIBucketNoEncryption)
	if f.Severity != finding.SeverityMedium {
		t.Errorf("Severity = %v; want SeverityMedium", f.Severity)
	}
	if f.Evidence["kms_key_id"] != "" {
		t.Errorf("Evidence[kms_key_id] = %v; want empty", f.Evidence["kms_key_id"])
	}
}

func TestCheckBucket_WithCMEK(t *testing.T) {
	bucket := bucketDetail{
		Name:             "encrypted",
		Namespace:        "testns",
		CompartmentID:    "ocid1.compartment.oc1..test",
		PublicAccessType: "NoPublicAccess",
		KmsKeyID:         "ocid1.key.oc1..aaaaaa",
	}
	findings := checkBucket(bucket, "testns", "us-ashburn-1", "example.com")
	assertNotHasCheckID(t, findings, finding.CheckCloudOCIBucketNoEncryption)
}

// ── checkBucket — fully secure bucket produces no findings ──────────────────

func TestCheckBucket_FullySecure_NoFindings(t *testing.T) {
	bucket := bucketDetail{
		Name:             "secure-bucket",
		Namespace:        "testns",
		CompartmentID:    "ocid1.compartment.oc1..test",
		PublicAccessType: "NoPublicAccess",
		KmsKeyID:         "ocid1.key.oc1..aaaaaa",
	}
	findings := checkBucket(bucket, "testns", "us-ashburn-1", "example.com")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for fully secure bucket, got %d", len(findings))
		for _, f := range findings {
			t.Logf("  CheckID=%s Title=%s", f.CheckID, f.Title)
		}
	}
}

// ── checkBucket — all misconfigured ─────────────────────────────────────────

func TestCheckBucket_AllMisconfigured(t *testing.T) {
	bucket := bucketDetail{
		Name:             "bad-bucket",
		Namespace:        "testns",
		CompartmentID:    "ocid1.compartment.oc1..test",
		PublicAccessType: "ObjectRead",
		KmsKeyID:         "",
	}
	findings := checkBucket(bucket, "testns", "us-ashburn-1", "example.com")
	assertHasCheckID(t, findings, finding.CheckCloudOCIBucketPublic)
	assertHasCheckID(t, findings, finding.CheckCloudOCIBucketNoEncryption)
	if len(findings) != 2 {
		t.Errorf("expected exactly 2 findings for fully misconfigured bucket, got %d", len(findings))
	}
}

// ── checkBucket — finding metadata ──────────────────────────────────────────

func TestCheckBucket_FindingMetadata(t *testing.T) {
	bucket := bucketDetail{
		Name:             "mybucket",
		Namespace:        "mynamespace",
		CompartmentID:    "ocid1.compartment.oc1..abc",
		PublicAccessType: "ObjectRead",
		KmsKeyID:         "ocid1.key.oc1..aaaaaa",
	}
	findings := checkBucket(bucket, "mynamespace", "eu-frankfurt-1", "target.com")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Scanner != "cloud/oci" {
		t.Errorf("Scanner = %q; want %q", f.Scanner, "cloud/oci")
	}
	if f.Asset != "target.com" {
		t.Errorf("Asset = %q; want %q", f.Asset, "target.com")
	}
	if f.ProofCommand == "" {
		t.Error("ProofCommand should not be empty")
	}
	if f.Evidence["bucket"] != "mybucket" {
		t.Errorf("Evidence[bucket] = %v; want %q", f.Evidence["bucket"], "mybucket")
	}
	if f.Evidence["namespace"] != "mynamespace" {
		t.Errorf("Evidence[namespace] = %v; want %q", f.Evidence["namespace"], "mynamespace")
	}
	if f.Evidence["region"] != "eu-frankfurt-1" {
		t.Errorf("Evidence[region] = %v; want %q", f.Evidence["region"], "eu-frankfurt-1")
	}
	if f.DiscoveredAt.IsZero() {
		t.Error("DiscoveredAt should not be zero")
	}
}

// ── checkSecurityList — all-open ingress ────────────────────────────────────

func TestSecurityList_AllProtocolsOpen(t *testing.T) {
	sl := securityList{
		ID:          "ocid1.securitylist.oc1..test",
		DisplayName: "wide-open-sl",
		IngressRules: []ingressRule{
			{Protocol: "all", Source: "0.0.0.0/0", SourceType: "CIDR_BLOCK"},
		},
	}
	findings := checkSecurityList(sl, "test-vcn", "us-ashburn-1", "example.com")
	assertHasCheckID(t, findings, finding.CheckCloudOCISecurityListAllOpen)

	f := findByCheckID(findings, finding.CheckCloudOCISecurityListAllOpen)
	if f.Severity != finding.SeverityCritical {
		t.Errorf("Severity = %v; want SeverityCritical", f.Severity)
	}
}

func TestSecurityList_AllProtocolsOpenIPv6(t *testing.T) {
	sl := securityList{
		ID:          "ocid1.securitylist.oc1..test",
		DisplayName: "wide-open-sl-v6",
		IngressRules: []ingressRule{
			{Protocol: "all", Source: "::/0", SourceType: "CIDR_BLOCK"},
		},
	}
	findings := checkSecurityList(sl, "test-vcn", "us-ashburn-1", "example.com")
	assertHasCheckID(t, findings, finding.CheckCloudOCISecurityListAllOpen)
}

func TestSecurityList_TCPAllPortsNoOptions(t *testing.T) {
	// TCP protocol with no TCPOptions means all TCP ports are open.
	sl := securityList{
		ID:          "ocid1.securitylist.oc1..test",
		DisplayName: "tcp-no-options",
		IngressRules: []ingressRule{
			{Protocol: "6", Source: "0.0.0.0/0", SourceType: "CIDR_BLOCK"},
		},
	}
	findings := checkSecurityList(sl, "test-vcn", "us-ashburn-1", "example.com")
	assertHasCheckID(t, findings, finding.CheckCloudOCISecurityListAllOpen)
}

func TestSecurityList_TCPFullPortRange(t *testing.T) {
	sl := securityList{
		ID:          "ocid1.securitylist.oc1..test",
		DisplayName: "tcp-full-range",
		IngressRules: []ingressRule{
			{
				Protocol:   "6",
				Source:     "0.0.0.0/0",
				SourceType: "CIDR_BLOCK",
				TCPOptions: &portOptions{
					DestinationPortRange: &portRange{Min: 1, Max: 65535},
				},
			},
		},
	}
	findings := checkSecurityList(sl, "test-vcn", "us-ashburn-1", "example.com")
	assertHasCheckID(t, findings, finding.CheckCloudOCISecurityListAllOpen)
}

func TestSecurityList_UDPAllPortsNoOptions(t *testing.T) {
	sl := securityList{
		ID:          "ocid1.securitylist.oc1..test",
		DisplayName: "udp-no-options",
		IngressRules: []ingressRule{
			{Protocol: "17", Source: "0.0.0.0/0", SourceType: "CIDR_BLOCK"},
		},
	}
	findings := checkSecurityList(sl, "test-vcn", "us-ashburn-1", "example.com")
	assertHasCheckID(t, findings, finding.CheckCloudOCISecurityListAllOpen)
}

// ── checkSecurityList — SSH open ────────────────────────────────────────────

func TestSecurityList_SSHOpen(t *testing.T) {
	sl := securityList{
		ID:          "ocid1.securitylist.oc1..test",
		DisplayName: "ssh-open-sl",
		IngressRules: []ingressRule{
			{
				Protocol:   "6",
				Source:     "0.0.0.0/0",
				SourceType: "CIDR_BLOCK",
				TCPOptions: &portOptions{
					DestinationPortRange: &portRange{Min: 22, Max: 22},
				},
			},
		},
	}
	findings := checkSecurityList(sl, "test-vcn", "us-ashburn-1", "example.com")
	assertHasCheckID(t, findings, finding.CheckCloudOCISecurityListSSHOpen)
	// Should NOT also emit all-open since only port 22 is open.
	assertNotHasCheckID(t, findings, finding.CheckCloudOCISecurityListAllOpen)

	f := findByCheckID(findings, finding.CheckCloudOCISecurityListSSHOpen)
	if f.Severity != finding.SeverityHigh {
		t.Errorf("Severity = %v; want SeverityHigh", f.Severity)
	}
}

func TestSecurityList_SSHOpenInRange(t *testing.T) {
	// Port 22 is within the range 20-25.
	sl := securityList{
		ID:          "ocid1.securitylist.oc1..test",
		DisplayName: "ssh-range-sl",
		IngressRules: []ingressRule{
			{
				Protocol:   "6",
				Source:     "0.0.0.0/0",
				SourceType: "CIDR_BLOCK",
				TCPOptions: &portOptions{
					DestinationPortRange: &portRange{Min: 20, Max: 25},
				},
			},
		},
	}
	findings := checkSecurityList(sl, "test-vcn", "us-ashburn-1", "example.com")
	assertHasCheckID(t, findings, finding.CheckCloudOCISecurityListSSHOpen)
}

func TestSecurityList_SSHNotInRange(t *testing.T) {
	// Port range 80-443 does not include SSH.
	sl := securityList{
		ID:          "ocid1.securitylist.oc1..test",
		DisplayName: "https-only-sl",
		IngressRules: []ingressRule{
			{
				Protocol:   "6",
				Source:     "0.0.0.0/0",
				SourceType: "CIDR_BLOCK",
				TCPOptions: &portOptions{
					DestinationPortRange: &portRange{Min: 80, Max: 443},
				},
			},
		},
	}
	findings := checkSecurityList(sl, "test-vcn", "us-ashburn-1", "example.com")
	assertNotHasCheckID(t, findings, finding.CheckCloudOCISecurityListSSHOpen)
	assertNotHasCheckID(t, findings, finding.CheckCloudOCISecurityListAllOpen)
}

func TestSecurityList_PrivateSource_NoFindings(t *testing.T) {
	// Source is a private CIDR, not 0.0.0.0/0.
	sl := securityList{
		ID:          "ocid1.securitylist.oc1..test",
		DisplayName: "private-sl",
		IngressRules: []ingressRule{
			{Protocol: "all", Source: "10.0.0.0/8", SourceType: "CIDR_BLOCK"},
		},
	}
	findings := checkSecurityList(sl, "test-vcn", "us-ashburn-1", "example.com")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for private source, got %d", len(findings))
	}
}

func TestSecurityList_NoRules_NoFindings(t *testing.T) {
	sl := securityList{
		ID:           "ocid1.securitylist.oc1..test",
		DisplayName:  "empty-sl",
		IngressRules: nil,
	}
	findings := checkSecurityList(sl, "test-vcn", "us-ashburn-1", "example.com")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty security list, got %d", len(findings))
	}
}

// ── checkSecurityList — finding metadata ────────────────────────────────────

func TestSecurityList_FindingMetadata(t *testing.T) {
	sl := securityList{
		ID:          "ocid1.securitylist.oc1..abc123",
		DisplayName: "my-sl",
		IngressRules: []ingressRule{
			{Protocol: "all", Source: "0.0.0.0/0", SourceType: "CIDR_BLOCK"},
		},
	}
	findings := checkSecurityList(sl, "prod-vcn", "eu-frankfurt-1", "target.com")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Scanner != "cloud/oci" {
		t.Errorf("Scanner = %q; want %q", f.Scanner, "cloud/oci")
	}
	if f.Asset != "target.com" {
		t.Errorf("Asset = %q; want %q", f.Asset, "target.com")
	}
	if f.ProofCommand == "" {
		t.Error("ProofCommand should not be empty")
	}
	if f.Evidence["security_list_id"] != "ocid1.securitylist.oc1..abc123" {
		t.Errorf("Evidence[security_list_id] = %v; want the OCID", f.Evidence["security_list_id"])
	}
	if f.Evidence["vcn_name"] != "prod-vcn" {
		t.Errorf("Evidence[vcn_name] = %v; want %q", f.Evidence["vcn_name"], "prod-vcn")
	}
	if f.Evidence["region"] != "eu-frankfurt-1" {
		t.Errorf("Evidence[region] = %v; want %q", f.Evidence["region"], "eu-frankfurt-1")
	}
	if f.DiscoveredAt.IsZero() {
		t.Error("DiscoveredAt should not be zero")
	}
}

// ── checkNSG — all-open ingress ─────────────────────────────────────────────

func TestNSG_AllProtocolsOpen(t *testing.T) {
	nsg := nsgSummary{
		ID:          "ocid1.nsg.oc1..test",
		DisplayName: "wide-open-nsg",
		VcnID:       "ocid1.vcn.oc1..test",
	}
	rules := []nsgSecurityRule{
		{ID: "rule1", Direction: "INGRESS", Protocol: "all", Source: "0.0.0.0/0", SourceType: "CIDR_BLOCK"},
	}
	findings := checkNSG(nsg, rules, "test-vcn", "us-ashburn-1", "example.com")
	assertHasCheckID(t, findings, finding.CheckCloudOCINSGAllOpen)

	f := findByCheckID(findings, finding.CheckCloudOCINSGAllOpen)
	if f.Severity != finding.SeverityCritical {
		t.Errorf("Severity = %v; want SeverityCritical", f.Severity)
	}
}

func TestNSG_AllProtocolsOpenIPv6(t *testing.T) {
	nsg := nsgSummary{
		ID:          "ocid1.nsg.oc1..test",
		DisplayName: "wide-open-nsg-v6",
	}
	rules := []nsgSecurityRule{
		{ID: "rule1", Direction: "INGRESS", Protocol: "all", Source: "::/0", SourceType: "CIDR_BLOCK"},
	}
	findings := checkNSG(nsg, rules, "test-vcn", "us-ashburn-1", "example.com")
	assertHasCheckID(t, findings, finding.CheckCloudOCINSGAllOpen)
}

func TestNSG_TCPNoOptionsAllOpen(t *testing.T) {
	nsg := nsgSummary{
		ID:          "ocid1.nsg.oc1..test",
		DisplayName: "tcp-all-nsg",
	}
	rules := []nsgSecurityRule{
		{ID: "rule1", Direction: "INGRESS", Protocol: "6", Source: "0.0.0.0/0", SourceType: "CIDR_BLOCK"},
	}
	findings := checkNSG(nsg, rules, "test-vcn", "us-ashburn-1", "example.com")
	assertHasCheckID(t, findings, finding.CheckCloudOCINSGAllOpen)
}

func TestNSG_TCPFullPortRange(t *testing.T) {
	nsg := nsgSummary{
		ID:          "ocid1.nsg.oc1..test",
		DisplayName: "tcp-full-nsg",
	}
	rules := []nsgSecurityRule{
		{
			ID:         "rule1",
			Direction:  "INGRESS",
			Protocol:   "6",
			Source:     "0.0.0.0/0",
			SourceType: "CIDR_BLOCK",
			TCPOptions: &portOptions{
				DestinationPortRange: &portRange{Min: 1, Max: 65535},
			},
		},
	}
	findings := checkNSG(nsg, rules, "test-vcn", "us-ashburn-1", "example.com")
	assertHasCheckID(t, findings, finding.CheckCloudOCINSGAllOpen)
}

func TestNSG_EgressRulesIgnored(t *testing.T) {
	nsg := nsgSummary{
		ID:          "ocid1.nsg.oc1..test",
		DisplayName: "egress-only-nsg",
	}
	rules := []nsgSecurityRule{
		{ID: "rule1", Direction: "EGRESS", Protocol: "all", Source: "0.0.0.0/0", SourceType: "CIDR_BLOCK"},
	}
	findings := checkNSG(nsg, rules, "test-vcn", "us-ashburn-1", "example.com")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for egress-only rules, got %d", len(findings))
	}
}

func TestNSG_PrivateSource_NoFindings(t *testing.T) {
	nsg := nsgSummary{
		ID:          "ocid1.nsg.oc1..test",
		DisplayName: "private-nsg",
	}
	rules := []nsgSecurityRule{
		{ID: "rule1", Direction: "INGRESS", Protocol: "all", Source: "10.0.0.0/8", SourceType: "CIDR_BLOCK"},
	}
	findings := checkNSG(nsg, rules, "test-vcn", "us-ashburn-1", "example.com")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for private source, got %d", len(findings))
	}
}

func TestNSG_RestrictedPorts_NoFindings(t *testing.T) {
	nsg := nsgSummary{
		ID:          "ocid1.nsg.oc1..test",
		DisplayName: "restricted-nsg",
	}
	rules := []nsgSecurityRule{
		{
			ID:         "rule1",
			Direction:  "INGRESS",
			Protocol:   "6",
			Source:     "0.0.0.0/0",
			SourceType: "CIDR_BLOCK",
			TCPOptions: &portOptions{
				DestinationPortRange: &portRange{Min: 443, Max: 443},
			},
		},
	}
	findings := checkNSG(nsg, rules, "test-vcn", "us-ashburn-1", "example.com")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for HTTPS-only rule, got %d", len(findings))
	}
}

func TestNSG_NoRules_NoFindings(t *testing.T) {
	nsg := nsgSummary{
		ID:          "ocid1.nsg.oc1..test",
		DisplayName: "empty-nsg",
	}
	findings := checkNSG(nsg, nil, "test-vcn", "us-ashburn-1", "example.com")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty NSG, got %d", len(findings))
	}
}

// ── checkNSG — finding metadata ─────────────────────────────────────────────

func TestNSG_FindingMetadata(t *testing.T) {
	nsg := nsgSummary{
		ID:          "ocid1.nsg.oc1..abc123",
		DisplayName: "my-nsg",
	}
	rules := []nsgSecurityRule{
		{ID: "rule-xyz", Direction: "INGRESS", Protocol: "all", Source: "0.0.0.0/0", SourceType: "CIDR_BLOCK"},
	}
	findings := checkNSG(nsg, rules, "prod-vcn", "eu-frankfurt-1", "target.com")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Scanner != "cloud/oci" {
		t.Errorf("Scanner = %q; want %q", f.Scanner, "cloud/oci")
	}
	if f.Asset != "target.com" {
		t.Errorf("Asset = %q; want %q", f.Asset, "target.com")
	}
	if f.ProofCommand == "" {
		t.Error("ProofCommand should not be empty")
	}
	if f.Evidence["nsg_id"] != "ocid1.nsg.oc1..abc123" {
		t.Errorf("Evidence[nsg_id] = %v; want the OCID", f.Evidence["nsg_id"])
	}
	if f.Evidence["rule_id"] != "rule-xyz" {
		t.Errorf("Evidence[rule_id] = %v; want %q", f.Evidence["rule_id"], "rule-xyz")
	}
	if f.Evidence["vcn_name"] != "prod-vcn" {
		t.Errorf("Evidence[vcn_name] = %v; want %q", f.Evidence["vcn_name"], "prod-vcn")
	}
	if f.DiscoveredAt.IsZero() {
		t.Error("DiscoveredAt should not be zero")
	}
}

// ── checkKeyRotation — vault key no rotation ────────────────────────────────

func TestKeyRotation_NoAutoRotation(t *testing.T) {
	key := keyDetail{
		ID:                     "ocid1.key.oc1..test",
		DisplayName:            "master-key",
		LifecycleState:         "ENABLED",
		Algorithm:              "AES",
		TimeCreated:            time.Now().Add(-30 * 24 * time.Hour).Format(time.RFC3339),
		AutoKeyRotationDetails: nil,
	}
	findings := checkKeyRotation(key, "prod-vault", "us-ashburn-1", "example.com")
	assertHasCheckID(t, findings, finding.CheckCloudOCIVaultKeyNoRotation)

	f := findByCheckID(findings, finding.CheckCloudOCIVaultKeyNoRotation)
	// Key is less than 365 days old, so severity should be Medium.
	if f.Severity != finding.SeverityMedium {
		t.Errorf("Severity = %v; want SeverityMedium for recent key without rotation", f.Severity)
	}
}

func TestKeyRotation_ZeroIntervalDays(t *testing.T) {
	key := keyDetail{
		ID:             "ocid1.key.oc1..test",
		DisplayName:    "no-rotation-key",
		LifecycleState: "ENABLED",
		Algorithm:      "AES",
		TimeCreated:    time.Now().Add(-30 * 24 * time.Hour).Format(time.RFC3339),
		AutoKeyRotationDetails: &autoKeyRotation{
			RotationIntervalInDays: 0,
		},
	}
	findings := checkKeyRotation(key, "prod-vault", "us-ashburn-1", "example.com")
	assertHasCheckID(t, findings, finding.CheckCloudOCIVaultKeyNoRotation)
}

func TestKeyRotation_StaleKeyHighSeverity(t *testing.T) {
	// Key older than 365 days should produce High severity.
	key := keyDetail{
		ID:                     "ocid1.key.oc1..test",
		DisplayName:            "stale-key",
		LifecycleState:         "ENABLED",
		Algorithm:              "RSA",
		TimeCreated:            time.Now().Add(-400 * 24 * time.Hour).Format(time.RFC3339),
		AutoKeyRotationDetails: nil,
	}
	findings := checkKeyRotation(key, "prod-vault", "us-ashburn-1", "example.com")
	assertHasCheckID(t, findings, finding.CheckCloudOCIVaultKeyNoRotation)

	f := findByCheckID(findings, finding.CheckCloudOCIVaultKeyNoRotation)
	if f.Severity != finding.SeverityHigh {
		t.Errorf("Severity = %v; want SeverityHigh for stale key (>365 days)", f.Severity)
	}
	if !strings.Contains(f.Title, "key older than 365 days") {
		t.Errorf("Title should mention key age, got: %s", f.Title)
	}
}

func TestKeyRotation_WithAutoRotation_NoFindings(t *testing.T) {
	key := keyDetail{
		ID:             "ocid1.key.oc1..test",
		DisplayName:    "rotated-key",
		LifecycleState: "ENABLED",
		Algorithm:      "AES",
		TimeCreated:    time.Now().Add(-30 * 24 * time.Hour).Format(time.RFC3339),
		AutoKeyRotationDetails: &autoKeyRotation{
			RotationIntervalInDays: 90,
			LastCompletedRotation:  time.Now().Add(-10 * 24 * time.Hour).Format(time.RFC3339),
			NextRotation:           time.Now().Add(80 * 24 * time.Hour).Format(time.RFC3339),
		},
	}
	findings := checkKeyRotation(key, "prod-vault", "us-ashburn-1", "example.com")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for key with auto-rotation, got %d", len(findings))
		for _, f := range findings {
			t.Logf("  CheckID=%s Title=%s", f.CheckID, f.Title)
		}
	}
}

// ── checkKeyRotation — finding metadata ─────────────────────────────────────

func TestKeyRotation_FindingMetadata(t *testing.T) {
	key := keyDetail{
		ID:                     "ocid1.key.oc1..abc123",
		DisplayName:            "mykey",
		CompartmentID:          "ocid1.compartment.oc1..test",
		LifecycleState:         "ENABLED",
		Algorithm:              "ECDSA",
		TimeCreated:            time.Now().Add(-30 * 24 * time.Hour).Format(time.RFC3339),
		AutoKeyRotationDetails: nil,
	}
	findings := checkKeyRotation(key, "my-vault", "ap-tokyo-1", "target.com")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Scanner != "cloud/oci" {
		t.Errorf("Scanner = %q; want %q", f.Scanner, "cloud/oci")
	}
	if f.Asset != "target.com" {
		t.Errorf("Asset = %q; want %q", f.Asset, "target.com")
	}
	if f.ProofCommand == "" {
		t.Error("ProofCommand should not be empty")
	}
	if f.Evidence["key_id"] != "ocid1.key.oc1..abc123" {
		t.Errorf("Evidence[key_id] = %v; want the OCID", f.Evidence["key_id"])
	}
	if f.Evidence["vault_name"] != "my-vault" {
		t.Errorf("Evidence[vault_name] = %v; want %q", f.Evidence["vault_name"], "my-vault")
	}
	if f.Evidence["algorithm"] != "ECDSA" {
		t.Errorf("Evidence[algorithm] = %v; want %q", f.Evidence["algorithm"], "ECDSA")
	}
	if f.DiscoveredAt.IsZero() {
		t.Error("DiscoveredAt should not be zero")
	}
}

// ── isAllPortsCovered — pure function ───────────────────────────────────────

func TestIsAllPortsCovered(t *testing.T) {
	tests := []struct {
		name string
		rule ingressRule
		want bool
	}{
		{
			name: "protocol all (checked by caller, not this function)",
			rule: ingressRule{Protocol: "all"},
			want: false,
		},
		{
			name: "TCP no options means all ports",
			rule: ingressRule{Protocol: "6"},
			want: true,
		},
		{
			name: "UDP no options means all ports",
			rule: ingressRule{Protocol: "17"},
			want: true,
		},
		{
			name: "TCP full range",
			rule: ingressRule{
				Protocol:   "6",
				TCPOptions: &portOptions{DestinationPortRange: &portRange{Min: 1, Max: 65535}},
			},
			want: true,
		},
		{
			name: "UDP full range",
			rule: ingressRule{
				Protocol:   "17",
				UDPOptions: &portOptions{DestinationPortRange: &portRange{Min: 1, Max: 65535}},
			},
			want: true,
		},
		{
			name: "TCP restricted port",
			rule: ingressRule{
				Protocol:   "6",
				TCPOptions: &portOptions{DestinationPortRange: &portRange{Min: 443, Max: 443}},
			},
			want: false,
		},
		{
			name: "TCP small range",
			rule: ingressRule{
				Protocol:   "6",
				TCPOptions: &portOptions{DestinationPortRange: &portRange{Min: 80, Max: 443}},
			},
			want: false,
		},
		{
			name: "ICMP protocol (1) with no options",
			rule: ingressRule{Protocol: "1"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isAllPortsCovered(tt.rule)
			if got != tt.want {
				t.Errorf("isAllPortsCovered() = %v; want %v", got, tt.want)
			}
		})
	}
}

// ── isSSHCovered — pure function ────────────────────────────────────────────

func TestIsSSHCovered(t *testing.T) {
	tests := []struct {
		name string
		rule ingressRule
		want bool
	}{
		{
			name: "no TCP options means all ports including 22",
			rule: ingressRule{Protocol: "6"},
			want: true,
		},
		{
			name: "exact port 22",
			rule: ingressRule{
				Protocol:   "6",
				TCPOptions: &portOptions{DestinationPortRange: &portRange{Min: 22, Max: 22}},
			},
			want: true,
		},
		{
			name: "range includes 22",
			rule: ingressRule{
				Protocol:   "6",
				TCPOptions: &portOptions{DestinationPortRange: &portRange{Min: 20, Max: 25}},
			},
			want: true,
		},
		{
			name: "range starts at 22",
			rule: ingressRule{
				Protocol:   "6",
				TCPOptions: &portOptions{DestinationPortRange: &portRange{Min: 22, Max: 100}},
			},
			want: true,
		},
		{
			name: "range ends at 22",
			rule: ingressRule{
				Protocol:   "6",
				TCPOptions: &portOptions{DestinationPortRange: &portRange{Min: 1, Max: 22}},
			},
			want: true,
		},
		{
			name: "range below 22",
			rule: ingressRule{
				Protocol:   "6",
				TCPOptions: &portOptions{DestinationPortRange: &portRange{Min: 1, Max: 21}},
			},
			want: false,
		},
		{
			name: "range above 22",
			rule: ingressRule{
				Protocol:   "6",
				TCPOptions: &portOptions{DestinationPortRange: &portRange{Min: 23, Max: 443}},
			},
			want: false,
		},
		{
			name: "port 80 only",
			rule: ingressRule{
				Protocol:   "6",
				TCPOptions: &portOptions{DestinationPortRange: &portRange{Min: 80, Max: 80}},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSSHCovered(tt.rule)
			if got != tt.want {
				t.Errorf("isSSHCovered() = %v; want %v", got, tt.want)
			}
		})
	}
}

// ── scanError — pure function ───────────────────────────────────────────────

func TestScanError(t *testing.T) {
	f := scanError("example.com", "Object Storage scan failed: connection refused")
	if f.CheckID != finding.CheckCloudOCIScanError {
		t.Errorf("CheckID = %q; want %q", f.CheckID, finding.CheckCloudOCIScanError)
	}
	if f.Severity != finding.SeverityInfo {
		t.Errorf("Severity = %v; want SeverityInfo", f.Severity)
	}
	if f.Asset != "example.com" {
		t.Errorf("Asset = %q; want %q", f.Asset, "example.com")
	}
	if f.Scanner != "cloud/oci" {
		t.Errorf("Scanner = %q; want %q", f.Scanner, "cloud/oci")
	}
	if !strings.Contains(f.Description, "connection refused") {
		t.Errorf("Description should contain error detail, got: %s", f.Description)
	}
}

// ── publicAccessAction — pure function ──────────────────────────────────────

func TestPublicAccessAction(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"ObjectRead", "list and read objects from"},
		{"ObjectReadWithoutList", "read objects from (without listing)"},
		{"UnknownType", "access"},
		{"", "access"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := publicAccessAction(tt.input)
			if got != tt.want {
				t.Errorf("publicAccessAction(%q) = %q; want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ── truncate — pure function ────────────────────────────────────────────────

func TestTruncate(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		maxLen int
		want   string
	}{
		{"short string unchanged", "hello", 10, "hello"},
		{"exact length unchanged", "hello", 5, "hello"},
		{"truncated with ellipsis", "hello world", 5, "hello..."},
		{"empty string", "", 10, ""},
		{"zero maxLen", "hello", 0, "..."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncate(tt.input, tt.maxLen)
			if got != tt.want {
				t.Errorf("truncate(%q, %d) = %q; want %q", tt.input, tt.maxLen, got, tt.want)
			}
		})
	}
}

// ── host helpers — pure functions ───────────────────────────────────────────

func TestObjectStorageHost(t *testing.T) {
	got := objectStorageHost("us-ashburn-1")
	want := "objectstorage.us-ashburn-1.oraclecloud.com"
	if got != want {
		t.Errorf("objectStorageHost() = %q; want %q", got, want)
	}
}

func TestCoreHost(t *testing.T) {
	got := coreHost("eu-frankfurt-1")
	want := "iaas.eu-frankfurt-1.oraclecloud.com"
	if got != want {
		t.Errorf("coreHost() = %q; want %q", got, want)
	}
}

func TestIdentityHost(t *testing.T) {
	got := identityHost("ap-tokyo-1")
	want := "identity.ap-tokyo-1.oraclecloud.com"
	if got != want {
		t.Errorf("identityHost() = %q; want %q", got, want)
	}
}

func TestKmsManagementHost(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "full HTTPS URL",
			input: "https://abc123-management.kms.us-ashburn-1.oraclecloud.com",
			want:  "abc123-management.kms.us-ashburn-1.oraclecloud.com",
		},
		{
			name:  "URL with path",
			input: "https://abc123-management.kms.us-ashburn-1.oraclecloud.com/some/path",
			want:  "abc123-management.kms.us-ashburn-1.oraclecloud.com",
		},
		{
			name:  "bare host",
			input: "abc123-management.kms.us-ashburn-1.oraclecloud.com",
			want:  "abc123-management.kms.us-ashburn-1.oraclecloud.com",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := kmsManagementHost(tt.input)
			if got != tt.want {
				t.Errorf("kmsManagementHost(%q) = %q; want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ── Integration: scanObjectStorage with httptest ────────────────────────────

func TestScanObjectStorage_PublicBucketAndNoCMEK(t *testing.T) {
	mux := http.NewServeMux()

	// Namespace endpoint.
	mux.HandleFunc("/n/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/n/" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode("testnamespace")
			return
		}
		// Bucket detail endpoint: /n/{namespace}/b/{name}/
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) == 4 && parts[0] == "n" && parts[2] == "b" {
			bucketName := parts[3]
			var detail bucketDetail
			switch bucketName {
			case "public-bucket":
				detail = bucketDetail{
					Name:             "public-bucket",
					Namespace:        "testnamespace",
					CompartmentID:    "ocid1.compartment.oc1..test",
					PublicAccessType: "ObjectRead",
					KmsKeyID:         "",
				}
			case "secure-bucket":
				detail = bucketDetail{
					Name:             "secure-bucket",
					Namespace:        "testnamespace",
					CompartmentID:    "ocid1.compartment.oc1..test",
					PublicAccessType: "NoPublicAccess",
					KmsKeyID:         "ocid1.key.oc1..aaa",
				}
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(detail)
			return
		}
		// Bucket list endpoint: /n/{namespace}/b/?compartmentId=...
		if len(parts) == 3 && parts[0] == "n" && parts[2] == "b" {
			buckets := []bucketSummary{
				{Name: "public-bucket", Namespace: "testnamespace", CompartmentID: "ocid1.compartment.oc1..test"},
				{Name: "secure-bucket", Namespace: "testnamespace", CompartmentID: "ocid1.compartment.oc1..test"},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(buckets)
			return
		}
		http.NotFound(w, r)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	s, cfg := testScanner(ts)
	findings, err := scanObjectStorage(context.Background(), s, cfg, "example.com")
	if err != nil {
		t.Fatalf("scanObjectStorage error: %v", err)
	}

	// public-bucket should produce: BucketPublic + BucketNoEncryption.
	assertHasCheckID(t, findings, finding.CheckCloudOCIBucketPublic)
	assertHasCheckID(t, findings, finding.CheckCloudOCIBucketNoEncryption)

	// secure-bucket should produce no findings.
	// Total: 2 findings from public-bucket only.
	if countCheckID(findings, finding.CheckCloudOCIBucketPublic) != 1 {
		t.Errorf("expected exactly 1 BucketPublic finding, got %d", countCheckID(findings, finding.CheckCloudOCIBucketPublic))
	}
	if countCheckID(findings, finding.CheckCloudOCIBucketNoEncryption) != 1 {
		t.Errorf("expected exactly 1 BucketNoEncryption finding, got %d", countCheckID(findings, finding.CheckCloudOCIBucketNoEncryption))
	}
	if len(findings) != 2 {
		t.Errorf("expected 2 total findings, got %d", len(findings))
	}
}

func TestScanObjectStorage_AllSecure_NoFindings(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/n/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/n/" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode("testns")
			return
		}
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) == 4 && parts[0] == "n" && parts[2] == "b" {
			detail := bucketDetail{
				Name:             "good-bucket",
				Namespace:        "testns",
				CompartmentID:    "ocid1.compartment.oc1..test",
				PublicAccessType: "NoPublicAccess",
				KmsKeyID:         "ocid1.key.oc1..aaa",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(detail)
			return
		}
		if len(parts) == 3 && parts[0] == "n" && parts[2] == "b" {
			buckets := []bucketSummary{
				{Name: "good-bucket", Namespace: "testns", CompartmentID: "ocid1.compartment.oc1..test"},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(buckets)
			return
		}
		http.NotFound(w, r)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	s, cfg := testScanner(ts)
	findings, err := scanObjectStorage(context.Background(), s, cfg, "example.com")
	if err != nil {
		t.Fatalf("scanObjectStorage error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for all-secure buckets, got %d", len(findings))
		for _, f := range findings {
			t.Logf("  CheckID=%s Title=%s", f.CheckID, f.Title)
		}
	}
}

func TestScanObjectStorage_NamespaceAPIFailure(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/n/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"code":"InternalServerError","message":"service unavailable"}`))
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	s, cfg := testScanner(ts)
	_, err := scanObjectStorage(context.Background(), s, cfg, "example.com")
	if err == nil {
		t.Fatal("expected error when namespace API fails, got nil")
	}
}

// ── Integration: scanNetwork with httptest ──────────────────────────────────

func TestScanNetwork_SecurityListAllOpen(t *testing.T) {
	mux := http.NewServeMux()

	// VCN list.
	mux.HandleFunc("/20160918/vcns", func(w http.ResponseWriter, r *http.Request) {
		vcns := []vcnSummary{
			{ID: "ocid1.vcn.oc1..test", DisplayName: "test-vcn", CompartmentID: "ocid1.compartment.oc1..test"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(vcns)
	})

	// Security lists.
	mux.HandleFunc("/20160918/securityLists", func(w http.ResponseWriter, r *http.Request) {
		sls := []securityList{
			{
				ID:          "ocid1.securitylist.oc1..test",
				DisplayName: "bad-sl",
				VcnID:       "ocid1.vcn.oc1..test",
				IngressRules: []ingressRule{
					{Protocol: "all", Source: "0.0.0.0/0", SourceType: "CIDR_BLOCK"},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(sls)
	})

	// NSGs (empty).
	mux.HandleFunc("/20160918/networkSecurityGroups", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]nsgSummary{})
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	s, cfg := testScanner(ts)
	findings, err := scanNetwork(context.Background(), s, cfg, "example.com")
	if err != nil {
		t.Fatalf("scanNetwork error: %v", err)
	}
	assertHasCheckID(t, findings, finding.CheckCloudOCISecurityListAllOpen)
	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
	}
}

func TestScanNetwork_NSGAllOpen(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/20160918/vcns", func(w http.ResponseWriter, r *http.Request) {
		vcns := []vcnSummary{
			{ID: "ocid1.vcn.oc1..test", DisplayName: "test-vcn", CompartmentID: "ocid1.compartment.oc1..test"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(vcns)
	})

	mux.HandleFunc("/20160918/securityLists", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]securityList{})
	})

	// NSG rules endpoint (more specific path, must be registered first).
	mux.HandleFunc("/20160918/networkSecurityGroups/ocid1.nsg.oc1..test/securityRules", func(w http.ResponseWriter, r *http.Request) {
		rules := []nsgSecurityRule{
			{ID: "rule1", Direction: "INGRESS", Protocol: "all", Source: "0.0.0.0/0", SourceType: "CIDR_BLOCK"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rules)
	})

	// NSG list endpoint.
	mux.HandleFunc("/20160918/networkSecurityGroups", func(w http.ResponseWriter, r *http.Request) {
		nsgs := []nsgSummary{
			{ID: "ocid1.nsg.oc1..test", DisplayName: "bad-nsg", VcnID: "ocid1.vcn.oc1..test"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(nsgs)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	s, cfg := testScanner(ts)
	findings, err := scanNetwork(context.Background(), s, cfg, "example.com")
	if err != nil {
		t.Fatalf("scanNetwork error: %v", err)
	}
	assertHasCheckID(t, findings, finding.CheckCloudOCINSGAllOpen)
}

func TestScanNetwork_AllSecure_NoFindings(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/20160918/vcns", func(w http.ResponseWriter, r *http.Request) {
		vcns := []vcnSummary{
			{ID: "ocid1.vcn.oc1..test", DisplayName: "test-vcn", CompartmentID: "ocid1.compartment.oc1..test"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(vcns)
	})

	mux.HandleFunc("/20160918/securityLists", func(w http.ResponseWriter, r *http.Request) {
		sls := []securityList{
			{
				ID:          "ocid1.securitylist.oc1..test",
				DisplayName: "good-sl",
				VcnID:       "ocid1.vcn.oc1..test",
				IngressRules: []ingressRule{
					{
						Protocol:   "6",
						Source:     "10.0.0.0/8",
						SourceType: "CIDR_BLOCK",
						TCPOptions: &portOptions{
							DestinationPortRange: &portRange{Min: 443, Max: 443},
						},
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(sls)
	})

	mux.HandleFunc("/20160918/networkSecurityGroups", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/securityRules") {
			rules := []nsgSecurityRule{
				{
					ID:         "rule1",
					Direction:  "INGRESS",
					Protocol:   "6",
					Source:     "10.0.0.0/8",
					SourceType: "CIDR_BLOCK",
					TCPOptions: &portOptions{
						DestinationPortRange: &portRange{Min: 443, Max: 443},
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(rules)
			return
		}
		nsgs := []nsgSummary{
			{ID: "ocid1.nsg.oc1..test", DisplayName: "good-nsg", VcnID: "ocid1.vcn.oc1..test"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(nsgs)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	s, cfg := testScanner(ts)
	findings, err := scanNetwork(context.Background(), s, cfg, "example.com")
	if err != nil {
		t.Fatalf("scanNetwork error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for all-secure network, got %d", len(findings))
		for _, f := range findings {
			t.Logf("  CheckID=%s Title=%s", f.CheckID, f.Title)
		}
	}
}

func TestScanNetwork_VCNListAPIFailure(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/20160918/vcns", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"code":"NotAuthorized","message":"not authorized"}`))
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	s, cfg := testScanner(ts)
	_, err := scanNetwork(context.Background(), s, cfg, "example.com")
	if err == nil {
		t.Fatal("expected error when VCN list API fails, got nil")
	}
}

// ── Integration: scanVault with httptest ─────────────────────────────────────

func TestScanVault_KeyNoRotation(t *testing.T) {
	mux := http.NewServeMux()

	// Vault list.
	mux.HandleFunc("/20180608/vaults", func(w http.ResponseWriter, r *http.Request) {
		vaults := []vaultSummary{
			{
				ID:                 "ocid1.vault.oc1..test",
				DisplayName:        "test-vault",
				LifecycleState:     "ACTIVE",
				ManagementEndpoint: "https://abc-management.kms.us-ashburn-1.oraclecloud.com",
				VaultType:          "DEFAULT",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(vaults)
	})

	// Key detail endpoint (more specific, must be registered before the list).
	mux.HandleFunc("/20180608/keys/", func(w http.ResponseWriter, r *http.Request) {
		detail := keyDetail{
			ID:                     "ocid1.key.oc1..test",
			DisplayName:            "no-rotation-key",
			LifecycleState:         "ENABLED",
			Algorithm:              "AES",
			TimeCreated:            time.Now().Add(-30 * 24 * time.Hour).Format(time.RFC3339),
			AutoKeyRotationDetails: nil,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(detail)
	})

	// Key list endpoint.
	mux.HandleFunc("/20180608/keys", func(w http.ResponseWriter, r *http.Request) {
		keys := []keySummary{
			{
				ID:             "ocid1.key.oc1..test",
				DisplayName:    "no-rotation-key",
				LifecycleState: "ENABLED",
				Algorithm:      "AES",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(keys)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	s, cfg := testScanner(ts)
	// The vault scanner uses kmsManagementHost for key operations, which bypasses
	// baseURL since it builds the host from the vault's ManagementEndpoint. For
	// this integration test we verify the vault listing path works without error.
	// Full checkKeyRotation logic is covered by the pure-function tests above.
	findings, err := scanVault(context.Background(), s, cfg, "example.com")
	if err != nil {
		t.Fatalf("scanVault error: %v", err)
	}
	_ = findings
}

func TestScanVault_InactiveVaultsSkipped(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/20180608/vaults", func(w http.ResponseWriter, r *http.Request) {
		vaults := []vaultSummary{
			{
				ID:                 "ocid1.vault.oc1..deleted",
				DisplayName:        "deleted-vault",
				LifecycleState:     "DELETED",
				ManagementEndpoint: "https://abc-management.kms.us-ashburn-1.oraclecloud.com",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(vaults)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	s, cfg := testScanner(ts)
	findings, err := scanVault(context.Background(), s, cfg, "example.com")
	if err != nil {
		t.Fatalf("scanVault error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for inactive vaults, got %d", len(findings))
	}
}

func TestScanVault_APIFailure(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/20180608/vaults", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"code":"InternalServerError"}`))
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	s, cfg := testScanner(ts)
	_, err := scanVault(context.Background(), s, cfg, "example.com")
	if err == nil {
		t.Fatal("expected error when vault API fails, got nil")
	}
}

// ── Multiple NSG rules: only INGRESS from 0.0.0.0/0 flagged ────────────────

func TestNSG_MixedRules_OnlyOpenIngressFlagged(t *testing.T) {
	nsg := nsgSummary{
		ID:          "ocid1.nsg.oc1..test",
		DisplayName: "mixed-nsg",
	}
	rules := []nsgSecurityRule{
		// Egress rule (should be ignored).
		{ID: "rule1", Direction: "EGRESS", Protocol: "all", Source: "0.0.0.0/0", SourceType: "CIDR_BLOCK"},
		// Private ingress (should be ignored).
		{ID: "rule2", Direction: "INGRESS", Protocol: "all", Source: "172.16.0.0/12", SourceType: "CIDR_BLOCK"},
		// Restricted public ingress (should be ignored).
		{
			ID:         "rule3",
			Direction:  "INGRESS",
			Protocol:   "6",
			Source:     "0.0.0.0/0",
			SourceType: "CIDR_BLOCK",
			TCPOptions: &portOptions{
				DestinationPortRange: &portRange{Min: 443, Max: 443},
			},
		},
		// Open public ingress (should be flagged).
		{ID: "rule4", Direction: "INGRESS", Protocol: "all", Source: "0.0.0.0/0", SourceType: "CIDR_BLOCK"},
	}

	findings := checkNSG(nsg, rules, "test-vcn", "us-ashburn-1", "example.com")
	if countCheckID(findings, finding.CheckCloudOCINSGAllOpen) != 1 {
		t.Errorf("expected exactly 1 NSGAllOpen finding, got %d", countCheckID(findings, finding.CheckCloudOCINSGAllOpen))
	}
	if len(findings) != 1 {
		t.Errorf("expected 1 total finding, got %d", len(findings))
		for _, f := range findings {
			t.Logf("  CheckID=%s Title=%s", f.CheckID, f.Title)
		}
	}
}

// ── Security list: SSH and all-open from same list ──────────────────────────

func TestSecurityList_AllOpenSkipsSSH(t *testing.T) {
	// When a rule has protocol "all", checkSecurityList emits AllOpen and
	// continues (skipping further checks for that rule). A separate SSH-only
	// rule should still emit SSHOpen.
	sl := securityList{
		ID:          "ocid1.securitylist.oc1..test",
		DisplayName: "dual-rule-sl",
		IngressRules: []ingressRule{
			{Protocol: "all", Source: "0.0.0.0/0", SourceType: "CIDR_BLOCK"},
			{
				Protocol:   "6",
				Source:     "0.0.0.0/0",
				SourceType: "CIDR_BLOCK",
				TCPOptions: &portOptions{
					DestinationPortRange: &portRange{Min: 22, Max: 22},
				},
			},
		},
	}
	findings := checkSecurityList(sl, "test-vcn", "us-ashburn-1", "example.com")
	assertHasCheckID(t, findings, finding.CheckCloudOCISecurityListAllOpen)
	assertHasCheckID(t, findings, finding.CheckCloudOCISecurityListSSHOpen)
	if len(findings) != 2 {
		t.Errorf("expected 2 findings (AllOpen + SSHOpen), got %d", len(findings))
	}
}
