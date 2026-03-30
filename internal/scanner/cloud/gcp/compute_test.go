package gcp

import (
	"testing"

	computeapi "google.golang.org/api/compute/v1"

	"github.com/stormbane/beacon/internal/finding"
)

// ── zoneFromSelfLink ─────────────────────────────────────────────────────────

func TestZoneFromSelfLink(t *testing.T) {
	tests := []struct {
		name string
		link string
		want string
	}{
		{
			name: "full self link",
			link: "https://www.googleapis.com/compute/v1/projects/my-project/zones/us-central1-a",
			want: "us-central1-a",
		},
		{
			name: "zone name only",
			link: "us-east1-b",
			want: "us-east1-b",
		},
		{
			name: "partial path",
			link: "projects/my-project/zones/europe-west1-c",
			want: "europe-west1-c",
		},
		{
			name: "empty string",
			link: "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := zoneFromSelfLink(tt.link)
			if got != tt.want {
				t.Errorf("zoneFromSelfLink(%q) = %q; want %q", tt.link, got, tt.want)
			}
		})
	}
}

// ── metadataValueEquals ──────────────────────────────────────────────────────

func TestMetadataValueEquals(t *testing.T) {
	strPtr := func(s string) *string { return &s }

	tests := []struct {
		name  string
		md    *computeapi.Metadata
		key   string
		value string
		want  bool
	}{
		{
			name: "exact match",
			md: &computeapi.Metadata{
				Items: []*computeapi.MetadataItems{
					{Key: "serial-port-enable", Value: strPtr("true")},
				},
			},
			key:   "serial-port-enable",
			value: "true",
			want:  true,
		},
		{
			name: "case insensitive key",
			md: &computeapi.Metadata{
				Items: []*computeapi.MetadataItems{
					{Key: "Serial-Port-Enable", Value: strPtr("true")},
				},
			},
			key:   "serial-port-enable",
			value: "true",
			want:  true,
		},
		{
			name: "case insensitive value",
			md: &computeapi.Metadata{
				Items: []*computeapi.MetadataItems{
					{Key: "enable-oslogin", Value: strPtr("TRUE")},
				},
			},
			key:   "enable-oslogin",
			value: "true",
			want:  true,
		},
		{
			name: "value mismatch",
			md: &computeapi.Metadata{
				Items: []*computeapi.MetadataItems{
					{Key: "serial-port-enable", Value: strPtr("false")},
				},
			},
			key:   "serial-port-enable",
			value: "true",
			want:  false,
		},
		{
			name: "key not present",
			md: &computeapi.Metadata{
				Items: []*computeapi.MetadataItems{
					{Key: "other-key", Value: strPtr("true")},
				},
			},
			key:   "serial-port-enable",
			value: "true",
			want:  false,
		},
		{
			name:  "nil metadata",
			md:    nil,
			key:   "serial-port-enable",
			value: "true",
			want:  false,
		},
		{
			name: "empty items",
			md: &computeapi.Metadata{
				Items: []*computeapi.MetadataItems{},
			},
			key:   "serial-port-enable",
			value: "true",
			want:  false,
		},
		{
			name: "nil value pointer",
			md: &computeapi.Metadata{
				Items: []*computeapi.MetadataItems{
					{Key: "serial-port-enable", Value: nil},
				},
			},
			key:   "serial-port-enable",
			value: "true",
			want:  false,
		},
		{
			name: "multiple items finds correct one",
			md: &computeapi.Metadata{
				Items: []*computeapi.MetadataItems{
					{Key: "foo", Value: strPtr("bar")},
					{Key: "enable-oslogin", Value: strPtr("true")},
					{Key: "baz", Value: strPtr("qux")},
				},
			},
			key:   "enable-oslogin",
			value: "true",
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := metadataValueEquals(tt.md, tt.key, tt.value)
			if got != tt.want {
				t.Errorf("metadataValueEquals(%v, %q, %q) = %v; want %v", tt.md, tt.key, tt.value, got, tt.want)
			}
		})
	}
}

// ── checkInstance ─────────────────────────────────────────────────────────────

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

func TestCheckInstance_DefaultServiceAccount(t *testing.T) {
	inst := &computeapi.Instance{
		Name:   "test-instance",
		Status: "RUNNING",
		Zone:   "https://www.googleapis.com/compute/v1/projects/my-project/zones/us-central1-a",
		ServiceAccounts: []*computeapi.ServiceAccount{
			{Email: "123456789-compute@developer.gserviceaccount.com"},
		},
	}

	findings := checkInstance(inst, "my-project", "example.com")

	if !hasCheckID(findings, finding.CheckCloudGCPComputeDefaultSA) {
		t.Error("expected CheckCloudGCPComputeDefaultSA finding for default service account")
	}
}

func TestCheckInstance_CustomServiceAccount_NoDefaultSAFinding(t *testing.T) {
	inst := &computeapi.Instance{
		Name:   "test-instance",
		Status: "RUNNING",
		Zone:   "us-central1-a",
		ServiceAccounts: []*computeapi.ServiceAccount{
			{Email: "my-custom-sa@my-project.iam.gserviceaccount.com"},
		},
	}

	findings := checkInstance(inst, "my-project", "example.com")

	if hasCheckID(findings, finding.CheckCloudGCPComputeDefaultSA) {
		t.Error("should not flag custom service account as default SA")
	}
}

func TestCheckInstance_NoServiceAccounts_NoDefaultSAFinding(t *testing.T) {
	inst := &computeapi.Instance{
		Name:   "test-instance",
		Status: "RUNNING",
		Zone:   "us-central1-a",
	}

	findings := checkInstance(inst, "my-project", "example.com")

	if hasCheckID(findings, finding.CheckCloudGCPComputeDefaultSA) {
		t.Error("should not flag instance with no service accounts")
	}
}

func TestCheckInstance_SerialPortEnabled(t *testing.T) {
	strPtr := func(s string) *string { return &s }

	inst := &computeapi.Instance{
		Name:   "serial-instance",
		Status: "RUNNING",
		Zone:   "us-central1-a",
		Metadata: &computeapi.Metadata{
			Items: []*computeapi.MetadataItems{
				{Key: "serial-port-enable", Value: strPtr("true")},
			},
		},
	}

	findings := checkInstance(inst, "my-project", "example.com")

	if !hasCheckID(findings, finding.CheckCloudGCPComputeSerialPort) {
		t.Error("expected CheckCloudGCPComputeSerialPort finding when serial port is enabled")
	}
}

func TestCheckInstance_SerialPortDisabled_NoFinding(t *testing.T) {
	strPtr := func(s string) *string { return &s }

	inst := &computeapi.Instance{
		Name:   "safe-instance",
		Status: "RUNNING",
		Zone:   "us-central1-a",
		Metadata: &computeapi.Metadata{
			Items: []*computeapi.MetadataItems{
				{Key: "serial-port-enable", Value: strPtr("false")},
			},
		},
	}

	findings := checkInstance(inst, "my-project", "example.com")

	if hasCheckID(findings, finding.CheckCloudGCPComputeSerialPort) {
		t.Error("should not flag serial port when it is disabled")
	}
}

func TestCheckInstance_OSLoginEnabled_NoFinding(t *testing.T) {
	strPtr := func(s string) *string { return &s }

	inst := &computeapi.Instance{
		Name:   "oslogin-instance",
		Status: "RUNNING",
		Zone:   "us-central1-a",
		Metadata: &computeapi.Metadata{
			Items: []*computeapi.MetadataItems{
				{Key: "enable-oslogin", Value: strPtr("true")},
			},
		},
	}

	findings := checkInstance(inst, "my-project", "example.com")

	if hasCheckID(findings, finding.CheckCloudGCPComputeNoOSLogin) {
		t.Error("should not flag instance with OS Login enabled")
	}
}

func TestCheckInstance_OSLoginDisabled(t *testing.T) {
	inst := &computeapi.Instance{
		Name:   "no-oslogin-instance",
		Status: "RUNNING",
		Zone:   "us-central1-a",
		// No metadata at all → OS Login is not enabled.
	}

	findings := checkInstance(inst, "my-project", "example.com")

	if !hasCheckID(findings, finding.CheckCloudGCPComputeNoOSLogin) {
		t.Error("expected CheckCloudGCPComputeNoOSLogin finding when OS Login is not enabled")
	}
}

func TestCheckInstance_OSLoginFalse(t *testing.T) {
	strPtr := func(s string) *string { return &s }

	inst := &computeapi.Instance{
		Name:   "oslogin-false-instance",
		Status: "RUNNING",
		Zone:   "us-central1-a",
		Metadata: &computeapi.Metadata{
			Items: []*computeapi.MetadataItems{
				{Key: "enable-oslogin", Value: strPtr("false")},
			},
		},
	}

	findings := checkInstance(inst, "my-project", "example.com")

	if !hasCheckID(findings, finding.CheckCloudGCPComputeNoOSLogin) {
		t.Error("expected CheckCloudGCPComputeNoOSLogin finding when OS Login is explicitly false")
	}
}

func TestCheckInstance_PublicIPs_InEvidence(t *testing.T) {
	inst := &computeapi.Instance{
		Name:   "public-instance",
		Status: "RUNNING",
		Zone:   "us-central1-a",
		NetworkInterfaces: []*computeapi.NetworkInterface{
			{
				AccessConfigs: []*computeapi.AccessConfig{
					{NatIP: "35.192.0.1"},
				},
			},
			{
				AccessConfigs: []*computeapi.AccessConfig{
					{NatIP: "35.192.0.2"},
				},
			},
		},
		ServiceAccounts: []*computeapi.ServiceAccount{
			{Email: "123456789-compute@developer.gserviceaccount.com"},
		},
	}

	findings := checkInstance(inst, "my-project", "example.com")

	// The default SA finding should have public IPs in evidence.
	for _, f := range findings {
		if f.CheckID == finding.CheckCloudGCPComputeDefaultSA {
			ips, ok := f.Evidence["public_ips"].([]string)
			if !ok {
				t.Fatal("expected public_ips in evidence to be []string")
			}
			if len(ips) != 2 {
				t.Errorf("expected 2 public IPs, got %d", len(ips))
			}
			return
		}
	}
	t.Error("expected CheckCloudGCPComputeDefaultSA finding")
}

func TestCheckInstance_NoPublicIPs(t *testing.T) {
	inst := &computeapi.Instance{
		Name:   "private-instance",
		Status: "RUNNING",
		Zone:   "us-central1-a",
		NetworkInterfaces: []*computeapi.NetworkInterface{
			{
				// No access configs → no public IP.
				AccessConfigs: []*computeapi.AccessConfig{},
			},
		},
		ServiceAccounts: []*computeapi.ServiceAccount{
			{Email: "123456789-compute@developer.gserviceaccount.com"},
		},
	}

	findings := checkInstance(inst, "my-project", "example.com")

	for _, f := range findings {
		if f.CheckID == finding.CheckCloudGCPComputeDefaultSA {
			ips, ok := f.Evidence["public_ips"].([]string)
			// nil or empty is fine — just shouldn't have any IPs.
			if ok && len(ips) > 0 {
				t.Errorf("expected no public IPs, got %v", ips)
			}
			return
		}
	}
}

func TestCheckInstance_AllIssues(t *testing.T) {
	// Instance with every possible issue: default SA, serial port, no OS Login.
	strPtr := func(s string) *string { return &s }

	inst := &computeapi.Instance{
		Name:   "bad-instance",
		Status: "RUNNING",
		Zone:   "https://www.googleapis.com/compute/v1/projects/my-project/zones/us-central1-a",
		Metadata: &computeapi.Metadata{
			Items: []*computeapi.MetadataItems{
				{Key: "serial-port-enable", Value: strPtr("true")},
			},
		},
		ServiceAccounts: []*computeapi.ServiceAccount{
			{Email: "123456789-compute@developer.gserviceaccount.com"},
		},
	}

	findings := checkInstance(inst, "my-project", "example.com")

	if !hasCheckID(findings, finding.CheckCloudGCPComputeDefaultSA) {
		t.Error("expected default SA finding")
	}
	if !hasCheckID(findings, finding.CheckCloudGCPComputeSerialPort) {
		t.Error("expected serial port finding")
	}
	if !hasCheckID(findings, finding.CheckCloudGCPComputeNoOSLogin) {
		t.Error("expected no OS Login finding")
	}
}

func TestCheckInstance_FullySecure_OnlyNoOSLoginIfMissing(t *testing.T) {
	strPtr := func(s string) *string { return &s }

	inst := &computeapi.Instance{
		Name:   "secure-instance",
		Status: "RUNNING",
		Zone:   "us-central1-a",
		Metadata: &computeapi.Metadata{
			Items: []*computeapi.MetadataItems{
				{Key: "enable-oslogin", Value: strPtr("true")},
				{Key: "serial-port-enable", Value: strPtr("false")},
			},
		},
		ServiceAccounts: []*computeapi.ServiceAccount{
			{Email: "my-sa@my-project.iam.gserviceaccount.com"},
		},
	}

	findings := checkInstance(inst, "my-project", "example.com")

	if hasCheckID(findings, finding.CheckCloudGCPComputeDefaultSA) {
		t.Error("should not flag custom service account")
	}
	if hasCheckID(findings, finding.CheckCloudGCPComputeSerialPort) {
		t.Error("should not flag disabled serial port")
	}
	if hasCheckID(findings, finding.CheckCloudGCPComputeNoOSLogin) {
		t.Error("should not flag OS Login when enabled")
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for secure instance, got %d", len(findings))
	}
}

func TestCheckInstance_FindingFields(t *testing.T) {
	inst := &computeapi.Instance{
		Name:   "field-test-instance",
		Status: "RUNNING",
		Zone:   "https://www.googleapis.com/compute/v1/projects/my-project/zones/us-east4-c",
		ServiceAccounts: []*computeapi.ServiceAccount{
			{Email: "123456789-compute@developer.gserviceaccount.com"},
		},
	}

	findings := checkInstance(inst, "prod-project", "example.com")

	for _, f := range findings {
		if f.CheckID == finding.CheckCloudGCPComputeDefaultSA {
			if f.Scanner != "cloud/gcp" {
				t.Errorf("scanner = %q; want cloud/gcp", f.Scanner)
			}
			if f.Asset != "example.com" {
				t.Errorf("asset = %q; want example.com", f.Asset)
			}
			if f.Severity != finding.SeverityMedium {
				t.Errorf("severity = %v; want Medium", f.Severity)
			}
			zone, _ := f.Evidence["zone"].(string)
			if zone != "us-east4-c" {
				t.Errorf("evidence zone = %q; want us-east4-c", zone)
			}
			pid, _ := f.Evidence["project_id"].(string)
			if pid != "prod-project" {
				t.Errorf("evidence project_id = %q; want prod-project", pid)
			}
			if f.ProofCommand == "" {
				t.Error("ProofCommand should not be empty")
			}
			return
		}
	}
	t.Error("expected CheckCloudGCPComputeDefaultSA finding")
}
