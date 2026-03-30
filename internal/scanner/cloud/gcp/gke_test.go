package gcp

import (
	"testing"

	containerapi "google.golang.org/api/container/v1"

	"github.com/stormbane/beacon/internal/finding"
)

// ── checkCluster ─────────────────────────────────────────────────────────────

func TestCheckCluster_FullyInsecure(t *testing.T) {
	// Cluster with every issue: public endpoint, no authorized networks,
	// no workload identity, no binary auth.
	cluster := &containerapi.Cluster{
		Name:     "insecure-cluster",
		Location: "us-central1",
		Endpoint: "34.123.45.67",
	}

	findings := checkCluster(cluster, "my-project", "example.com")

	expected := []finding.CheckID{
		finding.CheckCloudGCPGKEPublicEndpoint,
		finding.CheckCloudGCPGKENoWorkloadIdentity,
		finding.CheckCloudGCPGKENoMasterAuthNetworks,
		finding.CheckCloudGCPGKENoBinaryAuth,
	}

	for _, id := range expected {
		if !hasCheckID(findings, id) {
			t.Errorf("expected finding %s for fully insecure cluster", id)
		}
	}
}

func TestCheckCluster_FullySecure(t *testing.T) {
	cluster := &containerapi.Cluster{
		Name:     "secure-cluster",
		Location: "us-central1",
		Endpoint: "34.123.45.67",
		PrivateClusterConfig: &containerapi.PrivateClusterConfig{
			EnablePrivateEndpoint: true,
		},
		MasterAuthorizedNetworksConfig: &containerapi.MasterAuthorizedNetworksConfig{
			Enabled: true,
			CidrBlocks: []*containerapi.CidrBlock{
				{CidrBlock: "10.0.0.0/8"},
			},
		},
		WorkloadIdentityConfig: &containerapi.WorkloadIdentityConfig{
			WorkloadPool: "my-project.svc.id.goog",
		},
		BinaryAuthorization: &containerapi.BinaryAuthorization{
			Enabled: true,
		},
	}

	findings := checkCluster(cluster, "my-project", "example.com")

	if len(findings) != 0 {
		for _, f := range findings {
			t.Errorf("unexpected finding: %s — %s", f.CheckID, f.Title)
		}
	}
}

// ── Public endpoint checks ───────────────────────────────────────────────────

func TestCheckCluster_PublicEndpoint_NoAuthorizedNetworks(t *testing.T) {
	cluster := &containerapi.Cluster{
		Name:     "public-cluster",
		Location: "us-east1",
		Endpoint: "35.200.0.1",
		// No PrivateClusterConfig → public endpoint.
		// No MasterAuthorizedNetworksConfig → unrestricted.
		WorkloadIdentityConfig: &containerapi.WorkloadIdentityConfig{
			WorkloadPool: "my-project.svc.id.goog",
		},
		BinaryAuthorization: &containerapi.BinaryAuthorization{
			Enabled: true,
		},
	}

	findings := checkCluster(cluster, "my-project", "example.com")

	if !hasCheckID(findings, finding.CheckCloudGCPGKEPublicEndpoint) {
		t.Error("expected public endpoint finding when no authorized networks configured")
	}
}

func TestCheckCluster_PublicEndpoint_WithAuthorizedNetworks_NoFinding(t *testing.T) {
	cluster := &containerapi.Cluster{
		Name:     "restricted-cluster",
		Location: "us-east1",
		Endpoint: "35.200.0.1",
		MasterAuthorizedNetworksConfig: &containerapi.MasterAuthorizedNetworksConfig{
			Enabled: true,
			CidrBlocks: []*containerapi.CidrBlock{
				{CidrBlock: "10.0.0.0/8"},
			},
		},
		WorkloadIdentityConfig: &containerapi.WorkloadIdentityConfig{
			WorkloadPool: "my-project.svc.id.goog",
		},
		BinaryAuthorization: &containerapi.BinaryAuthorization{
			Enabled: true,
		},
	}

	findings := checkCluster(cluster, "my-project", "example.com")

	if hasCheckID(findings, finding.CheckCloudGCPGKEPublicEndpoint) {
		t.Error("should not flag public endpoint when authorized networks are configured")
	}
}

func TestCheckCluster_PublicEndpoint_AuthorizedNetworksEnabledButEmpty(t *testing.T) {
	cluster := &containerapi.Cluster{
		Name:     "empty-auth-cluster",
		Location: "us-east1",
		Endpoint: "35.200.0.1",
		MasterAuthorizedNetworksConfig: &containerapi.MasterAuthorizedNetworksConfig{
			Enabled:    true,
			CidrBlocks: []*containerapi.CidrBlock{},
		},
		WorkloadIdentityConfig: &containerapi.WorkloadIdentityConfig{
			WorkloadPool: "my-project.svc.id.goog",
		},
		BinaryAuthorization: &containerapi.BinaryAuthorization{
			Enabled: true,
		},
	}

	findings := checkCluster(cluster, "my-project", "example.com")

	if !hasCheckID(findings, finding.CheckCloudGCPGKEPublicEndpoint) {
		t.Error("expected public endpoint finding when authorized networks enabled but CIDR list is empty")
	}
}

func TestCheckCluster_PrivateEndpoint_NoPublicEndpointFinding(t *testing.T) {
	cluster := &containerapi.Cluster{
		Name:     "private-cluster",
		Location: "us-central1",
		PrivateClusterConfig: &containerapi.PrivateClusterConfig{
			EnablePrivateEndpoint: true,
		},
		// Even without master authorized networks, private endpoint is safe.
		WorkloadIdentityConfig: &containerapi.WorkloadIdentityConfig{
			WorkloadPool: "my-project.svc.id.goog",
		},
		BinaryAuthorization: &containerapi.BinaryAuthorization{
			Enabled: true,
		},
	}

	findings := checkCluster(cluster, "my-project", "example.com")

	if hasCheckID(findings, finding.CheckCloudGCPGKEPublicEndpoint) {
		t.Error("should not flag public endpoint for private cluster")
	}
}

// ── Workload Identity checks ─────────────────────────────────────────────────

func TestCheckCluster_NoWorkloadIdentity_NilConfig(t *testing.T) {
	cluster := &containerapi.Cluster{
		Name:     "no-wi-cluster",
		Location: "us-central1",
		PrivateClusterConfig: &containerapi.PrivateClusterConfig{
			EnablePrivateEndpoint: true,
		},
		MasterAuthorizedNetworksConfig: &containerapi.MasterAuthorizedNetworksConfig{
			Enabled: true,
			CidrBlocks: []*containerapi.CidrBlock{
				{CidrBlock: "10.0.0.0/8"},
			},
		},
		BinaryAuthorization: &containerapi.BinaryAuthorization{
			Enabled: true,
		},
		// WorkloadIdentityConfig is nil.
	}

	findings := checkCluster(cluster, "my-project", "example.com")

	if !hasCheckID(findings, finding.CheckCloudGCPGKENoWorkloadIdentity) {
		t.Error("expected workload identity finding when config is nil")
	}
}

func TestCheckCluster_NoWorkloadIdentity_EmptyPool(t *testing.T) {
	cluster := &containerapi.Cluster{
		Name:     "empty-wi-cluster",
		Location: "us-central1",
		PrivateClusterConfig: &containerapi.PrivateClusterConfig{
			EnablePrivateEndpoint: true,
		},
		MasterAuthorizedNetworksConfig: &containerapi.MasterAuthorizedNetworksConfig{
			Enabled: true,
			CidrBlocks: []*containerapi.CidrBlock{
				{CidrBlock: "10.0.0.0/8"},
			},
		},
		BinaryAuthorization: &containerapi.BinaryAuthorization{
			Enabled: true,
		},
		WorkloadIdentityConfig: &containerapi.WorkloadIdentityConfig{
			WorkloadPool: "", // Empty pool → not enabled.
		},
	}

	findings := checkCluster(cluster, "my-project", "example.com")

	if !hasCheckID(findings, finding.CheckCloudGCPGKENoWorkloadIdentity) {
		t.Error("expected workload identity finding when workload pool is empty")
	}
}

func TestCheckCluster_WorkloadIdentityEnabled_NoFinding(t *testing.T) {
	cluster := &containerapi.Cluster{
		Name:     "wi-cluster",
		Location: "us-central1",
		PrivateClusterConfig: &containerapi.PrivateClusterConfig{
			EnablePrivateEndpoint: true,
		},
		MasterAuthorizedNetworksConfig: &containerapi.MasterAuthorizedNetworksConfig{
			Enabled: true,
			CidrBlocks: []*containerapi.CidrBlock{
				{CidrBlock: "10.0.0.0/8"},
			},
		},
		BinaryAuthorization: &containerapi.BinaryAuthorization{
			Enabled: true,
		},
		WorkloadIdentityConfig: &containerapi.WorkloadIdentityConfig{
			WorkloadPool: "my-project.svc.id.goog",
		},
	}

	findings := checkCluster(cluster, "my-project", "example.com")

	if hasCheckID(findings, finding.CheckCloudGCPGKENoWorkloadIdentity) {
		t.Error("should not flag workload identity when enabled")
	}
}

// ── Master Authorized Networks checks ────────────────────────────────────────

func TestCheckCluster_NoMasterAuthNetworks_NilConfig(t *testing.T) {
	cluster := &containerapi.Cluster{
		Name:     "no-auth-cluster",
		Location: "us-central1",
		PrivateClusterConfig: &containerapi.PrivateClusterConfig{
			EnablePrivateEndpoint: true,
		},
		WorkloadIdentityConfig: &containerapi.WorkloadIdentityConfig{
			WorkloadPool: "my-project.svc.id.goog",
		},
		BinaryAuthorization: &containerapi.BinaryAuthorization{
			Enabled: true,
		},
	}

	findings := checkCluster(cluster, "my-project", "example.com")

	if !hasCheckID(findings, finding.CheckCloudGCPGKENoMasterAuthNetworks) {
		t.Error("expected master auth networks finding when config is nil")
	}
}

func TestCheckCluster_MasterAuthNetworks_Disabled(t *testing.T) {
	cluster := &containerapi.Cluster{
		Name:     "disabled-auth-cluster",
		Location: "us-central1",
		PrivateClusterConfig: &containerapi.PrivateClusterConfig{
			EnablePrivateEndpoint: true,
		},
		MasterAuthorizedNetworksConfig: &containerapi.MasterAuthorizedNetworksConfig{
			Enabled: false,
		},
		WorkloadIdentityConfig: &containerapi.WorkloadIdentityConfig{
			WorkloadPool: "my-project.svc.id.goog",
		},
		BinaryAuthorization: &containerapi.BinaryAuthorization{
			Enabled: true,
		},
	}

	findings := checkCluster(cluster, "my-project", "example.com")

	if !hasCheckID(findings, finding.CheckCloudGCPGKENoMasterAuthNetworks) {
		t.Error("expected master auth networks finding when disabled")
	}
}

// ── Binary Authorization checks ──────────────────────────────────────────────

func TestCheckCluster_NoBinaryAuth_NilConfig(t *testing.T) {
	cluster := &containerapi.Cluster{
		Name:     "no-binauth-cluster",
		Location: "us-central1",
		PrivateClusterConfig: &containerapi.PrivateClusterConfig{
			EnablePrivateEndpoint: true,
		},
		MasterAuthorizedNetworksConfig: &containerapi.MasterAuthorizedNetworksConfig{
			Enabled: true,
			CidrBlocks: []*containerapi.CidrBlock{
				{CidrBlock: "10.0.0.0/8"},
			},
		},
		WorkloadIdentityConfig: &containerapi.WorkloadIdentityConfig{
			WorkloadPool: "my-project.svc.id.goog",
		},
		// BinaryAuthorization is nil.
	}

	findings := checkCluster(cluster, "my-project", "example.com")

	if !hasCheckID(findings, finding.CheckCloudGCPGKENoBinaryAuth) {
		t.Error("expected binary auth finding when config is nil")
	}
}

func TestCheckCluster_BinaryAuth_Disabled(t *testing.T) {
	cluster := &containerapi.Cluster{
		Name:     "binauth-off-cluster",
		Location: "us-central1",
		PrivateClusterConfig: &containerapi.PrivateClusterConfig{
			EnablePrivateEndpoint: true,
		},
		MasterAuthorizedNetworksConfig: &containerapi.MasterAuthorizedNetworksConfig{
			Enabled: true,
			CidrBlocks: []*containerapi.CidrBlock{
				{CidrBlock: "10.0.0.0/8"},
			},
		},
		WorkloadIdentityConfig: &containerapi.WorkloadIdentityConfig{
			WorkloadPool: "my-project.svc.id.goog",
		},
		BinaryAuthorization: &containerapi.BinaryAuthorization{
			Enabled: false,
		},
	}

	findings := checkCluster(cluster, "my-project", "example.com")

	if !hasCheckID(findings, finding.CheckCloudGCPGKENoBinaryAuth) {
		t.Error("expected binary auth finding when disabled")
	}
}

func TestCheckCluster_BinaryAuth_Enabled_NoFinding(t *testing.T) {
	cluster := &containerapi.Cluster{
		Name:     "binauth-on-cluster",
		Location: "us-central1",
		PrivateClusterConfig: &containerapi.PrivateClusterConfig{
			EnablePrivateEndpoint: true,
		},
		MasterAuthorizedNetworksConfig: &containerapi.MasterAuthorizedNetworksConfig{
			Enabled: true,
			CidrBlocks: []*containerapi.CidrBlock{
				{CidrBlock: "10.0.0.0/8"},
			},
		},
		WorkloadIdentityConfig: &containerapi.WorkloadIdentityConfig{
			WorkloadPool: "my-project.svc.id.goog",
		},
		BinaryAuthorization: &containerapi.BinaryAuthorization{
			Enabled: true,
		},
	}

	findings := checkCluster(cluster, "my-project", "example.com")

	if hasCheckID(findings, finding.CheckCloudGCPGKENoBinaryAuth) {
		t.Error("should not flag binary auth when enabled")
	}
}

// ── Finding field checks ─────────────────────────────────────────────────────

func TestCheckCluster_FindingFields(t *testing.T) {
	cluster := &containerapi.Cluster{
		Name:     "field-test-cluster",
		Location: "europe-west1",
		Endpoint: "35.233.0.1",
	}

	findings := checkCluster(cluster, "prod-project", "example.com")

	// Look at the public endpoint finding for field validation.
	for _, f := range findings {
		if f.CheckID == finding.CheckCloudGCPGKEPublicEndpoint {
			if f.Scanner != "cloud/gcp" {
				t.Errorf("scanner = %q; want cloud/gcp", f.Scanner)
			}
			if f.Asset != "example.com" {
				t.Errorf("asset = %q; want example.com", f.Asset)
			}
			if f.Severity != finding.SeverityHigh {
				t.Errorf("severity = %v; want High", f.Severity)
			}
			loc, _ := f.Evidence["location"].(string)
			if loc != "europe-west1" {
				t.Errorf("evidence location = %q; want europe-west1", loc)
			}
			pid, _ := f.Evidence["project_id"].(string)
			if pid != "prod-project" {
				t.Errorf("evidence project_id = %q; want prod-project", pid)
			}
			ep, _ := f.Evidence["endpoint"].(string)
			if ep != "35.233.0.1" {
				t.Errorf("evidence endpoint = %q; want 35.233.0.1", ep)
			}
			snap, _ := f.Evidence["resource_snapshot"].(string)
			if snap == "" {
				t.Error("expected non-empty resource_snapshot in evidence")
			}
			if f.ProofCommand == "" {
				t.Error("ProofCommand should not be empty")
			}
			return
		}
	}
	t.Error("expected CheckCloudGCPGKEPublicEndpoint finding for field validation")
}

func TestCheckCluster_Severities(t *testing.T) {
	cluster := &containerapi.Cluster{
		Name:     "severity-test",
		Location: "us-central1",
	}

	findings := checkCluster(cluster, "my-project", "example.com")

	wantSeverity := map[finding.CheckID]finding.Severity{
		finding.CheckCloudGCPGKEPublicEndpoint:       finding.SeverityHigh,
		finding.CheckCloudGCPGKENoWorkloadIdentity:   finding.SeverityHigh,
		finding.CheckCloudGCPGKENoMasterAuthNetworks: finding.SeverityHigh,
		finding.CheckCloudGCPGKENoBinaryAuth:         finding.SeverityMedium,
	}

	for id, sev := range wantSeverity {
		for _, f := range findings {
			if f.CheckID == id {
				if f.Severity != sev {
					t.Errorf("%s severity = %v; want %v", id, f.Severity, sev)
				}
				break
			}
		}
	}
}
