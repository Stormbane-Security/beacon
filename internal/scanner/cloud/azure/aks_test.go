package azure

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice"

	"github.com/stormbane/beacon/internal/finding"
)

func networkPolicyPtr(p armcontainerservice.NetworkPolicy) *armcontainerservice.NetworkPolicy {
	return &p
}

func strPtr(s string) *string { return &s }

// -------------------------------------------------------------------------
// evaluateAKSCluster — public API endpoint
// -------------------------------------------------------------------------

func TestAKS_PublicEndpoint_NoIPRestriction(t *testing.T) {
	props := &armcontainerservice.ManagedClusterProperties{
		APIServerAccessProfile: &armcontainerservice.ManagedClusterAPIServerAccessProfile{
			EnablePrivateCluster: boolPtr(false),
			AuthorizedIPRanges:   []*string{},
		},
		EnableRBAC: boolPtr(true),
		NetworkProfile: &armcontainerservice.NetworkProfile{
			NetworkPolicy: networkPolicyPtr(armcontainerservice.NetworkPolicyAzure),
		},
	}
	findings := evaluateAKSCluster("test-aks", props, "sub-123", "example.com")
	assertHasCheckID(t, findings, finding.CheckCloudAzureAKSPublicEndpoint)
}

func TestAKS_PublicEndpoint_NilPrivateCluster(t *testing.T) {
	// When EnablePrivateCluster is nil, the cluster defaults to public.
	props := &armcontainerservice.ManagedClusterProperties{
		APIServerAccessProfile: &armcontainerservice.ManagedClusterAPIServerAccessProfile{
			EnablePrivateCluster: nil,
			AuthorizedIPRanges:   []*string{},
		},
		EnableRBAC: boolPtr(true),
		NetworkProfile: &armcontainerservice.NetworkProfile{
			NetworkPolicy: networkPolicyPtr(armcontainerservice.NetworkPolicyAzure),
		},
	}
	findings := evaluateAKSCluster("test-aks", props, "sub-123", "example.com")
	assertHasCheckID(t, findings, finding.CheckCloudAzureAKSPublicEndpoint)
}

func TestAKS_PrivateCluster_NoFinding(t *testing.T) {
	props := &armcontainerservice.ManagedClusterProperties{
		APIServerAccessProfile: &armcontainerservice.ManagedClusterAPIServerAccessProfile{
			EnablePrivateCluster: boolPtr(true),
			AuthorizedIPRanges:   []*string{},
		},
		EnableRBAC: boolPtr(true),
		NetworkProfile: &armcontainerservice.NetworkProfile{
			NetworkPolicy: networkPolicyPtr(armcontainerservice.NetworkPolicyAzure),
		},
	}
	findings := evaluateAKSCluster("test-aks", props, "sub-123", "example.com")
	assertNotHasCheckID(t, findings, finding.CheckCloudAzureAKSPublicEndpoint)
}

func TestAKS_PublicEndpoint_WithIPRestrictions_NoFinding(t *testing.T) {
	props := &armcontainerservice.ManagedClusterProperties{
		APIServerAccessProfile: &armcontainerservice.ManagedClusterAPIServerAccessProfile{
			EnablePrivateCluster: boolPtr(false),
			AuthorizedIPRanges:   []*string{strPtr("10.0.0.0/8")},
		},
		EnableRBAC: boolPtr(true),
		NetworkProfile: &armcontainerservice.NetworkProfile{
			NetworkPolicy: networkPolicyPtr(armcontainerservice.NetworkPolicyAzure),
		},
	}
	findings := evaluateAKSCluster("test-aks", props, "sub-123", "example.com")
	assertNotHasCheckID(t, findings, finding.CheckCloudAzureAKSPublicEndpoint)
}

func TestAKS_NilAPIServerAccessProfile_NoPublicEndpointFinding(t *testing.T) {
	// When the profile is nil, the code skips the check entirely.
	props := &armcontainerservice.ManagedClusterProperties{
		APIServerAccessProfile: nil,
		EnableRBAC:             boolPtr(true),
		NetworkProfile: &armcontainerservice.NetworkProfile{
			NetworkPolicy: networkPolicyPtr(armcontainerservice.NetworkPolicyAzure),
		},
	}
	findings := evaluateAKSCluster("test-aks", props, "sub-123", "example.com")
	assertNotHasCheckID(t, findings, finding.CheckCloudAzureAKSPublicEndpoint)
}

// -------------------------------------------------------------------------
// evaluateAKSCluster — RBAC
// -------------------------------------------------------------------------

func TestAKS_RBACDisabled(t *testing.T) {
	props := &armcontainerservice.ManagedClusterProperties{
		EnableRBAC: boolPtr(false),
		NetworkProfile: &armcontainerservice.NetworkProfile{
			NetworkPolicy: networkPolicyPtr(armcontainerservice.NetworkPolicyAzure),
		},
	}
	findings := evaluateAKSCluster("test-aks", props, "sub-123", "example.com")
	assertHasCheckID(t, findings, finding.CheckCloudAzureAKSNoRBAC)
}

func TestAKS_RBACNil_EmitsFinding(t *testing.T) {
	// When EnableRBAC is nil, the scanner treats it as disabled.
	props := &armcontainerservice.ManagedClusterProperties{
		EnableRBAC: nil,
		NetworkProfile: &armcontainerservice.NetworkProfile{
			NetworkPolicy: networkPolicyPtr(armcontainerservice.NetworkPolicyAzure),
		},
	}
	findings := evaluateAKSCluster("test-aks", props, "sub-123", "example.com")
	assertHasCheckID(t, findings, finding.CheckCloudAzureAKSNoRBAC)
}

func TestAKS_RBACEnabled_NoFinding(t *testing.T) {
	props := &armcontainerservice.ManagedClusterProperties{
		EnableRBAC: boolPtr(true),
		NetworkProfile: &armcontainerservice.NetworkProfile{
			NetworkPolicy: networkPolicyPtr(armcontainerservice.NetworkPolicyAzure),
		},
	}
	findings := evaluateAKSCluster("test-aks", props, "sub-123", "example.com")
	assertNotHasCheckID(t, findings, finding.CheckCloudAzureAKSNoRBAC)
}

// -------------------------------------------------------------------------
// evaluateAKSCluster — network policy
// -------------------------------------------------------------------------

func TestAKS_NoNetworkPolicy_NilProfile(t *testing.T) {
	props := &armcontainerservice.ManagedClusterProperties{
		EnableRBAC:     boolPtr(true),
		NetworkProfile: nil,
	}
	findings := evaluateAKSCluster("test-aks", props, "sub-123", "example.com")
	assertHasCheckID(t, findings, finding.CheckCloudAzureAKSNoNetPolicy)
}

func TestAKS_NoNetworkPolicy_NilPolicy(t *testing.T) {
	props := &armcontainerservice.ManagedClusterProperties{
		EnableRBAC: boolPtr(true),
		NetworkProfile: &armcontainerservice.NetworkProfile{
			NetworkPolicy: nil,
		},
	}
	findings := evaluateAKSCluster("test-aks", props, "sub-123", "example.com")
	assertHasCheckID(t, findings, finding.CheckCloudAzureAKSNoNetPolicy)
}

func TestAKS_NetworkPolicy_None(t *testing.T) {
	props := &armcontainerservice.ManagedClusterProperties{
		EnableRBAC: boolPtr(true),
		NetworkProfile: &armcontainerservice.NetworkProfile{
			NetworkPolicy: networkPolicyPtr(armcontainerservice.NetworkPolicy("none")),
		},
	}
	findings := evaluateAKSCluster("test-aks", props, "sub-123", "example.com")
	assertHasCheckID(t, findings, finding.CheckCloudAzureAKSNoNetPolicy)
}

func TestAKS_NetworkPolicy_Empty(t *testing.T) {
	props := &armcontainerservice.ManagedClusterProperties{
		EnableRBAC: boolPtr(true),
		NetworkProfile: &armcontainerservice.NetworkProfile{
			NetworkPolicy: networkPolicyPtr(armcontainerservice.NetworkPolicy("")),
		},
	}
	findings := evaluateAKSCluster("test-aks", props, "sub-123", "example.com")
	assertHasCheckID(t, findings, finding.CheckCloudAzureAKSNoNetPolicy)
}

func TestAKS_NetworkPolicyAzure_NoFinding(t *testing.T) {
	props := &armcontainerservice.ManagedClusterProperties{
		EnableRBAC: boolPtr(true),
		NetworkProfile: &armcontainerservice.NetworkProfile{
			NetworkPolicy: networkPolicyPtr(armcontainerservice.NetworkPolicyAzure),
		},
	}
	findings := evaluateAKSCluster("test-aks", props, "sub-123", "example.com")
	assertNotHasCheckID(t, findings, finding.CheckCloudAzureAKSNoNetPolicy)
}

func TestAKS_NetworkPolicyCalico_NoFinding(t *testing.T) {
	props := &armcontainerservice.ManagedClusterProperties{
		EnableRBAC: boolPtr(true),
		NetworkProfile: &armcontainerservice.NetworkProfile{
			NetworkPolicy: networkPolicyPtr(armcontainerservice.NetworkPolicyCalico),
		},
	}
	findings := evaluateAKSCluster("test-aks", props, "sub-123", "example.com")
	assertNotHasCheckID(t, findings, finding.CheckCloudAzureAKSNoNetPolicy)
}

// -------------------------------------------------------------------------
// evaluateAKSCluster — fully secure cluster
// -------------------------------------------------------------------------

func TestAKS_FullySecure_NoFindings(t *testing.T) {
	props := &armcontainerservice.ManagedClusterProperties{
		APIServerAccessProfile: &armcontainerservice.ManagedClusterAPIServerAccessProfile{
			EnablePrivateCluster: boolPtr(true),
		},
		EnableRBAC: boolPtr(true),
		NetworkProfile: &armcontainerservice.NetworkProfile{
			NetworkPolicy: networkPolicyPtr(armcontainerservice.NetworkPolicyAzure),
		},
	}
	findings := evaluateAKSCluster("secure-aks", props, "sub-123", "example.com")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for fully secure AKS cluster, got %d", len(findings))
		for _, f := range findings {
			t.Logf("  CheckID=%s Title=%s", f.CheckID, f.Title)
		}
	}
}

// -------------------------------------------------------------------------
// evaluateAKSCluster — all misconfigured
// -------------------------------------------------------------------------

func TestAKS_AllMisconfigured(t *testing.T) {
	props := &armcontainerservice.ManagedClusterProperties{
		APIServerAccessProfile: &armcontainerservice.ManagedClusterAPIServerAccessProfile{
			EnablePrivateCluster: boolPtr(false),
			AuthorizedIPRanges:   []*string{},
		},
		EnableRBAC:     boolPtr(false),
		NetworkProfile: nil,
	}
	findings := evaluateAKSCluster("bad-aks", props, "sub-123", "example.com")
	assertHasCheckID(t, findings, finding.CheckCloudAzureAKSPublicEndpoint)
	assertHasCheckID(t, findings, finding.CheckCloudAzureAKSNoRBAC)
	assertHasCheckID(t, findings, finding.CheckCloudAzureAKSNoNetPolicy)
	if len(findings) != 3 {
		t.Errorf("expected 3 findings for fully misconfigured cluster, got %d", len(findings))
	}
}

// -------------------------------------------------------------------------
// evaluateAKSCluster — finding metadata
// -------------------------------------------------------------------------

func TestAKS_FindingMetadata(t *testing.T) {
	props := &armcontainerservice.ManagedClusterProperties{
		EnableRBAC:     boolPtr(false),
		NetworkProfile: &armcontainerservice.NetworkProfile{
			NetworkPolicy: networkPolicyPtr(armcontainerservice.NetworkPolicyAzure),
		},
	}
	findings := evaluateAKSCluster("my-cluster", props, "sub-xyz", "target.io")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.CheckID != finding.CheckCloudAzureAKSNoRBAC {
		t.Errorf("CheckID = %q; want %q", f.CheckID, finding.CheckCloudAzureAKSNoRBAC)
	}
	if f.Scanner != "cloud/azure" {
		t.Errorf("Scanner = %q; want %q", f.Scanner, "cloud/azure")
	}
	if f.Asset != "target.io" {
		t.Errorf("Asset = %q; want %q", f.Asset, "target.io")
	}
	if f.Severity != finding.SeverityHigh {
		t.Errorf("Severity = %v; want SeverityHigh", f.Severity)
	}
	if f.ProofCommand == "" {
		t.Error("ProofCommand should not be empty")
	}
	if f.Evidence["cluster_name"] != "my-cluster" {
		t.Errorf("Evidence[cluster_name] = %v; want %q", f.Evidence["cluster_name"], "my-cluster")
	}
	if f.Evidence["subscription_id"] != "sub-xyz" {
		t.Errorf("Evidence[subscription_id] = %v; want %q", f.Evidence["subscription_id"], "sub-xyz")
	}
}

// -------------------------------------------------------------------------
// evaluateAKSCluster — table-driven severity check
// -------------------------------------------------------------------------

func TestAKS_Severities(t *testing.T) {
	tests := []struct {
		name    string
		checkID finding.CheckID
		wantSev finding.Severity
		props   *armcontainerservice.ManagedClusterProperties
	}{
		{
			name:    "public endpoint is high severity",
			checkID: finding.CheckCloudAzureAKSPublicEndpoint,
			wantSev: finding.SeverityHigh,
			props: &armcontainerservice.ManagedClusterProperties{
				APIServerAccessProfile: &armcontainerservice.ManagedClusterAPIServerAccessProfile{
					EnablePrivateCluster: boolPtr(false),
					AuthorizedIPRanges:   []*string{},
				},
				EnableRBAC: boolPtr(true),
				NetworkProfile: &armcontainerservice.NetworkProfile{
					NetworkPolicy: networkPolicyPtr(armcontainerservice.NetworkPolicyAzure),
				},
			},
		},
		{
			name:    "RBAC disabled is high severity",
			checkID: finding.CheckCloudAzureAKSNoRBAC,
			wantSev: finding.SeverityHigh,
			props: &armcontainerservice.ManagedClusterProperties{
				EnableRBAC: boolPtr(false),
				NetworkProfile: &armcontainerservice.NetworkProfile{
					NetworkPolicy: networkPolicyPtr(armcontainerservice.NetworkPolicyAzure),
				},
			},
		},
		{
			name:    "no network policy is medium severity",
			checkID: finding.CheckCloudAzureAKSNoNetPolicy,
			wantSev: finding.SeverityMedium,
			props: &armcontainerservice.ManagedClusterProperties{
				EnableRBAC:     boolPtr(true),
				NetworkProfile: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := evaluateAKSCluster("aks", tt.props, "sub-1", "asset")
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
