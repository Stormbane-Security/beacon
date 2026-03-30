package asset

import (
	"sort"
	"testing"
)

func testGraph() *AssetGraph {
	return &AssetGraph{
		ScanRunID: "test-run",
		Domain:    "example.com",
		Assets: []Asset{
			{ID: "domain:example.com", Type: AssetTypeDomain, Provider: "web", Name: "example.com"},
			{ID: "domain:api.example.com", Type: AssetTypeSubdomain, Provider: "web", Name: "api.example.com"},
			{ID: "ip:1.2.3.4", Type: AssetTypeIP, Provider: "network", Name: "1.2.3.4"},
			{ID: "gcp_compute_instance:prod-api", Type: AssetTypeGCPInstance, Provider: "gcp", Name: "prod-api"},
			{ID: "gcp_gke_cluster:prod-cluster", Type: AssetTypeGCPCluster, Provider: "gcp", Name: "prod-cluster"},
			{ID: "gcp_service_account:api-sa", Type: AssetTypeGCPServiceAccount, Provider: "gcp", Name: "api-sa"},
			{ID: "gcp_project:my-project", Type: AssetTypeGCPProject, Provider: "gcp", Name: "my-project"},
			{ID: "github_repo:org/infra", Type: AssetTypeGitHubRepo, Provider: "github", Name: "org/infra"},
		},
		Relationships: []Relationship{
			{FromID: "domain:api.example.com", ToID: "domain:example.com", Type: RelBelongsTo, Confidence: 1.0},
			{FromID: "domain:api.example.com", ToID: "ip:1.2.3.4", Type: RelPointsTo, Confidence: 1.0},
			{FromID: "ip:1.2.3.4", ToID: "gcp_compute_instance:prod-api", Type: RelLikelySameAs, Confidence: 0.98},
			{FromID: "gcp_compute_instance:prod-api", ToID: "gcp_service_account:api-sa", Type: RelUses, Confidence: 1.0},
			{FromID: "gcp_service_account:api-sa", ToID: "gcp_project:my-project", Type: RelAccesses, Confidence: 1.0},
			{FromID: "gcp_gke_cluster:prod-cluster", ToID: "gcp_project:my-project", Type: RelBelongsTo, Confidence: 1.0},
			{FromID: "github_repo:org/infra", ToID: "gcp_compute_instance:prod-api", Type: RelManages, Confidence: 1.0},
			{FromID: "github_repo:org/infra", ToID: "gcp_gke_cluster:prod-cluster", Type: RelDeploysTo, Confidence: 1.0},
		},
		Findings: []FindingRef{
			{FindingID: "f1", AssetID: "domain:api.example.com", CheckID: "web.ssrf", Severity: "critical", Title: "SSRF"},
			{FindingID: "f2", AssetID: "gcp_compute_instance:prod-api", CheckID: "cloud.gcp.gke_legacy_metadata", Severity: "high", Title: "Legacy metadata"},
			{FindingID: "f3", AssetID: "gcp_service_account:api-sa", CheckID: "iam.primitive_role", Severity: "high", Title: "Primitive role"},
			{FindingID: "f4", AssetID: "gcp_gke_cluster:prod-cluster", CheckID: "cloud.gcp.gke_no_network_policy", Severity: "medium", Title: "No network policy"},
		},
	}
}

func TestReachable(t *testing.T) {
	g := testGraph()
	tr := NewTraverser(g)

	// From the domain, following all edges, we should reach IP and beyond.
	reachable := tr.Reachable("domain:api.example.com", nil)
	if len(reachable) == 0 {
		t.Fatal("expected reachable assets from domain:api.example.com")
	}

	reachableSet := map[string]bool{}
	for _, id := range reachable {
		reachableSet[id] = true
	}

	if !reachableSet["ip:1.2.3.4"] {
		t.Error("expected ip:1.2.3.4 to be reachable")
	}
	if !reachableSet["domain:example.com"] {
		t.Error("expected domain:example.com to be reachable via belongs_to")
	}
}

func TestReachableWithTypeFilter(t *testing.T) {
	g := testGraph()
	tr := NewTraverser(g)

	// Only follow points_to edges from the subdomain.
	reachable := tr.Reachable("domain:api.example.com", []RelationshipType{RelPointsTo})
	if len(reachable) != 1 || reachable[0] != "ip:1.2.3.4" {
		t.Errorf("expected only ip:1.2.3.4 via points_to, got %v", reachable)
	}
}

func TestAncestors(t *testing.T) {
	g := testGraph()
	tr := NewTraverser(g)

	// Ancestors of the GCP project should include assets that access it.
	ancestors := tr.Ancestors("gcp_project:my-project", nil)
	ancestorSet := map[string]bool{}
	for _, id := range ancestors {
		ancestorSet[id] = true
	}

	if !ancestorSet["gcp_service_account:api-sa"] {
		t.Error("expected gcp_service_account:api-sa as ancestor via accesses")
	}
	if !ancestorSet["gcp_gke_cluster:prod-cluster"] {
		t.Error("expected gcp_gke_cluster:prod-cluster as ancestor via belongs_to")
	}
}

func TestBlastRadius(t *testing.T) {
	g := testGraph()
	tr := NewTraverser(g)

	// Blast radius from the GitHub repo — manages compute, deploys to cluster.
	result := tr.BlastRadius("github_repo:org/infra")

	if len(result.ReachableIDs) == 0 {
		t.Fatal("expected reachable assets in blast radius")
	}

	reachableSet := map[string]bool{}
	for _, id := range result.ReachableIDs {
		reachableSet[id] = true
	}

	if !reachableSet["gcp_compute_instance:prod-api"] {
		t.Error("expected compute instance reachable")
	}
	if !reachableSet["gcp_gke_cluster:prod-cluster"] {
		t.Error("expected cluster reachable")
	}

	if result.ClustersReachable < 1 {
		t.Error("expected at least 1 cluster reachable")
	}

	if result.RiskScore <= 0 {
		t.Error("expected positive risk score")
	}
}

func TestShortestPath(t *testing.T) {
	g := testGraph()
	tr := NewTraverser(g)

	path := tr.ShortestPath("domain:api.example.com", "gcp_project:my-project")
	if path == nil {
		t.Fatal("expected a path from domain to GCP project")
	}

	if path[0] != "domain:api.example.com" {
		t.Errorf("path should start at source, got %s", path[0])
	}
	if path[len(path)-1] != "gcp_project:my-project" {
		t.Errorf("path should end at destination, got %s", path[len(path)-1])
	}

	// Should be: domain → ip → gcp_instance → service_account → project
	if len(path) != 5 {
		t.Errorf("expected 5-hop path, got %d: %v", len(path), path)
	}
}

func TestShortestPathSameNode(t *testing.T) {
	g := testGraph()
	tr := NewTraverser(g)

	path := tr.ShortestPath("ip:1.2.3.4", "ip:1.2.3.4")
	if len(path) != 1 || path[0] != "ip:1.2.3.4" {
		t.Errorf("expected single-element path for same node, got %v", path)
	}
}

func TestShortestPathNoRoute(t *testing.T) {
	g := testGraph()
	tr := NewTraverser(g)

	// No outgoing edges from the project to the domain (reverse direction).
	path := tr.ShortestPath("gcp_project:my-project", "domain:api.example.com")
	if path != nil {
		t.Errorf("expected no path, got %v", path)
	}
}

func TestNeighbors(t *testing.T) {
	g := testGraph()
	tr := NewTraverser(g)

	neighbors := tr.Neighbors("gcp_compute_instance:prod-api")
	sort.Strings(neighbors)

	// Should have: ip:1.2.3.4 (inbound), gcp_service_account (outbound), github_repo (inbound)
	expected := []string{"gcp_service_account:api-sa", "github_repo:org/infra", "ip:1.2.3.4"}
	if len(neighbors) != len(expected) {
		t.Fatalf("expected %d neighbors, got %d: %v", len(expected), len(neighbors), neighbors)
	}
	for i, id := range expected {
		if neighbors[i] != id {
			t.Errorf("neighbor[%d] = %s, want %s", i, neighbors[i], id)
		}
	}
}

func TestFindingsFor(t *testing.T) {
	g := testGraph()
	tr := NewTraverser(g)

	findings := tr.FindingsFor("domain:api.example.com")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].CheckID != "web.ssrf" {
		t.Errorf("expected web.ssrf finding, got %s", findings[0].CheckID)
	}
}

func TestAssetLookup(t *testing.T) {
	g := testGraph()
	tr := NewTraverser(g)

	a := tr.Asset("ip:1.2.3.4")
	if a == nil {
		t.Fatal("expected to find ip:1.2.3.4")
	}
	if a.Type != AssetTypeIP {
		t.Errorf("expected AssetTypeIP, got %s", a.Type)
	}

	if tr.Asset("nonexistent") != nil {
		t.Error("expected nil for nonexistent asset")
	}
}
