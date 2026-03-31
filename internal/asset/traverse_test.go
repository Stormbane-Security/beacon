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

// ---------------------------------------------------------------------------
// Edge case: reconstructPath with broken parent chain
// ---------------------------------------------------------------------------

func TestReconstructPathBrokenChain(t *testing.T) {
	// Build a graph A→B→C→D, but we'll call reconstructPath with a parent
	// map that is missing intermediate node C. This simulates a corrupted
	// parent chain that should return nil instead of looping.
	g := &AssetGraph{
		ScanRunID: "test-broken",
		Assets: []Asset{
			{ID: "a", Type: AssetTypeDomain, Provider: "web", Name: "a"},
			{ID: "b", Type: AssetTypeDomain, Provider: "web", Name: "b"},
			{ID: "d", Type: AssetTypeDomain, Provider: "web", Name: "d"},
		},
		Relationships: []Relationship{
			{FromID: "a", ToID: "b", Type: RelPointsTo, Confidence: 1.0},
			// b→c edge missing (c doesn't exist), but we have a→b
		},
	}
	_ = NewTraverser(g) // just ensure construction works

	// Directly test reconstructPath with a parent map that has a gap.
	// d's parent is c, but c has no parent entry (broken chain).
	parent := map[string]string{
		"b": "a",
		"d": "c",
		// "c" has no entry — broken chain
	}
	path := reconstructPath(parent, "a", "d")
	if path != nil {
		t.Errorf("expected nil path for broken parent chain, got %v", path)
	}
}

// ---------------------------------------------------------------------------
// Edge case: reconstructPath with self-loop in parent map
// ---------------------------------------------------------------------------

func TestReconstructPathSelfLoop(t *testing.T) {
	// A parent map where an entry points to itself should return nil
	// rather than looping forever.
	parent := map[string]string{
		"b": "a",
		"c": "c", // self-loop
		"d": "c",
	}
	path := reconstructPath(parent, "a", "d")
	if path != nil {
		t.Errorf("expected nil path for self-loop in parent chain, got %v", path)
	}
}

// ---------------------------------------------------------------------------
// Edge case: Traverser on a nil/empty graph
// ---------------------------------------------------------------------------

func TestTraverserNilGraph(t *testing.T) {
	g := &AssetGraph{
		ScanRunID: "test-empty",
		// Zero assets, zero relationships, zero findings.
	}
	tr := NewTraverser(g)

	// Reachable from a nonexistent node should return empty, not panic.
	reachable := tr.Reachable("nonexistent", nil)
	if len(reachable) != 0 {
		t.Errorf("Reachable on empty graph: expected 0, got %d", len(reachable))
	}

	// Ancestors from a nonexistent node should return empty.
	ancestors := tr.Ancestors("nonexistent", nil)
	if len(ancestors) != 0 {
		t.Errorf("Ancestors on empty graph: expected 0, got %d", len(ancestors))
	}

	// BlastRadius on a nonexistent node should return zero-value result.
	br := tr.BlastRadius("nonexistent")
	if br.RiskScore != 0 {
		t.Errorf("BlastRadius on empty graph: expected risk score 0, got %f", br.RiskScore)
	}
	if len(br.ReachableIDs) != 0 {
		t.Errorf("BlastRadius on empty graph: expected 0 reachable, got %d", len(br.ReachableIDs))
	}

	// ShortestPath on nonexistent nodes should return nil.
	path := tr.ShortestPath("nonexistent-a", "nonexistent-b")
	if path != nil {
		t.Errorf("ShortestPath on empty graph: expected nil, got %v", path)
	}

	// Neighbors on nonexistent node should return empty.
	neighbors := tr.Neighbors("nonexistent")
	if len(neighbors) != 0 {
		t.Errorf("Neighbors on empty graph: expected 0, got %d", len(neighbors))
	}

	// FindingsFor on nonexistent node should return nil/empty.
	findings := tr.FindingsFor("nonexistent")
	if len(findings) != 0 {
		t.Errorf("FindingsFor on empty graph: expected 0, got %d", len(findings))
	}

	// Asset lookup on nonexistent node should return nil.
	a := tr.Asset("nonexistent")
	if a != nil {
		t.Errorf("Asset on empty graph: expected nil, got %+v", a)
	}
}

// ---------------------------------------------------------------------------
// Edge case: BlastRadius on a nonexistent asset in a populated graph
// ---------------------------------------------------------------------------

func TestBlastRadiusEmptyGraph(t *testing.T) {
	g := testGraph()
	tr := NewTraverser(g)

	result := tr.BlastRadius("totally-fake-asset-id")

	if result.OriginID != "totally-fake-asset-id" {
		t.Errorf("OriginID = %q, want %q", result.OriginID, "totally-fake-asset-id")
	}
	if len(result.ReachableIDs) != 0 {
		t.Errorf("expected 0 reachable IDs, got %d", len(result.ReachableIDs))
	}
	if result.RiskScore != 0 {
		t.Errorf("expected risk score 0 for nonexistent asset, got %f", result.RiskScore)
	}
	if result.CloudAccountsReachable != 0 {
		t.Errorf("expected 0 cloud accounts, got %d", result.CloudAccountsReachable)
	}
	if result.ClustersReachable != 0 {
		t.Errorf("expected 0 clusters, got %d", result.ClustersReachable)
	}
	if result.ReposReachable != 0 {
		t.Errorf("expected 0 repos, got %d", result.ReposReachable)
	}
	if result.PackagesReachable != 0 {
		t.Errorf("expected 0 packages, got %d", result.PackagesReachable)
	}
}

// ---------------------------------------------------------------------------
// Edge case: ShortestPath between two disconnected nodes
// ---------------------------------------------------------------------------

func TestShortestPathNoPath(t *testing.T) {
	// Build a graph with two isolated clusters: A→B and C→D (no edges between them).
	g := &AssetGraph{
		ScanRunID: "test-nopath",
		Assets: []Asset{
			{ID: "a", Type: AssetTypeDomain, Provider: "web", Name: "a"},
			{ID: "b", Type: AssetTypeDomain, Provider: "web", Name: "b"},
			{ID: "c", Type: AssetTypeDomain, Provider: "web", Name: "c"},
			{ID: "d", Type: AssetTypeDomain, Provider: "web", Name: "d"},
		},
		Relationships: []Relationship{
			{FromID: "a", ToID: "b", Type: RelPointsTo, Confidence: 1.0},
			{FromID: "c", ToID: "d", Type: RelPointsTo, Confidence: 1.0},
		},
	}
	tr := NewTraverser(g)

	// a can reach b, but not c or d.
	path := tr.ShortestPath("a", "c")
	if path != nil {
		t.Errorf("expected nil path between disconnected nodes, got %v", path)
	}

	path = tr.ShortestPath("a", "d")
	if path != nil {
		t.Errorf("expected nil path between disconnected nodes, got %v", path)
	}

	// Verify path within the same cluster still works.
	path = tr.ShortestPath("a", "b")
	if path == nil || len(path) != 2 {
		t.Errorf("expected [a, b] path, got %v", path)
	}
}

// ---------------------------------------------------------------------------
// Edge case: Reachable with cycles in the graph
// ---------------------------------------------------------------------------

func TestReachableWithCycles(t *testing.T) {
	// Build a cyclic graph: A→B→C→A.
	g := &AssetGraph{
		ScanRunID: "test-cycle",
		Assets: []Asset{
			{ID: "a", Type: AssetTypeDomain, Provider: "web", Name: "a"},
			{ID: "b", Type: AssetTypeDomain, Provider: "web", Name: "b"},
			{ID: "c", Type: AssetTypeDomain, Provider: "web", Name: "c"},
		},
		Relationships: []Relationship{
			{FromID: "a", ToID: "b", Type: RelPointsTo, Confidence: 1.0},
			{FromID: "b", ToID: "c", Type: RelPointsTo, Confidence: 1.0},
			{FromID: "c", ToID: "a", Type: RelPointsTo, Confidence: 1.0},
		},
	}
	tr := NewTraverser(g)

	reachable := tr.Reachable("a", nil)

	// Should contain b and c exactly once each; a is the start node and should
	// not appear in the results (Reachable excludes the start node).
	if len(reachable) != 2 {
		t.Fatalf("expected 2 reachable nodes from a in cycle, got %d: %v", len(reachable), reachable)
	}

	reachableSet := map[string]bool{}
	for _, id := range reachable {
		if reachableSet[id] {
			t.Errorf("node %q appears more than once in reachable set", id)
		}
		reachableSet[id] = true
	}
	if !reachableSet["b"] {
		t.Error("expected b to be reachable from a")
	}
	if !reachableSet["c"] {
		t.Error("expected c to be reachable from a")
	}
	if reachableSet["a"] {
		t.Error("start node a should not appear in reachable results")
	}
}
