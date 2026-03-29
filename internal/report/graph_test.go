package report

import (
	"strings"
	"testing"
	"time"

	"github.com/stormbane/beacon/internal/asset"
)

// testGraph returns a small but representative asset graph for testing.
func testGraph() asset.AssetGraph {
	return asset.AssetGraph{
		ScanRunID:   "run-1",
		Domain:      "example.com",
		GeneratedAt: time.Date(2026, 3, 29, 12, 0, 0, 0, time.UTC),
		Assets: []asset.Asset{
			{
				ID:       "domain:example.com",
				Type:     asset.AssetTypeDomain,
				Provider: "web",
				Name:     "example.com",
			},
			{
				ID:       "ip:93.184.216.34",
				Type:     asset.AssetTypeIP,
				Provider: "network",
				Name:     "93.184.216.34",
			},
			{
				ID:       "domain:api.example.com",
				Type:     asset.AssetTypeSubdomain,
				Provider: "web",
				Name:     "api.example.com",
			},
		},
		Relationships: []asset.Relationship{
			{
				FromID:     "domain:example.com",
				ToID:       "ip:93.184.216.34",
				Type:       asset.RelPointsTo,
				Confidence: 1.0,
			},
			{
				FromID:     "domain:api.example.com",
				ToID:       "ip:93.184.216.34",
				Type:       asset.RelPointsTo,
				Confidence: 0.85,
			},
		},
		Findings: []asset.FindingRef{
			{
				FindingID: "cors-0",
				AssetID:   "domain:example.com",
				CheckID:   "cors.wildcard_origin",
				Severity:  "high",
				Title:     "CORS allows wildcard origin",
			},
			{
				FindingID: "tls-0",
				AssetID:   "domain:example.com",
				CheckID:   "tls.weak_cipher",
				Severity:  "medium",
				Title:     "Weak TLS cipher suite",
			},
		},
	}
}

func TestRenderGraphDOT_ValidDigraph(t *testing.T) {
	out := RenderGraphDOT(testGraph())

	if !strings.HasPrefix(out, "digraph beacon {") {
		t.Error("expected output to start with 'digraph beacon {'")
	}
	if !strings.HasSuffix(strings.TrimSpace(out), "}") {
		t.Error("expected output to end with '}'")
	}
}

func TestRenderGraphDOT_ContainsDomainLabel(t *testing.T) {
	out := RenderGraphDOT(testGraph())

	if !strings.Contains(out, "example.com") {
		t.Error("expected graph to contain the domain 'example.com'")
	}
}

func TestRenderGraphDOT_ContainsAllNodes(t *testing.T) {
	out := RenderGraphDOT(testGraph())

	// Each asset should produce a node line with its DOT-escaped ID.
	for _, id := range []string{"n_domain_example_com", "n_ip_93_184_216_34", "n_domain_api_example_com"} {
		if !strings.Contains(out, id) {
			t.Errorf("expected node ID %q in DOT output", id)
		}
	}
}

func TestRenderGraphDOT_ContainsEdges(t *testing.T) {
	out := RenderGraphDOT(testGraph())

	// High-confidence edge should be present.
	if !strings.Contains(out, "->") {
		t.Error("expected at least one edge ('->') in DOT output")
	}
}

func TestRenderGraphDOT_LowConfidenceEdgeIsDashed(t *testing.T) {
	out := RenderGraphDOT(testGraph())

	// The 0.85 confidence edge should have style=dashed.
	if !strings.Contains(out, "dashed") {
		t.Error("expected low-confidence edge to be dashed")
	}
}

func TestRenderGraphDOT_FindingAnnotation(t *testing.T) {
	out := RenderGraphDOT(testGraph())

	// Node with findings should show the finding count.
	if !strings.Contains(out, "2 findings") {
		t.Error("expected '2 findings' annotation on the domain node")
	}
}

func TestRenderGraphDOT_SeverityBorderColor(t *testing.T) {
	out := RenderGraphDOT(testGraph())

	// The domain node has a high-severity finding, so it should have the
	// high-severity border color.
	if !strings.Contains(out, "#ff8844") {
		t.Error("expected high-severity border color #ff8844")
	}
}

func TestRenderGraphDOT_EmptyGraph(t *testing.T) {
	g := asset.AssetGraph{
		ScanRunID: "run-empty",
		Domain:    "empty.example.com",
	}
	out := RenderGraphDOT(g)

	if !strings.HasPrefix(out, "digraph beacon {") {
		t.Error("empty graph should still produce valid digraph header")
	}
	if !strings.Contains(out, "empty.example.com") {
		t.Error("expected domain in graph title even with no assets")
	}
}

func TestRenderGraphDOT_NodeShapes(t *testing.T) {
	g := asset.AssetGraph{
		ScanRunID: "run-shapes",
		Domain:    "shapes.example.com",
		Assets: []asset.Asset{
			{ID: "domain:shapes.example.com", Type: asset.AssetTypeDomain, Name: "shapes.example.com"},
			{ID: "ip:1.2.3.4", Type: asset.AssetTypeIP, Name: "1.2.3.4"},
			{ID: "gcp:bucket:test", Type: asset.AssetTypeGCPBucket, Name: "test-bucket"},
			{ID: "gcp:cluster:prod", Type: asset.AssetTypeGCPCluster, Name: "prod-cluster"},
			{ID: "gcp:sa:deploy@proj.iam", Type: asset.AssetTypeGCPServiceAccount, Name: "deploy@proj.iam"},
			{ID: "github:repo:org/app", Type: asset.AssetTypeGitHubRepo, Name: "org/app"},
		},
	}
	out := RenderGraphDOT(g)

	// Domains should be boxes, IPs ellipses, buckets cylinders, etc.
	shapes := map[string]string{
		"n_domain_shapes_example_com": "box",
		"n_ip_1_2_3_4":               "ellipse",
		"n_gcp_bucket_test":          "cylinder",
		"n_gcp_cluster_prod":         "hexagon",
		"n_gcp_sa_deploy_proj_iam":   "diamond",
		"n_github_repo_org_app":      "note",
	}
	for nodeID, expectedShape := range shapes {
		// Find the line containing this node ID and check its shape.
		found := false
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, nodeID) && strings.Contains(line, "shape="+expectedShape) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected node %s to have shape=%s", nodeID, expectedShape)
		}
	}
}

func TestRenderGraphDOT_DeterministicOutput(t *testing.T) {
	g := testGraph()
	out1 := RenderGraphDOT(g)
	out2 := RenderGraphDOT(g)

	if out1 != out2 {
		t.Error("expected deterministic output from RenderGraphDOT across calls")
	}
}

func TestRenderGraphDOT_CloudProviderColors(t *testing.T) {
	g := asset.AssetGraph{
		ScanRunID: "run-colors",
		Domain:    "cloud.example.com",
		Assets: []asset.Asset{
			{ID: "gcp:inst:web-1", Type: asset.AssetTypeGCPInstance, Name: "web-1"},
			{ID: "aws:ec2:i-abc", Type: asset.AssetTypeAWSEC2, Name: "i-abc"},
			{ID: "azure:vm:web", Type: asset.AssetTypeAzureVM, Name: "web"},
		},
	}
	out := RenderGraphDOT(g)

	// GCP nodes should use green-ish fill, AWS orange-ish, Azure blue-ish.
	if !strings.Contains(out, "#2d4a22") {
		t.Error("expected GCP fill color #2d4a22")
	}
	if !strings.Contains(out, "#4a3522") {
		t.Error("expected AWS fill color #4a3522")
	}
	if !strings.Contains(out, "#22354a") {
		t.Error("expected Azure fill color #22354a")
	}
}

func TestRenderGraphDOT_SpecialCharactersInDomain(t *testing.T) {
	g := asset.AssetGraph{
		ScanRunID: "run-special",
		Domain:    `test<script>alert("xss")</script>.example.com`,
		Assets:    []asset.Asset{},
	}
	out := RenderGraphDOT(g)

	// The domain label should have angle brackets escaped.
	if strings.Contains(out, "<script>") {
		t.Error("angle brackets in domain name should be escaped in DOT output")
	}
}
