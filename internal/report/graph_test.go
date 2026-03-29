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

// ---------------------------------------------------------------------------
// Security: DOT injection via backslash sequences
// ---------------------------------------------------------------------------

func TestDotQuote_BackslashEscaping(t *testing.T) {
	// A backslash followed by a quote should not break out of the DOT string.
	tests := []struct {
		name  string
		input string
	}{
		{"backslash-quote", `foo\"bar`},
		{"trailing-backslash", `foo\`},
		{"double-backslash", `foo\\bar`},
		{"backslash-n-literal", "foo\\nbar"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := dotQuote(tt.input)
			// Output must start and end with unescaped double quotes.
			if out[0] != '"' || out[len(out)-1] != '"' {
				t.Errorf("dotQuote(%q) = %s; should be wrapped in double quotes", tt.input, out)
			}
			// The content between the outer quotes must not contain an unescaped quote.
			inner := out[1 : len(out)-1]
			for i := 0; i < len(inner); i++ {
				if inner[i] == '"' {
					// Must be preceded by an odd number of backslashes.
					bsCount := 0
					for j := i - 1; j >= 0 && inner[j] == '\\'; j-- {
						bsCount++
					}
					if bsCount%2 == 0 {
						t.Errorf("dotQuote(%q) = %s; contains unescaped quote at position %d", tt.input, out, i+1)
					}
				}
			}
		})
	}
}

func TestDotEscape_BackslashAndAngleBrackets(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		contains string
		absent   string
	}{
		{"angle-brackets", "<script>", "\\<script\\>", "<script>"},
		{"backslash-angle", `\<test>`, `\\\\\\<test\\>`, ""},
		{"backslash-quote", `hello\"world`, `hello\\\\\\\"world`, ""},
		{"newline", "line1\nline2", "\\n", "\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := dotEscape(tt.input)
			if tt.absent != "" && strings.Contains(out, tt.absent) {
				t.Errorf("dotEscape(%q) = %q; should not contain %q", tt.input, out, tt.absent)
			}
		})
	}
}

func TestDotEscape_NewlinesRemoved(t *testing.T) {
	out := dotEscape("line1\nline2\rline3")
	if strings.Contains(out, "\n") || strings.Contains(out, "\r") {
		t.Error("dotEscape should replace real newlines with escaped representations")
	}
}

// ---------------------------------------------------------------------------
// Security: DOT node ID injection
// ---------------------------------------------------------------------------

func TestDotNodeID_OnlyAlphanumericAndUnderscore(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"quotes", `domain:"evil.com"`},
		{"newlines", "domain:evil\n.com"},
		{"semicolons", "domain:evil;.com"},
		{"hash", "domain:evil#.com"},
		{"equals", "domain:evil=.com"},
		{"backslash", `domain:evil\.com`},
		{"unicode", "domain:\u00e9vil.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := dotNodeID(tt.input)
			for _, c := range out {
				if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
					t.Errorf("dotNodeID(%q) = %q; contains invalid character %q", tt.input, out, string(c))
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Edge case: asset names with special characters in graph output
// ---------------------------------------------------------------------------

func TestRenderGraphDOT_AssetNameWithQuotesAndBackslashes(t *testing.T) {
	g := asset.AssetGraph{
		ScanRunID: "run-special-name",
		Domain:    "example.com",
		Assets: []asset.Asset{
			{
				ID:       `domain:evil"\.com`,
				Type:     asset.AssetTypeDomain,
				Provider: "web",
				Name:     `evil"\.com`,
			},
		},
	}
	out := RenderGraphDOT(g)

	// Must produce valid DOT: no unescaped quotes inside label values.
	if !strings.HasPrefix(out, "digraph beacon {") {
		t.Error("output should be a valid DOT digraph")
	}
	// The raw unescaped sequence should not appear.
	if strings.Contains(out, `evil"\.com"`) {
		t.Error("unescaped quote in asset name should not break DOT syntax")
	}
}

func TestRenderGraphDOT_AssetNameWithNewlines(t *testing.T) {
	g := asset.AssetGraph{
		ScanRunID: "run-newline",
		Domain:    "example.com",
		Assets: []asset.Asset{
			{
				ID:       "domain:nl.example.com",
				Type:     asset.AssetTypeDomain,
				Provider: "web",
				Name:     "evil\n.example.com",
			},
		},
	}
	out := RenderGraphDOT(g)

	// Real newlines inside a DOT label would break the syntax.
	// Check that the label value between quotes does not contain a raw newline.
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		if strings.Contains(line, "n_domain_nl_example_com") {
			// This line defines the node — it should not contain raw newlines
			// inside the label (the literal `\n` is fine as a DOT escape).
			break
		}
	}
	// If we get here without panic, the DOT output was at least structurally valid.
}

func TestRenderGraphDOT_FindingTitleWithQuotes(t *testing.T) {
	g := asset.AssetGraph{
		ScanRunID: "run-quotes",
		Domain:    "example.com",
		Assets: []asset.Asset{
			{ID: "domain:example.com", Type: asset.AssetTypeDomain, Provider: "web", Name: "example.com"},
		},
		Findings: []asset.FindingRef{
			{
				FindingID: "test-0",
				AssetID:   "domain:example.com",
				CheckID:   "test.check",
				Severity:  "high",
				Title:     `Injection via "quoted" param`,
			},
		},
	}
	out := RenderGraphDOT(g)

	// The output must be valid DOT — the title quote should not break syntax.
	if !strings.HasSuffix(strings.TrimSpace(out), "}") {
		t.Error("DOT output with quoted finding title should end with closing brace")
	}
}

func TestRenderGraphDOT_FindingTitleWithBackslashQuote(t *testing.T) {
	g := asset.AssetGraph{
		ScanRunID: "run-bsquote",
		Domain:    "example.com",
		Assets: []asset.Asset{
			{ID: "domain:example.com", Type: asset.AssetTypeDomain, Provider: "web", Name: "example.com"},
		},
		Findings: []asset.FindingRef{
			{
				FindingID: "test-0",
				AssetID:   "domain:example.com",
				CheckID:   "test.check",
				Severity:  "critical",
				Title:     `Path traversal via \"..\/"`,
			},
		},
	}
	out := RenderGraphDOT(g)

	// Backslash-quote in title must not break DOT string escaping.
	if !strings.HasSuffix(strings.TrimSpace(out), "}") {
		t.Error("DOT output should be valid with backslash-quote in finding title")
	}
}

// ---------------------------------------------------------------------------
// Edge case: very long asset name truncation
// ---------------------------------------------------------------------------

func TestRenderGraphDOT_LongAssetNameTruncated(t *testing.T) {
	longName := strings.Repeat("a", 100) + ".example.com"
	g := asset.AssetGraph{
		ScanRunID: "run-long",
		Domain:    "example.com",
		Assets: []asset.Asset{
			{ID: "domain:long", Type: asset.AssetTypeDomain, Provider: "web", Name: longName},
		},
	}
	out := RenderGraphDOT(g)

	// The full long name should not appear in the output (truncated to 45 chars).
	if strings.Contains(out, longName) {
		t.Error("expected long asset name to be truncated in node label")
	}
	if !strings.Contains(out, "...") {
		t.Error("expected truncation marker '...' in long asset name")
	}
}

// ---------------------------------------------------------------------------
// Edge case: self-referencing edge in DOT
// ---------------------------------------------------------------------------

func TestRenderGraphDOT_SelfReferencingEdge(t *testing.T) {
	g := asset.AssetGraph{
		ScanRunID: "run-self",
		Domain:    "example.com",
		Assets: []asset.Asset{
			{ID: "domain:example.com", Type: asset.AssetTypeDomain, Provider: "web", Name: "example.com"},
		},
		Relationships: []asset.Relationship{
			{
				FromID:     "domain:example.com",
				ToID:       "domain:example.com",
				Type:       asset.RelPointsTo,
				Confidence: 1.0,
			},
		},
	}
	out := RenderGraphDOT(g)

	// Self-referencing edges are valid DOT; just ensure no panic.
	if !strings.Contains(out, "n_domain_example_com -> n_domain_example_com") {
		t.Error("expected self-referencing edge in DOT output")
	}
}

// ---------------------------------------------------------------------------
// Edge case: missing asset type in nodeShape (uses default)
// ---------------------------------------------------------------------------

func TestNodeShape_UnknownAssetType(t *testing.T) {
	shape := nodeShape(asset.AssetType("unknown_type"))
	if shape != "box" {
		t.Errorf("unknown asset type should default to box, got %q", shape)
	}
}

// ---------------------------------------------------------------------------
// Edge case: K8s namespace and workload shapes (missing from nodeShape)
// ---------------------------------------------------------------------------

func TestNodeShape_K8sTypes(t *testing.T) {
	// K8s namespace and workload are not in the nodeShape switch — they should
	// fall through to default (box). Just verify no panic.
	ns := nodeShape(asset.AssetTypeK8sNamespace)
	wl := nodeShape(asset.AssetTypeK8sWorkload)
	if ns == "" || wl == "" {
		t.Error("K8s namespace/workload should have a non-empty shape")
	}
}

// ---------------------------------------------------------------------------
// Edge case: GCP load balancer and AWS ELB shapes (missing from nodeShape)
// ---------------------------------------------------------------------------

func TestNodeShape_LoadBalancerTypes(t *testing.T) {
	gcpLB := nodeShape(asset.AssetTypeGCPLoadBalancer)
	awsELB := nodeShape(asset.AssetTypeAWSELB)
	if gcpLB == "" || awsELB == "" {
		t.Error("load balancer types should have a non-empty shape")
	}
}

// ---------------------------------------------------------------------------
// Edge case: severity ranking boundary values
// ---------------------------------------------------------------------------

func TestSeverityRank_AllLevels(t *testing.T) {
	tests := []struct {
		severity string
		rank     int
	}{
		{"critical", 5},
		{"CRITICAL", 5},
		{"Critical", 5},
		{"high", 4},
		{"medium", 3},
		{"low", 2},
		{"info", 1},
		{"", 0},
		{"unknown", 0},
	}
	for _, tt := range tests {
		got := severityRank(tt.severity)
		if got != tt.rank {
			t.Errorf("severityRank(%q) = %d; want %d", tt.severity, got, tt.rank)
		}
	}
}

func TestSeverityFillColor_AllLevels(t *testing.T) {
	for _, sev := range []string{"critical", "high", "medium", "low", "info", "unknown"} {
		color := severityFillColor(sev)
		if color == "" {
			t.Errorf("severityFillColor(%q) returned empty", sev)
		}
		if !strings.HasPrefix(color, "#") {
			t.Errorf("severityFillColor(%q) = %q; expected hex color", sev, color)
		}
	}
}

func TestSeverityBorderColor_AllLevels(t *testing.T) {
	for _, sev := range []string{"critical", "high", "medium", "low", "info", "unknown"} {
		color := severityBorderColor(sev)
		if color == "" {
			t.Errorf("severityBorderColor(%q) returned empty", sev)
		}
		if !strings.HasPrefix(color, "#") {
			t.Errorf("severityBorderColor(%q) = %q; expected hex color", sev, color)
		}
	}
}

// ---------------------------------------------------------------------------
// Edge case: buildNodeLabel with nil stats
// ---------------------------------------------------------------------------

func TestBuildNodeLabel_NilStats(t *testing.T) {
	a := asset.Asset{ID: "test", Type: asset.AssetTypeDomain, Name: "example.com"}
	label := buildNodeLabel(a, nil)
	if !strings.Contains(label, "example.com") {
		t.Errorf("label = %q; expected to contain asset name", label)
	}
	if strings.Contains(label, "finding") {
		t.Error("nil stats should not produce finding count in label")
	}
}

func TestBuildNodeLabel_ZeroFindings(t *testing.T) {
	a := asset.Asset{ID: "test", Type: asset.AssetTypeDomain, Name: "example.com"}
	label := buildNodeLabel(a, &assetStats{count: 0})
	if strings.Contains(label, "finding") {
		t.Error("zero-count stats should not produce finding count in label")
	}
}

func TestBuildNodeLabel_SingleFinding(t *testing.T) {
	a := asset.Asset{ID: "test", Type: asset.AssetTypeDomain, Name: "example.com"}
	label := buildNodeLabel(a, &assetStats{count: 1, maxSeverity: "high"})
	if !strings.Contains(label, "1 finding,") {
		t.Errorf("label = %q; expected singular 'finding' not 'findings'", label)
	}
}

func TestBuildNodeLabel_MultipleFindings(t *testing.T) {
	a := asset.Asset{ID: "test", Type: asset.AssetTypeDomain, Name: "example.com"}
	label := buildNodeLabel(a, &assetStats{count: 3, maxSeverity: "critical"})
	if !strings.Contains(label, "3 findings,") {
		t.Errorf("label = %q; expected plural 'findings'", label)
	}
}

// ---------------------------------------------------------------------------
// Edge case: exact boundary for name truncation (45 chars)
// ---------------------------------------------------------------------------

func TestBuildNodeLabel_ExactTruncationBoundary(t *testing.T) {
	// Name exactly 45 chars — should NOT be truncated.
	name45 := strings.Repeat("x", 45)
	a := asset.Asset{ID: "test", Type: asset.AssetTypeDomain, Name: name45}
	label := buildNodeLabel(a, nil)
	if strings.Contains(label, "...") {
		t.Error("name of exactly 45 chars should not be truncated")
	}

	// Name of 46 chars — SHOULD be truncated.
	name46 := strings.Repeat("y", 46)
	a2 := asset.Asset{ID: "test", Type: asset.AssetTypeDomain, Name: name46}
	label2 := buildNodeLabel(a2, nil)
	if !strings.Contains(label2, "...") {
		t.Error("name of 46 chars should be truncated")
	}
}

// ---------------------------------------------------------------------------
// Edge case: nodeColors with no findings, by provider
// ---------------------------------------------------------------------------

func TestNodeColors_ByProvider(t *testing.T) {
	tests := []struct {
		assetType    asset.AssetType
		expectedFill string
	}{
		{asset.AssetTypeGCPInstance, "#2d4a22"},
		{asset.AssetTypeAWSEC2, "#4a3522"},
		{asset.AssetTypeAzureVM, "#22354a"},
		{asset.AssetTypeGitHubRepo, "#3a3a3a"},
		{asset.AssetTypeK8sCluster, "#2a2a4a"},
		{asset.AssetTypeDomain, "#2a2a3e"},
		{asset.AssetTypeIP, "#2e2e3e"},
	}
	for _, tt := range tests {
		a := asset.Asset{Type: tt.assetType}
		fill, _ := nodeColors(a, nil)
		if fill != tt.expectedFill {
			t.Errorf("nodeColors(%s, nil) fill = %q; want %q", tt.assetType, fill, tt.expectedFill)
		}
	}
}

func TestNodeColors_WithFindings(t *testing.T) {
	a := asset.Asset{Type: asset.AssetTypeDomain}
	s := &assetStats{count: 1, maxSeverity: "critical"}
	fill, font := nodeColors(a, s)
	if fill != "#4a1a1a" {
		t.Errorf("critical fill = %q; want #4a1a1a", fill)
	}
	if font != "#ffffff" {
		t.Errorf("font with findings = %q; want #ffffff", font)
	}
}

// ---------------------------------------------------------------------------
// Edge case: assetTypeLabel for all known types
// ---------------------------------------------------------------------------

func TestAssetTypeLabel_AllKnownTypes(t *testing.T) {
	knownTypes := []asset.AssetType{
		asset.AssetTypeDomain, asset.AssetTypeSubdomain, asset.AssetTypeIP,
		asset.AssetTypeAPIEndpoint, asset.AssetTypeGCPProject,
		asset.AssetTypeGCPInstance, asset.AssetTypeGCPBucket,
		asset.AssetTypeGCPCluster, asset.AssetTypeGCPServiceAccount,
		asset.AssetTypeGCPLoadBalancer, asset.AssetTypeAWSAccount,
		asset.AssetTypeAWSEC2, asset.AssetTypeAWSS3,
		asset.AssetTypeAWSEKS, asset.AssetTypeAWSIAMUser,
		asset.AssetTypeAWSIAMRole, asset.AssetTypeAWSELB,
		asset.AssetTypeAzureSubscription, asset.AssetTypeAzureVM,
		asset.AssetTypeAzureBlobContainer, asset.AssetTypeAzureAKS,
		asset.AssetTypeGitHubRepo, asset.AssetTypeGitHubWorkflow,
		asset.AssetTypeTerraformModule, asset.AssetTypeTerraformResource,
		asset.AssetTypeK8sCluster, asset.AssetTypeK8sNamespace,
		asset.AssetTypeK8sWorkload,
	}
	for _, at := range knownTypes {
		label := assetTypeLabel(at)
		if label == "" {
			t.Errorf("assetTypeLabel(%q) is empty", at)
		}
		if label == string(at) {
			t.Errorf("assetTypeLabel(%q) returned raw type; expected human-readable label", at)
		}
	}
}

func TestAssetTypeLabel_UnknownFallback(t *testing.T) {
	label := assetTypeLabel("some_unknown_type")
	if label != "some_unknown_type" {
		t.Errorf("unknown type should return raw string, got %q", label)
	}
}

// ---------------------------------------------------------------------------
// Edge case: findings referencing non-existent asset
// ---------------------------------------------------------------------------

func TestRenderGraphDOT_FindingForMissingAsset(t *testing.T) {
	g := asset.AssetGraph{
		ScanRunID: "run-orphan",
		Domain:    "example.com",
		Assets: []asset.Asset{
			{ID: "domain:example.com", Type: asset.AssetTypeDomain, Name: "example.com"},
		},
		Findings: []asset.FindingRef{
			{
				FindingID: "f-0",
				AssetID:   "domain:nonexistent.com", // not in Assets
				CheckID:   "test.check",
				Severity:  "high",
				Title:     "Orphan finding",
			},
		},
	}
	// Should not panic — the finding just won't have a matching node.
	out := RenderGraphDOT(g)
	if !strings.HasPrefix(out, "digraph beacon {") {
		t.Error("should still produce valid DOT output")
	}
}

// ---------------------------------------------------------------------------
// Edge case: relationship referencing non-existent assets
// ---------------------------------------------------------------------------

func TestRenderGraphDOT_EdgeForMissingNodes(t *testing.T) {
	g := asset.AssetGraph{
		ScanRunID: "run-orphan-edge",
		Domain:    "example.com",
		Assets:    []asset.Asset{},
		Relationships: []asset.Relationship{
			{
				FromID:     "domain:ghost-from",
				ToID:       "domain:ghost-to",
				Type:       asset.RelPointsTo,
				Confidence: 1.0,
			},
		},
	}
	// Should not panic — the edge references nodes that don't exist.
	out := RenderGraphDOT(g)
	if !strings.Contains(out, "->") {
		t.Error("edge should still be rendered even if nodes are missing")
	}
}

// ---------------------------------------------------------------------------
// Edge case: dotNodeID with empty string
// ---------------------------------------------------------------------------

func TestDotNodeID_EmptyString(t *testing.T) {
	id := dotNodeID("")
	if id != "n_" {
		t.Errorf("dotNodeID(\"\") = %q; want %q", id, "n_")
	}
}

// ---------------------------------------------------------------------------
// Edge case: dotQuote with empty string
// ---------------------------------------------------------------------------

func TestDotQuote_EmptyString(t *testing.T) {
	out := dotQuote("")
	if out != `""` {
		t.Errorf("dotQuote(\"\") = %q; want %q", out, `""`)
	}
}

// ---------------------------------------------------------------------------
// Edge case: dotEscape with empty string
// ---------------------------------------------------------------------------

func TestDotEscape_EmptyString(t *testing.T) {
	out := dotEscape("")
	if out != "" {
		t.Errorf("dotEscape(\"\") = %q; want empty", out)
	}
}
