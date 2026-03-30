package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/stormbane/beacon/internal/asset"
)

// assetStats tracks finding counts and severity for a single asset node.
type assetStats struct {
	count       int
	maxSeverity string
	titles      []string
}

// RenderGraphDOT produces a Graphviz DOT representation of the asset topology
// discovered during scanning. Assets become nodes with labels showing type,
// name, and finding count. Relationships become edges labeled with the
// relationship type. Findings are shown as colored annotations on their
// respective asset nodes.
//
// The output can be rendered with:
//
//	beacon scan --domain example.com --format graph | dot -Tsvg -o topology.svg
//	beacon scan --domain example.com --format graph | dot -Tpng -o topology.png
func RenderGraphDOT(g asset.AssetGraph) string {
	var b strings.Builder

	b.WriteString("digraph beacon {\n")
	b.WriteString("    rankdir=LR;\n")
	b.WriteString("    bgcolor=\"#1a1a2e\";\n")
	b.WriteString("    node [style=filled, fontname=\"Helvetica\", fontsize=11];\n")
	b.WriteString("    edge [fontname=\"Helvetica\", fontsize=9, color=\"#888888\", fontcolor=\"#cccccc\"];\n")
	b.WriteString("    label=\"Beacon Asset Graph — " + dotEscape(g.Domain) + "\";\n")
	b.WriteString("    labelloc=t;\n")
	b.WriteString("    fontname=\"Helvetica Bold\";\n")
	b.WriteString("    fontsize=16;\n")
	b.WriteString("    fontcolor=\"#e0e0e0\";\n")
	b.WriteString("\n")

	// Build finding counts and max-severity per asset for node coloring.
	stats := make(map[string]*assetStats)
	for _, fr := range g.Findings {
		s, ok := stats[fr.AssetID]
		if !ok {
			s = &assetStats{}
			stats[fr.AssetID] = s
		}
		s.count++
		s.titles = append(s.titles, fmt.Sprintf("[%s] %s", fr.Severity, fr.Title))
		if severityRank(fr.Severity) > severityRank(s.maxSeverity) {
			s.maxSeverity = fr.Severity
		}
	}

	// Sort assets for deterministic output.
	sortedAssets := make([]asset.Asset, len(g.Assets))
	copy(sortedAssets, g.Assets)
	sort.Slice(sortedAssets, func(i, j int) bool {
		return sortedAssets[i].ID < sortedAssets[j].ID
	})

	// Emit nodes.
	for _, a := range sortedAssets {
		nodeID := dotNodeID(a.ID)
		label := buildNodeLabel(a, stats[a.ID])
		fillColor, fontColor := nodeColors(a, stats[a.ID])
		shape := nodeShape(a.Type)

		b.WriteString(fmt.Sprintf("    %s [label=%s, shape=%s, fillcolor=\"%s\", fontcolor=\"%s\"",
			nodeID, dotQuote(label), shape, fillColor, fontColor))

		// Add a colored border for nodes with findings.
		if s, ok := stats[a.ID]; ok && s.count > 0 {
			borderColor := severityBorderColor(s.maxSeverity)
			b.WriteString(fmt.Sprintf(", color=\"%s\", penwidth=2.0", borderColor))
		} else {
			b.WriteString(", color=\"#444466\"")
		}

		// Add tooltip with finding details.
		if s, ok := stats[a.ID]; ok && len(s.titles) > 0 {
			tooltip := strings.Join(s.titles, "\\n")
			b.WriteString(fmt.Sprintf(", tooltip=%s", dotQuote(tooltip)))
		}

		b.WriteString("];\n")
	}

	b.WriteString("\n")

	// Sort relationships for deterministic output.
	sortedRels := make([]asset.Relationship, len(g.Relationships))
	copy(sortedRels, g.Relationships)
	sort.Slice(sortedRels, func(i, j int) bool {
		if sortedRels[i].FromID != sortedRels[j].FromID {
			return sortedRels[i].FromID < sortedRels[j].FromID
		}
		if sortedRels[i].ToID != sortedRels[j].ToID {
			return sortedRels[i].ToID < sortedRels[j].ToID
		}
		return sortedRels[i].Type < sortedRels[j].Type
	})

	// Emit edges.
	for _, r := range sortedRels {
		fromID := dotNodeID(r.FromID)
		toID := dotNodeID(r.ToID)
		edgeLabel := string(r.Type)
		edgeStyle := "solid"
		edgeColor := "#888888"

		if r.Confidence < 0.9 {
			edgeStyle = "dashed"
			edgeColor = "#666666"
			edgeLabel = fmt.Sprintf("%s (%.0f%%)", r.Type, r.Confidence*100)
		}

		b.WriteString(fmt.Sprintf("    %s -> %s [label=%s, style=%s, color=\"%s\"];\n",
			fromID, toID, dotQuote(edgeLabel), edgeStyle, edgeColor))
	}

	b.WriteString("}\n")
	return b.String()
}

// buildNodeLabel creates a multi-line label for an asset node.
func buildNodeLabel(a asset.Asset, s *assetStats) string {
	// Type label (short form)
	typeLabel := assetTypeLabel(a.Type)

	// Name — truncate if too long
	name := a.Name
	if len(name) > 45 {
		name = name[:20] + "..." + name[len(name)-20:]
	}

	label := typeLabel + "\\n" + name

	if s != nil && s.count > 0 {
		label += fmt.Sprintf("\\n(%d finding", s.count)
		if s.count != 1 {
			label += "s"
		}
		label += ", " + s.maxSeverity + ")"
	}

	return label
}

// assetTypeLabel returns a short display label for an asset type.
func assetTypeLabel(t asset.AssetType) string {
	labels := map[asset.AssetType]string{
		asset.AssetTypeDomain:              "Domain",
		asset.AssetTypeSubdomain:           "Subdomain",
		asset.AssetTypeIP:                  "IP",
		asset.AssetTypeAPIEndpoint:         "API Endpoint",
		asset.AssetTypeGCPProject:          "GCP Project",
		asset.AssetTypeGCPInstance:         "GCP Instance",
		asset.AssetTypeGCPBucket:           "GCP Bucket",
		asset.AssetTypeGCPCluster:          "GKE Cluster",
		asset.AssetTypeGCPServiceAccount:   "GCP SA",
		asset.AssetTypeGCPLoadBalancer:     "GCP LB",
		asset.AssetTypeAWSAccount:          "AWS Account",
		asset.AssetTypeAWSEC2:              "EC2 Instance",
		asset.AssetTypeAWSS3:              "S3 Bucket",
		asset.AssetTypeAWSEKS:              "EKS Cluster",
		asset.AssetTypeAWSIAMUser:          "IAM User",
		asset.AssetTypeAWSIAMRole:          "IAM Role",
		asset.AssetTypeAWSELB:              "AWS ELB",
		asset.AssetTypeAzureSubscription:   "Azure Sub",
		asset.AssetTypeAzureVM:             "Azure VM",
		asset.AssetTypeAzureBlobContainer:  "Azure Blob",
		asset.AssetTypeAzureAKS:            "AKS Cluster",
		asset.AssetTypeGitHubRepo:          "GitHub Repo",
		asset.AssetTypeGitHubWorkflow:      "GH Workflow",
		asset.AssetTypeTerraformModule:     "TF Module",
		asset.AssetTypeTerraformResource:   "TF Resource",
		asset.AssetTypeK8sCluster:          "K8s Cluster",
		asset.AssetTypeK8sNamespace:        "K8s NS",
		asset.AssetTypeK8sWorkload:         "K8s Workload",
	}
	if label, ok := labels[t]; ok {
		return label
	}
	return string(t)
}

// nodeShape returns the DOT shape for an asset type category.
func nodeShape(t asset.AssetType) string {
	switch t {
	case asset.AssetTypeDomain, asset.AssetTypeSubdomain:
		return "box"
	case asset.AssetTypeIP:
		return "ellipse"
	case asset.AssetTypeGCPBucket, asset.AssetTypeAWSS3, asset.AssetTypeAzureBlobContainer:
		return "cylinder"
	case asset.AssetTypeGCPCluster, asset.AssetTypeAWSEKS, asset.AssetTypeAzureAKS,
		asset.AssetTypeK8sCluster:
		return "hexagon"
	case asset.AssetTypeGCPServiceAccount, asset.AssetTypeAWSIAMUser, asset.AssetTypeAWSIAMRole:
		return "diamond"
	case asset.AssetTypeGitHubRepo, asset.AssetTypeGitHubWorkflow:
		return "note"
	case asset.AssetTypeTerraformModule, asset.AssetTypeTerraformResource:
		return "parallelogram"
	default:
		return "box"
	}
}

// nodeColors returns fill and font colors for a node based on its asset type
// and finding severity.
func nodeColors(a asset.Asset, s *assetStats) (fillColor, fontColor string) {
	if s != nil && s.count > 0 {
		return severityFillColor(s.maxSeverity), "#ffffff"
	}

	// Clean nodes — color by provider/type category.
	switch {
	case strings.HasPrefix(string(a.Type), "gcp_"):
		return "#2d4a22", "#a8d08d"
	case strings.HasPrefix(string(a.Type), "aws_"):
		return "#4a3522", "#d0a070"
	case strings.HasPrefix(string(a.Type), "azure_"):
		return "#22354a", "#70a8d0"
	case strings.HasPrefix(string(a.Type), "github_"):
		return "#3a3a3a", "#c8c8c8"
	case strings.HasPrefix(string(a.Type), "k8s_"):
		return "#2a2a4a", "#8888cc"
	case strings.HasPrefix(string(a.Type), "terraform_"):
		return "#3a2a4a", "#b088cc"
	case a.Type == asset.AssetTypeDomain || a.Type == asset.AssetTypeSubdomain:
		return "#2a2a3e", "#c0c0d8"
	case a.Type == asset.AssetTypeIP:
		return "#2e2e3e", "#b0b0c8"
	default:
		return "#2a2a3e", "#c0c0d8"
	}
}

// severityRank returns a numeric rank for sorting by severity.
func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

// severityFillColor returns a muted background color for nodes with findings.
func severityFillColor(maxSeverity string) string {
	switch strings.ToLower(maxSeverity) {
	case "critical":
		return "#4a1a1a"
	case "high":
		return "#4a2a1a"
	case "medium":
		return "#4a3a1a"
	case "low":
		return "#2a3a1a"
	default:
		return "#1a2a3a"
	}
}

// severityBorderColor returns a bright border color indicating finding severity.
func severityBorderColor(maxSeverity string) string {
	switch strings.ToLower(maxSeverity) {
	case "critical":
		return "#ff4444"
	case "high":
		return "#ff8844"
	case "medium":
		return "#ffcc44"
	case "low":
		return "#88cc44"
	default:
		return "#4488cc"
	}
}

// dotNodeID converts an asset ID to a valid DOT node identifier.
// Only alphanumeric characters and underscores are kept; everything else
// is replaced with underscores to prevent DOT syntax injection.
func dotNodeID(id string) string {
	var b strings.Builder
	b.WriteString("n_")
	for _, c := range id {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' {
			b.WriteRune(c)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

// dotQuote wraps a string in double quotes for DOT syntax, escaping
// backslashes, double quotes, and newlines to prevent DOT injection.
func dotQuote(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	return "\"" + s + "\""
}

// dotEscape escapes characters that are special in DOT labels.
// Backslashes are escaped first to avoid double-escaping the backslashes
// introduced by subsequent replacements.
func dotEscape(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "<", "\\<")
	s = strings.ReplaceAll(s, ">", "\\>")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	return s
}
