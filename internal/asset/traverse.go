package asset

// Traverser provides graph traversal and blast radius computation for
// an AssetGraph. It pre-indexes adjacency lists on construction so
// repeated queries are O(E) in the worst case but fast in practice.
type Traverser struct {
	graph    *AssetGraph
	byID     map[string]*Asset
	outEdges map[string][]Relationship // fromID → relationships
	inEdges  map[string][]Relationship // toID  → relationships
	findings map[string][]FindingRef   // assetID → findings
}

// NewTraverser builds traversal indexes for the given graph.
func NewTraverser(g *AssetGraph) *Traverser {
	t := &Traverser{
		graph:    g,
		byID:     make(map[string]*Asset, len(g.Assets)),
		outEdges: make(map[string][]Relationship, len(g.Assets)),
		inEdges:  make(map[string][]Relationship, len(g.Assets)),
		findings: make(map[string][]FindingRef, len(g.Findings)),
	}
	for i := range g.Assets {
		t.byID[g.Assets[i].ID] = &g.Assets[i]
	}
	for _, r := range g.Relationships {
		t.outEdges[r.FromID] = append(t.outEdges[r.FromID], r)
		t.inEdges[r.ToID] = append(t.inEdges[r.ToID], r)
	}
	for _, f := range g.Findings {
		t.findings[f.AssetID] = append(t.findings[f.AssetID], f)
	}
	return t
}

// Reachable returns all asset IDs reachable from startID by following
// outgoing edges of the given relationship types. If types is nil,
// all edge types are followed. Traversal is BFS with cycle detection.
func (t *Traverser) Reachable(startID string, types []RelationshipType) []string {
	typeSet := make(map[RelationshipType]bool, len(types))
	for _, rt := range types {
		typeSet[rt] = true
	}
	filterAll := len(types) == 0

	visited := map[string]bool{startID: true}
	queue := []string{startID}
	var result []string

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		for _, rel := range t.outEdges[current] {
			if !filterAll && !typeSet[rel.Type] {
				continue
			}
			if visited[rel.ToID] {
				continue
			}
			visited[rel.ToID] = true
			result = append(result, rel.ToID)
			queue = append(queue, rel.ToID)
		}
	}
	return result
}

// Ancestors returns all asset IDs that can reach targetID by following
// incoming edges of the given relationship types. If types is nil,
// all edge types are followed. Traversal is reverse BFS.
func (t *Traverser) Ancestors(targetID string, types []RelationshipType) []string {
	typeSet := make(map[RelationshipType]bool, len(types))
	for _, rt := range types {
		typeSet[rt] = true
	}
	filterAll := len(types) == 0

	visited := map[string]bool{targetID: true}
	queue := []string{targetID}
	var result []string

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		for _, rel := range t.inEdges[current] {
			if !filterAll && !typeSet[rel.Type] {
				continue
			}
			if visited[rel.FromID] {
				continue
			}
			visited[rel.FromID] = true
			result = append(result, rel.FromID)
			queue = append(queue, rel.FromID)
		}
	}
	return result
}

// BlastRadius computes the blast radius for a compromised asset. It returns
// a BlastRadiusResult containing all assets reachable through lateral movement
// relationships, aggregated finding severity counts, and a risk score.
func (t *Traverser) BlastRadius(assetID string) BlastRadiusResult {
	// Lateral movement relationship types — edges an attacker can traverse.
	lateralTypes := []RelationshipType{
		RelManages,
		RelExposes,
		RelDeploysTo,
		RelUses,
		RelAccesses,
		RelLikelySameAs,
	}

	reachable := t.Reachable(assetID, lateralTypes)

	result := BlastRadiusResult{
		OriginID:     assetID,
		ReachableIDs: reachable,
		SeverityCounts: map[string]int{
			"critical": 0,
			"high":     0,
			"medium":   0,
			"low":      0,
			"info":     0,
		},
	}

	// Collect all findings on reachable assets.
	allIDs := append([]string{assetID}, reachable...)
	for _, id := range allIDs {
		for _, f := range t.findings[id] {
			result.SeverityCounts[f.Severity]++
			result.AffectedFindings = append(result.AffectedFindings, f)
		}
	}

	// Classify reachable assets.
	for _, id := range reachable {
		a, ok := t.byID[id]
		if !ok {
			continue
		}
		switch a.Type {
		case AssetTypeGCPProject, AssetTypeAWSAccount, AssetTypeAzureSubscription:
			result.CloudAccountsReachable++
		case AssetTypeGCPCluster, AssetTypeAWSEKS, AssetTypeAzureAKS, AssetTypeK8sCluster:
			result.ClustersReachable++
		case AssetTypeGitHubRepo:
			result.ReposReachable++
		case AssetTypeGitHubPackage:
			result.PackagesReachable++
		}
	}

	// Compute risk score: weighted combination of severity counts and reach.
	result.RiskScore = computeRiskScore(result)
	return result
}

// BlastRadiusResult captures the computed blast radius for one compromised asset.
type BlastRadiusResult struct {
	OriginID               string            `json:"origin_id"`
	ReachableIDs           []string          `json:"reachable_ids"`
	SeverityCounts         map[string]int    `json:"severity_counts"`
	AffectedFindings       []FindingRef      `json:"affected_findings"`
	CloudAccountsReachable int               `json:"cloud_accounts_reachable"`
	ClustersReachable      int               `json:"clusters_reachable"`
	ReposReachable         int               `json:"repos_reachable"`
	PackagesReachable      int               `json:"packages_reachable"`
	RiskScore              float64           `json:"risk_score"`
}

// computeRiskScore assigns a 0-10 score based on severity counts and lateral reach.
func computeRiskScore(r BlastRadiusResult) float64 {
	score := 0.0

	// Severity-weighted finding contribution (capped at 6.0).
	score += float64(r.SeverityCounts["critical"]) * 1.0
	score += float64(r.SeverityCounts["high"]) * 0.6
	score += float64(r.SeverityCounts["medium"]) * 0.3
	score += float64(r.SeverityCounts["low"]) * 0.1
	if score > 6.0 {
		score = 6.0
	}

	// Lateral reach contribution (capped at 4.0).
	reachScore := 0.0
	reachScore += float64(r.CloudAccountsReachable) * 1.5
	reachScore += float64(r.ClustersReachable) * 1.0
	reachScore += float64(r.ReposReachable) * 0.5
	totalReachable := len(r.ReachableIDs)
	if totalReachable > 10 {
		reachScore += 1.0 // bonus for broad reach
	}
	if reachScore > 4.0 {
		reachScore = 4.0
	}
	score += reachScore

	if score > 10.0 {
		score = 10.0
	}
	return score
}

// ShortestPath returns the shortest path (sequence of asset IDs) from srcID
// to dstID following any relationship type. Returns nil if no path exists.
func (t *Traverser) ShortestPath(srcID, dstID string) []string {
	if srcID == dstID {
		return []string{srcID}
	}

	visited := map[string]bool{srcID: true}
	parent := map[string]string{}
	queue := []string{srcID}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		for _, rel := range t.outEdges[current] {
			if visited[rel.ToID] {
				continue
			}
			visited[rel.ToID] = true
			parent[rel.ToID] = current

			if rel.ToID == dstID {
				return reconstructPath(parent, srcID, dstID)
			}
			queue = append(queue, rel.ToID)
		}
	}
	return nil
}

// reconstructPath traces parent pointers back from dst to src.
func reconstructPath(parent map[string]string, src, dst string) []string {
	var path []string
	for cur := dst; cur != src; cur = parent[cur] {
		path = append(path, cur)
		next, ok := parent[cur]
		if !ok {
			return nil // broken chain — no valid path
		}
		if next == cur {
			return nil // self-loop — prevent infinite loop
		}
	}
	path = append(path, src)
	// Reverse.
	for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 {
		path[i], path[j] = path[j], path[i]
	}
	return path
}

// FindingsFor returns all finding references attached to the given asset.
func (t *Traverser) FindingsFor(assetID string) []FindingRef {
	return t.findings[assetID]
}

// Asset returns the asset with the given ID, or nil if not found.
func (t *Traverser) Asset(id string) *Asset {
	return t.byID[id]
}

// Neighbors returns all directly connected asset IDs (both directions).
func (t *Traverser) Neighbors(assetID string) []string {
	seen := map[string]bool{}
	for _, r := range t.outEdges[assetID] {
		seen[r.ToID] = true
	}
	for _, r := range t.inEdges[assetID] {
		seen[r.FromID] = true
	}
	result := make([]string, 0, len(seen))
	for id := range seen {
		result = append(result, id)
	}
	return result
}
