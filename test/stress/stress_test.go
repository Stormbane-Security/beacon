//go:build stress

package stress

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stormbane-security/beacon/internal/asset"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/playbook"
	"github.com/stormbane-security/beacon/internal/store"
	sqlitestore "github.com/stormbane-security/beacon/internal/store/sqlite"
)

// TestConcurrentStoreWrites verifies that 100 goroutines writing findings
// to a real SQLite store concurrently produce no database-locked errors
// or data corruption. Each goroutine saves 10 findings with unique CheckIDs.
// After all complete, verifies the total count matches expected (accounting
// for the INSERT OR IGNORE dedup on scan_run_id + check_id + asset + title).
//
// Run with -race to catch data races:
//
//	go test ./test/stress/ -tags=stress -run=TestConcurrentStoreWrites -race -timeout=60s
func TestConcurrentStoreWrites(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "stress.db")

	st, err := sqlitestore.Open(dbPath)
	if err != nil {
		t.Fatalf("opening sqlite store: %v", err)
	}
	defer st.Close()

	ctx := context.Background()

	// Create a target and scan run.
	target, err := st.UpsertTarget(ctx, "stress.example.com")
	if err != nil {
		t.Fatalf("upserting target: %v", err)
	}
	scanRunID := uuid.NewString()
	err = st.CreateScanRun(ctx, &store.ScanRun{
		ID:        scanRunID,
		TargetID:  target.ID,
		Domain:    "stress.example.com",
		ScanType:  module.ScanSurface,
		Modules:   []string{"surface"},
		Status:    store.StatusRunning,
		StartedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("creating scan run: %v", err)
	}

	const goroutines = 100
	const findingsPerGoroutine = 10

	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	for g := range goroutines {
		wg.Add(1)
		go func(gID int) {
			defer wg.Done()

			batch := make([]finding.Finding, findingsPerGoroutine)
			for i := range findingsPerGoroutine {
				batch[i] = finding.Finding{
					CheckID:      finding.CheckID(fmt.Sprintf("stress.goroutine_%d_finding_%d", gID, i)),
					Module:       "surface",
					Scanner:      "stress",
					Severity:     finding.SeverityMedium,
					Title:        fmt.Sprintf("Stress finding g%d #%d", gID, i),
					Description:  "Concurrent write stress test finding",
					Asset:        fmt.Sprintf("asset-g%d-%d.example.com", gID, i),
					Evidence:     map[string]any{"goroutine": gID, "index": i},
					ProofCommand: fmt.Sprintf("echo 'stress g%d #%d'", gID, i),
					DiscoveredAt: time.Now(),
				}
			}

			if err := st.SaveFindings(ctx, scanRunID, batch); err != nil {
				errs <- fmt.Errorf("goroutine %d: %w", gID, err)
			}
		}(g)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("write error: %v", err)
	}

	// Verify total count: all findings have unique (check_id, asset, title)
	// tuples, so none should be deduped.
	got, err := st.GetFindings(ctx, scanRunID)
	if err != nil {
		t.Fatalf("getting findings: %v", err)
	}
	expected := goroutines * findingsPerGoroutine
	if len(got) != expected {
		t.Errorf("expected %d findings, got %d", expected, len(got))
	}
}

// TestLargeFindingSetProcessing verifies that saving 10,000 findings in a
// single SaveFindings call completes without OOM or timeout. This tests the
// SQLite transaction batching under pressure.
func TestLargeFindingSetProcessing(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "large.db")

	st, err := sqlitestore.Open(dbPath)
	if err != nil {
		t.Fatalf("opening sqlite store: %v", err)
	}
	defer st.Close()

	ctx := context.Background()

	target, err := st.UpsertTarget(ctx, "large.example.com")
	if err != nil {
		t.Fatalf("upserting target: %v", err)
	}
	scanRunID := uuid.NewString()
	err = st.CreateScanRun(ctx, &store.ScanRun{
		ID:        scanRunID,
		TargetID:  target.ID,
		Domain:    "large.example.com",
		ScanType:  module.ScanSurface,
		Modules:   []string{"surface"},
		Status:    store.StatusRunning,
		StartedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("creating scan run: %v", err)
	}

	const totalFindings = 10_000
	batch := make([]finding.Finding, totalFindings)
	for i := range totalFindings {
		batch[i] = finding.Finding{
			CheckID:      finding.CheckID(fmt.Sprintf("large.check_%05d", i)),
			Module:       "surface",
			Scanner:      "stress",
			Severity:     finding.Severity(i % 5), // rotate through severity levels
			Title:        fmt.Sprintf("Large batch finding #%d", i),
			Description:  "Large batch stress test",
			Asset:        fmt.Sprintf("asset-%05d.example.com", i),
			Evidence:     map[string]any{"index": i},
			ProofCommand: fmt.Sprintf("echo 'finding %d'", i),
			DiscoveredAt: time.Now(),
		}
	}

	deadline := time.After(30 * time.Second)
	done := make(chan error, 1)
	go func() {
		done <- st.SaveFindings(ctx, scanRunID, batch)
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("SaveFindings failed: %v", err)
		}
	case <-deadline:
		t.Fatal("SaveFindings did not complete within 30 seconds")
	}

	// Verify all findings persisted.
	got, err := st.GetFindings(ctx, scanRunID)
	if err != nil {
		t.Fatalf("GetFindings: %v", err)
	}
	if len(got) != totalFindings {
		t.Errorf("expected %d findings, got %d", totalFindings, len(got))
	}
}

// TestAssetGraphBlastRadius builds an asset graph with 1000 assets and 2000
// relationships. It verifies that BlastRadius computation completes within
// 5 seconds and produces valid results. Also tests that deep chains don't
// cause stack overflow (BFS traversal, not DFS).
func TestAssetGraphBlastRadius(t *testing.T) {
	const numAssets = 1000
	const numRelationships = 2000

	graph := &asset.AssetGraph{
		ScanRunID:   uuid.NewString(),
		Domain:      "blast.example.com",
		GeneratedAt: time.Now(),
	}

	// Build assets: mix of types so BlastRadius classifies them.
	assetTypes := []asset.AssetType{
		asset.AssetTypeDomain,
		asset.AssetTypeSubdomain,
		asset.AssetTypeIP,
		asset.AssetTypeGCPProject,
		asset.AssetTypeAWSAccount,
		asset.AssetTypeAzureSubscription,
		asset.AssetTypeGCPCluster,
		asset.AssetTypeAWSEKS,
		asset.AssetTypeGitHubRepo,
		asset.AssetTypeGitHubPackage,
	}

	for i := range numAssets {
		graph.Assets = append(graph.Assets, asset.Asset{
			ID:           fmt.Sprintf("asset:%d", i),
			Type:         assetTypes[i%len(assetTypes)],
			Provider:     "test",
			Name:         fmt.Sprintf("asset-%d", i),
			DiscoveredBy: "stress",
			Confidence:   1.0,
			DiscoveredAt: time.Now(),
		})
	}

	// Build relationships: each asset connects to the next 2, creating a
	// wide graph with moderate depth. Uses lateral movement types so
	// BlastRadius traverses them.
	relTypes := []asset.RelationshipType{
		asset.RelManages,
		asset.RelExposes,
		asset.RelDeploysTo,
		asset.RelUses,
		asset.RelAccesses,
	}
	for i := range numRelationships {
		from := i % numAssets
		to := (from + 1 + (i / numAssets)) % numAssets
		if from == to {
			to = (to + 1) % numAssets
		}
		graph.Relationships = append(graph.Relationships, asset.Relationship{
			FromID:     fmt.Sprintf("asset:%d", from),
			ToID:       fmt.Sprintf("asset:%d", to),
			Type:       relTypes[i%len(relTypes)],
			Confidence: 1.0,
		})
	}

	// Add findings to some assets.
	severities := []string{"critical", "high", "medium", "low", "info"}
	for i := 0; i < 500; i++ {
		graph.Findings = append(graph.Findings, asset.FindingRef{
			FindingID: uuid.NewString(),
			AssetID:   fmt.Sprintf("asset:%d", i),
			CheckID:   fmt.Sprintf("stress.check_%d", i),
			Severity:  severities[i%len(severities)],
			Title:     fmt.Sprintf("Stress finding %d", i),
		})
	}

	// Build traverser and run BlastRadius within timeout.
	deadline := time.After(5 * time.Second)
	done := make(chan asset.BlastRadiusResult, 1)
	go func() {
		trav := asset.NewTraverser(graph)
		done <- trav.BlastRadius("asset:0")
	}()

	select {
	case result := <-done:
		if len(result.ReachableIDs) == 0 {
			t.Error("BlastRadius returned zero reachable assets on a connected graph")
		}
		if result.RiskScore < 0 || result.RiskScore > 10 {
			t.Errorf("RiskScore out of range [0,10]: %f", result.RiskScore)
		}
		// With 2000 edges across 1000 nodes and lateral movement types,
		// we should reach a substantial portion of the graph.
		if len(result.ReachableIDs) < 10 {
			t.Errorf("expected significant reachability, got %d assets", len(result.ReachableIDs))
		}
		t.Logf("BlastRadius: %d reachable, score=%.1f, crits=%d, highs=%d",
			len(result.ReachableIDs), result.RiskScore,
			result.SeverityCounts["critical"], result.SeverityCounts["high"])
	case <-deadline:
		t.Fatal("BlastRadius did not complete within 5 seconds")
	}

	// Test deep chain traversal: build a linear chain of 500 nodes to verify
	// BFS doesn't stack overflow.
	deepGraph := &asset.AssetGraph{
		ScanRunID:   uuid.NewString(),
		Domain:      "deep.example.com",
		GeneratedAt: time.Now(),
	}
	const chainLen = 500
	for i := range chainLen {
		deepGraph.Assets = append(deepGraph.Assets, asset.Asset{
			ID:           fmt.Sprintf("chain:%d", i),
			Type:         asset.AssetTypeSubdomain,
			Provider:     "test",
			Name:         fmt.Sprintf("chain-%d", i),
			DiscoveredBy: "stress",
			Confidence:   1.0,
			DiscoveredAt: time.Now(),
		})
	}
	for i := 0; i < chainLen-1; i++ {
		deepGraph.Relationships = append(deepGraph.Relationships, asset.Relationship{
			FromID:     fmt.Sprintf("chain:%d", i),
			ToID:       fmt.Sprintf("chain:%d", i+1),
			Type:       asset.RelManages,
			Confidence: 1.0,
		})
	}

	trav := asset.NewTraverser(deepGraph)
	reachable := trav.Reachable("chain:0", nil)
	if len(reachable) != chainLen-1 {
		t.Errorf("deep chain: expected %d reachable, got %d", chainLen-1, len(reachable))
	}
}

// TestPlaybookMatchingAtScale loads all playbooks and runs matching against
// 100 different evidence sets. Verifies matching completes within 2 seconds
// total, catching any N^2 behavior.
func TestPlaybookMatchingAtScale(t *testing.T) {
	reg, err := playbook.Load()
	if err != nil {
		t.Fatalf("loading playbooks: %v", err)
	}

	all := reg.All()
	if len(all) < 100 {
		t.Logf("loaded %d playbooks (expected ~124)", len(all))
	}

	// Build 100 diverse evidence sets that exercise different match paths.
	evidenceSets := make([]playbook.Evidence, 100)
	platforms := []string{
		"wordpress", "drupal", "nginx", "apache", "express", "django",
		"rails", "spring", "laravel", "flask", "nextjs", "nuxtjs",
		"couchdb", "rabbitmq", "minio", "neo4j", "jenkins", "grafana",
		"kibana", "gitlab", "sonarqube", "airflow",
	}
	frameworks := []string{
		"react", "angular", "vue", "svelte", "jquery", "bootstrap",
		"tailwind", "ember", "backbone", "remix",
	}
	cloudProviders := []string{"aws", "gcp", "azure", "digitalocean", "heroku"}
	authSystems := []string{"oauth2", "saml", "oidc", "basic", "jwt", "api_key"}

	for i := range 100 {
		ev := playbook.Evidence{
			Headers:         make(map[string]string),
			ServiceVersions: make(map[string]string),
		}

		// Vary the evidence across different dimensions.
		ev.ServiceVersions["platform"] = platforms[i%len(platforms)]
		ev.Framework = frameworks[i%len(frameworks)]
		ev.CloudProvider = cloudProviders[i%len(cloudProviders)]
		ev.AuthSystem = authSystems[i%len(authSystems)]

		// Add headers that some playbooks look for.
		ev.Headers["server"] = platforms[i%len(platforms)]
		ev.Headers["x-powered-by"] = frameworks[i%len(frameworks)]

		if i%3 == 0 {
			ev.IsKubernetes = true
		}
		if i%5 == 0 {
			ev.IsServerless = true
		}
		if i%7 == 0 {
			ev.Body512 = fmt.Sprintf("Powered by %s", platforms[i%len(platforms)])
		}

		evidenceSets[i] = ev
	}

	start := time.Now()

	for _, ev := range evidenceSets {
		matched := reg.Match(ev)
		// Just verify it doesn't panic and returns something.
		_ = matched
	}

	elapsed := time.Since(start)
	if elapsed > 2*time.Second {
		t.Errorf("playbook matching took %v (budget: 2s) — possible N^2 behavior", elapsed)
	}
	t.Logf("matched %d evidence sets against %d playbooks in %v", len(evidenceSets), len(all), elapsed)
}
