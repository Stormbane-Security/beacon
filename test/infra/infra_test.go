//go:build infra

package infra

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// TestDockerfileBuild verifies the Dockerfile builds successfully.
// Skipped if docker is not available.
//
// Run: go test ./test/infra/ -tags=infra -run=TestDockerfileBuild -timeout=10m
func TestDockerfileBuild(t *testing.T) {
	if !dockerAvailable() {
		t.Skip("docker not available")
	}

	projectRoot := findProjectRoot(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "build",
		"-t", "beacon-infra-test",
		"-f", filepath.Join(projectRoot, "Dockerfile"),
		projectRoot)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("docker build failed: %v", err)
	}

	// Clean up the image after the test.
	t.Cleanup(func() {
		_ = exec.Command("docker", "rmi", "-f", "beacon-infra-test").Run()
	})
}

// TestDockerImageRunsAndResponds builds the Docker image, starts a container,
// verifies it responds on the health check endpoint, then cleans up.
// Skipped if docker is not available.
//
// Run: go test ./test/infra/ -tags=infra -run=TestDockerImageRunsAndResponds -timeout=10m
func TestDockerImageRunsAndResponds(t *testing.T) {
	if !dockerAvailable() {
		t.Skip("docker not available")
	}

	projectRoot := findProjectRoot(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Build first.
	buildCmd := exec.CommandContext(ctx, "docker", "build",
		"-t", "beacon-run-test",
		"-f", filepath.Join(projectRoot, "Dockerfile"),
		projectRoot)
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("docker build failed: %v", err)
	}

	// Find a free port.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("finding free port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	containerName := fmt.Sprintf("beacon-run-test-%d", port)

	// Run the container with the API key set and port mapped.
	runCmd := exec.CommandContext(ctx, "docker", "run",
		"-d",
		"--name", containerName,
		"-p", fmt.Sprintf("%d:8080", port),
		"-e", "BEACON_API_KEY=test-infra-key",
		"beacon-run-test")
	out, err := runCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker run failed: %v\n%s", err, string(out))
	}

	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", containerName).Run()
		_ = exec.Command("docker", "rmi", "-f", "beacon-run-test").Run()
	})

	// Wait for the container to respond on the health endpoint.
	client := &http.Client{Timeout: 2 * time.Second}
	healthURL := fmt.Sprintf("http://127.0.0.1:%d/healthz", port)

	deadline := time.After(60 * time.Second)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	responded := false
	for !responded {
		select {
		case <-ctx.Done():
			t.Fatal("context cancelled waiting for container health check")
		case <-deadline:
			// Grab container logs for debugging.
			logsCmd := exec.Command("docker", "logs", containerName)
			logs, _ := logsCmd.CombinedOutput()
			t.Fatalf("container did not respond on %s within 60s\nlogs:\n%s", healthURL, string(logs))
		case <-ticker.C:
			resp, err := client.Get(healthURL)
			if err != nil {
				continue
			}
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				responded = true
			}
		}
	}

	// Verify the API responds to an authenticated request.
	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/v1/scans", port), nil)
	req.Header.Set("Authorization", "Bearer test-infra-key")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /v1/scans failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /v1/scans: expected 200, got %d", resp.StatusCode)
	}
}

// TestBinaryBuildsForTargetPlatforms verifies cross-compilation succeeds
// for linux/amd64 and linux/arm64.
//
// Run: go test ./test/infra/ -tags=infra -run=TestBinaryBuildsForTargetPlatforms -timeout=5m
func TestBinaryBuildsForTargetPlatforms(t *testing.T) {
	projectRoot := findProjectRoot(t)

	targets := []struct {
		goos   string
		goarch string
	}{
		{"linux", "amd64"},
		{"linux", "arm64"},
	}

	for _, tgt := range targets {
		name := fmt.Sprintf("%s/%s", tgt.goos, tgt.goarch)
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()

			// Build to /dev/null (or NUL on Windows).
			outPath := os.DevNull
			if runtime.GOOS == "windows" {
				outPath = "NUL"
			}

			cmd := exec.CommandContext(ctx, "go", "build", "-o", outPath, "./cmd/beacon/")
			cmd.Dir = projectRoot
			cmd.Env = append(os.Environ(),
				"GOOS="+tgt.goos,
				"GOARCH="+tgt.goarch,
				"CGO_ENABLED=0",
			)

			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("cross-compile %s failed: %v\n%s", name, err, string(output))
			}
		})
	}

	// Also verify the current platform builds.
	t.Run(runtime.GOOS+"/"+runtime.GOARCH, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()

		outPath := filepath.Join(t.TempDir(), "beacon-native")
		cmd := exec.CommandContext(ctx, "go", "build", "-o", outPath, "./cmd/beacon/")
		cmd.Dir = projectRoot

		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("native build failed: %v\n%s", err, string(output))
		}

		// Verify the binary was produced and is executable.
		info, err := os.Stat(outPath)
		if err != nil {
			t.Fatalf("stat built binary: %v", err)
		}
		if info.Size() == 0 {
			t.Error("built binary is empty")
		}

		// Quick smoke test: run --help.
		helpCmd := exec.CommandContext(ctx, outPath, "--help")
		if err := helpCmd.Run(); err != nil {
			// --help might exit non-zero on some CLIs; that's acceptable
			// as long as it doesn't crash (exit code 2 is typical for usage).
			if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() > 2 {
				t.Errorf("binary --help exited with code %d", exitErr.ExitCode())
			}
		}
	})
}

// TestMigrationSQLSyntax reads both migration files and verifies they contain
// valid SQL by executing them against a temporary in-memory SQLite database.
// The SQLite migration is fully validated; the Postgres migration is validated
// for basic SQL structure (Postgres-specific syntax like UUID types and
// gen_random_uuid() won't work in SQLite, so we validate parse structure).
//
// Run: go test ./test/infra/ -tags=infra -run=TestMigrationSQLSyntax -timeout=30s
func TestMigrationSQLSyntax(t *testing.T) {
	projectRoot := findProjectRoot(t)
	migrationsDir := filepath.Join(projectRoot, "migrations")

	t.Run("sqlite_migration_executes", func(t *testing.T) {
		sqlitePath := filepath.Join(migrationsDir, "0001_initial_schema.sql")
		sqlBytes, err := os.ReadFile(sqlitePath)
		if err != nil {
			t.Fatalf("reading SQLite migration: %v", err)
		}
		sqlContent := string(sqlBytes)
		if len(sqlContent) == 0 {
			t.Fatal("SQLite migration file is empty")
		}

		// Open an in-memory SQLite database and execute the migration.
		db, err := sql.Open("sqlite", ":memory:")
		if err != nil {
			t.Fatalf("opening in-memory sqlite: %v", err)
		}
		defer db.Close()

		if _, err := db.Exec(sqlContent); err != nil {
			t.Fatalf("executing SQLite migration: %v", err)
		}

		// Verify expected tables exist.
		expectedTables := []string{
			"targets",
			"scan_runs",
			"findings",
			"enriched_findings",
			"reports",
			"asset_executions",
			"unmatched_assets",
			"playbook_suggestions",
			"enrichment_cache",
			"correlation_findings",
			"finding_suppressions",
			"scanner_metrics",
			"discovery_audit",
			"sanitized_scanner_metrics",
			"fingerprint_rules",
			"asset_graphs",
		}

		for _, tbl := range expectedTables {
			var count int
			err := db.QueryRow(
				"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", tbl,
			).Scan(&count)
			if err != nil {
				t.Errorf("checking table %s: %v", tbl, err)
				continue
			}
			if count == 0 {
				t.Errorf("table %s was not created by the migration", tbl)
			}
		}

		// Verify expected indexes exist (spot check).
		expectedIndexes := []string{
			"idx_scan_runs_domain",
			"idx_findings_scan_run",
			"idx_findings_severity",
			"idx_scanner_metrics_scan_run",
			"idx_correlations_domain",
			"idx_suppressions_domain",
		}

		for _, idx := range expectedIndexes {
			var count int
			err := db.QueryRow(
				"SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?", idx,
			).Scan(&count)
			if err != nil {
				t.Errorf("checking index %s: %v", idx, err)
				continue
			}
			if count == 0 {
				t.Errorf("index %s was not created by the migration", idx)
			}
		}

		// Verify we can insert a row into each core table (schema is complete).
		_, err = db.Exec(`INSERT INTO targets (id, domain, created_at) VALUES ('t1', 'test.com', datetime('now'))`)
		if err != nil {
			t.Errorf("inserting into targets: %v", err)
		}
		_, err = db.Exec(`INSERT INTO scan_runs (id, target_id, domain, scan_type, status, started_at)
			VALUES ('sr1', 't1', 'test.com', 'surface', 'pending', datetime('now'))`)
		if err != nil {
			t.Errorf("inserting into scan_runs: %v", err)
		}
		_, err = db.Exec(`INSERT INTO findings (id, scan_run_id, check_id, module, scanner, severity, title, description, asset, discovered_at)
			VALUES ('f1', 'sr1', 'tls.cert_expiry', 'surface', 'tls', 'high', 'Cert expiry', 'Cert expires soon', 'test.com', datetime('now'))`)
		if err != nil {
			t.Errorf("inserting into findings: %v", err)
		}
	})

	t.Run("postgres_migration_structure", func(t *testing.T) {
		pgPath := filepath.Join(migrationsDir, "0001_postgres.sql")
		sqlBytes, err := os.ReadFile(pgPath)
		if err != nil {
			t.Fatalf("reading Postgres migration: %v", err)
		}
		sqlContent := string(sqlBytes)
		if len(sqlContent) == 0 {
			t.Fatal("Postgres migration file is empty")
		}

		// Verify it contains the same tables as the SQLite migration.
		expectedTables := []string{
			"targets",
			"scan_runs",
			"findings",
			"enriched_findings",
			"reports",
			"asset_executions",
			"unmatched_assets",
			"playbook_suggestions",
			"enrichment_cache",
			"correlation_findings",
			"finding_suppressions",
			"scanner_metrics",
			"discovery_audit",
			"sanitized_scanner_metrics",
			"fingerprint_rules",
			"asset_graphs",
		}

		for _, tbl := range expectedTables {
			if !strings.Contains(sqlContent, tbl) {
				t.Errorf("Postgres migration missing table: %s", tbl)
			}
		}

		// Verify it uses Postgres-specific types.
		pgFeatures := []string{
			"UUID",
			"TIMESTAMPTZ",
			"JSONB",
			"BYTEA",
			"gen_random_uuid()",
		}
		for _, feat := range pgFeatures {
			if !strings.Contains(sqlContent, feat) {
				t.Errorf("Postgres migration missing expected feature: %s", feat)
			}
		}

		// Verify foreign key constraints are present.
		fkCount := strings.Count(sqlContent, "REFERENCES")
		if fkCount < 10 {
			t.Errorf("expected at least 10 REFERENCES constraints, found %d", fkCount)
		}

		// Verify CREATE INDEX statements.
		idxCount := strings.Count(sqlContent, "CREATE INDEX")
		if idxCount < 10 {
			t.Errorf("expected at least 10 CREATE INDEX statements, found %d", idxCount)
		}
	})
}

// dockerAvailable returns true if the docker CLI is functional.
func dockerAvailable() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "info")
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run() == nil
}

// findProjectRoot walks up from the test file's directory to find the
// project root (containing go.mod).
func findProjectRoot(t *testing.T) string {
	t.Helper()

	// Start from the known project path.
	root := "/Users/patrick/beacon"

	// Fall back to walking up from the current working directory.
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		dir, err := os.Getwd()
		if err != nil {
			t.Fatalf("getting working directory: %v", err)
		}
		for {
			if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
				return dir
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				t.Fatal("could not find project root (go.mod)")
			}
			dir = parent
		}
	}

	return root
}
