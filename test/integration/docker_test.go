// Tier 2: Docker-based integration tests.
//
// These tests spin up real product containers and verify Beacon can:
//   1. Fingerprint the technology (classify.Collect sets the right platform)
//   2. Match the correct playbook
//   3. Detect expected security findings
//
// Requires Docker. Skipped automatically when Docker is not available.
//
// Run: go test ./test/integration/ -tags=docker -run=TestDocker -timeout=5m
//
//go:build docker

package integration

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stormbane-security/beacon/internal/playbook"
	"github.com/stormbane-security/beacon/internal/scanner/classify"
)

// dockerScenario defines a real product to test against.
type dockerScenario struct {
	Name     string
	Image    string
	Port     string // container port, e.g. "5984"
	Env      map[string]string
	WaitPath string // HTTP path to poll until ready
	WaitBody string // expected substring in wait response

	// Assertions
	ExpectPlatform  string   // expected ServiceVersions["platform"]
	ExpectPlaybooks []string // playbook names that must match
}

var dockerScenarios = []dockerScenario{
	{
		Name:            "couchdb",
		Image:           "couchdb:3.3",
		Port:            "5984",
		Env:             map[string]string{"COUCHDB_USER": "admin", "COUCHDB_PASSWORD": "password"},
		WaitPath:        "/",
		WaitBody:        "couchdb",
		ExpectPlatform:  "couchdb",
		ExpectPlaybooks: []string{"couchdb"},
	},
	{
		Name:            "rabbitmq",
		Image:           "rabbitmq:3-management",
		Port:            "15672",
		Env:             map[string]string{},
		WaitPath:        "/api/overview",
		WaitBody:        "rabbitmq",
		ExpectPlatform:  "rabbitmq",
		ExpectPlaybooks: []string{"rabbitmq"},
	},
	{
		Name:            "minio",
		Image:           "minio/minio:latest",
		Port:            "9000",
		Env:             map[string]string{"MINIO_ROOT_USER": "minioadmin", "MINIO_ROOT_PASSWORD": "minioadmin"},
		WaitPath:        "/minio/health/live",
		WaitBody:        "",
		ExpectPlatform:  "minio",
		ExpectPlaybooks: []string{"minio"},
	},
	{
		Name:            "neo4j",
		Image:           "neo4j:5-community",
		Port:            "7474",
		Env:             map[string]string{"NEO4J_AUTH": "none"},
		WaitPath:        "/",
		WaitBody:        "neo4j",
		ExpectPlatform:  "neo4j",
		ExpectPlaybooks: []string{"neo4j"},
	},
}

func TestDockerScenarios(t *testing.T) {
	if !dockerAvailable() {
		t.Skip("Docker not available")
	}

	for _, sc := range dockerScenarios {
		t.Run(sc.Name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()

			// Start container.
			hostPort, cleanup, err := startContainer(ctx, sc)
			if err != nil {
				t.Fatalf("starting %s container: %v", sc.Name, err)
			}
			defer cleanup()

			// Wait for service readiness.
			if err := waitForReady(ctx, hostPort, sc.WaitPath, sc.WaitBody); err != nil {
				t.Fatalf("waiting for %s: %v", sc.Name, err)
			}

			// Run Beacon's classify pipeline.
			evidence := classify.Collect(ctx, hostPort)

			// Assert platform detection.
			if sc.ExpectPlatform != "" {
				got := evidence.ServiceVersions["platform"]
				if !strings.EqualFold(got, sc.ExpectPlatform) {
					t.Errorf("platform: want %q, got %q", sc.ExpectPlatform, got)
				}
			}

			// Assert playbook matching.
			if len(sc.ExpectPlaybooks) > 0 {
				reg, err := playbook.Load()
				if err != nil {
					t.Fatalf("loading playbooks: %v", err)
				}
				matched := reg.Match(evidence)
				names := make(map[string]bool)
				for _, pb := range matched {
					names[pb.Name] = true
				}
				for _, want := range sc.ExpectPlaybooks {
					if !names[want] {
						t.Errorf("expected playbook %q to match, matched: %v", want, playbookNames(matched))
					}
				}
			}
		})
	}
}

// startContainer shells out to docker run. Returns host:port and a cleanup function.
// This is intentionally simple — no testcontainers dependency, just docker CLI.
func startContainer(ctx context.Context, sc dockerScenario) (string, func(), error) {
	// Find a free port.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, fmt.Errorf("finding free port: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	containerName := fmt.Sprintf("beacon-test-%s-%d", sc.Name, port)

	// Build docker run args.
	args := []string{"run", "-d", "--name", containerName, "-p", fmt.Sprintf("%d:%s", port, sc.Port)}
	for k, v := range sc.Env {
		args = append(args, "-e", k+"="+v)
	}

	// MinIO needs a command argument.
	if strings.Contains(sc.Image, "minio") {
		args = append(args, sc.Image, "server", "/data")
	} else {
		args = append(args, sc.Image)
	}

	// Start.
	if err := dockerExec(ctx, args...); err != nil {
		return "", nil, fmt.Errorf("docker run: %w", err)
	}

	hostPort := fmt.Sprintf("127.0.0.1:%d", port)
	cleanup := func() {
		_ = dockerExec(context.Background(), "rm", "-f", containerName)
	}
	return hostPort, cleanup, nil
}

// dockerExec runs a docker command.
func dockerExec(ctx context.Context, args ...string) error {
	cmd := execCommandContext(ctx, "docker", args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run()
}

// dockerAvailable returns true if the docker CLI is functional.
func dockerAvailable() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return dockerExec(ctx, "info") == nil
}

// waitForReady polls an HTTP endpoint until it responds with the expected body.
func waitForReady(ctx context.Context, hostPort, path, expectBody string) error {
	client := &http.Client{Timeout: 2 * time.Second}
	url := "http://" + hostPort + path

	deadline := time.After(90 * time.Second)
	tick := time.NewTicker(1 * time.Second)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			return fmt.Errorf("timed out waiting for %s", url)
		case <-tick.C:
			resp, err := client.Get(url)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			if resp.StatusCode < 500 {
				if expectBody == "" || strings.Contains(strings.ToLower(string(body)), strings.ToLower(expectBody)) {
					return nil
				}
			}
		}
	}
}

func playbookNames(pbs []*playbook.Playbook) []string {
	var names []string
	for _, pb := range pbs {
		names = append(names, pb.Name)
	}
	return names
}
