package githubactions_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
	"github.com/stormbane/beacon/internal/scanner/githubactions"
)

// ── helpers ──────────────────────────────────────────────────────────────────

func hasCheckID(findings []finding.Finding, id finding.CheckID) bool {
	for _, f := range findings {
		if f.CheckID == id {
			return true
		}
	}
	return false
}

func findByCheckID(findings []finding.Finding, id finding.CheckID) *finding.Finding {
	for _, f := range findings {
		if f.CheckID == id {
			return &f
		}
	}
	return nil
}

func countByCheckID(findings []finding.Finding, id finding.CheckID) int {
	n := 0
	for _, f := range findings {
		if f.CheckID == id {
			n++
		}
	}
	return n
}

// mockGitHubAPI creates an httptest server that serves:
//  1. /package.json → a package.json with repository pointing to owner/repo
//  2. /repos/{owner}/{repo}/contents/.github/workflows → workflow file listing
//  3. Each workflow's download_url → raw YAML content
//
// The workflows parameter maps filename to YAML content.
func mockGitHubAPI(t *testing.T, owner, repo string, workflows map[string]string) (*httptest.Server, *httptest.Server) {
	t.Helper()

	// GitHub API mock
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Workflow listing
		workflowDir := fmt.Sprintf("/repos/%s/%s/contents/.github/workflows", owner, repo)
		if path == workflowDir {
			var entries []map[string]string
			for name := range workflows {
				entries = append(entries, map[string]string{
					"name":         name,
					"path":         ".github/workflows/" + name,
					"download_url": "http://" + r.Host + "/raw/" + name,
				})
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(entries)
			return
		}

		// Raw workflow content
		if strings.HasPrefix(path, "/raw/") {
			name := strings.TrimPrefix(path, "/raw/")
			if content, ok := workflows[name]; ok {
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprint(w, content)
				return
			}
		}

		w.WriteHeader(http.StatusNotFound)
	}))

	// Asset server mock (serves package.json that links to the repo)
	assetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/package.json" {
			pkg := map[string]any{
				"name":       "test-app",
				"repository": fmt.Sprintf("https://github.com/%s/%s", owner, repo),
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(pkg)
			return
		}
		if r.URL.Path == "/" {
			fmt.Fprintf(w, `<html><body><a href="https://github.com/%s/%s">GitHub</a></body></html>`, owner, repo)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))

	return apiServer, assetServer
}

// redirectTransport intercepts HTTP requests to api.github.com and the asset
// server, redirecting them to test servers.
type redirectTransport struct {
	apiURL    string
	assetHost string // host:port of the asset server
	assetURL  string
	wrapped   http.RoundTripper
}

func (t *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Redirect GitHub API requests
	if req.URL.Host == "api.github.com" {
		newURL := t.apiURL + req.URL.Path
		newReq, err := http.NewRequestWithContext(req.Context(), req.Method, newURL, req.Body)
		if err != nil {
			return nil, err
		}
		for k, v := range req.Header {
			newReq.Header[k] = v
		}
		return t.wrapped.RoundTrip(newReq)
	}

	// Redirect asset server requests (the scanner tries https then http)
	if req.URL.Host == t.assetHost {
		newURL := t.assetURL + req.URL.Path
		newReq, err := http.NewRequestWithContext(req.Context(), req.Method, newURL, req.Body)
		if err != nil {
			return nil, err
		}
		for k, v := range req.Header {
			newReq.Header[k] = v
		}
		return t.wrapped.RoundTrip(newReq)
	}

	return t.wrapped.RoundTrip(req)
}

// runScanner sets up the transport redirect and runs the scanner.
func runScanner(t *testing.T, apiURL, assetHost, assetURL string, workflows map[string]string) ([]finding.Finding, error) {
	t.Helper()

	origTransport := http.DefaultTransport
	http.DefaultTransport = &redirectTransport{
		apiURL:    apiURL,
		assetHost: assetHost,
		assetURL:  assetURL,
		wrapped:   origTransport,
	}
	defer func() { http.DefaultTransport = origTransport }()

	s := githubactions.New("")
	return s.Run(context.Background(), assetHost, module.ScanSurface)
}

// ── Test: scanner name ───────────────────────────────────────────────────────

func TestName(t *testing.T) {
	s := githubactions.New("")
	if s.Name() != "githubactions" {
		t.Errorf("Name() = %q; want %q", s.Name(), "githubactions")
	}
}

// ── Test: cancelled context ──────────────────────────────────────────────────

func TestRun_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	s := githubactions.New("")
	findings, err := s.Run(ctx, "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings on cancelled ctx, got %d", len(findings))
	}
}

// ── Test: no repo discovered → no findings ──────────────────────────────────

func TestRun_NoRepoDiscovered(t *testing.T) {
	// Asset server that has no package.json or GitHub links
	assetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer assetServer.Close()

	asset := strings.TrimPrefix(assetServer.URL, "http://")

	origTransport := http.DefaultTransport
	http.DefaultTransport = &redirectTransport{
		apiURL:    "http://unused",
		assetHost: asset,
		assetURL:  assetServer.URL,
		wrapped:   origTransport,
	}
	defer func() { http.DefaultTransport = origTransport }()

	s := githubactions.New("")
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when no repo discovered, got %d", len(findings))
	}
}

// ── Test: repo discovered → emits repo_discovered finding ───────────────────

func TestRun_RepoDiscovered(t *testing.T) {
	safeWorkflow := `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
      - run: echo "Hello"
`
	apiServer, assetServer := mockGitHubAPI(t, "acme", "webapp", map[string]string{
		"ci.yml": safeWorkflow,
	})
	defer apiServer.Close()
	defer assetServer.Close()

	asset := strings.TrimPrefix(assetServer.URL, "http://")
	findings, err := runScanner(t, apiServer.URL, asset, assetServer.URL, map[string]string{"ci.yml": safeWorkflow})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckGHActionRepoDiscovered) {
		t.Error("expected repo_discovered finding")
	}

	f := findByCheckID(findings, finding.CheckGHActionRepoDiscovered)
	if f != nil {
		if f.Severity != finding.SeverityInfo {
			t.Errorf("repo_discovered severity = %v; want Info", f.Severity)
		}
		if f.Scanner != "githubactions" {
			t.Errorf("scanner = %q; want %q", f.Scanner, "githubactions")
		}
	}
}

// ── Test: pull_request_target + checkout PR head → Critical ─────────────────

func TestRun_PRTargetUnsafe(t *testing.T) {
	dangerousWorkflow := `
name: PR Check
on:
  pull_request_target:
    types: [opened, synchronize]
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm test
`
	apiServer, assetServer := mockGitHubAPI(t, "acme", "webapp", map[string]string{
		"pr-check.yml": dangerousWorkflow,
	})
	defer apiServer.Close()
	defer assetServer.Close()

	asset := strings.TrimPrefix(assetServer.URL, "http://")
	findings, err := runScanner(t, apiServer.URL, asset, assetServer.URL, map[string]string{"pr-check.yml": dangerousWorkflow})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckGHActionPRTargetUnsafe) {
		t.Error("expected pull_request_target_unsafe finding")
	}

	f := findByCheckID(findings, finding.CheckGHActionPRTargetUnsafe)
	if f != nil {
		if f.Severity != finding.SeverityCritical {
			t.Errorf("pr_target severity = %v; want Critical", f.Severity)
		}
		if f.ProofCommand == "" {
			t.Error("ProofCommand must be set")
		}
	}
}

// ── Test: secrets in PR-triggered workflow → Critical ───────────────────────

func TestRun_SecretsInPRWorkflow(t *testing.T) {
	workflow := `
name: PR Deploy
on:
  pull_request:
    branches: [main]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
      - run: echo "deploying"
        env:
          API_KEY: ${{ secrets.DEPLOY_API_KEY }}
          DB_PASS: ${{ secrets.DATABASE_PASSWORD }}
`
	apiServer, assetServer := mockGitHubAPI(t, "acme", "webapp", map[string]string{
		"deploy.yml": workflow,
	})
	defer apiServer.Close()
	defer assetServer.Close()

	asset := strings.TrimPrefix(assetServer.URL, "http://")
	findings, err := runScanner(t, apiServer.URL, asset, assetServer.URL, map[string]string{"deploy.yml": workflow})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckGHActionSecretsEchoed) {
		t.Error("expected secrets_echoed finding for PR workflow with secrets")
	}

	f := findByCheckID(findings, finding.CheckGHActionSecretsEchoed)
	if f != nil {
		if f.Severity != finding.SeverityCritical {
			t.Errorf("secrets_echoed severity = %v; want Critical", f.Severity)
		}
	}
}

// ── Test: overly broad permissions → High ───────────────────────────────────

func TestRun_OverlyBroadPermissions(t *testing.T) {
	workflow := `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    permissions: write-all
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
      - run: echo "build"
`
	apiServer, assetServer := mockGitHubAPI(t, "acme", "webapp", map[string]string{
		"ci.yml": workflow,
	})
	defer apiServer.Close()
	defer assetServer.Close()

	asset := strings.TrimPrefix(assetServer.URL, "http://")
	findings, err := runScanner(t, apiServer.URL, asset, assetServer.URL, map[string]string{"ci.yml": workflow})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckGHActionOverpermissioned) {
		t.Error("expected overpermissioned finding for write-all permissions")
	}

	f := findByCheckID(findings, finding.CheckGHActionOverpermissioned)
	if f != nil {
		if f.Severity != finding.SeverityHigh {
			t.Errorf("overpermissioned severity = %v; want High", f.Severity)
		}
	}
}

// ── Test: mutable action ref (not pinned to SHA) → Medium ───────────────────

func TestRun_UnpinnedAction(t *testing.T) {
	workflow := `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: some-third-party/action@main
`
	apiServer, assetServer := mockGitHubAPI(t, "acme", "webapp", map[string]string{
		"ci.yml": workflow,
	})
	defer apiServer.Close()
	defer assetServer.Close()

	asset := strings.TrimPrefix(assetServer.URL, "http://")
	findings, err := runScanner(t, apiServer.URL, asset, assetServer.URL, map[string]string{"ci.yml": workflow})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckGHActionUnpinned) {
		t.Error("expected unpinned_action finding for tag-based action refs")
	}

	// Should emit at least 2 unpinned findings (one for each unpinned action)
	count := countByCheckID(findings, finding.CheckGHActionUnpinned)
	if count < 2 {
		t.Errorf("expected at least 2 unpinned findings, got %d", count)
	}
}

// ── Test: pinned SHA actions → no unpinned finding ──────────────────────────

func TestRun_PinnedAction_NoFinding(t *testing.T) {
	workflow := `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
      - uses: actions/setup-node@b39b52d1213e96004bfcb1c61a8a6fa8ab84f3e8
`
	apiServer, assetServer := mockGitHubAPI(t, "acme", "webapp", map[string]string{
		"ci.yml": workflow,
	})
	defer apiServer.Close()
	defer assetServer.Close()

	asset := strings.TrimPrefix(assetServer.URL, "http://")
	findings, err := runScanner(t, apiServer.URL, asset, assetServer.URL, map[string]string{"ci.yml": workflow})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckGHActionUnpinned) {
		t.Error("should not emit unpinned_action for SHA-pinned actions")
	}
}

// ── Test: shell injection via GitHub context fields → High ──────────────────

func TestRun_ScriptInjection(t *testing.T) {
	workflow := `
name: PR Title Check
on: pull_request
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "PR title: ${{ github.event.pull_request.title }}"
`
	apiServer, assetServer := mockGitHubAPI(t, "acme", "webapp", map[string]string{
		"title-check.yml": workflow,
	})
	defer apiServer.Close()
	defer assetServer.Close()

	asset := strings.TrimPrefix(assetServer.URL, "http://")
	findings, err := runScanner(t, apiServer.URL, asset, assetServer.URL, map[string]string{"title-check.yml": workflow})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckGHActionScriptInjection) {
		t.Errorf("expected script_injection finding for PR title interpolation in run: step")
	}

	f := findByCheckID(findings, finding.CheckGHActionScriptInjection)
	if f != nil {
		if f.Severity != finding.SeverityHigh {
			t.Errorf("script_injection severity = %v; want High", f.Severity)
		}
	}
}

// ── Test: self-hosted runner on PR workflow → High ──────────────────────────

func TestRun_SelfHostedOnPR(t *testing.T) {
	workflow := `
name: CI
on: pull_request
jobs:
  build:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
      - run: make build
`
	apiServer, assetServer := mockGitHubAPI(t, "acme", "webapp", map[string]string{
		"ci.yml": workflow,
	})
	defer apiServer.Close()
	defer assetServer.Close()

	asset := strings.TrimPrefix(assetServer.URL, "http://")
	findings, err := runScanner(t, apiServer.URL, asset, assetServer.URL, map[string]string{"ci.yml": workflow})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckGHActionSelfHostedPublic) {
		t.Error("expected self_hosted_on_public_repo finding for self-hosted runner on PR workflow")
	}

	f := findByCheckID(findings, finding.CheckGHActionSelfHostedPublic)
	if f != nil {
		if f.Severity != finding.SeverityHigh {
			t.Errorf("self_hosted severity = %v; want High", f.Severity)
		}
	}
}

// ── Test: workflow_run + artifacts + secrets → High ─────────────────────────

func TestRun_WorkflowRunArtifactPoisoning(t *testing.T) {
	workflow := `
name: Deploy
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions: write-all
    steps:
      - uses: actions/download-artifact@v4
      - run: ./deploy.sh
        env:
          TOKEN: ${{ secrets.DEPLOY_TOKEN }}
`
	apiServer, assetServer := mockGitHubAPI(t, "acme", "webapp", map[string]string{
		"deploy.yml": workflow,
	})
	defer apiServer.Close()
	defer assetServer.Close()

	asset := strings.TrimPrefix(assetServer.URL, "http://")
	findings, err := runScanner(t, apiServer.URL, asset, assetServer.URL, map[string]string{"deploy.yml": workflow})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckGHActionWorkflowRunUnsafe) {
		t.Error("expected workflow_run_unsafe finding for artifact + secrets combination")
	}
}

// ── Test: long-lived AWS credentials → High ─────────────────────────────────

func TestRun_LongLivedAWSCredentials(t *testing.T) {
	workflow := `
name: Deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
`
	apiServer, assetServer := mockGitHubAPI(t, "acme", "webapp", map[string]string{
		"deploy.yml": workflow,
	})
	defer apiServer.Close()
	defer assetServer.Close()

	asset := strings.TrimPrefix(assetServer.URL, "http://")
	findings, err := runScanner(t, apiServer.URL, asset, assetServer.URL, map[string]string{"deploy.yml": workflow})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckGHActionAWSLongLivedKey) {
		t.Error("expected aws_long_lived_key finding for static AWS credentials")
	}

	f := findByCheckID(findings, finding.CheckGHActionAWSLongLivedKey)
	if f != nil {
		if f.Severity != finding.SeverityHigh {
			t.Errorf("aws_long_lived_key severity = %v; want High", f.Severity)
		}
	}
}

// ── Test: long-lived GCP credentials → High ─────────────────────────────────

func TestRun_LongLivedGCPCredentials(t *testing.T) {
	workflow := `
name: Deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
      - run: echo "$KEY" > /tmp/key.json
        env:
          KEY: ${{ secrets.GCP_SA_KEY }}
`
	apiServer, assetServer := mockGitHubAPI(t, "acme", "webapp", map[string]string{
		"deploy.yml": workflow,
	})
	defer apiServer.Close()
	defer assetServer.Close()

	asset := strings.TrimPrefix(assetServer.URL, "http://")
	findings, err := runScanner(t, apiServer.URL, asset, assetServer.URL, map[string]string{"deploy.yml": workflow})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckGHActionGCPServiceAccountKey) {
		t.Error("expected gcp_service_account_key finding for GCP_SA_KEY")
	}
}

// ── Test: safe workflow produces no security findings ────────────────────────

func TestRun_SafeWorkflow_NoSecurityFindings(t *testing.T) {
	workflow := `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
      - uses: actions/setup-node@b39b52d1213e96004bfcb1c61a8a6fa8ab84f3e8
      - run: npm ci
      - run: npm test
`
	apiServer, assetServer := mockGitHubAPI(t, "acme", "webapp", map[string]string{
		"ci.yml": workflow,
	})
	defer apiServer.Close()
	defer assetServer.Close()

	asset := strings.TrimPrefix(assetServer.URL, "http://")
	findings, err := runScanner(t, apiServer.URL, asset, assetServer.URL, map[string]string{"ci.yml": workflow})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should only have info findings (repo_discovered, etc.), no security findings
	securityCheckIDs := []finding.CheckID{
		finding.CheckGHActionPRTargetUnsafe,
		finding.CheckGHActionSecretsEchoed,
		finding.CheckGHActionOverpermissioned,
		finding.CheckGHActionScriptInjection,
		finding.CheckGHActionSelfHostedPublic,
		finding.CheckGHActionWorkflowRunUnsafe,
		finding.CheckGHActionAWSLongLivedKey,
		finding.CheckGHActionGCPServiceAccountKey,
		finding.CheckGHActionAzureCredentials,
	}

	for _, checkID := range securityCheckIDs {
		if hasCheckID(findings, checkID) {
			t.Errorf("safe workflow should not trigger %s", checkID)
		}
	}
}

// ── Test: no workflow files → only repo_discovered ──────────────────────────

func TestRun_NoWorkflows(t *testing.T) {
	// API server that returns 404 for workflows directory
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer apiServer.Close()

	// Asset server that exposes a package.json
	assetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/package.json" {
			pkg := map[string]any{
				"name":       "test-app",
				"repository": "https://github.com/acme/webapp",
			}
			json.NewEncoder(w).Encode(pkg)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer assetServer.Close()

	asset := strings.TrimPrefix(assetServer.URL, "http://")

	origTransport := http.DefaultTransport
	http.DefaultTransport = &redirectTransport{
		apiURL:    apiServer.URL,
		assetHost: asset,
		assetURL:  assetServer.URL,
		wrapped:   origTransport,
	}
	defer func() { http.DefaultTransport = origTransport }()

	s := githubactions.New("")
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// No workflows = no findings (scanner returns nil when fetchWorkflows returns empty)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when no workflows exist, got %d", len(findings))
	}
}

// ── Test: multiple vulnerabilities in one workflow ──────────────────────────

func TestRun_MultipleVulnerabilities(t *testing.T) {
	// A truly terrible workflow with multiple issues
	workflow := `
name: Dangerous PR Handler
on:
  pull_request_target:
    types: [opened]
jobs:
  build:
    runs-on: self-hosted
    permissions: write-all
    steps:
      - uses: actions/checkout@v4
        with:
          ref: "${{ github.event.pull_request.head.sha }}"
      - uses: some-third-party/deploy@latest
      - run: |
          echo "PR: ${{ github.event.pull_request.title }}"
        env:
          SECRET: "${{ secrets.DEPLOY_KEY }}"
          AWS_ACCESS_KEY_ID: "${{ secrets.AWS_ACCESS_KEY_ID }}"
          AWS_SECRET_ACCESS_KEY: "${{ secrets.AWS_SECRET_ACCESS_KEY }}"
`
	apiServer, assetServer := mockGitHubAPI(t, "acme", "webapp", map[string]string{
		"dangerous.yml": workflow,
	})
	defer apiServer.Close()
	defer assetServer.Close()

	asset := strings.TrimPrefix(assetServer.URL, "http://")
	findings, err := runScanner(t, apiServer.URL, asset, assetServer.URL, map[string]string{"dangerous.yml": workflow})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should find many issues
	expected := []finding.CheckID{
		finding.CheckGHActionPRTargetUnsafe,
		finding.CheckGHActionSecretsEchoed,
		finding.CheckGHActionOverpermissioned,
		finding.CheckGHActionUnpinned,
		finding.CheckGHActionScriptInjection,
		finding.CheckGHActionSelfHostedPublic,
		finding.CheckGHActionAWSLongLivedKey,
	}

	for _, checkID := range expected {
		if !hasCheckID(findings, checkID) {
			t.Errorf("missing expected finding: %s", checkID)
		}
	}
}

// ── Test: deploy target extraction ──────────────────────────────────────────

func TestRun_DeployTargetExtraction(t *testing.T) {
	workflow := `
name: Deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
      - run: flyctl deploy
        env:
          FLY_APP: myapp.fly.dev
          PROD_URL: https://api.production.example.com/v1
`
	apiServer, assetServer := mockGitHubAPI(t, "acme", "webapp", map[string]string{
		"deploy.yml": workflow,
	})
	defer apiServer.Close()
	defer assetServer.Close()

	asset := strings.TrimPrefix(assetServer.URL, "http://")
	findings, err := runScanner(t, apiServer.URL, asset, assetServer.URL, map[string]string{"deploy.yml": workflow})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckGHActionDeployTargets) {
		t.Error("expected deploy_targets finding with extracted deployment URLs")
	}
}

// ── Test: head_ref context injection ────────────────────────────────────────

func TestRun_HeadRefInjection(t *testing.T) {
	workflow := `
name: Branch Check
on: pull_request
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "Branch: ${{ github.head_ref }}"
`
	apiServer, assetServer := mockGitHubAPI(t, "acme", "webapp", map[string]string{
		"branch.yml": workflow,
	})
	defer apiServer.Close()
	defer assetServer.Close()

	asset := strings.TrimPrefix(assetServer.URL, "http://")
	findings, err := runScanner(t, apiServer.URL, asset, assetServer.URL, map[string]string{"branch.yml": workflow})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckGHActionScriptInjection) {
		t.Error("expected script_injection finding for github.head_ref interpolation")
	}
}

// ── Test: workflow with malformed YAML → silently skipped ───────────────────

func TestRun_MalformedYAML(t *testing.T) {
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if strings.Contains(path, "contents/.github/workflows") {
			entries := []map[string]string{
				{
					"name":         "broken.yml",
					"path":         ".github/workflows/broken.yml",
					"download_url": "http://" + r.Host + "/raw/broken.yml",
				},
			}
			json.NewEncoder(w).Encode(entries)
			return
		}
		if path == "/raw/broken.yml" {
			// Invalid YAML
			fmt.Fprint(w, "{{{{not valid yaml: [")
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer apiServer.Close()

	assetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/package.json" {
			json.NewEncoder(w).Encode(map[string]any{
				"repository": "https://github.com/acme/webapp",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer assetServer.Close()

	asset := strings.TrimPrefix(assetServer.URL, "http://")

	origTransport := http.DefaultTransport
	http.DefaultTransport = &redirectTransport{
		apiURL:    apiServer.URL,
		assetHost: asset,
		assetURL:  assetServer.URL,
		wrapped:   origTransport,
	}
	defer func() { http.DefaultTransport = origTransport }()

	s := githubactions.New("")
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Malformed YAML should be silently skipped — no findings (and no repo_discovered
	// since there are no valid workflows to scan)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for malformed YAML, got %d", len(findings))
	}
}

// ── Test: Azure credentials detection ───────────────────────────────────────

func TestRun_LongLivedAzureCredentials(t *testing.T) {
	workflow := `
name: Deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
      - uses: azure/login@v1
        with:
          creds: ${{ secrets.AZURE_CREDENTIALS }}
`
	apiServer, assetServer := mockGitHubAPI(t, "acme", "webapp", map[string]string{
		"deploy.yml": workflow,
	})
	defer apiServer.Close()
	defer assetServer.Close()

	asset := strings.TrimPrefix(assetServer.URL, "http://")
	findings, err := runScanner(t, apiServer.URL, asset, assetServer.URL, map[string]string{"deploy.yml": workflow})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckGHActionAzureCredentials) {
		t.Error("expected azure_credentials finding for AZURE_CREDENTIALS")
	}
}

// ── Test: local action refs (./) are not flagged ─────────────────────────────

func TestRun_LocalActionRefNotFlagged(t *testing.T) {
	workflow := `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
      - uses: ./.github/actions/custom-action
`
	apiServer, assetServer := mockGitHubAPI(t, "acme", "webapp", map[string]string{
		"ci.yml": workflow,
	})
	defer apiServer.Close()
	defer assetServer.Close()

	asset := strings.TrimPrefix(assetServer.URL, "http://")
	findings, err := runScanner(t, apiServer.URL, asset, assetServer.URL, map[string]string{"ci.yml": workflow})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Local action refs (./) should not be flagged as unpinned
	for _, f := range findings {
		if f.CheckID == finding.CheckGHActionUnpinned {
			ev, ok := f.Evidence["action"].(string)
			if ok && strings.HasPrefix(ev, "./") {
				t.Error("local action ref (./) should not be flagged as unpinned")
			}
		}
	}
}