package circleci_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanner/circleci"
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

func countByCheckID(findings []finding.Finding, id finding.CheckID) int {
	n := 0
	for _, f := range findings {
		if f.CheckID == id {
			n++
		}
	}
	return n
}

func findByCheckID(findings []finding.Finding, id finding.CheckID) *finding.Finding {
	for _, f := range findings {
		if f.CheckID == id {
			return &f
		}
	}
	return nil
}

// redirectTransport intercepts HTTP requests to api.github.com and sends
// them to the local httptest server instead.
type redirectTransport struct {
	testURL string
	wrapped http.RoundTripper
}

func (t *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == "api.github.com" {
		newURL := t.testURL + req.URL.Path
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

// ghFileContent mirrors the GitHub Contents API response structure.
type ghFileContent struct {
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
}

// mockGitHubAPI creates an httptest server that serves CircleCI config YAML at
// /repos/{owner}/{repo}/contents/.circleci/config.yml.
func mockGitHubAPI(t *testing.T, owner, repo, configYAML string, statusCode int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expected := fmt.Sprintf("/repos/%s/%s/contents/.circleci/config.yml", owner, repo)
		if r.URL.Path == expected {
			if statusCode != http.StatusOK {
				w.WriteHeader(statusCode)
				return
			}
			resp := ghFileContent{
				Content:  base64.StdEncoding.EncodeToString([]byte(configYAML)),
				Encoding: "base64",
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(statusCode)
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
}

// runScanner sets up the transport redirect and runs the CircleCI scanner.
func runScanner(t *testing.T, ts *httptest.Server, target string, scanType module.ScanType) ([]finding.Finding, error) {
	t.Helper()
	origTransport := http.DefaultTransport
	http.DefaultTransport = &redirectTransport{
		testURL: ts.URL,
		wrapped: origTransport,
	}
	defer func() { http.DefaultTransport = origTransport }()

	s := circleci.New("") // no token = public repo
	return s.Run(context.Background(), target, scanType)
}

// ── scanner name ─────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	s := circleci.New("")
	if s.Name() != "circleci" {
		t.Errorf("Name() = %q; want %q", s.Name(), "circleci")
	}
}

// ── invalid target ───────────────────────────────────────────────────────────

func TestInvalidTarget_ReturnsError(t *testing.T) {
	s := circleci.New("")
	_, err := s.Run(context.Background(), "invalid-no-slash", module.ScanSurface)
	if err == nil {
		t.Fatal("expected error for invalid target, got nil")
	}
}

// ── ScanSurface — public config ──────────────────────────────────────────────

func TestScanSurface_PublicConfig_Detected(t *testing.T) {
	yaml := `
version: 2.1
jobs:
  build:
    docker:
      - image: node:18
    steps:
      - checkout
      - run: npm install
      - run: npm test
`
	ts := mockGitHubAPI(t, "myorg", "myrepo", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "myorg/myrepo", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckCircleCIPublicConfig) {
		t.Error("expected CheckCircleCIPublicConfig finding for publicly accessible config")
	}
}

func TestScanSurface_PublicConfig_HasCorrectSeverity(t *testing.T) {
	yaml := `
version: 2.1
jobs:
  build:
    docker:
      - image: golang:1.22
    steps:
      - checkout
      - run: go build ./...
`
	ts := mockGitHubAPI(t, "myorg", "myrepo", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "myorg/myrepo", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	f := findByCheckID(findings, finding.CheckCircleCIPublicConfig)
	if f == nil {
		t.Fatal("expected CheckCircleCIPublicConfig finding")
	}
	if f.Severity != finding.SeverityInfo {
		t.Errorf("expected SeverityInfo, got %v", f.Severity)
	}
}

// ── ScanSurface — all checks run ─────────────────────────────────────────────

func TestScanSurface_DetectsAllIssues(t *testing.T) {
	yaml := `
version: 2.1
jobs:
  build:
    docker:
      - image: node:18
    steps:
      - checkout
      - setup_remote_docker
      - run:
          no_output_timeout: 0
          command: |
            echo $SECRET_TOKEN
            npm install
            npm test
      - store_artifacts:
          path: ~/.ssh
  deploy:
    machine: true
    steps:
      - checkout
      - run: deploy.sh
workflows:
  main:
    jobs:
      - build:
          context: my-org-context
      - deploy
`
	ts := mockGitHubAPI(t, "myorg", "myrepo", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "myorg/myrepo", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckCircleCIUnpinnedImage) {
		t.Error("expected unpinned image finding for node:18")
	}
	if !hasCheckID(findings, finding.CheckCircleCISecretEchoed) {
		t.Error("expected secret echoed finding for echo $SECRET_TOKEN")
	}
	if !hasCheckID(findings, finding.CheckCircleCIInsecureStep) {
		t.Error("expected insecure step finding")
	}
	if !hasCheckID(findings, finding.CheckCircleCIUnconstrained) {
		t.Error("expected unconstrained context finding")
	}
	if !hasCheckID(findings, finding.CheckCircleCIMachineExecutor) {
		t.Error("expected machine executor finding")
	}
}

// ── unpinned images ──────────────────────────────────────────────────────────

func TestUnpinnedImage_MutableTag_Detected(t *testing.T) {
	yaml := `
version: 2.1
jobs:
  build:
    docker:
      - image: python:3.12
    steps:
      - checkout
      - run: python setup.py test
`
	ts := mockGitHubAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckCircleCIUnpinnedImage) {
		t.Error("expected unpinned image finding for python:3.12")
	}
	f := findByCheckID(findings, finding.CheckCircleCIUnpinnedImage)
	if f.Severity != finding.SeverityMedium {
		t.Errorf("expected SeverityMedium, got %v", f.Severity)
	}
}

func TestUnpinnedImage_LatestTag_Detected(t *testing.T) {
	yaml := `
version: 2.1
jobs:
  build:
    docker:
      - image: ubuntu
    steps:
      - checkout
      - run: apt-get update
`
	ts := mockGitHubAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckCircleCIUnpinnedImage) {
		t.Error("expected unpinned image finding for 'ubuntu' (implicit latest tag)")
	}
}

func TestPinnedImage_SHA256Digest_NoFinding(t *testing.T) {
	yaml := `
version: 2.1
jobs:
  build:
    docker:
      - image: node@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
    steps:
      - checkout
      - run: npm test
`
	ts := mockGitHubAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(findings, finding.CheckCircleCIUnpinnedImage) {
		t.Error("expected no unpinned image finding for sha256-pinned image")
	}
}

func TestUnpinnedImage_MultipleImages_DedupedByRef(t *testing.T) {
	yaml := `
version: 2.1
jobs:
  lint:
    docker:
      - image: node:18
    steps:
      - checkout
      - run: npm run lint
  test:
    docker:
      - image: node:18
    steps:
      - checkout
      - run: npm test
  build:
    docker:
      - image: golang:1.22
    steps:
      - checkout
      - run: go build ./...
`
	ts := mockGitHubAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	count := countByCheckID(findings, finding.CheckCircleCIUnpinnedImage)
	if count != 2 {
		t.Errorf("expected 2 unpinned image findings (node:18 deduped + golang:1.22), got %d", count)
	}
}

func TestUnpinnedImage_PrivateRegistry_Detected(t *testing.T) {
	yaml := `
version: 2.1
jobs:
  build:
    docker:
      - image: registry.example.com:5000/myapp:latest
    steps:
      - checkout
      - run: make test
`
	ts := mockGitHubAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckCircleCIUnpinnedImage) {
		t.Error("expected unpinned image finding for private registry image with mutable tag")
	}
}

// ── secret echoed ────────────────────────────────────────────────────────────

func TestSecretEchoed_DirectEcho_Detected(t *testing.T) {
	yaml := `
version: 2.1
jobs:
  build:
    docker:
      - image: node@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
    steps:
      - checkout
      - run: echo $SECRET_TOKEN
`
	ts := mockGitHubAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckCircleCISecretEchoed) {
		t.Error("expected secret echoed finding for 'echo $SECRET_TOKEN'")
	}
	f := findByCheckID(findings, finding.CheckCircleCISecretEchoed)
	if f.Severity != finding.SeverityHigh {
		t.Errorf("expected SeverityHigh, got %v", f.Severity)
	}
}

func TestSecretEchoed_CircleToken_Detected(t *testing.T) {
	yaml := `
version: 2.1
jobs:
  build:
    docker:
      - image: node@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
    steps:
      - checkout
      - run: echo $CIRCLE_TOKEN
`
	ts := mockGitHubAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckCircleCISecretEchoed) {
		t.Error("expected secret echoed finding for 'echo $CIRCLE_TOKEN'")
	}
}

func TestSecretEchoed_DockerhubPassword_Detected(t *testing.T) {
	yaml := `
version: 2.1
jobs:
  build:
    docker:
      - image: node@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
    steps:
      - checkout
      - run: echo $DOCKERHUB_PASSWORD
`
	ts := mockGitHubAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckCircleCISecretEchoed) {
		t.Error("expected secret echoed finding for 'echo $DOCKERHUB_PASSWORD'")
	}
}

func TestSecretEchoed_Printf_Detected(t *testing.T) {
	yaml := `
version: 2.1
jobs:
  build:
    docker:
      - image: alpine@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
    steps:
      - checkout
      - run: printf '%s' $AWS_SECRET_ACCESS_KEY
`
	ts := mockGitHubAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckCircleCISecretEchoed) {
		t.Error("expected secret echoed finding for printf of AWS_SECRET_ACCESS_KEY")
	}
}

func TestSecretEchoed_CurlWithToken_Detected(t *testing.T) {
	yaml := `
version: 2.1
jobs:
  build:
    docker:
      - image: alpine@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
    steps:
      - checkout
      - run: curl -H "Authorization: $SECRET_TOKEN" https://api.example.com
`
	ts := mockGitHubAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckCircleCISecretEchoed) {
		t.Error("expected secret echoed finding for curl with $SECRET_TOKEN")
	}
}

func TestSecretEchoed_BracketSyntax_Detected(t *testing.T) {
	yaml := `
version: 2.1
jobs:
  build:
    docker:
      - image: alpine@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
    steps:
      - checkout
      - run: echo ${DOCKER_PASSWORD}
`
	ts := mockGitHubAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckCircleCISecretEchoed) {
		t.Error("expected secret echoed finding for echo ${DOCKER_PASSWORD}")
	}
}

func TestSecretEchoed_NonSecretVar_NoFinding(t *testing.T) {
	yaml := `
version: 2.1
jobs:
  build:
    docker:
      - image: alpine@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
    steps:
      - checkout
      - run: echo $BUILD_NUMBER
      - run: echo $HOME
      - run: echo $CIRCLE_SHA1
`
	ts := mockGitHubAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(findings, finding.CheckCircleCISecretEchoed) {
		t.Error("expected no secret echoed finding for non-secret environment variables")
	}
}

func TestSecretEchoed_Deduplicated(t *testing.T) {
	yaml := `
version: 2.1
jobs:
  build:
    docker:
      - image: alpine@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
    steps:
      - checkout
      - run: echo $API_KEY
      - run: echo $API_KEY
`
	ts := mockGitHubAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	count := countByCheckID(findings, finding.CheckCircleCISecretEchoed)
	if count != 1 {
		t.Errorf("expected 1 deduplicated secret echoed finding, got %d", count)
	}
}

func TestSecretEchoed_MultipleDistinctVars_AllDetected(t *testing.T) {
	yaml := `
version: 2.1
jobs:
  build:
    docker:
      - image: alpine@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
    steps:
      - checkout
      - run: echo $SECRET_TOKEN
      - run: printf '%s' $API_KEY
      - run: cat $DOCKER_PASSWORD
`
	ts := mockGitHubAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	count := countByCheckID(findings, finding.CheckCircleCISecretEchoed)
	if count < 3 {
		t.Errorf("expected at least 3 secret echoed findings for 3 distinct secret variables, got %d", count)
	}
}

// ── insecure steps: setup_remote_docker ──────────────────────────────────────

func TestInsecureStep_SetupRemoteDocker_NoVersion_Detected(t *testing.T) {
	yaml := `
version: 2.1
jobs:
  build:
    docker:
      - image: node@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
    steps:
      - checkout
      - setup_remote_docker
      - run: docker build -t myapp .
`
	ts := mockGitHubAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckCircleCIInsecureStep) {
		t.Error("expected insecure step finding for setup_remote_docker without version")
	}
}

func TestInsecureStep_SetupRemoteDocker_WithVersion_NoFinding(t *testing.T) {
	yaml := `
version: 2.1
jobs:
  build:
    docker:
      - image: node@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
    steps:
      - checkout
      - setup_remote_docker:
          version: 20.10.24
      - run: docker build -t myapp .
`
	ts := mockGitHubAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.CheckID == finding.CheckCircleCIInsecureStep && f.Title == "setup_remote_docker without version pin" {
			t.Error("expected no setup_remote_docker finding when version is specified")
		}
	}
}

// ── insecure steps: no_output_timeout: 0 ─────────────────────────────────────

func TestInsecureStep_NoOutputTimeoutZero_Detected(t *testing.T) {
	yaml := `
version: 2.1
jobs:
  build:
    docker:
      - image: node@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
    steps:
      - checkout
      - run:
          no_output_timeout: 0
          command: npm run integration-tests
`
	ts := mockGitHubAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckCircleCIInsecureStep) {
		t.Error("expected insecure step finding for no_output_timeout: 0")
	}
}

func TestInsecureStep_NoOutputTimeoutNonZero_NoFinding(t *testing.T) {
	yaml := `
version: 2.1
jobs:
  build:
    docker:
      - image: node@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
    steps:
      - checkout
      - run:
          no_output_timeout: 30m
          command: npm test
`
	ts := mockGitHubAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.CheckID == finding.CheckCircleCIInsecureStep && f.Title == "Step disables output timeout (no_output_timeout: 0)" {
			t.Error("expected no timeout finding for no_output_timeout: 30m")
		}
	}
}

// ── insecure steps: store_artifacts with sensitive paths ─────────────────────

func TestInsecureStep_SensitiveArtifacts_SSH_Detected(t *testing.T) {
	yaml := `
version: 2.1
jobs:
  build:
    docker:
      - image: node@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
    steps:
      - checkout
      - store_artifacts:
          path: ~/.ssh
`
	ts := mockGitHubAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckCircleCIInsecureStep) {
		t.Error("expected insecure step finding for store_artifacts with ~/.ssh")
	}
}

func TestInsecureStep_SensitiveArtifacts_EtcShadow_Detected(t *testing.T) {
	yaml := `
version: 2.1
jobs:
  build:
    docker:
      - image: node@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
    steps:
      - checkout
      - store_artifacts:
          path: /etc/shadow
`
	ts := mockGitHubAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckCircleCIInsecureStep) {
		t.Error("expected insecure step finding for store_artifacts with /etc/shadow")
	}
}

func TestInsecureStep_SensitiveArtifacts_AWS_Detected(t *testing.T) {
	yaml := `
version: 2.1
jobs:
  build:
    docker:
      - image: node@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
    steps:
      - checkout
      - store_artifacts:
          path: ~/.aws
`
	ts := mockGitHubAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckCircleCIInsecureStep) {
		t.Error("expected insecure step finding for store_artifacts with ~/.aws")
	}
}

func TestInsecureStep_SafeArtifacts_NoFinding(t *testing.T) {
	yaml := `
version: 2.1
jobs:
  build:
    docker:
      - image: node@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
    steps:
      - checkout
      - run: npm test
      - store_artifacts:
          path: /tmp/test-results
`
	ts := mockGitHubAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.CheckID == finding.CheckCircleCIInsecureStep && f.Title == "store_artifacts exposes sensitive file paths" {
			t.Error("expected no sensitive artifact finding for /tmp/test-results")
		}
	}
}

// ── unconstrained context ────────────────────────────────────────────────────

func TestUnconstrainedContext_NoFilters_Detected(t *testing.T) {
	yaml := `
version: 2.1
jobs:
  deploy:
    docker:
      - image: node@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
    steps:
      - checkout
      - run: deploy.sh
workflows:
  main:
    jobs:
      - deploy:
          context: production-secrets
`
	ts := mockGitHubAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckCircleCIUnconstrained) {
		t.Error("expected unconstrained context finding for context without branch filters")
	}
}

func TestUnconstrainedContext_WithFilters_NoFinding(t *testing.T) {
	yaml := `
version: 2.1
jobs:
  deploy:
    docker:
      - image: node@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
    steps:
      - checkout
      - run: deploy.sh
workflows:
  main:
    jobs:
      - deploy:
          context: production-secrets
          filters:
            branches:
              only:
                - main
`
	ts := mockGitHubAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(findings, finding.CheckCircleCIUnconstrained) {
		t.Error("expected no unconstrained context finding when branch filters are present")
	}
}

func TestUnconstrainedContext_CorrectSeverity(t *testing.T) {
	yaml := `
version: 2.1
jobs:
  deploy:
    docker:
      - image: node@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
    steps:
      - checkout
workflows:
  main:
    jobs:
      - deploy:
          context: my-ctx
`
	ts := mockGitHubAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	f := findByCheckID(findings, finding.CheckCircleCIUnconstrained)
	if f == nil {
		t.Fatal("expected unconstrained context finding")
	}
	if f.Severity != finding.SeverityMedium {
		t.Errorf("expected SeverityMedium, got %v", f.Severity)
	}
}

// ── machine executor ─────────────────────────────────────────────────────────

func TestMachineExecutor_MachineTrue_Detected(t *testing.T) {
	yaml := `
version: 2.1
jobs:
  build:
    machine: true
    steps:
      - checkout
      - run: make build
`
	ts := mockGitHubAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckCircleCIMachineExecutor) {
		t.Error("expected machine executor finding for machine: true")
	}
}

func TestMachineExecutor_ExecutorMachine_Detected(t *testing.T) {
	yaml := `
version: 2.1
jobs:
  build:
    executor: machine
    steps:
      - checkout
      - run: make build
`
	ts := mockGitHubAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckCircleCIMachineExecutor) {
		t.Error("expected machine executor finding for executor: machine")
	}
}

func TestMachineExecutor_CorrectSeverity(t *testing.T) {
	yaml := `
version: 2.1
jobs:
  build:
    machine: true
    steps:
      - checkout
`
	ts := mockGitHubAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	f := findByCheckID(findings, finding.CheckCircleCIMachineExecutor)
	if f == nil {
		t.Fatal("expected machine executor finding")
	}
	if f.Severity != finding.SeverityMedium {
		t.Errorf("expected SeverityMedium, got %v", f.Severity)
	}
}

func TestMachineExecutor_DockerExecutor_NoFinding(t *testing.T) {
	yaml := `
version: 2.1
jobs:
  build:
    docker:
      - image: node@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
    steps:
      - checkout
      - run: npm test
`
	ts := mockGitHubAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(findings, finding.CheckCircleCIMachineExecutor) {
		t.Error("expected no machine executor finding for Docker executor")
	}
}

// ── safe config — no findings except public config info ──────────────────────

func TestSafeConfig_NoSecurityFindings(t *testing.T) {
	yaml := `
version: 2.1
jobs:
  build:
    docker:
      - image: node@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
    steps:
      - checkout
      - run: npm ci
      - run: npm test
      - run: npm run build
`
	ts := mockGitHubAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if f.CheckID != finding.CheckCircleCIPublicConfig {
			t.Errorf("unexpected finding in safe config: CheckID=%s Title=%q", f.CheckID, f.Title)
		}
	}
}

func TestSafeConfig_AllImagesPinned_NoUnpinnedFindings(t *testing.T) {
	yaml := `
version: 2.1
jobs:
  lint:
    docker:
      - image: node@sha256:1111111111111111111111111111111111111111111111111111111111111111
    steps:
      - checkout
      - run: npm run lint
  test:
    docker:
      - image: golang@sha256:2222222222222222222222222222222222222222222222222222222222222222
    steps:
      - checkout
      - run: go test ./...
  build:
    docker:
      - image: python@sha256:3333333333333333333333333333333333333333333333333333333333333333
    steps:
      - checkout
      - run: python -m pytest
`
	ts := mockGitHubAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(findings, finding.CheckCircleCIUnpinnedImage) {
		t.Error("expected no unpinned image findings when all images are pinned by sha256")
	}
}

// ── API error handling ───────────────────────────────────────────────────────

func TestAPI_404_ReturnsError(t *testing.T) {
	ts := mockGitHubAPI(t, "acme", "norepo", "", http.StatusNotFound)
	defer ts.Close()

	_, err := runScanner(t, ts, "acme/norepo", module.ScanSurface)
	if err == nil {
		t.Fatal("expected error for 404 response, got nil")
	}
}

func TestAPI_403_ReturnsError(t *testing.T) {
	ts := mockGitHubAPI(t, "acme", "private", "", http.StatusForbidden)
	defer ts.Close()

	_, err := runScanner(t, ts, "acme/private", module.ScanSurface)
	if err == nil {
		t.Fatal("expected error for 403 response, got nil")
	}
}

// ── finding metadata ─────────────────────────────────────────────────────────

func TestFinding_HasProofCommand(t *testing.T) {
	yaml := `
version: 2.1
jobs:
  build:
    docker:
      - image: node:18
    steps:
      - checkout
      - run: echo $API_KEY
`
	ts := mockGitHubAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.ProofCommand == "" {
			t.Errorf("finding %s (%s) has empty ProofCommand", f.CheckID, f.Title)
		}
	}
}

func TestFinding_HasCorrectAsset(t *testing.T) {
	yaml := `
version: 2.1
jobs:
  build:
    docker:
      - image: node:18
    steps:
      - checkout
      - run: npm test
`
	ts := mockGitHubAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Asset != "acme/app" {
			t.Errorf("finding %s has Asset=%q; want %q", f.CheckID, f.Asset, "acme/app")
		}
	}
}

func TestFinding_HasCorrectModuleAndScanner(t *testing.T) {
	yaml := `
version: 2.1
jobs:
  build:
    docker:
      - image: node:18
    steps:
      - checkout
      - run: npm test
`
	ts := mockGitHubAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Module != "surface" {
			t.Errorf("finding %s has Module=%q; want %q", f.CheckID, f.Module, "surface")
		}
		if f.Scanner != "circleci" {
			t.Errorf("finding %s has Scanner=%q; want %q", f.CheckID, f.Scanner, "circleci")
		}
	}
}

func TestFinding_HasEvidence(t *testing.T) {
	yaml := `
version: 2.1
jobs:
  build:
    docker:
      - image: node:18
    steps:
      - checkout
      - run: echo $SECRET_TOKEN
`
	ts := mockGitHubAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Evidence == nil {
			t.Errorf("finding %s (%s) has nil Evidence", f.CheckID, f.Title)
		}
	}
}

func TestFinding_HasDiscoveredAt(t *testing.T) {
	yaml := `
version: 2.1
jobs:
  build:
    docker:
      - image: node:18
    steps:
      - checkout
`
	ts := mockGitHubAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.DiscoveredAt.IsZero() {
			t.Errorf("finding %s (%s) has zero DiscoveredAt", f.CheckID, f.Title)
		}
	}
}

// ── context cancellation ─────────────────────────────────────────────────────

func TestContextCancellation_ReturnsError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a slow server that never responds.
		<-r.Context().Done()
	}))
	defer ts.Close()

	origTransport := http.DefaultTransport
	http.DefaultTransport = &redirectTransport{
		testURL: ts.URL,
		wrapped: origTransport,
	}
	defer func() { http.DefaultTransport = origTransport }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	s := circleci.New("")
	_, err := s.Run(ctx, "acme/app", module.ScanSurface)
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}
