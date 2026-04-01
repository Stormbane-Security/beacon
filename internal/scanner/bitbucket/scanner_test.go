package bitbucket_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanner/bitbucket"
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
	for i := range findings {
		if findings[i].CheckID == id {
			return &findings[i]
		}
	}
	return nil
}

// redirectTransport intercepts HTTP requests to api.bitbucket.org and sends
// them to the local httptest server instead.
type redirectTransport struct {
	testURL string
	wrapped http.RoundTripper
}

func (t *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == "api.bitbucket.org" {
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

// mockBitbucketAPI creates an httptest server that serves pipeline YAML at
// /2.0/repositories/{workspace}/{repo}/src/HEAD/bitbucket-pipelines.yml.
func mockBitbucketAPI(t *testing.T, workspace, repo, pipelineYAML string, statusCode int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expected := fmt.Sprintf("/2.0/repositories/%s/%s/src/HEAD/bitbucket-pipelines.yml", workspace, repo)
		if r.URL.Path == expected {
			w.WriteHeader(statusCode)
			fmt.Fprint(w, pipelineYAML)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
}

// runScanner sets up the transport redirect and runs the Bitbucket scanner.
func runScanner(t *testing.T, ts *httptest.Server, target string, scanType module.ScanType) ([]finding.Finding, error) {
	t.Helper()
	origTransport := http.DefaultTransport
	http.DefaultTransport = &redirectTransport{
		testURL: ts.URL,
		wrapped: origTransport,
	}
	defer func() { http.DefaultTransport = origTransport }()

	s := bitbucket.New()
	return s.Run(context.Background(), target, scanType)
}

// ── scanner name ─────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	s := bitbucket.New()
	if s.Name() != "bitbucket" {
		t.Errorf("Name() = %q; want %q", s.Name(), "bitbucket")
	}
}

// ── invalid target ───────────────────────────────────────────────────────────

func TestInvalidTarget_ReturnsError(t *testing.T) {
	s := bitbucket.New()
	_, err := s.Run(context.Background(), "invalid-no-slash", module.ScanSurface)
	if err == nil {
		t.Fatal("expected error for invalid target, got nil")
	}
}

// ── ScanSurface — public pipeline config ─────────────────────────────────────

func TestScanSurface_PublicPipeline_DetectsPublicConfig(t *testing.T) {
	yaml := `
image: node:18

pipelines:
  default:
    - step:
        name: Build
        script:
          - npm install
          - npm test
`
	ts := mockBitbucketAPI(t, "myteam", "myrepo", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "myteam/myrepo", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckBitbucketPublicPipeline) {
		t.Error("expected CheckBitbucketPublicPipeline finding for publicly accessible pipeline config")
	}
}

func TestScanSurface_PublicPipeline_HasCorrectSeverity(t *testing.T) {
	yaml := `
image: golang:1.22
pipelines:
  default:
    - step:
        script:
          - go build ./...
`
	ts := mockBitbucketAPI(t, "myteam", "myrepo", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "myteam/myrepo", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	f := findByCheckID(findings, finding.CheckBitbucketPublicPipeline)
	if f == nil {
		t.Fatal("expected CheckBitbucketPublicPipeline finding")
	}
	if f.Severity != finding.SeverityInfo {
		t.Errorf("expected SeverityInfo, got %v", f.Severity)
	}
}

// ── ScanDeep — all checks run ────────────────────────────────────────────────

func TestScanDeep_DetectsAllIssues(t *testing.T) {
	yaml := `
image: node:18

pipelines:
  default:
    - step:
        name: Build
        max-time: 0
        run-as-user: 0
        services:
          - docker
        script:
          - echo $SECRET_TOKEN
          - npm install
          - npm test
        after-script:
          - echo "done"

definitions:
  services:
    docker:
      memory: 2048
`
	ts := mockBitbucketAPI(t, "myteam", "myrepo", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "myteam/myrepo", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckBitbucketPipelineUnpinned) {
		t.Error("expected unpinned image finding for node:18")
	}
	if !hasCheckID(findings, finding.CheckBitbucketPipelineSecretEchoed) {
		t.Error("expected secret echoed finding for echo $SECRET_TOKEN")
	}
	if !hasCheckID(findings, finding.CheckBitbucketPipelineInsecureStep) {
		t.Error("expected insecure step finding")
	}
}

// ── unpinned images ──────────────────────────────────────────────────────────

func TestUnpinnedImage_MutableTag_Detected(t *testing.T) {
	yaml := `
image: python:3.12

pipelines:
  default:
    - step:
        script:
          - python setup.py test
`
	ts := mockBitbucketAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckBitbucketPipelineUnpinned) {
		t.Error("expected unpinned image finding for python:3.12")
	}
	f := findByCheckID(findings, finding.CheckBitbucketPipelineUnpinned)
	if f.Severity != finding.SeverityMedium {
		t.Errorf("expected SeverityMedium, got %v", f.Severity)
	}
}

func TestUnpinnedImage_LatestTag_Detected(t *testing.T) {
	yaml := `
image: ubuntu

pipelines:
  default:
    - step:
        script:
          - apt-get update
`
	ts := mockBitbucketAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckBitbucketPipelineUnpinned) {
		t.Error("expected unpinned image finding for 'ubuntu' (implicit latest tag)")
	}
}

func TestPinnedImage_SHA256Digest_NoFinding(t *testing.T) {
	yaml := `
image: node@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789

pipelines:
  default:
    - step:
        script:
          - npm test
`
	ts := mockBitbucketAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(findings, finding.CheckBitbucketPipelineUnpinned) {
		t.Error("expected no unpinned image finding for sha256-pinned image")
	}
}

func TestUnpinnedImage_MultipleImages_DedupedByRef(t *testing.T) {
	// Same image ref appears twice — should be deduplicated to one finding.
	yaml := `
image: node:18

pipelines:
  default:
    - step:
        image: node:18
        script:
          - npm run lint
    - step:
        image: golang:1.22
        script:
          - go test ./...
`
	ts := mockBitbucketAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// node:18 appears twice (top-level + step) but should be deduplicated.
	// golang:1.22 produces one more. Total: 2 unique unpinned image findings.
	count := countByCheckID(findings, finding.CheckBitbucketPipelineUnpinned)
	if count != 2 {
		t.Errorf("expected 2 unpinned image findings (node:18 deduped + golang:1.22), got %d", count)
	}
}

func TestUnpinnedImage_PrivateRegistry_Detected(t *testing.T) {
	yaml := `
image: registry.example.com:5000/myapp:latest

pipelines:
  default:
    - step:
        script:
          - make test
`
	ts := mockBitbucketAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckBitbucketPipelineUnpinned) {
		t.Error("expected unpinned image finding for private registry image with mutable tag")
	}
}

// ── secret echoed ────────────────────────────────────────────────────────────

func TestSecretEchoed_DirectEcho_Detected(t *testing.T) {
	yaml := `
image: node:18

pipelines:
  default:
    - step:
        script:
          - echo $SECRET_TOKEN
          - npm install
`
	ts := mockBitbucketAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckBitbucketPipelineSecretEchoed) {
		t.Error("expected secret echoed finding for 'echo $SECRET_TOKEN'")
	}
	f := findByCheckID(findings, finding.CheckBitbucketPipelineSecretEchoed)
	if f.Severity != finding.SeverityCritical {
		t.Errorf("expected SeverityCritical, got %v", f.Severity)
	}
}

func TestSecretEchoed_Printf_Detected(t *testing.T) {
	yaml := `
image: alpine

pipelines:
  default:
    - step:
        script:
          - printf '%s' $AWS_SECRET_ACCESS_KEY
`
	ts := mockBitbucketAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckBitbucketPipelineSecretEchoed) {
		t.Error("expected secret echoed finding for printf of AWS_SECRET_ACCESS_KEY")
	}
}

func TestSecretEchoed_BracketSyntax_Detected(t *testing.T) {
	yaml := `
image: alpine

pipelines:
  default:
    - step:
        script:
          - echo ${DOCKER_PASSWORD}
`
	ts := mockBitbucketAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckBitbucketPipelineSecretEchoed) {
		t.Error("expected secret echoed finding for echo ${DOCKER_PASSWORD}")
	}
}

func TestSecretEchoed_NonSecretVar_NoFinding(t *testing.T) {
	yaml := `
image: alpine

pipelines:
  default:
    - step:
        script:
          - echo $BUILD_NUMBER
          - echo $HOME
          - echo $CI_COMMIT_SHA
`
	ts := mockBitbucketAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(findings, finding.CheckBitbucketPipelineSecretEchoed) {
		t.Error("expected no secret echoed finding for non-secret environment variables")
	}
}

func TestSecretEchoed_Deduplicated(t *testing.T) {
	yaml := `
image: alpine

pipelines:
  default:
    - step:
        script:
          - echo $API_KEY
          - echo $API_KEY
`
	ts := mockBitbucketAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	count := countByCheckID(findings, finding.CheckBitbucketPipelineSecretEchoed)
	if count != 1 {
		t.Errorf("expected 1 deduplicated secret echoed finding, got %d", count)
	}
}

// ── insecure steps: after-script ─────────────────────────────────────────────

func TestInsecureStep_AfterScript_Detected(t *testing.T) {
	yaml := `
image: node:18

pipelines:
  default:
    - step:
        script:
          - npm test
        after-script:
          - curl -X POST https://hooks.slack.com/notify -d "build done"
`
	ts := mockBitbucketAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckBitbucketPipelineInsecureStep) {
		t.Error("expected insecure step finding for after-script block")
	}
}

// ── insecure steps: max-time: 0 ─────────────────────────────────────────────

func TestInsecureStep_MaxTimeZero_Detected(t *testing.T) {
	yaml := `
image: node:18

pipelines:
  default:
    - step:
        max-time: 0
        script:
          - npm run integration-tests
`
	ts := mockBitbucketAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckBitbucketPipelineInsecureStep) {
		t.Error("expected insecure step finding for max-time: 0")
	}
}

func TestInsecureStep_MaxTimeNonZero_NoFinding(t *testing.T) {
	yaml := `
image: node:18

pipelines:
  default:
    - step:
        max-time: 30
        script:
          - npm test
`
	ts := mockBitbucketAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.CheckID == finding.CheckBitbucketPipelineInsecureStep && f.Title == "Pipeline step has no execution timeout (max-time: 0)" {
			t.Error("expected no insecure step finding for max-time: 30")
		}
	}
}

// ── insecure steps: Docker-in-Docker ─────────────────────────────────────────

func TestInsecureStep_DockerInDocker_Detected(t *testing.T) {
	yaml := `
image: node:18

pipelines:
  default:
    - step:
        services:
          - docker
        script:
          - docker build -t myapp .
          - docker push myapp

definitions:
  services:
    docker:
      memory: 2048
`
	ts := mockBitbucketAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckBitbucketPipelineInsecureStep) {
		t.Error("expected insecure step finding for Docker-in-Docker service")
	}
}

func TestInsecureStep_DockerServiceWithoutServicesBlock_NoFinding(t *testing.T) {
	// A step referencing docker in its script without a services: block should
	// not trigger the Docker-in-Docker check.
	yaml := `
image: node:18

pipelines:
  default:
    - step:
        script:
          - docker --version
`
	ts := mockBitbucketAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.CheckID == finding.CheckBitbucketPipelineInsecureStep && f.Title == "Pipeline uses Docker-in-Docker service (privileged mode)" {
			t.Error("expected no Docker-in-Docker finding without a services: block definition")
		}
	}
}

// ── insecure steps: run-as-user: 0 ──────────────────────────────────────────

func TestInsecureStep_RunAsRoot_Detected(t *testing.T) {
	yaml := `
image: node:18

pipelines:
  default:
    - step:
        run-as-user: 0
        script:
          - npm test
`
	ts := mockBitbucketAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckBitbucketPipelineInsecureStep) {
		t.Error("expected insecure step finding for run-as-user: 0")
	}
}

func TestInsecureStep_RunAsNonRoot_NoFinding(t *testing.T) {
	yaml := `
image: node:18

pipelines:
  default:
    - step:
        run-as-user: 1000
        script:
          - npm test
`
	ts := mockBitbucketAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.CheckID == finding.CheckBitbucketPipelineInsecureStep && f.Title == "Pipeline step runs as root (run-as-user: 0)" {
			t.Error("expected no run-as-root finding for run-as-user: 1000")
		}
	}
}

// ── safe pipeline — no findings except public pipeline info ──────────────────

func TestSafePipeline_NoSecurityFindings(t *testing.T) {
	yaml := `
image: node@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789

pipelines:
  default:
    - step:
        max-time: 30
        script:
          - npm ci
          - npm test
          - npm run build
`
	ts := mockBitbucketAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The only finding should be the public pipeline info-level finding.
	for _, f := range findings {
		if f.CheckID != finding.CheckBitbucketPublicPipeline {
			t.Errorf("unexpected finding in safe pipeline: CheckID=%s Title=%q", f.CheckID, f.Title)
		}
	}
}

func TestSafePipeline_AllImagesPinned_NoUnpinnedFindings(t *testing.T) {
	yaml := `
image: node@sha256:1111111111111111111111111111111111111111111111111111111111111111

pipelines:
  default:
    - step:
        image: golang@sha256:2222222222222222222222222222222222222222222222222222222222222222
        script:
          - go test ./...
    - step:
        image: python@sha256:3333333333333333333333333333333333333333333333333333333333333333
        script:
          - python -m pytest
`
	ts := mockBitbucketAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(findings, finding.CheckBitbucketPipelineUnpinned) {
		t.Error("expected no unpinned image findings when all images are pinned by sha256")
	}
}

// ── target formats ───────────────────────────────────────────────────────────

func TestTarget_BitbucketURL_Parsed(t *testing.T) {
	yaml := `
image: node:18
pipelines:
  default:
    - step:
        script:
          - npm test
`
	ts := mockBitbucketAPI(t, "myteam", "myrepo", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "https://bitbucket.org/myteam/myrepo", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error for Bitbucket URL target: %v", err)
	}
	if !hasCheckID(findings, finding.CheckBitbucketPublicPipeline) {
		t.Error("expected findings when target is a full Bitbucket URL")
	}
}

// ── API error handling ───────────────────────────────────────────────────────

func TestAPI_404_ReturnsError(t *testing.T) {
	ts := mockBitbucketAPI(t, "acme", "norepo", "", http.StatusNotFound)
	defer ts.Close()

	_, err := runScanner(t, ts, "acme/norepo", module.ScanSurface)
	if err == nil {
		t.Fatal("expected error for 404 response, got nil")
	}
}

func TestAPI_403_ReturnsError(t *testing.T) {
	ts := mockBitbucketAPI(t, "acme", "private", "", http.StatusForbidden)
	defer ts.Close()

	_, err := runScanner(t, ts, "acme/private", module.ScanSurface)
	if err == nil {
		t.Fatal("expected error for 403 response, got nil")
	}
}

// ── proof command ────────────────────────────────────────────────────────────

func TestFinding_HasProofCommand(t *testing.T) {
	yaml := `
image: node:18

pipelines:
  default:
    - step:
        script:
          - echo $API_KEY
`
	ts := mockBitbucketAPI(t, "acme", "app", yaml, http.StatusOK)
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

// ── multiple secret variables ────────────────────────────────────────────────

func TestSecretEchoed_MultipleDistinctVars_AllDetected(t *testing.T) {
	yaml := `
image: alpine

pipelines:
  default:
    - step:
        script:
          - echo $SECRET_TOKEN
          - printf '%s' $API_KEY
          - cat $DOCKER_PASSWORD
`
	ts := mockBitbucketAPI(t, "acme", "app", yaml, http.StatusOK)
	defer ts.Close()

	findings, err := runScanner(t, ts, "acme/app", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	count := countByCheckID(findings, finding.CheckBitbucketPipelineSecretEchoed)
	if count < 3 {
		t.Errorf("expected at least 3 secret echoed findings for 3 distinct secret variables, got %d", count)
	}
}
