package ghactions

import (
	"testing"

	"github.com/stormbane/beacon/internal/finding"
)

// -------------------------------------------------------------------------
// Unpinned action tests
// -------------------------------------------------------------------------

func TestUnpinnedAction_Detected(t *testing.T) {
	yaml := `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@main
`
	findings := checkUnpinnedActions(yaml, "testorg/testrepo")
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for unpinned action, got none")
	}
	for _, f := range findings {
		if f.CheckID != finding.CheckGHActionUnpinned {
			t.Errorf("unexpected CheckID %q, want %q", f.CheckID, finding.CheckGHActionUnpinned)
		}
		if f.Severity != finding.SeverityMedium {
			t.Errorf("unexpected severity %v, want Medium", f.Severity)
		}
	}
}

func TestPinnedAction_NoFinding(t *testing.T) {
	yaml := `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@abcdef1234567890abcdef1234567890abcdef12
`
	findings := checkUnpinnedActions(yaml, "testorg/testrepo")
	if len(findings) != 0 {
		t.Fatalf("expected no findings for fully-pinned action, got %d: %v", len(findings), findings)
	}
}

func TestLocalAction_NotFlagged(t *testing.T) {
	// Local actions (./.github/actions/…) are controlled by the repo itself
	// and must not be flagged as unpinned.
	yaml := `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/my-custom-action
`
	findings := checkUnpinnedActions(yaml, "testorg/testrepo")
	if len(findings) != 0 {
		t.Fatalf("expected no findings for local action, got %d", len(findings))
	}
}

func TestUnpinnedAction_DedupedAcrossSteps(t *testing.T) {
	// The same unpinned action used twice should produce only one finding.
	yaml := `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/checkout@v3
`
	findings := checkUnpinnedActions(yaml, "testorg/testrepo")
	if len(findings) != 1 {
		t.Fatalf("expected 1 deduplicated finding, got %d", len(findings))
	}
}

// -------------------------------------------------------------------------
// Script injection tests
// -------------------------------------------------------------------------

func TestScriptInjection_PRTitle(t *testing.T) {
	yaml := `
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Print title
        run: echo "PR title is ${{ github.event.pull_request.title }}"
`
	findings := checkScriptInjection(yaml, "testorg/testrepo")
	if len(findings) == 0 {
		t.Fatal("expected a script injection finding for PR title in run step, got none")
	}
	for _, f := range findings {
		if f.CheckID != finding.CheckGHActionScriptInjection {
			t.Errorf("unexpected CheckID %q, want %q", f.CheckID, finding.CheckGHActionScriptInjection)
		}
		if f.Severity != finding.SeverityCritical {
			t.Errorf("unexpected severity %v, want Critical", f.Severity)
		}
	}
}

func TestScriptInjection_IssueTitle(t *testing.T) {
	yaml := `
on: issues
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "Issue: ${{ github.event.issue.title }}"
`
	findings := checkScriptInjection(yaml, "testorg/testrepo")
	if len(findings) == 0 {
		t.Fatal("expected a script injection finding for issue title, got none")
	}
}

func TestScriptInjection_SafeEnvVar_NoFinding(t *testing.T) {
	// Using an intermediate env var is the safe pattern — should produce no finding.
	yaml := `
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Print title safely
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
        run: echo "$PR_TITLE"
`
	findings := checkScriptInjection(yaml, "testorg/testrepo")
	if len(findings) != 0 {
		t.Fatalf("expected no findings for safe env-var pattern, got %d", len(findings))
	}
}

// -------------------------------------------------------------------------
// Overpermissioned tests
// -------------------------------------------------------------------------

func TestOverpermissioned_WriteAll(t *testing.T) {
	yaml := `
on: push
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
`
	findings := checkOverpermissioned(yaml, "testorg/testrepo")
	if len(findings) == 0 {
		t.Fatal("expected an overpermissioned finding for write-all, got none")
	}
	for _, f := range findings {
		if f.CheckID != finding.CheckGHActionOverpermissioned {
			t.Errorf("unexpected CheckID %q", f.CheckID)
		}
		if f.Severity != finding.SeverityHigh {
			t.Errorf("unexpected severity %v, want High", f.Severity)
		}
	}
}

func TestOverpermissioned_NoneBlock_HasFinding(t *testing.T) {
	// No permissions block at all → defaults may be permissive.
	yaml := `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
`
	findings := checkOverpermissioned(yaml, "testorg/testrepo")
	if len(findings) == 0 {
		t.Fatal("expected an overpermissioned finding when permissions block is absent")
	}
}

func TestOverpermissioned_RestrictedPermissions_NoFinding(t *testing.T) {
	// Explicit minimal permissions → no finding.
	yaml := `
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
`
	findings := checkOverpermissioned(yaml, "testorg/testrepo")
	if len(findings) != 0 {
		t.Fatalf("expected no findings for restricted permissions, got %d: %v", len(findings), findings)
	}
}

// -------------------------------------------------------------------------
// pull_request_target tests
// -------------------------------------------------------------------------

func TestPRTargetUnsafe_Detected(t *testing.T) {
	yaml := `
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: make test
`
	findings := checkPRTargetUnsafe(yaml, "testorg/testrepo")
	if len(findings) == 0 {
		t.Fatal("expected pull_request_target unsafe finding, got none")
	}
	if findings[0].CheckID != finding.CheckGHActionPRTargetUnsafe {
		t.Errorf("unexpected CheckID %q", findings[0].CheckID)
	}
	if findings[0].Severity != finding.SeverityCritical {
		t.Errorf("unexpected severity %v, want Critical", findings[0].Severity)
	}
}

func TestPRTargetSafe_NoUnsafeCheckout(t *testing.T) {
	// pull_request_target without unsafe checkout is acceptable.
	yaml := `
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: make test
`
	findings := checkPRTargetUnsafe(yaml, "testorg/testrepo")
	if len(findings) != 0 {
		t.Fatalf("expected no findings for safe pull_request_target workflow, got %d", len(findings))
	}
}

// -------------------------------------------------------------------------
// Secrets echoed tests
// -------------------------------------------------------------------------

func TestSecretsEchoed_DirectEcho(t *testing.T) {
	yaml := `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ secrets.API_KEY }}
`
	findings := checkSecretsEchoed(yaml, "testorg/testrepo")
	if len(findings) == 0 {
		t.Fatal("expected a secrets-echoed finding for direct echo, got none")
	}
	if findings[0].CheckID != finding.CheckGHActionSecretsEchoed {
		t.Errorf("unexpected CheckID %q", findings[0].CheckID)
	}
	if findings[0].Severity != finding.SeverityCritical {
		t.Errorf("unexpected severity %v, want Critical", findings[0].Severity)
	}
}

func TestSecretsEchoed_IndirectEcho(t *testing.T) {
	yaml := `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - env:
          TOKEN: ${{ secrets.DEPLOY_TOKEN }}
        run: echo $TOKEN
`
	findings := checkSecretsEchoed(yaml, "testorg/testrepo")
	if len(findings) == 0 {
		t.Fatal("expected a secrets-echoed finding for indirect echo via env var, got none")
	}
}

// -------------------------------------------------------------------------
// Self-hosted runner tests
// -------------------------------------------------------------------------

func TestSelfHostedOnPublic_Detected(t *testing.T) {
	yaml := `
on: push
jobs:
  build:
    runs-on: [self-hosted, linux]
    steps:
      - run: make build
`
	findings := checkSelfHostedOnPublic(yaml, "testorg/testrepo")
	if len(findings) == 0 {
		t.Fatal("expected a self-hosted finding, got none")
	}
	if findings[0].CheckID != finding.CheckGHActionSelfHostedPublic {
		t.Errorf("unexpected CheckID %q", findings[0].CheckID)
	}
	if findings[0].Severity != finding.SeverityCritical {
		t.Errorf("unexpected severity %v, want Critical", findings[0].Severity)
	}
}

func TestSelfHostedOnPublic_GitHubHosted_NoFinding(t *testing.T) {
	yaml := `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make build
`
	findings := checkSelfHostedOnPublic(yaml, "testorg/testrepo")
	if len(findings) != 0 {
		t.Fatalf("expected no findings for GitHub-hosted runner, got %d", len(findings))
	}
}

// -------------------------------------------------------------------------
// Artifact signing tests
// -------------------------------------------------------------------------

func TestArtifactSigning_ReleaseMissingSign(t *testing.T) {
	yaml := `
on:
  release:
    types: [published]
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: goreleaser/goreleaser@v1
`
	findings := checkArtifactSigning(yaml, "testorg/testrepo")
	if len(findings) == 0 {
		t.Fatal("expected unsigned_release_artifacts finding, got none")
	}
	if findings[0].CheckID != finding.CheckGHActionUnsignedRelease {
		t.Errorf("unexpected CheckID %q", findings[0].CheckID)
	}
}

func TestArtifactSigning_WithCosign_NoFinding(t *testing.T) {
	yaml := `
on:
  release:
    types: [published]
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: sigstore/cosign-installer@v3
      - uses: goreleaser/goreleaser@v1
`
	findings := checkArtifactSigning(yaml, "testorg/testrepo")
	if len(findings) != 0 {
		t.Fatalf("expected no findings when cosign is present, got %d", len(findings))
	}
}

func TestArtifactSigning_NoPushTrigger_NoFinding(t *testing.T) {
	yaml := `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: goreleaser/goreleaser@v1
`
	findings := checkArtifactSigning(yaml, "testorg/testrepo")
	if len(findings) != 0 {
		t.Fatalf("expected no findings for non-release trigger, got %d", len(findings))
	}
}

// -------------------------------------------------------------------------
// Reusable workflow pinning tests
// -------------------------------------------------------------------------

func TestReusableWorkflow_Unpinned_Detected(t *testing.T) {
	yaml := `
on: push
jobs:
  call:
    uses: myorg/myrepo/.github/workflows/ci.yml@v2
`
	findings := checkReusableWorkflowPinning(yaml, "testorg/testrepo")
	if len(findings) == 0 {
		t.Fatal("expected reusable_workflow_unpinned finding, got none")
	}
	if findings[0].CheckID != finding.CheckGHActionReusableWorkflowUnpinned {
		t.Errorf("unexpected CheckID %q", findings[0].CheckID)
	}
}

func TestReusableWorkflow_PinnedToSHA_NoFinding(t *testing.T) {
	yaml := `
on: push
jobs:
  call:
    uses: myorg/myrepo/.github/workflows/ci.yml@abcdef1234567890abcdef1234567890abcdef12
`
	findings := checkReusableWorkflowPinning(yaml, "testorg/testrepo")
	if len(findings) != 0 {
		t.Fatalf("expected no findings for SHA-pinned reusable workflow, got %d", len(findings))
	}
}

func TestReusableWorkflow_LocalWorkflow_NoFinding(t *testing.T) {
	// Local reusable workflows (./.github/workflows/…) are not external supply-chain risk.
	yaml := `
on: push
jobs:
  call:
    uses: ./.github/workflows/shared.yml
`
	findings := checkReusableWorkflowPinning(yaml, "testorg/testrepo")
	if len(findings) != 0 {
		t.Fatalf("expected no findings for local reusable workflow, got %d", len(findings))
	}
}

// -------------------------------------------------------------------------
// workflow_dispatch injection tests
// -------------------------------------------------------------------------

func TestWorkflowDispatchInjection_Detected(t *testing.T) {
	yaml := `
on:
  workflow_dispatch:
    inputs:
      branch:
        description: 'Branch to deploy'
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: git checkout ${{ inputs.branch }}
`
	findings := checkWorkflowDispatchInjection(yaml, "testorg/testrepo")
	if len(findings) == 0 {
		t.Fatal("expected workflow_dispatch_injection finding, got none")
	}
	if findings[0].CheckID != finding.CheckGHActionWorkflowDispatchInjection {
		t.Errorf("unexpected CheckID %q", findings[0].CheckID)
	}
	if findings[0].Severity != finding.SeverityCritical {
		t.Errorf("unexpected severity %v, want Critical", findings[0].Severity)
	}
}

func TestWorkflowDispatchInjection_SafeEnvVar_NoFinding(t *testing.T) {
	yaml := `
on:
  workflow_dispatch:
    inputs:
      branch:
        description: 'Branch to deploy'
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - env:
          BRANCH: ${{ inputs.branch }}
        run: git checkout "$BRANCH"
`
	findings := checkWorkflowDispatchInjection(yaml, "testorg/testrepo")
	if len(findings) != 0 {
		t.Fatalf("expected no findings when input is via env var, got %d", len(findings))
	}
}

func TestWorkflowDispatchInjection_NoPushTrigger_NoFinding(t *testing.T) {
	yaml := `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ inputs.branch }}
`
	// No workflow_dispatch trigger, so inputs.* injection check should not fire.
	findings := checkWorkflowDispatchInjection(yaml, "testorg/testrepo")
	if len(findings) != 0 {
		t.Fatalf("expected no findings for non-dispatch trigger, got %d", len(findings))
	}
}
