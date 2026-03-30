package ghorg

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

// -------------------------------------------------------------------------
// helpers
// -------------------------------------------------------------------------

// newTestScanner creates a Scanner whose HTTP client routes all requests to
// the supplied test server instead of api.github.com.
func newTestScanner(ts *httptest.Server, token string) *Scanner {
	return &Scanner{
		token:      token,
		httpClient: ts.Client(),
	}
}

func hasCheckID(findings []finding.Finding, id finding.CheckID) bool {
	for _, f := range findings {
		if f.CheckID == id {
			return true
		}
	}
	return false
}

func hasSeverity(findings []finding.Finding, id finding.CheckID, sev finding.Severity) bool {
	for _, f := range findings {
		if f.CheckID == id && f.Severity == sev {
			return true
		}
	}
	return false
}

func assertHasCheckID(t *testing.T, findings []finding.Finding, id finding.CheckID) {
	t.Helper()
	for _, f := range findings {
		if f.CheckID == id {
			return
		}
	}
	t.Errorf("expected finding with CheckID %q but none found (got %d findings)", id, len(findings))
}

func assertNotHasCheckID(t *testing.T, findings []finding.Finding, id finding.CheckID) {
	t.Helper()
	for _, f := range findings {
		if f.CheckID == id {
			t.Errorf("unexpected finding with CheckID %q", id)
		}
	}
}

// fakeGitHubAPI builds a test server that serves the three org API endpoints
// with the provided response structs. nil values cause that endpoint to
// return 404 (simulating a missing/forbidden resource).
func fakeGitHubAPI(meta *ghOrgMeta, actions *ghOrgActionsPermissions, workflow *ghOrgWorkflowPermissions) *httptest.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/orgs/test-org", func(w http.ResponseWriter, r *http.Request) {
		if meta == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(meta)
	})

	mux.HandleFunc("/orgs/test-org/actions/permissions/workflow", func(w http.ResponseWriter, r *http.Request) {
		if workflow == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(workflow)
	})

	mux.HandleFunc("/orgs/test-org/actions/permissions", func(w http.ResponseWriter, r *http.Request) {
		if actions == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(actions)
	})

	return httptest.NewServer(mux)
}

// runWithFakeAPI creates the test server, overrides the scanner's apiGet
// target, and runs the scanner. It returns findings. Because the scanner
// hardcodes api.github.com URLs in apiGet, we override apiGet indirectly by
// pointing the scanner's httpClient at a server that rewrites URLs via a
// custom transport.
func runWithFakeAPI(t *testing.T, token string, meta *ghOrgMeta, actions *ghOrgActionsPermissions, workflow *ghOrgWorkflowPermissions) []finding.Finding {
	t.Helper()
	ts := fakeGitHubAPI(meta, actions, workflow)
	defer ts.Close()

	s := &Scanner{
		token: token,
		httpClient: &http.Client{
			// Use a custom transport that rewrites api.github.com URLs to the
			// test server.
			Transport: &rewriteTransport{target: ts.URL},
		},
	}

	findings, err := s.Run(context.Background(), "test-org", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return findings
}

// rewriteTransport rewrites requests from https://api.github.com/... to the
// test server URL, then delegates to the default transport.
type rewriteTransport struct {
	target string // e.g. "http://127.0.0.1:12345"
}

func (rt *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Rewrite the scheme + host to point at our test server.
	req.URL.Scheme = "http"
	// Parse test server host.
	req.URL.Host = rt.target[len("http://"):]
	return http.DefaultTransport.RoundTrip(req)
}

// =========================================================================
// MFA enforcement checks
// =========================================================================

func TestMFANotRequired_Critical(t *testing.T) {
	meta := &ghOrgMeta{
		TwoFactorRequirementEnabled: false,
		PublicRepos:                 0,
	}
	findings := runWithFakeAPI(t, "", meta, nil, nil)
	assertHasCheckID(t, findings, finding.CheckGitHubOrgMFANotRequired)
	if !hasSeverity(findings, finding.CheckGitHubOrgMFANotRequired, finding.SeverityCritical) {
		t.Error("expected SeverityCritical for MFA not required")
	}
}

func TestMFARequired_NoFinding(t *testing.T) {
	meta := &ghOrgMeta{
		TwoFactorRequirementEnabled: true,
		PublicRepos:                 0,
	}
	findings := runWithFakeAPI(t, "", meta, nil, nil)
	assertNotHasCheckID(t, findings, finding.CheckGitHubOrgMFANotRequired)
}

func TestMFAFinding_HasCorrectFields(t *testing.T) {
	meta := &ghOrgMeta{
		TwoFactorRequirementEnabled: false,
	}
	findings := runWithFakeAPI(t, "", meta, nil, nil)

	for _, f := range findings {
		if f.CheckID != finding.CheckGitHubOrgMFANotRequired {
			continue
		}
		if f.Scanner != scannerName {
			t.Errorf("expected Scanner=%q, got %q", scannerName, f.Scanner)
		}
		if f.Module != "github" {
			t.Errorf("expected Module=github, got %q", f.Module)
		}
		if f.Asset != "test-org" {
			t.Errorf("expected Asset=test-org, got %q", f.Asset)
		}
		if f.ProofCommand == "" {
			t.Error("ProofCommand must not be empty")
		}
		if f.Evidence == nil {
			t.Error("Evidence must not be nil")
		}
		if val, ok := f.Evidence["two_factor_requirement_enabled"]; !ok || val != false {
			t.Error("Evidence must contain two_factor_requirement_enabled=false")
		}
		if f.DiscoveredAt.IsZero() {
			t.Error("DiscoveredAt must be set")
		}
		return
	}
	t.Fatal("MFA finding not found")
}

// =========================================================================
// Public repos (informational)
// =========================================================================

func TestPublicRepos_InfoFinding(t *testing.T) {
	meta := &ghOrgMeta{
		TwoFactorRequirementEnabled: true,
		PublicRepos:                 42,
	}
	findings := runWithFakeAPI(t, "", meta, nil, nil)
	assertHasCheckID(t, findings, finding.CheckGitHubPublicRepos)
	if !hasSeverity(findings, finding.CheckGitHubPublicRepos, finding.SeverityInfo) {
		t.Error("expected SeverityInfo for public repos finding")
	}
}

func TestPublicRepos_ZeroRepos_NoFinding(t *testing.T) {
	meta := &ghOrgMeta{
		TwoFactorRequirementEnabled: true,
		PublicRepos:                 0,
	}
	findings := runWithFakeAPI(t, "", meta, nil, nil)
	assertNotHasCheckID(t, findings, finding.CheckGitHubPublicRepos)
}

func TestPublicRepos_EvidenceContainsCount(t *testing.T) {
	meta := &ghOrgMeta{
		TwoFactorRequirementEnabled: true,
		PublicRepos:                 7,
	}
	findings := runWithFakeAPI(t, "", meta, nil, nil)

	for _, f := range findings {
		if f.CheckID != finding.CheckGitHubPublicRepos {
			continue
		}
		count, ok := f.Evidence["public_repos"]
		if !ok {
			t.Fatal("Evidence must contain public_repos key")
		}
		if count != 7 {
			t.Errorf("expected public_repos=7 in evidence, got %v", count)
		}
		return
	}
	t.Fatal("public repos finding not found")
}

// =========================================================================
// Actions policy checks (require token)
// =========================================================================

func TestActionsUnrestricted_Medium(t *testing.T) {
	meta := &ghOrgMeta{TwoFactorRequirementEnabled: true}
	actions := &ghOrgActionsPermissions{
		AllowedActions:        "all",
		ForkPRWorkflowsPolicy: "require_approval",
	}
	findings := runWithFakeAPI(t, "test-token", meta, actions, nil)
	assertHasCheckID(t, findings, finding.CheckGitHubActionsUnrestricted)
	if !hasSeverity(findings, finding.CheckGitHubActionsUnrestricted, finding.SeverityMedium) {
		t.Error("expected SeverityMedium for unrestricted actions")
	}
}

func TestActionsRestricted_Selected_NoFinding(t *testing.T) {
	meta := &ghOrgMeta{TwoFactorRequirementEnabled: true}
	actions := &ghOrgActionsPermissions{
		AllowedActions:        "selected",
		ForkPRWorkflowsPolicy: "require_approval",
	}
	findings := runWithFakeAPI(t, "test-token", meta, actions, nil)
	assertNotHasCheckID(t, findings, finding.CheckGitHubActionsUnrestricted)
}

func TestActionsRestricted_LocalOnly_NoFinding(t *testing.T) {
	meta := &ghOrgMeta{TwoFactorRequirementEnabled: true}
	actions := &ghOrgActionsPermissions{
		AllowedActions:        "local_only",
		ForkPRWorkflowsPolicy: "require_approval",
	}
	findings := runWithFakeAPI(t, "test-token", meta, actions, nil)
	assertNotHasCheckID(t, findings, finding.CheckGitHubActionsUnrestricted)
}

func TestActionsUnrestricted_EvidenceCorrect(t *testing.T) {
	meta := &ghOrgMeta{TwoFactorRequirementEnabled: true}
	actions := &ghOrgActionsPermissions{
		AllowedActions:        "all",
		ForkPRWorkflowsPolicy: "require_approval",
	}
	findings := runWithFakeAPI(t, "test-token", meta, actions, nil)

	for _, f := range findings {
		if f.CheckID != finding.CheckGitHubActionsUnrestricted {
			continue
		}
		if val, ok := f.Evidence["allowed_actions"]; !ok || val != "all" {
			t.Errorf("expected allowed_actions=all in evidence, got %v", f.Evidence)
		}
		return
	}
	t.Fatal("actions unrestricted finding not found")
}

// =========================================================================
// Fork PR workflow approval checks
// =========================================================================

func TestForkPRWorkflowsPolicy_RunWorkflows_High(t *testing.T) {
	meta := &ghOrgMeta{TwoFactorRequirementEnabled: true}
	actions := &ghOrgActionsPermissions{
		AllowedActions:        "selected",
		ForkPRWorkflowsPolicy: "run_workflows",
	}
	findings := runWithFakeAPI(t, "test-token", meta, actions, nil)
	assertHasCheckID(t, findings, finding.CheckGitHubForkWorkflowApproval)
	if !hasSeverity(findings, finding.CheckGitHubForkWorkflowApproval, finding.SeverityHigh) {
		t.Error("expected SeverityHigh for fork PR no approval")
	}
}

func TestForkPRWorkflowsPolicy_Empty_High(t *testing.T) {
	meta := &ghOrgMeta{TwoFactorRequirementEnabled: true}
	actions := &ghOrgActionsPermissions{
		AllowedActions:        "selected",
		ForkPRWorkflowsPolicy: "", // empty string also triggers
	}
	findings := runWithFakeAPI(t, "test-token", meta, actions, nil)
	assertHasCheckID(t, findings, finding.CheckGitHubForkWorkflowApproval)
}

func TestForkPRWorkflowsPolicy_RequireApproval_NoFinding(t *testing.T) {
	meta := &ghOrgMeta{TwoFactorRequirementEnabled: true}
	actions := &ghOrgActionsPermissions{
		AllowedActions:        "selected",
		ForkPRWorkflowsPolicy: "require_approval",
	}
	findings := runWithFakeAPI(t, "test-token", meta, actions, nil)
	assertNotHasCheckID(t, findings, finding.CheckGitHubForkWorkflowApproval)
}

// =========================================================================
// Default workflow token permissions
// =========================================================================

func TestDefaultTokenWrite_High(t *testing.T) {
	meta := &ghOrgMeta{TwoFactorRequirementEnabled: true}
	workflow := &ghOrgWorkflowPermissions{
		DefaultWorkflowPermissions: "write",
	}
	findings := runWithFakeAPI(t, "test-token", meta, nil, workflow)
	assertHasCheckID(t, findings, finding.CheckGitHubDefaultTokenWrite)
	if !hasSeverity(findings, finding.CheckGitHubDefaultTokenWrite, finding.SeverityHigh) {
		t.Error("expected SeverityHigh for default token write")
	}
}

func TestDefaultTokenRead_NoFinding(t *testing.T) {
	meta := &ghOrgMeta{TwoFactorRequirementEnabled: true}
	workflow := &ghOrgWorkflowPermissions{
		DefaultWorkflowPermissions: "read",
	}
	findings := runWithFakeAPI(t, "test-token", meta, nil, workflow)
	assertNotHasCheckID(t, findings, finding.CheckGitHubDefaultTokenWrite)
}

func TestDefaultTokenWrite_EvidenceCorrect(t *testing.T) {
	meta := &ghOrgMeta{TwoFactorRequirementEnabled: true}
	workflow := &ghOrgWorkflowPermissions{
		DefaultWorkflowPermissions: "write",
	}
	findings := runWithFakeAPI(t, "test-token", meta, nil, workflow)

	for _, f := range findings {
		if f.CheckID != finding.CheckGitHubDefaultTokenWrite {
			continue
		}
		if val, ok := f.Evidence["default_workflow_permissions"]; !ok || val != "write" {
			t.Errorf("expected default_workflow_permissions=write in evidence, got %v", f.Evidence)
		}
		return
	}
	t.Fatal("default token write finding not found")
}

// =========================================================================
// Token-gated checks: without token, actions/workflow checks are skipped
// =========================================================================

func TestNoToken_SkipsActionsAndWorkflowChecks(t *testing.T) {
	meta := &ghOrgMeta{TwoFactorRequirementEnabled: true}
	// These would normally trigger findings, but without a token the scanner
	// should skip the API calls entirely.
	actions := &ghOrgActionsPermissions{
		AllowedActions:        "all",
		ForkPRWorkflowsPolicy: "run_workflows",
	}
	workflow := &ghOrgWorkflowPermissions{
		DefaultWorkflowPermissions: "write",
	}
	findings := runWithFakeAPI(t, "", meta, actions, workflow)
	assertNotHasCheckID(t, findings, finding.CheckGitHubActionsUnrestricted)
	assertNotHasCheckID(t, findings, finding.CheckGitHubForkWorkflowApproval)
	assertNotHasCheckID(t, findings, finding.CheckGitHubDefaultTokenWrite)
}

// =========================================================================
// Combined scenarios
// =========================================================================

func TestAllMisconfigured_AllFindings(t *testing.T) {
	meta := &ghOrgMeta{
		TwoFactorRequirementEnabled: false,
		PublicRepos:                 10,
	}
	actions := &ghOrgActionsPermissions{
		AllowedActions:        "all",
		ForkPRWorkflowsPolicy: "run_workflows",
	}
	workflow := &ghOrgWorkflowPermissions{
		DefaultWorkflowPermissions: "write",
	}
	findings := runWithFakeAPI(t, "test-token", meta, actions, workflow)

	assertHasCheckID(t, findings, finding.CheckGitHubOrgMFANotRequired)
	assertHasCheckID(t, findings, finding.CheckGitHubPublicRepos)
	assertHasCheckID(t, findings, finding.CheckGitHubActionsUnrestricted)
	assertHasCheckID(t, findings, finding.CheckGitHubForkWorkflowApproval)
	assertHasCheckID(t, findings, finding.CheckGitHubDefaultTokenWrite)

	if len(findings) != 5 {
		t.Errorf("expected exactly 5 findings when everything is misconfigured, got %d", len(findings))
	}
}

func TestAllSecure_NoFindings(t *testing.T) {
	meta := &ghOrgMeta{
		TwoFactorRequirementEnabled: true,
		PublicRepos:                 0,
	}
	actions := &ghOrgActionsPermissions{
		AllowedActions:        "selected",
		ForkPRWorkflowsPolicy: "require_approval",
	}
	workflow := &ghOrgWorkflowPermissions{
		DefaultWorkflowPermissions: "read",
	}
	findings := runWithFakeAPI(t, "test-token", meta, actions, workflow)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when everything is secure, got %d", len(findings))
		for _, f := range findings {
			t.Logf("  unexpected: %s (%s)", f.CheckID, f.Severity)
		}
	}
}

// =========================================================================
// API error handling
// =========================================================================

func TestOrgMetaError_ReturnsError(t *testing.T) {
	// Server returns 500 for the org meta endpoint.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	s := &Scanner{
		token: "",
		httpClient: &http.Client{
			Transport: &rewriteTransport{target: ts.URL},
		},
	}

	_, err := s.Run(context.Background(), "test-org", module.ScanSurface)
	if err == nil {
		t.Fatal("expected error when org meta API fails, got nil")
	}
}

func TestActionsEndpoint404_GracefulDegradation(t *testing.T) {
	// Org meta succeeds but actions endpoints return 404 — scanner should
	// still return the MFA finding and not error.
	meta := &ghOrgMeta{TwoFactorRequirementEnabled: false}
	// Pass nil for actions and workflow to simulate 404.
	findings := runWithFakeAPI(t, "test-token", meta, nil, nil)
	assertHasCheckID(t, findings, finding.CheckGitHubOrgMFANotRequired)
	// No actions/workflow findings because those endpoints failed.
	assertNotHasCheckID(t, findings, finding.CheckGitHubActionsUnrestricted)
	assertNotHasCheckID(t, findings, finding.CheckGitHubDefaultTokenWrite)
}

// =========================================================================
// Scanner name
// =========================================================================

func TestName(t *testing.T) {
	s := New("test-token")
	if s.Name() != "github.org" {
		t.Errorf("expected scanner name %q, got %q", "github.org", s.Name())
	}
}

// =========================================================================
// Context cancellation
// =========================================================================

func TestContextCancelled_ReturnsError(t *testing.T) {
	meta := &ghOrgMeta{TwoFactorRequirementEnabled: false}
	ts := fakeGitHubAPI(meta, nil, nil)
	defer ts.Close()

	s := &Scanner{
		token: "",
		httpClient: &http.Client{
			Transport: &rewriteTransport{target: ts.URL},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Run

	_, err := s.Run(ctx, "test-org", module.ScanSurface)
	if err == nil {
		t.Error("expected error when context is cancelled, got nil")
	}
}

// =========================================================================
// Authorization header set when token is present
// =========================================================================

func TestAuthorizationHeaderSent(t *testing.T) {
	var gotAuth string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ghOrgMeta{TwoFactorRequirementEnabled: true})
	}))
	defer ts.Close()

	s := &Scanner{
		token: "my-secret-token",
		httpClient: &http.Client{
			Transport: &rewriteTransport{target: ts.URL},
		},
	}

	_, err := s.Run(context.Background(), "test-org", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotAuth != "token my-secret-token" {
		t.Errorf("expected Authorization header 'token my-secret-token', got %q", gotAuth)
	}
}

func TestNoToken_NoAuthorizationHeader(t *testing.T) {
	var gotAuth string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ghOrgMeta{TwoFactorRequirementEnabled: true})
	}))
	defer ts.Close()

	s := &Scanner{
		token: "",
		httpClient: &http.Client{
			Transport: &rewriteTransport{target: ts.URL},
		},
	}

	_, err := s.Run(context.Background(), "test-org", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotAuth != "" {
		t.Errorf("expected no Authorization header when token is empty, got %q", gotAuth)
	}
}

// =========================================================================
// Table-driven: MFA + PublicRepos matrix
// =========================================================================

func TestOrgMetaFindings_TableDriven(t *testing.T) {
	tests := []struct {
		name        string
		mfaEnabled  bool
		publicRepos int
		wantMFA     bool
		wantPublic  bool
	}{
		{
			name:        "no MFA, no public repos",
			mfaEnabled:  false,
			publicRepos: 0,
			wantMFA:     true,
			wantPublic:  false,
		},
		{
			name:        "no MFA, has public repos",
			mfaEnabled:  false,
			publicRepos: 5,
			wantMFA:     true,
			wantPublic:  true,
		},
		{
			name:        "MFA enabled, has public repos",
			mfaEnabled:  true,
			publicRepos: 3,
			wantMFA:     false,
			wantPublic:  true,
		},
		{
			name:        "MFA enabled, no public repos",
			mfaEnabled:  true,
			publicRepos: 0,
			wantMFA:     false,
			wantPublic:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meta := &ghOrgMeta{
				TwoFactorRequirementEnabled: tt.mfaEnabled,
				PublicRepos:                 tt.publicRepos,
			}
			findings := runWithFakeAPI(t, "", meta, nil, nil)

			if got := hasCheckID(findings, finding.CheckGitHubOrgMFANotRequired); got != tt.wantMFA {
				t.Errorf("MFA finding: got %v, want %v", got, tt.wantMFA)
			}
			if got := hasCheckID(findings, finding.CheckGitHubPublicRepos); got != tt.wantPublic {
				t.Errorf("public repos finding: got %v, want %v", got, tt.wantPublic)
			}
		})
	}
}

// =========================================================================
// Table-driven: Actions policy matrix
// =========================================================================

func TestActionsPermissions_TableDriven(t *testing.T) {
	tests := []struct {
		name               string
		allowedActions     string
		forkPRPolicy       string
		wantUnrestricted   bool
		wantForkNoApproval bool
	}{
		{
			name:               "all actions, run_workflows fork policy",
			allowedActions:     "all",
			forkPRPolicy:       "run_workflows",
			wantUnrestricted:   true,
			wantForkNoApproval: true,
		},
		{
			name:               "all actions, empty fork policy",
			allowedActions:     "all",
			forkPRPolicy:       "",
			wantUnrestricted:   true,
			wantForkNoApproval: true,
		},
		{
			name:               "selected actions, run_workflows fork policy",
			allowedActions:     "selected",
			forkPRPolicy:       "run_workflows",
			wantUnrestricted:   false,
			wantForkNoApproval: true,
		},
		{
			name:               "selected actions, require_approval fork policy",
			allowedActions:     "selected",
			forkPRPolicy:       "require_approval",
			wantUnrestricted:   false,
			wantForkNoApproval: false,
		},
		{
			name:               "local_only actions, require_approval fork policy",
			allowedActions:     "local_only",
			forkPRPolicy:       "require_approval",
			wantUnrestricted:   false,
			wantForkNoApproval: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meta := &ghOrgMeta{TwoFactorRequirementEnabled: true}
			actions := &ghOrgActionsPermissions{
				AllowedActions:        tt.allowedActions,
				ForkPRWorkflowsPolicy: tt.forkPRPolicy,
			}
			findings := runWithFakeAPI(t, "test-token", meta, actions, nil)

			if got := hasCheckID(findings, finding.CheckGitHubActionsUnrestricted); got != tt.wantUnrestricted {
				t.Errorf("actions unrestricted: got %v, want %v", got, tt.wantUnrestricted)
			}
			if got := hasCheckID(findings, finding.CheckGitHubForkWorkflowApproval); got != tt.wantForkNoApproval {
				t.Errorf("fork no approval: got %v, want %v", got, tt.wantForkNoApproval)
			}
		})
	}
}

// =========================================================================
// Table-driven: workflow token permissions
// =========================================================================

func TestWorkflowPermissions_TableDriven(t *testing.T) {
	tests := []struct {
		name            string
		defaultPerms    string
		wantTokenWrite  bool
	}{
		{"write default", "write", true},
		{"read default", "read", false},
		{"empty default", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meta := &ghOrgMeta{TwoFactorRequirementEnabled: true}
			workflow := &ghOrgWorkflowPermissions{
				DefaultWorkflowPermissions: tt.defaultPerms,
			}
			findings := runWithFakeAPI(t, "test-token", meta, nil, workflow)

			if got := hasCheckID(findings, finding.CheckGitHubDefaultTokenWrite); got != tt.wantTokenWrite {
				t.Errorf("default token write: got %v, want %v", got, tt.wantTokenWrite)
			}
		})
	}
}

// =========================================================================
// ProofCommand contains org name
// =========================================================================

func TestProofCommand_ContainsOrgName(t *testing.T) {
	meta := &ghOrgMeta{
		TwoFactorRequirementEnabled: false,
		PublicRepos:                 5,
	}
	actions := &ghOrgActionsPermissions{
		AllowedActions:        "all",
		ForkPRWorkflowsPolicy: "run_workflows",
	}
	workflow := &ghOrgWorkflowPermissions{
		DefaultWorkflowPermissions: "write",
	}
	findings := runWithFakeAPI(t, "test-token", meta, actions, workflow)

	for _, f := range findings {
		if f.ProofCommand == "" {
			// PublicRepos finding may not have a proof command.
			continue
		}
		if !containsSubstring(f.ProofCommand, "test-org") {
			t.Errorf("ProofCommand for %s should contain org name 'test-org', got: %s", f.CheckID, f.ProofCommand)
		}
	}
}

func containsSubstring(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && stringContains(s, sub))
}

func stringContains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// =========================================================================
// API request sends correct headers
// =========================================================================

func TestAPIRequestHeaders(t *testing.T) {
	var gotAccept, gotAPIVersion string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAccept = r.Header.Get("Accept")
		gotAPIVersion = r.Header.Get("X-GitHub-Api-Version")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ghOrgMeta{TwoFactorRequirementEnabled: true})
	}))
	defer ts.Close()

	s := &Scanner{
		token: "test",
		httpClient: &http.Client{
			Transport: &rewriteTransport{target: ts.URL},
		},
	}

	_, err := s.Run(context.Background(), "test-org", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotAccept != "application/vnd.github+json" {
		t.Errorf("expected Accept header 'application/vnd.github+json', got %q", gotAccept)
	}
	if gotAPIVersion != "2022-11-28" {
		t.Errorf("expected X-GitHub-Api-Version '2022-11-28', got %q", gotAPIVersion)
	}
}

// =========================================================================
// sanitizePathSegment tests
// =========================================================================

func TestSanitizePathSegment_Normal(t *testing.T) {
	result := sanitizePathSegment("my-org")
	if result != "my-org" {
		t.Errorf("expected my-org, got %q", result)
	}
}

func TestSanitizePathSegment_PathTraversal(t *testing.T) {
	result := sanitizePathSegment("../../etc")
	// Slashes and dots should be percent-encoded.
	if result == "../../etc" {
		t.Errorf("path traversal was not sanitized: %q", result)
	}
	if containsSubstring(result, "/") {
		t.Errorf("result should not contain raw slashes: %q", result)
	}
}

func TestSanitizePathSegment_QueryInjection(t *testing.T) {
	result := sanitizePathSegment("org?admin=true")
	// Query parameter should be stripped.
	if containsSubstring(result, "?") {
		t.Errorf("query parameter was not stripped: %q", result)
	}
}

func TestSanitizePathSegment_FragmentInjection(t *testing.T) {
	result := sanitizePathSegment("org#fragment")
	if containsSubstring(result, "#") {
		t.Errorf("fragment was not stripped: %q", result)
	}
}

func TestSanitizePathSegment_Empty(t *testing.T) {
	result := sanitizePathSegment("")
	if result != "" {
		t.Errorf("expected empty string, got %q", result)
	}
}

// =========================================================================
// Rate limit handling
// =========================================================================

func TestRateLimit403_ReturnsError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", "0") // already expired
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()

	s := &Scanner{
		token: "",
		httpClient: &http.Client{
			Transport: &rewriteTransport{target: ts.URL},
		},
	}

	_, err := s.Run(context.Background(), "test-org", module.ScanSurface)
	if err == nil {
		t.Fatal("expected error on rate-limited 403, got nil")
	}
}

// =========================================================================
// ForkPRWorkflowsPolicy JSON mapping (regression test for the JSON tag fix)
// =========================================================================

func TestForkPRWorkflowsPolicy_CorrectJSONField(t *testing.T) {
	// This test verifies that the ForkPRWorkflowsPolicy field is
	// deserialized from the correct JSON key. Before the fix, it was
	// mapped to "default_workflow_permissions" which is wrong.
	jsonBody := `{
		"enabled_repositories": "all",
		"allowed_actions": "selected",
		"fork_pull_request_workflows_policy": "run_workflows"
	}`
	var ap ghOrgActionsPermissions
	if err := json.Unmarshal([]byte(jsonBody), &ap); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if ap.ForkPRWorkflowsPolicy != "run_workflows" {
		t.Errorf("expected ForkPRWorkflowsPolicy=run_workflows, got %q", ap.ForkPRWorkflowsPolicy)
	}
	if ap.AllowedActions != "selected" {
		t.Errorf("expected AllowedActions=selected, got %q", ap.AllowedActions)
	}
}

func TestForkPRWorkflowsPolicy_OldJSONField_DoesNotMismatch(t *testing.T) {
	// Ensure that "default_workflow_permissions" in the actions/permissions
	// response does NOT incorrectly populate ForkPRWorkflowsPolicy.
	jsonBody := `{
		"allowed_actions": "all",
		"default_workflow_permissions": "write"
	}`
	var ap ghOrgActionsPermissions
	if err := json.Unmarshal([]byte(jsonBody), &ap); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if ap.ForkPRWorkflowsPolicy == "write" {
		t.Error("ForkPRWorkflowsPolicy should NOT be populated from default_workflow_permissions")
	}
	if ap.ForkPRWorkflowsPolicy != "" {
		t.Errorf("expected ForkPRWorkflowsPolicy to be empty, got %q", ap.ForkPRWorkflowsPolicy)
	}
}
