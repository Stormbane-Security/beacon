package playbook_test

// Audit tests — written after a behavioral audit of the playbook and scanner
// configuration. Each test documents a real invariant, not a rubber-stamp.
//
// Tests cover:
//  1. Baseline coverage — new scanners must appear in baseline.yaml
//  2. Scanner mode guards — deep-only scanners must return nothing in surface mode
//  3. Playbook match correctness — specific playbooks fire only when expected
//  4. Hasura playbook does NOT fire on generic JSON responses

import (
	"context"
	"testing"

	"github.com/stormbane/beacon/internal/module"
	"github.com/stormbane/beacon/internal/playbook"
	"github.com/stormbane/beacon/internal/scanner/crlf"
	"github.com/stormbane/beacon/internal/scanner/hpp"
	"github.com/stormbane/beacon/internal/scanner/protopollution"
	"github.com/stormbane/beacon/internal/scanner/ssrf"
	"github.com/stormbane/beacon/internal/scanner/ssti"
)

// ── 1. Baseline coverage ─────────────────────────────────────────────────────

// TestBaseline_NewScannersRegistered parses the embedded baseline.yaml and
// verifies that every new scanner introduced in the recent audit appears in
// either the surface or deep scanner list.  If a scanner is missing from
// baseline.yaml, it will never run on most assets.
func TestBaseline_NewScannersRegistered(t *testing.T) {
	reg, err := playbook.Load()
	if err != nil {
		t.Fatalf("playbook.Load: %v", err)
	}

	baseline := reg.Get("baseline")
	if baseline == nil {
		t.Fatal("baseline playbook not found in registry")
	}

	// Union all scanner names from surface + deep.
	allScanners := make(map[string]bool)
	for _, s := range baseline.Surface.Scanners {
		allScanners[s] = true
	}
	for _, s := range baseline.Deep.Scanners {
		allScanners[s] = true
	}

	// These scanners must all appear in baseline so they run on every asset.
	mustHave := []string{
		"saml",           // surface: passive SAML endpoint discovery
		"iam",            // surface: SCIM / OIDC / OAuth endpoint discovery
		"ssti",           // deep:    template injection active probes
		"crlf",           // deep:    CRLF injection active probes
		"log4shell",      // surface: Java signal detection
		"protopollution", // deep:    prototype pollution JSON probes
		"web3detect",     // surface: Web3 wallet library passive detection
		"ssrf",           // deep:    SSRF cloud-metadata injection
		"nginx",          // surface: Nginx alias traversal path probes
		"hpp",            // deep:    HTTP parameter pollution probes
	}

	for _, name := range mustHave {
		if !allScanners[name] {
			t.Errorf("scanner %q is missing from baseline.yaml surface/deep scanner lists — it will never run on most assets", name)
		}
	}
}

// ── 2. Scanner mode guards ────────────────────────────────────────────────────

// TestSSTI_SurfaceModeReturnsNothing verifies that the SSTI scanner (deep-only
// active payloads) does not return findings when called with ScanSurface.
func TestSSTI_SurfaceModeReturnsNothing(t *testing.T) {
	s := ssti.New()
	findings, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("ssti.Run returned error in surface mode: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("ssti scanner must not return findings in surface mode, got %d", len(findings))
	}
}

// TestCRLF_SurfaceModeReturnsNothing verifies the CRLF scanner (deep-only) is
// silent in surface mode.
func TestCRLF_SurfaceModeReturnsNothing(t *testing.T) {
	s := crlf.New()
	findings, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("crlf.Run returned error in surface mode: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("crlf scanner must not return findings in surface mode, got %d", len(findings))
	}
}

// TestProtoPollution_SurfaceModeReturnsNothing verifies the prototype pollution
// scanner (deep-only) is silent in surface mode.
func TestProtoPollution_SurfaceModeReturnsNothing(t *testing.T) {
	s := protopollution.New()
	findings, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("protopollution.Run returned error in surface mode: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("protopollution scanner must not return findings in surface mode, got %d", len(findings))
	}
}

// TestSSRF_SurfaceModeReturnsNothing verifies the SSRF scanner (deep-only) is
// silent in surface mode.
func TestSSRF_SurfaceModeReturnsNothing(t *testing.T) {
	s := ssrf.New()
	findings, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("ssrf.Run returned error in surface mode: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("ssrf scanner must not return findings in surface mode, got %d", len(findings))
	}
}

// TestHPP_SurfaceModeReturnsNothing verifies the HPP scanner (deep-only) is
// silent in surface mode.
func TestHPP_SurfaceModeReturnsNothing(t *testing.T) {
	s := hpp.New()
	findings, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("hpp.Run returned error in surface mode: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("hpp scanner must not return findings in surface mode, got %d", len(findings))
	}
}

// ── 3. Playbook match correctness ────────────────────────────────────────────

// TestSAMLPlaybook_FiresOnSAMLMetadataPath verifies that a playbook with
// path_responds matching /saml/metadata fires when that path is in
// RespondingPaths.  This is the canonical SAML discovery trigger.
func TestSAMLPlaybook_FiresOnSAMLMetadataPath(t *testing.T) {
	p := mustParse(t, `
name: saml_test
match:
  any:
    - path_responds: /saml/metadata
    - path_responds: /saml2/metadata
`)
	ev := playbook.Evidence{
		RespondingPaths: []string{"/saml/metadata", "/login"},
	}
	if !p.Matches(ev) {
		t.Fatal("SAML playbook must fire when /saml/metadata is in RespondingPaths")
	}
}

// TestSAMLPlaybook_DoesNotFireOnUnrelatedPaths verifies that the SAML playbook
// does not fire when only unrelated paths are present.
func TestSAMLPlaybook_DoesNotFireOnUnrelatedPaths(t *testing.T) {
	p := mustParse(t, `
name: saml_test
match:
  any:
    - path_responds: /saml/metadata
    - path_responds: /saml2/metadata
`)
	ev := playbook.Evidence{
		RespondingPaths: []string{"/login", "/api/v1", "/health"},
	}
	if p.Matches(ev) {
		t.Fatal("SAML playbook must not fire when only unrelated paths are present")
	}
}

// TestAILLMPlaybook_FiresOnOpenAIPath verifies the AI/LLM playbook fires when
// an OpenAI-compatible endpoint responds.
func TestAILLMPlaybook_FiresOnOpenAIPath(t *testing.T) {
	p := mustParse(t, `
name: ai_llm_test
match:
  any:
    - path_responds: /v1/chat/completions
    - path_responds: /v1/models
    - ai_endpoint_present: true
`)
	ev := playbook.Evidence{
		RespondingPaths: []string{"/v1/chat/completions"},
	}
	if !p.Matches(ev) {
		t.Fatal("AI/LLM playbook must fire when /v1/chat/completions is in RespondingPaths")
	}
}

// TestAILLMPlaybook_FiresOnAIEndpointSignal verifies the AI/LLM playbook fires
// when aidetect has populated AIEndpoints (ai_endpoint_present: true).
func TestAILLMPlaybook_FiresOnAIEndpointSignal(t *testing.T) {
	p := mustParse(t, `
name: ai_llm_test
match:
  any:
    - path_responds: /v1/chat/completions
    - ai_endpoint_present: true
`)
	ev := playbook.Evidence{
		AIEndpoints: []string{"https://api.example.com/v1/completions"},
	}
	if !p.Matches(ev) {
		t.Fatal("AI/LLM playbook must fire when AIEndpoints is non-empty")
	}
}

// TestAILLMPlaybook_DoesNotFireOnGenericWebAsset verifies the AI/LLM playbook
// does not fire on a plain web asset with no AI signals.
func TestAILLMPlaybook_DoesNotFireOnGenericWebAsset(t *testing.T) {
	p := mustParse(t, `
name: ai_llm_test
match:
  any:
    - path_responds: /v1/chat/completions
    - path_responds: /v1/models
    - path_responds: /api/tags
    - ai_endpoint_present: true
    - body_contains: '"finish_reason"'
    - body_contains: '"choices":['
`)
	ev := playbook.Evidence{
		RespondingPaths: []string{"/", "/login", "/about"},
		Body512:         "<html><head><title>Example</title></head>",
	}
	if p.Matches(ev) {
		t.Fatal("AI/LLM playbook must not fire on a plain HTML web asset with no AI signals")
	}
}

// ── 4. Hasura playbook does not fire on generic JSON ────────────────────────

// TestHasura_DoesNotFireOnGenericJSONBody verifies that the hasura playbook
// does not match a generic REST API asset just because its body contains "data".
// The overly broad `body_contains: "data"` rule was removed; this test ensures
// it stays removed and the playbook only fires on Hasura-specific signals.
func TestHasura_DoesNotFireOnGenericJSONBody(t *testing.T) {
	reg, err := playbook.Load()
	if err != nil {
		t.Fatalf("playbook.Load: %v", err)
	}
	hasura := reg.Get("hasura")
	if hasura == nil {
		t.Fatal("hasura playbook not found in registry")
	}

	// A typical generic JSON API response body — contains "data" but is not Hasura.
	ev := playbook.Evidence{
		Body512:         `{"data":{"users":[]},"meta":{"total":0}}`,
		RespondingPaths: []string{"/api/v1/users", "/health"},
	}
	if hasura.Matches(ev) {
		t.Error("hasura playbook must not fire on a generic JSON API body containing \"data\" — " +
			"the body_contains:\"data\" rule was too broad and has been removed")
	}
}

// TestHasura_FiresOnHasuraSpecificPath verifies the hasura playbook still fires
// correctly on actual Hasura signals after the broad rule was removed.
func TestHasura_FiresOnHasuraSpecificPath(t *testing.T) {
	reg, err := playbook.Load()
	if err != nil {
		t.Fatalf("playbook.Load: %v", err)
	}
	hasura := reg.Get("hasura")
	if hasura == nil {
		t.Fatal("hasura playbook not found in registry")
	}

	ev := playbook.Evidence{
		RespondingPaths: []string{"/v1/graphql", "/healthz"},
	}
	if !hasura.Matches(ev) {
		t.Error("hasura playbook must fire when /v1/graphql is in RespondingPaths")
	}
}
