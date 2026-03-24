package playbook_test

// Tests derived from the playbook YAML specification, not from the implementation.
// Each case documents what the contract MUST be:
//   - which evidence fields trigger each rule type
//   - case sensitivity expectations
//   - combinator (any / all) semantics
//   - edge cases (empty evidence, empty rule sets)

import (
	"testing"

	"github.com/stormbane/beacon/internal/playbook"
)

// mustParse builds a Playbook from inline YAML. Fails the test if YAML is invalid.
func mustParse(t *testing.T, yamlSrc string) *playbook.Playbook {
	t.Helper()
	p, err := playbook.ParsePlaybook([]byte(yamlSrc))
	if err != nil {
		t.Fatalf("parse playbook YAML: %v", err)
	}
	return p
}

// ── always ───────────────────────────────────────────────────────────────────

func TestAlwaysMatchesEmptyEvidence(t *testing.T) {
	p := mustParse(t, `
name: baseline
match:
  always: true
`)
	if !p.Matches(playbook.Evidence{}) {
		t.Fatal("always playbook must match empty evidence")
	}
}

func TestAlwaysMatchesAnyEvidence(t *testing.T) {
	p := mustParse(t, `
name: baseline
match:
  always: true
`)
	ev := playbook.Evidence{
		ASNOrg:  "RANDOM ORG",
		Headers: map[string]string{"x-custom": "value"},
	}
	if !p.Matches(ev) {
		t.Fatal("always playbook must match any evidence")
	}
}

// ── header_present ───────────────────────────────────────────────────────────

func TestHeaderPresentMatchesWhenHeaderExists(t *testing.T) {
	p := mustParse(t, `
name: cloudflare
match:
  any:
    - header_present: "cf-ray"
`)
	ev := playbook.Evidence{Headers: map[string]string{"cf-ray": "abc123"}}
	if !p.Matches(ev) {
		t.Fatal("must match when cf-ray header is present")
	}
}

func TestHeaderPresentNoMatchWhenHeaderAbsent(t *testing.T) {
	p := mustParse(t, `
name: cloudflare
match:
  any:
    - header_present: "cf-ray"
`)
	ev := playbook.Evidence{Headers: map[string]string{"server": "nginx"}}
	if p.Matches(ev) {
		t.Fatal("must not match when cf-ray header is absent")
	}
}

func TestHeaderPresentIsCaseInsensitive(t *testing.T) {
	p := mustParse(t, `
name: test
match:
  any:
    - header_present: "CF-Ray"
`)
	// HTTP headers are stored lower-case in Evidence; rule matching must be case-insensitive.
	ev := playbook.Evidence{Headers: map[string]string{"cf-ray": "abc"}}
	if !p.Matches(ev) {
		t.Fatal("header_present matching must be case-insensitive")
	}
}

// ── header_value ─────────────────────────────────────────────────────────────

func TestHeaderValueMatchesSubstring(t *testing.T) {
	p := mustParse(t, `
name: wordpress
match:
  any:
    - header_value:
        name: "x-powered-by"
        contains: "PHP"
`)
	ev := playbook.Evidence{Headers: map[string]string{"x-powered-by": "PHP/8.1"}}
	if !p.Matches(ev) {
		t.Fatal("header_value must match when header contains the substring")
	}
}

func TestHeaderValueNoMatchWhenSubstringAbsent(t *testing.T) {
	p := mustParse(t, `
name: wordpress
match:
  any:
    - header_value:
        name: "x-powered-by"
        contains: "PHP"
`)
	ev := playbook.Evidence{Headers: map[string]string{"x-powered-by": "ASP.NET"}}
	if p.Matches(ev) {
		t.Fatal("header_value must not match when header value does not contain the substring")
	}
}

func TestHeaderValueNoMatchWhenHeaderAbsent(t *testing.T) {
	p := mustParse(t, `
name: test
match:
  any:
    - header_value:
        name: "x-powered-by"
        contains: "PHP"
`)
	ev := playbook.Evidence{Headers: map[string]string{"server": "nginx"}}
	if p.Matches(ev) {
		t.Fatal("header_value must not match when the header is absent entirely")
	}
}

func TestHeaderValueIsCaseInsensitive(t *testing.T) {
	p := mustParse(t, `
name: test
match:
  any:
    - header_value:
        name: "Server"
        contains: "nginx"
`)
	ev := playbook.Evidence{Headers: map[string]string{"server": "NGINX/1.25"}}
	if !p.Matches(ev) {
		t.Fatal("header_value contains comparison must be case-insensitive")
	}
}

// ── asn_org_contains ─────────────────────────────────────────────────────────

func TestASNOrgContainsMatch(t *testing.T) {
	p := mustParse(t, `
name: cloudflare
match:
  any:
    - asn_org_contains: "CLOUDFLARE"
`)
	ev := playbook.Evidence{ASNOrg: "Cloudflare, Inc."}
	if !p.Matches(ev) {
		t.Fatal("asn_org_contains must match case-insensitively")
	}
}

func TestASNOrgContainsNoMatch(t *testing.T) {
	p := mustParse(t, `
name: cloudflare
match:
  any:
    - asn_org_contains: "CLOUDFLARE"
`)
	ev := playbook.Evidence{ASNOrg: "Amazon AWS"}
	if p.Matches(ev) {
		t.Fatal("asn_org_contains must not match a different org")
	}
}

// ── dns_suffix ────────────────────────────────────────────────────────────────

func TestDNSSuffixMatchesHostnameEnding(t *testing.T) {
	p := mustParse(t, `
name: cloudfront
match:
  any:
    - dns_suffix: ".cloudfront.net"
`)
	ev := playbook.Evidence{Hostname: "d1234.cloudfront.net"}
	if !p.Matches(ev) {
		t.Fatal("dns_suffix must match when hostname ends with the suffix")
	}
}

func TestDNSSuffixNoMatchWhenSuffixDiffers(t *testing.T) {
	p := mustParse(t, `
name: cloudfront
match:
  any:
    - dns_suffix: ".cloudfront.net"
`)
	ev := playbook.Evidence{Hostname: "example.amazonaws.com"}
	if p.Matches(ev) {
		t.Fatal("dns_suffix must not match a different suffix")
	}
}

// ── cname_contains ───────────────────────────────────────────────────────────

func TestCNAMEContainsMatchesChainEntry(t *testing.T) {
	p := mustParse(t, `
name: aws_ec2
match:
  any:
    - cname_contains: ".elb.amazonaws.com"
`)
	ev := playbook.Evidence{CNAMEChain: []string{"my-lb-123.us-east-1.elb.amazonaws.com"}}
	if !p.Matches(ev) {
		t.Fatal("cname_contains must match when any CNAME entry contains the substring")
	}
}

func TestCNAMEContainsNoMatchWhenChainEmpty(t *testing.T) {
	p := mustParse(t, `
name: aws_ec2
match:
  any:
    - cname_contains: ".elb.amazonaws.com"
`)
	ev := playbook.Evidence{CNAMEChain: []string{}}
	if p.Matches(ev) {
		t.Fatal("cname_contains must not match an empty CNAME chain")
	}
}

func TestCNAMEContainsMatchesAnyEntryNotJustFirst(t *testing.T) {
	p := mustParse(t, `
name: test
match:
  any:
    - cname_contains: "target.example.com"
`)
	ev := playbook.Evidence{CNAMEChain: []string{"first.other.com", "target.example.com"}}
	if !p.Matches(ev) {
		t.Fatal("cname_contains must match any entry in the chain, not just the first")
	}
}

// ── title_contains ───────────────────────────────────────────────────────────

func TestTitleContainsMatch(t *testing.T) {
	p := mustParse(t, `
name: grafana
match:
  any:
    - title_contains: "Grafana"
`)
	ev := playbook.Evidence{Title: "Grafana - Home"}
	if !p.Matches(ev) {
		t.Fatal("title_contains must match when title contains the substring")
	}
}

func TestTitleContainsIsCaseInsensitive(t *testing.T) {
	p := mustParse(t, `
name: grafana
match:
  any:
    - title_contains: "Grafana"
`)
	ev := playbook.Evidence{Title: "grafana - home"}
	if !p.Matches(ev) {
		t.Fatal("title_contains comparison must be case-insensitive")
	}
}

func TestTitleContainsNoMatchWhenTitleDiffers(t *testing.T) {
	p := mustParse(t, `
name: grafana
match:
  any:
    - title_contains: "Grafana"
`)
	ev := playbook.Evidence{Title: "Kibana - Home"}
	if p.Matches(ev) {
		t.Fatal("title_contains must not match a different title")
	}
}

// ── body_contains ─────────────────────────────────────────────────────────────

func TestBodyContainsMatch(t *testing.T) {
	p := mustParse(t, `
name: wordpress
match:
  any:
    - body_contains: "wp-content"
`)
	ev := playbook.Evidence{Body512: `<link href="/wp-content/themes/`}
	if !p.Matches(ev) {
		t.Fatal("body_contains must match when body prefix contains the substring")
	}
}

func TestBodyContainsNoMatch(t *testing.T) {
	p := mustParse(t, `
name: wordpress
match:
  any:
    - body_contains: "wp-content"
`)
	ev := playbook.Evidence{Body512: `<html><head><title>Hello</title>`}
	if p.Matches(ev) {
		t.Fatal("body_contains must not match when body does not contain the substring")
	}
}

// ── cert_san_contains ─────────────────────────────────────────────────────────

func TestCertSANContainsMatchesAnySAN(t *testing.T) {
	p := mustParse(t, `
name: aws_ec2
match:
  any:
    - cert_san_contains: ".compute.amazonaws.com"
`)
	ev := playbook.Evidence{CertSANs: []string{"ec2-1-2-3-4.compute.amazonaws.com"}}
	if !p.Matches(ev) {
		t.Fatal("cert_san_contains must match when any SAN contains the substring")
	}
}

func TestCertSANContainsNoMatchWhenSANsEmpty(t *testing.T) {
	p := mustParse(t, `
name: aws_ec2
match:
  any:
    - cert_san_contains: ".compute.amazonaws.com"
`)
	ev := playbook.Evidence{CertSANs: []string{}}
	if p.Matches(ev) {
		t.Fatal("cert_san_contains must not match when SAN list is empty")
	}
}

// ── path_responds ─────────────────────────────────────────────────────────────

func TestPathRespondsMatchesKnownPath(t *testing.T) {
	p := mustParse(t, `
name: jenkins
match:
  any:
    - path_responds: "/login"
`)
	ev := playbook.Evidence{RespondingPaths: []string{"/login", "/api"}}
	if !p.Matches(ev) {
		t.Fatal("path_responds must match when the path is in RespondingPaths")
	}
}

func TestPathRespondsNoMatchWhenPathAbsent(t *testing.T) {
	p := mustParse(t, `
name: jenkins
match:
  any:
    - path_responds: "/login"
`)
	ev := playbook.Evidence{RespondingPaths: []string{"/health"}}
	if p.Matches(ev) {
		t.Fatal("path_responds must not match when the path is not in RespondingPaths")
	}
}

// ── any combinator ────────────────────────────────────────────────────────────

func TestAnyCombinatorMatchesWhenOneRuleMatches(t *testing.T) {
	p := mustParse(t, `
name: test
match:
  any:
    - header_present: "cf-ray"
    - asn_org_contains: "CLOUDFLARE"
`)
	// Only the second rule matches.
	ev := playbook.Evidence{
		ASNOrg:  "Cloudflare, Inc.",
		Headers: map[string]string{},
	}
	if !p.Matches(ev) {
		t.Fatal("any combinator must match when at least one rule is satisfied")
	}
}

func TestAnyCombinatorNoMatchWhenNoRulesMatch(t *testing.T) {
	p := mustParse(t, `
name: test
match:
  any:
    - header_present: "cf-ray"
    - asn_org_contains: "CLOUDFLARE"
`)
	ev := playbook.Evidence{
		ASNOrg:  "Amazon AWS",
		Headers: map[string]string{"server": "nginx"},
	}
	if p.Matches(ev) {
		t.Fatal("any combinator must not match when no rules are satisfied")
	}
}

// ── all combinator ────────────────────────────────────────────────────────────

func TestAllCombinatorMatchesOnlyWhenEveryRuleMatches(t *testing.T) {
	p := mustParse(t, `
name: test
match:
  all:
    - header_present: "cf-ray"
    - asn_org_contains: "CLOUDFLARE"
`)
	ev := playbook.Evidence{
		ASNOrg:  "Cloudflare, Inc.",
		Headers: map[string]string{"cf-ray": "abc"},
	}
	if !p.Matches(ev) {
		t.Fatal("all combinator must match when every rule is satisfied")
	}
}

func TestAllCombinatorNoMatchWhenOneRuleFails(t *testing.T) {
	p := mustParse(t, `
name: test
match:
  all:
    - header_present: "cf-ray"
    - asn_org_contains: "CLOUDFLARE"
`)
	// cf-ray present, but ASN org is not Cloudflare.
	ev := playbook.Evidence{
		ASNOrg:  "Amazon AWS",
		Headers: map[string]string{"cf-ray": "abc"},
	}
	if p.Matches(ev) {
		t.Fatal("all combinator must not match when any rule is unsatisfied")
	}
}

// ── empty match config ────────────────────────────────────────────────────────

// TestParsePlaybook_EmptyRuleWarning verifies that ParsePlaybook does not return
// an error (and does not panic) when a playbook contains a rule with no conditions.
// The warning is emitted to the log — we just verify parsing succeeds and the
// resulting playbook does not match any evidence (consistent with ruleMatches behaviour).
func TestParsePlaybook_EmptyRuleWarning(t *testing.T) {
	p, err := playbook.ParsePlaybook([]byte(`
name: test_empty_rule
match:
  any:
    - {}
`))
	if err != nil {
		t.Fatalf("ParsePlaybook returned unexpected error: %v", err)
	}
	// An empty rule inside any: should never match.
	if p.Matches(playbook.Evidence{ASNOrg: "anything", Headers: map[string]string{"x-foo": "bar"}}) {
		t.Error("playbook with only empty rules must not match any evidence")
	}
}

func TestEmptyMatchNeverMatches(t *testing.T) {
	p := mustParse(t, `
name: test
match: {}
`)
	// No always, no any, no all — must not match anything.
	ev := playbook.Evidence{
		ASNOrg:  "Cloudflare",
		Headers: map[string]string{"cf-ray": "abc"},
		Title:   "Grafana",
	}
	if p.Matches(ev) {
		t.Fatal("a playbook with an empty match config must not match any evidence")
	}
}

// TestMatch_EmptyAnyNeverMatches verifies that an any: list with zero rules
// never matches, regardless of the evidence supplied.
func TestMatch_EmptyAnyNeverMatches(t *testing.T) {
	// We express this via a playbook whose match block has an any: list that is
	// syntactically empty (only whitespace after the key). ParsePlaybook should
	// treat this the same as a nil/missing any list — no rules means no match.
	p := mustParse(t, `
name: test_empty_any
match:
  any: []
`)
	ev := playbook.Evidence{
		ASNOrg:  "Cloudflare",
		Headers: map[string]string{"cf-ray": "abc", "x-sucuri-id": "1"},
		Title:   "Admin Panel",
	}
	if p.Matches(ev) {
		t.Fatal("Match{Any: []} must never match any evidence — empty rule list has no satisfying assignment")
	}
}

// TestMatch_AllConditionsAND verifies that a playbook with two rules in all:
// only matches when BOTH conditions are satisfied simultaneously.
func TestMatch_AllConditionsAND(t *testing.T) {
	p := mustParse(t, `
name: test_all_and
match:
  all:
    - header_present: "cf-ray"
    - asn_org_contains: "CLOUDFLARE"
`)

	// Both conditions satisfied → must match.
	both := playbook.Evidence{
		ASNOrg:  "Cloudflare, Inc.",
		Headers: map[string]string{"cf-ray": "abc123"},
	}
	if !p.Matches(both) {
		t.Fatal("all: combinator must match when both conditions are satisfied")
	}

	// Only the first condition satisfied → must not match.
	onlyHeader := playbook.Evidence{
		ASNOrg:  "Amazon AWS",
		Headers: map[string]string{"cf-ray": "abc123"},
	}
	if p.Matches(onlyHeader) {
		t.Fatal("all: combinator must not match when the second condition is unsatisfied")
	}

	// Only the second condition satisfied → must not match.
	onlyASN := playbook.Evidence{
		ASNOrg:  "Cloudflare, Inc.",
		Headers: map[string]string{"server": "nginx"},
	}
	if p.Matches(onlyASN) {
		t.Fatal("all: combinator must not match when the first condition is unsatisfied")
	}
}

// TestMatch_LLMProviderCaseInsensitive verifies that llm_provider_contains
// performs a case-insensitive substring match against Evidence.LLMProvider.
// A rule specifying "OpenAI" should match an Evidence with LLMProvider "openai".
func TestMatch_LLMProviderCaseInsensitive(t *testing.T) {
	p := mustParse(t, `
name: test_llm_provider
match:
  any:
    - llm_provider_contains: "OpenAI"
`)

	// Mixed-case rule should match lower-case evidence value.
	ev := playbook.Evidence{LLMProvider: "openai"}
	if !p.Matches(ev) {
		t.Fatal("llm_provider_contains must match case-insensitively: 'OpenAI' should match 'openai'")
	}

	// Rule should not match an unrelated provider.
	evOther := playbook.Evidence{LLMProvider: "anthropic"}
	if p.Matches(evOther) {
		t.Fatal("llm_provider_contains must not match an unrelated provider")
	}

	// Empty LLMProvider should not match.
	evEmpty := playbook.Evidence{}
	if p.Matches(evEmpty) {
		t.Fatal("llm_provider_contains must not match when LLMProvider is empty")
	}
}

// TestMatch_AnyConditionsOR verifies that a playbook with two rules in any:
// matches when EITHER (or both) conditions are satisfied.
func TestMatch_AnyConditionsOR(t *testing.T) {
	p := mustParse(t, `
name: test_any_or
match:
  any:
    - header_present: "cf-ray"
    - asn_org_contains: "CLOUDFLARE"
`)

	// Only the first condition satisfied → must match.
	onlyHeader := playbook.Evidence{
		ASNOrg:  "Amazon AWS",
		Headers: map[string]string{"cf-ray": "xyz789"},
	}
	if !p.Matches(onlyHeader) {
		t.Fatal("any: combinator must match when the first condition alone is satisfied")
	}

	// Only the second condition satisfied → must match.
	onlyASN := playbook.Evidence{
		ASNOrg:  "Cloudflare, Inc.",
		Headers: map[string]string{"server": "nginx"},
	}
	if !p.Matches(onlyASN) {
		t.Fatal("any: combinator must match when the second condition alone is satisfied")
	}

	// Neither condition satisfied → must not match.
	neither := playbook.Evidence{
		ASNOrg:  "Amazon AWS",
		Headers: map[string]string{"server": "nginx"},
	}
	if p.Matches(neither) {
		t.Fatal("any: combinator must not match when neither condition is satisfied")
	}
}
