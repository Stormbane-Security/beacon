package playbook

import (
	"testing"
)

func TestMatches_AlwaysTrue(t *testing.T) {
	p := Playbook{
		Name:  "baseline",
		Match: MatchConfig{Always: true},
	}
	e := Evidence{} // empty evidence
	if !p.Matches(e) {
		t.Error("always:true playbook should match any evidence")
	}
}

func TestMatches_AnyMatch(t *testing.T) {
	p := Playbook{
		Name: "wordpress",
		Match: MatchConfig{
			Any: []MatchRule{
				{BodyContains: "wp-content"},
				{BodyContains: "wp-includes"},
			},
		},
	}

	// Should match when body contains one of the patterns.
	e := Evidence{Body512: "some text with wp-content/themes"}
	if !p.Matches(e) {
		t.Error("any-rule playbook should match when body contains wp-content")
	}

	// Should NOT match when body has no matching content.
	e2 := Evidence{Body512: "just a normal page"}
	if p.Matches(e2) {
		t.Error("any-rule playbook should not match unrelated body content")
	}
}

func TestMatches_AllMatch(t *testing.T) {
	p := Playbook{
		Name: "test_all",
		Match: MatchConfig{
			All: []MatchRule{
				{FrameworkContains: "django"},
				{CloudProviderContains: "aws"},
			},
		},
	}

	// Should match when ALL conditions are met.
	e := Evidence{Framework: "django", CloudProvider: "aws"}
	if !p.Matches(e) {
		t.Error("all-rules playbook should match when all conditions met")
	}

	// Should NOT match when only one condition is met.
	e2 := Evidence{Framework: "django", CloudProvider: "gcp"}
	if p.Matches(e2) {
		t.Error("all-rules playbook should not match when only one condition met")
	}
}

func TestMatches_AllAndAnyCombined(t *testing.T) {
	// This tests the bug fixed in round 2: combined All + Any evaluation.
	// When both All and Any are present, ALL of the All conditions must match
	// AND at least one Any condition must also match.
	p := Playbook{
		Name: "combined_test",
		Match: MatchConfig{
			All: []MatchRule{
				{CloudProviderContains: "aws"},
			},
			Any: []MatchRule{
				{FrameworkContains: "django"},
				{FrameworkContains: "flask"},
			},
		},
	}

	// Case 1: All conditions met + one Any condition met -> should match
	e1 := Evidence{CloudProvider: "aws", Framework: "django"}
	if !p.Matches(e1) {
		t.Error("combined All+Any: should match when all All met and one Any met")
	}

	// Case 2: All conditions met + different Any condition met -> should match
	e2 := Evidence{CloudProvider: "aws", Framework: "flask"}
	if !p.Matches(e2) {
		t.Error("combined All+Any: should match when all All met and a different Any met")
	}

	// Case 3: All conditions met + NO Any condition met -> should NOT match
	e3 := Evidence{CloudProvider: "aws", Framework: "rails"}
	if p.Matches(e3) {
		t.Error("combined All+Any: should NOT match when All met but no Any met")
	}

	// Case 4: All conditions NOT met + Any condition met -> should NOT match
	e4 := Evidence{CloudProvider: "gcp", Framework: "django"}
	if p.Matches(e4) {
		t.Error("combined All+Any: should NOT match when All not met even if Any met")
	}

	// Case 5: Neither All nor Any met -> should NOT match
	e5 := Evidence{CloudProvider: "gcp", Framework: "rails"}
	if p.Matches(e5) {
		t.Error("combined All+Any: should NOT match when neither All nor Any met")
	}
}

func TestMatches_AllAndAnyCombined_MultipleAllRules(t *testing.T) {
	p := Playbook{
		Name: "multi_all",
		Match: MatchConfig{
			All: []MatchRule{
				{CloudProviderContains: "aws"},
				{AuthSystemContains: "cognito"},
			},
			Any: []MatchRule{
				{FrameworkContains: "django"},
				{FrameworkContains: "express"},
			},
		},
	}

	// All All met + one Any met -> match
	e1 := Evidence{CloudProvider: "aws", AuthSystem: "cognito", Framework: "django"}
	if !p.Matches(e1) {
		t.Error("should match: all All conditions and one Any condition met")
	}

	// One All not met + Any met -> no match
	e2 := Evidence{CloudProvider: "aws", AuthSystem: "okta", Framework: "django"}
	if p.Matches(e2) {
		t.Error("should not match: one All condition (cognito) not met")
	}
}

func TestMatches_EmptyRuleNeverMatches(t *testing.T) {
	p := Playbook{
		Name: "empty_rule",
		Match: MatchConfig{
			Any: []MatchRule{
				{}, // empty rule: no conditions set
			},
		},
	}
	e := Evidence{Body512: "anything"}
	if p.Matches(e) {
		t.Error("empty rule with no conditions should never match")
	}
}

func TestMatches_NoMatchConfig(t *testing.T) {
	// A playbook with no match config at all should never match.
	p := Playbook{Name: "no_match"}
	e := Evidence{Body512: "anything"}
	if p.Matches(e) {
		t.Error("playbook with no match config should not match")
	}
}

func TestParsePlaybook_BasicYAML(t *testing.T) {
	yaml := `
name: test
description: A test playbook
match:
  any:
    - body_contains: "wp-content"
    - framework_contains: "django"
surface:
  scanners:
    - cors
    - tls
`
	p, err := ParsePlaybook([]byte(yaml))
	if err != nil {
		t.Fatalf("ParsePlaybook: %v", err)
	}
	if p.Name != "test" {
		t.Errorf("Name = %q, want %q", p.Name, "test")
	}
	if len(p.Match.Any) != 2 {
		t.Errorf("Match.Any length = %d, want 2", len(p.Match.Any))
	}
	if len(p.Surface.Scanners) != 2 {
		t.Errorf("Surface.Scanners length = %d, want 2", len(p.Surface.Scanners))
	}
}

func TestRuleMatches_HeaderValue(t *testing.T) {
	rule := MatchRule{
		HeaderValue: &HeaderValueMatch{
			Name:     "set-cookie",
			Contains: "csrftoken",
		},
	}
	e := Evidence{Headers: map[string]string{"set-cookie": "csrftoken=abc123; path=/"}}
	if !ruleMatches(rule, e) {
		t.Error("header_value rule should match when header contains substring")
	}

	e2 := Evidence{Headers: map[string]string{"set-cookie": "session=xyz"}}
	if ruleMatches(rule, e2) {
		t.Error("header_value rule should not match when header lacks substring")
	}
}

// ---------------------------------------------------------------------------
// Integration tests: real playbook YAML matching
// ---------------------------------------------------------------------------

func TestIntegration_BaselineMatchesAnything(t *testing.T) {
	reg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	baseline := reg.Get("baseline")
	if baseline == nil {
		t.Fatal("baseline playbook not found in registry")
	}

	// Baseline has always:true, so it should match even empty evidence.
	if !baseline.Matches(Evidence{}) {
		t.Error("baseline should match empty evidence")
	}
	if !baseline.Matches(Evidence{Body512: "random text"}) {
		t.Error("baseline should match arbitrary evidence")
	}
}

func TestIntegration_WordPressMatchesWPContent(t *testing.T) {
	reg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	wp := reg.Get("wordpress")
	if wp == nil {
		t.Fatal("wordpress playbook not found in registry")
	}

	// Should match: body contains wp-content
	e := Evidence{Body512: "<link rel='stylesheet' href='/wp-content/themes/flavor/style.css'>"}
	if !wp.Matches(e) {
		t.Error("wordpress should match body containing wp-content")
	}

	// Should match: path_responds wp-login.php
	e2 := Evidence{RespondingPaths: []string{"/wp-login.php"}}
	if !wp.Matches(e2) {
		t.Error("wordpress should match when /wp-login.php responds")
	}

	// Should NOT match: unrelated body content
	e3 := Evidence{Body512: "Welcome to our Rails application"}
	if wp.Matches(e3) {
		t.Error("wordpress should not match unrelated body content")
	}
}

func TestIntegration_DjangoMatchesFramework(t *testing.T) {
	reg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	dj := reg.Get("django")
	if dj == nil {
		t.Fatal("django playbook not found in registry")
	}

	// Should match: framework_contains django
	e := Evidence{Framework: "django"}
	if !dj.Matches(e) {
		t.Error("django should match evidence with framework=django")
	}

	// Should match: body contains Django
	e2 := Evidence{Body512: "Django Debug Page: DJANGO_SETTINGS_MODULE not found"}
	if !dj.Matches(e2) {
		t.Error("django should match body containing Django")
	}

	// Should match: csrftoken cookie
	e3 := Evidence{Headers: map[string]string{"set-cookie": "csrftoken=abc123"}}
	if !dj.Matches(e3) {
		t.Error("django should match csrftoken cookie header")
	}

	// Should NOT match: just having x-frame-options or other generic headers
	e4 := Evidence{Headers: map[string]string{"x-frame-options": "SAMEORIGIN"}}
	if dj.Matches(e4) {
		t.Error("django should NOT match generic x-frame-options header alone")
	}

	// Should NOT match: random framework
	e5 := Evidence{Framework: "rails"}
	if dj.Matches(e5) {
		t.Error("django should not match framework=rails")
	}
}

func TestIntegration_RegistryMatch_BaselineAlwaysFirst(t *testing.T) {
	reg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// WordPress evidence should match both baseline and wordpress.
	e := Evidence{Body512: "wp-content/themes/flavor"}
	matched := reg.Match(e)
	if len(matched) < 2 {
		t.Fatalf("expected at least 2 matched playbooks, got %d", len(matched))
	}
	if matched[0].Name != "baseline" {
		t.Errorf("first matched playbook = %q, want %q", matched[0].Name, "baseline")
	}
	foundWP := false
	for _, p := range matched {
		if p.Name == "wordpress" {
			foundWP = true
			break
		}
	}
	if !foundWP {
		t.Error("wordpress playbook not matched for wp-content evidence")
	}
}

func TestRuleMatches_CheckIDPresent(t *testing.T) {
	rule := MatchRule{CheckIDPresent: "netdev.mikrotik_detected"}
	e := Evidence{PhaseACheckIDs: []string{"port.ssh_open", "netdev.mikrotik_detected"}}
	if !ruleMatches(rule, e) {
		t.Error("check_id rule should match when PhaseACheckIDs contains the ID")
	}

	e2 := Evidence{PhaseACheckIDs: []string{"port.ssh_open"}}
	if ruleMatches(rule, e2) {
		t.Error("check_id rule should not match when PhaseACheckIDs lacks the ID")
	}
}
