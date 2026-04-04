package fingerprintdb

import (
	"testing"

	"github.com/stormbane-security/beacon/internal/playbook"
	"github.com/stormbane-security/beacon/internal/store"
)

// activeRule returns a minimal active FingerprintRule for the given signal/field.
func activeRule(signalType, signalKey, signalValue, field, value string) store.FingerprintRule {
	return store.FingerprintRule{
		SignalType:  signalType,
		SignalKey:   signalKey,
		SignalValue: signalValue,
		Field:       field,
		Value:       value,
		Status:      "active",
	}
}

// ---------------------------------------------------------------------------
// Nil Headers map must not panic
// ---------------------------------------------------------------------------

func TestMatchSignal_NilHeaders_NoMatch(t *testing.T) {
	ev := &playbook.Evidence{Headers: nil}
	rule := activeRule("header", "cf-ray", "", "cloud_provider", "cloudflare")

	// Must not panic — this was previously a nil-map dereference.
	Apply([]store.FingerprintRule{rule}, ev)

	if ev.CloudProvider != "" {
		t.Errorf("expected no match on nil Headers, got CloudProvider=%q", ev.CloudProvider)
	}
}

func TestMatchSignal_NilHeaders_ServerAlias_NoMatch(t *testing.T) {
	ev := &playbook.Evidence{Headers: nil}
	rule := activeRule("server", "", "nginx", "proxy_type", "nginx")

	// Must not panic.
	Apply([]store.FingerprintRule{rule}, ev)

	if ev.ProxyType != "" {
		t.Errorf("expected no match for server rule with nil Headers, got ProxyType=%q", ev.ProxyType)
	}
}

// ---------------------------------------------------------------------------
// Header rule: match and no-match
// ---------------------------------------------------------------------------

func TestMatchSignal_HeaderPresent_Matches(t *testing.T) {
	ev := &playbook.Evidence{
		Headers: map[string]string{"cf-ray": "abc123-LAX"},
	}
	rule := activeRule("header", "cf-ray", "", "cloud_provider", "cloudflare")
	Apply([]store.FingerprintRule{rule}, ev)

	if ev.CloudProvider != "cloudflare" {
		t.Errorf("expected CloudProvider=cloudflare, got %q", ev.CloudProvider)
	}
}

func TestMatchSignal_HeaderValue_Matches(t *testing.T) {
	ev := &playbook.Evidence{
		Headers: map[string]string{"server": "nginx/1.25.3"},
	}
	rule := activeRule("server", "", "nginx", "proxy_type", "nginx")
	Apply([]store.FingerprintRule{rule}, ev)

	if ev.ProxyType != "nginx" {
		t.Errorf("expected ProxyType=nginx, got %q", ev.ProxyType)
	}
}

func TestMatchSignal_HeaderValue_NoMatch(t *testing.T) {
	ev := &playbook.Evidence{
		Headers: map[string]string{"server": "Apache"},
	}
	rule := activeRule("server", "", "nginx", "proxy_type", "nginx")
	Apply([]store.FingerprintRule{rule}, ev)

	if ev.ProxyType != "" {
		t.Errorf("expected no match for server=Apache with nginx rule, got ProxyType=%q", ev.ProxyType)
	}
}

// ---------------------------------------------------------------------------
// Pending rule must not apply
// ---------------------------------------------------------------------------

func TestPendingRule_NeverApplied(t *testing.T) {
	ev := &playbook.Evidence{
		Headers: map[string]string{"cf-ray": "abc123-LAX"},
	}
	rule := store.FingerprintRule{
		SignalType:  "header",
		SignalKey:   "cf-ray",
		SignalValue: "",
		Field:       "cloud_provider",
		Value:       "cloudflare",
		Status:      "pending", // not active — must be ignored
	}
	Apply([]store.FingerprintRule{rule}, ev)

	if ev.CloudProvider != "" {
		t.Errorf("pending rule must not set fields, got CloudProvider=%q", ev.CloudProvider)
	}
}

// ---------------------------------------------------------------------------
// Higher-priority value already set: rules must not overwrite
// ---------------------------------------------------------------------------

func TestSetField_DoesNotOverwriteExisting(t *testing.T) {
	ev := &playbook.Evidence{
		Headers:       map[string]string{"x-powered-by": "express"},
		CloudProvider: "aws", // already set by a higher-priority source
	}
	rule := activeRule("header", "x-powered-by", "express", "cloud_provider", "gcp")
	Apply([]store.FingerprintRule{rule}, ev)

	if ev.CloudProvider != "aws" {
		t.Errorf("existing CloudProvider must not be overwritten, got %q", ev.CloudProvider)
	}
}

// ---------------------------------------------------------------------------
// backend_services: additive (no duplicates)
// ---------------------------------------------------------------------------

func TestSetField_BackendServices_Additive(t *testing.T) {
	ev := &playbook.Evidence{
		Headers:         map[string]string{"x-powered-by": "express"},
		BackendServices: []string{"redis"},
	}
	rule := activeRule("header", "x-powered-by", "express", "backend_services", "node")
	Apply([]store.FingerprintRule{rule}, ev)

	found := false
	for _, s := range ev.BackendServices {
		if s == "node" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'node' to be appended to BackendServices")
	}
	if len(ev.BackendServices) != 2 {
		t.Errorf("expected BackendServices len=2, got %d: %v", len(ev.BackendServices), ev.BackendServices)
	}
}

func TestSetField_BackendServices_NoDuplicates(t *testing.T) {
	ev := &playbook.Evidence{
		Headers:         map[string]string{"x-powered-by": "express"},
		BackendServices: []string{"node"},
	}
	rule := activeRule("header", "x-powered-by", "express", "backend_services", "node")
	Apply([]store.FingerprintRule{rule}, ev)

	if len(ev.BackendServices) != 1 {
		t.Errorf("duplicate backend_service must not be added, got %d: %v", len(ev.BackendServices), ev.BackendServices)
	}
}

// ---------------------------------------------------------------------------
// Body signal matching
// ---------------------------------------------------------------------------

func TestMatchSignal_Body_Matches(t *testing.T) {
	ev := &playbook.Evidence{
		Body512: "<html><head><title>Welcome to nginx!</title></head>",
	}
	rule := activeRule("body", "", "welcome to nginx", "proxy_type", "nginx")
	Apply([]store.FingerprintRule{rule}, ev)

	if ev.ProxyType != "nginx" {
		t.Errorf("expected body match to set ProxyType=nginx, got %q", ev.ProxyType)
	}
}

func TestMatchSignal_Body_NoMatch(t *testing.T) {
	ev := &playbook.Evidence{
		Body512: "<html><head><title>Apache HTTP Server</title></head>",
	}
	rule := activeRule("body", "", "nginx", "proxy_type", "nginx")
	Apply([]store.FingerprintRule{rule}, ev)

	if ev.ProxyType != "" {
		t.Errorf("expected no match for nginx in Apache body, got ProxyType=%q", ev.ProxyType)
	}
}

// ---------------------------------------------------------------------------
// Path signal matching
// ---------------------------------------------------------------------------

func TestMatchSignal_Path_Matches(t *testing.T) {
	ev := &playbook.Evidence{
		Headers:         map[string]string{},
		RespondingPaths: []string{"/.well-known/openid-configuration"},
	}
	rule := activeRule("path", "", "/.well-known/openid-configuration", "auth_system", "oidc")
	Apply([]store.FingerprintRule{rule}, ev)

	if ev.AuthSystem != "oidc" {
		t.Errorf("expected path match to set AuthSystem=oidc, got %q", ev.AuthSystem)
	}
}

// ---------------------------------------------------------------------------
// Cookie signal matching
// ---------------------------------------------------------------------------

func TestMatchSignal_Cookie_Matches(t *testing.T) {
	ev := &playbook.Evidence{
		Headers:     map[string]string{},
		CookieNames: []string{"JSESSIONID", "csrftoken"},
	}
	rule := activeRule("cookie", "", "jsessionid", "framework", "java")
	Apply([]store.FingerprintRule{rule}, ev)

	if ev.Framework != "java" {
		t.Errorf("expected cookie match to set Framework=java, got %q", ev.Framework)
	}
}

// ---------------------------------------------------------------------------
// Title signal matching
// ---------------------------------------------------------------------------

func TestMatchSignal_Title_Matches(t *testing.T) {
	ev := &playbook.Evidence{
		Headers: map[string]string{},
		Title:   "Grafana",
	}
	rule := activeRule("title", "", "grafana", "backend_services", "grafana")
	Apply([]store.FingerprintRule{rule}, ev)

	found := false
	for _, s := range ev.BackendServices {
		if s == "grafana" {
			found = true
		}
	}
	if !found {
		t.Error("expected title match to add grafana to BackendServices")
	}
}

// ---------------------------------------------------------------------------
// CNAME signal matching
// ---------------------------------------------------------------------------

func TestMatchSignal_CNAME_Matches(t *testing.T) {
	ev := &playbook.Evidence{
		Headers:    map[string]string{},
		CNAMEChain: []string{"example.com.cdn.cloudflare.net"},
	}
	rule := activeRule("cname", "", "cloudflare", "cloud_provider", "cloudflare")
	Apply([]store.FingerprintRule{rule}, ev)

	if ev.CloudProvider != "cloudflare" {
		t.Errorf("expected cname match to set CloudProvider=cloudflare, got %q", ev.CloudProvider)
	}
}

// ---------------------------------------------------------------------------
// Realistic service fingerprint scenarios (end-to-end classify)
// ---------------------------------------------------------------------------

func TestFingerprint_NginxProxy(t *testing.T) {
	rules := BuiltinRules()
	ev := &playbook.Evidence{
		Headers: map[string]string{"server": "nginx/1.25.3"},
	}
	Apply(rules, ev)

	if ev.ProxyType != "nginx" {
		t.Errorf("nginx server header should set ProxyType=nginx, got %q", ev.ProxyType)
	}
}

func TestFingerprint_ApacheProxy(t *testing.T) {
	rules := BuiltinRules()
	ev := &playbook.Evidence{
		Headers: map[string]string{"server": "Apache/2.4.58 (Ubuntu)"},
	}
	Apply(rules, ev)

	if ev.ProxyType != "apache" {
		t.Errorf("Apache server header should set ProxyType=apache, got %q", ev.ProxyType)
	}
}

func TestFingerprint_CloudflareHeaders(t *testing.T) {
	rules := BuiltinRules()
	ev := &playbook.Evidence{
		Headers: map[string]string{
			"cf-ray": "abc123-LAX",
			"server": "cloudflare",
		},
	}
	Apply(rules, ev)

	if ev.CloudProvider != "cloudflare" {
		t.Errorf("cf-ray header should set CloudProvider=cloudflare, got %q", ev.CloudProvider)
	}
}

func TestFingerprint_AWSHeaders(t *testing.T) {
	rules := BuiltinRules()
	ev := &playbook.Evidence{
		Headers: map[string]string{
			"x-amzn-requestid": "ABCD1234EFGH5678",
		},
	}
	Apply(rules, ev)

	if ev.CloudProvider != "aws" {
		t.Errorf("x-amzn-requestid should set CloudProvider=aws, got %q", ev.CloudProvider)
	}
}

func TestFingerprint_ExpressFramework(t *testing.T) {
	rules := BuiltinRules()
	ev := &playbook.Evidence{
		Headers: map[string]string{
			"x-powered-by": "Express",
		},
	}
	Apply(rules, ev)

	found := false
	for _, s := range ev.BackendServices {
		if s == "express" || s == "node" || s == "nodejs" {
			found = true
		}
	}
	if ev.Framework == "" && !found {
		t.Error("Express x-powered-by should set Framework or add to BackendServices")
	}
}

func TestFingerprint_PHPFramework(t *testing.T) {
	rules := BuiltinRules()
	ev := &playbook.Evidence{
		Headers: map[string]string{
			"x-powered-by": "PHP/8.2.0",
		},
	}
	Apply(rules, ev)

	if ev.Framework != "php" {
		t.Errorf("PHP x-powered-by should set Framework=php, got %q", ev.Framework)
	}
}

func TestFingerprint_GrafanaPath(t *testing.T) {
	rules := BuiltinRules()
	ev := &playbook.Evidence{
		Headers:         map[string]string{},
		RespondingPaths: []string{"/api/health"},
	}
	Apply(rules, ev)

	found := false
	for _, s := range ev.BackendServices {
		if s == "grafana" {
			found = true
		}
	}
	if !found {
		t.Error("Grafana /api/health path should add grafana to BackendServices")
	}
}

func TestFingerprint_TeamCityPath(t *testing.T) {
	rules := BuiltinRules()
	ev := &playbook.Evidence{
		Headers:         map[string]string{},
		RespondingPaths: []string{"/app/rest/server"},
	}
	Apply(rules, ev)

	found := false
	for _, s := range ev.BackendServices {
		if s == "teamcity" {
			found = true
		}
	}
	if !found {
		t.Error("TeamCity /app/rest/server path should add teamcity to BackendServices")
	}
}

func TestFingerprint_GCPHeaders(t *testing.T) {
	rules := BuiltinRules()
	ev := &playbook.Evidence{
		Headers: map[string]string{
			"x-goog-request-id": "1234567890",
		},
	}
	Apply(rules, ev)

	if ev.CloudProvider != "gcp" {
		t.Errorf("x-goog-request-id should set CloudProvider=gcp, got %q", ev.CloudProvider)
	}
}

func TestFingerprint_OIDC_Path(t *testing.T) {
	rules := BuiltinRules()
	ev := &playbook.Evidence{
		Headers:         map[string]string{},
		RespondingPaths: []string{"/.well-known/openid-configuration"},
	}
	Apply(rules, ev)

	if ev.AuthSystem != "oidc" {
		t.Errorf("OIDC well-known path should set AuthSystem=oidc, got %q", ev.AuthSystem)
	}
}
