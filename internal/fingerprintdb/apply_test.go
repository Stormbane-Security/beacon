package fingerprintdb

import (
	"testing"

	"github.com/stormbane/beacon/internal/playbook"
	"github.com/stormbane/beacon/internal/store"
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
