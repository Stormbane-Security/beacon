package fingerprintdb

import (
	"github.com/stormbane-security/beacon/internal/store"
	"github.com/stormbane-security/infra"
)

// BuiltinRules returns a copy of all builtin fingerprint rules for use in
// auto-generated integration tests. Combines rules from the infra module's
// technology YAML with protocol-level signals that don't map to a technology.
func BuiltinRules() []store.FingerprintRule {
	rules := infraRules()
	rules = append(rules, protocolRules...)
	cp := make([]store.FingerprintRule, len(rules))
	copy(cp, rules)
	return cp
}

// infraRules converts infra.AllFingerprints() to store.FingerprintRule format.
func infraRules() []store.FingerprintRule {
	fps := infra.AllFingerprints()
	rules := make([]store.FingerprintRule, len(fps))
	for i, fp := range fps {
		rules[i] = store.FingerprintRule{
			SignalType:  fp.Signal,
			SignalKey:   fp.Key,
			SignalValue: fp.Match,
			Field:       fp.Field,
			Value:       fp.Value,
			Source:      "builtin",
			Status:      "active",
			Confidence:  fp.Confidence,
		}
	}
	return rules
}

// builtinRules is the combined rule set used by Seed().
var builtinRules []store.FingerprintRule

func init() {
	builtinRules = BuiltinRules()
}

// protocolRules are detection signals for protocols and concepts that don't
// map to a specific technology in infra. These stay in Beacon because they
// detect authentication mechanisms and generic protocols, not products.
var protocolRules = []store.FingerprintRule{
	// ── Auth protocols ────────────────────────────────────────────────────
	{SignalType: "path", SignalKey: "", SignalValue: "/.well-known/openid-configuration", Field: "auth_system", Value: "oidc", Source: "builtin", Status: "active", Confidence: 1.0},
	{SignalType: "path", SignalKey: "", SignalValue: "/saml", Field: "auth_system", Value: "saml", Source: "builtin", Status: "active", Confidence: 0.85},

	// ── Web3 wallet injection ─────────────────────────────────────────────
	{SignalType: "body", SignalKey: "", SignalValue: "window.ethereum", Field: "auth_system", Value: "web3_wallet", Source: "builtin", Status: "active", Confidence: 0.95},
	{SignalType: "body", SignalKey: "", SignalValue: "window.solana", Field: "auth_system", Value: "solana_wallet", Source: "builtin", Status: "active", Confidence: 0.95},

	// ── JSON-RPC detection ────────────────────────────────────────────────
	{SignalType: "body", SignalKey: "", SignalValue: "\"jsonrpc\"", Field: "backend_services", Value: "jsonrpc", Source: "builtin", Status: "active", Confidence: 0.7},
}
