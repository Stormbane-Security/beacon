// Package fingerprintdb provides a data-driven fingerprint rule engine.
// Rules are stored in the beacon SQLite database and applied to Evidence
// after the deterministic fingerprintTech() pass to fill remaining gaps.
//
// Rule evaluation order:
//  1. builtin rules (seeded from code on first run) — highest priority
//  2. user rules (added via `beacon fingerprints add`)
//  3. ai rules (discovered by Claude FillGaps)
//
// Rules with status="pending" are never applied — they require human approval
// via `beacon fingerprints approve <id>` first.
package fingerprintdb

import (
	"context"
	"strings"

	"github.com/stormbane/beacon/internal/playbook"
	"github.com/stormbane/beacon/internal/store"
)

// Apply evaluates all active rules against ev and fills any empty Evidence
// fields. Rules only fill fields that are currently empty — they never
// overwrite values already set by fingerprintTech() or higher-priority rules.
// The backend_services field is additive: rules append to it.
func Apply(rules []store.FingerprintRule, ev *playbook.Evidence) {
	for _, r := range rules {
		if r.Status != "active" {
			continue
		}
		if !matchSignal(r, ev) {
			continue
		}
		setField(r.Field, r.Value, ev)
	}
}

// matchSignal returns true when the rule's signal matches the evidence.
func matchSignal(r store.FingerprintRule, ev *playbook.Evidence) bool {
	needle := strings.ToLower(r.SignalValue)
	switch r.SignalType {
	case "header":
		key := strings.ToLower(r.SignalKey)
		val := strings.ToLower(ev.Headers[key])
		// Empty SignalValue means "header exists with any value".
		if needle == "" {
			return val != ""
		}
		return strings.Contains(val, needle)
	case "body":
		return strings.Contains(strings.ToLower(ev.Body512), needle)
	case "path":
		for _, p := range ev.RespondingPaths {
			if strings.Contains(strings.ToLower(p), needle) {
				return true
			}
		}
	case "cookie":
		for _, c := range ev.CookieNames {
			if strings.Contains(strings.ToLower(c), needle) {
				return true
			}
		}
	case "cname":
		for _, c := range ev.CNAMEChain {
			if strings.Contains(strings.ToLower(c), needle) {
				return true
			}
		}
	case "title":
		return strings.Contains(strings.ToLower(ev.Title), needle)
	case "dns_suffix":
		return strings.Contains(strings.ToLower(ev.DNSSuffix), needle)
	case "asn_org":
		return strings.Contains(strings.ToLower(ev.ASNOrg), needle)
	case "server":
		// Convenience alias for header "server".
		return strings.Contains(strings.ToLower(ev.Headers["server"]), needle)
	}
	return false
}

// setField assigns value to the named Evidence field, respecting these rules:
//   - Most fields: only set when currently empty (never overwrite).
//   - backend_services: always append (additive).
func setField(field, value string, ev *playbook.Evidence) {
	switch field {
	case "framework":
		if ev.Framework == "" {
			ev.Framework = value
		}
	case "proxy_type":
		if ev.ProxyType == "" {
			ev.ProxyType = value
		}
	case "auth_system":
		if ev.AuthSystem == "" {
			ev.AuthSystem = value
		}
	case "cloud_provider":
		if ev.CloudProvider == "" {
			ev.CloudProvider = value
		}
	case "infra_layer":
		if ev.InfraLayer == "" {
			ev.InfraLayer = value
		}
	case "backend_services":
		// Avoid duplicates.
		for _, s := range ev.BackendServices {
			if strings.EqualFold(s, value) {
				return
			}
		}
		ev.BackendServices = append(ev.BackendServices, value)
	}
}

// Seed inserts the builtin rules into the database if they don't already exist.
// Should be called once at startup. Uses upsert so running multiple times is safe.
func Seed(ctx context.Context, st store.Store) error {
	for i := range builtinRules {
		if err := st.UpsertFingerprintRule(ctx, &builtinRules[i]); err != nil {
			return err
		}
	}
	return nil
}
