// Package integration provides auto-generated and Docker-based integration
// tests for Beacon's detection pipeline.
//
// Tier 1 tests (this file) auto-generate test fixtures from Beacon's own
// fingerprint rules and playbook match conditions. Every rule becomes a test
// case — no hand-writing required. If someone adds a fingerprint rule, they
// get a regression test for free.
//
// Run: go test ./test/integration/ -run=TestFingerprintRules
package integration

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane-security/beacon/internal/fingerprintdb"
	"github.com/stormbane-security/beacon/internal/playbook"
	"github.com/stormbane-security/beacon/internal/store"
)

// TestFingerprintRules auto-generates a test case for every builtin
// fingerprint rule. For each rule, it creates an httptest server that
// emits the expected signal (header, body, cookie, etc.), builds an
// Evidence packet from that response, applies the rule, and asserts
// the correct field was set.
func TestFingerprintRules(t *testing.T) {
	rules := fingerprintdb.BuiltinRules()
	if len(rules) == 0 {
		t.Fatal("no builtin rules found")
	}

	for i, rule := range rules {
		name := fmt.Sprintf("%s/%s=%s", rule.SignalType, rule.Field, rule.Value)
		if rule.SignalKey != "" {
			name = fmt.Sprintf("%s[%s]/%s=%s", rule.SignalType, rule.SignalKey, rule.Field, rule.Value)
		}

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			// Build an Evidence packet that should trigger this rule.
			ev := evidenceForRule(rule)

			// Apply the single rule against the evidence.
			matched := fingerprintdb.Apply([]store.FingerprintRule{rule}, &ev)
			if len(matched) == 0 {
				t.Errorf("rule %d (%s→%s=%s) did not fire against generated evidence",
					i, rule.SignalType, rule.Field, rule.Value)
				return
			}

			// Verify the correct field was set.
			actual := evidenceField(ev, rule.Field)
			if rule.Field == "backend_services" {
				// backend_services is additive — check it contains the value.
				if !containsCI(ev.BackendServices, rule.Value) {
					t.Errorf("expected BackendServices to contain %q, got %v", rule.Value, ev.BackendServices)
				}
			} else if !strings.EqualFold(actual, rule.Value) {
				t.Errorf("expected %s=%q, got %q", rule.Field, rule.Value, actual)
			}
		})
	}
}

// TestFingerprintRules_HTTPServer verifies fingerprint rules against real
// HTTP responses by spinning up an httptest server for each header/body/server
// rule. This tests the full pipeline: HTTP response → Evidence → rule match.
func TestFingerprintRules_HTTPServer(t *testing.T) {
	rules := fingerprintdb.BuiltinRules()

	for i, rule := range rules {
		// Only test rules that can be expressed as HTTP responses.
		switch rule.SignalType {
		case "header", "server", "body", "cookie":
			// These can be served via httptest.
		default:
			continue // cname, dns_suffix, asn_org, path — need DNS/path infra.
		}

		name := fmt.Sprintf("http/%s/%s=%s", rule.SignalType, rule.Field, rule.Value)
		if rule.SignalKey != "" {
			name = fmt.Sprintf("http/%s[%s]/%s=%s", rule.SignalType, rule.SignalKey, rule.Field, rule.Value)
		}

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(ruleHandler(rule))
			defer srv.Close()

			// Build evidence from the server response.
			ev := collectHTTPEvidence(t, srv.URL)

			// Apply the rule.
			matched := fingerprintdb.Apply([]store.FingerprintRule{rule}, &ev)
			if len(matched) == 0 {
				t.Errorf("rule %d (%s→%s=%s) did not fire against HTTP server",
					i, rule.SignalType, rule.Field, rule.Value)
			}
		})
	}
}

// evidenceForRule builds a minimal Evidence that should trigger the given rule.
func evidenceForRule(r store.FingerprintRule) playbook.Evidence {
	ev := playbook.Evidence{
		Headers: make(map[string]string),
	}
	switch r.SignalType {
	case "header":
		key := strings.ToLower(r.SignalKey)
		if r.SignalValue == "" {
			ev.Headers[key] = "present"
		} else {
			ev.Headers[key] = r.SignalValue
		}
	case "server":
		ev.Headers["server"] = r.SignalValue
	case "body":
		ev.Body512 = r.SignalValue
	case "path":
		ev.RespondingPaths = []string{r.SignalValue}
	case "cookie":
		ev.CookieNames = []string{r.SignalValue}
	case "cname":
		ev.CNAMEChain = []string{"target" + r.SignalValue}
	case "title":
		ev.Title = r.SignalValue
	case "dns_suffix":
		ev.DNSSuffix = r.SignalValue
	case "asn_org":
		ev.ASNOrg = r.SignalValue
	}
	return ev
}

// ruleHandler returns an HTTP handler that emits the signal described by the rule.
func ruleHandler(r store.FingerprintRule) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch r.SignalType {
		case "header":
			if r.SignalValue == "" {
				w.Header().Set(r.SignalKey, "test-value")
			} else {
				w.Header().Set(r.SignalKey, r.SignalValue)
			}
		case "server":
			w.Header().Set("Server", r.SignalValue)
		case "body":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, "<html><body>%s</body></html>", r.SignalValue)
		case "cookie":
			http.SetCookie(w, &http.Cookie{Name: r.SignalValue, Value: "test"})
		}
		w.WriteHeader(http.StatusOK)
	})
}

// collectHTTPEvidence makes a GET request to the URL and builds a minimal
// Evidence packet from the response — headers, body, cookies.
func collectHTTPEvidence(t *testing.T, rawURL string) playbook.Evidence {
	t.Helper()
	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	defer resp.Body.Close()

	ev := playbook.Evidence{
		Headers: make(map[string]string),
	}

	// Collect headers (lowercase keys, like classify.go does).
	for k, vals := range resp.Header {
		ev.Headers[strings.ToLower(k)] = strings.Join(vals, ", ")
	}

	// Collect body prefix.
	buf := make([]byte, 512)
	n, _ := resp.Body.Read(buf)
	ev.Body512 = string(buf[:n])

	// Collect cookie names from Set-Cookie.
	for _, cookie := range resp.Cookies() {
		ev.CookieNames = append(ev.CookieNames, cookie.Name)
	}

	return ev
}

// evidenceField returns the value of the named Evidence field.
func evidenceField(ev playbook.Evidence, field string) string {
	switch field {
	case "framework":
		return ev.Framework
	case "proxy_type":
		return ev.ProxyType
	case "auth_system":
		return ev.AuthSystem
	case "cloud_provider":
		return ev.CloudProvider
	case "infra_layer":
		return ev.InfraLayer
	case "backend_services":
		return strings.Join(ev.BackendServices, ",")
	default:
		return ""
	}
}

// containsCI checks if slice contains value (case-insensitive).
func containsCI(slice []string, val string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, val) {
			return true
		}
	}
	return false
}
