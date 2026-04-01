package okta_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanner/okta"
)

func hasCheckID(findings []finding.Finding, id finding.CheckID) bool {
	for _, f := range findings {
		if f.CheckID == id {
			return true
		}
	}
	return false
}

func findByCheckID(findings []finding.Finding, id finding.CheckID) *finding.Finding {
	for i, f := range findings {
		if f.CheckID == id {
			return &findings[i]
		}
	}
	return nil
}

// --- Sign-on policy tests ---

func TestOkta_MFANotEnforced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/policies":
			if r.URL.Query().Get("type") == "OKTA_SIGN_ON" {
				_ = json.NewEncoder(w).Encode([]map[string]any{
					{
						"id":     "pol1",
						"name":   "Default Policy",
						"status": "ACTIVE",
						"type":   "OKTA_SIGN_ON",
					},
				})
				return
			}
			_ = json.NewEncoder(w).Encode([]any{})
		case "/api/v1/policies/pol1/rules":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{
					"id":     "rule1",
					"name":   "Allow No MFA",
					"status": "ACTIVE",
					"actions": map[string]any{
						"signon": map[string]any{
							"access":        "ALLOW",
							"requireFactor": false,
						},
					},
				},
			})
		default:
			json.NewEncoder(w).Encode([]any{})
		}
	}))
	defer srv.Close()

	s := okta.New("test.okta.com", "test-token")
	s.SetBaseURL(srv.URL)

	findings, err := s.Run(context.Background(), "test.okta.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckOktaMFANotEnforced) {
		t.Error("expected MFA not enforced finding")
	}

	f := findByCheckID(findings, finding.CheckOktaMFANotEnforced)
	if f.Severity != finding.SeverityCritical {
		t.Errorf("expected Critical severity, got %s", f.Severity)
	}
	if f.Scanner != "okta" {
		t.Errorf("expected scanner 'okta', got %q", f.Scanner)
	}
}

func TestOkta_MFAEnforced_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/policies":
			if r.URL.Query().Get("type") == "OKTA_SIGN_ON" {
				json.NewEncoder(w).Encode([]map[string]any{
					{"id": "pol1", "name": "Secure Policy", "status": "ACTIVE", "type": "OKTA_SIGN_ON"},
				})
				return
			}
			json.NewEncoder(w).Encode([]any{})
		case "/api/v1/policies/pol1/rules":
			json.NewEncoder(w).Encode([]map[string]any{
				{
					"id":     "rule1",
					"name":   "Require MFA",
					"status": "ACTIVE",
					"actions": map[string]any{
						"signon": map[string]any{
							"access":        "ALLOW",
							"requireFactor": true,
						},
					},
				},
			})
		default:
			json.NewEncoder(w).Encode([]any{})
		}
	}))
	defer srv.Close()

	s := okta.New("test.okta.com", "test-token")
	s.SetBaseURL(srv.URL)

	findings, _ := s.Run(context.Background(), "test.okta.com", module.ScanSurface)
	if hasCheckID(findings, finding.CheckOktaMFANotEnforced) {
		t.Error("unexpected MFA finding when MFA is enforced")
	}
}

// --- Password policy tests ---

func TestOkta_WeakPasswordPolicy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/policies":
			ptype := r.URL.Query().Get("type")
			if ptype == "PASSWORD" {
				json.NewEncoder(w).Encode([]map[string]any{
					{
						"id": "ppol1", "name": "Weak Policy", "status": "ACTIVE", "type": "PASSWORD",
						"settings": map[string]any{
							"password": map[string]any{
								"complexity": map[string]any{
									"minLength":    8,
									"minUpperCase": 0,
									"minNumber":    0,
									"minSymbol":    0,
								},
								"age":     map[string]any{},
								"lockout": map[string]any{},
							},
						},
					},
				})
				return
			}
			json.NewEncoder(w).Encode([]any{})
		default:
			json.NewEncoder(w).Encode([]any{})
		}
	}))
	defer srv.Close()

	s := okta.New("test.okta.com", "test-token")
	s.SetBaseURL(srv.URL)

	findings, _ := s.Run(context.Background(), "test.okta.com", module.ScanSurface)
	if !hasCheckID(findings, finding.CheckOktaWeakPasswordPolicy) {
		t.Error("expected weak password policy finding")
	}
}

func TestOkta_StrongPasswordPolicy_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/policies":
			if r.URL.Query().Get("type") == "PASSWORD" {
				json.NewEncoder(w).Encode([]map[string]any{
					{
						"id": "ppol1", "name": "Strong Policy", "status": "ACTIVE", "type": "PASSWORD",
						"settings": map[string]any{
							"password": map[string]any{
								"complexity": map[string]any{
									"minLength":    14,
									"minUpperCase": 1,
									"minNumber":    1,
									"minSymbol":    1,
								},
								"age":     map[string]any{},
								"lockout": map[string]any{},
							},
						},
					},
				})
				return
			}
			json.NewEncoder(w).Encode([]any{})
		default:
			json.NewEncoder(w).Encode([]any{})
		}
	}))
	defer srv.Close()

	s := okta.New("test.okta.com", "test-token")
	s.SetBaseURL(srv.URL)

	findings, _ := s.Run(context.Background(), "test.okta.com", module.ScanSurface)
	if hasCheckID(findings, finding.CheckOktaWeakPasswordPolicy) {
		t.Error("unexpected weak password finding with strong policy")
	}
}

// --- API token tests ---

func TestOkta_APITokenNoExpiry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/api-tokens":
			json.NewEncoder(w).Encode([]map[string]any{
				{
					"id":      "tkn1",
					"name":    "CI Token",
					"created": "2025-01-01T00:00:00Z",
					// No expiresAt = zero time
				},
			})
		default:
			json.NewEncoder(w).Encode([]any{})
		}
	}))
	defer srv.Close()

	s := okta.New("test.okta.com", "test-token")
	s.SetBaseURL(srv.URL)

	findings, _ := s.Run(context.Background(), "test.okta.com", module.ScanSurface)
	if !hasCheckID(findings, finding.CheckOktaAPITokenNoExpiry) {
		t.Error("expected API token no expiry finding")
	}
}

func TestOkta_APITokenLongLived(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/api-tokens":
			json.NewEncoder(w).Encode([]map[string]any{
				{
					"id":        "tkn2",
					"name":      "Long Token",
					"created":   "2025-01-01T00:00:00Z",
					"expiresAt": "2027-01-01T00:00:00Z",
				},
			})
		default:
			json.NewEncoder(w).Encode([]any{})
		}
	}))
	defer srv.Close()

	s := okta.New("test.okta.com", "test-token")
	s.SetBaseURL(srv.URL)

	findings, _ := s.Run(context.Background(), "test.okta.com", module.ScanSurface)
	if !hasCheckID(findings, finding.CheckOktaAPITokenLongLived) {
		t.Error("expected API token long-lived finding")
	}
}

// --- ThreatInsight tests ---

func TestOkta_ThreatInsightDisabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/threats/configuration":
			json.NewEncoder(w).Encode(map[string]any{
				"action": "none",
			})
		default:
			json.NewEncoder(w).Encode([]any{})
		}
	}))
	defer srv.Close()

	s := okta.New("test.okta.com", "test-token")
	s.SetBaseURL(srv.URL)

	findings, _ := s.Run(context.Background(), "test.okta.com", module.ScanSurface)
	if !hasCheckID(findings, finding.CheckOktaThreatInsightDisabled) {
		t.Error("expected ThreatInsight disabled finding")
	}
}

func TestOkta_ThreatInsightBlock_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/threats/configuration":
			json.NewEncoder(w).Encode(map[string]any{
				"action": "block",
			})
		default:
			json.NewEncoder(w).Encode([]any{})
		}
	}))
	defer srv.Close()

	s := okta.New("test.okta.com", "test-token")
	s.SetBaseURL(srv.URL)

	findings, _ := s.Run(context.Background(), "test.okta.com", module.ScanSurface)
	if hasCheckID(findings, finding.CheckOktaThreatInsightDisabled) {
		t.Error("unexpected ThreatInsight finding when set to block")
	}
}

// --- Group rules tests ---

func TestOkta_NoGroupRules(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/groups/rules":
			json.NewEncoder(w).Encode([]any{})
		default:
			json.NewEncoder(w).Encode([]any{})
		}
	}))
	defer srv.Close()

	s := okta.New("test.okta.com", "test-token")
	s.SetBaseURL(srv.URL)

	findings, _ := s.Run(context.Background(), "test.okta.com", module.ScanSurface)
	if !hasCheckID(findings, finding.CheckOktaNoGroupRules) {
		t.Error("expected no group rules finding")
	}
}

func TestOkta_HasGroupRules_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/groups/rules":
			json.NewEncoder(w).Encode([]map[string]any{
				{"id": "r1", "name": "Engineering", "status": "ACTIVE"},
			})
		default:
			json.NewEncoder(w).Encode([]any{})
		}
	}))
	defer srv.Close()

	s := okta.New("test.okta.com", "test-token")
	s.SetBaseURL(srv.URL)

	findings, _ := s.Run(context.Background(), "test.okta.com", module.ScanSurface)
	if hasCheckID(findings, finding.CheckOktaNoGroupRules) {
		t.Error("unexpected no group rules finding when rules exist")
	}
}

// --- Empty group tests ---

func TestOkta_EmptyGroup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/groups":
			json.NewEncoder(w).Encode([]map[string]any{
				{
					"id":      "grp1",
					"type":    "OKTA_GROUP",
					"profile": map[string]string{"name": "Stale Team", "description": ""},
				},
			})
		case "/api/v1/groups/grp1/users":
			json.NewEncoder(w).Encode([]any{})
		default:
			json.NewEncoder(w).Encode([]any{})
		}
	}))
	defer srv.Close()

	s := okta.New("test.okta.com", "test-token")
	s.SetBaseURL(srv.URL)

	findings, _ := s.Run(context.Background(), "test.okta.com", module.ScanSurface)
	if !hasCheckID(findings, finding.CheckOktaGroupNoMembers) {
		t.Error("expected empty group finding")
	}
}

// --- App permissive access tests ---

func TestOkta_AppAssignedToEveryone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/apps":
			json.NewEncoder(w).Encode([]map[string]any{
				{"id": "app1", "label": "Admin Console", "status": "ACTIVE", "name": "admin"},
			})
		case "/api/v1/apps/app1/groups":
			json.NewEncoder(w).Encode([]map[string]any{
				{"id": "grp_everyone", "priority": 0},
			})
		case "/api/v1/groups/grp_everyone":
			json.NewEncoder(w).Encode(map[string]any{
				"id":      "grp_everyone",
				"type":    "BUILT_IN",
				"profile": map[string]string{"name": "Everyone"},
			})
		default:
			json.NewEncoder(w).Encode([]any{})
		}
	}))
	defer srv.Close()

	s := okta.New("test.okta.com", "test-token")
	s.SetBaseURL(srv.URL)

	findings, _ := s.Run(context.Background(), "test.okta.com", module.ScanSurface)
	if !hasCheckID(findings, finding.CheckOktaAppPermissiveAccess) {
		t.Error("expected app permissive access finding for Everyone group")
	}
}

// --- No token = no scan ---

func TestOkta_NoToken_ReturnsNil(t *testing.T) {
	s := okta.New("test.okta.com", "")
	findings, err := s.Run(context.Background(), "test.okta.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if findings != nil {
		t.Errorf("expected nil findings with no token, got %d", len(findings))
	}
}

// --- Context cancellation ---

func TestOkta_ContextCancelled_NoPanic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]any{})
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	s := okta.New("test.okta.com", "test-token")
	s.SetBaseURL(srv.URL)

	findings, _ := s.Run(ctx, "test.okta.com", module.ScanSurface)
	_ = findings
}

// --- Name ---

func TestOkta_Name(t *testing.T) {
	s := okta.New("test.okta.com", "test-token")
	if s.Name() != "okta" {
		t.Errorf("expected name 'okta', got %q", s.Name())
	}
}

// --- User no MFA ---

func TestOkta_UserNoMFA(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/users":
			json.NewEncoder(w).Encode([]map[string]any{
				{
					"id":     "usr1",
					"status": "ACTIVE",
					"profile": map[string]string{
						"login": "alice@example.com",
						"email": "alice@example.com",
					},
				},
			})
		case "/api/v1/users/usr1/factors":
			json.NewEncoder(w).Encode([]any{}) // no factors
		case "/api/v1/users/usr1/roles":
			json.NewEncoder(w).Encode([]any{}) // not admin
		default:
			json.NewEncoder(w).Encode([]any{})
		}
	}))
	defer srv.Close()

	s := okta.New("test.okta.com", "test-token")
	s.SetBaseURL(srv.URL)

	findings, _ := s.Run(context.Background(), "test.okta.com", module.ScanSurface)
	if !hasCheckID(findings, finding.CheckOktaUserNoMFA) {
		t.Error("expected user no MFA finding")
	}

	f := findByCheckID(findings, finding.CheckOktaUserNoMFA)
	if f == nil {
		t.Fatal("finding not found")
	}
	if f.Evidence["login"] != "alice@example.com" {
		t.Errorf("expected login in evidence, got %v", f.Evidence["login"])
	}
}

// --- All findings have scanner field ---

func TestOkta_AllFindingsHaveScannerField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/policies":
			if r.URL.Query().Get("type") == "OKTA_SIGN_ON" {
				json.NewEncoder(w).Encode([]map[string]any{
					{"id": "pol1", "name": "Default", "status": "ACTIVE"},
				})
				return
			}
			json.NewEncoder(w).Encode([]any{})
		case "/api/v1/policies/pol1/rules":
			json.NewEncoder(w).Encode([]map[string]any{
				{
					"id": "r1", "name": "Weak", "status": "ACTIVE",
					"actions": map[string]any{
						"signon": map[string]any{"access": "ALLOW", "requireFactor": false},
					},
				},
			})
		case "/api/v1/threats/configuration":
			json.NewEncoder(w).Encode(map[string]any{"action": "none"})
		case "/api/v1/groups/rules":
			json.NewEncoder(w).Encode([]any{})
		default:
			json.NewEncoder(w).Encode([]any{})
		}
	}))
	defer srv.Close()

	s := okta.New("test.okta.com", "test-token")
	s.SetBaseURL(srv.URL)

	findings, _ := s.Run(context.Background(), "test.okta.com", module.ScanSurface)
	for _, f := range findings {
		if f.Scanner != "okta" {
			t.Errorf("finding %s has scanner %q, expected 'okta'", f.CheckID, f.Scanner)
		}
		if f.Module != "surface" {
			t.Errorf("finding %s has module %q, expected 'surface'", f.CheckID, f.Module)
		}
	}
}

// --- Session timeout tests ---

func TestOkta_NoSessionTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/policies":
			ptype := r.URL.Query().Get("type")
			if ptype == "OKTA_SIGN_ON" {
				json.NewEncoder(w).Encode([]map[string]any{
					{
						"id": "pol1", "name": "Default Policy", "status": "ACTIVE",
						"settings": map[string]any{
							"session": map[string]any{
								"maxSessionIdleMinutes":     0,
								"maxSessionLifetimeMinutes": 0,
							},
						},
					},
				})
				return
			}
			json.NewEncoder(w).Encode([]any{})
		default:
			json.NewEncoder(w).Encode([]any{})
		}
	}))
	defer srv.Close()

	s := okta.New("test.okta.com", "test-token")
	s.SetBaseURL(srv.URL)

	findings, _ := s.Run(context.Background(), "test.okta.com", module.ScanSurface)
	if !hasCheckID(findings, finding.CheckOktaNoSessionTimeout) {
		t.Error("expected no session timeout finding")
	}
}

// --- Inactive admin test ---

func TestOkta_InactiveAdmin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/users":
			json.NewEncoder(w).Encode([]map[string]any{
				{
					"id":        "usr_admin",
					"status":    "ACTIVE",
					"lastLogin": "2025-01-01T00:00:00Z",
					"profile": map[string]string{
						"login": "oldadmin@example.com",
						"email": "oldadmin@example.com",
					},
				},
			})
		case "/api/v1/users/usr_admin/roles":
			json.NewEncoder(w).Encode([]map[string]any{
				{"id": "r1", "type": "SUPER_ADMIN", "label": "Super Admin"},
			})
		case "/api/v1/users/usr_admin/factors":
			json.NewEncoder(w).Encode([]map[string]any{
				{"id": "f1", "factorType": "token:software:totp", "status": "ACTIVE"},
			})
		default:
			json.NewEncoder(w).Encode([]any{})
		}
	}))
	defer srv.Close()

	s := okta.New("test.okta.com", "test-token")
	s.SetBaseURL(srv.URL)

	findings, _ := s.Run(context.Background(), "test.okta.com", module.ScanSurface)
	if !hasCheckID(findings, finding.CheckOktaInactiveAdmin) {
		t.Error("expected inactive admin finding")
	}

	f := findByCheckID(findings, finding.CheckOktaInactiveAdmin)
	if f == nil {
		t.Fatal("finding not found")
	}
	if _, ok := f.Evidence["days_ago"]; !ok {
		t.Error("expected days_ago in evidence")
	}
}

// --- ProofCommand placeholder (for Okta, we use API URL as proof) ---

func TestOkta_FindingFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/threats/configuration":
			json.NewEncoder(w).Encode(map[string]any{"action": "audit_only"})
		default:
			json.NewEncoder(w).Encode([]any{})
		}
	}))
	defer srv.Close()

	s := okta.New("test.okta.com", "test-token")
	s.SetBaseURL(srv.URL)

	findings, _ := s.Run(context.Background(), "test.okta.com", module.ScanSurface)
	f := findByCheckID(findings, finding.CheckOktaThreatInsightDisabled)
	if f == nil {
		t.Fatal("expected ThreatInsight finding")
	}
	if f.Asset != "test.okta.com" {
		t.Errorf("expected asset 'test.okta.com', got %q", f.Asset)
	}
	if f.DiscoveredAt.IsZero() {
		t.Error("expected DiscoveredAt to be set")
	}
	fmt.Println("title:", f.Title)
}
