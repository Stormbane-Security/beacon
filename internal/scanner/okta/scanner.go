// Package okta scans an Okta organization for identity and access
// management misconfigurations via the Okta Management API.
//
// All checks run in surface mode — they only read configuration, never
// modify anything. Requires an Okta API token with read-only admin access.
package okta

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)

// Scanner checks Okta org configuration for security misconfigurations.
type Scanner struct {
	token   string
	baseURL string // e.g., "https://yourorg.okta.com"
	client  *http.Client
}

// New creates an Okta scanner. The domain should be like "yourorg.okta.com"
// (no scheme). The token is an Okta API token with read-only admin access.
func New(domain, token string) *Scanner {
	base := domain
	if !strings.HasPrefix(base, "http") {
		base = "https://" + base
	}
	base = strings.TrimSuffix(base, "/")

	return &Scanner{
		token:   token,
		baseURL: base,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SetBaseURL overrides the API base URL (for testing).
func (s *Scanner) SetBaseURL(url string) {
	s.baseURL = strings.TrimSuffix(url, "/")
}

func (s *Scanner) Name() string { return "okta" }

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if s.token == "" {
		return nil, nil
	}

	var findings []finding.Finding

	checks := []func(ctx context.Context, asset string) ([]finding.Finding, error){
		s.checkSignOnPolicies,
		s.checkPasswordPolicies,
		s.checkSessionPolicy,
		s.checkAdminUsers,
		s.checkAPITokens,
		s.checkGroups,
		s.checkGroupRules,
		s.checkApps,
		s.checkUsers,
		s.checkThreatInsight,
	}

	for _, check := range checks {
		if ctx.Err() != nil {
			break
		}
		fs, err := check(ctx, asset)
		if err != nil {
			continue // best-effort: skip checks that fail
		}
		findings = append(findings, fs...)
	}

	return findings, nil
}

// --- API helpers ---

func (s *Scanner) get(ctx context.Context, path string, result any) error {
	url := s.baseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "SSWS "+s.token)
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("okta API %d: %s", resp.StatusCode, string(body))
	}

	return json.NewDecoder(resp.Body).Decode(result)
}

func makeFinding(asset string, checkID finding.CheckID, title, desc string, evidence map[string]any) finding.Finding {
	sev := finding.Meta(checkID).DefaultSeverity
	return finding.Finding{
		CheckID:      checkID,
		Asset:        asset,
		Title:        title,
		Description:  desc,
		Severity:     sev,
		Scanner:      "okta",
		Module:       "surface",
		Evidence:     evidence,
		DiscoveredAt: time.Now(),
	}
}

// --- Sign-on policies ---

type signOnPolicy struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	Type       string `json:"type"`
	Conditions struct {
		People struct {
			Groups struct {
				Include []string `json:"include"`
			} `json:"groups"`
		} `json:"people"`
	} `json:"conditions"`
}

type signOnPolicyRule struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Actions struct {
		Signon struct {
			Access                  string `json:"access"`
			RequireFactor           bool   `json:"requireFactor"`
			FactorPromptMode        string `json:"factorPromptMode"`
			FactorLifetime          int    `json:"factorLifetime"`
			RememberDeviceByDefault bool   `json:"rememberDeviceByDefault"`
		} `json:"signon"`
	} `json:"actions"`
}

func (s *Scanner) checkSignOnPolicies(ctx context.Context, asset string) ([]finding.Finding, error) {
	var policies []signOnPolicy
	if err := s.get(ctx, "/api/v1/policies?type=OKTA_SIGN_ON", &policies); err != nil {
		return nil, err
	}

	var findings []finding.Finding
	for _, p := range policies {
		if p.Status != "ACTIVE" {
			continue
		}

		var rules []signOnPolicyRule
		if err := s.get(ctx, fmt.Sprintf("/api/v1/policies/%s/rules", p.ID), &rules); err != nil {
			continue
		}

		for _, r := range rules {
			if r.Status != "ACTIVE" {
				continue
			}
			if r.Actions.Signon.Access == "ALLOW" && !r.Actions.Signon.RequireFactor {
				findings = append(findings, makeFinding(asset,
					finding.CheckOktaMFANotEnforced,
					fmt.Sprintf("Okta sign-on policy %q rule %q does not require MFA", p.Name, r.Name),
					"Sign-on policy rule allows access without MFA. An attacker with compromised credentials can access the organization without a second factor.",
					map[string]any{
						"policy_id":   p.ID,
						"policy_name": p.Name,
						"rule_id":     r.ID,
						"rule_name":   r.Name,
					},
				))
			}
		}
	}
	return findings, nil
}

// --- Password policies ---

type passwordPolicy struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Status   string `json:"status"`
	Type     string `json:"type"`
	Settings struct {
		Password struct {
			Complexity struct {
				MinLength         int    `json:"minLength"`
				MinLowerCase      int    `json:"minLowerCase"`
				MinUpperCase      int    `json:"minUpperCase"`
				MinNumber         int    `json:"minNumber"`
				MinSymbol         int    `json:"minSymbol"`
				ExcludeUsername    bool   `json:"excludeUsername"`
				ExcludeAttributes []string `json:"excludeAttributes"`
			} `json:"complexity"`
			Age struct {
				MaxAgeDays int `json:"maxAgeDays"`
				MinAgeMins int `json:"minAgeMinutes"`
				HistoryCount int `json:"historyCount"`
			} `json:"age"`
			Lockout struct {
				MaxAttempts       int  `json:"maxAttempts"`
				AutoUnlockMinutes int  `json:"autoUnlockMinutes"`
				ShowLockoutFailures bool `json:"showLockoutFailures"`
			} `json:"lockout"`
		} `json:"password"`
	} `json:"settings"`
}

func (s *Scanner) checkPasswordPolicies(ctx context.Context, asset string) ([]finding.Finding, error) {
	var policies []passwordPolicy
	if err := s.get(ctx, "/api/v1/policies?type=PASSWORD", &policies); err != nil {
		return nil, err
	}

	var findings []finding.Finding
	for _, p := range policies {
		if p.Status != "ACTIVE" {
			continue
		}
		complexity := p.Settings.Password.Complexity
		if complexity.MinLength < 12 || (complexity.MinUpperCase == 0 && complexity.MinNumber == 0 && complexity.MinSymbol == 0) {
			findings = append(findings, makeFinding(asset,
				finding.CheckOktaWeakPasswordPolicy,
				fmt.Sprintf("Okta password policy %q allows weak passwords", p.Name),
				fmt.Sprintf("Password policy requires only %d characters with insufficient complexity. NIST 800-63B recommends minimum 12 characters.", complexity.MinLength),
				map[string]any{
					"policy_id":   p.ID,
					"policy_name": p.Name,
					"min_length":  complexity.MinLength,
					"min_upper":   complexity.MinUpperCase,
					"min_number":  complexity.MinNumber,
					"min_symbol":  complexity.MinSymbol,
				},
			))
		}
	}
	return findings, nil
}

// --- Session policy ---

type sessionPolicy struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Status   string `json:"status"`
	Type     string `json:"type"`
	Settings struct {
		Session struct {
			MaxSessionIdleMinutes    int  `json:"maxSessionIdleMinutes"`
			MaxSessionLifetimeMinutes int `json:"maxSessionLifetimeMinutes"`
			UsePersistentCookie      bool `json:"usePersistentCookie"`
		} `json:"session"`
	} `json:"settings"`
}

func (s *Scanner) checkSessionPolicy(ctx context.Context, asset string) ([]finding.Finding, error) {
	// Okta uses the same policies endpoint with type filter.
	// For global session policy, we look at type ACCESS_POLICY or check org settings.
	var policies []sessionPolicy
	if err := s.get(ctx, "/api/v1/policies?type=OKTA_SIGN_ON", &policies); err != nil {
		return nil, err
	}

	var findings []finding.Finding
	for _, p := range policies {
		if p.Status != "ACTIVE" {
			continue
		}
		session := p.Settings.Session
		// Flag if no idle timeout (0 = unlimited) or lifetime > 24 hours.
		if session.MaxSessionIdleMinutes == 0 || session.MaxSessionLifetimeMinutes == 0 ||
			session.MaxSessionLifetimeMinutes > 1440 {
			findings = append(findings, makeFinding(asset,
				finding.CheckOktaNoSessionTimeout,
				fmt.Sprintf("Okta session policy %q has no effective timeout", p.Name),
				"Session policy allows unlimited idle time or session lifetime exceeding 24 hours. Stale sessions increase the risk of session hijacking.",
				map[string]any{
					"policy_id":       p.ID,
					"policy_name":     p.Name,
					"idle_minutes":    session.MaxSessionIdleMinutes,
					"lifetime_minutes": session.MaxSessionLifetimeMinutes,
				},
			))
		}
	}
	return findings, nil
}

// --- Admin users ---

type oktaUser struct {
	ID          string    `json:"id"`
	Status      string    `json:"status"`
	LastLogin   time.Time `json:"lastLogin"`
	Profile     struct {
		Login     string `json:"login"`
		Email     string `json:"email"`
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
	} `json:"profile"`
}

type adminRole struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Label string `json:"label"`
}

func (s *Scanner) checkAdminUsers(ctx context.Context, asset string) ([]finding.Finding, error) {
	var users []oktaUser
	if err := s.get(ctx, "/api/v1/users?filter=status+eq+%22ACTIVE%22&limit=200", &users); err != nil {
		return nil, err
	}

	var findings []finding.Finding
	cutoff := time.Now().AddDate(0, 0, -90)

	for _, u := range users {
		// Check if user has admin role.
		var roles []adminRole
		if err := s.get(ctx, fmt.Sprintf("/api/v1/users/%s/roles", u.ID), &roles); err != nil {
			continue
		}
		if len(roles) == 0 {
			continue
		}

		isAdmin := false
		for _, r := range roles {
			if strings.Contains(r.Type, "ADMIN") || strings.Contains(r.Type, "SUPER") {
				isAdmin = true
				break
			}
		}
		if !isAdmin {
			continue
		}

		if !u.LastLogin.IsZero() && u.LastLogin.Before(cutoff) {
			findings = append(findings, makeFinding(asset,
				finding.CheckOktaInactiveAdmin,
				fmt.Sprintf("Okta admin %s has not logged in for 90+ days", u.Profile.Login),
				"Admin account has been inactive for over 90 days. Inactive admin accounts are a risk — they could be targeted by attackers without being noticed.",
				map[string]any{
					"user_id":    u.ID,
					"login":     u.Profile.Login,
					"last_login": u.LastLogin.Format(time.RFC3339),
					"days_ago":  int(time.Since(u.LastLogin).Hours() / 24),
				},
			))
		}
	}
	return findings, nil
}

// --- API tokens ---

type apiToken struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	ExpiresAt time.Time `json:"expiresAt"`
	Created   time.Time `json:"created"`
}

func (s *Scanner) checkAPITokens(ctx context.Context, asset string) ([]finding.Finding, error) {
	var tokens []apiToken
	if err := s.get(ctx, "/api/v1/api-tokens", &tokens); err != nil {
		return nil, err
	}

	var findings []finding.Finding
	now := time.Now()

	for _, t := range tokens {
		if t.ExpiresAt.IsZero() {
			findings = append(findings, makeFinding(asset,
				finding.CheckOktaAPITokenNoExpiry,
				fmt.Sprintf("Okta API token %q has no expiration", t.Name),
				"API token with no expiration date. If compromised, the token provides persistent access until manually revoked.",
				map[string]any{
					"token_id":   t.ID,
					"token_name": t.Name,
					"created":    t.Created.Format(time.RFC3339),
				},
			))
		} else if t.ExpiresAt.After(now.AddDate(0, 0, 90)) {
			findings = append(findings, makeFinding(asset,
				finding.CheckOktaAPITokenLongLived,
				fmt.Sprintf("Okta API token %q expires in 90+ days", t.Name),
				"API token has a long expiration window. Consider shorter-lived tokens and automated rotation.",
				map[string]any{
					"token_id":    t.ID,
					"token_name":  t.Name,
					"expires_at":  t.ExpiresAt.Format(time.RFC3339),
					"days_until":  int(time.Until(t.ExpiresAt).Hours() / 24),
				},
			))
		}
	}
	return findings, nil
}

// --- Groups ---

type oktaGroup struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Profile struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	} `json:"profile"`
}

func (s *Scanner) checkGroups(ctx context.Context, asset string) ([]finding.Finding, error) {
	var groups []oktaGroup
	if err := s.get(ctx, "/api/v1/groups?limit=200", &groups); err != nil {
		return nil, err
	}

	var findings []finding.Finding
	for _, g := range groups {
		// Check if group has members.
		var members []oktaUser
		if err := s.get(ctx, fmt.Sprintf("/api/v1/groups/%s/users?limit=1", g.ID), &members); err != nil {
			continue
		}
		if len(members) == 0 && g.Type != "BUILT_IN" {
			findings = append(findings, makeFinding(asset,
				finding.CheckOktaGroupNoMembers,
				fmt.Sprintf("Okta group %q has no members", g.Profile.Name),
				"Empty group may indicate stale configuration. Review whether this group is still needed or if membership rules need updating.",
				map[string]any{
					"group_id":   g.ID,
					"group_name": g.Profile.Name,
					"group_type": g.Type,
				},
			))
		}
	}
	return findings, nil
}

// --- Group rules ---

type groupRule struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Type   string `json:"type"`
}

func (s *Scanner) checkGroupRules(ctx context.Context, asset string) ([]finding.Finding, error) {
	var rules []groupRule
	if err := s.get(ctx, "/api/v1/groups/rules?limit=200", &rules); err != nil {
		return nil, err
	}

	if len(rules) == 0 {
		return []finding.Finding{makeFinding(asset,
			finding.CheckOktaNoGroupRules,
			"No Okta group rules defined",
			"No automated group rules are configured. Groups are managed manually, which increases the risk of stale memberships and inconsistent access. Consider group rules based on department, title, or other profile attributes.",
			map[string]any{
				"rule_count": 0,
			},
		)}, nil
	}

	return nil, nil
}

// --- Applications ---

type oktaApp struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Label    string `json:"label"`
	Status   string `json:"status"`
	SignOnMode string `json:"signOnMode"`
	Settings struct {
		SignOn struct {
			DefaultRelayState string `json:"defaultRelayState"`
		} `json:"signOn"`
	} `json:"settings"`
}

type appGroupAssignment struct {
	ID       string `json:"id"`
	Priority int    `json:"priority"`
}

func (s *Scanner) checkApps(ctx context.Context, asset string) ([]finding.Finding, error) {
	var apps []oktaApp
	if err := s.get(ctx, "/api/v1/apps?limit=200&filter=status+eq+%22ACTIVE%22", &apps); err != nil {
		return nil, err
	}

	var findings []finding.Finding
	for _, app := range apps {
		// Check if app is assigned to "Everyone" group.
		var groups []appGroupAssignment
		if err := s.get(ctx, fmt.Sprintf("/api/v1/apps/%s/groups?limit=200", app.ID), &groups); err != nil {
			continue
		}

		// The "Everyone" group in Okta has a well-known assignment pattern.
		// We check the number of group assignments — if a high-privilege app
		// is assigned to many groups, it's worth flagging.
		for _, g := range groups {
			// Check if this is the Everyone group by looking up the group.
			var grp oktaGroup
			if err := s.get(ctx, fmt.Sprintf("/api/v1/groups/%s", g.ID), &grp); err != nil {
				continue
			}
			if grp.Profile.Name == "Everyone" {
				findings = append(findings, makeFinding(asset,
					finding.CheckOktaAppPermissiveAccess,
					fmt.Sprintf("Okta app %q is assigned to Everyone group", app.Label),
					"Application is accessible to all users via the Everyone group. Consider restricting to specific groups based on job function.",
					map[string]any{
						"app_id":    app.ID,
						"app_label": app.Label,
						"group_id":  g.ID,
					},
				))
				break
			}
		}
	}
	return findings, nil
}

// --- Users (MFA enrollment) ---

type mfaFactor struct {
	ID         string `json:"id"`
	FactorType string `json:"factorType"`
	Status     string `json:"status"`
}

func (s *Scanner) checkUsers(ctx context.Context, asset string) ([]finding.Finding, error) {
	var users []oktaUser
	if err := s.get(ctx, "/api/v1/users?filter=status+eq+%22ACTIVE%22&limit=200", &users); err != nil {
		return nil, err
	}

	var findings []finding.Finding
	for _, u := range users {
		var factors []mfaFactor
		if err := s.get(ctx, fmt.Sprintf("/api/v1/users/%s/factors", u.ID), &factors); err != nil {
			continue
		}

		hasActiveFactor := false
		for _, f := range factors {
			if f.Status == "ACTIVE" {
				hasActiveFactor = true
				break
			}
		}

		if !hasActiveFactor {
			findings = append(findings, makeFinding(asset,
				finding.CheckOktaUserNoMFA,
				fmt.Sprintf("Okta user %s has no MFA factors enrolled", u.Profile.Login),
				"User has no active MFA factors. Even if the sign-on policy requires MFA, this user cannot authenticate with a second factor.",
				map[string]any{
					"user_id": u.ID,
					"login":   u.Profile.Login,
					"email":   u.Profile.Email,
				},
			))
		}
	}
	return findings, nil
}

// --- ThreatInsight ---

type threatInsightConfig struct {
	Action        string   `json:"action"`
	ExcludeZones  []string `json:"excludeZones"`
}

func (s *Scanner) checkThreatInsight(ctx context.Context, asset string) ([]finding.Finding, error) {
	var config threatInsightConfig
	if err := s.get(ctx, "/api/v1/threats/configuration", &config); err != nil {
		return nil, err
	}

	if config.Action != "block" {
		return []finding.Finding{makeFinding(asset,
			finding.CheckOktaThreatInsightDisabled,
			"Okta ThreatInsight is not in block mode",
			fmt.Sprintf("ThreatInsight is set to %q. Set to \"block\" to automatically block known-malicious IPs from authentication attempts.", config.Action),
			map[string]any{
				"current_action": config.Action,
			},
		)}, nil
	}

	return nil, nil
}
