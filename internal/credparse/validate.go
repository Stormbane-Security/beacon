package credparse

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ValidationResult is the outcome of a least-privilege credential check.
type ValidationResult struct {
	Valid    bool   // whether the credential is live/active
	Service string // confirmed service (aws, github, slack, etc.)
	Identity string // who/what the credential belongs to
	Scopes   string // what permissions/scopes, if discoverable
	Detail   string // human-readable summary
	Error    string // if validation failed (network error, etc.)
}

// ValidateCredential performs a least-privilege identity check on a credential.
// These calls verify "is this key live?" without accessing any data.
// Returns nil if the credential type doesn't have a known validation endpoint.
func ValidateCredential(ctx context.Context, cred Credential) *ValidationResult {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	switch cred.Type {
	case "aws_access_key":
		return validateAWSKey(ctx, cred)
	case "github_pat", "github_pat_fine":
		return validateGitHubToken(ctx, cred)
	case "github_oauth":
		return validateGitHubToken(ctx, cred)
	case "slack_token":
		return validateSlackToken(ctx, cred)
	case "google_oauth":
		return validateGoogleToken(ctx, cred)
	case "stripe_secret", "stripe_restricted":
		return validateStripeKey(ctx, cred)
	case "sendgrid_api_key":
		return validateSendGridKey(ctx, cred)
	case "gitlab_token":
		return validateGitLabToken(ctx, cred)
	default:
		return nil
	}
}

// validateAWSKey calls sts:GetCallerIdentity — requires zero IAM permissions.
// Returns account ID, ARN, and user ID without accessing any resources.
func validateAWSKey(ctx context.Context, cred Credential) *ValidationResult {
	// sts:GetCallerIdentity requires SigV4 signing. We use the query string
	// API which is simpler to construct without the full AWS SDK.
	// The access key alone isn't enough — we need the secret key too.
	// If we only have the access key, we can still report it as found
	// but can't validate it.
	return &ValidationResult{
		Valid:   false,
		Service: "aws",
		Detail:  fmt.Sprintf("AWS access key %s...%s found — validation requires secret key pair", cred.Value[:4], cred.Value[len(cred.Value)-4:]),
		Error:   "access_key_only",
	}
}

// validateGitHubToken calls GET /user — returns username and scopes.
func validateGitHubToken(ctx context.Context, cred Credential) *ValidationResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", nil)
	if err != nil {
		return &ValidationResult{Error: err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+cred.Value)
	req.Header.Set("User-Agent", "beacon-security-scanner")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return &ValidationResult{Error: fmt.Sprintf("github api: %v", err)}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return &ValidationResult{
			Valid:   false,
			Service: "github",
			Detail:  "GitHub token is invalid or revoked",
		}
	}

	if resp.StatusCode != http.StatusOK {
		return &ValidationResult{
			Valid:   false,
			Service: "github",
			Error:   fmt.Sprintf("github api returned %d", resp.StatusCode),
		}
	}

	var user struct {
		Login string `json:"login"`
		Name  string `json:"name"`
		Type  string `json:"type"` // User, Bot, Organization
	}
	if err := json.Unmarshal(body, &user); err != nil {
		return &ValidationResult{Valid: true, Service: "github", Detail: "token is valid but couldn't parse response"}
	}

	scopes := resp.Header.Get("X-OAuth-Scopes")

	return &ValidationResult{
		Valid:    true,
		Service:  "github",
		Identity: fmt.Sprintf("%s (%s)", user.Login, user.Type),
		Scopes:   scopes,
		Detail:   fmt.Sprintf("GitHub token belongs to %s (%s), scopes: %s", user.Login, user.Type, scopes),
	}
}

// validateSlackToken calls auth.test — returns workspace and user info.
func validateSlackToken(ctx context.Context, cred Credential) *ValidationResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://slack.com/api/auth.test", strings.NewReader(""))
	if err != nil {
		return &ValidationResult{Error: err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+cred.Value)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return &ValidationResult{Error: fmt.Sprintf("slack api: %v", err)}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	var result struct {
		OK    bool   `json:"ok"`
		User  string `json:"user"`
		Team  string `json:"team"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return &ValidationResult{Error: "couldn't parse slack response"}
	}

	if !result.OK {
		return &ValidationResult{
			Valid:   false,
			Service: "slack",
			Detail:  fmt.Sprintf("Slack token invalid: %s", result.Error),
		}
	}

	return &ValidationResult{
		Valid:    true,
		Service:  "slack",
		Identity: fmt.Sprintf("%s @ %s", result.User, result.Team),
		Detail:   fmt.Sprintf("Slack token belongs to user %q in workspace %q", result.User, result.Team),
	}
}

// validateGoogleToken calls tokeninfo — returns token validity and scopes.
func validateGoogleToken(ctx context.Context, cred Credential) *ValidationResult {
	url := "https://oauth2.googleapis.com/tokeninfo?access_token=" + cred.Value
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return &ValidationResult{Error: err.Error()}
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return &ValidationResult{Error: fmt.Sprintf("google api: %v", err)}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	if resp.StatusCode != http.StatusOK {
		return &ValidationResult{
			Valid:   false,
			Service: "google",
			Detail:  "Google OAuth token is invalid or expired",
		}
	}

	var info struct {
		Scope    string `json:"scope"`
		Email    string `json:"email"`
		Audience string `json:"aud"`
		Expires  string `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return &ValidationResult{Valid: true, Service: "google", Detail: "token is valid but couldn't parse details"}
	}

	return &ValidationResult{
		Valid:    true,
		Service:  "google",
		Identity: info.Email,
		Scopes:   info.Scope,
		Detail:   fmt.Sprintf("Google token for %s, scopes: %s, expires in %ss", info.Email, info.Scope, info.Expires),
	}
}

// validateStripeKey calls GET /v1/account — returns account ID only.
func validateStripeKey(ctx context.Context, cred Credential) *ValidationResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.stripe.com/v1/account", nil)
	if err != nil {
		return &ValidationResult{Error: err.Error()}
	}
	req.SetBasicAuth(cred.Value, "")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return &ValidationResult{Error: fmt.Sprintf("stripe api: %v", err)}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	if resp.StatusCode == http.StatusUnauthorized {
		return &ValidationResult{
			Valid:   false,
			Service: "stripe",
			Detail:  "Stripe key is invalid or revoked",
		}
	}

	var account struct {
		ID          string `json:"id"`
		BusinessName string `json:"business_profile"`
	}
	if err := json.Unmarshal(body, &account); err != nil {
		if resp.StatusCode == http.StatusOK {
			return &ValidationResult{Valid: true, Service: "stripe", Detail: "Stripe key is valid"}
		}
		return &ValidationResult{Valid: false, Service: "stripe", Error: "unexpected response"}
	}

	return &ValidationResult{
		Valid:    true,
		Service:  "stripe",
		Identity: account.ID,
		Detail:   fmt.Sprintf("Stripe key is valid, account: %s", account.ID),
	}
}

// validateSendGridKey calls GET /v3/user/profile.
func validateSendGridKey(ctx context.Context, cred Credential) *ValidationResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.sendgrid.com/v3/user/profile", nil)
	if err != nil {
		return &ValidationResult{Error: err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+cred.Value)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return &ValidationResult{Error: fmt.Sprintf("sendgrid api: %v", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return &ValidationResult{Valid: false, Service: "sendgrid", Detail: "SendGrid key is invalid"}
	}

	return &ValidationResult{
		Valid:   resp.StatusCode == http.StatusOK,
		Service: "sendgrid",
		Detail:  fmt.Sprintf("SendGrid key validation returned %d", resp.StatusCode),
	}
}

// validateGitLabToken calls GET /api/v4/user.
func validateGitLabToken(ctx context.Context, cred Credential) *ValidationResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://gitlab.com/api/v4/user", nil)
	if err != nil {
		return &ValidationResult{Error: err.Error()}
	}
	req.Header.Set("PRIVATE-TOKEN", cred.Value)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return &ValidationResult{Error: fmt.Sprintf("gitlab api: %v", err)}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	if resp.StatusCode == http.StatusUnauthorized {
		return &ValidationResult{Valid: false, Service: "gitlab", Detail: "GitLab token is invalid"}
	}

	var user struct {
		Username string `json:"username"`
		Name     string `json:"name"`
		IsAdmin  bool   `json:"is_admin"`
	}
	if err := json.Unmarshal(body, &user); err != nil {
		if resp.StatusCode == http.StatusOK {
			return &ValidationResult{Valid: true, Service: "gitlab", Detail: "GitLab token is valid"}
		}
		return &ValidationResult{Valid: false, Service: "gitlab", Error: "unexpected response"}
	}

	adminStr := ""
	if user.IsAdmin {
		adminStr = " (ADMIN)"
	}

	return &ValidationResult{
		Valid:    true,
		Service:  "gitlab",
		Identity: fmt.Sprintf("%s%s", user.Username, adminStr),
		Detail:   fmt.Sprintf("GitLab token belongs to %s (%s)%s", user.Username, user.Name, adminStr),
	}
}
