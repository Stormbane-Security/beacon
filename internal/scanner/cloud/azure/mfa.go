package azure

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/stormbane/beacon/internal/finding"
)

// scanConditionalAccessMFA checks whether the Azure AD tenant has conditional access
// policies or security defaults that enforce MFA. Since the Microsoft Graph SDK for
// conditional access requires specific permissions, we use a lightweight HTTP probe
// against the Graph API to check for security defaults and conditional access policies.
func scanConditionalAccessMFA(ctx context.Context, cred *azidentity.DefaultAzureCredential, subID, asset string) ([]finding.Finding, error) {
	// Acquire a token for Microsoft Graph.
	token, err := cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{"https://graph.microsoft.com/.default"},
	})
	if err != nil {
		// Cannot acquire Graph token — conditional access check skipped.
		return nil, nil
	}

	httpClient := &http.Client{Timeout: 15 * time.Second}

	// Check 1: Security defaults status.
	// Security defaults enforce MFA for all users at no extra cost.
	secDefaultsURL := "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"
	secReq, err := http.NewRequestWithContext(ctx, http.MethodGet, secDefaultsURL, nil)
	if err != nil {
		return nil, nil
	}
	secReq.Header.Set("Authorization", "Bearer "+token.Token)
	secResp, err := httpClient.Do(secReq)
	if err != nil {
		return nil, nil
	}
	secBody, _ := io.ReadAll(io.LimitReader(secResp.Body, 16384))
	secResp.Body.Close()

	secDefaultsEnabled := false
	if secResp.StatusCode == 200 {
		bodyStr := string(secBody)
		// Look for "isEnabled":true in the response.
		if strings.Contains(bodyStr, `"isEnabled":true`) || strings.Contains(bodyStr, `"isEnabled": true`) {
			secDefaultsEnabled = true
		}
	}

	// Check 2: Conditional access policies.
	// If security defaults are on, conditional access is not needed (they are mutually exclusive).
	if secDefaultsEnabled {
		return nil, nil
	}

	caURL := "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
	caReq, err := http.NewRequestWithContext(ctx, http.MethodGet, caURL, nil)
	if err != nil {
		return nil, nil
	}
	caReq.Header.Set("Authorization", "Bearer "+token.Token)
	caResp, err := httpClient.Do(caReq)
	if err != nil {
		return nil, nil
	}
	caBody, _ := io.ReadAll(io.LimitReader(caResp.Body, 65536))
	caResp.Body.Close()

	hasMFAPolicy := false
	if caResp.StatusCode == 200 {
		bodyStr := string(caBody)
		// Look for policies that require MFA (grant control "mfa").
		// The Graph API returns builtInControls containing "mfa" when MFA is required.
		if strings.Contains(bodyStr, `"mfa"`) && strings.Contains(bodyStr, `"enabled"`) {
			hasMFAPolicy = true
		}
	}

	if hasMFAPolicy {
		return nil, nil
	}

	// Neither security defaults nor conditional access MFA policy found.
	return []finding.Finding{{
		CheckID: finding.CheckCloudAzureNoConditionalAccessMFA,
		Title:   fmt.Sprintf("Azure AD has no MFA enforcement via security defaults or conditional access (subscription: %s)", subID),
		Description: "Neither Azure AD security defaults nor a conditional access policy requiring " +
			"multi-factor authentication was detected. Without MFA enforcement, compromised " +
			"credentials alone are sufficient to access Azure resources. Enable security defaults " +
			"(free) or configure a conditional access policy requiring MFA for all users, " +
			"especially for privileged roles.",
		Severity:     finding.SeverityHigh,
		Asset:        asset,
		Scanner:      "cloud/azure",
		ProofCommand: "az rest --method GET --url 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy'",
		Evidence: map[string]any{
			"subscription_id":       subID,
			"security_defaults":     secDefaultsEnabled,
			"conditional_access_mfa": hasMFAPolicy,
		},
		DiscoveredAt: time.Now(),
	}}, nil
}
