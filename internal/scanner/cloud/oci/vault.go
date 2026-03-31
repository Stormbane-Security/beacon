package oci

import (
	"context"
	"fmt"
	"time"

	"github.com/stormbane/beacon/internal/finding"
)

// vaultSummary represents a vault in the list response.
type vaultSummary struct {
	ID                string `json:"id"`
	DisplayName       string `json:"displayName"`
	CompartmentID     string `json:"compartmentId"`
	LifecycleState    string `json:"lifecycleState"`    // ACTIVE, DELETED, etc.
	ManagementEndpoint string `json:"managementEndpoint"` // HTTPS endpoint for key management
	VaultType         string `json:"vaultType"`          // DEFAULT, VIRTUAL_PRIVATE
}

// keySummary represents a key in the list response.
type keySummary struct {
	ID             string `json:"id"`
	DisplayName    string `json:"displayName"`
	CompartmentID  string `json:"compartmentId"`
	LifecycleState string `json:"lifecycleState"`
	Algorithm      string `json:"algorithm"` // AES, RSA, ECDSA
}

// keyDetail represents full key details including rotation schedule.
type keyDetail struct {
	ID                   string               `json:"id"`
	DisplayName          string               `json:"displayName"`
	CompartmentID        string               `json:"compartmentId"`
	LifecycleState       string               `json:"lifecycleState"`
	Algorithm            string               `json:"algorithm"`
	CurrentKeyVersion    string               `json:"currentKeyVersion"`
	TimeCreated          string               `json:"timeCreated"`
	AutoKeyRotationDetails *autoKeyRotation   `json:"autoKeyRotationDetails"`
}

type autoKeyRotation struct {
	RotationIntervalInDays int    `json:"rotationIntervalInDays"`
	LastCompletedRotation  string `json:"timeOfLastRotation"`
	NextRotation           string `json:"timeOfNextRotation"`
}

// scanVault checks OCI Vault keys for rotation schedule compliance.
func scanVault(ctx context.Context, s *Scanner, cfg *ociConfig, asset string) ([]finding.Finding, error) {
	host := fmt.Sprintf("kms.%s.oraclecloud.com", cfg.Region)
	compartmentID := cfg.Tenancy

	// List vaults.
	vaultPath := fmt.Sprintf("/20180608/vaults?compartmentId=%s", compartmentID)
	var vaults []vaultSummary
	if err := s.doSignedRequest(ctx, cfg, "GET", host, vaultPath, &vaults); err != nil {
		return nil, fmt.Errorf("list vaults: %w", err)
	}

	var findings []finding.Finding
	for _, vault := range vaults {
		if vault.LifecycleState != "ACTIVE" {
			continue
		}

		mgmtHost := kmsManagementHost(vault.ManagementEndpoint)
		if mgmtHost == "" {
			continue
		}

		// List keys in this vault.
		keysPath := fmt.Sprintf("/20180608/keys?compartmentId=%s", compartmentID)
		var keys []keySummary
		if err := s.doSignedRequest(ctx, cfg, "GET", mgmtHost, keysPath, &keys); err != nil {
			// Key listing may fail if credentials don't have access to this vault.
			continue
		}

		for _, key := range keys {
			if key.LifecycleState != "ENABLED" {
				continue
			}

			// Get key details for rotation info.
			detailPath := fmt.Sprintf("/20180608/keys/%s", key.ID)
			var detail keyDetail
			if err := s.doSignedRequest(ctx, cfg, "GET", mgmtHost, detailPath, &detail); err != nil {
				continue
			}

			findings = append(findings, checkKeyRotation(detail, vault.DisplayName, cfg.Region, asset)...)
		}
	}

	return findings, nil
}

// checkKeyRotation evaluates whether a key has automatic rotation configured.
func checkKeyRotation(key keyDetail, vaultName, region, asset string) []finding.Finding {
	var findings []finding.Finding

	noRotation := false
	if key.AutoKeyRotationDetails == nil {
		noRotation = true
	} else if key.AutoKeyRotationDetails.RotationIntervalInDays == 0 {
		noRotation = true
	}

	if noRotation {
		// Also check if the key has been manually rotated recently.
		// If timeCreated is older than 365 days and no auto-rotation is configured,
		// flag it.
		created, err := time.Parse(time.RFC3339, key.TimeCreated)
		stale := err == nil && time.Since(created) > 365*24*time.Hour

		sev := finding.SeverityMedium
		titleSuffix := ""
		if stale {
			sev = finding.SeverityHigh
			titleSuffix = " (key older than 365 days)"
		}

		findings = append(findings, finding.Finding{
			CheckID: finding.CheckCloudOCIVaultKeyNoRotation,
			Title:   fmt.Sprintf("OCI Vault key has no automatic rotation: %s%s", key.DisplayName, titleSuffix),
			Description: fmt.Sprintf(
				"Vault key %s in vault %s (region %s) does not have automatic key rotation "+
					"configured. Without rotation, a compromised key has unlimited useful life. "+
					"Enable automatic key rotation with a maximum interval of 365 days to comply "+
					"with CIS OCI benchmarks and limit the blast radius of key compromise.",
				key.DisplayName, vaultName, region,
			),
			Severity:     sev,
			Asset:        asset,
			Scanner:      scannerTag,
			ProofCommand: fmt.Sprintf("oci kms management key get --key-id %s --query 'data.\"auto-key-rotation-details\"'", key.ID),
			Evidence: map[string]any{
				"key_id":           key.ID,
				"key_name":         key.DisplayName,
				"vault_name":       vaultName,
				"region":           region,
				"algorithm":        key.Algorithm,
				"time_created":     key.TimeCreated,
				"auto_rotation":    key.AutoKeyRotationDetails,
				"lifecycle_state":  key.LifecycleState,
			},
			DiscoveredAt: time.Now(),
		})
	}

	return findings
}
