package gcp

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/api/option"
	secretmanager "google.golang.org/api/secretmanager/v1"

	"github.com/stormbane-security/beacon/internal/finding"
)

func scanSecretManager(ctx context.Context, projectID, asset string, opts []option.ClientOption) ([]finding.Finding, error) {
	svc, err := secretmanager.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("secretmanager service: %w", err)
	}

	var findings []finding.Finding
	parent := fmt.Sprintf("projects/%s", projectID)

	var pageToken string
	for {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		call := svc.Projects.Secrets.List(parent).Context(ctx)
		if pageToken != "" {
			call = call.PageToken(pageToken)
		}
		resp, err := call.Do()
		if err != nil {
			break // Non-fatal: Secret Manager API may not be enabled.
		}

		for _, secret := range resp.Secrets {
			findings = append(findings, checkSecretRotation(secret, projectID, asset)...)
			findings = append(findings, checkSecretVersionDestroy(secret, projectID, asset)...)
		}

		if resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
	}

	return findings, nil
}

// checkSecretRotation checks if a Secret Manager secret has automatic rotation configured.
func checkSecretRotation(secret *secretmanager.Secret, projectID, asset string) []finding.Finding {
	if secret.Rotation != nil && secret.Rotation.RotationPeriod != "" {
		return nil
	}

	shortName := lastPathSegment(secret.Name)

	return []finding.Finding{{
		CheckID: finding.CheckCloudGCPSecretNoRotation,
		Title:   fmt.Sprintf("Secret Manager secret without automatic rotation: %s", shortName),
		Description: fmt.Sprintf(
			"Secret %s in project %s does not have automatic rotation configured. "+
				"Secrets without rotation may remain valid indefinitely after compromise. "+
				"Configure a rotation period and rotation function to ensure secrets are "+
				"rotated regularly.",
			shortName, projectID,
		),
		Severity:     finding.SeverityMedium,
		Asset:        asset,
		Scanner:      "cloud/gcp",
		ProofCommand: fmt.Sprintf("gcloud secrets describe %s --project=%s --format='get(rotation)'", shortName, projectID),
		Evidence: map[string]any{
			"secret":        shortName,
			"full_name":     secret.Name,
			"resource_type": "secret_manager_secret",
			"project_id":    projectID,
		},
		DiscoveredAt: time.Now(),
	}}
}

// checkSecretVersionDestroy checks if a Secret Manager secret has automatic
// version destruction configured (VersionDestroyTtl).
func checkSecretVersionDestroy(secret *secretmanager.Secret, projectID, asset string) []finding.Finding {
	if secret.VersionDestroyTtl != "" {
		return nil
	}

	shortName := lastPathSegment(secret.Name)

	return []finding.Finding{{
		CheckID: finding.CheckCloudGCPSecretNoVersionDestroy,
		Title:   fmt.Sprintf("Secret Manager secret without automatic version destruction: %s", shortName),
		Description: fmt.Sprintf(
			"Secret %s in project %s does not have automatic version destruction configured. "+
				"Old secret versions persist indefinitely, increasing the window for "+
				"compromised credentials to remain accessible. Set a version_destroy_ttl "+
				"to automatically destroy old versions after a grace period.",
			shortName, projectID,
		),
		Severity:     finding.SeverityLow,
		Asset:        asset,
		Scanner:      "cloud/gcp",
		ProofCommand: fmt.Sprintf("gcloud secrets describe %s --project=%s --format='get(versionDestroyTtl)'", shortName, projectID),
		Evidence: map[string]any{
			"secret":        shortName,
			"full_name":     secret.Name,
			"resource_type": "secret_manager_secret",
			"project_id":    projectID,
		},
		DiscoveredAt: time.Now(),
	}}
}
