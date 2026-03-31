package gcp

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/api/option"
	storageapi "google.golang.org/api/storage/v1"

	"github.com/stormbane/beacon/internal/finding"
)

func scanBuckets(ctx context.Context, projectID, asset string, opts []option.ClientOption) ([]finding.Finding, error) {
	svc, err := storageapi.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("storage service: %w", err)
	}

	var findings []finding.Finding
	if err := svc.Buckets.List(projectID).Pages(ctx,
		func(page *storageapi.Buckets) error {
			for _, bucket := range page.Items {
				// Get IAM policy for each bucket.
				policy, err := svc.Buckets.GetIamPolicy(bucket.Name).Context(ctx).Do()
				if err != nil {
					continue
				}

				for _, binding := range policy.Bindings {
					for _, member := range binding.Members {
						if member == "allUsers" || member == "allAuthenticatedUsers" {
							desc := fmt.Sprintf(
								"GCS bucket gs://%s grants %s to %s. Any internet user can %s this bucket. "+
									"Remove the allUsers/allAuthenticatedUsers binding and enable Uniform Bucket-Level Access.",
								bucket.Name, binding.Role, member, roleToAction(binding.Role),
							)
							findings = append(findings, finding.Finding{
								CheckID:      finding.CheckCloudGCPBucketPublic,
								Title:        fmt.Sprintf("Public GCS bucket: gs://%s", bucket.Name),
								Description:  desc,
								Severity:     finding.SeverityCritical,
								Asset:        asset,
								Scanner:      "cloud/gcp",
								ProofCommand: fmt.Sprintf("gsutil iam get gs://%s", bucket.Name),
								Evidence: map[string]any{
									"bucket":     bucket.Name,
									"project_id": projectID,
									"role":       binding.Role,
									"member":     member,
									"location":   bucket.Location,
								},
								DiscoveredAt: time.Now(),
							})
						}
					}
				}
				// Check for missing customer-managed encryption key (CMEK).
				// When encryption.defaultKmsKeyName is empty, the bucket uses
				// Google-managed encryption (GMEK). CMEK gives the organization
				// control over key rotation, revocation, and access policies.
				if bucket.Encryption == nil || bucket.Encryption.DefaultKmsKeyName == "" {
					findings = append(findings, finding.Finding{
						CheckID: finding.CheckCloudGCPBucketNoCMEK,
						Title:   fmt.Sprintf("GCS bucket has no customer-managed encryption key: gs://%s", bucket.Name),
						Description: fmt.Sprintf(
							"GCS bucket gs://%s in project %s does not have a customer-managed encryption "+
								"key (CMEK) configured. Data is encrypted with Google-managed keys by default, "+
								"but CMEK provides organizational control over key rotation schedules, "+
								"revocation, and access policies. Configure a Cloud KMS key as the default "+
								"encryption key for the bucket.",
							bucket.Name, projectID,
						),
						Severity:     finding.SeverityMedium,
						Asset:        asset,
						Scanner:      "cloud/gcp",
						ProofCommand: fmt.Sprintf("gsutil kms get gs://%s", bucket.Name),
						Evidence: map[string]any{
							"bucket":     bucket.Name,
							"project_id": projectID,
							"location":   bucket.Location,
						},
						DiscoveredAt: time.Now(),
					})
				}
			}
			return nil
		}); err != nil {
		return nil, fmt.Errorf("list buckets: %w", err)
	}
	return findings, nil
}

func roleToAction(role string) string {
	switch role {
	case "roles/storage.objectAdmin", "roles/storage.admin":
		return "read, write, and delete objects in"
	case "roles/storage.objectCreator":
		return "upload objects to"
	case "roles/storage.objectViewer", "roles/storage.legacyObjectReader":
		return "read objects from"
	default:
		return "access"
	}
}
