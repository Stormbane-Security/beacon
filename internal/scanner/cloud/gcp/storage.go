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
