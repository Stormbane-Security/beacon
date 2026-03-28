package gcp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"google.golang.org/api/cloudresourcemanager/v1"
	iamapi "google.golang.org/api/iam/v1"
	"google.golang.org/api/option"

	"github.com/stormbane/beacon/internal/finding"
)

// primitiveRoles are overpermissive legacy roles that grant broad access.
var primitiveRoles = map[string]bool{
	"roles/owner":  true,
	"roles/editor": true,
}

func scanIAM(ctx context.Context, projectID, asset string, opts []option.ClientOption) ([]finding.Finding, error) {
	var findings []finding.Finding

	// Check project-level IAM bindings.
	crmSvc, err := cloudresourcemanager.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("cloudresourcemanager: %w", err)
	}

	policy, err := crmSvc.Projects.GetIamPolicy(
		"projects/"+projectID,
		&cloudresourcemanager.GetIamPolicyRequest{},
	).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("get IAM policy: %w", err)
	}

	for _, binding := range policy.Bindings {
		if primitiveRoles[binding.Role] {
			for _, member := range binding.Members {
				// Skip Google-managed service agents.
				if strings.Contains(member, "gserviceaccount.com") &&
					strings.Contains(member, "robot") {
					continue
				}
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudGCPIAMPrimitiveRole,
					Title:   fmt.Sprintf("GCP primitive role %s granted to %s", binding.Role, member),
					Description: fmt.Sprintf(
						"Project %s has %s assigned to %s. Primitive roles (owner/editor) "+
							"grant broad access across all GCP services. Replace with specific "+
							"predefined or custom roles following the principle of least privilege.",
						projectID, binding.Role, member,
					),
					Severity:     finding.SeverityHigh,
					Asset:        asset,
					Scanner:      "cloud/gcp",
					ProofCommand: fmt.Sprintf("gcloud projects get-iam-policy %s --flatten='bindings[].members' --format='table(bindings.role,bindings.members)'", projectID),
					Evidence: map[string]any{
						"project_id": projectID,
						"role":       binding.Role,
						"member":     member,
					},
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	// Check service account keys.
	iamSvc, err := iamapi.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("iam service: %w", err)
	}

	saResp, err := iamSvc.Projects.ServiceAccounts.List("projects/" + projectID).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("list service accounts: %w", err)
	}

	for _, sa := range saResp.Accounts {
		keysResp, err := iamSvc.Projects.ServiceAccounts.Keys.List(sa.Name).
			KeyTypes("USER_MANAGED").
			Context(ctx).Do()
		if err != nil {
			continue
		}

		for _, key := range keysResp.Keys {
			// Flag any user-managed key existence.
			findings = append(findings, finding.Finding{
				CheckID: finding.CheckCloudGCPServiceAccountKey,
				Title:   fmt.Sprintf("GCP service account has user-managed key: %s", sa.Email),
				Description: fmt.Sprintf(
					"Service account %s has a user-managed key. Keys are long-lived credentials "+
						"that cannot be automatically rotated. Prefer Workload Identity Federation "+
						"or short-lived tokens via the metadata server.",
					sa.Email,
				),
				Severity:     finding.SeverityMedium,
				Asset:        asset,
				Scanner:      "cloud/gcp",
				ProofCommand: fmt.Sprintf("gcloud iam service-accounts keys list --iam-account=%s", sa.Email),
				Evidence: map[string]any{
					"project_id":      projectID,
					"service_account": sa.Email,
					"key_name":        key.Name,
					"valid_after":     key.ValidAfterTime,
				},
				DiscoveredAt: time.Now(),
			})

			// Flag keys older than 90 days.
			created, err := time.Parse(time.RFC3339, key.ValidAfterTime)
			if err == nil && time.Since(created) > 90*24*time.Hour {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudGCPServiceAccountKeyOld,
					Title:   fmt.Sprintf("GCP service account key older than 90 days: %s", sa.Email),
					Description: fmt.Sprintf(
						"Service account %s has a key created %s ago. Keys older than 90 days "+
							"indicate a rotation failure and increase the blast radius if compromised. "+
							"Rotate or delete the key and migrate to Workload Identity Federation.",
						sa.Email, formatAge(created),
					),
					Severity:     finding.SeverityHigh,
					Asset:        asset,
					Scanner:      "cloud/gcp",
					ProofCommand: fmt.Sprintf("gcloud iam service-accounts keys list --iam-account=%s", sa.Email),
					Evidence: map[string]any{
						"project_id":      projectID,
						"service_account": sa.Email,
						"key_name":        key.Name,
						"created":         key.ValidAfterTime,
						"age_days":        int(time.Since(created).Hours() / 24),
					},
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return findings, nil
}

func formatAge(t time.Time) string {
	d := time.Since(t)
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}
