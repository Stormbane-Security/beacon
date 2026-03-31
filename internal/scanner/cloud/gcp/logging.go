package gcp

import (
	"context"
	"fmt"
	"time"

	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/option"

	"github.com/stormbane/beacon/internal/finding"
)

func scanAuditLogging(ctx context.Context, projectID, asset string, opts []option.ClientOption) ([]finding.Finding, error) {
	svc, err := cloudresourcemanager.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("cloudresourcemanager: %w", err)
	}

	policy, err := svc.Projects.GetIamPolicy(
		"projects/"+projectID,
		&cloudresourcemanager.GetIamPolicyRequest{
			Options: &cloudresourcemanager.GetPolicyOptions{
				RequestedPolicyVersion: 3,
			},
		},
	).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("get IAM policy: %w", err)
	}

	var findings []finding.Finding

	// Check if DATA_READ and DATA_WRITE audit log types are enabled for allServices.
	hasDataRead := false
	hasDataWrite := false

	for _, auditConfig := range policy.AuditConfigs {
		if auditConfig.Service == "allServices" {
			for _, logConfig := range auditConfig.AuditLogConfigs {
				switch logConfig.LogType {
				case "DATA_READ":
					hasDataRead = true
				case "DATA_WRITE":
					hasDataWrite = true
				}
			}
		}
	}

	if !hasDataRead || !hasDataWrite {
		var missing []string
		if !hasDataRead {
			missing = append(missing, "DATA_READ")
		}
		if !hasDataWrite {
			missing = append(missing, "DATA_WRITE")
		}

		findings = append(findings, finding.Finding{
			CheckID: finding.CheckCloudGCPNoAuditLogging,
			Title:   fmt.Sprintf("GCP project does not have full data access audit logging: %s", projectID),
			Description: fmt.Sprintf(
				"Project %s does not have %s audit log types enabled for allServices. "+
					"Without data access audit logging, reads and writes to sensitive GCP resources "+
					"(Cloud Storage objects, BigQuery tables, Datastore entities, etc.) are not recorded. "+
					"This limits forensic capability during incident response. Enable DATA_READ and "+
					"DATA_WRITE audit logs for allServices in the project IAM policy.",
				projectID, formatMissing(missing),
			),
			Severity:     finding.SeverityHigh,
			Asset:        asset,
			Scanner:      "cloud/gcp",
			ProofCommand: fmt.Sprintf("gcloud projects get-iam-policy %s --format='yaml(auditConfigs)'", projectID),
			Evidence: map[string]any{
				"resource_type":    "gcp_project",
				"project_id":       projectID,
				"missing_log_types": missing,
				"data_read":        hasDataRead,
				"data_write":       hasDataWrite,
			},
			DiscoveredAt: time.Now(),
		})
	}

	return findings, nil
}

func formatMissing(types []string) string {
	if len(types) == 1 {
		return types[0]
	}
	return types[0] + " and " + types[1]
}
