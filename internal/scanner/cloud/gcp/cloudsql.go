package gcp

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/api/option"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"

	"github.com/stormbane/beacon/internal/finding"
)

func scanCloudSQL(ctx context.Context, projectID, asset string, opts []option.ClientOption) ([]finding.Finding, error) {
	svc, err := sqladmin.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("sqladmin service: %w", err)
	}

	var findings []finding.Finding
	var pageToken string
	for {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		call := svc.Instances.List(projectID).Context(ctx)
		if pageToken != "" {
			call = call.PageToken(pageToken)
		}
		resp, err := call.Do()
		if err != nil {
			return findings, fmt.Errorf("list cloud sql instances: %w", err)
		}

		for _, inst := range resp.Items {
			findings = append(findings, checkCloudSQLInstance(inst, projectID, asset)...)
		}

		if resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
	}

	return findings, nil
}

func checkCloudSQLInstance(inst *sqladmin.DatabaseInstance, projectID, asset string) []finding.Finding {
	var findings []finding.Finding

	instanceName := inst.Name
	region := inst.Region

	// Check for public IP with 0.0.0.0/0 in authorized networks.
	if inst.Settings != nil && inst.Settings.IpConfiguration != nil {
		for _, network := range inst.Settings.IpConfiguration.AuthorizedNetworks {
			if network.Value == "0.0.0.0/0" {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudGCPCloudSQLPublic,
					Title:   fmt.Sprintf("Cloud SQL instance has public IP with 0.0.0.0/0 authorized: %s", instanceName),
					Description: fmt.Sprintf(
						"Cloud SQL instance %s in project %s has a public IP address and authorizes "+
							"connections from 0.0.0.0/0 (the entire internet). This allows any IP address to "+
							"attempt authentication against the database. Remove the 0.0.0.0/0 authorized "+
							"network and restrict access to specific trusted CIDRs, or use Cloud SQL Auth Proxy.",
						instanceName, projectID,
					),
					Severity:     finding.SeverityCritical,
					Asset:        asset,
					Scanner:      "cloud/gcp",
					ProofCommand: fmt.Sprintf("gcloud sql instances describe %s --project=%s --format='get(settings.ipConfiguration)'", instanceName, projectID),
					Evidence: map[string]any{
						"instance":      instanceName,
						"resource_type": "cloud_sql_instance",
						"project_id":    projectID,
						"region":        region,
						"network_name":  network.Name,
						"network_value": network.Value,
					},
					DiscoveredAt: time.Now(),
				})
				break // One finding per instance is enough.
			}
		}

		// Check SSL not required.
		if !inst.Settings.IpConfiguration.RequireSsl {
			findings = append(findings, finding.Finding{
				CheckID: finding.CheckCloudGCPCloudSQLNoSSL,
				Title:   fmt.Sprintf("Cloud SQL instance does not require SSL: %s", instanceName),
				Description: fmt.Sprintf(
					"Cloud SQL instance %s in project %s does not require SSL/TLS for connections. "+
						"Without SSL enforcement, database connections may transmit credentials and data in "+
						"plaintext, vulnerable to network sniffing. Enable 'require SSL' in the instance's "+
						"IP configuration.",
					instanceName, projectID,
				),
				Severity:     finding.SeverityHigh,
				Asset:        asset,
				Scanner:      "cloud/gcp",
				ProofCommand: fmt.Sprintf("gcloud sql instances describe %s --project=%s --format='get(settings.ipConfiguration.requireSsl)'", instanceName, projectID),
				Evidence: map[string]any{
					"instance":      instanceName,
					"resource_type": "cloud_sql_instance",
					"project_id":    projectID,
					"region":        region,
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	// Check automated backups not enabled.
	if inst.Settings != nil {
		backupDisabled := inst.Settings.BackupConfiguration == nil || !inst.Settings.BackupConfiguration.Enabled
		if backupDisabled {
			findings = append(findings, finding.Finding{
				CheckID: finding.CheckCloudGCPCloudSQLNoBackup,
				Title:   fmt.Sprintf("Cloud SQL instance has no automated backups: %s", instanceName),
				Description: fmt.Sprintf(
					"Cloud SQL instance %s in project %s does not have automated backups enabled. "+
						"Without backups, data loss from accidental deletion, corruption, or ransomware "+
						"is unrecoverable. Enable automated backups in the instance's backup configuration.",
					instanceName, projectID,
				),
				Severity:     finding.SeverityMedium,
				Asset:        asset,
				Scanner:      "cloud/gcp",
				ProofCommand: fmt.Sprintf("gcloud sql instances describe %s --project=%s --format='get(settings.backupConfiguration)'", instanceName, projectID),
				Evidence: map[string]any{
					"instance":      instanceName,
					"resource_type": "cloud_sql_instance",
					"project_id":    projectID,
					"region":        region,
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings
}
