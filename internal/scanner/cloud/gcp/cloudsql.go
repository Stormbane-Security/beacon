package gcp

import (
	"context"
	"fmt"
	"net"
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

				// TCP connectivity test: confirm whether the public Cloud SQL
				// instance is actually reachable from the internet.
				for _, ipAddr := range inst.IpAddresses {
					if ipAddr.Type == "PRIMARY" && ipAddr.IpAddress != "" {
						// Cloud SQL default ports: MySQL=3306, PostgreSQL=5432, SQL Server=1433.
						port := databasePort(inst.DatabaseVersion)
						addr := net.JoinHostPort(ipAddr.IpAddress, fmt.Sprintf("%d", port))
						conn, dialErr := net.DialTimeout("tcp", addr, 5*time.Second)
						if dialErr == nil {
							conn.Close()
							findings = append(findings, finding.Finding{
								CheckID: finding.CheckCloudGCPCloudSQLReachable,
								Title:   fmt.Sprintf("Cloud SQL instance is publicly reachable via TCP: %s", instanceName),
								Description: fmt.Sprintf(
									"Cloud SQL instance %s in project %s is not only configured with a "+
										"public IP and 0.0.0.0/0 authorized network but actually accepts TCP "+
										"connections from the internet on %s. An attacker can attempt brute-force "+
										"authentication. Restrict network access immediately.",
									instanceName, projectID, addr,
								),
								Severity:     finding.SeverityCritical,
								Asset:        asset,
								Scanner:      "cloud/gcp",
								ProofCommand: fmt.Sprintf("nc -zv %s %d", ipAddr.IpAddress, port),
								Evidence: map[string]any{
									"instance":      instanceName,
									"resource_type": "cloud_sql_instance",
									"project_id":    projectID,
									"region":        region,
									"endpoint":      addr,
								},
								DiscoveredAt: time.Now(),
							})
						}
						break
					}
				}

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

// databasePort returns the default port for a Cloud SQL database version string.
func databasePort(databaseVersion string) int {
	switch {
	case len(databaseVersion) >= 5 && databaseVersion[:5] == "MYSQL":
		return 3306
	case len(databaseVersion) >= 8 && databaseVersion[:8] == "POSTGRES":
		return 5432
	case len(databaseVersion) >= 9 && databaseVersion[:9] == "SQLSERVER":
		return 1433
	default:
		return 3306
	}
}
