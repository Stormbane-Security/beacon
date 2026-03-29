package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	computeapi "google.golang.org/api/compute/v1"
	"google.golang.org/api/option"

	"github.com/stormbane/beacon/internal/finding"
)

const defaultServiceAccount = "compute@developer.gserviceaccount.com"

func scanCompute(ctx context.Context, projectID, asset string, opts []option.ClientOption) ([]finding.Finding, error) {
	svc, err := computeapi.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("compute service: %w", err)
	}

	var findings []finding.Finding

	// Iterate all zones to find instances.
	if err := svc.Instances.AggregatedList(projectID).Context(ctx).Pages(ctx,
		func(page *computeapi.InstanceAggregatedList) error {
			for _, items := range page.Items {
				for _, inst := range items.Instances {
					if inst.Status != "RUNNING" {
						continue
					}
					findings = append(findings, checkInstance(inst, projectID, asset)...)
				}
			}
			return nil
		}); err != nil {
		return nil, fmt.Errorf("list instances: %w", err)
	}

	return findings, nil
}

func checkInstance(inst *computeapi.Instance, projectID, asset string) []finding.Finding {
	var findings []finding.Finding

	// Collect all public IPs.
	var publicIPs []string
	for _, iface := range inst.NetworkInterfaces {
		for _, ac := range iface.AccessConfigs {
			if ac.NatIP != "" {
				publicIPs = append(publicIPs, ac.NatIP)
			}
		}
	}

	// Marshal full instance JSON for resource snapshot.
	var resourceSnapshot string
	if b, err := json.Marshal(inst); err == nil {
		if len(b) > 32768 {
			b = b[:32768]
		}
		resourceSnapshot = string(b)
	}

	// Check for default service account.
	for _, sa := range inst.ServiceAccounts {
		if strings.HasSuffix(sa.Email, defaultServiceAccount) {
			findings = append(findings, finding.Finding{
				CheckID: finding.CheckCloudGCPComputeDefaultSA,
				Title:   fmt.Sprintf("GCP instance uses default service account: %s", inst.Name),
				Description: fmt.Sprintf(
					"Instance %s in project %s uses the Compute Engine default service account, "+
						"which has the Editor role on the project by default. This violates least privilege. "+
						"Create a dedicated service account with only the permissions the instance needs.",
					inst.Name, projectID,
				),
				Severity:     finding.SeverityMedium,
				Asset:        asset,
				Scanner:      "cloud/gcp",
				ProofCommand: fmt.Sprintf("gcloud compute instances describe %s --zone=%s --format='get(serviceAccounts)'", inst.Name, zoneFromSelfLink(inst.Zone)),
				Evidence: map[string]any{
					"instance":          inst.Name,
					"instance_id":       inst.Name,
					"resource_type":     "compute_instance",
					"project_id":        projectID,
					"zone":              zoneFromSelfLink(inst.Zone),
					"service_account":   sa.Email,
					"public_ips":        publicIPs,
					"resource_snapshot": resourceSnapshot,
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	// Check for serial port access enabled.
	// serial-port-enable: true in instance or project metadata exposes a console
	// that can be used for privilege escalation.
	if metadataValueEquals(inst.Metadata, "serial-port-enable", "true") {
		findings = append(findings, finding.Finding{
			CheckID: finding.CheckCloudGCPComputeSerialPort,
			Title:   fmt.Sprintf("GCP instance has serial port access enabled: %s", inst.Name),
			Description: fmt.Sprintf(
				"Instance %s in project %s has serial port access enabled via metadata "+
					"'serial-port-enable: true'. The interactive serial console can be used for "+
					"privilege escalation if an attacker gains OS-level access. Disable serial port "+
					"access unless required for debugging.",
				inst.Name, projectID,
			),
			Severity:     finding.SeverityMedium,
			Asset:        asset,
			Scanner:      "cloud/gcp",
			ProofCommand: fmt.Sprintf("gcloud compute instances describe %s --zone=%s --format='get(metadata.items)'", inst.Name, zoneFromSelfLink(inst.Zone)),
			Evidence: map[string]any{
				"instance":          inst.Name,
				"instance_id":       inst.Name,
				"resource_type":     "compute_instance",
				"project_id":        projectID,
				"zone":              zoneFromSelfLink(inst.Zone),
				"public_ips":        publicIPs,
				"resource_snapshot": resourceSnapshot,
			},
			DiscoveredAt: time.Now(),
		})
	}

	// Check for OS Login disabled.
	// Without OS Login (enable-oslogin: true), instances rely on legacy SSH key
	// management via project/instance metadata, which lacks centralized access
	// control and audit logging.
	if !metadataValueEquals(inst.Metadata, "enable-oslogin", "true") {
		findings = append(findings, finding.Finding{
			CheckID: finding.CheckCloudGCPComputeNoOSLogin,
			Title:   fmt.Sprintf("GCP instance does not have OS Login enabled: %s", inst.Name),
			Description: fmt.Sprintf(
				"Instance %s in project %s does not have OS Login enabled. Without OS Login, "+
					"SSH access is managed via legacy SSH keys in project or instance metadata, "+
					"which lacks centralized IAM-based access control and audit logging. "+
					"Enable OS Login by setting 'enable-oslogin: TRUE' in instance metadata.",
				inst.Name, projectID,
			),
			Severity:     finding.SeverityMedium,
			Asset:        asset,
			Scanner:      "cloud/gcp",
			ProofCommand: fmt.Sprintf("gcloud compute instances describe %s --zone=%s --format='get(metadata.items)'", inst.Name, zoneFromSelfLink(inst.Zone)),
			Evidence: map[string]any{
				"instance":          inst.Name,
				"instance_id":       inst.Name,
				"resource_type":     "compute_instance",
				"project_id":        projectID,
				"zone":              zoneFromSelfLink(inst.Zone),
				"public_ips":        publicIPs,
				"resource_snapshot": resourceSnapshot,
			},
			DiscoveredAt: time.Now(),
		})
	}

	return findings
}

// metadataValueEquals checks if a GCP instance metadata key has a specific value (case-insensitive).
func metadataValueEquals(md *computeapi.Metadata, key, value string) bool {
	if md == nil {
		return false
	}
	for _, item := range md.Items {
		if strings.EqualFold(item.Key, key) && item.Value != nil && strings.EqualFold(*item.Value, value) {
			return true
		}
	}
	return false
}

func zoneFromSelfLink(link string) string {
	parts := strings.Split(link, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return link
}
