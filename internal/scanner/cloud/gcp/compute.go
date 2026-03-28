package gcp

import (
	"context"
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

	// Check for public IP.
	var externalIP string
	for _, iface := range inst.NetworkInterfaces {
		for _, ac := range iface.AccessConfigs {
			if ac.NatIP != "" {
				externalIP = ac.NatIP
				break
			}
		}
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
					"instance":        inst.Name,
					"project_id":      projectID,
					"zone":            zoneFromSelfLink(inst.Zone),
					"service_account": sa.Email,
					"external_ip":     externalIP,
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings
}

func zoneFromSelfLink(link string) string {
	parts := strings.Split(link, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return link
}
