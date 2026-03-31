package gcp

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/api/option"
	runapi "google.golang.org/api/run/v2"

	"github.com/stormbane/beacon/internal/finding"
)

func scanCloudRun(ctx context.Context, projectID, asset string, opts []option.ClientOption) ([]finding.Finding, error) {
	svc, err := runapi.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("cloud run service: %w", err)
	}

	var findings []finding.Finding

	// List all Cloud Run services across all regions (location "-").
	parent := fmt.Sprintf("projects/%s/locations/-", projectID)
	var pageToken string
	for {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		call := svc.Projects.Locations.Services.List(parent).Context(ctx)
		if pageToken != "" {
			call = call.PageToken(pageToken)
		}
		resp, err := call.Do()
		if err != nil {
			return findings, fmt.Errorf("list cloud run services: %w", err)
		}

		for _, service := range resp.Services {
			findings = append(findings, checkCloudRunService(ctx, svc, service, projectID, asset)...)
		}

		if resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
	}

	return findings, nil
}

func checkCloudRunService(ctx context.Context, svc *runapi.Service, service *runapi.GoogleCloudRunV2Service, projectID, asset string) []finding.Finding {
	var findings []finding.Finding

	serviceName := service.Name
	// Extract short name and region from the full resource name
	// Format: projects/{project}/locations/{location}/services/{service}
	shortName := lastSegment(serviceName)
	region := extractRegion(serviceName)

	// Check IAM policy for unauthenticated access.
	policy, err := svc.Projects.Locations.Services.GetIamPolicy(serviceName).Context(ctx).Do()
	if err == nil {
		for _, binding := range policy.Bindings {
			if binding.Role == "roles/run.invoker" {
				for _, member := range binding.Members {
					if member == "allUsers" || member == "allAuthenticatedUsers" {
						findings = append(findings, finding.Finding{
							CheckID: finding.CheckCloudGCPCloudRunUnauthenticated,
							Title:   fmt.Sprintf("Cloud Run service allows unauthenticated invocations: %s", shortName),
							Description: fmt.Sprintf(
								"Cloud Run service %s in project %s grants %s the roles/run.invoker role, "+
									"allowing anyone on the internet to invoke this service without authentication. "+
									"Remove the %s binding unless this service is intentionally public-facing.",
								shortName, projectID, member, member,
							),
							Severity:     finding.SeverityHigh,
							Asset:        asset,
							Scanner:      "cloud/gcp",
							ProofCommand: fmt.Sprintf("gcloud run services get-iam-policy %s --region=%s --project=%s", shortName, region, projectID),
							Evidence: map[string]any{
								"service":       shortName,
								"resource_type": "cloud_run_service",
								"project_id":    projectID,
								"region":        region,
								"role":          binding.Role,
								"member":        member,
							},
							DiscoveredAt: time.Now(),
						})
					}
				}
			}
		}
	}

	// Check Binary Authorization.
	if service.BinaryAuthorization == nil || (!service.BinaryAuthorization.UseDefault && service.BinaryAuthorization.Policy == "") {
		findings = append(findings, finding.Finding{
			CheckID: finding.CheckCloudGCPCloudRunNoBinaryAuth,
			Title:   fmt.Sprintf("Cloud Run service has no Binary Authorization: %s", shortName),
			Description: fmt.Sprintf(
				"Cloud Run service %s in project %s does not enforce Binary Authorization. "+
					"Without it, any container image can be deployed, including compromised supply chain images. "+
					"Enable Binary Authorization to require attestation before deployment.",
				shortName, projectID,
			),
			Severity:     finding.SeverityMedium,
			Asset:        asset,
			Scanner:      "cloud/gcp",
			ProofCommand: fmt.Sprintf("gcloud run services describe %s --region=%s --project=%s --format='get(binaryAuthorization)'", shortName, region, projectID),
			Evidence: map[string]any{
				"service":       shortName,
				"resource_type": "cloud_run_service",
				"project_id":    projectID,
				"region":        region,
			},
			DiscoveredAt: time.Now(),
		})
	}

	// Check VPC Connector.
	hasVPCConnector := false
	if service.Template != nil && service.Template.VpcAccess != nil {
		if service.Template.VpcAccess.Connector != "" || len(service.Template.VpcAccess.NetworkInterfaces) > 0 {
			hasVPCConnector = true
		}
	}
	if !hasVPCConnector {
		findings = append(findings, finding.Finding{
			CheckID: finding.CheckCloudGCPCloudRunNoVPCConnector,
			Title:   fmt.Sprintf("Cloud Run service has no VPC connector: %s", shortName),
			Description: fmt.Sprintf(
				"Cloud Run service %s in project %s does not have a VPC connector configured. "+
					"Without a VPC connector, all egress traffic from the service goes via the public internet, "+
					"which may expose sensitive data in transit to internal services. Configure a Serverless VPC "+
					"Access connector to route egress through your VPC.",
				shortName, projectID,
			),
			Severity:     finding.SeverityMedium,
			Asset:        asset,
			Scanner:      "cloud/gcp",
			ProofCommand: fmt.Sprintf("gcloud run services describe %s --region=%s --project=%s --format='get(template.vpcAccess)'", shortName, region, projectID),
			Evidence: map[string]any{
				"service":       shortName,
				"resource_type": "cloud_run_service",
				"project_id":    projectID,
				"region":        region,
			},
			DiscoveredAt: time.Now(),
		})
	}

	return findings
}

// lastSegment returns the last path segment of a resource name.
func lastSegment(name string) string {
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == '/' {
			return name[i+1:]
		}
	}
	return name
}

// extractRegion returns the location segment from a Cloud Run resource name.
// Format: projects/{project}/locations/{location}/services/{service}
func extractRegion(name string) string {
	const prefix = "/locations/"
	for i := 0; i < len(name); i++ {
		if i+len(prefix) <= len(name) && name[i:i+len(prefix)] == prefix {
			rest := name[i+len(prefix):]
			for j := 0; j < len(rest); j++ {
				if rest[j] == '/' {
					return rest[:j]
				}
			}
			return rest
		}
	}
	return "unknown"
}
