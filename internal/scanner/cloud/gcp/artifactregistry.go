package gcp

import (
	"context"
	"fmt"
	"strings"
	"time"

	artifactregistry "google.golang.org/api/artifactregistry/v1"
	"google.golang.org/api/option"

	"github.com/stormbane/beacon/internal/finding"
)

func scanArtifactRegistry(ctx context.Context, projectID, asset string, opts []option.ClientOption) ([]finding.Finding, error) {
	svc, err := artifactregistry.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("artifact registry service: %w", err)
	}

	var findings []finding.Finding

	// List all repos across all locations (location "-").
	parent := fmt.Sprintf("projects/%s/locations/-", projectID)
	var pageToken string
	for {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		call := svc.Projects.Locations.Repositories.List(parent).Context(ctx)
		if pageToken != "" {
			call = call.PageToken(pageToken)
		}
		resp, err := call.Do()
		if err != nil {
			return findings, fmt.Errorf("list artifact registry repos: %w", err)
		}

		for _, repo := range resp.Repositories {
			repoFindings := checkArtifactRegistryRepo(ctx, svc, repo, projectID, asset)
			findings = append(findings, repoFindings...)
		}

		if resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
	}

	return findings, nil
}

func checkArtifactRegistryRepo(ctx context.Context, svc *artifactregistry.Service, repo *artifactregistry.Repository, projectID, asset string) []finding.Finding {
	var findings []finding.Finding

	repoName := repo.Name
	shortName := repoShortName(repoName)
	region := repoRegion(repoName)

	// Get IAM policy for the repo.
	policy, err := svc.Projects.Locations.Repositories.GetIamPolicy(repoName).Context(ctx).Do()
	if err != nil {
		return findings
	}

	for _, binding := range policy.Bindings {
		for _, member := range binding.Members {
			if member == "allUsers" || member == "allAuthenticatedUsers" {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudGCPArtifactRegistryPublic,
					Title:   fmt.Sprintf("Artifact Registry repo is publicly accessible: %s", shortName),
					Description: fmt.Sprintf(
						"Artifact Registry repository %s in project %s grants %s the %s role. "+
							"This allows anyone to access container images or packages in this repository, "+
							"potentially exposing proprietary code, internal dependencies, or supply chain artifacts. "+
							"Remove the %s binding to restrict access.",
						shortName, projectID, member, binding.Role, member,
					),
					Severity:     finding.SeverityHigh,
					Asset:        asset,
					Scanner:      "cloud/gcp",
					ProofCommand: fmt.Sprintf("gcloud artifacts repositories get-iam-policy %s --location=%s --project=%s", shortName, region, projectID),
					Evidence: map[string]any{
						"repository":    shortName,
						"resource_type": "artifact_registry_repository",
						"project_id":    projectID,
						"region":        region,
						"role":          binding.Role,
						"member":        member,
						"format":        repo.Format,
					},
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return findings
}

// repoShortName returns the repository name from a full resource name.
// Format: projects/{project}/locations/{location}/repositories/{repo}
func repoShortName(name string) string {
	parts := strings.Split(name, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return name
}

// repoRegion returns the location from a full resource name.
// Format: projects/{project}/locations/{location}/repositories/{repo}
func repoRegion(name string) string {
	parts := strings.Split(name, "/")
	for i, part := range parts {
		if part == "locations" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return "unknown"
}
