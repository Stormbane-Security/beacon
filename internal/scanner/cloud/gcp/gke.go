package gcp

import (
	"context"
	"fmt"
	"time"

	containerapi "google.golang.org/api/container/v1"
	"google.golang.org/api/option"

	"github.com/stormbane/beacon/internal/finding"
)

func scanGKE(ctx context.Context, projectID, asset string, opts []option.ClientOption) ([]finding.Finding, error) {
	svc, err := containerapi.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("container service: %w", err)
	}

	resp, err := svc.Projects.Locations.Clusters.List(
		fmt.Sprintf("projects/%s/locations/-", projectID),
	).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("list clusters: %w", err)
	}

	var findings []finding.Finding
	for _, cluster := range resp.Clusters {
		findings = append(findings, checkCluster(cluster, projectID, asset)...)
	}
	return findings, nil
}

func checkCluster(cluster *containerapi.Cluster, projectID, asset string) []finding.Finding {
	var findings []finding.Finding

	// Public endpoint with no authorized networks.
	// A nil PrivateClusterConfig or EnablePrivateEndpoint==false means the API server
	// is reachable on a public IP.
	privateEndpointEnabled := cluster.PrivateClusterConfig != nil &&
		cluster.PrivateClusterConfig.EnablePrivateEndpoint
	if !privateEndpointEnabled {
		masterAuth := cluster.MasterAuthorizedNetworksConfig
		if masterAuth == nil || !masterAuth.Enabled || len(masterAuth.CidrBlocks) == 0 {
			findings = append(findings, finding.Finding{
				CheckID: finding.CheckCloudGCPGKEPublicEndpoint,
				Title:   fmt.Sprintf("GKE cluster has public endpoint with no authorized networks: %s", cluster.Name),
				Description: fmt.Sprintf(
					"Cluster %s in project %s has a public Kubernetes API server endpoint "+
						"with no authorized network restrictions. Any IP can attempt to reach the API. "+
						"Enable Master Authorized Networks to restrict access to trusted CIDRs, "+
						"or enable private cluster mode.",
					cluster.Name, projectID,
				),
				Severity:     finding.SeverityHigh,
				Asset:        asset,
				Scanner:      "cloud/gcp",
				ProofCommand: fmt.Sprintf("gcloud container clusters describe %s --location=%s --format='get(masterAuthorizedNetworksConfig,privateClusterConfig)'", cluster.Name, cluster.Location),
				Evidence: map[string]any{
					"cluster":    cluster.Name,
					"project_id": projectID,
					"location":   cluster.Location,
					"endpoint":   cluster.Endpoint,
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	// Binary Authorization disabled.
	if cluster.BinaryAuthorization == nil || !cluster.BinaryAuthorization.Enabled {
		findings = append(findings, finding.Finding{
			CheckID: finding.CheckCloudGCPGKENoBinaryAuth,
			Title:   fmt.Sprintf("GKE cluster has Binary Authorization disabled: %s", cluster.Name),
			Description: fmt.Sprintf(
				"Cluster %s in project %s does not enforce Binary Authorization. "+
					"Without it, any container image (including compromised supply chain images) "+
					"can be deployed. Enable Binary Authorization and require attestation from "+
					"a trusted authority (e.g., Cloud Build) before allowing deployment.",
				cluster.Name, projectID,
			),
			Severity:     finding.SeverityMedium,
			Asset:        asset,
			Scanner:      "cloud/gcp",
			ProofCommand: fmt.Sprintf("gcloud container clusters describe %s --location=%s --format='get(binaryAuthorization)'", cluster.Name, cluster.Location),
			Evidence: map[string]any{
				"cluster":    cluster.Name,
				"project_id": projectID,
				"location":   cluster.Location,
			},
			DiscoveredAt: time.Now(),
		})
	}

	return findings
}
