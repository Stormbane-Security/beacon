package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	containerapi "google.golang.org/api/container/v1"
	"google.golang.org/api/option"

	"github.com/stormbane-security/beacon/internal/finding"
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

	// Marshal full cluster JSON for resource snapshot.
	var resourceSnapshot string
	if b, err := json.Marshal(cluster); err == nil {
		if len(b) > 32768 {
			b = b[:32768]
		}
		resourceSnapshot = string(b)
	}

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
					"cluster":           cluster.Name,
					"instance_id":       cluster.Name,
					"resource_type":     "gke_cluster",
					"project_id":        projectID,
					"location":          cluster.Location,
					"region":            cluster.Location,
					"endpoint":          cluster.Endpoint,
					"resource_snapshot": resourceSnapshot,
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	// Workload Identity disabled.
	// Without Workload Identity, pods use the node's GCP service account credentials,
	// giving all pods on a node access to the same GCP resources.
	if cluster.WorkloadIdentityConfig == nil || cluster.WorkloadIdentityConfig.WorkloadPool == "" {
		findings = append(findings, finding.Finding{
			CheckID: finding.CheckCloudGCPGKENoWorkloadIdentity,
			Title:   fmt.Sprintf("GKE cluster does not have Workload Identity enabled: %s", cluster.Name),
			Description: fmt.Sprintf(
				"Cluster %s in project %s does not have Workload Identity enabled. Without it, "+
					"pods use the node's GCP service account, giving all pods on the node access to "+
					"the same GCP credentials. Enable Workload Identity to assign per-pod Google "+
					"service accounts via Kubernetes service account annotation.",
				cluster.Name, projectID,
			),
			Severity:     finding.SeverityHigh,
			Asset:        asset,
			Scanner:      "cloud/gcp",
			ProofCommand: fmt.Sprintf("gcloud container clusters describe %s --location=%s --format='get(workloadIdentityConfig)'", cluster.Name, cluster.Location),
			Evidence: map[string]any{
				"cluster":           cluster.Name,
				"instance_id":       cluster.Name,
				"resource_type":     "gke_cluster",
				"project_id":        projectID,
				"location":          cluster.Location,
				"region":            cluster.Location,
				"resource_snapshot": resourceSnapshot,
			},
			DiscoveredAt: time.Now(),
		})
	}

	// Master Authorized Networks disabled.
	// Without master authorized networks, the Kubernetes API server is reachable
	// from any IP address, increasing the attack surface.
	masterAuth := cluster.MasterAuthorizedNetworksConfig
	if masterAuth == nil || !masterAuth.Enabled {
		findings = append(findings, finding.Finding{
			CheckID: finding.CheckCloudGCPGKENoMasterAuthNetworks,
			Title:   fmt.Sprintf("GKE cluster does not have master authorized networks enabled: %s", cluster.Name),
			Description: fmt.Sprintf(
				"Cluster %s in project %s does not have master authorized networks enabled. "+
					"This means the Kubernetes API server can be reached from any IP address. "+
					"Enable master authorized networks and restrict access to trusted CIDRs.",
				cluster.Name, projectID,
			),
			Severity:     finding.SeverityHigh,
			Asset:        asset,
			Scanner:      "cloud/gcp",
			ProofCommand: fmt.Sprintf("gcloud container clusters describe %s --location=%s --format='get(masterAuthorizedNetworksConfig)'", cluster.Name, cluster.Location),
			Evidence: map[string]any{
				"cluster":           cluster.Name,
				"instance_id":       cluster.Name,
				"resource_type":     "gke_cluster",
				"project_id":        projectID,
				"location":          cluster.Location,
				"region":            cluster.Location,
				"resource_snapshot": resourceSnapshot,
			},
			DiscoveredAt: time.Now(),
		})
	}

	// Binary Authorization disabled.
	binaryAuthEnabled := false
	if cluster.BinaryAuthorization != nil {
		if cluster.BinaryAuthorization.EvaluationMode != "" {
			binaryAuthEnabled = cluster.BinaryAuthorization.EvaluationMode != "DISABLED"
		} else {
			binaryAuthEnabled = cluster.BinaryAuthorization.Enabled
		}
	}
	if !binaryAuthEnabled {
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
				"cluster":           cluster.Name,
				"instance_id":       cluster.Name,
				"resource_type":     "gke_cluster",
				"project_id":        projectID,
				"location":          cluster.Location,
				"region":            cluster.Location,
				"resource_snapshot": resourceSnapshot,
			},
			DiscoveredAt: time.Now(),
		})
	}

	// Shielded Nodes disabled.
	// Shielded GKE Nodes protect against rootkit and bootkit attacks by
	// verifying the integrity of the node OS at boot time using vTPM-measured
	// boot and secure boot.
	if cluster.ShieldedNodes == nil || !cluster.ShieldedNodes.Enabled {
		findings = append(findings, finding.Finding{
			CheckID: finding.CheckCloudGKEShieldedNodesDisabled,
			Title:   fmt.Sprintf("GKE cluster does not have Shielded Nodes enabled: %s", cluster.Name),
			Description: fmt.Sprintf(
				"Cluster %s in project %s does not have Shielded GKE Nodes enabled. "+
					"Without Shielded Nodes, cluster nodes are vulnerable to rootkit and bootkit "+
					"attacks that can persist across reboots and compromise the node before the OS "+
					"kernel loads. Enable Shielded GKE Nodes to enforce secure boot, vTPM-measured "+
					"boot, and integrity monitoring on all nodes.",
				cluster.Name, projectID,
			),
			Severity:     finding.SeverityMedium,
			Asset:        asset,
			Scanner:      "cloud/gcp",
			ProofCommand: fmt.Sprintf("gcloud container clusters describe %s --location=%s --format='get(shieldedNodes)'", cluster.Name, cluster.Location),
			Evidence: map[string]any{
				"cluster":           cluster.Name,
				"instance_id":       cluster.Name,
				"resource_type":     "gke_cluster",
				"project_id":        projectID,
				"location":          cluster.Location,
				"region":            cluster.Location,
				"resource_snapshot": resourceSnapshot,
			},
			DiscoveredAt: time.Now(),
		})
	}

	// Network policy not enabled.
	// Without network policy enforcement, all pods in the cluster can
	// communicate freely, enabling unrestricted lateral movement after a
	// pod compromise. Skip this check if Dataplane V2 (Cilium) is enabled,
	// since it provides network policy enforcement natively.
	dataplaneV2 := cluster.NetworkConfig != nil &&
		cluster.NetworkConfig.DatapathProvider == "ADVANCED_DATAPATH"
	networkPolicyEnabled := cluster.NetworkPolicy != nil && cluster.NetworkPolicy.Enabled
	if !dataplaneV2 && !networkPolicyEnabled {
		findings = append(findings, finding.Finding{
			CheckID: finding.CheckCloudGKENoNetworkPolicy,
			Title:   fmt.Sprintf("GKE cluster does not have network policy enabled: %s", cluster.Name),
			Description: fmt.Sprintf(
				"Cluster %s in project %s does not have a network policy provider enabled "+
					"and is not using Dataplane V2 (Cilium). Without network policy enforcement, "+
					"all pods can communicate with all other pods, enabling unrestricted lateral "+
					"movement after a pod compromise. Enable a network policy provider (Calico) "+
					"or switch to Dataplane V2.",
				cluster.Name, projectID,
			),
			Severity:     finding.SeverityMedium,
			Asset:        asset,
			Scanner:      "cloud/gcp",
			ProofCommand: fmt.Sprintf("gcloud container clusters describe %s --location=%s --format='get(networkPolicy,networkConfig.datapathProvider)'", cluster.Name, cluster.Location),
			Evidence: map[string]any{
				"cluster":           cluster.Name,
				"instance_id":       cluster.Name,
				"resource_type":     "gke_cluster",
				"project_id":        projectID,
				"location":          cluster.Location,
				"region":            cluster.Location,
				"resource_snapshot": resourceSnapshot,
			},
			DiscoveredAt: time.Now(),
		})
	}

	// Legacy metadata endpoint enabled.
	// The legacy GCP metadata API (v0.1/v1beta1) does not require the
	// Metadata-Flavor: Google header, making it exploitable via SSRF to
	// steal node credentials and service account tokens.
	findings = append(findings, checkLegacyMetadata(cluster, projectID, asset, resourceSnapshot)...)

	// Node pools using the default compute service account.
	// The default compute SA typically has project-editor permissions,
	// which is far too broad for GKE nodes.
	findings = append(findings, checkNodeDefaultSA(cluster, projectID, asset, resourceSnapshot)...)

	// Node auto-upgrade disabled.
	findings = append(findings, checkNodeAutoUpgrade(cluster, projectID, asset, resourceSnapshot)...)

	return findings
}

// checkLegacyMetadata checks node pools for the legacy metadata endpoint.
func checkLegacyMetadata(cluster *containerapi.Cluster, projectID, asset, resourceSnapshot string) []finding.Finding {
	var findings []finding.Finding

	type poolRef struct {
		name     string
		metadata map[string]string
	}

	var pools []poolRef
	for _, np := range cluster.NodePools {
		if np.Config != nil && np.Config.Metadata != nil {
			pools = append(pools, poolRef{name: np.Name, metadata: np.Config.Metadata})
		} else if cluster.NodeConfig != nil && cluster.NodeConfig.Metadata != nil {
			// Inherit cluster-level metadata when the node pool has no explicit config.
			pools = append(pools, poolRef{name: np.Name, metadata: cluster.NodeConfig.Metadata})
		} else {
			// No metadata config at pool or cluster level — legacy endpoints are
			// enabled by default, so include with empty map to trigger the check.
			pools = append(pools, poolRef{name: np.Name, metadata: map[string]string{}})
		}
	}
	// Fall back to cluster-level node config if there are no node pools at all.
	if len(pools) == 0 {
		metadata := map[string]string{}
		if cluster.NodeConfig != nil && cluster.NodeConfig.Metadata != nil {
			metadata = cluster.NodeConfig.Metadata
		}
		pools = append(pools, poolRef{name: "(cluster-default)", metadata: metadata})
	}

	for _, p := range pools {
		val, exists := p.metadata["disable-legacy-endpoints"]
		if !exists || val == "false" {
			findings = append(findings, finding.Finding{
				CheckID: finding.CheckCloudGKELegacyMetadataEnabled,
				Title:   fmt.Sprintf("GKE node pool has legacy metadata endpoint enabled: %s/%s", cluster.Name, p.name),
				Description: fmt.Sprintf(
					"Node pool %q in cluster %s (project %s) has the legacy GCP metadata endpoint enabled. "+
						"The legacy metadata API (v0.1 and v1beta1) does not require the Metadata-Flavor header, "+
						"making it exploitable via SSRF attacks to steal service account tokens and node "+
						"credentials. Set metadata disable-legacy-endpoints=true on all node pools.",
					p.name, cluster.Name, projectID,
				),
				Severity:     finding.SeverityHigh,
				Asset:        asset,
				Scanner:      "cloud/gcp",
				ProofCommand: fmt.Sprintf("gcloud container node-pools describe %s --cluster=%s --location=%s --format='get(config.metadata)'", p.name, cluster.Name, cluster.Location),
				Evidence: map[string]any{
					"cluster":           cluster.Name,
					"node_pool":         p.name,
					"instance_id":       cluster.Name,
					"resource_type":     "gke_cluster",
					"project_id":        projectID,
					"location":          cluster.Location,
					"region":            cluster.Location,
					"resource_snapshot": resourceSnapshot,
				},
				DiscoveredAt: time.Now(),
			})
		}
	}
	return findings
}

// checkNodeDefaultSA flags node pools using the default compute service account.
func checkNodeDefaultSA(cluster *containerapi.Cluster, projectID, asset, resourceSnapshot string) []finding.Finding {
	var findings []finding.Finding

	isDefaultSA := func(sa string) bool {
		return sa == "" || sa == "default" || strings.HasSuffix(sa, "-compute@developer.gserviceaccount.com")
	}

	for _, np := range cluster.NodePools {
		if np.Config == nil {
			continue
		}
		if isDefaultSA(np.Config.ServiceAccount) {
			findings = append(findings, finding.Finding{
				CheckID: finding.CheckCloudGKENodeDefaultSA,
				Title:   fmt.Sprintf("GKE node pool uses default compute service account: %s/%s", cluster.Name, np.Name),
				Description: fmt.Sprintf(
					"Node pool %q in cluster %s (project %s) uses the default Compute Engine service account. "+
						"The default SA typically has project-editor permissions, giving all pods on the node "+
						"access to most GCP resources in the project. Create a dedicated, least-privilege "+
						"service account for each node pool and combine with Workload Identity for per-pod "+
						"credential isolation.",
					np.Name, cluster.Name, projectID,
				),
				Severity:     finding.SeverityHigh,
				Asset:        asset,
				Scanner:      "cloud/gcp",
				ProofCommand: fmt.Sprintf("gcloud container node-pools describe %s --cluster=%s --location=%s --format='get(config.serviceAccount)'", np.Name, cluster.Name, cluster.Location),
				Evidence: map[string]any{
					"cluster":           cluster.Name,
					"node_pool":         np.Name,
					"service_account":   np.Config.ServiceAccount,
					"instance_id":       cluster.Name,
					"resource_type":     "gke_cluster",
					"project_id":        projectID,
					"location":          cluster.Location,
					"region":            cluster.Location,
					"resource_snapshot": resourceSnapshot,
				},
				DiscoveredAt: time.Now(),
			})
		}
	}
	return findings
}

// checkNodeAutoUpgrade flags node pools with auto-upgrade disabled.
func checkNodeAutoUpgrade(cluster *containerapi.Cluster, projectID, asset, resourceSnapshot string) []finding.Finding {
	var findings []finding.Finding
	for _, np := range cluster.NodePools {
		if np.Management == nil || !np.Management.AutoUpgrade {
			findings = append(findings, finding.Finding{
				CheckID: finding.CheckCloudGKENoAutoUpgrade,
				Title:   fmt.Sprintf("GKE node pool has auto-upgrade disabled: %s/%s", cluster.Name, np.Name),
				Description: fmt.Sprintf(
					"Node pool %q in cluster %s (project %s) does not have automatic node upgrades enabled. "+
						"Without auto-upgrade, nodes remain on older Kubernetes versions with known "+
						"vulnerabilities, increasing the risk of node compromise. Enable auto-upgrade "+
						"to receive security patches automatically.",
					np.Name, cluster.Name, projectID,
				),
				Severity:     finding.SeverityMedium,
				Asset:        asset,
				Scanner:      "cloud/gcp",
				ProofCommand: fmt.Sprintf("gcloud container node-pools describe %s --cluster=%s --location=%s --format='get(management.autoUpgrade)'", np.Name, cluster.Name, cluster.Location),
				Evidence: map[string]any{
					"cluster":           cluster.Name,
					"node_pool":         np.Name,
					"instance_id":       cluster.Name,
					"resource_type":     "gke_cluster",
					"project_id":        projectID,
					"location":          cluster.Location,
					"region":            cluster.Location,
					"resource_snapshot": resourceSnapshot,
				},
				DiscoveredAt: time.Now(),
			})
		}
	}
	return findings
}
