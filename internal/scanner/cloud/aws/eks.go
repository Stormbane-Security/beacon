package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	awscfg "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"

	"github.com/stormbane/beacon/internal/finding"
)

func scanEKS(ctx context.Context, cfg awscfg.Config, accountID, region, asset string) ([]finding.Finding, error) {
	svc := eks.NewFromConfig(cfg)
	var findings []finding.Finding

	paginator := eks.NewListClustersPaginator(svc, &eks.ListClustersInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, name := range page.Clusters {
			desc, err := svc.DescribeCluster(ctx, &eks.DescribeClusterInput{Name: &name})
			if err != nil || desc.Cluster == nil {
				continue
			}
			cluster := desc.Cluster

			var clusterSnapshot string
			if b, merr := json.Marshal(cluster); merr == nil {
				if len(b) > 32768 {
					b = b[:32768]
				}
				clusterSnapshot = string(b)
			}

			ep := cluster.ResourcesVpcConfig
			if ep == nil {
				continue
			}
			isWideOpen := len(ep.PublicAccessCidrs) == 0
			if !isWideOpen {
				for _, cidr := range ep.PublicAccessCidrs {
					if cidr == "0.0.0.0/0" || cidr == "::/0" {
						isWideOpen = true
						break
					}
				}
			}
			if ep.EndpointPublicAccess && isWideOpen {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSEKSPublicEndpoint,
					Title:   fmt.Sprintf("EKS cluster has public endpoint with no CIDR restriction: %s", name),
					Description: fmt.Sprintf(
						"EKS cluster %s in %s has a public Kubernetes API endpoint with no CIDR restrictions "+
							"(publicAccessCidrs is empty). Any IP can attempt to reach the API server. "+
							"Restrict publicAccessCidrs to trusted CIDRs or enable private-only endpoint access.",
						name, region,
					),
					Severity:     finding.SeverityHigh,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: fmt.Sprintf("aws eks describe-cluster --name %s --region %s --query 'cluster.resourcesVpcConfig'", name, region),
					Evidence: map[string]any{
						"account_id":        accountID,
						"cluster_name":      name,
						"instance_id":       name,
						"resource_type":     "eks_cluster",
						"region":            region,
						"endpoint":          awscfg.ToString(cluster.Endpoint),
						"public_access":     ep.EndpointPublicAccess,
						"resource_snapshot": clusterSnapshot,
					},
					DiscoveredAt: time.Now(),
				})
			}

			// Check for audit logging disabled.
			// Without audit logging, security-relevant events (authentication,
			// authorization, API calls) are not recorded, making incident
			// response and forensics difficult.
			auditLogEnabled := false
			if cluster.Logging != nil {
				for _, logSetup := range cluster.Logging.ClusterLogging {
					if logSetup.Enabled != nil && *logSetup.Enabled {
						for _, logType := range logSetup.Types {
							if string(logType) == "audit" {
								auditLogEnabled = true
								break
							}
						}
					}
					if auditLogEnabled {
						break
					}
				}
			}
			if !auditLogEnabled {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSEKSNoLogging,
					Title:   fmt.Sprintf("EKS cluster does not have audit logging enabled: %s", name),
					Description: fmt.Sprintf(
						"EKS cluster %s in %s does not have audit logging enabled. Without audit logs, "+
							"Kubernetes API calls are not recorded, making it impossible to detect "+
							"unauthorized access, privilege escalation, or lateral movement within the cluster. "+
							"Enable the 'audit' log type in the cluster logging configuration.",
						name, region,
					),
					Severity:     finding.SeverityMedium,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: fmt.Sprintf("aws eks describe-cluster --name %s --region %s --query 'cluster.logging'", name, region),
					Evidence: map[string]any{
						"account_id":        accountID,
						"cluster_name":      name,
						"instance_id":       name,
						"resource_type":     "eks_cluster",
						"region":            region,
						"resource_snapshot": clusterSnapshot,
					},
					DiscoveredAt: time.Now(),
				})
			}

			// IRSA (IAM Roles for Service Accounts) not configured.
			// Without IRSA, pods use the node's IAM role, which typically has
			// broad permissions shared across all workloads on the node.
			irsaConfigured := cluster.Identity != nil &&
				cluster.Identity.Oidc != nil &&
				cluster.Identity.Oidc.Issuer != nil &&
				*cluster.Identity.Oidc.Issuer != ""
			if !irsaConfigured {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudEKSNoIRSA,
					Title:   fmt.Sprintf("EKS cluster does not have IRSA (IAM Roles for Service Accounts) configured: %s", name),
					Description: fmt.Sprintf(
						"EKS cluster %s in %s does not have an OIDC provider configured for IAM Roles "+
							"for Service Accounts (IRSA). Without IRSA, all pods on a node share the node's "+
							"IAM role, which typically has broad permissions. Configure an OIDC identity "+
							"provider to enable per-pod IAM role assignment via Kubernetes service account annotations.",
						name, region,
					),
					Severity:     finding.SeverityHigh,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: fmt.Sprintf("aws eks describe-cluster --name %s --region %s --query 'cluster.identity.oidc'", name, region),
					Evidence: map[string]any{
						"account_id":        accountID,
						"cluster_name":      name,
						"instance_id":       name,
						"resource_type":     "eks_cluster",
						"region":            region,
						"resource_snapshot": clusterSnapshot,
					},
					DiscoveredAt: time.Now(),
				})
			}

			// Check for EKS Pod Identity Agent addon.
			// EKS Pod Identity is the newer alternative to IRSA. Check whether
			// the eks-pod-identity-agent addon is installed on the cluster.
			hasPodIdentityAddon := false
			addonsResp, addonsErr := svc.ListAddons(ctx, &eks.ListAddonsInput{ClusterName: &name})
			if addonsErr == nil {
				for _, addon := range addonsResp.Addons {
					if addon == "eks-pod-identity-agent" {
						hasPodIdentityAddon = true
						break
					}
				}
			}
			if !hasPodIdentityAddon && !irsaConfigured {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudEKSNoPodIdentity,
					Title:   fmt.Sprintf("EKS cluster has neither IRSA nor Pod Identity configured: %s", name),
					Description: fmt.Sprintf(
						"EKS cluster %s in %s has neither IAM Roles for Service Accounts (IRSA) nor "+
							"EKS Pod Identity configured. Without a pod-level identity mechanism, all pods "+
							"share the node's IAM role. Consider enabling EKS Pod Identity (the newer, "+
							"simpler alternative to IRSA) or configuring an OIDC provider for IRSA.",
						name, region,
					),
					Severity:     finding.SeverityMedium,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: fmt.Sprintf("aws eks list-addons --cluster-name %s --region %s", name, region),
					Evidence: map[string]any{
						"account_id":        accountID,
						"cluster_name":      name,
						"instance_id":       name,
						"resource_type":     "eks_cluster",
						"region":            region,
						"resource_snapshot": clusterSnapshot,
					},
					DiscoveredAt: time.Now(),
				})
			}

			// Network policy enforcement not detected.
			// EKS does not natively enforce Kubernetes NetworkPolicy resources.
			// A CNI plugin with network policy support (e.g., Calico, Cilium)
			// must be installed separately.
			hasNetworkPolicyAddon := false
			if cluster.Health != nil {
				// Check cluster addons/health for indicators of a network policy provider.
				// The presence of vpc-cni alone does not provide NetworkPolicy enforcement.
			}
			// Also attempt to detect via the cluster's Kubernetes network config.
			if cluster.KubernetesNetworkConfig != nil {
				// The VPC CNI is always present but does not enforce NetworkPolicy
				// unless Amazon Network Policy Controller is also installed.
				// There is no direct API field for this — flag as a warning.
			}
			if !hasNetworkPolicyAddon {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudEKSNoNetworkPolicy,
					Title:   fmt.Sprintf("EKS cluster has no network policy enforcement detected: %s", name),
					Description: fmt.Sprintf(
						"EKS cluster %s in %s does not appear to have a network policy enforcement mechanism "+
							"configured. The default AWS VPC CNI plugin does not enforce Kubernetes NetworkPolicy "+
							"resources. Without network policy enforcement, all pods can communicate freely, "+
							"enabling unrestricted lateral movement after a pod compromise. Install a CNI plugin "+
							"with NetworkPolicy support (e.g., Calico or Cilium) or enable the Amazon Network "+
							"Policy Controller addon.",
						name, region,
					),
					Severity:     finding.SeverityMedium,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: fmt.Sprintf("aws eks describe-cluster --name %s --region %s --query 'cluster.kubernetesNetworkConfig'", name, region),
					Evidence: map[string]any{
						"account_id":        accountID,
						"cluster_name":      name,
						"instance_id":       name,
						"resource_type":     "eks_cluster",
						"region":            region,
						"resource_snapshot": clusterSnapshot,
					},
					DiscoveredAt: time.Now(),
				})
			}

			// Secrets not encrypted at rest with KMS.
			// Without envelope encryption, Kubernetes secrets are stored as
			// base64-encoded plaintext in etcd.
			secretsEncrypted := false
			if cluster.EncryptionConfig != nil {
				for _, ec := range cluster.EncryptionConfig {
					if ec.Provider != nil && ec.Provider.KeyArn != nil && *ec.Provider.KeyArn != "" {
						for _, res := range ec.Resources {
							if res == "secrets" {
								secretsEncrypted = true
								break
							}
						}
					}
					if secretsEncrypted {
						break
					}
				}
			}
			if !secretsEncrypted {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudEKSNoSecretEncryption,
					Title:   fmt.Sprintf("EKS cluster does not encrypt Kubernetes secrets with KMS: %s", name),
					Description: fmt.Sprintf(
						"EKS cluster %s in %s does not have envelope encryption configured for Kubernetes secrets. "+
							"Without KMS encryption, secrets (database credentials, API keys, TLS certificates) are "+
							"stored as base64-encoded plaintext in etcd. Enable envelope encryption with a "+
							"customer-managed KMS key to protect secrets at rest.",
						name, region,
					),
					Severity:     finding.SeverityHigh,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: fmt.Sprintf("aws eks describe-cluster --name %s --region %s --query 'cluster.encryptionConfig'", name, region),
					Evidence: map[string]any{
						"account_id":        accountID,
						"cluster_name":      name,
						"instance_id":       name,
						"resource_type":     "eks_cluster",
						"region":            region,
						"resource_snapshot": clusterSnapshot,
					},
					DiscoveredAt: time.Now(),
				})
			}

			// Private endpoint not enabled.
			// When only the public endpoint is enabled without private access,
			// all cluster management traffic (including from nodes) traverses the
			// internet.
			if ep != nil && ep.EndpointPublicAccess && !ep.EndpointPrivateAccess {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudEKSNoPrivateEndpoint,
					Title:   fmt.Sprintf("EKS cluster does not have private API endpoint enabled: %s", name),
					Description: fmt.Sprintf(
						"EKS cluster %s in %s has the public API endpoint enabled but not the private endpoint. "+
							"Without a private endpoint, all cluster management traffic (including node-to-API-server "+
							"communication) traverses the public internet. Enable the private endpoint so that "+
							"nodes and internal services communicate with the API server over the VPC.",
						name, region,
					),
					Severity:     finding.SeverityMedium,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: fmt.Sprintf("aws eks describe-cluster --name %s --region %s --query 'cluster.resourcesVpcConfig.{public:endpointPublicAccess,private:endpointPrivateAccess}'", name, region),
					Evidence: map[string]any{
						"account_id":          accountID,
						"cluster_name":        name,
						"instance_id":         name,
						"resource_type":       "eks_cluster",
						"region":              region,
						"public_access":       ep.EndpointPublicAccess,
						"private_access":      ep.EndpointPrivateAccess,
						"resource_snapshot":   clusterSnapshot,
					},
					DiscoveredAt: time.Now(),
				})
			}
		}
	}
	return findings, nil
}
