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
			if ep != nil && ep.EndpointPublicAccess && len(ep.PublicAccessCidrs) == 0 {
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
		}
	}
	return findings, nil
}
