package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	awscfg "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"

	"github.com/stormbane-security/beacon/internal/finding"
)

func scanECS(ctx context.Context, cfg awscfg.Config, accountID, region, asset string) ([]finding.Finding, error) {
	svc := ecs.NewFromConfig(cfg)
	var findings []finding.Finding

	// List all clusters.
	clusterArns, err := listClusters(ctx, svc)
	if err != nil {
		return nil, fmt.Errorf("list ECS clusters: %w", err)
	}

	// Scan task definitions (independent of clusters).
	tdFindings := scanTaskDefinitions(ctx, svc, accountID, region, asset)
	findings = append(findings, tdFindings...)

	// Scan services per cluster.
	for _, clusterArn := range clusterArns {
		svcFindings := scanECSServices(ctx, svc, clusterArn, accountID, region, asset)
		findings = append(findings, svcFindings...)
	}

	return findings, nil
}

func listClusters(ctx context.Context, svc *ecs.Client) ([]string, error) {
	var arns []string
	paginator := ecs.NewListClustersPaginator(svc, &ecs.ListClustersInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if len(arns) == 0 {
				return nil, err
			}
			break
		}
		arns = append(arns, page.ClusterArns...)
	}
	return arns, nil
}

func scanTaskDefinitions(ctx context.Context, svc *ecs.Client, accountID, region, asset string) []finding.Finding {
	var findings []finding.Finding

	// List active task definition families.
	famPaginator := ecs.NewListTaskDefinitionFamiliesPaginator(svc, &ecs.ListTaskDefinitionFamiliesInput{
		Status: ecstypes.TaskDefinitionFamilyStatusActive,
	})
	for famPaginator.HasMorePages() {
		page, err := famPaginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, family := range page.Families {
			tdOut, err := svc.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{
				TaskDefinition: awscfg.String(family),
			})
			if err != nil {
				continue
			}
			td := tdOut.TaskDefinition
			if td == nil {
				continue
			}

			tdArn := awscfg.ToString(td.TaskDefinitionArn)
			snapshot := truncatedJSON(td, 32768)

			// Check 1: Host network mode.
			if td.NetworkMode == ecstypes.NetworkModeHost {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSECSHostNetworkMode,
					Title:   fmt.Sprintf("ECS task definition uses host network mode: %s", family),
					Description: fmt.Sprintf(
						"ECS task definition %s uses host network mode. Containers sharing the host "+
							"network namespace can access host-level services bound to localhost (e.g. "+
							"instance metadata, sidecar proxies) and sniff traffic from other containers. "+
							"Use awsvpc or bridge network mode unless host networking is explicitly required.",
						family,
					),
					Severity:     finding.SeverityHigh,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: fmt.Sprintf("aws ecs describe-task-definition --task-definition %s --region %s", family, region),
					Evidence: map[string]any{
						"account_id":           accountID,
						"region":               region,
						"resource_type":        "ecs_task_definition",
						"task_definition_arn":  tdArn,
						"network_mode":         string(td.NetworkMode),
						"resource_snapshot":    snapshot,
					},
					DiscoveredAt: time.Now(),
				})
			}

			// Check 2: No logging configured on any container.
			hasLogging := false
			for _, cd := range td.ContainerDefinitions {
				if cd.LogConfiguration != nil {
					hasLogging = true
					break
				}
			}
			if !hasLogging && len(td.ContainerDefinitions) > 0 {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSECSNoLogging,
					Title:   fmt.Sprintf("ECS task definition has no logging configured: %s", family),
					Description: fmt.Sprintf(
						"No container in ECS task definition %s has a log configuration. Without "+
							"logging, container stdout/stderr is lost, making incident response and "+
							"forensics impossible. Configure awslogs, splunk, or another log driver.",
						family,
					),
					Severity:     finding.SeverityMedium,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: fmt.Sprintf("aws ecs describe-task-definition --task-definition %s --region %s", family, region),
					Evidence: map[string]any{
						"account_id":           accountID,
						"region":               region,
						"resource_type":        "ecs_task_definition",
						"task_definition_arn":  tdArn,
						"resource_snapshot":    snapshot,
					},
					DiscoveredAt: time.Now(),
				})
			}

			// Check 3 & 4: Per-container checks.
			for _, cd := range td.ContainerDefinitions {
				containerName := awscfg.ToString(cd.Name)

				// Check 3: Privileged container.
				if cd.Privileged != nil && *cd.Privileged {
					findings = append(findings, finding.Finding{
						CheckID: finding.CheckCloudAWSECSPrivilegedContainer,
						Title:   fmt.Sprintf("ECS container runs in privileged mode: %s/%s", family, containerName),
						Description: fmt.Sprintf(
							"Container %s in ECS task definition %s runs with privileged=true. "+
								"Privileged containers have full access to the host kernel, devices, "+
								"and can escape the container boundary. Remove privileged mode and "+
								"grant only the specific Linux capabilities required.",
							containerName, family,
						),
						Severity:     finding.SeverityCritical,
						Asset:        asset,
						Scanner:      "cloud/aws",
						ProofCommand: fmt.Sprintf("aws ecs describe-task-definition --task-definition %s --region %s", family, region),
						Evidence: map[string]any{
							"account_id":           accountID,
							"region":               region,
							"resource_type":        "ecs_task_definition",
							"task_definition_arn":  tdArn,
							"container_name":       containerName,
							"resource_snapshot":    snapshot,
						},
						DiscoveredAt: time.Now(),
					})
				}

				// Check 4: Secrets in environment variables.
				var suspectKeys []string
				for _, env := range cd.Environment {
					key := strings.ToUpper(awscfg.ToString(env.Name))
					if containsSecretKeyword(key) {
						suspectKeys = append(suspectKeys, awscfg.ToString(env.Name))
					}
				}
				if len(suspectKeys) > 0 {
					findings = append(findings, finding.Finding{
						CheckID: finding.CheckCloudAWSECSSecretsInEnv,
						Title:   fmt.Sprintf("ECS container has secrets in environment variables: %s/%s", family, containerName),
						Description: fmt.Sprintf(
							"Container %s in ECS task definition %s passes sensitive values via "+
								"plaintext environment variables (%s). Environment variables are visible "+
								"in the task definition, CloudTrail logs, and container inspect output. "+
								"Use AWS Secrets Manager or SSM Parameter Store references instead.",
							containerName, family, strings.Join(suspectKeys, ", "),
						),
						Severity:     finding.SeverityHigh,
						Asset:        asset,
						Scanner:      "cloud/aws",
						ProofCommand: fmt.Sprintf("aws ecs describe-task-definition --task-definition %s --region %s", family, region),
						Evidence: map[string]any{
							"account_id":           accountID,
							"region":               region,
							"resource_type":        "ecs_task_definition",
							"task_definition_arn":  tdArn,
							"container_name":       containerName,
							"suspect_env_keys":     suspectKeys,
							"resource_snapshot":    snapshot,
						},
						DiscoveredAt: time.Now(),
					})
				}
			}
		}
	}

	return findings
}

func scanECSServices(ctx context.Context, svc *ecs.Client, clusterArn, accountID, region, asset string) []finding.Finding {
	var findings []finding.Finding

	// List services in the cluster.
	var serviceArns []string
	svcPaginator := ecs.NewListServicesPaginator(svc, &ecs.ListServicesInput{
		Cluster: awscfg.String(clusterArn),
	})
	for svcPaginator.HasMorePages() {
		page, err := svcPaginator.NextPage(ctx)
		if err != nil {
			break
		}
		serviceArns = append(serviceArns, page.ServiceArns...)
	}

	// DescribeServices accepts up to 10 ARNs at a time.
	for i := 0; i < len(serviceArns); i += 10 {
		end := i + 10
		if end > len(serviceArns) {
			end = len(serviceArns)
		}
		batch := serviceArns[i:end]

		descOut, err := svc.DescribeServices(ctx, &ecs.DescribeServicesInput{
			Cluster:  awscfg.String(clusterArn),
			Services: batch,
		})
		if err != nil {
			continue
		}

		for _, service := range descOut.Services {
			serviceName := awscfg.ToString(service.ServiceName)

			// Check 5: ECS Exec enabled.
			if service.EnableExecuteCommand {
				snapshot := truncatedJSON(service, 32768)
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSECSExecEnabled,
					Title:   fmt.Sprintf("ECS service has execute command enabled: %s", serviceName),
					Description: fmt.Sprintf(
						"ECS service %s in cluster %s has EnableExecuteCommand=true. This allows "+
							"anyone with ecs:ExecuteCommand IAM permission to open an interactive "+
							"shell inside running containers, bypassing application-level access "+
							"controls. Disable execute command unless actively debugging, and restrict "+
							"ecs:ExecuteCommand IAM permissions tightly.",
						serviceName, clusterArn,
					),
					Severity:     finding.SeverityMedium,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: fmt.Sprintf("aws ecs describe-services --cluster %s --services %s --region %s", clusterArn, serviceName, region),
					Evidence: map[string]any{
						"account_id":        accountID,
						"region":            region,
						"resource_type":     "ecs_service",
						"service_name":      serviceName,
						"cluster_arn":       clusterArn,
						"resource_snapshot": snapshot,
					},
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return findings
}

// containsSecretKeyword returns true if the environment variable key name
// (uppercased) contains a keyword that suggests it holds a secret value.
func containsSecretKeyword(key string) bool {
	keywords := []string{"PASSWORD", "SECRET", "API_KEY", "APIKEY", "TOKEN", "PRIVATE_KEY", "DB_PASS"}
	for _, kw := range keywords {
		if strings.Contains(key, kw) {
			return true
		}
	}
	return false
}

// truncatedJSON marshals v to JSON and truncates to maxLen bytes.
func truncatedJSON(v any, maxLen int) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	if len(b) > maxLen {
		b = b[:maxLen]
	}
	return string(b)
}
