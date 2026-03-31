package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	awscfg "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"github.com/stormbane/beacon/internal/finding"
)

// eolRuntimes lists Lambda runtimes that have reached end-of-life and no
// longer receive security patches from AWS.
var eolRuntimes = map[string]bool{
	"python2.7":      true,
	"python3.6":      true,
	"python3.7":      true,
	"nodejs10.x":     true,
	"nodejs12.x":     true,
	"nodejs14.x":     true,
	"dotnetcore2.1":  true,
	"dotnetcore3.1":  true,
	"ruby2.5":        true,
	"ruby2.7":        true,
	"java8":          true,
	"go1.x":          true,
}

// secretKeyPatterns are substrings that, when found in an environment variable
// key (case-insensitive), suggest the value may contain a secret.
var secretKeyPatterns = []string{
	"PASSWORD",
	"SECRET",
	"API_KEY",
	"APIKEY",
	"TOKEN",
	"PRIVATE_KEY",
	"DB_PASS",
	"DATABASE_URL",
}

func scanLambda(ctx context.Context, cfg awscfg.Config, accountID, region, asset string) ([]finding.Finding, error) {
	svc := lambda.NewFromConfig(cfg)
	var findings []finding.Finding

	paginator := lambda.NewListFunctionsPaginator(svc, &lambda.ListFunctionsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if len(findings) == 0 {
				return nil, fmt.Errorf("list lambda functions: %w", err)
			}
			break
		}

		for _, fn := range page.Functions {
			fnName := awscfg.ToString(fn.FunctionName)
			runtime := string(fn.Runtime)

			// Build a resource snapshot (truncated to 32KB) for evidence.
			var resourceSnapshot string
			if b, merr := json.Marshal(fn); merr == nil {
				if len(b) > 32768 {
					b = b[:32768]
				}
				resourceSnapshot = string(b)
			}

			proofCmd := fmt.Sprintf("aws lambda get-function-configuration --function-name %s --region %s", fnName, region)

			// Check 1: No VPC configuration.
			if fn.VpcConfig == nil || len(fn.VpcConfig.SubnetIds) == 0 {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSLambdaNoVPC,
					Title:   fmt.Sprintf("Lambda function has no VPC configuration: %s", fnName),
					Description: fmt.Sprintf(
						"Lambda function %s in %s is not attached to a VPC. Functions outside a VPC "+
							"cannot leverage VPC security groups or network ACLs for egress filtering, "+
							"increasing the blast radius if the function is compromised. Attach the "+
							"function to a VPC with appropriate subnet and security group configuration.",
						fnName, region,
					),
					Severity:     finding.SeverityMedium,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: proofCmd,
					Evidence: map[string]any{
						"account_id":        accountID,
						"function_name":     fnName,
						"region":            region,
						"resource_type":     "lambda_function",
						"runtime":           runtime,
						"resource_snapshot": resourceSnapshot,
					},
					DiscoveredAt: time.Now(),
				})
			}

			// Check 2: Environment variables containing potential secrets.
			if fn.Environment != nil && len(fn.Environment.Variables) > 0 {
				var suspiciousKeys []string
				for key := range fn.Environment.Variables {
					upperKey := strings.ToUpper(key)
					for _, pattern := range secretKeyPatterns {
						if strings.Contains(upperKey, pattern) {
							suspiciousKeys = append(suspiciousKeys, key)
							break
						}
					}
				}
				if len(suspiciousKeys) > 0 {
					findings = append(findings, finding.Finding{
						CheckID: finding.CheckCloudAWSLambdaEnvSecrets,
						Title:   fmt.Sprintf("Lambda function has potential secrets in environment variables: %s", fnName),
						Description: fmt.Sprintf(
							"Lambda function %s in %s has environment variable keys that suggest secrets "+
								"are stored in plaintext: %s. Plaintext secrets in environment variables are "+
								"visible to anyone with Lambda read access and appear in CloudTrail logs. "+
								"Use AWS Secrets Manager or SSM Parameter Store (SecureString) instead.",
							fnName, region, strings.Join(suspiciousKeys, ", "),
						),
						Severity:     finding.SeverityHigh,
						Asset:        asset,
						Scanner:      "cloud/aws",
						ProofCommand: proofCmd,
						Evidence: map[string]any{
							"account_id":        accountID,
							"function_name":     fnName,
							"region":            region,
							"resource_type":     "lambda_function",
							"runtime":           runtime,
							"suspicious_keys":   suspiciousKeys,
							"resource_snapshot": resourceSnapshot,
						},
						DiscoveredAt: time.Now(),
					})
				}
			}

			// Check 3: End-of-life runtime.
			if eolRuntimes[runtime] {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSLambdaRuntimeEOL,
					Title:   fmt.Sprintf("Lambda function uses end-of-life runtime (%s): %s", runtime, fnName),
					Description: fmt.Sprintf(
						"Lambda function %s in %s uses runtime %s which has reached end-of-life. "+
							"EOL runtimes no longer receive security patches from AWS, leaving the "+
							"function vulnerable to known exploits. Migrate to a supported runtime version.",
						fnName, region, runtime,
					),
					Severity:     finding.SeverityHigh,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: proofCmd,
					Evidence: map[string]any{
						"account_id":        accountID,
						"function_name":     fnName,
						"region":            region,
						"resource_type":     "lambda_function",
						"runtime":           runtime,
						"resource_snapshot": resourceSnapshot,
					},
					DiscoveredAt: time.Now(),
				})
			}

			// Check 4: No dead-letter queue configured.
			if fn.DeadLetterConfig == nil || awscfg.ToString(fn.DeadLetterConfig.TargetArn) == "" {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSLambdaNoDLQ,
					Title:   fmt.Sprintf("Lambda function has no dead-letter queue configured: %s", fnName),
					Description: fmt.Sprintf(
						"Lambda function %s in %s does not have a dead-letter queue (DLQ) configured. "+
							"Without a DLQ, failed asynchronous invocations are silently discarded after "+
							"retry exhaustion, causing data loss and making failures invisible. Configure "+
							"a DLQ (SQS queue or SNS topic) to capture failed events.",
						fnName, region,
					),
					Severity:     finding.SeverityLow,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: proofCmd,
					Evidence: map[string]any{
						"account_id":        accountID,
						"function_name":     fnName,
						"region":            region,
						"resource_type":     "lambda_function",
						"runtime":           runtime,
						"resource_snapshot": resourceSnapshot,
					},
					DiscoveredAt: time.Now(),
				})
			}

			// Check 5: X-Ray tracing not enabled.
			if fn.TracingConfig == nil || fn.TracingConfig.Mode != lambdatypes.TracingModeActive {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSLambdaNoTracing,
					Title:   fmt.Sprintf("Lambda function does not have X-Ray tracing enabled: %s", fnName),
					Description: fmt.Sprintf(
						"Lambda function %s in %s does not have AWS X-Ray active tracing enabled. "+
							"Without tracing, it is difficult to diagnose performance issues, detect "+
							"anomalous invocation patterns, or investigate security incidents. Enable "+
							"active tracing by setting TracingConfig.Mode to Active.",
						fnName, region,
					),
					Severity:     finding.SeverityLow,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: proofCmd,
					Evidence: map[string]any{
						"account_id":        accountID,
						"function_name":     fnName,
						"region":            region,
						"resource_type":     "lambda_function",
						"runtime":           runtime,
						"resource_snapshot": resourceSnapshot,
					},
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return findings, nil
}
