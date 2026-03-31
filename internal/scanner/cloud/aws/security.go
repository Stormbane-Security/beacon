package aws

// This file contains account-level AWS security posture checks:
// GuardDuty, Security Hub, AWS Config, KMS rotation, Lambda,
// API Gateway, SNS/SQS, Secrets Manager.

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	awscfg "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"

	"github.com/stormbane/beacon/internal/finding"
)

func scanSecurity(ctx context.Context, cfg awscfg.Config, accountID, region, asset string) ([]finding.Finding, error) {
	var findings []finding.Finding

	// --- GuardDuty ---
	if f, err := checkGuardDuty(ctx, cfg, accountID, region, asset); err == nil {
		findings = append(findings, f...)
	}

	// --- Security Hub ---
	if f, err := checkSecurityHub(ctx, cfg, accountID, region, asset); err == nil {
		findings = append(findings, f...)
	}

	// --- AWS Config ---
	if f, err := checkAWSConfig(ctx, cfg, accountID, region, asset); err == nil {
		findings = append(findings, f...)
	}

	// --- KMS Key Rotation ---
	if f, err := checkKMSRotation(ctx, cfg, accountID, region, asset); err == nil {
		findings = append(findings, f...)
	}

	// --- Lambda Function URLs without auth ---
	if f, err := checkLambdaNoAuth(ctx, cfg, accountID, region, asset); err == nil {
		findings = append(findings, f...)
	}

	// --- Lambda Overprivileged ---
	if f, err := checkLambdaOverprivileged(ctx, cfg, accountID, region, asset); err == nil {
		findings = append(findings, f...)
	}

	// --- API Gateway No Auth ---
	if f, err := checkAPIGatewayNoAuth(ctx, cfg, accountID, region, asset); err == nil {
		findings = append(findings, f...)
	}

	// --- SNS No Encryption ---
	if f, err := checkSNSEncryption(ctx, cfg, accountID, region, asset); err == nil {
		findings = append(findings, f...)
	}

	// --- SQS No Encryption ---
	if f, err := checkSQSEncryption(ctx, cfg, accountID, region, asset); err == nil {
		findings = append(findings, f...)
	}

	// --- Secrets Manager No Rotation ---
	if f, err := checkSecretsRotation(ctx, cfg, accountID, region, asset); err == nil {
		findings = append(findings, f...)
	}

	return findings, nil
}

// checkGuardDuty verifies that GuardDuty is enabled by listing detectors.
func checkGuardDuty(ctx context.Context, cfg awscfg.Config, accountID, region, asset string) ([]finding.Finding, error) {
	svc := guardduty.NewFromConfig(cfg)

	resp, err := svc.ListDetectors(ctx, &guardduty.ListDetectorsInput{})
	if err != nil {
		return nil, fmt.Errorf("guardduty list detectors: %w", err)
	}

	if len(resp.DetectorIds) == 0 {
		return []finding.Finding{{
			CheckID: finding.CheckCloudAWSNoGuardDuty,
			Title:   "Amazon GuardDuty is not enabled",
			Description: "Amazon GuardDuty is not enabled. GuardDuty provides intelligent threat " +
				"detection using machine learning to identify malicious activity, unauthorized " +
				"behavior, and compromised instances.",
			Severity:     finding.SeverityHigh,
			Asset:        asset,
			Scanner:      "cloud/aws",
			ProofCommand: fmt.Sprintf("aws guardduty list-detectors --region %s", region),
			Evidence: map[string]any{
				"account_id":    accountID,
				"region":        region,
				"resource_type": "guardduty",
			},
			DiscoveredAt: time.Now(),
		}}, nil
	}

	return nil, nil
}

// checkSecurityHub verifies that AWS Security Hub is enabled in the account.
func checkSecurityHub(ctx context.Context, cfg awscfg.Config, accountID, region, asset string) ([]finding.Finding, error) {
	svc := securityhub.NewFromConfig(cfg)

	_, err := svc.DescribeHub(ctx, &securityhub.DescribeHubInput{})
	if err != nil {
		// If the call fails, Security Hub is not enabled (or we lack permissions).
		// Distinguish between "not enabled" and "access denied" by checking the error message.
		errMsg := err.Error()
		if strings.Contains(errMsg, "AccessDeniedException") {
			return nil, fmt.Errorf("securityhub describe hub: %w", err)
		}
		return []finding.Finding{{
			CheckID: finding.CheckCloudAWSNoSecurityHub,
			Title:   "AWS Security Hub is not enabled",
			Description: "AWS Security Hub is not enabled. Security Hub aggregates findings from " +
				"GuardDuty, Inspector, Macie, and third-party tools into a single pane of glass " +
				"for centralized security monitoring and compliance checks.",
			Severity:     finding.SeverityMedium,
			Asset:        asset,
			Scanner:      "cloud/aws",
			ProofCommand: fmt.Sprintf("aws securityhub describe-hub --region %s", region),
			Evidence: map[string]any{
				"account_id":    accountID,
				"region":        region,
				"resource_type": "securityhub",
			},
			DiscoveredAt: time.Now(),
		}}, nil
	}

	return nil, nil
}

// checkAWSConfig verifies that AWS Config is enabled and recording.
func checkAWSConfig(ctx context.Context, cfg awscfg.Config, accountID, region, asset string) ([]finding.Finding, error) {
	svc := configservice.NewFromConfig(cfg)

	resp, err := svc.DescribeConfigurationRecorders(ctx, &configservice.DescribeConfigurationRecordersInput{})
	if err != nil {
		return nil, fmt.Errorf("configservice describe recorders: %w", err)
	}

	if len(resp.ConfigurationRecorders) == 0 {
		return []finding.Finding{{
			CheckID: finding.CheckCloudAWSNoConfig,
			Title:   "AWS Config is not enabled (no configuration recorders)",
			Description: "AWS Config has no configuration recorders. Without Config, changes to " +
				"resource configurations are not tracked, making it impossible to audit " +
				"infrastructure drift, enforce compliance rules, or investigate incidents.",
			Severity:     finding.SeverityMedium,
			Asset:        asset,
			Scanner:      "cloud/aws",
			ProofCommand: fmt.Sprintf("aws configservice describe-configuration-recorders --region %s", region),
			Evidence: map[string]any{
				"account_id":    accountID,
				"region":        region,
				"resource_type": "config",
			},
			DiscoveredAt: time.Now(),
		}}, nil
	}

	// Check if any recorder is actually recording.
	statusResp, err := svc.DescribeConfigurationRecorderStatus(ctx, &configservice.DescribeConfigurationRecorderStatusInput{})
	if err != nil {
		return nil, fmt.Errorf("configservice describe recorder status: %w", err)
	}

	var findings []finding.Finding
	for _, status := range statusResp.ConfigurationRecordersStatus {
		if !status.Recording {
			recorderName := awscfg.ToString(status.Name)
			findings = append(findings, finding.Finding{
				CheckID: finding.CheckCloudAWSNoConfig,
				Title:   fmt.Sprintf("AWS Config recorder is not recording: %s", recorderName),
				Description: fmt.Sprintf(
					"AWS Config recorder %s exists but is not actively recording. "+
						"Configuration changes are not being tracked, leaving gaps in "+
						"compliance monitoring and incident investigation.",
					recorderName,
				),
				Severity:     finding.SeverityMedium,
				Asset:        asset,
				Scanner:      "cloud/aws",
				ProofCommand: fmt.Sprintf("aws configservice describe-configuration-recorder-status --region %s", region),
				Evidence: map[string]any{
					"account_id":    accountID,
					"recorder_name": recorderName,
					"recording":     false,
					"region":        region,
					"resource_type": "config",
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings, nil
}

// checkKMSRotation verifies that customer-managed KMS keys have automatic rotation enabled.
func checkKMSRotation(ctx context.Context, cfg awscfg.Config, accountID, region, asset string) ([]finding.Finding, error) {
	svc := kms.NewFromConfig(cfg)
	var findings []finding.Finding

	paginator := kms.NewListKeysPaginator(svc, &kms.ListKeysInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, key := range page.Keys {
			select {
			case <-ctx.Done():
				return findings, ctx.Err()
			default:
			}

			keyID := awscfg.ToString(key.KeyId)

			// Describe the key to filter out AWS-managed keys.
			descResp, err := svc.DescribeKey(ctx, &kms.DescribeKeyInput{
				KeyId: key.KeyId,
			})
			if err != nil {
				continue
			}
			// Only check customer-managed keys.
			if descResp.KeyMetadata.KeyManager != kmstypes.KeyManagerTypeCustomer {
				continue
			}
			// Skip disabled or pending-deletion keys.
			if descResp.KeyMetadata.KeyState != kmstypes.KeyStateEnabled {
				continue
			}

			rotResp, err := svc.GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{
				KeyId: key.KeyId,
			})
			if err != nil {
				continue
			}

			if !rotResp.KeyRotationEnabled {
				findings = append(findings, finding.Finding{
					CheckID:     finding.CheckCloudAWSKMSNoRotation,
					Title:       fmt.Sprintf("KMS customer-managed key does not have rotation enabled: %s", keyID),
					Description: "KMS customer-managed key does not have automatic annual rotation enabled.",
					Severity:    finding.SeverityMedium,
					Asset:       asset,
					Scanner:     "cloud/aws",
					ProofCommand: fmt.Sprintf(
						"aws kms get-key-rotation-status --key-id %s --region %s", keyID, region,
					),
					Evidence: map[string]any{
						"account_id":    accountID,
						"key_id":        keyID,
						"region":        region,
						"resource_type": "kms_key",
					},
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return findings, nil
}

// checkLambdaNoAuth finds Lambda function URLs configured without authentication.
func checkLambdaNoAuth(ctx context.Context, cfg awscfg.Config, accountID, region, asset string) ([]finding.Finding, error) {
	svc := lambda.NewFromConfig(cfg)
	var findings []finding.Finding

	paginator := lambda.NewListFunctionsPaginator(svc, &lambda.ListFunctionsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, fn := range page.Functions {
			select {
			case <-ctx.Done():
				return findings, ctx.Err()
			default:
			}

			fnName := awscfg.ToString(fn.FunctionName)

			urlResp, err := svc.ListFunctionUrlConfigs(ctx, &lambda.ListFunctionUrlConfigsInput{
				FunctionName: fn.FunctionName,
			})
			if err != nil {
				continue
			}

			for _, urlCfg := range urlResp.FunctionUrlConfigs {
				if urlCfg.AuthType == lambdatypes.FunctionUrlAuthTypeNone {
					findings = append(findings, finding.Finding{
						CheckID: finding.CheckCloudAWSLambdaNoAuth,
						Title:   fmt.Sprintf("Lambda function URL configured without authentication: %s", fnName),
						Description: "Lambda function URL configured without authentication. " +
							"Anyone with the URL can invoke the function.",
						Severity:     finding.SeverityHigh,
						Asset:        asset,
						Scanner:      "cloud/aws",
						ProofCommand: fmt.Sprintf("aws lambda list-function-url-configs --function-name %s --region %s", fnName, region),
						Evidence: map[string]any{
							"account_id":    accountID,
							"function_name": fnName,
							"function_url":  awscfg.ToString(urlCfg.FunctionUrl),
							"auth_type":     string(urlCfg.AuthType),
							"region":        region,
							"resource_type": "lambda_function",
						},
						DiscoveredAt: time.Now(),
					})
				}
			}
		}
	}

	return findings, nil
}

// checkLambdaOverprivileged checks Lambda execution roles for Action:* Resource:* policies.
func checkLambdaOverprivileged(ctx context.Context, cfg awscfg.Config, accountID, region, asset string) ([]finding.Finding, error) {
	lambdaSvc := lambda.NewFromConfig(cfg)
	iamSvc := iam.NewFromConfig(cfg)
	var findings []finding.Finding

	paginator := lambda.NewListFunctionsPaginator(lambdaSvc, &lambda.ListFunctionsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, fn := range page.Functions {
			select {
			case <-ctx.Done():
				return findings, ctx.Err()
			default:
			}

			fnName := awscfg.ToString(fn.FunctionName)
			roleARN := awscfg.ToString(fn.Role)
			if roleARN == "" {
				continue
			}

			// Extract role name from ARN: arn:aws:iam::123456789012:role/RoleName
			roleName := roleARN
			if idx := strings.LastIndex(roleARN, "/"); idx >= 0 {
				roleName = roleARN[idx+1:]
			}

			// List attached managed policies on the role.
			policiesResp, err := iamSvc.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
				RoleName: awscfg.String(roleName),
			})
			if err != nil {
				continue
			}

			for _, attached := range policiesResp.AttachedPolicies {
				policyARN := awscfg.ToString(attached.PolicyArn)

				// Get the default policy version.
				policyResp, err := iamSvc.GetPolicy(ctx, &iam.GetPolicyInput{
					PolicyArn: attached.PolicyArn,
				})
				if err != nil || policyResp.Policy == nil {
					continue
				}

				versionResp, err := iamSvc.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
					PolicyArn: attached.PolicyArn,
					VersionId: policyResp.Policy.DefaultVersionId,
				})
				if err != nil || versionResp.PolicyVersion == nil {
					continue
				}

				rawDoc := awscfg.ToString(versionResp.PolicyVersion.Document)
				doc, _ := url.QueryUnescape(rawDoc)
				if doc == "" {
					doc = rawDoc
				}

				if (strings.Contains(doc, `"Action":"*"`) && strings.Contains(doc, `"Resource":"*"`)) ||
					(strings.Contains(doc, `"Action": "*"`) && strings.Contains(doc, `"Resource": "*"`)) {
					findings = append(findings, finding.Finding{
						CheckID: finding.CheckCloudAWSLambdaOverprivileged,
						Title:   fmt.Sprintf("Lambda function execution role has overly broad permissions: %s", fnName),
						Description: "Lambda function execution role has overly broad permissions " +
							"(Action:* Resource:*), violating least privilege.",
						Severity:     finding.SeverityHigh,
						Asset:        asset,
						Scanner:      "cloud/aws",
						ProofCommand: fmt.Sprintf("aws iam list-attached-role-policies --role-name %s", roleName),
						Evidence: map[string]any{
							"account_id":    accountID,
							"function_name": fnName,
							"role_arn":      roleARN,
							"policy_arn":    policyARN,
							"region":        region,
							"resource_type": "lambda_function",
						},
						DiscoveredAt: time.Now(),
					})
					break // one finding per function is enough
				}
			}
		}
	}

	return findings, nil
}

// checkAPIGatewayNoAuth finds API Gateway methods that have no authorization configured.
func checkAPIGatewayNoAuth(ctx context.Context, cfg awscfg.Config, accountID, region, asset string) ([]finding.Finding, error) {
	svc := apigateway.NewFromConfig(cfg)
	var findings []finding.Finding

	apisResp, err := svc.GetRestApis(ctx, &apigateway.GetRestApisInput{})
	if err != nil {
		return nil, fmt.Errorf("apigateway get rest apis: %w", err)
	}

	for _, api := range apisResp.Items {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		apiID := awscfg.ToString(api.Id)
		apiName := awscfg.ToString(api.Name)

		resourcesResp, err := svc.GetResources(ctx, &apigateway.GetResourcesInput{
			RestApiId: api.Id,
		})
		if err != nil {
			continue
		}

		for _, resource := range resourcesResp.Items {
			resourcePath := awscfg.ToString(resource.Path)

			for httpMethod := range resource.ResourceMethods {
				methodResp, err := svc.GetMethod(ctx, &apigateway.GetMethodInput{
					RestApiId:  api.Id,
					ResourceId: resource.Id,
					HttpMethod: awscfg.String(httpMethod),
				})
				if err != nil {
					continue
				}

				authType := awscfg.ToString(methodResp.AuthorizationType)
				if authType == "NONE" {
					findings = append(findings, finding.Finding{
						CheckID: finding.CheckCloudAWSAPIGatewayNoAuth,
						Title:   fmt.Sprintf("API Gateway method has no authorization: %s %s %s", apiName, httpMethod, resourcePath),
						Description: fmt.Sprintf(
							"API Gateway REST API %s has method %s %s with authorizationType NONE. "+
								"Unauthenticated callers can invoke this endpoint. Add an authorizer "+
								"(IAM, Cognito, Lambda, or API key) to restrict access.",
							apiName, httpMethod, resourcePath,
						),
						Severity:     finding.SeverityHigh,
						Asset:        asset,
						Scanner:      "cloud/aws",
						ProofCommand: fmt.Sprintf("aws apigateway get-method --rest-api-id %s --resource-id %s --http-method %s --region %s", apiID, awscfg.ToString(resource.Id), httpMethod, region),
						Evidence: map[string]any{
							"account_id":    accountID,
							"api_id":        apiID,
							"api_name":      apiName,
							"resource_path": resourcePath,
							"http_method":   httpMethod,
							"auth_type":     authType,
							"region":        region,
							"resource_type": "apigateway_method",
						},
						DiscoveredAt: time.Now(),
					})
				}
			}
		}
	}

	return findings, nil
}

// checkSNSEncryption verifies that SNS topics have KMS encryption configured.
func checkSNSEncryption(ctx context.Context, cfg awscfg.Config, accountID, region, asset string) ([]finding.Finding, error) {
	svc := sns.NewFromConfig(cfg)
	var findings []finding.Finding

	paginator := sns.NewListTopicsPaginator(svc, &sns.ListTopicsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, topic := range page.Topics {
			select {
			case <-ctx.Done():
				return findings, ctx.Err()
			default:
			}

			topicARN := awscfg.ToString(topic.TopicArn)

			attrs, err := svc.GetTopicAttributes(ctx, &sns.GetTopicAttributesInput{
				TopicArn: topic.TopicArn,
			})
			if err != nil {
				continue
			}

			if attrs.Attributes["KmsMasterKeyId"] == "" {
				// Extract topic name from ARN for display.
				topicName := topicARN
				if idx := strings.LastIndex(topicARN, ":"); idx >= 0 {
					topicName = topicARN[idx+1:]
				}

				findings = append(findings, finding.Finding{
					CheckID:     finding.CheckCloudAWSSNSNoEncryption,
					Title:       fmt.Sprintf("SNS topic does not have KMS encryption: %s", topicName),
					Description: "SNS topic is not encrypted with a KMS key. Messages in transit and at rest are not protected by customer-managed encryption.",
					Severity:    finding.SeverityMedium,
					Asset:       asset,
					Scanner:     "cloud/aws",
					ProofCommand: fmt.Sprintf(
						"aws sns get-topic-attributes --topic-arn %s --region %s --query 'Attributes.KmsMasterKeyId'", topicARN, region,
					),
					Evidence: map[string]any{
						"account_id":    accountID,
						"topic_arn":     topicARN,
						"region":        region,
						"resource_type": "sns_topic",
					},
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return findings, nil
}

// checkSQSEncryption verifies that SQS queues have encryption configured.
func checkSQSEncryption(ctx context.Context, cfg awscfg.Config, accountID, region, asset string) ([]finding.Finding, error) {
	svc := sqs.NewFromConfig(cfg)
	var findings []finding.Finding

	resp, err := svc.ListQueues(ctx, &sqs.ListQueuesInput{})
	if err != nil {
		return nil, fmt.Errorf("sqs list queues: %w", err)
	}

	for _, queueURL := range resp.QueueUrls {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		attrs, err := svc.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{
			QueueUrl: awscfg.String(queueURL),
			AttributeNames: []sqsAttrName{
				sqsAttrName("KmsMasterKeyId"),
				sqsAttrName("SqsManagedSseEnabled"),
			},
		})
		if err != nil {
			continue
		}

		kmsKey := attrs.Attributes["KmsMasterKeyId"]
		sqsManaged := attrs.Attributes["SqsManagedSseEnabled"]

		if kmsKey == "" && sqsManaged != "true" {
			// Extract queue name from URL for display.
			queueName := queueURL
			if idx := strings.LastIndex(queueURL, "/"); idx >= 0 {
				queueName = queueURL[idx+1:]
			}

			findings = append(findings, finding.Finding{
				CheckID:     finding.CheckCloudAWSSQSNoEncryption,
				Title:       fmt.Sprintf("SQS queue does not have encryption enabled: %s", queueName),
				Description: "SQS queue is not encrypted. Neither KMS encryption nor SQS-managed SSE is enabled, leaving messages unprotected at rest.",
				Severity:    finding.SeverityMedium,
				Asset:       asset,
				Scanner:     "cloud/aws",
				ProofCommand: fmt.Sprintf(
					"aws sqs get-queue-attributes --queue-url %s --attribute-names KmsMasterKeyId SqsManagedSseEnabled --region %s", queueURL, region,
				),
				Evidence: map[string]any{
					"account_id":    accountID,
					"queue_url":     queueURL,
					"region":        region,
					"resource_type": "sqs_queue",
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings, nil
}

// sqsAttrName is an alias for the SQS QueueAttributeName type.
type sqsAttrName = sqstypes.QueueAttributeName

// checkSecretsRotation verifies that Secrets Manager secrets have rotation enabled.
func checkSecretsRotation(ctx context.Context, cfg awscfg.Config, accountID, region, asset string) ([]finding.Finding, error) {
	svc := secretsmanager.NewFromConfig(cfg)
	var findings []finding.Finding

	paginator := secretsmanager.NewListSecretsPaginator(svc, &secretsmanager.ListSecretsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, secret := range page.SecretList {
			select {
			case <-ctx.Done():
				return findings, ctx.Err()
			default:
			}

			secretName := awscfg.ToString(secret.Name)

			if secret.RotationEnabled == nil || !*secret.RotationEnabled {
				findings = append(findings, finding.Finding{
					CheckID:     finding.CheckCloudAWSSecretsNoRotation,
					Title:       fmt.Sprintf("Secrets Manager secret does not have rotation enabled: %s", secretName),
					Description: "Secrets Manager secret does not have automatic rotation enabled. Long-lived secrets increase the blast radius of a credential leak.",
					Severity:    finding.SeverityMedium,
					Asset:       asset,
					Scanner:     "cloud/aws",
					ProofCommand: fmt.Sprintf(
						"aws secretsmanager describe-secret --secret-id %s --region %s --query '{RotationEnabled:RotationEnabled}'", secretName, region,
					),
					Evidence: map[string]any{
						"account_id":    accountID,
						"secret_name":   secretName,
						"region":        region,
						"resource_type": "secretsmanager_secret",
					},
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return findings, nil
}
