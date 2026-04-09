module github.com/stormbane-security/beacon

go 1.26.2

require (
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.20.0
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.13.1
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice v1.0.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization v1.0.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute v1.0.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerregistry/armcontainerregistry v1.2.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice v1.0.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cosmos/armcosmos v1.0.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault v1.5.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor v0.11.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork v1.1.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/postgresql/armpostgresqlflexibleservers v1.1.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/redis/armredis v1.0.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/security/armsecurity v0.14.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql v1.2.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage v1.8.1
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/subscription/armsubscription v1.2.0
	github.com/aws/aws-sdk-go-v2 v1.41.5
	github.com/aws/aws-sdk-go-v2/config v1.32.13
	github.com/aws/aws-sdk-go-v2/service/apigateway v1.39.1
	github.com/aws/aws-sdk-go-v2/service/cloudfront v1.60.4
	github.com/aws/aws-sdk-go-v2/service/cloudtrail v1.55.9
	github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs v1.66.0
	github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider v1.59.3
	github.com/aws/aws-sdk-go-v2/service/configservice v1.62.1
	github.com/aws/aws-sdk-go-v2/service/docdb v1.48.13
	github.com/aws/aws-sdk-go-v2/service/dynamodb v1.57.1
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.296.1
	github.com/aws/aws-sdk-go-v2/service/ecr v1.56.2
	github.com/aws/aws-sdk-go-v2/service/ecs v1.75.0
	github.com/aws/aws-sdk-go-v2/service/eks v1.81.2
	github.com/aws/aws-sdk-go-v2/service/elasticache v1.51.13
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2 v1.54.10
	github.com/aws/aws-sdk-go-v2/service/guardduty v1.74.2
	github.com/aws/aws-sdk-go-v2/service/iam v1.53.7
	github.com/aws/aws-sdk-go-v2/service/kinesis v1.43.5
	github.com/aws/aws-sdk-go-v2/service/kms v1.50.4
	github.com/aws/aws-sdk-go-v2/service/lambda v1.88.5
	github.com/aws/aws-sdk-go-v2/service/opensearch v1.62.0
	github.com/aws/aws-sdk-go-v2/service/rds v1.117.1
	github.com/aws/aws-sdk-go-v2/service/redshift v1.62.5
	github.com/aws/aws-sdk-go-v2/service/route53 v1.62.5
	github.com/aws/aws-sdk-go-v2/service/s3 v1.97.3
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.41.5
	github.com/aws/aws-sdk-go-v2/service/securityhub v1.68.3
	github.com/aws/aws-sdk-go-v2/service/sesv2 v1.60.2
	github.com/aws/aws-sdk-go-v2/service/sns v1.39.15
	github.com/aws/aws-sdk-go-v2/service/sqs v1.42.25
	github.com/aws/aws-sdk-go-v2/service/ssm v1.68.4
	github.com/aws/aws-sdk-go-v2/service/sts v1.41.10
	github.com/aws/aws-sdk-go-v2/service/wafv2 v1.71.3
	github.com/chromedp/cdproto v0.0.0-20260321001828-e3e3800016bc
	github.com/chromedp/chromedp v0.15.1
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1
	github.com/google/uuid v1.6.0
	github.com/stormbane-security/infra v0.2.0
	golang.org/x/crypto v0.49.0
	golang.org/x/net v0.52.0
	golang.org/x/term v0.41.0
	google.golang.org/api v0.273.0
	google.golang.org/grpc v1.79.3
	gopkg.in/yaml.v3 v3.0.1
	modernc.org/sqlite v1.47.0
)

require (
	cloud.google.com/go/auth v0.18.2 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.8 // indirect
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.11.2 // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v1.6.0 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.8 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.19.13 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.21 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.21 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.21 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.6 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.22 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.9.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery v1.11.21 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.21 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.19.21 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.0.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.30.14 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.35.18 // indirect
	github.com/aws/smithy-go v1.24.2 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/chromedp/sysutil v1.1.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-json-experiment/json v0.0.0-20260214004413-d219187c3433 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/gobwas/httphead v0.1.0 // indirect
	github.com/gobwas/pool v0.2.1 // indirect
	github.com/gobwas/ws v1.4.0 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.0 // indirect
	github.com/google/s2a-go v0.1.9 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.14 // indirect
	github.com/googleapis/gax-go/v2 v2.19.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.61.0 // indirect
	go.opentelemetry.io/otel v1.42.0 // indirect
	go.opentelemetry.io/otel/metric v1.42.0 // indirect
	go.opentelemetry.io/otel/trace v1.42.0 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/text v0.35.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260319201613-d00831a3d3e7 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	modernc.org/libc v1.70.0 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)
