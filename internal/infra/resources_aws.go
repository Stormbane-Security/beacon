package infra

func init() {
	for _, r := range []*ResourceMeta{
		// ── Compute ──
		{Type: "aws.ec2_instance", Name: "EC2 Instance", Provider: AWS, Service: "ec2", Category: ResCompute,
			CLIDescribe: "aws ec2 describe-instances --instance-ids {id}", TerraformType: "aws_instance",
			ARNPattern: "arn:aws:ec2:{region}:{account}:instance/{id}"},
		{Type: "aws.ec2_security_group", Name: "EC2 Security Group", Provider: AWS, Service: "ec2", Category: ResNetwork,
			CLIDescribe: "aws ec2 describe-security-groups --group-ids {id}", TerraformType: "aws_security_group",
			ARNPattern: "arn:aws:ec2:{region}:{account}:security-group/{id}"},
		{Type: "aws.ec2_volume", Name: "EBS Volume", Provider: AWS, Service: "ec2", Category: ResStorage,
			CLIDescribe: "aws ec2 describe-volumes --volume-ids {id}", TerraformType: "aws_ebs_volume",
			ARNPattern: "arn:aws:ec2:{region}:{account}:volume/{id}"},
		{Type: "aws.ec2_ami", Name: "EC2 AMI", Provider: AWS, Service: "ec2", Category: ResCompute,
			CLIDescribe: "aws ec2 describe-images --image-ids {id}", TerraformType: "aws_ami"},
		{Type: "aws.lambda_function", Name: "Lambda Function", Provider: AWS, Service: "lambda", Category: ResServerless,
			CLIDescribe: "aws lambda get-function --function-name {id}", TerraformType: "aws_lambda_function",
			ARNPattern: "arn:aws:lambda:{region}:{account}:function:{id}"},

		// ── Containers ──
		{Type: "aws.eks_cluster", Name: "EKS Cluster", Provider: AWS, Service: "eks", Category: ResContainer,
			CLIDescribe: "aws eks describe-cluster --name {id}", TerraformType: "aws_eks_cluster",
			ARNPattern: "arn:aws:eks:{region}:{account}:cluster/{id}"},
		{Type: "aws.ecs_cluster", Name: "ECS Cluster", Provider: AWS, Service: "ecs", Category: ResContainer,
			CLIDescribe: "aws ecs describe-clusters --clusters {id}", TerraformType: "aws_ecs_cluster",
			ARNPattern: "arn:aws:ecs:{region}:{account}:cluster/{id}"},
		{Type: "aws.ecs_service", Name: "ECS Service", Provider: AWS, Service: "ecs", Category: ResContainer,
			CLIDescribe: "aws ecs describe-services --cluster {cluster} --services {id}", TerraformType: "aws_ecs_service"},
		{Type: "aws.ecr_repository", Name: "ECR Repository", Provider: AWS, Service: "ecr", Category: ResRegistry,
			CLIDescribe: "aws ecr describe-repositories --repository-names {id}", TerraformType: "aws_ecr_repository",
			ARNPattern: "arn:aws:ecr:{region}:{account}:repository/{id}"},

		// ── Storage ──
		{Type: "aws.s3_bucket", Name: "S3 Bucket", Provider: AWS, Service: "s3", Category: ResStorage,
			CLIDescribe: "aws s3api get-bucket-acl --bucket {id}", TerraformType: "aws_s3_bucket",
			ARNPattern: "arn:aws:s3:::{id}"},

		// ── Databases ──
		{Type: "aws.rds_instance", Name: "RDS Instance", Provider: AWS, Service: "rds", Category: ResDatabase,
			CLIDescribe: "aws rds describe-db-instances --db-instance-identifier {id}", TerraformType: "aws_db_instance",
			ARNPattern: "arn:aws:rds:{region}:{account}:db:{id}"},
		{Type: "aws.rds_cluster", Name: "RDS Aurora Cluster", Provider: AWS, Service: "rds", Category: ResDatabase,
			CLIDescribe: "aws rds describe-db-clusters --db-cluster-identifier {id}", TerraformType: "aws_rds_cluster",
			ARNPattern: "arn:aws:rds:{region}:{account}:cluster:{id}"},
		{Type: "aws.dynamodb_table", Name: "DynamoDB Table", Provider: AWS, Service: "dynamodb", Category: ResDatabase,
			CLIDescribe: "aws dynamodb describe-table --table-name {id}", TerraformType: "aws_dynamodb_table",
			ARNPattern: "arn:aws:dynamodb:{region}:{account}:table/{id}"},
		{Type: "aws.elasticache_cluster", Name: "ElastiCache Cluster", Provider: AWS, Service: "elasticache", Category: ResCache,
			CLIDescribe: "aws elasticache describe-cache-clusters --cache-cluster-id {id}", TerraformType: "aws_elasticache_cluster",
			ARNPattern: "arn:aws:elasticache:{region}:{account}:cluster:{id}"},
		{Type: "aws.redshift_cluster", Name: "Redshift Cluster", Provider: AWS, Service: "redshift", Category: ResDatabase,
			CLIDescribe: "aws redshift describe-clusters --cluster-identifier {id}", TerraformType: "aws_redshift_cluster",
			ARNPattern: "arn:aws:redshift:{region}:{account}:cluster:{id}"},
		{Type: "aws.documentdb_cluster", Name: "DocumentDB Cluster", Provider: AWS, Service: "docdb", Category: ResDatabase,
			CLIDescribe: "aws docdb describe-db-clusters --db-cluster-identifier {id}", TerraformType: "aws_docdb_cluster",
			ARNPattern: "arn:aws:rds:{region}:{account}:cluster:{id}"},
		{Type: "aws.opensearch_domain", Name: "OpenSearch Domain", Provider: AWS, Service: "opensearch", Category: ResSearch,
			CLIDescribe: "aws opensearch describe-domain --domain-name {id}", TerraformType: "aws_opensearch_domain",
			ARNPattern: "arn:aws:es:{region}:{account}:domain/{id}"},

		// ── Networking ──
		{Type: "aws.vpc", Name: "VPC", Provider: AWS, Service: "ec2", Category: ResNetwork,
			CLIDescribe: "aws ec2 describe-vpcs --vpc-ids {id}", TerraformType: "aws_vpc",
			ARNPattern: "arn:aws:ec2:{region}:{account}:vpc/{id}"},
		{Type: "aws.subnet", Name: "Subnet", Provider: AWS, Service: "ec2", Category: ResNetwork,
			CLIDescribe: "aws ec2 describe-subnets --subnet-ids {id}", TerraformType: "aws_subnet"},
		{Type: "aws.alb", Name: "Application Load Balancer", Provider: AWS, Service: "elbv2", Category: ResNetwork,
			CLIDescribe: "aws elbv2 describe-load-balancers --load-balancer-arns {id}", TerraformType: "aws_lb"},
		{Type: "aws.cloudfront_distribution", Name: "CloudFront Distribution", Provider: AWS, Service: "cloudfront", Category: ResCDN,
			CLIDescribe: "aws cloudfront get-distribution --id {id}", TerraformType: "aws_cloudfront_distribution",
			ARNPattern: "arn:aws:cloudfront::{account}:distribution/{id}"},
		{Type: "aws.route53_zone", Name: "Route 53 Hosted Zone", Provider: AWS, Service: "route53", Category: ResNetwork,
			CLIDescribe: "aws route53 get-hosted-zone --id {id}", TerraformType: "aws_route53_zone"},
		{Type: "aws.api_gateway", Name: "API Gateway REST API", Provider: AWS, Service: "apigateway", Category: ResNetwork,
			CLIDescribe: "aws apigateway get-rest-api --rest-api-id {id}", TerraformType: "aws_api_gateway_rest_api"},

		// ── Security & Identity ──
		{Type: "aws.iam_role", Name: "IAM Role", Provider: AWS, Service: "iam", Category: ResIdentity,
			CLIDescribe: "aws iam get-role --role-name {id}", TerraformType: "aws_iam_role",
			ARNPattern: "arn:aws:iam::{account}:role/{id}"},
		{Type: "aws.iam_user", Name: "IAM User", Provider: AWS, Service: "iam", Category: ResIdentity,
			CLIDescribe: "aws iam get-user --user-name {id}", TerraformType: "aws_iam_user",
			ARNPattern: "arn:aws:iam::{account}:user/{id}"},
		{Type: "aws.iam_policy", Name: "IAM Policy", Provider: AWS, Service: "iam", Category: ResIdentity,
			CLIDescribe: "aws iam get-policy --policy-arn {id}", TerraformType: "aws_iam_policy"},
		{Type: "aws.kms_key", Name: "KMS Key", Provider: AWS, Service: "kms", Category: ResSecurity,
			CLIDescribe: "aws kms describe-key --key-id {id}", TerraformType: "aws_kms_key",
			ARNPattern: "arn:aws:kms:{region}:{account}:key/{id}"},
		{Type: "aws.secrets_manager_secret", Name: "Secrets Manager Secret", Provider: AWS, Service: "secretsmanager", Category: ResSecurity,
			CLIDescribe: "aws secretsmanager describe-secret --secret-id {id}", TerraformType: "aws_secretsmanager_secret",
			ARNPattern: "arn:aws:secretsmanager:{region}:{account}:secret:{id}"},
		{Type: "aws.cognito_user_pool", Name: "Cognito User Pool", Provider: AWS, Service: "cognito-idp", Category: ResIdentity,
			CLIDescribe: "aws cognito-idp describe-user-pool --user-pool-id {id}", TerraformType: "aws_cognito_user_pool",
			ARNPattern: "arn:aws:cognito-idp:{region}:{account}:userpool/{id}"},
		{Type: "aws.wafv2_web_acl", Name: "WAFv2 Web ACL", Provider: AWS, Service: "wafv2", Category: ResSecurity,
			CLIDescribe: "aws wafv2 get-web-acl --name {name} --scope {scope} --id {id}", TerraformType: "aws_wafv2_web_acl"},

		// ── Messaging ──
		{Type: "aws.sqs_queue", Name: "SQS Queue", Provider: AWS, Service: "sqs", Category: ResMessaging,
			CLIDescribe: "aws sqs get-queue-attributes --queue-url {id} --attribute-names All", TerraformType: "aws_sqs_queue",
			ARNPattern: "arn:aws:sqs:{region}:{account}:{id}"},
		{Type: "aws.sns_topic", Name: "SNS Topic", Provider: AWS, Service: "sns", Category: ResMessaging,
			CLIDescribe: "aws sns get-topic-attributes --topic-arn {id}", TerraformType: "aws_sns_topic"},
		{Type: "aws.kinesis_stream", Name: "Kinesis Stream", Provider: AWS, Service: "kinesis", Category: ResMessaging,
			CLIDescribe: "aws kinesis describe-stream --stream-name {id}", TerraformType: "aws_kinesis_stream",
			ARNPattern: "arn:aws:kinesis:{region}:{account}:stream/{id}"},

		// ── Monitoring ──
		{Type: "aws.cloudwatch_log_group", Name: "CloudWatch Log Group", Provider: AWS, Service: "logs", Category: ResMonitoring,
			CLIDescribe: "aws logs describe-log-groups --log-group-name-prefix {id}", TerraformType: "aws_cloudwatch_log_group",
			ARNPattern: "arn:aws:logs:{region}:{account}:log-group:{id}"},
		{Type: "aws.cloudtrail_trail", Name: "CloudTrail Trail", Provider: AWS, Service: "cloudtrail", Category: ResMonitoring,
			CLIDescribe: "aws cloudtrail get-trail --name {id}", TerraformType: "aws_cloudtrail"},
	} {
		RegisterResource(r)
	}
}
