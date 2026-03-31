package infra

// Cloud providers and their managed services.

// Cloud provider IDs.
const (
	AWS          Technology = "aws"
	GCP          Technology = "gcp"
	Azure        Technology = "azure"
	Cloudflare   Technology = "cloudflare"
	Vercel       Technology = "vercel"
	Netlify      Technology = "netlify"
	Heroku       Technology = "heroku"
	DigitalOcean Technology = "digitalocean"
	Linode       Technology = "linode"
	Hetzner      Technology = "hetzner"
	OCI          Technology = "oci" // Oracle Cloud
	Fly          Technology = "fly"
	Railway      Technology = "railway"
	Render       Technology = "render"
)

func init() {
	// ── Cloud Providers ──
	for _, m := range []*TechMeta{
		{ID: AWS, Name: "Amazon Web Services", Category: CategoryCloud, Vendor: "Amazon"},
		{ID: GCP, Name: "Google Cloud Platform", Category: CategoryCloud, Vendor: "Google"},
		{ID: Azure, Name: "Microsoft Azure", Category: CategoryCloud, Vendor: "Microsoft"},
		{ID: Cloudflare, Name: "Cloudflare", Category: CategoryCloud, Vendor: "Cloudflare"},
		{ID: Vercel, Name: "Vercel", Category: CategoryCloud, Vendor: "Vercel"},
		{ID: Netlify, Name: "Netlify", Category: CategoryCloud, Vendor: "Netlify"},
		{ID: Heroku, Name: "Heroku", Category: CategoryCloud, Vendor: "Salesforce", Aliases: []string{"herokuish"}},
		{ID: DigitalOcean, Name: "DigitalOcean", Category: CategoryCloud, Vendor: "DigitalOcean", Aliases: []string{"do"}},
		{ID: Fly, Name: "Fly.io", Category: CategoryCloud, Vendor: "Fly.io"},
		{ID: Railway, Name: "Railway", Category: CategoryCloud, Vendor: "Railway"},
		{ID: Render, Name: "Render", Category: CategoryCloud, Vendor: "Render"},
	} {
		Register(m)
	}

	// ── AWS Managed Services ──
	for _, m := range []*TechMeta{
		{ID: "aws-ec2", Name: "Amazon EC2", Category: CategoryPlatform, CloudProvider: AWS, Vendor: "Amazon", DefaultPorts: []int{22, 80, 443}},
		{ID: "aws-ecs", Name: "Amazon ECS", Category: CategoryContainer, CloudProvider: AWS, Vendor: "Amazon"},
		{ID: "aws-eks", Name: "Amazon EKS", Category: CategoryContainer, CloudProvider: AWS, Vendor: "Amazon", Aliases: []string{"eks"}},
		{ID: "aws-lambda", Name: "AWS Lambda", Category: CategoryPlatform, CloudProvider: AWS, Vendor: "Amazon", Tags: []string{"serverless"}},
		{ID: "aws-fargate", Name: "AWS Fargate", Category: CategoryContainer, CloudProvider: AWS, Vendor: "Amazon", Tags: []string{"serverless"}},
		{ID: "aws-s3", Name: "Amazon S3", Category: CategoryCloud, CloudProvider: AWS, Vendor: "Amazon"},
		{ID: "aws-rds", Name: "Amazon RDS", Category: CategoryDatabase, CloudProvider: AWS, Vendor: "Amazon"},
		{ID: "aws-dynamodb", Name: "Amazon DynamoDB", Category: CategoryDatabase, CloudProvider: AWS, Vendor: "Amazon", Tags: []string{"nosql", "serverless"}},
		{ID: "aws-elasticache", Name: "Amazon ElastiCache", Category: CategoryDatabase, CloudProvider: AWS, Vendor: "Amazon", Tags: []string{"cache"}},
		{ID: "aws-redshift", Name: "Amazon Redshift", Category: CategoryDatabase, CloudProvider: AWS, Vendor: "Amazon", Tags: []string{"warehouse"}},
		{ID: "aws-opensearch", Name: "Amazon OpenSearch", Category: CategoryDatabase, CloudProvider: AWS, Vendor: "Amazon", Tags: []string{"search"}},
		{ID: "aws-documentdb", Name: "Amazon DocumentDB", Category: CategoryDatabase, CloudProvider: AWS, Vendor: "Amazon", Tags: []string{"nosql"}},
		{ID: "aws-cloudfront", Name: "Amazon CloudFront", Category: CategoryCDN, CloudProvider: AWS, Vendor: "Amazon"},
		{ID: "aws-alb", Name: "AWS Application Load Balancer", Category: CategoryServer, CloudProvider: AWS, Vendor: "Amazon", Layer: LayerLoadBalancer, Aliases: []string{"aws-elb"}},
		{ID: "aws-api-gateway", Name: "Amazon API Gateway", Category: CategoryGateway, CloudProvider: AWS, Vendor: "Amazon"},
		{ID: "aws-route53", Name: "Amazon Route 53", Category: CategoryCloud, CloudProvider: AWS, Vendor: "Amazon"},
		{ID: "aws-cognito", Name: "Amazon Cognito", Category: CategoryAuth, CloudProvider: AWS, Vendor: "Amazon"},
		{ID: "aws-waf", Name: "AWS WAF", Category: CategorySecurity, CloudProvider: AWS, Vendor: "Amazon"},
		{ID: "aws-guardduty", Name: "Amazon GuardDuty", Category: CategorySecurity, CloudProvider: AWS, Vendor: "Amazon"},
		{ID: "aws-sqs", Name: "Amazon SQS", Category: CategoryMessaging, CloudProvider: AWS, Vendor: "Amazon", Tags: []string{"queue"}},
		{ID: "aws-sns", Name: "Amazon SNS", Category: CategoryMessaging, CloudProvider: AWS, Vendor: "Amazon", Tags: []string{"pubsub"}},
		{ID: "aws-kinesis", Name: "Amazon Kinesis", Category: CategoryMessaging, CloudProvider: AWS, Vendor: "Amazon", Tags: []string{"streaming"}},
		{ID: "aws-ses", Name: "Amazon SES", Category: CategoryCloud, CloudProvider: AWS, Vendor: "Amazon", Tags: []string{"email"}},
		{ID: "aws-ecr", Name: "Amazon ECR", Category: CategoryContainer, CloudProvider: AWS, Vendor: "Amazon", Tags: []string{"registry"}},
		{ID: "aws-cloudwatch", Name: "Amazon CloudWatch", Category: CategoryMonitoring, CloudProvider: AWS, Vendor: "Amazon"},
		{ID: "aws-cloudtrail", Name: "AWS CloudTrail", Category: CategoryMonitoring, CloudProvider: AWS, Vendor: "Amazon"},
	} {
		Register(m)
	}

	// ── GCP Managed Services ──
	for _, m := range []*TechMeta{
		{ID: "gcp-compute", Name: "Compute Engine", Category: CategoryPlatform, CloudProvider: GCP, Vendor: "Google", Aliases: []string{"gce"}},
		{ID: "gcp-gke", Name: "Google Kubernetes Engine", Category: CategoryContainer, CloudProvider: GCP, Vendor: "Google", Aliases: []string{"gke"}},
		{ID: "gcp-cloud-run", Name: "Cloud Run", Category: CategoryPlatform, CloudProvider: GCP, Vendor: "Google", Tags: []string{"serverless"}, Aliases: []string{"cloud-run"}},
		{ID: "gcp-cloud-functions", Name: "Cloud Functions", Category: CategoryPlatform, CloudProvider: GCP, Vendor: "Google", Tags: []string{"serverless"}},
		{ID: "gcp-cloud-sql", Name: "Cloud SQL", Category: CategoryDatabase, CloudProvider: GCP, Vendor: "Google"},
		{ID: "gcp-spanner", Name: "Cloud Spanner", Category: CategoryDatabase, CloudProvider: GCP, Vendor: "Google"},
		{ID: "gcp-bigtable", Name: "Cloud Bigtable", Category: CategoryDatabase, CloudProvider: GCP, Vendor: "Google", Tags: []string{"nosql"}},
		{ID: "gcp-firestore", Name: "Cloud Firestore", Category: CategoryDatabase, CloudProvider: GCP, Vendor: "Google", Tags: []string{"nosql"}},
		{ID: "gcp-bigquery", Name: "BigQuery", Category: CategoryDatabase, CloudProvider: GCP, Vendor: "Google", Tags: []string{"warehouse"}},
		{ID: "gcp-memorystore", Name: "Memorystore", Category: CategoryDatabase, CloudProvider: GCP, Vendor: "Google", Tags: []string{"cache"}},
		{ID: "gcp-gcs", Name: "Cloud Storage", Category: CategoryCloud, CloudProvider: GCP, Vendor: "Google"},
		{ID: "gcp-pubsub", Name: "Cloud Pub/Sub", Category: CategoryMessaging, CloudProvider: GCP, Vendor: "Google", Tags: []string{"pubsub"}},
		{ID: "gcp-cloud-cdn", Name: "Cloud CDN", Category: CategoryCDN, CloudProvider: GCP, Vendor: "Google"},
		{ID: "gcp-cloud-armor", Name: "Cloud Armor", Category: CategorySecurity, CloudProvider: GCP, Vendor: "Google", Tags: []string{"waf"}},
		{ID: "gcp-cloud-dns", Name: "Cloud DNS", Category: CategoryCloud, CloudProvider: GCP, Vendor: "Google"},
		{ID: "gcp-artifact-registry", Name: "Artifact Registry", Category: CategoryContainer, CloudProvider: GCP, Vendor: "Google", Tags: []string{"registry"}},
		{ID: "gcp-secret-manager", Name: "Secret Manager", Category: CategorySecurity, CloudProvider: GCP, Vendor: "Google"},
		{ID: "gcp-cloud-logging", Name: "Cloud Logging", Category: CategoryMonitoring, CloudProvider: GCP, Vendor: "Google"},
	} {
		Register(m)
	}

	// ── Azure Managed Services ──
	for _, m := range []*TechMeta{
		{ID: "azure-vm", Name: "Azure Virtual Machines", Category: CategoryPlatform, CloudProvider: Azure, Vendor: "Microsoft"},
		{ID: "azure-aks", Name: "Azure Kubernetes Service", Category: CategoryContainer, CloudProvider: Azure, Vendor: "Microsoft", Aliases: []string{"aks"}},
		{ID: "azure-app-service", Name: "Azure App Service", Category: CategoryPlatform, CloudProvider: Azure, Vendor: "Microsoft"},
		{ID: "azure-functions", Name: "Azure Functions", Category: CategoryPlatform, CloudProvider: Azure, Vendor: "Microsoft", Tags: []string{"serverless"}},
		{ID: "azure-sql", Name: "Azure SQL Database", Category: CategoryDatabase, CloudProvider: Azure, Vendor: "Microsoft"},
		{ID: "azure-cosmos-db", Name: "Azure Cosmos DB", Category: CategoryDatabase, CloudProvider: Azure, Vendor: "Microsoft", Tags: []string{"nosql"}},
		{ID: "azure-postgres", Name: "Azure Database for PostgreSQL", Category: CategoryDatabase, CloudProvider: Azure, Vendor: "Microsoft"},
		{ID: "azure-redis", Name: "Azure Cache for Redis", Category: CategoryDatabase, CloudProvider: Azure, Vendor: "Microsoft", Tags: []string{"cache"}},
		{ID: "azure-blob", Name: "Azure Blob Storage", Category: CategoryCloud, CloudProvider: Azure, Vendor: "Microsoft"},
		{ID: "azure-acr", Name: "Azure Container Registry", Category: CategoryContainer, CloudProvider: Azure, Vendor: "Microsoft", Tags: []string{"registry"}},
		{ID: "azure-cdn", Name: "Azure CDN", Category: CategoryCDN, CloudProvider: Azure, Vendor: "Microsoft"},
		{ID: "azure-front-door", Name: "Azure Front Door", Category: CategoryCDN, CloudProvider: Azure, Vendor: "Microsoft", Tags: []string{"waf"}},
		{ID: "azure-service-bus", Name: "Azure Service Bus", Category: CategoryMessaging, CloudProvider: Azure, Vendor: "Microsoft", Tags: []string{"queue"}},
		{ID: "azure-event-hubs", Name: "Azure Event Hubs", Category: CategoryMessaging, CloudProvider: Azure, Vendor: "Microsoft", Tags: []string{"streaming"}},
		{ID: "azure-key-vault", Name: "Azure Key Vault", Category: CategorySecurity, CloudProvider: Azure, Vendor: "Microsoft"},
		{ID: "azure-monitor", Name: "Azure Monitor", Category: CategoryMonitoring, CloudProvider: Azure, Vendor: "Microsoft"},
	} {
		Register(m)
	}
}
