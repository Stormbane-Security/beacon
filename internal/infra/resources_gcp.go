package infra

func init() {
	for _, r := range []*ResourceMeta{
		// ── Compute ──
		{Type: "gcp.compute_instance", Name: "Compute Engine Instance", Provider: GCP, Service: "compute", Category: ResCompute,
			CLIDescribe: "gcloud compute instances describe {id} --zone {zone}", TerraformType: "google_compute_instance"},
		{Type: "gcp.compute_firewall", Name: "Firewall Rule", Provider: GCP, Service: "compute", Category: ResNetwork,
			CLIDescribe: "gcloud compute firewall-rules describe {id}", TerraformType: "google_compute_firewall"},
		{Type: "gcp.compute_network", Name: "VPC Network", Provider: GCP, Service: "compute", Category: ResNetwork,
			CLIDescribe: "gcloud compute networks describe {id}", TerraformType: "google_compute_network"},
		{Type: "gcp.compute_subnetwork", Name: "Subnetwork", Provider: GCP, Service: "compute", Category: ResNetwork,
			CLIDescribe: "gcloud compute networks subnets describe {id} --region {region}", TerraformType: "google_compute_subnetwork"},
		{Type: "gcp.cloud_function", Name: "Cloud Function", Provider: GCP, Service: "cloudfunctions", Category: ResServerless,
			CLIDescribe: "gcloud functions describe {id} --region {region}", TerraformType: "google_cloudfunctions2_function"},
		{Type: "gcp.cloud_run_service", Name: "Cloud Run Service", Provider: GCP, Service: "run", Category: ResServerless,
			CLIDescribe: "gcloud run services describe {id} --region {region}", TerraformType: "google_cloud_run_v2_service"},

		// ── Containers ──
		{Type: "gcp.gke_cluster", Name: "GKE Cluster", Provider: GCP, Service: "container", Category: ResContainer,
			CLIDescribe: "gcloud container clusters describe {id} --zone {zone}", TerraformType: "google_container_cluster"},
		{Type: "gcp.gke_node_pool", Name: "GKE Node Pool", Provider: GCP, Service: "container", Category: ResContainer,
			CLIDescribe: "gcloud container node-pools describe {id} --cluster {cluster} --zone {zone}", TerraformType: "google_container_node_pool"},
		{Type: "gcp.artifact_registry", Name: "Artifact Registry Repository", Provider: GCP, Service: "artifactregistry", Category: ResRegistry,
			CLIDescribe: "gcloud artifacts repositories describe {id} --location {location}", TerraformType: "google_artifact_registry_repository"},

		// ── Storage ──
		{Type: "gcp.storage_bucket", Name: "Cloud Storage Bucket", Provider: GCP, Service: "storage", Category: ResStorage,
			CLIDescribe: "gcloud storage buckets describe gs://{id}", TerraformType: "google_storage_bucket"},

		// ── Databases ──
		{Type: "gcp.cloudsql_instance", Name: "Cloud SQL Instance", Provider: GCP, Service: "sqladmin", Category: ResDatabase,
			CLIDescribe: "gcloud sql instances describe {id}", TerraformType: "google_sql_database_instance"},
		{Type: "gcp.spanner_instance", Name: "Cloud Spanner Instance", Provider: GCP, Service: "spanner", Category: ResDatabase,
			CLIDescribe: "gcloud spanner instances describe {id}", TerraformType: "google_spanner_instance"},
		{Type: "gcp.bigtable_instance", Name: "Bigtable Instance", Provider: GCP, Service: "bigtable", Category: ResDatabase,
			CLIDescribe: "gcloud bigtable instances describe {id}", TerraformType: "google_bigtable_instance"},
		{Type: "gcp.firestore_database", Name: "Firestore Database", Provider: GCP, Service: "firestore", Category: ResDatabase,
			CLIDescribe: "gcloud firestore databases describe --database {id}", TerraformType: "google_firestore_database"},
		{Type: "gcp.memorystore_instance", Name: "Memorystore (Redis) Instance", Provider: GCP, Service: "redis", Category: ResCache,
			CLIDescribe: "gcloud redis instances describe {id} --region {region}", TerraformType: "google_redis_instance"},
		{Type: "gcp.bigquery_dataset", Name: "BigQuery Dataset", Provider: GCP, Service: "bigquery", Category: ResDatabase,
			CLIDescribe: "bq show {id}", TerraformType: "google_bigquery_dataset"},

		// ── Networking ──
		{Type: "gcp.cloud_dns_zone", Name: "Cloud DNS Managed Zone", Provider: GCP, Service: "dns", Category: ResNetwork,
			CLIDescribe: "gcloud dns managed-zones describe {id}", TerraformType: "google_dns_managed_zone"},
		{Type: "gcp.cloud_armor_policy", Name: "Cloud Armor Security Policy", Provider: GCP, Service: "compute", Category: ResSecurity,
			CLIDescribe: "gcloud compute security-policies describe {id}", TerraformType: "google_compute_security_policy"},
		{Type: "gcp.cloud_cdn", Name: "Cloud CDN Backend Service", Provider: GCP, Service: "compute", Category: ResCDN,
			CLIDescribe: "gcloud compute backend-services describe {id}", TerraformType: "google_compute_backend_service"},
		{Type: "gcp.load_balancer", Name: "HTTP(S) Load Balancer", Provider: GCP, Service: "compute", Category: ResNetwork,
			CLIDescribe: "gcloud compute url-maps describe {id}", TerraformType: "google_compute_url_map"},

		// ── Security & Identity ──
		{Type: "gcp.iam_service_account", Name: "IAM Service Account", Provider: GCP, Service: "iam", Category: ResIdentity,
			CLIDescribe: "gcloud iam service-accounts describe {id}", TerraformType: "google_service_account"},
		{Type: "gcp.iam_policy_binding", Name: "IAM Policy Binding", Provider: GCP, Service: "iam", Category: ResIdentity,
			TerraformType: "google_project_iam_binding"},
		{Type: "gcp.secret", Name: "Secret Manager Secret", Provider: GCP, Service: "secretmanager", Category: ResSecurity,
			CLIDescribe: "gcloud secrets describe {id}", TerraformType: "google_secret_manager_secret"},
		{Type: "gcp.kms_key", Name: "Cloud KMS Key", Provider: GCP, Service: "cloudkms", Category: ResSecurity,
			CLIDescribe: "gcloud kms keys describe {id} --keyring {keyring} --location {location}", TerraformType: "google_kms_crypto_key"},

		// ── Messaging ──
		{Type: "gcp.pubsub_topic", Name: "Pub/Sub Topic", Provider: GCP, Service: "pubsub", Category: ResMessaging,
			CLIDescribe: "gcloud pubsub topics describe {id}", TerraformType: "google_pubsub_topic"},
		{Type: "gcp.pubsub_subscription", Name: "Pub/Sub Subscription", Provider: GCP, Service: "pubsub", Category: ResMessaging,
			CLIDescribe: "gcloud pubsub subscriptions describe {id}", TerraformType: "google_pubsub_subscription"},

		// ── Monitoring ──
		{Type: "gcp.log_sink", Name: "Cloud Logging Sink", Provider: GCP, Service: "logging", Category: ResMonitoring,
			CLIDescribe: "gcloud logging sinks describe {id}", TerraformType: "google_logging_project_sink"},
		{Type: "gcp.alert_policy", Name: "Cloud Monitoring Alert Policy", Provider: GCP, Service: "monitoring", Category: ResMonitoring,
			CLIDescribe: "gcloud alpha monitoring policies describe {id}", TerraformType: "google_monitoring_alert_policy"},
	} {
		RegisterResource(r)
	}
}
