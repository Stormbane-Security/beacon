package infra

func init() {
	for _, r := range []*ResourceMeta{
		// ── Compute ──
		{Type: "azure.virtual_machine", Name: "Virtual Machine", Provider: Azure, Service: "compute", Category: ResCompute,
			CLIDescribe: "az vm show --ids {id}", TerraformType: "azurerm_linux_virtual_machine"},
		{Type: "azure.vmss", Name: "VM Scale Set", Provider: Azure, Service: "compute", Category: ResCompute,
			CLIDescribe: "az vmss show --ids {id}", TerraformType: "azurerm_linux_virtual_machine_scale_set"},
		{Type: "azure.app_service", Name: "App Service", Provider: Azure, Service: "web", Category: ResCompute,
			CLIDescribe: "az webapp show --ids {id}", TerraformType: "azurerm_linux_web_app"},
		{Type: "azure.function_app", Name: "Function App", Provider: Azure, Service: "web", Category: ResServerless,
			CLIDescribe: "az functionapp show --ids {id}", TerraformType: "azurerm_linux_function_app"},

		// ── Containers ──
		{Type: "azure.aks_cluster", Name: "AKS Cluster", Provider: Azure, Service: "containerservice", Category: ResContainer,
			CLIDescribe: "az aks show --ids {id}", TerraformType: "azurerm_kubernetes_cluster"},
		{Type: "azure.acr", Name: "Container Registry", Provider: Azure, Service: "containerregistry", Category: ResRegistry,
			CLIDescribe: "az acr show --ids {id}", TerraformType: "azurerm_container_registry"},
		{Type: "azure.container_instance", Name: "Container Instance", Provider: Azure, Service: "containerinstance", Category: ResContainer,
			CLIDescribe: "az container show --ids {id}", TerraformType: "azurerm_container_group"},

		// ── Storage ──
		{Type: "azure.storage_account", Name: "Storage Account", Provider: Azure, Service: "storage", Category: ResStorage,
			CLIDescribe: "az storage account show --ids {id}", TerraformType: "azurerm_storage_account"},
		{Type: "azure.blob_container", Name: "Blob Container", Provider: Azure, Service: "storage", Category: ResStorage,
			TerraformType: "azurerm_storage_container"},

		// ── Databases ──
		{Type: "azure.sql_server", Name: "SQL Server", Provider: Azure, Service: "sql", Category: ResDatabase,
			CLIDescribe: "az sql server show --ids {id}", TerraformType: "azurerm_mssql_server"},
		{Type: "azure.sql_database", Name: "SQL Database", Provider: Azure, Service: "sql", Category: ResDatabase,
			CLIDescribe: "az sql db show --ids {id}", TerraformType: "azurerm_mssql_database"},
		{Type: "azure.cosmos_account", Name: "Cosmos DB Account", Provider: Azure, Service: "documentdb", Category: ResDatabase,
			CLIDescribe: "az cosmosdb show --ids {id}", TerraformType: "azurerm_cosmosdb_account"},
		{Type: "azure.postgres_flexible", Name: "PostgreSQL Flexible Server", Provider: Azure, Service: "dbforpostgresql", Category: ResDatabase,
			CLIDescribe: "az postgres flexible-server show --ids {id}", TerraformType: "azurerm_postgresql_flexible_server"},
		{Type: "azure.redis_cache", Name: "Redis Cache", Provider: Azure, Service: "cache", Category: ResCache,
			CLIDescribe: "az redis show --ids {id}", TerraformType: "azurerm_redis_cache"},

		// ── Networking ──
		{Type: "azure.vnet", Name: "Virtual Network", Provider: Azure, Service: "network", Category: ResNetwork,
			CLIDescribe: "az network vnet show --ids {id}", TerraformType: "azurerm_virtual_network"},
		{Type: "azure.nsg", Name: "Network Security Group", Provider: Azure, Service: "network", Category: ResNetwork,
			CLIDescribe: "az network nsg show --ids {id}", TerraformType: "azurerm_network_security_group"},
		{Type: "azure.public_ip", Name: "Public IP Address", Provider: Azure, Service: "network", Category: ResNetwork,
			CLIDescribe: "az network public-ip show --ids {id}", TerraformType: "azurerm_public_ip"},
		{Type: "azure.load_balancer", Name: "Load Balancer", Provider: Azure, Service: "network", Category: ResNetwork,
			CLIDescribe: "az network lb show --ids {id}", TerraformType: "azurerm_lb"},
		{Type: "azure.front_door", Name: "Front Door", Provider: Azure, Service: "cdn", Category: ResCDN,
			CLIDescribe: "az afd profile show --ids {id}", TerraformType: "azurerm_cdn_frontdoor_profile"},
		{Type: "azure.dns_zone", Name: "DNS Zone", Provider: Azure, Service: "dns", Category: ResNetwork,
			CLIDescribe: "az network dns zone show --ids {id}", TerraformType: "azurerm_dns_zone"},
		{Type: "azure.application_gateway", Name: "Application Gateway", Provider: Azure, Service: "network", Category: ResNetwork,
			CLIDescribe: "az network application-gateway show --ids {id}", TerraformType: "azurerm_application_gateway"},

		// ── Security & Identity ──
		{Type: "azure.key_vault", Name: "Key Vault", Provider: Azure, Service: "keyvault", Category: ResSecurity,
			CLIDescribe: "az keyvault show --ids {id}", TerraformType: "azurerm_key_vault"},
		{Type: "azure.managed_identity", Name: "Managed Identity", Provider: Azure, Service: "msi", Category: ResIdentity,
			CLIDescribe: "az identity show --ids {id}", TerraformType: "azurerm_user_assigned_identity"},
		{Type: "azure.role_assignment", Name: "Role Assignment", Provider: Azure, Service: "authorization", Category: ResIdentity,
			TerraformType: "azurerm_role_assignment"},

		// ── Messaging ──
		{Type: "azure.service_bus_namespace", Name: "Service Bus Namespace", Provider: Azure, Service: "servicebus", Category: ResMessaging,
			CLIDescribe: "az servicebus namespace show --ids {id}", TerraformType: "azurerm_servicebus_namespace"},
		{Type: "azure.event_hub_namespace", Name: "Event Hub Namespace", Provider: Azure, Service: "eventhub", Category: ResMessaging,
			CLIDescribe: "az eventhubs namespace show --ids {id}", TerraformType: "azurerm_eventhub_namespace"},

		// ── Monitoring ──
		{Type: "azure.log_analytics_workspace", Name: "Log Analytics Workspace", Provider: Azure, Service: "operationalinsights", Category: ResMonitoring,
			CLIDescribe: "az monitor log-analytics workspace show --ids {id}", TerraformType: "azurerm_log_analytics_workspace"},
		{Type: "azure.monitor_diagnostic", Name: "Diagnostic Setting", Provider: Azure, Service: "monitor", Category: ResMonitoring,
			TerraformType: "azurerm_monitor_diagnostic_setting"},
	} {
		RegisterResource(r)
	}
}
