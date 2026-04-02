# Drydock Test Coverage

Tracks which beacon check IDs have drydock e2e tests, and which require cloud accounts or physical hardware.

## Coverage Summary

| Category | Total Check IDs | Docker Testable | Cloud Required | Hardware Required | Covered |
|----------|----------------|-----------------|----------------|-------------------|---------|
| Email Security | 17 | 10 | 0 | 0 | 1 |
| TLS/SSL | 27 | 27 | 0 | 0 | 2 |
| DNS Security | 7 | 5 | 0 | 0 | 1 |
| HTTP Headers | 7 | 7 | 0 | 0 | 2 |
| Exposure/Misconfig | 13 | 13 | 0 | 0 | 6 |
| Web Application | 40+ | 40+ | 0 | 0 | 20 |
| Port/Service | 60+ | 55+ | 0 | 5 | 40+ |
| CVE Detection | 150+ | 30+ | 120+ | 0 | 6 |
| GitHub Actions | 48+ | 0 | 48+ (needs repos) | 0 | 0 |
| GitHub Repo Config | 15 | 0 | 15 (needs repos) | 0 | 0 |
| Cloud AWS | 80+ | 0 | 80+ | 0 | 0 |
| Cloud GCP | 40+ | 0 | 40+ | 0 | 0 |
| Cloud Azure | 30+ | 0 | 30+ | 0 | 0 |
| Cloud DO/OCI | 13 | 0 | 13 | 0 | 0 |
| AI/LLM | 11 | 5 | 0 | 6 (GPU) | 1 |
| Web3/Blockchain | 18 | 10 | 0 | 0 | 1 |
| WiFi | 6 | 0 | 0 | 6 | 0 |
| On-prem Docker | 12 | 12 | 0 | 0 | 1 |
| On-prem K8s | 18 | 10 (k3s) | 0 | 0 | 0 |
| On-prem VMware | 12 | 0 | 0 | 12 | 0 |
| On-prem Proxmox | 12 | 1 (API mock) | 0 | 11 | 1 |
| On-prem NAS | 9 | 0 | 0 | 9 | 0 |
| On-prem libvirt | 6 | 0 | 0 | 6 | 0 |
| On-prem Network | 9 | 5 | 0 | 4 | 0 |
| OAuth/OIDC/JWT | 20+ | 20+ | 0 | 0 | 2 |
| SAML | 9 | 9 | 0 | 0 | 1 |
| IAM/Identity | 12 | 5 | 0 | 0 | 1 |
| Gateway/CDN | 17 | 15 | 2 | 0 | 5 |
| DLP | 8 | 8 | 0 | 0 | 2 |
| Dirbust | 2 | 2 | 0 | 0 | 1 |
| GraphQL | 5 | 5 | 0 | 0 | 1 |
| WAF | 5 | 5 | 0 | 0 | 1 |
| CI/CD (GitLab) | 10 | 10 | 0 | 0 | 1 |
| CI/CD (TeamCity) | 7 | 7 | 0 | 0 | 1 |
| Terraform | 17 | 17 (static) | 0 | 0 | 0 |
| Supply Chain | 15 | 5 | 10 | 0 | 0 |
| Okta | 15 | 0 | 15 | 0 | 0 |
| Correlation | 8 | 0 (AI-generated) | 0 | 0 | 0 |

## Cloud Account Required (tag: cloud-needed)

These check IDs require real cloud provider accounts and cannot be tested locally:

### AWS (cloud.aws.*)
- All 80+ AWS checks require AWS account with IAM, S3, EC2, EKS, RDS, Lambda, etc.
- Tag: `cloud-needed:aws`

### GCP (cloud.gcp.*)
- All 40+ GCP checks require GCP project with IAM, GCS, GKE, Cloud SQL, etc.
- Tag: `cloud-needed:gcp`

### Azure (cloud.azure.*)
- All 30+ Azure checks require Azure subscription with storage, AKS, SQL, etc.
- Tag: `cloud-needed:azure`

### DigitalOcean (cloud.do.*)
- 7 checks require DigitalOcean account
- Tag: `cloud-needed:digitalocean`

### Oracle Cloud (cloud.oci.*)
- 6 checks require OCI tenancy
- Tag: `cloud-needed:oci`

### GitHub Actions/Repo (ghaction.*, github.*)
- 60+ checks require GitHub repos with specific workflow configurations
- Tag: `cloud-needed:github`

### Okta (iam.okta_*)
- 15 checks require Okta dev tenant
- Tag: `cloud-needed:okta`

## Hardware Required (tag: hardware-needed)

### WiFi (wifi.*)
- wifi.open_network, wifi.wep_network, wifi.wps_enabled, wifi.wpa2_tkip, wifi.gateway_exposed, wifi.pmkid_capture
- Requires wireless NIC in monitor mode
- Tag: `hardware-needed:wifi`

### VMware ESXi/vCenter (onprem.vmware.*)
- 12 checks require ESXi host or vCenter instance
- Tag: `hardware-needed:vmware`

### NAS Appliances (onprem.nas.*)
- 9 checks require Synology/TrueNAS/QNAP device
- Tag: `hardware-needed:nas`

### libvirt/KVM (onprem.libvirt.*)
- 6 checks require KVM host with libvirt
- Tag: `hardware-needed:libvirt`

### GPU-dependent AI (ai.*)
- ai.prompt_injection, ai.system_prompt_leak, ai.ssrf_via_llm, ai.data_exfiltration, ai.tool_abuse, ai.indirect_injection
- Full LLM exploitation requires GPU-accelerated models
- Tag: `hardware-needed:gpu`

### ICS/SCADA (port.s7comm_*, port.ethernet_ip_*, port.dnp3_*, port.bacnet_*)
- 4 checks require real PLC/SCADA hardware or licensed simulators
- Tag: `hardware-needed:ics`

## Existing Test Files

### databases/
- clickhouse.yaml → port.clickhouse_exposed
- couchdb.yaml → port.couchdb_unauthenticated
- influxdb.yaml → port.influxdb_exposed
- memcached.yaml → port.memcached_unauthenticated
- mongodb.yaml → port.database_exposed
- mysql.yaml → port.database_exposed
- mysql-noauth.yaml → port.mysql_no_auth
- postgres.yaml → port.database_exposed
- postgres-trust.yaml → port.postgresql_trust
- mssql.yaml → port.database_exposed, port.mssql_default_creds
- rabbitmq-default-creds.yaml → port.rabbitmq_default_creds
- redis.yaml → port.redis_unauthenticated

### services/
- activemq.yaml → port.activemq_exposed
- adguard.yaml → port.adguard_exposed
- airflow.yaml → port.airflow_exposed
- argocd.yaml → port.argocd_exposed
- artifactory.yaml → port.artifactory_exposed
- consul-no-acl.yaml → port.consul_no_acl
- docker-registry.yaml → container.registry_exposed
- elasticsearch.yaml → port.elasticsearch_unauthenticated
- ftp.yaml → port.ftp_anonymous
- gitea.yaml → cve.gitea_cmd_injection
- grafana.yaml → port identification
- grpc-reflection.yaml → port.grpc_reflection_enabled
- harbor.yaml → port.harbor_exposed
- jenkins.yaml → port identification
- jupyter.yaml → port.jupyter_exposed
- kafka.yaml → port.kafka_exposed
- keycloak.yaml → oauth/oidc
- kong.yaml → gateway.kong_admin_exposed
- ldap.yaml → port.ldap_exposed
- minio.yaml → port identification
- minio-default-creds.yaml → port.minio_default_credentials
- mlflow.yaml → port.mlflow_exposed
- mosquitto.yaml → port.mqtt_exposed
- nacos.yaml → port.nacos_exposed
- nats.yaml → port.nats_monitoring_exposed
- neo4j.yaml → port.neo4j_exposed
- netdata.yaml → port.netdata_exposed
- nexus.yaml → port.nexus_exposed
- nifi.yaml → port.nifi_exposed
- phpmyadmin.yaml → web.default_credentials
- prometheus.yaml → port.prometheus_unauthenticated
- proxmox-api.yaml → port.proxmox_exposed
- pulsar.yaml → port.pulsar_admin_exposed
- rabbitmq.yaml → port.amqp_exposed, port.rabbitmq_mgmt_exposed
- ray.yaml → port.ray_dashboard_exposed
- smb.yaml → port.smb_exposed
- solr.yaml → cve.solr_admin_exposed
- sonarqube.yaml → port identification
- ssh.yaml → port.ssh_exposed
- stepca.yaml → port.step_ca_exposed
- superset.yaml → port.superset_exposed
- telnet.yaml → port.telnet_exposed
- traefik.yaml → gateway.traefik_api_exposed
- vault.yaml → port identification
- vnc.yaml → port.vnc_exposed
- webmin.yaml → port.webmin_exposed
- wordpress.yaml → cms.plugin_found
- zookeeper.yaml → port.zookeeper_exposed

### scanners/
- aidetect.yaml → ai.endpoint_exposed, ai.model_info_exposed
- cmdinj.yaml → web.command_injection
- cors.yaml → web.cors_misconfiguration
- crlf.yaml → web.crlf_injection
- csrf.yaml → web.csrf_token_missing
- dirbust-extensions.yaml → dirbust.path_found
- domxss.yaml → web.xss (DOM-based)
- fingerprint-php.yaml → web.tech_detected (WordPress)
- fingerprint-spring.yaml → web.tech_detected (Spring Boot)
- graphql.yaml → graphql.introspection_enabled
- hostheader.yaml → web.host_header_injection
- jwt.yaml → jwt.weak_algorithm
- nginx-alias.yaml → web.nginx_alias_traversal
- oauth.yaml → oauth.missing_state, oauth.missing_pkce
- openredir.yaml → web.open_redirect
- port-identification.yaml → port.service_identified
- secheaders.yaml → headers.missing_csp, headers.missing_hsts, etc.
- secheaders-secure.yaml → negative test (no findings)
- sqli.yaml → web.sqli
- ssrf.yaml → web.ssrf
- ssti.yaml → web.ssti
- tls.yaml → tls.cert_self_signed, tls.protocol_tls10
- tls-variants.yaml → tls.cert_weak_key, tls.no_pfs
- wafdetect.yaml → waf.detected
- web3.yaml → web3.wallet_lib_detected
- xxe.yaml → web.xxe

### exposure/
- dangerous-methods.yaml → web.dangerous_method_enabled
- docker-api.yaml → port.docker_unauthenticated
- env-file.yaml → exposure.env_file_exposed
- git-exposed.yaml → exposure.git_exposed
- spring-actuator.yaml → exposure.spring_actuator
- swagger.yaml → web.swagger_exposed
- swagger-petstore.yaml → web.swagger_exposed

### email/
- missing-dmarc.yaml → email.dmarc_missing, email.spf_missing
- smtp-relay.yaml → port.smtp_exposed
- imap-pop3.yaml → port.imap_exposed

### dlp/
- api-keys.yaml → dlp.api_key
- sensitive-data.yaml → dlp.ssn_pattern, dlp.credit_card

### fingerprint/
- apache-proxy.yaml → web.tech_detected (Apache)
- consul-service.yaml → classify (Consul)
- elasticsearch-service.yaml → classify (Elasticsearch)
- envoy-express.yaml → classify (Envoy + Express)
- express-framework.yaml → classify (Express)
- grafana-service.yaml → classify (Grafana)
- haproxy-elasticsearch.yaml → classify (HAProxy)
- keycloak-auth.yaml → classify (Keycloak)
- nginx-grafana.yaml → classify (Nginx + Grafana)
- nginx-proxy.yaml → classify (Nginx)
- php-framework.yaml → classify (PHP)

### infrastructure/
- apache.yaml → classify (Apache httpd)
- consul.yaml → classify + port.consul_no_acl
- etcd.yaml → port.etcd_exposed
- nginx.yaml → classify (Nginx)
- nginx-status.yaml → gateway.nginx_status_exposed

### cve/
- apache-traversal.yaml → cve.apache_http_path_traversal (httpd 2.4.49)
- grafana-traversal.yaml → cve.grafana_path_traversal (Grafana 8.2.0)
- log4shell.yaml → cve.log4shell (Log4j 2.14.1)
- tomcat-ghostcat.yaml → cve.tomcat_ghostcat (Tomcat 9.0.30 AJP)
- activemq-rce.yaml → cve.activemq_rce (ActiveMQ 5.15.15)

### cicd/
- gitlab.yaml → gitlab.public_registration
- teamcity.yaml → teamcity.guest_access

### identity/
- saml.yaml → saml.endpoint_exposed, saml.metadata_exposed
- ldap-injection.yaml → iam.ldap_injection

### web-vulns/
- clickjacking.yaml → http.clickjacking
- default-creds.yaml → web.default_credentials
- deserialize.yaml → web.insecure_deserialize
- error-leak.yaml → web.error_info_leak
- file-upload.yaml → web.file_upload_bypass
- path-traversal.yaml → web.path_traversal
- smuggling.yaml → web.http_request_smuggling

### dns/
- open-resolver.yaml → port.dns_open_resolver
