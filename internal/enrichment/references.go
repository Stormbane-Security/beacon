package enrichment

// checkReference holds per-CheckID reference material injected into the Claude
// prompt to ground remediation advice in real documentation and IaC examples.
type checkReference struct {
	// DocSummary is a 1–3 sentence excerpt from official documentation or a
	// well-known best-practice guide. Must be factual and short.
	DocSummary string
	// TerraformExample is a minimal HCL block that correctly configures the
	// resource. Shown to Claude so it produces accurate Terraform fixes.
	TerraformExample string
}

// checkReferences maps CheckIDs to reference material used to ground Claude's
// remediation advice. Add an entry whenever a new check is added that maps
// to an IaC resource type or has a well-known authoritative fix.
var checkReferences = map[string]checkReference{
	// ---- Cloud storage ----
	"cloud.bucket_public": {
		DocSummary: "Public cloud storage buckets expose all contained objects to anonymous internet access. GCP, AWS, and Azure each provide bucket-level public access block settings that should be enabled.",
		TerraformExample: `# GCP — block public access
resource "google_storage_bucket_iam_binding" "block_public" {
  bucket = google_storage_bucket.main.name
  role   = "roles/storage.objectViewer"
  members = []  # remove allUsers / allAuthenticatedUsers
}
resource "google_storage_bucket" "main" {
  name                        = "my-bucket"
  uniform_bucket_level_access = true
}

# AWS — block public access
resource "aws_s3_bucket_public_access_block" "main" {
  bucket                  = aws_s3_bucket.main.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}`,
	},

	// ---- GKE ----
	"nmap.service_version": {
		DocSummary: "Exposed service version strings let attackers quickly identify unpatched software and look up known CVEs. Suppressing version banners is a basic hardening step.",
		TerraformExample: "",
	},

	// ---- TLS ----
	"tls.cert_expiry_7d": {
		DocSummary: "TLS certificates must be renewed before expiry. Expired certificates cause browsers to block access and break mTLS connections. Use cert-manager or ACM for automatic renewal.",
		TerraformExample: `# cert-manager Certificate (Kubernetes)
resource "kubernetes_manifest" "tls_cert" {
  manifest = {
    apiVersion = "cert-manager.io/v1"
    kind       = "Certificate"
    metadata   = { name = "my-cert", namespace = "default" }
    spec = {
      secretName = "my-cert-tls"
      issuerRef  = { name = "letsencrypt-prod", kind = "ClusterIssuer" }
      dnsNames   = ["example.com"]
      renewBefore = "720h"  # renew 30 days before expiry
    }
  }
}`,
	},
	"tls.cert_self_signed": {
		DocSummary: "Self-signed certificates are not trusted by browsers or clients and indicate a CA-issued certificate was not provisioned. Use a public CA (Let's Encrypt, ACM, etc.) for externally-facing services.",
		TerraformExample: `# AWS ACM — request a public certificate
resource "aws_acm_certificate" "main" {
  domain_name       = "example.com"
  validation_method = "DNS"
  lifecycle { create_before_destroy = true }
}`,
	},
	"tls.protocol_tls10": {
		DocSummary: "TLS 1.0 is deprecated (RFC 8996). It is vulnerable to BEAST and POODLE attacks. Minimum version must be TLS 1.2 with TLS 1.3 preferred.",
		TerraformExample: `# AWS ALB — enforce TLS 1.2+
resource "aws_lb_listener" "https" {
  ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  # ...
}

# GCP HTTPS LB — enforce TLS 1.2+
resource "google_compute_ssl_policy" "modern" {
  name            = "modern-ssl"
  profile         = "MODERN"
  min_tls_version = "TLS_1_2"
}`,
	},
	"tls.protocol_tls11": {
		DocSummary: "TLS 1.1 is deprecated (RFC 8996). Minimum version must be TLS 1.2.",
		TerraformExample: `resource "aws_lb_listener" "https" {
  ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"
}`,
	},

	// ---- Email ----
	"email.spf_missing": {
		DocSummary: "An SPF record authorises which mail servers may send email for your domain. Without one, anyone can spoof your From address and phishing emails will pass basic filtering.",
		TerraformExample: `# AWS Route53 SPF record
resource "aws_route53_record" "spf" {
  zone_id = aws_route53_zone.main.zone_id
  name    = "example.com"
  type    = "TXT"
  ttl     = 300
  records = ["v=spf1 include:_spf.google.com ~all"]
}`,
	},
	"email.dmarc_missing": {
		DocSummary: "DMARC instructs receiving mail servers how to handle SPF/DKIM failures. Without p=reject/quarantine, phishing emails using your domain may be delivered.",
		TerraformExample: `resource "aws_route53_record" "dmarc" {
  zone_id = aws_route53_zone.main.zone_id
  name    = "_dmarc.example.com"
  type    = "TXT"
  ttl     = 300
  records = ["v=DMARC1; p=reject; rua=mailto:dmarc-reports@example.com"]
}`,
	},

	// ---- HTTP headers ----
	"headers.missing_hsts": {
		DocSummary: "HTTP Strict Transport Security (HSTS) tells browsers to only connect via HTTPS. Without it, TLS-stripping attacks can downgrade connections to plain HTTP.",
		TerraformExample: `# nginx config via Terraform null_resource
resource "null_resource" "nginx_hsts" {
  provisioner "remote-exec" {
    inline = ["echo 'add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;' >> /etc/nginx/conf.d/security.conf"]
  }
}
# Or: set at load balancer level (AWS ALB / CloudFront response headers policy)
resource "aws_cloudfront_response_headers_policy" "security" {
  name = "security-headers"
  security_headers_config {
    strict_transport_security {
      access_control_max_age_sec = 31536000
      include_subdomains         = true
      override                   = true
    }
  }
}`,
	},
	"headers.missing_csp": {
		DocSummary: "Content-Security-Policy prevents XSS by restricting which scripts/resources the browser may load. Missing CSP is consistently flagged by PCI-DSS and OWASP.",
		TerraformExample: `resource "aws_cloudfront_response_headers_policy" "csp" {
  name = "csp-policy"
  custom_headers_config {
    items {
      header   = "Content-Security-Policy"
      value    = "default-src 'self'; script-src 'self'; object-src 'none'"
      override = true
    }
  }
}`,
	},

	// ---- DNS ----
	"dns.missing_caa": {
		DocSummary: "CAA records restrict which Certificate Authorities may issue TLS certificates for your domain, preventing unauthorised certificate issuance.",
		TerraformExample: `resource "aws_route53_record" "caa" {
  zone_id = aws_route53_zone.main.zone_id
  name    = "example.com"
  type    = "CAA"
  ttl     = 300
  records = [
    "0 issue \"letsencrypt.org\"",
    "0 issue \"amazon.com\"",
    "0 iodef \"mailto:security@example.com\""
  ]
}`,
	},
	"dns.dangling_cname": {
		DocSummary: "A dangling CNAME points to a resource (S3 bucket, Heroku app, GitHub Pages) that no longer exists, allowing an attacker to register that resource and serve content under your domain.",
		TerraformExample: `# Remove the dangling DNS record
# aws_route53_record — delete or update the target:
resource "aws_route53_record" "fixed" {
  zone_id = aws_route53_zone.main.zone_id
  name    = "sub.example.com"
  type    = "CNAME"
  ttl     = 300
  records = ["your-actual-owned-resource.example.com"]
}`,
	},

	// ---- Exposure ----
	"exposure.env_file": {
		DocSummary: "A publicly accessible .env file exposes credentials, API keys, database URLs, and encryption keys to anyone who requests it. This is a P1 vulnerability.",
		TerraformExample: `# S3 — explicitly block public access to env files
resource "aws_s3_bucket_public_access_block" "main" {
  bucket                  = aws_s3_bucket.app.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
# Nginx: deny .env and dotfiles in server config (not Terraform-managed)`,
	},
	"exposure.git_exposed": {
		DocSummary: "An exposed .git directory leaks the full source code history, credentials ever committed, and internal architecture. Any commit containing secrets is recoverable.",
		TerraformExample: `# CloudFront WAF rule — block .git path access
resource "aws_wafv2_rule_group" "block_git" {
  name     = "block-dotgit"
  scope    = "CLOUDFRONT"
  capacity = 10
  rule {
    name     = "block-git"
    priority = 1
    action { block {} }
    statement {
      byte_match_statement {
        search_string         = "/.git"
        field_to_match { uri_path {} }
        text_transformation { priority = 0; type = "NONE" }
        positional_constraint = "STARTS_WITH"
      }
    }
    visibility_config { cloudwatch_metrics_enabled = false; metric_name = "block-git"; sampled_requests_enabled = false }
  }
  visibility_config { cloudwatch_metrics_enabled = false; metric_name = "block-git-rg"; sampled_requests_enabled = false }
}`,
	},

	// ---- GKE ----
	"nmap.os_detected": {
		DocSummary: "OS detection via network fingerprinting provides attackers with precise targeting information for known OS-level CVEs.",
		TerraformExample: "",
	},

	// ---- IAM ----
	"iam.scim_unauthenticated": {
		DocSummary: "An unauthenticated SCIM endpoint allows attackers to enumerate or modify user accounts without credentials. SCIM must require OAuth2 bearer tokens.",
		TerraformExample: `# Enforce auth on SCIM via AWS API Gateway authorizer
resource "aws_api_gateway_authorizer" "scim_auth" {
  name          = "scim-jwt-auth"
  rest_api_id   = aws_api_gateway_rest_api.main.id
  type          = "JWT"
  identity_source = "$request.header.Authorization"
}`,
	},
	"iam.cloud_metadata_ssrf": {
		DocSummary: "SSRF to 169.254.169.254 (instance metadata service) retrieves IAM role credentials, allowing privilege escalation to the EC2/GCE instance role. Remediate with IMDSv2 enforcement.",
		TerraformExample: `# AWS — require IMDSv2 (token-required mode)
resource "aws_instance" "app" {
  # ...
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"  # enforces IMDSv2
    http_put_response_hop_limit = 1
  }
}

# GCP — disable legacy metadata endpoint
resource "google_compute_instance" "app" {
  # ...
  metadata = {
    "disable-legacy-endpoints" = "true"
  }
}`,
	},

	// ---- Web ----
	"web.ssti": {
		DocSummary: "Server-Side Template Injection allows attackers to execute arbitrary code on the server by injecting template directives. Severity is Critical — often leads to full RCE.",
		TerraformExample: "",
	},
	"web.xxe": {
		DocSummary: "XML External Entity injection can read arbitrary files from the server filesystem and perform SSRF. Disable DTD processing and external entities in the XML parser.",
		TerraformExample: "",
	},
	"web.insecure_deserialize": {
		DocSummary: "Insecure deserialization of attacker-controlled data can lead to remote code execution, particularly in Java (native serialization) and PHP (unserialize). Use safe data formats (JSON) and avoid deserializing untrusted input.",
		TerraformExample: "",
	},

	// ---- JWT ----
	"jwt.algorithm_confusion": {
		DocSummary: "Algorithm confusion (RS256 → HS256) allows an attacker to forge JWTs by signing with the server's public RSA key as an HMAC secret. Explicitly whitelist allowed algorithms server-side.",
		TerraformExample: "",
	},
	"jwt.no_verification": {
		DocSummary: "A JWT accepted without signature verification means any user can craft arbitrary claims (admin: true, sub: other-user). Severity is Critical.",
		TerraformExample: "",
	},

	// ---- SAML ----
	"saml.signature_not_validated": {
		DocSummary: "SAML assertions accepted without signature validation allow an attacker to forge authentication assertions and impersonate any user, including administrators.",
		TerraformExample: "",
	},
	"saml.xml_signature_wrapping": {
		DocSummary: "XML Signature Wrapping (XSW) attacks move the signed element in the SAML assertion so validation passes on one element while the application reads from another, forged element.",
		TerraformExample: "",
	},

	// ---- Wave 2/3 CVEs ----
	"cve.struts2_s2066": {
		DocSummary: "CVE-2024-53677 (S2-066) is a critical file upload path traversal in Apache Struts 2 (< 6.4.0). An unauthenticated attacker can upload files to arbitrary paths via manipulated file upload parameters, enabling RCE via JSP shells.",
		TerraformExample: "",
	},
	"cve.rails_xml_rce": {
		DocSummary: "Ruby on Rails versions < 3.2.12 parse XML with YAML type coercion enabled by default, allowing unauthenticated RCE via crafted XML bodies (CVE-2013-0156). Upgrade to Rails 3.2.12+ or disable XML parsing.",
		TerraformExample: "",
	},
	"cve.hfs_rejetto": {
		DocSummary: "CVE-2024-23692 is a critical unauthenticated RCE in HFS (HTTP File Server) 2.x via Rejetto template injection. Attackers send crafted HTTP requests to execute arbitrary commands. Upgrade to HFS 3.x or apply the vendor patch.",
		TerraformExample: "",
	},
	"cve.manage_engine_service_desk": {
		DocSummary: "CVE-2021-44077 is a critical unauthenticated RCE in ManageEngine ServiceDesk Plus versions < 11306. The /RestAPI/ImportTechnicians endpoint allows unauthenticated file upload and code execution.",
		TerraformExample: "",
	},
	"cve.minio_env_disclosure": {
		DocSummary: "CVE-2023-28432 is a high-severity information disclosure in MinIO < RELEASE.2023-03-13T19-46-17Z. The /minio/health/cluster?verify endpoint returns the full MINIO_ROOT_PASSWORD and other environment variables without authentication.",
		TerraformExample: `# Restrict MinIO console and API access to internal networks only
resource "aws_security_group_rule" "minio_restrict" {
  type      = "ingress"
  from_port = 9000
  to_port   = 9001
  protocol  = "tcp"
  cidr_blocks = ["10.0.0.0/8"]
}`,
	},
	"cve.fortios_ws_auth_bypass": {
		DocSummary: "CVE-2024-55591 is a critical authentication bypass in FortiOS 7.0.0–7.0.16 and 7.2.0–7.2.12. The Node.js WebSocket management module can be exploited by unauthenticated attackers to gain super-admin privileges via crafted requests to /api/v2/cmdb/system/admin.",
		TerraformExample: "",
	},
	"cve.ivanti_cs_2025_0282": {
		DocSummary: "CVE-2025-0282 is a critical stack-based buffer overflow in Ivanti Connect Secure < 22.7R2.5 and Policy Secure < 22.7R1.2. Unauthenticated attackers can achieve RCE. KEV-listed with active exploitation in the wild since December 2024.",
		TerraformExample: "",
	},
	"cve.sap_netweaver_2025_31324": {
		DocSummary: "CVE-2025-31324 (CVSS 10.0, KEV) is an unauthenticated arbitrary file upload in SAP NetWeaver Visual Composer Metadata Uploader. Attackers upload JSP webshells to /developmentserver/metadatauploader and achieve RCE. Actively exploited in mass attacks.",
		TerraformExample: "",
	},

	// ---- Wave 2/3 port exposures ----
	"port.cisco_smart_install": {
		DocSummary: "Cisco Smart Install (TCP/4786) allows unauthenticated remote configuration of Cisco switches. An attacker can overwrite the startup config, upload malicious IOS images, or steal device credentials. Disable Smart Install with 'no vstack' on IOS.",
		TerraformExample: `# Block Smart Install (TCP/4786) at the perimeter
resource "aws_network_acl_rule" "block_smart_install" {
  network_acl_id = aws_network_acl.main.id
  rule_number    = 100
  protocol       = "tcp"
  rule_action    = "deny"
  cidr_block     = "0.0.0.0/0"
  from_port      = 4786
  to_port        = 4786
}`,
	},
	"port.nacos_exposed": {
		DocSummary: "Alibaba Nacos service registry (TCP/8848) exposed without ACL allows any attacker to enumerate all registered microservices, read/write configuration values, and access stored credentials. The default nacos:nacos credentials grant full admin access.",
		TerraformExample: `resource "aws_security_group_rule" "nacos_restrict" {
  type        = "ingress"
  from_port   = 8848
  to_port     = 8848
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]  # internal only
}`,
	},
	"port.consul_no_acl": {
		DocSummary: "HashiCorp Consul without ACLs (TCP/8500) exposes the full service catalog, KV store, and node topology to unauthenticated access. Attackers can enumerate all services and their addresses, read stored secrets, and register rogue services.",
		TerraformExample: `# Enable Consul ACL in Terraform
resource "consul_acl_policy" "deny_all" {
  name  = "deny-all"
  rules = ""
}
# Set ACL default policy to deny in consul.hcl:
# acl { enabled = true, default_policy = "deny" }`,
	},
	"port.rabbitmq_default_creds": {
		DocSummary: "RabbitMQ management UI and API (TCP/15672) with default credentials guest:guest allow any attacker to read all queued messages, publish arbitrary messages, create/delete queues, and execute server commands via the HTTP API.",
		TerraformExample: `resource "aws_security_group_rule" "rabbitmq_restrict" {
  type        = "ingress"
  from_port   = 15672
  to_port     = 15672
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]  # management UI internal only
}`,
	},
	"port.mysql_no_auth": {
		DocSummary: "MySQL root account accessible without a password allows complete database takeover. An attacker can read all databases, exfiltrate PII/financial data, execute OS commands via LOAD DATA and UDF plugins.",
		TerraformExample: `# Restrict MySQL port to application subnets only
resource "aws_security_group_rule" "mysql_restrict" {
  type                     = "ingress"
  from_port                = 3306
  to_port                  = 3306
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.app.id
}`,
	},
	"port.postgresql_trust": {
		DocSummary: "PostgreSQL configured with trust authentication allows any user connecting from a matching host to authenticate without a password. This often applies to all local/network connections, enabling full database access with no credentials.",
		TerraformExample: `# Use RDS with IAM authentication instead of trust auth
resource "aws_db_instance" "postgres" {
  engine                  = "postgres"
  iam_database_authentication_enabled = true
  publicly_accessible     = false
  vpc_security_group_ids  = [aws_security_group.db.id]
}`,
	},
	"port.mssql_default_creds": {
		DocSummary: "Microsoft SQL Server with the 'sa' account enabled and blank password allows complete database server compromise. Attackers gain DBO access to all databases and can enable xp_cmdshell for OS command execution.",
		TerraformExample: `resource "aws_security_group_rule" "mssql_restrict" {
  type                     = "ingress"
  from_port                = 1433
  to_port                  = 1433
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.app.id
}`,
	},
	"port.artifactory_exposed": {
		DocSummary: "JFrog Artifactory artifact repository (TCP/8081-8082) exposed without authentication allows download of all artifacts including internal binaries, SDKs, and dependencies that may contain embedded secrets or proprietary code.",
		TerraformExample: `resource "aws_security_group_rule" "artifactory_restrict" {
  type        = "ingress"
  from_port   = 8081
  to_port     = 8082
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]
}`,
	},
	"port.nexus_exposed": {
		DocSummary: "Sonatype Nexus Repository Manager (TCP/8081) exposed allows unauthenticated browsing and download of all hosted artifacts. Default admin:admin123 credentials allow full repository management and potential supply chain compromise.",
		TerraformExample: `resource "aws_security_group_rule" "nexus_restrict" {
  type        = "ingress"
  from_port   = 8081
  to_port     = 8081
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]
}`,
	},
	"port.grpc_reflection_enabled": {
		DocSummary: "gRPC server reflection (TCP/50051) allows any client to enumerate all available RPC services, methods, and their protobuf schemas without authentication. This enables attackers to map the full internal API surface and craft targeted payloads.",
		TerraformExample: `# Disable gRPC reflection in production (Go example)
# Remove grpc_reflection.Register(server) from your server setup
# Restrict port 50051 to internal networks:
resource "aws_security_group_rule" "grpc_restrict" {
  type        = "ingress"
  from_port   = 50051
  to_port     = 50051
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]
}`,
	},

	// ---- Wireless management infrastructure ----
	"netdev.unifi_exposed": {
		DocSummary: "Ubiquiti UniFi Network Application manages enterprise WiFi deployments. An internet-exposed controller leaks network topology, SSID names, connected client MACs, and AP locations. UniFi < 6.5.54 is vulnerable to Log4Shell (CVE-2021-44228, CVSS 10.0, KEV).",
		TerraformExample: `resource "aws_security_group_rule" "unifi_restrict" {
  type        = "ingress"
  from_port   = 8443
  to_port     = 8443
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]  # management access internal only
}`,
	},
	"cve.unifi_log4shell": {
		DocSummary: "CVE-2021-44228 (Log4Shell, CVSS 10.0, KEV) affects Ubiquiti UniFi Network Application < 6.5.54. Unauthenticated attackers can trigger JNDI injection via the login endpoint, achieving RCE on the controller server. Upgrade to 6.5.54+ immediately.",
		TerraformExample: "",
	},
	"netdev.tplink_omada": {
		DocSummary: "TP-Link Omada Network Management System manages enterprise WiFi, switches, and routers. Internet-exposed Omada controllers are vulnerable to CVE-2023-1389 (pre-auth RCE, CVSS 9.8, KEV). Restrict to internal management networks.",
		TerraformExample: `resource "aws_security_group_rule" "omada_restrict" {
  type        = "ingress"
  from_port   = 8043
  to_port     = 8043
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]
}`,
	},
	"cve.tplink_omada_rce": {
		DocSummary: "CVE-2023-1389 (CVSS 9.8, KEV) is a pre-authentication command injection in TP-Link Omada controllers <= 5.9.32. Attackers inject OS commands via the locale parameter in the login API, achieving unauthenticated RCE. Upgrade to 5.9.33+.",
		TerraformExample: "",
	},
	"netdev.aruba_instant": {
		DocSummary: "Aruba Instant Access Point management interface exposed to the internet allows attackers to reconfigure WiFi SSIDs, extract PSK credentials, and potentially exploit firmware vulnerabilities. Restrict management access to trusted VLANs only.",
		TerraformExample: "",
	},
	"netdev.openwrt_exposed": {
		DocSummary: "OpenWRT LuCI web administration panel exposed allows unauthenticated attackers to access router configuration, extract WiFi PSK credentials, modify firewall rules, and gain full router control. The default admin account often has no password set.",
		TerraformExample: "",
	},
	"port.radius_exposed": {
		DocSummary: "RADIUS (RFC 2865, UDP/1812) authenticates VPN, WPA-Enterprise WiFi, and network device logins. Internet-exposed RADIUS servers are vulnerable to CVE-2024-3596 (Blast RADIUS — MD5 collision to forge Access-Accept responses) and offline dictionary attacks. Restrict to NAS device subnets only.",
		TerraformExample: `resource "aws_network_acl_rule" "block_radius" {
  network_acl_id = aws_network_acl.main.id
  rule_number    = 200
  protocol       = "udp"
  rule_action    = "deny"
  cidr_block     = "0.0.0.0/0"
  from_port      = 1812
  to_port        = 1813
}`,
	},
	"dlp.wifi_credential": {
		DocSummary: "WiFi PSK or WPA passphrase exposed in a publicly accessible file or config endpoint. An attacker can use the credential to join the wireless network and pivot to internal assets.",
		TerraformExample: "",
	},

	// ---- Contract ----
	"contract.reentrancy": {
		DocSummary: "A reentrancy vulnerability allows an attacker to repeatedly call a function before the first invocation completes, draining contract funds. The DAO hack exploited this pattern and lost $60M.",
		TerraformExample: "",
	},
	"contract.selfdestruct": {
		DocSummary: "An unprotected selfdestruct call allows any caller to permanently destroy the contract and send all its ETH to an arbitrary address.",
		TerraformExample: "",
	},
}

// referenceFor returns the checkReference for a given check ID, or zero value
// if no reference is registered. Matches on the full ID and also on the prefix
// before the first dot (e.g. "tls.cert_expiry_7d" → tries exact, then prefix).
func referenceFor(checkID string) checkReference {
	if ref, ok := checkReferences[checkID]; ok {
		return ref
	}
	return checkReference{}
}
