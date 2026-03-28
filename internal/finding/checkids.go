package finding

// CheckID is a stable, dotted-namespace identifier for a specific security check.
// These are defined before any scanner is written and never change.
// Used for: deduplication, delta comparison across scans, enrichment caching.
type CheckID = string

const (
	// Email Security
	CheckEmailSPFMissing            CheckID = "email.spf_missing"
	CheckEmailSPFSoftfail           CheckID = "email.spf_softfail"
	CheckEmailSPFLookupLimit        CheckID = "email.spf_lookup_limit"
	CheckEmailDMARCMissing          CheckID = "email.dmarc_missing"
	CheckEmailDMARCPolicyNone       CheckID = "email.dmarc_policy_none"
	CheckEmailDMARCSubdomainNone    CheckID = "email.dmarc_subdomain_policy_none"
	CheckEmailDMARCNoReporting      CheckID = "email.dmarc_no_reporting"
	CheckEmailDKIMMissing           CheckID = "email.dkim_missing"
	CheckEmailDKIMWeakKey           CheckID = "email.dkim_weak_key"
	CheckEmailMTASTSMissing         CheckID = "email.mta_sts_missing"
	CheckEmailMTASTSNotEnforced     CheckID = "email.mta_sts_not_enforced"
	CheckEmailMTASTSPolicyFetchFail CheckID = "email.mta_sts_policy_fetch_fail"
	CheckEmailTLSRPTMissing         CheckID = "email.tls_rpt_missing"
	CheckEmailBIMIMissing           CheckID = "email.bimi_missing"
	CheckEmailDANEMissing           CheckID = "email.dane_missing"
	CheckEmailSpoofable             CheckID = "email.spoofable"
	CheckEmailSPFIncludes           CheckID = "email.spf_includes" // INFO: list of third-party senders authorized by SPF

	// TLS / SSL
	CheckTLSCertExpiry7d        CheckID = "tls.cert_expiry_7d"
	CheckTLSCertExpiry30d       CheckID = "tls.cert_expiry_30d"
	CheckTLSCertSelfSigned      CheckID = "tls.cert_self_signed"
	CheckTLSCertHostnameMismatch CheckID = "tls.cert_hostname_mismatch"
	CheckTLSCertChainInvalid    CheckID = "tls.cert_chain_invalid"
	CheckTLSProtocolSSLv2       CheckID = "tls.protocol_sslv2"
	CheckTLSProtocolSSLv3       CheckID = "tls.protocol_sslv3"
	CheckTLSProtocolTLS10       CheckID = "tls.protocol_tls10"
	CheckTLSProtocolTLS11       CheckID = "tls.protocol_tls11"
	CheckTLSWeakCipher          CheckID = "tls.weak_cipher"
	CheckTLSBEAST               CheckID = "tls.beast"              // CBC ciphers in TLS 1.0 (BEAST attack)
	CheckTLSHeartbleed          CheckID = "tls.heartbleed"
	CheckTLSPOODLE              CheckID = "tls.poodle"
	CheckTLSROBOT               CheckID = "tls.robot"
	CheckTLSCCSInjection        CheckID = "cve.tls_ccs_injection"  // CVE-2014-0224 OpenSSL CCS injection MitM — premature ChangeCipherSpec (CVSS 6.8)

	// New TLS checks — native Go implementation (no external binary required)
	CheckTLSCertWeakKey          CheckID = "tls.cert_weak_key"           // RSA<2048 or EC<224 — High, Surface
	CheckTLSCertWeakSignature    CheckID = "tls.cert_weak_sig"           // MD5 or SHA-1 signed — High, Surface
	CheckTLSCertLongValidity     CheckID = "tls.cert_long_validity"      // Valid > 398 days (post-2020 CA/B Forum limit) — Low, Surface
	CheckTLSCertNoOCSP           CheckID = "tls.cert_no_ocsp"           // No OCSP URL in AIA — Low, Surface
	CheckTLSCertRevoked          CheckID = "tls.cert_revoked"            // OCSP says revoked — Critical, Surface
	CheckTLSCertNoSCT            CheckID = "tls.cert_no_sct"            // No Signed Certificate Timestamp (CT) — Low, Surface
	CheckTLSNoPFS                CheckID = "tls.no_pfs"                  // No forward-secret cipher negotiated — High, Surface
	CheckTLSNoTLS13              CheckID = "tls.no_tls13"               // TLS 1.3 not supported — Low, Surface
	CheckTLSCertWildcard         CheckID = "tls.cert_wildcard"           // Wildcard cert in use — Info, Surface
	CheckTLSMixedContent         CheckID = "tls.mixed_content"           // HTTP resources loaded on HTTPS page — Medium, Surface
	CheckTLSNoSecureRenegotiation CheckID = "tls.no_secure_renegotiation" // RFC 5746 Secure Renegotiation not advertised — Medium, Surface
	CheckTLSCRLNoURL             CheckID = "tls.cert_no_crl"            // No CRL distribution point — Info, Surface
	CheckTLSHSTSShortMaxAge      CheckID = "tls.hsts_short_max_age"     // HSTS max-age < 180 days — Medium, Surface
	CheckTLSHSTSNoSubdomains     CheckID = "tls.hsts_no_subdomains"     // HSTS missing includeSubDomains — Low, Surface
	CheckTLSHSTSNoPreload        CheckID = "tls.hsts_no_preload"        // HSTS missing preload directive — Info, Surface
	CheckTLSCertSANMissing       CheckID = "tls.cert_san_missing"       // Cert has no SAN (deprecated CN-only) — Medium, Surface

	// DNS Security
	CheckDNSAXFRAllowed    CheckID = "dns.axfr_allowed"
	CheckDNSWildcard       CheckID = "dns.wildcard_dns"
	CheckDNSDanglingCNAME  CheckID = "dns.dangling_cname"
	CheckDNSMissingCAA     CheckID = "dns.missing_caa"
	CheckDNSDNSSECMissing  CheckID = "dns.dnssec_missing"

	// HTTP Security Headers
	CheckHeadersMissingCSP              CheckID = "headers.missing_csp"
	CheckHeadersMissingHSTS             CheckID = "headers.missing_hsts"
	CheckHeadersMissingXFrameOptions    CheckID = "headers.missing_x_frame_options"
	CheckHeadersMissingXContentType     CheckID = "headers.missing_x_content_type"
	CheckHeadersMissingReferrerPolicy   CheckID = "headers.missing_referrer_policy"
	CheckHeadersMissingPermissionsPolicy CheckID = "headers.missing_permissions_policy"
	CheckHeadersServerInfoLeak          CheckID = "headers.server_info_leak"

	// Exposure / Misconfiguration
	CheckExposureHTTPNoRedirect   CheckID = "exposure.http_no_redirect"
	CheckExposureStagingSubdomain CheckID = "exposure.staging_subdomain"
	CheckExposureAdminPath        CheckID = "exposure.admin_path"
	CheckExposureRobotsLeak       CheckID = "exposure.robots_disallow_leak"
	CheckExposureEnvFile          CheckID = "exposure.env_file_exposed"
	CheckExposureGitExposed       CheckID = "exposure.git_exposed"
	CheckExposureBackupFile       CheckID = "exposure.backup_file"
	CheckExposureAPIDocs          CheckID = "exposure.api_docs"
	CheckExposureMonitoringPanel  CheckID = "exposure.monitoring_panel"
	CheckExposureCICDPanel        CheckID = "exposure.cicd_panel"
	CheckExposureSpringActuator   CheckID = "exposure.spring_actuator"
	CheckExposureCloudStorage     CheckID = "exposure.cloud_storage"
	CheckExposureSensitiveFile    CheckID = "exposure.sensitive_file"

	// Nuclei-sourced (mapped from template IDs)
	CheckNucleiS3BucketExposed   CheckID = "nuclei.s3_bucket_exposed"
	CheckNucleiMisconfiguredCORS CheckID = "nuclei.misconfigured_cors"
	CheckNucleiStaleTemplates    CheckID = "nuclei.stale_templates" // templates >30 days old

	// Subdomain / Asset Discovery
	CheckSubdomainTakeover  CheckID = "subdomain.takeover"
	CheckDomainTyposquat    CheckID = "domain.typosquat" // registered lookalike domain

	// Web Application Security (deep only)
	CheckWebTechDetected      CheckID = "web.tech_detected"
	CheckWebOutdatedSoftware  CheckID = "web.outdated_software"
	CheckWebDebugEndpoint     CheckID = "web.debug_endpoint"
	CheckWebErrorInfoLeak     CheckID = "web.error_info_leak"
	CheckWebXSS               CheckID = "web.xss"
	CheckWebSQLi              CheckID = "web.sqli"
	CheckWebOpenRedirect      CheckID = "web.open_redirect"
	CheckWebSSRF              CheckID = "web.ssrf"
	CheckWebPathTraversal          CheckID = "web.path_traversal"
	CheckWebDefaultCredentials     CheckID = "web.default_credentials"
	CheckWebHTTPRequestSmuggling   CheckID = "web.http_request_smuggling"
	CheckWebDangerousMethodEnabled CheckID = "web.dangerous_method_enabled"   // PUT/DELETE/TRACE enabled on web server
	CheckSecretInResponseHeader    CheckID = "web.secret_in_response_header"  // API key or token leaked in HTTP response header

	// Asset Intelligence (no API keys — all open services)
	CheckAssetReverseIP     CheckID = "asset.reverse_ip"        // HackerTarget reverse IP — open, no key
	CheckAssetOrgDomains    CheckID = "asset.org_domains"       // crt.sh org cert search — open, no key
	CheckAssetASNRanges     CheckID = "asset.asn_ranges"        // BGP/ASN IP ranges via bgpview.io — open, no key
	CheckAssetPassiveDNS    CheckID = "asset.passive_dns"       // historical DNS records via HackerTarget — open, no key
	CheckAssetHistoricalURLs CheckID = "asset.historical_urls"  // Wayback Machine + OTX via gau — open, no key
	CheckAssetCrawlEndpoints CheckID = "asset.crawl_endpoints"  // endpoints discovered by katana crawler
	CheckAssetScreenshot    CheckID = "asset.screenshot"        // screenshot captured by gowitness

	// WHOIS / Domain Registration
	CheckWHOISDomainExpiry7d  CheckID = "whois.domain_expiry_7d"   // domain expires within 7 days
	CheckWHOISDomainExpiry30d CheckID = "whois.domain_expiry_30d"  // domain expires within 30 days
	CheckWHOISDomainInfo      CheckID = "whois.domain_info"        // registrar, nameservers, creation date

	// Cloud Storage Buckets
	CheckCloudBucketPublic   CheckID = "cloud.bucket_public"   // publicly readable bucket
	CheckCloudBucketExists   CheckID = "cloud.bucket_exists"   // bucket exists (may be private)
	CheckCloudBucketWritable CheckID = "cloud.bucket_writable" // bucket is publicly writable (PUT succeeds)

	// Web Content Analysis
	CheckJSHardcodedSecret   CheckID = "js.hardcoded_secret"
	CheckJSInternalEndpoint  CheckID = "js.internal_endpoint"
	CheckJSSourceMapExposed  CheckID = "js.source_map_exposed"
	CheckCookieMissingSecure   CheckID = "cookie.missing_secure"
	CheckCookieMissingHTTPOnly CheckID = "cookie.missing_httponly"
	CheckCookieMissingSameSite CheckID = "cookie.missing_samesite"
	CheckCSPUnsafeInline     CheckID = "csp.unsafe_inline"
	CheckCSPUnsafeEval       CheckID = "csp.unsafe_eval"
	CheckCSPWildcardSource   CheckID = "csp.wildcard_source"
	CheckWAFNotDetected      CheckID = "waf.not_detected"
	CheckWAFDetected         CheckID = "waf.detected"           // WAF vendor fingerprinted from headers
	CheckWAFOriginExposed    CheckID = "waf.origin_exposed"     // origin IP directly accessible, bypassing WAF
	CheckWAFBypassHeader     CheckID = "waf.bypass_via_header"  // WAF bypassable via spoofed IP header (deep)
	CheckWAFInsecureMode     CheckID = "waf.insecure_ssl_mode"  // Cloudflare flexible SSL: origin served over plain HTTP
	CheckIDSDetected         CheckID = "ids.detected"           // IDS/NGFW vendor identified from response patterns

	// DLP — data-loss detection in HTTP responses and screenshots
	// Regex patterns run against the raw page body (complement to webcontent's JS scanning).
	// Vision findings are produced by Claude analyzing screenshot images.
	CheckDLPSSN           CheckID = "dlp.ssn_pattern"      // SSN pattern in HTTP response
	CheckDLPCreditCard    CheckID = "dlp.credit_card"       // credit card number in HTTP response
	CheckDLPDatabaseURL   CheckID = "dlp.database_url"      // database connection string with credentials
	CheckDLPPrivateKey    CheckID = "dlp.private_key"       // PEM private key in HTTP response
	CheckDLPAPIKey        CheckID = "dlp.api_key"           // API key or secret found in config/env dump path
	CheckDLPEmailList     CheckID = "dlp.email_list"        // bulk email dump (>10 addresses)
	CheckDLPVision        CheckID = "dlp.vision_finding"    // Claude Vision detected sensitive content
	CheckVisionServiceID  CheckID = "dlp.vision_service_id" // Claude Vision identified service on unmatched asset

	// Dirbusting — deep mode only (requires --permission-confirmed)
	// Active path enumeration sends targeted HTTP requests beyond normal browsing.
	CheckDirbustFound      CheckID = "dirbust.path_found"       // interesting path responded
	CheckDirbustWAFBlocked CheckID = "dirbust.waf_blocked"      // WAF blocked dirbusting activity

	// Port / service exposure — TCP connect scan, no exploit payloads → Surface
	// Detecting an open port is equivalent to what any network scan or internet index does.
	CheckPortRedisUnauth         CheckID = "port.redis_unauthenticated"         // Redis with no auth
	CheckPortElasticsearchUnauth CheckID = "port.elasticsearch_unauthenticated" // Elasticsearch with no auth
	CheckPortPrometheusUnauth    CheckID = "port.prometheus_unauthenticated"    // Prometheus metrics API open
	CheckPortDockerUnauth        CheckID = "port.docker_unauthenticated"        // Docker daemon API open
	CheckPortKubeletUnauth       CheckID = "port.kubelet_unauthenticated"       // Kubelet API open
	CheckPortMemcachedUnauth     CheckID = "port.memcached_unauthenticated"     // Memcached with no auth
	CheckPortJupyterExposed      CheckID = "port.jupyter_exposed"               // Jupyter Notebook open
	CheckPortCouchDBUnauth       CheckID = "port.couchdb_unauthenticated"       // CouchDB with no auth
	CheckPortSSHExposed          CheckID = "port.ssh_exposed"                   // SSH accessible from internet
	CheckPortRDPExposed          CheckID = "port.rdp_exposed"                   // RDP accessible from internet
	CheckPortVNCExposed          CheckID = "port.vnc_exposed"                   // VNC remote desktop accessible from internet
	CheckPortTelnetExposed       CheckID = "port.telnet_exposed"                // Telnet (plaintext)
	CheckPortFTPExposed          CheckID = "port.ftp_exposed"                   // FTP accessible from internet
	CheckPortFTPAnonymous        CheckID = "port.ftp_anonymous"                 // FTP accepts anonymous login (no credentials)
	CheckPortFTPVsftpdBackdoor   CheckID = "cve.vsftpd_backdoor_2011"           // CVE-2011-2523 vsftpd 2.3.4 supply-chain backdoor — banner identifies compromised version (CVSS 10.0)
	CheckPortSMBExposed          CheckID = "port.smb_exposed"                   // SMB/Windows filesharing exposed
	CheckPortSMBNullSession      CheckID = "port.smb_null_session"              // SMB accepts null session (unauthenticated share list)
	CheckPortSMBv1Enabled        CheckID = "port.smb_v1_enabled"                // SMBv1 protocol accepted — EternalBlue/WannaCry risk (CVE-2017-0144)
	CheckPortDatabaseExposed     CheckID = "port.database_exposed"              // Database port exposed (MySQL/Postgres/MSSQL/Oracle)
	CheckPortK8sAPIExposed       CheckID = "port.k8s_api_exposed"               // Kubernetes API server exposed
	CheckPortWinRMExposed        CheckID = "port.winrm_exposed"                 // WinRM remote management exposed
	CheckPortAMQPExposed         CheckID = "port.amqp_exposed"                  // AMQP message broker exposed
	CheckPortKafkaExposed        CheckID = "port.kafka_exposed"                 // Apache Kafka broker exposed
	CheckPortZooKeeperExposed    CheckID = "port.zookeeper_exposed"             // Apache ZooKeeper exposed
	CheckPortInfluxDBExposed     CheckID = "port.influxdb_exposed"              // InfluxDB time-series DB exposed
	CheckPortSplunkMgmtExposed   CheckID = "port.splunk_mgmt_exposed"           // Splunk management API exposed

	// GraphQL
	CheckGraphQLIntrospection         CheckID = "graphql.introspection_enabled"      // introspection leaks full schema
	CheckGraphQLBatchQuery             CheckID = "graphql.batch_query_enabled"        // batch queries amplify request count
	CheckGraphQLPersistedQueryBypass  CheckID = "graphql.persisted_query_bypass"     // server accepts arbitrary persisted queries

	// Email deliverability — SMTP probe (passive observation, no mail sent) → Surface
	CheckEmailSMTPOpenRelay   CheckID = "email.smtp_open_relay"     // SMTP server accepts mail for external domains
	CheckEmailSMTPBannerLeak  CheckID = "email.smtp_banner_leak"    // SMTP banner leaks server software/version

	// Version / software currency — observed from HTTP headers and service banners → Surface
	// Passive observation only: no probing beyond what classify already does.
	CheckVersionOutdated CheckID = "version.outdated_software" // known EOL or critically outdated software version

	// DNS Intelligence — passive DNS queries only → Surface
	CheckDNSTXTHarvest CheckID = "dns.txt_harvest"   // all TXT records (SPF, DMARC, verification tokens, etc.)
	CheckDNSNSRecords  CheckID = "dns.ns_records"    // authoritative nameservers (may reveal internal infra)

	// TLS Fingerprinting — standard TLS handshake probing → Surface
	CheckTLSJARM CheckID = "tls.jarm_fingerprint" // JARM TLS fingerprint identifies server software

	// Shodan host intelligence — passive API query → Surface (requires API key)
	CheckShodanHostInfo CheckID = "asset.shodan_host" // Shodan host record: open ports, banners, CVEs

	// Virtual host discovery — HTTP request with Host: header → Surface
	CheckVHostFound CheckID = "asset.vhost_found" // virtual host responding at this IP

	// CDN origin discovery — passive DNS, historical records, common patterns → Surface
	CheckCDNOriginFound CheckID = "asset.cdn_origin_found" // origin IP found behind CDN

	// ASN IP range active probing — HTTP probe per IP in owned ranges → Surface
	CheckASNIPService CheckID = "asset.asn_ip_service" // HTTP service found on org-owned IP
	CheckPTRRecord    CheckID = "asset.ptr_record"     // PTR record found in ASN range

	// Multi-service per-port discovery — a distinct service found on a non-standard port
	// warrants its own fingerprint and playbook matching pass.
	CheckPortServiceDiscovered CheckID = "asset.port_service_discovered"

	// Host header injection — active probe with malicious Host: values → Deep
	CheckHostHeaderInjection CheckID = "web.host_header_injection"

	// JWT security — parsed from cookies/response bodies (passive observation) → Surface
	CheckJWTWeakAlg          CheckID = "jwt.weak_algorithm"    // alg:none or trivially broken
	CheckJWTLongExpiry        CheckID = "jwt.long_expiry"       // token never expires or > 7 days
	CheckJWTSensitivePayload  CheckID = "jwt.sensitive_payload" // PII/role data in unencrypted payload

	// HIBP — query public breach API for domain exposure → Surface
	CheckHIBPBreach CheckID = "asset.hibp_breach" // domain's users found in known breach database

	// theHarvester — employee identity enumeration from public OSINT sources → Surface
	CheckHarvesterEmails      CheckID = "osint.harvester_emails"      // employee email addresses discovered
	CheckHarvesterSubdomains  CheckID = "osint.harvester_subdomains"  // subdomains discovered via OSINT
	CheckHarvesterUnavailable CheckID = "osint.harvester_unavailable" // theHarvester not installed — scan skipped

	// CORS misconfiguration — active test with attacker Origin values → Deep
	CheckCORSMisconfiguration CheckID = "web.cors_misconfiguration"

	// Bing dork search — passive search engine query for exposed files → Surface
	CheckBingDorkExposure CheckID = "asset.dork_exposure"

	// CMS plugin enumeration — HTTP probe on well-known CMS paths → Surface
	CheckCMSPluginFound      CheckID = "cms.plugin_found"      // CMS plugin detected
	CheckCMSPluginVulnerable CheckID = "cms.plugin_vulnerable" // plugin version has known CVE

	// GitHub Actions
	CheckGHActionUnpinned         CheckID = "ghaction.unpinned_action"
	CheckGHActionPRTargetUnsafe   CheckID = "ghaction.pull_request_target_unsafe"
	CheckGHActionScriptInjection  CheckID = "ghaction.script_injection"
	CheckGHActionOverpermissioned CheckID = "ghaction.overpermissioned"
	CheckGHActionSecretsEchoed    CheckID = "ghaction.secrets_echoed"
	CheckGHActionSelfHostedPublic CheckID = "ghaction.self_hosted_on_public_repo"

	// GitHub Actions — workflow behavior gaps
	CheckGHActionWorkflowRunUnsafe           CheckID = "ghaction.workflow_run_unsafe"
	CheckGHActionGitHubEnvInjection          CheckID = "ghaction.github_env_injection"
	CheckGHActionSecretsInherit              CheckID = "ghaction.secrets_inherit"
	CheckGHActionInsecureCommands            CheckID = "ghaction.insecure_commands"
	CheckGHActionBotConditionSpoofable       CheckID = "ghaction.bot_condition_spoofable"
	CheckGHActionArtiPacked                  CheckID = "ghaction.artipacked"
	CheckGHActionCachePoisoning              CheckID = "ghaction.cache_poisoning"
	CheckGHActionUnsignedRelease             CheckID = "ghaction.unsigned_release_artifacts"
	CheckGHActionReusableWorkflowUnpinned    CheckID = "ghaction.reusable_workflow_unpinned"
	CheckGHActionWorkflowDispatchInjection   CheckID = "ghaction.workflow_dispatch_injection"
	CheckGHActionKnownCompromised            CheckID = "ghaction.known_compromised_action"

	// GitHub Actions — CI/CD safety bypass patterns
	// These checks catch workflows that deliberately circumvent the PR review
	// and branch protection controls GitHub provides as safety guardrails.
	CheckGHActionIssueCommentUnsafe       CheckID = "ghaction.issue_comment_unsafe"       // issue_comment + PR checkout = RCE
	CheckGHActionAutoMerge               CheckID = "ghaction.workflow_auto_merge"          // workflow merges PRs — bypasses branch protection
	CheckGHActionAutoApprove             CheckID = "ghaction.workflow_auto_approve"        // workflow approves its own PRs — bypasses required reviews
	CheckGHActionScheduledWrite          CheckID = "ghaction.scheduled_write_permissions"  // scheduled trigger + write access = unmanned code changes
	CheckGHActionMissingJobTimeout       CheckID = "ghaction.missing_job_timeout"          // no timeout-minutes — workflow can run indefinitely
	CheckGHActionContinueOnErrorSecurity CheckID = "ghaction.continue_on_error_security"  // security step with continue-on-error: true

	// GitHub repository configuration — additional hardening
	CheckGitHubNoCodeowners          CheckID = "github.no_codeowners"           // no CODEOWNERS file — critical paths unprotected
	CheckGitHubNoTagProtection       CheckID = "github.no_tag_protection"       // tags can be created/moved/deleted by any contributor
	CheckGitHubNoEnvProtection       CheckID = "github.no_environment_protection" // deployment environments without required reviewers

	// GitHub Actions — OIDC vs long-lived credential checks
	CheckGHActionAWSLongLivedKey        CheckID = "ghaction.aws_long_lived_key"
	CheckGHActionGCPServiceAccountKey   CheckID = "ghaction.gcp_service_account_key"
	CheckGHActionAzureCredentials       CheckID = "ghaction.azure_credentials_secret"
	CheckGHActionNPMTokenNotOIDC        CheckID = "ghaction.npm_token_not_oidc"
	CheckGHActionPyPITokenNotTrusted    CheckID = "ghaction.pypi_token_not_trusted_publishing"
	CheckGHActionDockerPasswordSecret   CheckID = "ghaction.docker_password_not_oidc"
	CheckGHActionVercelToken            CheckID = "ghaction.vercel_token_secret"
	CheckGHActionTerraformCloudToken    CheckID = "ghaction.terraform_cloud_token"
	CheckGHActionFlyToken               CheckID = "ghaction.fly_token_secret"
	CheckGHActionPATUsedInWorkflow      CheckID = "ghaction.pat_used_in_workflow"
	// Informational: deploy targets extracted from workflow files for cross-scan correlation.
	CheckGHActionDeployTargets          CheckID = "ghaction.deploy_targets"
	// Informational: records how a GitHub repository was linked to a scanned domain.
	// Evidence includes discovery_method (package_json, html_link) and source_url.
	CheckGHActionRepoDiscovered         CheckID = "ghaction.repo_discovered"
	// AI-generated attack path connecting CI/CD findings to deployed infrastructure.
	CheckCICDAttackPath                 CheckID = "cicd.attack_path"

	// GitHub repository configuration
	CheckGitHubNoBranchProtection      CheckID = "github.no_branch_protection"
	CheckGitHubNoSecretScanning        CheckID = "github.secret_scanning_disabled"
	CheckGitHubNoDependabot            CheckID = "github.no_dependabot"
	CheckGitHubNoSAST                  CheckID = "github.no_sast"
	CheckGitHubNoVulnAlerts            CheckID = "github.vuln_alerts_disabled"
	CheckGitHubForkWorkflowApproval    CheckID = "github.fork_workflow_no_approval"
	CheckGitHubDefaultTokenWrite       CheckID = "github.default_token_write"
	CheckGitHubActionsUnrestricted     CheckID = "github.actions_unrestricted"
	CheckGitHubWebhookNoSecret         CheckID = "github.webhook_no_secret"
	CheckGitHubOrgMFANotRequired       CheckID = "github.org_mfa_not_required"

	// GitHub repository configuration — additional security controls
	CheckGitHubNoPushProtection       CheckID = "github.no_push_protection"
	CheckGitHubNoSignedCommits        CheckID = "github.no_signed_commits"
	CheckGitHubNoRequiredStatusChecks CheckID = "github.no_required_status_checks"
	CheckGitHubNoDependencyReview     CheckID = "github.no_dependency_review"

	// GitHub secret/key leaks in source code
	CheckGitHubSecretInCode            CheckID = "github.secret_in_code"
	CheckGitHubPrivateKeyInRepo        CheckID = "github.private_key_in_repo"

	// Dependency confusion — package name lookup in public registry → Surface
	CheckDependencyConfusion CheckID = "supply_chain.dependency_confusion"

	// URLScan.io passive scan index — query public archive → Surface
	CheckURLScanFindings CheckID = "asset.urlscan_findings"

	// API rate limiting — missing or misconfigured throttling → Deep
	CheckRateLimitMissing       CheckID = "api.rate_limit_missing"        // no rate limit detected after burst
	CheckRateLimitBypass        CheckID = "api.rate_limit_bypass"         // rate limit bypassable via header rotation
	CheckRateLimitNoRetryAfter  CheckID = "api.rate_limit_no_retry_after" // 429 returned but no Retry-After header

	// OAuth / OIDC / JWKS security — active probe for auth flow weaknesses → Deep
	CheckOAuthMissingState    CheckID = "oauth.missing_state"        // state parameter absent → CSRF
	CheckOAuthMissingPKCE     CheckID = "oauth.missing_pkce"         // PKCE not enforced → auth code interception
	CheckOAuthOpenRedirect    CheckID = "oauth.open_redirect"        // redirect_uri accepts arbitrary domains
	CheckOAuthTokenLeakReferer CheckID = "oauth.token_leak_referer"  // access token appears in Referer header
	CheckJWKSExposed          CheckID = "oauth.jwks_exposed"         // JWKS endpoint publicly enumerable
	CheckOIDCImplicitFlow     CheckID = "oauth.implicit_flow"        // deprecated implicit flow in use
	CheckJWTNoVerification    CheckID = "jwt.no_server_verification" // server accepts tampered/invalid JWT

	// GitHub / CI (Phase 2)
	CheckGitHubPublicRepos    CheckID = "github.public_repos"
	CheckGitHubTrackedEnvFile CheckID = "github.tracked_env_file"
	CheckCICDUnpinnedAction   CheckID = "cicd.unpinned_action"
	CheckCICDScriptInjection  CheckID = "cicd.script_injection"
	CheckCICDPwnRequest       CheckID = "cicd.pwn_request"
	CheckCICDBroadPermissions CheckID = "cicd.broad_permissions"
	CheckSecretsAPIKey        CheckID = "secrets.api_key_in_repo"

	// Jenkins — active probe with Groovy payload → Deep
	CheckJenkinsGroovyRCE CheckID = "jenkins.groovy_rce" // unauthenticated Groovy script console confirmed RCE

	// AI / LLM Security — Surface: passive detection of AI-powered endpoints
	CheckAIEndpointExposed  CheckID = "ai.endpoint_exposed"    // LLM/chat API endpoint reachable without auth
	CheckAIKeyExposed       CheckID = "ai.api_key_exposed"     // LLM provider API key found in response/headers
	CheckAIStreamingOpen    CheckID = "ai.streaming_open"      // unauthenticated SSE/streaming LLM endpoint

	// AI / LLM Security — Deep: active prompt injection and extraction probes
	CheckAIPromptInjection  CheckID = "ai.prompt_injection"    // model behavior overridden by injected prompt
	CheckAISystemLeak       CheckID = "ai.system_prompt_leak"  // system prompt content extracted from model
	CheckAISSRFViaPLLM      CheckID = "ai.ssrf_via_llm"        // LLM fetched an internal URL when prompted
	CheckAIDataExfil        CheckID = "ai.data_exfiltration"   // model returned sensitive data it should not
	CheckAIToolAbuse        CheckID = "ai.tool_abuse"          // agent tool call triggered by injected prompt
	CheckAIModelInfoExposed CheckID = "ai.model_info_exposed"  // model name/version disclosed unauthenticated
	CheckAIIndirectInjection CheckID = "ai.indirect_injection" // LLM honored instructions injected via fetched content

	// JWT / OIDC / JWKS — advanced token security checks
	CheckJWTAlgorithmConfusion  CheckID = "jwt.algorithm_confusion"   // RS256 public key used as HS256 HMAC secret
	CheckJWTAudienceMissing     CheckID = "jwt.audience_missing"      // server accepts tokens with wrong aud claim
	CheckJWTIssuerNotValidated  CheckID = "jwt.issuer_not_validated"  // server accepts tokens from arbitrary issuers
	CheckJWTEncryptionMissing   CheckID = "jwt.no_encryption"         // sensitive claims in unencrypted JWT (not JWE)
	CheckJWTReplayMissing       CheckID = "jwt.replay_missing"        // token lacks jti; replay accepted
	CheckJWKSWeakKey            CheckID = "jwt.jwks_weak_key"         // RSA key in JWKS is < 2048 bits
	CheckJWKSMissingKID         CheckID = "jwt.jwks_missing_kid"      // JWKS key has no kid field
	CheckOIDCWeakSigningAlg     CheckID = "oidc.weak_signing_alg"     // discovery doc includes "none" or weak alg
	CheckOIDCMissingJWKSURI     CheckID = "oidc.missing_jwks_uri"     // OIDC discovery doc has no jwks_uri
	CheckOAuthTokenInFragment   CheckID = "oauth.token_in_url_fragment" // access token in Location header fragment
	CheckOAuthRefreshNotRotated CheckID = "oauth.refresh_not_rotated" // same refresh token accepted twice
	CheckOAuthTokenLongExpiry   CheckID = "oauth.token_long_expiry"   // access token expires_in > 24h
	CheckOIDCBackchannelMissing CheckID = "iam.backchannel_logout_missing" // no backchannel logout support

	// SAML security — endpoint discovery (surface) and active tampering probes (deep)
	CheckSAMLEndpointExposed       CheckID = "saml.endpoint_exposed"
	CheckSAMLMetadataExposed       CheckID = "saml.metadata_exposed"
	CheckSAMLSignatureNotValidated CheckID = "saml.signature_not_validated"
	CheckSAMLXMLWrapping           CheckID = "saml.xml_signature_wrapping"
	CheckSAMLReplayAllowed         CheckID = "saml.assertion_replay"
	CheckSAMLIssuerNotValidated    CheckID = "saml.issuer_not_validated"
	CheckSAMLAudienceNotValidated  CheckID = "saml.audience_not_validated"
	CheckSAMLXXEInjection          CheckID = "saml.xxe_injection"
	CheckSAMLOpenRedirect          CheckID = "saml.open_redirect"

	// IAM / Identity Management security
	CheckSCIMExposed             CheckID = "iam.scim_exposed"
	CheckSCIMUnauthenticated     CheckID = "iam.scim_unauthenticated"
	CheckOIDCUserinfoLeak        CheckID = "iam.oidc_userinfo_leak"
	CheckOAuthIntrospectExposed  CheckID = "iam.token_introspect_exposed"
	CheckOAuthDeviceFlowExposed  CheckID = "iam.device_auth_flow"
	CheckOAuthDynClientReg       CheckID = "iam.dynamic_client_reg"
	CheckLDAPInjection           CheckID = "iam.ldap_injection"
	CheckCloudMetadataSSRF       CheckID = "iam.cloud_metadata_ssrf"
	CheckIdentityProviderExposed CheckID = "iam.idp_admin_exposed"
	CheckOAuthPKCEDowngrade      CheckID = "iam.pkce_downgrade"
	CheckOAuthClientSecretLeak   CheckID = "iam.client_secret_in_js"
	CheckIdentityRoleEscalation  CheckID = "iam.role_assignment_exposed"

	// Web application — new injection and misconfiguration checks
	CheckWebSSTI              CheckID = "web.ssti"                   // server-side template injection
	CheckWebCRLFInjection     CheckID = "web.crlf_injection"         // CRLF injection in headers
	CheckWebPrototypePollution CheckID = "web.prototype_pollution"   // Node.js prototype pollution
	CheckWebXXE               CheckID = "web.xxe"                    // XML external entity injection
	CheckWebInsecureDeserialize CheckID = "web.insecure_deserialize" // insecure deserialization
	CheckWebHPP               CheckID = "web.http_parameter_pollution" // HTTP parameter pollution
	CheckWebNginxAliasTraversal CheckID = "web.nginx_alias_traversal" // nginx alias path traversal
	CheckWebIISShortname      CheckID = "web.iis_shortname"          // IIS 8.3 shortname enumeration
	CheckWebFileUpload        CheckID = "web.file_upload_bypass"     // file upload MIME/extension bypass
	CheckWebAPIFuzz           CheckID = "web.api_fuzz_error"         // API endpoint returns 500 on fuzz input
	CheckCVELog4Shell              CheckID = "cve.log4shell"                   // CVE-2021-44228 Log4j JNDI injection
	CheckCVEN8nRCE                 CheckID = "cve.n8n_rce"                     // CVE-2026-21858/CVE-2025-68613 n8n pre-auth RCE
	CheckCVECraftCMSRCE            CheckID = "cve.craftcms_rce"                // CVE-2025-32432 Craft CMS pre-auth code injection
	CheckCVELivewireRCE            CheckID = "cve.livewire_rce"                // CVE-2025-54068 Laravel Livewire pre-auth RCE
	CheckCVEBeyondTrustRCE         CheckID = "cve.beyondtrust_rce"             // CVE-2026-1731 BeyondTrust pre-auth OS command injection
	CheckCVENginxUIBackup          CheckID = "cve.nginxui_backup_exposed"      // CVE-2026-27944 Nginx-UI unauth backup + key disclosure
	CheckCVESolarWindsWHD          CheckID = "cve.solarwinds_whd_rce"          // CVE-2025-26399 SolarWinds Web Help Desk RCE
	CheckCVEIvantiEPMAuthBypass    CheckID = "cve.ivanti_epm_auth_bypass"      // CVE-2026-1603 Ivanti EPM auth bypass → cred theft
	CheckCVELangflowRCE            CheckID = "cve.langflow_rce"                // CVE-2026-33017 Langflow AI pipeline pre-auth RCE
	CheckCVEOmnissaSSRF            CheckID = "cve.omnissa_workspace_ssrf"      // CVE-2021-22054 Omnissa Workspace ONE unauthenticated SSRF
	CheckPortJuniperAnomalyExposed CheckID = "port.juniper_anomaly_exposed"    // CVE-2026-21902 Juniper PTX port 8160 pre-auth RCE
	CheckPortTelnetdVulnerable     CheckID = "port.telnetd_gnu_vulnerable"     // CVE-2026-32746 GNU telnetd ≤ 2.7 pre-auth stack overflow
	CheckCVETelnetBSDEncrypt       CheckID = "cve.telnetd_bsd_encrypt_2011"   // CVE-2011-4862 BSD telnetd Kerberos encrypt key buffer overflow → pre-auth RCE (CVSS 10.0)
	CheckPortOllamaExposed         CheckID = "port.ollama_exposed"             // Ollama LLM server exposed without auth (port 11434)

	// ── CVEs from Oct 2025 – Mar 2026 KEV additions ────────────────────────
	CheckCVEIvantiEPMMRCE      CheckID = "cve.ivanti_epmm_rce"          // CVE-2026-1281/1340 Ivanti EPMM MDM pre-auth OS cmd injection
	CheckCVECiscoFMCRCE        CheckID = "cve.cisco_fmc_rce"            // CVE-2026-20131 Cisco FMC pre-auth Java deserialization RCE
	CheckCVEHPEOneViewRCE      CheckID = "cve.hpe_oneview_rce"          // CVE-2025-37164 HPE OneView pre-auth RCE (CVSS 10.0, KEV)
	CheckCVECitrixBleed2       CheckID = "cve.citrix_netscaler_memleak" // CVE-2025-5777 Citrix NetScaler pre-auth memory disclosure
	CheckCVEFortiOSSSOBypass   CheckID = "cve.fortios_sso_bypass"       // CVE-2026-24858 FortiOS FortiCloud SSO auth bypass (KEV)
	CheckCVEFortiWebAuthBypass CheckID = "cve.fortiweb_auth_bypass"     // CVE-2025-64446 FortiWeb path traversal auth bypass (CVSS 9.8, KEV)
	CheckCVECiscoASARCE        CheckID = "cve.cisco_asa_ftd_rce"        // CVE-2025-20333/20362 Cisco ASA/FTD pre-auth RCE (KEV)
	CheckCVEMCPServerExposed   CheckID = "cve.mcp_server_exposed"       // CVE-2026-27825 MCP server unauthenticated SSRF/RCE

	// ── Non-HTTP protocol exposure (IoT, industrial, telecom) ────────────────
	CheckPortMQTTExposed    CheckID = "port.mqtt_exposed"     // MQTT broker accessible without auth (port 1883/8883)
	CheckPortSIPExposed     CheckID = "port.sip_exposed"      // SIP PBX/proxy exposed (port 5060/5061)
	CheckPortRTSPExposed    CheckID = "port.rtsp_exposed"     // RTSP video stream accessible (port 554)
	CheckPortIPPExposed     CheckID = "port.ipp_exposed"      // IPP network printer accessible (port 631)
	CheckPortISCSIExposed   CheckID = "port.iscsi_exposed"    // iSCSI storage target accessible (port 3260)
	CheckPortModbusExposed  CheckID = "port.modbus_exposed"   // Modbus TCP SCADA/OT device accessible (port 502)
	CheckPortNetconfExposed CheckID = "port.netconf_exposed"  // NETCONF network device management (port 830)
	CheckPortWinboxExposed  CheckID = "port.winbox_exposed"   // MikroTik Winbox management protocol (port 8291)

	// ── Network device vendor identification ──────────────────────────────────
	// Emitted when a device's SSH banner or HTTP response reveals a specific
	// network vendor. These are Info-level identification findings used by
	// playbooks to trigger network-device-specific checks.
	CheckNetDeviceCiscoDetected    CheckID = "netdev.cisco_detected"     // Cisco IOS/NX-OS/ASA device identified
	CheckNetDeviceJuniperDetected  CheckID = "netdev.juniper_detected"   // Juniper JunOS device identified
	CheckNetDeviceMikroTikDetected CheckID = "netdev.mikrotik_detected"  // MikroTik RouterOS device identified
	CheckNetDeviceUbiquitiDetected CheckID = "netdev.ubiquiti_detected"  // Ubiquiti UniFi/AirOS device identified
	CheckNetDeviceFortinetDetected CheckID = "netdev.fortinet_detected"  // Fortinet FortiGate/FortiSwitch identified
	CheckNetDevicePaloAltoDetected CheckID = "netdev.paloalto_detected"  // Palo Alto PAN-OS device identified
	CheckNetDeviceHuaweiDetected   CheckID = "netdev.huawei_detected"    // Huawei VRP network device identified
	CheckNetDeviceBMCExposed       CheckID = "netdev.bmc_exposed"        // Server BMC/iDRAC/iLO management interface exposed
	CheckCVEErlangOTPSSH           CheckID = "cve.erlang_otp_ssh_rce"    // CVE-2025-32433 Erlang/OTP SSH pre-auth unauthenticated RCE (CVSS 10.0, KEV)
	CheckCVEVeeamBackupExposed     CheckID = "cve.veeam_backup_exposed"   // CVE-2025-23120 Veeam B&R unauthenticated RCE via deserialization (CVSS 9.9, KEV)
	CheckPortDevServerExposed      CheckID = "port.dev_server_exposed"    // Vite/webpack/other JS dev server exposed publicly
	CheckPortGradioExposed         CheckID = "port.gradio_exposed"        // Gradio ML demo server exposed without auth (port 7860)
	CheckPortWebminExposed         CheckID = "port.webmin_exposed"        // Webmin server management panel exposed (port 10000)
	CheckPortWazuhAPIExposed       CheckID = "port.wazuh_api_exposed"     // Wazuh SIEM/XDR REST API exposed (port 55000)

	// ── Additional network vendor identification ──────────────────────────────
	CheckNetDeviceF5Detected       CheckID = "netdev.f5_detected"         // F5 BIG-IP load balancer identified (/tmui/login.jsp)
	CheckNetDeviceSonicWallDetected CheckID = "netdev.sonicwall_detected" // SonicWall firewall/VPN identified (/auth.html)
	CheckNetDeviceCheckPointDetected CheckID = "netdev.checkpoint_detected" // Check Point firewall identified
	CheckNetDeviceHPArubaDetected  CheckID = "netdev.hparuba_detected"    // HP/Aruba network switch identified
	CheckNetDeviceTPLinkDetected   CheckID = "netdev.tplink_detected"     // TP-Link SOHO router identified
	CheckNetDeviceDLinkDetected    CheckID = "netdev.dlink_detected"      // D-Link SOHO router identified
	CheckNetDeviceNetgearDetected  CheckID = "netdev.netgear_detected"    // Netgear SOHO router identified
	CheckNetDeviceAsteriskDetected CheckID = "netdev.asterisk_detected"   // Asterisk/FreePBX VoIP PBX identified

	// ── Industrial Control Systems (ICS/SCADA/OT) ───────────────────────────
	// Any ICS protocol on the internet is a Critical finding regardless of version.
	CheckPortS7CommExposed      CheckID = "port.s7comm_exposed"       // Siemens S7 PLC accessible (port 102)
	CheckPortEtherNetIPExposed  CheckID = "port.ethernet_ip_exposed"  // Rockwell EtherNet/IP PLC accessible (port 44818)
	CheckPortDNP3Exposed        CheckID = "port.dnp3_exposed"         // DNP3 electric utility SCADA accessible (port 20000)
	CheckPortBACnetExposed      CheckID = "port.bacnet_exposed"       // BACnet building automation accessible (port 47808)
	CheckPortAsteriskAMIExposed CheckID = "port.asterisk_ami_exposed" // Asterisk Manager Interface accessible (port 5038)
	CheckPortJetDirectExposed   CheckID = "port.jetdirect_exposed"    // JetDirect/PJL printer raw print port accessible (port 9100)
	CheckPortMikroTikAPIExposed CheckID = "port.mikrotik_api_exposed" // MikroTik RouterOS API accessible (port 8728)
	CheckPortCheckPointExposed  CheckID = "port.checkpoint_topology"  // Check Point FW-1 topology port accessible (port 264)

	// ── Email / messaging server exposure ───────────────────────────────────
	// Ports 25/587 (SMTP), 143/993 (IMAP), 110/995 (POP3) exposed to internet.
	CheckPortSMTPExposed CheckID = "port.smtp_exposed" // SMTP/submission port reachable
	CheckPortIMAPExposed CheckID = "port.imap_exposed" // IMAP port reachable
	CheckPortPOP3Exposed CheckID = "port.pop3_exposed" // POP3 port reachable
	CheckPortSMTPOpenRelay CheckID = "port.smtp_open_relay" // SMTP server relays mail for arbitrary senders
	CheckPortExImVulnerable CheckID = "port.exim_vulnerable" // Exim version < 4.98.1 (CVE-2025-26794 SQL injection)

	// ── Directory services and identity infrastructure ───────────────────────
	// LDAP (389/636), Active Directory Global Catalog (3268/3269), Kerberos (88)
	// exposure. An internet-facing domain controller is a critical misconfiguration.
	CheckPortLDAPExposed            CheckID = "port.ldap_exposed"             // LDAP answering anonymously (port 389/636)
	CheckPortActiveDirectoryExposed CheckID = "port.active_directory_exposed" // LDAP rootDSE reveals AD DC attributes — internet-facing DC
	CheckPortKerberosExposed        CheckID = "port.kerberos_exposed"         // Kerberos KDC port 88 reachable from internet
	CheckPortGlobalCatalogExposed   CheckID = "port.global_catalog_exposed"   // AD Global Catalog port 3268/3269 reachable

	// ── Erlang/OTP ecosystem ─────────────────────────────────────────────────
	CheckPortEPMDExposed CheckID = "port.epmd_exposed" // Erlang Port Mapper Daemon listing nodes without auth (port 4369)

	// ── DNS server exposure ──────────────────────────────────────────────────
	CheckPortDNSOpenResolver  CheckID = "port.dns_open_resolver"   // DNS server answers recursive queries for external domains
	CheckPortDNSVersionExposed CheckID = "port.dns_version_exposed" // BIND/DNS version disclosed via version.bind CHAOS query

	// ── WINS / NetBIOS name service ──────────────────────────────────────────
	CheckPortWINSExposed CheckID = "port.wins_exposed" // WINS server port 1512 reachable (Samba CVE-2025-10230 context)

	// ── NFS / RPC ────────────────────────────────────────────────────────────
	CheckPortRPCBindExposed    CheckID = "port.rpcbind_exposed"       // RPC portmapper 111 answering — enumerates all RPC services
	CheckPortNFSExportsExposed CheckID = "port.nfs_exports_exposed"   // NFS exports enumerable without authentication

	// ── SNMP defaults ────────────────────────────────────────────────────────
	CheckPortSNMPPublicCommunity   CheckID = "port.snmp_public_community"   // SNMP 'public' community string valid (unauthenticated read)
	CheckPortSNMPWritableCommunity CheckID = "port.snmp_writable_community" // SNMP 'private' community string allows SET operations

	// ── UDP service exposure ──────────────────────────────────────────────────
	// All probed via pure-Go UDP sockets — no root/nmap required.
	CheckPortNTPExposed         CheckID = "port.ntp_exposed"           // NTP server accessible on UDP 123
	CheckPortNTPAmplification   CheckID = "port.ntp_amplification"     // NTP monlist enabled (CVE-2013-5211) — DDoS amplification source
	CheckPortTFTPAnonymous      CheckID = "port.tftp_anonymous"        // TFTP server responds to RRQ without authentication
	CheckPortSSDPExposed        CheckID = "port.ssdp_exposed"          // SSDP/UPnP responds on UDP 1900 — IoT/router internet exposure
	CheckCVELibupnpSSDPRCE      CheckID = "cve.libupnp_ssdp_overflow"  // CVE-2012-5958 libupnp ≤ 1.6.17 SSDP SUBSCRIBE buffer overflow → RCE (CVSS 10.0)
	CheckPortIKEExposed         CheckID = "port.ike_exposed"           // IKE/IPSec VPN endpoint on UDP 500
	CheckPortNetBIOSNSExposed   CheckID = "port.netbios_ns_exposed"    // NetBIOS Name Service on UDP 137 — Windows name service internet-facing
	CheckPortSTUNExposed        CheckID = "port.stun_exposed"          // STUN server on UDP 3478 — IP leakage and TURN relay abuse
	CheckPortMDNSExposed        CheckID = "port.mdns_exposed"          // mDNS/Bonjour on UDP 5353 — should never answer from internet

	// Network — nmap-powered fingerprinting and vulnerability detection
	CheckNmapOSDetected     CheckID = "nmap.os_detected"
	CheckNmapServiceVersion CheckID = "nmap.service_version"
	CheckNmapUDPExposed     CheckID = "nmap.udp_service_exposed"
	CheckNmapVulnScript     CheckID = "nmap.vuln_script_hit"
	CheckNmapSNMPExposed    CheckID = "nmap.snmp_exposed"
	CheckNmapDNSRecursion   CheckID = "nmap.dns_recursion"
	CheckNmapFTPAnonymous   CheckID = "nmap.ftp_anonymous"
	CheckNmapSSHAlgorithms  CheckID = "nmap.ssh_weak_algorithms"

	// External intelligence APIs (all optional — keys required)
	CheckVirusTotalReputation CheckID = "intel.virustotal_reputation"
	CheckCensysHostData       CheckID = "intel.censys_host"
	CheckGreyNoiseContext     CheckID = "intel.greynoise"

	// Infrastructure layer: API gateways, load balancers, CDN edges, service mesh
	// Surface: passive detection and admin interface exposure
	// Deep: route enumeration, auth bypass probing
	CheckGatewayKongAdminExposed    CheckID = "gateway.kong_admin_exposed"     // Kong admin API accessible on :8001 or /kong-admin
	CheckGatewayKongRouteEnum       CheckID = "gateway.kong_route_enumeration" // Kong /routes or /services listing backend services
	CheckGatewayHAProxyStatsExposed CheckID = "gateway.haproxy_stats_exposed"  // HAProxy stats page without authentication
	CheckGatewayNginxStatusExposed  CheckID = "gateway.nginx_status_exposed"   // nginx stub_status module enabled (/nginx_status)
	CheckGatewayVarnishDebugExposed CheckID = "gateway.varnish_debug_info"     // Varnish debug headers or PURGE method enabled
	CheckGatewayTraefikAPIExposed   CheckID = "gateway.traefik_api_exposed"    // Traefik /api/rawdata exposes all routers+services
	CheckGatewayEnvoyAdminExposed   CheckID = "gateway.envoy_admin_exposed"    // Envoy /config_dump or /clusters accessible
	CheckGatewayLinkerdVizExposed   CheckID = "gateway.linkerd_viz_exposed"    // Linkerd viz dashboard exposed without auth
	CheckGatewayAWSAPIGWStageInfo   CheckID = "gateway.aws_apigw_stage_info"   // AWS API Gateway stage name or ID in response
	CheckGatewayAzureAPIMExposed    CheckID = "gateway.azure_apim_exposed"     // Azure APIM developer portal or mgmt API accessible
	CheckGatewayApigeeExposed       CheckID = "gateway.apigee_exposed"         // Apigee management API or debug endpoint accessible
	CheckGatewayF5AdminExposed      CheckID = "gateway.f5_admin_exposed"       // F5 BIG-IP iControl REST or TMUI accessible
	CheckGatewayCitrixAdminExposed  CheckID = "gateway.citrix_netscaler_admin" // Citrix NetScaler/ADC management interface accessible
	CheckGatewayTykDashExposed      CheckID = "gateway.tyk_dashboard_exposed"  // Tyk API Gateway dashboard or API accessible
	CheckCDNAkamaiPragmaInfo        CheckID = "cdn.akamai_pragma_info"         // Akamai debug headers exposed via Pragma: akamai-x-cache-on
	CheckCDNFastlyDebugExposed      CheckID = "cdn.fastly_debug_exposed"       // Fastly debug info in Surrogate-Key or X-Served-By headers
	CheckCDNVarnishPurgeEnabled     CheckID = "cdn.varnish_purge_enabled"      // Varnish cache accepts PURGE requests without auth

	// Swagger / OpenAPI spec exposure and endpoint fuzzing
	CheckSwaggerExposed CheckID = "web.swagger_exposed" // OpenAPI/Swagger spec publicly accessible

	// Web3 / blockchain passive detection
	CheckWeb3WalletLibDetected  CheckID = "web3.wallet_lib_detected"
	CheckWeb3RPCEndpointExposed CheckID = "web3.rpc_endpoint_exposed"
	CheckWeb3ContractFound      CheckID = "web3.contract_address_found"

	// EVM smart contract vulnerability scanning
	CheckContractReentrancy       CheckID = "contract.reentrancy"         // reentrancy vulnerability detected in contract bytecode
	CheckContractSelfDestruct     CheckID = "contract.selfdestruct"       // unprotected selfdestruct opcode
	CheckContractUncheckedCall    CheckID = "contract.unchecked_call"     // unchecked low-level call return value
	CheckContractIntegerOverflow  CheckID = "contract.integer_overflow"   // potential integer overflow / underflow
	CheckContractSourceExposed    CheckID = "contract.source_exposed"     // contract source code verified and retrievable
	CheckContractProxyAdmin       CheckID = "contract.proxy_admin"        // upgradeable proxy with admin slot detectable

	// Blockchain node / validator / miner detection
	CheckChainNodeRPCExposed      CheckID = "chain.node_rpc_exposed"      // Ethereum/Bitcoin/Solana JSON-RPC port open and responding
	CheckChainNodeUnauthorized    CheckID = "chain.node_rpc_unauth"       // JSON-RPC accepts state-changing calls without auth
	CheckChainNodeValidatorExposed CheckID = "chain.validator_api_exposed" // ETH2 beacon/validator client API accessible
	CheckChainNodeMinerExposed    CheckID = "chain.miner_rpc_exposed"     // eth_mining/eth_hashrate reveals active miner
	CheckChainNodePeerCountLeak   CheckID = "chain.peer_count_leak"       // net_peerCount leaks network topology
	CheckChainNodeWSExposed       CheckID = "chain.node_ws_exposed"       // WebSocket JSON-RPC port accessible
	CheckChainNodeGrafanaExposed  CheckID = "chain.node_grafana_exposed"  // node monitoring dashboard exposed without auth

	// Web3 / SIWE authenticated security testing — Deep (requires --permission-confirmed)
	// Surface: detect SIWE/SIWS login pages and nonce endpoints
	// Deep: ephemeral wallet login + domain bypass, nonce reuse, replay, escalation probes
	CheckWeb3SIWEEndpoint          CheckID = "web3.siwe_endpoint"            // SIWE nonce/verify endpoint detected (EVM)
	CheckWeb3SIWSDEndpoint         CheckID = "web3.siws_endpoint"            // SIWS nonce/verify endpoint detected (Solana)
	CheckWeb3SIWEDomainBypass      CheckID = "web3.siwe_domain_bypass"       // server accepts SIWE/SIWS message for wrong domain
	CheckWeb3SIWENonceReuse        CheckID = "web3.siwe_nonce_reuse"         // server accepts already-used nonce
	CheckWeb3SIWEReplay            CheckID = "web3.siwe_replay"              // server accepts backdated/expired SIWE/SIWS message
	CheckWeb3SIWEChainMismatch     CheckID = "web3.siwe_chain_mismatch"      // server accepts message for wrong chain ID
	CheckWeb3SIWEURIMismatch       CheckID = "web3.siwe_uri_mismatch"        // server accepts message with wrong URI field
	CheckWeb3SIWEOverHTTP          CheckID = "web3.siwe_over_http"           // SIWE/SIWS auth accessible over plain HTTP (signature interception)
	CheckWeb3HorizontalEscalation  CheckID = "web3.horizontal_escalation"    // session allows access to another wallet's resources

	// ── Recent high-severity CVEs (2025) ──────────────────────────────────────
	CheckPortFTPWingRCE               CheckID = "port.ftp_wing_rce"                // CVE-2025-47812 Wing FTP Server ≤ 7.4.3 pre-auth RCE (CISA KEV)
	CheckPortRedisVulnerableCVE2025   CheckID = "cve.redis_cve_2025_49844"         // CVE-2025-49844 Redis < 7.2.11/7.4.6/8.0.4/8.2.2 unauthenticated RCE
	CheckPortBGPExposed               CheckID = "port.bgp_exposed"                 // BGP port 179 accessible — routing infrastructure exposed
	CheckPortKibanaVulnerable         CheckID = "cve.kibana_cve_2025_25015"        // CVE-2025-25015 Kibana 8.15.0–8.17.2 prototype pollution RCE (CVSS 9.9)
	CheckPortMinIODefaultCreds        CheckID = "port.minio_default_credentials"   // MinIO console (port 9001) accepts minioadmin:minioadmin default credentials
	CheckCVENextJSMiddlewareBypass    CheckID = "cve.nextjs_middleware_bypass"      // CVE-2025-29927 Next.js middleware auth bypass via X-Middleware-Subrequest (CVSS 9.1, KEV)
	CheckCVEViteFileRead              CheckID = "cve.vite_file_read"               // CVE-2025-30208 Vite dev server arbitrary file read via /@fs/ path double-query confusion (CVSS 9.1)
	CheckCVEIngressNightmare          CheckID = "cve.ingress_nightmare"            // CVE-2025-1974 ingress-nginx admission webhook exposed — pre-auth RCE via annotation injection (CVSS 9.8, KEV)
	CheckCVETomcatPartialPUT          CheckID = "cve.tomcat_partial_put"           // CVE-2025-24813 Apache Tomcat partial PUT accepted on .session path — deserialization RCE vector (CVSS 9.8, KEV)

	// ── Recent high-severity CVEs (2024) ──────────────────────────────────────
	CheckCVEOpenSSHRegreSSHion    CheckID = "cve.openssh_regresshion"      // CVE-2024-6387 OpenSSH 8.5p1–9.7p1 signal handler race → unauthenticated RCE (CVSS 8.1, KEV)
	CheckCVEJenkinsCLIFileRead    CheckID = "cve.jenkins_cli_file_read"    // CVE-2024-23897 Jenkins < 2.442 args4j @file CLI arbitrary file read (CVSS 9.8, KEV)
	CheckCVEScreenConnectBypass   CheckID = "cve.screenconnect_setup_bypass" // CVE-2024-1709 ConnectWise ScreenConnect < 23.9.8 setup wizard auth bypass (CVSS 10.0, KEV)
	CheckCVETeamCityAuthBypass    CheckID = "cve.teamcity_auth_bypass"     // CVE-2024-27198 JetBrains TeamCity < 2023.11.4 REST API path-confusion auth bypass (CVSS 9.8, KEV)
	CheckCVEFortiManagerJump      CheckID = "cve.fortimanager_fortijump"   // CVE-2024-47575 FortiManager FGFM missing auth → rogue device register + RCE (CVSS 9.8, KEV)
	CheckCVEPHPCGIArgInjection    CheckID = "cve.php_cgi_arg_injection"    // CVE-2024-4577 PHP CGI on Windows Best-Fit arg injection → RCE (CVSS 9.8, KEV)
	CheckCVEExpeditionRCE         CheckID = "cve.paloalto_expedition_rce"  // CVE-2024-9463 Palo Alto Expedition < 1.2.96 unauthenticated OS command injection (CVSS 9.9, KEV)
	CheckCVEFortiOSSSLVPN         CheckID = "cve.fortios_ssl_vpn_rce"      // CVE-2024-21762 FortiOS < 7.4.3 SSL VPN out-of-bounds write → unauthenticated RCE (CVSS 9.6, KEV)
	CheckCVECheckPointFileRead    CheckID = "cve.checkpoint_file_read"     // CVE-2024-24919 Check Point CloudGuard arbitrary file read via /clients/MyCRL (CVSS 8.6, KEV)

	// ── Recent high-severity CVEs (2023) — additional ────────────────────────
	CheckCVESharePointJWT CheckID = "cve.sharepoint_jwt_bypass" // CVE-2023-29357 SharePoint Server 2019 JWT none-alg auth bypass — version from MicrosoftSharePointTeamServices header (CVSS 9.8, KEV)

	// ── Recent high-severity CVEs (2023) ──────────────────────────────────────
	CheckCVEOwnCloudPhpInfo     CheckID = "cve.owncloud_phpinfo"              // CVE-2023-49103 ownCloud graphapi phpinfo() leak — admin password in env vars (CVSS 10.0, KEV)
	CheckCVEMOVEitWebShell      CheckID = "cve.moveit_webshell"               // CVE-2023-34362 MOVEit Transfer — CL0P human2.aspx web shell compromise indicator (CVSS 9.8, KEV)
	CheckCVEConfluenceSetup     CheckID = "cve.confluence_setup_bypass"       // CVE-2023-22515 Confluence setup wizard accessible — allows unauthenticated admin creation (CVSS 10.0, KEV)
	CheckCVEConfluenceRestore   CheckID = "cve.confluence_restore_bypass"     // CVE-2023-22518 Confluence restore endpoint accessible — unauthenticated DB restore → RCE (CVSS 10.0, KEV)
	CheckCVECiscoIOSXEImplant   CheckID = "cve.cisco_iosxe_implant"           // CVE-2023-20198 Cisco IOS XE web UI — BadCandy implant present (CVSS 10.0, KEV)
	CheckCVEIvantiConnectSecure CheckID = "cve.ivanti_connect_secure_bypass"  // CVE-2023-46805 Ivanti Connect Secure path traversal auth bypass (CVSS 8.2, KEV)
	CheckCVECitrixBleed         CheckID = "cve.citrix_bleed"                  // CVE-2023-4966 Citrix NetScaler OIDC session token memory leak (CVSS 9.4, KEV)
	CheckCVEJuniperJWeb         CheckID = "cve.juniper_jweb_php_injection"    // CVE-2023-36844/45 Juniper J-Web PHP env injection → unauthenticated RCE (CVSS 9.8, KEV)
	CheckCVESysAid              CheckID = "cve.sysaid_path_traversal"         // CVE-2023-47246 SysAid On-Prem path traversal → WAR upload → RCE (CVSS 9.8, KEV)
	CheckCVETeamCityRPC2        CheckID = "cve.teamcity_rpc2_bypass"          // CVE-2023-42793 TeamCity < 2023.05.4 /RPC2 wildcard bypass → admin token (CVSS 9.8, KEV)

	// ── Recent high-severity CVEs (2022) ──────────────────────────────────────
	CheckCVEF5BigIPAuthBypass  CheckID = "cve.f5_bigip_icr_auth_bypass"  // CVE-2022-1388 F5 BIG-IP iControl REST unauthenticated RCE via /mgmt/shared/echo (CVSS 9.8, KEV)
	CheckCVEConfluenceOGNL    CheckID = "cve.confluence_ognl_rce"        // CVE-2022-26134 Confluence OGNL injection → pre-auth RCE (CVSS 9.8, KEV)
	CheckCVEFortiOSAuthBypass CheckID = "cve.fortios_auth_bypass"        // CVE-2022-40684 FortiOS/FortiProxy HTTP header auth bypass (CVSS 9.8, KEV)
	CheckCVEVMwareWorkspaceONE CheckID = "cve.vmware_workspace_one_ssti" // CVE-2022-22954 VMware Workspace ONE Access FreeMarker SSTI → RCE (CVSS 9.8, KEV)
	CheckCVEWSO2FileUpload     CheckID = "cve.wso2_file_upload_rce"      // CVE-2022-29464 WSO2 API Manager/IS unrestricted file upload → RCE (CVSS 9.8, KEV)
	CheckCVESpring4Shell       CheckID = "cve.spring4shell"               // CVE-2022-22965 Spring MVC classloader RCE via class.module.classLoader (CVSS 9.8, KEV)
	CheckCVEZimbraAuthBypass   CheckID = "cve.zimbra_auth_bypass"         // CVE-2022-37042 Zimbra mboximport auth bypass → RCE (CVSS 9.8, KEV)
	CheckCVESophosFW           CheckID = "cve.sophos_firewall_exposed"    // CVE-2022-3236/1040 Sophos Firewall auth bypass/RCE — login fingerprint (CVSS 9.8, KEV)
	CheckCVEManageEngineSAML   CheckID = "cve.manageengine_saml_rce"      // CVE-2022-47966 ManageEngine SAML pre-auth RCE via SAML endpoint (CVSS 9.8, KEV)
	CheckCVEMagentoRCE         CheckID = "cve.magento_template_rce"       // CVE-2022-24086 Adobe Commerce/Magento unauthenticated template injection (CVSS 9.8, KEV)

	// ── Recent high-severity CVEs (2021) ──────────────────────────────────────
	CheckCVEExchangeProxyLogon   CheckID = "cve.exchange_proxylogon"       // CVE-2021-26855 Exchange ProxyLogon SSRF — pre-auth, version from X-OWA-Version (CVSS 9.8, KEV)
	CheckCVEExchangeProxyShell   CheckID = "cve.exchange_proxyshell"       // CVE-2021-34473/34523/31207 Exchange ProxyShell — version from X-OWA-Version (CVSS 9.8, KEV)
	CheckCVEvCenterExposed       CheckID = "cve.vcenter_exposed"           // CVE-2021-21985/22005 VMware vCenter internet-exposed — /sdk version disclosure (CVSS 9.8, KEV)
	CheckCVEApacheHTTPTraversal  CheckID = "cve.apache_http_path_traversal" // CVE-2021-41773/42013 Apache httpd 2.4.49–2.4.50 path traversal → RCE (CVSS 9.8, KEV)
	CheckCVEGitLabRCE            CheckID = "cve.gitlab_rce"                // CVE-2021-22205 GitLab ExifTool pre-auth RCE — version from /api/v4/version (CVSS 10.0, KEV)
	CheckCVESaltStackAPI         CheckID = "cve.saltstack_api_exposed"     // CVE-2021-25281/25282 SaltStack API auth bypass + path traversal (CVSS 9.8, KEV)
	CheckCVEAccellionFTA         CheckID = "cve.accellion_fta_exposed"     // CVE-2021-27101-27104 Accellion FTA (EOL) — exploitation target for data extortion (CVSS 9.8, KEV)

	// ── Recent high-severity CVEs (2020) ──────────────────────────────────────
	CheckCVEF5BigIPTMUI          CheckID = "cve.f5_bigip_tmui_rce"         // CVE-2020-5902 F5 BIG-IP TMUI RCE via /tmui/login.jsp (CVSS 9.8, KEV)
	CheckCVEWebLogicConsole      CheckID = "cve.weblogic_console_bypass"   // CVE-2020-14882/14883 Oracle WebLogic admin console auth bypass (CVSS 9.8, KEV)
	CheckCVECitrixADCInfo        CheckID = "cve.citrix_adc_info_leak"      // CVE-2019-19781/2020-8196 Citrix ADC/Gateway unauthenticated info disclosure (CVSS 9.8, KEV)
	CheckCVESolarWindsOrion      CheckID = "cve.solarwinds_orion_exposed"  // CVE-2020-10148 SolarWinds Orion auth bypass — supply chain + direct login bypass (CVSS 9.8, KEV)
	CheckCVEApacheUnomi          CheckID = "cve.apache_unomi_rce"          // CVE-2020-13942 Apache Unomi RCE via MVEL/OGNL expression in context.json (CVSS 9.8, KEV)
	CheckCVELiferayRCE           CheckID = "cve.liferay_jsonws_rce"        // CVE-2020-7961 Liferay Portal Java deserialization via /api/jsonws (CVSS 9.8, KEV)
	CheckCVEMobileIronRCE        CheckID = "cve.mobileiron_rce"            // CVE-2020-15505 MobileIron MDM RCE via /mifs/user/login.jsp (CVSS 9.8, KEV)

	// ── Recent high-severity CVEs (2019) ──────────────────────────────────────
	CheckCVEPulseSecureVPN    CheckID = "cve.pulse_secure_vpn_exposed"   // CVE-2019-11510 Pulse Secure arbitrary file read — login fingerprint (CVSS 10.0, KEV)
	CheckCVEPANGlobalProtect       CheckID = "cve.pan_globalprotect_exposed"       // CVE-2019-1579 PAN-OS GlobalProtect unauthenticated RCE — version from prelogin (CVSS 9.8, KEV)
	CheckCVEPANGlobalProtectCMD    CheckID = "cve.pan_globalprotect_cmd_injection" // CVE-2024-3400 PAN-OS 10.2/11.0/11.1 GlobalProtect OS command injection — version from prelogin (CVSS 10.0, KEV, nation-state exploited)
	CheckCVECrowdPdkInstall   CheckID = "cve.crowd_pdkinstall_exposed"   // CVE-2019-11580 Atlassian Crowd pdkinstall plugin endpoint pre-auth accessible (CVSS 9.8, KEV)
	CheckCVETelerikRAU        CheckID = "cve.telerik_rau_exposed"         // CVE-2019-18935 Telerik RadAsyncUpload endpoint exposed — pre-auth deserialization (CVSS 9.8, KEV)
	CheckCVEWebLogicAsync     CheckID = "cve.weblogic_async_rce"          // CVE-2019-2725 Oracle WebLogic /_async/ endpoint pre-auth deserialization RCE (CVSS 9.8, KEV)
	CheckCVESolrAdminExposed  CheckID = "cve.solr_admin_exposed"          // CVE-2019-17558 Apache Solr unauthenticated admin API — SSTI via Velocity template (CVSS 9.8, KEV)
	CheckCVEEximRCE2019       CheckID = "cve.exim_rce_2019"               // CVE-2019-10149 Exim 4.87–4.91 DELIVER_FAIL_STR local part expansion → RCE (CVSS 9.8, KEV)
	CheckCVEDLinkHNAP         CheckID = "cve.dlink_hnap_rce"              // CVE-2019-16920 D-Link HNAP API unauthenticated remote command injection (CVSS 9.8)

	// ── Recent high-severity CVEs (2018) ──────────────────────────────────────
	CheckCVEDrupalgeddon2           CheckID = "cve.drupal_drupalgeddon2"           // CVE-2018-7600/7602 Drupal RCE (Drupalgeddon2/3) — version from CHANGELOG.txt (CVSS 9.8, KEV)
	CheckCVEManageEngineDesktopCVE  CheckID = "cve.manageengine_desktop_central"   // CVE-2020-10189 ManageEngine Desktop Central pre-auth file upload → RCE (CVSS 9.8, KEV)
	CheckCVEOpenSSHUsernameEnum     CheckID = "cve.openssh_username_enum_2018"     // CVE-2018-15473 OpenSSH ≤ 7.7 username enumeration via malformed auth packet (CVSS 5.3)
	CheckCVEKubernetesPrivEsc       CheckID = "cve.kubernetes_priv_esc_2018"       // CVE-2018-1002105 Kubernetes ≤ 1.12.2 API server WebSocket upgrade priv esc → cluster admin (CVSS 9.8, KEV)
	CheckCVEJenkinsStaplerRCE       CheckID = "cve.jenkins_stapler_rce_2018"       // CVE-2018-1000861 Jenkins ≤ 2.153 Stapler URL routing pre-auth RCE via ACL bypass (CVSS 9.8)
	CheckCVEEximHeapOverflow        CheckID = "cve.exim_heap_overflow_2018"        // CVE-2018-6789 Exim < 4.90.1 base64d() off-by-one heap overflow → pre-auth RCE (CVSS 9.8, KEV)
	CheckCVEApacheTikaRCE           CheckID = "cve.apache_tika_cmd_injection_2018" // CVE-2018-1335 Apache Tika Server 1.7–1.17 X-Tika-OCR* header command injection → RCE (CVSS 9.8)

	// ── Recent high-severity CVEs (2017) ──────────────────────────────────────
	CheckCVEWebLogicWLSWSAT       CheckID = "cve.weblogic_wls_wsat"          // CVE-2017-10271 Oracle WebLogic wls-wsat pre-auth XXE → RCE — endpoint exposed (CVSS 9.8, KEV)
	CheckCVEHikvisionISAPI        CheckID = "cve.hikvision_isapi"             // CVE-2017-7921 Hikvision IP camera unauthenticated ISAPI access (CVSS 9.8, KEV)
	CheckCVEIntelAMTAuthBypass    CheckID = "cve.intel_amt_auth_bypass"       // CVE-2017-5689 Intel AMT empty-digest authentication bypass — management engine exposed (CVSS 9.8, KEV)
	CheckCVEDotNetNukeTraversal   CheckID = "cve.dnn_imagehandler_traversal"  // CVE-2017-0929 DotNetNuke DnnImageHandler path traversal → machineKey leak → RCE (CVSS 9.8)
	CheckCVEPrimefacesEL          CheckID = "cve.primefaces_el_injection"     // CVE-2017-1000486 Primefaces EL injection via default hardcoded secret key (CVSS 9.8)

	// ── Recent high-severity CVEs (2016) ──────────────────────────────────────
	CheckCVEShiroRememberMe      CheckID = "cve.shiro_remember_me"          // CVE-2016-4437 Apache Shiro remember-me deserialization — rememberMe=deleteMe oracle (CVSS 9.8, KEV)
	CheckCVEWebSphereConsole     CheckID = "cve.websphere_console_exposed"  // CVE-2016-5983 IBM WebSphere admin console exposed — deserialization RCE (CVSS 9.8)
	CheckCVESpringOAuthSpEL      CheckID = "cve.spring_oauth_spel"          // CVE-2016-4977 Spring Security OAuth2 SpEL injection via redirect_uri error page (CVSS 9.8)
	CheckCVEOXAppSuiteSSRF       CheckID = "cve.ox_appsuite_ssrf"           // CVE-2016-4047 Open-Xchange AppSuite SSRF via unvalidated proxy URL (CVSS 8.8)

	// ── Recent high-severity CVEs (2015) ──────────────────────────────────────
	CheckCVEJBossJMXInvoker            CheckID = "cve.jboss_jmx_invoker"           // CVE-2015-7501 JBoss JMXInvokerServlet pre-auth Java deserialization RCE (CVSS 9.8, KEV)
	CheckCVEIISHTTPSys                 CheckID = "cve.iis_httpsys_range"            // CVE-2015-1635 (MS15-034) IIS HTTP.sys Range header integer overflow → DoS/RCE (CVSS 10.0, KEV)
	CheckCVEElasticsearchGroovyRCE     CheckID = "cve.elasticsearch_groovy_rce"     // CVE-2015-1427 Elasticsearch ≤ 1.5.x Groovy sandbox escape → unauthenticated RCE (CVSS 10.0)
	CheckCVEJoomlaObjectInjection      CheckID = "cve.joomla_object_injection"      // CVE-2015-8562 Joomla 1.5–3.4.5 PHP object injection via HTTP User-Agent → RCE (CVSS 9.8, KEV)
)

// AI-driven adaptive recon — target profiling via Claude.
const (
	CheckAdaptiveReconProfile CheckID = "ai.target_profile" // AI-generated target profile with recommended modules + evasion tips
)

// Dynamic auth flow mutation — authfuzz scanner (Deep only).
const (
	CheckAuthFuzzStateBypass      CheckID = "authfuzz.state_bypass"       // OAuth state parameter not validated (CSRF on auth flow)
	CheckAuthFuzzCodeInterception CheckID = "authfuzz.code_interception"   // Authorization code accepted more than once (no invalidation)
	CheckAuthFuzzRedirectAbuse    CheckID = "authfuzz.redirect_uri_abuse"  // redirect_uri not strictly validated
	CheckAuthFuzzTokenSubstitution CheckID = "authfuzz.token_substitution" // Modified/unsigned JWT accepted on protected endpoint
	CheckSIWENonceReuse            CheckID = "authfuzz.siwe_nonce_reuse"   // SIWE nonce accepted more than once
	CheckSIWEChainBypass           CheckID = "authfuzz.siwe_chain_bypass"  // SIWE message accepted for wrong chain ID
	CheckSIWEReplayAttack          CheckID = "authfuzz.siwe_replay"        // SIWE expired/backdated message accepted
)

// Cross-asset correlation findings — generated by batch AI analysis.
// These are never emitted by individual scanners; only the batch analyze job produces them.
const (
	CheckCorrelationCICDToProd         CheckID = "correlation.cicd_to_prod_chain"
	CheckCorrelationAuthBypassViaProxy CheckID = "correlation.auth_bypass_via_proxy"
	CheckCorrelationStagingToProd      CheckID = "correlation.staging_to_prod_exposure"
	CheckCorrelationEmailPlusLogin     CheckID = "correlation.email_spoofing_plus_login"
	CheckCorrelationCredentialReuse    CheckID = "correlation.credential_reuse_across_assets"
	CheckCorrelationLateralMovement    CheckID = "correlation.lateral_movement_path"
	CheckCorrelationGeneric            CheckID = "correlation.attack_chain"

	// Terraform / IaC static analysis
	CheckTerraformS3BucketPublic       CheckID = "terraform.s3_bucket_public"
	CheckTerraformGCSBucketPublic      CheckID = "terraform.gcs_bucket_public"
	CheckTerraformGKEPublicEndpoint    CheckID = "terraform.gke_public_endpoint"
	CheckTerraformGKELegacyABAC       CheckID = "terraform.gke_legacy_abac"
	CheckTerraformGKENoNetworkPolicy   CheckID = "terraform.gke_no_network_policy"
	CheckTerraformRDSPublic            CheckID = "terraform.rds_publicly_accessible"
	CheckTerraformRDSUnencrypted       CheckID = "terraform.rds_unencrypted"
	CheckTerraformSGOpenIngress        CheckID = "terraform.sg_open_ingress"
	CheckTerraformIAMWildcardPolicy    CheckID = "terraform.iam_wildcard_policy"
	CheckTerraformIAMAdminPolicy       CheckID = "terraform.iam_admin_policy_attached"
	CheckTerraformSecretsInCode        CheckID = "terraform.secrets_in_code"
	CheckTerraformUnencryptedEBS       CheckID = "terraform.ebs_unencrypted"
	CheckTerraformIMDSv1Enabled        CheckID = "terraform.imdsv1_enabled"
	CheckTerraformPublicECRRepo        CheckID = "terraform.ecr_public_repo"
	CheckTerraformCloudFrontHTTP       CheckID = "terraform.cloudfront_http_allowed"
	CheckTerraformLBHTTP               CheckID = "terraform.lb_http_only"
	CheckTerraformTFStatePublic        CheckID = "terraform.tfstate_public_backend"

	// AI fingerprinting and cross-asset analysis
	CheckAIFPCrossAsset    CheckID = "aifp.cross_asset_finding"   // AI-identified cross-asset vulnerability
	CheckAIFPUnknownTech   CheckID = "aifp.unknown_technology"    // AI classified unknown tech — verify and review rule
)

// ScanMode indicates which scan mode a check requires.
//
// ModeSurface — safe without explicit permission. Makes only the kinds of
// requests a browser or DNS resolver would make: DNS lookups, TLS handshakes,
// standard HTTP GETs to known paths, queries to public third-party APIs.
// Legal in all reasonable jurisdictions without owner consent.
//
// ModeDeep — requires explicit written authorization from the asset owner
// (--permission-confirmed flag). Includes: active vulnerability probing,
// payload injection (XSS/SQLi/SSRF/path traversal), brute-force or
// credential attempts, aggressive cipher-suite negotiation (testssl.sh),
// and any check that could trigger WAF bans, rate limits, or log noise
// on the target system. Unauthorized use may violate:
//   - US:   Computer Fraud and Abuse Act (18 U.S.C. § 1030)
//   - UK:   Computer Misuse Act 1990
//   - EU:   Directive 2013/40/EU on attacks against information systems
//   - DE:   StGB §202a (data espionage), §202c (hacking tools/methods)
//   - AU:   Criminal Code Act 1995 Part 10.7
//   - CA:   Criminal Code R.S.C. 1985 s342.1
//   - JP:   Unauthorized Computer Access Law (不正アクセス禁止法)
//   - BR:   Lei nº 12.737/2012 (Lei Carolina Dieckmann)
//   - SG:   Computer Misuse Act (Cap. 50A)
//   - IN:   Information Technology Act 2000, s43/66
//   - and equivalent laws in other jurisdictions.
type ScanMode int

const (
	ModeSurface ScanMode = iota // no permission required — safe active HTTP/DNS
	ModeDeep                    // requires explicit written authorization
)

// CheckMeta holds metadata about a check used for display and mode gating.
type CheckMeta struct {
	CheckID         CheckID
	DefaultSeverity Severity
	Mode            ScanMode // ModeSurface or ModeDeep
}

// Registry maps CheckIDs to their metadata.
// Mode column: S = ModeSurface (no permission needed), D = ModeDeep (requires --permission-confirmed)
//
// Surface rationale: DNS lookups, standard TLS handshake, normal HTTP GETs to
// known paths, and queries to public third-party APIs are indistinguishable
// from what a browser, search engine crawler, or email server would do.
//
// Deep rationale: testssl.sh actively negotiates deprecated protocols and
// sends exploit-probe payloads; Nuclei active templates inject XSS/SQLi/SSRF
// payloads; credential testing attempts real logins; all of these constitute
// "unauthorized access" under CFAA/CMA/Directive 2013/40/EU and equivalents
// when run without explicit written owner consent.
var Registry = map[CheckID]CheckMeta{
	// Email — DNS TXT/MX lookups only → Surface
	CheckEmailSpoofable:          {CheckEmailSpoofable, SeverityCritical, ModeSurface},
	CheckEmailDMARCMissing:       {CheckEmailDMARCMissing, SeverityHigh, ModeSurface},
	CheckEmailDMARCPolicyNone:    {CheckEmailDMARCPolicyNone, SeverityHigh, ModeSurface},
	CheckEmailSPFMissing:         {CheckEmailSPFMissing, SeverityHigh, ModeSurface},
	CheckEmailSPFSoftfail:        {CheckEmailSPFSoftfail, SeverityMedium, ModeSurface},
	CheckEmailSPFLookupLimit:     {CheckEmailSPFLookupLimit, SeverityMedium, ModeSurface},
	CheckEmailDMARCSubdomainNone: {CheckEmailDMARCSubdomainNone, SeverityMedium, ModeSurface},
	CheckEmailDMARCNoReporting:   {CheckEmailDMARCNoReporting, SeverityLow, ModeSurface},
	CheckEmailDKIMMissing:        {CheckEmailDKIMMissing, SeverityMedium, ModeSurface},
	CheckEmailDKIMWeakKey:        {CheckEmailDKIMWeakKey, SeverityMedium, ModeSurface},
	CheckEmailMTASTSMissing:         {CheckEmailMTASTSMissing, SeverityLow, ModeSurface},
	CheckEmailMTASTSNotEnforced:     {CheckEmailMTASTSNotEnforced, SeverityMedium, ModeSurface},
	CheckEmailMTASTSPolicyFetchFail: {CheckEmailMTASTSPolicyFetchFail, SeverityMedium, ModeSurface},
	CheckEmailTLSRPTMissing:      {CheckEmailTLSRPTMissing, SeverityLow, ModeSurface},
	CheckEmailBIMIMissing:        {CheckEmailBIMIMissing, SeverityInfo, ModeSurface},
	CheckEmailDANEMissing:        {CheckEmailDANEMissing, SeverityLow, ModeSurface},
	CheckEmailSPFIncludes:        {CheckEmailSPFIncludes, SeverityInfo, ModeSurface},

	// TLS — cert observation via normal handshake → Surface
	// Protocol/cipher tests use testssl.sh which actively forces deprecated
	// handshakes and sends crypto-exploit probes → Deep
	CheckTLSCertExpiry7d:         {CheckTLSCertExpiry7d, SeverityCritical, ModeSurface},
	CheckTLSCertExpiry30d:        {CheckTLSCertExpiry30d, SeverityHigh, ModeSurface},
	CheckTLSCertSelfSigned:       {CheckTLSCertSelfSigned, SeverityHigh, ModeSurface},
	CheckTLSCertHostnameMismatch: {CheckTLSCertHostnameMismatch, SeverityHigh, ModeSurface},
	CheckTLSCertChainInvalid:     {CheckTLSCertChainInvalid, SeverityHigh, ModeSurface},
	CheckTLSProtocolSSLv2:        {CheckTLSProtocolSSLv2, SeverityCritical, ModeDeep},
	CheckTLSProtocolSSLv3:        {CheckTLSProtocolSSLv3, SeverityCritical, ModeDeep},
	CheckTLSProtocolTLS10:        {CheckTLSProtocolTLS10, SeverityHigh, ModeDeep},
	CheckTLSProtocolTLS11:        {CheckTLSProtocolTLS11, SeverityMedium, ModeDeep},
	CheckTLSWeakCipher:           {CheckTLSWeakCipher, SeverityHigh, ModeDeep},
	CheckTLSBEAST:                {CheckTLSBEAST, SeverityLow, ModeDeep},
	CheckTLSHeartbleed:           {CheckTLSHeartbleed, SeverityCritical, ModeDeep},
	CheckTLSPOODLE:               {CheckTLSPOODLE, SeverityHigh, ModeDeep},
	CheckTLSROBOT:                {CheckTLSROBOT, SeverityHigh, ModeDeep},
	CheckTLSCCSInjection:         {CheckTLSCCSInjection, SeverityHigh, ModeDeep},

	// New native TLS checks
	CheckTLSCertWeakKey:           {CheckTLSCertWeakKey, SeverityHigh, ModeSurface},
	CheckTLSCertWeakSignature:     {CheckTLSCertWeakSignature, SeverityHigh, ModeSurface},
	CheckTLSCertLongValidity:      {CheckTLSCertLongValidity, SeverityLow, ModeSurface},
	CheckTLSCertNoOCSP:            {CheckTLSCertNoOCSP, SeverityLow, ModeSurface},
	CheckTLSCertRevoked:           {CheckTLSCertRevoked, SeverityCritical, ModeSurface},
	CheckTLSCertNoSCT:             {CheckTLSCertNoSCT, SeverityLow, ModeSurface},
	CheckTLSNoPFS:                 {CheckTLSNoPFS, SeverityHigh, ModeSurface},
	CheckTLSNoTLS13:               {CheckTLSNoTLS13, SeverityLow, ModeSurface},
	CheckTLSCertWildcard:          {CheckTLSCertWildcard, SeverityInfo, ModeSurface},
	CheckTLSMixedContent:          {CheckTLSMixedContent, SeverityMedium, ModeSurface},
	CheckTLSNoSecureRenegotiation: {CheckTLSNoSecureRenegotiation, SeverityMedium, ModeSurface},
	CheckTLSCRLNoURL:              {CheckTLSCRLNoURL, SeverityInfo, ModeSurface},
	CheckTLSHSTSShortMaxAge:       {CheckTLSHSTSShortMaxAge, SeverityMedium, ModeSurface},
	CheckTLSHSTSNoSubdomains:      {CheckTLSHSTSNoSubdomains, SeverityLow, ModeSurface},
	CheckTLSHSTSNoPreload:         {CheckTLSHSTSNoPreload, SeverityInfo, ModeSurface},
	CheckTLSCertSANMissing:        {CheckTLSCertSANMissing, SeverityMedium, ModeSurface},

	// DNS — AXFR is an active zone-transfer probe, requires --permission-confirmed → Deep
	// Other DNS checks are passive queries → Surface
	CheckDNSAXFRAllowed:   {CheckDNSAXFRAllowed, SeverityCritical, ModeDeep},
	CheckDNSWildcard:      {CheckDNSWildcard, SeverityMedium, ModeSurface},
	CheckDNSDanglingCNAME: {CheckDNSDanglingCNAME, SeverityHigh, ModeSurface},
	CheckDNSMissingCAA:    {CheckDNSMissingCAA, SeverityLow, ModeSurface},
	CheckDNSDNSSECMissing: {CheckDNSDNSSECMissing, SeverityLow, ModeSurface},

	// Headers — single normal HTTP GET, reading response headers → Surface
	CheckHeadersMissingCSP:               {CheckHeadersMissingCSP, SeverityMedium, ModeSurface},
	CheckHeadersMissingHSTS:              {CheckHeadersMissingHSTS, SeverityMedium, ModeSurface},
	CheckHeadersMissingXFrameOptions:     {CheckHeadersMissingXFrameOptions, SeverityMedium, ModeSurface},
	CheckHeadersMissingXContentType:      {CheckHeadersMissingXContentType, SeverityLow, ModeSurface},
	CheckHeadersMissingReferrerPolicy:    {CheckHeadersMissingReferrerPolicy, SeverityLow, ModeSurface},
	CheckHeadersMissingPermissionsPolicy: {CheckHeadersMissingPermissionsPolicy, SeverityLow, ModeSurface},
	CheckHeadersServerInfoLeak:           {CheckHeadersServerInfoLeak, SeverityLow, ModeSurface},

	// Exposure — GET requests to well-known paths (same as any crawler) → Surface
	CheckExposureHTTPNoRedirect:   {CheckExposureHTTPNoRedirect, SeverityMedium, ModeSurface},
	CheckExposureStagingSubdomain: {CheckExposureStagingSubdomain, SeverityHigh, ModeSurface},
	CheckExposureAdminPath:        {CheckExposureAdminPath, SeverityHigh, ModeSurface},
	CheckExposureRobotsLeak:       {CheckExposureRobotsLeak, SeverityLow, ModeSurface},
	CheckExposureEnvFile:          {CheckExposureEnvFile, SeverityCritical, ModeSurface},
	CheckExposureGitExposed:       {CheckExposureGitExposed, SeverityCritical, ModeSurface},
	CheckExposureBackupFile:       {CheckExposureBackupFile, SeverityHigh, ModeSurface},
	CheckExposureAPIDocs:          {CheckExposureAPIDocs, SeverityMedium, ModeSurface},
	CheckExposureMonitoringPanel:  {CheckExposureMonitoringPanel, SeverityHigh, ModeSurface},
	CheckExposureCICDPanel:        {CheckExposureCICDPanel, SeverityHigh, ModeSurface},
	CheckExposureSpringActuator:   {CheckExposureSpringActuator, SeverityCritical, ModeSurface},
	CheckExposureCloudStorage:     {CheckExposureCloudStorage, SeverityCritical, ModeSurface},
	CheckExposureSensitiveFile:    {CheckExposureSensitiveFile, SeverityHigh, ModeSurface},
	CheckNucleiS3BucketExposed:    {CheckNucleiS3BucketExposed, SeverityCritical, ModeSurface},
	CheckNucleiMisconfiguredCORS:  {CheckNucleiMisconfiguredCORS, SeverityMedium, ModeSurface},
	CheckNucleiStaleTemplates:     {CheckNucleiStaleTemplates, SeverityMedium, ModeSurface},

	// Subdomain takeover — DNS observation only → Surface
	CheckSubdomainTakeover: {CheckSubdomainTakeover, SeverityCritical, ModeSurface},
	// Typosquat — DNS lookups only → Surface
	CheckDomainTyposquat:   {CheckDomainTyposquat, SeverityHigh, ModeSurface},

	// Web — passive fingerprinting from normal responses → Surface
	// Active payload injection (XSS/SQLi/SSRF/traversal) and credential
	// attempts constitute unauthorized access without consent → Deep
	CheckWebTechDetected:       {CheckWebTechDetected, SeverityInfo, ModeSurface},
	CheckWebOutdatedSoftware:   {CheckWebOutdatedSoftware, SeverityHigh, ModeSurface},
	CheckWebDebugEndpoint:      {CheckWebDebugEndpoint, SeverityHigh, ModeSurface},
	CheckWebErrorInfoLeak:      {CheckWebErrorInfoLeak, SeverityMedium, ModeSurface},
	CheckWebXSS:                {CheckWebXSS, SeverityHigh, ModeDeep},
	CheckWebSQLi:               {CheckWebSQLi, SeverityCritical, ModeDeep},
	CheckWebOpenRedirect:       {CheckWebOpenRedirect, SeverityMedium, ModeDeep},
	CheckWebSSRF:               {CheckWebSSRF, SeverityCritical, ModeDeep},
	CheckWebPathTraversal:      {CheckWebPathTraversal, SeverityHigh, ModeDeep},
	CheckWebDefaultCredentials:   {CheckWebDefaultCredentials, SeverityCritical, ModeDeep},
	CheckWebHTTPRequestSmuggling:   {CheckWebHTTPRequestSmuggling, SeverityHigh, ModeDeep},
	CheckWebDangerousMethodEnabled: {CheckWebDangerousMethodEnabled, SeverityMedium, ModeSurface},
	CheckSecretInResponseHeader:    {CheckSecretInResponseHeader, SeverityHigh, ModeSurface},

	// Asset Intelligence — queries external public APIs, no target contact → Surface
	CheckAssetReverseIP:      {CheckAssetReverseIP, SeverityInfo, ModeSurface},
	CheckAssetOrgDomains:     {CheckAssetOrgDomains, SeverityInfo, ModeSurface},
	CheckAssetASNRanges:      {CheckAssetASNRanges, SeverityInfo, ModeSurface},
	CheckAssetPassiveDNS:     {CheckAssetPassiveDNS, SeverityInfo, ModeSurface},
	CheckAssetHistoricalURLs: {CheckAssetHistoricalURLs, SeverityInfo, ModeSurface},
	CheckAssetCrawlEndpoints: {CheckAssetCrawlEndpoints, SeverityInfo, ModeSurface},
	CheckAssetScreenshot:     {CheckAssetScreenshot, SeverityInfo, ModeSurface},

	// WHOIS / RDAP — queries public registry servers → Surface
	CheckWHOISDomainExpiry7d:  {CheckWHOISDomainExpiry7d, SeverityCritical, ModeSurface},
	CheckWHOISDomainExpiry30d: {CheckWHOISDomainExpiry30d, SeverityHigh, ModeSurface},
	CheckWHOISDomainInfo:      {CheckWHOISDomainInfo, SeverityInfo, ModeSurface},

	// Cloud Buckets — HTTP GET/PUT probes to public cloud storage URLs → Surface
	CheckCloudBucketPublic:   {CheckCloudBucketPublic, SeverityCritical, ModeSurface},
	CheckCloudBucketExists:   {CheckCloudBucketExists, SeverityInfo, ModeSurface},
	CheckCloudBucketWritable: {CheckCloudBucketWritable, SeverityCritical, ModeSurface},

	// Web Content — fetching public JS/HTML and reading response cookies → Surface
	CheckJSHardcodedSecret:     {CheckJSHardcodedSecret, SeverityCritical, ModeSurface},
	CheckJSInternalEndpoint:    {CheckJSInternalEndpoint, SeverityMedium, ModeSurface},
	CheckJSSourceMapExposed:    {CheckJSSourceMapExposed, SeverityMedium, ModeSurface},
	CheckCookieMissingSecure:   {CheckCookieMissingSecure, SeverityMedium, ModeSurface},
	CheckCookieMissingHTTPOnly: {CheckCookieMissingHTTPOnly, SeverityMedium, ModeSurface},
	CheckCookieMissingSameSite: {CheckCookieMissingSameSite, SeverityLow, ModeSurface},
	CheckCSPUnsafeInline:       {CheckCSPUnsafeInline, SeverityMedium, ModeSurface},
	CheckCSPUnsafeEval:         {CheckCSPUnsafeEval, SeverityMedium, ModeSurface},
	CheckCSPWildcardSource:     {CheckCSPWildcardSource, SeverityHigh, ModeSurface},
	CheckWAFNotDetected:     {CheckWAFNotDetected, SeverityMedium, ModeSurface},
	CheckWAFDetected:        {CheckWAFDetected, SeverityInfo, ModeSurface},
	CheckWAFOriginExposed:   {CheckWAFOriginExposed, SeverityCritical, ModeSurface},
	CheckWAFBypassHeader:    {CheckWAFBypassHeader, SeverityHigh, ModeDeep},
	CheckWAFInsecureMode:    {CheckWAFInsecureMode, SeverityHigh, ModeSurface},
	CheckIDSDetected:        {CheckIDSDetected, SeverityInfo, ModeSurface},

	// DLP — scanning public HTTP responses and screenshots → Surface
	// All checks observe only what is already publicly accessible.
	CheckDLPSSN:        {CheckDLPSSN, SeverityCritical, ModeSurface},
	CheckDLPCreditCard: {CheckDLPCreditCard, SeverityCritical, ModeSurface},
	CheckDLPDatabaseURL: {CheckDLPDatabaseURL, SeverityCritical, ModeSurface},
	CheckDLPPrivateKey: {CheckDLPPrivateKey, SeverityCritical, ModeSurface},
	CheckDLPAPIKey:     {CheckDLPAPIKey, SeverityCritical, ModeSurface},
	CheckDLPEmailList:  {CheckDLPEmailList, SeverityHigh, ModeSurface},
	CheckDLPVision:       {CheckDLPVision, SeverityHigh, ModeSurface},
	CheckVisionServiceID: {CheckVisionServiceID, SeverityInfo, ModeSurface},

	// Dirbusting — active path enumeration requires explicit owner consent → Deep
	CheckDirbustFound:      {CheckDirbustFound, SeverityHigh, ModeDeep},
	CheckDirbustWAFBlocked: {CheckDirbustWAFBlocked, SeverityMedium, ModeDeep},

	// Port scan — TCP connect to detect open services → Surface
	CheckPortRedisUnauth:         {CheckPortRedisUnauth, SeverityCritical, ModeSurface},
	CheckPortElasticsearchUnauth: {CheckPortElasticsearchUnauth, SeverityCritical, ModeSurface},
	CheckPortPrometheusUnauth:    {CheckPortPrometheusUnauth, SeverityCritical, ModeSurface},
	CheckPortDockerUnauth:        {CheckPortDockerUnauth, SeverityCritical, ModeSurface},
	CheckPortKubeletUnauth:       {CheckPortKubeletUnauth, SeverityCritical, ModeSurface},
	CheckPortMemcachedUnauth:     {CheckPortMemcachedUnauth, SeverityHigh, ModeSurface},
	CheckPortJupyterExposed:      {CheckPortJupyterExposed, SeverityHigh, ModeSurface},
	CheckPortCouchDBUnauth:       {CheckPortCouchDBUnauth, SeverityHigh, ModeSurface},
	CheckPortSSHExposed:          {CheckPortSSHExposed, SeverityMedium, ModeSurface},
	CheckPortRDPExposed:          {CheckPortRDPExposed, SeverityCritical, ModeSurface},
	CheckPortVNCExposed:          {CheckPortVNCExposed, SeverityCritical, ModeSurface},
	CheckPortTelnetExposed:       {CheckPortTelnetExposed, SeverityHigh, ModeSurface},
	CheckPortFTPExposed:          {CheckPortFTPExposed, SeverityMedium, ModeSurface},
	CheckPortFTPAnonymous:        {CheckPortFTPAnonymous, SeverityHigh, ModeSurface},
	CheckPortFTPVsftpdBackdoor:   {CheckPortFTPVsftpdBackdoor, SeverityCritical, ModeSurface},
	CheckPortSMBExposed:          {CheckPortSMBExposed, SeverityHigh, ModeSurface},
	CheckPortSMBNullSession:      {CheckPortSMBNullSession, SeverityCritical, ModeSurface},
	CheckPortSMBv1Enabled:        {CheckPortSMBv1Enabled, SeverityCritical, ModeSurface},
	CheckPortDatabaseExposed:     {CheckPortDatabaseExposed, SeverityHigh, ModeSurface},
	CheckPortK8sAPIExposed:       {CheckPortK8sAPIExposed, SeverityCritical, ModeSurface},
	CheckPortWinRMExposed:        {CheckPortWinRMExposed, SeverityHigh, ModeSurface},
	CheckPortAMQPExposed:         {CheckPortAMQPExposed, SeverityHigh, ModeSurface},
	CheckPortKafkaExposed:        {CheckPortKafkaExposed, SeverityHigh, ModeSurface},
	CheckPortZooKeeperExposed:    {CheckPortZooKeeperExposed, SeverityHigh, ModeSurface},
	CheckPortInfluxDBExposed:     {CheckPortInfluxDBExposed, SeverityHigh, ModeSurface},
	CheckPortSplunkMgmtExposed:   {CheckPortSplunkMgmtExposed, SeverityHigh, ModeSurface},

	// GraphQL — Surface: introspection query; Deep: batch + persisted query probes
	CheckGraphQLIntrospection:        {CheckGraphQLIntrospection, SeverityMedium, ModeSurface},
	CheckGraphQLBatchQuery:            {CheckGraphQLBatchQuery, SeverityMedium, ModeDeep},
	CheckGraphQLPersistedQueryBypass:  {CheckGraphQLPersistedQueryBypass, SeverityMedium, ModeDeep},

	// Email SMTP — connecting to the published MX server is what any mail agent does → Surface
	CheckEmailSMTPOpenRelay:  {CheckEmailSMTPOpenRelay, SeverityCritical, ModeSurface},
	CheckEmailSMTPBannerLeak: {CheckEmailSMTPBannerLeak, SeverityLow, ModeSurface},

	// Version currency — passively observed from HTTP Server header and service banners → Surface
	CheckVersionOutdated: {CheckVersionOutdated, SeverityHigh, ModeSurface},

	// DNS Intelligence — passive DNS queries only → Surface
	CheckDNSTXTHarvest: {CheckDNSTXTHarvest, SeverityInfo, ModeSurface},
	CheckDNSNSRecords:  {CheckDNSNSRecords, SeverityInfo, ModeSurface},

	// TLS Fingerprinting — standard TLS handshake only → Surface
	CheckTLSJARM: {CheckTLSJARM, SeverityInfo, ModeSurface},

	// Shodan — passive public API query → Surface
	CheckShodanHostInfo: {CheckShodanHostInfo, SeverityInfo, ModeSurface},

	// Virtual host discovery — HTTP request with different Host: header → Surface
	CheckVHostFound: {CheckVHostFound, SeverityInfo, ModeSurface},

	// CDN bypass → Surface
	CheckCDNOriginFound: {CheckCDNOriginFound, SeverityHigh, ModeSurface},

	// ASN IP range probing → Surface
	CheckASNIPService: {CheckASNIPService, SeverityInfo, ModeSurface},
	CheckPTRRecord:    {CheckPTRRecord, SeverityInfo, ModeSurface},

	// Multi-service per-port → Surface
	CheckPortServiceDiscovered: {CheckPortServiceDiscovered, SeverityInfo, ModeSurface},

	// Host header injection → Deep
	CheckHostHeaderInjection: {CheckHostHeaderInjection, SeverityHigh, ModeDeep},

	// JWT → Surface (observation only)
	CheckJWTWeakAlg:         {CheckJWTWeakAlg, SeverityCritical, ModeSurface},
	CheckJWTLongExpiry:       {CheckJWTLongExpiry, SeverityMedium, ModeSurface},
	CheckJWTSensitivePayload: {CheckJWTSensitivePayload, SeverityHigh, ModeSurface},

	// HIBP → Surface
	CheckHIBPBreach: {CheckHIBPBreach, SeverityHigh, ModeSurface},

	// theHarvester OSINT → Surface
	CheckHarvesterEmails:      {CheckHarvesterEmails, SeverityMedium, ModeSurface},
	CheckHarvesterSubdomains:  {CheckHarvesterSubdomains, SeverityInfo, ModeSurface},
	CheckHarvesterUnavailable: {CheckHarvesterUnavailable, SeverityInfo, ModeSurface},

	// CORS → Deep
	CheckCORSMisconfiguration: {CheckCORSMisconfiguration, SeverityCritical, ModeDeep},

	// Bing dorks → Surface
	CheckBingDorkExposure: {CheckBingDorkExposure, SeverityHigh, ModeSurface},

	// CMS plugins → Surface
	CheckCMSPluginFound:      {CheckCMSPluginFound, SeverityInfo, ModeSurface},
	CheckCMSPluginVulnerable: {CheckCMSPluginVulnerable, SeverityHigh, ModeSurface},

	// Dependency confusion → Surface
	CheckDependencyConfusion: {CheckDependencyConfusion, SeverityCritical, ModeSurface},

	// URLScan.io → Surface
	CheckURLScanFindings: {CheckURLScanFindings, SeverityInfo, ModeSurface},

	// API rate limiting → Deep
	CheckRateLimitMissing:      {CheckRateLimitMissing, SeverityHigh, ModeDeep},
	CheckRateLimitBypass:       {CheckRateLimitBypass, SeverityHigh, ModeDeep},
	CheckRateLimitNoRetryAfter: {CheckRateLimitNoRetryAfter, SeverityInfo, ModeDeep},

	// OAuth / OIDC → Deep
	CheckOAuthMissingState:     {CheckOAuthMissingState, SeverityHigh, ModeDeep},
	CheckOAuthMissingPKCE:      {CheckOAuthMissingPKCE, SeverityMedium, ModeDeep},
	CheckOAuthOpenRedirect:     {CheckOAuthOpenRedirect, SeverityCritical, ModeDeep},
	CheckOAuthTokenLeakReferer: {CheckOAuthTokenLeakReferer, SeverityHigh, ModeDeep},
	CheckJWKSExposed:           {CheckJWKSExposed, SeverityInfo, ModeSurface},
	CheckOIDCImplicitFlow:      {CheckOIDCImplicitFlow, SeverityMedium, ModeSurface},
	CheckJWTNoVerification:     {CheckJWTNoVerification, SeverityCritical, ModeDeep},

	// GitHub / CI — queries public GitHub API and reads public repo content → Surface
	// Credential/secret scanning is passive (reading committed content) → Surface
	CheckGitHubPublicRepos:    {CheckGitHubPublicRepos, SeverityInfo, ModeSurface},
	CheckGitHubTrackedEnvFile: {CheckGitHubTrackedEnvFile, SeverityCritical, ModeSurface},
	CheckCICDUnpinnedAction:   {CheckCICDUnpinnedAction, SeverityHigh, ModeSurface},
	CheckCICDScriptInjection:  {CheckCICDScriptInjection, SeverityCritical, ModeSurface},
	CheckCICDPwnRequest:       {CheckCICDPwnRequest, SeverityCritical, ModeSurface},
	CheckCICDBroadPermissions: {CheckCICDBroadPermissions, SeverityHigh, ModeSurface},
	CheckSecretsAPIKey:        {CheckSecretsAPIKey, SeverityCritical, ModeSurface},

	// GitHub Actions — gaps
	CheckGHActionWorkflowRunUnsafe:     {CheckGHActionWorkflowRunUnsafe, SeverityCritical, ModeSurface},
	CheckGHActionGitHubEnvInjection:    {CheckGHActionGitHubEnvInjection, SeverityHigh, ModeSurface},
	CheckGHActionSecretsInherit:        {CheckGHActionSecretsInherit, SeverityMedium, ModeSurface},
	CheckGHActionInsecureCommands:      {CheckGHActionInsecureCommands, SeverityHigh, ModeSurface},
	CheckGHActionBotConditionSpoofable: {CheckGHActionBotConditionSpoofable, SeverityMedium, ModeSurface},
	CheckGHActionArtiPacked:                 {CheckGHActionArtiPacked, SeverityHigh, ModeSurface},
	CheckGHActionCachePoisoning:             {CheckGHActionCachePoisoning, SeverityHigh, ModeSurface},
	CheckGHActionUnsignedRelease:            {CheckGHActionUnsignedRelease, SeverityMedium, ModeSurface},
	CheckGHActionReusableWorkflowUnpinned:   {CheckGHActionReusableWorkflowUnpinned, SeverityMedium, ModeSurface},
	CheckGHActionWorkflowDispatchInjection:  {CheckGHActionWorkflowDispatchInjection, SeverityCritical, ModeSurface},
	CheckGHActionKnownCompromised:           {CheckGHActionKnownCompromised, SeverityCritical, ModeSurface},
	// GitHub Actions — CI/CD safety bypass
	CheckGHActionIssueCommentUnsafe:       {CheckGHActionIssueCommentUnsafe, SeverityCritical, ModeSurface},
	CheckGHActionAutoMerge:               {CheckGHActionAutoMerge, SeverityCritical, ModeSurface},
	CheckGHActionAutoApprove:             {CheckGHActionAutoApprove, SeverityHigh, ModeSurface},
	CheckGHActionScheduledWrite:          {CheckGHActionScheduledWrite, SeverityHigh, ModeSurface},
	CheckGHActionMissingJobTimeout:       {CheckGHActionMissingJobTimeout, SeverityMedium, ModeSurface},
	CheckGHActionContinueOnErrorSecurity: {CheckGHActionContinueOnErrorSecurity, SeverityMedium, ModeSurface},
	CheckGHActionDeployTargets:           {CheckGHActionDeployTargets, SeverityInfo, ModeSurface},
	CheckGHActionRepoDiscovered:          {CheckGHActionRepoDiscovered, SeverityInfo, ModeSurface},
	// GitHub repo hardening
	CheckGitHubNoCodeowners:    {CheckGitHubNoCodeowners, SeverityMedium, ModeSurface},
	CheckGitHubNoTagProtection: {CheckGitHubNoTagProtection, SeverityMedium, ModeSurface},
	CheckGitHubNoEnvProtection: {CheckGitHubNoEnvProtection, SeverityHigh, ModeSurface},
	// GitHub Actions — OIDC
	CheckGHActionAWSLongLivedKey:       {CheckGHActionAWSLongLivedKey, SeverityHigh, ModeSurface},
	CheckGHActionGCPServiceAccountKey:  {CheckGHActionGCPServiceAccountKey, SeverityHigh, ModeSurface},
	CheckGHActionAzureCredentials:      {CheckGHActionAzureCredentials, SeverityHigh, ModeSurface},
	CheckGHActionNPMTokenNotOIDC:       {CheckGHActionNPMTokenNotOIDC, SeverityMedium, ModeSurface},
	CheckGHActionPyPITokenNotTrusted:   {CheckGHActionPyPITokenNotTrusted, SeverityMedium, ModeSurface},
	CheckGHActionDockerPasswordSecret:  {CheckGHActionDockerPasswordSecret, SeverityMedium, ModeSurface},
	CheckGHActionVercelToken:           {CheckGHActionVercelToken, SeverityMedium, ModeSurface},
	CheckGHActionTerraformCloudToken:   {CheckGHActionTerraformCloudToken, SeverityMedium, ModeSurface},
	CheckGHActionFlyToken:              {CheckGHActionFlyToken, SeverityMedium, ModeSurface},
	CheckGHActionPATUsedInWorkflow:     {CheckGHActionPATUsedInWorkflow, SeverityMedium, ModeSurface},
	// GitHub repo config
	CheckGitHubNoBranchProtection:     {CheckGitHubNoBranchProtection, SeverityHigh, ModeSurface},
	CheckGitHubNoSecretScanning:       {CheckGitHubNoSecretScanning, SeverityHigh, ModeSurface},
	CheckGitHubNoDependabot:           {CheckGitHubNoDependabot, SeverityMedium, ModeSurface},
	CheckGitHubNoSAST:                 {CheckGitHubNoSAST, SeverityMedium, ModeSurface},
	CheckGitHubNoVulnAlerts:           {CheckGitHubNoVulnAlerts, SeverityMedium, ModeSurface},
	CheckGitHubForkWorkflowApproval:   {CheckGitHubForkWorkflowApproval, SeverityHigh, ModeSurface},
	CheckGitHubDefaultTokenWrite:      {CheckGitHubDefaultTokenWrite, SeverityHigh, ModeSurface},
	CheckGitHubActionsUnrestricted:    {CheckGitHubActionsUnrestricted, SeverityMedium, ModeSurface},
	CheckGitHubWebhookNoSecret:        {CheckGitHubWebhookNoSecret, SeverityHigh, ModeSurface},
	CheckGitHubOrgMFANotRequired:      {CheckGitHubOrgMFANotRequired, SeverityCritical, ModeSurface},
	CheckGitHubNoPushProtection:       {CheckGitHubNoPushProtection, SeverityHigh, ModeSurface},
	CheckGitHubNoSignedCommits:        {CheckGitHubNoSignedCommits, SeverityLow, ModeSurface},
	CheckGitHubNoRequiredStatusChecks: {CheckGitHubNoRequiredStatusChecks, SeverityMedium, ModeSurface},
	CheckGitHubNoDependencyReview:     {CheckGitHubNoDependencyReview, SeverityMedium, ModeSurface},
	// GitHub secret leaks
	CheckGitHubSecretInCode:           {CheckGitHubSecretInCode, SeverityCritical, ModeSurface},
	CheckGitHubPrivateKeyInRepo:       {CheckGitHubPrivateKeyInRepo, SeverityCritical, ModeSurface},

	// nmap — service version fingerprinting (surface) and NSE vuln scripts (deep)
	CheckNmapServiceVersion: {CheckNmapServiceVersion, SeverityInfo, ModeSurface},
	CheckNmapVulnScript:     {CheckNmapVulnScript, SeverityCritical, ModeDeep},
	CheckNmapSNMPExposed:    {CheckNmapSNMPExposed, SeverityHigh, ModeSurface},
	CheckNmapDNSRecursion:   {CheckNmapDNSRecursion, SeverityMedium, ModeSurface},
	CheckNmapFTPAnonymous:   {CheckNmapFTPAnonymous, SeverityHigh, ModeSurface},
	CheckNmapSSHAlgorithms:  {CheckNmapSSHAlgorithms, SeverityMedium, ModeSurface},

	// Non-HTTP protocol exposure
	CheckPortMQTTExposed:    {CheckPortMQTTExposed, SeverityHigh, ModeSurface},
	CheckPortSIPExposed:     {CheckPortSIPExposed, SeverityMedium, ModeSurface},
	CheckPortRTSPExposed:    {CheckPortRTSPExposed, SeverityMedium, ModeSurface},
	CheckPortIPPExposed:     {CheckPortIPPExposed, SeverityMedium, ModeSurface},
	CheckPortISCSIExposed:   {CheckPortISCSIExposed, SeverityHigh, ModeSurface},
	CheckPortModbusExposed:  {CheckPortModbusExposed, SeverityCritical, ModeSurface},
	CheckPortNetconfExposed: {CheckPortNetconfExposed, SeverityHigh, ModeSurface},
	CheckPortWinboxExposed:  {CheckPortWinboxExposed, SeverityHigh, ModeSurface},

	// Network device vendor identification (Info findings)
	CheckNetDeviceCiscoDetected:    {CheckNetDeviceCiscoDetected, SeverityInfo, ModeSurface},
	CheckNetDeviceJuniperDetected:  {CheckNetDeviceJuniperDetected, SeverityInfo, ModeSurface},
	CheckNetDeviceMikroTikDetected: {CheckNetDeviceMikroTikDetected, SeverityInfo, ModeSurface},
	CheckNetDeviceUbiquitiDetected: {CheckNetDeviceUbiquitiDetected, SeverityInfo, ModeSurface},
	CheckNetDeviceFortinetDetected: {CheckNetDeviceFortinetDetected, SeverityInfo, ModeSurface},
	CheckNetDevicePaloAltoDetected: {CheckNetDevicePaloAltoDetected, SeverityInfo, ModeSurface},
	CheckNetDeviceHuaweiDetected:   {CheckNetDeviceHuaweiDetected, SeverityInfo, ModeSurface},
	CheckNetDeviceBMCExposed:       {CheckNetDeviceBMCExposed, SeverityHigh, ModeSurface},
	CheckCVEErlangOTPSSH:           {CheckCVEErlangOTPSSH, SeverityCritical, ModeSurface},
	CheckCVEVeeamBackupExposed:     {CheckCVEVeeamBackupExposed, SeverityCritical, ModeSurface},
	CheckPortDevServerExposed:      {CheckPortDevServerExposed, SeverityHigh, ModeSurface},
	CheckPortGradioExposed:         {CheckPortGradioExposed, SeverityHigh, ModeSurface},
	CheckPortWebminExposed:         {CheckPortWebminExposed, SeverityHigh, ModeSurface},
	CheckPortWazuhAPIExposed:       {CheckPortWazuhAPIExposed, SeverityHigh, ModeSurface},
	CheckNetDeviceF5Detected:       {CheckNetDeviceF5Detected, SeverityInfo, ModeSurface},
	CheckNetDeviceSonicWallDetected: {CheckNetDeviceSonicWallDetected, SeverityInfo, ModeSurface},
	CheckNetDeviceCheckPointDetected: {CheckNetDeviceCheckPointDetected, SeverityInfo, ModeSurface},
	CheckNetDeviceHPArubaDetected:  {CheckNetDeviceHPArubaDetected, SeverityInfo, ModeSurface},
	CheckNetDeviceTPLinkDetected:   {CheckNetDeviceTPLinkDetected, SeverityInfo, ModeSurface},
	CheckNetDeviceDLinkDetected:    {CheckNetDeviceDLinkDetected, SeverityInfo, ModeSurface},
	CheckNetDeviceNetgearDetected:  {CheckNetDeviceNetgearDetected, SeverityInfo, ModeSurface},
	CheckNetDeviceAsteriskDetected: {CheckNetDeviceAsteriskDetected, SeverityInfo, ModeSurface},
	CheckPortS7CommExposed:         {CheckPortS7CommExposed, SeverityCritical, ModeSurface},
	CheckPortEtherNetIPExposed:     {CheckPortEtherNetIPExposed, SeverityCritical, ModeSurface},
	CheckPortDNP3Exposed:           {CheckPortDNP3Exposed, SeverityCritical, ModeSurface},
	CheckPortBACnetExposed:         {CheckPortBACnetExposed, SeverityHigh, ModeSurface},
	CheckPortAsteriskAMIExposed:    {CheckPortAsteriskAMIExposed, SeverityHigh, ModeSurface},
	CheckPortJetDirectExposed:      {CheckPortJetDirectExposed, SeverityMedium, ModeSurface},
	CheckPortMikroTikAPIExposed:    {CheckPortMikroTikAPIExposed, SeverityHigh, ModeSurface},
	CheckPortCheckPointExposed:     {CheckPortCheckPointExposed, SeverityHigh, ModeSurface},

	// Email / messaging server exposure
	CheckPortSMTPExposed:           {CheckPortSMTPExposed, SeverityMedium, ModeSurface},
	CheckPortIMAPExposed:           {CheckPortIMAPExposed, SeverityMedium, ModeSurface},
	CheckPortPOP3Exposed:           {CheckPortPOP3Exposed, SeverityMedium, ModeSurface},
	CheckPortSMTPOpenRelay:         {CheckPortSMTPOpenRelay, SeverityHigh, ModeSurface},
	CheckPortExImVulnerable:        {CheckPortExImVulnerable, SeverityCritical, ModeSurface},

	// Directory services and identity infrastructure
	CheckPortLDAPExposed:            {CheckPortLDAPExposed, SeverityHigh, ModeSurface},
	CheckPortActiveDirectoryExposed: {CheckPortActiveDirectoryExposed, SeverityCritical, ModeSurface},
	CheckPortKerberosExposed:        {CheckPortKerberosExposed, SeverityHigh, ModeSurface},
	CheckPortGlobalCatalogExposed:   {CheckPortGlobalCatalogExposed, SeverityHigh, ModeSurface},

	// Erlang/OTP ecosystem
	CheckPortEPMDExposed: {CheckPortEPMDExposed, SeverityHigh, ModeSurface},

	// DNS server exposure
	CheckPortDNSOpenResolver:   {CheckPortDNSOpenResolver, SeverityMedium, ModeSurface},
	CheckPortDNSVersionExposed: {CheckPortDNSVersionExposed, SeverityLow, ModeSurface},

	// WINS / NetBIOS
	CheckPortWINSExposed: {CheckPortWINSExposed, SeverityHigh, ModeSurface},

	// NFS / RPC
	CheckPortRPCBindExposed:    {CheckPortRPCBindExposed, SeverityMedium, ModeSurface},
	CheckPortNFSExportsExposed: {CheckPortNFSExportsExposed, SeverityHigh, ModeSurface},

	// SNMP default credentials
	CheckPortSNMPPublicCommunity:   {CheckPortSNMPPublicCommunity, SeverityHigh, ModeSurface},
	CheckPortSNMPWritableCommunity: {CheckPortSNMPWritableCommunity, SeverityCritical, ModeSurface},

	// Jenkins — active Groovy payload probe → Deep
	CheckJenkinsGroovyRCE: {CheckJenkinsGroovyRCE, SeverityCritical, ModeDeep},

	// CVE-specific active detection — single HTTP probe, no payloads, surface-safe
	CheckCVEN8nRCE:                 {CheckCVEN8nRCE, SeverityCritical, ModeSurface},
	CheckCVECraftCMSRCE:            {CheckCVECraftCMSRCE, SeverityCritical, ModeSurface},
	CheckCVELivewireRCE:            {CheckCVELivewireRCE, SeverityCritical, ModeSurface},
	CheckCVEBeyondTrustRCE:         {CheckCVEBeyondTrustRCE, SeverityCritical, ModeSurface},
	CheckCVENginxUIBackup:          {CheckCVENginxUIBackup, SeverityCritical, ModeSurface},
	CheckCVESolarWindsWHD:          {CheckCVESolarWindsWHD, SeverityCritical, ModeSurface},
	CheckCVEIvantiEPMAuthBypass:    {CheckCVEIvantiEPMAuthBypass, SeverityCritical, ModeSurface},
	CheckCVELangflowRCE:            {CheckCVELangflowRCE, SeverityCritical, ModeSurface},
	CheckCVEOmnissaSSRF:            {CheckCVEOmnissaSSRF, SeverityHigh, ModeSurface},
	CheckPortJuniperAnomalyExposed: {CheckPortJuniperAnomalyExposed, SeverityCritical, ModeSurface},
	CheckPortTelnetdVulnerable:     {CheckPortTelnetdVulnerable, SeverityCritical, ModeSurface},
	CheckCVETelnetBSDEncrypt:       {CheckCVETelnetBSDEncrypt, SeverityCritical, ModeSurface},
	CheckPortOllamaExposed:         {CheckPortOllamaExposed, SeverityHigh, ModeSurface},
	CheckCVEIvantiEPMMRCE:          {CheckCVEIvantiEPMMRCE, SeverityCritical, ModeSurface},
	CheckCVECiscoFMCRCE:            {CheckCVECiscoFMCRCE, SeverityCritical, ModeSurface},
	CheckCVEHPEOneViewRCE:          {CheckCVEHPEOneViewRCE, SeverityCritical, ModeSurface},
	CheckCVECitrixBleed2:           {CheckCVECitrixBleed2, SeverityCritical, ModeSurface},
	CheckCVEFortiOSSSOBypass:       {CheckCVEFortiOSSSOBypass, SeverityCritical, ModeSurface},
	CheckCVEFortiWebAuthBypass:     {CheckCVEFortiWebAuthBypass, SeverityCritical, ModeSurface},
	CheckCVECiscoASARCE:            {CheckCVECiscoASARCE, SeverityCritical, ModeSurface},
	CheckCVEMCPServerExposed:          {CheckCVEMCPServerExposed, SeverityHigh, ModeSurface},
	CheckCVENextJSMiddlewareBypass:    {CheckCVENextJSMiddlewareBypass, SeverityCritical, ModeSurface},
	CheckCVEViteFileRead:              {CheckCVEViteFileRead, SeverityCritical, ModeSurface},
	CheckCVEIngressNightmare:          {CheckCVEIngressNightmare, SeverityCritical, ModeSurface},
	CheckCVETomcatPartialPUT:          {CheckCVETomcatPartialPUT, SeverityCritical, ModeDeep},
	CheckCVEOpenSSHRegreSSHion:        {CheckCVEOpenSSHRegreSSHion, SeverityHigh, ModeSurface},
	CheckCVEJenkinsCLIFileRead:        {CheckCVEJenkinsCLIFileRead, SeverityCritical, ModeSurface},
	CheckCVEScreenConnectBypass:       {CheckCVEScreenConnectBypass, SeverityCritical, ModeSurface},
	CheckCVETeamCityAuthBypass:        {CheckCVETeamCityAuthBypass, SeverityCritical, ModeSurface},
	CheckCVEFortiManagerJump:          {CheckCVEFortiManagerJump, SeverityCritical, ModeSurface},
	CheckCVEPHPCGIArgInjection:        {CheckCVEPHPCGIArgInjection, SeverityCritical, ModeSurface},
	CheckCVEExpeditionRCE:             {CheckCVEExpeditionRCE, SeverityCritical, ModeSurface},
	CheckCVEFortiOSSSLVPN:             {CheckCVEFortiOSSSLVPN, SeverityCritical, ModeSurface},
	CheckCVECheckPointFileRead:        {CheckCVECheckPointFileRead, SeverityHigh, ModeSurface},

	// 2023 CVEs
	CheckCVEOwnCloudPhpInfo:     {CheckCVEOwnCloudPhpInfo, SeverityCritical, ModeSurface},
	CheckCVEMOVEitWebShell:      {CheckCVEMOVEitWebShell, SeverityCritical, ModeSurface},
	CheckCVEConfluenceSetup:     {CheckCVEConfluenceSetup, SeverityCritical, ModeSurface},
	CheckCVEConfluenceRestore:   {CheckCVEConfluenceRestore, SeverityCritical, ModeSurface},
	CheckCVECiscoIOSXEImplant:   {CheckCVECiscoIOSXEImplant, SeverityCritical, ModeSurface},
	CheckCVEIvantiConnectSecure: {CheckCVEIvantiConnectSecure, SeverityCritical, ModeSurface},
	CheckCVECitrixBleed:         {CheckCVECitrixBleed, SeverityCritical, ModeSurface},
	CheckCVEJuniperJWeb:         {CheckCVEJuniperJWeb, SeverityCritical, ModeSurface},
	CheckCVESysAid:              {CheckCVESysAid, SeverityHigh, ModeSurface},
	CheckCVETeamCityRPC2:        {CheckCVETeamCityRPC2, SeverityCritical, ModeDeep},
	CheckCVESharePointJWT:       {CheckCVESharePointJWT, SeverityCritical, ModeSurface},

	// 2022 CVEs
	CheckCVEF5BigIPAuthBypass:   {CheckCVEF5BigIPAuthBypass, SeverityCritical, ModeSurface},
	CheckCVEConfluenceOGNL:      {CheckCVEConfluenceOGNL, SeverityCritical, ModeSurface},
	CheckCVEFortiOSAuthBypass:   {CheckCVEFortiOSAuthBypass, SeverityCritical, ModeSurface},
	CheckCVEVMwareWorkspaceONE:  {CheckCVEVMwareWorkspaceONE, SeverityCritical, ModeSurface},
	CheckCVEWSO2FileUpload:      {CheckCVEWSO2FileUpload, SeverityCritical, ModeSurface},
	CheckCVESpring4Shell:        {CheckCVESpring4Shell, SeverityCritical, ModeSurface},
	CheckCVEZimbraAuthBypass:    {CheckCVEZimbraAuthBypass, SeverityCritical, ModeSurface},
	CheckCVESophosFW:            {CheckCVESophosFW, SeverityCritical, ModeSurface},
	CheckCVEManageEngineSAML:    {CheckCVEManageEngineSAML, SeverityCritical, ModeSurface},
	CheckCVEMagentoRCE:          {CheckCVEMagentoRCE, SeverityCritical, ModeSurface},

	// 2021 CVEs
	CheckCVEExchangeProxyLogon:  {CheckCVEExchangeProxyLogon, SeverityCritical, ModeSurface},
	CheckCVEExchangeProxyShell:  {CheckCVEExchangeProxyShell, SeverityCritical, ModeSurface},
	CheckCVEvCenterExposed:      {CheckCVEvCenterExposed, SeverityCritical, ModeSurface},
	CheckCVEApacheHTTPTraversal: {CheckCVEApacheHTTPTraversal, SeverityCritical, ModeSurface},
	CheckCVEGitLabRCE:           {CheckCVEGitLabRCE, SeverityCritical, ModeSurface},
	CheckCVESaltStackAPI:        {CheckCVESaltStackAPI, SeverityCritical, ModeSurface},
	CheckCVEAccellionFTA:        {CheckCVEAccellionFTA, SeverityHigh, ModeSurface},

	// 2020 CVEs
	CheckCVEF5BigIPTMUI:     {CheckCVEF5BigIPTMUI, SeverityCritical, ModeSurface},
	CheckCVEWebLogicConsole: {CheckCVEWebLogicConsole, SeverityCritical, ModeSurface},
	CheckCVECitrixADCInfo:   {CheckCVECitrixADCInfo, SeverityCritical, ModeSurface},
	CheckCVESolarWindsOrion: {CheckCVESolarWindsOrion, SeverityCritical, ModeSurface},
	CheckCVEApacheUnomi:     {CheckCVEApacheUnomi, SeverityCritical, ModeSurface},
	CheckCVELiferayRCE:      {CheckCVELiferayRCE, SeverityCritical, ModeSurface},
	CheckCVEMobileIronRCE:   {CheckCVEMobileIronRCE, SeverityCritical, ModeSurface},

	// 2019 CVEs
	CheckCVEPulseSecureVPN:   {CheckCVEPulseSecureVPN, SeverityCritical, ModeSurface},
	CheckCVEPANGlobalProtect:    {CheckCVEPANGlobalProtect, SeverityCritical, ModeSurface},
	CheckCVEPANGlobalProtectCMD: {CheckCVEPANGlobalProtectCMD, SeverityCritical, ModeSurface},
	CheckCVECrowdPdkInstall:  {CheckCVECrowdPdkInstall, SeverityCritical, ModeSurface},
	CheckCVETelerikRAU:       {CheckCVETelerikRAU, SeverityCritical, ModeSurface},
	CheckCVEWebLogicAsync:    {CheckCVEWebLogicAsync, SeverityCritical, ModeSurface},
	CheckCVESolrAdminExposed: {CheckCVESolrAdminExposed, SeverityHigh, ModeSurface},
	CheckCVEEximRCE2019:      {CheckCVEEximRCE2019, SeverityCritical, ModeSurface},
	CheckCVEDLinkHNAP:        {CheckCVEDLinkHNAP, SeverityCritical, ModeSurface},

	// 2018 CVEs
	CheckCVEDrupalgeddon2:          {CheckCVEDrupalgeddon2, SeverityCritical, ModeSurface},
	CheckCVEManageEngineDesktopCVE: {CheckCVEManageEngineDesktopCVE, SeverityCritical, ModeSurface},
	CheckCVEOpenSSHUsernameEnum:    {CheckCVEOpenSSHUsernameEnum, SeverityMedium, ModeSurface},
	CheckCVEKubernetesPrivEsc:      {CheckCVEKubernetesPrivEsc, SeverityCritical, ModeSurface},
	CheckCVEJenkinsStaplerRCE:      {CheckCVEJenkinsStaplerRCE, SeverityCritical, ModeSurface},
	CheckCVEEximHeapOverflow:       {CheckCVEEximHeapOverflow, SeverityCritical, ModeSurface},
	CheckCVEApacheTikaRCE:          {CheckCVEApacheTikaRCE, SeverityCritical, ModeSurface},

	// 2017 CVEs
	CheckCVEWebLogicWLSWSAT:     {CheckCVEWebLogicWLSWSAT, SeverityCritical, ModeSurface},
	CheckCVEHikvisionISAPI:      {CheckCVEHikvisionISAPI, SeverityCritical, ModeSurface},
	CheckCVEIntelAMTAuthBypass:  {CheckCVEIntelAMTAuthBypass, SeverityCritical, ModeSurface},
	CheckCVEDotNetNukeTraversal: {CheckCVEDotNetNukeTraversal, SeverityHigh, ModeSurface},
	CheckCVEPrimefacesEL:        {CheckCVEPrimefacesEL, SeverityHigh, ModeSurface},

	// 2016 CVEs
	CheckCVEShiroRememberMe:  {CheckCVEShiroRememberMe, SeverityCritical, ModeSurface},
	CheckCVEWebSphereConsole: {CheckCVEWebSphereConsole, SeverityHigh, ModeSurface},
	CheckCVESpringOAuthSpEL:  {CheckCVESpringOAuthSpEL, SeverityCritical, ModeSurface},
	CheckCVEOXAppSuiteSSRF:   {CheckCVEOXAppSuiteSSRF, SeverityHigh, ModeSurface},

	// 2012 CVEs
	CheckCVELibupnpSSDPRCE: {CheckCVELibupnpSSDPRCE, SeverityCritical, ModeSurface},

	// 2015 CVEs
	CheckCVEJBossJMXInvoker:            {CheckCVEJBossJMXInvoker, SeverityCritical, ModeSurface},
	CheckCVEIISHTTPSys:                 {CheckCVEIISHTTPSys, SeverityCritical, ModeSurface},
	CheckCVEElasticsearchGroovyRCE:     {CheckCVEElasticsearchGroovyRCE, SeverityCritical, ModeSurface},
	CheckCVEJoomlaObjectInjection:      {CheckCVEJoomlaObjectInjection, SeverityCritical, ModeSurface},

	// JWT / OIDC / JWKS advanced checks
	CheckJWTAlgorithmConfusion:  {CheckJWTAlgorithmConfusion, SeverityCritical, ModeDeep},
	CheckJWTAudienceMissing:     {CheckJWTAudienceMissing, SeverityHigh, ModeDeep},
	CheckJWTIssuerNotValidated:  {CheckJWTIssuerNotValidated, SeverityHigh, ModeDeep},
	CheckJWTEncryptionMissing:   {CheckJWTEncryptionMissing, SeverityMedium, ModeSurface},
	CheckJWTReplayMissing:       {CheckJWTReplayMissing, SeverityMedium, ModeDeep},
	CheckJWKSWeakKey:            {CheckJWKSWeakKey, SeverityHigh, ModeSurface},
	CheckJWKSMissingKID:         {CheckJWKSMissingKID, SeverityMedium, ModeSurface},
	CheckOIDCWeakSigningAlg:     {CheckOIDCWeakSigningAlg, SeverityHigh, ModeSurface},
	CheckOIDCMissingJWKSURI:     {CheckOIDCMissingJWKSURI, SeverityHigh, ModeSurface},
	CheckOAuthTokenInFragment:   {CheckOAuthTokenInFragment, SeverityHigh, ModeSurface},
	CheckOAuthRefreshNotRotated: {CheckOAuthRefreshNotRotated, SeverityMedium, ModeDeep},
	CheckOAuthTokenLongExpiry:   {CheckOAuthTokenLongExpiry, SeverityMedium, ModeSurface},
	CheckOIDCBackchannelMissing: {CheckOIDCBackchannelMissing, SeverityMedium, ModeSurface},

	// SAML security
	CheckSAMLEndpointExposed:       {CheckSAMLEndpointExposed, SeverityInfo, ModeSurface},
	CheckSAMLMetadataExposed:       {CheckSAMLMetadataExposed, SeverityInfo, ModeSurface},
	CheckSAMLSignatureNotValidated: {CheckSAMLSignatureNotValidated, SeverityCritical, ModeDeep},
	CheckSAMLXMLWrapping:           {CheckSAMLXMLWrapping, SeverityCritical, ModeDeep},
	CheckSAMLReplayAllowed:         {CheckSAMLReplayAllowed, SeverityHigh, ModeDeep},
	CheckSAMLIssuerNotValidated:    {CheckSAMLIssuerNotValidated, SeverityHigh, ModeDeep},
	CheckSAMLAudienceNotValidated:  {CheckSAMLAudienceNotValidated, SeverityHigh, ModeDeep},
	CheckSAMLXXEInjection:          {CheckSAMLXXEInjection, SeverityCritical, ModeDeep},
	CheckSAMLOpenRedirect:          {CheckSAMLOpenRedirect, SeverityMedium, ModeDeep},

	// IAM / Identity
	CheckSCIMExposed:             {CheckSCIMExposed, SeverityInfo, ModeSurface},
	CheckSCIMUnauthenticated:     {CheckSCIMUnauthenticated, SeverityCritical, ModeSurface},
	CheckOIDCUserinfoLeak:        {CheckOIDCUserinfoLeak, SeverityHigh, ModeSurface},
	CheckOAuthIntrospectExposed:  {CheckOAuthIntrospectExposed, SeverityHigh, ModeSurface},
	CheckOAuthDeviceFlowExposed:  {CheckOAuthDeviceFlowExposed, SeverityMedium, ModeSurface},
	CheckOAuthDynClientReg:       {CheckOAuthDynClientReg, SeverityHigh, ModeSurface},
	CheckLDAPInjection:           {CheckLDAPInjection, SeverityCritical, ModeDeep},
	CheckCloudMetadataSSRF:       {CheckCloudMetadataSSRF, SeverityCritical, ModeDeep},
	CheckIdentityProviderExposed: {CheckIdentityProviderExposed, SeverityCritical, ModeSurface},
	CheckOAuthPKCEDowngrade:      {CheckOAuthPKCEDowngrade, SeverityHigh, ModeDeep},
	CheckOAuthClientSecretLeak:   {CheckOAuthClientSecretLeak, SeverityCritical, ModeSurface},
	CheckIdentityRoleEscalation:  {CheckIdentityRoleEscalation, SeverityCritical, ModeSurface},

	// Web application injection and misconfiguration
	CheckWebSSTI:               {CheckWebSSTI, SeverityCritical, ModeDeep},
	CheckWebCRLFInjection:      {CheckWebCRLFInjection, SeverityHigh, ModeDeep},
	CheckWebPrototypePollution: {CheckWebPrototypePollution, SeverityHigh, ModeDeep},
	CheckWebXXE:                {CheckWebXXE, SeverityCritical, ModeDeep},
	CheckWebInsecureDeserialize: {CheckWebInsecureDeserialize, SeverityCritical, ModeDeep},
	CheckWebHPP:                {CheckWebHPP, SeverityMedium, ModeDeep},
	CheckWebNginxAliasTraversal: {CheckWebNginxAliasTraversal, SeverityCritical, ModeSurface},
	CheckWebIISShortname:       {CheckWebIISShortname, SeverityMedium, ModeSurface},
	CheckWebFileUpload:         {CheckWebFileUpload, SeverityCritical, ModeDeep},
	CheckWebAPIFuzz:            {CheckWebAPIFuzz, SeverityHigh, ModeDeep},
	CheckCVELog4Shell:          {CheckCVELog4Shell, SeverityCritical, ModeDeep},

	// Nmap additional
	CheckNmapOSDetected:  {CheckNmapOSDetected, SeverityInfo, ModeSurface},
	CheckNmapUDPExposed:  {CheckNmapUDPExposed, SeverityMedium, ModeSurface},

	// External intelligence APIs
	CheckVirusTotalReputation: {CheckVirusTotalReputation, SeverityHigh, ModeSurface},
	CheckCensysHostData:       {CheckCensysHostData, SeverityMedium, ModeSurface},
	CheckGreyNoiseContext:     {CheckGreyNoiseContext, SeverityInfo, ModeSurface},

	// Infrastructure layer: API gateways, load balancers, CDN edges, service mesh
	CheckGatewayKongAdminExposed:    {CheckGatewayKongAdminExposed, SeverityCritical, ModeSurface},
	CheckGatewayKongRouteEnum:       {CheckGatewayKongRouteEnum, SeverityHigh, ModeSurface},
	CheckGatewayHAProxyStatsExposed: {CheckGatewayHAProxyStatsExposed, SeverityHigh, ModeSurface},
	CheckGatewayNginxStatusExposed:  {CheckGatewayNginxStatusExposed, SeverityMedium, ModeSurface},
	CheckGatewayVarnishDebugExposed: {CheckGatewayVarnishDebugExposed, SeverityLow, ModeSurface},
	CheckGatewayTraefikAPIExposed:   {CheckGatewayTraefikAPIExposed, SeverityHigh, ModeSurface},
	CheckGatewayEnvoyAdminExposed:   {CheckGatewayEnvoyAdminExposed, SeverityCritical, ModeSurface},
	CheckGatewayLinkerdVizExposed:   {CheckGatewayLinkerdVizExposed, SeverityHigh, ModeSurface},
	CheckGatewayAWSAPIGWStageInfo:   {CheckGatewayAWSAPIGWStageInfo, SeverityMedium, ModeSurface},
	CheckGatewayAzureAPIMExposed:    {CheckGatewayAzureAPIMExposed, SeverityHigh, ModeSurface},
	CheckGatewayApigeeExposed:       {CheckGatewayApigeeExposed, SeverityHigh, ModeSurface},
	CheckGatewayF5AdminExposed:      {CheckGatewayF5AdminExposed, SeverityCritical, ModeSurface},
	CheckGatewayCitrixAdminExposed:  {CheckGatewayCitrixAdminExposed, SeverityCritical, ModeSurface},
	CheckGatewayTykDashExposed:      {CheckGatewayTykDashExposed, SeverityHigh, ModeSurface},
	CheckCDNAkamaiPragmaInfo:        {CheckCDNAkamaiPragmaInfo, SeverityLow, ModeSurface},
	CheckCDNFastlyDebugExposed:      {CheckCDNFastlyDebugExposed, SeverityLow, ModeSurface},
	CheckCDNVarnishPurgeEnabled:     {CheckCDNVarnishPurgeEnabled, SeverityMedium, ModeSurface},

	// Swagger / OpenAPI
	CheckSwaggerExposed: {CheckSwaggerExposed, SeverityMedium, ModeSurface},

	// Web3 / blockchain
	CheckWeb3WalletLibDetected:  {CheckWeb3WalletLibDetected, SeverityInfo, ModeSurface},
	CheckWeb3RPCEndpointExposed: {CheckWeb3RPCEndpointExposed, SeverityHigh, ModeSurface},
	CheckWeb3ContractFound:      {CheckWeb3ContractFound, SeverityInfo, ModeSurface},

	// EVM smart contract vulnerability scanning
	CheckContractReentrancy:      {CheckContractReentrancy, SeverityCritical, ModeDeep},
	CheckContractSelfDestruct:    {CheckContractSelfDestruct, SeverityCritical, ModeDeep},
	CheckContractUncheckedCall:   {CheckContractUncheckedCall, SeverityHigh, ModeDeep},
	CheckContractIntegerOverflow: {CheckContractIntegerOverflow, SeverityHigh, ModeDeep},
	CheckContractSourceExposed:   {CheckContractSourceExposed, SeverityMedium, ModeSurface},
	CheckContractProxyAdmin:      {CheckContractProxyAdmin, SeverityHigh, ModeSurface},

	// Blockchain node detection
	CheckChainNodeRPCExposed:       {CheckChainNodeRPCExposed, SeverityCritical, ModeSurface},
	CheckChainNodeUnauthorized:     {CheckChainNodeUnauthorized, SeverityCritical, ModeSurface},
	CheckChainNodeValidatorExposed: {CheckChainNodeValidatorExposed, SeverityCritical, ModeSurface},
	CheckChainNodeMinerExposed:     {CheckChainNodeMinerExposed, SeverityHigh, ModeSurface},
	CheckChainNodePeerCountLeak:    {CheckChainNodePeerCountLeak, SeverityMedium, ModeSurface},
	CheckChainNodeWSExposed:        {CheckChainNodeWSExposed, SeverityHigh, ModeSurface},
	CheckChainNodeGrafanaExposed:   {CheckChainNodeGrafanaExposed, SeverityHigh, ModeSurface},

	// Web3 / SIWE + SIWS authenticated security testing
	CheckWeb3SIWEEndpoint:         {CheckWeb3SIWEEndpoint, SeverityInfo, ModeSurface},
	CheckWeb3SIWSDEndpoint:        {CheckWeb3SIWSDEndpoint, SeverityInfo, ModeSurface},
	CheckWeb3SIWEDomainBypass:     {CheckWeb3SIWEDomainBypass, SeverityHigh, ModeDeep},
	CheckWeb3SIWENonceReuse:       {CheckWeb3SIWENonceReuse, SeverityHigh, ModeDeep},
	CheckWeb3SIWEReplay:           {CheckWeb3SIWEReplay, SeverityMedium, ModeDeep},
	CheckWeb3SIWEChainMismatch:    {CheckWeb3SIWEChainMismatch, SeverityHigh, ModeDeep},
	CheckWeb3SIWEURIMismatch:      {CheckWeb3SIWEURIMismatch, SeverityMedium, ModeDeep},
	CheckWeb3SIWEOverHTTP:         {CheckWeb3SIWEOverHTTP, SeverityHigh, ModeSurface},
	CheckWeb3HorizontalEscalation: {CheckWeb3HorizontalEscalation, SeverityCritical, ModeDeep},

	// Cross-asset correlation findings — batch AI analysis only, always surfaced
	CheckCorrelationCICDToProd:         {CheckCorrelationCICDToProd, SeverityCritical, ModeSurface},
	CheckCorrelationAuthBypassViaProxy: {CheckCorrelationAuthBypassViaProxy, SeverityHigh, ModeSurface},
	CheckCorrelationStagingToProd:      {CheckCorrelationStagingToProd, SeverityHigh, ModeSurface},
	CheckCorrelationEmailPlusLogin:     {CheckCorrelationEmailPlusLogin, SeverityHigh, ModeSurface},
	CheckCorrelationCredentialReuse:    {CheckCorrelationCredentialReuse, SeverityCritical, ModeSurface},
	CheckCorrelationLateralMovement:    {CheckCorrelationLateralMovement, SeverityCritical, ModeSurface},
	CheckCorrelationGeneric:            {CheckCorrelationGeneric, SeverityHigh, ModeSurface},

	// Terraform / IaC static analysis — always ModeSurface (file analysis, no network probing)
	CheckTerraformS3BucketPublic:    {CheckTerraformS3BucketPublic, SeverityHigh, ModeSurface},
	CheckTerraformGCSBucketPublic:   {CheckTerraformGCSBucketPublic, SeverityHigh, ModeSurface},
	CheckTerraformGKEPublicEndpoint: {CheckTerraformGKEPublicEndpoint, SeverityCritical, ModeSurface},
	CheckTerraformGKELegacyABAC:    {CheckTerraformGKELegacyABAC, SeverityHigh, ModeSurface},
	CheckTerraformGKENoNetworkPolicy: {CheckTerraformGKENoNetworkPolicy, SeverityMedium, ModeSurface},
	CheckTerraformRDSPublic:         {CheckTerraformRDSPublic, SeverityCritical, ModeSurface},
	CheckTerraformRDSUnencrypted:    {CheckTerraformRDSUnencrypted, SeverityHigh, ModeSurface},
	CheckTerraformSGOpenIngress:     {CheckTerraformSGOpenIngress, SeverityHigh, ModeSurface},
	CheckTerraformIAMWildcardPolicy: {CheckTerraformIAMWildcardPolicy, SeverityHigh, ModeSurface},
	CheckTerraformIAMAdminPolicy:    {CheckTerraformIAMAdminPolicy, SeverityCritical, ModeSurface},
	CheckTerraformSecretsInCode:     {CheckTerraformSecretsInCode, SeverityCritical, ModeSurface},
	CheckTerraformUnencryptedEBS:    {CheckTerraformUnencryptedEBS, SeverityHigh, ModeSurface},
	CheckTerraformIMDSv1Enabled:     {CheckTerraformIMDSv1Enabled, SeverityHigh, ModeSurface},
	CheckTerraformPublicECRRepo:     {CheckTerraformPublicECRRepo, SeverityMedium, ModeSurface},
	CheckTerraformCloudFrontHTTP:    {CheckTerraformCloudFrontHTTP, SeverityMedium, ModeSurface},
	CheckTerraformLBHTTP:            {CheckTerraformLBHTTP, SeverityMedium, ModeSurface},
	CheckTerraformTFStatePublic:     {CheckTerraformTFStatePublic, SeverityCritical, ModeSurface},

	// AI fingerprinting / cross-asset
	CheckAIFPCrossAsset:  {CheckAIFPCrossAsset, SeverityMedium, ModeSurface},
	CheckAIFPUnknownTech: {CheckAIFPUnknownTech, SeverityInfo, ModeSurface},
}

// Meta returns the CheckMeta for a given CheckID, or a safe default if not registered.
// Unregistered checks default to ModeDeep (fail closed) — if we don't know what a check
// does, we require explicit permission rather than silently running it in surface scans.
func Meta(id CheckID) CheckMeta {
	if m, ok := Registry[id]; ok {
		return m
	}
	return CheckMeta{CheckID: id, DefaultSeverity: SeverityInfo, Mode: ModeDeep}
}
