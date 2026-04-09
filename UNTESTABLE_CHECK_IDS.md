# Untestable Check IDs

Check IDs in `internal/finding/checkids.go` that cannot be covered by Docker-based
(drydock) integration tests. Every check ID in beacon is either:

1. **Tested** — a `tests/scanners/*.yaml` assertion verifies detection, or
2. **Documented here** — with a reason why Docker testing is infeasible.

---

## Category: Not Emitted by Any Scanner (`not_emitted_by_scanner`)

These check IDs are defined in `checkids.go` but no scanner produces them.
They exist because a different (more specific) check ID is emitted instead,
or the feature was planned but not implemented.

| Check ID | Reason |
|---|---|
| `exposure.api_docs` | Scanner emits `web.swagger_exposed` instead |
| `exposure.security_txt` | Scanner emits `wellknown.security_txt` instead |
| `exposure.sitemap_xml` | Scanner emits `wellknown.sitemap_xml` or `exposure.sitemap_sensitive_url` instead |
| `exposure.vcs_exposed` | Scanner emits `exposure.git_exposed` instead |
| `exposure.source_maps_exposed` | Scanner emits `js.source_map_exposed` instead |
| `exposure.cloud_storage` | Scanner emits `cloud.bucket_public` instead; only referenced in correlation |
| `exposure.staging_subdomain` | Detected by classify as metadata, not emitted as a finding |
| `port.prometheus_exposed` | Scanner emits `port.prometheus_unauthenticated` instead |
| `port.couchdb_no_auth` | Scanner emits `port.couchdb_unauthenticated` instead |
| `exposure.http_no_redirect` | Defined but no scanner implements HTTP-to-HTTPS redirect detection |
| `exposure.robots_disallow_leak` | Defined but no scanner implements it; `exposure.robots_sensitive_path` is emitted instead |
| `exposure.backup_file` | Only referenced in correlation scanner; primary scanner emits `exposure.sensitive_file` |
| `web.outdated_software` | Defined but no scanner implements generic outdated-software detection; `version.outdated_software` is a separate ID used by version fingerprinting |
| `tls.no_secure_renegotiation` | Defined but no scanner implements RFC 5746 secure renegotiation detection |
| `tls.mixed_content` | Defined but no scanner implements mixed-content detection (needs page rendering) |
| `websocket.endpoint_open` | Defined but no scanner emits this; WebSocket detection is fingerprinting-only |
| `websocket.no_auth` | Defined but no scanner emits this check ID |

---

## Category: Requires API Keys (`needs_api_key`)

External intelligence APIs that require paid/limited API keys not available
in CI.

| Check ID | Service |
|---|---|
| `intel.censys_host` | Censys API |
| `intel.greynoise` | GreyNoise API |
| `intel.virustotal_reputation` | VirusTotal API |
| `dlp.vision_finding` | Claude Vision API |
| `dlp.vision_service_id` | Claude Vision API |
| `asset.shodan_host` | Shodan API |

---

## Category: Requires Real Infrastructure (`needs_real_infra`)

These check IDs require hardware, enterprise software, or cloud
infrastructure that cannot be replicated in Docker.

### TLS — Legacy Protocol Vulnerabilities

| Check ID | Reason |
|---|---|
| `tls.heartbleed` | Requires specific vulnerable OpenSSL version (< 1.0.1g); no Docker image available |
| `tls.poodle` | Requires SSLv3 support; modern OpenSSL builds strip SSLv3 entirely |
| `tls.beast` | Requires CBC ciphers in TLS 1.0; Go TLS client rejects insecure ciphers |
| `tls.robot` | Requires RSA key exchange with specific timing oracle; needs patched OpenSSL |
| `cve.tls_ccs_injection` | Requires CVE-2014-0224 vulnerable OpenSSL; no maintained Docker image |
| `tls.cert_revoked` | Requires real OCSP responder + CA infrastructure to verify revocation |
| `tls.cert_chain_invalid` | Requires intermediate CA to be missing from chain; hard to simulate in Docker |
| `tls.cert_hostname_mismatch` | TLS scanner connects to `host:port` — in drydock the hostname is `localhost` which matches the self-signed cert CN |

### TLS — HSTS (Self-Signed Cert Limitation)

| Check ID | Reason |
|---|---|
| `tls.hsts_short_max_age` | HSTS HTTP client does not skip cert verification — self-signed certs fail the HTTPS fetch, so HSTS header is never read. Covered by unit tests. |
| `tls.hsts_no_subdomains` | Same self-signed cert limitation as above. Covered by unit tests. |
| `tls.hsts_no_preload` | Same self-signed cert limitation as above. Covered by unit tests. |

### TLS — JA3S/Portscan Probes

| Check ID | Reason |
|---|---|
| `tls.weak_cipher_negotiated` | Go TLS client refuses to negotiate insecure ciphers, so JA3S probe never observes a weak suite. Covered by unit tests. |
| `tls.expired_cert_detected` | Portscan JA3S probe emits this, but drydock port remapping means portscan may not probe the correct port. Assertion added to tls-expired-cert.yaml for best-effort testing. |

### SAML — Requires IdP

| Check ID | Reason |
|---|---|
| `saml.endpoint_exposed` | Needs SAML service provider with real IdP metadata |
| `saml.metadata_exposed` | Needs SAML SP metadata endpoint |
| `saml.signature_not_validated` | Needs SAML response processing — requires Keycloak or similar |
| `saml.xml_signature_wrapping` | Needs XML signature validation logic |
| `saml.assertion_replay` | Needs SAML assertion processing with timestamp validation |
| `saml.issuer_not_validated` | Needs SAML response from arbitrary issuer |
| `saml.audience_not_validated` | Needs SAML response with wrong audience |
| `saml.xxe_injection` | Needs SAML XML parser vulnerable to external entities |
| `saml.open_redirect` | Needs SAML RelayState redirect handling |

### OAuth/OIDC — Deep Checks Requiring Real Provider

| Check ID | Reason |
|---|---|
| `oauth.implicit_flow_accepted` | Needs OAuth provider that accepts `response_type=token` |
| `oauth.token_endpoint_no_auth` | Needs OAuth token endpoint without client authentication |
| `oauth.token_in_url_fragment` | Needs OAuth provider returning tokens in Location fragment |
| `oauth.refresh_not_rotated` | Needs OAuth provider with refresh token endpoint |
| `oauth.token_long_expiry` | Needs real OAuth token issuance with long `expires_in` |
| `iam.backchannel_logout_missing` | Needs OIDC provider with backchannel logout support |

### Web — Requires Specific Technology Stack

| Check ID | Reason |
|---|---|
| `web.iis_shortname` | Requires IIS server with 8.3 filename generation enabled |
| `web.ognl_injection` | Requires Apache Struts or Confluence with OGNL expression evaluation |
| `web.spel_injection` | Requires Spring Framework with SpEL expression evaluation |
| `web.el_injection` | Requires JSP/JSF container with Expression Language evaluation |
| `web.xsd_injection` | Requires XML processor with remote XSD schema loading |
| `web.http_request_smuggling` | Requires specific frontend/backend proxy pair with CL/TE disagreement |
| `web.pdf_ssrf` | Requires PDF generation service (wkhtmltopdf, Puppeteer) with HTML-to-PDF |
| `web.redos` | Requires endpoint with vulnerable regex that causes catastrophic backtracking |

### Network Hardware / Active Directory / ICS

| Check ID | Reason |
|---|---|
| `port.rdp_exposed` | Windows RDP service |
| `port.rdp_weak_encryption` | Windows RDP with specific encryption configuration |
| `port.rdp_no_nla` | Windows RDP without Network Level Authentication |
| `port.winrm_exposed` | Windows WinRM service |
| `port.smb_exposed` | Windows/Samba SMB service (testable but complex Docker setup) |
| `port.smb_null_session` | SMB null session requires Samba or Windows configuration |
| `port.smb_v1_enabled` | SMBv1 requires specific old Samba version |
| `port.active_directory_exposed` | Active Directory domain controller |
| `port.kerberos_exposed` | Kerberos KDC |
| `port.global_catalog_exposed` | AD Global Catalog |
| `port.ldap_exposed` | LDAP directory (testable but complex) |
| `port.wins_exposed` | Windows WINS name service |
| `port.s7comm_exposed` | Siemens S7 PLC (ICS hardware) |
| `port.ethernet_ip_exposed` | Rockwell EtherNet/IP PLC (ICS hardware) |
| `port.dnp3_exposed` | DNP3 SCADA protocol (ICS hardware) |
| `port.bacnet_exposed` | BACnet building automation (ICS hardware) |
| `port.modbus_exposed` | Modbus TCP SCADA (ICS hardware) |
| `port.mqtt_exposed` | MQTT broker (testable but not prioritized) |
| `port.sip_exposed` | SIP PBX/proxy (telecom hardware) |
| `port.rtsp_exposed` | RTSP video stream (camera hardware) |
| `port.ipp_exposed` | IPP network printer |
| `port.iscsi_exposed` | iSCSI storage target |
| `port.netconf_exposed` | NETCONF network management |
| `port.winbox_exposed` | MikroTik Winbox (router hardware) |
| `port.bgp_exposed` | BGP routing (network hardware) |
| `port.radius_exposed` | RADIUS authentication server |
| `port.cisco_smart_install` | Cisco IOS Smart Install (network hardware) |

### Network Device Vendor Detection

| Check ID | Reason |
|---|---|
| `netdev.cisco_detected` | Requires Cisco IOS/NX-OS device |
| `netdev.juniper_detected` | Requires Juniper JunOS device |
| `netdev.mikrotik_detected` | Requires MikroTik RouterOS device |
| `netdev.ubiquiti_detected` | Requires Ubiquiti UniFi/AirOS device |
| `netdev.fortinet_detected` | Requires Fortinet FortiGate device |
| `netdev.paloalto_detected` | Requires Palo Alto PAN-OS device |
| `netdev.huawei_detected` | Requires Huawei VRP device |
| `netdev.bmc_exposed` | Requires server with iDRAC/iLO/IPMI BMC |
| `netdev.f5_detected` | Requires F5 BIG-IP load balancer |
| `netdev.sonicwall_detected` | Requires SonicWall firewall |
| `netdev.checkpoint_detected` | Requires Check Point firewall |
| `netdev.hparuba_detected` | Requires HP/Aruba network switch |
| `netdev.tplink_detected` | Requires TP-Link SOHO router |
| `netdev.dlink_detected` | Requires D-Link SOHO router |
| `netdev.netgear_detected` | Requires Netgear SOHO router |
| `netdev.asterisk_detected` | Requires Asterisk/FreePBX PBX |
| `netdev.unifi_exposed` | Requires UniFi Network Application |
| `netdev.tplink_omada` | Requires TP-Link Omada controller |
| `netdev.aruba_instant` | Requires Aruba Instant AP |
| `netdev.openwrt_exposed` | Requires OpenWRT device |

### WiFi Scanning

| Check ID | Reason |
|---|---|
| `wifi.open_network` | Requires WiFi adapter in monitor mode |
| `wifi.wep_network` | Requires WiFi adapter + WEP AP |
| `wifi.wps_enabled` | Requires WiFi adapter + WPS-enabled AP |
| `wifi.wpa2_tkip` | Requires WiFi adapter + WPA2-TKIP AP |
| `wifi.gateway_exposed` | Requires local network gateway |
| `wifi.pmkid_capture` | Requires WiFi adapter in monitor mode |

### Cloud Provider APIs (Authenticated Scanning)

All `cloud.aws.*`, `cloud.gcp.*`, `cloud.azure.*`, `cloud.do.*`, `cloud.oci.*`
check IDs require real cloud accounts with API credentials. Not Docker-testable.

### On-Prem Infrastructure APIs

All `onprem.proxmox.*`, `onprem.docker.*`, `onprem.k8s.*`, `onprem.vmware.*`,
`onprem.network.*`, `onprem.nas.*`, `onprem.libvirt.*` check IDs require real
on-prem infrastructure with API access. Not Docker-testable.

### Okta Identity Provider

All `iam.okta_*` check IDs require a real Okta tenant with API token.
Not Docker-testable.

---

## Category: Requires Crawl Pipeline (`needs_crawl_pipeline`)

These scanners work in full scan mode but require the crawl pipeline
(katana + parameter discovery) to find injection points. Running with
`--scanners <name>` alone is insufficient — the scanner needs discovered
endpoints and parameters from the crawl phase.

### Second-Order Injection

| Check ID | Reason |
|---|---|
| `web.second_order_reflection` | Needs crawl to find injection points + observation endpoints |
| `web.second_order_sqli` | Needs crawl to find injection points + observation endpoints |
| `web.second_order_xss` | Needs crawl to find injection points + observation endpoints |

### Race Condition / State Machine

| Check ID | Reason |
|---|---|
| `web.race_condition_no_idempotency` | Needs crawl to find state-changing endpoints |
| `web.method_bypass` | Needs crawl to find auth-protected endpoints |
| `web.horizontal_privesc` | Needs crawl + two user sessions |
| `web.step_bypass` | Needs crawl to discover multi-step workflow |
| `web.incomplete_auth_flow` | Needs crawl to discover auth flow steps |
| `web.state_skip_detected` | Needs crawl to discover auth state machine |

### API Fuzzing

| Check ID | Reason |
|---|---|
| `web.api_fuzz_error` | Needs crawl to discover API endpoints + parameter types |
| `web.prototype_pollution` | Needs crawl to find JSON body endpoints |

### WebSocket

| Check ID | Reason |
|---|---|
| `websocket.endpoint_open` | Defined but not emitted by any scanner (fingerprinting only) |
| `websocket.message_injection` | Needs crawl to discover WebSocket endpoints |
| `websocket.no_auth` | Defined but not emitted by any scanner |

### Cache Poisoning

| Check ID | Reason |
|---|---|
| `cache.poison_unkeyed` | Needs crawl to find cache-backed pages + unkeyed header reflection |
| `cache.deception` | Needs crawl to find dynamic pages that get cached with static extensions |
| `cache.host_routing` | Needs crawl to find cacheable endpoints where Host header affects routing |

### WAF Bypass (Needs Bypassable WAF)

| Check ID | Reason |
|---|---|
| `waf.bypass_via_header` | Needs a WAF that can actually be bypassed; ModSecurity CRS is too strong |
| `waf.bypass_via_path` | Same — needs exploitable WAF path normalization |
| `waf.bypass_via_method` | Same — needs WAF that doesn't inspect all methods |
| `waf.bypass_via_ctype` | Same — needs WAF with Content-Type confusion |
| `waf.bypass_found` | Same — needs WAF vulnerable to adaptive encoding |
| `waf.bypass_double_encode` | Same — needs WAF that doesn't decode double-encoded payloads |

---

## Category: JWT Deep Probes Not Yet Implemented (`scanner_not_implemented`)

The JWT scanner code exists but the deep-mode active probes are not yet
wired to drydock fixtures. The vulnerable server fixtures exist and are
ready for when the scanner is extended.

| Check ID | Reason |
|---|---|
| `jwt.alg_none_variant` | Scanner sends modified JWTs but needs crawl to find JWT-accepting endpoints in drydock |
| `jwt.empty_secret` | Same — needs endpoint discovery pipeline |
| `jwt.kid_sql_injection` | Same — needs endpoint discovery pipeline |
| `jwt.algorithm_confusion` | Scanner not yet implemented |
| `jwt.audience_missing` | Scanner not yet implemented |
| `jwt.issuer_not_validated` | Scanner not yet implemented |
| `jwt.no_server_verification` | Scanner not yet implemented |
| `jwt.jwks_weak_key` | Scanner not yet implemented |

---

## Category: Cookie — Requires HTTPS (`needs_https`)

| Check ID | Reason |
|---|---|
| `cookie.no_secure_prefix` | Only fires when `Secure` flag is already set (HTTPS cookies). Self-signed certs in drydock don't trigger the Secure flag path. Covered by unit tests. |

---

## Category: DNS Rebinding — Requires Routable Hostname (`needs_dns`)

| Check ID | Reason |
|---|---|
| `web.dns_rebinding_internal_routable` | Needs DNS resolution to internal IP; `localhost` in drydock is already internal. Covered by unit tests. |

---

## Category: SSRF Redirect — Requires Crawl Pipeline (`needs_crawl`)

| Check ID | Reason |
|---|---|
| `web.ssrf_redirect_metadata` | SSRF scanner needs crawl pipeline to discover injectable parameters; the scanner code works but needs parameter discovery to trigger in drydock. |

---

## Category: Default Credentials — Tested via Service-Specific Tests

| Check ID | Status |
|---|---|
| `web.default_credentials` | Emitted by `exposedfiles` scanner. Tested via service-specific tests (e.g., `port.grafana_default_credentials`, `port.airflow_default_credentials`). The generic `web.default_credentials` check ID fires only when the exposedfiles scanner finds a login page matching its built-in credential list. |

---

## Category: Correlation Findings (`correlation_only`)

All `correlation.*` check IDs are produced by batch AI analysis across
multiple findings, not by individual scanners. They require a full scan
with multiple findings present for the correlation engine to trigger.

---

## Category: Terraform/IaC Static Analysis (`needs_iac_files`)

All `terraform.*` check IDs require Terraform/HCL files as input to the
static analyzer. Not Docker-testable (they scan code, not running services).

---

## Category: GitHub/GitLab/CI-CD (`needs_scm_api`)

All `ghaction.*`, `github.*`, `gitlab.*`, `teamcity.*`, `bitbucket.*`,
`circleci.*`, `cicd.*` check IDs require access to SCM provider APIs
(GitHub, GitLab, etc.) with repository access tokens. Not Docker-testable.

---

## Category: JARM Fingerprint

| Check ID | Status |
|---|---|
| `tls.jarm_fingerprint` | Emitted by `classify/jarm.go`. Requires 10 TLS handshakes with specific parameters. Works in full scans but in drydock the JARM scanner may not probe the remapped port. Covered by unit tests. |

---

## Category: Nmap-Sourced Findings (`needs_nmap`)

All `nmap.*` check IDs are produced by parsing nmap XML output. They are
tested when nmap is available but are not guaranteed to fire in all Docker
environments (nmap may not be installed or may require root for some scans).

---

## Summary

| Category | Count | Example |
|---|---|---|
| Not emitted by scanner | 13 | `exposure.api_docs` |
| Needs API key | 6 | `intel.censys_host` |
| Needs real infrastructure | ~80 | `tls.heartbleed`, `saml.*`, network devices |
| Needs crawl pipeline | ~25 | `web.second_order_xss`, `cache.deception` |
| Scanner not implemented | 8 | `jwt.algorithm_confusion` |
| Needs HTTPS | 1 | `cookie.no_secure_prefix` |
| Needs DNS | 1 | `web.dns_rebinding_internal_routable` |
| Needs crawl | 1 | `web.ssrf_redirect_metadata` |
| Correlation only | ~15 | `correlation.*` |
| Terraform/IaC | ~17 | `terraform.*` |
| SCM/CI-CD APIs | ~60+ | `ghaction.*`, `github.*` |
| Nmap-sourced | ~30 | `nmap.*` |
| Cloud/on-prem APIs | ~200+ | `cloud.aws.*`, `onprem.*` |
