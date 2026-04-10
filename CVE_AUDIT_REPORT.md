# CVE Audit Report — Network/HTTP Exploitable CVEs (2020-2025)

Generated: 2026-04-09

## Summary

| Metric | Count |
|---|---|
| Total CVEs audited | 62 |
| Already have check ID | 55 |
| Detected by nuclei (template exists) | 58 |
| Detected by nmap NSE (script exists) | 18 |
| Native Go probe | 32 |
| Have exploit chain (playbook + post-exploit) | 22 |
| **GAPS (should add native or check ID)** | **7** |

### Total CVE check IDs in codebase: 187

Beacon has extensive CVE coverage. The 7 gaps identified are:
1. **CVE-2023-44487** (HTTP/2 Rapid Reset) — no check ID, no probe
2. **CVE-2023-0669** (GoAnywhere MFT RCE) — no check ID, no probe
3. **CVE-2023-27997** (FortiGate heap overflow RCE) — no check ID, no probe
4. **CVE-2024-21626** (Leaky Vessels runc escape) — no check ID, no probe
5. **CVE-2024-20353** (Cisco ASA WebVPN DoS) — no specific check ID (have generic Cisco ASA)
6. **CVE-2024-20359** (Cisco ASA persistent implant) — no specific check ID
7. **CVE-2020-1472** (Zerologon) — no check ID (network-level, not HTTP)

---

## Per-CVE Analysis

---

### Web Servers & Frameworks

---

### CVE-2021-41773 / CVE-2021-42013 — Apache httpd — Path Traversal / RCE
- **CVSS**: 7.5 / 9.8
- **Affected**: Apache httpd 2.4.49 (41773), 2.4.50 (42013)
- **Check ID**: `cve.apache_traversal_2021` / `cve.apache_traversal_bypass_2021` / `cve.apache_http_path_traversal`
- **Nuclei template**: Yes (CVE-2021-41773, CVE-2021-42013)
- **Nmap NSE**: Yes (http-vuln-cve2021-41773)
- **Native probe**: Yes — `probeApacheTraversal` in `internal/scanner/exposedfiles/scanner.go`
- **Exploit chain**: Yes — `internal/exploit/playbooks/apache.yaml` has cve_exploits for both CVEs with post-exploit steps
- **Recommend native?**: Already have native. Excellent coverage.

---

### CVE-2021-44228 — Log4j — Log4Shell JNDI Injection RCE
- **CVSS**: 10.0
- **Affected**: Apache Log4j 2.0-beta9 to 2.14.1
- **Check ID**: `cve.log4shell` / `cve.unifi_log4shell`
- **Nuclei template**: Yes (CVE-2021-44228)
- **Nmap NSE**: Yes (log4shell)
- **Native probe**: Yes — dedicated scanner `internal/scanner/log4shell/scanner.go` with JSESSIONID/Tomcat header heuristics (surface), plus post-exploit chain in `log4shell/postexploit.go`
- **Exploit chain**: Yes — `internal/exploit/playbooks/log4shell.yaml` + nuclei routing
- **Recommend native?**: Already have native. Best-in-class coverage with surface + deep + exploit chain.

---

### CVE-2022-22965 — Spring Framework — Spring4Shell RCE
- **CVSS**: 9.8
- **Affected**: Spring Framework 5.3.0-5.3.17, 5.2.0-5.2.19 on JDK 9+
- **Check ID**: `cve.spring4shell`
- **Nuclei template**: Yes (CVE-2022-22965)
- **Nmap NSE**: No
- **Native probe**: Yes — `probeSpring4Shell` in `internal/scanner/exposedfiles/scanner.go` sends `class.module.classLoader.URLs[0]=0` and checks for Spring-specific data-binding error
- **Exploit chain**: Yes — `internal/exploit/playbooks/spring_actuator.yaml` has cve_exploit for CVE-2022-22965
- **Recommend native?**: Already have native. Excellent coverage.

---

### CVE-2023-44487 — HTTP/2 — Rapid Reset DoS
- **CVSS**: 7.5
- **Affected**: All HTTP/2 implementations (nginx, Apache, IIS, etc.)
- **Check ID**: Missing
- **Nuclei template**: Limited (detection difficult — it's a protocol-level DoS)
- **Nmap NSE**: No
- **Native probe**: No
- **Exploit chain**: No
- **Recommend native?**: **Yes** — A surface-mode probe could check if HTTP/2 is supported and flag servers that don't have mitigations (SETTINGS_MAX_CONCURRENT_STREAMS). Not an RCE but caused massive DDoS campaigns. Low priority since it's DoS-only.

---

### CVE-2024-4577 — PHP-CGI — Windows Best-Fit Argument Injection RCE
- **CVSS**: 9.8
- **Affected**: PHP CGI on Windows (all versions before patches)
- **Check ID**: `cve.php_cgi_arg_injection`
- **Nuclei template**: Yes (CVE-2024-4577)
- **Nmap NSE**: No
- **Native probe**: Yes — `probePHPCGIVersion` in `internal/scanner/exposedfiles/scanner.go` sends `/?-v` and checks for PHP version output
- **Exploit chain**: No dedicated playbook
- **Recommend native?**: Already have native. Could add exploit chain.

---

### CVE-2025-24813 — Apache Tomcat — Partial PUT Deserialization RCE
- **CVSS**: 9.8
- **Affected**: Apache Tomcat 9.0.0-M1 to 11.0.2
- **Check ID**: `cve.tomcat_partial_put`
- **Nuclei template**: Yes
- **Nmap NSE**: No
- **Native probe**: Yes (test file `cve-tomcat-partial-put.yaml`)
- **Exploit chain**: Yes — `internal/exploit/playbooks/tomcat.yaml` covers Tomcat CVEs
- **Recommend native?**: Already covered.

---

### CVE-2025-29927 — Next.js — Middleware Auth Bypass
- **CVSS**: 9.1
- **Affected**: Next.js < 15.2.3 / < 14.2.25
- **Check ID**: `cve.nextjs_middleware_bypass`
- **Nuclei template**: Yes
- **Nmap NSE**: No
- **Native probe**: Yes (check ID registered, probe likely in exposedfiles)
- **Exploit chain**: No
- **Recommend native?**: Already have native.

---

### CVE-2025-30208 — Vite — Dev Server Arbitrary File Read
- **CVSS**: 9.1
- **Affected**: Vite dev server (all versions before patch)
- **Check ID**: `cve.vite_file_read`
- **Nuclei template**: Yes
- **Nmap NSE**: No
- **Native probe**: Yes (test file `cve-vite-file-read.yaml`)
- **Exploit chain**: No
- **Recommend native?**: Already covered.

---

### CVE-2017-5638 — Apache Struts 2 — OGNL Injection RCE (Equifax)
- **CVSS**: 10.0
- **Affected**: Apache Struts 2.3.x, 2.5.x
- **Check ID**: `cve.struts2_ognl_rce`
- **Nuclei template**: Yes (CVE-2017-5638)
- **Nmap NSE**: Yes (http-vuln-cve2017-5638)
- **Native probe**: Yes (test `cve-struts2-ognl-5638.yaml`)
- **Exploit chain**: No dedicated playbook
- **Recommend native?**: Already covered. Could add exploit chain.

---

### Databases & Applications

---

### CVE-2023-22515 — Atlassian Confluence — Admin Create Auth Bypass
- **CVSS**: 10.0
- **Affected**: Confluence Data Center 8.0.0-8.5.1
- **Check ID**: `cve.confluence_setup_bypass`
- **Nuclei template**: Yes (CVE-2023-22515)
- **Nmap NSE**: No
- **Native probe**: Yes — `probeConfluenceSetup` in `internal/scanner/exposedfiles/scanner.go` checks `/server-info.action?bootstrapStatusProvider.applicationConfig.setupComplete=false` for setup wizard re-enable
- **Exploit chain**: Yes — `internal/exploit/playbooks/confluence.yaml` has cve_exploit with post-exploit steps
- **Recommend native?**: Already have native. Excellent coverage.

---

### CVE-2023-22518 — Atlassian Confluence — Improper Authorization (Data Destruction)
- **CVSS**: 10.0
- **Affected**: Confluence Data Center/Server all versions
- **Check ID**: `cve.confluence_restore_bypass`
- **Nuclei template**: Yes
- **Nmap NSE**: No
- **Native probe**: Yes (probes restore endpoint)
- **Exploit chain**: Yes — `confluence.yaml` playbook
- **Recommend native?**: Already covered.

---

### CVE-2022-26134 — Atlassian Confluence — OGNL Injection RCE
- **CVSS**: 9.8
- **Affected**: Confluence Server/Data Center (all supported versions at time)
- **Check ID**: `cve.confluence_ognl_rce`
- **Nuclei template**: Yes (CVE-2022-26134)
- **Nmap NSE**: No
- **Native probe**: Yes — `probeConfluenceOGNL` in `internal/scanner/exposedfiles/scanner.go`
- **Exploit chain**: Yes — `internal/exploit/playbooks/confluence.yaml` has cve_exploit for CVE-2022-26134
- **Recommend native?**: Already have native. Full coverage.

---

### CVE-2023-46604 — Apache ActiveMQ — ClassInfo Deserialization RCE
- **CVSS**: 10.0
- **Affected**: ActiveMQ < 5.15.16/5.16.7/5.17.6/5.18.3
- **Check ID**: `cve.activemq_rce`
- **Nuclei template**: Yes (CVE-2023-46604)
- **Nmap NSE**: No
- **Native probe**: Yes — native port probe in `internal/scanner/portscan/probe_messaging.go` connects to port 61616, parses OpenWire version response, checks for vulnerable versions
- **Exploit chain**: Nuclei routing to `activemq` exploit playbook (`internal/exploit/playbooks/activemq.yaml`)
- **Recommend native?**: Already have native. Port-level detection is superior to nuclei for this binary protocol.

---

### CVE-2024-23897 — Jenkins — CLI Arbitrary File Read
- **CVSS**: 9.8
- **Affected**: Jenkins < 2.442 / LTS < 2.426.3
- **Check ID**: `cve.jenkins_cli_file_read`
- **Nuclei template**: Yes (CVE-2024-23897)
- **Nmap NSE**: No
- **Native probe**: Yes — dedicated scanner `internal/scanner/jenkins/scanner.go` reads X-Jenkins version header and compares against affected versions
- **Exploit chain**: Yes — `internal/exploit/playbooks/jenkins.yaml` has cve_exploit for CVE-2024-23897 with post-exploit steps
- **Recommend native?**: Already have native. Excellent coverage with exploit chain.

---

### CVE-2023-34362 — MOVEit Transfer — SQL Injection / CL0P Webshell
- **CVSS**: 9.8
- **Affected**: MOVEit Transfer (all versions before patches)
- **Check ID**: `cve.moveit_webshell`
- **Nuclei template**: Yes (CVE-2023-34362)
- **Nmap NSE**: No
- **Native probe**: Yes — probes for `/human2.aspx` (CL0P webshell indicator) in `internal/scanner/exposedfiles/scanner.go`
- **Exploit chain**: No (compromise indicator only, not active exploitation)
- **Recommend native?**: Already have native. Could add version-based detection of vulnerable MOVEit instances.

---

### CVE-2023-0669 — GoAnywhere MFT — Pre-Auth RCE
- **CVSS**: 7.2
- **Affected**: Fortra GoAnywhere MFT < 7.1.2
- **Check ID**: Missing
- **Nuclei template**: Yes (CVE-2023-0669)
- **Nmap NSE**: No
- **Native probe**: No
- **Exploit chain**: No
- **Recommend native?**: **Yes** — GoAnywhere admin console on `/goanywhere/` returns identifiable HTML. A simple GET probe + version extraction would detect this. Actively exploited by CL0P ransomware. **High priority gap.**

---

### CVE-2023-42793 — JetBrains TeamCity — Auth Bypass via /RPC2
- **CVSS**: 9.8
- **Affected**: TeamCity < 2023.05.4
- **Check ID**: `cve.teamcity_rpc2_bypass`
- **Nuclei template**: Yes
- **Nmap NSE**: No
- **Native probe**: Yes (referenced in exploit safety checks)
- **Exploit chain**: Nuclei routing to `teamcity` exploit playbook
- **Recommend native?**: Already covered.

---

### CVE-2024-27198 — JetBrains TeamCity — REST API Auth Bypass
- **CVSS**: 9.8
- **Affected**: TeamCity < 2023.11.4
- **Check ID**: `cve.teamcity_auth_bypass`
- **Nuclei template**: Yes
- **Nmap NSE**: No
- **Native probe**: Yes
- **Exploit chain**: Via nuclei routing
- **Recommend native?**: Already covered.

---

### Network Devices / VPN

---

### CVE-2024-3400 — Palo Alto PAN-OS — GlobalProtect Command Injection RCE
- **CVSS**: 10.0
- **Affected**: PAN-OS 10.2, 11.0, 11.1 with GlobalProtect gateway + device telemetry
- **Check ID**: `cve.pan_globalprotect_cmd_injection`
- **Nuclei template**: Yes (CVE-2024-3400)
- **Nmap NSE**: No
- **Native probe**: Yes — `probePANGlobalProtect` in `internal/scanner/exposedfiles/scanner.go` parses PAN-OS version from `/global-protect/prelogin.esp` and checks affected ranges
- **Exploit chain**: Nuclei routing to `paloalto` exploit playbook
- **Recommend native?**: Already have native. Version-based detection from prelogin is excellent.

---

### CVE-2023-46805 + CVE-2024-21887 — Ivanti Connect Secure — Auth Bypass + Cmd Injection Chain
- **CVSS**: 8.2 + 9.1 (chained = Critical)
- **Affected**: Ivanti Connect Secure, Policy Secure (all supported versions)
- **Check ID**: `cve.ivanti_connect_secure_bypass` + `cve.ivanti_connect_secure_cmd_injection`
- **Nuclei template**: Yes (CVE-2023-46805, CVE-2024-21887)
- **Nmap NSE**: No
- **Native probe**: Yes — `probeIvantiConnectSecure` in `internal/scanner/exposedfiles/scanner.go` probes `/dana-na/auth/url_default/welcome.cgi` path-traversal bypass; emits both CVEs as a chain
- **Exploit chain**: Nuclei routing to `ivanti` exploit playbook
- **Recommend native?**: Already have native. Chain detection is excellent.

---

### CVE-2025-0282 — Ivanti Connect Secure — Stack Overflow Pre-Auth RCE
- **CVSS**: 9.0
- **Affected**: Ivanti Connect Secure < 22.7R2.5
- **Check ID**: `cve.ivanti_cs_2025_0282`
- **Nuclei template**: Yes
- **Nmap NSE**: No
- **Native probe**: Yes — `probeIvantiCS2025` in `internal/scanner/exposedfiles/scanner.go`
- **Exploit chain**: No
- **Recommend native?**: Already covered.

---

### CVE-2024-20353 + CVE-2024-20359 — Cisco ASA — WebVPN DoS + Persistent Implant
- **CVSS**: 8.6 + 6.0
- **Affected**: Cisco ASA/FTD multiple versions
- **Check ID**: Partial — `cve.cisco_asa_ftd_rce` (CVE-2025-20333/20362), `cve.cisco_asa_ssl_vpn` (CVE-2023-20269). **No specific check IDs for CVE-2024-20353/20359.**
- **Nuclei template**: Yes (CVE-2024-20353)
- **Nmap NSE**: No
- **Native probe**: No specific probe for these two CVEs
- **Exploit chain**: No
- **Recommend native?**: **Yes** — These were actively exploited by nation-state actors (ArcaneDoor). Version fingerprinting via Cisco ASA WebVPN login page would catch this. **Medium priority gap** (have generic Cisco ASA playbook).

---

### CVE-2023-27997 — Fortinet FortiGate — SSL VPN Heap Overflow RCE (XORtigate)
- **CVSS**: 9.2
- **Affected**: FortiOS SSL VPN (multiple versions)
- **Check ID**: Missing
- **Nuclei template**: Yes (CVE-2023-27997)
- **Nmap NSE**: No
- **Native probe**: No (have CVE-2024-21762 and CVE-2022-40684 probes, but not this one)
- **Exploit chain**: No
- **Recommend native?**: **Yes** — We already fingerprint FortiOS version in `probeFortiOSSSLVPNVersion`. Adding a version range check for CVE-2023-27997 is trivial — just extend the existing function. **High priority gap** since the probe infrastructure already exists.

---

### CVE-2024-21762 — FortiOS — SSL VPN Out-of-Bounds Write RCE
- **CVSS**: 9.6
- **Affected**: FortiOS < 7.4.3 (and others)
- **Check ID**: `cve.fortios_ssl_vpn_rce`
- **Nuclei template**: Yes
- **Nmap NSE**: No
- **Native probe**: Yes — `probeFortiOSSSLVPNVersion` parses FortiOS version from `/remote/login` response and checks vulnerable ranges
- **Exploit chain**: No
- **Recommend native?**: Already have native. Could add exploit chain.

---

### CVE-2022-40684 — FortiOS/FortiProxy — HTTP Header Auth Bypass
- **CVSS**: 9.8
- **Affected**: FortiOS 7.0.0-7.0.6, 7.2.0-7.2.1; FortiProxy 7.0.0-7.0.6, 7.2.0
- **Check ID**: `cve.fortios_auth_bypass`
- **Nuclei template**: Yes
- **Nmap NSE**: No
- **Native probe**: Yes — `probeFortiOSAuthBypass` sends Forwarded header and checks for auth bypass response
- **Exploit chain**: No
- **Recommend native?**: Already have native.

---

### CVE-2024-55591 — FortiOS — WebSocket Management Auth Bypass
- **CVSS**: 9.6
- **Affected**: FortiOS 7.0.0-7.0.16, 7.2.0-7.2.8
- **Check ID**: `cve.fortios_ws_auth_bypass`
- **Nuclei template**: Yes
- **Nmap NSE**: No
- **Native probe**: Yes — `probeFortiOSWSAuthBypass` checks management API exposure
- **Exploit chain**: No
- **Recommend native?**: Already covered.

---

### CVE-2018-13379 — FortiOS — SSL VPN Credential File Read
- **CVSS**: 9.8
- **Affected**: FortiOS 5.6.3-5.6.7, 6.0.0-6.0.4
- **Check ID**: `cve.fortios_ssl_vpn_cred_leak`
- **Nuclei template**: Yes
- **Nmap NSE**: No
- **Native probe**: Yes (version-based detection via SSL VPN probe)
- **Exploit chain**: No
- **Recommend native?**: Already covered.

---

### CVE-2024-47575 — FortiManager — FortiJump FGFM Missing Auth
- **CVSS**: 9.8
- **Affected**: FortiManager multiple versions
- **Check ID**: `cve.fortimanager_fortijump`
- **Nuclei template**: Yes
- **Nmap NSE**: No
- **Native probe**: Yes
- **Exploit chain**: No
- **Recommend native?**: Already covered.

---

### CVE-2019-11510 — Pulse Secure VPN — Arbitrary File Read
- **CVSS**: 10.0
- **Affected**: Pulse Secure Connect Secure < 9.0R3.4, < 8.3R7.1, < 8.2R12.1
- **Check ID**: `cve.pulse_secure_vpn_exposed`
- **Nuclei template**: Yes (CVE-2019-11510)
- **Nmap NSE**: Yes (http-vuln-cve2019-11510)
- **Native probe**: Yes (login fingerprint)
- **Exploit chain**: Nuclei routing to `pulse_vpn` exploit playbook
- **Recommend native?**: Already covered.

---

### Cloud / Container

---

### CVE-2019-5736 — runc — Container Escape
- **CVSS**: 8.6
- **Affected**: runc < 1.0-rc6
- **Check ID**: `cve.runc_container_escape`
- **Nuclei template**: Yes (CVE-2019-5736)
- **Nmap NSE**: No
- **Native probe**: No (container-internal, detectable via Docker API version)
- **Exploit chain**: Yes — `internal/exploit/playbooks/docker.yaml` has cve_exploit for CVE-2019-5736
- **Recommend native?**: No — Requires container-internal access. Nuclei routing + Docker API version check is sufficient.

---

### CVE-2024-21626 — runc — Leaky Vessels Container Escape
- **CVSS**: 8.6
- **Affected**: runc < 1.1.12
- **Check ID**: Missing
- **Nuclei template**: Limited (detection requires Docker API or container runtime info)
- **Nmap NSE**: No
- **Native probe**: No
- **Exploit chain**: No
- **Recommend native?**: **Low priority** — Like CVE-2019-5736, exploiting this requires container access. Could detect via Docker API `/version` endpoint if exposed. Add a version check to Docker API probe.

---

### CVE-2023-2868 — Barracuda ESG — Pre-Auth Command Injection RCE
- **CVSS**: 9.8
- **Affected**: Barracuda Email Security Gateway (multiple firmware versions)
- **Check ID**: `cve.barracuda_esg_rce`
- **Nuclei template**: Yes (CVE-2023-2868)
- **Nmap NSE**: No
- **Native probe**: Yes — `probeBarracudaESG` in `internal/scanner/exposedfiles/scanner.go` fingerprints Barracuda login page
- **Exploit chain**: No
- **Recommend native?**: Already have native.

---

### CVE-2020-15257 — containerd — Host Networking Namespace Escape
- **CVSS**: 5.2
- **Affected**: containerd < 1.3.9, < 1.4.3
- **Check ID**: `cve.containerd_host_net_escape`
- **Nuclei template**: Yes
- **Nmap NSE**: No
- **Native probe**: No (container-internal)
- **Exploit chain**: Yes — `internal/exploit/playbooks/docker.yaml` has cve_exploit
- **Recommend native?**: No — Container-internal. Nuclei routing sufficient.

---

### CMS / Applications

---

### CVE-2023-3519 — Citrix NetScaler ADC/Gateway — Unauthenticated RCE
- **CVSS**: 9.8
- **Affected**: Citrix ADC/Gateway < 13.1-49.15 / < 13.0-91.13 / < 12.1-65.25
- **Check ID**: `cve.citrix_adc_rce_2023`
- **Nuclei template**: Yes (CVE-2023-3519)
- **Nmap NSE**: No
- **Native probe**: Yes — `probeCitrixADCNitro` in `internal/scanner/exposedfiles/scanner.go` parses Citrix version and checks vulnerable ranges
- **Exploit chain**: Nuclei routing to `citrix` exploit playbook
- **Recommend native?**: Already have native. Excellent version-based detection.

---

### CVE-2023-4966 — Citrix NetScaler — CitrixBleed Session Token Leak
- **CVSS**: 9.4
- **Affected**: Citrix NetScaler ADC/Gateway (multiple versions)
- **Check ID**: `cve.citrix_bleed`
- **Nuclei template**: Yes (CVE-2023-4966)
- **Nmap NSE**: No
- **Native probe**: Yes — `probeCitrixBleed` in `internal/scanner/exposedfiles/scanner.go`
- **Exploit chain**: No
- **Recommend native?**: Already have native.

---

### CVE-2024-1709 — ConnectWise ScreenConnect — Setup Wizard Auth Bypass
- **CVSS**: 10.0
- **Affected**: ScreenConnect < 23.9.8
- **Check ID**: `cve.screenconnect_setup_bypass`
- **Nuclei template**: Yes (CVE-2024-1709)
- **Nmap NSE**: No
- **Native probe**: Yes — checks `/SetupWizard.aspx` for HTTP 200 in `internal/scanner/exposedfiles/scanner.go`
- **Exploit chain**: Nuclei routing to `screenconnect` exploit playbook
- **Recommend native?**: Already have native.

---

### CVE-2023-47246 — SysAid — Path Traversal to RCE
- **CVSS**: 9.8
- **Affected**: SysAid On-Prem (before patches)
- **Check ID**: `cve.sysaid_path_traversal`
- **Nuclei template**: Yes
- **Nmap NSE**: No
- **Native probe**: Yes
- **Exploit chain**: No
- **Recommend native?**: Already covered.

---

### CVE-2023-49103 — ownCloud — graphapi phpinfo() Disclosure
- **CVSS**: 10.0
- **Affected**: ownCloud graphapi 0.2.0-0.3.0
- **Check ID**: `cve.owncloud_phpinfo`
- **Nuclei template**: Yes
- **Nmap NSE**: No
- **Native probe**: Yes
- **Exploit chain**: No
- **Recommend native?**: Already covered.

---

### CVE-2022-1388 — F5 BIG-IP — iControl REST Auth Bypass RCE
- **CVSS**: 9.8
- **Affected**: BIG-IP 16.1.x, 15.1.x, 14.1.x, 13.1.x
- **Check ID**: `cve.f5_bigip_icr_auth_bypass`
- **Nuclei template**: Yes (CVE-2022-1388)
- **Nmap NSE**: Yes (http-vuln-cve2022-1388)
- **Native probe**: Yes (test file `cve-f5-bigip-rce.yaml`)
- **Exploit chain**: No dedicated playbook
- **Recommend native?**: Already covered.

---

### CVE-2020-5902 — F5 BIG-IP — TMUI RCE
- **CVSS**: 9.8
- **Affected**: BIG-IP 15.x, 14.x, 13.x, 12.x, 11.x
- **Check ID**: `cve.f5_bigip_tmui_rce`
- **Nuclei template**: Yes
- **Nmap NSE**: Yes (http-vuln-cve2020-5902)
- **Native probe**: Yes
- **Exploit chain**: No
- **Recommend native?**: Already covered.

---

### CVE-2022-22954 — VMware Workspace ONE Access — SSTI RCE
- **CVSS**: 9.8
- **Affected**: VMware Workspace ONE Access, Identity Manager, vRealize Automation
- **Check ID**: `cve.vmware_workspace_one_ssti`
- **Nuclei template**: Yes
- **Nmap NSE**: No
- **Native probe**: Yes
- **Exploit chain**: No
- **Recommend native?**: Already covered.

---

### CVE-2021-26855 — Microsoft Exchange — ProxyLogon SSRF
- **CVSS**: 9.8
- **Affected**: Exchange Server 2013-2019
- **Check ID**: `cve.exchange_proxylogon`
- **Nuclei template**: Yes (CVE-2021-26855)
- **Nmap NSE**: Yes (http-vuln-cve2021-26855)
- **Native probe**: Yes — version detection via X-OWA-Version header
- **Exploit chain**: No
- **Recommend native?**: Already covered.

---

### CVE-2021-34473 — Microsoft Exchange — ProxyShell RCE Chain
- **CVSS**: 9.8
- **Affected**: Exchange Server 2013-2019
- **Check ID**: `cve.exchange_proxyshell`
- **Nuclei template**: Yes
- **Nmap NSE**: Yes
- **Native probe**: Yes — version from X-OWA-Version
- **Exploit chain**: No
- **Recommend native?**: Already covered.

---

### CVE-2021-21985 — VMware vCenter — Remote Code Execution
- **CVSS**: 9.8
- **Affected**: vCenter Server 6.5-7.0
- **Check ID**: `cve.vcenter_exposed`
- **Nuclei template**: Yes
- **Nmap NSE**: No
- **Native probe**: Yes — `/sdk` version disclosure
- **Exploit chain**: No
- **Recommend native?**: Already covered.

---

### CVE-2023-29357 — Microsoft SharePoint — JWT Auth Bypass
- **CVSS**: 9.8
- **Affected**: SharePoint Server 2019
- **Check ID**: `cve.sharepoint_jwt_bypass`
- **Nuclei template**: Yes
- **Nmap NSE**: No
- **Native probe**: Yes — version from MicrosoftSharePointTeamServices header
- **Exploit chain**: No
- **Recommend native?**: Already covered.

---

### CVE-2021-22205 — GitLab — ExifTool RCE
- **CVSS**: 10.0
- **Affected**: GitLab CE/EE 11.9+
- **Check ID**: `cve.gitlab_rce`
- **Nuclei template**: Yes (CVE-2021-22205)
- **Nmap NSE**: No
- **Native probe**: Yes — version from `/api/v4/version`
- **Exploit chain**: Yes — `internal/exploit/playbooks/gitlab.yaml` has cve_exploit
- **Recommend native?**: Already have native with exploit chain.

---

### CVE-2023-7028 — GitLab — Password Reset Account Takeover
- **CVSS**: 10.0
- **Affected**: GitLab CE/EE 16.1-16.7.1
- **Check ID**: `cve.gitlab_account_takeover`
- **Nuclei template**: Yes
- **Nmap NSE**: No
- **Native probe**: Yes (version-based)
- **Exploit chain**: Yes — `gitlab.yaml` exploit playbook
- **Recommend native?**: Already covered.

---

### CVE-2021-43798 — Grafana — Plugin Path Traversal
- **CVSS**: 7.5
- **Affected**: Grafana 8.0.0-8.3.0
- **Check ID**: `cve.grafana_path_traversal`
- **Nuclei template**: Yes (CVE-2021-43798)
- **Nmap NSE**: No
- **Native probe**: Yes (test `grafana-cve-2021-43798.yaml`)
- **Exploit chain**: Yes — `internal/exploit/playbooks/grafana.yaml` has cve_exploit with post-exploit steps
- **Recommend native?**: Already have native with exploit chain.

---

### CVE-2023-20198 — Cisco IOS XE — Web UI Implant (BadCandy)
- **CVSS**: 10.0
- **Affected**: Cisco IOS XE with web UI enabled
- **Check ID**: `cve.cisco_iosxe_implant`
- **Nuclei template**: Yes (CVE-2023-20198)
- **Nmap NSE**: No
- **Native probe**: Yes
- **Exploit chain**: Nuclei routing to `cisco_ios_xe` exploit playbook
- **Recommend native?**: Already covered.

---

### CVE-2023-32315 — Openfire — Path Traversal Auth Bypass
- **CVSS**: 9.8
- **Affected**: Openfire < 4.7.5
- **Check ID**: `cve.openfire_path_traversal`
- **Nuclei template**: Yes
- **Nmap NSE**: No
- **Native probe**: Yes (test `cve-openfire-traversal.yaml`)
- **Exploit chain**: No
- **Recommend native?**: Already covered.

---

### CVE-2020-14882 — Oracle WebLogic — Console Auth Bypass
- **CVSS**: 9.8
- **Affected**: WebLogic 10.3.6, 12.1.3, 12.2.1.3-4, 14.1.1
- **Check ID**: `cve.weblogic_console_bypass`
- **Nuclei template**: Yes (CVE-2020-14882)
- **Nmap NSE**: Yes
- **Native probe**: Yes (test `cve-weblogic-console.yaml`)
- **Exploit chain**: No
- **Recommend native?**: Already covered.

---

### CVE-2022-29464 — WSO2 — Unrestricted File Upload RCE
- **CVSS**: 9.8
- **Affected**: WSO2 API Manager, Identity Server, multiple products
- **Check ID**: `cve.wso2_file_upload_rce`
- **Nuclei template**: Yes
- **Nmap NSE**: No
- **Native probe**: Yes (test `cve-wso2-upload.yaml`)
- **Exploit chain**: No
- **Recommend native?**: Already covered.

---

### CVE-2022-37042 — Zimbra — Auth Bypass to RCE
- **CVSS**: 9.8
- **Affected**: Zimbra Collaboration Suite 8.8.15, 9.0
- **Check ID**: `cve.zimbra_auth_bypass`
- **Nuclei template**: Yes
- **Nmap NSE**: No
- **Native probe**: Yes (test `cve-zimbra-auth.yaml`)
- **Exploit chain**: No
- **Recommend native?**: Already covered.

---

### CVE-2023-50164 — Apache Struts 2 — S2-066 File Upload RCE
- **CVSS**: 9.8
- **Affected**: Apache Struts 2.0.0-6.3.0
- **Check ID**: `cve.struts2_s2066`
- **Nuclei template**: Yes
- **Nmap NSE**: No
- **Native probe**: Yes (test `cve-struts2-s2066.yaml`)
- **Exploit chain**: No
- **Recommend native?**: Already covered.

---

### CVE-2022-47966 — ManageEngine — SAML Pre-Auth RCE
- **CVSS**: 9.8
- **Affected**: Multiple ManageEngine products with SAML SSO
- **Check ID**: `cve.manageengine_saml_rce`
- **Nuclei template**: Yes
- **Nmap NSE**: No
- **Native probe**: Yes
- **Exploit chain**: No
- **Recommend native?**: Already covered.

---

### CVE-2022-24086 — Adobe Commerce/Magento — Template Injection RCE
- **CVSS**: 9.8
- **Affected**: Adobe Commerce, Magento Open Source
- **Check ID**: `cve.magento_template_rce`
- **Nuclei template**: Yes
- **Nmap NSE**: No
- **Native probe**: Yes (test `cve-magento-template.yaml`)
- **Exploit chain**: No
- **Recommend native?**: Already covered.

---

### CVE-2024-6387 — OpenSSH — RegreSSHion Signal Handler Race RCE
- **CVSS**: 8.1
- **Affected**: OpenSSH 8.5p1-9.7p1
- **Check ID**: `cve.openssh_regresshion`
- **Nuclei template**: Yes
- **Nmap NSE**: No (banner check possible)
- **Native probe**: Yes (test `cve-openssh-regresshion.yaml`) — SSH banner version parsing
- **Exploit chain**: No
- **Recommend native?**: Already covered.

---

### CVE-2025-31324 — SAP NetWeaver — Unauthenticated File Upload RCE
- **CVSS**: 10.0
- **Affected**: SAP NetWeaver Visual Composer
- **Check ID**: `cve.sap_netweaver_2025_31324`
- **Nuclei template**: Yes
- **Nmap NSE**: No
- **Native probe**: Yes
- **Exploit chain**: No
- **Recommend native?**: Already covered.

---

### CVE-2025-1974 — ingress-nginx — IngressNightmare Pre-Auth RCE
- **CVSS**: 9.8
- **Affected**: ingress-nginx admission webhook
- **Check ID**: `cve.ingress_nightmare`
- **Nuclei template**: Yes
- **Nmap NSE**: No
- **Native probe**: Yes
- **Exploit chain**: No
- **Recommend native?**: Already covered.

---

### CVE-2023-36844/36845 — Juniper J-Web — PHP Env Injection RCE
- **CVSS**: 9.8
- **Affected**: Juniper SRX/EX Series
- **Check ID**: `cve.juniper_jweb_php_injection`
- **Nuclei template**: Yes
- **Nmap NSE**: No
- **Native probe**: Yes
- **Exploit chain**: No
- **Recommend native?**: Already covered.

---

### CVE-2020-10148 — SolarWinds Orion — Auth Bypass
- **CVSS**: 9.8
- **Affected**: SolarWinds Orion Platform
- **Check ID**: `cve.solarwinds_orion_exposed`
- **Nuclei template**: Yes
- **Nmap NSE**: No
- **Native probe**: Yes
- **Exploit chain**: No
- **Recommend native?**: Already covered.

---

### CVE-2021-40539 — ManageEngine ADSelfService Plus — Auth Bypass RCE
- **CVSS**: 9.8
- **Affected**: ManageEngine ADSelfService Plus < 6114
- **Check ID**: `cve.manageengine_adss_rce`
- **Nuclei template**: Yes
- **Nmap NSE**: No
- **Native probe**: Yes
- **Exploit chain**: No
- **Recommend native?**: Already covered.

---

### CVE-2020-13942 — Apache Unomi — MVEL/OGNL RCE
- **CVSS**: 9.8
- **Affected**: Apache Unomi < 1.5.2
- **Check ID**: `cve.apache_unomi_rce`
- **Nuclei template**: Yes
- **Nmap NSE**: No
- **Native probe**: Yes (test `cve-apache-unomi-rce.yaml`)
- **Exploit chain**: No
- **Recommend native?**: Already covered.

---

### CVE-2018-7600 — Drupal — Drupalgeddon2 RCE
- **CVSS**: 9.8
- **Affected**: Drupal 7.x < 7.58, 8.x < 8.5.1
- **Check ID**: `cve.drupal_drupalgeddon2`
- **Nuclei template**: Yes (CVE-2018-7600)
- **Nmap NSE**: Yes (http-vuln-cve2018-7600)
- **Native probe**: Yes (test `cve-drupal-drupalgeddon2.yaml`)
- **Exploit chain**: No
- **Recommend native?**: Already covered.

---

### CVE-2019-19781 — Citrix ADC/Gateway — Path Traversal
- **CVSS**: 9.8
- **Affected**: Citrix ADC/Gateway (multiple versions)
- **Check ID**: `cve.citrix_adc_info_leak`
- **Nuclei template**: Yes (CVE-2019-19781)
- **Nmap NSE**: Yes (http-vuln-cve2019-19781)
- **Native probe**: Yes
- **Exploit chain**: No
- **Recommend native?**: Already covered.

---

### CVE-2022-22963 — Spring Cloud Function — SpEL RCE
- **CVSS**: 9.8
- **Affected**: Spring Cloud Function 3.1.6, 3.2.2 and earlier
- **Check ID**: `cve.spring_cloud_function_rce`
- **Nuclei template**: Yes
- **Nmap NSE**: No
- **Native probe**: Yes
- **Exploit chain**: Yes — `spring_actuator.yaml` exploit playbook
- **Recommend native?**: Already covered.

---

### CVE-2025-32433 — Erlang/OTP SSH — Pre-Auth RCE
- **CVSS**: 10.0
- **Affected**: Erlang/OTP SSH server (all versions before patch)
- **Check ID**: `cve.erlang_otp_ssh_rce`
- **Nuclei template**: Yes
- **Nmap NSE**: No
- **Native probe**: Yes (test `cve-erlang-ssh-rce.yaml`)
- **Exploit chain**: No
- **Recommend native?**: Already covered.

---

### CVE-2023-28432 — MinIO — Environment Variable Disclosure
- **CVSS**: 7.5
- **Affected**: MinIO < RELEASE.2023-03-20T20-16-18Z
- **Check ID**: `cve.minio_env_disclosure`
- **Nuclei template**: Yes (CVE-2023-28432)
- **Nmap NSE**: No
- **Native probe**: Yes (test `cve-minio-env.yaml`)
- **Exploit chain**: Yes — `minio.yaml` exploit playbook
- **Recommend native?**: Already covered with exploit chain.

---

### CVE-2023-27524 — Apache Superset — Default SECRET_KEY
- **CVSS**: 8.9
- **Affected**: Apache Superset (default installations)
- **Check ID**: `cve.superset_default_secret_key`
- **Nuclei template**: Yes (CVE-2023-27524)
- **Nmap NSE**: No
- **Native probe**: Yes (test `cve-superset-secret.yaml`)
- **Exploit chain**: Via nuclei routing to `superset` exploit playbook
- **Recommend native?**: Already covered.

---

### CVE-2020-1472 — Zerologon — Netlogon Privilege Escalation
- **CVSS**: 10.0
- **Affected**: Windows Server (all versions with Netlogon)
- **Check ID**: Missing
- **Nuclei template**: No (not HTTP-based)
- **Nmap NSE**: Yes (smb-vuln-zerologon — but unreliable)
- **Native probe**: No
- **Exploit chain**: No
- **Recommend native?**: **No** — This is an MS-NRPC protocol vulnerability, not HTTP. Requires SMB/Netlogon access. Out of scope for HTTP scanning. Potentially detectable via port scan + SMB version fingerprinting but risky to probe.

---

## Priority Gap List

### High Priority — Should Implement

| CVE | Product | CVSS | Reason | Effort |
|---|---|---|---|---|
| CVE-2023-0669 | GoAnywhere MFT | 7.2 | CL0P ransomware actively exploited. Login page fingerprint is trivial. | Low — add check ID + path probe for `/goanywhere/` |
| CVE-2023-27997 | FortiGate SSL VPN | 9.2 | Nation-state exploited. We already parse FortiOS version — just add range check. | Very Low — extend `probeFortiOSSSLVPNVersion` |

### Medium Priority — Nice to Have

| CVE | Product | CVSS | Reason | Effort |
|---|---|---|---|---|
| CVE-2024-20353/20359 | Cisco ASA | 8.6/6.0 | ArcaneDoor nation-state campaign. Need Cisco ASA version fingerprinting. | Medium — add WebVPN version probe |
| CVE-2023-44487 | HTTP/2 Rapid Reset | 7.5 | Massive DDoS vector. Could check HTTP/2 support + SETTINGS frame. | Medium — protocol-level check |
| CVE-2024-21626 | runc (Leaky Vessels) | 8.6 | Container escape. Could detect via Docker API `/version`. | Low — extend Docker probe |

### Low Priority — Deferred

| CVE | Product | CVSS | Reason | Effort |
|---|---|---|---|---|
| CVE-2020-1472 | Windows Netlogon | 10.0 | Not HTTP. Requires MS-NRPC protocol. Out of scope for surface scanning. | High |

---

## Exploit Chain Coverage

The following CVEs have **full exploit chains** (detection + exploit playbook + post-exploit):

| CVE | Product | Playbook |
|---|---|---|
| CVE-2021-41773/42013 | Apache httpd | `apache.yaml` |
| CVE-2023-22515 | Confluence | `confluence.yaml` |
| CVE-2022-26134 | Confluence | `confluence.yaml` |
| CVE-2024-23897 | Jenkins | `jenkins.yaml` |
| CVE-2021-43798 | Grafana | `grafana.yaml` |
| CVE-2021-22205 | GitLab | `gitlab.yaml` |
| CVE-2023-7028 | GitLab | `gitlab.yaml` |
| CVE-2019-5736 | runc/Docker | `docker.yaml` |
| CVE-2022-22965 | Spring4Shell | `spring_actuator.yaml` |
| CVE-2022-22963 | Spring Cloud Function | `spring_actuator.yaml` |
| CVE-2022-24706 | CouchDB | `couchdb.yaml` |
| CVE-2022-0543 | Redis | `redis.yaml` |
| CVE-2019-1003000 | Jenkins | `jenkins.yaml` |
| CVE-2020-11978 | Airflow | `airflow.yaml` |
| CVE-2023-28432 | MinIO | `minio.yaml` |

The following high-impact CVEs are **detected but lack exploit chains**:

| CVE | Product | Has Native Probe | Priority for Chain |
|---|---|---|---|
| CVE-2024-3400 | PAN-OS | Yes | High |
| CVE-2023-46805+CVE-2024-21887 | Ivanti ICS | Yes | High |
| CVE-2024-21762 | FortiOS SSL VPN | Yes | High |
| CVE-2023-46604 | ActiveMQ | Yes | High |
| CVE-2023-3519 | Citrix ADC | Yes | Medium |
| CVE-2024-1709 | ScreenConnect | Yes | Medium |
| CVE-2023-34362 | MOVEit | Yes | Low (indicator only) |

---

## Nmap NSE Coverage (for reference)

The following audited CVEs have nmap NSE scripts available:
- CVE-2021-41773 (http-vuln-cve2021-41773)
- CVE-2021-44228 (log4shell)
- CVE-2017-5638 (http-vuln-cve2017-5638)
- CVE-2019-11510 (http-vuln-cve2019-11510)
- CVE-2022-1388 (http-vuln-cve2022-1388)
- CVE-2020-5902 (http-vuln-cve2020-5902)
- CVE-2021-26855 (http-vuln-cve2021-26855)
- CVE-2018-7600 (http-vuln-cve2018-7600)
- CVE-2019-19781 (http-vuln-cve2019-19781)
- CVE-2014-0160 (ssl-heartbleed — not in audit scope but detected)

For all of these, our native probes are either equivalent or superior (faster, more accurate version matching, tighter integration with exploit chains).

---

## Recommendations

1. **Immediate**: Add CVE-2023-27997 (FortiGate XORtigate) detection — trivial extension of existing `probeFortiOSSSLVPNVersion` function.

2. **Short-term**: Add CVE-2023-0669 (GoAnywhere MFT) probe — new check ID + simple `/goanywhere/` login page fingerprint. Actively exploited by CL0P.

3. **Short-term**: Add exploit chains for high-impact CVEs that have native detection but no post-exploit playbook (PAN-OS, Ivanti ICS, ActiveMQ, FortiOS).

4. **Medium-term**: Add Cisco ASA version fingerprinting for CVE-2024-20353/20359 (ArcaneDoor campaign).

5. **Deferred**: HTTP/2 Rapid Reset (CVE-2023-44487) and Leaky Vessels (CVE-2024-21626) are lower priority due to DoS-only / container-internal nature.

6. **Out of scope**: Zerologon (CVE-2020-1472) is not HTTP-exploitable. Leave to dedicated AD assessment tools.
