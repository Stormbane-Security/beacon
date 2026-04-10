# Untestable port.* Check IDs

Port check IDs that cannot be covered by drydock tests, grouped by reason.

## Not emitted by any scanner (check ID defined but no probe emits it)

These check IDs exist in `internal/finding/checkids.go` but no scanner code
references them. They need scanner implementation before tests can be written.

| Check ID | Notes |
|---|---|
| `port.checkpoint_topology` | Defined but no detect function emits it |
| `port.couchdb_no_auth` | Defined but probe emits `port.couchdb_unauthenticated` instead |
| `port.k8s_dashboard_exposed` | Defined but no detect function emits it |
| `port.kubelet_readonly_exposed` | Defined but no detect function emits it |
| `port.prometheus_exposed` | Defined but probe emits `port.prometheus_unauthenticated` instead |
| `port.snmp_writable_community` | Defined but no detect function emits it |
| `port.telnetd_gnu_vulnerable` | Defined but no detect function emits it |

## Requires Active Directory domain controller

| Check ID | Reason |
|---|---|
| `port.active_directory_exposed` | Needs full AD DC (not available as lightweight Docker image) |
| `port.global_catalog_exposed` | Needs AD DC with Global Catalog role (port 3268) |
| `port.kerberos_exposed` | Needs AD/MIT Kerberos KDC |

## Requires real network hardware or vendor-specific OS

| Check ID | Reason |
|---|---|
| `port.cisco_smart_install` | Cisco IOS-only protocol |
| `port.juniper_anomaly_exposed` | Junos OS anomaly detection port |
| `port.mikrotik_api_exposed` | RouterOS API — no public Docker image |
| `port.winbox_exposed` | RouterOS Winbox protocol — no public Docker image |

## Requires ICS/SCADA hardware or specialized simulators

| Check ID | Reason |
|---|---|
| `port.bacnet_exposed` | BACnet/IP building automation — UDP 47808, no reliable Docker simulator |
| `port.ethernet_ip_exposed` | EtherNet/IP CIP protocol — needs PLC simulator |

## UDP-only protocols (hard to test in Docker)

| Check ID | Reason |
|---|---|
| `port.ike_exposed` | IKE/IPsec on UDP 500 — needs strongSwan + complex config |
| `port.iscsi_exposed` | iSCSI target — TCP but needs kernel module support |
| `port.mdns_exposed` | mDNS on UDP 5353 — needs multicast networking |
| `port.netbios_ns_exposed` | NetBIOS Name Service on UDP 137 |
| `port.ntp_amplification` | NTP monlist on UDP 123 — needs vulnerable ntpd version |
| `port.ssdp_exposed` | SSDP on UDP 1900 — needs UPnP stack |
| `port.stun_exposed` | STUN on UDP 3478 — needs STUN server |

## Windows-only or vendor-specific services

| Check ID | Reason |
|---|---|
| `port.winrm_exposed` | Windows Remote Management — needs Windows Server |
| `port.wins_exposed` | Windows Internet Naming Service — legacy, Windows-only |
| `port.netconf_exposed` | NETCONF over SSH — needs network device with NETCONF subsystem |

## Requires specific vulnerable software versions

| Check ID | Reason |
|---|---|
| `port.exim_vulnerable` | Needs specific vulnerable Exim version (no public Docker image) |
| `port.ftp_wing_rce` | Wing FTP Server RCE — Windows-only commercial software |

## Printer/specialized protocols

| Check ID | Reason |
|---|---|
| `port.jetdirect_exposed` | HP JetDirect on port 9100 — needs printer or simulator |
| `port.ipp_exposed` | Internet Printing Protocol on port 631 — needs CUPS but probe may expect specific responses |

## Specialized server protocols

| Check ID | Reason |
|---|---|
| `port.bgp_exposed` | BGP on TCP 179 — needs BGP speaker (FRRouting possible but complex) |
| `port.sip_exposed` | SIP on UDP 5060 — needs SIP registrar |
| `port.rtsp_exposed` | RTSP on TCP 554 — needs media server |
| `port.radius_exposed` | RADIUS on UDP 1812 — needs FreeRADIUS with specific config |
| `port.asterisk_ami_exposed` | Asterisk Manager Interface on TCP 5038 — needs Asterisk PBX |

## Heavy images with complex setup requirements

| Check ID | Reason |
|---|---|
| `port.adguard_exposed` | Needs initial setup wizard completion before API responds |
| `port.argocd_exposed` | ArgoCD server — requires K8s-like environment or complex setup |
| `port.bamboo_exposed` | Atlassian Bamboo — very heavy, requires license |
| `port.superset_default_credentials` | Apache Superset — heavy image, complex init, needs DB migration |
| `port.zabbix_default_credentials` | Zabbix — needs zabbix-server + zabbix-web + database |
| `port.pgadmin_default_credentials` | pgAdmin — probe broken (reported separately) |
| `port.wazuh_api_exposed` | Wazuh manager — complex multi-container setup |

## AI/ML images (too heavy for CI)

| Check ID | Reason |
|---|---|
| `port.comfyui_exposed` | ComfyUI — requires GPU, very large image |
| `port.sglang_exposed` | SGLang — requires GPU, very large image |
| `port.vllm_exposed` | vLLM — requires GPU, very large image |
| `port.openwebui_exposed` | Open WebUI — large image, needs Ollama backend |
| `port.huggingface_tgi_exposed` | HuggingFace TGI — requires GPU, very large image |
| `port.localai_exposed` | LocalAI — large image, CPU inference very slow |

## Requires real Kubernetes cluster

| Check ID | Reason |
|---|---|
| `port.k8s_dashboard_exposed` | Kubernetes Dashboard — needs real cluster |
| `port.kubelet_readonly_exposed` | Kubelet read-only port 10255 — needs real kubelet |
| `port.kubelet_unauthenticated` | Kubelet port 10250 — needs real kubelet |

## Requires specific misconfiguration not achievable in standard Docker images

| Check ID | Reason |
|---|---|
| `port.vault_unsealed_no_auth` | Vault dev mode still requires token for /v1/sys/mounts. Needs a Vault with ACLs completely disabled, which no standard Docker config provides |
| `port.rdp_weak_encryption` | xrdp supports TLS, so probe detects rdp_no_nla instead. Needs an RDP server that rejects TLS entirely (Windows with specific GPO) |

## Hypervisor

| Check ID | Reason |
|---|---|
| `port.proxmox_exposed` | Proxmox VE — bare-metal hypervisor, cannot run in Docker |
