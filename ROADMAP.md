# Beacon Roadmap

## Current State (2026-04-09)

- **1,195 check IDs** across 150+ scanners
- **~390 check IDs tested** in drydock with 510+ test files
- **53 exploit playbooks** + 60 post-exploit modules
- **126 native Go protocol probes** (no nmap dependency for service ID)
- **7 attack chain patterns** in correlation scanner
- **5 active exploit chains** in chain engine (gated behind --exploit)
- **Nuclei → exploit routing** maps 38 tags + 17 CVE template IDs to playbooks
- **Full pipeline E2E**: 43 findings against Juice Shop in one scan
- **CI**: parallelized Go CI (lint || build+test || security), 6 scanner test batches

## Immediate (next session)

### Remaining Drydock Tests (~30 check IDs)
Check IDs that need the crawl pipeline to work (won't fire in --scanners isolated mode):
- second-order injection (3 IDs)
- race condition (1 ID)
- method bypass, horizontal privesc, state skip (3 IDs)
- WebSocket (3 IDs)
- cache poisoning (3 IDs)
- WAF bypass (11 IDs)
- API fuzzing (1 ID)
- prototype pollution (1 ID)

**Approach**: Write full-pipeline E2E tests (no --scanners filter) against apps that trigger these.

### Variant Testing
Test the same vulnerability across multiple tech stacks:
- SQLi: PHP + Node.js + Python + Java
- XSS: PHP + React + Angular + Vue
- SSRF: Python + Java + Node.js
- This ensures detection works regardless of the backend technology.

## Medium Term

### Beacon Agent
Cloud-focused post-exploitation:
- Cloud IAM mapping (AWS STS, GCP metadata, Azure IMDS)
- Privilege escalation paths
- Multi-channel data exfiltration
- Lateral movement via discovered credentials

### Forecast Integration
Wire beacon's correlation chains into the AI analysis layer:
- Attack path prioritization
- Business impact assessment
- Automated remediation suggestions
- Cross-scan trending

### Windows Server VM Tests (12 check IDs)
Requires a Windows Server VM with Active Directory:
- port.active_directory_exposed
- port.global_catalog_exposed
- port.kerberos_exposed
- port.winrm_exposed
- port.wins_exposed, port.netbios_ns_exposed
- port.smb_null_session
- port.rdp_weak_encryption
- web.iis_shortname

## Performance Benchmarks

| Target | Scan Time | Notes |
|--------|-----------|-------|
| localhost (full pipeline) | 8.0s | Private IP skip + connection pooling |
| localhost (7 scanners) | 0.76s | Filtered mode |
| MongoDB (single port) | 0.7s | Concurrent quickProtocolCheck |
| CouchDB (single port) | 6.0s | ProbeCatTLS + exploit filtering |

## Architecture Decisions

- **Native Go probes > nmap**: 126 probes, 10-50x faster, zero dependency
- **Keep nuclei**: 8,000+ CVE templates, community-maintained
- **Keep testssl**: 100+ TLS checks, not worth reimplementing
- **Service-aware scanner skipping**: Database targets skip 30+ HTTP scanners
- **Exploit safety gates**: read_only/write/destructive classification enforced at runtime
- **Honeypot detection**: skip exploitation when target is a honeypot
