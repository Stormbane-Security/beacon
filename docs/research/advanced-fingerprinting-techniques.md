# Advanced Fingerprinting & Discovery Techniques Research

Research compiled April 2026. Techniques sourced from academic papers, bug bounty
methodologies, red team tradecraft, and open-source tooling analysis.

---

## 1. Advanced HTTP Fingerprinting

### 1.1 HTTP Header Ordering Analysis

**How it works:** Different web servers return HTTP response headers in characteristic
orders. Apache consistently places `Date` before `Server`, then `Last-Modified`,
`ETag`, `Accept-Ranges`, `Content-Length`, `Connection`, `Content-Type`. Nginx
typically orders `Date`, `Content-Type`, `Content-Length` with `Server` appearing
later. IIS places `Server` before `Date`. These orderings persist even when the
`Server` header value is spoofed or removed.

**What it reveals:** Web server software identity, even behind reverse proxies or
when banners are stripped. Can also reveal proxy chains (e.g., Cloudflare in front
of Nginx in front of Apache each contribute their own ordering artifacts).

**Implementation difficulty (Go):** Easy. Make an HTTP request, record the order of
response headers using `httputil.DumpResponse` or iterate `resp.Header` (note: Go's
`http.Response.Header` map doesn't preserve order, so you need to use the raw
response or a custom transport that captures wire-order headers via
`net/http/httputil`).

**Mode:** Passive (surface). Just a normal GET request.

**Real-world example:** The httprint tool uses header ordering as one of its primary
fingerprint vectors and can identify server software with high confidence even when
all identifying headers are removed. The NDSS 2024 paper "Untangle" achieved 100%
accuracy on first-layer identification and 90.3% on second-layer identification
using this and related techniques across 13 proxy/server technologies.

### 1.2 Error Page Differential Analysis

**How it works:** Send requests designed to trigger different HTTP error codes (400,
401, 403, 404, 405, 500, 501, 502, 503, 505) and compare response bodies. Each
server has distinctive default error pages:

- Apache: Uses `<!DOCTYPE HTML PUBLIC` declarations, formatted HTML with server
  version
- Nginx: Returns simplified HTML markup with server version
- IIS: Returns detailed error pages with Microsoft-specific styling
- Tomcat: Returns Java stack traces with distinctive formatting
- lighttpd: Returns XHTML/XML-formatted responses

Specific trigger techniques:
- `GET / HTTP/3.0` -- invalid HTTP version triggers 400 or 505
- `SANTA / HTTP/1.1` -- invalid method triggers 400 or 501
- `DELETE / HTTP/1.0` -- Apache returns 405, IIS returns 403, Netscape returns 401
- `GET /AAAA...x4096 HTTP/1.1` -- long URL triggers 414
- `GET / JUNK/1.0` -- invalid protocol; Apache returns 200, IIS returns 400

**What it reveals:** Exact server software and version, even when Server header is
modified. The HTML structure, CSS classes, specific phrases ("Method Not Allowed"
vs "Operation on resource forbidden"), and DOCTYPE declarations are all distinctive.

**Implementation difficulty (Go):** Easy. Send 5-8 malformed requests, hash the
response bodies (or extract key phrases), compare against a signature database.

**Mode:** Active (deep). Malformed requests may trigger WAF alerts or IDS signatures.

**Real-world example:** The httprint tool uses statistical fuzzy analysis to compare
error responses against known signatures, achieving reliable identification even
through banner modification.

### 1.3 HTTP Method Behavior Fingerprinting

**How it works:** Send requests using each HTTP method (GET, HEAD, POST, PUT, DELETE,
PATCH, OPTIONS, TRACE, CONNECT) to the same endpoint and record:
- Status code returned for each method
- Whether an `Allow` header is present
- Response body content and length
- Whether CORS headers appear on OPTIONS

Different servers respond to unsupported methods differently:
- Apache: 405 with `Allow` header listing supported methods
- IIS: 403 for DELETE, different handling per method
- Nginx: 405 with minimal response body
- Netscape/iPlanet: 401 requiring authentication

The OPTIONS response is particularly revealing -- it lists allowed methods and may
include server-specific headers.

**What it reveals:** Server software, framework (Rails returns specific headers on
OPTIONS), whether WebDAV is enabled (PROPFIND, MKCOL methods accepted), and API
framework behavior.

**Implementation difficulty (Go):** Easy. Send 9 requests with different methods,
record status codes. Build a signature like `GET:200,HEAD:200,POST:405,PUT:405,DELETE:405,OPTIONS:200,TRACE:405`.

**Mode:** Active (deep). PUT/DELETE requests could have side effects on misconfigured
servers.

### 1.4 HTTP Response Timing Analysis

**How it works:** Measure Time-To-First-Byte (TTFB) for identical requests. A server
directly connected to the internet responds faster than one behind a reverse proxy.
The reverse proxy adds measurable latency from its own processing and forwarding.
NDSS 2025 research on "cross-layer RTT" showed that comparing TCP-level RTT with
HTTP-level RTT reveals proxy presence -- the application-layer RTT includes
additional time for request forwarding that creates measurable discrepancies.

Technique: Send multiple requests, measure both TCP handshake time and HTTP response
time. If HTTP response time significantly exceeds TCP RTT, a proxy or additional
processing layer is present. The delta reveals the approximate processing overhead.

**What it reveals:** Presence of reverse proxies, CDNs, WAFs. Can estimate
geographic distance between proxy and origin. JA4L/JA4LS fingerprints encode this
latency information.

**Implementation difficulty (Go):** Medium. Need precise timing at TCP level (custom
`net.Dialer` with timestamps on handshake completion) and HTTP level (time from
request sent to first byte received). Statistical analysis over multiple samples.

**Mode:** Passive (surface). Normal requests, just measured precisely.

### 1.5 Connection Behavior Fingerprinting

**How it works:** Analyze how servers handle connection-level HTTP features:

- **Keep-Alive timing:** The `Keep-Alive: timeout=N, max=M` header values vary by
  server. Apache defaults to `timeout=5, max=100`. Nginx doesn't send Keep-Alive
  header by default.
- **Max concurrent connections:** Open multiple simultaneous connections; different
  servers enforce different limits.
- **Chunked encoding support:** Send `Transfer-Encoding: chunked` requests and
  observe behavior. Nginx, Apache, and IIS handle malformed chunked requests
  differently.
- **Pipelining behavior:** Send multiple requests on a single connection without
  waiting for responses. HTTP/1.1 pipelining support varies.
- **Connection close behavior:** Whether the server sends `Connection: close` or
  keeps connections open varies by implementation.

**What it reveals:** Server software, version-specific behaviors, proxy presence.

**Implementation difficulty (Go):** Medium. Requires raw TCP connections via
`net.Conn` with manual HTTP request construction to test edge cases that Go's HTTP
client would normalize.

**Mode:** Active (deep). Connection abuse tests could affect server stability.

### 1.6 TLS Fingerprinting (JA3/JA4)

**How it works:** The JA3S method fingerprints server TLS by hashing the Server Hello
message fields: TLS version, accepted cipher suite, and extensions list. The
concatenated values are MD5-hashed into a 32-character fingerprint.

JA4S improves on JA3S with the `a_b_c` format that is resistant to randomization and
supports partial matching. JA4X fingerprints X.509 certificates. JA4H fingerprints
HTTP headers.

The complete JA4+ suite:
- **JA4** -- TLS client fingerprint
- **JA4S** -- TLS server fingerprint
- **JA4H** -- HTTP client fingerprint (header ordering, values)
- **JA4L/JA4LS** -- Client/server latency measurement
- **JA4X** -- X.509 certificate fingerprint
- **JA4SSH** -- SSH traffic fingerprint (packet sizes, timing)
- **JA4T** -- TCP client fingerprint (window size, options, MSS)
- **JA4TS** -- TCP server fingerprint
- **JA4D** -- DHCP client fingerprint
- **JA4D6** -- DHCPv6 client fingerprint

**What it reveals:** Server software, TLS library (OpenSSL vs BoringSSL vs Go
crypto/tls), operating system, proxy presence. JA4T reveals OS via TCP stack
parameters.

**Implementation difficulty (Go):** Hard. Requires intercepting the raw TLS
handshake before Go's `crypto/tls` processes it. Need a custom TLS implementation
or packet capture. The `github.com/FoxIO-LLC/ja4` repository provides reference
implementations. JA4T requires raw socket access for TCP SYN analysis.

**Mode:** Passive (surface). Just analyzing normal TLS handshake parameters.

**Real-world example:** AWS WAF added JA4 fingerprinting support in March 2025 for
rate-based rules. GreyNoise uses JA4T to identify scanning infrastructure --
discovering that specific JA4T fingerprints like `29200_2-4-8-1-3_1424_7` map to
known scanning clusters in specific cloud providers.

### 1.7 HTTP/2 SETTINGS Frame Fingerprinting

**How it works:** When an HTTP/2 connection is established, the client sends a
SETTINGS frame containing six parameters: HEADER_TABLE_SIZE, ENABLE_PUSH,
MAX_CONCURRENT_STREAMS, INITIAL_WINDOW_SIZE, MAX_FRAME_SIZE, MAX_HEADER_LIST_SIZE.
Different implementations use different default values.

The fingerprint format: `[SETTINGS]|WINDOW_UPDATE|PRIORITY|Pseudo-Header-Order`

Servers also have characteristic SETTINGS values. Nginx, Apache with mod_http2,
Envoy, Caddy, and other HTTP/2 implementations all use different defaults.

Additionally, pseudo-header ordering (`:method`, `:path`, `:authority`, `:scheme`)
varies between implementations.

**What it reveals:** HTTP/2 implementation (Nginx, Apache, h2o, Envoy, etc.),
potentially the web framework, proxy software.

**Implementation difficulty (Go):** Hard. Go's `net/http` HTTP/2 implementation
doesn't expose raw SETTINGS frames. Need to use `golang.org/x/net/http2` directly
or capture at the frame level. For server fingerprinting, connect and read the
server's SETTINGS frame from the connection preface.

**Mode:** Passive (surface). Normal HTTP/2 connection establishment.

### 1.8 Default File/Path Fingerprinting

**How it works:** Probe for technology-specific default files and paths:

- **WordPress:** `/wp-content/`, `/wp-admin/`, `/wp-login.php`,
  `/wp-includes/js/jquery/jquery.js`, `/xmlrpc.php`
- **Drupal:** `/core/misc/favicon.ico`, `/CHANGELOG.txt`, `/README.txt`,
  `/sites/default/files/`
- **Joomla:** `/administrator/`, `/components/`, `/language/en-GB/en-GB.xml`
- **Rails:** `/rails/info`, `/assets/application.js`
- **Django:** `/admin/`, `/static/admin/css/`
- **Spring Boot:** `/actuator/`, `/actuator/health`, `/actuator/info`,
  `/actuator/env`
- **Express/Node:** `/package.json`, `/node_modules/`
- **ASP.NET:** `/web.config`, `/elmah.axd`, `/trace.axd`
- **Tomcat:** `/manager/html`, `/host-manager/html`, `/WEB-INF/`

**Favicon hash matching:** Compute the MurmurHash3 (for Shodan) or MD5 (for OWASP
database) of `/favicon.ico` and compare against known hashes. OWASP maintains a
database of 300+ favicon-to-technology mappings (e.g., Jenkins, Jira, Confluence,
GitWeb, Nagios, phpMyAdmin).

**What it reveals:** Exact technology stack, version numbers (from CHANGELOG/README
files), framework, CMS, and administrative interfaces.

**Implementation difficulty (Go):** Easy. HTTP GET requests to a list of known paths,
check for 200 responses, hash favicon. Maintain a signature database.

**Mode:** Mixed. Checking common paths is surface-safe. Probing administrative paths
(actuator, manager) is deep.

---

## 2. DNS-Based Discovery

### 2.1 DNSSEC Zone Walking (NSEC/NSEC3)

**How it works:** DNSSEC uses NSEC records to provide authenticated denial of
existence. NSEC records form a chain listing the next existing domain name in the
zone, creating a linked list of all domain names. By querying for non-existent names
and following NSEC records, you can enumerate every name in the zone.

NSEC3 uses hashed names to prevent direct enumeration, but the hashes can be
brute-forced offline. RFC 9276 recommends 0 iterations and no salt, making NSEC3
cracking trivial.

Walk procedure:
1. Query for a non-existent name (e.g., `0.example.com`)
2. NSEC response reveals the next valid name (e.g., `admin.example.com`)
3. Query for a name just after that (e.g., `admin0.example.com`)
4. Repeat until wrapping back to the start

**What it reveals:** Complete zone enumeration -- every subdomain, even those not
publicly documented.

**Implementation difficulty (Go):** Medium. Use `github.com/miekg/dns` to send DNS
queries with DNSSEC flags, parse NSEC/NSEC3 records from authority section. For
NSEC3, need offline hash cracking against a wordlist.

**Mode:** Active (deep). Sends many DNS queries, detectable by DNS monitoring.

**Real-world example:** The `nsec3map` tool can enumerate complete DNSSEC-signed
zones. Nmap includes an `dns-nsec3-enum` NSE script for this.

### 2.2 DNS Rebinding Detection

**How it works:** DNS rebinding attacks use a domain with short TTL that alternates
between a public IP (to pass same-origin checks) and a private/internal IP (to
access internal services). Detection involves:

1. Resolve a target domain multiple times with short intervals
2. Check if resolutions alternate between public and private (RFC1918) IPs
3. Monitor for TTL values of 0 or 1 (suspicious short TTLs)
4. Check if CNAME chains resolve to private address space

Detection signals: Domain resolves to both public and private IPs across queries.
TTL is abnormally low (0-5 seconds). CNAME chain includes intermediate names
resolving to private space.

**What it reveals:** Active DNS rebinding infrastructure, potential for SSRF attacks
via DNS, services vulnerable to rebinding.

**Implementation difficulty (Go):** Medium. Resolve domain multiple times using
`net.Resolver`, check if any responses are in RFC1918 ranges. Track TTL values (need
raw DNS queries via `github.com/miekg/dns` to get actual TTL, since Go's resolver
doesn't expose it).

**Mode:** Passive (surface). Just DNS resolution.

**Real-world example:** NCC Group's Singularity framework demonstrates how DNS
rebinding can access internal services through a browser.

### 2.3 Wildcard DNS Detection and Bypass

**How it works:** Query several random subdomains (e.g., `xk7f9a2b.example.com`).
If they all resolve, a wildcard DNS record exists. Record the wildcard IP(s). Then
during subdomain enumeration, filter out any results matching the wildcard IP(s).

Advanced technique: Not all wildcards are simple -- some use different IPs for
different subdomain prefixes (e.g., `*.dev` vs `*.staging`). Test with random names
under each discovered prefix pattern.

Bypass technique: Even with wildcards, explicitly configured subdomains may resolve
to different IPs. Count distinct resolution IPs; those appearing rarely (compared
to the frequent wildcard IP) indicate real, explicitly configured subdomains.

**What it reveals:** Which subdomains are real vs wildcard-matched, accurate
subdomain enumeration results.

**Implementation difficulty (Go):** Easy. Resolve 5-10 random subdomains, check if
they resolve. If so, record the IPs as wildcard signatures and filter subsequent
results. ShuffleDNS and subfinder both implement this.

**Mode:** Active (deep). DNS brute-forcing involved.

### 2.4 CNAME Chain Analysis

**How it works:** Resolve a domain and follow its CNAME chain to identify:
- CDN providers (e.g., CNAME to `*.cloudfront.net`, `*.akamaiedge.net`)
- Cloud services (e.g., CNAME to `*.s3.amazonaws.com`, `*.azurewebsites.net`)
- Load balancers (e.g., CNAME to ELB endpoints)
- Subdomain takeover candidates (CNAME to unclaimed services)
- SaaS providers (CNAME to `*.herokuapp.com`, `*.netlify.app`)

**What it reveals:** Infrastructure provider, hosting platform, CDN, potential
subdomain takeover targets (dangling CNAMEs).

**Implementation difficulty (Go):** Easy. Recursive CNAME resolution with
`github.com/miekg/dns`, matching terminal CNAME against known provider patterns.

**Mode:** Passive (surface). Standard DNS resolution.

### 2.5 DNS Cache Snooping

**How it works:** Send non-recursive DNS queries (RD flag = 0) to a target's
recursive DNS server for specific domain names. If the server returns a positive
response, it means someone at that organization recently resolved that domain (it's
cached). This reveals browsing patterns and service usage.

Timing-based variant: Send recursive queries and measure response time. Cached
entries respond in <5ms; uncached entries take 50-500ms for resolution.

**What it reveals:** Which websites and services the target organization uses,
internal service names, potential third-party dependencies. Can confirm whether an
organization uses specific security products, SaaS tools, or partner services.

**Implementation difficulty (Go):** Easy. Use `github.com/miekg/dns` to send queries
with `RecursionDesired = false`. Check if response contains an answer.

**Mode:** Active (deep). Probing DNS servers directly. May be detectable.

### 2.6 Passive DNS Sources

**How it works:** Query multiple passive DNS databases to find historical and current
DNS records without making any direct queries to the target:

| Source | Access | Notes |
|--------|--------|-------|
| crt.sh | Free | CT log search, supports wildcard queries (`%.example.com`) |
| VirusTotal | API key (free tier) | DNS from malware analysis + user queries |
| SecurityTrails | API key (paid) | Large historical DNS database |
| Shodan InternetDB | Free, no key | Open ports, vulns, hostnames per IP |
| Censys | API key (1000 free/month) | Certificate + host search |
| RiskIQ/PassiveTotal | API key | 400M+ unique records/day |
| AlienVault OTX | Free | Threat intelligence feeds |
| Common Crawl | Free | Web crawl data, URL extraction |
| Wayback Machine | Free | Historical URL archive |
| BGP.Tools | Free | ASN/BGP routing data |
| Hurricane Electric | Free | BGP toolkit, prefix lookups |

**What it reveals:** Historical subdomains, IP address changes, infrastructure
migrations, related domains, deleted endpoints.

**Implementation difficulty (Go):** Easy-Medium. REST API calls to each service.
Use `github.com/projectdiscovery/subfinder` as a library (Go) which wraps 20+
sources.

**Mode:** Passive (surface). No direct target interaction.

### 2.7 SPF/DKIM/DMARC Record Mining

**How it works:** Query TXT records for email authentication:

- **SPF (`_spf.example.com` or TXT on apex):** Contains `include:` directives
  listing authorized sending services. `include:spf.protection.outlook.com` reveals
  Microsoft 365 usage. `include:amazonses.com` reveals AWS SES usage.
  `ip4:x.x.x.x` directives reveal actual mail server IPs.

- **DMARC (`_dmarc.example.com`):** Contains `rua=` and `ruf=` directives pointing
  to reporting addresses, which may reveal monitoring services or additional domains.

- **DKIM (`<selector>._domainkey.example.com`):** Reveals key sizes and email
  service providers. Common selectors: `google`, `selector1`, `selector2`, `default`,
  `s1`, `s2`, `k1`, `mandrill`, `mailchimp`.

**Reverse SPF lookup:** Services like dnslytics.com/reverse-spf can find all domains
sharing the same SPF record, revealing related domains owned by the same
organization.

**What it reveals:** Email providers (Google Workspace, O365, Proofpoint,
Mimecast), marketing platforms (Mailchimp, SendGrid), additional IP ranges, related
domains, and organization structure.

**Implementation difficulty (Go):** Easy. DNS TXT lookups with `net.LookupTXT()` or
`github.com/miekg/dns`, parse SPF record syntax.

**Mode:** Passive (surface). Public DNS records.

### 2.8 MX Record Analysis

**How it works:** Query MX records for the target domain and map them to known email
providers:

- `*.google.com` / `*.googlemail.com` -- Google Workspace
- `*.protection.outlook.com` -- Microsoft 365
- `*.pphosted.com` -- Proofpoint
- `*.mimecast.com` -- Mimecast
- `mail.example.com` -- Self-hosted (reveals internal infrastructure)

Priority values reveal primary vs backup mail routing.

**What it reveals:** Email provider, security email gateway, self-hosted mail
infrastructure IPs.

**Implementation difficulty (Go):** Easy. `net.LookupMX()`, match against known
provider patterns.

**Mode:** Passive (surface).

### 2.9 NS Delegation Analysis

**How it works:** Query NS records and map to known DNS providers:

- `*.awsdns-*` -- AWS Route53
- `*.cloudflare.com` -- Cloudflare
- `*.azure-dns.*` -- Azure DNS
- `*.googledomains.com` -- Google Cloud DNS
- `ns*.example.com` -- Self-hosted DNS (reveals infrastructure)
- `*.domaincontrol.com` -- GoDaddy
- `*.ultradns.com` -- Neustar/UltraDNS

**What it reveals:** DNS provider, hosting provider correlation, self-managed vs
cloud-managed DNS.

**Implementation difficulty (Go):** Easy. `net.LookupNS()`, match against known
patterns.

**Mode:** Passive (surface).

### 2.10 CHAOS TXT Records

**How it works:** Query for TXT records in the CHAOS class (class 3):

```
dig CH TXT version.bind @target-dns-server
dig CH TXT hostname.bind @target-dns-server
dig CH TXT authors.bind @target-dns-server
dig CH TXT id.server @target-dns-server
```

BIND DNS servers respond to these with the software version and hostname by default.
Even when the version string is overridden, the response pattern itself confirms
BIND usage (non-BIND servers typically return REFUSED or NXDOMAIN).

**What it reveals:** DNS server software (BIND) and exact version, server hostname.

**Implementation difficulty (Go):** Easy. Send CHAOS class TXT query using
`github.com/miekg/dns` with `Qclass = dns.ClassCHAOS`.

**Mode:** Active (deep). Direct probing of DNS server.

---

## 3. Network-Level Discovery

### 3.1 TCP Window Size & TTL OS Fingerprinting

**How it works:** Different operating systems use different default TTL and TCP
window size values in their SYN/SYN-ACK packets:

| OS | Default TTL | Common Window Size |
|----|-------------|-------------------|
| Linux | 64 | 64240, 29200 |
| Windows | 128 | 8192, 65535 |
| macOS/iOS | 64 | 65535 |
| FreeBSD | 64 | 65535 |
| Cisco IOS | 255 | 4128 |
| Solaris | 255 | 8760 |

JA4T captures these as `window_options_mss_ttl` format. The TCP options field order
also varies: Linux uses MSS, SackOK, Timestamp, NOP, Window Scale (2-4-8-1-3);
Windows uses MSS, NOP, Window Scale, NOP, NOP, SackOK (2-1-3-1-1-4).

**What it reveals:** Remote operating system with high confidence. Also reveals
approximate hop count (default TTL minus observed TTL).

**Implementation difficulty (Go):** Hard. Requires raw socket access
(`syscall.Socket` with `AF_INET, SOCK_RAW`) to read SYN-ACK TCP headers. Need root
privileges. Can use `github.com/google/gopacket` for packet parsing.

**Mode:** Passive (surface) if observing responses to normal connections. Active
(deep) if sending crafted probes.

### 3.2 IP ID Sequence Analysis

**How it works:** The IP Identification field is used for fragment reassembly. By
observing IP ID values across multiple packets:

- **Incremental (global):** Old Windows (pre-Vista) increments globally -- enables
  idle/zombie scanning
- **Incremental (per-connection):** Linux increments per connection
- **Random:** Modern Windows, hardened Linux
- **Zero:** Linux (DF-flagged packets), some IoT

Idle scanning: If a third-party host uses global incremental IP IDs, an attacker can
infer whether a target port is open by observing IP ID increments on the idle host
after sending spoofed packets.

**What it reveals:** OS identification, vulnerability to idle scanning attacks.

**Implementation difficulty (Go):** Hard. Requires raw packet capture and analysis.
Need `gopacket` or raw sockets with IP-level parsing.

**Mode:** Active (deep). Sends crafted packets.

### 3.3 ICMP Timestamp & Netmask Probing

**How it works:**
- **ICMP Timestamp (Type 13):** Request system time from remote host. Response
  reveals local time, enabling timezone detection and clock skew analysis for OS
  fingerprinting.
- **ICMP Netmask (Type 17):** Request subnet mask. Most modern systems don't
  respond, but those that do reveal internal network configuration.

**What it reveals:** OS type (based on response behavior), timezone, internal
network configuration, whether ICMP is filtered.

**Implementation difficulty (Go):** Medium. Use `golang.org/x/net/icmp` to craft
Type 13/17 messages, parse responses. Need root for raw ICMP.

**Mode:** Active (deep). Active probing. Many firewalls block these.

### 3.4 Path MTU Discovery Fingerprinting

**How it works:** Different operating systems implement Path MTU Discovery
differently. By observing the Don't Fragment (DF) bit, initial packet sizes, and
response to ICMP "Fragmentation Needed" messages, you can fingerprint the OS.
VPN tunnels reduce the effective MTU by a characteristic amount per protocol:

| Protocol | MTU Reduction | Effective MTU |
|----------|--------------|---------------|
| WireGuard | 80 bytes | 1420 |
| OpenVPN (UDP) | 52 bytes | 1448 |
| IPsec (ESP+NAT-T) | 72 bytes | 1428 |
| SSH tunnel | 36-44 bytes | 1456-1464 |

p0f (passive OS fingerprinting) includes MTU analysis for VPN detection.

**What it reveals:** OS type, VPN/tunnel presence and protocol type.

**Implementation difficulty (Go):** Hard. Requires raw packet inspection with
`gopacket`. MTU probing needs crafting oversized packets with DF bit set.

**Mode:** Active (deep).

### 3.5 mDNS / LLMNR / NBT-NS Enumeration

**How it works:** These are local network name resolution protocols:

- **mDNS (port 5353 UDP):** Used by Apple Bonjour and Linux avahi. Send queries to
  multicast address `224.0.0.251`. Devices respond with their services (printers,
  AirPlay, file shares, etc.).
- **LLMNR (port 5355 UDP):** Microsoft's link-local name resolution. Multicast to
  `224.0.0.252`.
- **NBT-NS (port 137 UDP):** Legacy NetBIOS name resolution. Broadcast-based.

Responder (Python tool) passively captures these queries and can actively poison
responses to capture NTLMv2 hashes.

**What it reveals:** Local network device inventory, hostnames, service types,
operating systems, potential for credential capture via poisoning.

**Implementation difficulty (Go):** Medium. Join multicast groups with
`net.ListenMulticastUDP`, send/receive mDNS queries using DNS wire format.
`github.com/hashicorp/mdns` provides a Go mDNS library.

**Mode:** Active (authorized). Only for internal network assessment. mDNS poisoning
is definitely authorized-only.

### 3.6 SNMP Community String Enumeration

**How it works:** SNMP v1/v2c uses "community strings" as passwords. Default strings
are well-known: `public` (read-only), `private` (read-write). Tools like
`onesixtyone` brute-force community strings by sending GetRequest PDUs with
candidate strings to UDP port 161. Valid strings return data; invalid strings return
no response or an error.

Nmap's `snmp-brute` script tests common strings. Once a valid string is found,
`snmpwalk` can extract extensive system information: hostname, OS, running processes,
network interfaces, installed software, routing tables.

**What it reveals:** System configuration details, OS, running services, network
topology, routing information, installed software. With read-write access (private
string), full device compromise.

**Implementation difficulty (Go):** Easy. Use `github.com/gosnmp/gosnmp` to send
SNMP GetRequest with candidate community strings, detect valid responses.

**Mode:** Active (authorized). Brute-forcing authentication credentials.

---

## 4. Web Application Fingerprinting

### 4.1 WAF Fingerprinting

**How it works:** Beyond wafw00f's basic approach, advanced techniques include:

1. **Behavioral analysis:** Send known-malicious payloads (XSS, SQLi) and observe
   blocking behavior. Different WAFs block at different stages and return different
   response codes/bodies.

2. **Timing analysis:** WAFs add measurable latency for inspection. Baseline request
   time vs malicious request time reveals inspection overhead patterns specific to
   each WAF.

3. **Parsing discrepancy detection (WAFFLED):** The 2025 WAFFLED research found 1207
   bypasses across AWS WAF, Azure WAF, Cloud Armor, Cloudflare, and ModSecurity by
   mutating non-payload content elements:
   - Altering multipart boundaries
   - Adding XML namespace variations
   - JSON structural mutations (null bytes, field misplacement)
   - Header manipulation

4. **Error page signatures:** Each WAF has distinctive error/block pages (Cloudflare's
   "Attention Required", AWS WAF's 403 page, Akamai's reference ID format).

5. **Cookie injection:** Some WAFs set distinctive cookies (`__cfduid` for
   Cloudflare, `AWSALB` for AWS ALB, `_bm_sz` for Akamai Bot Manager).

**What it reveals:** WAF product and version, rule set type, bypass opportunities.

**Implementation difficulty (Go):** Medium. Send baseline request, then requests with
XSS/SQLi test strings, compare responses. Match error pages against known WAF
signatures.

**Mode:** Active (deep). Sending attack payloads.

### 4.2 CDN Detection and Origin IP Discovery

**How it works:** Multiple techniques to find origin IPs behind CDN/reverse proxies:

1. **Historical DNS records:** Query SecurityTrails, Shodan, Censys for historical A
   records from before CDN deployment.

2. **SSL certificate pivoting:** Search Censys for the target's SSL certificate
   (by SHA256 hash or Common Name) across all IPs. The origin server likely uses
   the same cert.

3. **Favicon hash search:** Compute MurmurHash3 of `/favicon.ico`, search Shodan
   with `http.favicon.hash:<hash>` to find all IPs serving the same favicon.

4. **Unique content search:** Find unique strings in the response (copyright notice,
   analytics ID, custom header) and search Shodan/Censys for IPs with matching
   content: `http.html:"UniqueString123"`.

5. **Email header analysis:** Trigger email from the application (password reset,
   signup confirmation). The `Received:` header often reveals the origin server IP.

6. **DNS records other than A:** Check MX, SPF, TXT records which may reference the
   origin IP directly.

7. **Subdomain scanning:** Non-primary subdomains (dev, staging, api, mail) may point
   directly to origin infrastructure without CDN.

8. **SSRF exploitation:** If the application has SSRF, force it to connect outbound
   to your server, revealing the origin IP in your logs.

9. **Cloud IP range exclusion:** If target uses Cloudflare, get all Cloudflare IPs
   and scan the remaining address space associated with the org's ASN.

Tools: CloudFlair, CloudFail, CF-Hero.

**What it reveals:** Origin server IP, enabling direct access bypassing WAF/CDN
protections.

**Implementation difficulty (Go):** Medium. Combination of DNS lookups, Shodan/Censys
API queries, and HTTP request analysis.

**Mode:** Mixed. Passive DNS/certificate searches are surface. SSRF-based discovery
is authorized.

### 4.3 JavaScript Library/Framework Version Detection

**How it works:**

1. **Source map detection:** Check for `.map` files referenced in JavaScript bundles
   via `//# sourceMappingURL=` comments. Source maps expose original file paths,
   variable names, and potentially full source code. Check both inline references and
   common paths (`/static/js/main.js.map`, `/assets/app.js.map`).

2. **Bundle analysis:** Parse JavaScript bundles for library signatures:
   - jQuery: Search for `jQuery.fn.jquery` or version string pattern
   - React: Look for `react.version` or `__REACT_DEVTOOLS_GLOBAL_HOOK__`
   - Angular: Check for `ng-version` attribute in HTML, or `angular.version`
   - Vue: Look for `Vue.version` or `__VUE__`
   - Webpack: Check for `webpackJsonp`, `__webpack_require__`, webpack runtime
     patterns

3. **Comment/banner extraction:** Libraries often include version comments at the top
   of minified files (e.g., `/*! jQuery v3.6.0 |`).

4. **Known-hash matching:** Hash the entire JS file and compare against a database
   of known library versions (similar to Wappalyzer/retire.js approach).

5. **Wappalyzer patterns:** ProjectDiscovery's `wappalyzergo` Go library implements
   the Wappalyzer detection engine with regex patterns matching headers, cookies,
   meta tags, HTML content, and JavaScript variables.

**What it reveals:** Frontend framework and version, build tool, potentially internal
source code structure and paths, API endpoints hidden in JS bundles, hardcoded
secrets.

**Implementation difficulty (Go):** Medium. HTTP requests to check for source maps,
regex matching against known patterns. Use `wappalyzergo` for broad detection.

**Mode:** Passive (surface). Just analyzing publicly served files.

**Real-world example:** Source map exposure has been used in bug bounties to discover
hardcoded API keys, internal URLs, and sensitive business logic, often earning
high-severity payouts.

### 4.4 Cookie Attribute Analysis

**How it works:** Session cookie naming conventions reliably identify backend
frameworks:

| Cookie Name | Technology |
|-------------|-----------|
| `PHPSESSID` | PHP |
| `JSESSIONID` | Java (Tomcat, JBoss, etc.) |
| `ASP.NET_SessionId` | ASP.NET |
| `CFID` / `CFTOKEN` | Adobe ColdFusion |
| `_session_id` | Ruby on Rails |
| `connect.sid` | Express.js (Node.js) |
| `csrftoken` / `sessionid` | Django |
| `session` (Flask-style) | Flask |
| `laravel_session` | Laravel (PHP) |
| `_gorilla_csrf` | Gorilla (Go) |
| `rack.session` | Ruby Rack |

Additional cookie attributes reveal security posture:
- Missing `Secure` flag -- cookies sent over HTTP
- Missing `HttpOnly` -- cookies accessible to JavaScript
- `SameSite` value -- CSRF protection level
- Cookie path and domain scope

**What it reveals:** Backend framework/language, security configuration, potential
for session attacks.

**Implementation difficulty (Go):** Easy. Parse `Set-Cookie` headers, match cookie
names against known patterns.

**Mode:** Passive (surface). Analyzing response headers from normal requests.

### 4.5 CSP Header Mining

**How it works:** Parse the `Content-Security-Policy` header to extract all
whitelisted domains. These reveal:

- CDN providers (`cdn.example.com`, `*.cloudfront.net`)
- Analytics services (`*.google-analytics.com`, `*.hotjar.com`)
- API endpoints (`api.example.com`, `api-v2.example.com`)
- Third-party integrations (`*.stripe.com`, `*.intercom.io`)
- Internal services accidentally whitelisted
- Staging/development domains

Also check `Content-Security-Policy-Report-Only` headers and `report-uri` /
`report-to` directives which may reveal internal monitoring infrastructure.

**What it reveals:** Complete map of trusted third-party services, internal API
endpoints, potential additional attack surface.

**Implementation difficulty (Go):** Easy. Parse CSP header string, extract domain
names from each directive (`script-src`, `connect-src`, `img-src`, etc.).

**Mode:** Passive (surface). Analyzing response headers.

**Real-world example:** CSP policies have been found to whitelist entire S3 domains,
allowing attackers to host malicious scripts on their own S3 buckets and have them
loaded by the target application.

### 4.6 robots.txt and sitemap.xml Mining

**How it works:** Fetch `/robots.txt` and parse `Disallow` directives -- these
intentionally list paths the site owner wants hidden from search engines, which are
often the most interesting paths for security testing:

- Admin panels (`/admin/`, `/administrator/`)
- API endpoints (`/api/v1/`, `/graphql`)
- Development/staging paths (`/dev/`, `/staging/`, `/test/`)
- Backup files (`/backup/`, `/old/`)
- Configuration files (`/config/`, `/.env`)

Fetch `/sitemap.xml` (and referenced sub-sitemaps) to discover the complete URL
structure of the application, including pages that may not be linked from the main
navigation.

Historical robots.txt via Wayback Machine (`web.archive.org/web/*/example.com/robots.txt`)
reveals paths that were once disallowed but may still be accessible.

**What it reveals:** Hidden paths, admin interfaces, API endpoints, application
structure, deprecated functionality.

**Implementation difficulty (Go):** Easy. HTTP GET, text parsing for robots.txt,
XML parsing for sitemap.xml.

**Mode:** Passive (surface). Publicly accessible files.

### 4.7 .well-known URI Enumeration

**How it works:** Probe the IANA-registered `.well-known` URIs that reveal
technology and configuration:

| URI | Reveals |
|-----|---------|
| `/.well-known/security.txt` | Security contact, PGP key, bug bounty program |
| `/.well-known/openid-configuration` | OAuth/OIDC provider, all auth endpoints, supported scopes, signing algorithms, JWKS URI |
| `/.well-known/jwks.json` | Public keys for JWT verification |
| `/.well-known/change-password` | Password reset endpoint |
| `/.well-known/webfinger` | Identity federation, Mastodon/ActivityPub |
| `/.well-known/nodeinfo` | Federated social network software/version |
| `/.well-known/apple-app-site-association` | Associated iOS apps, universal links |
| `/.well-known/assetlinks.json` | Associated Android apps |
| `/.well-known/mta-sts.txt` | Email MTA-STS policy |
| `/.well-known/matrix/server` | Matrix server delegation |
| `/.well-known/acme-challenge/` | Let's Encrypt certificate validation |
| `/.well-known/caldav` / `/.well-known/carddav` | Calendar/contact server |
| `/.well-known/host-meta` | Host metadata (LRDD) |
| `/.well-known/oauth-authorization-server` | OAuth 2.0 server metadata |
| `/.well-known/resource-priority` | Resource priority hints |
| `/.well-known/traffic-advice` | CDN/proxy traffic handling |

The `openid-configuration` endpoint is particularly valuable -- it returns a JSON
document listing the authorization endpoint, token endpoint, userinfo endpoint,
supported grant types, supported scopes, JWKS URI, and signing algorithms.

**What it reveals:** Authentication infrastructure, associated apps, federation
status, email security policy, platform technology.

**Implementation difficulty (Go):** Easy. HTTP GET to each path, check for 200
responses, parse JSON/text content.

**Mode:** Passive (surface). All publicly accessible.

### 4.8 Version Control Repository Exposure

**How it works:** Check for exposed VCS metadata directories:

- **Git:** `GET /.git/HEAD` -- returns `ref: refs/heads/main` if exposed. Then
  download `.git/config`, `.git/index`, `.git/packed-refs`, and recursively
  download objects to reconstruct the full repository.
- **SVN:** `GET /.svn/entries` -- returns repository metadata if exposed.
- **Mercurial:** `GET /.hg/store/00manifest.i` -- returns manifest data.
- **Bazaar:** `GET /.bzr/README` -- returns Bazaar repository marker.

CVE-2025-66036 documents the widespread nature of `.git` exposure. Tools like
`git-dumper` can reconstruct entire repositories from exposed `.git/` directories.

Additional checks:
- `/.git/config` -- may contain remote URLs with credentials
- `/.git/logs/HEAD` -- commit history with author emails
- `/.env` -- environment variables with secrets
- `/.DS_Store` -- macOS directory metadata leaking file names

**What it reveals:** Complete source code, commit history with author names/emails,
configuration files, API keys, database credentials, internal URLs.

**Implementation difficulty (Go):** Easy. HTTP HEAD/GET requests to known paths,
check for 200 responses.

**Mode:** Surface for detection (checking existence). Deep for extraction
(downloading repository contents).

**Real-world example:** Thousands of exposed .git repositories discovered across
cloud providers, corporate networks, and government websites. Often yields
credentials for full infrastructure compromise.

### 4.9 Webpack/Source Map Analysis

**How it works:**

1. Parse HTML/JS for source map references (`//# sourceMappingURL=`)
2. Fetch the `.map` file
3. Parse the Source Map V3 JSON format which contains:
   - `sources`: Array of original file paths (reveals project structure)
   - `sourcesContent`: Optionally contains the full original source code
   - `names`: Variable and function names from original source
   - `mappings`: Position mappings

4. Analyze extracted source for:
   - Hardcoded API keys and secrets
   - Internal API endpoint URLs
   - Authentication logic
   - Business logic vulnerabilities
   - Dependency confusion opportunities (internal package names)

The Ostorlab 2025 research demonstrated using source maps to identify internal npm
package names for dependency confusion attacks.

**What it reveals:** Full original source code, project structure, internal
package names, API endpoints, hardcoded secrets.

**Implementation difficulty (Go):** Medium. Parse JS files for sourceMappingURL,
fetch and parse Source Map V3 JSON, extract source paths and content.

**Mode:** Passive (surface). Analyzing publicly served files.

---

## 5. Cloud and Infrastructure Fingerprinting

### 5.1 Cloud Provider Identification

**How it works:** Multiple methods to identify the cloud provider:

1. **IP range matching:** Each cloud provider publishes their IP ranges:
   - AWS: `https://ip-ranges.amazonaws.com/ip-ranges.json`
   - Azure: `https://www.microsoft.com/en-us/download/details.aspx?id=56519`
   - GCP: `https://www.gstatic.com/ipranges/cloud.json`
   - Cloudflare: `https://www.cloudflare.com/ips/`

2. **ASN lookup:** Map IP to ASN, then ASN to organization:
   - AS16509 = Amazon (AWS)
   - AS15169 = Google (GCP)
   - AS8075 = Microsoft (Azure)
   - AS13335 = Cloudflare
   - AS14618 = Amazon (AWS us-east-1)

3. **Reverse DNS patterns:**
   - `*.compute.amazonaws.com` -- AWS EC2
   - `*.compute.googleusercontent.com` -- GCP Compute
   - `*.cloudapp.azure.com` -- Azure VM

4. **Response headers:**
   - `X-Amz-*` headers -- AWS
   - `X-Azure-*` headers -- Azure
   - `X-Cloud-Trace-Context` -- GCP
   - `CF-Ray` -- Cloudflare

Tools: `github.com/blacklanternsecurity/cloudcheck` (Rust),
`github.com/nccgroup/cloud_ip_ranges`.

**What it reveals:** Cloud provider, region, service type.

**Implementation difficulty (Go):** Easy. Download IP range files, build prefix
trees for lookup. ASN lookup via Team Cymru or BGP databases.

**Mode:** Passive (surface).

### 5.2 Kubernetes API Server Detection

**How it works:** Scan for Kubernetes-related ports and probe for API server
endpoints:

| Port | Service |
|------|---------|
| 6443 | Kubernetes API Server (default) |
| 8443 | Kubernetes API Server (alternate) |
| 10250 | Kubelet API |
| 10255 | Kubelet read-only API |
| 10257 | kube-controller-manager |
| 10259 | kube-scheduler |
| 2379/2380 | etcd |
| 30000-32767 | NodePort range |

Probe endpoints:
- `/version` -- returns Kubernetes version JSON
- `/healthz` -- health check endpoint
- `/.well-known/openid-configuration` -- OIDC configuration
- `/api` -- API group listing
- `/api/v1/namespaces` -- namespace listing (if RBAC allows)

Kubelet API (`port 10250`):
- `/pods` -- lists all pods on the node
- `/run/<namespace>/<pod>/<container>` -- execute commands in containers

Shodan reports ~287K Kubelet APIs exposed to the internet, ~100 fully exploitable.

**What it reveals:** Kubernetes presence, version, node configuration, running pods,
potential for cluster compromise.

**Implementation difficulty (Go):** Easy. HTTP requests to known ports/endpoints,
parse JSON responses. Use `client-go` library for authenticated enumeration.

**Mode:** Active (deep). Direct service probing.

### 5.3 Docker API Exposure

**How it works:** Docker daemon can be exposed on TCP port 2375 (unencrypted) or
2376 (TLS). Probe for:

- `GET /version` -- Docker version info
- `GET /info` -- system-wide information
- `GET /containers/json` -- list running containers
- `GET /images/json` -- list images

An exposed Docker API allows arbitrary container creation with host filesystem
mounts, enabling complete host compromise.

**What it reveals:** Docker presence and version, running containers, images,
system configuration. Full host compromise if writable.

**Implementation difficulty (Go):** Easy. HTTP GET to port 2375/2376, parse JSON.

**Mode:** Active (deep).

### 5.4 etcd Exposure

**How it works:** etcd listens on port 2379. Probe for:

- `GET /version` -- etcd version
- `GET /v2/keys/` -- list all keys (v2 API)
- `GET /v3/kv/range` -- range query (v3 API)
- `GET /health` -- health endpoint

Exposed etcd in Kubernetes clusters contains all secrets, configurations, and
cluster state.

**What it reveals:** etcd version, potentially all Kubernetes secrets, service
account tokens, TLS certificates.

**Implementation difficulty (Go):** Easy. HTTP GET to port 2379. Use
`go.etcd.io/etcd/client/v3` for proper v3 API access.

**Mode:** Active (deep).

### 5.5 Cloud Storage Enumeration

**How it works:** Enumerate cloud storage buckets using keyword permutations based
on the target organization:

- **AWS S3:** Check `http://<bucket>.s3.amazonaws.com` and
  `http://s3.amazonaws.com/<bucket>`. CNAME records pointing to
  `*.s3.amazonaws.com` confirm S3 usage.
- **GCS:** Check `https://storage.googleapis.com/<bucket>` or
  `http://<bucket>.storage.googleapis.com`.
- **Azure Blob:** Check `https://<account>.blob.core.windows.net/<container>`.

Permutation patterns: `{company}`, `{company}-prod`, `{company}-dev`,
`{company}-staging`, `{company}-backup`, `{company}-logs`, `{company}-data`,
`{company}-assets`, `{company}-static`, `{company}-media`.

Response analysis:
- 200/403 -- bucket exists (403 = exists but no ListBucket permission)
- 404 -- bucket doesn't exist
- Bucket listing enabled (XML response with Contents) -- major finding

Tools: s3enum, CloudBrute, GrayHatWarfare.

**What it reveals:** Exposed storage buckets, potentially sensitive data, backup
files, log files.

**Implementation difficulty (Go):** Easy. HTTP HEAD/GET requests with permuted
bucket names.

**Mode:** Active (deep). Brute-forcing resource names.

### 5.6 Serverless Function Detection

**How it works:** Detect serverless endpoints by URL patterns and response
characteristics:

- **AWS Lambda URLs:** `*.lambda-url.<region>.on.aws` pattern
- **API Gateway:** `*.execute-api.<region>.amazonaws.com`
- **Cloud Functions:** `<region>-<project>.cloudfunctions.net`
- **Azure Functions:** `<name>.azurewebsites.net/api/`

Response headers:
- `X-Amzn-Requestid` -- Lambda/API Gateway
- `X-Cloud-Trace-Context` -- GCP Cloud Functions
- `Function-Execution-Id` -- GCP Cloud Functions

Cold start timing: First request to a serverless function is measurably slower
(100ms-2s) than subsequent requests, creating a distinctive timing pattern.

**What it reveals:** Serverless platform, region, potentially function names.

**Implementation difficulty (Go):** Easy. URL pattern matching and header analysis.

**Mode:** Passive (surface). Analyzing response characteristics.

### 5.7 Service Mesh Detection

**How it works:** Detect service mesh sidecars and control planes:

- **Istio:** Check for `x-envoy-*` response headers (Envoy sidecar proxy),
  `istio-pilot` on port 15010/15012, Envoy admin on port 15000.
- **Linkerd:** Check for `l5d-*` headers, Linkerd control plane on port 8084.
- **Consul Connect:** Check for Consul API on port 8500, Envoy sidecar.

Headers that reveal mesh presence:
- `x-envoy-upstream-service-time` -- Envoy (Istio/Consul)
- `x-envoy-decorator-operation` -- Envoy routing info
- `server: envoy` -- Envoy proxy
- `l5d-server-id` -- Linkerd

**What it reveals:** Service mesh in use, internal service topology hints,
sidecar proxy version.

**Implementation difficulty (Go):** Easy. Check response headers for known mesh
patterns.

**Mode:** Passive (surface). Analyzing response headers.

---

## 6. Passive Reconnaissance

### 6.1 Google Dorking

**How it works:** Use Google advanced search operators to find indexed sensitive
content:

**File discovery:**
- `site:example.com filetype:pdf` -- find PDFs
- `site:example.com filetype:xlsx OR filetype:docx` -- office documents
- `site:example.com filetype:sql OR filetype:bak` -- database dumps/backups
- `site:example.com filetype:env OR filetype:yml OR filetype:json` -- config files
- `site:example.com filetype:log` -- log files

**Path discovery:**
- `site:example.com inurl:admin` -- admin panels
- `site:example.com inurl:api` -- API endpoints
- `site:example.com inurl:debug OR inurl:trace` -- debug endpoints
- `site:example.com intitle:"index of"` -- directory listings

**Information disclosure:**
- `site:example.com "password" OR "secret" OR "api_key"` -- credential leaks
- `site:example.com ext:xml | ext:conf | ext:cnf` -- configuration files
- `"example.com" inurl:pastebin.com OR inurl:trello.com` -- external references

**What it reveals:** Sensitive files, admin interfaces, API endpoints, leaked
credentials, configuration details, third-party service usage.

**Implementation difficulty (Go):** Medium. Can scrape Google search results, but
risks rate limiting/CAPTCHA. Better to use Google Custom Search API (100 free
queries/day) or SerpAPI. Or just generate dork strings for manual review.

**Mode:** Passive (surface). Searching public indexes.

### 6.2 GitHub/GitLab Code Search

**How it works:** Search public repositories for organization-specific secrets:

```
"example.com" password OR secret OR api_key OR token
"example.com" filename:.env
"example.com" filename:config.yml
org:target-org language:python password
org:target-org filename:id_rsa
"s3.amazonaws.com/target" OR "target.s3.amazonaws.com"
"target-org" AKIA  (AWS access key prefix)
```

Tools:
- **TruffleHog:** Scans Git history for high-entropy strings matching secret
  patterns. Verifies discovered credentials against APIs.
- **Git-hound:** Searches all of GitHub (not just known repos) for organization-
  specific secrets.
- **Gitrob:** Maps organization repos and flags interesting files.

**What it reveals:** API keys, database credentials, internal URLs, infrastructure
details, service configurations, private keys.

**Implementation difficulty (Go):** Easy. Use GitHub API v4 (GraphQL) code search,
or GitHub's `gh api search/code` endpoint. TruffleHog is available as a Go library.

**Mode:** Passive (surface). Searching public repositories.

**Real-world example:** The EleKtra-Leak campaign automatically harvests AWS keys
from GitHub within minutes of exposure and launches EC2 instances for cryptojacking.
GitGuardian reports 13 million API credentials sitting in public repos.

### 6.3 Wayback Machine URL Mining

**How it works:** Use archive.org APIs and related tools to find historical URLs:

1. **GAU (GetAllURLs):** Fetches URLs from Wayback Machine, Common Crawl,
   AlienVault OTX, and URLScan simultaneously.

2. **Wayback CDX API:** `http://web.archive.org/cdx/search/cdx?url=*.example.com/*&output=json&collapse=urlkey`
   returns all archived URLs with timestamps.

3. **Historical robots.txt:** Check archived `robots.txt` files for paths that were
   once disallowed but may now be accessible without protection.

4. **Deleted pages:** Find endpoints/pages that have been removed but may still
   function on the server.

Post-processing: Filter unique URLs, extract parameters, identify API patterns,
find interesting file extensions (.sql, .bak, .env, .config).

**What it reveals:** Deleted endpoints, historical API versions, removed admin
panels, deprecated functionality, leaked parameters.

**Implementation difficulty (Go):** Easy. HTTP GET to CDX API, parse JSON response.
GAU is written in Go and usable as a library.

**Mode:** Passive (surface). Querying public archives.

### 6.4 Shodan/Censys/ZoomEye Queries

**How it works:** Search internet-wide scan databases for target infrastructure:

**Shodan queries:**
- `ssl.cert.subject.CN:"example.com"` -- find all IPs with matching cert
- `http.favicon.hash:<hash>` -- find IPs with same favicon
- `http.html:"Unique String"` -- find IPs serving matching content
- `org:"Target Organization"` -- all devices for an organization
- `asn:AS12345` -- all devices in an ASN
- `hostname:example.com` -- all subdomains indexed

**Censys queries:**
- `services.tls.certificates.leaf.names: example.com` -- certificate-based search
- `services.http.response.body: "uniquestring"` -- content matching
- `autonomous_system.asn: 12345` -- ASN-based search

**InternetDB API (free, no key):**
`https://internetdb.shodan.io/<IP>` returns open ports, vulns, CPEs, hostnames,
and tags. Updated weekly. No rate limits for non-commercial use.

**What it reveals:** Complete internet-facing infrastructure, open ports, services,
vulnerabilities, SSL certificates, historical data.

**Implementation difficulty (Go):** Easy. REST API calls. Shodan Go client:
`github.com/ns3777k/go-shodan`.

**Mode:** Passive (surface). Querying third-party databases.

### 6.5 BGP/ASN Mapping

**How it works:** Map an organization's complete IP space:

1. Find the organization's ASN(s) via WHOIS or `whois -h whois.cymru.com <IP>`
2. Query all prefixes announced by that ASN via BGP routing tables
3. Enumerate the complete IP range from announced prefixes
4. Check each IP for services

Data sources:
- Team Cymru: `v4.whois.cymru.com` (ASN mapping)
- BGP.Tools: API for prefix/ASN data
- Hurricane Electric: `bgp.he.net` (comprehensive BGP toolkit)
- RIPE/ARIN/APNIC: Regional Internet Registries for WHOIS data

Five RIRs maintain IP allocation databases: ARIN (North America), RIPE NCC (Europe),
APNIC (Asia-Pacific), LACNIC (Latin America), AFRINIC (Africa).

**What it reveals:** Complete IP address space, all announced prefixes, peering
relationships, multi-homed connections, transit providers.

**Implementation difficulty (Go):** Medium. WHOIS parsing, BGP data API queries.
Use `github.com/nitefood/asn` as reference for data sources.

**Mode:** Passive (surface). Public routing data.

### 6.6 Certificate Transparency Log Analysis

**How it works:** All CAs must log certificates to public CT logs before issuance.
Search these logs for target domains:

**crt.sh queries:**
- `%.example.com` -- all certs including wildcards
- Direct PostgreSQL access for high-speed extraction
- RSS feed for monitoring new certificates
- JSON API: `https://crt.sh/?q=%.example.com&output=json`

**Advanced patterns:**
- Track wildcard certificate patterns -- `*.example.com` indicates significant
  infrastructure
- Monitor certificate issuance timing for infrastructure migration events
- Correlate issuing CA to identify organizational practices
- Analyze SAN fields -- certificates often list multiple domains revealing
  related infrastructure
- Certificate serial number patterns for attribution

**Censys certificate search:**
- Search by SHA256, CN, or SAN
- REST API and Python library available
- 1000 free queries/month

**What it reveals:** All subdomains ever issued certificates, related domains on
same certificates, CA preferences, infrastructure changes over time.

**Implementation difficulty (Go):** Easy. HTTP GET to crt.sh JSON API, parse
results. For real-time monitoring, use CT log stream APIs.

**Mode:** Passive (surface). Public certificate data.

---

## 7. Advanced Service Detection

### 7.1 Protocol Detection on Non-Standard Ports

**How it works:** Don't assume port = protocol. Use protocol-level probes to detect
services on any port:

1. **HTTP detection:** Send `GET / HTTP/1.1\r\n\r\n` to any open port. If response
   starts with `HTTP/`, it's an HTTP service.

2. **TLS detection:** Attempt TLS handshake on any port. If handshake succeeds,
   it's TLS-wrapped (could be HTTPS, SMTPS, IMAPS, etc.).

3. **Protocol-specific banners:**
   - SSH: Connection returns `SSH-2.0-<implementation>` immediately
   - MySQL: Sends greeting packet with version string on connect
   - PostgreSQL: Responds to startup message with authentication request
   - Redis: Responds to `PING` with `+PONG`
   - MongoDB: Responds to isMaster wire protocol command
   - Elasticsearch: HTTP API responds on default port 9200
   - RabbitMQ: AMQP protocol starts with `AMQP\x00\x00\x09\x01`

4. **Fallback probes:** Send increasing specificity probes until a match:
   - NULL probe (just connect, read banner)
   - HTTP probe
   - TLS probe
   - Protocol-specific probes

Fingerprintx (Go, Praetorian) implements this for 51 protocols with a "fast mode"
for default ports and full mode for any port.

**What it reveals:** Actual service on each open port, version information.

**Implementation difficulty (Go):** Medium-Hard. Need to implement probe/response
logic for each protocol. Or use `github.com/praetorian-inc/fingerprintx` as a
library.

**Mode:** Active (deep). Sending protocol-specific probes.

### 7.2 STARTTLS Detection

**How it works:** Connect to mail server ports and check for STARTTLS upgrade
capability:

- **SMTP (25/587):** Send `EHLO probe.test`, look for `250-STARTTLS` in response
- **IMAP (143):** Send `. CAPABILITY`, look for `STARTTLS` capability
- **POP3 (110):** Send `CAPA`, look for `STLS` capability
- **LDAP (389):** Extended operation to negotiate TLS

After detecting STARTTLS support, upgrade the connection and analyze the TLS
certificate and cipher suite for additional fingerprinting.

Test for STARTTLS stripping vulnerability: Compare behavior when STARTTLS is
supported but a MITM removes the advertisement.

**What it reveals:** Mail server software, TLS support level, certificate
information, cipher suite strength, potential for downgrade attacks.

**Implementation difficulty (Go):** Medium. Need plaintext protocol interaction
followed by `tls.Client()` upgrade. Use `crypto/tls` for TLS analysis.

**Mode:** Active (deep). Direct service interaction.

### 7.3 VPN Endpoint Detection

**How it works:** Detect VPN endpoints by protocol-specific signatures:

- **OpenVPN:** Sends opcode byte at fixed offset in UDP packets. Default port 1194.
  TLS handshake patterns distinctive (JA3 fingerprint differs from browsers).

- **WireGuard:** Fixed-length encrypted UDP packets. Default port 51820. Handshake
  uses message types 0x01 (initiation, 148 bytes), 0x02 (response, 92 bytes),
  0x03 (cookie reply, 64 bytes), 0x04 (data).

- **IPsec/IKEv2:** ISAKMP headers on UDP 500/4500. IKE_SA_INIT exchange has
  distinctive format.

- **MTU-based detection:** VPN tunnels reduce effective MTU by protocol-specific
  amounts. WireGuard: 1420 MTU (80-byte overhead). OpenVPN UDP: 1448 (52-byte
  overhead). IPsec: 1428 (72-byte overhead).

**What it reveals:** VPN presence and protocol type, encryption settings, potential
for further exploitation.

**Implementation difficulty (Go):** Hard. Requires raw UDP packet analysis and
protocol-specific parsers.

**Mode:** Active (deep). Sending protocol-specific probes.

### 7.4 Database Service Fingerprinting

**How it works:** Each database has a distinctive handshake:

- **MySQL (3306):** Server sends greeting with protocol version, server version,
  thread ID, auth plugin data, capability flags.

- **PostgreSQL (5432):** Client sends StartupMessage, server responds with
  AuthenticationOk or authentication challenge. Version exposed in `server_version`
  parameter.

- **MongoDB (27017):** Wire protocol with op codes. `isMaster` command returns
  version, maxBSON, election info.

- **Redis (6379):** Send `PING`, expect `+PONG`. `INFO` command returns version,
  OS, memory stats.

- **Elasticsearch (9200):** HTTP API. `GET /` returns version, cluster name, Lucene
  version.

- **CouchDB (5984):** HTTP API. `GET /` returns version and features.

- **Cassandra (9042):** CQL native protocol. STARTUP frame elicits READY or
  AUTHENTICATE response.

- **MSSQL (1433):** TDS protocol. Pre-login message exchange reveals version.

**What it reveals:** Database type, version, configuration, authentication
requirements.

**Implementation difficulty (Go):** Medium. Protocol-specific handshake
implementation. Fingerprintx covers most of these.

**Mode:** Active (deep). Direct database connection.

### 7.5 gRPC Service Enumeration

**How it works:** Two approaches:

**Reflection-based (easy):** If gRPC reflection is enabled, query the reflection API
to discover all services, methods, and message types:
```
grpcurl -plaintext target:50051 list
grpcurl -plaintext target:50051 describe ServiceName
```

**Blind enumeration (when reflection is disabled):** The grpc-scan tool exploits
error message differences:
- Non-existent service: `Unimplemented: unknown service [name]`
- Real service, invalid method: `Unimplemented: unknown method [name] for service [ServiceName]`
- Valid service/method, no auth: `Unauthenticated` error

The tool generates candidate service names using patterns:
- Base: `User`, `UserService`, `Users`, `UserAPI`
- Namespaced: `user.User`, `api.v1.User`, `com.company.User`
- Methods: `Get`, `List`, `Create`, `Update`, `Delete`, `Search`

Requests use HTTP/2 multiplexing for fast enumeration.

**What it reveals:** Available gRPC services and methods, authentication
requirements, API surface.

**Implementation difficulty (Go):** Medium. Use `google.golang.org/grpc` to make
unary calls with empty protos, analyze error codes. Go has excellent gRPC support.

**Mode:** Active (deep). Service enumeration/brute-forcing.

### 7.6 WebSocket Endpoint Discovery

**How it works:** The STEWS tool provides a methodology:

1. **Discovery:** Try WebSocket upgrade on common paths (`/ws`, `/websocket`,
   `/socket`, `/socket.io/`, `/signalr`, `/hub`, `/stream`, `/events`,
   `/graphql`). A successful upgrade returns HTTP 101 "Switching Protocols".

2. **Fingerprinting:** After connection, send protocol-level fuzzing:
   - Test supported WebSocket protocol versions
   - Check reserved bit handling
   - Test opcode support (text, binary, ping, pong, close)
   - Measure maximum frame size
   - Check for verbose error messages revealing server library

3. **Vulnerability testing:**
   - Cross-Site WebSocket Hijacking (CSWSH): Check if Origin header is validated
   - Authentication: Check if auth tokens are required or carried from HTTP session
   - Message injection: Test for command injection in WebSocket messages

**What it reveals:** WebSocket endpoints, server library/framework, authentication
model, CSWSH vulnerabilities.

**Implementation difficulty (Go):** Medium. Use `github.com/gorilla/websocket` for
WebSocket connections, test upgrade on candidate paths.

**Mode:** Active (deep). Service probing and fuzzing.

### 7.7 Message Queue Detection

**How it works:** Detect exposed message queue systems:

- **RabbitMQ:** Management UI on 15672 (HTTP), AMQP on 5672. Check
  `GET /api/overview` for version info.
- **Kafka:** Brokers on 9092, ZooKeeper on 2181. Kafka protocol handshake with
  ApiVersions request.
- **NATS:** Default port 4222 (client), 8222 (monitoring HTTP). `INFO` command
  returns version and cluster info.
- **Redis (as message broker):** Port 6379, `PING`/`INFO` commands.
- **MQTT:** Port 1883 (unencrypted), 8883 (TLS). CONNECT packet handshake.

**What it reveals:** Message queue type, version, cluster configuration, potential
for unauthorized access to message streams.

**Implementation difficulty (Go):** Medium. Protocol-specific handshakes. Go has
good client libraries for most MQ systems.

**Mode:** Active (deep).

---

## 8. Multi-Layer Fingerprinting (Untangle)

The NDSS 2024 paper "Untangle" introduced a methodology for fingerprinting servers
behind multiple layers (CDN -> WAF -> reverse proxy -> origin):

**Technique:** HTTP differential fuzzing. Send requests that trigger different
behavior at different layers:

1. Build a "behavior repository" by fuzzing each known server type in isolation
2. Craft requests that exploit HTTP processing differences between layers:
   - Request line parsing differences
   - Header handling variations
   - Content-Length vs Transfer-Encoding priority
   - URL encoding normalization
   - Method handling differences

3. Each layer may modify/add/remove headers or return its own error, allowing
   identification

**Results:** 100% first-layer accuracy, 90.3% second-layer, 50.7% third-layer
across 13 proxy/server technologies (Nginx, Apache, Caddy, HAProxy, Varnish,
Envoy, Traefik, IIS, Tomcat, etc.).

**Implementation difficulty (Go):** Hard. Requires a signature database built from
controlled testing of each server type, plus a fuzzing engine for probe generation.

**Mode:** Active (deep). Sends malformed/unusual requests.

---

## Summary: Technique Priority Matrix

### Passive / Surface-Safe (implement first)

| Technique | Value | Difficulty |
|-----------|-------|-----------|
| Header ordering analysis | High | Easy |
| Cookie name fingerprinting | High | Easy |
| CSP header mining | High | Easy |
| DNS TXT record mining (SPF/DMARC/DKIM) | High | Easy |
| MX/NS record analysis | Medium | Easy |
| CNAME chain analysis | High | Easy |
| Cloud provider IP identification | High | Easy |
| Response header tech fingerprinting | High | Easy |
| robots.txt/sitemap.xml mining | High | Easy |
| .well-known URI enumeration | High | Easy |
| Passive DNS aggregation | High | Easy-Medium |
| CT log analysis | High | Easy |
| Shodan/Censys passive queries | High | Easy |
| Source map detection | High | Easy |
| Favicon hash matching | Medium | Easy |
| Service mesh header detection | Medium | Easy |
| Serverless function detection | Medium | Easy |
| BGP/ASN mapping | Medium | Medium |
| JA3S/JA4S TLS fingerprinting | High | Hard |
| HTTP/2 SETTINGS fingerprinting | Medium | Hard |
| TCP/TTL OS fingerprinting (passive) | Medium | Hard |

### Active / Deep Mode

| Technique | Value | Difficulty |
|-----------|-------|-----------|
| Error page differential analysis | High | Easy |
| HTTP method fingerprinting | High | Easy |
| VCS exposure detection (.git) | Critical | Easy |
| Default path fingerprinting | High | Easy |
| Cloud storage enumeration | High | Easy |
| Wildcard DNS detection | Medium | Easy |
| CHAOS TXT records | Medium | Easy |
| Kubernetes API detection | Critical | Easy |
| Docker/etcd exposure | Critical | Easy |
| WAF fingerprinting | High | Medium |
| STARTTLS detection | Medium | Medium |
| Database fingerprinting | High | Medium |
| gRPC enumeration | High | Medium |
| WebSocket discovery | High | Medium |
| DNSSEC zone walking | High | Medium |
| Protocol detection (non-standard ports) | High | Medium-Hard |
| VPN endpoint detection | Medium | Hard |
| Multi-layer fingerprinting (Untangle) | High | Hard |

### Authorized Mode Only

| Technique | Value | Difficulty |
|-----------|-------|-----------|
| CDN origin IP discovery (SSRF) | Critical | Medium |
| DNS cache snooping | Medium | Easy |
| SNMP enumeration | High | Easy |
| mDNS/LLMNR/NBT-NS | High | Medium |
| ICMP timestamp/netmask probing | Low | Medium |
| IP ID sequence analysis | Low | Hard |

---

## Key Go Libraries for Implementation

| Library | Purpose |
|---------|---------|
| `github.com/miekg/dns` | DNS queries (DNSSEC, CHAOS, raw control) |
| `github.com/projectdiscovery/wappalyzergo` | Technology detection (Wappalyzer patterns) |
| `github.com/projectdiscovery/subfinder` | Passive subdomain enumeration |
| `github.com/praetorian-inc/fingerprintx` | Protocol fingerprinting (51 protocols) |
| `github.com/google/gopacket` | Raw packet capture/analysis |
| `github.com/gosnmp/gosnmp` | SNMP operations |
| `github.com/gorilla/websocket` | WebSocket connections |
| `github.com/hashicorp/mdns` | mDNS discovery |
| `golang.org/x/net/http2` | HTTP/2 frame-level access |
| `golang.org/x/net/icmp` | ICMP probing |
| `google.golang.org/grpc` | gRPC service interaction |
| `github.com/ns3777k/go-shodan` | Shodan API client |
| `go.etcd.io/etcd/client/v3` | etcd client |
| `github.com/FoxIO-LLC/ja4` | JA4+ fingerprint suite |

---

## Sources

- [YesWeHack: HTTP Fingerprinting](https://www.yeswehack.com/learn-bug-bounty/recon-series-http-fingerprinting)
- [OWASP: Fingerprint Web Server](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server)
- [Net-Square: HTTP Fingerprinting Paper (httprint)](https://net-square.com/httprint_paper.html)
- [Untangle: Multi-Layer Web Server Fingerprinting (NDSS 2024)](https://www.ndss-symposium.org/ndss-paper/untangle-multi-layer-web-server-fingerprinting/)
- [FoxIO JA4+ Network Fingerprinting](https://github.com/FoxIO-LLC/ja4)
- [FoxIO: JA4T TCP Fingerprinting](https://blog.foxio.io/ja4t-tcp-fingerprinting)
- [Salesforce: TLS Fingerprinting with JA3](https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967/)
- [HTTP/2 Fingerprinting (lwthiker)](https://lwthiker.com/networks/2022/06/17/http2-fingerprinting.html)
- [Akamai: Passive Fingerprinting of HTTP/2 Clients (Black Hat EU 2017)](https://blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf)
- [Sentry: Abusing Exposed Sourcemaps](https://blog.sentry.security/abusing-exposed-sourcemaps/)
- [Ostorlab: Dependency Confusion via Source Maps](https://blog.ostorlab.co/mapping-dependency-confusion.html)
- [Pen Test Partners: DNSSEC NSEC Zone Walking](https://www.pentestpartners.com/security-blog/dnssec-nsec-the-accidental-treasure-map-to-your-subdomains/)
- [nsec3map: Zone Enumeration Tool](https://github.com/anonion0/nsec3map)
- [NCC Group: Singularity DNS Rebinding Framework](https://github.com/nccgroup/singularity)
- [Intigriti: Identifying Server Origin IP](https://www.intigriti.com/researchers/blog/hacking-tools/identifying-servers-origin-ip)
- [CloudFlair: Cloudflare Bypass via Censys](https://github.com/christophetd/CloudFlair)
- [Praetorian: fingerprintx](https://github.com/praetorian-inc/fingerprintx)
- [Adversis: Blind Enumeration of gRPC Services](https://www.adversis.io/blogs/blind-enumeration-of-grpc-services)
- [STEWS: WebSocket Security Testing](https://github.com/PalindromeLabs/STEWS)
- [Nmap: TCP/IP Fingerprinting Methods](https://nmap.org/book/osdetect-methods.html)
- [WAFFLED: Exploiting WAF Parsing Discrepancies (2025)](https://arxiv.org/html/2503.10846v1)
- [OWASP: Favicons Database](https://owasp.org/www-community/favicons_database)
- [IANA: Well-Known URIs Registry](https://www.iana.org/assignments/well-known-uris/well-known-uris.xhtml)
- [dnslytics: Reverse SPF Lookup](https://dnslytics.com/reverse-spf/)
- [ProjectDiscovery: wappalyzergo](https://github.com/projectdiscovery/wappalyzergo)
- [ProjectDiscovery: Nuclei Advanced Usage](https://projectdiscovery.io/blog/ultimate-nuclei-guide)
- [Shodan InternetDB API](https://internetdb.shodan.io/)
- [Advanced CT Hunting (secybers)](https://secybers.com/blog-details/advanced-certificate-transparency-hunting-uncovering-hidden-infrastructure-through-ct-log-analysis)
- [p0f-mtu: MTU-based VPN Detection](https://github.com/ValdikSS/p0f-mtu)
- [Jason Haddix: The Bug Hunter's Methodology](https://github.com/jhaddix/tbhm)
- [HackTricks: LLMNR/NBT-NS/mDNS Spoofing](https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks)
- [OpenVPN Fingerprinting (USENIX Security 2022)](https://arxiv.org/html/2403.03998v1)
- [Kubernetes Penetration Testing Guide 2026](https://www.hackingdream.net/2026/01/kubernetes-penetration-testing-complete-guide.html)
- [GAU: GetAllURLs](https://github.com/lc/gau)
- [YesWeHack: Wayback Machine Recon](https://www.yeswehack.com/learn-bug-bounty/recon-wayback-machine-web-archive)
- [Subdomain Enumeration Guide: Wildcard Filtering](https://sidxparab.gitbook.io/subdomain-enumeration-guide/active-enumeration/dns-bruteforcing)
- [Git Exposure: CVE-2025-66036](https://undercodetesting.com/the-git-folder-exposed-how-a-single-misconfiguration-can-hand-hackers-your-entire-source-code-cve-2025-66036-deep-dive-video/)
- [NDSS 2025: Cross-Layer RTT Proxy Fingerprinting](https://www.ndss-symposium.org/wp-content/uploads/2025-966-paper.pdf)
- [DNS Cache Snooping (ISC)](https://kb.isc.org/docs/aa-00509)
- [Wiz: Reconnaissance Overview](https://www.wiz.io/bug-bounty-masterclass/reconnaissance/overview)
